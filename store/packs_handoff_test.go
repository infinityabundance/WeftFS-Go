package store_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
)

func packedOptionsAtDefault(chunk uint64) store.Options {
	opts := store.DefaultOptions()
	opts.ChunkSize = chunk
	opts.Packing = true
	opts.PackOptions = store.DefaultPackOptions()
	stamp := overlayFixedTimestamp
	opts.FixedTimestampNS = &stamp
	return opts
}

func packRustArgs(dir string) []string {
	return []string{
		"--store", dir,
		"--pack",
		"--fixed-timestamp-ns", "1700000000000000000",
	}
}

func TestGoPacksRustReadsAndVerifies(t *testing.T) {
	bin := rustBinary(t)
	dir := t.TempDir()
	opts := packedOptionsAtDefault(65536)
	payload := overlayPattern(300_000, 51)
	s, err := store.Init(dir, opts)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	id, err := s.CreateFileSeeded(model.RootID, []byte("packed.bin"), payload, 0o644, 0, 0, nil, []byte("go-pack-seed"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.WriteFile(id, 150_000, []byte("go-packed-write")); err != nil {
		t.Fatalf("write: %v", err)
	}
	record, err := s.ObjectMeta(id)
	if err != nil {
		t.Fatalf("meta: %v", err)
	}
	head := s.Head()
	stats, ok := s.PackStats()
	if !ok || stats.SealedPacks == 0 || stats.PackedMembers == 0 {
		t.Fatalf("Go wrote no packs: %+v", stats)
	}
	s.Close()
	want := append([]byte(nil), payload...)
	copy(want[150_000:], []byte("go-packed-write"))

	args := packRustArgs(dir)
	runRust(t, bin, append(args, "verify", "--full")...)
	rustBytes := runRustBytes(t, bin, append(args, "cat", "/packed.bin")...)
	if !bytes.Equal(rustBytes, want) {
		t.Fatalf("rust read of Go packs differs")
	}
	stat := decodeJSONObject(t, runRust(t, bin, append(args, "stat", "/packed.bin", "--json")...))
	if stat["content_id"].(string) != record.Content.Hex() {
		t.Fatalf("manifest id differs: rust %v go %s", stat["content_id"], record.Content.Hex())
	}
	info := decodeJSONObject(t, runRust(t, bin, append(args, "--json", "info")...))
	if info["snapshot_root"].(string) != head.Hex() {
		t.Fatalf("rust head differs from the Go head")
	}
}

func TestRustPacksGoReadsAndVerifies(t *testing.T) {
	bin := rustBinary(t)
	dir := t.TempDir()
	payloadDir := t.TempDir()
	payload := overlayPattern(280_000, 52)
	payloadPath := filepath.Join(payloadDir, "payload.bin")
	if err := os.WriteFile(payloadPath, payload, 0o644); err != nil {
		t.Fatalf("payload: %v", err)
	}
	args := packRustArgs(dir)
	runRust(t, bin, append(args, "init")...)
	runRust(t, bin, append(args, "create", "/rustpacked.bin", "--file", payloadPath, "--seed", "rust-pack-seed")...)
	runRust(t, bin, append(args, "write", "/rustpacked.bin", "--offset", "120000", "--text", "rust-packed-write")...)
	want := append([]byte(nil), payload...)
	copy(want[120000:], []byte("rust-packed-write"))
	stat := decodeJSONObject(t, runRust(t, bin, append(args, "stat", "/rustpacked.bin", "--json")...))
	info := decodeJSONObject(t, runRust(t, bin, append(args, "--json", "info")...))

	reader, err := store.OpenWithOptions(dir, store.ReadOnly, packedOptionsAtDefault(65536))
	if err != nil {
		t.Fatalf("Go open Rust packed store: %v", err)
	}
	defer reader.Close()
	id, err := reader.ResolvePath("/rustpacked.bin")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got, err := reader.ReadObject(id)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("Go read of Rust packs: %v", err)
	}
	record, err := reader.ObjectMeta(id)
	if err != nil {
		t.Fatalf("meta: %v", err)
	}
	if record.Content.Hex() != stat["content_id"].(string) {
		t.Fatalf("manifest id differs: go %s rust %v", record.Content.Hex(), stat["content_id"])
	}
	if reader.Head().Hex() != info["snapshot_root"].(string) {
		t.Fatalf("Go head differs from the Rust head")
	}
	if report, err := reader.Verify(true); err != nil || !report.OK {
		t.Fatalf("Go verify of Rust packs: %v %+v", err, report)
	}
}

func TestGoGCReclaimsPacksThenRustVerifies(t *testing.T) {
	bin := rustBinary(t)
	dir := t.TempDir()
	opts := packedOptionsAtDefault(65536)
	opts.GCGraceSecs = 0
	s, err := store.Init(dir, opts)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	payloads := make(map[string][]byte)
	for i := 0; i < 6; i++ {
		name := "pack-" + itoaU64(uint64(i))
		data := overlayPattern(20_000+i*1000, byte(70+i))
		payloads["/"+name] = data
		if _, err := s.CreateFileSeeded(model.RootID, []byte(name), data, 0o644, 0, 0, nil, []byte("gc-pack-seed-"+itoaU64(uint64(i)))); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	if report, err := s.Verify(true); err != nil || !report.OK {
		t.Fatalf("pre-gc verify: %v %+v", err, report)
	}
	if err := s.Unlink(model.RootID, []byte("pack-0")); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	gc, err := s.GC(true)
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if gc.ReclaimedPacks.DeletedPacks == 0 && gc.ReclaimedPacks.DeletedCatalogSegments == 0 {
		t.Fatalf("gc reclaimed no pack metadata: %+v", gc.ReclaimedPacks)
	}
	s.Close()
	runRust(t, bin, append(packRustArgs(dir), "verify", "--full")...)
	for path, want := range payloads {
		if path == "/pack-0" {
			continue
		}
		rustBytes := runRustBytes(t, bin, append(packRustArgs(dir), "cat", path)...)
		if !bytes.Equal(rustBytes, want) {
			t.Fatalf("rust read of %s after Go GC differs", path)
		}
	}
}
