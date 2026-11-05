package store_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
)

type rustStat struct {
	ContentHash     string `json:"content_hash"`
	ContentIdentity string `json:"content_identity"`
	ChunkSize       uint64 `json:"chunk_size"`
	Chunks          int    `json:"chunks"`
}

func rustStatOf(t *testing.T, bin, dir, path string) rustStat {
	t.Helper()
	output := runRust(t, bin, "--store", dir, "--json", "stat", path)
	var stat rustStat
	if err := json.Unmarshal([]byte(output), &stat); err != nil {
		t.Fatalf("parse rust stat json: %v\n%s", err, output)
	}
	return stat
}

func TestMerkleHandoffRustWritesGoReads(t *testing.T) {
	bin := rustBinary(t)
	dir := t.TempDir()
	data := patternBytes(5_000)
	input := filepath.Join(t.TempDir(), "input.bin")
	if err := os.WriteFile(input, data, 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}
	runRust(t, bin, "--store", dir, "--content-identity", "merkle", "init")
	runRust(t, bin, "--store", dir, "--content-identity", "merkle", "create", "/f.bin", "--file", input, "--seed", "rust-merkle-seed")

	stat := rustStatOf(t, bin, dir, "/f.bin")
	if stat.ContentIdentity != "merkle" {
		t.Fatalf("rust content_identity = %q", stat.ContentIdentity)
	}
	expectedRoot := model.MerkleRootChunks(goChunksFor(data, 65536))
	if stat.ContentHash != expectedRoot.Hex() {
		t.Fatalf("rust root %s != Go-computed %s", stat.ContentHash, expectedRoot.Hex())
	}

	s, err := store.Open(dir, store.ReadWrite)
	if err != nil {
		t.Fatalf("go open: %v", err)
	}
	id, err := s.ResolvePath("/f.bin")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	record, err := s.ObjectMeta(id)
	if err != nil {
		t.Fatalf("object meta: %v", err)
	}
	manifest, err := store.ReadManifest(dir, record.Content)
	if err != nil {
		t.Fatalf("go read manifest: %v", err)
	}
	if manifest.Identity != model.ContentIdentityMerkleV1 {
		t.Fatalf("go parsed identity = %q", manifest.Identity)
	}
	if manifest.ContentHash.Hex() != stat.ContentHash {
		t.Fatalf("go parsed root %s != rust %s", manifest.ContentHash.Hex(), stat.ContentHash)
	}
	if model.MerkleRootChunks(manifest.Chunks) != manifest.ContentHash {
		t.Fatal("go root recomputation disagrees with the manifest")
	}
	got, err := s.ReadObject(id)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("go read: %v", err)
	}
	// Go writes a 4 KiB range; Rust must read the exact bytes and keep v3.
	payload := bytes.Repeat([]byte{0x5A}, 4096)
	if _, err := s.WriteFile(id, 100, payload); err != nil {
		t.Fatalf("go write: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("go close: %v", err)
	}
	want := append([]byte(nil), data...)
	copy(want[100:100+len(payload)], payload)

	runRust(t, bin, "--store", dir, "verify", "--full")
	cat := runRust(t, bin, "--store", dir, "cat", "/f.bin")
	if !bytes.Equal([]byte(cat), want) {
		t.Fatalf("rust cat after Go write disagrees (len %d vs %d)", len(cat), len(want))
	}
	after := rustStatOf(t, bin, dir, "/f.bin")
	if after.ContentIdentity != "merkle" {
		t.Fatalf("rust downgraded identity after Go write: %q", after.ContentIdentity)
	}
	if after.ContentHash != model.MerkleRootChunks(goChunksFor(want, 65536)).Hex() {
		t.Fatalf("rust root after Go write disagrees with Go computation")
	}
}

func TestMerkleHandoffGoWritesRustReads(t *testing.T) {
	bin := rustBinary(t)
	dir := t.TempDir()
	data := patternBytes(4_321)
	opts := fixedOptions()
	opts.ContentIdentity = model.ContentIdentityMerkleV1
	s, err := store.Init(dir, opts)
	if err != nil {
		t.Fatalf("go init: %v", err)
	}
	root, _ := s.ResolvePath("/")
	if _, err := s.CreateFileSeeded(root, []byte("go.bin"), data, 0o644, 0, 0, nil, []byte("go-merkle-seed")); err != nil {
		t.Fatalf("go create: %v", err)
	}
	expectedRoot := model.MerkleRootChunks(goChunksFor(data, 65536))
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	runRust(t, bin, "--store", dir, "verify", "--full")
	stat := rustStatOf(t, bin, dir, "/go.bin")
	if stat.ContentIdentity != "merkle" || stat.ContentHash != expectedRoot.Hex() {
		t.Fatalf("rust stat = %+v, want merkle root %s", stat, expectedRoot.Hex())
	}
	cat := runRust(t, bin, "--store", dir, "cat", "/go.bin")
	if !bytes.Equal([]byte(cat), data) {
		t.Fatalf("rust cat disagrees (len %d vs %d)", len(cat), len(data))
	}
}

// goChunksFor builds the chunk table a correct writer must produce for the
// given bytes and chunk size. Blob ids are recomputed locally from the bytes;
// only the Merkle root is compared.
func goChunksFor(data []byte, chunkSize int) []model.ChunkRef {
	chunks := make([]model.ChunkRef, 0, (len(data)+chunkSize-1)/chunkSize)
	for start := 0; start < len(data); start += chunkSize {
		end := start + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, model.ChunkRef{Hash: model.ContentHash(data[start:end]), Len: uint64(end - start)})
	}
	return chunks
}
