package store_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
)

// Cross-language overlay equality. The Rust binary is used only as an oracle;
// no production package invokes it. Every test skips (never passes) when the
// oracle cannot run in this court.

const overlayFixedTimestamp int64 = 1700000000000000000

func overlayPolicyArgs(dir string) []string {
	return []string{
		"--store", dir,
		"--representation", "overlay",
		"--content-identity", "merkle",
		"--fixed-timestamp-ns", "1700000000000000000",
	}
}

func overlayGoOptions(chunk uint64) store.Options {
	opts := overlayOptions(chunk)
	stamp := overlayFixedTimestamp
	opts.FixedTimestampNS = &stamp
	return opts
}

func rustInitOverlay(t *testing.T, bin, dir string) {
	t.Helper()
	// Rust's chunk size is a per-command policy flag, not persisted by `init`.
	// The oracle calls below run without one and therefore use the default
	// 64 KiB chunk grid; the Go side is configured to match.
	runRust(t, bin, append(overlayPolicyArgs(dir), "init")...)
}

func u64Text(v uint64) string { return strconv.FormatUint(v, 10) }

// rustOverlayStatJSON invokes `stat --json` with the full policy flags.
func rustOverlayStatJSON(t *testing.T, bin, dir, path string) map[string]any {
	t.Helper()
	args := append(overlayPolicyArgs(dir), "stat", path, "--json")
	out := runRust(t, bin, args...)
	return decodeJSONObject(t, out)
}

func decodeJSONObject(t *testing.T, text string) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal([]byte(text), &value); err != nil {
		t.Fatalf("parse JSON %q: %v", text, err)
	}
	return value
}

func rustInfo(t *testing.T, bin, dir string) map[string]any {
	t.Helper()
	out := runRust(t, bin, "--store", dir, "--json", "info")
	return decodeJSONObject(t, out)
}

func manifestBytes(t *testing.T, dir string, id model.Hash32) []byte {
	t.Helper()
	bytesValue, err := os.ReadFile(store.ManifestPath(dir, id))
	if err != nil {
		t.Fatalf("read manifest blob %s: %v", id.Hex(), err)
	}
	return bytesValue
}

// Build the same overlay history with each implementation and compare the
// final manifest bytes and the published head. Fixed clock and fixed ObjectId
// seeds make both runs deterministic, so equality here means byte equality of
// the on-disk representation, not merely equal logical content.
func TestOverlayWriterMatchesRustByteForByte(t *testing.T) {
	bin := rustBinary(t)
	const chunk = 65536
	payloadDir := t.TempDir()
	base := overlayPattern(int(6*chunk)+77, 21)
	edit1 := []byte("rust-and-go-same-bytes")
	edit2 := bytes.Repeat([]byte{0xA7}, 900)
	payloadPath := filepath.Join(payloadDir, "base.bin")
	edit1Path := filepath.Join(payloadDir, "edit1.bin")
	edit2Path := filepath.Join(payloadDir, "edit2.bin")
	for path, data := range map[string][]byte{payloadPath: base, edit1Path: edit1, edit2Path: edit2} {
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatalf("write payload: %v", err)
		}
	}

	rustDir := t.TempDir()
	rustInitOverlay(t, bin, rustDir)
	args := overlayPolicyArgs(rustDir)
	runRust(t, bin, append(args, "create", "/same.bin", "--file", payloadPath, "--seed", "overlay-same-seed")...)
	runRust(t, bin, append(args, "write", "/same.bin", "--offset", "100", "--file", edit1Path)...)
	runRust(t, bin, append(args, "write", "/same.bin", "--offset", "150000", "--file", edit2Path)...)
	runRust(t, bin, append(args, "write", "/same.bin", "--offset", "400000", "--text", "appended-tail")...)
	rustStatValue := rustOverlayStatJSON(t, bin, rustDir, "/same.bin")
	rustContent, ok := rustStatValue["content_id"].(string)
	if !ok || len(rustContent) != 64 {
		t.Fatalf("rust stat has no content_id: %+v", rustStatValue)
	}
	rustHead, ok := rustInfo(t, bin, rustDir)["snapshot_root"].(string)
	if !ok || len(rustHead) != 64 {
		t.Fatalf("rust info has no snapshot_root")
	}

	goDir := t.TempDir()
	s := initOverlayStore(t, goDir, overlayGoOptions(chunk))
	defer s.Close()
	id, err := s.CreateFileSeeded(model.RootID, []byte("same.bin"), base, 0o644, 0, 0, nil, []byte("overlay-same-seed"))
	if err != nil {
		t.Fatalf("go create: %v", err)
	}
	if _, err := s.WriteFile(id, 100, edit1); err != nil {
		t.Fatalf("go write 1: %v", err)
	}
	if _, err := s.WriteFile(id, 150000, edit2); err != nil {
		t.Fatalf("go write 2: %v", err)
	}
	if _, err := s.WriteFile(id, 400000, []byte("appended-tail")); err != nil {
		t.Fatalf("go write 3: %v", err)
	}
	record, err := s.ObjectMeta(id)
	if err != nil {
		t.Fatalf("go meta: %v", err)
	}
	if record.Content.Hex() != rustContent {
		t.Fatalf("manifest id differs:\n go  %s\n rust %s", record.Content.Hex(), rustContent)
	}
	if s.Head().Hex() != rustHead {
		t.Fatalf("published head differs:\n go  %s\n rust %s", s.Head().Hex(), rustHead)
	}
	goManifestBytes := manifestBytes(t, goDir, record.Content)
	rustManifestBytes := manifestBytes(t, rustDir, record.Content)
	if !bytes.Equal(goManifestBytes, rustManifestBytes) {
		t.Fatalf("overlay manifest bytes differ (%d vs %d bytes)", len(goManifestBytes), len(rustManifestBytes))
	}
	t.Logf("byte-equal overlay manifest=%s bytes=%d head=%s", record.Content.Hex(), len(goManifestBytes), s.Head().Hex())
	manifest := manifestOf(t, s, id)
	if manifest.Representation == nil || manifest.Representation.Kind != model.RepresentationOverlay {
		t.Fatalf("go result is not an overlay representation")
	}

	// The Rust verifier accepts the Go store and reads the same bytes.
	t.Logf("rust verify --full accepted the Go store after an identical history")
	s.Close()
	runRust(t, bin, "--store", goDir, "verify", "--full")
	reader := reopenOverlayReadOnly(t, goDir)
	defer reader.Close()
	got, err := reader.ReadObject(id)
	if err != nil {
		t.Fatalf("go read after rust verify: %v", err)
	}
	rustCat := runRustBytes(t, bin, append(overlayPolicyArgs(rustDir), "cat", "/same.bin")...)
	if !bytes.Equal(got, rustCat) {
		t.Fatalf("go bytes differ from rust bytes after the same history")
	}
}

func reopenOverlayReadOnly(t *testing.T, dir string) *store.Store {
	t.Helper()
	s, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("reopen read-only: %v", err)
	}
	return s
}

// Rust writes the base and one layer; Go must continue the exact chain, and a
// Rust verifier must accept the result.
func TestOverlayGoExtendsRustStore(t *testing.T) {
	bin := rustBinary(t)
	const chunk = 4096
	payloadDir := t.TempDir()
	base := overlayPattern(int(5*chunk), 22)
	basePath := filepath.Join(payloadDir, "base.bin")
	editPath := filepath.Join(payloadDir, "edit.bin")
	if err := os.WriteFile(basePath, base, 0o644); err != nil {
		t.Fatalf("write base: %v", err)
	}
	edit := []byte("rust-first-layer")
	if err := os.WriteFile(editPath, edit, 0o644); err != nil {
		t.Fatalf("write edit: %v", err)
	}

	rustDir := t.TempDir()
	rustInitOverlay(t, bin, rustDir)
	args := overlayPolicyArgs(rustDir)
	runRust(t, bin, append(args, "create", "/mixed.bin", "--file", basePath, "--seed", "overlay-mixed-seed")...)
	runRust(t, bin, append(args, "write", "/mixed.bin", "--offset", "0", "--file", editPath)...)

	expected := append([]byte(nil), base...)
	copy(expected, edit)

	s := openOverlayWritable(t, rustDir, chunk)
	id, err := s.ResolvePath("/mixed.bin")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	goEdit := []byte("go-second-layer")
	if _, err := s.WriteFile(id, chunk+7, goEdit); err != nil {
		t.Fatalf("go writes over rust overlay: %v", err)
	}
	copy(expected[chunk+7:], goEdit)
	if _, err := s.WriteFile(id, uint64(len(expected)), []byte("go-tail")); err != nil {
		t.Fatalf("go append over rust overlay: %v", err)
	}
	expected = append(expected, []byte("go-tail")...)
	got, err := s.ReadObject(id)
	if err != nil || !bytes.Equal(got, expected) {
		t.Fatalf("go read after extending rust store: %v", err)
	}
	s.Close()

	runRust(t, bin, "--store", rustDir, "verify", "--full")
	rustBytes := runRustBytes(t, bin, append(overlayPolicyArgs(rustDir), "cat", "/mixed.bin")...)
	if !bytes.Equal(rustBytes, expected) {
		t.Fatalf("rust read differs from the Go continuation")
	}
	rustStatValue := rustOverlayStatJSON(t, bin, rustDir, "/mixed.bin")
	if rustStatValue["content_hash"].(string) != manifestOfReadOnly(t, rustDir, "/mixed.bin").ContentHash.Hex() {
		t.Fatalf("rust content_hash disagrees with the on-disk manifest")
	}
}

func openOverlayWritable(t *testing.T, dir string, chunk uint64) *store.Store {
	t.Helper()
	s, err := store.OpenWithOptions(dir, store.ReadWrite, overlayOptions(chunk))
	if err != nil {
		t.Fatalf("open writable overlay store: %v", err)
	}
	return s
}

func manifestOfReadOnly(t *testing.T, dir, path string) model.Manifest {
	t.Helper()
	s := reopenOverlayReadOnly(t, dir)
	defer s.Close()
	id, err := s.ResolvePath(path)
	if err != nil {
		t.Fatalf("resolve %s: %v", path, err)
	}
	return manifestOf(t, s, id)
}

// Go compacts a Rust-written overlay and Rust must verify the canonical object.
func TestOverlayGoCompactsRustStore(t *testing.T) {
	bin := rustBinary(t)
	const chunk = 4096
	payloadDir := t.TempDir()
	base := overlayPattern(int(4*chunk)+19, 23)
	basePath := filepath.Join(payloadDir, "base.bin")
	editPath := filepath.Join(payloadDir, "edit.bin")
	edit := []byte("layer-for-compaction")
	if err := os.WriteFile(basePath, base, 0o644); err != nil {
		t.Fatalf("write base: %v", err)
	}
	if err := os.WriteFile(editPath, edit, 0o644); err != nil {
		t.Fatalf("write edit: %v", err)
	}
	expected := append([]byte(nil), base...)
	copy(expected[chunk+11:], edit)

	rustDir := t.TempDir()
	rustInitOverlay(t, bin, rustDir)
	args := overlayPolicyArgs(rustDir)
	runRust(t, bin, append(args, "create", "/compact2.bin", "--file", basePath, "--seed", "overlay-compact-seed")...)
	runRust(t, bin, append(args, "write", "/compact2.bin", "--offset", u64Text(chunk+11), "--file", editPath)...)
	before := manifestOfReadOnly(t, rustDir, "/compact2.bin")
	if before.Representation == nil || before.Representation.Kind != model.RepresentationOverlay {
		t.Fatalf("rust output is not an overlay")
	}

	s := openOverlayWritable(t, rustDir, chunk)
	id, err := s.ResolvePath("/compact2.bin")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	report, err := s.Compact(id)
	if err != nil {
		t.Fatalf("go compact of rust overlay: %v", err)
	}
	if report.ContentRoot != before.ContentHash {
		t.Fatalf("compaction changed the Rust content root")
	}
	s.Close()

	runRust(t, bin, "--store", rustDir, "verify", "--full")
	after := manifestOfReadOnly(t, rustDir, "/compact2.bin")
	if after.Representation != nil {
		t.Fatalf("compacted object still has a representation")
	}
	if after.ContentHash != before.ContentHash {
		t.Fatalf("rust content root changed across Go compaction")
	}
	rustBytes := runRustBytes(t, bin, append(overlayPolicyArgs(rustDir), "cat", "/compact2.bin")...)
	if !bytes.Equal(rustBytes, expected) {
		t.Fatalf("rust read after go compaction differs")
	}
}

// Rust compacts a Go-written overlay; Go must read the canonical object and
// reproduce the same content root.
func TestOverlayRustCompactsGoStore(t *testing.T) {
	bin := rustBinary(t)
	const chunk = 4096
	dir := t.TempDir()
	s := initOverlayStore(t, dir, overlayGoOptions(chunk))
	base := overlayPattern(int(3*chunk)+5, 24)
	id, err := s.CreateFileSeeded(model.RootID, []byte("go-compact.bin"), base, 0o644, 0, 0, nil, []byte("overlay-go-compact-seed"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	expected := append([]byte(nil), base...)
	edits := []struct {
		offset uint64
		data   []byte
	}{
		{13, []byte("one")},
		{chunk + 3, []byte("two")},
		{uint64(len(base)), []byte("three")},
	}
	for _, edit := range edits {
		if _, err := s.WriteFile(id, edit.offset, edit.data); err != nil {
			t.Fatalf("write: %v", err)
		}
		if int(edit.offset)+len(edit.data) > len(expected) {
			expected = append(expected, make([]byte, int(edit.offset)+len(edit.data)-len(expected))...)
		}
		copy(expected[edit.offset:], edit.data)
	}
	before := manifestOf(t, s, id)
	if before.Representation == nil || before.Representation.Kind != model.RepresentationOverlay {
		t.Fatalf("go output is not an overlay")
	}
	s.Close()

	runRust(t, bin, append(overlayPolicyArgs(dir), "compact", "/go-compact.bin")...)
	reader := reopenOverlayReadOnly(t, dir)
	defer reader.Close()
	after := manifestOf(t, reader, id)
	if after.Representation != nil {
		t.Fatalf("rust compact left a representation: %+v", after.Representation)
	}
	if after.ContentHash != before.ContentHash {
		t.Fatalf("content root changed across rust compaction")
	}
	got, err := reader.ReadObject(id)
	if err != nil || !bytes.Equal(got, expected) {
		t.Fatalf("go read after rust compaction: %v", err)
	}
}
