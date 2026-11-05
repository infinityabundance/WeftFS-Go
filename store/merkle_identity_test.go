package store_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

func merkleOptions(chunkSize uint64) store.Options {
	opts := fixedOptions()
	opts.ChunkSize = chunkSize
	opts.GCGraceSecs = 0
	opts.ContentIdentity = model.ContentIdentityMerkleV1
	return opts
}

func patternBytes(length int) []byte {
	out := make([]byte, length)
	for i := range out {
		out[i] = byte(i % 251)
	}
	return out
}

func largePattern(length int, chunk int) []byte {
	out := make([]byte, length)
	for start := 0; start < length; start += chunk {
		end := start + chunk
		if end > length {
			end = length
		}
		value := byte((start / chunk) % 251)
		for i := start; i < end; i++ {
			out[i] = value
		}
	}
	return out
}

func manifestFor(t *testing.T, dir string, id model.Hash32, s *store.Store) model.Manifest {
	t.Helper()
	record, err := s.ObjectMeta(id)
	if err != nil {
		t.Fatalf("object meta: %v", err)
	}
	manifest, err := store.ReadManifest(dir, record.Content)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	return manifest
}

func TestMerkleRootDeterministicAndChunkSizeDependent(t *testing.T) {
	data := patternBytes(5_000)
	dirA := t.TempDir()
	a, err := store.Init(dirA, merkleOptions(1024))
	if err != nil {
		t.Fatalf("init a: %v", err)
	}
	root, _ := a.ResolvePath("/")
	idA, err := a.CreateFileSeeded(root, []byte("a.bin"), data, 0o644, 0, 0, nil, []byte("seed-a"))
	if err != nil {
		t.Fatalf("create a: %v", err)
	}
	manifestA := manifestFor(t, dirA, idA, a)

	dirB := t.TempDir()
	b, err := store.Init(dirB, merkleOptions(1024))
	if err != nil {
		t.Fatalf("init b: %v", err)
	}
	rootB, _ := b.ResolvePath("/")
	idB, err := b.CreateFileSeeded(rootB, []byte("b.bin"), data, 0o644, 0, 0, nil, []byte("seed-b"))
	if err != nil {
		t.Fatalf("create b: %v", err)
	}
	manifestB := manifestFor(t, dirB, idB, b)

	if manifestA.Identity != model.ContentIdentityMerkleV1 {
		t.Fatalf("identity = %q", manifestA.Identity)
	}
	if manifestA.ContentHash != manifestB.ContentHash {
		t.Fatalf("same bytes/chunk size produced different roots: %s vs %s", manifestA.ContentHash.Hex(), manifestB.ContentHash.Hex())
	}
	if got := model.MerkleRootChunks(manifestA.Chunks); got != manifestA.ContentHash {
		t.Fatalf("root = %s, recomputed %s", manifestA.ContentHash.Hex(), got.Hex())
	}
	if manifestA.ContentHash == model.ContentHash(data) {
		t.Fatal("merkle root must not equal the whole-file ContentId")
	}

	// The manifest must be a canonical v3 record with content_root and
	// content_identity, not content_hash.
	value, err := model.DecodeWCB(mustEncode(t, manifestA))
	if err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	m, err := model.AsMap(value)
	if err != nil {
		t.Fatalf("as map: %v", err)
	}
	if _, ok := m["content_root"]; !ok {
		t.Fatal("v3 manifest has no content_root")
	}
	if _, ok := m["content_hash"]; ok {
		t.Fatal("v3 manifest must not carry content_hash")
	}
	identityText, err := model.GetText(m, "content_identity")
	if err != nil || identityText != "merkle-v1" {
		t.Fatalf("content_identity = %q, %v", identityText, err)
	}

	// Chunk size is part of the manifest, so changing it changes the root.
	dirC := t.TempDir()
	c, err := store.Init(dirC, merkleOptions(512))
	if err != nil {
		t.Fatalf("init c: %v", err)
	}
	rootC, _ := c.ResolvePath("/")
	idC, err := c.CreateFileSeeded(rootC, []byte("c.bin"), data, 0o644, 0, 0, nil, []byte("seed-c"))
	if err != nil {
		t.Fatalf("create c: %v", err)
	}
	if manifestC := manifestFor(t, dirC, idC, c); manifestC.ContentHash == manifestA.ContentHash {
		t.Fatal("different chunk size must change the root")
	}

	// The default whole-file identity is untouched.
	dirRaw := t.TempDir()
	raw, err := store.Init(dirRaw, fixedOptions())
	if err != nil {
		t.Fatalf("init raw: %v", err)
	}
	rootRaw, _ := raw.ResolvePath("/")
	idRaw, err := raw.CreateFileSeeded(rootRaw, []byte("raw.bin"), data, 0o644, 0, 0, nil, []byte("seed-raw"))
	if err != nil {
		t.Fatalf("create raw: %v", err)
	}
	manifestRaw := manifestFor(t, dirRaw, idRaw, raw)
	if manifestRaw.Identity != model.ContentIdentityWholeFile {
		t.Fatalf("default identity = %q", manifestRaw.Identity)
	}
	if manifestRaw.ContentHash != model.ContentHash(data) {
		t.Fatal("default whole-file ContentId changed")
	}
}

func mustEncode(t *testing.T, manifest model.Manifest) []byte {
	t.Helper()
	b, err := manifest.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return b
}

func TestMerkleEdgeSizes(t *testing.T) {
	cases := []struct {
		length int
		chunk  uint64
		chunks int
	}{
		{0, 16, 0},
		{1, 16, 1},
		{15, 16, 1},
		{16, 16, 1},
		{17, 16, 2},
		{64, 16, 4},
		{65, 16, 5},
	}
	for _, tc := range cases {
		dir := t.TempDir()
		s, err := store.Init(dir, merkleOptions(tc.chunk))
		if err != nil {
			t.Fatalf("init: %v", err)
		}
		root, _ := s.ResolvePath("/")
		data := patternBytes(tc.length)
		id, err := s.CreateFileSeeded(root, []byte("f"), data, 0o644, 0, 0, nil, []byte("edge"))
		if err != nil {
			t.Fatalf("len %d create: %v", tc.length, err)
		}
		manifest := manifestFor(t, dir, id, s)
		if len(manifest.Chunks) != tc.chunks {
			t.Fatalf("len %d chunks = %d, want %d", tc.length, len(manifest.Chunks), tc.chunks)
		}
		if model.MerkleRootChunks(manifest.Chunks) != manifest.ContentHash {
			t.Fatalf("len %d root mismatch", tc.length)
		}
		if tc.length == 0 && manifest.ContentHash != model.MerkleEmptyRoot() {
			t.Fatalf("empty root = %s", manifest.ContentHash.Hex())
		}
		got, err := s.ReadObject(id)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("len %d read: %v", tc.length, err)
		}
		report, err := s.Verify(true)
		if err != nil || !report.OK {
			t.Fatalf("len %d verify: %v %+v", tc.length, err, report)
		}
	}
}

func TestMerkle128MiBOverwriteDoesNotReadWholeFile(t *testing.T) {
	const size = 128 * 1024 * 1024
	const chunk = 64 * 1024
	dir := t.TempDir()
	s, err := store.Init(dir, merkleOptions(chunk))
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	root, _ := s.ResolvePath("/")
	data := largePattern(size, chunk)
	id, err := s.CreateFileSeeded(root, []byte("large.bin"), data, 0o644, 0, 0, nil, []byte("large"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	before := manifestFor(t, dir, id, s)
	if len(before.Chunks) != size/chunk {
		t.Fatalf("chunks = %d", len(before.Chunks))
	}

	offset := uint64(33_000_001)
	payload := bytes.Repeat([]byte{0xA5}, 4*1024)
	s.ResetWriteChunkReads()
	if _, err := s.WriteFile(id, offset, payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if reads := s.WriteChunkReads(); reads > 2 {
		t.Fatalf("4 KiB overwrite read %d chunk blobs of a %d-chunk file", reads, len(before.Chunks))
	}

	after := manifestFor(t, dir, id, s)
	if after.Identity != model.ContentIdentityMerkleV1 {
		t.Fatalf("identity after write = %q", after.Identity)
	}
	if after.ContentHash == before.ContentHash {
		t.Fatal("root did not change")
	}
	if model.MerkleRootChunks(after.Chunks) != after.ContentHash {
		t.Fatal("rewritten root is inconsistent")
	}
	first := int(offset / chunk)
	last := int((offset + uint64(len(payload)) - 1) / chunk)
	for index := range before.Chunks {
		if index < first || index > last {
			if before.Chunks[index] != after.Chunks[index] {
				t.Fatalf("untouched chunk %d changed", index)
			}
		}
	}
	got, err := s.ReadRange(id, offset, uint64(len(payload)))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("range read: %v", err)
	}
	record, _ := s.ObjectMeta(id)
	report, err := s.VerifyContentRegion(record.Content, offset, uint64(len(payload)))
	if err != nil {
		t.Fatalf("verify region: %v", err)
	}
	if report.ChunksVerified != last-first+1 || report.ContentRoot != after.ContentHash {
		t.Fatalf("region report = %+v", report)
	}
	full, err := s.Verify(true)
	if err != nil || !full.OK {
		t.Fatalf("verify: %v %+v", err, full)
	}
}

func TestMerkleTamperedChunkNamesIndex(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, merkleOptions(16))
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	root, _ := s.ResolvePath("/")
	id, err := s.CreateFileSeeded(root, []byte("t.bin"), patternBytes(40), 0o644, 0, 0, nil, []byte("tamper"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	manifest := manifestFor(t, dir, id, s)
	path := store.ObjectPath(dir, manifest.Chunks[1].Hash)
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read blob: %v", err)
	}
	blob[3] ^= 0x01
	if err := os.WriteFile(path, blob, 0o644); err != nil {
		t.Fatalf("write blob: %v", err)
	}

	if _, err := s.ReadRange(id, 16, 4); err == nil || !contains(err.Error(), "chunk 1") {
		t.Fatalf("range read must name chunk 1: %v", err)
	}
	record, _ := s.ObjectMeta(id)
	if _, err := s.VerifyContentRegion(record.Content, 16, 4); err == nil || !contains(err.Error(), "chunk 1") {
		t.Fatalf("verify region must name chunk 1: %v", err)
	}
	report, err := s.Verify(true)
	if err != nil || report.OK {
		t.Fatalf("verify should fail: %v %+v", err, report)
	}
	found := false
	for _, problem := range report.Problems {
		if contains(problem.Detail, "chunk 1") {
			found = true
		}
	}
	if !found {
		t.Fatalf("verify problems do not name chunk 1: %+v", report.Problems)
	}
}

func TestMerkleManifestRootMismatchAndUnknownSchema(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, merkleOptions(16))
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	root, _ := s.ResolvePath("/")
	id, err := s.CreateFileSeeded(root, []byte("m.bin"), patternBytes(40), 0o644, 0, 0, nil, []byte("root"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	manifest := manifestFor(t, dir, id, s)

	corrupted := manifest
	corrupted.Chunks = append([]model.ChunkRef(nil), manifest.Chunks...)
	corrupted.Chunks[0].Hash = model.ContentHash([]byte("not-the-chunk"))
	// Keep the declared root: the chunk table no longer folds to it.
	if _, err := model.ManifestFromWCB(corrupted.ToWCB()); werr.ClassOf(err) != werr.Corrupt {
		t.Fatalf("root mismatch = %v, want Corrupt", err)
	}

	value, err := model.DecodeWCB(mustEncode(t, manifest))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	m, _ := model.AsMap(value)
	m["schema"] = wcb.TextValue("weft.manifest.v9")
	if _, err := model.ManifestFromWCB(model.Map(m)); werr.ClassOf(err) != werr.Unsupported {
		t.Fatalf("unknown schema = %v, want UnsupportedVersion", err)
	}
}

func TestMerkleReopenGCVerify(t *testing.T) {
	dir := t.TempDir()
	var id model.Hash32
	data := patternBytes(1_000)
	func() {
		s, err := store.Init(dir, merkleOptions(256))
		if err != nil {
			t.Fatalf("init: %v", err)
		}
		defer s.Close()
		root, _ := s.ResolvePath("/")
		id, err = s.CreateFileSeeded(root, []byte("keep.bin"), data, 0o644, 0, 0, nil, []byte("reopen"))
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		report, err := s.Verify(true)
		if err != nil || !report.OK {
			t.Fatalf("verify: %v %+v", err, report)
		}
	}()

	// Reopen under the default identity: a v3 file must stay v3.
	opts := fixedOptions()
	opts.ChunkSize = 256
	s, err := store.OpenWithOptions(dir, store.ReadWrite, opts)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s.Close()
	got, err := s.ReadObject(id)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("read after reopen: %v", err)
	}
	manifest := manifestFor(t, dir, id, s)
	if manifest.Identity != model.ContentIdentityMerkleV1 {
		t.Fatalf("reopened identity = %q", manifest.Identity)
	}
	gc, err := s.GC(true)
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if len(gc.Deleted) != 0 {
		t.Fatalf("gc deleted reachable files: %+v", gc.Deleted)
	}
	if _, err := s.WriteFile(id, 0, []byte("XY")); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	rewritten := manifestFor(t, dir, id, s)
	if rewritten.Identity != model.ContentIdentityMerkleV1 {
		t.Fatalf("rewrite downgraded identity to %q", rewritten.Identity)
	}
	expected := append([]byte(nil), data...)
	copy(expected[0:2], []byte("XY"))
	got, err = s.ReadObject(id)
	if err != nil || !bytes.Equal(got, expected) {
		t.Fatalf("rewritten read: %v", err)
	}
	if model.MerkleRootChunks(rewritten.Chunks) != rewritten.ContentHash {
		t.Fatal("rewritten root is inconsistent")
	}
	report, err := s.Verify(true)
	if err != nil || !report.OK {
		t.Fatalf("final verify: %v %+v", err, report)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || bytes.Contains([]byte(haystack), []byte(needle))
}
