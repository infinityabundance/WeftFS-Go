package store

// These tests pin the raised 1 TiB file bound and the mirrored chunk-count
// bound. They are internal because they build a manifest through the store's
// chunk writer (storeBlob) instead of allocating the whole file in memory.
// The on-disk format is unchanged: a manifest is a size, a chunk size, and
// chunk references, so these are exactly the objects the Rust store writes.

import (
	"bytes"
	"io"
	"math"
	"testing"

	"github.com/infinityabundance/WeftCodec-Go/hash"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

const (
	// 300 MiB is above the old 256 MiB bound and cheap enough to materialize
	// as 19 x 16 MiB chunks written one at a time.
	largeFileSize  uint64 = 300 * 1024 * 1024
	largeChunkSize uint64 = 16 * 1024 * 1024
)

// largePattern is the deterministic content of the test file.
func largePattern(offset uint64) byte { return byte((offset*31 + 7) % 251) }

func fillLargePattern(dst []byte, offset uint64) {
	for i := range dst {
		dst[i] = largePattern(offset + uint64(i))
	}
}

// patternReader streams largePattern for whole-file hashing without buffering.
type patternReader struct {
	offset uint64
	end    uint64
}

func (r *patternReader) Read(p []byte) (int, error) {
	if r.offset >= r.end {
		return 0, io.EOF
	}
	n := uint64(len(p))
	if n > r.end-r.offset {
		n = r.end - r.offset
	}
	for i := uint64(0); i < n; i++ {
		p[i] = largePattern(r.offset + i)
	}
	r.offset += n
	return int(n), nil
}

// TestManifestAboveLegacyBoundOpensAndReads builds a 300 MiB manifest through
// the streaming chunk writer (19 x 16 MiB chunks, one buffer reused), then
// opens it with ReadManifest and reads ranges exactly.
func TestManifestAboveLegacyBoundOpensAndReads(t *testing.T) {
	options := DefaultOptions()
	options.ChunkSize = largeChunkSize
	s, err := Init(t.TempDir(), options)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()

	size := largeFileSize
	chunks := make([]model.ChunkRef, 0, int(size/largeChunkSize)+1)
	buffer := make([]byte, largeChunkSize)
	for start := uint64(0); start < size; {
		length := size - start
		if length > largeChunkSize {
			length = largeChunkSize
		}
		chunk := buffer[:length]
		fillLargePattern(chunk, start)
		chunkID, err := s.storeBlob(BlobObject, model.DomainChunk, chunk)
		if err != nil {
			t.Fatalf("store chunk at %d: %v", start, err)
		}
		chunks = append(chunks, model.ChunkRef{Hash: chunkID, Len: length})
		start += length
	}
	if len(chunks) != 19 {
		t.Fatalf("chunk count = %d, want 19", len(chunks))
	}

	contentHash, err := hash.DomainReader(model.DomainChunk, &patternReader{offset: 0, end: size})
	if err != nil {
		t.Fatalf("hash content: %v", err)
	}
	manifest := model.Manifest{
		Size: size, ChunkSize: largeChunkSize, Chunks: chunks, ContentHash: contentHash,
	}
	encoded, err := manifest.Encode()
	if err != nil {
		t.Fatalf("encode manifest: %v", err)
	}
	manifestID, err := s.storeBlob(BlobManifest, model.DomainManifest, encoded)
	if err != nil {
		t.Fatalf("store manifest: %v", err)
	}

	opened, err := ReadManifest(s.Root(), manifestID)
	if err != nil {
		t.Fatalf("ReadManifest: %v", err)
	}
	if opened.Size != size {
		t.Fatalf("manifest size = %d, want %d", opened.Size, size)
	}
	if len(opened.Chunks) != len(chunks) {
		t.Fatalf("manifest chunks = %d, want %d", len(opened.Chunks), len(chunks))
	}

	ranges := []struct {
		name   string
		offset uint64
		length uint64
	}{
		{"crosses a chunk boundary", largeChunkSize - 1000, 100_000},
		{"inside one chunk", 5*largeChunkSize + 12345, 4096},
		{"short read at EOF", size - 4096, 65536},
	}
	for _, read := range ranges {
		got, err := ReadRange(s.Root(), opened, read.offset, read.length, false)
		if err != nil {
			t.Fatalf("%s: ReadRange: %v", read.name, err)
		}
		wantLen := read.length
		if read.offset+wantLen > size {
			wantLen = size - read.offset
		}
		want := make([]byte, wantLen)
		fillLargePattern(want, read.offset)
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: range bytes mismatch (%d bytes)", read.name, len(got))
		}
	}
}

// TestManifestChunkCountBound checks the mirrored MAX_CHUNKS_PER_FILE bound.
// A v1 manifest's chunk count is fixed by size/chunk_size (every non-final
// chunk must be full), so an over-bound count is rejected from the declared
// size before any chunk entry is materialized.
func TestManifestChunkCountBound(t *testing.T) {
	chunkSize := uint64(model.DefaultChunkSize)

	over := model.Manifest{
		Size: (model.MaxChunksPerFile + 1) * chunkSize,
		// Empty chunk list: the count bound must fire first.
		ChunkSize: chunkSize,
	}
	_, err := model.ManifestFromWCB(over.ToWCB())
	if werr.ClassOf(err) != werr.LimitExceeded {
		t.Fatalf("over-bound manifest = %v, want LimitExceeded", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("chunk bound")) {
		t.Fatalf("over-bound manifest error = %q, want the chunk bound", err)
	}

	// Exactly MaxChunksPerFile chunks is inside the bound; the manifest then
	// fails later schema validation (chunks are missing), not the count bound.
	atBound := model.Manifest{
		Size:      model.MaxChunksPerFile * chunkSize,
		ChunkSize: chunkSize,
	}
	_, err = model.ManifestFromWCB(atBound.ToWCB())
	if werr.ClassOf(err) != werr.Corrupt {
		t.Fatalf("at-bound manifest = %v, want Corrupt (count bound is inclusive)", err)
	}
}

// TestSizesThatDoNotFitIntAreRejected pins the conversion guard. On a 64-bit
// platform the guard cannot be reached through ReadRange because MaxFileBytes
// is far below maxInt; on a 32-bit platform it is the first line of defence.
func TestSizesThatDoNotFitIntAreRejected(t *testing.T) {
	if got, err := checkedSize(uint64(maxInt)); err != nil || got != maxInt {
		t.Fatalf("checkedSize(maxInt) = %d, %v; want %d, nil", got, err, maxInt)
	}
	for _, value := range []uint64{uint64(maxInt) + 1, math.MaxUint64} {
		if _, err := checkedSize(value); werr.ClassOf(err) != werr.LimitExceeded {
			t.Fatalf("checkedSize(%d) = %v, want LimitExceeded", value, err)
		} else if !bytes.Contains([]byte(err.Error()), []byte("does not fit int")) {
			t.Fatalf("checkedSize(%d) error = %q, want the int conversion limit", value, err)
		}
	}

	// A synthetic manifest with a huge declared size is rejected instead of
	// being truncated into an addressable length.
	root := t.TempDir()
	synthetic := model.Manifest{Size: math.MaxUint64, ChunkSize: model.DefaultChunkSize}
	if _, err := ReadRange(root, synthetic, 0, math.MaxUint64, false); werr.ClassOf(err) != werr.LimitExceeded {
		t.Fatalf("ReadRange(huge manifest) = %v, want LimitExceeded", err)
	}
}
