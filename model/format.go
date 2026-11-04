package model

import (
	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// Commit is a commit record (WEFT-MODEL.md §2.2).
type Commit struct {
	Generation  uint64
	Parent      *Hash32
	TimestampNS int64
	Ops         []Op
	Checkpoint  *Hash32
}

var commitKeys = []string{"schema", "generation", "parent", "timestamp_ns", "ops", "checkpoint"}

// ToWCB returns the canonical commit map.
func (c Commit) ToWCB() wcb.Value {
	ops := make([]wcb.Value, 0, len(c.Ops))
	for _, op := range c.Ops {
		ops = append(ops, op.ToWCB())
	}
	return Map(map[string]wcb.Value{
		"schema":       wcb.TextValue(CommitSchema),
		"generation":   wcb.U64Value(c.Generation),
		"parent":       OptHashValue(c.Parent),
		"timestamp_ns": wcb.TimestampValue(c.TimestampNS),
		"ops":          wcb.ArrayValue(ops),
		"checkpoint":   OptHashValue(c.Checkpoint),
	})
}

// Encode returns canonical WCB bytes of the commit record.
func (c Commit) Encode() ([]byte, error) { return EncodeWCB(c.ToWCB()) }

// ID returns H("weft/store/commit/v1", WCB(commit)).
func (c Commit) ID() (Hash32, error) {
	b, err := c.Encode()
	if err != nil {
		return Hash32{}, err
	}
	return CommitIDBytes(b), nil
}

// CommitFromWCB parses a commit record.
func CommitFromWCB(v wcb.Value) (Commit, error) {
	m, err := AsMap(v)
	if err != nil {
		return Commit{}, err
	}
	if err := CheckKeys(m, commitKeys...); err != nil {
		return Commit{}, err
	}
	schema, err := GetText(m, "schema")
	if err != nil {
		return Commit{}, err
	}
	if schema != CommitSchema {
		return Commit{}, werr.Newf(werr.UnknownSchema, "commit schema `%s` is not `%s`", schema, CommitSchema)
	}
	generation, err := GetU64(m, "generation")
	if err != nil {
		return Commit{}, err
	}
	parent, err := GetOptHash(m, "parent")
	if err != nil {
		return Commit{}, err
	}
	timestamp, err := GetTimestamp(m, "timestamp_ns")
	if err != nil {
		return Commit{}, err
	}
	opValues, err := GetArray(m, "ops")
	if err != nil {
		return Commit{}, err
	}
	ops := make([]Op, 0, len(opValues))
	for _, item := range opValues {
		op, err := OpFromWCB(item)
		if err != nil {
			return Commit{}, err
		}
		ops = append(ops, op)
	}
	checkpoint, err := GetOptHash(m, "checkpoint")
	if err != nil {
		return Commit{}, err
	}
	return Commit{
		Generation: generation, Parent: parent, TimestampNS: timestamp,
		Ops: ops, Checkpoint: checkpoint,
	}, nil
}

// ChunkRef names one chunk of a file.
type ChunkRef struct {
	Hash Hash32
	Len  uint64
}

// Manifest is a file content manifest (WEFT-MODEL.md §2.3).
type Manifest struct {
	Size        uint64
	ChunkSize   uint64
	Chunks      []ChunkRef
	ContentHash Hash32
}

var manifestKeys = []string{"schema", "size", "chunk_size", "chunks", "content_hash"}

// MaxChunksPerFile is the maximum number of chunk references in one manifest
// (16 Mi, i.e. exactly the 1 TiB file bound at the default 64 KiB chunk size).
// It mirrors the Rust store's MAX_CHUNKS_PER_FILE. A smaller configured
// chunk_size reaches this resource limit first and fails with LimitExceeded on
// write; it bounds the in-memory and encoded manifest rather than silently
// growing with file size. Reading validates it too, so a manifest over the
// bound is rejected instead of materialized.
const MaxChunksPerFile uint64 = 16_777_216

// ToWCB returns the canonical manifest map.
func (m Manifest) ToWCB() wcb.Value {
	chunks := make([]wcb.Value, 0, len(m.Chunks))
	for _, chunk := range m.Chunks {
		chunks = append(chunks, Map(map[string]wcb.Value{
			"hash": HashValue(chunk.Hash),
			"len":  wcb.U64Value(chunk.Len),
		}))
	}
	return Map(map[string]wcb.Value{
		"schema":       wcb.TextValue(ManifestSchema),
		"size":         wcb.U64Value(m.Size),
		"chunk_size":   wcb.U64Value(m.ChunkSize),
		"chunks":       wcb.ArrayValue(chunks),
		"content_hash": HashValue(m.ContentHash),
	})
}

// Encode returns canonical WCB bytes.
func (m Manifest) Encode() ([]byte, error) { return EncodeWCB(m.ToWCB()) }

// ID returns H("weft/manifest/v1", WCB(manifest)).
func (m Manifest) ID() (Hash32, error) {
	b, err := m.Encode()
	if err != nil {
		return Hash32{}, err
	}
	return ManifestID(b), nil
}

// ManifestFromWCB parses and validates a file manifest.
func ManifestFromWCB(v wcb.Value) (Manifest, error) {
	m, err := AsMap(v)
	if err != nil {
		return Manifest{}, err
	}
	if err := CheckKeys(m, manifestKeys...); err != nil {
		return Manifest{}, err
	}
	schema, err := GetText(m, "schema")
	if err != nil {
		return Manifest{}, err
	}
	// The normative spelling is `weft.manifest.v1`; the earlier
	// `weftfs.manifest.v1` spelling is accepted on read for compatibility with
	// early notes, exactly as the Rust reader does.
	if schema != ManifestSchema && schema != LegacyManifest {
		return Manifest{}, werr.Newf(werr.UnknownSchema, "manifest schema `%s` is not `%s`", schema, ManifestSchema)
	}
	size, err := GetU64(m, "size")
	if err != nil {
		return Manifest{}, err
	}
	chunkSize, err := GetU64(m, "chunk_size")
	if err != nil {
		return Manifest{}, err
	}
	if chunkSize == 0 || chunkSize > MaxChunkSize {
		return Manifest{}, werr.Newf(werr.Malformed, "manifest chunk_size is out of range")
	}
	// Every non-final chunk must be full (checked below), so the chunk count is
	// fixed by size/chunk_size. Reject an over-bound declaration before any
	// per-chunk work happens.
	requiredChunks := size / chunkSize
	if size%chunkSize != 0 {
		requiredChunks++
	}
	if requiredChunks > MaxChunksPerFile {
		return Manifest{}, werr.Newf(werr.LimitExceeded, "manifest exceeds the %d-chunk bound", MaxChunksPerFile)
	}
	items, err := GetArray(m, "chunks")
	if err != nil {
		return Manifest{}, err
	}
	if uint64(len(items)) > MaxChunksPerFile {
		return Manifest{}, werr.Newf(werr.LimitExceeded, "manifest exceeds the %d-chunk bound", MaxChunksPerFile)
	}
	chunks := make([]ChunkRef, 0, len(items))
	var total uint64
	for _, item := range items {
		cm, err := AsMap(item)
		if err != nil {
			return Manifest{}, err
		}
		if err := CheckKeys(cm, "hash", "len"); err != nil {
			return Manifest{}, err
		}
		length, err := GetU64(cm, "len")
		if err != nil {
			return Manifest{}, err
		}
		if length == 0 {
			return Manifest{}, werr.Newf(werr.Corrupt, "manifest chunk has zero length")
		}
		if length > chunkSize {
			return Manifest{}, werr.Newf(werr.Corrupt, "manifest chunk exceeds chunk_size")
		}
		sum, ok := addChecked(total, length)
		if !ok {
			return Manifest{}, werr.Newf(werr.Corrupt, "manifest size overflows")
		}
		total = sum
		hash, err := GetHash(cm, "hash")
		if err != nil {
			return Manifest{}, err
		}
		chunks = append(chunks, ChunkRef{Hash: hash, Len: length})
	}
	if total != size {
		return Manifest{}, werr.Newf(werr.Corrupt, "manifest chunk lengths sum to %d, declared size is %d", total, size)
	}
	if size == 0 && len(chunks) != 0 {
		return Manifest{}, werr.Newf(werr.Corrupt, "empty file manifest must have no chunks")
	}
	if size > 0 && len(chunks) == 0 {
		return Manifest{}, werr.Newf(werr.Corrupt, "non-empty file manifest has no chunks")
	}
	for index, chunk := range chunks {
		isLast := index+1 == len(chunks)
		if !isLast && chunk.Len != chunkSize {
			return Manifest{}, werr.Newf(werr.Corrupt, "non-final chunk is not full")
		}
	}
	contentHash, err := GetHash(m, "content_hash")
	if err != nil {
		return Manifest{}, err
	}
	if size == 0 && contentHash != ContentHash(nil) {
		return Manifest{}, werr.Newf(werr.Corrupt, "empty manifest content hash mismatch")
	}
	return Manifest{Size: size, ChunkSize: chunkSize, Chunks: chunks, ContentHash: contentHash}, nil
}

func addChecked(a, b uint64) (uint64, bool) {
	if a > ^uint64(0)-b {
		return 0, false
	}
	return a + b, true
}
