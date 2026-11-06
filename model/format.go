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

// RepresentationKind is the physical representation of a v2 manifest's
// logical bytes.
type RepresentationKind string

const (
	// RepresentationRaw means the concatenated chunk blobs are the content.
	RepresentationRaw RepresentationKind = "raw"
	// RepresentationCodec means a WFT1 frame decodes to the content.
	RepresentationCodec RepresentationKind = "codec"
	// RepresentationTensor means a WeftTensor frame (modes 10-14) decodes to
	// the content. It is additive within v2; raw and codec are unchanged.
	RepresentationTensor RepresentationKind = "tensor"
)

// Representation strategies carried by a v2 manifest. The strategy is
// informational and is cross-checked against the frame header mode on every
// decode.
const (
	StrategyRaw       = "raw"
	StrategyZstd      = "zstd"
	StrategyDelta     = "delta"
	StrategyReference = "reference"
	// Tensor strategies; the spelling is fixed by the tensor mode (WEFT-MODEL
	// §2.3.1).
	StrategyTensorSharded = "tensor-sharded"
	StrategyFloatTensor   = "float-tensor"
	StrategyWeightDelta   = "weight-delta"
	StrategyKvCache       = "kv-cache"
	StrategyActivation    = "activation"
	StrategySemanticDelta = "semantic-delta"
)

// Representation is the canonical WCB `representation` map of a
// `weft.manifest.v2` record (WEFT-MODEL.md §2.3.1).
//
// Frame is a manifest-domain blob id whose bytes are the complete WFT1 frame.
// Dependencies are content roots (manifest ids) in frame dependency-table
// order.
type Representation struct {
	Kind         RepresentationKind
	Frame        *Hash32
	Dependencies []Hash32
	Strategy     string
	DecodedSize  uint64
	// Tensor is non-nil exactly when Kind is RepresentationTensor.
	Tensor *TensorRepresentation
}

var representationKeys = []string{"kind", "frame", "dependencies", "strategy", "decoded_size"}

// ToWCB returns the canonical representation map.
func (r Representation) ToWCB() wcb.Value {
	if r.Kind == RepresentationTensor {
		return tensorRepresentationToWCB(r)
	}
	dependencies := make([]wcb.Value, 0, len(r.Dependencies))
	for _, dependency := range r.Dependencies {
		dependencies = append(dependencies, HashValue(dependency))
	}
	return Map(map[string]wcb.Value{
		"kind":         wcb.TextValue(string(r.Kind)),
		"frame":        OptHashValue(r.Frame),
		"dependencies": wcb.ArrayValue(dependencies),
		"strategy":     wcb.TextValue(r.Strategy),
		"decoded_size": wcb.U64Value(r.DecodedSize),
	})
}

// RepresentationFromWCB parses and validates a representation map.
func RepresentationFromWCB(v wcb.Value) (Representation, error) {
	var representation Representation
	m, err := AsMap(v)
	if err != nil {
		return representation, err
	}
	kindText, err := GetText(m, "kind")
	if err != nil {
		return representation, err
	}
	kind := RepresentationKind(kindText)
	if kind == RepresentationTensor {
		return tensorRepresentationFromWCB(m)
	}
	if kind != RepresentationRaw && kind != RepresentationCodec {
		return representation, werr.Newf(werr.Malformed, "unknown representation kind `%s`", kindText)
	}
	if err := CheckKeys(m, representationKeys...); err != nil {
		return representation, err
	}
	frame, err := GetOptHash(m, "frame")
	if err != nil {
		return representation, err
	}
	items, err := GetArray(m, "dependencies")
	if err != nil {
		return representation, err
	}
	dependencies := make([]Hash32, 0, len(items))
	for _, item := range items {
		if item.Kind != wcb.Bytes {
			return representation, werr.Newf(werr.Malformed, "representation dependency must be bytes32")
		}
		dependency, err := hashFromSlice(item.Bytes)
		if err != nil {
			return representation, err
		}
		dependencies = append(dependencies, dependency)
	}
	strategy, err := GetText(m, "strategy")
	if err != nil {
		return representation, err
	}
	decodedSize, err := GetU64(m, "decoded_size")
	if err != nil {
		return representation, err
	}
	switch kind {
	case RepresentationRaw:
		if frame != nil {
			return representation, werr.Newf(werr.Malformed, "raw representation must not name a frame")
		}
		if len(dependencies) != 0 {
			return representation, werr.Newf(werr.Malformed, "raw representation must not have dependencies")
		}
		if strategy != StrategyRaw {
			return representation, werr.Newf(werr.Malformed, "raw representation strategy must be `raw`")
		}
	case RepresentationCodec:
		if frame == nil || *frame == ZeroHash {
			return representation, werr.Newf(werr.Malformed, "codec representation requires a non-zero frame id")
		}
		switch strategy {
		case StrategyZstd:
			if len(dependencies) != 0 {
				return representation, werr.Newf(werr.Malformed, "zstd representation must not have dependencies")
			}
		case StrategyDelta, StrategyReference:
			if len(dependencies) != 1 {
				return representation, werr.Newf(werr.Malformed, "delta/reference representation requires exactly one dependency")
			}
		default:
			return representation, werr.Newf(werr.Malformed, "unknown codec strategy `%s`", strategy)
		}
	}
	return Representation{
		Kind: kind, Frame: frame, Dependencies: dependencies,
		Strategy: strategy, DecodedSize: decodedSize,
	}, nil
}

// Manifest is a file content manifest (WEFT-MODEL.md §2.3).
//
// Representation is nil for the frozen v1 schema and non-nil for the
// experimental v2 representation schema. A v1 manifest must never contain a
// representation key; a v2 manifest must always contain one.
//
// Identity selects the schema. The zero value is WholeFileV1, so every
// existing construction stays byte-identical to v1/v2. MerkleV3 writes
// `weft.manifest.v3` and stores the Merkle root in ContentHash (the wire field
// is `content_root`).
type Manifest struct {
	Size           uint64
	ChunkSize      uint64
	Chunks         []ChunkRef
	ContentHash    Hash32
	Representation *Representation
	Identity       ContentIdentity
}

// ContentIdentity selects the content root construction of a file manifest.
type ContentIdentity string

const (
	// ContentIdentityWholeFile is the frozen v1/v2 H("weft/chunk/v1", bytes)
	// identity. It is the zero value and the default.
	ContentIdentityWholeFile ContentIdentity = ""
	// ContentIdentityMerkleV1 is the `weft.manifest.v3` Merkle root. Its wire
	// spelling is `merkle-v1`.
	ContentIdentityMerkleV1 ContentIdentity = "merkle-v1"
)

var manifestKeys = []string{"schema", "size", "chunk_size", "chunks", "content_hash"}

var manifestKeysV2 = []string{"schema", "size", "chunk_size", "chunks", "content_hash", "representation"}

var manifestKeysV3 = []string{"schema", "size", "chunk_size", "chunks", "content_root", "content_identity"}

var manifestKeysV3Representation = []string{"schema", "size", "chunk_size", "chunks", "content_root", "content_identity", "representation"}

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
	if m.Identity == ContentIdentityMerkleV1 {
		fields := map[string]wcb.Value{
			"schema":           wcb.TextValue(ManifestSchemaV3),
			"size":             wcb.U64Value(m.Size),
			"chunk_size":       wcb.U64Value(m.ChunkSize),
			"chunks":           wcb.ArrayValue(chunks),
			"content_root":     HashValue(m.ContentHash),
			"content_identity": wcb.TextValue(string(ContentIdentityMerkleV1)),
		}
		if m.Representation != nil {
			fields["representation"] = m.Representation.ToWCB()
		}
		return Map(fields)
	}
	if m.Representation == nil {
		return Map(map[string]wcb.Value{
			"schema":       wcb.TextValue(ManifestSchema),
			"size":         wcb.U64Value(m.Size),
			"chunk_size":   wcb.U64Value(m.ChunkSize),
			"chunks":       wcb.ArrayValue(chunks),
			"content_hash": HashValue(m.ContentHash),
		})
	}
	return Map(map[string]wcb.Value{
		"schema":         wcb.TextValue(ManifestSchemaV2),
		"size":           wcb.U64Value(m.Size),
		"chunk_size":     wcb.U64Value(m.ChunkSize),
		"chunks":         wcb.ArrayValue(chunks),
		"content_hash":   HashValue(m.ContentHash),
		"representation": m.Representation.ToWCB(),
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
	schema, err := GetText(m, "schema")
	if err != nil {
		return Manifest{}, err
	}
	// The normative v1 spelling is `weft.manifest.v1`; the earlier
	// `weftfs.manifest.v1` spelling is accepted on read. The experimental v2
	// schema has exactly one spelling, `weft.manifest.v2`, and the Merkle v3
	// schema exactly one, `weft.manifest.v3`. Any other schema is
	// UnsupportedVersion, matching the Rust reader.
	identity := ContentIdentityWholeFile
	v2 := false
	switch schema {
	case ManifestSchema, LegacyManifest:
		if err := CheckKeys(m, manifestKeys...); err != nil {
			return Manifest{}, err
		}
	case ManifestSchemaV2:
		v2 = true
		if err := CheckKeys(m, manifestKeysV2...); err != nil {
			return Manifest{}, err
		}
	case ManifestSchemaV3:
		identity = ContentIdentityMerkleV1
		keys := manifestKeysV3
		if _, present := m["representation"]; present {
			keys = manifestKeysV3Representation
		}
		if err := CheckKeys(m, keys...); err != nil {
			return Manifest{}, err
		}
		name, err := GetText(m, "content_identity")
		if err != nil {
			return Manifest{}, err
		}
		if name != string(ContentIdentityMerkleV1) {
			return Manifest{}, werr.Newf(werr.Malformed, "unknown manifest content_identity `%s`", name)
		}
	default:
		return Manifest{}, werr.Newf(werr.Unsupported, "manifest schema `%s` is not a supported v1/v2/v3 schema", schema)
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
	var representation *Representation
	if v2 || identity == ContentIdentityMerkleV1 {
		if value, present := m["representation"]; present {
			parsed, err := RepresentationFromWCB(value)
			if err != nil {
				return Manifest{}, err
			}
			representation = &parsed
		} else if v2 {
			return Manifest{}, werr.Newf(werr.Malformed, "weft.manifest.v2 is missing its representation map")
		}
	}
	if identity == ContentIdentityMerkleV1 && representation != nil && representation.Kind != RepresentationRaw {
		return Manifest{}, werr.Newf(werr.Corrupt, "a Merkle v3 manifest may only carry a raw representation")
	}
	// A codec or tensor representation carries bytes only inside its frame and
	// lists no chunk references; raw (and v1) manifests list them.
	representationBacked := representation != nil &&
		(representation.Kind == RepresentationCodec || representation.Kind == RepresentationTensor)
	if !representationBacked {
		// Every non-final chunk must be full (checked below), so the chunk
		// count is fixed by size/chunk_size. Reject an over-bound declaration
		// before any per-chunk work happens.
		requiredChunks := size / chunkSize
		if size%chunkSize != 0 {
			requiredChunks++
		}
		if requiredChunks > MaxChunksPerFile {
			return Manifest{}, werr.Newf(werr.LimitExceeded, "manifest exceeds the %d-chunk bound", MaxChunksPerFile)
		}
	}
	items, err := GetArray(m, "chunks")
	if err != nil {
		return Manifest{}, err
	}
	if uint64(len(items)) > MaxChunksPerFile {
		return Manifest{}, werr.Newf(werr.LimitExceeded, "manifest exceeds the %d-chunk bound", MaxChunksPerFile)
	}
	if representationBacked && len(items) != 0 {
		return Manifest{}, werr.Newf(werr.Corrupt, "%s manifest must not list chunk references", representation.Kind)
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
	if !representationBacked {
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
	}
	var contentHash Hash32
	if identity == ContentIdentityMerkleV1 {
		declared, err := GetHash(m, "content_root")
		if err != nil {
			return Manifest{}, err
		}
		computed := MerkleRootChunks(chunks)
		if declared != computed {
			return Manifest{}, werr.Newf(werr.Corrupt, "merkle content_root does not match the manifest chunk hashes")
		}
		contentHash = declared
	} else {
		contentHash, err = GetHash(m, "content_hash")
		if err != nil {
			return Manifest{}, err
		}
		if size == 0 && contentHash != ContentHash(nil) {
			return Manifest{}, werr.Newf(werr.Corrupt, "empty manifest content hash mismatch")
		}
	}
	if representation != nil && representation.DecodedSize != size {
		return Manifest{}, werr.Newf(werr.Corrupt, "representation decoded_size %d differs from manifest size %d", representation.DecodedSize, size)
	}
	return Manifest{
		Size: size, ChunkSize: chunkSize, Chunks: chunks, ContentHash: contentHash,
		Representation: representation, Identity: identity,
	}, nil
}

func addChecked(a, b uint64) (uint64, bool) {
	if a > ^uint64(0)-b {
		return 0, false
	}
	return a + b, true
}
