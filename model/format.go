package model

import (
	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// IndexAttestation is the commit's record of the selector index it published.
//
// The segment's own digest only proves the bytes did not change by accident.
// This record proves completeness: `CandidatesRoot` is the digest of the full
// candidate sets an honest index must contain, so a forger who removes an
// entry, re-sorts, fixes the counts, and recomputes the self-digest still
// cannot match it. `StateRoot` binds the attestation to this commit's own
// authoritative fields.
type IndexAttestation struct {
	ObjectCount    uint64
	RelationCount  uint64
	EntryCount     uint64
	StateRoot      Hash32
	CandidatesRoot Hash32
}

var attestationKeys = []string{
	"candidates_root", "entry_count", "object_count", "relation_count", "state_root",
}

// ToWCB returns the canonical attestation map.
func (a IndexAttestation) ToWCB() wcb.Value {
	return Map(map[string]wcb.Value{
		"object_count":    wcb.U64Value(a.ObjectCount),
		"relation_count":  wcb.U64Value(a.RelationCount),
		"entry_count":     wcb.U64Value(a.EntryCount),
		"state_root":      HashValue(a.StateRoot),
		"candidates_root": HashValue(a.CandidatesRoot),
	})
}

// AttestationFromWCB parses an attestation map.
func AttestationFromWCB(v wcb.Value) (IndexAttestation, error) {
	m, err := AsMap(v)
	if err != nil {
		return IndexAttestation{}, err
	}
	if err := CheckKeys(m, attestationKeys...); err != nil {
		return IndexAttestation{}, err
	}
	objectCount, err := GetU64(m, "object_count")
	if err != nil {
		return IndexAttestation{}, err
	}
	relationCount, err := GetU64(m, "relation_count")
	if err != nil {
		return IndexAttestation{}, err
	}
	entryCount, err := GetU64(m, "entry_count")
	if err != nil {
		return IndexAttestation{}, err
	}
	stateRoot, err := GetHash(m, "state_root")
	if err != nil {
		return IndexAttestation{}, err
	}
	candidatesRoot, err := GetHash(m, "candidates_root")
	if err != nil {
		return IndexAttestation{}, err
	}
	return IndexAttestation{
		ObjectCount: objectCount, RelationCount: relationCount, EntryCount: entryCount,
		StateRoot: stateRoot, CandidatesRoot: candidatesRoot,
	}, nil
}

// Commit is a commit record (WEFT-MODEL.md §2.2).
type Commit struct {
	Generation       uint64
	Parent           *Hash32
	TimestampNS      int64
	Ops              []Op
	Checkpoint       *Hash32
	IndexAttestation *IndexAttestation
}

var commitKeysV1 = []string{"schema", "generation", "parent", "timestamp_ns", "ops", "checkpoint"}
var commitKeysV2 = []string{"schema", "generation", "parent", "timestamp_ns", "ops", "checkpoint", "index_attestation"}

func (c Commit) fields() map[string]wcb.Value {
	ops := make([]wcb.Value, 0, len(c.Ops))
	for _, op := range c.Ops {
		ops = append(ops, op.ToWCB())
	}
	return map[string]wcb.Value{
		"generation":   wcb.U64Value(c.Generation),
		"parent":       OptHashValue(c.Parent),
		"timestamp_ns": wcb.TimestampValue(c.TimestampNS),
		"ops":          wcb.ArrayValue(ops),
		"checkpoint":   OptHashValue(c.Checkpoint),
	}
}

// FieldsWCB returns the canonical v1-shaped bytes of the six authoritative
// fields. It is the `state_root` preimage and is independent of whether this
// record carries an attestation.
func (c Commit) FieldsWCB() ([]byte, error) {
	m := c.fields()
	m["schema"] = wcb.TextValue(CommitSchema)
	return EncodeWCB(Map(m))
}

// ToWCB returns the canonical commit map. A commit with an attestation is
// `weftfs.commit.v2`; one without is the frozen `weftfs.commit.v1`.
func (c Commit) ToWCB() wcb.Value {
	m := c.fields()
	if c.IndexAttestation != nil {
		m["schema"] = wcb.TextValue(CommitSchemaV2)
		m["index_attestation"] = c.IndexAttestation.ToWCB()
	} else {
		m["schema"] = wcb.TextValue(CommitSchema)
	}
	return Map(m)
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
	schema, err := GetText(m, "schema")
	if err != nil {
		return Commit{}, err
	}
	var attestation *IndexAttestation
	switch schema {
	case CommitSchema:
		if err := CheckKeys(m, commitKeysV1...); err != nil {
			return Commit{}, err
		}
	case CommitSchemaV2:
		if err := CheckKeys(m, commitKeysV2...); err != nil {
			return Commit{}, err
		}
		if raw, ok := m["index_attestation"]; ok {
			if raw.Kind != wcb.Null {
				parsed, err := AttestationFromWCB(raw)
				if err != nil {
					return Commit{}, err
				}
				attestation = &parsed
			}
		}
	default:
		return Commit{}, werr.Newf(werr.UnknownSchema, "commit schema `%s` is neither `%s` nor `%s`", schema, CommitSchema, CommitSchemaV2)
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
		Ops: ops, Checkpoint: checkpoint, IndexAttestation: attestation,
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
	// RepresentationOverlay means a `weft.manifest.v4` immutable-overlay
	// representation: an immutable base manifest plus ordered extents. It has
	// no top-level chunk table; the canonical table is derived from the chain.
	RepresentationOverlay RepresentationKind = "overlay"
)

// Representation strategies carried by a v2 manifest. The strategy is
// informational and is cross-checked against the frame header mode on every
// decode.
const (
	StrategyRaw       = "raw"
	StrategyZstd      = "zstd"
	StrategyDelta     = "delta"
	StrategyReference = "reference"
	// StrategyZstdPatch is a mode-4 DICTIONARY frame whose raw-content
	// dictionary is the whole declared base (the `zstd --patch-from` analogue).
	// It carries exactly one dependency.
	StrategyZstdPatch = "zstd-patch"
	// Tensor strategies; the spelling is fixed by the tensor mode (WEFT-MODEL
	// §2.3.1).
	StrategyTensorSharded = "tensor-sharded"
	StrategyFloatTensor   = "float-tensor"
	StrategyWeightDelta   = "weight-delta"
	StrategySparseDelta   = "sparse-delta"
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
	// Overlay is non-nil exactly when Kind is RepresentationOverlay.
	Overlay *OverlayRepresentation
}

// OverlayExtent is one immutable extent of a `weft.manifest.v4` overlay.
type OverlayExtent struct {
	Offset uint64
	Length uint64
	Chunks []ChunkRef
}

// OverlayRepresentation is the `kind:"overlay"` representation payload.
type OverlayRepresentation struct {
	Base            Hash32
	BaseContentRoot Hash32
	BaseSize        uint64
	Depth           uint64
	OverlayBytes    uint64
	Extents         []OverlayExtent
}

var overlayRepresentationKeys = []string{
	"kind", "base", "base_content_root", "base_size", "depth",
	"overlay_bytes", "decoded_size", "extents", "strategy",
}

func chunkRefToWCB(chunk ChunkRef) wcb.Value {
	return Map(map[string]wcb.Value{
		"hash": HashValue(chunk.Hash),
		"len":  wcb.U64Value(chunk.Len),
	})
}

func overlayRepresentationToWCB(r Representation) wcb.Value {
	overlay := OverlayRepresentation{}
	if r.Overlay != nil {
		overlay = *r.Overlay
	}
	extents := make([]wcb.Value, 0, len(overlay.Extents))
	for _, extent := range overlay.Extents {
		chunks := make([]wcb.Value, 0, len(extent.Chunks))
		for _, chunk := range extent.Chunks {
			chunks = append(chunks, chunkRefToWCB(chunk))
		}
		extents = append(extents, Map(map[string]wcb.Value{
			"offset": wcb.U64Value(extent.Offset),
			"length": wcb.U64Value(extent.Length),
			"chunks": wcb.ArrayValue(chunks),
		}))
	}
	return Map(map[string]wcb.Value{
		"kind":              wcb.TextValue(string(RepresentationOverlay)),
		"base":              HashValue(overlay.Base),
		"base_content_root": HashValue(overlay.BaseContentRoot),
		"base_size":         wcb.U64Value(overlay.BaseSize),
		"depth":             wcb.U64Value(overlay.Depth),
		"overlay_bytes":     wcb.U64Value(overlay.OverlayBytes),
		"decoded_size":      wcb.U64Value(r.DecodedSize),
		"extents":           wcb.ArrayValue(extents),
		"strategy":          wcb.TextValue(r.Strategy),
	})
}

func overlayRepresentationFromWCB(m map[string]wcb.Value) (Representation, error) {
	var representation Representation
	if err := CheckKeys(m, overlayRepresentationKeys...); err != nil {
		return representation, err
	}
	base, err := GetHash(m, "base")
	if err != nil {
		return representation, err
	}
	if base == ZeroHash {
		return representation, werr.Newf(werr.Malformed, "overlay base must be a non-zero manifest id")
	}
	baseContentRoot, err := GetHash(m, "base_content_root")
	if err != nil {
		return representation, err
	}
	if baseContentRoot == ZeroHash {
		return representation, werr.Newf(werr.Malformed, "overlay base_content_root must be non-zero")
	}
	baseSize, err := GetU64(m, "base_size")
	if err != nil {
		return representation, err
	}
	depth, err := GetU64(m, "depth")
	if err != nil {
		return representation, err
	}
	if depth == 0 {
		return representation, werr.Newf(werr.Malformed, "overlay depth must be positive")
	}
	if depth > MaxOverlayChainDepth {
		return representation, werr.Newf(werr.LimitExceeded,
			"overlay depth %d exceeds the hard bound %d", depth, MaxOverlayChainDepth)
	}
	overlayBytes, err := GetU64(m, "overlay_bytes")
	if err != nil {
		return representation, err
	}
	if overlayBytes == 0 {
		return representation, werr.Newf(werr.Malformed, "overlay_bytes must be positive")
	}
	decodedSize, err := GetU64(m, "decoded_size")
	if err != nil {
		return representation, err
	}
	strategy, err := GetText(m, "strategy")
	if err != nil {
		return representation, err
	}
	if strategy != "overlay" {
		return representation, werr.Newf(werr.Malformed, "overlay representation strategy must be `overlay`")
	}
	items, err := GetArray(m, "extents")
	if err != nil {
		return representation, err
	}
	if len(items) == 0 {
		return representation, werr.Newf(werr.Malformed, "overlay representation has no extents")
	}
	if len(items) > MaxOverlayExtentsPerManifest {
		return representation, werr.Newf(werr.LimitExceeded,
			"overlay manifest lists more than %d extents", MaxOverlayExtentsPerManifest)
	}
	extents := make([]OverlayExtent, 0, len(items))
	for _, item := range items {
		extentMap, err := AsMap(item)
		if err != nil {
			return representation, err
		}
		if err := CheckKeys(extentMap, "offset", "length", "chunks"); err != nil {
			return representation, err
		}
		offset, err := GetU64(extentMap, "offset")
		if err != nil {
			return representation, err
		}
		length, err := GetU64(extentMap, "length")
		if err != nil {
			return representation, err
		}
		if length == 0 {
			return representation, werr.Newf(werr.Malformed, "overlay extent length must be positive")
		}
		chunks, err := overlayChunksFromWCB(extentMap)
		if err != nil {
			return representation, err
		}
		if len(chunks) == 0 {
			return representation, werr.Newf(werr.Malformed, "overlay extent has no chunks")
		}
		extents = append(extents, OverlayExtent{Offset: offset, Length: length, Chunks: chunks})
	}
	representation = Representation{
		Kind:        RepresentationOverlay,
		Strategy:    strategy,
		DecodedSize: decodedSize,
		Overlay: &OverlayRepresentation{
			Base: base, BaseContentRoot: baseContentRoot, BaseSize: baseSize,
			Depth: depth, OverlayBytes: overlayBytes, Extents: extents,
		},
	}
	return representation, nil
}

func overlayChunksFromWCB(extentMap map[string]wcb.Value) ([]ChunkRef, error) {
	items, err := GetArray(extentMap, "chunks")
	if err != nil {
		return nil, err
	}
	chunks := make([]ChunkRef, 0, len(items))
	for _, item := range items {
		chunkMap, err := AsMap(item)
		if err != nil {
			return nil, err
		}
		if err := CheckKeys(chunkMap, "hash", "len"); err != nil {
			return nil, err
		}
		length, err := GetU64(chunkMap, "len")
		if err != nil {
			return nil, err
		}
		if length == 0 {
			return nil, werr.Newf(werr.Corrupt, "overlay chunk has zero length")
		}
		hashValue, err := GetHash(chunkMap, "hash")
		if err != nil {
			return nil, err
		}
		if hashValue == ZeroHash {
			return nil, werr.Newf(werr.Malformed, "overlay chunk hash must be non-zero")
		}
		chunks = append(chunks, ChunkRef{Hash: hashValue, Len: length})
	}
	return chunks, nil
}

// ValidateShape checks a v4 overlay against the manifest's chunk grid and size.
// It is structural only; the base chain is resolved by the reader.
func (o OverlayRepresentation) ValidateShape(chunkSize, size uint64) error {
	if chunkSize == 0 || chunkSize > MaxChunkSize {
		return werr.Newf(werr.Malformed, "overlay chunk_size is out of range")
	}
	if o.Base == ZeroHash {
		return werr.Newf(werr.Malformed, "overlay base must be a non-zero manifest id")
	}
	if o.BaseContentRoot == ZeroHash {
		return werr.Newf(werr.Malformed, "overlay base_content_root must be non-zero")
	}
	if o.Depth == 0 {
		return werr.Newf(werr.Malformed, "overlay depth must be positive")
	}
	if o.Depth > MaxOverlayChainDepth {
		return werr.Newf(werr.LimitExceeded,
			"overlay depth %d exceeds the hard bound %d", o.Depth, MaxOverlayChainDepth)
	}
	if len(o.Extents) == 0 {
		return werr.Newf(werr.Malformed, "overlay representation has no extents")
	}
	if len(o.Extents) > MaxOverlayExtentsPerManifest {
		return werr.Newf(werr.LimitExceeded,
			"overlay manifest lists more than %d extents", MaxOverlayExtentsPerManifest)
	}
	if o.OverlayBytes == 0 {
		return werr.Newf(werr.Malformed, "overlay_bytes must be positive")
	}
	var extentTotal uint64
	var previousEnd *uint64
	for _, extent := range o.Extents {
		if extent.Length == 0 {
			return werr.Newf(werr.Malformed, "overlay extent length must be positive")
		}
		if extent.Offset%chunkSize != 0 {
			return werr.Newf(werr.Malformed, "overlay extent offset %d is not chunk-aligned", extent.Offset)
		}
		end, ok := addChecked(extent.Offset, extent.Length)
		if !ok {
			return werr.Newf(werr.Malformed, "overlay extent end overflows")
		}
		if end > size {
			return werr.Newf(werr.Corrupt, "overlay extent [%d, %d) lies past the %d-byte file", extent.Offset, end, size)
		}
		if previousEnd != nil && extent.Offset < *previousEnd {
			return werr.Newf(werr.Malformed,
				"overlay extents are not canonically ordered or overlap at %d", extent.Offset)
		}
		previousEnd = &end
		expectedCount := extent.Length / chunkSize
		if extent.Length%chunkSize != 0 {
			expectedCount++
		}
		if uint64(len(extent.Chunks)) != expectedCount {
			return werr.Newf(werr.Corrupt,
				"overlay extent at %d has %d chunks, expected %d",
				extent.Offset, len(extent.Chunks), expectedCount)
		}
		var sum uint64
		for index, chunk := range extent.Chunks {
			chunkStart, ok := addChecked(extent.Offset, uint64(index)*chunkSize)
			if !ok {
				return werr.Newf(werr.Corrupt, "overlay chunk offset overflows")
			}
			expectedLen := chunkSize
			if size-chunkStart < chunkSize {
				expectedLen = size - chunkStart
			}
			if chunk.Len != expectedLen {
				return werr.Newf(werr.Corrupt,
					"overlay chunk %d at %d is %d bytes, expected %d",
					index, chunkStart, chunk.Len, expectedLen)
			}
			sum, ok = addChecked(sum, chunk.Len)
			if !ok {
				return werr.Newf(werr.Corrupt, "overlay extent length overflows")
			}
		}
		if sum != extent.Length {
			return werr.Newf(werr.Corrupt,
				"overlay extent chunks sum to %d, declared length is %d", sum, extent.Length)
		}
		var okTotal bool
		extentTotal, okTotal = addChecked(extentTotal, extent.Length)
		if !okTotal {
			return werr.Newf(werr.Corrupt, "overlay byte total overflows")
		}
	}
	if o.OverlayBytes < extentTotal {
		return werr.Newf(werr.Corrupt,
			"overlay_bytes %d is smaller than this manifest's extents (%d)", o.OverlayBytes, extentTotal)
	}
	return nil
}

var representationKeys = []string{"kind", "frame", "dependencies", "strategy", "decoded_size"}

// ToWCB returns the canonical representation map.
func (r Representation) ToWCB() wcb.Value {
	if r.Kind == RepresentationOverlay {
		return overlayRepresentationToWCB(r)
	}
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
	if kind == RepresentationOverlay {
		return overlayRepresentationFromWCB(m)
	}
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
		case StrategyDelta, StrategyReference, StrategyZstdPatch:
			if len(dependencies) != 1 {
				return representation, werr.Newf(werr.Malformed, "delta/reference/zstd-patch representation requires exactly one dependency")
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

var manifestKeysV4 = []string{"schema", "size", "chunk_size", "content_root", "content_identity", "representation"}

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
	if m.Representation != nil && m.Representation.Kind == RepresentationOverlay {
		return Map(map[string]wcb.Value{
			"schema":           wcb.TextValue(ManifestSchemaV4),
			"size":             wcb.U64Value(m.Size),
			"chunk_size":       wcb.U64Value(m.ChunkSize),
			"content_root":     HashValue(m.ContentHash),
			"content_identity": wcb.TextValue(string(ContentIdentityMerkleV1)),
			"representation":   m.Representation.ToWCB(),
		})
	}
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
	v4 := false
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
	case ManifestSchemaV4:
		identity = ContentIdentityMerkleV1
		v4 = true
		if err := CheckKeys(m, manifestKeysV4...); err != nil {
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
		return Manifest{}, werr.Newf(werr.Unsupported, "manifest schema `%s` is not a supported v1/v2/v3/v4 schema", schema)
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
		} else if v2 || v4 {
			return Manifest{}, werr.Newf(werr.Malformed, "%s is missing its representation map", schema)
		}
	}
	if v2 && representation != nil && representation.Kind == RepresentationOverlay {
		return Manifest{}, werr.Newf(werr.Malformed, "kind:\"overlay\" requires schema weft.manifest.v4")
	}
	if v4 {
		if representation == nil || representation.Kind != RepresentationOverlay || representation.Overlay == nil {
			return Manifest{}, werr.Newf(werr.Corrupt, "weft.manifest.v4 may only carry a kind:\"overlay\" representation")
		}
		if representation.DecodedSize != size {
			return Manifest{}, werr.Newf(werr.Corrupt, "overlay decoded_size differs from manifest size")
		}
		if err := representation.Overlay.ValidateShape(chunkSize, size); err != nil {
			return Manifest{}, err
		}
		declared, err := GetHash(m, "content_root")
		if err != nil {
			return Manifest{}, err
		}
		if declared == ZeroHash {
			return Manifest{}, werr.Newf(werr.Malformed, "overlay content_root must be non-zero")
		}
		return Manifest{
			Size: size, ChunkSize: chunkSize, Chunks: nil, ContentHash: declared,
			Representation: representation, Identity: identity,
		}, nil
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
