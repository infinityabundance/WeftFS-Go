package model

import (
	"testing"

	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

func v4Chunk(seed string, length uint64) ChunkRef {
	return ChunkRef{Hash: ContentHash([]byte(seed)), Len: length}
}

func v4ExtentValue(offset, length uint64, chunks []ChunkRef) wcb.Value {
	items := make([]wcb.Value, 0, len(chunks))
	for _, chunk := range chunks {
		items = append(items, Map(map[string]wcb.Value{
			"hash": HashValue(chunk.Hash),
			"len":  wcb.U64Value(chunk.Len),
		}))
	}
	return Map(map[string]wcb.Value{
		"offset": wcb.U64Value(offset),
		"length": wcb.U64Value(length),
		"chunks": wcb.ArrayValue(items),
	})
}

func v4Fixture() Manifest {
	baseChunks := []ChunkRef{
		v4Chunk("base-0", 8), v4Chunk("base-1", 8),
		v4Chunk("base-2", 8), v4Chunk("base-3", 8),
	}
	replacement := v4Chunk("overlay-1", 8)
	table := []ChunkRef{baseChunks[0], replacement, baseChunks[2], baseChunks[3]}
	return Manifest{
		Size:        32,
		ChunkSize:   8,
		ContentHash: MerkleRootChunks(table),
		Representation: &Representation{
			Kind:        RepresentationOverlay,
			Strategy:    "overlay",
			DecodedSize: 32,
			Overlay: &OverlayRepresentation{
				Base:            ContentHash([]byte("base-manifest")),
				BaseContentRoot: MerkleRootChunks(baseChunks),
				BaseSize:        32,
				Depth:           1,
				OverlayBytes:    8,
				Extents: []OverlayExtent{{
					Offset: 8, Length: 8, Chunks: []ChunkRef{replacement},
				}},
			},
		},
		Identity: ContentIdentityMerkleV1,
	}
}

func v4Value(t *testing.T) wcb.Value {
	t.Helper()
	value := CloneValue(v4Fixture().ToWCB())
	if value.Kind != wcb.Map {
		t.Fatalf("v4 ToWCB is not a map")
	}
	return value
}

func v4Representation(value wcb.Value) map[string]wcb.Value {
	return value.Map["representation"].Map
}

func v4Extents(value wcb.Value) []wcb.Value {
	return v4Representation(value)["extents"].Array
}

func expectV4Class(t *testing.T, value wcb.Value, class werr.Kind) {
	t.Helper()
	_, err := ManifestFromWCB(value)
	if err == nil {
		t.Fatalf("v4 value unexpectedly parsed")
	}
	if got := werr.ClassOf(err); got != class {
		t.Fatalf("class = %s, want %s (%v)", got, class, err)
	}
}

func TestManifestV4OverlayRoundTrip(t *testing.T) {
	manifest := v4Fixture()
	value := manifest.ToWCB()
	if value.Kind != wcb.Map {
		t.Fatalf("v4 is not a map")
	}
	if _, present := value.Map["chunks"]; present {
		t.Fatalf("v4 must not carry a top-level chunk table")
	}
	if got := value.Map["schema"].Str; got != ManifestSchemaV4 {
		t.Fatalf("schema = %s, want %s", got, ManifestSchemaV4)
	}
	parsed, err := ManifestFromWCB(value)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Identity != ContentIdentityMerkleV1 {
		t.Fatalf("identity = %s, want merkle-v1", parsed.Identity)
	}
	if parsed.Representation == nil || parsed.Representation.Kind != RepresentationOverlay {
		t.Fatalf("representation = %+v", parsed.Representation)
	}
	if parsed.Representation.Overlay == nil || parsed.Representation.Overlay.Depth != 1 {
		t.Fatalf("overlay = %+v", parsed.Representation.Overlay)
	}
	if parsed.Size != 32 || parsed.ChunkSize != 8 || len(parsed.Chunks) != 0 {
		t.Fatalf("parsed manifest = %+v", parsed)
	}
	bytesValue, err := manifest.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeWCB(bytesValue)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	reparsed, err := ManifestFromWCB(decoded)
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	reencoded, err := reparsed.Encode()
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if string(reencoded) != string(bytesValue) {
		t.Fatalf("canonical re-encode changed bytes")
	}
}

func TestManifestV4RejectsMalformedShapes(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(wcb.Value)
		class  werr.Kind
	}{
		{
			name: "missing representation",
			mutate: func(value wcb.Value) {
				delete(value.Map, "representation")
			},
			class: werr.Malformed,
		},
		{
			name: "top-level chunks",
			mutate: func(value wcb.Value) {
				value.Map["chunks"] = wcb.ArrayValue(nil)
			},
			class: werr.Malformed,
		},
		{
			name: "wrong content identity",
			mutate: func(value wcb.Value) {
				value.Map["content_identity"] = wcb.TextValue("whole-file-v1")
			},
			class: werr.Malformed,
		},
		{
			name: "zero content root",
			mutate: func(value wcb.Value) {
				value.Map["content_root"] = HashValue(ZeroHash)
			},
			class: werr.Malformed,
		},
		{
			name: "zero base",
			mutate: func(value wcb.Value) {
				v4Representation(value)["base"] = HashValue(ZeroHash)
			},
			class: werr.Malformed,
		},
		{
			name: "zero base content root",
			mutate: func(value wcb.Value) {
				v4Representation(value)["base_content_root"] = HashValue(ZeroHash)
			},
			class: werr.Malformed,
		},
		{
			name: "zero depth",
			mutate: func(value wcb.Value) {
				v4Representation(value)["depth"] = wcb.U64Value(0)
			},
			class: werr.Malformed,
		},
		{
			name: "depth beyond bound",
			mutate: func(value wcb.Value) {
				v4Representation(value)["depth"] = wcb.U64Value(MaxOverlayChainDepth + 1)
			},
			class: werr.LimitExceeded,
		},
		{
			name: "zero overlay bytes",
			mutate: func(value wcb.Value) {
				v4Representation(value)["overlay_bytes"] = wcb.U64Value(0)
			},
			class: werr.Malformed,
		},
		{
			name: "overlay bytes below extents",
			mutate: func(value wcb.Value) {
				v4Representation(value)["overlay_bytes"] = wcb.U64Value(7)
			},
			class: werr.Corrupt,
		},
		{
			name: "no extents",
			mutate: func(value wcb.Value) {
				v4Representation(value)["extents"] = wcb.ArrayValue(nil)
			},
			class: werr.Malformed,
		},
		{
			name: "too many extents",
			mutate: func(value wcb.Value) {
				extents := make([]wcb.Value, 0, MaxOverlayExtentsPerManifest+1)
				for index := 0; index <= MaxOverlayExtentsPerManifest; index++ {
					extents = append(extents, v4ExtentValue(0, 8, []ChunkRef{v4Chunk("x", 8)}))
				}
				v4Representation(value)["extents"] = wcb.ArrayValue(extents)
			},
			class: werr.LimitExceeded,
		},
		{
			name: "unaligned offset",
			mutate: func(value wcb.Value) {
				v4Extents(value)[0].Map["offset"] = wcb.U64Value(4)
			},
			class: werr.Malformed,
		},
		{
			name: "zero length",
			mutate: func(value wcb.Value) {
				v4Extents(value)[0].Map["length"] = wcb.U64Value(0)
			},
			class: werr.Malformed,
		},
		{
			name: "past EOF",
			mutate: func(value wcb.Value) {
				v4Representation(value)["extents"] = wcb.ArrayValue([]wcb.Value{
					v4ExtentValue(24, 16, []ChunkRef{v4Chunk("a", 8), v4Chunk("b", 8)}),
				})
			},
			class: werr.Corrupt,
		},
		{
			name: "chunk count mismatch",
			mutate: func(value wcb.Value) {
				v4Extents(value)[0].Map["chunks"] = wcb.ArrayValue([]wcb.Value{
					v4ExtentValue(0, 8, []ChunkRef{v4Chunk("a", 8)}).Map["chunks"].Array[0],
					v4ExtentValue(0, 8, []ChunkRef{v4Chunk("b", 8)}).Map["chunks"].Array[0],
				})
			},
			class: werr.Corrupt,
		},
		{
			name: "chunk length mismatch",
			mutate: func(value wcb.Value) {
				v4Extents(value)[0].Map["chunks"] = wcb.ArrayValue([]wcb.Value{
					v4ExtentValue(0, 8, []ChunkRef{v4Chunk("a", 4)}).Map["chunks"].Array[0],
				})
			},
			class: werr.Corrupt,
		},
		{
			name: "zero chunk length",
			mutate: func(value wcb.Value) {
				v4Extents(value)[0].Map["chunks"].Array[0].Map["len"] = wcb.U64Value(0)
			},
			class: werr.Corrupt,
		},
		{
			name: "zero chunk hash",
			mutate: func(value wcb.Value) {
				v4Extents(value)[0].Map["chunks"].Array[0].Map["hash"] = HashValue(ZeroHash)
			},
			class: werr.Malformed,
		},
		{
			name: "unsorted extents",
			mutate: func(value wcb.Value) {
				v4Representation(value)["extents"] = wcb.ArrayValue([]wcb.Value{
					v4ExtentValue(8, 8, []ChunkRef{v4Chunk("a", 8)}),
					v4ExtentValue(0, 8, []ChunkRef{v4Chunk("b", 8)}),
				})
			},
			class: werr.Malformed,
		},
		{
			name: "overlapping extents",
			mutate: func(value wcb.Value) {
				v4Representation(value)["extents"] = wcb.ArrayValue([]wcb.Value{
					v4ExtentValue(0, 16, []ChunkRef{v4Chunk("a", 8), v4Chunk("b", 8)}),
					v4ExtentValue(8, 8, []ChunkRef{v4Chunk("c", 8)}),
				})
			},
			class: werr.Malformed,
		},
		{
			name: "wrong strategy",
			mutate: func(value wcb.Value) {
				v4Representation(value)["strategy"] = wcb.TextValue("raw")
			},
			class: werr.Malformed,
		},
		{
			name: "v2 overlay",
			mutate: func(value wcb.Value) {
				value.Map["schema"] = wcb.TextValue(ManifestSchemaV2)
				value.Map["content_hash"] = HashValue(ContentHash([]byte("x")))
				value.Map["chunks"] = wcb.ArrayValue(nil)
			},
			class: werr.Malformed,
		},
		{
			name: "v3 overlay",
			mutate: func(value wcb.Value) {
				value.Map["schema"] = wcb.TextValue(ManifestSchemaV3)
				value.Map["chunks"] = wcb.ArrayValue(nil)
			},
			class: werr.Corrupt,
		},
		{
			name: "raw representation in v4",
			mutate: func(value wcb.Value) {
				raw := Representation{Kind: RepresentationRaw, Strategy: StrategyRaw, DecodedSize: 32}
				value.Map["representation"] = raw.ToWCB()
			},
			class: werr.Corrupt,
		},
		{
			name: "unknown schema",
			mutate: func(value wcb.Value) {
				value.Map["schema"] = wcb.TextValue("weft.manifest.v9")
			},
			class: werr.Unsupported,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := v4Value(t)
			test.mutate(value)
			expectV4Class(t, value, test.class)
		})
	}
}
