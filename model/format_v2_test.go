package model

import (
	"bytes"
	"testing"

	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

func sampleHash(seed byte) Hash32 {
	var h Hash32
	for i := range h {
		h[i] = seed
	}
	return h
}

func TestManifestV2CodecRoundTrip(t *testing.T) {
	frame := sampleHash(7)
	dependency := sampleHash(9)
	manifest := Manifest{
		Size:        96 * 1024,
		ChunkSize:   65536,
		ContentHash: ContentHash([]byte("payload")),
		Representation: &Representation{
			Kind:         RepresentationCodec,
			Frame:        &frame,
			Dependencies: []Hash32{dependency},
			Strategy:     StrategyDelta,
			DecodedSize:  96 * 1024,
		},
	}
	encoded, err := manifest.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	value, err := DecodeWCB(encoded)
	if err != nil {
		t.Fatalf("decode WCB: %v", err)
	}
	parsed, err := ManifestFromWCB(value)
	if err != nil {
		t.Fatalf("parse v2: %v", err)
	}
	if parsed.Representation == nil {
		t.Fatal("v2 manifest lost its representation")
	}
	if parsed.Representation.Kind != RepresentationCodec ||
		parsed.Representation.Strategy != StrategyDelta ||
		parsed.Representation.Frame == nil || *parsed.Representation.Frame != frame ||
		len(parsed.Representation.Dependencies) != 1 ||
		parsed.Representation.Dependencies[0] != dependency ||
		parsed.Representation.DecodedSize != manifest.Size {
		t.Fatalf("representation round trip mismatch: %+v", parsed.Representation)
	}
	reencoded, err := parsed.Encode()
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if !bytes.Equal(encoded, reencoded) {
		t.Fatal("v2 manifest re-encoding is not byte-identical")
	}
}

func TestManifestV2RawRoundTrip(t *testing.T) {
	manifest := Manifest{
		Size:        4,
		ChunkSize:   65536,
		Chunks:      []ChunkRef{{Hash: sampleHash(3), Len: 4}},
		ContentHash: ContentHash([]byte("data")),
		Representation: &Representation{
			Kind:        RepresentationRaw,
			Strategy:    StrategyRaw,
			DecodedSize: 4,
		},
	}
	encoded, err := manifest.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	value, err := DecodeWCB(encoded)
	if err != nil {
		t.Fatalf("decode WCB: %v", err)
	}
	parsed, err := ManifestFromWCB(value)
	if err != nil {
		t.Fatalf("parse v2 raw: %v", err)
	}
	if parsed.Representation == nil || parsed.Representation.Kind != RepresentationRaw {
		t.Fatalf("v2 raw representation lost: %+v", parsed.Representation)
	}
	if len(parsed.Chunks) != 1 || parsed.Chunks[0].Len != 4 {
		t.Fatalf("v2 raw chunks mismatch: %+v", parsed.Chunks)
	}
}

func TestManifestSchemaRules(t *testing.T) {
	v1WithRepresentation := Map(map[string]wcb.Value{
		"schema":         wcb.TextValue(ManifestSchema),
		"size":           wcb.U64Value(0),
		"chunk_size":     wcb.U64Value(65536),
		"chunks":         wcb.ArrayValue(nil),
		"content_hash":   HashValue(ContentHash(nil)),
		"representation": (&Representation{Kind: RepresentationRaw, Strategy: StrategyRaw}).ToWCB(),
	})
	if _, err := ManifestFromWCB(v1WithRepresentation); werr.ClassOf(err) != werr.Malformed {
		t.Fatalf("v1 with representation = %v, want Malformed", err)
	}

	v2WithoutRepresentation := Map(map[string]wcb.Value{
		"schema":       wcb.TextValue(ManifestSchemaV2),
		"size":         wcb.U64Value(0),
		"chunk_size":   wcb.U64Value(65536),
		"chunks":       wcb.ArrayValue(nil),
		"content_hash": HashValue(ContentHash(nil)),
	})
	if _, err := ManifestFromWCB(v2WithoutRepresentation); werr.ClassOf(err) != werr.Malformed {
		t.Fatalf("v2 without representation = %v, want Malformed", err)
	}

	unknownSchema := Map(map[string]wcb.Value{
		"schema":       wcb.TextValue("weft.manifest.v3"),
		"size":         wcb.U64Value(0),
		"chunk_size":   wcb.U64Value(65536),
		"chunks":       wcb.ArrayValue(nil),
		"content_hash": HashValue(ContentHash(nil)),
	})
	if _, err := ManifestFromWCB(unknownSchema); werr.ClassOf(err) != werr.Unsupported {
		t.Fatalf("unknown schema = %v, want UnsupportedVersion", err)
	}
}

func v2Manifest(t *testing.T, representation *Representation, chunks []wcb.Value, size uint64) wcb.Value {
	t.Helper()
	return Map(map[string]wcb.Value{
		"schema":         wcb.TextValue(ManifestSchemaV2),
		"size":           wcb.U64Value(size),
		"chunk_size":     wcb.U64Value(65536),
		"chunks":         wcb.ArrayValue(chunks),
		"content_hash":   HashValue(ContentHash(nil)),
		"representation": representation.ToWCB(),
	})
}

func TestRepresentationRules(t *testing.T) {
	frame := sampleHash(1)
	other := sampleHash(2)
	chunk := Map(map[string]wcb.Value{
		"hash": HashValue(sampleHash(5)),
		"len":  wcb.U64Value(1),
	})

	codecWithChunk := v2Manifest(t, &Representation{
		Kind: RepresentationCodec, Frame: &frame, Strategy: StrategyZstd, DecodedSize: 0,
	}, []wcb.Value{chunk}, 0)
	if _, err := ManifestFromWCB(codecWithChunk); werr.ClassOf(err) != werr.Corrupt {
		t.Fatalf("codec with chunks = %v, want Corrupt", err)
	}

	rawWithFrame := v2Manifest(t, &Representation{
		Kind: RepresentationRaw, Frame: &frame, Strategy: StrategyRaw, DecodedSize: 0,
	}, nil, 0)
	if _, err := ManifestFromWCB(rawWithFrame); werr.ClassOf(err) != werr.Malformed {
		t.Fatalf("raw with frame = %v, want Malformed", err)
	}

	decodedSizeMismatch := v2Manifest(t, &Representation{
		Kind: RepresentationCodec, Frame: &frame, Strategy: StrategyZstd, DecodedSize: 9,
	}, nil, 0)
	if _, err := ManifestFromWCB(decodedSizeMismatch); werr.ClassOf(err) != werr.Corrupt {
		t.Fatalf("decoded_size mismatch = %v, want Corrupt", err)
	}

	zstdWithDependency := v2Manifest(t, &Representation{
		Kind: RepresentationCodec, Frame: &frame, Strategy: StrategyZstd,
		Dependencies: []Hash32{other}, DecodedSize: 0,
	}, nil, 0)
	if _, err := ManifestFromWCB(zstdWithDependency); werr.ClassOf(err) != werr.Malformed {
		t.Fatalf("zstd with dependency = %v, want Malformed", err)
	}

	deltaWithoutDependency := v2Manifest(t, &Representation{
		Kind: RepresentationCodec, Frame: &frame, Strategy: StrategyDelta, DecodedSize: 0,
	}, nil, 0)
	if _, err := ManifestFromWCB(deltaWithoutDependency); werr.ClassOf(err) != werr.Malformed {
		t.Fatalf("delta without dependency = %v, want Malformed", err)
	}
}
