package index

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/infinityabundance/WeftCodec-Go/hash"
	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/model"
)

// The WFX2 header constants are the cross-language contract: a change here
// breaks loading a segment written by Rust (or by an earlier Go build).
func TestWFX2Constants(t *testing.T) {
	if MagicV2 != "WFX2" || MagicV1 != "WFX1" {
		t.Fatalf("magic moved: %q %q", MagicV1, MagicV2)
	}
	if VersionV2 != 1 || DomainV2 != "weft/index/v2" {
		t.Fatalf("version/domain moved: %d %q", VersionV2, DomainV2)
	}
	if HeaderBytes != 72 || DigestBytes != 32 {
		t.Fatalf("header/digest size moved: %d %d", HeaderBytes, DigestBytes)
	}
}

// TestEqKeyLayout pins the canonical comparison-key bytes. These are the bytes
// Rust writes in the attr_eq section; a divergence would silently miss
// candidates when the other implementation reads the segment.
func TestEqKeyLayout(t *testing.T) {
	cases := []struct {
		value wcb.Value
		hex   string
	}{
		{wcb.TextValue("red"), "0702050b776566742e65712e7374720503726564"},
		{wcb.U64Value(3), "0702050b776566742e65712e6e756d050133"},
		{wcb.I64Value(-2), "0702050b776566742e65712e6e756d05022d32"},
		{wcb.BoolValue(true), "0702050c776566742e65712e626f6f6c02"},
		{wcb.NullValue(), "0702050c776566742e65712e6e756c6c00"},
		{wcb.BytesValue([]byte{1, 2}), "0702050d776566742e65712e627974657306020102"},
	}
	for _, test := range cases {
		key, ok, err := EqKey(test.value)
		if err != nil || !ok {
			t.Fatalf("kind %d: ok=%v err=%v", test.value.Kind, ok, err)
		}
		if hex.EncodeToString(key) != test.hex {
			t.Fatalf("kind %d key = %x, want %s", test.value.Kind, key, test.hex)
		}
	}
	// Numeric families normalize together: U64(3) must not equal I64(3)'s key
	// only by accident.
	u, _, _ := EqKey(wcb.U64Value(3))
	i, _, _ := EqKey(wcb.I64Value(3))
	if !bytes.Equal(u, i) {
		t.Fatal("U64 and I64 must share a numeric key")
	}
	ts, _, _ := EqKey(wcb.TimestampValue(3))
	if !bytes.Equal(u, ts) {
		t.Fatal("Timestamp must share the numeric key")
	}
	if _, ok, _ := EqKey(wcb.ArrayValue(nil)); ok {
		t.Fatal("arrays must not have an equality key")
	}
	if _, ok, _ := EqKey(wcb.MapValue(nil)); ok {
		t.Fatal("maps must not have an equality key")
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	state := model.NewState()
	state.Generation = 9
	subjectA := model.Hash32{0x01}
	subjectB := model.Hash32{0x02}
	target := model.Hash32{0x03}
	state.Objects[subjectA] = model.ObjectRecord{
		ID: subjectA, Kind: model.KindFile, Attrs: map[string]wcb.Value{
			"team":   wcb.TextValue("red"),
			"score":  wcb.U64Value(3),
			"signed": wcb.I64Value(-2),
			"flag":   wcb.BoolValue(true),
			"empty":  wcb.NullValue(),
			"blob":   wcb.BytesValue([]byte{1, 2, 3}),
			"nested": wcb.MapValue(map[string]wcb.Value{"a": wcb.U64Value(1)}),
		},
	}
	state.Objects[subjectB] = model.ObjectRecord{
		ID: subjectB, Kind: model.KindFile, Attrs: map[string]wcb.Value{
			"team": wcb.TextValue("blue"),
		},
	}
	state.Entries[model.Hash32{0x04}] = model.EntryRecord{ID: model.Hash32{0x04}, Parent: model.RootID, Name: []byte("x"), Target: subjectA}
	state.Relations[model.Hash32{0x05}] = model.RelationRecord{
		ID: model.Hash32{0x05}, Subject: subjectA, Predicate: "links",
		Kind: model.RelationObject, Target: model.ObjectTarget(target),
	}
	state.Relations[model.Hash32{0x06}] = model.RelationRecord{
		ID: model.Hash32{0x06}, Subject: subjectA, Predicate: "tagged_as",
		Kind: model.RelationValue, Target: model.ValueTarget(wcb.TextValue("alpha")),
	}
	state.Relations[model.Hash32{0x07}] = model.RelationRecord{
		ID: model.Hash32{0x07}, Subject: subjectB, Predicate: "score",
		Kind: model.RelationValue, Target: model.ValueTarget(wcb.U64Value(7)),
	}

	built := Build(state)
	if !built.Complete() {
		t.Fatal("the fixture index should be complete")
	}
	commit := model.Hash32{0xAB}
	built.WithCommit(commit)
	data, err := built.EncodeFile()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if string(data[0:4]) != MagicV2 {
		t.Fatalf("magic = %q", data[0:4])
	}
	if len(data) <= HeaderBytes+DigestBytes {
		t.Fatalf("segment is too short: %d", len(data))
	}
	decoded, err := DecodeFile(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Commit() != commit || !decoded.MatchesState(state) {
		t.Fatalf("decoded identity/state guard: commit=%s", decoded.Commit().Hex())
	}
	if !decoded.Complete() {
		t.Fatal("a decoded segment is always complete")
	}
	if len(decoded.ObjectsWithAttr["team"]) != 2 {
		t.Fatalf("team set = %v", decoded.ObjectsWithAttr)
	}
	if _, ok := decoded.ObjectsWithAttr["empty"]; ok {
		t.Fatal("a null attribute must not be indexed as present")
	}
	if _, ok := decoded.ObjectsByAttrEq[AttrEqKey{Name: "nested", Key: string(mustEq(t, wcb.U64Value(1)))}]; ok {
		t.Fatal("a map attribute must not have an equality entry")
	}
	tags := decoded.Tags["alpha"]
	if _, ok := tags[subjectA]; !ok || len(tags) != 1 {
		t.Fatalf("tag set = %v", tags)
	}
	if len(decoded.RelationsFrom) != 3 {
		t.Fatalf("relation groups = %d", len(decoded.RelationsFrom))
	}
	if edges := decoded.RelationsFrom[RelationPair{Subject: subjectA, Predicate: "links"}]; len(edges) != 1 ||
		edges[0].Target.Object == nil || *edges[0].Target.Object != target {
		t.Fatalf("object edge = %+v", edges)
	}
	// Encode is deterministic: build again and compare bytes.
	again, err := Build(state).WithCommit(commit).EncodeFile()
	if err != nil {
		t.Fatalf("encode again: %v", err)
	}
	if !bytes.Equal(data, again) {
		t.Fatal("encoding is not deterministic")
	}
	// Re-encoding a decode preserves the bytes exactly.
	third, err := decoded.EncodeFile()
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if !bytes.Equal(data, third) {
		t.Fatal("decode/encode is not byte-identical")
	}
}

func mustEq(t *testing.T, value wcb.Value) []byte {
	t.Helper()
	key, ok, err := EqKey(value)
	if err != nil || !ok {
		t.Fatalf("EqKey: ok=%v err=%v", ok, err)
	}
	return key
}

// TestDecodeRejectsNonCanonicalOrder proves the canonical array-order checks
// (Rust's decoder is looser here; Go's is deliberately stricter for a segment it
// wrote, and Rust segments are always canonical).
func TestDecodeRejectsNonCanonicalOrder(t *testing.T) {
	state := model.NewState()
	state.Generation = 1
	a := model.Hash32{0x02}
	b := model.Hash32{0x01}
	for _, id := range []model.Hash32{a, b} {
		state.Objects[id] = model.ObjectRecord{ID: id, Kind: model.KindFile,
			Attrs: map[string]wcb.Value{"team": wcb.TextValue("red")}}
	}
	data, err := Build(state).WithCommit(model.Hash32{0x09}).EncodeFile()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// The set is written ascending; flip the two ids and reseal the digest.
	body := append([]byte(nil), data[:len(data)-DigestBytes]...)
	// Locate the first id set: header(72) + count(4) + name len+bytes(4+4) +
	// id count(4) + 2*32 id bytes.
	offset := HeaderBytes + 4 + 4 + len("team") + 4
	first := append([]byte(nil), body[offset:offset+32]...)
	second := append([]byte(nil), body[offset+32:offset+64]...)
	copy(body[offset:offset+32], second)
	copy(body[offset+32:offset+64], first)
	tampered := append(body, hashDomain(body)...)
	if _, err := DecodeFile(tampered); err == nil {
		t.Fatal("an unordered id set must be rejected")
	}
}

func hashDomain(body []byte) []byte {
	digest := hash.Domain(DomainV2, body)
	return digest[:]
}

// TestFullSegmentWithValueTargetTailResolves is the WFX3 regression for the
// reader bound: a relation edge carrying a value target is one kind byte plus
// its payload, so a full segment whose last relation row is such an edge has
// fewer than `edgeCount * 32` bytes after the count. The reader used to refuse
// that valid segment as corrupt; every reopen then rebuilt the index.
func TestFullSegmentWithValueTargetTailResolves(t *testing.T) {
	state := model.NewState()
	state.Generation = 3
	subject := model.Hash32{0x11}
	state.Objects[subject] = model.ObjectRecord{ID: subject, Kind: model.KindFile}
	state.Relations[model.Hash32{0x12}] = model.RelationRecord{
		ID: model.Hash32{0x12}, Subject: subject, Predicate: "tagged_as",
		Kind: model.RelationValue, Target: model.ValueTarget(wcb.TextValue("alpha")),
	}
	built := Build(state)
	data, err := EncodeFull(built)
	if err != nil {
		t.Fatalf("encode full: %v", err)
	}
	segment, err := DecodeSegment(data)
	if err != nil {
		t.Fatalf("decode segment: %v", err)
	}
	resolved, err := ResolveChainSegment(segment, func(_, _ model.Hash32) ([]byte, error) {
		t.Fatal("a full segment must not ask for a base")
		return nil, nil
	})
	if err != nil {
		t.Fatalf("resolve full segment with a value-target tail: %v", err)
	}
	if resolved.Index.Generation() != 3 || resolved.Index.RelationCount() != 1 {
		t.Fatalf("resolved generation=%d relations=%d", resolved.Index.Generation(), resolved.Index.RelationCount())
	}
}
