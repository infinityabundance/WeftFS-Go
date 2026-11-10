package index

// WFX3 incremental advisory index segments.
//
// A WFX2 segment is a full-state snapshot. WFX3 adds a delta segment: an
// immediate base segment id plus the changed index rows. A reader resolves the
// full ancestor and applies the deltas in order. The format is internal and
// rebuildable; the commit attestation names the segment chain so a forged or
// partial chain is refused.
//
// The layout is byte-identical to Rust's `src/index_chain.rs`. See
// `docs/INDEX-AMPLIFICATION.md`.

import (
	"bytes"
	"sort"

	"github.com/infinityabundance/WeftCodec-Go/hash"
	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

const (
	// MagicV3 is the incremental segment magic.
	MagicV3 = "WFX3"
	// VersionV3 is the WFX3 layout version.
	VersionV3 uint32 = 1
	// DomainV3 is the integrity digest domain.
	DomainV3 = "weft/index/segment/v3"
	// DomainChain is the attested chain root domain.
	DomainChain = "weft/index/chain/v1"
	// DefaultMaxChainDeltas is the writer default.
	DefaultMaxChainDeltas uint32 = 32
	// HardMaxChainDeltas is the reader bound.
	HardMaxChainDeltas uint32 = 256
)

const (
	wfx3HeaderBytes = 113
	wfx3DigestBytes = 32
	presentFlag     = byte(1)
	absentFlag      = byte(0)
)

// SegmentKind is full or delta.
type SegmentKind string

const (
	SegmentFull  SegmentKind = "full"
	SegmentDelta SegmentKind = "delta"
)

// SegmentHeader is the parsed WFX3 header.
type SegmentHeader struct {
	Kind           SegmentKind
	Generation     uint64
	BaseGeneration uint64
	BaseID         model.Hash32
	BaseCommit     model.Hash32
	ObjectCount    uint64
	RelationCount  uint64
	EntryCount     uint64
}

// Segment is a parsed, integrity-checked WFX3 file.
type Segment struct {
	Header SegmentHeader
	ID     model.Hash32
	body   []byte
}

// IndexChain is the attested chain: head first, full ancestor last.
type IndexChain struct {
	Kind  SegmentKind
	Chain []model.Hash32
}

// Depth is chain length minus one.
func (c IndexChain) Depth() uint64 {
	if len(c.Chain) == 0 {
		return 0
	}
	return uint64(len(c.Chain) - 1)
}

// Base is the immediate base segment id for a delta.
func (c IndexChain) Base() *model.Hash32 {
	if c.Kind != SegmentDelta || len(c.Chain) < 2 {
		return nil
	}
	copy := c.Chain[1]
	return &copy
}

// Root is H("weft/index/chain/v1", WCB({generation, chain})).
func (c IndexChain) Root(generation uint64) (model.Hash32, error) {
	values := make([]wcb.Value, 0, len(c.Chain))
	for _, id := range c.Chain {
		values = append(values, model.HashValue(id))
	}
	value := model.Map(map[string]wcb.Value{
		"generation": wcb.U64Value(generation),
		"chain":      wcb.ArrayValue(values),
	})
	encoded, err := model.EncodeWCB(value)
	if err != nil {
		return model.Hash32{}, err
	}
	return hash.Domain(DomainChain, encoded), nil
}

// SegmentID is H("weft/index/segment/v3", body without the trailing digest).
func SegmentID(body []byte) model.Hash32 {
	return hash.Domain(DomainV3, body)
}

// FileSegmentID is the id of an encoded segment file.
func FileSegmentID(file []byte) (model.Hash32, error) {
	if len(file) < wfx3DigestBytes {
		return model.Hash32{}, werr.Newf(werr.Corrupt, "WFX3 segment is truncated")
	}
	return SegmentID(file[:len(file)-wfx3DigestBytes]), nil
}

// DecodeSegment parses and integrity-checks a WFX3 file.
func DecodeSegment(data []byte) (*Segment, error) {
	if len(data) < wfx3HeaderBytes+wfx3DigestBytes {
		return nil, werr.Newf(werr.Corrupt, "WFX3 segment is truncated")
	}
	if uint64(len(data)) > MaxFileBytes {
		return nil, werr.Newf(werr.LimitExceeded,
			"WFX3 segment is %d bytes, above the %d-byte cap", len(data), MaxFileBytes)
	}
	body, trailer := data[:len(data)-wfx3DigestBytes], data[len(data)-wfx3DigestBytes:]
	digest := hash.Domain(DomainV3, body)
	if !bytes.Equal(trailer, digest[:]) {
		return nil, werr.Newf(werr.Corrupt, "WFX3 segment integrity digest mismatch")
	}
	header, err := decodeWfx3Header(body)
	if err != nil {
		return nil, err
	}
	return &Segment{Header: header, ID: digest, body: body}, nil
}

func decodeWfx3Header(body []byte) (SegmentHeader, error) {
	if len(body) < wfx3HeaderBytes {
		return SegmentHeader{}, werr.Newf(werr.Corrupt, "WFX3 header is truncated")
	}
	if string(body[0:4]) != MagicV3 {
		return SegmentHeader{}, werr.Newf(werr.Malformed, "bad WFX3 magic")
	}
	version := leU32(body[4:8])
	if version != VersionV3 {
		return SegmentHeader{}, werr.Newf(werr.Unsupported,
			"WFX3 version %d is not %d", version, VersionV3)
	}
	var header SegmentHeader
	switch body[8] {
	case 0:
		header.Kind = SegmentFull
	case 1:
		header.Kind = SegmentDelta
	default:
		return SegmentHeader{}, werr.Newf(werr.Malformed,
			"index segment kind %d is reserved", body[8])
	}
	header.Generation = leU64(body[9:17])
	header.BaseGeneration = leU64(body[17:25])
	copy(header.BaseID[:], body[25:57])
	copy(header.BaseCommit[:], body[57:89])
	header.ObjectCount = leU64(body[89:97])
	header.RelationCount = leU64(body[97:105])
	header.EntryCount = leU64(body[105:113])
	if header.Generation == 0 {
		return SegmentHeader{}, werr.Newf(werr.Corrupt, "WFX3 generation must be positive")
	}
	zero := model.Hash32{}
	switch header.Kind {
	case SegmentFull:
		if header.BaseGeneration != 0 || header.BaseID != zero || header.BaseCommit != zero {
			return SegmentHeader{}, werr.Newf(werr.Corrupt,
				"a full WFX3 segment must not name a base")
		}
	case SegmentDelta:
		if header.BaseGeneration == 0 || header.BaseGeneration+1 != header.Generation {
			return SegmentHeader{}, werr.Newf(werr.Corrupt,
				"a WFX3 delta must name the immediately previous generation")
		}
		if header.BaseID == zero || header.BaseCommit == zero {
			return SegmentHeader{}, werr.Newf(werr.Corrupt,
				"a WFX3 delta must name its base segment and commit")
		}
	}
	return header, nil
}

// EncodeFull encodes a full WFX3 segment for `index`.
func EncodeFull(index *StateIndex) ([]byte, error) {
	header := SegmentHeader{
		Kind:          SegmentFull,
		Generation:    index.generation,
		ObjectCount:   uint64(index.objectCount),
		RelationCount: uint64(index.relationCount),
		EntryCount:    uint64(index.entryCount),
	}
	return encodeWfx3(header, index, nil)
}

// EncodeDelta encodes a delta from `base` to `index`.
func EncodeDelta(base, index *StateIndex, baseID, baseCommit model.Hash32) ([]byte, error) {
	if base.generation+1 != index.generation {
		return nil, werr.Newf(werr.InvalidArgument,
			"a WFX3 delta base must be the immediately previous generation")
	}
	header := SegmentHeader{
		Kind:           SegmentDelta,
		Generation:     index.generation,
		BaseGeneration: base.generation,
		BaseID:         baseID,
		BaseCommit:     baseCommit,
		ObjectCount:    uint64(index.objectCount),
		RelationCount:  uint64(index.relationCount),
		EntryCount:     uint64(index.entryCount),
	}
	return encodeWfx3(header, index, base)
}

func encodeWfx3(header SegmentHeader, index, base *StateIndex) ([]byte, error) {
	out := make([]byte, 0, wfx3HeaderBytes+1024)
	out = append(out, MagicV3...)
	out = appendU32(out, VersionV3)
	if header.Kind == SegmentFull {
		out = append(out, 0)
	} else {
		out = append(out, 1)
	}
	out = appendU64(out, header.Generation)
	out = appendU64(out, header.BaseGeneration)
	out = append(out, header.BaseID[:]...)
	out = append(out, header.BaseCommit[:]...)
	out = appendU64(out, header.ObjectCount)
	out = appendU64(out, header.RelationCount)
	out = appendU64(out, header.EntryCount)

	// objects_with_attr
	var names []string
	seen := map[string]struct{}{}
	for name := range index.ObjectsWithAttr {
		if _, ok := seen[name]; !ok {
			seen[name] = struct{}{}
			names = append(names, name)
		}
	}
	if base != nil {
		for name := range base.ObjectsWithAttr {
			if _, ok := seen[name]; !ok {
				seen[name] = struct{}{}
				names = append(names, name)
			}
		}
	}
	sort.Strings(names)
	type namedSet struct {
		name string
		ids  IDSet
		have bool
	}
	var rows []namedSet
	for _, name := range names {
		next, okNext := index.ObjectsWithAttr[name]
		var prev IDSet
		okPrev := false
		if base != nil {
			prev, okPrev = base.ObjectsWithAttr[name]
		}
		if base != nil && okNext == okPrev && sameIDSet(next, prev) {
			continue
		}
		rows = append(rows, namedSet{name: name, ids: next, have: okNext})
	}
	var err error
	if out, err = appendU32Checked(out, uint64(len(rows))); err != nil {
		return nil, err
	}
	for _, row := range rows {
		if out, err = appendString(out, row.name); err != nil {
			return nil, err
		}
		if row.have {
			out = append(out, presentFlag)
			if out, err = appendIDSet(out, row.ids); err != nil {
				return nil, err
			}
		} else {
			out = append(out, absentFlag)
		}
	}

	// objects_by_attr_eq
	keySet := map[AttrEqKey]struct{}{}
	for key := range index.ObjectsByAttrEq {
		keySet[key] = struct{}{}
	}
	if base != nil {
		for key := range base.ObjectsByAttrEq {
			keySet[key] = struct{}{}
		}
	}
	keys := make([]AttrEqKey, 0, len(keySet))
	for key := range keySet {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Name != keys[j].Name {
			return keys[i].Name < keys[j].Name
		}
		return keys[i].Key < keys[j].Key
	})
	type attrRow struct {
		key  AttrEqKey
		ids  IDSet
		have bool
	}
	var attrRows []attrRow
	for _, key := range keys {
		next, okNext := index.ObjectsByAttrEq[key]
		var prev IDSet
		okPrev := false
		if base != nil {
			prev, okPrev = base.ObjectsByAttrEq[key]
		}
		if base != nil && okNext == okPrev && sameIDSet(next, prev) {
			continue
		}
		attrRows = append(attrRows, attrRow{key: key, ids: next, have: okNext})
	}
	if out, err = appendU32Checked(out, uint64(len(attrRows))); err != nil {
		return nil, err
	}
	for _, row := range attrRows {
		if out, err = appendString(out, row.key.Name); err != nil {
			return nil, err
		}
		if out, err = appendBytes(out, []byte(row.key.Key)); err != nil {
			return nil, err
		}
		if row.have {
			out = append(out, presentFlag)
			if out, err = appendIDSet(out, row.ids); err != nil {
				return nil, err
			}
		} else {
			out = append(out, absentFlag)
		}
	}

	// relations_from
	pairSet := map[RelationPair]struct{}{}
	for pair := range index.RelationsFrom {
		pairSet[pair] = struct{}{}
	}
	if base != nil {
		for pair := range base.RelationsFrom {
			pairSet[pair] = struct{}{}
		}
	}
	pairs := make([]RelationPair, 0, len(pairSet))
	for pair := range pairSet {
		pairs = append(pairs, pair)
	}
	sort.Slice(pairs, func(i, j int) bool {
		if cmp := bytes.Compare(pairs[i].Subject[:], pairs[j].Subject[:]); cmp != 0 {
			return cmp < 0
		}
		return pairs[i].Predicate < pairs[j].Predicate
	})
	type relationRow struct {
		pair  RelationPair
		edges [][]byte
		have  bool
	}
	var relationRows []relationRow
	for _, pair := range pairs {
		next, okNext := index.RelationsFrom[pair]
		var prev []IndexedRelation
		okPrev := false
		if base != nil {
			prev, okPrev = base.RelationsFrom[pair]
		}
		nextCanon, err := canonicalEdges(next)
		if err != nil {
			return nil, err
		}
		prevCanon, err := canonicalEdges(prev)
		if err != nil {
			return nil, err
		}
		if base != nil && okNext == okPrev && sameBytes(nextCanon, prevCanon) {
			continue
		}
		relationRows = append(relationRows, relationRow{pair: pair, edges: nextCanon, have: okNext})
	}
	if out, err = appendU32Checked(out, uint64(len(relationRows))); err != nil {
		return nil, err
	}
	for _, row := range relationRows {
		out = append(out, row.pair.Subject[:]...)
		if out, err = appendString(out, row.pair.Predicate); err != nil {
			return nil, err
		}
		if row.have {
			out = append(out, presentFlag)
			if out, err = appendU32Checked(out, uint64(len(row.edges))); err != nil {
				return nil, err
			}
			for _, edge := range row.edges {
				out = append(out, edge...)
			}
		} else {
			out = append(out, absentFlag)
		}
	}

	// tags
	tagSet := map[string]struct{}{}
	for tag := range index.Tags {
		tagSet[tag] = struct{}{}
	}
	if base != nil {
		for tag := range base.Tags {
			tagSet[tag] = struct{}{}
		}
	}
	tags := make([]string, 0, len(tagSet))
	for tag := range tagSet {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	var tagRows []namedSet
	for _, tag := range tags {
		next, okNext := index.Tags[tag]
		var prev IDSet
		okPrev := false
		if base != nil {
			prev, okPrev = base.Tags[tag]
		}
		if base != nil && okNext == okPrev && sameIDSet(next, prev) {
			continue
		}
		tagRows = append(tagRows, namedSet{name: tag, ids: next, have: okNext})
	}
	if out, err = appendU32Checked(out, uint64(len(tagRows))); err != nil {
		return nil, err
	}
	for _, row := range tagRows {
		if out, err = appendString(out, row.name); err != nil {
			return nil, err
		}
		if row.have {
			out = append(out, presentFlag)
			if out, err = appendIDSet(out, row.ids); err != nil {
				return nil, err
			}
		} else {
			out = append(out, absentFlag)
		}
	}

	if uint64(len(out))+wfx3DigestBytes > MaxFileBytes {
		return nil, werr.Newf(werr.LimitExceeded,
			"WFX3 segment is %d bytes, above the %d-byte cap",
			len(out)+wfx3DigestBytes, MaxFileBytes)
	}
	digest := hash.Domain(DomainV3, out)
	return append(out, digest[:]...), nil
}

func sameIDSet(a, b IDSet) bool {
	if len(a) != len(b) {
		return false
	}
	for id := range a {
		if _, ok := b[id]; !ok {
			return false
		}
	}
	return true
}

func sameBytes(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

func canonicalEdges(edges []IndexedRelation) ([][]byte, error) {
	out := make([][]byte, 0, len(edges))
	for _, edge := range edges {
		encoded, err := targetBytes(edge)
		if err != nil {
			return nil, err
		}
		out = append(out, encoded)
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i], out[j]) < 0 })
	return out, nil
}

// ResolvedChain is a resolved index plus its attested chain.
type ResolvedChain struct {
	Index *StateIndex
	Chain IndexChain
}

// ResolveChain resolves a head segment and its ancestors. `load` returns the
// bytes stored for the base commit named by a delta header.
func ResolveChain(head []byte, load func(commit, id model.Hash32) ([]byte, error)) (*ResolvedChain, error) {
	segment, err := DecodeSegment(head)
	if err != nil {
		return nil, err
	}
	return ResolveChainSegment(segment, load)
}

// ResolveChainSegment resolves an already-decoded head segment.
func ResolveChainSegment(head *Segment, load func(commit, id model.Hash32) ([]byte, error)) (*ResolvedChain, error) {
	if head.Header.Kind == SegmentFull {
		index, err := resolveParsedSegment(head, nil)
		if err != nil {
			return nil, err
		}
		return &ResolvedChain{
			Index: index,
			Chain: IndexChain{Kind: SegmentFull, Chain: []model.Hash32{head.ID}},
		}, nil
	}
	segments := []*Segment{head}
	for {
		last := segments[len(segments)-1]
		if last.Header.Kind == SegmentFull {
			break
		}
		if len(segments) > int(HardMaxChainDeltas)+1 {
			return nil, werr.Newf(werr.LimitExceeded,
				"WFX3 index chain is deeper than %d deltas", HardMaxChainDeltas)
		}
		baseBytes, err := load(last.Header.BaseCommit, last.Header.BaseID)
		if err != nil {
			return nil, werr.Newf(werr.Corrupt,
				"cannot read base segment %s for commit %s: %v",
				last.Header.BaseID.Hex(), last.Header.BaseCommit.Hex(), err)
		}
		base, err := DecodeSegment(baseBytes)
		if err != nil {
			return nil, werr.Newf(werr.Corrupt,
				"base segment %s for commit %s: %v",
				last.Header.BaseID.Hex(), last.Header.BaseCommit.Hex(), err)
		}
		if base.ID != last.Header.BaseID {
			return nil, werr.Newf(werr.Corrupt,
				"WFX3 base segment id does not match the bytes it names")
		}
		if base.Header.Generation != last.Header.BaseGeneration {
			return nil, werr.Newf(werr.Corrupt,
				"WFX3 base segment generation does not match the delta header")
		}
		segments = append(segments, base)
	}
	ids := make([]model.Hash32, 0, len(segments))
	for _, segment := range segments {
		ids = append(ids, segment.ID)
	}
	var resolved *StateIndex
	for i := len(segments) - 1; i >= 0; i-- {
		next, err := resolveParsedSegment(segments[i], resolved)
		if err != nil {
			return nil, err
		}
		if next.generation != segments[i].Header.Generation {
			return nil, werr.Newf(werr.Corrupt, "WFX3 resolved generation mismatch")
		}
		resolved = next
	}
	if resolved == nil {
		return nil, werr.Newf(werr.Corrupt, "WFX3 chain resolved to nothing")
	}
	return &ResolvedChain{
		Index: resolved,
		Chain: IndexChain{Kind: SegmentDelta, Chain: ids},
	}, nil
}

// ResolveSegment resolves one segment file against an optional base index.
func ResolveSegment(data []byte, base *StateIndex) (*StateIndex, error) {
	segment, err := DecodeSegment(data)
	if err != nil {
		return nil, err
	}
	return resolveParsedSegment(segment, base)
}

func resolveParsedSegment(segment *Segment, base *StateIndex) (*StateIndex, error) {
	header := segment.Header
	reader := &reader{data: segment.body}
	if _, err := reader.take(wfx3HeaderBytes); err != nil {
		return nil, err
	}
	var objectsWithAttr map[string]IDSet
	var objectsByAttrEq map[AttrEqKey]IDSet
	var relationsFrom map[RelationPair][]IndexedRelation
	var tags map[string]IDSet
	if header.Kind == SegmentFull {
		if base != nil {
			return nil, werr.Newf(werr.Corrupt, "a full WFX3 segment cannot have a base")
		}
		objectsWithAttr = map[string]IDSet{}
		objectsByAttrEq = map[AttrEqKey]IDSet{}
		relationsFrom = map[RelationPair][]IndexedRelation{}
		tags = map[string]IDSet{}
	} else {
		if base == nil {
			return nil, werr.Newf(werr.Corrupt, "a WFX3 delta segment has no base")
		}
		objectsWithAttr = cloneIDSetMap(base.ObjectsWithAttr)
		objectsByAttrEq = cloneAttrMap(base.ObjectsByAttrEq)
		relationsFrom = cloneRelationMap(base.RelationsFrom)
		tags = cloneIDSetMap(base.Tags)
	}

	var lastName string
	seenName := false
	names, err := reader.boundedCount(4)
	if err != nil {
		return nil, err
	}
	for i := 0; i < names; i++ {
		name, err := reader.string()
		if err != nil {
			return nil, err
		}
		if seenName && name <= lastName {
			return nil, werr.Newf(werr.Corrupt, "WFX3 objects_with_attr rows are not sorted")
		}
		lastName, seenName = name, true
		flag, err := reader.u8()
		if err != nil {
			return nil, err
		}
		switch flag {
		case presentFlag:
			ids, err := reader.idSet()
			if err != nil {
				return nil, err
			}
			objectsWithAttr[name] = ids
		case absentFlag:
			if header.Kind == SegmentFull {
				return nil, werr.Newf(werr.Corrupt, "WFX3 full segment contains a tombstone")
			}
			if _, ok := objectsWithAttr[name]; !ok {
				return nil, werr.Newf(werr.Corrupt,
					"WFX3 objects_with_attr tombstone has no base row")
			}
			delete(objectsWithAttr, name)
		default:
			return nil, werr.Newf(werr.Corrupt, "WFX3 present flag is not 0/1")
		}
	}

	var lastAttr AttrEqKey
	seenAttr := false
	count, err := reader.boundedCount(4)
	if err != nil {
		return nil, err
	}
	for i := 0; i < count; i++ {
		name, err := reader.string()
		if err != nil {
			return nil, err
		}
		key, err := reader.bytes()
		if err != nil {
			return nil, err
		}
		current := AttrEqKey{Name: name, Key: string(key)}
		if seenAttr && !attrKeyLess(lastAttr, current) {
			return nil, werr.Newf(werr.Corrupt, "WFX3 attr_eq rows are not sorted")
		}
		lastAttr, seenAttr = current, true
		flag, err := reader.u8()
		if err != nil {
			return nil, err
		}
		switch flag {
		case presentFlag:
			ids, err := reader.idSet()
			if err != nil {
				return nil, err
			}
			objectsByAttrEq[current] = ids
		case absentFlag:
			if header.Kind == SegmentFull {
				return nil, werr.Newf(werr.Corrupt, "WFX3 full segment contains a tombstone")
			}
			if _, ok := objectsByAttrEq[current]; !ok {
				return nil, werr.Newf(werr.Corrupt, "WFX3 attr_eq tombstone has no base row")
			}
			delete(objectsByAttrEq, current)
		default:
			return nil, werr.Newf(werr.Corrupt, "WFX3 present flag is not 0/1")
		}
	}

	var lastPair RelationPair
	seenPair := false
	count, err = reader.boundedCount(4)
	if err != nil {
		return nil, err
	}
	for i := 0; i < count; i++ {
		subject, err := reader.hash32()
		if err != nil {
			return nil, err
		}
		predicate, err := reader.string()
		if err != nil {
			return nil, err
		}
		pair := RelationPair{Subject: subject, Predicate: predicate}
		if seenPair && !pairLess(lastPair, pair) {
			return nil, werr.Newf(werr.Corrupt, "WFX3 relation rows are not sorted")
		}
		lastPair, seenPair = pair, true
		flag, err := reader.u8()
		if err != nil {
			return nil, err
		}
		switch flag {
		case presentFlag:
			edgeCount, err := reader.boundedCount(32)
			if err != nil {
				return nil, err
			}
			edges := make([]IndexedRelation, 0, edgeCount)
			var lastTarget []byte
			for j := 0; j < edgeCount; j++ {
				edge, encoded, err := readTarget(reader)
				if err != nil {
					return nil, err
				}
				if lastTarget != nil && bytes.Compare(encoded, lastTarget) <= 0 {
					return nil, werr.Newf(werr.Corrupt, "WFX3 relation targets are not sorted")
				}
				lastTarget = encoded
				edges = append(edges, edge)
			}
			relationsFrom[pair] = edges
		case absentFlag:
			if header.Kind == SegmentFull {
				return nil, werr.Newf(werr.Corrupt, "WFX3 full segment contains a tombstone")
			}
			if _, ok := relationsFrom[pair]; !ok {
				return nil, werr.Newf(werr.Corrupt, "WFX3 relation tombstone has no base row")
			}
			delete(relationsFrom, pair)
		default:
			return nil, werr.Newf(werr.Corrupt, "WFX3 present flag is not 0/1")
		}
	}

	var lastTag string
	seenTag := false
	count, err = reader.boundedCount(4)
	if err != nil {
		return nil, err
	}
	for i := 0; i < count; i++ {
		tag, err := reader.string()
		if err != nil {
			return nil, err
		}
		if seenTag && tag <= lastTag {
			return nil, werr.Newf(werr.Corrupt, "WFX3 tag rows are not sorted")
		}
		lastTag, seenTag = tag, true
		flag, err := reader.u8()
		if err != nil {
			return nil, err
		}
		switch flag {
		case presentFlag:
			ids, err := reader.idSet()
			if err != nil {
				return nil, err
			}
			tags[tag] = ids
		case absentFlag:
			if header.Kind == SegmentFull {
				return nil, werr.Newf(werr.Corrupt, "WFX3 full segment contains a tombstone")
			}
			if _, ok := tags[tag]; !ok {
				return nil, werr.Newf(werr.Corrupt, "WFX3 tag tombstone has no base row")
			}
			delete(tags, tag)
		default:
			return nil, werr.Newf(werr.Corrupt, "WFX3 present flag is not 0/1")
		}
	}
	if reader.remaining() != 0 {
		return nil, werr.Newf(werr.Corrupt, "trailing bytes after WFX3 sections")
	}
	resolved := &StateIndex{
		generation:      header.Generation,
		objectCount:     int(header.ObjectCount),
		relationCount:   int(header.RelationCount),
		entryCount:      int(header.EntryCount),
		complete:        true,
		ObjectsByAttrEq: objectsByAttrEq,
		ObjectsWithAttr: objectsWithAttr,
		RelationsFrom:   relationsFrom,
		Tags:            tags,
	}
	if uint64(resolved.objectCount) != header.ObjectCount ||
		uint64(resolved.relationCount) != header.RelationCount ||
		uint64(resolved.entryCount) != header.EntryCount {
		return nil, werr.Newf(werr.Corrupt,
			"resolved WFX3 index counts disagree with its header")
	}
	return resolved, nil
}

func attrKeyLess(a, b AttrEqKey) bool {
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	return a.Key < b.Key
}

func pairLess(a, b RelationPair) bool {
	if cmp := bytes.Compare(a.Subject[:], b.Subject[:]); cmp != 0 {
		return cmp < 0
	}
	return a.Predicate < b.Predicate
}

func cloneIDSetMap(source map[string]IDSet) map[string]IDSet {
	out := make(map[string]IDSet, len(source))
	for key, ids := range source {
		out[key] = cloneIDSet(ids)
	}
	return out
}

func cloneAttrMap(source map[AttrEqKey]IDSet) map[AttrEqKey]IDSet {
	out := make(map[AttrEqKey]IDSet, len(source))
	for key, ids := range source {
		out[key] = cloneIDSet(ids)
	}
	return out
}

func cloneRelationMap(source map[RelationPair][]IndexedRelation) map[RelationPair][]IndexedRelation {
	out := make(map[RelationPair][]IndexedRelation, len(source))
	for key, edges := range source {
		copied := make([]IndexedRelation, len(edges))
		copy(copied, edges)
		out[key] = copied
	}
	return out
}

func cloneIDSet(source IDSet) IDSet {
	out := make(IDSet, len(source))
	for id := range source {
		out[id] = struct{}{}
	}
	return out
}

func leU32(data []byte) uint32 {
	return uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
}

func leU64(data []byte) uint64 {
	var value uint64
	for i := 0; i < 8; i++ {
		value |= uint64(data[i]) << (8 * i)
	}
	return value
}
