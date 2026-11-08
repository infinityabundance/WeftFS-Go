// Package index is the per-state contextual index for selector candidate
// narrowing, plus its compact advisory on-disk segment (WFX2).
//
// This is the Go port of the Rust reference `src/index.rs`. An index is **not**
// a semantic authority: `resolver.ResolveStateWithBudget` still evaluates every
// candidate with the authoritative evaluator. The index may over-approximate a
// match set (a superset) but must never under-approximate, because a missing
// entry would silently drop a result.
//
// The WFX2 file is advisory derived data. Its bytes are internal to the store
// format (not a frozen normative format), but the layout is deliberately shared
// with Rust so either implementation can load a segment the other wrote. A
// segment that fails any check is discarded and rebuilt from replayed state.
package index

import (
	"bytes"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/infinityabundance/WeftCodec-Go/hash"
	"github.com/infinityabundance/WeftCodec-Go/selector"
	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// WFX2 layout constants. The magic, version, domain, element tags, and header
// size match the Rust reference exactly; a change here breaks cross-language
// segment loading.
const (
	// MagicV1 is the superseded canonical-WCB magic. WFX1 files are discarded
	// (rebuilt from state), never interpreted.
	MagicV1 = "WFX1"
	// MagicV2 is the compact binary magic.
	MagicV2 = "WFX2"
	// VersionV2 is the WFX2 layout version.
	VersionV2 uint32 = 1
	// DomainV2 is the integrity-digest domain over every preceding WFX2 byte.
	DomainV2 = "weft/index/v2"
	// DomainCandidates is the domain of the section digest the commit attests.
	DomainCandidates = "weft/index/candidates/v1"
	// DomainState is the domain of the six-field commit digest the commit
	// attests.
	DomainState = "weft/index/state/v1"
	// HeaderBytes is magic(4) + version(4) + commit(32) + generation/object/
	// relation/entry(32).
	HeaderBytes = 72
	// DigestBytes is the trailing BLAKE3 digest length.
	DigestBytes = 32
	// MaxFileBytes is the hard cap on one index segment. Larger files are never
	// written or loaded; the index is advisory.
	MaxFileBytes uint64 = 256 * 1024 * 1024
)

// Relation-target tags used by the sorted relations_from section.
const (
	kindObject    byte = 0
	kindNull      byte = 1
	kindBool      byte = 2
	kindU64       byte = 3
	kindI64       byte = 4
	kindTimestamp byte = 5
	kindStr       byte = 6
	kindBytes     byte = 7
)

// IndexedRelation is one relation edge kept by the index.
type IndexedRelation struct {
	Kind   model.RelationKind
	Target model.RelationTarget
}

// IDSet is a set of object ids. Iteration order is never used for bytes or
// results: every encoded section and every resolver candidate list is sorted.
type IDSet map[model.Hash32]struct{}

// AttrEqKey addresses attribute equality: attribute name plus the canonical WCB
// bytes of the normalized comparison key.
type AttrEqKey struct {
	Name string
	Key  string
}

// RelationPair addresses outgoing edges by subject and predicate.
type RelationPair struct {
	Subject   model.Hash32
	Predicate string
}

// StateIndex is an owned, data-only index derived from one replayed State.
type StateIndex struct {
	commit        model.Hash32
	generation    uint64
	objectCount   int
	relationCount int
	entryCount    int
	// complete is false when at least one scalar attribute value could not be
	// encoded. Callers must then treat every candidate set as a full
	// authorized scan.
	complete bool

	ObjectsByAttrEq map[AttrEqKey]IDSet
	ObjectsWithAttr map[string]IDSet
	RelationsFrom   map[RelationPair][]IndexedRelation
	Tags            map[string]IDSet
}

// Build derives an index from a replayed state.
func Build(state *model.State) *StateIndex {
	out := &StateIndex{
		generation:      state.Generation,
		objectCount:     len(state.Objects),
		relationCount:   len(state.Relations),
		entryCount:      len(state.Entries),
		complete:        true,
		ObjectsByAttrEq: make(map[AttrEqKey]IDSet),
		ObjectsWithAttr: make(map[string]IDSet),
		RelationsFrom:   make(map[RelationPair][]IndexedRelation),
		Tags:            make(map[string]IDSet),
	}
	for _, record := range state.Objects {
		for name, value := range record.Attrs {
			if value.Kind != wcb.Null {
				addID(out.ObjectsWithAttr, name, record.ID)
			}
			key, ok, err := EqKey(value)
			switch {
			case err != nil:
				// An encoding limit would lose entries; mark the index
				// incomplete so callers scan the authorized universe instead.
				out.complete = false
			case ok:
				bucket := out.ObjectsByAttrEq[AttrEqKey{Name: name, Key: string(key)}]
				if bucket == nil {
					bucket = make(IDSet)
					out.ObjectsByAttrEq[AttrEqKey{Name: name, Key: string(key)}] = bucket
				}
				bucket[record.ID] = struct{}{}
			}
		}
	}
	for _, relation := range state.Relations {
		if relation.Kind == model.RelationValue && relation.Predicate == "tagged_as" &&
			relation.Target.Object == nil && relation.Target.Value.Kind == wcb.Text {
			addID(out.Tags, relation.Target.Value.Str, relation.Subject)
		}
		key := RelationPair{Subject: relation.Subject, Predicate: relation.Predicate}
		out.RelationsFrom[key] = append(out.RelationsFrom[key], IndexedRelation{
			Kind:   relation.Kind,
			Target: relation.Target,
		})
	}
	return out
}

func addID(m map[string]IDSet, name string, id model.Hash32) {
	bucket := m[name]
	if bucket == nil {
		bucket = make(IDSet)
		m[name] = bucket
	}
	bucket[id] = struct{}{}
}

// Complete reports whether every scalar attribute value was encodable.
func (x *StateIndex) Complete() bool { return x.complete }

// ObjectCount is the number of indexed objects (diagnostic only).
func (x *StateIndex) ObjectCount() int { return x.objectCount }

// Commit is the commit this index describes (zero when not yet attached).
func (x *StateIndex) Commit() model.Hash32 { return x.commit }

// WithCommit attaches the commit key before persisting a freshly built index.
func (x *StateIndex) WithCommit(commit model.Hash32) *StateIndex {
	x.commit = commit
	return x
}

// MatchesState is the cheap structural guard that the index still describes
// `state`. Resolvers must refuse an index that fails it: an index for a
// different state shape could under-select candidates.
func (x *StateIndex) MatchesState(state *model.State) bool {
	return x.generation == state.Generation &&
		x.objectCount == len(state.Objects) &&
		x.relationCount == len(state.Relations) &&
		x.entryCount == len(state.Entries)
}

// EncodeFile encodes the compact advisory segment (WFX2).
//
// Sections are written once, sorted, so a load is a sequential read plus map
// insertion. An incomplete index is never persisted: it could under-select and
// must stay in memory only.
func (x *StateIndex) EncodeFile() ([]byte, error) {
	body, err := x.encodeBody()
	if err != nil {
		return nil, err
	}
	total := uint64(len(body)) + DigestBytes
	if total > MaxFileBytes {
		return nil, werr.Newf(werr.LimitExceeded,
			"index file is %d bytes, above the %d-byte cap", total, MaxFileBytes)
	}
	digest := hash.Domain(DomainV2, body)
	return append(body, digest[:]...), nil
}

// CandidatesRoot is the digest of the candidate sections an honest index must
// contain. The commit attests it, so a self-consistent subset is rejected.
func (x *StateIndex) CandidatesRoot() (model.Hash32, error) {
	body, err := x.encodeBody()
	if err != nil {
		return model.Hash32{}, err
	}
	if len(body) < HeaderBytes {
		return model.Hash32{}, werr.Newf(werr.Corrupt, "index body is shorter than its header")
	}
	return hash.Domain(DomainCandidates, body[HeaderBytes:]), nil
}

// Generation is the replayed generation this index describes.
func (x *StateIndex) Generation() uint64 { return x.generation }

// RelationCount is the indexed relation count (diagnostic only).
func (x *StateIndex) RelationCount() int { return x.relationCount }

// EntryCount is the indexed entry count (diagnostic only).
func (x *StateIndex) EntryCount() int { return x.entryCount }

// WithGeneration sets the generation used for structural matching. A caller
// building an index for a commit that is about to publish needs this because
// the live state still carries the previous generation.
func (x *StateIndex) WithGeneration(generation uint64) *StateIndex {
	x.generation = generation
	return x
}

func (x *StateIndex) encodeBody() ([]byte, error) {
	if !x.complete {
		return nil, werr.Newf(werr.InvalidArgument,
			"an incomplete selector index cannot be persisted")
	}
	out := make([]byte, 0, HeaderBytes+1024)
	out = append(out, MagicV2...)
	out = appendU32(out, VersionV2)
	out = append(out, x.commit[:]...)
	out = appendU64(out, x.generation)
	out = appendU64(out, uint64(x.objectCount))
	out = appendU64(out, uint64(x.relationCount))
	out = appendU64(out, uint64(x.entryCount))

	names := make([]string, 0, len(x.ObjectsWithAttr))
	for name := range x.ObjectsWithAttr {
		names = append(names, name)
	}
	sort.Strings(names)
	var err error
	if out, err = appendU32Checked(out, uint64(len(names))); err != nil {
		return nil, err
	}
	for _, name := range names {
		if out, err = appendString(out, name); err != nil {
			return nil, err
		}
		if out, err = appendIDSet(out, x.ObjectsWithAttr[name]); err != nil {
			return nil, err
		}
	}

	type attrEqEntry struct {
		key AttrEqKey
		ids IDSet
	}
	attrEq := make([]attrEqEntry, 0, len(x.ObjectsByAttrEq))
	for key, ids := range x.ObjectsByAttrEq {
		attrEq = append(attrEq, attrEqEntry{key: key, ids: ids})
	}
	sort.Slice(attrEq, func(i, j int) bool {
		left, right := attrEq[i].key, attrEq[j].key
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		return bytes.Compare([]byte(left.Key), []byte(right.Key)) < 0
	})
	if out, err = appendU32Checked(out, uint64(len(attrEq))); err != nil {
		return nil, err
	}
	for _, entry := range attrEq {
		if out, err = appendString(out, entry.key.Name); err != nil {
			return nil, err
		}
		if out, err = appendBytes(out, []byte(entry.key.Key)); err != nil {
			return nil, err
		}
		if out, err = appendIDSet(out, entry.ids); err != nil {
			return nil, err
		}
	}

	type edge struct {
		subject   model.Hash32
		predicate string
		target    []byte
	}
	edges := make([]edge, 0, len(x.RelationsFrom))
	for pair, list := range x.RelationsFrom {
		for _, relation := range list {
			encoded, err := targetBytes(relation)
			if err != nil {
				return nil, err
			}
			edges = append(edges, edge{subject: pair.Subject, predicate: pair.Predicate, target: encoded})
		}
	}
	sort.SliceStable(edges, func(i, j int) bool {
		left, right := edges[i], edges[j]
		if cmp := bytes.Compare(left.subject[:], right.subject[:]); cmp != 0 {
			return cmp < 0
		}
		if left.predicate != right.predicate {
			return left.predicate < right.predicate
		}
		return bytes.Compare(left.target, right.target) < 0
	})
	if out, err = appendU32Checked(out, uint64(len(edges))); err != nil {
		return nil, err
	}
	for _, edge := range edges {
		out = append(out, edge.subject[:]...)
		if out, err = appendString(out, edge.predicate); err != nil {
			return nil, err
		}
		out = append(out, edge.target...)
	}

	tags := make([]string, 0, len(x.Tags))
	for tag := range x.Tags {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	if out, err = appendU32Checked(out, uint64(len(tags))); err != nil {
		return nil, err
	}
	for _, tag := range tags {
		if out, err = appendString(out, tag); err != nil {
			return nil, err
		}
		if out, err = appendIDSet(out, x.Tags[tag]); err != nil {
			return nil, err
		}
	}

	return out, nil
}

// DecodeFile decodes a WFX2 segment. Any failure is an error; the caller
// ignores the segment and rebuilds from state. WFX1 segments are deliberately
// discarded.
func DecodeFile(data []byte) (*StateIndex, error) {
	if len(data) < HeaderBytes+DigestBytes {
		return nil, werr.Newf(werr.Corrupt, "index file is truncated")
	}
	if string(data[0:4]) == MagicV1 {
		return nil, werr.Newf(werr.Unsupported,
			"WFX1 index segment is advisory and superseded; rebuilding")
	}
	if string(data[0:4]) != MagicV2 {
		return nil, werr.Newf(werr.Malformed, "bad index file magic")
	}
	if uint64(len(data)) > MaxFileBytes {
		return nil, werr.Newf(werr.LimitExceeded,
			"index file is %d bytes, above the %d-byte cap", len(data), MaxFileBytes)
	}
	body, trailer := data[:len(data)-DigestBytes], data[len(data)-DigestBytes:]
	digest := hash.Domain(DomainV2, body)
	if !bytes.Equal(trailer, digest[:]) {
		return nil, werr.Newf(werr.Corrupt, "index integrity digest mismatch")
	}
	reader := &reader{data: body}
	magic, err := reader.take(4)
	if err != nil {
		return nil, err
	}
	if string(magic) != MagicV2 {
		return nil, werr.Newf(werr.Malformed, "bad index file magic")
	}
	version, err := reader.u32()
	if err != nil {
		return nil, err
	}
	if version != VersionV2 {
		return nil, werr.Newf(werr.Unsupported,
			"index version %d is not %d", version, VersionV2)
	}
	commit, err := reader.hash32()
	if err != nil {
		return nil, err
	}
	generation, err := reader.u64()
	if err != nil {
		return nil, err
	}
	objectCount, err := reader.count("object count")
	if err != nil {
		return nil, err
	}
	relationCount, err := reader.count("relation count")
	if err != nil {
		return nil, err
	}
	entryCount, err := reader.count("entry count")
	if err != nil {
		return nil, err
	}

	objectsWithAttr, err := readNamedSets(reader, 8)
	if err != nil {
		return nil, err
	}

	attrEqCount, err := reader.boundedCount(12)
	if err != nil {
		return nil, err
	}
	objectsByAttrEq := make(map[AttrEqKey]IDSet, attrEqCount)
	previousName := ""
	previousKey := []byte(nil)
	for position := 0; position < attrEqCount; position++ {
		name, err := reader.string()
		if err != nil {
			return nil, err
		}
		key, err := reader.bytes()
		if err != nil {
			return nil, err
		}
		// Canonical section order is validated: the writer sorts by (name,
		// key). A segment that is out of order is not one this code wrote.
		if position > 0 {
			cmp := strings.Compare(name, previousName)
			if cmp == 0 {
				cmp = bytes.Compare(key, previousKey)
			}
			if cmp <= 0 {
				return nil, werr.Newf(werr.Corrupt,
					"attr_eq entries are not in canonical order")
			}
		}
		previousName = name
		previousKey = append(previousKey[:0], key...)
		ids, err := reader.idSet()
		if err != nil {
			return nil, err
		}
		attrKey := AttrEqKey{Name: name, Key: string(key)}
		if _, exists := objectsByAttrEq[attrKey]; exists {
			return nil, werr.Newf(werr.Corrupt, "duplicate attr_eq entry in index")
		}
		objectsByAttrEq[attrKey] = ids
	}

	edgeCount, err := reader.boundedCount(37)
	if err != nil {
		return nil, err
	}
	relationsFrom := make(map[RelationPair][]IndexedRelation)
	var group *RelationPair
	var groupEdges []IndexedRelation
	var previousEdge []byte
	var havePreviousEdge bool
	saveGroup := func() error {
		if group == nil {
			return nil
		}
		if _, exists := relationsFrom[*group]; exists {
			return werr.Newf(werr.Corrupt, "duplicate relations_from entry in index")
		}
		relationsFrom[*group] = groupEdges
		return nil
	}
	for position := 0; position < edgeCount; position++ {
		subject, err := reader.hash32()
		if err != nil {
			return nil, err
		}
		predicate, err := reader.string()
		if err != nil {
			return nil, err
		}
		relation, encoded, err := readTarget(reader)
		if err != nil {
			return nil, err
		}
		// Edges are grouped by (subject, predicate), groups ascend in that
		// order, and targets inside a group ascend by encoded bytes.
		if group == nil || group.Subject != subject || group.Predicate != predicate {
			if err := saveGroup(); err != nil {
				return nil, err
			}
			if group != nil {
				cmp := bytes.Compare(group.Subject[:], subject[:])
				if cmp > 0 || (cmp == 0 && group.Predicate >= predicate) {
					return nil, werr.Newf(werr.Corrupt,
						"relations_from entries are not in canonical order")
				}
			}
			group = &RelationPair{Subject: subject, Predicate: predicate}
			groupEdges = nil
			havePreviousEdge = false
		} else if havePreviousEdge && bytes.Compare(previousEdge, encoded) > 0 {
			return nil, werr.Newf(werr.Corrupt,
				"relations_from entries are not in canonical order")
		}
		groupEdges = append(groupEdges, relation)
		previousEdge = append(previousEdge[:0], encoded...)
		havePreviousEdge = true
	}
	if err := saveGroup(); err != nil {
		return nil, err
	}

	tags, err := readNamedSets(reader, 8)
	if err != nil {
		return nil, err
	}
	if reader.remaining() != 0 {
		return nil, werr.Newf(werr.Corrupt, "trailing bytes after index sections")
	}

	return &StateIndex{
		commit:          commit,
		generation:      generation,
		objectCount:     objectCount,
		relationCount:   relationCount,
		entryCount:      entryCount,
		complete:        true,
		ObjectsByAttrEq: objectsByAttrEq,
		ObjectsWithAttr: objectsWithAttr,
		RelationsFrom:   relationsFrom,
		Tags:            tags,
	}, nil
}

// AttrFieldKey is the attribute name addressed by an `attrs.<path>` field.
// Longer paths are joined with '.', matching the evaluator.
func AttrFieldKey(field selector.Field) (string, bool) {
	if len(field.Segments) < 2 || field.Segments[0] != "attrs" {
		return "", false
	}
	return strings.Join(field.Segments[1:], "."), true
}

// FieldAlwaysPresent reports whether `resolveField` always returns non-null for
// a root field. `has` on these is true for every authorized object.
func FieldAlwaysPresent(field selector.Field) bool {
	return len(field.Segments) == 1 && alwaysPresentFields[field.Segments[0]]
}

var alwaysPresentFields = map[string]bool{
	"object_id": true, "content_id": true, "namespace": true,
	"size": true, "mtime": true, "kind": true,
}

// EqKey is the canonical comparison key for attribute equality.
//
// ok is false for arrays/maps (never equal to a scalar literal); err reports a
// scalar value the canonical encoder rejects under default limits, which makes
// the index incomplete rather than wrong.
func EqKey(value wcb.Value) (key []byte, ok bool, err error) {
	switch value.Kind {
	case wcb.Array, wcb.Map:
		return nil, false, nil
	case wcb.U64:
		return numericKey(strconv.FormatUint(value.U, 10))
	case wcb.I64, wcb.Timestamp:
		return numericKey(strconv.FormatInt(value.I, 10))
	case wcb.Null:
		return tagged("null", wcb.NullValue())
	case wcb.Bool:
		return tagged("bool", value)
	case wcb.Text:
		return tagged("str", value)
	case wcb.Bytes:
		return tagged("bytes", value)
	default:
		return nil, false, werr.Newf(werr.Malformed, "unknown attribute value kind")
	}
}

func tagged(tag string, value wcb.Value) ([]byte, bool, error) {
	encoded, err := wcb.EncodeDefault(wcb.ArrayValue([]wcb.Value{
		wcb.TextValue("weft.eq." + tag), value,
	}))
	if err != nil {
		return nil, false, err
	}
	return encoded, true, nil
}

func numericKey(text string) ([]byte, bool, error) {
	encoded, err := wcb.EncodeDefault(wcb.ArrayValue([]wcb.Value{
		wcb.TextValue("weft.eq.num"), wcb.TextValue(text),
	}))
	if err != nil {
		return nil, false, err
	}
	return encoded, true, nil
}

// ---- encoding helpers ----------------------------------------------------

func appendU32(out []byte, value uint32) []byte {
	return append(out, byte(value), byte(value>>8), byte(value>>16), byte(value>>24))
}

func appendU64(out []byte, value uint64) []byte {
	var buf [8]byte
	for i := 0; i < 8; i++ {
		buf[i] = byte(value >> (8 * i))
	}
	return append(out, buf[:]...)
}

func appendU32Checked(out []byte, value uint64) ([]byte, error) {
	if value > uint64(^uint32(0)) {
		return nil, werr.Newf(werr.LimitExceeded, "index count exceeds u32")
	}
	return appendU32(out, uint32(value)), nil
}

func appendBytes(out, data []byte) ([]byte, error) {
	var err error
	if out, err = appendU32Checked(out, uint64(len(data))); err != nil {
		return nil, err
	}
	return append(out, data...), nil
}

func appendString(out []byte, text string) ([]byte, error) {
	return appendBytes(out, []byte(text))
}

func appendIDSet(out []byte, ids IDSet) ([]byte, error) {
	sorted := sortedIDs(ids)
	var err error
	if out, err = appendU32Checked(out, uint64(len(sorted))); err != nil {
		return nil, err
	}
	for _, id := range sorted {
		out = append(out, id[:]...)
	}
	return out, nil
}

func sortedIDs(ids IDSet) []model.Hash32 {
	out := make([]model.Hash32, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

// targetBytes is `target kind || target payload`, used both as the sort key and
// written verbatim.
func targetBytes(relation IndexedRelation) ([]byte, error) {
	out := make([]byte, 0, 40)
	if relation.Target.Object != nil {
		out = append(out, kindObject)
		out = append(out, relation.Target.Object[:]...)
		return out, nil
	}
	value := relation.Target.Value
	switch value.Kind {
	case wcb.Null:
		return append(out, kindNull), nil
	case wcb.Bool:
		if value.Bool {
			return append(out, kindBool, 1), nil
		}
		return append(out, kindBool, 0), nil
	case wcb.U64:
		return appendU64(append(out, kindU64), value.U), nil
	case wcb.I64:
		return appendU64(append(out, kindI64), uint64(value.I)), nil
	case wcb.Timestamp:
		return appendU64(append(out, kindTimestamp), uint64(value.I)), nil
	case wcb.Text:
		return appendString(append(out, kindStr), value.Str)
	case wcb.Bytes:
		return appendBytes(append(out, kindBytes), value.Bytes)
	default:
		return nil, werr.Newf(werr.Malformed,
			"index relation value target must be a scalar")
	}
}

func readNamedSets(reader *reader, minElementBytes int) (map[string]IDSet, error) {
	count, err := reader.boundedCount(minElementBytes)
	if err != nil {
		return nil, err
	}
	out := make(map[string]IDSet, count)
	previous := ""
	for position := 0; position < count; position++ {
		name, err := reader.string()
		if err != nil {
			return nil, err
		}
		if position > 0 && name <= previous {
			return nil, werr.Newf(werr.Corrupt,
				"named index sets are not in canonical order")
		}
		previous = name
		ids, err := reader.idSet()
		if err != nil {
			return nil, err
		}
		if _, exists := out[name]; exists {
			return nil, werr.Newf(werr.Corrupt, "duplicate named set in index")
		}
		out[name] = ids
	}
	return out, nil
}

// readTarget returns the decoded edge plus the exact bytes it occupied, which
// the caller uses for the canonical-order check.
func readTarget(reader *reader) (IndexedRelation, []byte, error) {
	start := reader.pos
	tag, err := reader.u8()
	if err != nil {
		return IndexedRelation{}, nil, err
	}
	var relation IndexedRelation
	switch tag {
	case kindObject:
		value, err := reader.hash32()
		if err != nil {
			return IndexedRelation{}, nil, err
		}
		relation = IndexedRelation{Kind: model.RelationObject, Target: model.ObjectTarget(value)}
	case kindNull:
		relation = IndexedRelation{Kind: model.RelationValue, Target: model.ValueTarget(wcb.NullValue())}
	case kindBool:
		flag, err := reader.u8()
		if err != nil {
			return IndexedRelation{}, nil, err
		}
		if flag > 1 {
			return IndexedRelation{}, nil, werr.Newf(werr.Malformed,
				"index boolean target is not 0/1")
		}
		relation = IndexedRelation{Kind: model.RelationValue, Target: model.ValueTarget(wcb.BoolValue(flag == 1))}
	case kindU64:
		number, err := reader.u64()
		if err != nil {
			return IndexedRelation{}, nil, err
		}
		relation = IndexedRelation{Kind: model.RelationValue, Target: model.ValueTarget(wcb.U64Value(number))}
	case kindI64:
		number, err := reader.u64()
		if err != nil {
			return IndexedRelation{}, nil, err
		}
		relation = IndexedRelation{Kind: model.RelationValue, Target: model.ValueTarget(wcb.I64Value(int64(number)))}
	case kindTimestamp:
		number, err := reader.u64()
		if err != nil {
			return IndexedRelation{}, nil, err
		}
		relation = IndexedRelation{Kind: model.RelationValue, Target: model.ValueTarget(wcb.TimestampValue(int64(number)))}
	case kindStr:
		text, err := reader.string()
		if err != nil {
			return IndexedRelation{}, nil, err
		}
		relation = IndexedRelation{Kind: model.RelationValue, Target: model.ValueTarget(wcb.TextValue(text))}
	case kindBytes:
		data, err := reader.bytes()
		if err != nil {
			return IndexedRelation{}, nil, err
		}
		relation = IndexedRelation{Kind: model.RelationValue, Target: model.ValueTarget(wcb.BytesValue(append([]byte(nil), data...)))}
	default:
		return IndexedRelation{}, nil, werr.Newf(werr.Malformed,
			"unknown index relation target tag %d", tag)
	}
	return relation, reader.data[start:reader.pos], nil
}

// ---- bounds-checked reader ----------------------------------------------

type reader struct {
	data []byte
	pos  int
}

func (r *reader) remaining() int { return len(r.data) - r.pos }

func (r *reader) take(length int) ([]byte, error) {
	if length < 0 || r.pos+length > len(r.data) {
		return nil, werr.Newf(werr.Corrupt, "index section is truncated")
	}
	out := r.data[r.pos : r.pos+length]
	r.pos += length
	return out, nil
}

func (r *reader) u8() (byte, error) {
	value, err := r.take(1)
	if err != nil {
		return 0, err
	}
	return value[0], nil
}

func (r *reader) u32() (uint32, error) {
	value, err := r.take(4)
	if err != nil {
		return 0, err
	}
	return uint32(value[0]) | uint32(value[1])<<8 | uint32(value[2])<<16 | uint32(value[3])<<24, nil
}

func (r *reader) u64() (uint64, error) {
	value, err := r.take(8)
	if err != nil {
		return 0, err
	}
	var out uint64
	for i := 7; i >= 0; i-- {
		out = out<<8 | uint64(value[i])
	}
	return out, nil
}

func (r *reader) hash32() (model.Hash32, error) {
	var out model.Hash32
	value, err := r.take(hash.HashLen)
	if err != nil {
		return out, err
	}
	copy(out[:], value)
	return out, nil
}

func (r *reader) bytes() ([]byte, error) {
	length, err := r.u32()
	if err != nil {
		return nil, err
	}
	return r.take(int(length))
}

func (r *reader) string() (string, error) {
	data, err := r.bytes()
	if err != nil {
		return "", err
	}
	if !utf8.Valid(data) {
		return "", werr.Newf(werr.Malformed, "index text is not valid UTF-8")
	}
	return string(data), nil
}

// count reads a u64 header count that must fit an int.
func (r *reader) count(what string) (int, error) {
	value, err := r.u64()
	if err != nil {
		return 0, err
	}
	if value > uint64(maxInt) {
		return 0, werr.Newf(werr.LimitExceeded,
			"%s (%d) does not fit int", what, value)
	}
	return int(value), nil
}

// boundedCount reads a section count after proving the remaining bytes can hold
// that many minimum-size elements, so a corrupt count cannot allocate.
func (r *reader) boundedCount(minElementBytes int) (int, error) {
	count, err := r.u32()
	if err != nil {
		return 0, err
	}
	value := int(count)
	if minElementBytes != 0 && value > r.remaining()/minElementBytes {
		return 0, werr.Newf(werr.Corrupt,
			"index section count exceeds the remaining bytes")
	}
	return value, nil
}

func (r *reader) idSet() (IDSet, error) {
	count, err := r.u32()
	if err != nil {
		return nil, err
	}
	value := int(count)
	if value > r.remaining()/hash.HashLen {
		return nil, werr.Newf(werr.Corrupt,
			"index object-id set count exceeds the remaining bytes")
	}
	out := make(IDSet, value)
	var previous model.Hash32
	for position := 0; position < value; position++ {
		id, err := r.hash32()
		if err != nil {
			return nil, err
		}
		if position > 0 && !previous.Less(id) {
			return nil, werr.Newf(werr.Corrupt,
				"index object-id set is not strictly ascending")
		}
		previous = id
		out[id] = struct{}{}
	}
	return out, nil
}

const maxInt = int(^uint(0) >> 1)
