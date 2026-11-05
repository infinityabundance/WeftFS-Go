package model

import (
	"bytes"
	"sort"
	"strconv"

	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// State is the complete replayed namespace state.
type State struct {
	Generation uint64
	Objects    map[Hash32]ObjectRecord
	Entries    map[Hash32]EntryRecord
	Relations  map[Hash32]RelationRecord
	Snapshots  map[string]Hash32
	Tips       map[Hash32]Hash32
}

// RootID is the namespace root object id (32 zero bytes).
var RootID = ZeroHash

// NewState returns an empty state.
func NewState() *State {
	return &State{
		Objects:   make(map[Hash32]ObjectRecord),
		Entries:   make(map[Hash32]EntryRecord),
		Relations: make(map[Hash32]RelationRecord),
		Snapshots: make(map[string]Hash32),
		Tips:      make(map[Hash32]Hash32),
	}
}

// Clone deep-copies the state.
func (s *State) Clone() *State {
	out := &State{
		Generation: s.Generation,
		Objects:    make(map[Hash32]ObjectRecord, len(s.Objects)),
		Entries:    make(map[Hash32]EntryRecord, len(s.Entries)),
		Relations:  make(map[Hash32]RelationRecord, len(s.Relations)),
		Snapshots:  make(map[string]Hash32, len(s.Snapshots)),
		Tips:       make(map[Hash32]Hash32, len(s.Tips)),
	}
	for k, v := range s.Objects {
		out.Objects[k] = v.Clone()
	}
	for k, v := range s.Entries {
		v.Name = append([]byte(nil), v.Name...)
		out.Entries[k] = v
	}
	for k, v := range s.Relations {
		out.Relations[k] = v.Clone()
	}
	for k, v := range s.Snapshots {
		out.Snapshots[k] = v
	}
	for k, v := range s.Tips {
		out.Tips[k] = v
	}
	return out
}

// ApplyOps applies a list atomically: all or nothing.
func (s *State) ApplyOps(ops []Op) error {
	// `set_quota_usage` describes the state after the other ops, so it must be
	// last; a reset must stand alone.
	usageSeen := false
	for i, op := range ops {
		usage, ok := op.(SetQuotaUsageOp)
		if !ok {
			continue
		}
		if usageSeen {
			return werr.Newf(werr.Malformed, "a commit may contain at most one set_quota_usage op")
		}
		usageSeen = true
		if i+1 != len(ops) {
			return werr.Newf(werr.Malformed, "set_quota_usage must be the last op in its commit")
		}
		if usage.Reset && len(ops) != 1 {
			return werr.Newf(werr.Malformed, "a quota usage reset must be the only op in its commit")
		}
	}
	next := s.Clone()
	for _, op := range ops {
		if op == nil {
			return werr.Newf(werr.Malformed, "nil commit op")
		}
		if err := op.apply(next); err != nil {
			return err
		}
	}
	*s = *next
	return nil
}

func (o PutObjectOp) apply(s *State) error {
	if err := ValidateObjectRecord(o.Record); err != nil {
		return err
	}
	s.Objects[o.Record.ID] = o.Record.Clone()
	return nil
}

func (o DeleteObjectOp) apply(s *State) error {
	if o.ID == RootID {
		return werr.Newf(werr.Malformed, "cannot delete the namespace root")
	}
	if _, ok := s.Objects[o.ID]; !ok {
		return werr.Newf(werr.Malformed, "delete_object for a missing object")
	}
	for _, entry := range s.Entries {
		if entry.Target == o.ID {
			return werr.Newf(werr.Malformed, "delete_object while a directory entry still targets it")
		}
		if entry.Parent == o.ID {
			return werr.Newf(werr.Malformed, "delete_object while it is still an entry parent")
		}
	}
	delete(s.Objects, o.ID)
	delete(s.Tips, o.ID)
	return nil
}

func (o PutEntryOp) apply(s *State) error {
	rec := o.Record
	if err := ValidateNameBytes(rec.Name); err != nil {
		return err
	}
	expected, err := DeriveEntryID(rec.Parent, rec.Name)
	if err != nil {
		return err
	}
	if expected != rec.ID {
		return werr.Newf(werr.Corrupt, "put_entry id does not match (parent,name)")
	}
	parent, ok := s.Objects[rec.Parent]
	if !ok {
		return werr.Newf(werr.Malformed, "put_entry parent does not exist")
	}
	if parent.Kind != KindDir {
		return werr.Newf(werr.Malformed, "put_entry parent is not a directory")
	}
	if _, ok := s.Objects[rec.Target]; !ok {
		return werr.Newf(werr.Malformed, "put_entry target does not exist")
	}
	if existing, ok := s.Entries[rec.ID]; ok {
		if !entryEqual(existing, rec) {
			return werr.Newf(werr.Malformed, "put_entry would duplicate an existing (parent,name)")
		}
		return nil
	}
	rec.Name = append([]byte(nil), rec.Name...)
	s.Entries[rec.ID] = rec
	return nil
}

func (o DelEntryOp) apply(s *State) error {
	if _, ok := s.Entries[o.ID]; !ok {
		return werr.Newf(werr.Malformed, "del_entry for a missing entry")
	}
	delete(s.Entries, o.ID)
	return nil
}

func (o PutRelationOp) apply(s *State) error {
	rec := o.Record
	expected, err := DeriveRelationID(rec.Subject, rec.Predicate, rec.Kind, rec.Target, rec.Provenance, rec.Attrs)
	if err != nil {
		return err
	}
	if expected != rec.ID {
		return werr.Newf(werr.Corrupt, "put_relation id does not match assertion")
	}
	if existing, ok := s.Relations[rec.ID]; ok {
		if !relationEqual(existing, rec) {
			return werr.Newf(werr.Malformed, "put_relation would replace a different assertion with the same id")
		}
		return nil
	}
	s.Relations[rec.ID] = rec.Clone()
	return nil
}

func (o DelRelationOp) apply(s *State) error {
	if _, ok := s.Relations[o.ID]; !ok {
		return werr.Newf(werr.Malformed, "del_relation for a missing relation")
	}
	delete(s.Relations, o.ID)
	return nil
}

func (o SetSnapshotOp) apply(s *State) error {
	if err := ValidateSnapshotName(o.SnapshotName); err != nil {
		return err
	}
	if o.Commit == ZeroHash {
		return werr.Newf(werr.Malformed, "snapshot points at the zero hash")
	}
	s.Snapshots[o.SnapshotName] = o.Commit
	return nil
}

func (o SetTipOp) apply(s *State) error {
	if _, ok := s.Objects[o.Object]; !ok {
		return werr.Newf(werr.Malformed, "set_tip for a missing object")
	}
	s.Tips[o.Object] = o.Version
	return nil
}

// Lookup returns the target of (parent,name).
func (s *State) Lookup(parent Hash32, name []byte) (Hash32, error) {
	id, err := DeriveEntryID(parent, name)
	if err != nil {
		return Hash32{}, err
	}
	entry, ok := s.Entries[id]
	if !ok {
		return Hash32{}, werr.Newf(werr.NotFound, "no such directory entry")
	}
	return entry.Target, nil
}

// ListDir returns entries with the given parent sorted by unsigned byte name.
func (s *State) ListDir(parent Hash32) ([]EntryRecord, error) {
	object, ok := s.Objects[parent]
	if !ok {
		return nil, werr.Newf(werr.NotFound, "no such parent object")
	}
	if object.Kind != KindDir {
		return nil, werr.Newf(werr.NotDir, "object is not a directory")
	}
	out := make([]EntryRecord, 0)
	for _, entry := range s.Entries {
		if entry.Parent == parent {
			entry.Name = append([]byte(nil), entry.Name...)
			out = append(out, entry)
		}
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].Name, out[j].Name) < 0 })
	return out, nil
}

// EntriesFor returns all entries pointing at target, sorted by (parent,name).
func (s *State) EntriesFor(target Hash32) []EntryRecord {
	out := make([]EntryRecord, 0)
	for _, entry := range s.Entries {
		if entry.Target == target {
			entry.Name = append([]byte(nil), entry.Name...)
			out = append(out, entry)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if c := bytes.Compare(out[i].Parent[:], out[j].Parent[:]); c != 0 {
			return c < 0
		}
		return bytes.Compare(out[i].Name, out[j].Name) < 0
	})
	return out
}

// PathFor returns the lexicographically first path for an object, if any.
func (s *State) PathFor(target Hash32) ([]byte, bool) {
	if target == RootID {
		return []byte("/"), true
	}
	entries := s.EntriesFor(target)
	if len(entries) == 0 {
		return nil, false
	}
	entry := entries[0]
	components := [][]byte{append([]byte(nil), entry.Name...)}
	current := entry.Parent
	visited := make(map[Hash32]bool)
	for current != RootID {
		if visited[current] {
			return nil, false
		}
		visited[current] = true
		parents := s.EntriesFor(current)
		if len(parents) == 0 {
			return nil, false
		}
		components = append(components, append([]byte(nil), parents[0].Name...))
		current = parents[0].Parent
	}
	var path []byte
	for i := len(components) - 1; i >= 0; i-- {
		path = append(path, '/')
		path = append(path, components[i]...)
	}
	return path, true
}

// NLink returns the POSIX link count of an object.
func (s *State) NLink(id Hash32) uint64 {
	record, ok := s.Objects[id]
	if !ok {
		return 0
	}
	if record.Kind == KindDir {
		var subdirs uint64
		for _, entry := range s.Entries {
			if entry.Parent != id {
				continue
			}
			if child, ok := s.Objects[entry.Target]; ok && child.Kind == KindDir {
				subdirs++
			}
		}
		return 2 + subdirs
	}
	var links uint64
	for _, entry := range s.Entries {
		if entry.Target == id {
			links++
		}
	}
	return links
}

// IsWithin reports whether node is ancestor or a descendant of it.
func (s *State) IsWithin(ancestor, node Hash32) bool {
	current := node
	visited := make(map[Hash32]bool)
	for {
		if current == ancestor {
			return true
		}
		if visited[current] {
			return false
		}
		visited[current] = true
		parents := s.EntriesFor(current)
		if len(parents) == 0 {
			return false
		}
		current = parents[0].Parent
	}
}

// ---- canonical checkpoint encoding --------------------------------------

// StateToWCB returns the state manifest map for `generation`.
func StateToWCB(s *State, generation uint64) wcb.Value {
	objectIDs := SortHashKeys(s.Objects)
	objects := make([]wcb.Value, 0, len(objectIDs))
	for _, id := range objectIDs {
		objects = append(objects, s.Objects[id].ToWCB())
	}

	entries := make([]EntryRecord, 0, len(s.Entries))
	for _, entry := range s.Entries {
		entry.Name = append([]byte(nil), entry.Name...)
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		if c := bytes.Compare(entries[i].Parent[:], entries[j].Parent[:]); c != 0 {
			return c < 0
		}
		return bytes.Compare(entries[i].Name, entries[j].Name) < 0
	})
	entryValues := make([]wcb.Value, 0, len(entries))
	for _, entry := range entries {
		entryValues = append(entryValues, entry.ToWCB())
	}

	relationIDs := SortHashKeys(s.Relations)
	relations := make([]wcb.Value, 0, len(relationIDs))
	for _, id := range relationIDs {
		relations = append(relations, s.Relations[id].ToWCB())
	}

	snapshots := make(map[string]wcb.Value, len(s.Snapshots))
	for name, hash := range s.Snapshots {
		snapshots[name] = HashValue(hash)
	}
	tips := make(map[string]wcb.Value, len(s.Tips))
	for object, version := range s.Tips {
		tips[object.Hex()] = HashValue(version)
	}

	return Map(map[string]wcb.Value{
		"schema":     wcb.TextValue(StateSchema),
		"generation": wcb.U64Value(generation),
		"objects":    wcb.ArrayValue(objects),
		"entries":    wcb.ArrayValue(entryValues),
		"relations":  wcb.ArrayValue(relations),
		"snapshots":  wcb.MapValue(snapshots),
		"tips":       wcb.MapValue(tips),
	})
}

// EncodeState returns canonical WCB bytes of a checkpoint state manifest.
func EncodeState(s *State, generation uint64) ([]byte, error) {
	return EncodeWCB(StateToWCB(s, generation))
}

// DecodeState parses a checkpoint state manifest. Structural problems are
// Malformed; identity mismatches are Corrupt.
func DecodeState(v wcb.Value) (*State, error) {
	m, err := AsMap(v)
	if err != nil {
		return nil, err
	}
	if err := CheckKeys(m, "schema", "generation", "objects", "entries", "relations", "snapshots", "tips"); err != nil {
		return nil, err
	}
	schema, err := GetText(m, "schema")
	if err != nil {
		return nil, err
	}
	if schema != StateSchema {
		return nil, werr.Newf(werr.UnknownSchema, "state manifest schema `%s` is not `%s`", schema, StateSchema)
	}
	generation, err := GetU64(m, "generation")
	if err != nil {
		return nil, err
	}
	state := NewState()
	state.Generation = generation

	objectValues, err := GetArray(m, "objects")
	if err != nil {
		return nil, err
	}
	for _, item := range objectValues {
		rec, err := ObjectFromWCB(item)
		if err != nil {
			return nil, err
		}
		if _, exists := state.Objects[rec.ID]; exists {
			return nil, werr.Newf(werr.Malformed, "duplicate object id in state manifest")
		}
		state.Objects[rec.ID] = rec
	}

	entryValues, err := GetArray(m, "entries")
	if err != nil {
		return nil, err
	}
	for _, item := range entryValues {
		rec, err := EntryFromWCB(item)
		if err != nil {
			return nil, err
		}
		if _, exists := state.Entries[rec.ID]; exists {
			return nil, werr.Newf(werr.Malformed, "duplicate entry id in state manifest")
		}
		state.Entries[rec.ID] = rec
	}

	relationValues, err := GetArray(m, "relations")
	if err != nil {
		return nil, err
	}
	for _, item := range relationValues {
		rec, err := RelationFromWCB(item)
		if err != nil {
			return nil, err
		}
		if _, exists := state.Relations[rec.ID]; exists {
			return nil, werr.Newf(werr.Malformed, "duplicate relation id in state manifest")
		}
		state.Relations[rec.ID] = rec
	}

	snapshotMap, err := GetMap(m, "snapshots")
	if err != nil {
		return nil, err
	}
	for name, value := range snapshotMap {
		if value.Kind != wcb.Bytes || len(value.Bytes) != 32 {
			return nil, werr.Newf(werr.Corrupt, "snapshot hash must be 32 bytes")
		}
		h, _ := hashFromSlice(value.Bytes)
		if h == ZeroHash {
			return nil, werr.Newf(werr.Corrupt, "snapshot points at the zero hash")
		}
		state.Snapshots[name] = h
	}

	tipMap, err := GetMap(m, "tips")
	if err != nil {
		return nil, err
	}
	for key, value := range tipMap {
		h, err := parseHexHash(key)
		if err != nil {
			return nil, werr.Newf(werr.Corrupt, "tip key must be a 32-byte hex object id")
		}
		if h.Hex() != key {
			return nil, werr.Newf(werr.Corrupt, "tip key must be lowercase hex")
		}
		if value.Kind != wcb.Bytes || len(value.Bytes) != 32 {
			return nil, werr.Newf(werr.Corrupt, "tip version must be 32 bytes")
		}
		version, _ := hashFromSlice(value.Bytes)
		state.Tips[h] = version
	}
	return state, nil
}

func parseHexHash(s string) (Hash32, error) {
	var h Hash32
	if len(s) != 64 {
		return h, werr.Newf(werr.Corrupt, "hash hex must be 64 characters")
	}
	for i := 0; i < 32; i++ {
		hi, ok1 := hexNibble(s[i*2])
		lo, ok2 := hexNibble(s[i*2+1])
		if !ok1 || !ok2 {
			return h, werr.Newf(werr.Corrupt, "invalid hex digit")
		}
		h[i] = hi<<4 | lo
	}
	return h, nil
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

// ---- equality helpers ----------------------------------------------------

func wcbEqual(a, b wcb.Value) bool {
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case wcb.Null:
		return true
	case wcb.Bool:
		return a.Bool == b.Bool
	case wcb.U64:
		return a.U == b.U
	case wcb.I64, wcb.Timestamp:
		return a.I == b.I
	case wcb.Text:
		return a.Str == b.Str
	case wcb.Bytes:
		return bytes.Equal(a.Bytes, b.Bytes)
	case wcb.Array:
		if len(a.Array) != len(b.Array) {
			return false
		}
		for i := range a.Array {
			if !wcbEqual(a.Array[i], b.Array[i]) {
				return false
			}
		}
		return true
	case wcb.Map:
		if len(a.Map) != len(b.Map) {
			return false
		}
		for k, av := range a.Map {
			bv, ok := b.Map[k]
			if !ok || !wcbEqual(av, bv) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func attrsEqual(a, b map[string]wcb.Value) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok || !wcbEqual(av, bv) {
			return false
		}
	}
	return true
}

func entryEqual(a, b EntryRecord) bool {
	return a.ID == b.ID && a.Parent == b.Parent && a.Target == b.Target &&
		bytes.Equal(a.Name, b.Name)
}

func relationEqual(a, b RelationRecord) bool {
	if a.ID != b.ID || a.Subject != b.Subject || a.Predicate != b.Predicate ||
		a.Kind != b.Kind {
		return false
	}
	if (a.Target.Object == nil) != (b.Target.Object == nil) {
		return false
	}
	if a.Target.Object != nil {
		if *a.Target.Object != *b.Target.Object {
			return false
		}
	} else if !wcbEqual(a.Target.Value, b.Target.Value) {
		return false
	}
	return attrsEqual(a.Attrs, b.Attrs) && attrsEqual(a.Provenance, b.Provenance)
}

// FormatU64 renders an unsigned integer for diagnostics.
func FormatU64(v uint64) string { return strconv.FormatUint(v, 10) }
