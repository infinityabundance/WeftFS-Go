package model

import (
	"bytes"

	weftcontext "github.com/infinityabundance/WeftCodec-Go/context"
	"github.com/infinityabundance/WeftCodec-Go/hash"
	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// ObjectKind is the POSIX object class.
type ObjectKind string

const (
	KindFile    ObjectKind = "file"
	KindDir     ObjectKind = "dir"
	KindSymlink ObjectKind = "symlink"
)

// ParseObjectKind validates a kind string.
func ParseObjectKind(s string) (ObjectKind, error) {
	switch ObjectKind(s) {
	case KindFile, KindDir, KindSymlink:
		return ObjectKind(s), nil
	default:
		return "", werr.Newf(werr.Malformed, "unknown object kind `%s`", s)
	}
}

// ObjectRecord is an immutable object record (WEFT-MODEL.md §2.4).
type ObjectRecord struct {
	ID      Hash32
	Kind    ObjectKind
	Mode    uint64
	UID     uint64
	GID     uint64
	MtimeNS int64
	Version Hash32
	// Content root. For files this is the manifest hash; for directories the
	// empty content digest; for symlinks the target-bytes digest.
	Content Hash32
	Size    uint64
	Attrs   map[string]wcb.Value
}

var objectKeys = []string{
	"id", "kind", "mode", "uid", "gid", "mtime_ns", "version", "content", "size", "attrs",
}

// ToWCB returns the canonical map form.
func (r ObjectRecord) ToWCB() wcb.Value {
	return Map(map[string]wcb.Value{
		"id":       HashValue(r.ID),
		"kind":     wcb.TextValue(string(r.Kind)),
		"mode":     wcb.U64Value(r.Mode),
		"uid":      wcb.U64Value(r.UID),
		"gid":      wcb.U64Value(r.GID),
		"mtime_ns": wcb.TimestampValue(r.MtimeNS),
		"version":  HashValue(r.Version),
		"content":  HashValue(r.Content),
		"size":     wcb.U64Value(r.Size),
		"attrs":    wcb.MapValue(CloneAttrs(r.Attrs)),
	})
}

// ObjectFromWCB parses an object record map.
func ObjectFromWCB(v wcb.Value) (ObjectRecord, error) {
	m, err := AsMap(v)
	if err != nil {
		return ObjectRecord{}, err
	}
	return ObjectFromMap(m)
}

// ObjectFromMap parses an object record from a map with exactly the expected
// keys.
func ObjectFromMap(m map[string]wcb.Value) (ObjectRecord, error) {
	if err := CheckKeys(m, objectKeys...); err != nil {
		return ObjectRecord{}, err
	}
	id, err := GetHash(m, "id")
	if err != nil {
		return ObjectRecord{}, err
	}
	kindText, err := GetText(m, "kind")
	if err != nil {
		return ObjectRecord{}, err
	}
	kind, err := ParseObjectKind(kindText)
	if err != nil {
		return ObjectRecord{}, err
	}
	mode, err := GetU64(m, "mode")
	if err != nil {
		return ObjectRecord{}, err
	}
	uid, err := GetU64(m, "uid")
	if err != nil {
		return ObjectRecord{}, err
	}
	gid, err := GetU64(m, "gid")
	if err != nil {
		return ObjectRecord{}, err
	}
	mtime, err := GetTimestamp(m, "mtime_ns")
	if err != nil {
		return ObjectRecord{}, err
	}
	version, err := GetHash(m, "version")
	if err != nil {
		return ObjectRecord{}, err
	}
	content, err := GetHash(m, "content")
	if err != nil {
		return ObjectRecord{}, err
	}
	size, err := GetU64(m, "size")
	if err != nil {
		return ObjectRecord{}, err
	}
	attrs, err := GetMap(m, "attrs")
	if err != nil {
		return ObjectRecord{}, err
	}
	rec := ObjectRecord{
		ID: id, Kind: kind, Mode: mode, UID: uid, GID: gid, MtimeNS: mtime,
		Version: version, Content: content, Size: size, Attrs: attrs,
	}
	if err := ValidateObjectRecord(rec); err != nil {
		return ObjectRecord{}, err
	}
	return rec, nil
}

// Clone deep-copies an object record.
func (r ObjectRecord) Clone() ObjectRecord {
	r.Attrs = CloneAttrs(r.Attrs)
	return r
}

// SymlinkTarget returns the target bytes of a symlink record.
func (r ObjectRecord) SymlinkTarget() ([]byte, bool) {
	v, ok := r.Attrs[AttrSymlinkTarget]
	if !ok || v.Kind != wcb.Bytes {
		return nil, false
	}
	return v.Bytes, true
}

// ValidateObjectRecord enforces the invariants of WEFT-MODEL.md §2.4.
func ValidateObjectRecord(r ObjectRecord) error {
	if _, err := ObjectCausalClosure(r); err != nil {
		return err
	}
	if r.Mode > 0o7777 {
		return werr.Newf(werr.Malformed, "mode must fit POSIX permission bits")
	}
	if r.Kind == KindDir && r.Size != 0 {
		return werr.Newf(werr.Malformed, "directory objects must have size 0")
	}
	if r.Kind == KindSymlink {
		if _, ok := r.Attrs[AttrSymlinkTarget]; !ok {
			return werr.Newf(werr.Malformed, "symlink object is missing weft.symlink.target")
		}
	}
	if value, ok := r.Attrs[AttrACLRead]; ok {
		if value.Kind != wcb.Array {
			return werr.Newf(werr.Malformed, "weft.acl.read must be an array of u64 uid values")
		}
		for _, item := range value.Array {
			if item.Kind != wcb.U64 {
				return werr.Newf(werr.Malformed, "weft.acl.read must be an array of u64 uid values")
			}
		}
	}
	return nil
}

// EntryRecord is a directory entry (WEFT-MODEL.md §2.4).
type EntryRecord struct {
	ID     Hash32
	Parent Hash32
	Name   []byte
	Target Hash32
}

var entryKeys = []string{"id", "parent", "name", "target"}

// DeriveEntryID computes H("weft/entry/v1", WCB({"parent","name"})).
func DeriveEntryID(parent Hash32, name []byte) (Hash32, error) {
	value := Map(map[string]wcb.Value{
		"parent": HashValue(parent),
		"name":   wcb.BytesValue(append([]byte(nil), name...)),
	})
	b, err := EncodeWCB(value)
	if err != nil {
		return Hash32{}, err
	}
	return hashDomain(DomainEntry, b), nil
}

// ToWCB returns the canonical map form.
func (r EntryRecord) ToWCB() wcb.Value {
	return Map(map[string]wcb.Value{
		"id":     HashValue(r.ID),
		"parent": HashValue(r.Parent),
		"name":   wcb.BytesValue(append([]byte(nil), r.Name...)),
		"target": HashValue(r.Target),
	})
}

// EntryFromWCB parses and validates an entry record.
func EntryFromWCB(v wcb.Value) (EntryRecord, error) {
	m, err := AsMap(v)
	if err != nil {
		return EntryRecord{}, err
	}
	return EntryFromMap(m)
}

// EntryFromMap parses an entry record from a map.
func EntryFromMap(m map[string]wcb.Value) (EntryRecord, error) {
	if err := CheckKeys(m, entryKeys...); err != nil {
		return EntryRecord{}, err
	}
	parent, err := GetHash(m, "parent")
	if err != nil {
		return EntryRecord{}, err
	}
	name, err := GetBytes(m, "name")
	if err != nil {
		return EntryRecord{}, err
	}
	expected, err := DeriveEntryID(parent, name)
	if err != nil {
		return EntryRecord{}, err
	}
	id, err := GetHash(m, "id")
	if err != nil {
		return EntryRecord{}, err
	}
	if id != expected {
		return EntryRecord{}, werr.Newf(werr.Corrupt, "entry id does not match (parent,name)")
	}
	target, err := GetHash(m, "target")
	if err != nil {
		return EntryRecord{}, err
	}
	return EntryRecord{ID: id, Parent: parent, Name: name, Target: target}, nil
}

// RelationKind is the target class of an assertion.
type RelationKind string

const (
	RelationObject RelationKind = "object"
	RelationValue  RelationKind = "value"
)

// ParseRelationKind validates a relation kind.
func ParseRelationKind(s string) (RelationKind, error) {
	switch RelationKind(s) {
	case RelationObject, RelationValue:
		return RelationKind(s), nil
	default:
		return "", werr.Newf(werr.Malformed, "unknown relation kind `%s`", s)
	}
}

// RelationTarget is an object edge or a scalar value.
type RelationTarget struct {
	Object *Hash32
	Value  wcb.Value
}

// ObjectTarget builds an object target.
func ObjectTarget(h Hash32) RelationTarget { return RelationTarget{Object: &h} }

// ValueTarget builds a scalar target.
func ValueTarget(v wcb.Value) RelationTarget { return RelationTarget{Value: v} }

// RelationRecord is a relation assertion.
type RelationRecord struct {
	ID         Hash32
	Subject    Hash32
	Predicate  string
	Kind       RelationKind
	Target     RelationTarget
	Provenance map[string]wcb.Value
	Attrs      map[string]wcb.Value
}

var relationKeys = []string{
	"id", "subject", "predicate", "kind", "object", "provenance", "attrs",
}

// DeriveRelationID computes H("weft/relation/v1", WCB(assertion without id)).
func DeriveRelationID(subject Hash32, predicate string, kind RelationKind, target RelationTarget, provenance, attrs map[string]wcb.Value) (Hash32, error) {
	var objectValue wcb.Value
	switch kind {
	case RelationObject:
		if target.Object == nil {
			return Hash32{}, werr.Newf(werr.Malformed, "object relation target is missing")
		}
		objectValue = HashValue(*target.Object)
	case RelationValue:
		if err := ValidateScalar(target.Value); err != nil {
			return Hash32{}, err
		}
		objectValue = CloneValue(target.Value)
	default:
		return Hash32{}, werr.Newf(werr.Malformed, "unknown relation kind `%s`", kind)
	}
	var provValue wcb.Value
	if provenance == nil {
		provValue = wcb.NullValue()
	} else {
		provValue = wcb.MapValue(CloneAttrs(provenance))
	}
	value := Map(map[string]wcb.Value{
		"subject":    HashValue(subject),
		"predicate":  wcb.TextValue(predicate),
		"kind":       wcb.TextValue(string(kind)),
		"object":     objectValue,
		"provenance": provValue,
		"attrs":      wcb.MapValue(CloneAttrs(attrs)),
	})
	b, err := EncodeWCB(value)
	if err != nil {
		return Hash32{}, err
	}
	return hashDomain(DomainRelation, b), nil
}

// NewRelationRecord builds a relation record and derives its identity.
func NewRelationRecord(subject Hash32, predicate string, target RelationTarget, provenance, attrs map[string]wcb.Value) (RelationRecord, error) {
	var kind RelationKind
	if target.Object != nil {
		kind = RelationObject
	} else {
		kind = RelationValue
	}
	id, err := DeriveRelationID(subject, predicate, kind, target, provenance, attrs)
	if err != nil {
		return RelationRecord{}, err
	}
	return RelationRecord{
		ID: id, Subject: subject, Predicate: predicate, Kind: kind, Target: target,
		Provenance: cloneOrNil(provenance), Attrs: CloneAttrs(attrs),
	}, nil
}

func cloneOrNil(m map[string]wcb.Value) map[string]wcb.Value {
	if m == nil {
		return nil
	}
	return CloneAttrs(m)
}

// ToWCB returns the canonical map form.
func (r RelationRecord) ToWCB() wcb.Value {
	var objectValue wcb.Value
	if r.Kind == RelationObject || r.Target.Object != nil {
		if r.Target.Object != nil {
			objectValue = HashValue(*r.Target.Object)
		} else {
			objectValue = wcb.NullValue()
		}
	} else {
		objectValue = CloneValue(r.Target.Value)
	}
	var provValue wcb.Value
	if r.Provenance == nil {
		provValue = wcb.NullValue()
	} else {
		provValue = wcb.MapValue(CloneAttrs(r.Provenance))
	}
	return Map(map[string]wcb.Value{
		"id":         HashValue(r.ID),
		"subject":    HashValue(r.Subject),
		"predicate":  wcb.TextValue(r.Predicate),
		"kind":       wcb.TextValue(string(r.Kind)),
		"object":     objectValue,
		"provenance": provValue,
		"attrs":      wcb.MapValue(CloneAttrs(r.Attrs)),
	})
}

// RelationFromWCB parses and validates a relation record.
func RelationFromWCB(v wcb.Value) (RelationRecord, error) {
	m, err := AsMap(v)
	if err != nil {
		return RelationRecord{}, err
	}
	return RelationFromMap(m)
}

// RelationFromMap parses a relation record from a map.
func RelationFromMap(m map[string]wcb.Value) (RelationRecord, error) {
	if err := CheckKeys(m, relationKeys...); err != nil {
		return RelationRecord{}, err
	}
	subject, err := GetHash(m, "subject")
	if err != nil {
		return RelationRecord{}, err
	}
	predicate, err := GetText(m, "predicate")
	if err != nil {
		return RelationRecord{}, err
	}
	kindText, err := GetText(m, "kind")
	if err != nil {
		return RelationRecord{}, err
	}
	kind, err := ParseRelationKind(kindText)
	if err != nil {
		return RelationRecord{}, err
	}
	var target RelationTarget
	switch kind {
	case RelationObject:
		h, err := GetHash(m, "object")
		if err != nil {
			return RelationRecord{}, err
		}
		target = ObjectTarget(h)
	case RelationValue:
		value, err := Field(m, "object")
		if err != nil {
			return RelationRecord{}, err
		}
		if err := ValidateScalar(value); err != nil {
			return RelationRecord{}, err
		}
		target = ValueTarget(CloneValue(value))
	}
	provenance, err := GetOptMap(m, "provenance")
	if err != nil {
		return RelationRecord{}, err
	}
	attrs, err := GetMap(m, "attrs")
	if err != nil {
		return RelationRecord{}, err
	}
	expected, err := DeriveRelationID(subject, predicate, kind, target, provenance, attrs)
	if err != nil {
		return RelationRecord{}, err
	}
	id, err := GetHash(m, "id")
	if err != nil {
		return RelationRecord{}, err
	}
	if id != expected {
		return RelationRecord{}, werr.Newf(werr.Corrupt, "relation id does not match its assertion")
	}
	return RelationRecord{
		ID: id, Subject: subject, Predicate: predicate, Kind: kind, Target: target,
		Provenance: provenance, Attrs: attrs,
	}, nil
}

// Clone deep-copies a relation record.
func (r RelationRecord) Clone() RelationRecord {
	r.Attrs = CloneAttrs(r.Attrs)
	r.Provenance = cloneOrNil(r.Provenance)
	if r.Target.Object == nil {
		r.Target.Value = CloneValue(r.Target.Value)
	} else {
		h := *r.Target.Object
		r.Target.Object = &h
	}
	return r
}

// DeriveVersionID computes VersionId from the frozen bytes_only version
// record (WEFT-MODEL.md §2.3.1).
func DeriveVersionID(object, content Hash32, size uint64, mtimeNS int64, parent *Hash32) (Hash32, error) {
	return DeriveVersionIDWithIdentity(object, content, size, mtimeNS, parent, weftcontext.BytesOnly, nil)
}

// DeriveVersionIDWithIdentity computes VersionId under an explicit identity
// mode (WEFT-CAUSAL.md §2). BytesOnly emits exactly the frozen v1 record;
// CausalExact adds identity_mode and causal_hash.
func DeriveVersionIDWithIdentity(object, content Hash32, size uint64, mtimeNS int64, parent *Hash32, mode weftcontext.IdentityMode, causalHash *Hash32) (Hash32, error) {
	fields := map[string]wcb.Value{
		"schema":   wcb.TextValue(VersionSchema),
		"object":   HashValue(object),
		"content":  HashValue(content),
		"size":     wcb.U64Value(size),
		"mtime_ns": wcb.TimestampValue(mtimeNS),
		"parent":   OptHashValue(parent),
	}
	switch mode {
	case weftcontext.BytesOnly:
		if causalHash != nil {
			return Hash32{}, werr.Newf(werr.NonCanonical, "bytes_only version record must not carry a causal hash")
		}
	case weftcontext.CausalExact:
		if causalHash == nil || *causalHash == ZeroHash {
			return Hash32{}, werr.Newf(werr.NonCanonical, "causal_exact version record requires a nonzero causal hash")
		}
		fields["identity_mode"] = wcb.TextValue(weftcontext.CausalExact.String())
		fields["causal_hash"] = HashValue(*causalHash)
	default:
		return Hash32{}, werr.Newf(werr.Unsupported, "unknown identity mode")
	}
	b, err := EncodeWCB(Map(fields))
	if err != nil {
		return Hash32{}, err
	}
	return VersionIDBytes(b), nil
}

// causalHashesFromAttr parses a reserved causal array attribute.
func causalHashesFromAttr(value wcb.Value, what string) ([]Hash32, error) {
	if value.Kind != wcb.Array {
		return nil, werr.Newf(werr.Malformed, "%s must be an array of bytes32", what)
	}
	out := make([]Hash32, 0, len(value.Array))
	for _, item := range value.Array {
		if item.Kind != wcb.Bytes || len(item.Bytes) != hash.HashLen {
			return nil, werr.Newf(werr.Malformed, "%s must contain bytes32", what)
		}
		h, err := hash.FromSlice(item.Bytes)
		if err != nil {
			return nil, werr.Newf(werr.Malformed, "%s contains an invalid hash", what)
		}
		if h == ZeroHash {
			return nil, werr.Newf(werr.Malformed, "%s must not contain the zero hash", what)
		}
		out = append(out, h)
	}
	return out, nil
}

// ObjectCausalClosure extracts and validates the causal closure stored on an
// object record. A partial or inconsistent set is Corrupt.
func ObjectCausalClosure(record ObjectRecord) (*weftcontext.CausalClosure, error) {
	parentsValue, hasParents := record.Attrs[AttrCausalParents]
	closureValue, hasClosure := record.Attrs[AttrCausalClosure]
	hashValue, hasHash := record.Attrs[AttrCausalHash]
	modeValue, hasMode := record.Attrs[AttrIdentityMode]
	if !hasParents && !hasClosure && !hasHash && !hasMode {
		return nil, nil
	}
	if !hasParents || !hasClosure || !hasHash {
		return nil, werr.Newf(werr.Corrupt, "partial causal attributes: parents, closure, and hash are all required")
	}
	parents, err := causalHashesFromAttr(parentsValue, AttrCausalParents)
	if err != nil {
		return nil, err
	}
	closure, err := causalHashesFromAttr(closureValue, AttrCausalClosure)
	if err != nil {
		return nil, err
	}
	if hashValue.Kind != wcb.Bytes || len(hashValue.Bytes) != hash.HashLen {
		return nil, werr.Newf(werr.Corrupt, "weft.causal.hash must be bytes32")
	}
	recordHash, err := hash.FromSlice(hashValue.Bytes)
	if err != nil || recordHash == ZeroHash {
		return nil, werr.Newf(werr.Corrupt, "weft.causal.hash is invalid")
	}
	closureRecord, err := weftcontext.NewCausalClosure(parents, closure)
	if err != nil {
		return nil, werr.FromCodec(err)
	}
	id, err := closureRecord.ID()
	if err != nil {
		return nil, werr.FromCodec(err)
	}
	if id != recordHash {
		return nil, werr.Newf(werr.Corrupt, "weft.causal.hash does not match the recorded closure")
	}
	if hasMode {
		if modeValue.Kind != wcb.Text {
			return nil, werr.Newf(werr.Corrupt, "weft.identity.mode must be text")
		}
		mode, err := weftcontext.ParseIdentityMode(modeValue.Str)
		if err != nil {
			return nil, werr.FromCodec(err)
		}
		if mode != weftcontext.CausalExact {
			return nil, werr.Newf(werr.NonCanonical, "bytes_only must be the absence of weft.identity.mode")
		}
	}
	return closureRecord, nil
}

// IdentityFromAttrs returns the identity mode and causal hash implied by an
// object's reserved attrs.
func IdentityFromAttrs(record ObjectRecord) (weftcontext.IdentityMode, *Hash32, error) {
	closure, err := ObjectCausalClosure(record)
	if err != nil {
		return weftcontext.BytesOnly, nil, err
	}
	if closure == nil {
		return weftcontext.BytesOnly, nil, nil
	}
	id, err := closure.ID()
	if err != nil {
		return weftcontext.BytesOnly, nil, werr.FromCodec(err)
	}
	return weftcontext.CausalExact, &id, nil
}

// ApplyCausalAttrs attaches canonical causal attributes to an attribute map.
func ApplyCausalAttrs(attrs map[string]wcb.Value, closure *weftcontext.CausalClosure, mode weftcontext.IdentityMode, causalHash Hash32) {
	parents := make([]wcb.Value, 0, len(closure.Parents))
	for _, item := range closure.Parents {
		parents = append(parents, wcb.BytesValue(append([]byte(nil), item[:]...)))
	}
	closureValues := make([]wcb.Value, 0, len(closure.Closure))
	for _, item := range closure.Closure {
		closureValues = append(closureValues, wcb.BytesValue(append([]byte(nil), item[:]...)))
	}
	attrs[AttrCausalParents] = wcb.ArrayValue(parents)
	attrs[AttrCausalClosure] = wcb.ArrayValue(closureValues)
	attrs[AttrCausalHash] = wcb.BytesValue(append([]byte(nil), causalHash[:]...))
	if mode == weftcontext.CausalExact {
		attrs[AttrIdentityMode] = wcb.TextValue(weftcontext.CausalExact.String())
	} else {
		delete(attrs, AttrIdentityMode)
	}
}

// ValidateNameBytes rejects names that cannot be a single POSIX component.
func ValidateNameBytes(name []byte) error {
	if len(name) == 0 {
		return werr.Newf(werr.InvalidName, "name must not be empty")
	}
	if len(name) > MaxNameBytes {
		return werr.Newf(werr.InvalidName, "name exceeds 255 bytes")
	}
	if bytes.IndexByte(name, 0) >= 0 {
		return werr.Newf(werr.InvalidName, "name must not contain NUL")
	}
	if bytes.IndexByte(name, '/') >= 0 {
		return werr.Newf(werr.InvalidName, "name must not contain '/'")
	}
	if string(name) == "." || string(name) == ".." {
		return werr.Newf(werr.InvalidName, "'.' and '..' are reserved")
	}
	return nil
}

// ValidateSnapshotName validates a snapshot name.
func ValidateSnapshotName(name string) error {
	if name == "" {
		return werr.Newf(werr.InvalidName, "snapshot name must not be empty")
	}
	if len(name) > 255 {
		return werr.Newf(werr.InvalidName, "snapshot name exceeds 255 bytes")
	}
	if bytes.IndexByte([]byte(name), 0) >= 0 || bytes.IndexByte([]byte(name), '/') >= 0 {
		return werr.Newf(werr.InvalidName, "snapshot name must not contain NUL or '/'")
	}
	if name == "." || name == ".." {
		return werr.Newf(werr.InvalidName, "'.' and '..' are reserved")
	}
	return nil
}

// hashDomain is the single v1 hash construction.
func hashDomain(domain string, data []byte) Hash32 {
	return hash.Domain(domain, data)
}
