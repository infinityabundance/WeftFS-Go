package model

import (
	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// Op is one commit operation (WEFT-MODEL.md §2.2). Concrete op types are
// values; a nil Op is invalid.
type Op interface {
	// Name is the canonical `op` discriminator.
	Name() string
	// ToWCB returns the canonical map, including the `op` key.
	ToWCB() wcb.Value
	// apply mutates state, validating the whole op.
	apply(s *State) error
}

// PutObjectOp stores an object record.
type PutObjectOp struct{ Record ObjectRecord }

// DeleteObjectOp removes an object record.
type DeleteObjectOp struct{ ID Hash32 }

// PutEntryOp stores a directory entry.
type PutEntryOp struct{ Record EntryRecord }

// DelEntryOp removes a directory entry.
type DelEntryOp struct{ ID Hash32 }

// PutRelationOp stores a relation assertion.
type PutRelationOp struct{ Record RelationRecord }

// DelRelationOp removes a relation assertion.
type DelRelationOp struct{ ID Hash32 }

// SetSnapshotOp binds a name to a commit hash.
type SetSnapshotOp struct {
	SnapshotName string
	Commit       Hash32
}

// SetTipOp records the current version of an object.
type SetTipOp struct {
	Object  Hash32
	Version Hash32
}

func (PutObjectOp) Name() string    { return "put_object" }
func (DeleteObjectOp) Name() string { return "delete_object" }
func (PutEntryOp) Name() string     { return "put_entry" }
func (DelEntryOp) Name() string     { return "del_entry" }
func (PutRelationOp) Name() string  { return "put_relation" }
func (DelRelationOp) Name() string  { return "del_relation" }
func (SetSnapshotOp) Name() string  { return "set_snapshot" }
func (SetTipOp) Name() string       { return "set_tip" }

// ToWCB encodes an op exactly as the Rust reference does: the record map with
// the `op` key inserted, then canonical WCB ordering.
func (o PutObjectOp) ToWCB() wcb.Value {
	return withOp(o.Record.ToWCB(), o.Name())
}

func (o DeleteObjectOp) ToWCB() wcb.Value {
	return Map(map[string]wcb.Value{"op": wcb.TextValue(o.Name()), "id": HashValue(o.ID)})
}

func (o PutEntryOp) ToWCB() wcb.Value {
	return withOp(o.Record.ToWCB(), o.Name())
}

func (o DelEntryOp) ToWCB() wcb.Value {
	return Map(map[string]wcb.Value{"op": wcb.TextValue(o.Name()), "id": HashValue(o.ID)})
}

func (o PutRelationOp) ToWCB() wcb.Value {
	return withOp(o.Record.ToWCB(), o.Name())
}

func (o DelRelationOp) ToWCB() wcb.Value {
	return Map(map[string]wcb.Value{"op": wcb.TextValue(o.Name()), "id": HashValue(o.ID)})
}

func (o SetSnapshotOp) ToWCB() wcb.Value {
	return Map(map[string]wcb.Value{
		"op":     wcb.TextValue(o.Name()),
		"name":   wcb.TextValue(o.SnapshotName),
		"commit": HashValue(o.Commit),
	})
}

func (o SetTipOp) ToWCB() wcb.Value {
	return Map(map[string]wcb.Value{
		"op":      wcb.TextValue(o.Name()),
		"object":  HashValue(o.Object),
		"version": HashValue(o.Version),
	})
}

func withOp(v wcb.Value, op string) wcb.Value {
	m, _ := AsMap(v)
	out := make(map[string]wcb.Value, len(m)+1)
	for k, val := range m {
		out[k] = CloneValue(val)
	}
	out["op"] = wcb.TextValue(op)
	return Map(out)
}

// OpFromWCB parses one commit op.
func OpFromWCB(v wcb.Value) (Op, error) {
	m, err := AsMap(v)
	if err != nil {
		return nil, err
	}
	name, err := GetText(m, "op")
	if err != nil {
		return nil, err
	}
	without := make(map[string]wcb.Value, len(m)-1)
	for k, val := range m {
		if k != "op" {
			without[k] = val
		}
	}
	switch name {
	case "put_object":
		rec, err := ObjectFromMap(without)
		if err != nil {
			return nil, err
		}
		return PutObjectOp{Record: rec}, nil
	case "delete_object":
		if err := CheckKeys(without, "id"); err != nil {
			return nil, err
		}
		id, err := GetHash(without, "id")
		if err != nil {
			return nil, err
		}
		return DeleteObjectOp{ID: id}, nil
	case "put_entry":
		rec, err := EntryFromMap(without)
		if err != nil {
			return nil, err
		}
		return PutEntryOp{Record: rec}, nil
	case "del_entry":
		if err := CheckKeys(without, "id"); err != nil {
			return nil, err
		}
		id, err := GetHash(without, "id")
		if err != nil {
			return nil, err
		}
		return DelEntryOp{ID: id}, nil
	case "put_relation":
		rec, err := RelationFromMap(without)
		if err != nil {
			return nil, err
		}
		return PutRelationOp{Record: rec}, nil
	case "del_relation":
		if err := CheckKeys(without, "id"); err != nil {
			return nil, err
		}
		id, err := GetHash(without, "id")
		if err != nil {
			return nil, err
		}
		return DelRelationOp{ID: id}, nil
	case "set_snapshot":
		if err := CheckKeys(without, "name", "commit"); err != nil {
			return nil, err
		}
		name, err := GetText(without, "name")
		if err != nil {
			return nil, err
		}
		commit, err := GetHash(without, "commit")
		if err != nil {
			return nil, err
		}
		return SetSnapshotOp{SnapshotName: name, Commit: commit}, nil
	case "set_tip":
		if err := CheckKeys(without, "object", "version"); err != nil {
			return nil, err
		}
		object, err := GetHash(without, "object")
		if err != nil {
			return nil, err
		}
		version, err := GetHash(without, "version")
		if err != nil {
			return nil, err
		}
		return SetTipOp{Object: object, Version: version}, nil
	case "set_quota_usage":
		return setQuotaUsageFromMap(without)
	default:
		return nil, werr.Newf(werr.Malformed, "unknown commit op `%s`", name)
	}
}
