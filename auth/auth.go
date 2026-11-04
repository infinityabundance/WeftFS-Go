// Package auth implements the v1 POSIX-style authorization predicate
// (WEFT-MODEL.md §6). A principal is (uid, gid, supplementary groups). Read
// access requires the POSIX read bit for the matching class and, when
// attrs["weft.acl.read"] exists, the principal's uid must appear in that
// array. uid 0 is not special; mount-level root behavior is a FUSE policy.
package auth

import (
	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/model"
)

// Principal is a caller identity supplied by the kernel or by tests.
type Principal struct {
	UID    uint64
	GID    uint64
	Groups []uint64
}

// New builds a principal.
func New(uid, gid uint64, groups []uint64) Principal {
	return Principal{UID: uid, GID: gid, Groups: append([]uint64(nil), groups...)}
}

// Root is a principal that owns everything created with uid/gid 0.
func Root() Principal { return Principal{UID: 0, GID: 0} }

func (p Principal) inGroup(gid uint64) bool {
	if p.GID == gid {
		return true
	}
	for _, g := range p.Groups {
		if g == gid {
			return true
		}
	}
	return false
}

// EffectiveMode returns the permission bits (4 read, 2 write, 1 execute)
// applicable to this principal.
func EffectiveMode(object model.ObjectRecord, principal Principal) uint64 {
	switch {
	case principal.UID == object.UID:
		return (object.Mode >> 6) & 0o7
	case principal.inGroup(object.GID):
		return (object.Mode >> 3) & 0o7
	default:
		return object.Mode & 0o7
	}
}

// ACLAllows is the ACL predicate. A malformed weft.acl.read value denies
// (fail closed).
func ACLAllows(object model.ObjectRecord, principal Principal) bool {
	value, ok := object.Attrs[model.AttrACLRead]
	if !ok {
		return true
	}
	if value.Kind != wcb.Array {
		return false
	}
	for _, item := range value.Array {
		if item.Kind == wcb.U64 && item.U == principal.UID {
			return true
		}
	}
	return false
}

// CanRead reports whether the principal may read the object.
func CanRead(object model.ObjectRecord, principal Principal) bool {
	return EffectiveMode(object, principal)&0o4 != 0 && ACLAllows(object, principal)
}

// CanTraverse reports whether the principal may traverse the directory.
func CanTraverse(object model.ObjectRecord, principal Principal) bool {
	return EffectiveMode(object, principal)&0o1 != 0
}

// CanWrite reports whether the principal may write the object.
func CanWrite(object model.ObjectRecord, principal Principal) bool {
	return EffectiveMode(object, principal)&0o2 != 0 && ACLAllows(object, principal)
}

// RelationVisible reports whether a relation is visible: the subject must be
// readable and, for object targets, the target must be visible. Callers pass
// false for a missing or unauthorized target object.
func RelationVisible(subject *model.ObjectRecord, targetVisible bool, principal Principal) bool {
	if subject == nil {
		return false
	}
	return CanRead(*subject, principal) && targetVisible
}
