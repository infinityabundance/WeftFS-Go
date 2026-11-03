// Package model defines the WeftFS v1 entities, canonical records, commit ops,
// and in-memory state. Byte layouts follow spec/WEFT-MODEL.md and
// WEFTCODEC-FORMAT.md §8 (WCB). There is no language-specific serialization on
// the persistent path: every record is a canonical WCB map.
package model

import (
	"github.com/infinityabundance/WeftCodec-Go/hash"
)

// Hash32 is a 32-byte Weft identity.
type Hash32 = hash.Hash32

// ZeroHash is the all-zero digest.
var ZeroHash = hash.Zero

// Domain strings used by WeftFS records. The codec domains live in
// WeftCodec-Go/hash; the entry domain is store-specific and normative in
// WEFT-MODEL.md §2.3.1.
const (
	DomainChunk    = hash.DomainChunk
	DomainManifest = hash.DomainManifest
	DomainVersion  = hash.DomainVersion
	DomainCommit   = hash.DomainCommit
	DomainRelation = hash.DomainRelation
	DomainObject   = hash.DomainObject
	DomainSelector = hash.DomainSelector
	DomainSnapshot = hash.DomainSnapshot
	DomainEntry    = "weft/entry/v1"
)

// Namespace used by v1.
const DefaultNamespace = "default"

// Format and schema constants (WEFT-MODEL.md §2).
const (
	FormatContents   = "weftfs-store 1\n"
	SuperblockBytes  = 8192
	SlotBytes        = 4096
	FormatMajor      = 1
	FormatMinor      = 0
	CommitSchema     = "weftfs.commit.v1"
	ManifestSchema   = "weft.manifest.v1"
	StateSchema      = "weftfs.state.v1"
	VersionSchema    = "weftfs.version.v1"
	LegacyManifest   = "weftfs.manifest.v1"
	MaxNameBytes     = 255
	MaxChunkSize     = 16 * 1024 * 1024
	DefaultChunkSize = 65536
)

// Reserved attribute keys and predicates (WEFT-MODEL.md §2.5).
const (
	AttrSymlinkTarget = "weft.symlink.target"
	AttrACLRead       = "weft.acl.read"
	SavedContextPred  = "saved_context"
	SavedContextAttr  = "selector_hex"
	XattrPrefix       = "xattr."
)

// ObjectIDFromSeed returns H("weft/object/v1", seed).
func ObjectIDFromSeed(seed []byte) Hash32 {
	return hash.Domain(DomainObject, seed)
}

// ContentHash returns H("weft/chunk/v1", bytes), the whole-content digest.
func ContentHash(b []byte) Hash32 {
	return hash.Domain(DomainChunk, b)
}

// ManifestID returns H("weft/manifest/v1", wcbBytes).
func ManifestID(wcbBytes []byte) Hash32 {
	return hash.Domain(DomainManifest, wcbBytes)
}

// VersionIDBytes returns H("weft/version/v1", wcbBytes).
func VersionIDBytes(wcbBytes []byte) Hash32 {
	return hash.Domain(DomainVersion, wcbBytes)
}

// CommitIDBytes returns H("weft/store/commit/v1", wcbBytes).
func CommitIDBytes(wcbBytes []byte) Hash32 {
	return hash.Domain(DomainCommit, wcbBytes)
}
