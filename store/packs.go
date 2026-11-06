// Physical object packs: the Go port of `src/packs.rs`.
//
// A content-addressed namespace costs one physical request per small blob. The
// commit plane lets the store publish a *catalog* atomically, so small
// immutable blobs are grouped into a few large pack objects and served by a
// ranged read of the member's bytes.
//
// Contract (identical to Rust):
//
//   - a blob at most `MemberThresholdBytes` is appended to the open pack; when
//     the open pack reaches `TargetBytes` or `MaxMembersPerPack` it is
//     published with create-once semantics under `packs/<ab>/<H(PACK_DOMAIN,
//     bytes)>` and its members are recorded in the catalog. Larger blobs stay
//     flat;
//   - the pack is published *before* any catalog record names it, so a crash
//     leaves an unreferenced pack, never a dangling entry;
//   - membership is `key -> (pack, offset, length, digest)` in immutable
//     content-addressed segments plus one mutable `pack-catalog.root` control
//     record replaced with a compare-and-swap;
//   - a reader performs one catalog lookup and one ranged read of exactly the
//     member's bytes, then verifies the member digest;
//   - a plane without true range reads is refused, because packing it would
//     turn a small read into a whole-pack read;
//   - when the catalog bound is reached, packing stops and new blobs are
//     published flat. Nothing fails.
package store

import (
	"encoding/binary"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/infinityabundance/WeftCodec-Go/hash"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// Pack domains and layout constants. They must equal src/packs.rs.
const (
	PackDomain           = "weft/pack/v1"
	CatalogSegmentDomain = "weft/pack/catalog-segment/v1"
	CatalogRootDomain    = "weft/pack/catalog-root/v1"
	MemberDomain         = "weft/pack/member/v1"

	CatalogEntryBytes  uint64 = 113
	segmentHeaderBytes uint64 = 16
	rootHeaderBytes    uint64 = 20
	memberDigestBytes  uint64 = 32
	packFormatVersion  uint32 = 1

	packCatalogRootName = "pack-catalog.root"
	maxAbsentKeys       = 4096
)

var (
	segmentMagic = []byte("WPS1")
	rootMagic    = []byte("WPR1")
)

// PackOptions is the physical packing policy. Every field is a hard bound.
type PackOptions struct {
	TargetBytes          uint64 `json:"target_bytes"`
	MemberThresholdBytes uint64 `json:"member_threshold_bytes"`
	MaxMembersPerPack    uint32 `json:"max_members_per_pack"`
	MaxCatalogBytes      uint64 `json:"max_catalog_bytes"`
	CatalogSegments      uint32 `json:"catalog_segments"`
}

// DefaultPackOptions returns the Rust defaults.
func DefaultPackOptions() PackOptions {
	return PackOptions{
		TargetBytes:          16 * 1024 * 1024,
		MemberThresholdBytes: 64 * 1024,
		MaxMembersPerPack:    65_536,
		MaxCatalogBytes:      8 * 1024 * 1024,
		CatalogSegments:      256,
	}
}

// Validate enforces the policy. There is no unvalidated path into the plane.
func (o PackOptions) Validate() error {
	if o.TargetBytes < 4096 {
		return werr.Newf(werr.InvalidArgument, "pack_target_bytes must be at least 4096")
	}
	if o.TargetBytes > 1024*1024*1024 {
		return werr.Newf(werr.LimitExceeded, "pack_target_bytes is above the 1 GiB pack bound")
	}
	if o.MemberThresholdBytes == 0 {
		return werr.Newf(werr.InvalidArgument, "member_threshold_bytes must be positive")
	}
	if o.MemberThresholdBytes > o.TargetBytes {
		return werr.Newf(werr.InvalidArgument,
			"member_threshold_bytes must not exceed pack_target_bytes; a member that cannot fit in a pack is not packable")
	}
	if o.MaxMembersPerPack == 0 {
		return werr.Newf(werr.InvalidArgument, "max_members_per_pack must be positive")
	}
	if o.CatalogSegments == 0 || o.CatalogSegments > 4096 || o.CatalogSegments&(o.CatalogSegments-1) != 0 {
		return werr.Newf(werr.InvalidArgument, "catalog_segments must be a power of two in 1..=4096")
	}
	minimum := uint64(o.CatalogSegments) * (segmentHeaderBytes + memberDigestBytes + CatalogEntryBytes)
	if o.MaxCatalogBytes < minimum {
		return werr.Newf(werr.InvalidArgument,
			"max_catalog_bytes must be at least %d for %d catalog segments (room for one entry per segment)",
			minimum, o.CatalogSegments)
	}
	return nil
}

// MaxCatalogEntries is the maximum number of catalogued members.
func (o PackOptions) MaxCatalogEntries() uint64 { return o.MaxCatalogBytes / CatalogEntryBytes }

// PackStats are the pack-plane counters for receipts.
type PackStats struct {
	SealedPacks             uint64 `json:"sealed_packs"`
	PackedMembers           uint64 `json:"packed_members"`
	PackedBytes             uint64 `json:"packed_bytes"`
	FlatMembers             uint64 `json:"flat_members"`
	FlatBytes               uint64 `json:"flat_bytes"`
	CatalogEntries          uint64 `json:"catalog_entries"`
	CatalogSegmentPublishes uint64 `json:"catalog_segment_publishes"`
	CatalogRootPublishes    uint64 `json:"catalog_root_publishes"`
	OpenPackBytes           uint64 `json:"open_pack_bytes"`
	OpenPackMembers         uint64 `json:"open_pack_members"`
	PackingDisabled         bool   `json:"packing_disabled"`
}

type memberKey struct {
	kind byte
	id   model.Hash32
}

type packEntry struct {
	kind   byte
	id     model.Hash32
	pack   model.Hash32
	offset uint64
	length uint64
	digest model.Hash32
}

func (e packEntry) key() memberKey { return memberKey{kind: e.kind, id: e.id} }

func (e packEntry) encode(out []byte) []byte {
	out = append(out, e.kind)
	out = append(out, e.id[:]...)
	out = append(out, e.pack[:]...)
	var buf [16]byte
	binary.LittleEndian.PutUint64(buf[:8], e.offset)
	binary.LittleEndian.PutUint64(buf[8:], e.length)
	out = append(out, buf[:]...)
	out = append(out, e.digest[:]...)
	return out
}

func decodePackEntry(data []byte) (packEntry, error) {
	if uint64(len(data)) != CatalogEntryBytes {
		return packEntry{}, werr.Newf(werr.Corrupt, "catalog entry has the wrong length")
	}
	var entry packEntry
	cursor := 0
	entry.kind = data[cursor]
	cursor++
	copy(entry.id[:], data[cursor:cursor+32])
	cursor += 32
	copy(entry.pack[:], data[cursor:cursor+32])
	cursor += 32
	entry.offset = binary.LittleEndian.Uint64(data[cursor : cursor+8])
	cursor += 8
	entry.length = binary.LittleEndian.Uint64(data[cursor : cursor+8])
	cursor += 8
	copy(entry.digest[:], data[cursor:cursor+32])
	if entry.kind > 2 {
		return packEntry{}, werr.Newf(werr.Corrupt, "catalog entry carries unknown member kind %d", entry.kind)
	}
	return entry, nil
}

type packSegment struct {
	index   uint32
	entries []packEntry
}

func (s *packSegment) encode() []byte {
	out := make([]byte, 0, segmentHeaderBytes+uint64(len(s.entries))*CatalogEntryBytes+memberDigestBytes)
	out = append(out, segmentMagic...)
	var header [12]byte
	binary.LittleEndian.PutUint32(header[0:4], packFormatVersion)
	binary.LittleEndian.PutUint32(header[4:8], s.index)
	binary.LittleEndian.PutUint32(header[8:12], uint32(len(s.entries)))
	out = append(out, header[:]...)
	for _, entry := range s.entries {
		out = entry.encode(out)
	}
	digest := hash.Domain(CatalogSegmentDomain, out)
	out = append(out, digest[:]...)
	return out
}

func decodePackSegment(data []byte) (*packSegment, error) {
	minimum := segmentHeaderBytes + memberDigestBytes
	if uint64(len(data)) < minimum {
		return nil, werr.Newf(werr.Corrupt, "catalog segment is too short")
	}
	if string(data[:4]) != string(segmentMagic) {
		return nil, werr.Newf(werr.Corrupt, "catalog segment magic mismatch")
	}
	version := binary.LittleEndian.Uint32(data[4:8])
	if version != packFormatVersion {
		return nil, werr.Newf(werr.Unsupported, "catalog segment version %d is not supported", version)
	}
	index := binary.LittleEndian.Uint32(data[8:12])
	count := uint64(binary.LittleEndian.Uint32(data[12:16]))
	bodyLen := segmentHeaderBytes + count*CatalogEntryBytes
	if bodyLen+memberDigestBytes != uint64(len(data)) {
		return nil, werr.Newf(werr.Corrupt, "catalog segment length does not match its entry count")
	}
	digestAt := int(bodyLen)
	expected := hash.Domain(CatalogSegmentDomain, data[:digestAt])
	if string(data[digestAt:]) != string(expected[:]) {
		return nil, werr.Newf(werr.Corrupt, "catalog segment digest mismatch")
	}
	entries := make([]packEntry, 0, count)
	cursor := int(segmentHeaderBytes)
	var previous memberKey
	havePrevious := false
	for i := uint64(0); i < count; i++ {
		entry, err := decodePackEntry(data[cursor : cursor+int(CatalogEntryBytes)])
		if err != nil {
			return nil, err
		}
		key := entry.key()
		if havePrevious && !memberKeyLess(previous, key) {
			return nil, werr.Newf(werr.Corrupt, "catalog segment entries are not strictly ordered")
		}
		previous = key
		havePrevious = true
		if entry.pack == model.ZeroHash || entry.digest == model.ZeroHash || entry.length == 0 {
			return nil, werr.Newf(werr.Corrupt, "catalog entry has a zero pack, digest, or length")
		}
		entries = append(entries, entry)
		cursor += int(CatalogEntryBytes)
	}
	return &packSegment{index: index, entries: entries}, nil
}

func memberKeyLess(a, b memberKey) bool {
	if a.kind != b.kind {
		return a.kind < b.kind
	}
	return a.id.Hex() < b.id.Hex()
}

func memberIdentity(kind BlobKind) (byte, bool) {
	switch kind {
	case BlobObject:
		return 0, true
	case BlobManifest:
		return 1, true
	case BlobIndex:
		return 2, true
	default:
		return 0, false
	}
}

func packSegmentIndex(id model.Hash32, segments uint32) int {
	raw := binary.LittleEndian.Uint32(id[:4])
	return int(raw & (segments - 1))
}

type packState struct {
	loaded       bool
	rootToken    *string
	segmentIDs   []model.Hash32
	segments     []*packSegment
	totalEntries uint64
	openBytes    []byte
	openEntries  []packEntry
	openIndex    map[memberKey]int
	absent       map[memberKey]struct{}
	counters     PackStats
	notes        []string
}

// PackedBlobPlane groups small blobs into physical packs.
type PackedBlobPlane struct {
	inner   BlobAccess
	catalog ControlPlane
	options PackOptions
	mu      sync.Mutex
	state   packState
}

// NewPackedBlobPlane wraps an inner plane. It refuses a plane without true
// range reads and an invalid policy before any byte is written.
func NewPackedBlobPlane(inner BlobAccess, catalog ControlPlane, options PackOptions) (*PackedBlobPlane, error) {
	if err := options.Validate(); err != nil {
		return nil, err
	}
	caps := inner.Capabilities()
	if !caps.TrueRangeReads {
		return nil, werr.Newf(werr.Unsupported,
			"packed blobs need true range reads from the inner blob plane `%s`; refusing to pack because a small member would otherwise read the whole pack",
			caps.Backend)
	}
	if options.TargetBytes > caps.MaxObjectBytes {
		return nil, werr.Newf(werr.LimitExceeded,
			"pack_target_bytes (%d) is above the inner plane's %d-byte object bound",
			options.TargetBytes, caps.MaxObjectBytes)
	}
	if options.MaxCatalogBytes > caps.MaxObjectBytes {
		return nil, werr.Newf(werr.LimitExceeded, "max_catalog_bytes is above the inner plane's object bound")
	}
	return &PackedBlobPlane{
		inner: inner, catalog: catalog, options: options,
		state: packState{openIndex: map[memberKey]int{}, absent: map[memberKey]struct{}{}},
	}, nil
}

// Options returns the active policy.
func (p *PackedBlobPlane) Options() PackOptions { return p.options }

func (p *PackedBlobPlane) Label() string {
	return "packed-" + p.inner.Label()
}

func (p *PackedBlobPlane) Capabilities() BlobCapabilities {
	caps := p.inner.Capabilities()
	caps.Backend = "packed-" + caps.Backend
	caps.Publication = "small blobs grouped into content-addressed packs published with the inner plane; the catalog root is replaced with compare-and-swap"
	return caps
}

func (p *PackedBlobPlane) Root() string { return p.inner.Root() }

// PackStats returns this handle's own counters plus the catalog truth.
func (p *PackedBlobPlane) PackStats() PackStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	stats := p.state.counters
	stats.CatalogEntries = p.state.totalEntries + uint64(len(p.state.openEntries))
	stats.OpenPackBytes = uint64(len(p.state.openBytes))
	stats.OpenPackMembers = uint64(len(p.state.openEntries))
	for _, note := range p.state.notes {
		if strings.HasPrefix(note, "catalog bound reached") {
			stats.PackingDisabled = true
		}
	}
	return stats
}

func (p *PackedBlobPlane) ensureLoadedLocked() error {
	if p.state.loaded {
		return nil
	}
	segments := int(p.options.CatalogSegments)
	data, token, present, err := p.catalog.ReadControl(packCatalogRootName)
	if err != nil {
		return err
	}
	if !present {
		p.state.segmentIDs = make([]model.Hash32, segments)
		p.state.segments = make([]*packSegment, segments)
		p.state.totalEntries = 0
		p.state.rootToken = nil
		p.state.loaded = true
		return nil
	}
	ids, total, err := decodeCatalogRoot(data, p.options.CatalogSegments)
	if err != nil {
		return err
	}
	p.state.segmentIDs = ids
	p.state.segments = make([]*packSegment, segments)
	p.state.totalEntries = total
	tokenCopy := token
	p.state.rootToken = &tokenCopy
	p.state.loaded = true
	return nil
}

func (p *PackedBlobPlane) loadSegmentLocked(index int) (*packSegment, error) {
	if index < 0 || index >= len(p.state.segmentIDs) {
		return nil, werr.Newf(werr.Corrupt, "catalog segment index is out of bounds")
	}
	if p.state.segments[index] != nil {
		return p.state.segments[index], nil
	}
	id := p.state.segmentIDs[index]
	if id == model.ZeroHash {
		segment := &packSegment{index: uint32(index)}
		p.state.segments[index] = segment
		return segment, nil
	}
	data, err := p.inner.Get(BlobPackCatalog, id)
	if err != nil {
		return nil, err
	}
	segment, err := decodePackSegment(data)
	if err != nil {
		return nil, err
	}
	if segment.index != uint32(index) {
		return nil, werr.Newf(werr.Corrupt, "catalog segment %d decodes as segment %d", index, segment.index)
	}
	p.state.segments[index] = segment
	return segment, nil
}

func (p *PackedBlobPlane) findLocked(kind BlobKind, id model.Hash32) (*packEntry, *packSegment, error) {
	memberKind, ok := memberIdentity(kind)
	if !ok {
		return nil, nil, nil
	}
	key := memberKey{kind: memberKind, id: id}
	if position, ok := p.state.openIndex[key]; ok {
		if position < 0 || position >= len(p.state.openEntries) {
			return nil, nil, werr.Newf(werr.Corrupt, "open pack index is inconsistent")
		}
		entry := p.state.openEntries[position]
		return &entry, nil, nil
	}
	index := packSegmentIndex(id, p.options.CatalogSegments)
	segment, err := p.loadSegmentLocked(index)
	if err != nil {
		return nil, nil, err
	}
	position := sort.Search(len(segment.entries), func(i int) bool {
		return !memberKeyLess(segment.entries[i].key(), key)
	})
	if position < len(segment.entries) && segment.entries[position].key() == key {
		entry := segment.entries[position]
		return &entry, segment, nil
	}
	return nil, nil, nil
}

func (p *PackedBlobPlane) Get(kind BlobKind, id model.Hash32) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensureLoadedLocked(); err != nil {
		return nil, err
	}
	entry, segment, err := p.findLocked(kind, id)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return p.inner.Get(kind, id)
	}
	var data []byte
	if segment == nil {
		start := entry.offset
		end := start + entry.length
		if end < start || end > uint64(len(p.state.openBytes)) {
			return nil, werr.Newf(werr.Corrupt, "open pack range is out of bounds")
		}
		data = append([]byte(nil), p.state.openBytes[start:end]...)
	} else {
		data, err = p.inner.GetRange(BlobPack, entry.pack, entry.offset, entry.length)
		if err != nil {
			return nil, err
		}
		if uint64(len(data)) != entry.length {
			return nil, werr.Newf(werr.Corrupt,
				"pack %s returned %d bytes for member %s at offset %d (expected %d)",
				entry.pack.Hex(), len(data), id.Hex(), entry.offset, entry.length)
		}
	}
	if err := verifyMemberDigest(*entry, data); err != nil {
		return nil, err
	}
	return data, nil
}

func (p *PackedBlobPlane) GetRange(kind BlobKind, id model.Hash32, offset, length uint64) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensureLoadedLocked(); err != nil {
		return nil, err
	}
	entry, segment, err := p.findLocked(kind, id)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return p.inner.GetRange(kind, id, offset, length)
	}
	if offset > entry.length {
		return nil, werr.Newf(werr.InvalidArgument,
			"read offset %d is beyond %s (%d bytes)", offset, id.Hex(), entry.length)
	}
	want := entry.length - offset
	if length < want {
		want = length
	}
	if want == 0 {
		return []byte{}, nil
	}
	if segment == nil {
		start := entry.offset + offset
		end := start + want
		if end < start || end > uint64(len(p.state.openBytes)) {
			return nil, werr.Newf(werr.Corrupt, "open pack range is out of bounds")
		}
		return append([]byte(nil), p.state.openBytes[start:end]...), nil
	}
	data, err := p.inner.GetRange(BlobPack, entry.pack, entry.offset+offset, want)
	if err != nil {
		return nil, err
	}
	if uint64(len(data)) != want {
		return nil, werr.Newf(werr.Corrupt,
			"pack %s returned %d bytes for a %d-byte member range", entry.pack.Hex(), len(data), want)
	}
	return data, nil
}

func (p *PackedBlobPlane) Put(kind BlobKind, id model.Hash32, data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensureLoadedLocked(); err != nil {
		return err
	}
	entry, segment, err := p.findLocked(kind, id)
	if err != nil {
		return err
	}
	if entry != nil {
		existing, err := p.readEntryLocked(*entry, segment)
		if err != nil {
			return err
		}
		if overlayBytesSame(existing, data) {
			return nil
		}
		return werr.Newf(werr.Exists, "key %s is already packed with different bytes", id.Hex())
	}
	// The store reads a blob before publishing it, so an absent observation can
	// skip the duplicate flat request in this process.
	key := memberKey{}
	haveKey := false
	if memberKind, ok := memberIdentity(kind); ok {
		key = memberKey{kind: memberKind, id: id}
		haveKey = true
		if _, absent := p.state.absent[key]; !absent {
			if existing, err := p.inner.Get(kind, id); err == nil {
				if overlayBytesSame(existing, data) {
					return nil
				}
				return werr.Newf(werr.Exists, "key %s already exists with different bytes", id.Hex())
			} else if typed, ok := err.(*werr.Error); !ok || typed.Kind != werr.NotFound {
				return err
			} else {
				p.rememberAbsentLocked(key)
			}
		}
	}
	memberKind, packable := memberIdentity(kind)
	if !packable {
		return p.inner.Put(kind, id, data)
	}
	length := uint64(len(data))
	pending := p.state.totalEntries + uint64(len(p.state.openEntries))
	if length == 0 || length > p.options.MemberThresholdBytes || pending >= p.options.MaxCatalogEntries() {
		if pending >= p.options.MaxCatalogEntries() && length > 0 && length <= p.options.MemberThresholdBytes {
			p.noteLocked("catalog bound reached; new blobs are published flat")
		}
		p.state.counters.FlatMembers++
		p.state.counters.FlatBytes += length
		if haveKey {
			delete(p.state.absent, key)
		}
		return p.inner.Put(kind, id, data)
	}
	if err := p.appendLocked(memberKind, id, data); err != nil {
		return err
	}
	if haveKey {
		delete(p.state.absent, key)
	}
	return nil
}

func (p *PackedBlobPlane) readEntryLocked(entry packEntry, segment *packSegment) ([]byte, error) {
	if segment == nil {
		start := entry.offset
		end := start + entry.length
		if end < start || end > uint64(len(p.state.openBytes)) {
			return nil, werr.Newf(werr.Corrupt, "open pack range is out of bounds")
		}
		return append([]byte(nil), p.state.openBytes[start:end]...), nil
	}
	data, err := p.inner.GetRange(BlobPack, entry.pack, entry.offset, entry.length)
	if err != nil {
		return nil, err
	}
	if uint64(len(data)) != entry.length {
		return nil, werr.Newf(werr.Corrupt, "existing pack member is truncated")
	}
	if err := verifyMemberDigest(entry, data); err != nil {
		return nil, err
	}
	return data, nil
}

func (p *PackedBlobPlane) appendLocked(kind byte, id model.Hash32, data []byte) error {
	length := uint64(len(data))
	wouldOverflow := func() bool {
		return uint64(len(p.state.openBytes))+length > p.options.TargetBytes ||
			uint64(len(p.state.openEntries)) >= uint64(p.options.MaxMembersPerPack)
	}
	if len(p.state.openEntries) > 0 && wouldOverflow() {
		if err := p.sealLocked(); err != nil {
			return err
		}
	}
	if len(p.state.openEntries) > 0 && wouldOverflow() {
		return werr.Newf(werr.LimitExceeded,
			"member of %d bytes does not fit the open pack target %d", length, p.options.TargetBytes)
	}
	offset := uint64(len(p.state.openBytes))
	p.state.openBytes = append(p.state.openBytes, data...)
	entry := packEntry{
		kind: kind, id: id, offset: offset, length: length,
		digest: hash.Domain(MemberDomain, data),
	}
	position := len(p.state.openEntries)
	p.state.openEntries = append(p.state.openEntries, entry)
	p.state.openIndex[entry.key()] = position
	p.state.counters.PackedMembers++
	p.state.counters.PackedBytes += length
	return nil
}

func (p *PackedBlobPlane) sealLocked() error {
	if len(p.state.openEntries) == 0 {
		return nil
	}
	packBytes := p.state.openBytes
	entries := p.state.openEntries
	index := p.state.openIndex
	p.state.openBytes = nil
	p.state.openEntries = nil
	p.state.openIndex = map[memberKey]int{}
	if err := p.sealInnerLocked(packBytes, entries); err != nil {
		p.state.openBytes = packBytes
		p.state.openEntries = entries
		p.state.openIndex = index
		return err
	}
	return nil
}

func (p *PackedBlobPlane) sealInnerLocked(packBytes []byte, entries []packEntry) error {
	packID := hash.Domain(PackDomain, packBytes)
	for i := range entries {
		entries[i].pack = packID
	}
	// 1. Publish the pack first. A crash after this leaves an unreferenced
	//    pack, never a catalog entry pointing at missing bytes.
	if err := p.inner.Put(BlobPack, packID, packBytes); err != nil {
		return err
	}
	crashPoint("pack_after_pack_object")

	// 2. Publish each touched catalog segment as an immutable object.
	perSegment := make(map[int][]packEntry)
	for _, entry := range entries {
		index := packSegmentIndex(entry.id, p.options.CatalogSegments)
		perSegment[index] = append(perSegment[index], entry)
	}
	newIDs := append([]model.Hash32(nil), p.state.segmentIDs...)
	type pendingSegment struct {
		index   int
		segment *packSegment
		data    []byte
	}
	pending := make([]pendingSegment, 0, len(perSegment))
	indexes := make([]int, 0, len(perSegment))
	for index := range perSegment {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	for _, index := range indexes {
		current, err := p.loadSegmentLocked(index)
		if err != nil {
			return err
		}
		merged := append([]packEntry(nil), current.entries...)
		merged = append(merged, perSegment[index]...)
		sort.Slice(merged, func(i, j int) bool { return memberKeyLess(merged[i].key(), merged[j].key()) })
		for i := 1; i < len(merged); i++ {
			if merged[i].key() == merged[i-1].key() {
				return werr.Newf(werr.Corrupt, "catalog already names a member being packed again")
			}
		}
		segment := &packSegment{index: uint32(index), entries: merged}
		data := segment.encode()
		fragment := segmentFragmentID(data)
		newIDs[index] = fragment
		pending = append(pending, pendingSegment{index: index, segment: segment, data: data})
	}
	for _, item := range pending {
		fragment := segmentFragmentID(item.data)
		if err := p.inner.Put(BlobPackCatalog, fragment, item.data); err != nil {
			return err
		}
		p.state.counters.CatalogSegmentPublishes++
	}
	crashPoint("pack_after_catalog_segments")

	// 3. Publish the root with one compare-and-swap.
	newTotal := p.state.totalEntries + uint64(len(entries))
	root, err := encodeCatalogRoot(newIDs, newTotal)
	if err != nil {
		return err
	}
	token, err := p.catalog.CompareExchange(packCatalogRootName, p.state.rootToken, root)
	if err != nil {
		return err
	}
	tokenCopy := token
	p.state.rootToken = &tokenCopy
	p.state.segmentIDs = newIDs
	p.state.totalEntries = newTotal
	for _, item := range pending {
		p.state.segments[item.index] = item.segment
	}
	p.state.counters.SealedPacks++
	p.state.counters.CatalogRootPublishes++
	return nil
}

func (p *PackedBlobPlane) Delete(kind BlobKind, id model.Hash32) error {
	return p.DeleteEntry(BlobEntry{Kind: kind, ID: id, Rel: blobRelPath(kind, id), Size: 0})
}

func (p *PackedBlobPlane) DeleteEntry(entry BlobEntry) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensureLoadedLocked(); err != nil {
		return err
	}
	found, segment, err := p.findLocked(entry.Kind, entry.ID)
	if err != nil {
		return err
	}
	if found == nil {
		return p.inner.DeleteEntry(entry)
	}
	if segment == nil {
		// Buffered member: rebuild the open pack without it.
		removed := found.key()
		entries := p.state.openEntries
		bytesValue := make([]byte, 0, len(p.state.openBytes))
		kept := make([]packEntry, 0, len(entries))
		index := make(map[memberKey]int, len(entries))
		for _, item := range entries {
			if item.key() == removed {
				continue
			}
			start := item.offset
			end := start + item.length
			item.offset = uint64(len(bytesValue))
			bytesValue = append(bytesValue, p.state.openBytes[start:end]...)
			index[item.key()] = len(kept)
			kept = append(kept, item)
		}
		p.state.openBytes = bytesValue
		p.state.openEntries = kept
		p.state.openIndex = index
		return nil
	}
	index := packSegmentIndex(entry.ID, p.options.CatalogSegments)
	current, err := p.loadSegmentLocked(index)
	if err != nil {
		return err
	}
	kept := make([]packEntry, 0, len(current.entries))
	for _, item := range current.entries {
		if item.key() != found.key() {
			kept = append(kept, item)
		}
	}
	segment = &packSegment{index: uint32(index), entries: kept}
	data := segment.encode()
	fragment := segmentFragmentID(data)
	if err := p.inner.Put(BlobPackCatalog, fragment, data); err != nil {
		return err
	}
	p.state.counters.CatalogSegmentPublishes++
	newIDs := append([]model.Hash32(nil), p.state.segmentIDs...)
	newIDs[index] = fragment
	newTotal := p.state.totalEntries - 1
	root, err := encodeCatalogRoot(newIDs, newTotal)
	if err != nil {
		return err
	}
	token, err := p.catalog.CompareExchange(packCatalogRootName, p.state.rootToken, root)
	if err != nil {
		return err
	}
	tokenCopy := token
	p.state.rootToken = &tokenCopy
	p.state.segmentIDs = newIDs
	p.state.totalEntries = newTotal
	p.state.segments[index] = segment
	p.state.counters.CatalogRootPublishes++
	return nil
}

func (p *PackedBlobPlane) Length(kind BlobKind, id model.Hash32) (uint64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensureLoadedLocked(); err != nil {
		return 0, err
	}
	entry, _, err := p.findLocked(kind, id)
	if err != nil {
		return 0, err
	}
	if entry != nil {
		return entry.length, nil
	}
	return p.inner.Length(kind, id)
}

func (p *PackedBlobPlane) Exists(kind BlobKind, id model.Hash32) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensureLoadedLocked(); err != nil {
		return false, err
	}
	entry, _, err := p.findLocked(kind, id)
	if err != nil {
		return false, err
	}
	if entry != nil {
		return true, nil
	}
	return p.inner.Exists(kind, id)
}

func (p *PackedBlobPlane) List(kindDir string) ([]BlobEntry, []string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensureLoadedLocked(); err != nil {
		return nil, nil, err
	}
	entries, problems, err := p.inner.List(kindDir)
	if err != nil {
		return nil, nil, err
	}
	var wantKind byte
	switch kindDir {
	case "objects":
		wantKind = 0
	case "manifests":
		wantKind = 1
	case "indexes":
		wantKind = 2
	default:
		return entries, problems, nil
	}
	for index := range p.state.segmentIDs {
		segment, err := p.loadSegmentLocked(index)
		if err != nil {
			return nil, nil, err
		}
		for _, entry := range segment.entries {
			if entry.kind != wantKind {
				continue
			}
			kind := BlobObject
			if entry.kind == 1 {
				kind = BlobManifest
			} else if entry.kind == 2 {
				kind = BlobIndex
			}
			modTime := time.Time{}
			if when, ok := p.inner.Modified(BlobPack, entry.pack); ok {
				modTime = when
			}
			entries = append(entries, BlobEntry{
				Kind: kind, ID: entry.id, Rel: blobRelPath(kind, entry.id),
				Size: entry.length, ModTime: modTime,
			})
		}
	}
	for _, entry := range p.state.openEntries {
		if entry.kind != wantKind {
			continue
		}
		kind := BlobObject
		if entry.kind == 1 {
			kind = BlobManifest
		} else if entry.kind == 2 {
			kind = BlobIndex
		}
		entries = append(entries, BlobEntry{
			Kind: kind, ID: entry.id, Rel: blobRelPath(kind, entry.id), Size: entry.length,
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Rel < entries[j].Rel })
	deduped := entries[:0]
	for i, entry := range entries {
		if i > 0 && entry.Rel == entries[i-1].Rel {
			continue
		}
		deduped = append(deduped, entry)
	}
	return deduped, problems, nil
}

func (p *PackedBlobPlane) Modified(kind BlobKind, id model.Hash32) (time.Time, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensureLoadedLocked(); err != nil {
		return time.Time{}, false
	}
	entry, _, err := p.findLocked(kind, id)
	if err != nil {
		return time.Time{}, false
	}
	if entry != nil {
		if when, ok := p.inner.Modified(BlobPack, entry.pack); ok {
			return when, true
		}
		// An open (unpublished) member is brand new for the grace gate.
		return time.Time{}, false
	}
	return p.inner.Modified(kind, id)
}

func (p *PackedBlobPlane) Flush() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensureLoadedLocked(); err != nil {
		return err
	}
	return p.sealLocked()
}

// PackCatalogStats reads the catalog and reports what it actually names.
func (p *PackedBlobPlane) PackCatalogStats() (PackStats, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensureLoadedLocked(); err != nil {
		return PackStats{}, err
	}
	packs := make(map[model.Hash32]struct{})
	var entries, bytesValue uint64
	for index := range p.state.segmentIDs {
		segment, err := p.loadSegmentLocked(index)
		if err != nil {
			return PackStats{}, err
		}
		for _, entry := range segment.entries {
			packs[entry.pack] = struct{}{}
			entries++
			bytesValue += entry.length
		}
	}
	stats := p.state.counters
	stats.SealedPacks = uint64(len(packs))
	stats.PackedMembers = entries
	stats.PackedBytes = bytesValue
	stats.CatalogEntries = entries
	stats.OpenPackBytes = uint64(len(p.state.openBytes))
	stats.OpenPackMembers = uint64(len(p.state.openEntries))
	return stats, nil
}

func (p *PackedBlobPlane) ReclaimUnreferencedPacks() (PackReclaim, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensureLoadedLocked(); err != nil {
		return PackReclaim{}, err
	}
	referenced := make(map[model.Hash32]struct{})
	var liveMembers uint64
	for index := range p.state.segmentIDs {
		segment, err := p.loadSegmentLocked(index)
		if err != nil {
			return PackReclaim{}, err
		}
		for _, entry := range segment.entries {
			referenced[entry.pack] = struct{}{}
			liveMembers++
		}
	}
	report := PackReclaim{LivePacks: uint64(len(referenced)), LiveMembers: liveMembers}
	packs, _, err := p.inner.List("packs")
	if err != nil {
		return report, err
	}
	for _, pack := range packs {
		if _, ok := referenced[pack.ID]; ok {
			continue
		}
		if err := p.inner.DeleteEntry(pack); err != nil {
			return report, err
		}
		report.DeletedPacks++
		report.DeletedPackBytes += pack.Size
	}
	liveSegments := make(map[model.Hash32]struct{})
	for _, id := range p.state.segmentIDs {
		if id != model.ZeroHash {
			liveSegments[id] = struct{}{}
		}
	}
	catalogs, _, err := p.inner.List("pack-catalog")
	if err != nil {
		return report, err
	}
	for _, segment := range catalogs {
		if _, ok := liveSegments[segment.ID]; ok {
			continue
		}
		if err := p.inner.DeleteEntry(segment); err != nil {
			return report, err
		}
		report.DeletedCatalogSegments++
	}
	return report, nil
}

func (p *PackedBlobPlane) VerifyPacks() ([]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	problems := make([]string, 0)
	if err := p.ensureLoadedLocked(); err != nil {
		return []string{"pack catalog root: " + err.Error()}, nil
	}
	var entries uint64
	ranges := make(map[model.Hash32][][2]uint64)
	for index := range p.state.segmentIDs {
		segment, err := p.loadSegmentLocked(index)
		if err != nil {
			problems = append(problems, "pack catalog segment "+itoa(uint64(index))+": "+err.Error())
			continue
		}
		entries += uint64(len(segment.entries))
		for _, entry := range segment.entries {
			ranges[entry.pack] = append(ranges[entry.pack], [2]uint64{entry.offset, entry.length})
		}
	}
	if entries != p.state.totalEntries {
		problems = append(problems, "pack catalog root declares "+itoa(p.state.totalEntries)+
			" entries but its segments hold "+itoa(entries))
	}
	packs := make([]model.Hash32, 0, len(ranges))
	for pack := range ranges {
		packs = append(packs, pack)
	}
	sort.Slice(packs, func(i, j int) bool { return packs[i].Hex() < packs[j].Hex() })
	for _, pack := range packs {
		spans := ranges[pack]
		length, err := p.inner.Length(BlobPack, pack)
		if err != nil {
			if typed, ok := err.(*werr.Error); ok && typed.Kind == werr.NotFound {
				problems = append(problems, "pack "+pack.Hex()+" named by the catalog is missing")
			} else {
				problems = append(problems, "pack "+pack.Hex()+": "+err.Error())
			}
			continue
		}
		sort.Slice(spans, func(i, j int) bool {
			if spans[i][0] != spans[j][0] {
				return spans[i][0] < spans[j][0]
			}
			return spans[i][1] < spans[j][1]
		})
		var cursor uint64
		for _, span := range spans {
			if span[0] < cursor {
				problems = append(problems, "pack "+pack.Hex()+" has overlapping catalog members at offset "+itoa(span[0]))
			}
			end := span[0] + span[1]
			if end > length {
				problems = append(problems, "pack "+pack.Hex()+" is "+itoa(length)+
					" bytes but a member ends at "+itoa(end))
			}
			cursor = end
		}
	}
	return problems, nil
}

func (p *PackedBlobPlane) noteLocked(text string) {
	if len(p.state.notes) < 16 {
		for _, existing := range p.state.notes {
			if existing == text {
				return
			}
		}
		p.state.notes = append(p.state.notes, text)
	}
}

func (p *PackedBlobPlane) rememberAbsentLocked(key memberKey) {
	if _, ok := p.state.absent[key]; ok {
		return
	}
	if len(p.state.absent) >= maxAbsentKeys {
		for candidate := range p.state.absent {
			delete(p.state.absent, candidate)
			break
		}
	}
	p.state.absent[key] = struct{}{}
}

func verifyMemberDigest(entry packEntry, data []byte) error {
	digest := hash.Domain(MemberDomain, data)
	if digest != entry.digest {
		return werr.Newf(werr.Corrupt, "packed member %s does not match its catalog digest", entry.id.Hex())
	}
	return nil
}

func segmentFragmentID(data []byte) model.Hash32 {
	payloadLen := len(data) - int(memberDigestBytes)
	return hash.Domain(CatalogSegmentDomain, data[:payloadLen])
}

func encodeCatalogRoot(ids []model.Hash32, total uint64) ([]byte, error) {
	out := make([]byte, 0, rootHeaderBytes+uint64(len(ids))*32+memberDigestBytes)
	out = append(out, rootMagic...)
	var header [16]byte
	binary.LittleEndian.PutUint32(header[0:4], packFormatVersion)
	binary.LittleEndian.PutUint32(header[4:8], uint32(len(ids)))
	binary.LittleEndian.PutUint64(header[8:16], total)
	out = append(out, header[:]...)
	for _, id := range ids {
		out = append(out, id[:]...)
	}
	digest := hash.Domain(CatalogRootDomain, out)
	out = append(out, digest[:]...)
	return out, nil
}

func decodeCatalogRoot(data []byte, expectedSegments uint32) ([]model.Hash32, uint64, error) {
	minimum := rootHeaderBytes + memberDigestBytes
	if uint64(len(data)) < minimum {
		return nil, 0, werr.Newf(werr.Corrupt, "pack catalog root is too short")
	}
	if string(data[:4]) != string(rootMagic) {
		return nil, 0, werr.Newf(werr.Corrupt, "pack catalog root magic mismatch")
	}
	version := binary.LittleEndian.Uint32(data[4:8])
	if version != packFormatVersion {
		return nil, 0, werr.Newf(werr.Unsupported, "pack catalog root version %d is not supported", version)
	}
	segments := binary.LittleEndian.Uint32(data[8:12])
	if segments != expectedSegments {
		return nil, 0, werr.Newf(werr.Unsupported,
			"pack catalog root names %d segments but this plane is configured for %d",
			segments, expectedSegments)
	}
	total := binary.LittleEndian.Uint64(data[12:20])
	bodyLen := rootHeaderBytes + uint64(segments)*32
	if bodyLen+memberDigestBytes != uint64(len(data)) {
		return nil, 0, werr.Newf(werr.Corrupt, "pack catalog root length does not match its segment count")
	}
	digestAt := int(bodyLen)
	expected := hash.Domain(CatalogRootDomain, data[:digestAt])
	if string(data[digestAt:]) != string(expected[:]) {
		return nil, 0, werr.Newf(werr.Corrupt, "pack catalog root digest mismatch")
	}
	ids := make([]model.Hash32, 0, segments)
	cursor := int(rootHeaderBytes)
	for i := uint32(0); i < segments; i++ {
		var id model.Hash32
		copy(id[:], data[cursor:cursor+32])
		ids = append(ids, id)
		cursor += 32
	}
	return ids, total, nil
}
