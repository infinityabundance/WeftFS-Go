// Zero-trust KV-cache pages: store-level parity with the Rust
// `src/kv_capability.rs` (WEFT-KV-PROVENANCE.md §10, docs/KV-CACHE-GOVERNANCE.md).
//
// A KV page is a frozen mode-12 (`KV_CACHE`) or additive mode-19
// (`KV_CACHE_PROV`) frame plus a canonical capability descriptor stored in
// reserved attributes. The descriptor is content-addressed; its id is what a
// capability scope must name in `roots`, alongside the coarse `kv.<tenant>`
// namespace in `namespaces`.
//
// Read discipline (identical to Rust, normative):
//
//  1. Every failure before a byte is returned — unknown object, missing or
//     malformed descriptor, a descriptor id that does not match its bytes, an
//     absent or expired capability, a foreign tenant, a missing `kv.<tenant>`
//     namespace, a missing descriptor id in the scope's roots, or a POSIX/ACL
//     denial — is the same `Unauthorized` error with the same text
//     (`KvDenied`). Nothing about existence or contents is disclosed.
//  2. A content id is not a credential.
//  3. Only after authorization is the frame decoded, and the descriptor is
//     re-derived from the frame and compared field by field. That mismatch is
//     `Corrupt` and is reported only to an authorized reader.
//
// Difference from Rust, stated rather than hidden: Rust's `Principal` carries
// an already-verified `CapabilityEnvelope`, and the store rejects a principal
// with none. The Go store never carried envelopes — its capability is an
// `*auth.Capability` value (a content-addressed scope, not a signature), which
// every other Go authorization path (`ExactIDObject`, the resolver, the FUSE
// context mount) takes as an explicit argument. `KvPrincipal` is therefore the
// faithful union of the two Rust fields, and a nil `Capability` is denied
// exactly like an absent envelope. No Go path verifies an Ed25519 grant; that
// gap is pre-existing and is not introduced here.
package store

import (
	"encoding/hex"

	"github.com/infinityabundance/WeftCodec-Go/frame"
	"github.com/infinityabundance/WeftCodec-Go/hash"
	"github.com/infinityabundance/WeftCodec-Go/limits"
	"github.com/infinityabundance/WeftCodec-Go/modes"
	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/auth"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// Canonical descriptor schemas and identity domains (verbatim from
// `src/kv_capability.rs`).
const (
	// KvDescriptorSchema is the mode-12 capability descriptor schema.
	KvDescriptorSchema = "weft.kv.capability.v1"
	// DomainKvDescriptor is its identity domain.
	DomainKvDescriptor = "weft/kv/capability/v1"
	// KvProvDescriptorSchema is the mode-19 capability descriptor schema.
	KvProvDescriptorSchema = "weft.kv.prov_capability.v1"
	// DomainKvProvDescriptor is its identity domain.
	DomainKvProvDescriptor = "weft/kv/prov_capability/v1"
)

// Reserved attribute names and the namespace prefix.
const (
	// AttrKvDescriptor holds the canonical descriptor bytes as hex text.
	AttrKvDescriptor = "weft.kv.descriptor"
	// AttrKvDescriptorID holds the descriptor id as hex text.
	AttrKvDescriptorID = "weft.kv.descriptor_id"
	// AttrKvTenant is the tenant label.
	AttrKvTenant = "weft.kv.tenant"
	// AttrKvModel is the model version that produced the page.
	AttrKvModel = "weft.kv.model"
	// AttrKvSession is the inference session id.
	AttrKvSession = "weft.kv.session"
	// AttrKvPageBytes is the exact logical page length.
	AttrKvPageBytes = "weft.kv.page_bytes"
	// AttrKvMode records the frame mode (19). Absent means mode 12, which keeps
	// every pre-existing page readable.
	AttrKvMode = "weft.kv.mode"
	// KvNamespacePrefix is the namespace prefix a capability must grant.
	KvNamespacePrefix = "kv."
)

// KvDenied is the single non-disclosing denial text. Every pre-byte failure
// uses it. It is byte-identical to the Rust `KV_DENIED` constant.
const KvDenied = "kv page is not available to this principal"

func kvDenied() error { return werr.New(werr.Unauthorized, KvDenied) }

// ReservedKvAttributeNames lists every attribute a KV page may use, for tests
// and documentation (mirrors Rust `reserved_attribute_names`). The mode-19
// provenance-root attribute is `AttrKVProvRoot`, declared in retention.go.
func ReservedKvAttributeNames() [8]string {
	return [8]string{
		AttrKvDescriptor,
		AttrKvDescriptorID,
		AttrKvTenant,
		AttrKvModel,
		AttrKvSession,
		AttrKvPageBytes,
		AttrKvMode,
		AttrKVProvRoot,
	}
}

// KvPageMode is the frame mode of a stored KV page.
type KvPageMode uint64

const (
	// KvPageMode12 is the frozen mode-12 `KV_CACHE` page.
	KvPageMode12 KvPageMode = 12
	// KvPageModeProvenance is the additive mode-19 `KV_CACHE_PROV` page.
	KvPageModeProvenance KvPageMode = 19
)

// Value returns the numeric mode (12 or 19).
func (m KvPageMode) Value() uint64 { return uint64(m) }

// String names the mode, matching the Rust `KvPageMode` variants.
func (m KvPageMode) String() string {
	switch m {
	case KvPageMode12:
		return "Page12"
	case KvPageModeProvenance:
		return "Provenance"
	default:
		return "Unknown"
	}
}

// KvDescriptor is a KV page's capability descriptor (mode 12).
//
// It is stored as canonical WCB under `weft.kv.descriptor` and its id is
// H("weft/kv/capability/v1", canonical bytes). The shape is the mode-12
// canonical `[page_rows, head_count, head_dim]`.
type KvDescriptor struct {
	Tenant    string
	Model     string
	Session   string
	Layer     uint32
	PageIndex uint64
	PageCount uint64
	SeqStart  uint64
	SeqEnd    uint64
	Dtype     string
	HeadCount uint32
	HeadDim   uint32
	Shape     []uint64
	PageBytes uint64
}

// NewKvDescriptor builds a descriptor from a mode-12 input, its tenant, and the
// exact page bytes.
func NewKvDescriptor(input modes.KvCacheInput, tenant string, pageBytes uint64) (KvDescriptor, error) {
	rows, err := kvRows(input)
	if err != nil {
		return KvDescriptor{}, err
	}
	return KvDescriptor{
		Tenant:    tenant,
		Model:     input.Model,
		Session:   input.Session,
		Layer:     input.Layer,
		PageIndex: input.PageIndex,
		PageCount: input.PageCount,
		SeqStart:  input.SeqStart,
		SeqEnd:    input.SeqEnd,
		Dtype:     input.Dtype.Name,
		HeadCount: input.HeadCount,
		HeadDim:   input.HeadDim,
		Shape:     []uint64{rows, uint64(input.HeadCount), uint64(input.HeadDim)},
		PageBytes: pageBytes,
	}, nil
}

// kvRows is the mode-12 page-row count, with the same refusal Rust uses when
// seq_start is past seq_end.
func kvRows(input modes.KvCacheInput) (uint64, error) {
	if input.SeqEnd < input.SeqStart {
		return 0, werr.Newf(werr.InvalidArgument,
			"kv page seq_start must be below seq_end")
	}
	return input.SeqEnd - input.SeqStart, nil
}

func (d KvDescriptor) value() wcb.Value {
	return wcb.MapValue(map[string]wcb.Value{
		"schema":     wcb.TextValue(KvDescriptorSchema),
		"tenant":     wcb.TextValue(d.Tenant),
		"model":      wcb.TextValue(d.Model),
		"session":    wcb.TextValue(d.Session),
		"layer":      wcb.U64Value(uint64(d.Layer)),
		"page_index": wcb.U64Value(d.PageIndex),
		"page_count": wcb.U64Value(d.PageCount),
		"seq_start":  wcb.U64Value(d.SeqStart),
		"seq_end":    wcb.U64Value(d.SeqEnd),
		"dtype":      wcb.TextValue(d.Dtype),
		"head_count": wcb.U64Value(uint64(d.HeadCount)),
		"head_dim":   wcb.U64Value(uint64(d.HeadDim)),
		"shape":      kvShapeValue(d.Shape),
		"page_bytes": wcb.U64Value(d.PageBytes),
	})
}

func kvShapeValue(shape []uint64) wcb.Value {
	items := make([]wcb.Value, 0, len(shape))
	for _, dim := range shape {
		items = append(items, wcb.U64Value(dim))
	}
	return wcb.ArrayValue(items)
}

// CanonicalBytes returns the canonical WCB descriptor bytes.
func (d KvDescriptor) CanonicalBytes() ([]byte, error) {
	encoded, err := wcb.EncodeDefault(d.value())
	if err != nil {
		return nil, werr.FromCodec(err)
	}
	return encoded, nil
}

// ID is H("weft/kv/capability/v1", canonical bytes).
func (d KvDescriptor) ID() (model.Hash32, error) {
	encoded, err := d.CanonicalBytes()
	if err != nil {
		return model.Hash32{}, err
	}
	return hash.Domain(DomainKvDescriptor, encoded), nil
}

// Namespace is the grant namespace: `kv.<tenant>`.
func (d KvDescriptor) Namespace() string { return KvNamespacePrefix + d.Tenant }

// ParseKvDescriptor strictly decodes a canonical descriptor. Unknown keys,
// missing keys, wrong WCB types, a foreign schema, and non-canonical bytes are
// rejected; it mirrors Rust `KvDescriptor::from_canonical_bytes`.
func ParseKvDescriptor(encoded []byte) (KvDescriptor, error) {
	value, err := wcb.DecodeDefault(encoded)
	if err != nil {
		return KvDescriptor{}, werr.FromCodec(err)
	}
	if value.Kind != wcb.Map {
		return KvDescriptor{}, werr.Newf(werr.Corrupt, "kv descriptor is not a map")
	}
	known := map[string]bool{
		"schema": true, "tenant": true, "model": true, "session": true,
		"layer": true, "page_index": true, "page_count": true,
		"seq_start": true, "seq_end": true, "dtype": true,
		"head_count": true, "head_dim": true, "shape": true, "page_bytes": true,
	}
	for key := range value.Map {
		if !known[key] {
			return KvDescriptor{}, werr.Newf(werr.Corrupt, "unknown kv descriptor key `%s`", key)
		}
	}
	if len(value.Map) != len(known) {
		return KvDescriptor{}, werr.Newf(werr.Corrupt, "kv descriptor is missing a field")
	}
	schema, err := kvText(value.Map, "schema", "kv descriptor")
	if err != nil {
		return KvDescriptor{}, err
	}
	if schema != KvDescriptorSchema {
		return KvDescriptor{}, werr.Newf(werr.Corrupt, "unknown kv descriptor schema")
	}
	shape, err := kvShape(value.Map, "kv descriptor")
	if err != nil {
		return KvDescriptor{}, err
	}
	tenant, err := kvText(value.Map, "tenant", "kv descriptor")
	if err != nil {
		return KvDescriptor{}, err
	}
	modelName, err := kvText(value.Map, "model", "kv descriptor")
	if err != nil {
		return KvDescriptor{}, err
	}
	session, err := kvText(value.Map, "session", "kv descriptor")
	if err != nil {
		return KvDescriptor{}, err
	}
	layer, err := kvU32(value.Map, "layer", "kv descriptor", "does not fit u32")
	if err != nil {
		return KvDescriptor{}, err
	}
	pageIndex, err := kvU64(value.Map, "page_index", "kv descriptor")
	if err != nil {
		return KvDescriptor{}, err
	}
	pageCount, err := kvU64(value.Map, "page_count", "kv descriptor")
	if err != nil {
		return KvDescriptor{}, err
	}
	seqStart, err := kvU64(value.Map, "seq_start", "kv descriptor")
	if err != nil {
		return KvDescriptor{}, err
	}
	seqEnd, err := kvU64(value.Map, "seq_end", "kv descriptor")
	if err != nil {
		return KvDescriptor{}, err
	}
	dtype, err := kvText(value.Map, "dtype", "kv descriptor")
	if err != nil {
		return KvDescriptor{}, err
	}
	headCount, err := kvU32(value.Map, "head_count", "kv descriptor", "does not fit u32")
	if err != nil {
		return KvDescriptor{}, err
	}
	headDim, err := kvU32(value.Map, "head_dim", "kv descriptor", "does not fit u32")
	if err != nil {
		return KvDescriptor{}, err
	}
	pageBytes, err := kvU64(value.Map, "page_bytes", "kv descriptor")
	if err != nil {
		return KvDescriptor{}, err
	}
	descriptor := KvDescriptor{
		Tenant: tenant, Model: modelName, Session: session, Layer: layer,
		PageIndex: pageIndex, PageCount: pageCount, SeqStart: seqStart, SeqEnd: seqEnd,
		Dtype: dtype, HeadCount: headCount, HeadDim: headDim, Shape: shape,
		PageBytes: pageBytes,
	}
	// Canonicality: the re-encoded bytes must be identical.
	canonical, err := descriptor.CanonicalBytes()
	if err != nil {
		return KvDescriptor{}, err
	}
	if string(canonical) != string(encoded) {
		return KvDescriptor{}, werr.Newf(werr.Corrupt, "kv descriptor is not canonical")
	}
	return descriptor, nil
}

// KvProvDescriptor is the capability descriptor of a provenance-bound
// (mode-19) KV page: the mode-12 page identity plus the codec's
// `descriptor_root`, so a scope that names this descriptor id names the
// provenance as well as the page.
type KvProvDescriptor struct {
	KvDescriptor
	ProvenanceRoot model.Hash32
}

// NewKvProvDescriptor builds a descriptor from a mode-19 input, its tenant,
// exact page bytes and the codec descriptor root.
func NewKvProvDescriptor(input modes.KvCacheInput, tenant string, pageBytes uint64, provenanceRoot model.Hash32) (KvProvDescriptor, error) {
	page, err := NewKvDescriptor(input, tenant, pageBytes)
	if err != nil {
		return KvProvDescriptor{}, err
	}
	return KvProvDescriptor{KvDescriptor: page, ProvenanceRoot: provenanceRoot}, nil
}

func (d KvProvDescriptor) value() wcb.Value {
	base := d.KvDescriptor.value().Map
	out := make(map[string]wcb.Value, len(base)+1)
	for key, value := range base {
		out[key] = value
	}
	out["schema"] = wcb.TextValue(KvProvDescriptorSchema)
	out["provenance_root"] = wcb.TextValue(d.ProvenanceRoot.Hex())
	return wcb.MapValue(out)
}

// CanonicalBytes returns the canonical WCB descriptor bytes.
func (d KvProvDescriptor) CanonicalBytes() ([]byte, error) {
	encoded, err := wcb.EncodeDefault(d.value())
	if err != nil {
		return nil, werr.FromCodec(err)
	}
	return encoded, nil
}

// ID is H("weft/kv/prov_capability/v1", canonical bytes).
func (d KvProvDescriptor) ID() (model.Hash32, error) {
	encoded, err := d.CanonicalBytes()
	if err != nil {
		return model.Hash32{}, err
	}
	return hash.Domain(DomainKvProvDescriptor, encoded), nil
}

// Namespace is the grant namespace: `kv.<tenant>`.
func (d KvProvDescriptor) Namespace() string { return KvNamespacePrefix + d.Tenant }

// ParseKvProvDescriptor strictly decodes a canonical provenance-bound
// descriptor (mirrors Rust `KvProvDescriptor::from_canonical_bytes`).
func ParseKvProvDescriptor(encoded []byte) (KvProvDescriptor, error) {
	value, err := wcb.DecodeDefault(encoded)
	if err != nil {
		return KvProvDescriptor{}, werr.FromCodec(err)
	}
	if value.Kind != wcb.Map {
		return KvProvDescriptor{}, werr.Newf(werr.Corrupt,
			"kv provenance descriptor is not a map")
	}
	known := map[string]bool{
		"schema": true, "tenant": true, "model": true, "session": true,
		"layer": true, "page_index": true, "page_count": true,
		"seq_start": true, "seq_end": true, "dtype": true,
		"head_count": true, "head_dim": true, "shape": true, "page_bytes": true,
		"provenance_root": true,
	}
	for key := range value.Map {
		if !known[key] {
			return KvProvDescriptor{}, werr.Newf(werr.Corrupt,
				"unknown kv provenance descriptor key `%s`", key)
		}
	}
	if len(value.Map) != len(known) {
		return KvProvDescriptor{}, werr.Newf(werr.Corrupt,
			"kv provenance descriptor is missing a field")
	}
	schema, err := kvText(value.Map, "schema", "kv provenance descriptor")
	if err != nil {
		return KvProvDescriptor{}, err
	}
	if schema != KvProvDescriptorSchema {
		return KvProvDescriptor{}, werr.Newf(werr.Corrupt,
			"unknown kv provenance descriptor schema")
	}
	shape, err := kvShape(value.Map, "kv provenance descriptor")
	if err != nil {
		return KvProvDescriptor{}, err
	}
	tenant, err := kvText(value.Map, "tenant", "kv provenance descriptor")
	if err != nil {
		return KvProvDescriptor{}, err
	}
	modelName, err := kvText(value.Map, "model", "kv provenance descriptor")
	if err != nil {
		return KvProvDescriptor{}, err
	}
	session, err := kvText(value.Map, "session", "kv provenance descriptor")
	if err != nil {
		return KvProvDescriptor{}, err
	}
	layer, err := kvU32(value.Map, "layer", "kv provenance descriptor", "layer exceeds u32")
	if err != nil {
		return KvProvDescriptor{}, err
	}
	pageIndex, err := kvU64(value.Map, "page_index", "kv provenance descriptor")
	if err != nil {
		return KvProvDescriptor{}, err
	}
	pageCount, err := kvU64(value.Map, "page_count", "kv provenance descriptor")
	if err != nil {
		return KvProvDescriptor{}, err
	}
	seqStart, err := kvU64(value.Map, "seq_start", "kv provenance descriptor")
	if err != nil {
		return KvProvDescriptor{}, err
	}
	seqEnd, err := kvU64(value.Map, "seq_end", "kv provenance descriptor")
	if err != nil {
		return KvProvDescriptor{}, err
	}
	dtype, err := kvText(value.Map, "dtype", "kv provenance descriptor")
	if err != nil {
		return KvProvDescriptor{}, err
	}
	headCount, err := kvU32(value.Map, "head_count", "kv provenance descriptor", "head_count exceeds u32")
	if err != nil {
		return KvProvDescriptor{}, err
	}
	headDim, err := kvU32(value.Map, "head_dim", "kv provenance descriptor", "head_dim exceeds u32")
	if err != nil {
		return KvProvDescriptor{}, err
	}
	pageBytes, err := kvU64(value.Map, "page_bytes", "kv provenance descriptor")
	if err != nil {
		return KvProvDescriptor{}, err
	}
	rootText, err := kvText(value.Map, "provenance_root", "kv provenance descriptor")
	if err != nil {
		return KvProvDescriptor{}, err
	}
	provenanceRoot, err := hash.FromHex(rootText)
	if err != nil {
		return KvProvDescriptor{}, werr.Newf(werr.Corrupt, "kv provenance root is not a hash")
	}
	descriptor := KvProvDescriptor{
		KvDescriptor: KvDescriptor{
			Tenant: tenant, Model: modelName, Session: session, Layer: layer,
			PageIndex: pageIndex, PageCount: pageCount, SeqStart: seqStart,
			SeqEnd: seqEnd, Dtype: dtype, HeadCount: headCount, HeadDim: headDim,
			Shape: shape, PageBytes: pageBytes,
		},
		ProvenanceRoot: provenanceRoot,
	}
	canonical, err := descriptor.CanonicalBytes()
	if err != nil {
		return KvProvDescriptor{}, err
	}
	if string(canonical) != string(encoded) {
		return KvProvDescriptor{}, werr.Newf(werr.Corrupt,
			"kv provenance descriptor is not canonical")
	}
	return descriptor, nil
}

func kvText(values map[string]wcb.Value, key, subject string) (string, error) {
	value, ok := values[key]
	if !ok || value.Kind != wcb.Text {
		return "", werr.Newf(werr.Corrupt, "%s `%s` is not text", subject, key)
	}
	return value.Str, nil
}

func kvU64(values map[string]wcb.Value, key, subject string) (uint64, error) {
	value, ok := values[key]
	if !ok || value.Kind != wcb.U64 {
		return 0, werr.Newf(werr.Corrupt, "%s `%s` is not u64", subject, key)
	}
	return value.U, nil
}

func kvU32(values map[string]wcb.Value, key, subject, overflow string) (uint32, error) {
	number, err := kvU64(values, key, subject)
	if err != nil {
		return 0, err
	}
	if number > 0xFFFF_FFFF {
		return 0, werr.Newf(werr.Corrupt, "%s %s", subject, overflow)
	}
	return uint32(number), nil
}

func kvShape(values map[string]wcb.Value, subject string) ([]uint64, error) {
	value, ok := values["shape"]
	if !ok || value.Kind != wcb.Array {
		return nil, werr.Newf(werr.Corrupt, "%s `shape` is not an array", subject)
	}
	shape := make([]uint64, 0, len(value.Array))
	for _, item := range value.Array {
		if item.Kind != wcb.U64 {
			return nil, werr.Newf(werr.Corrupt, "%s shape entry is not u64", subject)
		}
		shape = append(shape, item.U)
	}
	return shape, nil
}

// storedKvDescriptor is whichever descriptor an object record carries.
type storedKvDescriptor struct {
	Mode       KvPageMode
	Page       KvDescriptor
	Provenance KvProvDescriptor
}

func (d storedKvDescriptor) descriptorID() (model.Hash32, error) {
	if d.Mode == KvPageModeProvenance {
		return d.Provenance.ID()
	}
	return d.Page.ID()
}

func (d storedKvDescriptor) namespace() string {
	if d.Mode == KvPageModeProvenance {
		return d.Provenance.Namespace()
	}
	return d.Page.Namespace()
}

func (d storedKvDescriptor) tenant() string {
	if d.Mode == KvPageModeProvenance {
		return d.Provenance.Tenant
	}
	return d.Page.Tenant
}

// KvPageWrite is the result of writing one mode-12 page.
type KvPageWrite struct {
	ObjectID     model.Hash32
	DescriptorID model.Hash32
	FrameBytes   uint64
	PageBytes    uint64
}

// KvProvPageWrite is the result of writing one mode-19 page.
type KvProvPageWrite struct {
	ObjectID       model.Hash32
	DescriptorID   model.Hash32
	ProvenanceRoot model.Hash32
	FrameBytes     uint64
	PageBytes      uint64
}

// WriteKvPage stores one mode-12 KV page guarded by a canonical capability
// descriptor (mirrors Rust `Store::write_kv_page`).
func (s *Store) WriteKvPage(parent model.Hash32, name []byte, tenant string, input modes.KvCacheInput, elements []byte, uid, gid uint64) (KvPageWrite, error) {
	lim := limits.Default()
	frameBytes, err := modes.EncodeKvPage(input, elements, lim)
	if err != nil {
		return KvPageWrite{}, werr.FromCodec(err)
	}
	descriptor, err := NewKvDescriptor(input, tenant, uint64(len(elements)))
	if err != nil {
		return KvPageWrite{}, err
	}
	descriptorID, err := descriptor.ID()
	if err != nil {
		return KvPageWrite{}, err
	}
	attrs, err := kvPageAttrs(descriptor)
	if err != nil {
		return KvPageWrite{}, err
	}
	objectID, err := s.CreateFile(parent, name, frameBytes, 0o644, uid, gid, attrs)
	if err != nil {
		return KvPageWrite{}, err
	}
	return KvPageWrite{
		ObjectID:     objectID,
		DescriptorID: descriptorID,
		FrameBytes:   uint64(len(frameBytes)),
		PageBytes:    uint64(len(elements)),
	}, nil
}

// WriteKvProvPage stores one provenance-bound (mode-19) KV page (mirrors Rust
// `Store::write_kv_prov_page`).
//
// The codec descriptor root is re-derived from the encoded frame, never taken
// from the caller, so the stored capability descriptor names the provenance the
// frame actually carries.
func (s *Store) WriteKvProvPage(parent model.Hash32, name []byte, tenant string, input modes.KvCacheInput, elements []byte, provenance modes.KvProvenanceInput, uid, gid uint64) (KvProvPageWrite, error) {
	lim := limits.Default()
	frameBytes, err := modes.EncodeKvProvPage(input, elements, provenance, lim)
	if err != nil {
		return KvProvPageWrite{}, werr.FromCodec(err)
	}
	parsed, err := frame.Parse(frameBytes, lim)
	if err != nil {
		return KvProvPageWrite{}, werr.FromCodec(err)
	}
	codecDescriptor, err := modes.KvProvMetadata(parsed, lim)
	if err != nil {
		return KvProvPageWrite{}, werr.FromCodec(err)
	}
	provenanceRoot, err := codecDescriptor.Root(lim)
	if err != nil {
		return KvProvPageWrite{}, werr.FromCodec(err)
	}
	descriptor, err := NewKvProvDescriptor(input, tenant, uint64(len(elements)), provenanceRoot)
	if err != nil {
		return KvProvPageWrite{}, err
	}
	descriptorID, err := descriptor.ID()
	if err != nil {
		return KvProvPageWrite{}, err
	}
	attrs, err := kvProvPageAttrs(descriptor)
	if err != nil {
		return KvProvPageWrite{}, err
	}
	objectID, err := s.CreateFile(parent, name, frameBytes, 0o644, uid, gid, attrs)
	if err != nil {
		return KvProvPageWrite{}, err
	}
	return KvProvPageWrite{
		ObjectID:       objectID,
		DescriptorID:   descriptorID,
		ProvenanceRoot: provenanceRoot,
		FrameBytes:     uint64(len(frameBytes)),
		PageBytes:      uint64(len(elements)),
	}, nil
}

// kvPageAttrs is the mode-12 attribute set (Rust `descriptor_attrs`).
func kvPageAttrs(descriptor KvDescriptor) (map[string]wcb.Value, error) {
	canonical, err := descriptor.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	id, err := descriptor.ID()
	if err != nil {
		return nil, err
	}
	return map[string]wcb.Value{
		AttrKvDescriptor:   wcb.TextValue(hex.EncodeToString(canonical)),
		AttrKvDescriptorID: wcb.TextValue(id.Hex()),
		AttrKvTenant:       wcb.TextValue(descriptor.Tenant),
		AttrKvModel:        wcb.TextValue(descriptor.Model),
		AttrKvSession:      wcb.TextValue(descriptor.Session),
		AttrKvPageBytes:    wcb.U64Value(descriptor.PageBytes),
	}, nil
}

// kvProvPageAttrs is the mode-19 attribute set (Rust `prov_descriptor_attrs`).
func kvProvPageAttrs(descriptor KvProvDescriptor) (map[string]wcb.Value, error) {
	canonical, err := descriptor.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	id, err := descriptor.ID()
	if err != nil {
		return nil, err
	}
	return map[string]wcb.Value{
		AttrKvDescriptor:   wcb.TextValue(hex.EncodeToString(canonical)),
		AttrKvDescriptorID: wcb.TextValue(id.Hex()),
		AttrKvTenant:       wcb.TextValue(descriptor.Tenant),
		AttrKvModel:        wcb.TextValue(descriptor.Model),
		AttrKvSession:      wcb.TextValue(descriptor.Session),
		AttrKvPageBytes:    wcb.U64Value(descriptor.PageBytes),
		AttrKvMode:         wcb.U64Value(KvPageModeProvenance.Value()),
		AttrKVProvRoot:     wcb.TextValue(descriptor.ProvenanceRoot.Hex()),
	}, nil
}

// KvDescriptor returns the mode-12 capability descriptor of a stored page.
//
// This is *not* an authorization path: it exists so verification and
// administration can inspect identity. It never returns page bytes.
func (s *Store) KvDescriptor(id model.Hash32) (KvDescriptor, error) {
	record, err := s.ObjectMeta(id)
	if err != nil {
		return KvDescriptor{}, err
	}
	return kvDescriptorOf(record)
}

// KvProvDescriptor returns the provenance-bound descriptor of a stored
// mode-19 page (metadata only, never page bytes).
func (s *Store) KvProvDescriptor(id model.Hash32) (KvProvDescriptor, error) {
	record, err := s.ObjectMeta(id)
	if err != nil {
		return KvProvDescriptor{}, err
	}
	return kvProvDescriptorOf(record)
}

// KvPageMode returns the frame mode of a stored KV page (metadata only).
func (s *Store) KvPageMode(id model.Hash32) (KvPageMode, error) {
	record, err := s.ObjectMeta(id)
	if err != nil {
		return 0, err
	}
	descriptor, err := kvDescriptorOfAny(record)
	if err != nil {
		return 0, err
	}
	return descriptor.Mode, nil
}

// KvPrincipal is the read identity for a KV page: the POSIX principal plus the
// capability scope that names the page. A nil Capability never authorizes.
//
// It exists because Rust's `Principal` carries `Option<VerifiedEnvelope>` while
// Go's `auth.Principal` deliberately carries no capability at all; see the
// package comment at the top of this file.
type KvPrincipal struct {
	Principal  auth.Principal
	Capability *auth.Capability
}

// NewKvPrincipal builds a KV read identity.
func NewKvPrincipal(principal auth.Principal, capability *auth.Capability) KvPrincipal {
	return KvPrincipal{Principal: principal, Capability: capability}
}

// readKvAuthorized is the shared authorization preamble.
//
// Ordering is normative and identical to Rust: object record → descriptor →
// derived descriptor id → capability presence and validity →
// tenant/namespace/root grant → POSIX authorization → read. Every failure
// before a byte is returned is the same KvDenied.
func (s *Store) readKvAuthorized(id model.Hash32, principal KvPrincipal, nowNS int64) (storedKvDescriptor, []byte, error) {
	record, err := s.ObjectMeta(id)
	if err != nil {
		return storedKvDescriptor{}, nil, kvDenied()
	}
	descriptor, err := kvDescriptorOfAny(record)
	if err != nil {
		return storedKvDescriptor{}, nil, kvDenied()
	}
	descriptorID, err := descriptor.descriptorID()
	if err != nil {
		return storedKvDescriptor{}, nil, kvDenied()
	}
	capability := principal.Capability
	if capability == nil || capability.Scope == nil {
		return storedKvDescriptor{}, nil, kvDenied()
	}
	if err := capability.CheckValidAt(nowNS); err != nil {
		return storedKvDescriptor{}, nil, kvDenied()
	}
	if capability.Scope.Principal != descriptor.tenant() ||
		!capability.AllowsNamespace(descriptor.namespace()) ||
		!capability.AllowsRoot(descriptorID) {
		return storedKvDescriptor{}, nil, kvDenied()
	}
	if !auth.CanRead(record, principal.Principal) {
		return storedKvDescriptor{}, nil, kvDenied()
	}
	bytes, err := s.ReadObject(id)
	if err != nil {
		return storedKvDescriptor{}, nil, kvDenied()
	}
	return descriptor, bytes, nil
}

// ReadKvPage reads one mode-12 KV page under an authenticated capability.
//
// Fails closed before any byte is returned with KvDenied for an unknown object,
// a missing or malformed descriptor, a descriptor id that does not match its
// bytes, an absent or expired capability, a foreign tenant, a missing
// `kv.<tenant>` namespace, a missing descriptor id in the scope's roots, or a
// POSIX/ACL denial.
func (s *Store) ReadKvPage(id model.Hash32, principal KvPrincipal, nowNS int64) (modes.DecodedKvPage, error) {
	stored, bytes, err := s.readKvAuthorized(id, principal, nowNS)
	if err != nil {
		return modes.DecodedKvPage{}, err
	}
	if stored.Mode != KvPageMode12 {
		return modes.DecodedKvPage{}, werr.Newf(werr.Corrupt,
			"kv page is provenance-bound (mode 19); use read_kv_prov_page")
	}
	lim := limits.Default()
	parsed, err := frame.Parse(bytes, lim)
	if err != nil {
		return modes.DecodedKvPage{}, werr.FromCodec(err)
	}
	decoded, err := modes.DecodeKvPage(parsed, lim)
	if err != nil {
		return modes.DecodedKvPage{}, werr.FromCodec(err)
	}
	fromFrame := KvDescriptor{
		Tenant:    stored.Page.Tenant,
		Model:     decoded.Meta.Model,
		Session:   decoded.Meta.Session,
		Layer:     decoded.Meta.Layer,
		PageIndex: decoded.Meta.PageIndex,
		PageCount: decoded.Meta.PageCount,
		SeqStart:  decoded.Meta.SeqStart,
		SeqEnd:    decoded.Meta.SeqEnd,
		Dtype:     decoded.Meta.Dtype.Name,
		HeadCount: decoded.Meta.HeadCount,
		HeadDim:   decoded.Meta.HeadDim,
		Shape:     decoded.Meta.Shape,
		PageBytes: decoded.Meta.PageBytes,
	}
	if !kvDescriptorEqual(fromFrame, stored.Page) {
		return modes.DecodedKvPage{}, werr.Newf(werr.Corrupt,
			"kv page descriptor does not match its frame metadata")
	}
	return decoded, nil
}

// ReadKvProvPage reads one provenance-bound (mode-19) KV page under an
// authenticated capability.
//
// The authorization preamble is identical to ReadKvPage. After authorization
// the mode-19 descriptor is decoded and compared field by field with the stored
// capability descriptor, including the codec descriptor root; any mismatch is
// Corrupt. A mode-12 object is never decoded by this path and a mode-19 object
// is never decoded by the mode-12 path: a request whose scope does not name the
// object emits zero bytes.
func (s *Store) ReadKvProvPage(id model.Hash32, principal KvPrincipal, nowNS int64) (modes.DecodedKvProvPage, error) {
	stored, bytes, err := s.readKvAuthorized(id, principal, nowNS)
	if err != nil {
		return modes.DecodedKvProvPage{}, err
	}
	if stored.Mode != KvPageModeProvenance {
		return modes.DecodedKvProvPage{}, werr.Newf(werr.Corrupt,
			"kv page is a plain mode-12 page; use read_kv_page")
	}
	lim := limits.Default()
	parsed, err := frame.Parse(bytes, lim)
	if err != nil {
		return modes.DecodedKvProvPage{}, werr.FromCodec(err)
	}
	decoded, err := modes.DecodeKvProvPage(parsed, lim)
	if err != nil {
		return modes.DecodedKvProvPage{}, werr.FromCodec(err)
	}
	fromFrame := KvProvDescriptor{
		KvDescriptor: KvDescriptor{
			Tenant:    stored.Provenance.Tenant,
			Model:     decoded.Descriptor.Page.Model,
			Session:   decoded.Descriptor.Page.Session,
			Layer:     decoded.Descriptor.Page.Layer,
			PageIndex: decoded.Descriptor.Page.PageIndex,
			PageCount: decoded.Descriptor.Page.PageCount,
			SeqStart:  decoded.Descriptor.Page.SeqStart,
			SeqEnd:    decoded.Descriptor.Page.SeqEnd,
			Dtype:     decoded.Descriptor.Page.Dtype.Name,
			HeadCount: decoded.Descriptor.Page.HeadCount,
			HeadDim:   decoded.Descriptor.Page.HeadDim,
			Shape:     decoded.Descriptor.Page.Shape,
			PageBytes: decoded.Descriptor.Page.PageBytes,
		},
		ProvenanceRoot: decoded.Root,
	}
	if !kvProvDescriptorEqual(fromFrame, stored.Provenance) {
		return modes.DecodedKvProvPage{}, werr.Newf(werr.Corrupt,
			"kv provenance descriptor does not match its frame metadata")
	}
	return decoded, nil
}

func kvDescriptorEqual(a, b KvDescriptor) bool {
	if a.Tenant != b.Tenant || a.Model != b.Model || a.Session != b.Session ||
		a.Layer != b.Layer || a.PageIndex != b.PageIndex || a.PageCount != b.PageCount ||
		a.SeqStart != b.SeqStart || a.SeqEnd != b.SeqEnd || a.Dtype != b.Dtype ||
		a.HeadCount != b.HeadCount || a.HeadDim != b.HeadDim || a.PageBytes != b.PageBytes {
		return false
	}
	if len(a.Shape) != len(b.Shape) {
		return false
	}
	for index := range a.Shape {
		if a.Shape[index] != b.Shape[index] {
			return false
		}
	}
	return true
}

func kvProvDescriptorEqual(a, b KvProvDescriptor) bool {
	return a.ProvenanceRoot == b.ProvenanceRoot && kvDescriptorEqual(a.KvDescriptor, b.KvDescriptor)
}

// kvDescriptorOf extracts and validates the mode-12 descriptor an object record
// carries.
func kvDescriptorOf(record model.ObjectRecord) (KvDescriptor, error) {
	text, ok := record.Attrs[AttrKvDescriptor]
	if !ok || text.Kind != wcb.Text {
		return KvDescriptor{}, werr.Newf(werr.Corrupt, "kv page has no descriptor")
	}
	encoded, err := hex.DecodeString(text.Str)
	if err != nil {
		return KvDescriptor{}, werr.Newf(werr.Corrupt, "kv descriptor is not hex")
	}
	descriptor, err := ParseKvDescriptor(encoded)
	if err != nil {
		return KvDescriptor{}, err
	}
	idText, ok := record.Attrs[AttrKvDescriptorID]
	if !ok || idText.Kind != wcb.Text {
		return KvDescriptor{}, werr.Newf(werr.Corrupt, "kv page has no descriptor id")
	}
	recorded, err := hash.FromHex(idText.Str)
	if err != nil {
		return KvDescriptor{}, werr.Newf(werr.Corrupt, "kv descriptor id is not a hash")
	}
	derived, err := descriptor.ID()
	if err != nil {
		return KvDescriptor{}, err
	}
	if recorded != derived {
		return KvDescriptor{}, werr.Newf(werr.Corrupt,
			"kv descriptor id does not match its bytes")
	}
	return descriptor, nil
}

// kvProvDescriptorOf extracts and validates the provenance-bound descriptor an
// object record carries.
func kvProvDescriptorOf(record model.ObjectRecord) (KvProvDescriptor, error) {
	text, ok := record.Attrs[AttrKvDescriptor]
	if !ok || text.Kind != wcb.Text {
		return KvProvDescriptor{}, werr.Newf(werr.Corrupt, "kv page has no descriptor")
	}
	encoded, err := hex.DecodeString(text.Str)
	if err != nil {
		return KvProvDescriptor{}, werr.Newf(werr.Corrupt, "kv descriptor is not hex")
	}
	descriptor, err := ParseKvProvDescriptor(encoded)
	if err != nil {
		return KvProvDescriptor{}, err
	}
	idText, ok := record.Attrs[AttrKvDescriptorID]
	if !ok || idText.Kind != wcb.Text {
		return KvProvDescriptor{}, werr.Newf(werr.Corrupt, "kv page has no descriptor id")
	}
	recorded, err := hash.FromHex(idText.Str)
	if err != nil {
		return KvProvDescriptor{}, werr.Newf(werr.Corrupt, "kv descriptor id is not a hash")
	}
	derived, err := descriptor.ID()
	if err != nil {
		return KvProvDescriptor{}, err
	}
	if recorded != derived {
		return KvProvDescriptor{}, werr.Newf(werr.Corrupt,
			"kv descriptor id does not match its bytes")
	}
	// The recorded provenance root must be the one the descriptor names. Rust
	// checks only a text-valued attribute (`if let Some(Value::Str(..))`), so a
	// non-text value is ignored here too; parity means the same accept/reject
	// decision on the same store state.
	if rootText, ok := record.Attrs[AttrKVProvRoot]; ok && rootText.Kind == wcb.Text {
		recordedRoot, err := hash.FromHex(rootText.Str)
		if err != nil {
			return KvProvDescriptor{}, werr.Newf(werr.Corrupt,
				"kv provenance root is not a hash")
		}
		if recordedRoot != descriptor.ProvenanceRoot {
			return KvProvDescriptor{}, werr.Newf(werr.Corrupt,
				"kv provenance root attribute does not match its descriptor")
		}
	}
	return descriptor, nil
}

// kvDescriptorOfAny reads whichever descriptor a record carries. An absent mode
// attribute means mode 12, which keeps every pre-R5 page readable.
func kvDescriptorOfAny(record model.ObjectRecord) (storedKvDescriptor, error) {
	modeValue, ok := record.Attrs[AttrKvMode]
	if !ok {
		page, err := kvDescriptorOf(record)
		if err != nil {
			return storedKvDescriptor{}, err
		}
		return storedKvDescriptor{Mode: KvPageMode12, Page: page}, nil
	}
	if modeValue.Kind != wcb.U64 {
		return storedKvDescriptor{}, werr.Newf(werr.Corrupt,
			"kv page mode is not recognised")
	}
	switch modeValue.U {
	case KvPageMode12.Value():
		page, err := kvDescriptorOf(record)
		if err != nil {
			return storedKvDescriptor{}, err
		}
		return storedKvDescriptor{Mode: KvPageMode12, Page: page}, nil
	case KvPageModeProvenance.Value():
		provenance, err := kvProvDescriptorOf(record)
		if err != nil {
			return storedKvDescriptor{}, err
		}
		return storedKvDescriptor{Mode: KvPageModeProvenance, Provenance: provenance}, nil
	default:
		return storedKvDescriptor{}, werr.Newf(werr.Corrupt,
			"kv page mode is not recognised")
	}
}
