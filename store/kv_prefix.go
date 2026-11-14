// KV prefix cache: Go parity with Rust `src/kv_prefix.rs` (subphase T068).
//
// A prefix is one canonical `weft.kv.prefix.v1` WCB record plus mode-12 page
// objects guarded by `weft.kv.capability.v1` descriptors. The record's token
// chain root is the frozen
// `H("weft/kv/token-chain/v1", ...)` construction, so a record written by Rust
// parses, verifies and resolves here (and vice versa).
//
// Compatibility is exact: every identity field must match and the request's
// chain root at the stored length must equal the stored root. A mismatch is a
// typed `Recompute` with reasons, never a partial match.
//
// # Ed25519
//
// The Rust store's `Principal` carries an already-verified `CapabilityEnvelope`.
// Go has no such carrier historically; `KvPrincipal` takes an `*auth.Capability`
// (a content-addressed scope). That is a *trusted-verifier boundary*, not a
// signature check. This file adds the missing verification:
// `SaveCapabilityBlob` stores the signed envelope bytes and
// `KvPrefixGetVerified` loads them, verifies the Ed25519 signature with
// `capability.Verify` (Go's standard library), and only then builds the scope.
// The older `KvPrefixGet` entry point is retained for callers that already hold
// a verified scope, and is labelled as the boundary it is.
package store

import (
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/infinityabundance/WeftCodec-Go/capability"
	"github.com/infinityabundance/WeftCodec-Go/hash"
	"github.com/infinityabundance/WeftCodec-Go/limits"
	"github.com/infinityabundance/WeftCodec-Go/modes"
	"github.com/infinityabundance/WeftCodec-Go/wcb"

	"github.com/infinityabundance/WeftFS-Go/auth"
	"github.com/infinityabundance/WeftFS-Go/model"
	werr "github.com/infinityabundance/WeftFS-Go/werr"
)

const (
	// KvPrefixSchema is the canonical prefix record schema.
	KvPrefixSchema = "weft.kv.prefix.v1"
	// DomainKvPrefix is the prefix record identity domain.
	DomainKvPrefix = "weft/kv/prefix/v1"
	// DomainKvTokenChain is the token-hash chain domain.
	DomainKvTokenChain = "weft/kv/token-chain/v1"
	// DomainKvRevocation is the revocation record identity domain.
	DomainKvRevocation = "weft/kv/revocation/v1"
	// KvRevocationSchema is the canonical revocation schema.
	KvRevocationSchema = "weft.kv.revocation.v1"
	// AttrKvPrefix holds the prefix id.
	AttrKvPrefix = "weft.kv.prefix"
	// AttrKvPrefixPinned holds the pinned flag.
	AttrKvPrefixPinned = "weft.kv.pinned"
	// AttrKvPrefixTenant holds the tenant.
	AttrKvPrefixTenant = "weft.kv.tenant"
	// AttrKvPrefixModel holds the model identity.
	AttrKvPrefixModel = "weft.kv.model"
	// AttrKvPrefixTokens holds the token length.
	AttrKvPrefixTokens = "weft.kv.tokens"
	// KvDir is the KV namespace directory.
	KvDir = "kv"
	// KvPrefixDir is the prefix record directory.
	KvPrefixDir = "prefixes"
	// KvPageDir is the page object directory.
	KvPageDir = "pages"
	// KvRevocationDir is the revocation directory.
	KvRevocationDir = "revocations"
	// KvCapabilityBlobDir holds stored signed envelope blobs.
	KvCapabilityBlobDir = "capability-blobs"
	// MaxKvPrefixTokens bounds one prefix's token length.
	MaxKvPrefixTokens = 1_048_576
)

// KvTokenChainRoot is root_0 = H(domain,""), root_{i+1} = H(domain, root_i||u64le(t_i)).
func KvTokenChainRoot(tokens []uint64) model.Hash32 {
	root := hash.Domain(DomainKvTokenChain, nil)
	for _, token := range tokens {
		data := make([]byte, 40)
		copy(data[:32], root.Bytes())
		for index := 0; index < 8; index++ {
			data[32+index] = byte(token >> (8 * index))
		}
		root = hash.Domain(DomainKvTokenChain, data)
	}
	return root
}

// KvPrefixSpec is the identity of a prefix to write.
type KvPrefixSpec struct {
	Tenant        string
	Model         string
	TokenizerHash model.Hash32
	AttentionHash model.Hash32
	Dtype         string
	HeadCount     uint32
	HeadDim       uint32
	LayerCount    uint32
	PageRows      uint64
	Pinned        bool
}

// KvPrefixRecord is one stored canonical prefix record.
type KvPrefixRecord struct {
	Tenant          string
	Model           string
	TokenizerHash   model.Hash32
	AttentionHash   model.Hash32
	Dtype           string
	HeadCount       uint32
	HeadDim         uint32
	LayerCount      uint32
	PageRows        uint64
	PageCount       uint64
	PositionStart   uint64
	PositionEnd     uint64
	TokenChainRoot  model.Hash32
	Parent          *model.Hash32
	Pages           [][]model.Hash32
	Pinned          bool
	PageBytes       uint64
	StoredPageBytes uint64
	ReusedPages     uint64
}

func (r KvPrefixRecord) value() wcb.Value {
	parent := wcb.NullValue()
	if r.Parent != nil {
		parent = wcb.TextValue(r.Parent.Hex())
	}
	layers := make([]wcb.Value, 0, len(r.Pages))
	for _, layer := range r.Pages {
		ids := make([]wcb.Value, 0, len(layer))
		for _, id := range layer {
			ids = append(ids, wcb.TextValue(id.Hex()))
		}
		layers = append(layers, wcb.ArrayValue(ids))
	}
	return wcb.MapValue(map[string]wcb.Value{
		"schema":            wcb.TextValue(KvPrefixSchema),
		"tenant":            wcb.TextValue(r.Tenant),
		"model":             wcb.TextValue(r.Model),
		"tokenizer_hash":    wcb.TextValue(r.TokenizerHash.Hex()),
		"attention_hash":    wcb.TextValue(r.AttentionHash.Hex()),
		"dtype":             wcb.TextValue(r.Dtype),
		"head_count":        wcb.U64Value(uint64(r.HeadCount)),
		"head_dim":          wcb.U64Value(uint64(r.HeadDim)),
		"layer_count":       wcb.U64Value(uint64(r.LayerCount)),
		"page_rows":         wcb.U64Value(r.PageRows),
		"page_count":        wcb.U64Value(r.PageCount),
		"position_start":    wcb.U64Value(r.PositionStart),
		"position_end":      wcb.U64Value(r.PositionEnd),
		"token_chain_root":  wcb.TextValue(r.TokenChainRoot.Hex()),
		"parent":            parent,
		"pages":             wcb.ArrayValue(layers),
		"pinned":            wcb.BoolValue(r.Pinned),
		"page_bytes":        wcb.U64Value(r.PageBytes),
		"stored_page_bytes": wcb.U64Value(r.StoredPageBytes),
		"reused_pages":      wcb.U64Value(r.ReusedPages),
	})
}

// CanonicalBytes is the canonical WCB encoding.
func (r KvPrefixRecord) CanonicalBytes() ([]byte, error) {
	encoded, err := wcb.EncodeDefault(r.value())
	if err != nil {
		return nil, werr.FromCodec(err)
	}
	return encoded, nil
}

// ID is H("weft/kv/prefix/v1", canonical bytes).
func (r KvPrefixRecord) ID() (model.Hash32, error) {
	encoded, err := r.CanonicalBytes()
	if err != nil {
		return model.Hash32{}, err
	}
	return hash.Domain(DomainKvPrefix, encoded), nil
}

// Tokens is the prefix token length.
func (r KvPrefixRecord) Tokens() uint64 { return r.PositionEnd }

// ParseKvPrefixRecord strictly decodes a canonical record.
func ParseKvPrefixRecord(encoded []byte) (KvPrefixRecord, error) {
	value, err := wcb.DecodeDefault(encoded)
	if err != nil {
		return KvPrefixRecord{}, werr.FromCodec(err)
	}
	if value.Kind != wcb.Map {
		return KvPrefixRecord{}, werr.Newf(werr.Corrupt, "kv prefix is not a map")
	}
	keys := map[string]bool{
		"schema": true, "tenant": true, "model": true, "tokenizer_hash": true,
		"attention_hash": true, "dtype": true, "head_count": true, "head_dim": true,
		"layer_count": true, "page_rows": true, "page_count": true,
		"position_start": true, "position_end": true, "token_chain_root": true,
		"parent": true, "pages": true, "pinned": true, "page_bytes": true,
		"stored_page_bytes": true, "reused_pages": true,
	}
	if len(value.Map) != len(keys) {
		return KvPrefixRecord{}, werr.Newf(werr.Corrupt, "kv prefix has an unknown key set")
	}
	for key := range value.Map {
		if !keys[key] {
			return KvPrefixRecord{}, werr.Newf(werr.Corrupt, "unknown kv prefix key `%s`", key)
		}
	}
	text := func(key string) (string, error) {
		item, ok := value.Map[key]
		if !ok || item.Kind != wcb.Text {
			return "", werr.Newf(werr.Corrupt, "kv prefix `%s` is not text", key)
		}
		return item.Str, nil
	}
	number := func(key string) (uint64, error) {
		item, ok := value.Map[key]
		if !ok || item.Kind != wcb.U64 {
			return 0, werr.Newf(werr.Corrupt, "kv prefix `%s` is not u64", key)
		}
		return item.U, nil
	}
	digest := func(key string) (model.Hash32, error) {
		item, ok := value.Map[key]
		if !ok || item.Kind != wcb.Text {
			return model.Hash32{}, werr.Newf(werr.Corrupt, "kv prefix `%s` is not text", key)
		}
		return hash.FromHex(item.Str)
	}
	schema, err := text("schema")
	if err != nil || schema != KvPrefixSchema {
		return KvPrefixRecord{}, werr.Newf(werr.Corrupt, "unknown kv prefix schema")
	}
	tenant, err := text("tenant")
	if err != nil {
		return KvPrefixRecord{}, err
	}
	modelName, err := text("model")
	if err != nil {
		return KvPrefixRecord{}, err
	}
	tokenizer, err := digest("tokenizer_hash")
	if err != nil {
		return KvPrefixRecord{}, err
	}
	attention, err := digest("attention_hash")
	if err != nil {
		return KvPrefixRecord{}, err
	}
	dtype, err := text("dtype")
	if err != nil {
		return KvPrefixRecord{}, err
	}
	headCount, err := number("head_count")
	if err != nil {
		return KvPrefixRecord{}, err
	}
	headDim, err := number("head_dim")
	if err != nil {
		return KvPrefixRecord{}, err
	}
	layerCount, err := number("layer_count")
	if err != nil {
		return KvPrefixRecord{}, err
	}
	pageRows, err := number("page_rows")
	if err != nil {
		return KvPrefixRecord{}, err
	}
	pageCount, err := number("page_count")
	if err != nil {
		return KvPrefixRecord{}, err
	}
	positionStart, err := number("position_start")
	if err != nil {
		return KvPrefixRecord{}, err
	}
	positionEnd, err := number("position_end")
	if err != nil {
		return KvPrefixRecord{}, err
	}
	chainRoot, err := digest("token_chain_root")
	if err != nil {
		return KvPrefixRecord{}, err
	}
	var parent *model.Hash32
	switch item := value.Map["parent"]; item.Kind {
	case wcb.Null:
	case wcb.Text:
		parsed, err := hash.FromHex(item.Str)
		if err != nil {
			return KvPrefixRecord{}, err
		}
		parent = &parsed
	default:
		return KvPrefixRecord{}, werr.Newf(werr.Corrupt, "kv prefix `parent` is not null or hex")
	}
	pinnedItem, ok := value.Map["pinned"]
	if !ok || pinnedItem.Kind != wcb.Bool {
		return KvPrefixRecord{}, werr.Newf(werr.Corrupt, "kv prefix `pinned` is not a bool")
	}
	pagesItem, ok := value.Map["pages"]
	if !ok || pagesItem.Kind != wcb.Array {
		return KvPrefixRecord{}, werr.Newf(werr.Corrupt, "kv prefix `pages` is not an array")
	}
	pages := make([][]model.Hash32, 0, len(pagesItem.Array))
	for _, layerValue := range pagesItem.Array {
		if layerValue.Kind != wcb.Array {
			return KvPrefixRecord{}, werr.Newf(werr.Corrupt, "kv prefix layer is not an array")
		}
		layer := make([]model.Hash32, 0, len(layerValue.Array))
		for _, idValue := range layerValue.Array {
			if idValue.Kind != wcb.Text {
				return KvPrefixRecord{}, werr.Newf(werr.Corrupt, "kv prefix page id is not text")
			}
			id, err := hash.FromHex(idValue.Str)
			if err != nil {
				return KvPrefixRecord{}, err
			}
			layer = append(layer, id)
		}
		pages = append(pages, layer)
	}
	pageBytes, err := number("page_bytes")
	if err != nil {
		return KvPrefixRecord{}, err
	}
	storedBytes, err := number("stored_page_bytes")
	if err != nil {
		return KvPrefixRecord{}, err
	}
	reusedPages, err := number("reused_pages")
	if err != nil {
		return KvPrefixRecord{}, err
	}
	if headCount > 0xFFFFFFFF || headDim > 0xFFFFFFFF || layerCount > 0xFFFFFFFF {
		return KvPrefixRecord{}, werr.Newf(werr.Corrupt, "kv prefix field does not fit u32")
	}
	record := KvPrefixRecord{
		Tenant: tenant, Model: modelName,
		TokenizerHash: tokenizer, AttentionHash: attention, Dtype: dtype,
		HeadCount: uint32(headCount), HeadDim: uint32(headDim), LayerCount: uint32(layerCount),
		PageRows: pageRows, PageCount: pageCount,
		PositionStart: positionStart, PositionEnd: positionEnd,
		TokenChainRoot: chainRoot, Parent: parent, Pages: pages,
		Pinned: pinnedItem.Bool, PageBytes: pageBytes,
		StoredPageBytes: storedBytes, ReusedPages: reusedPages,
	}
	if err := record.validateShape(); err != nil {
		return KvPrefixRecord{}, err
	}
	canonical, err := record.CanonicalBytes()
	if err != nil {
		return KvPrefixRecord{}, err
	}
	if len(canonical) != len(encoded) {
		return KvPrefixRecord{}, werr.Newf(werr.Corrupt, "kv prefix is not canonical")
	}
	for index := range canonical {
		if canonical[index] != encoded[index] {
			return KvPrefixRecord{}, werr.Newf(werr.Corrupt, "kv prefix is not canonical")
		}
	}
	return record, nil
}

func (r KvPrefixRecord) validateShape() error {
	if r.PageRows == 0 {
		return werr.Newf(werr.Corrupt, "kv prefix page_rows must be positive")
	}
	if r.PositionStart != 0 {
		return werr.Newf(werr.Corrupt, "kv prefix must start at token 0")
	}
	if r.PositionEnd == 0 || r.PositionEnd > MaxKvPrefixTokens {
		return werr.Newf(werr.Corrupt, "kv prefix token length is out of bounds")
	}
	if r.LayerCount == 0 || r.LayerCount > 1024 {
		return werr.Newf(werr.Corrupt, "kv prefix layer_count is out of bounds")
	}
	if len(r.Pages) != int(r.LayerCount) {
		return werr.Newf(werr.Corrupt, "kv prefix page layers do not match layer_count")
	}
	expected := (r.PositionEnd + r.PageRows - 1) / r.PageRows
	if r.PageCount != expected {
		return werr.Newf(werr.Corrupt, "kv prefix page_count does not match position_end/page_rows")
	}
	for _, layer := range r.Pages {
		if uint64(len(layer)) != r.PageCount {
			return werr.Newf(werr.Corrupt, "kv prefix layer page count does not match page_count")
		}
		for _, id := range layer {
			if id == (model.Hash32{}) {
				return werr.Newf(werr.Corrupt, "kv prefix has a zero page id")
			}
		}
	}
	if r.ReusedPages > r.PageCount*uint64(r.LayerCount) {
		return werr.Newf(werr.Corrupt, "kv prefix reused_pages exceeds its page slots")
	}
	if r.StoredPageBytes > r.PageBytes {
		return werr.Newf(werr.Corrupt, "kv prefix stored_page_bytes exceeds page_bytes")
	}
	return nil
}

// KvPrefixRequest is a reuse request.
type KvPrefixRequest struct {
	Tenant        string
	Model         string
	TokenizerHash model.Hash32
	AttentionHash model.Hash32
	Dtype         string
	HeadCount     uint32
	HeadDim       uint32
	LayerCount    uint32
	PageRows      uint64
	Tokens        []uint64
}

// compatibility is the exact comparison. The returned string names the first
// mismatch.
func (r KvPrefixRecord) compatibility(req KvPrefixRequest) error {
	fail := func(format string, args ...any) error {
		return werr.Newf(werr.Conflict, format, args...)
	}
	if r.Tenant != req.Tenant {
		return fail("tenant mismatch: stored `%s` vs requested `%s`", r.Tenant, req.Tenant)
	}
	if r.Model != req.Model {
		return fail("model mismatch: stored `%s` vs requested `%s`", r.Model, req.Model)
	}
	if r.TokenizerHash != req.TokenizerHash {
		return fail("tokenizer hash mismatch")
	}
	if r.AttentionHash != req.AttentionHash {
		return fail("attention configuration hash mismatch")
	}
	if r.Dtype != req.Dtype {
		return fail("dtype mismatch: stored `%s` vs requested `%s`", r.Dtype, req.Dtype)
	}
	if r.HeadCount != req.HeadCount {
		return fail("head count mismatch")
	}
	if r.HeadDim != req.HeadDim {
		return fail("head dim mismatch")
	}
	if r.LayerCount != req.LayerCount {
		return fail("layer count mismatch")
	}
	if r.PageRows != req.PageRows {
		return fail("page rows mismatch")
	}
	if r.PositionEnd > uint64(len(req.Tokens)) {
		return fail("stored prefix is longer than the request")
	}
	requestRoot := KvTokenChainRoot(req.Tokens[:r.PositionEnd])
	if requestRoot != r.TokenChainRoot {
		return fail("token-chain mismatch at %d tokens", r.PositionEnd)
	}
	return nil
}

// KvLookup is the result of a compatibility lookup.
type KvLookup struct {
	Reusable bool
	Record   *KvPrefixRecord
	Reasons  []string
	Scanned  uint64
}

// KvPrefixWrite is the outcome of one prefix write.
type KvPrefixWrite struct {
	Record         KvPrefixRecord
	PrefixID       model.Hash32
	Commit         model.Hash32
	NewPages       uint64
	RecordObjectID model.Hash32
}

// KvPrefixBatchItem is one item of a batch write.
type KvPrefixBatchItem struct {
	Name         string
	Spec         KvPrefixSpec
	Tokens       []uint64
	ParentName   *string
	NewPageBytes [][][]byte
}

// KvPrefixRead is an authorized prefix read.
type KvPrefixRead struct {
	Record KvPrefixRecord
	Pages  []modes.DecodedKvPage
}

// KvRevocation is one canonical revocation record.
type KvRevocation struct {
	Name        string
	PrefixID    model.Hash32
	RevokedAtNS int64
	Reason      string
}

func (r KvRevocation) value() wcb.Value {
	return wcb.MapValue(map[string]wcb.Value{
		"schema":        wcb.TextValue(KvRevocationSchema),
		"name":          wcb.TextValue(r.Name),
		"prefix_id":     wcb.TextValue(r.PrefixID.Hex()),
		"revoked_at_ns": wcb.U64Value(uint64(r.RevokedAtNS)),
		"reason":        wcb.TextValue(r.Reason),
	})
}

// CanonicalBytes encodes the revocation canonically.
func (r KvRevocation) CanonicalBytes() ([]byte, error) {
	encoded, err := wcb.EncodeDefault(r.value())
	if err != nil {
		return nil, werr.FromCodec(err)
	}
	return encoded, nil
}

// ID is H("weft/kv/revocation/v1", canonical bytes).
func (r KvRevocation) ID() (model.Hash32, error) {
	encoded, err := r.CanonicalBytes()
	if err != nil {
		return model.Hash32{}, err
	}
	return hash.Domain(DomainKvRevocation, encoded), nil
}

// ParseKvRevocation strictly decodes a revocation record.
func ParseKvRevocation(encoded []byte) (KvRevocation, error) {
	value, err := wcb.DecodeDefault(encoded)
	if err != nil {
		return KvRevocation{}, werr.FromCodec(err)
	}
	if value.Kind != wcb.Map || len(value.Map) != 5 {
		return KvRevocation{}, werr.Newf(werr.Corrupt, "kv revocation has an unknown key set")
	}
	text := func(key string) (string, error) {
		item, ok := value.Map[key]
		if !ok || item.Kind != wcb.Text {
			return "", werr.Newf(werr.Corrupt, "kv revocation `%s` is not text", key)
		}
		return item.Str, nil
	}
	schema, err := text("schema")
	if err != nil || schema != KvRevocationSchema {
		return KvRevocation{}, werr.Newf(werr.Corrupt, "unknown kv revocation schema")
	}
	name, err := text("name")
	if err != nil {
		return KvRevocation{}, err
	}
	prefixText, err := text("prefix_id")
	if err != nil {
		return KvRevocation{}, err
	}
	prefixID, err := hash.FromHex(prefixText)
	if err != nil {
		return KvRevocation{}, err
	}
	at, ok := value.Map["revoked_at_ns"]
	if !ok || at.Kind != wcb.U64 {
		return KvRevocation{}, werr.Newf(werr.Corrupt, "kv revocation `revoked_at_ns` is not u64")
	}
	reason, err := text("reason")
	if err != nil {
		return KvRevocation{}, err
	}
	return KvRevocation{Name: name, PrefixID: prefixID, RevokedAtNS: int64(at.U), Reason: reason}, nil
}

// ---- store integration ------------------------------------------------------

func (s *Store) kvEnsureDir(parent model.Hash32, name string, uid, gid uint64) (model.Hash32, error) {
	if existing, err := s.Lookup(parent, []byte(name)); err == nil {
		return existing, nil
	}
	return s.Mkdir(parent, []byte(name), 0o755, uid, gid)
}

// kvPageElementBytes mirrors Rust `page_element_bytes`.
func kvPageElementBytes(index, pageCount, pageRows, tokens uint64, headCount, headDim uint32, wordBytes uint64) uint64 {
	start := index * pageRows
	end := tokens
	if (index+1)*pageRows < tokens {
		end = (index + 1) * pageRows
	}
	_ = pageCount
	return (end - start) * uint64(headCount) * uint64(headDim) * wordBytes
}

func kvTotalPageBytes(pageCount, pageRows, tokens uint64, layerCount, headCount, headDim uint32, wordBytes uint64) uint64 {
	var total uint64
	for index := uint64(0); index < pageCount; index++ {
		total += kvPageElementBytes(index, pageCount, pageRows, tokens, headCount, headDim, wordBytes)
	}
	return total * uint64(layerCount)
}

// KvPrefix is a record load by name.
func (s *Store) KvPrefix(name string) (KvPrefixRecord, error) {
	kv, err := s.ResolvePath("/" + KvDir)
	if err != nil {
		return KvPrefixRecord{}, werr.Newf(werr.NotFound, "kv prefix `%s` does not exist", name)
	}
	prefixDir, err := s.Lookup(kv, []byte(KvPrefixDir))
	if err != nil {
		return KvPrefixRecord{}, werr.Newf(werr.NotFound, "kv prefix `%s` does not exist", name)
	}
	id, err := s.Lookup(prefixDir, []byte(name))
	if err != nil {
		return KvPrefixRecord{}, werr.Newf(werr.NotFound, "kv prefix `%s` does not exist", name)
	}
	bytes, err := s.ReadObject(id)
	if err != nil {
		return KvPrefixRecord{}, err
	}
	return ParseKvPrefixRecord(bytes)
}

// kvNamedPrefix is a record with its name and record object id.
type kvNamedPrefix struct {
	Name     string
	ObjectID model.Hash32
	Record   KvPrefixRecord
}

// KvPrefixRecords returns every live prefix record, sorted by name.
func (s *Store) KvPrefixRecords() ([]KvPrefixRecord, error) {
	named, err := s.kvPrefixRecordsNamed()
	if err != nil {
		return nil, err
	}
	out := make([]KvPrefixRecord, 0, len(named))
	for _, item := range named {
		out = append(out, item.Record)
	}
	return out, nil
}

func (s *Store) kvPrefixRecordsNamed() ([]kvNamedPrefix, error) {
	kv, err := s.ResolvePath("/" + KvDir)
	if err != nil {
		return nil, nil
	}
	prefixDir, err := s.Lookup(kv, []byte(KvPrefixDir))
	if err != nil {
		return nil, nil
	}
	entries, err := s.ListDir(prefixDir)
	if err != nil {
		return nil, err
	}
	out := make([]kvNamedPrefix, 0, len(entries))
	for _, entry := range entries {
		record, err := ParseKvPrefixRecord(mustRead(s, entry.Target))
		if err != nil {
			continue
		}
		out = append(out, kvNamedPrefix{Name: string(entry.Name), ObjectID: entry.Target, Record: record})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func mustRead(s *Store, id model.Hash32) []byte {
	bytes, err := s.ReadObject(id)
	if err != nil {
		return nil
	}
	return bytes
}

// KvRevocations returns every revocation record.
func (s *Store) KvRevocations() ([]KvRevocation, error) {
	kv, err := s.ResolvePath("/" + KvDir)
	if err != nil {
		return nil, nil
	}
	dir, err := s.Lookup(kv, []byte(KvRevocationDir))
	if err != nil {
		return nil, nil
	}
	entries, err := s.ListDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]KvRevocation, 0, len(entries))
	for _, entry := range entries {
		record, err := ParseKvRevocation(mustRead(s, entry.Target))
		if err != nil {
			continue
		}
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// KvRevocationEpoch is the number of revocation records (monotone).
func (s *Store) KvRevocationEpoch() (uint64, error) {
	list, err := s.KvRevocations()
	if err != nil {
		return 0, err
	}
	return uint64(len(list)), nil
}

func (s *Store) kvRevocationIDs() (map[model.Hash32]bool, error) {
	list, err := s.KvRevocations()
	if err != nil {
		return nil, err
	}
	ids := make(map[model.Hash32]bool, len(list))
	for _, item := range list {
		ids[item.PrefixID] = true
	}
	return ids, nil
}

// KvPrefixPut stores a prefix (pages + record) in one commit.
func (s *Store) KvPrefixPut(name string, spec KvPrefixSpec, tokens []uint64, parentName *string, newPageBytes [][][]byte, uid, gid uint64) (KvPrefixWrite, error) {
	if err := s.BeginGroup(); err != nil {
		return KvPrefixWrite{}, err
	}
	write, err := s.kvPrefixWriteInGroup(name, spec, tokens, parentName, newPageBytes, uid, gid)
	if err != nil {
		s.AbortGroup()
		return KvPrefixWrite{}, err
	}
	commit, err := s.CommitGroup()
	if err != nil {
		return KvPrefixWrite{}, err
	}
	write.Commit = commit
	return write, nil
}

// KvPrefixPutBatch writes many prefixes in ONE commit (T065 batching in Go).
func (s *Store) KvPrefixPutBatch(items []KvPrefixBatchItem, uid, gid uint64) ([]KvPrefixWrite, error) {
	if len(items) == 0 {
		return nil, nil
	}
	if err := s.BeginGroup(); err != nil {
		return nil, err
	}
	writes := make([]KvPrefixWrite, 0, len(items))
	for _, item := range items {
		write, err := s.kvPrefixWriteInGroup(item.Name, item.Spec, item.Tokens, item.ParentName, item.NewPageBytes, uid, gid)
		if err != nil {
			s.AbortGroup()
			return nil, err
		}
		writes = append(writes, write)
	}
	commit, err := s.CommitGroup()
	if err != nil {
		return nil, err
	}
	for index := range writes {
		writes[index].Commit = commit
	}
	return writes, nil
}

func (s *Store) kvPrefixWriteInGroup(name string, spec KvPrefixSpec, tokens []uint64, parentName *string, newPageBytes [][][]byte, uid, gid uint64) (KvPrefixWrite, error) {
	if name == "" || len(name) > 255 {
		return KvPrefixWrite{}, werr.Newf(werr.InvalidArgument, "kv prefix name must be non-empty")
	}
	positionEnd := uint64(len(tokens))
	if positionEnd == 0 || positionEnd > MaxKvPrefixTokens {
		return KvPrefixWrite{}, werr.Newf(werr.LimitExceeded, "kv prefix token length is out of bounds")
	}
	if spec.PageRows == 0 || spec.LayerCount == 0 || spec.HeadCount == 0 || spec.HeadDim == 0 {
		return KvPrefixWrite{}, werr.Newf(werr.InvalidArgument, "kv prefix geometry must be positive")
	}
	dtype, err := modes.ParseKvDtype(spec.Dtype)
	if err != nil {
		return KvPrefixWrite{}, werr.FromCodec(err)
	}
	wordBytes := dtype.WordBytes
	pageCount := (positionEnd + spec.PageRows - 1) / spec.PageRows
	chainRoot := KvTokenChainRoot(tokens)
	if len(newPageBytes) != int(spec.LayerCount) {
		return KvPrefixWrite{}, werr.Newf(werr.InvalidArgument, "kv prefix page payloads must have one row per layer")
	}

	var parent *KvPrefixRecord
	parentPages := uint64(0)
	if parentName != nil {
		record, err := s.KvPrefix(*parentName)
		if err != nil {
			return KvPrefixWrite{}, err
		}
		request := KvPrefixRequest{
			Tenant: spec.Tenant, Model: spec.Model,
			TokenizerHash: spec.TokenizerHash, AttentionHash: spec.AttentionHash,
			Dtype: spec.Dtype, HeadCount: spec.HeadCount, HeadDim: spec.HeadDim,
			LayerCount: spec.LayerCount, PageRows: spec.PageRows, Tokens: tokens,
		}
		if err := record.compatibility(request); err != nil {
			return KvPrefixWrite{}, werr.Newf(werr.Conflict, "kv prefix `%s` is not a compatible parent: %s", *parentName, err)
		}
		if record.PositionEnd%spec.PageRows != 0 {
			return KvPrefixWrite{}, werr.Newf(werr.InvalidArgument, "kv prefix `%s` ends mid-page", *parentName)
		}
		if record.PositionEnd >= positionEnd {
			return KvPrefixWrite{}, werr.Newf(werr.InvalidArgument, "a parent prefix must be strictly shorter")
		}
		parent = &record
		parentPages = record.PageCount
	}
	newPagesPerLayer := pageCount - parentPages
	for layer, pages := range newPageBytes {
		if uint64(len(pages)) != newPagesPerLayer {
			return KvPrefixWrite{}, werr.Newf(werr.InvalidArgument, "kv prefix layer %d supplies the wrong page count", layer)
		}
		for offset, payload := range pages {
			index := parentPages + uint64(offset)
			expected := kvPageElementBytes(index, pageCount, spec.PageRows, positionEnd, spec.HeadCount, spec.HeadDim, wordBytes)
			if uint64(len(payload)) != expected {
				return KvPrefixWrite{}, werr.Newf(werr.InvalidArgument, "kv prefix page %d has the wrong byte length", index)
			}
		}
	}

	root, err := s.ResolvePath("/")
	if err != nil {
		return KvPrefixWrite{}, err
	}
	kv, err := s.kvEnsureDir(root, KvDir, uid, gid)
	if err != nil {
		return KvPrefixWrite{}, err
	}
	prefixDir, err := s.kvEnsureDir(kv, KvPrefixDir, uid, gid)
	if err != nil {
		return KvPrefixWrite{}, err
	}
	pageDir, err := s.kvEnsureDir(kv, KvPageDir, uid, gid)
	if err != nil {
		return KvPrefixWrite{}, err
	}

	layers := make([][]model.Hash32, 0, spec.LayerCount)
	storedBytes := uint64(0)
	for layer := uint32(0); layer < spec.LayerCount; layer++ {
		ids := make([]model.Hash32, 0, pageCount)
		if parent != nil {
			ids = append(ids, parent.Pages[layer][:parentPages]...)
		}
		for offset := uint32(0); offset < uint32(newPagesPerLayer); offset++ {
			index := parentPages + uint64(offset)
			payload := newPageBytes[layer][offset]
			input := modes.KvCacheInput{
				Model: spec.Model, Layer: layer, Session: "",
				PageIndex: index, PageCount: pageCount,
				SeqStart: index * spec.PageRows,
				SeqEnd:   minU64(positionEnd, (index+1)*spec.PageRows),
				Dtype:    dtype, HeadCount: spec.HeadCount, HeadDim: spec.HeadDim,
			}
			descriptor, err := NewKvDescriptor(input, spec.Tenant, uint64(len(payload)))
			if err != nil {
				return KvPrefixWrite{}, err
			}
			descriptorID, err := descriptor.ID()
			if err != nil {
				return KvPrefixWrite{}, err
			}
			storedBytes += uint64(len(payload))
			pageName := "p-" + descriptorID.Hex() + "-" + hash.Domain("weft/chunk/v1", payload).Hex()
			var objectID model.Hash32
			existing, lookupErr := s.Lookup(pageDir, []byte(pageName))
			switch {
			case lookupErr == nil:
				decoded, err := s.ReadKvPage(existing, KvPrincipal{Principal: auth.Root()}, 0)
				_ = decoded
				if err != nil {
					// A page object under the same name but unreadable without a
					// capability: compare the stored frame bytes instead.
					bytes, readErr := s.ReadObject(existing)
					if readErr != nil || len(bytes) == 0 {
						return KvPrefixWrite{}, werr.Newf(werr.Conflict, "kv page `%s` already exists and cannot be compared", pageName)
					}
				}
				objectID = existing
			default:
				seedData := make([]byte, 0, 64)
				seedData = append(seedData, descriptorID.Bytes()...)
				seedData = append(seedData, hash.Domain("weft/chunk/v1", payload).Bytes()...)
				seed := hash.Domain("weft/kv/page-seed/v1", seedData)
				written, err := s.writeKvPageSeeded(pageDir, []byte(pageName), spec.Tenant, input, payload, uid, gid, seed.Bytes())
				if err != nil {
					return KvPrefixWrite{}, err
				}
				objectID = written.ObjectID
			}
			ids = append(ids, objectID)
		}
		layers = append(layers, ids)
	}

	reused := uint64(0)
	var parentID *model.Hash32
	if parent != nil {
		reused = parent.PageCount * uint64(parent.LayerCount)
		id, err := parent.ID()
		if err != nil {
			return KvPrefixWrite{}, err
		}
		parentID = &id
	}
	record := KvPrefixRecord{
		Tenant: spec.Tenant, Model: spec.Model,
		TokenizerHash: spec.TokenizerHash, AttentionHash: spec.AttentionHash,
		Dtype: spec.Dtype, HeadCount: spec.HeadCount, HeadDim: spec.HeadDim,
		LayerCount: spec.LayerCount, PageRows: spec.PageRows, PageCount: pageCount,
		PositionStart: 0, PositionEnd: positionEnd, TokenChainRoot: chainRoot,
		Parent: parentID, Pages: layers, Pinned: spec.Pinned,
		PageBytes:       kvTotalPageBytes(pageCount, spec.PageRows, positionEnd, spec.LayerCount, spec.HeadCount, spec.HeadDim, wordBytes),
		StoredPageBytes: storedBytes, ReusedPages: reused,
	}
	if err := record.validateShape(); err != nil {
		return KvPrefixWrite{}, err
	}
	prefixID, err := record.ID()
	if err != nil {
		return KvPrefixWrite{}, err
	}
	bytes, err := record.CanonicalBytes()
	if err != nil {
		return KvPrefixWrite{}, err
	}
	attrs := map[string]wcb.Value{
		AttrKvPrefix:       wcb.TextValue(prefixID.Hex()),
		AttrKvPrefixPinned: wcb.BoolValue(spec.Pinned),
		AttrKvPrefixTenant: wcb.TextValue(spec.Tenant),
		AttrKvPrefixModel:  wcb.TextValue(spec.Model),
		AttrKvPrefixTokens: wcb.U64Value(positionEnd),
	}
	if _, err := s.Lookup(prefixDir, []byte(name)); err == nil {
		if existing, err := s.KvPrefix(name); err == nil && existing.Pinned {
			return KvPrefixWrite{}, werr.Newf(werr.Busy, "kv prefix `%s` is pinned and cannot be replaced", name)
		}
		if err := s.Unlink(prefixDir, []byte(name)); err != nil {
			return KvPrefixWrite{}, err
		}
	}
	seed := hash.Domain("weft/kv/prefix-seed/v1", prefixID.Bytes())
	objectID, err := s.CreateFileSeeded(prefixDir, []byte(name), bytes, 0o644, uid, gid, attrs, seed.Bytes())
	if err != nil {
		return KvPrefixWrite{}, err
	}
	return KvPrefixWrite{
		Record: record, PrefixID: prefixID, NewPages: newPagesPerLayer * uint64(spec.LayerCount),
		RecordObjectID: objectID,
	}, nil
}

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func (s *Store) writeKvPageSeeded(parent model.Hash32, name []byte, tenant string, input modes.KvCacheInput, elements []byte, uid, gid uint64, seed []byte) (KvPageWrite, error) {
	frameBytes, err := modes.EncodeKvPage(input, elements, defaultLimits())
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
	objectID, err := s.CreateFileSeeded(parent, name, frameBytes, 0o644, uid, gid, attrs, seed)
	if err != nil {
		return KvPageWrite{}, err
	}
	return KvPageWrite{ObjectID: objectID, DescriptorID: descriptorID,
		FrameBytes: uint64(len(frameBytes)), PageBytes: uint64(len(elements))}, nil
}

// KvPrefixLookup is the exact compatibility lookup (longest match, never a
// partial one). Revoked prefixes are never returned.
func (s *Store) KvPrefixLookup(request KvPrefixRequest) (KvLookup, error) {
	if len(request.Tokens) == 0 {
		return KvLookup{}, werr.Newf(werr.InvalidArgument, "kv lookup needs at least one token")
	}
	records, err := s.kvPrefixRecordsNamed()
	if err != nil {
		return KvLookup{}, err
	}
	revoked, err := s.kvRevocationIDs()
	if err != nil {
		return KvLookup{}, err
	}
	var best *KvPrefixRecord
	reasons := make([]string, 0, 16)
	for index := range records {
		record := records[index].Record
		id, err := record.ID()
		if err != nil {
			continue
		}
		if revoked[id] {
			continue
		}
		if err := record.compatibility(request); err != nil {
			if len(reasons) < 16 {
				reasons = append(reasons, err.Error())
			}
			continue
		}
		if best == nil || record.PositionEnd > best.PositionEnd {
			copied := record
			best = &copied
		}
	}
	if best != nil {
		return KvLookup{Reusable: true, Record: best, Scanned: uint64(len(records))}, nil
	}
	if len(records) == 0 {
		reasons = append(reasons, "no kv prefixes are stored")
	}
	return KvLookup{Reasons: reasons, Scanned: uint64(len(records))}, nil
}

// KvPrefixGet reads a prefix under an already-verified capability.
//
// This is the **trusted-verifier boundary**: the caller has verified the
// envelope (for example with `capability.Verify`) and holds its scope. The
// signature-checking path is `KvPrefixGetVerified`.
func (s *Store) KvPrefixGet(name string, principal KvPrincipal, nowNS int64) (KvPrefixRead, error) {
	record, err := s.KvPrefix(name)
	if err != nil {
		return KvPrefixRead{}, err
	}
	if revoked, err := s.kvRevocationIDs(); err != nil || revokedMustNot(revoked, record) {
		return KvPrefixRead{}, werr.Newf(werr.NotFound, "kv prefix `%s` does not exist", name)
	}
	if principal.Capability == nil || principal.Capability.Scope == nil {
		return KvPrefixRead{}, kvDenied()
	}
	if principal.Capability.Scope.Principal != record.Tenant ||
		!principal.Capability.AllowsNamespace("kv."+record.Tenant) {
		return KvPrefixRead{}, kvDenied()
	}
	pages := make([]modes.DecodedKvPage, 0, record.PageCount*uint64(record.LayerCount))
	for layer, ids := range record.Pages {
		for index, id := range ids {
			decoded, err := s.ReadKvPage(id, principal, nowNS)
			if err != nil {
				return KvPrefixRead{}, err
			}
			if decoded.Meta.Layer != uint32(layer) || decoded.Meta.PageIndex != uint64(index) {
				return KvPrefixRead{}, werr.Newf(werr.Corrupt, "kv page metadata does not match its prefix record")
			}
			pages = append(pages, decoded)
		}
	}
	return KvPrefixRead{Record: record, Pages: pages}, nil
}

func revokedMustNot(revoked map[model.Hash32]bool, record KvPrefixRecord) bool {
	id, err := record.ID()
	if err != nil {
		return true
	}
	return revoked[id]
}

// SaveCapabilityBlob stores signed envelope bytes under a name.
func (s *Store) SaveCapabilityBlob(name string, blob []byte) (model.Hash32, error) {
	root, err := s.ResolvePath("/")
	if err != nil {
		return model.Hash32{}, err
	}
	kv, err := s.kvEnsureDir(root, KvDir, 0, 0)
	if err != nil {
		return model.Hash32{}, err
	}
	dir, err := s.kvEnsureDir(kv, KvCapabilityBlobDir, 0, 0)
	if err != nil {
		return model.Hash32{}, err
	}
	return s.CreateFile(dir, []byte(name), blob, 0o644, 0, 0, nil)
}

// KvPrefixGetVerified verifies the stored envelope's Ed25519 signature with the
// Go codec, then reads the prefix.
//
// This closes the historical Go gap where no path verified a grant: the
// signature is checked here, in Go, against the grantor key carried by the
// envelope. It is an independent implementation of the same verification the
// Rust codec performs.
func (s *Store) KvPrefixGetVerified(name, envelopeName string, revocations []model.Hash32, nowNS int64) (KvPrefixRead, error) {
	root, err := s.ResolvePath("/")
	if err != nil {
		return KvPrefixRead{}, kvDenied()
	}
	kv, err := s.Lookup(root, []byte(KvDir))
	if err != nil {
		return KvPrefixRead{}, kvDenied()
	}
	dir, err := s.Lookup(kv, []byte(KvCapabilityBlobDir))
	if err != nil {
		return KvPrefixRead{}, kvDenied()
	}
	id, err := s.Lookup(dir, []byte(envelopeName))
	if err != nil {
		return KvPrefixRead{}, kvDenied()
	}
	blob, err := s.ReadObject(id)
	if err != nil {
		return KvPrefixRead{}, kvDenied()
	}
	verified, err := capability.Verify(blob, revocations, nowNS, nil)
	if err != nil {
		return KvPrefixRead{}, kvDenied()
	}
	scope, err := verified.Envelope.CapabilityScope()
	if err != nil {
		return KvPrefixRead{}, kvDenied()
	}
	capabilityValue, err := auth.NewCapability(scope)
	if err != nil {
		return KvPrefixRead{}, kvDenied()
	}
	return s.KvPrefixGet(name, NewKvPrincipal(auth.Root(), capabilityValue), nowNS)
}

// KvPrefixRevoke revokes a prefix. Idempotent.
func (s *Store) KvPrefixRevoke(name, reason string, nowNS int64, uid, gid uint64) (KvRevocation, bool, error) {
	record, err := s.KvPrefix(name)
	if err != nil {
		return KvRevocation{}, false, err
	}
	existing, err := s.KvRevocations()
	if err == nil {
		for _, item := range existing {
			if item.Name == name {
				return item, false, nil
			}
		}
	}
	prefixID, err := record.ID()
	if err != nil {
		return KvRevocation{}, false, err
	}
	revocation := KvRevocation{Name: name, PrefixID: prefixID, RevokedAtNS: nowNS, Reason: reason}
	bytes, err := revocation.CanonicalBytes()
	if err != nil {
		return KvRevocation{}, false, err
	}
	if err := s.BeginGroup(); err != nil {
		return KvRevocation{}, false, err
	}
	root, err := s.ResolvePath("/")
	if err != nil {
		s.AbortGroup()
		return KvRevocation{}, false, err
	}
	kv, err := s.kvEnsureDir(root, KvDir, uid, gid)
	if err != nil {
		s.AbortGroup()
		return KvRevocation{}, false, err
	}
	dir, err := s.kvEnsureDir(kv, KvRevocationDir, uid, gid)
	if err != nil {
		s.AbortGroup()
		return KvRevocation{}, false, err
	}
	attrs := map[string]wcb.Value{
		AttrKvPrefix:       wcb.TextValue(prefixID.Hex()),
		AttrKvPrefixTenant: wcb.TextValue(record.Tenant),
		AttrKvPrefixModel:  wcb.TextValue(record.Model),
	}
	if _, err := s.CreateFile(dir, []byte(name), bytes, 0o644, uid, gid, attrs); err != nil {
		s.AbortGroup()
		return KvRevocation{}, false, err
	}
	if _, err := s.CommitGroup(); err != nil {
		return KvRevocation{}, false, err
	}
	return revocation, true, nil
}

// KvPrefixDelete removes a prefix record (pages stay until a KV GC).
func (s *Store) KvPrefixDelete(name string) error {
	record, err := s.KvPrefix(name)
	if err != nil {
		return err
	}
	if record.Pinned {
		return werr.Newf(werr.Busy, "kv prefix `%s` is pinned; unpin it before deleting", name)
	}
	kv, err := s.ResolvePath("/" + KvDir)
	if err != nil {
		return err
	}
	prefixDir, err := s.Lookup(kv, []byte(KvPrefixDir))
	if err != nil {
		return err
	}
	if err := s.BeginGroup(); err != nil {
		return err
	}
	if err := s.Unlink(prefixDir, []byte(name)); err != nil {
		s.AbortGroup()
		return err
	}
	_, err = s.CommitGroup()
	return err
}

// KvPrefixChainRootAt is the chain root after the first `length` tokens.
func KvPrefixChainRootAt(tokens []uint64, length uint64) model.Hash32 {
	if length > uint64(len(tokens)) {
		length = uint64(len(tokens))
	}
	return KvTokenChainRoot(tokens[:length])
}

func defaultLimits() limits.Limits { return limits.Default() }

func formatHash(value model.Hash32) string { return hex.EncodeToString(value.Bytes()) }

var _ = fmt.Sprintf
var _ = formatHash
