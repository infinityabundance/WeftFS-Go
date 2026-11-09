// Retention bindings and class-aware GC ordering (subphase R6).
//
// The normative contract is `spec/WEFT-RETENTION.md`. This file is the Go
// parity implementation: the canonical `weft.retention.v1` record, the fixed
// current pointer, and a class-aware GC plan whose reachability precondition
// is computed exactly as `gcPass` computes it.
//
// The load-bearing rule is §5.3: class affects **ordering**, never reachability
// safety. A binding may retain unreachable bytes for its declared window; it
// can never cause a reachable blob to be reclaimed.
package store

import (
	"context"
	"crypto/ed25519"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/infinityabundance/WeftCodec-Go/hash"
	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

const (
	// RetentionSchema is the binding-record schema string.
	RetentionSchema = "weft.retention.v1"
	// RetentionDomain separates the binding identity hash.
	RetentionDomain = "weft/retention/v1"
	// MaxDeclaredLifetimeMS is 100 years in milliseconds.
	MaxDeclaredLifetimeMS uint64 = 3_155_760_000_000
	// MaxRetentionHistory bounds one descriptor's `supersedes` chain.
	MaxRetentionHistory = 4096
	// MaxRetentionProducerBytes bounds the producer string.
	MaxRetentionProducerBytes = 256
	// RetentionPointerBytes is the fixed current-pointer size.
	RetentionPointerBytes = 104
	// RetentionDir is the reserved namespace root.
	RetentionDir = "retention"
	// RetentionBindingsDir holds immutable canonical binding records.
	RetentionBindingsDir = "bindings"
	// RetentionCurrentDir holds mutable fixed-size current pointers.
	RetentionCurrentDir = "current"
	// AttrKVProvRoot is the reserved mode-19 provenance-root attribute.
	AttrKVProvRoot = "weft.kv.provenance_root"
)

var retentionPointerMagic = []byte("RPT1")

// RetentionClass is one of the four semantic retention classes.
type RetentionClass string

const (
	RetentionVolatile  RetentionClass = "volatile"
	RetentionSession   RetentionClass = "session"
	RetentionEphemeral RetentionClass = "ephemeral"
	RetentionDurable   RetentionClass = "durable"
)

// RetentionClassAll is the canonical class order.
var RetentionClassAll = []RetentionClass{
	RetentionVolatile,
	RetentionSession,
	RetentionEphemeral,
	RetentionDurable,
}

// ParseRetentionClass validates a class name.
func ParseRetentionClass(text string) (RetentionClass, error) {
	switch RetentionClass(text) {
	case RetentionVolatile, RetentionSession, RetentionEphemeral, RetentionDurable:
		return RetentionClass(text), nil
	default:
		return "", werr.Newf(werr.Malformed,
			"retention class `%s` is not one of volatile, session, ephemeral, durable", text)
	}
}

// Rank is the reclamation order; a lower rank is reclaimed first.
func (c RetentionClass) Rank() int {
	switch c {
	case RetentionVolatile:
		return 1
	case RetentionSession:
		return 2
	case RetentionEphemeral:
		return 3
	case RetentionDurable:
		return 4
	default:
		return 0
	}
}

// RequiresRoot reports whether the class needs a pin or snapshot/checkpoint.
func (c RetentionClass) RequiresRoot() bool { return c == RetentionDurable }

// RetentionSignature is an optional Ed25519 signature over the record without
// its signature key. The algorithm name is fixed in v1.
type RetentionSignature struct {
	PublicKey [32]byte
	Signature [64]byte
}

// RetentionBinding is one canonical `weft.retention.v1` record.
type RetentionBinding struct {
	DescriptorRoot     model.Hash32
	Class              RetentionClass
	DeclaredLifetimeMS uint64
	Producer           string
	PolicyEpoch        uint64
	IssuedAtNS         int64
	Supersedes         *model.Hash32
	Signature          *RetentionSignature
}

// RetentionBindingKeys are the exact record keys.
var RetentionBindingKeys = []string{
	"schema", "descriptor_root", "class", "declared_lifetime_ms", "producer",
	"policy_epoch", "issued_at", "supersedes", "signature",
}

// NewRetentionBinding builds and validates an unsigned binding.
func NewRetentionBinding(
	descriptorRoot model.Hash32,
	class RetentionClass,
	lifetimeMS uint64,
	producer string,
	policyEpoch uint64,
	issuedAtNS int64,
	supersedes *model.Hash32,
) (*RetentionBinding, error) {
	b := &RetentionBinding{
		DescriptorRoot:     descriptorRoot,
		Class:              class,
		DeclaredLifetimeMS: lifetimeMS,
		Producer:           producer,
		PolicyEpoch:        policyEpoch,
		IssuedAtNS:         issuedAtNS,
		Supersedes:         supersedes,
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return b, nil
}

// Validate is the structural rule set from §3 and §7.
func (b *RetentionBinding) Validate() error {
	if b.DescriptorRoot == model.ZeroHash {
		return werr.New(werr.Malformed, "retention descriptor_root must not be all zero")
	}
	if b.Producer == "" {
		return werr.New(werr.Malformed, "retention producer must not be empty")
	}
	if len(b.Producer) > MaxRetentionProducerBytes {
		return werr.Newf(werr.Malformed,
			"retention producer is %d bytes, above the %d-byte bound",
			len(b.Producer), MaxRetentionProducerBytes)
	}
	if b.Class.RequiresRoot() {
		if b.DeclaredLifetimeMS != 0 {
			return werr.New(werr.Malformed,
				"a durable retention binding must declare lifetime 0 (indefinite)")
		}
	} else {
		if b.DeclaredLifetimeMS == 0 {
			return werr.Newf(werr.Malformed,
				"a %s retention binding must declare a positive lifetime", b.Class)
		}
		if b.DeclaredLifetimeMS > MaxDeclaredLifetimeMS {
			return werr.Newf(werr.LimitExceeded,
				"declared lifetime %d ms exceeds the %d ms bound",
				b.DeclaredLifetimeMS, MaxDeclaredLifetimeMS)
		}
	}
	if b.Supersedes != nil && *b.Supersedes == model.ZeroHash {
		return werr.New(werr.Malformed, "retention supersedes must not be all zero (use null)")
	}
	if b.Signature != nil {
		if len(b.Signature.PublicKey) != ed25519.PublicKeySize ||
			len(b.Signature.Signature) != ed25519.SignatureSize {
			return werr.New(werr.Malformed, "retention signature has the wrong length")
		}
	}
	return nil
}

func (b *RetentionBinding) valueWithoutSignature() wcb.Value {
	var supersedes wcb.Value
	if b.Supersedes == nil {
		supersedes = wcb.NullValue()
	} else {
		supersedes = wcb.BytesValue(b.Supersedes.Bytes())
	}
	return wcb.MapValue(map[string]wcb.Value{
		"schema":               wcb.TextValue(RetentionSchema),
		"descriptor_root":      wcb.BytesValue(b.DescriptorRoot.Bytes()),
		"class":                wcb.TextValue(string(b.Class)),
		"declared_lifetime_ms": wcb.U64Value(b.DeclaredLifetimeMS),
		"producer":             wcb.TextValue(b.Producer),
		"policy_epoch":         wcb.U64Value(b.PolicyEpoch),
		"issued_at":            wcb.TimestampValue(b.IssuedAtNS),
		"supersedes":           supersedes,
	})
}

// ToValue renders the canonical record value.
func (b *RetentionBinding) ToValue() wcb.Value {
	fields := b.valueWithoutSignature().Map
	if b.Signature == nil {
		fields["signature"] = wcb.NullValue()
	} else {
		fields["signature"] = wcb.MapValue(map[string]wcb.Value{
			"algorithm":  wcb.TextValue("ed25519"),
			"public_key": wcb.BytesValue(b.Signature.PublicKey[:]),
			"signature":  wcb.BytesValue(b.Signature.Signature[:]),
		})
	}
	return wcb.MapValue(fields)
}

func (b *RetentionBinding) signingBytes() ([]byte, error) {
	return wcb.EncodeDefault(b.valueWithoutSignature())
}

// RetentionBindingFromValue parses a canonical record value.
func RetentionBindingFromValue(value wcb.Value) (*RetentionBinding, error) {
	if value.Kind != wcb.Map {
		return nil, werr.New(werr.Malformed, "retention record must be a WCB map")
	}
	for key := range value.Map {
		known := false
		for _, allowed := range RetentionBindingKeys {
			if key == allowed {
				known = true
				break
			}
		}
		if !known {
			return nil, werr.Newf(werr.Malformed, "unexpected map key `%s`", key)
		}
	}
	schema, err := retentionText(value.Map, "schema")
	if err != nil {
		return nil, err
	}
	if schema != RetentionSchema {
		return nil, werr.Newf(werr.Malformed,
			"retention schema `%s` is not `%s`", schema, RetentionSchema)
	}
	descriptor, err := retentionBytes(value.Map, "descriptor_root")
	if err != nil {
		return nil, err
	}
	if len(descriptor) != 32 {
		return nil, werr.New(werr.Malformed, "retention descriptor_root must be 32 bytes")
	}
	descriptorRoot, err := hash.FromSlice(descriptor)
	if err != nil {
		return nil, err
	}
	classText, err := retentionText(value.Map, "class")
	if err != nil {
		return nil, err
	}
	class, err := ParseRetentionClass(classText)
	if err != nil {
		return nil, err
	}
	lifetime, err := retentionU64(value.Map, "declared_lifetime_ms")
	if err != nil {
		return nil, err
	}
	producer, err := retentionText(value.Map, "producer")
	if err != nil {
		return nil, err
	}
	epoch, err := retentionU64(value.Map, "policy_epoch")
	if err != nil {
		return nil, err
	}
	issued, err := retentionTimestamp(value.Map, "issued_at")
	if err != nil {
		return nil, err
	}
	supersedesValue, ok := value.Map["supersedes"]
	if !ok {
		return nil, werr.New(werr.Malformed, "missing map key `supersedes`")
	}
	var supersedes *model.Hash32
	switch supersedesValue.Kind {
	case wcb.Null:
	case wcb.Bytes:
		if len(supersedesValue.Bytes) != 32 {
			return nil, werr.New(werr.Malformed, "retention supersedes must be 32 bytes")
		}
		hashValue, err := hash.FromSlice(supersedesValue.Bytes)
		if err != nil {
			return nil, err
		}
		supersedes = &hashValue
	default:
		return nil, werr.New(werr.Malformed, "retention supersedes must be bytes32 or null")
	}
	signature, err := retentionSignatureFromValue(value.Map["signature"])
	if err != nil {
		return nil, err
	}
	binding := &RetentionBinding{
		DescriptorRoot:     descriptorRoot,
		Class:              class,
		DeclaredLifetimeMS: lifetime,
		Producer:           producer,
		PolicyEpoch:        epoch,
		IssuedAtNS:         issued,
		Supersedes:         supersedes,
		Signature:          signature,
	}
	if err := binding.Validate(); err != nil {
		return nil, err
	}
	return binding, nil
}

func retentionSignatureFromValue(value wcb.Value) (*RetentionSignature, error) {
	switch value.Kind {
	case wcb.Null:
		return nil, nil
	case wcb.Map:
		algorithm, err := retentionText(value.Map, "algorithm")
		if err != nil {
			return nil, err
		}
		if algorithm != "ed25519" {
			return nil, werr.Newf(werr.Malformed,
				"retention signature algorithm `%s` is not `ed25519`", algorithm)
		}
		publicKey, err := retentionBytes(value.Map, "public_key")
		if err != nil {
			return nil, err
		}
		signature, err := retentionBytes(value.Map, "signature")
		if err != nil {
			return nil, err
		}
		if len(publicKey) != ed25519.PublicKeySize {
			return nil, werr.New(werr.Malformed, "retention signature public_key must be 32 bytes")
		}
		if len(signature) != ed25519.SignatureSize {
			return nil, werr.New(werr.Malformed, "retention signature must be 64 bytes")
		}
		out := &RetentionSignature{}
		copy(out.PublicKey[:], publicKey)
		copy(out.Signature[:], signature)
		return out, nil
	default:
		return nil, werr.New(werr.Malformed, "retention signature must be a map or null")
	}
}

func retentionText(fields map[string]wcb.Value, key string) (string, error) {
	value, ok := fields[key]
	if !ok {
		return "", werr.Newf(werr.Malformed, "missing map key `%s`", key)
	}
	if value.Kind != wcb.Text {
		return "", werr.Newf(werr.Malformed, "key `%s` must be text", key)
	}
	return value.Str, nil
}

func retentionBytes(fields map[string]wcb.Value, key string) ([]byte, error) {
	value, ok := fields[key]
	if !ok {
		return nil, werr.Newf(werr.Malformed, "missing map key `%s`", key)
	}
	if value.Kind != wcb.Bytes {
		return nil, werr.Newf(werr.Malformed, "key `%s` must be bytes", key)
	}
	return value.Bytes, nil
}

func retentionU64(fields map[string]wcb.Value, key string) (uint64, error) {
	value, ok := fields[key]
	if !ok {
		return 0, werr.Newf(werr.Malformed, "missing map key `%s`", key)
	}
	if value.Kind != wcb.U64 {
		return 0, werr.Newf(werr.Malformed, "key `%s` must be u64", key)
	}
	return value.U, nil
}

func retentionTimestamp(fields map[string]wcb.Value, key string) (int64, error) {
	value, ok := fields[key]
	if !ok {
		return 0, werr.Newf(werr.Malformed, "missing map key `%s`", key)
	}
	if value.Kind != wcb.Timestamp {
		return 0, werr.Newf(werr.Malformed, "key `%s` must be a timestamp", key)
	}
	return value.I, nil
}

// Encode returns the canonical record bytes.
func (b *RetentionBinding) Encode() ([]byte, error) { return wcb.EncodeDefault(b.ToValue()) }

// Decode parses canonical bytes and verifies a present signature.
func (b *RetentionBinding) Decode(data []byte) (*RetentionBinding, error) {
	value, err := wcb.DecodeDefault(data)
	if err != nil {
		return nil, err
	}
	binding, err := RetentionBindingFromValue(value)
	if err != nil {
		return nil, err
	}
	if err := binding.VerifySignature(); err != nil {
		return nil, err
	}
	return binding, nil
}

// DecodeRetentionBinding is the package-level decoder.
func DecodeRetentionBinding(data []byte) (*RetentionBinding, error) {
	return (&RetentionBinding{}).Decode(data)
}

// ID is H(RetentionDomain, canonical bytes).
func (b *RetentionBinding) ID() (model.Hash32, error) {
	data, err := b.Encode()
	if err != nil {
		return model.ZeroHash, err
	}
	return hash.Domain(RetentionDomain, data), nil
}

// Sign signs in place with an Ed25519 seed.
func (b *RetentionBinding) Sign(seed [32]byte) error {
	key := ed25519.NewKeyFromSeed(seed[:])
	message, err := b.signingBytes()
	if err != nil {
		return err
	}
	signature := ed25519.Sign(key, message)
	out := &RetentionSignature{}
	copy(out.PublicKey[:], key.Public().(ed25519.PublicKey))
	copy(out.Signature[:], signature)
	b.Signature = out
	return nil
}

// VerifySignature verifies a present signature against its embedded key. A
// missing signature is accepted here; trust-set policy is separate.
func (b *RetentionBinding) VerifySignature() error {
	if b.Signature == nil {
		return nil
	}
	message, err := b.signingBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(b.Signature.PublicKey[:]), message, b.Signature.Signature[:]) {
		return werr.New(werr.Corrupt, "retention binding signature does not verify")
	}
	return nil
}

// VerifySignatureWithTrust requires a signed record whose key is trusted.
func (b *RetentionBinding) VerifySignatureWithTrust(trust [][32]byte) error {
	if len(trust) == 0 {
		return b.VerifySignature()
	}
	if b.Signature == nil {
		return werr.New(werr.Unauthorized,
			"retention binding is unsigned and this store requires a trusted signer")
	}
	if err := b.VerifySignature(); err != nil {
		return err
	}
	for _, key := range trust {
		if key == b.Signature.PublicKey {
			return nil
		}
	}
	return werr.New(werr.Unauthorized,
		"retention binding signer is not in the configured trust set")
}

// ExpiresAtNS reports the expiry instant, or false for `durable`.
func (b *RetentionBinding) ExpiresAtNS() (int64, bool) {
	if b.Class.RequiresRoot() {
		return 0, false
	}
	ms := int64(MaxDeclaredLifetimeMS)
	if b.DeclaredLifetimeMS < uint64(1<<63-1) {
		ms = int64(b.DeclaredLifetimeMS)
	}
	if ms > (1<<63-1)/1_000_000 {
		return 1<<63 - 1, true
	}
	delta := ms * 1_000_000
	if b.IssuedAtNS > (1<<63-1)-delta {
		return 1<<63 - 1, true
	}
	return b.IssuedAtNS + delta, true
}

// IsLive reports whether the declared window is open. `durable` is protected
// by its root, not a clock, and reports false (it is ordered last).
func (b *RetentionBinding) IsLive(nowNS int64) bool {
	expiry, ok := b.ExpiresAtNS()
	return ok && nowNS < expiry
}

// RetentionPointer is the fixed-size mutable current pointer.
type RetentionPointer struct {
	DescriptorRoot model.Hash32
	Binding        model.Hash32
	Artifact       model.Hash32
}

// EncodePointer renders the fixed 104-byte pointer.
func (p *RetentionPointer) Encode() []byte {
	out := make([]byte, RetentionPointerBytes)
	copy(out[0:4], retentionPointerMagic)
	out[4] = 1
	copy(out[8:40], p.DescriptorRoot.Bytes())
	copy(out[40:72], p.Binding.Bytes())
	copy(out[72:104], p.Artifact.Bytes())
	return out
}

// DecodePointer parses a fixed 104-byte pointer.
func DecodePointer(data []byte) (*RetentionPointer, error) {
	if len(data) != RetentionPointerBytes {
		return nil, werr.Newf(werr.Corrupt,
			"retention pointer is %d bytes, expected %d", len(data), RetentionPointerBytes)
	}
	if string(data[0:4]) != "RPT1" {
		return nil, werr.New(werr.Corrupt, "retention pointer magic is not `RPT1`")
	}
	if data[4] != 1 {
		return nil, werr.Newf(werr.Unsupported,
			"retention pointer version %d is not 1", data[4])
	}
	if data[5] != 0 || data[6] != 0 || data[7] != 0 {
		return nil, werr.New(werr.Malformed, "retention pointer reserved bytes are not zero")
	}
	descriptor, err := hash.FromSlice(data[8:40])
	if err != nil {
		return nil, err
	}
	binding, err := hash.FromSlice(data[40:72])
	if err != nil {
		return nil, err
	}
	artifact, err := hash.FromSlice(data[72:104])
	if err != nil {
		return nil, err
	}
	return &RetentionPointer{DescriptorRoot: descriptor, Binding: binding, Artifact: artifact}, nil
}

// RetentionRequest publishes one binding. `Supersedes` is derived from the
// current pointer, never supplied by the caller.
type RetentionRequest struct {
	DescriptorRoot     model.Hash32
	Class              RetentionClass
	DeclaredLifetimeMS uint64
	Producer           string
	PolicyEpoch        uint64
	IssuedAtNS         *int64
	// Artifact is the manifest ContentId of the artifact. Go has no mode-19 KV
	// writer, so the anchor is explicit here; Rust resolves it from the live
	// object that carries the descriptor root.
	Artifact   *model.Hash32
	SignSeed   *[32]byte
	TrustKeys  [][32]byte
	TrustSetBy bool
}

// RetentionClassSummary reports one class in a GC plan.
type RetentionClassSummary struct {
	Class                 string
	ReachableArtifacts    uint64
	ReachableBlobs        uint64
	ReachableBytes        uint64
	RetainedLiveArtifacts uint64
	RetainedLiveBlobs     uint64
	RetainedLiveBytes     uint64
	ReclaimableArtifacts  uint64
	ReclaimableBlobs      uint64
	ReclaimableBytes      uint64
}

// RetainedArtifact is one binding whose bytes the plan retained.
type RetainedArtifact struct {
	DescriptorRoot model.Hash32
	Class          string
	Binding        model.Hash32
	Artifact       model.Hash32
	Expired        bool
	Bytes          uint64
	Reason         string
}

// RetentionCandidate is one reclaimable blob in plan order.
type RetentionCandidate struct {
	Path            string
	Bytes           uint64
	Class           string
	DescriptorRoots []model.Hash32
	ExpiryNS        *int64
}

// RetentionGCPlan is the observable output of GCPlan / RetentionGC.
type RetentionGCPlan struct {
	Applied            bool
	NowNS              int64
	BudgetBytes        *uint64
	GraceSecs          uint64
	ReachableManifests uint64
	ReachableChunks    uint64
	Classes            []RetentionClassSummary
	Retained           []RetainedArtifact
	Candidates         []RetentionCandidate
	PlannedBytes       uint64
	PlannedBlobs       uint64
	OverBudgetBytes    uint64
	ReclaimedBytes     uint64
	ReclaimedBlobs     uint64
	ReclaimedPackBytes uint64
	Problems           []string
}

type retentionOwner struct {
	descriptorRoot model.Hash32
	binding        model.Hash32
	class          RetentionClass
	expiryNS       *int64
	live           bool
	artifact       model.Hash32
	artifactBytes  uint64
	artifactBlobs  []model.Hash32
}

func (s *Store) retentionRootDir() (model.Hash32, bool, error) {
	id, err := s.ResolvePath("/" + RetentionDir)
	if err != nil {
		if werr.ClassOf(err) == werr.NotFound {
			return model.ZeroHash, false, nil
		}
		return model.ZeroHash, false, err
	}
	return id, true, nil
}

func (s *Store) retentionSubdir(name string) (model.Hash32, bool, error) {
	root, ok, err := s.retentionRootDir()
	if err != nil || !ok {
		return model.ZeroHash, false, err
	}
	id, err := s.Lookup(root, []byte(name))
	if err != nil {
		if werr.ClassOf(err) == werr.NotFound {
			return model.ZeroHash, false, nil
		}
		return model.ZeroHash, false, err
	}
	return id, true, nil
}

func (s *Store) ensureRetentionDir(parent model.Hash32, name string) (model.Hash32, error) {
	id, err := s.Lookup(parent, []byte(name))
	if err == nil {
		object, metaErr := s.ObjectMeta(id)
		if metaErr != nil {
			return model.ZeroHash, metaErr
		}
		if object.Kind != model.KindDir {
			return model.ZeroHash, werr.Newf(werr.NotDir,
				"`%s` exists and is not a directory", name)
		}
		return id, nil
	}
	if werr.ClassOf(err) != werr.NotFound {
		return model.ZeroHash, err
	}
	return s.Mkdir(parent, []byte(name), 0o755, s.options.OwnerUID, s.options.OwnerGID)
}

func (s *Store) ensureRetentionDirs() (model.Hash32, model.Hash32, error) {
	root, err := s.ResolvePath("/")
	if err != nil {
		return model.ZeroHash, model.ZeroHash, err
	}
	retention, err := s.ensureRetentionDir(root, RetentionDir)
	if err != nil {
		return model.ZeroHash, model.ZeroHash, err
	}
	bindings, err := s.ensureRetentionDir(retention, RetentionBindingsDir)
	if err != nil {
		return model.ZeroHash, model.ZeroHash, err
	}
	current, err := s.ensureRetentionDir(retention, RetentionCurrentDir)
	if err != nil {
		return model.ZeroHash, model.ZeroHash, err
	}
	return bindings, current, nil
}

// RetentionPointer returns the current pointer for a descriptor root.
func (s *Store) RetentionPointer(descriptorRoot model.Hash32) (*RetentionPointer, error) {
	dir, ok, err := s.retentionSubdir(RetentionCurrentDir)
	if err != nil || !ok {
		return nil, err
	}
	id, err := s.Lookup(dir, []byte(descriptorRoot.Hex()))
	if err != nil {
		if werr.ClassOf(err) == werr.NotFound {
			return nil, nil
		}
		return nil, err
	}
	data, err := s.ReadObject(id)
	if err != nil {
		return nil, err
	}
	pointer, err := DecodePointer(data)
	if err != nil {
		return nil, err
	}
	if pointer.DescriptorRoot != descriptorRoot {
		return nil, werr.Newf(werr.Corrupt,
			"retention pointer `%s` names descriptor root %s",
			descriptorRoot.Hex(), pointer.DescriptorRoot.Hex())
	}
	return pointer, nil
}

// RetentionBindingByID reads and verifies one immutable binding.
func (s *Store) RetentionBindingByID(id model.Hash32) (*RetentionBinding, error) {
	dir, ok, err := s.retentionSubdir(RetentionBindingsDir)
	if err != nil || !ok {
		return nil, werr.Newf(werr.NotFound, "retention binding %s does not exist", id.Hex())
	}
	object, err := s.Lookup(dir, []byte(id.Hex()))
	if err != nil {
		if werr.ClassOf(err) == werr.NotFound {
			return nil, werr.Newf(werr.NotFound, "retention binding %s does not exist", id.Hex())
		}
		return nil, err
	}
	data, err := s.ReadObject(object)
	if err != nil {
		return nil, err
	}
	binding, err := DecodeRetentionBinding(data)
	if err != nil {
		return nil, err
	}
	computed, err := binding.ID()
	if err != nil {
		return nil, err
	}
	if computed != id {
		return nil, werr.Newf(werr.Corrupt,
			"retention binding %s does not re-encode to its own identity", id.Hex())
	}
	return binding, nil
}

// RetentionOf returns the current binding for a descriptor root.
func (s *Store) RetentionOf(descriptorRoot model.Hash32) (*RetentionBinding, error) {
	pointer, err := s.RetentionPointer(descriptorRoot)
	if err != nil || pointer == nil {
		return nil, err
	}
	binding, err := s.RetentionBindingByID(pointer.Binding)
	if err != nil {
		return nil, err
	}
	if binding.DescriptorRoot != descriptorRoot {
		return nil, werr.Newf(werr.Corrupt,
			"retention binding %s names descriptor root %s, not %s",
			pointer.Binding.Hex(), binding.DescriptorRoot.Hex(), descriptorRoot.Hex())
	}
	return binding, nil
}

// RetentionHistory follows supersedes from the current binding, newest first.
func (s *Store) RetentionHistory(descriptorRoot model.Hash32, limit int) ([]RetentionHistoryEntry, error) {
	if limit <= 0 || limit > MaxRetentionHistory {
		limit = MaxRetentionHistory
	}
	pointer, err := s.RetentionPointer(descriptorRoot)
	if err != nil || pointer == nil {
		return nil, err
	}
	var out []RetentionHistoryEntry
	next := &pointer.Binding
	seen := make(map[model.Hash32]struct{})
	for next != nil && len(out) < limit {
		if _, ok := seen[*next]; ok {
			return nil, werr.Newf(werr.Corrupt,
				"retention history for %s contains a cycle at %s",
				descriptorRoot.Hex(), next.Hex())
		}
		seen[*next] = struct{}{}
		binding, err := s.RetentionBindingByID(*next)
		if err != nil {
			return nil, err
		}
		out = append(out, RetentionHistoryEntry{ID: *next, Binding: binding})
		next = binding.Supersedes
	}
	return out, nil
}

// RetentionHistoryEntry is one (RetentionId, binding) pair.
type RetentionHistoryEntry struct {
	ID      model.Hash32
	Binding *RetentionBinding
}

// SetRetention publishes (or rebinds) a retention binding.
func (s *Store) SetRetention(request RetentionRequest) (model.Hash32, error) {
	if err := s.requireWritable(); err != nil {
		return model.ZeroHash, err
	}
	if request.Artifact == nil {
		return model.ZeroHash, werr.New(werr.InvalidArgument,
			"a retention binding needs an explicit artifact content root")
	}
	artifact := *request.Artifact
	if exists, err := s.blobs.Exists(BlobManifest, artifact); err != nil {
		return model.ZeroHash, err
	} else if !exists {
		return model.ZeroHash, werr.Newf(werr.NotFound,
			"artifact manifest %s does not exist", artifact.Hex())
	}
	nowNS := s.nowNS()
	if request.IssuedAtNS != nil {
		nowNS = *request.IssuedAtNS
	}
	var supersedes *model.Hash32
	pointer, err := s.RetentionPointer(request.DescriptorRoot)
	if err != nil {
		return model.ZeroHash, err
	}
	if pointer != nil {
		if pointer.Artifact != artifact {
			return model.ZeroHash, werr.Newf(werr.Conflict,
				"descriptor root %s is already bound to artifact %s",
				request.DescriptorRoot.Hex(), pointer.Artifact.Hex())
		}
		current, err := s.RetentionBindingByID(pointer.Binding)
		if err != nil {
			return model.ZeroHash, err
		}
		if request.PolicyEpoch < current.PolicyEpoch {
			return model.ZeroHash, werr.Newf(werr.Conflict,
				"retention policy epoch %d is lower than the current epoch %d",
				request.PolicyEpoch, current.PolicyEpoch)
		}
		history, err := s.RetentionHistory(request.DescriptorRoot, MaxRetentionHistory)
		if err != nil {
			return model.ZeroHash, err
		}
		if len(history) >= MaxRetentionHistory {
			return model.ZeroHash, werr.Newf(werr.LimitExceeded,
				"retention history for %s reached the %d-binding bound",
				request.DescriptorRoot.Hex(), MaxRetentionHistory)
		}
		id := pointer.Binding
		supersedes = &id
	}
	if request.Class.RequiresRoot() {
		held, err := s.durableRootHolds(artifact, nowNS)
		if err != nil {
			return model.ZeroHash, err
		}
		if !held {
			return model.ZeroHash, werr.Newf(werr.InvalidArgument,
				"a durable retention binding requires an explicit pin or snapshot root for %s",
				request.DescriptorRoot.Hex())
		}
	}
	binding, err := NewRetentionBinding(
		request.DescriptorRoot, request.Class, request.DeclaredLifetimeMS,
		request.Producer, request.PolicyEpoch, nowNS, supersedes,
	)
	if err != nil {
		return model.ZeroHash, err
	}
	if request.SignSeed != nil {
		if err := binding.Sign(*request.SignSeed); err != nil {
			return model.ZeroHash, err
		}
	}
	if request.TrustSetBy || len(request.TrustKeys) > 0 {
		if err := binding.VerifySignatureWithTrust(request.TrustKeys); err != nil {
			return model.ZeroHash, err
		}
	}
	bindingID, err := binding.ID()
	if err != nil {
		return model.ZeroHash, err
	}
	bindingsDir, currentDir, err := s.ensureRetentionDirs()
	if err != nil {
		return model.ZeroHash, err
	}
	data, err := binding.Encode()
	if err != nil {
		return model.ZeroHash, err
	}
	if _, err := s.CreateFile(bindingsDir, []byte(bindingID.Hex()), data, 0o444,
		s.options.OwnerUID, s.options.OwnerGID, map[string]wcb.Value{}); err != nil {
		if werr.ClassOf(err) != werr.Exists {
			return model.ZeroHash, err
		}
		existingID, lookupErr := s.Lookup(bindingsDir, []byte(bindingID.Hex()))
		if lookupErr != nil {
			return model.ZeroHash, lookupErr
		}
		existing, readErr := s.ReadObject(existingID)
		if readErr != nil {
			return model.ZeroHash, readErr
		}
		if string(existing) != string(data) {
			return model.ZeroHash, werr.Newf(werr.Corrupt,
				"retention binding %s already exists with different bytes", bindingID.Hex())
		}
	}
	pointer = &RetentionPointer{
		DescriptorRoot: request.DescriptorRoot,
		Binding:        bindingID,
		Artifact:       artifact,
	}
	encoded := pointer.Encode()
	existingPointer, err := s.Lookup(currentDir, []byte(request.DescriptorRoot.Hex()))
	if err == nil {
		object, metaErr := s.ObjectMeta(existingPointer)
		if metaErr != nil {
			return model.ZeroHash, metaErr
		}
		if object.Size != RetentionPointerBytes {
			return model.ZeroHash, werr.Newf(werr.Corrupt,
				"existing retention pointer for %s is %d bytes",
				request.DescriptorRoot.Hex(), object.Size)
		}
		if _, err := s.WriteFile(existingPointer, 0, encoded); err != nil {
			return model.ZeroHash, err
		}
	} else if werr.ClassOf(err) == werr.NotFound {
		if _, err := s.CreateFile(currentDir, []byte(request.DescriptorRoot.Hex()), encoded,
			0o644, s.options.OwnerUID, s.options.OwnerGID, map[string]wcb.Value{}); err != nil {
			return model.ZeroHash, err
		}
	} else {
		return model.ZeroHash, err
	}
	return bindingID, nil
}

// durableRootHolds checks for an in-memory pin or a snapshot/checkpoint root.
func (s *Store) durableRootHolds(artifact model.Hash32, nowNS int64) (bool, error) {
	for _, record := range s.state.Objects {
		if record.Kind != model.KindFile || record.Content != artifact {
			continue
		}
		if s.ObjectPinCount(record.ID) > 0 {
			return true, nil
		}
	}
	_, _, origins, _, err := s.retentionReachability(nowNS)
	if err != nil {
		return false, err
	}
	for label := range origins[artifact] {
		if strings.HasPrefix(label, "snapshot:") || strings.HasPrefix(label, "checkpoint:") ||
			strings.HasPrefix(label, "pin:") || strings.HasPrefix(label, "transaction:") {
			return true, nil
		}
	}
	return false, nil
}

// retentionReachability computes the GC root set exactly as gcPass does, and
// records the root label that retained each blob.
func (s *Store) retentionReachability(nowNS int64) (
	manifests map[model.Hash32]struct{},
	chunks map[model.Hash32]struct{},
	origins map[model.Hash32]map[string]struct{},
	problems []string,
	err error,
) {
	ctx := context.Background()
	manifests = make(map[model.Hash32]struct{})
	chunks = make(map[model.Hash32]struct{})
	origins = make(map[model.Hash32]map[string]struct{})
	record := func(id model.Hash32, origin string) {
		if origins[id] == nil {
			origins[id] = make(map[string]struct{})
		}
		origins[id][origin] = struct{}{}
	}
	txGraceNS := int64(0)
	if s.options.GCGraceSecs < uint64((1<<62)/1_000_000_000) {
		txGraceNS = int64(s.options.GCGraceSecs) * 1_000_000_000
	} else {
		txGraceNS = 1 << 62
	}
	if _, txErr := s.markPreparedTransactions(txGraceNS, nowNS, manifests, chunks, &problems); txErr != nil {
		return nil, nil, nil, problems, txErr
	}
	merge := func(srcM, srcC map[model.Hash32]struct{}, origin string) {
		for id := range srcM {
			manifests[id] = struct{}{}
			record(id, origin)
		}
		for id := range srcC {
			chunks[id] = struct{}{}
			record(id, origin)
		}
	}
	tmpM := make(map[model.Hash32]struct{})
	tmpC := make(map[model.Hash32]struct{})
	if markErr := markState(ctx, s.blobs, s.state, tmpM, tmpC, &problems); markErr != nil {
		return nil, nil, nil, problems, markErr
	}
	merge(tmpM, tmpC, "head:"+s.head.Hex())

	names := make([]string, 0, len(s.state.Snapshots))
	for name := range s.state.Snapshots {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		state, stateErr := s.StateAt(s.state.Snapshots[name])
		if stateErr != nil {
			problems = append(problems, "snapshot "+name+" state is unreadable: "+stateErr.Error())
			continue
		}
		tmpM = make(map[model.Hash32]struct{})
		tmpC = make(map[model.Hash32]struct{})
		if markErr := markState(ctx, s.blobs, state, tmpM, tmpC, &problems); markErr != nil {
			return nil, nil, nil, problems, markErr
		}
		merge(tmpM, tmpC, "snapshot:"+s.state.Snapshots[name].Hex())
	}

	commits, commitErr := allCommitsFrom(s.commits, ^uint64(0))
	if commitErr != nil {
		return nil, nil, nil, problems, commitErr
	}
	for _, commit := range commits {
		if commit.Commit.Checkpoint == nil {
			continue
		}
		checkpoint := *commit.Commit.Checkpoint
		manifests[checkpoint] = struct{}{}
		record(checkpoint, "checkpoint:"+checkpoint.Hex())
		state, stateErr := readStateManifest(s.blobs, checkpoint)
		if stateErr != nil {
			problems = append(problems, "checkpoint "+checkpoint.Hex()+" is unreadable: "+stateErr.Error())
			continue
		}
		tmpM = make(map[model.Hash32]struct{})
		tmpC = make(map[model.Hash32]struct{})
		if markErr := markState(ctx, s.blobs, state, tmpM, tmpC, &problems); markErr != nil {
			return nil, nil, nil, problems, markErr
		}
		merge(tmpM, tmpC, "checkpoint:"+checkpoint.Hex())
	}

	pins := make([]model.Hash32, 0, len(s.contentPins))
	for content := range s.contentPins {
		pins = append(pins, content)
	}
	sort.Slice(pins, func(i, j int) bool { return pins[i].Less(pins[j]) })
	for _, content := range pins {
		manifests[content] = struct{}{}
		record(content, "pin:"+content.Hex())
		seen := make(map[model.Hash32]struct{})
		tmpM = make(map[model.Hash32]struct{})
		tmpC = make(map[model.Hash32]struct{})
		if markErr := markManifestTree(ctx, s.blobs, content, tmpM, tmpC, &problems, 0, seen); markErr != nil {
			return nil, nil, nil, problems, markErr
		}
		merge(tmpM, tmpC, "pin:"+content.Hex())
	}
	return manifests, chunks, origins, problems, nil
}

func smallestOrigin(origins map[model.Hash32]map[string]struct{}, id model.Hash32) string {
	labels := origins[id]
	smallest := ""
	for label := range labels {
		if smallest == "" || label < smallest {
			smallest = label
		}
	}
	return smallest
}

type retentionRawCandidate struct {
	candidate gcCandidate
	rank      int
	class     string
	expiryNS  *int64
	roots     []model.Hash32
}

// GCPlan computes a class-aware plan without deleting.
func (s *Store) GCPlan(nowNS int64, budgetBytes *uint64) (RetentionGCPlan, error) {
	plan, _, err := s.retentionPlan(nowNS, budgetBytes)
	return plan, err
}

// RetentionGC executes a class-aware plan. `apply == false` is GCPlan.
func (s *Store) RetentionGC(apply bool, nowNS int64, budgetBytes *uint64) (RetentionGCPlan, error) {
	if err := s.requireWritable(); err != nil {
		return RetentionGCPlan{}, err
	}
	plan, keys, err := s.retentionPlan(nowNS, budgetBytes)
	if err != nil {
		return plan, err
	}
	plan.Applied = apply
	if !apply || len(keys) == 0 {
		return plan, nil
	}
	for _, key := range keys {
		if err := s.blobs.DeleteEntry(key); err != nil {
			return plan, werr.Wrap(werr.Io, err, "cannot delete %s", key.Rel)
		}
	}
	reclaim, err := s.blobs.ReclaimUnreferencedPacks()
	if err != nil {
		plan.Problems = append(plan.Problems, "pack reclamation: "+err.Error())
	} else {
		plan.ReclaimedPackBytes = reclaim.DeletedPackBytes
	}
	plan.ReclaimedBytes = plan.PlannedBytes
	plan.ReclaimedBlobs = plan.PlannedBlobs
	return plan, nil
}

func (s *Store) retentionPlan(nowNS int64, budgetBytes *uint64) (RetentionGCPlan, []BlobEntry, error) {
	plan := RetentionGCPlan{
		NowNS:       nowNS,
		BudgetBytes: budgetBytes,
		GraceSecs:   s.options.GCGraceSecs,
	}
	manifests, chunks, origins, problems, err := s.retentionReachability(nowNS)
	if err != nil {
		return plan, nil, err
	}
	plan.Problems = append(plan.Problems, problems...)
	plan.ReachableManifests = uint64(len(manifests))
	plan.ReachableChunks = uint64(len(chunks))

	summaries := make(map[int]*RetentionClassSummary)
	for _, class := range RetentionClassAll {
		summaries[class.Rank()] = &RetentionClassSummary{Class: string(class)}
	}
	summaries[0] = &RetentionClassSummary{Class: "unbound"}

	var owners []retentionOwner
	currentDir, ok, err := s.retentionSubdir(RetentionCurrentDir)
	if err != nil {
		return plan, nil, err
	}
	if ok {
		entries, listErr := s.ListDir(currentDir)
		if listErr != nil {
			return plan, nil, listErr
		}
		for _, entry := range entries {
			name := string(entry.Name)
			data, readErr := s.ReadObject(entry.Target)
			if readErr != nil {
				plan.Problems = append(plan.Problems,
					"retention pointer `"+name+"` is unreadable: "+readErr.Error())
				continue
			}
			pointer, decodeErr := DecodePointer(data)
			if decodeErr != nil {
				plan.Problems = append(plan.Problems,
					"retention pointer `"+name+"` is unreadable: "+decodeErr.Error())
				continue
			}
			if pointer.DescriptorRoot.Hex() != name {
				plan.Problems = append(plan.Problems,
					"retention pointer `"+name+"` names descriptor root "+pointer.DescriptorRoot.Hex())
				continue
			}
			binding, bindErr := s.RetentionBindingByID(pointer.Binding)
			if bindErr != nil {
				plan.Problems = append(plan.Problems,
					"retention binding "+pointer.Binding.Hex()+" is unreadable: "+bindErr.Error())
				continue
			}
			if binding.DescriptorRoot != pointer.DescriptorRoot {
				plan.Problems = append(plan.Problems,
					"retention binding "+pointer.Binding.Hex()+" does not name descriptor root "+
						pointer.DescriptorRoot.Hex())
				continue
			}
			ctx := context.Background()
			artifactM := make(map[model.Hash32]struct{})
			artifactC := make(map[model.Hash32]struct{})
			seen := make(map[model.Hash32]struct{})
			if markErr := markManifestTree(ctx, s.blobs, pointer.Artifact,
				artifactM, artifactC, &plan.Problems, 0, seen); markErr != nil {
				return plan, nil, markErr
			}
			blobs := make([]model.Hash32, 0, len(artifactM)+len(artifactC))
			for id := range artifactM {
				blobs = append(blobs, id)
			}
			for id := range artifactC {
				blobs = append(blobs, id)
			}
			sort.Slice(blobs, func(i, j int) bool { return blobs[i].Less(blobs[j]) })
			var artifactBytes uint64
			for _, id := range blobs {
				artifactBytes += s.retentionBlobLen(id)
			}
			expiry, hasExpiry := binding.ExpiresAtNS()
			var expiryPtr *int64
			if hasExpiry {
				value := expiry
				expiryPtr = &value
			}
			owners = append(owners, retentionOwner{
				descriptorRoot: pointer.DescriptorRoot,
				binding:        pointer.Binding,
				class:          binding.Class,
				expiryNS:       expiryPtr,
				live:           binding.IsLive(nowNS),
				artifact:       pointer.Artifact,
				artifactBytes:  artifactBytes,
				artifactBlobs:  blobs,
			})
		}
	}

	ownersByBlob := make(map[model.Hash32][]int)
	for index := range owners {
		for _, blob := range owners[index].artifactBlobs {
			ownersByBlob[blob] = append(ownersByBlob[blob], index)
		}
	}

	for index := range owners {
		owner := &owners[index]
		summary := summaries[owner.class.Rank()]
		var reachableBlobs uint64
		for _, blob := range owner.artifactBlobs {
			if _, ok := manifests[blob]; ok {
				reachableBlobs++
			} else if _, ok := chunks[blob]; ok {
				reachableBlobs++
			}
		}
		if reachableBlobs > 0 {
			summary.ReachableArtifacts++
			summary.ReachableBlobs += reachableBlobs
			summary.ReachableBytes += owner.artifactBytes
			if !owner.live {
				reason := ""
				if origin := smallestOrigin(origins, owner.artifact); origin != "" {
					reason = "reachable from " + origin
				} else {
					for _, blob := range owner.artifactBlobs {
						if origin := smallestOrigin(origins, blob); origin != "" {
							reason = "reachable from " + origin
							break
						}
					}
				}
				if reason == "" {
					reason = "reachable from head"
				}
				plan.Retained = append(plan.Retained, RetainedArtifact{
					DescriptorRoot: owner.descriptorRoot,
					Class:          string(owner.class),
					Binding:        owner.binding,
					Artifact:       owner.artifact,
					Expired:        true,
					Bytes:          owner.artifactBytes,
					Reason:         reason,
				})
			}
		} else if owner.live {
			summary.RetainedLiveArtifacts++
			summary.RetainedLiveBlobs += uint64(len(owner.artifactBlobs))
			summary.RetainedLiveBytes += owner.artifactBytes
			reason := "retention live"
			if owner.expiryNS != nil {
				reason = "retention live until " + strconv.FormatInt(*owner.expiryNS, 10)
			}
			plan.Retained = append(plan.Retained, RetainedArtifact{
				DescriptorRoot: owner.descriptorRoot,
				Class:          string(owner.class),
				Binding:        owner.binding,
				Artifact:       owner.artifact,
				Expired:        false,
				Bytes:          owner.artifactBytes,
				Reason:         reason,
			})
		}
	}

	ctx := context.Background()
	report := GCReport{}
	now := time.Now()
	manifestCandidates, err := collectUnmarked(ctx, s.blobs, "manifests", manifests, now, s.options.GCGraceSecs, &report)
	if err != nil {
		return plan, nil, err
	}
	objectCandidates, err := collectUnmarked(ctx, s.blobs, "objects", chunks, now, s.options.GCGraceSecs, &report)
	if err != nil {
		return plan, nil, err
	}
	plan.Problems = append(plan.Problems, report.Problems...)
	raw := append(manifestCandidates, objectCandidates...)

	var candidates []retentionRawCandidate
	var retainedLiveBytes uint64
	for _, candidate := range raw {
		indices := ownersByBlob[candidate.id]
		if len(indices) == 0 {
			candidates = append(candidates, retentionRawCandidate{
				candidate: candidate,
				rank:      0,
				class:     "unbound",
			})
			continue
		}
		live := false
		for _, index := range indices {
			if owners[index].live {
				live = true
				break
			}
		}
		if live {
			retainedLiveBytes += candidate.size
			continue
		}
		rank := 0
		class := "unbound"
		var expiry *int64
		seenRoots := make(map[model.Hash32]struct{})
		var roots []model.Hash32
		for _, index := range indices {
			owner := &owners[index]
			if owner.class.Rank() > rank {
				rank = owner.class.Rank()
				class = string(owner.class)
			}
			if owner.expiryNS != nil && (expiry == nil || *owner.expiryNS > *expiry) {
				value := *owner.expiryNS
				expiry = &value
			}
			if _, ok := seenRoots[owner.descriptorRoot]; !ok {
				seenRoots[owner.descriptorRoot] = struct{}{}
				roots = append(roots, owner.descriptorRoot)
			}
		}
		sort.Slice(roots, func(i, j int) bool { return roots[i].Less(roots[j]) })
		candidates = append(candidates, retentionRawCandidate{
			candidate: candidate,
			rank:      rank,
			class:     class,
			expiryNS:  expiry,
			roots:     roots,
		})
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.rank != b.rank {
			return a.rank < b.rank
		}
		aExpiry := int64(-1 << 63)
		bExpiry := int64(-1 << 63)
		if a.expiryNS != nil {
			aExpiry = *a.expiryNS
		}
		if b.expiryNS != nil {
			bExpiry = *b.expiryNS
		}
		if aExpiry != bExpiry {
			return aExpiry < bExpiry
		}
		for k := 0; k < len(a.roots) && k < len(b.roots); k++ {
			if a.roots[k] != b.roots[k] {
				return a.roots[k].Less(b.roots[k])
			}
		}
		if len(a.roots) != len(b.roots) {
			return len(a.roots) < len(b.roots)
		}
		return a.candidate.rel < b.candidate.rel
	})

	var keys []BlobEntry
	var selectedBytes uint64
	for _, candidate := range candidates {
		fits := true
		if budgetBytes != nil {
			fits = selectedBytes == 0 || selectedBytes+candidate.candidate.size <= *budgetBytes
		}
		if !fits {
			break
		}
		if summary := summaries[candidate.rank]; summary != nil {
			summary.ReclaimableBlobs++
			summary.ReclaimableBytes += candidate.candidate.size
		}
		selectedBytes += candidate.candidate.size
		plan.Candidates = append(plan.Candidates, RetentionCandidate{
			Path:            candidate.candidate.rel,
			Bytes:           candidate.candidate.size,
			Class:           candidate.class,
			DescriptorRoots: candidate.roots,
			ExpiryNS:        candidate.expiryNS,
		})
		keys = append(keys, BlobEntry{
			Kind: candidate.candidate.kind,
			ID:   candidate.candidate.id,
			Rel:  candidate.candidate.rel,
			Size: candidate.candidate.size,
		})
	}
	plan.PlannedBytes = selectedBytes
	plan.PlannedBlobs = uint64(len(keys))
	if budgetBytes != nil && retainedLiveBytes > *budgetBytes {
		plan.OverBudgetBytes = retainedLiveBytes - *budgetBytes
	}
	for rank := 0; rank <= 4; rank++ {
		if summary := summaries[rank]; summary != nil {
			plan.Classes = append(plan.Classes, *summary)
		}
	}
	sort.Slice(plan.Retained, func(i, j int) bool {
		if plan.Retained[i].Class != plan.Retained[j].Class {
			return plan.Retained[i].Class < plan.Retained[j].Class
		}
		return plan.Retained[i].DescriptorRoot.Less(plan.Retained[j].DescriptorRoot)
	})
	return plan, keys, nil
}

func (s *Store) retentionBlobLen(id model.Hash32) uint64 {
	if length, err := s.blobs.Length(BlobManifest, id); err == nil {
		return length
	}
	if length, err := s.blobs.Length(BlobObject, id); err == nil {
		return length
	}
	return 0
}

func formatInt(value int64) string {
	return strconv.FormatInt(value, 10)
}
