package store

// Write budgets (quotas).
//
// A quota is an *admission* budget: every commit is charged the bytes and
// object records it would add, and a principal that would cross its configured
// limit is refused before the commit is published. Content already reachable
// from committed state costs zero.
//
// Usage is committed state: every policy-enabled commit carries one
// `set_quota_usage` op describing the cumulative usage after its other ops.
// The store-root `quota` file is policy-only (`WFQ2`); it is written only when
// a policy is installed or a legacy record is migrated. There is no separate
// durable usage write per commit. Older commits with no usage op replay
// unchanged, and replay rejects an assertion that disagrees with the
// recomputed admission totals as `Corrupt`. The encoding and ordering are
// byte-identical to the Rust store.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/infinityabundance/WeftCodec-Go/hash"
	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

const (
	// QuotaSchema is the legacy combined policy+usage record schema.
	QuotaSchema = "weftfs.quota.v1"
	// QuotaDomain separates the legacy record digest.
	QuotaDomain = "weft/quota/v1"
	// QuotaPolicySchema is the policy-only record schema.
	QuotaPolicySchema = "weftfs.quota.v2"
	// QuotaPolicyDomain separates the policy-only record digest.
	QuotaPolicyDomain = "weft/quota/v2"
	// MaxQuotaPrincipals bounds one store's policy.
	MaxQuotaPrincipals = 4096
	// MaxTenantBytes matches the capability envelope tenant bound.
	MaxTenantBytes = 256
)

var (
	quotaMagic       = []byte("WFQ1")
	quotaPolicyMagic = []byte("WFQ2")
)

// QuotaPrincipal is the identity a budget is attached to.
type QuotaPrincipal struct {
	// Kind is "posix" or "tenant".
	Kind   string
	UID    uint64
	GID    uint64
	Tenant string
}

// PosixPrincipal builds a POSIX quota principal.
func PosixPrincipal(uid, gid uint64) QuotaPrincipal {
	return QuotaPrincipal{Kind: "posix", UID: uid, GID: gid}
}

// TenantPrincipal builds a tenant quota principal.
func TenantPrincipal(tenant string) QuotaPrincipal {
	return QuotaPrincipal{Kind: "tenant", Tenant: tenant}
}

// SortKey is the canonical ordering key (identical to the Rust store).
func (p QuotaPrincipal) SortKey() string {
	if p.Kind == "tenant" {
		return "t:" + p.Tenant
	}
	return fmt.Sprintf("p:%020d:%020d", p.UID, p.GID)
}

// Display is `uid:gid` or `tenant:<name>`.
func (p QuotaPrincipal) Display() string {
	if p.Kind == "tenant" {
		return "tenant:" + p.Tenant
	}
	return fmt.Sprintf("%d:%d", p.UID, p.GID)
}

func (p QuotaPrincipal) validate() error {
	switch p.Kind {
	case "posix":
		return nil
	case "tenant":
		if len(p.Tenant) == 0 || len(p.Tenant) > MaxTenantBytes {
			return werr.Newf(werr.InvalidArgument, "tenant label must be 1..=%d bytes", MaxTenantBytes)
		}
		return nil
	default:
		return werr.Newf(werr.Malformed, "unknown quota principal kind `%s`", p.Kind)
	}
}

// QuotaBudget is one configured budget.
type QuotaBudget struct {
	Principal   QuotaPrincipal
	MaxNewBytes uint64
	MaxObjects  uint64
}

// QuotaCounters is cumulative admitted usage for one principal.
type QuotaCounters struct {
	UsedBytes   uint64
	UsedObjects uint64
}

func (c *QuotaCounters) add(other QuotaCounters) error {
	bytes, carry := addU64(c.UsedBytes, other.UsedBytes)
	if carry {
		return werr.Newf(werr.LimitExceeded, "quota byte counter overflow")
	}
	objects, carry := addU64(c.UsedObjects, other.UsedObjects)
	if carry {
		return werr.Newf(werr.LimitExceeded, "quota object counter overflow")
	}
	c.UsedBytes = bytes
	c.UsedObjects = objects
	return nil
}

func addU64(a, b uint64) (uint64, bool) {
	sum := a + b
	return sum, sum < a
}

// QuotaRecord is the decoded quota file.
type QuotaRecord struct {
	Generation uint64
	Commit     model.Hash32
	Budgets    []QuotaBudget
	Usage      []QuotaUsageEntry
}

// QuotaUsageEntry is one principal's counters in a record.
type QuotaUsageEntry struct {
	Principal QuotaPrincipal
	Counters  QuotaCounters
}

// QuotaState is the runtime policy and usage held by an open store.
type QuotaState struct {
	Policy        map[string]QuotaBudget
	Usage         map[string]QuotaCounters
	Generation    uint64
	Commit        model.Hash32
	Valid         bool
	RecordPresent bool
	// UsageCommitted is true when Usage came from a committed
	// `set_quota_usage` op (or was just published as one).
	UsageCommitted bool
	// MigratedPresent records a preserved legacy `quota.migrated` file.
	MigratedPresent bool
	Reason          string
}

func newQuotaState() QuotaState {
	return QuotaState{
		Policy: make(map[string]QuotaBudget),
		Usage:  make(map[string]QuotaCounters),
		Valid:  true,
	}
}

func (q QuotaState) enforced() bool { return len(q.Policy) > 0 }

// NormalizeQuotaPolicy sorts and validates a policy.
func NormalizeQuotaPolicy(budgets []QuotaBudget) ([]QuotaBudget, error) {
	if len(budgets) > MaxQuotaPrincipals {
		return nil, werr.Newf(werr.LimitExceeded, "at most %d quota principals are supported", MaxQuotaPrincipals)
	}
	for _, budget := range budgets {
		if err := budget.Principal.validate(); err != nil {
			return nil, err
		}
	}
	out := append([]QuotaBudget(nil), budgets...)
	sort.Slice(out, func(i, j int) bool { return out[i].Principal.SortKey() < out[j].Principal.SortKey() })
	for i := 1; i < len(out); i++ {
		if out[i].Principal.SortKey() == out[i-1].Principal.SortKey() {
			return nil, werr.Newf(werr.InvalidArgument, "duplicate quota for principal `%s`", out[i].Principal.Display())
		}
	}
	return out, nil
}

func principalValue(p QuotaPrincipal) map[string]wcb.Value {
	m := map[string]wcb.Value{}
	if p.Kind == "tenant" {
		m["kind"] = wcb.TextValue("tenant")
		m["tenant"] = wcb.TextValue(p.Tenant)
		return m
	}
	m["kind"] = wcb.TextValue("posix")
	m["uid"] = wcb.U64Value(p.UID)
	m["gid"] = wcb.U64Value(p.GID)
	return m
}

func principalFromMap(m map[string]wcb.Value) (QuotaPrincipal, error) {
	kind, err := model.GetText(m, "kind")
	if err != nil {
		return QuotaPrincipal{}, err
	}
	switch kind {
	case "posix":
		uid, err := model.GetU64(m, "uid")
		if err != nil {
			return QuotaPrincipal{}, err
		}
		gid, err := model.GetU64(m, "gid")
		if err != nil {
			return QuotaPrincipal{}, err
		}
		return QuotaPrincipal{Kind: "posix", UID: uid, GID: gid}, nil
	case "tenant":
		tenant, err := model.GetText(m, "tenant")
		if err != nil {
			return QuotaPrincipal{}, err
		}
		return QuotaPrincipal{Kind: "tenant", Tenant: tenant}, nil
	default:
		return QuotaPrincipal{}, werr.Newf(werr.Malformed, "unknown quota principal kind `%s`", kind)
	}
}

// ToWCB returns the canonical record value.
func (r QuotaRecord) ToWCB() wcb.Value {
	budgets := make([]wcb.Value, 0, len(r.Budgets))
	for _, budget := range r.Budgets {
		m := principalValue(budget.Principal)
		m["max_new_bytes"] = wcb.U64Value(budget.MaxNewBytes)
		m["max_objects"] = wcb.U64Value(budget.MaxObjects)
		budgets = append(budgets, wcb.MapValue(m))
	}
	usage := make([]wcb.Value, 0, len(r.Usage))
	for _, entry := range r.Usage {
		m := principalValue(entry.Principal)
		m["used_bytes"] = wcb.U64Value(entry.Counters.UsedBytes)
		m["used_objects"] = wcb.U64Value(entry.Counters.UsedObjects)
		usage = append(usage, wcb.MapValue(m))
	}
	return wcb.MapValue(map[string]wcb.Value{
		"schema":     wcb.TextValue(QuotaSchema),
		"generation": wcb.U64Value(r.Generation),
		"commit":     model.HashValue(r.Commit),
		"budgets":    wcb.ArrayValue(budgets),
		"usage":      wcb.ArrayValue(usage),
	})
}

// Normalize sorts budgets and usage into canonical order.
func (r *QuotaRecord) Normalize() error {
	if len(r.Budgets) > MaxQuotaPrincipals {
		return werr.Newf(werr.LimitExceeded, "at most %d quota principals are supported", MaxQuotaPrincipals)
	}
	for _, budget := range r.Budgets {
		if err := budget.Principal.validate(); err != nil {
			return err
		}
	}
	sort.SliceStable(r.Budgets, func(i, j int) bool {
		return r.Budgets[i].Principal.SortKey() < r.Budgets[j].Principal.SortKey()
	})
	for i := 0; i < len(r.Usage); i++ {
		if err := r.Usage[i].Principal.validate(); err != nil {
			return err
		}
	}
	sort.SliceStable(r.Usage, func(i, j int) bool {
		return r.Usage[i].Principal.SortKey() < r.Usage[j].Principal.SortKey()
	})
	for i := 1; i < len(r.Usage); i++ {
		if r.Usage[i].Principal.SortKey() == r.Usage[i-1].Principal.SortKey() {
			return werr.Newf(werr.NonCanonical, "duplicate quota usage principal")
		}
	}
	return nil
}

// EncodeBytes renders `WFQ1 || u64le(len) || WCB || digest`.
func (r QuotaRecord) EncodeBytes() ([]byte, error) {
	encoded, err := model.EncodeWCB(r.ToWCB())
	if err != nil {
		return nil, err
	}
	if len(encoded) > 64*1024*1024 {
		return nil, werr.Newf(werr.LimitExceeded, "quota record is implausibly large")
	}
	digest := hash.Domain(QuotaDomain, encoded)
	out := make([]byte, 0, 4+8+len(encoded)+32)
	out = append(out, quotaMagic...)
	var length [8]byte
	binary.LittleEndian.PutUint64(length[:], uint64(len(encoded)))
	out = append(out, length[:]...)
	out = append(out, encoded...)
	out = append(out, digest.Bytes()...)
	return out, nil
}

// DecodeQuotaRecord decodes and validates the on-disk bytes.
func DecodeQuotaRecord(b []byte) (QuotaRecord, error) {
	if len(b) < 4+8+32 {
		return QuotaRecord{}, werr.Newf(werr.Corrupt, "quota record is truncated")
	}
	if string(b[0:4]) != string(quotaMagic) {
		return QuotaRecord{}, werr.Newf(werr.Corrupt, "quota record has the wrong magic")
	}
	length := binary.LittleEndian.Uint64(b[4:12])
	if length > uint64(len(b)) {
		return QuotaRecord{}, werr.Newf(werr.Corrupt, "quota record length overflows")
	}
	if uint64(len(b)) != 12+length+32 {
		return QuotaRecord{}, werr.Newf(werr.Corrupt, "quota record length disagrees with its frame")
	}
	payload := b[12 : 12+length]
	digest := b[12+length:]
	if !bytes.Equal(hash.Domain(QuotaDomain, payload).Bytes(), digest) {
		return QuotaRecord{}, werr.Newf(werr.Corrupt, "quota record fails its digest check")
	}
	value, err := model.DecodeWCB(payload)
	if err != nil {
		return QuotaRecord{}, err
	}
	return quotaRecordFromValue(value)
}

// QuotaPolicyRecord is the policy-only `quota` file. Usage is intentionally
// absent: it is committed to the commit log instead.
type QuotaPolicyRecord struct {
	Budgets []QuotaBudget
}

// NewQuotaPolicyRecord normalizes a policy.
func NewQuotaPolicyRecord(budgets []QuotaBudget) (QuotaPolicyRecord, error) {
	normalized, err := NormalizeQuotaPolicy(budgets)
	if err != nil {
		return QuotaPolicyRecord{}, err
	}
	return QuotaPolicyRecord{Budgets: normalized}, nil
}

// ToWCB returns the canonical policy value.
func (r QuotaPolicyRecord) ToWCB() wcb.Value {
	budgets := make([]wcb.Value, 0, len(r.Budgets))
	for _, budget := range r.Budgets {
		m := principalValue(budget.Principal)
		m["max_new_bytes"] = wcb.U64Value(budget.MaxNewBytes)
		m["max_objects"] = wcb.U64Value(budget.MaxObjects)
		budgets = append(budgets, wcb.MapValue(m))
	}
	return wcb.MapValue(map[string]wcb.Value{
		"schema":  wcb.TextValue(QuotaPolicySchema),
		"budgets": wcb.ArrayValue(budgets),
	})
}

// EncodeBytes renders `WFQ2 || u64le(len) || WCB || digest`.
func (r QuotaPolicyRecord) EncodeBytes() ([]byte, error) {
	encoded, err := model.EncodeWCB(r.ToWCB())
	if err != nil {
		return nil, err
	}
	if len(encoded) > 64*1024*1024 {
		return nil, werr.Newf(werr.LimitExceeded, "quota policy record is implausibly large")
	}
	digest := hash.Domain(QuotaPolicyDomain, encoded)
	out := make([]byte, 0, 4+8+len(encoded)+32)
	out = append(out, quotaPolicyMagic...)
	var length [8]byte
	binary.LittleEndian.PutUint64(length[:], uint64(len(encoded)))
	out = append(out, length[:]...)
	out = append(out, encoded...)
	out = append(out, digest.Bytes()...)
	return out, nil
}

// DecodeQuotaPolicy decodes and validates a policy-only record.
func DecodeQuotaPolicy(b []byte) (QuotaPolicyRecord, error) {
	if len(b) < 4+8+32 {
		return QuotaPolicyRecord{}, werr.Newf(werr.Corrupt, "quota policy record is truncated")
	}
	if string(b[0:4]) != string(quotaPolicyMagic) {
		return QuotaPolicyRecord{}, werr.Newf(werr.Corrupt, "quota policy record has the wrong magic")
	}
	length := binary.LittleEndian.Uint64(b[4:12])
	if length > uint64(len(b)) {
		return QuotaPolicyRecord{}, werr.Newf(werr.Corrupt, "quota policy record length overflows")
	}
	if uint64(len(b)) != 12+length+32 {
		return QuotaPolicyRecord{}, werr.Newf(werr.Corrupt, "quota policy record length disagrees with its frame")
	}
	payload := b[12 : 12+length]
	digest := b[12+length:]
	if !bytes.Equal(hash.Domain(QuotaPolicyDomain, payload).Bytes(), digest) {
		return QuotaPolicyRecord{}, werr.Newf(werr.Corrupt, "quota policy record fails its digest check")
	}
	value, err := model.DecodeWCB(payload)
	if err != nil {
		return QuotaPolicyRecord{}, err
	}
	m, err := model.AsMap(value)
	if err != nil {
		return QuotaPolicyRecord{}, err
	}
	if err := model.CheckKeys(m, "schema", "budgets"); err != nil {
		return QuotaPolicyRecord{}, err
	}
	schema, err := model.GetText(m, "schema")
	if err != nil {
		return QuotaPolicyRecord{}, err
	}
	if schema != QuotaPolicySchema {
		return QuotaPolicyRecord{}, werr.Newf(werr.Unsupported, "quota policy schema `%s` is not `%s`", schema, QuotaPolicySchema)
	}
	budgetValues, err := model.GetArray(m, "budgets")
	if err != nil {
		return QuotaPolicyRecord{}, err
	}
	budgets := make([]QuotaBudget, 0, len(budgetValues))
	for _, item := range budgetValues {
		entry, err := model.AsMap(item)
		if err != nil {
			return QuotaPolicyRecord{}, err
		}
		if err := model.CheckKeys(entry, "kind", "uid", "gid", "tenant", "max_new_bytes", "max_objects"); err != nil {
			return QuotaPolicyRecord{}, err
		}
		principal, err := principalFromMap(entry)
		if err != nil {
			return QuotaPolicyRecord{}, err
		}
		maxBytes, err := model.GetU64(entry, "max_new_bytes")
		if err != nil {
			return QuotaPolicyRecord{}, err
		}
		maxObjects, err := model.GetU64(entry, "max_objects")
		if err != nil {
			return QuotaPolicyRecord{}, err
		}
		budgets = append(budgets, QuotaBudget{Principal: principal, MaxNewBytes: maxBytes, MaxObjects: maxObjects})
	}
	record, err := NewQuotaPolicyRecord(budgets)
	if err != nil {
		return QuotaPolicyRecord{}, err
	}
	for i := range budgets {
		if budgets[i] != record.Budgets[i] {
			return QuotaPolicyRecord{}, werr.Newf(werr.NonCanonical, "quota budgets are not in canonical principal order")
		}
	}
	return record, nil
}

func quotaRecordFromValue(value wcb.Value) (QuotaRecord, error) {
	m, err := model.AsMap(value)
	if err != nil {
		return QuotaRecord{}, err
	}
	if err := model.CheckKeys(m, "schema", "generation", "commit", "budgets", "usage"); err != nil {
		return QuotaRecord{}, err
	}
	schema, err := model.GetText(m, "schema")
	if err != nil {
		return QuotaRecord{}, err
	}
	if schema != QuotaSchema {
		return QuotaRecord{}, werr.Newf(werr.Unsupported, "quota schema `%s` is not `%s`", schema, QuotaSchema)
	}
	generation, err := model.GetU64(m, "generation")
	if err != nil {
		return QuotaRecord{}, err
	}
	commit, err := model.GetHash(m, "commit")
	if err != nil {
		return QuotaRecord{}, err
	}
	budgetValues, err := model.GetArray(m, "budgets")
	if err != nil {
		return QuotaRecord{}, err
	}
	budgets := make([]QuotaBudget, 0, len(budgetValues))
	for _, item := range budgetValues {
		entry, err := model.AsMap(item)
		if err != nil {
			return QuotaRecord{}, err
		}
		if err := model.CheckKeys(entry, "kind", "uid", "gid", "tenant", "max_new_bytes", "max_objects"); err != nil {
			return QuotaRecord{}, err
		}
		principal, err := principalFromMap(entry)
		if err != nil {
			return QuotaRecord{}, err
		}
		maxBytes, err := model.GetU64(entry, "max_new_bytes")
		if err != nil {
			return QuotaRecord{}, err
		}
		maxObjects, err := model.GetU64(entry, "max_objects")
		if err != nil {
			return QuotaRecord{}, err
		}
		budgets = append(budgets, QuotaBudget{Principal: principal, MaxNewBytes: maxBytes, MaxObjects: maxObjects})
	}
	usageValues, err := model.GetArray(m, "usage")
	if err != nil {
		return QuotaRecord{}, err
	}
	usage := make([]QuotaUsageEntry, 0, len(usageValues))
	for _, item := range usageValues {
		entry, err := model.AsMap(item)
		if err != nil {
			return QuotaRecord{}, err
		}
		if err := model.CheckKeys(entry, "kind", "uid", "gid", "tenant", "used_bytes", "used_objects"); err != nil {
			return QuotaRecord{}, err
		}
		principal, err := principalFromMap(entry)
		if err != nil {
			return QuotaRecord{}, err
		}
		usedBytes, err := model.GetU64(entry, "used_bytes")
		if err != nil {
			return QuotaRecord{}, err
		}
		usedObjects, err := model.GetU64(entry, "used_objects")
		if err != nil {
			return QuotaRecord{}, err
		}
		usage = append(usage, QuotaUsageEntry{Principal: principal, Counters: QuotaCounters{UsedBytes: usedBytes, UsedObjects: usedObjects}})
	}
	record := QuotaRecord{Generation: generation, Commit: commit, Budgets: budgets, Usage: usage}
	// Reject arrays that were not already canonical instead of silently sorting.
	before := append([]QuotaBudget(nil), budgets...)
	beforeUsage := append([]QuotaUsageEntry(nil), usage...)
	if err := record.Normalize(); err != nil {
		return QuotaRecord{}, err
	}
	for i := range before {
		if before[i] != record.Budgets[i] {
			return QuotaRecord{}, werr.Newf(werr.NonCanonical, "quota budgets are not in canonical principal order")
		}
	}
	for i := range beforeUsage {
		if beforeUsage[i] != record.Usage[i] {
			return QuotaRecord{}, werr.Newf(werr.NonCanonical, "quota usage is not in canonical principal order")
		}
	}
	return record, nil
}

// ParseQuotaBudget parses one `--quota` directive.
func ParseQuotaBudget(text string) (QuotaBudget, error) {
	parts := splitColon(text)
	number := func(value, what string) (uint64, error) {
		parsed, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return 0, werr.Newf(werr.InvalidArgument, "--quota %s must be a non-negative integer (got `%s`)", what, value)
		}
		return parsed, nil
	}
	if len(parts) == 4 && parts[0] == "tenant" {
		bytes, err := number(parts[2], "bytes")
		if err != nil {
			return QuotaBudget{}, err
		}
		objects, err := number(parts[3], "objects")
		if err != nil {
			return QuotaBudget{}, err
		}
		return QuotaBudget{Principal: TenantPrincipal(parts[1]), MaxNewBytes: bytes, MaxObjects: objects}, nil
	}
	if len(parts) == 4 {
		uid, err := number(parts[0], "uid")
		if err != nil {
			return QuotaBudget{}, err
		}
		gid, err := number(parts[1], "gid")
		if err != nil {
			return QuotaBudget{}, err
		}
		bytes, err := number(parts[2], "bytes")
		if err != nil {
			return QuotaBudget{}, err
		}
		objects, err := number(parts[3], "objects")
		if err != nil {
			return QuotaBudget{}, err
		}
		return QuotaBudget{Principal: PosixPrincipal(uid, gid), MaxNewBytes: bytes, MaxObjects: objects}, nil
	}
	return QuotaBudget{}, werr.Newf(werr.InvalidArgument,
		"--quota expects `uid:GID:BYTES:OBJECTS` or `tenant:NAME:BYTES:OBJECTS` (got `%s`)", text)
}

// ParseQuotaFile parses one directive per line, ignoring blanks and `#`.
func ParseQuotaFile(contents string) ([]QuotaBudget, error) {
	var out []QuotaBudget
	line := 0
	for _, raw := range splitLines(contents) {
		line++
		trimmed := trimSpace(raw)
		if trimmed == "" || trimmed[0] == '#' {
			continue
		}
		budget, err := ParseQuotaBudget(trimmed)
		if err != nil {
			return nil, werr.Newf(werr.InvalidArgument, "quota file line %d: %s", line, err.Error())
		}
		out = append(out, budget)
	}
	return out, nil
}

func quotaPath(root string) string         { return filepath.Join(root, "quota") }
func quotaMigratedPath(root string) string { return filepath.Join(root, "quota.migrated") }

func readStoreRecord(path string) ([]byte, bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, werr.Wrap(werr.Io, err, "cannot read %s", path)
	}
	return b, true, nil
}

// loadQuotaRecord loads the policy-only file and the committed usage. A legacy
// combined record is imported once on a writable open.
func (s *Store) loadQuotaRecord() {
	if err := s.loadQuotaRecordInner(); err != nil {
		s.quota.RecordPresent = true
		s.quota.Valid = false
		s.quota.Reason = fmt.Sprintf("quota state is unusable: %v", err)
	}
}

func (s *Store) loadQuotaRecordInner() error {
	current, currentPresent, err := readStoreRecord(quotaPath(s.root))
	if err != nil {
		return err
	}
	migrated, migratedPresent, err := readStoreRecord(quotaMigratedPath(s.root))
	if err != nil {
		return err
	}
	s.quota.MigratedPresent = migratedPresent

	state := newQuotaState()
	var legacy *QuotaRecord
	var legacyRaw []byte
	currentIsLegacy := false

	if currentPresent {
		state.RecordPresent = true
		switch {
		case bytes.HasPrefix(current, quotaPolicyMagic):
			record, err := DecodeQuotaPolicy(current)
			if err != nil {
				return err
			}
			for _, budget := range record.Budgets {
				state.Policy[budget.Principal.SortKey()] = budget
			}
		case bytes.HasPrefix(current, quotaMagic):
			record, err := DecodeQuotaRecord(current)
			if err != nil {
				return err
			}
			for _, budget := range record.Budgets {
				state.Policy[budget.Principal.SortKey()] = budget
			}
			legacy = &record
			legacyRaw = current
			currentIsLegacy = true
		default:
			return werr.Newf(werr.Corrupt, "quota record has an unknown magic")
		}
	} else if migratedPresent {
		state.RecordPresent = true
		if !bytes.HasPrefix(migrated, quotaMagic) {
			return werr.Newf(werr.Corrupt, "quota.migrated has an unknown magic")
		}
		record, err := DecodeQuotaRecord(migrated)
		if err != nil {
			return err
		}
		for _, budget := range record.Budgets {
			state.Policy[budget.Principal.SortKey()] = budget
		}
	}

	if currentIsLegacy && migratedPresent && !bytes.Equal(legacyRaw, migrated) {
		return werr.Newf(werr.Corrupt, "both quota and quota.migrated exist and disagree")
	}

	s.quota = state

	usage, committed, err := s.committedUsageFromHead()
	if err != nil {
		s.quota.Valid = false
		s.quota.Reason = fmt.Sprintf("committed quota usage is inconsistent: %v", err)
		return nil
	}
	if committed {
		s.quota.Usage = usage
		s.quota.UsageCommitted = true
	} else if s.quota.enforced() {
		derived, blobs, _, err := s.replayQuotaUsageWithCount()
		if err != nil {
			s.quota.Valid = false
			s.quota.Reason = fmt.Sprintf("committed quota usage is inconsistent: %v", err)
			return nil
		}
		s.quota.Usage = derived
		s.blobIndex = blobs
		s.blobIndexReady = true
		s.quota.UsageCommitted = false
	}
	s.quota.Generation = s.generation
	s.quota.Commit = s.head

	if migratedPresent {
		record, err := DecodeQuotaRecord(migrated)
		if err != nil {
			return err
		}
		if record.Generation == s.generation && record.Commit == s.head &&
			(s.quota.UsageCommitted || s.quota.enforced()) {
			recorded := map[string]QuotaCounters{}
			for _, entry := range record.Usage {
				recorded[entry.Principal.SortKey()] = entry.Counters
			}
			if !quotaUsageEqual(recorded, s.quota.Usage) {
				s.quota.Valid = false
				s.quota.Reason = "quota.migrated usage disagrees with committed usage"
				return nil
			}
		}
	}

	if legacy != nil && currentIsLegacy && s.mode == ReadWrite {
		if err := s.migrateLegacyQuota(*legacy, legacyRaw); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) migrateLegacyQuota(record QuotaRecord, raw []byte) error {
	if record.Generation == s.generation && record.Commit == s.head {
		recorded := map[string]QuotaCounters{}
		for _, entry := range record.Usage {
			recorded[entry.Principal.SortKey()] = entry.Counters
		}
		if !quotaUsageEqual(recorded, s.quota.Usage) {
			return werr.Newf(werr.Corrupt, "legacy quota record usage disagrees with committed state")
		}
	} else {
		s.notes = append(s.notes, fmt.Sprintf(
			"legacy quota record named generation %d (%s); usage was recomputed from committed state",
			record.Generation, record.Commit.Hex()))
	}
	if err := writeReplace(quotaMigratedPath(s.root), raw); err != nil {
		return err
	}
	policy, err := NewQuotaPolicyRecord(record.Budgets)
	if err != nil {
		return err
	}
	policyBytes, err := policy.EncodeBytes()
	if err != nil {
		return err
	}
	if err := writeReplace(quotaPath(s.root), policyBytes); err != nil {
		return err
	}
	s.quota.MigratedPresent = true
	s.quota.RecordPresent = true
	if len(s.quota.Usage) != 0 && !s.quota.UsageCommitted {
		op := quotaUsageOpFromMap(s.quota.Usage)
		if _, err := s.publishQuotaUsageOp(op); err != nil {
			return err
		}
		s.quota.UsageCommitted = true
	}
	s.quota.Generation = s.generation
	s.quota.Commit = s.head
	s.quota.Valid = true
	s.quota.Reason = ""
	return nil
}

func quotaUsageEqual(a, b map[string]QuotaCounters) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}

func (s *Store) persistQuotaPolicy() error {
	budgets := make([]QuotaBudget, 0, len(s.quota.Policy))
	for _, budget := range s.quota.Policy {
		budgets = append(budgets, budget)
	}
	record, err := NewQuotaPolicyRecord(budgets)
	if err != nil {
		return err
	}
	b, err := record.EncodeBytes()
	if err != nil {
		return err
	}
	return writeReplace(quotaPath(s.root), b)
}

func (s *Store) headUsageOp() (model.SetQuotaUsageOp, bool, error) {
	if s.generation == 0 {
		return model.SetQuotaUsageOp{}, false, nil
	}
	generation := s.generation
	loaded, err := LoadCommitFile(CommitPath(s.root, generation), &generation)
	if err != nil {
		return model.SetQuotaUsageOp{}, false, err
	}
	for i := len(loaded.Commit.Ops) - 1; i >= 0; i-- {
		if op, ok := loaded.Commit.Ops[i].(model.SetQuotaUsageOp); ok {
			return op, true, nil
		}
	}
	return model.SetQuotaUsageOp{}, false, nil
}

func (s *Store) committedUsageFromHead() (map[string]QuotaCounters, bool, error) {
	op, ok, err := s.headUsageOp()
	if err != nil || !ok {
		return nil, false, err
	}
	usage := map[string]QuotaCounters{}
	if op.Reset {
		return usage, true, nil
	}
	for _, entry := range op.Usage {
		principal := QuotaPrincipal{Kind: entry.Kind, UID: entry.UID, GID: entry.GID, Tenant: entry.Tenant}
		usage[principal.SortKey()] = QuotaCounters{UsedBytes: entry.UsedBytes, UsedObjects: entry.UsedObjects}
	}
	return usage, true, nil
}

func quotaUsageOpFromMap(usage map[string]QuotaCounters) model.SetQuotaUsageOp {
	entries := make([]model.QuotaUsageEntry, 0, len(usage))
	for key, counters := range usage {
		principal := principalForKey(key)
		entries = append(entries, model.QuotaUsageEntry{
			Kind: principal.Kind, UID: principal.UID, GID: principal.GID, Tenant: principal.Tenant,
			UsedBytes: counters.UsedBytes, UsedObjects: counters.UsedObjects,
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		left := QuotaPrincipal{Kind: entries[i].Kind, UID: entries[i].UID, GID: entries[i].GID, Tenant: entries[i].Tenant}
		right := QuotaPrincipal{Kind: entries[j].Kind, UID: entries[j].UID, GID: entries[j].GID, Tenant: entries[j].Tenant}
		return left.SortKey() < right.SortKey()
	})
	return model.SetQuotaUsageOp{Usage: entries}
}

func principalForKey(key string) QuotaPrincipal {
	if len(key) > 2 && key[0] == 't' && key[1] == ':' {
		return TenantPrincipal(key[2:])
	}
	var uid, gid uint64
	fmt.Sscanf(key, "p:%d:%d", &uid, &gid)
	return PosixPrincipal(uid, gid)
}

// QuotaPolicy returns the configured budgets in canonical order.
func (s *Store) QuotaPolicy() []QuotaBudget {
	out := make([]QuotaBudget, 0, len(s.quota.Policy))
	for _, budget := range s.quota.Policy {
		out = append(out, budget)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Principal.SortKey() < out[j].Principal.SortKey() })
	return out
}

// QuotaEnforced reports whether at least one budget is configured.
func (s *Store) QuotaEnforced() bool { return s.quota.enforced() }

// QuotaUsage returns one principal's counters (never another principal's).
func (s *Store) QuotaUsage(principal QuotaPrincipal) QuotaCounters {
	return s.quota.Usage[principal.SortKey()]
}

// QuotaBudget returns one principal's budget, if configured.
func (s *Store) QuotaBudget(principal QuotaPrincipal) (QuotaBudget, bool) {
	budget, ok := s.quota.Policy[principal.SortKey()]
	return budget, ok
}

// QuotaProblem returns why the record is unusable, if it is.
func (s *Store) QuotaProblem() string { return s.quota.Reason }

// InstallQuotaPolicy installs or replaces the budget policy (admin operation).
// The policy file is written only here, never per commit. Usage is committed
// state; when the head does not carry it, it is recomputed and published as
// one corrective op.
func (s *Store) InstallQuotaPolicy(budgets []QuotaBudget) error {
	if err := s.requireWritable(); err != nil {
		return err
	}
	normalized, err := NormalizeQuotaPolicy(budgets)
	if err != nil {
		return err
	}
	s.quota.Policy = make(map[string]QuotaBudget, len(normalized))
	for _, budget := range normalized {
		s.quota.Policy[budget.Principal.SortKey()] = budget
	}
	if !s.quota.Valid || !s.quota.UsageCommitted {
		usage, blobs, err := s.replayQuotaUsage()
		if err != nil {
			return err
		}
		s.quota.Usage = usage
		s.blobIndex = blobs
		s.blobIndexReady = true
		s.quota.Valid = true
		s.quota.Reason = ""
	}
	if err := s.persistQuotaPolicy(); err != nil {
		return err
	}
	s.quota.RecordPresent = true
	if !s.quota.UsageCommitted && len(s.quota.Usage) != 0 {
		if _, err := s.publishQuotaUsageOp(quotaUsageOpFromMap(s.quota.Usage)); err != nil {
			return err
		}
		s.quota.UsageCommitted = true
	}
	s.quota.Generation = s.generation
	s.quota.Commit = s.head
	return nil
}

// QuotaReset zeroes every usage counter (explicit admin operation). It
// publishes exactly one `set_quota_usage` reset op.
func (s *Store) QuotaReset() error {
	if err := s.requireWritable(); err != nil {
		return err
	}
	if _, err := s.publishQuotaUsageOp(model.SetQuotaUsageOp{Reset: true}); err != nil {
		return err
	}
	s.quota.Usage = make(map[string]QuotaCounters)
	s.quota.UsageCommitted = true
	s.quota.Generation = s.generation
	s.quota.Commit = s.head
	s.quota.Valid = true
	s.quota.Reason = ""
	return nil
}

// QuotaRebuild recomputes and validates usage from the published commit chain,
// then publishes a corrective usage op.
func (s *Store) QuotaRebuild() (uint64, error) {
	if err := s.requireWritable(); err != nil {
		return 0, err
	}
	if len(s.quota.Policy) == 0 && s.quota.RecordPresent {
		return 0, werr.Newf(werr.Corrupt,
			"quota record is unusable and no policy is known; re-run with `--quota` to install one")
	}
	usage, blobs, commits, err := s.replayQuotaUsageWithCount()
	if err != nil {
		return 0, err
	}
	if _, err := s.publishQuotaUsageOp(quotaUsageOpFromMap(usage)); err != nil {
		return 0, err
	}
	s.quota.Usage = usage
	s.blobIndex = blobs
	s.blobIndexReady = true
	s.quota.UsageCommitted = true
	s.quota.Generation = s.generation
	s.quota.Commit = s.head
	s.quota.Valid = true
	s.quota.Reason = ""
	return commits, nil
}

// PublishQuotaUsageForTest publishes an arbitrary usage assertion without
// enforcing admission. Used by the court that proves replay rejects an
// inconsistent assertion.
func (s *Store) PublishQuotaUsageForTest(op model.SetQuotaUsageOp) (model.Hash32, error) {
	return s.publishQuotaUsageOp(op)
}

// publishQuotaUsageOp publishes exactly one commit containing one
// `set_quota_usage` op.
func (s *Store) publishQuotaUsageOp(op model.SetQuotaUsageOp) (model.Hash32, error) {
	if err := s.requireWritable(); err != nil {
		return model.Hash32{}, err
	}
	if s.groupDepth != 0 {
		return model.Hash32{}, werr.Newf(werr.InvalidArgument,
			"a quota admin operation cannot run inside a group commit")
	}
	ops := []model.Op{op}
	newGeneration := s.nextGeneration
	timestamp := s.nowNS()
	nextState := s.state.Clone()
	if err := nextState.ApplyOps(ops); err != nil {
		return model.Hash32{}, err
	}
	nextState.Generation = newGeneration
	interval := s.options.CheckpointInterval
	wantsCheckpoint := interval > 0 && newGeneration%interval == 0
	var checkpoint *model.Hash32
	if wantsCheckpoint {
		encoded, err := model.EncodeState(nextState, newGeneration)
		if err != nil {
			return model.Hash32{}, err
		}
		id, err := s.storeBlob(BlobManifest, model.DomainManifest, encoded)
		if err != nil {
			return model.Hash32{}, err
		}
		checkpoint = &id
	}
	commit := model.Commit{
		Generation: newGeneration, Parent: hashPtr(s.head), TimestampNS: timestamp,
		Ops: ops, Checkpoint: checkpoint,
	}
	hash, err := s.publishCommit(commit)
	if err != nil {
		return model.Hash32{}, err
	}
	s.state = nextState
	s.head = hash
	s.generation = newGeneration
	if newGeneration == ^uint64(0) {
		return model.Hash32{}, werr.Newf(werr.LimitExceeded, "generation counter overflow")
	}
	s.nextGeneration = newGeneration + 1
	return hash, nil
}

func (s *Store) replayQuotaUsage() (map[string]QuotaCounters, map[model.Hash32]uint64, error) {
	usage, blobs, _, err := s.replayQuotaUsageWithCount()
	return usage, blobs, err
}

func (s *Store) replayQuotaUsageWithCount() (map[string]QuotaCounters, map[model.Hash32]uint64, uint64, error) {
	index, err := CommitIndex(s.root, ^uint64(0))
	if err != nil {
		return nil, nil, 0, err
	}
	var chain []model.Commit
	cursor := s.head
	seen := map[model.Hash32]bool{}
	for {
		if seen[cursor] {
			return nil, nil, 0, werr.Newf(werr.Corrupt, "commit chain contains a cycle")
		}
		seen[cursor] = true
		loaded, ok := index[cursor]
		if !ok {
			return nil, nil, 0, werr.Newf(werr.Corrupt, "commit %s is missing from the published chain", cursor.Hex())
		}
		chain = append(chain, loaded.Commit)
		if loaded.Commit.Parent == nil {
			break
		}
		cursor = *loaded.Commit.Parent
	}
	usage := map[string]QuotaCounters{}
	blobs := map[model.Hash32]uint64{}
	state := model.NewState()
	var commits uint64
	for i := len(chain) - 1; i >= 0; i-- {
		commit := chain[i]
		pre := quotaPreMap(state, commit.Ops)
		charges, additions, err := s.computeQuotaCharges(commit.Ops, pre, blobs)
		if err != nil {
			return nil, nil, 0, err
		}
		for key, counters := range charges {
			current := usage[key]
			if err := current.add(counters); err != nil {
				return nil, nil, 0, err
			}
			usage[key] = current
		}
		// A committed assertion must equal the totals derived from the object
		// ops of this commit and every earlier commit.
		for _, op := range commit.Ops {
			declared, ok := op.(model.SetQuotaUsageOp)
			if !ok {
				continue
			}
			if declared.Reset {
				if len(commit.Ops) != 1 || len(declared.Usage) != 0 {
					return nil, nil, 0, werr.Newf(werr.Corrupt,
						"quota usage reset must be the only op and declare an empty map")
				}
				usage = map[string]QuotaCounters{}
			} else {
				declaredMap := map[string]QuotaCounters{}
				for _, entry := range declared.Usage {
					principal := QuotaPrincipal{Kind: entry.Kind, UID: entry.UID, GID: entry.GID, Tenant: entry.Tenant}
					declaredMap[principal.SortKey()] = QuotaCounters{UsedBytes: entry.UsedBytes, UsedObjects: entry.UsedObjects}
				}
				if !quotaUsageEqual(declaredMap, usage) {
					return nil, nil, 0, werr.Newf(werr.Corrupt,
						"commit %d quota usage disagrees with the recomputed admission totals", commit.Generation)
				}
			}
			break
		}
		for blob, size := range additions {
			blobs[blob] = size
		}
		if err := state.ApplyOps(commit.Ops); err != nil {
			return nil, nil, 0, err
		}
		commits++
	}
	return usage, blobs, commits, nil
}

func (s *Store) ensureBlobIndex() error {
	if s.blobIndexReady {
		return nil
	}
	index := map[model.Hash32]uint64{}
	seen := map[model.Hash32]bool{}
	for _, record := range s.state.Objects {
		if record.Kind != model.KindFile {
			continue
		}
		additions := map[model.Hash32]uint64{}
		if _, err := s.collectManifestBlobs(record.Content, index, additions, seen, 0); err != nil {
			return err
		}
		for blob, size := range additions {
			index[blob] = size
		}
	}
	s.blobIndex = index
	s.blobIndexReady = true
	return nil
}

func (s *Store) collectManifestBlobs(
	manifestID model.Hash32,
	index map[model.Hash32]uint64,
	additions map[model.Hash32]uint64,
	seen map[model.Hash32]bool,
	depth int,
) (uint64, error) {
	if depth > int(model.MaxOverlayChainDepth) {
		return 0, werr.Newf(werr.Corrupt, "manifest tree exceeds the manifest-chain depth bound")
	}
	if seen[manifestID] {
		return 0, nil
	}
	seen[manifestID] = true
	if _, ok := index[manifestID]; ok {
		return 0, nil
	}
	if _, ok := additions[manifestID]; ok {
		return 0, nil
	}
	b, err := ReadBlobVerified(s.root, BlobManifest, manifestID, model.DomainManifest)
	if err != nil {
		return 0, err
	}
	size := uint64(len(b))
	additions[manifestID] = size
	total := size
	value, err := model.DecodeWCB(b)
	if err != nil {
		return 0, err
	}
	manifest, err := model.ManifestFromWCB(value)
	if err != nil {
		return 0, err
	}
	if rep := manifest.Representation; rep != nil && (rep.Kind == model.RepresentationCodec || rep.Kind == model.RepresentationTensor) {
		if depth > MaxCodecDependencyDepth {
			return 0, werr.Newf(werr.Corrupt, "manifest tree exceeds the codec dependency depth bound")
		}
		if rep.Frame != nil {
			if _, ok := index[*rep.Frame]; !ok {
				if _, ok := additions[*rep.Frame]; !ok {
					info, err := os.Stat(BlobPath(s.root, BlobManifest, *rep.Frame))
					if err != nil {
						return 0, werr.Wrap(werr.Corrupt, err, "missing frame blob")
					}
					length := uint64(info.Size())
					additions[*rep.Frame] = length
					total += length
				}
			}
		}
		for _, dependency := range rep.Dependencies {
			added, err := s.collectManifestBlobs(dependency, index, additions, seen, depth+1)
			if err != nil {
				return 0, err
			}
			total += added
		}
		return total, nil
	}
	if rep := manifest.Representation; rep != nil && rep.Kind == model.RepresentationOverlay {
		if rep.Overlay == nil {
			return 0, werr.Newf(werr.Corrupt, "overlay representation is missing its overlay map")
		}
		for _, extent := range rep.Overlay.Extents {
			for _, chunk := range extent.Chunks {
				if _, ok := index[chunk.Hash]; ok {
					continue
				}
				if _, ok := additions[chunk.Hash]; ok {
					continue
				}
				additions[chunk.Hash] = chunk.Len
				total += chunk.Len
			}
		}
		added, err := s.collectManifestBlobs(rep.Overlay.Base, index, additions, seen, depth+1)
		if err != nil {
			return 0, err
		}
		return total + added, nil
	}
	for _, chunk := range manifest.Chunks {
		if _, ok := index[chunk.Hash]; ok {
			continue
		}
		if _, ok := additions[chunk.Hash]; ok {
			continue
		}
		additions[chunk.Hash] = chunk.Len
		total += chunk.Len
	}
	return total, nil
}

func quotaPreMap(state *model.State, ops []model.Op) map[model.Hash32]*model.ObjectRecord {
	pre := map[model.Hash32]*model.ObjectRecord{}
	for _, op := range ops {
		put, ok := op.(model.PutObjectOp)
		if !ok {
			continue
		}
		if _, exists := pre[put.Record.ID]; exists {
			continue
		}
		if existing, ok := state.Objects[put.Record.ID]; ok {
			copy := existing.Clone()
			pre[put.Record.ID] = &copy
		} else {
			pre[put.Record.ID] = nil
		}
	}
	return pre
}

func (s *Store) computeQuotaCharges(
	ops []model.Op,
	pre map[model.Hash32]*model.ObjectRecord,
	index map[model.Hash32]uint64,
) (map[string]QuotaCounters, map[model.Hash32]uint64, error) {
	charges := map[string]QuotaCounters{}
	additions := map[model.Hash32]uint64{}
	seen := map[model.Hash32]bool{}
	for _, op := range ops {
		put, ok := op.(model.PutObjectOp)
		if !ok {
			continue
		}
		record := put.Record
		if record.ID == model.RootID {
			continue
		}
		previous := pre[record.ID]
		if previous != nil && objectRecordsEqual(*previous, record) {
			continue
		}
		principals := []QuotaPrincipal{PosixPrincipal(record.UID, record.GID)}
		if value, ok := record.Attrs[model.AttrTenant]; ok && value.Kind == wcb.Text {
			if value.Str != "" {
				principals = append(principals, TenantPrincipal(value.Str))
			}
		}
		recordBytes, err := model.EncodeWCB(record.ToWCB())
		if err != nil {
			return nil, nil, err
		}
		var contentBytes uint64
		contentChanged := previous == nil || previous.Content != record.Content || previous.Kind != record.Kind
		if record.Kind == model.KindFile && contentChanged {
			contentBytes, err = s.collectManifestBlobs(record.Content, index, additions, seen, 0)
			if err != nil {
				return nil, nil, err
			}
		}
		total, carry := addU64(uint64(len(recordBytes)), contentBytes)
		if carry {
			return nil, nil, werr.Newf(werr.LimitExceeded, "quota charge overflow")
		}
		isNew := uint64(0)
		if previous == nil {
			isNew = 1
		}
		for _, principal := range principals {
			current := charges[principal.SortKey()]
			if err := current.add(QuotaCounters{UsedBytes: total, UsedObjects: isNew}); err != nil {
				return nil, nil, err
			}
			charges[principal.SortKey()] = current
		}
	}
	return charges, additions, nil
}

// quotaPlan is the accepted outcome for one commit. usageAfter is the
// cumulative admitted usage the commit's `set_quota_usage` op will carry.
type quotaPlan struct {
	additions  map[model.Hash32]uint64
	usageAfter map[string]QuotaCounters
}

// quotaPreflight enforces every budget before a commit is published and
// computes the usage snapshot the commit will carry. A nil plan means no
// policy is configured.
func (s *Store) quotaPreflight(ops []model.Op, pre map[model.Hash32]*model.ObjectRecord) (*quotaPlan, error) {
	if !s.quota.enforced() {
		if s.quota.RecordPresent && !s.quota.Valid {
			return nil, werr.Newf(werr.Corrupt,
				"quota state is unusable; re-run with `--quota` to install a policy")
		}
		return nil, nil
	}
	if !s.quota.Valid {
		return nil, werr.Newf(werr.Corrupt,
			"quota usage is inconsistent with committed state; run `quota rebuild`")
	}
	if err := s.ensureBlobIndex(); err != nil {
		return nil, err
	}
	charges, additions, err := s.computeQuotaCharges(ops, pre, s.blobIndex)
	if err != nil {
		return nil, err
	}
	usageAfter := make(map[string]QuotaCounters, len(s.quota.Usage))
	for key, counters := range s.quota.Usage {
		usageAfter[key] = counters
	}
	for key, delta := range charges {
		current := usageAfter[key]
		if err := current.add(delta); err != nil {
			return nil, err
		}
		usageAfter[key] = current
	}
	for key, budget := range s.quota.Policy {
		after := usageAfter[key]
		if after.UsedBytes > budget.MaxNewBytes || after.UsedObjects > budget.MaxObjects {
			// Fixed, non-disclosing text: no usage, no limits, no principal.
			return nil, werr.Newf(werr.BudgetExceeded, "write budget exceeded")
		}
	}
	return &quotaPlan{additions: additions, usageAfter: usageAfter}, nil
}

func (s *Store) recordQuotaAfterCommit(plan *quotaPlan) {
	s.quota.Usage = plan.usageAfter
	s.quota.UsageCommitted = true
	for blob, size := range plan.additions {
		s.blobIndex[blob] = size
	}
	s.quota.Generation = s.generation
	s.quota.Commit = s.head
}

// writeReplace atomically replaces a mutable record.
func writeReplace(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := makeDir(dir); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "tmp", "quota-"+fmt.Sprintf("%d-%d", os.Getpid(), tmpCounter.Add(1)))
	if err := os.MkdirAll(filepath.Dir(tmp), 0o755); err != nil {
		return werr.Wrap(werr.Io, err, "cannot create tmp directory")
	}
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return werr.Wrap(werr.Io, err, "cannot create %s", tmp)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		_ = os.Remove(tmp)
		return werr.Wrap(werr.Io, err, "cannot write %s", tmp)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		_ = os.Remove(tmp)
		return werr.Wrap(werr.Io, err, "cannot fsync %s", tmp)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmp)
		return werr.Wrap(werr.Io, err, "cannot close %s", tmp)
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		_ = os.Remove(tmp)
		return werr.Wrap(werr.Io, err, "cannot chmod %s", tmp)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return werr.Wrap(werr.Io, err, "cannot replace %s", path)
	}
	if err := fsyncDir(dir); err != nil {
		return err
	}
	return nil
}

func objectRecordsEqual(a, b model.ObjectRecord) bool {
	left, errA := model.EncodeWCB(a.ToWCB())
	right, errB := model.EncodeWCB(b.ToWCB())
	return errA == nil && errB == nil && bytes.Equal(left, right)
}

func splitColon(text string) []string {
	var out []string
	start := 0
	for i := 0; i < len(text); i++ {
		if text[i] == ':' {
			out = append(out, text[start:i])
			start = i + 1
		}
	}
	return append(out, text[start:])
}

func splitLines(text string) []string {
	var out []string
	start := 0
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' {
			out = append(out, text[start:i])
			start = i + 1
		}
	}
	if start < len(text) {
		out = append(out, text[start:])
	}
	return out
}

func trimSpace(text string) string {
	start := 0
	end := len(text)
	for start < end && (text[start] == ' ' || text[start] == '\t' || text[start] == '\r') {
		start++
	}
	for end > start && (text[end-1] == ' ' || text[end-1] == '\t' || text[end-1] == '\r') {
		end--
	}
	return text[start:end]
}
