package model

import (
	"fmt"
	"sort"

	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// QuotaUsageEntry is one principal's cumulative admitted usage in a committed
// `set_quota_usage` assertion.
type QuotaUsageEntry struct {
	Kind        string
	UID         uint64
	GID         uint64
	Tenant      string
	UsedBytes   uint64
	UsedObjects uint64
}

func (e QuotaUsageEntry) sortKey() string {
	if e.Kind == "tenant" {
		return "t:" + e.Tenant
	}
	return fmt.Sprintf("p:%020d:%020d", e.UID, e.GID)
}

func (e QuotaUsageEntry) validate() error {
	switch e.Kind {
	case "posix":
		return nil
	case "tenant":
		if len(e.Tenant) == 0 || len(e.Tenant) > 256 {
			return werr.Newf(werr.InvalidArgument, "tenant label must be 1..=256 bytes")
		}
		return nil
	default:
		return werr.Newf(werr.Malformed, "unknown quota principal kind `%s`", e.Kind)
	}
}

// SetQuotaUsageOp records the cumulative admitted usage after the other ops in
// the same commit. It changes no namespace state. It must be the last op, and a
// reset must be the only op.
type SetQuotaUsageOp struct {
	Reset bool
	Usage []QuotaUsageEntry
}

// Name is the canonical `op` discriminator.
func (SetQuotaUsageOp) Name() string { return "set_quota_usage" }

// ToWCB encodes the op map canonically. The usage array is sorted by principal
// key with no duplicates, exactly like the Rust reference.
func (o SetQuotaUsageOp) ToWCB() wcb.Value {
	entries := append([]QuotaUsageEntry(nil), o.Usage...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].sortKey() < entries[j].sortKey() })
	values := make([]wcb.Value, 0, len(entries))
	for _, entry := range entries {
		values = append(values, entry.toWCB())
	}
	return Map(map[string]wcb.Value{
		"op":    wcb.TextValue(o.Name()),
		"reset": wcb.BoolValue(o.Reset),
		"usage": wcb.ArrayValue(values),
	})
}

func (e QuotaUsageEntry) toWCB() wcb.Value {
	if e.Kind == "tenant" {
		return Map(map[string]wcb.Value{
			"kind":         wcb.TextValue("tenant"),
			"tenant":       wcb.TextValue(e.Tenant),
			"used_bytes":   wcb.U64Value(e.UsedBytes),
			"used_objects": wcb.U64Value(e.UsedObjects),
		})
	}
	return Map(map[string]wcb.Value{
		"kind":         wcb.TextValue("posix"),
		"uid":          wcb.U64Value(e.UID),
		"gid":          wcb.U64Value(e.GID),
		"used_bytes":   wcb.U64Value(e.UsedBytes),
		"used_objects": wcb.U64Value(e.UsedObjects),
	})
}

// apply is a no-op for namespace state; replay validation lives in the store's
// quota replay, which recomputes the admission totals.
func (o SetQuotaUsageOp) apply(s *State) error { return nil }

func setQuotaUsageFromMap(m map[string]wcb.Value) (Op, error) {
	if err := CheckKeys(m, "reset", "usage"); err != nil {
		return nil, err
	}
	resetValue, ok := m["reset"]
	if !ok || resetValue.Kind != wcb.Bool {
		return nil, werr.Newf(werr.Malformed, "quota usage reset must be a bool")
	}
	values, err := GetArray(m, "usage")
	if err != nil {
		return nil, err
	}
	usage := make([]QuotaUsageEntry, 0, len(values))
	for _, value := range values {
		entry, err := AsMap(value)
		if err != nil {
			return nil, err
		}
		parsed, err := quotaUsageEntryFromMap(entry)
		if err != nil {
			return nil, err
		}
		usage = append(usage, parsed)
	}
	if resetValue.Bool && len(usage) != 0 {
		return nil, werr.Newf(werr.Malformed, "a quota usage reset must declare an empty usage map")
	}
	for _, entry := range usage {
		if err := entry.validate(); err != nil {
			return nil, err
		}
	}
	// Canonical order is rejected, not silently repaired.
	if !sortedQuotaUsage(usage) {
		return nil, werr.Newf(werr.NonCanonical, "quota usage is not in canonical principal order")
	}
	return SetQuotaUsageOp{Reset: resetValue.Bool, Usage: usage}, nil
}

func quotaUsageEntryFromMap(m map[string]wcb.Value) (QuotaUsageEntry, error) {
	if err := CheckKeys(m, "kind", "uid", "gid", "tenant", "used_bytes", "used_objects"); err != nil {
		return QuotaUsageEntry{}, err
	}
	kind, err := GetText(m, "kind")
	if err != nil {
		return QuotaUsageEntry{}, err
	}
	entry := QuotaUsageEntry{Kind: kind}
	switch kind {
	case "posix":
		entry.UID, err = GetU64(m, "uid")
		if err != nil {
			return QuotaUsageEntry{}, err
		}
		entry.GID, err = GetU64(m, "gid")
		if err != nil {
			return QuotaUsageEntry{}, err
		}
	case "tenant":
		entry.Tenant, err = GetText(m, "tenant")
		if err != nil {
			return QuotaUsageEntry{}, err
		}
	default:
		return QuotaUsageEntry{}, werr.Newf(werr.Malformed, "unknown quota principal kind `%s`", kind)
	}
	entry.UsedBytes, err = GetU64(m, "used_bytes")
	if err != nil {
		return QuotaUsageEntry{}, err
	}
	entry.UsedObjects, err = GetU64(m, "used_objects")
	if err != nil {
		return QuotaUsageEntry{}, err
	}
	return entry, nil
}

func sortedQuotaUsage(usage []QuotaUsageEntry) bool {
	for i := 1; i < len(usage); i++ {
		if usage[i-1].sortKey() >= usage[i].sortKey() {
			return false
		}
	}
	return true
}
