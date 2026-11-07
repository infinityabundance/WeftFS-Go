// Package resolver evaluates WeftQL selectors against a pinned WeftFS state
// (WEFT-SELECTORS.md §3). Evaluation order is normative:
//
//  1. compute the authorized universe first;
//  2. evaluate predicates (absent/mistyped comparisons are false; attr_ne is
//     defined only when both sides exist; not complements inside the
//     authorized universe);
//  3. order by the order list with an unconditional object_id ascending
//     tie-break;
//  4. apply offset, then limit.
//
// SelectorId is always the query hash; SnapshotID is the pinned commit hash.
// Neither is derived from the result set.
package resolver

import (
	"bytes"
	"sort"
	"strings"

	weftcontext "github.com/infinityabundance/WeftCodec-Go/context"
	"github.com/infinityabundance/WeftCodec-Go/limits"
	"github.com/infinityabundance/WeftCodec-Go/selector"
	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/auth"
	weftindex "github.com/infinityabundance/WeftFS-Go/index"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// ResolvedRef is a pinned reference returned by resolution.
type ResolvedRef struct {
	Namespace string
	Snapshot  model.Hash32
	ObjectID  model.Hash32
	VersionID model.Hash32
	ContentID model.Hash32
}

// EvidenceEntry is one piece of positive evidence for a match.
type EvidenceEntry struct {
	// Kind is "attr", "relation", or "tag".
	Kind  string
	Field string
	Value wcb.Value
	Has   bool
}

// Evidence is attached to one matched object.
type Evidence struct {
	ObjectID model.Hash32
	Entries  []EvidenceEntry
}

// Resolution is the full result.
type Resolution struct {
	SelectorID   model.Hash32
	SnapshotID   model.Hash32
	Results      []ResolvedRef
	MatchedCount uint64
	Evidence     []Evidence
}

// ResolveState evaluates a selector against an explicit replayed state.
func ResolveState(sel *selector.Selector, snapshotID model.Hash32, state *model.State, principal auth.Principal, lim limits.Limits) (*Resolution, error) {
	return ResolveStateWithBudget(sel, snapshotID, state, principal, lim, nil, nil, nil)
}

// WorkUnits returns the deterministic v1 work unit count: objects inspected
// plus relation edges traversed.
func WorkUnits(sel *selector.Selector, state *model.State) uint64 {
	work := uint64(len(state.Objects))
	if selectorHasRelations(sel.Predicate) {
		work += uint64(len(state.Relations))
	}
	return work
}

func selectorHasRelations(expr *selector.Expr) bool {
	switch expr.Kind {
	case selector.ExprTag, selector.ExprRelation:
		return true
	case selector.ExprAnd, selector.ExprOr:
		for _, item := range expr.Items {
			if selectorHasRelations(item) {
				return true
			}
		}
	case selector.ExprNot:
		return selectorHasRelations(expr.Inner)
	}
	return false
}

func selectorPredicatesAllowed(expr *selector.Expr, capability *auth.Capability) bool {
	switch expr.Kind {
	case selector.ExprTag:
		return capability.AllowsPredicate("tagged_as")
	case selector.ExprRelation:
		return capability.AllowsPredicate(expr.Name)
	case selector.ExprAnd, selector.ExprOr:
		for _, item := range expr.Items {
			if !selectorPredicatesAllowed(item, capability) {
				return false
			}
		}
	case selector.ExprNot:
		return selectorPredicatesAllowed(expr.Inner, capability)
	}
	return true
}

// ResolveStateWithBudget evaluates a selector with optional capability and
// budget enforcement. Authorization is applied before counting; an overrun is
// LimitExceeded, never a silently truncated success.
func ResolveStateWithBudget(sel *selector.Selector, snapshotID model.Hash32, state *model.State, principal auth.Principal, lim limits.Limits, capability *auth.Capability, contextRootID *model.Hash32, budget *weftcontext.Budget) (*Resolution, error) {
	return resolveStateInner(sel, snapshotID, state, principal, lim, capability, contextRootID, budget, nil)
}

// ResolveStateIndexed evaluates a selector with candidate narrowing from a
// caller-provided (cached or persisted) index. The index must describe `state`;
// an index that does not is refused with Corrupt rather than used, because it
// could under-select. Every candidate is still confirmed by the authoritative
// evaluator, so the index can never decide a match.
func ResolveStateIndexed(sel *selector.Selector, snapshotID model.Hash32, state *model.State, principal auth.Principal, lim limits.Limits, idx *weftindex.StateIndex) (*Resolution, error) {
	if idx == nil {
		return ResolveStateWithBudget(sel, snapshotID, state, principal, lim, nil, nil, nil)
	}
	return resolveStateInner(sel, snapshotID, state, principal, lim, nil, nil, nil, idx)
}

func resolveStateInner(sel *selector.Selector, snapshotID model.Hash32, state *model.State, principal auth.Principal, lim limits.Limits, capability *auth.Capability, contextRootID *model.Hash32, budget *weftcontext.Budget, idx *weftindex.StateIndex) (*Resolution, error) {
	if sel.Namespace != model.DefaultNamespace {
		return nil, werr.Newf(werr.NamespaceMismatch, "selector namespace `%s` is not `%s`", sel.Namespace, model.DefaultNamespace)
	}
	if capability != nil {
		namespaceAllowed := capability.AllowsNamespace(sel.Namespace)
		if !namespaceAllowed && contextRootID != nil && capability.AllowsRoot(*contextRootID) {
			namespaceAllowed = true
		}
		if !namespaceAllowed {
			return nil, werr.Newf(werr.Unauthorized, "capability does not grant this selection")
		}
		if len(capability.Scope.Roots) != 0 && contextRootID != nil && !capability.AllowsRoot(*contextRootID) {
			return nil, werr.Newf(werr.Unauthorized, "capability does not grant this context root")
		}
		if !selectorPredicatesAllowed(sel.Predicate, capability) {
			return nil, werr.Newf(werr.Unauthorized, "capability does not grant every relation predicate in the selector")
		}
	}
	if budget != nil {
		if budget.MaxWork != nil {
			work := WorkUnits(sel, state)
			if work > *budget.MaxWork {
				return nil, werr.LimitExceededf("resolver work %d exceeds max_work %d", work, *budget.MaxWork)
			}
		}
		if budget.MaxDepth != nil {
			depth := uint64(0)
			if selectorHasRelations(sel.Predicate) {
				depth = 1
			}
			if depth > *budget.MaxDepth {
				return nil, werr.LimitExceededf("traversal depth %d exceeds max_depth %d", depth, *budget.MaxDepth)
			}
		}
	}
	root, ok := state.Objects[model.RootID]
	if !ok {
		return nil, werr.Newf(werr.Corrupt, "namespace root is missing")
	}
	if !auth.CanRead(root, principal) {
		return nil, werr.Newf(werr.Unauthorized, "principal cannot read the namespace root")
	}
	selectorID, err := sel.SelectorID(lim)
	if err != nil {
		return nil, werr.FromCodec(err)
	}
	// Fail closed: an index that does not describe this state could
	// under-select candidates, which would be a silent correctness violation.
	if idx != nil && !idx.MatchesState(state) {
		return nil, werr.Newf(werr.Corrupt, "cached state index does not describe this state")
	}

	type match struct {
		record   model.ObjectRecord
		evidence []EvidenceEntry
	}
	matches := make([]match, 0)
	if idx == nil {
		for _, id := range model.SortHashKeys(state.Objects) {
			record := state.Objects[id]
			if !auth.CanRead(record, principal) {
				continue
			}
			if evidence, ok := evalExpr(sel.Predicate, record, state, principal); ok {
				matches = append(matches, match{record: record, evidence: evidence})
			}
		}
	} else {
		authorized := make(map[model.Hash32]struct{}, len(state.Objects))
		for id, record := range state.Objects {
			if auth.CanRead(record, principal) {
				authorized[id] = struct{}{}
			}
		}
		for id := range candidatesFor(sel.Predicate, idx, state, principal, authorized).ids {
			// Defense in depth: candidates are always intersected with the
			// authorized universe, but never rely on that for disclosure.
			if _, ok := authorized[id]; !ok {
				continue
			}
			record, ok := state.Objects[id]
			if !ok {
				continue
			}
			if evidence, ok := evalExpr(sel.Predicate, record, state, principal); ok {
				matches = append(matches, match{record: record, evidence: evidence})
			}
		}
	}
	matchedCount := uint64(len(matches))

	sort.Slice(matches, func(i, j int) bool {
		return compareRecords(matches[i].record, matches[j].record, sel.Order) < 0
	})

	offset := uint64(0)
	if sel.Offset != nil {
		offset = *sel.Offset
	}
	limit := ^uint64(0)
	if sel.Limit != nil {
		limit = *sel.Limit
	}
	total := uint64(len(matches))
	start := offset
	if start > total {
		start = total
	}
	end := start + limit
	if end < start || end > total {
		end = total
	}
	if budget != nil && budget.MaxResults != nil && end-start > *budget.MaxResults {
		return nil, werr.LimitExceededf("resolution would return %d results, budget is %d", end-start, *budget.MaxResults)
	}

	results := make([]ResolvedRef, 0, end-start)
	evidence := make([]Evidence, 0, end-start)
	for _, m := range matches[start:end] {
		results = append(results, ResolvedRef{
			Namespace: sel.Namespace,
			Snapshot:  snapshotID,
			ObjectID:  m.record.ID,
			VersionID: m.record.Version,
			ContentID: m.record.Content,
		})
		evidence = append(evidence, Evidence{ObjectID: m.record.ID, Entries: m.evidence})
	}

	return &Resolution{
		SelectorID:   selectorID,
		SnapshotID:   snapshotID,
		Results:      results,
		MatchedCount: matchedCount,
		Evidence:     evidence,
	}, nil
}

// RequireOne resolves exactly one object, rejecting zero (NotFound) and many
// (Ambiguous) using the full authorized count.
func RequireOne(sel *selector.Selector, snapshotID model.Hash32, state *model.State, principal auth.Principal, lim limits.Limits) (ResolvedRef, error) {
	resolution, err := ResolveState(sel, snapshotID, state, principal, lim)
	if err != nil {
		return ResolvedRef{}, err
	}
	switch resolution.MatchedCount {
	case 0:
		return ResolvedRef{}, werr.Newf(werr.NotFound, "selector matched no authorized objects")
	case 1:
		if len(resolution.Results) > 0 {
			return resolution.Results[0], nil
		}
		unpaged := *sel
		unpaged.Offset = nil
		unpaged.Limit = nil
		again, err := ResolveState(&unpaged, snapshotID, state, principal, lim)
		if err != nil {
			return ResolvedRef{}, err
		}
		if len(again.Results) == 0 {
			return ResolvedRef{}, werr.Newf(werr.NotFound, "selector matched no authorized objects")
		}
		return again.Results[0], nil
	default:
		// List every authorized id from the complete, unpaged evaluation. The
		// ambiguity class is only actionable if the caller sees the competing set.
		unpaged := *sel
		unpaged.Offset = nil
		unpaged.Limit = nil
		complete, err := ResolveState(&unpaged, snapshotID, state, principal, lim)
		if err != nil {
			return ResolvedRef{}, err
		}
		ids := make([]string, 0, len(complete.Results))
		for _, result := range complete.Results {
			ids = append(ids, result.ObjectID.Hex())
		}
		return ResolvedRef{}, werr.Newf(werr.Ambiguous,
			"selector matched %d authorized objects; require_one needs exactly 1 (object_ids: %s)",
			resolution.MatchedCount, strings.Join(ids, ","))
	}
}

func evalExpr(expr *selector.Expr, object model.ObjectRecord, state *model.State, principal auth.Principal) ([]EvidenceEntry, bool) {
	switch expr.Kind {
	case selector.ExprTrue:
		return []EvidenceEntry{}, true
	case selector.ExprFalse:
		return nil, false
	case selector.ExprHas:
		value, ok := resolveField(object, expr.Field)
		if !ok || value.Kind == wcb.Null {
			return nil, false
		}
		return []EvidenceEntry{{Kind: "attr", Field: expr.Field.String(), Value: value, Has: true}}, true
	case selector.ExprTag:
		var evidence []EvidenceEntry
		for _, relation := range state.Relations {
			if relation.Subject != object.ID || relation.Predicate != "tagged_as" {
				continue
			}
			if relation.Kind != model.RelationValue {
				continue
			}
			if relation.Target.Object != nil {
				continue
			}
			value := relation.Target.Value
			if value.Kind == wcb.Text && value.Str == expr.Name {
				evidence = append(evidence, EvidenceEntry{
					Kind: "tag", Field: "tagged_as", Value: value, Has: true,
				})
			}
		}
		if len(evidence) == 0 {
			return nil, false
		}
		return evidence, true
	case selector.ExprRelation:
		targetVisible := false
		if target, ok := state.Objects[expr.Target]; ok && auth.CanRead(target, principal) {
			targetVisible = true
		}
		if !targetVisible {
			return nil, false
		}
		for _, relation := range state.Relations {
			if relation.Subject != object.ID || relation.Predicate != expr.Name {
				continue
			}
			if relation.Kind != model.RelationObject || relation.Target.Object == nil {
				continue
			}
			if *relation.Target.Object == expr.Target {
				return []EvidenceEntry{{
					Kind: "relation", Field: expr.Name,
					Value: wcb.BytesValue(expr.Target.Bytes()), Has: true,
				}}, true
			}
		}
		return nil, false
	case selector.ExprCompare:
		left, ok := resolveField(object, expr.Field)
		if !ok {
			return nil, false
		}
		if !compare(left, expr.Op, literalValue(expr.Value)) {
			return nil, false
		}
		return []EvidenceEntry{{Kind: "attr", Field: expr.Field.String(), Value: left, Has: true}}, true
	case selector.ExprAnd:
		evidence := make([]EvidenceEntry, 0)
		for _, operand := range expr.Items {
			part, ok := evalExpr(operand, object, state, principal)
			if !ok {
				return nil, false
			}
			evidence = append(evidence, part...)
		}
		return evidence, true
	case selector.ExprOr:
		evidence := make([]EvidenceEntry, 0)
		any := false
		for _, operand := range expr.Items {
			if part, ok := evalExpr(operand, object, state, principal); ok {
				any = true
				evidence = append(evidence, part...)
			}
		}
		if !any {
			return nil, false
		}
		return evidence, true
	case selector.ExprNot:
		if _, ok := evalExpr(expr.Inner, object, state, principal); ok {
			return nil, false
		}
		return []EvidenceEntry{}, true
	default:
		return nil, false
	}
}

func literalValue(l selector.Literal) wcb.Value {
	switch l.Kind {
	case selector.LitNull:
		return wcb.NullValue()
	case selector.LitBool:
		return wcb.BoolValue(l.Bool)
	case selector.LitU64:
		return wcb.U64Value(l.U)
	case selector.LitI64:
		return wcb.I64Value(l.I)
	default:
		return wcb.TextValue(l.Str)
	}
}

// resolveField resolves a v1 root field on an object record. Unknown paths are
// absent (closed world), never errors.
func resolveField(object model.ObjectRecord, field selector.Field) (wcb.Value, bool) {
	segments := field.Segments
	if len(segments) == 0 {
		return wcb.Value{}, false
	}
	switch segments[0] {
	case "object_id":
		if len(segments) == 1 {
			return wcb.TextValue(object.ID.Hex()), true
		}
	case "content_id":
		if len(segments) == 1 {
			return wcb.TextValue(object.Content.Hex()), true
		}
	case "namespace":
		if len(segments) == 1 {
			return wcb.TextValue(model.DefaultNamespace), true
		}
	case "media_type":
		if len(segments) == 1 {
			if v, ok := object.Attrs["media_type"]; ok {
				return model.CloneValue(v), true
			}
			if v, ok := object.Attrs["weft.media_type"]; ok {
				return model.CloneValue(v), true
			}
			return wcb.Value{}, false
		}
	case "size":
		if len(segments) == 1 {
			return wcb.U64Value(object.Size), true
		}
	case "mtime":
		if len(segments) == 1 {
			return wcb.TimestampValue(object.MtimeNS), true
		}
	case "kind":
		if len(segments) == 1 {
			return wcb.TextValue(string(object.Kind)), true
		}
	case "attrs":
		if len(segments) > 1 {
			key := joinSegments(segments[1:])
			if v, ok := object.Attrs[key]; ok {
				return model.CloneValue(v), true
			}
			return wcb.Value{}, false
		}
	}
	return wcb.Value{}, false
}

func joinSegments(segments []string) string {
	out := segments[0]
	for _, segment := range segments[1:] {
		out += "." + segment
	}
	return out
}

func numeric(value wcb.Value) (int64, bool) {
	switch value.Kind {
	case wcb.U64:
		return int64(value.U), value.U <= ^uint64(0)>>1
	case wcb.I64, wcb.Timestamp:
		return value.I, true
	default:
		return 0, false
	}
}

// numericCompare compares two numeric values exactly, including u64 values
// above math.MaxInt64.
func numericCompare(left, right wcb.Value) (int, bool) {
	lok := left.Kind == wcb.U64 || left.Kind == wcb.I64 || left.Kind == wcb.Timestamp
	rok := right.Kind == wcb.U64 || right.Kind == wcb.I64 || right.Kind == wcb.Timestamp
	if !lok || !rok {
		return 0, false
	}
	// U64 values above MaxInt64 are handled by comparing sign-free.
	lneg := left.Kind != wcb.U64 && left.I < 0
	rneg := right.Kind != wcb.U64 && right.I < 0
	if lneg != rneg {
		if lneg {
			return -1, true
		}
		return 1, true
	}
	if !lneg {
		var lu, ru uint64
		if left.Kind == wcb.U64 {
			lu = left.U
		} else {
			lu = uint64(left.I)
		}
		if right.Kind == wcb.U64 {
			ru = right.U
		} else {
			ru = uint64(right.I)
		}
		switch {
		case lu < ru:
			return -1, true
		case lu > ru:
			return 1, true
		default:
			return 0, true
		}
	}
	var li, ri int64
	if left.Kind == wcb.U64 {
		li = int64(left.U)
	} else {
		li = left.I
	}
	if right.Kind == wcb.U64 {
		ri = int64(right.U)
	} else {
		ri = right.I
	}
	switch {
	case li < ri:
		return -1, true
	case li > ri:
		return 1, true
	default:
		return 0, true
	}
}

// equalValues: numeric families compare by value; other types compare only
// with the same type.
func equalValues(left, right wcb.Value) bool {
	if cmp, ok := numericCompare(left, right); ok {
		return cmp == 0
	}
	if left.Kind != right.Kind {
		return false
	}
	switch left.Kind {
	case wcb.Null:
		return true
	case wcb.Bool:
		return left.Bool == right.Bool
	case wcb.Text:
		return left.Str == right.Str
	case wcb.Bytes:
		return bytes.Equal(left.Bytes, right.Bytes)
	default:
		return false
	}
}

func comparableOrder(left, right wcb.Value) (int, bool) {
	if cmp, ok := numericCompare(left, right); ok {
		return cmp, true
	}
	if left.Kind != right.Kind {
		return 0, false
	}
	switch left.Kind {
	case wcb.Text:
		return bytes.Compare([]byte(left.Str), []byte(right.Str)), true
	case wcb.Bytes:
		return bytes.Compare(left.Bytes, right.Bytes), true
	case wcb.Bool:
		switch {
		case left.Bool == right.Bool:
			return 0, true
		case !left.Bool:
			return -1, true
		default:
			return 1, true
		}
	case wcb.Null:
		return 0, true
	default:
		return 0, false
	}
}

func compare(left wcb.Value, op selector.CmpOp, right wcb.Value) bool {
	switch op {
	case selector.OpEq:
		return equalValues(left, right)
	case selector.OpNe:
		cmp, ok := comparableOrder(left, right)
		return ok && cmp != 0
	case selector.OpLt:
		cmp, ok := comparableOrder(left, right)
		return ok && cmp < 0
	case selector.OpLe:
		cmp, ok := comparableOrder(left, right)
		return ok && cmp <= 0
	case selector.OpGt:
		cmp, ok := comparableOrder(left, right)
		return ok && cmp > 0
	case selector.OpGe:
		cmp, ok := comparableOrder(left, right)
		return ok && cmp >= 0
	default:
		return false
	}
}

func valueRank(value wcb.Value) int {
	switch value.Kind {
	case wcb.Null:
		return 0
	case wcb.Bool:
		return 1
	case wcb.U64, wcb.I64, wcb.Timestamp:
		return 2
	case wcb.Text:
		return 3
	case wcb.Bytes:
		return 4
	case wcb.Array:
		return 5
	case wcb.Map:
		return 6
	default:
		return 7
	}
}

func totalValueOrder(left, right wcb.Value) int {
	if cmp, ok := comparableOrder(left, right); ok {
		return cmp
	}
	l, r := valueRank(left), valueRank(right)
	switch {
	case l < r:
		return -1
	case l > r:
		return 1
	default:
		return 0
	}
}

func compareOptional(left wcb.Value, leftOK bool, right wcb.Value, rightOK bool) int {
	switch {
	case !leftOK && !rightOK:
		return 0
	case !leftOK:
		return -1
	case !rightOK:
		return 1
	default:
		return totalValueOrder(left, right)
	}
}

func compareRecords(left, right model.ObjectRecord, order []selector.OrderItem) int {
	for _, item := range order {
		lv, lok := resolveField(left, item.Field)
		rv, rok := resolveField(right, item.Field)
		cmp := compareOptional(lv, lok, rv, rok)
		if item.Desc {
			cmp = -cmp
		}
		if cmp != 0 {
			return cmp
		}
	}
	return bytes.Compare(left.ID[:], right.ID[:])
}
