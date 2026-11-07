// Candidate narrowing from a StateIndex (the Go port of the Rust
// `candidates_for`). The resolver body in resolver.go still evaluates every
// candidate with `evalExpr`; this file only decides which objects are worth
// evaluating.
//
// The rule is the same as Rust's: an index may over-approximate the match set
// but must never under-approximate. `Not` therefore complements only an exact
// candidate set; complementing an over-approximation would drop real matches.

package resolver

import (
	"github.com/infinityabundance/WeftCodec-Go/selector"
	"github.com/infinityabundance/WeftFS-Go/auth"
	weftindex "github.com/infinityabundance/WeftFS-Go/index"
	"github.com/infinityabundance/WeftFS-Go/model"
)

// candidateSet is a set of object ids plus whether it equals the evaluator's
// true match set (exact) or merely contains it.
type candidateSet struct {
	ids   map[model.Hash32]struct{}
	exact bool
}

func cloneIDs(source map[model.Hash32]struct{}) map[model.Hash32]struct{} {
	out := make(map[model.Hash32]struct{}, len(source))
	for id := range source {
		out[id] = struct{}{}
	}
	return out
}

// intersectIndex intersects an index set with the authorized universe. A nil or
// missing set yields the empty set, matching Rust's `intersect_index(None)`.
func intersectIndex(set weftindex.IDSet, authorized map[model.Hash32]struct{}) map[model.Hash32]struct{} {
	if len(set) <= len(authorized) {
		out := make(map[model.Hash32]struct{}, len(set))
		for id := range set {
			if _, ok := authorized[id]; ok {
				out[id] = struct{}{}
			}
		}
		return out
	}
	out := make(map[model.Hash32]struct{}, len(authorized))
	for id := range authorized {
		if _, ok := set[id]; ok {
			out[id] = struct{}{}
		}
	}
	return out
}

// candidatesFor derives the authorized candidate set for one AST node. It never
// decides a match.
func candidatesFor(expr *selector.Expr, idx *weftindex.StateIndex, state *model.State, principal auth.Principal, authorized map[model.Hash32]struct{}) candidateSet {
	// An incomplete index would drop entries; fail safe by scanning instead.
	if !idx.Complete() {
		return candidateSet{ids: authorized, exact: false}
	}
	switch expr.Kind {
	case selector.ExprTrue:
		return candidateSet{ids: authorized, exact: true}
	case selector.ExprFalse:
		return candidateSet{ids: map[model.Hash32]struct{}{}, exact: true}
	case selector.ExprHas:
		if key, ok := weftindex.AttrFieldKey(expr.Field); ok {
			return candidateSet{ids: intersectIndex(idx.ObjectsWithAttr[key], authorized), exact: true}
		}
		if weftindex.FieldAlwaysPresent(expr.Field) {
			return candidateSet{ids: authorized, exact: true}
		}
		// `media_type` can be absent or null; unknown paths are absent.
		return candidateSet{ids: authorized, exact: false}
	case selector.ExprTag:
		return candidateSet{ids: intersectIndex(idx.Tags[expr.Name], authorized), exact: true}
	case selector.ExprRelation:
		// `evalExpr` requires a readable target object; when it is absent or
		// hidden the predicate is false for every object.
		target := expr.Target
		record, exists := state.Objects[target]
		if !exists || !auth.CanRead(record, principal) {
			return candidateSet{ids: map[model.Hash32]struct{}{}, exact: true}
		}
		ids := make(map[model.Hash32]struct{})
		for pair, edges := range idx.RelationsFrom {
			if pair.Predicate != expr.Name {
				continue
			}
			if _, ok := authorized[pair.Subject]; !ok {
				continue
			}
			for _, edge := range edges {
				if edge.Kind == model.RelationObject && edge.Target.Object != nil &&
					*edge.Target.Object == target {
					ids[pair.Subject] = struct{}{}
					break
				}
			}
		}
		return candidateSet{ids: ids, exact: true}
	case selector.ExprCompare:
		if expr.Op != selector.OpEq {
			return candidateSet{ids: authorized, exact: false}
		}
		key, ok := weftindex.AttrFieldKey(expr.Field)
		if !ok {
			// Derived fields (`size`, `object_id`, …) are not indexed for
			// equality; the full authorized scan is the safe superset.
			return candidateSet{ids: authorized, exact: false}
		}
		encoded, usable, err := weftindex.EqKey(literalValue(expr.Value))
		if err != nil || !usable {
			return candidateSet{ids: authorized, exact: false}
		}
		return candidateSet{
			ids:   intersectIndex(idx.ObjectsByAttrEq[weftindex.AttrEqKey{Name: key, Key: string(encoded)}], authorized),
			exact: true,
		}
	case selector.ExprAnd:
		ids := cloneIDs(authorized)
		exact := true
		for _, item := range expr.Items {
			part := candidatesFor(item, idx, state, principal, authorized)
			for id := range ids {
				if _, ok := part.ids[id]; !ok {
					delete(ids, id)
				}
			}
			exact = exact && part.exact
		}
		return candidateSet{ids: ids, exact: exact}
	case selector.ExprOr:
		ids := make(map[model.Hash32]struct{})
		exact := true
		for _, item := range expr.Items {
			part := candidatesFor(item, idx, state, principal, authorized)
			for id := range part.ids {
				ids[id] = struct{}{}
			}
			exact = exact && part.exact
		}
		return candidateSet{ids: ids, exact: exact}
	case selector.ExprNot:
		part := candidatesFor(expr.Inner, idx, state, principal, authorized)
		if !part.exact {
			// `Not` complements inside the authorized universe; with only an
			// over-approximation available, scan the universe.
			return candidateSet{ids: authorized, exact: false}
		}
		ids := make(map[model.Hash32]struct{}, len(authorized))
		for id := range authorized {
			if _, ok := part.ids[id]; !ok {
				ids[id] = struct{}{}
			}
		}
		return candidateSet{ids: ids, exact: true}
	default:
		return candidateSet{ids: authorized, exact: false}
	}
}
