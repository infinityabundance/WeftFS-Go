package auth

import (
	weftcontext "github.com/infinityabundance/WeftCodec-Go/context"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// Capability is a capability scope plus its content address. It is an explicit
// additional narrowing, not a signature and not a security token against a
// privileged local attacker (WEFT-CAPABILITIES.md §7).
type Capability struct {
	Scope *weftcontext.CapabilityScope
	Hash  model.Hash32
}

// NewCapability computes the capability hash.
func NewCapability(scope *weftcontext.CapabilityScope) (*Capability, error) {
	hash, err := scope.ID()
	if err != nil {
		return nil, werr.FromCodec(err)
	}
	if hash == model.ZeroHash {
		return nil, werr.Newf(werr.NonCanonical, "capability hash must not be zero")
	}
	return &Capability{Scope: scope, Hash: hash}, nil
}

// AllowsNamespace reports whether the namespace is granted.
func (c *Capability) AllowsNamespace(namespace string) bool {
	for _, item := range c.Scope.Namespaces {
		if item == namespace {
			return true
		}
	}
	return false
}

// AllowsRoot reports whether the Context Root id is granted.
func (c *Capability) AllowsRoot(root model.Hash32) bool {
	for _, item := range c.Scope.Roots {
		if item == root {
			return true
		}
	}
	return false
}

// AllowsPredicate reports whether a relation predicate may be traversed.
func (c *Capability) AllowsPredicate(predicate string) bool {
	for _, item := range c.Scope.Predicates {
		if item == predicate {
			return true
		}
	}
	return false
}

// CheckValidAt enforces inclusive expiry against the store clock. Expiry is
// folded into a generic denial so it does not disclose grant contents.
func (c *Capability) CheckValidAt(nowNS int64) error {
	if c.Scope.ExpiresAt != nil && nowNS > *c.Scope.ExpiresAt {
		return werr.Newf(werr.Unauthorized, "capability is not valid")
	}
	return nil
}

// EffectiveBudget returns the component-wise minimum of a root budget and a
// capability budget; nil means unbounded within store policy.
func EffectiveBudget(root, capability *weftcontext.Budget) *weftcontext.Budget {
	if root == nil && capability == nil {
		return nil
	}
	if root == nil {
		return capability
	}
	if capability == nil {
		return root
	}
	return &weftcontext.Budget{
		MaxResults: minU64Ptr(root.MaxResults, capability.MaxResults),
		MaxBytes:   minU64Ptr(root.MaxBytes, capability.MaxBytes),
		MaxDepth:   minU64Ptr(root.MaxDepth, capability.MaxDepth),
		MaxWork:    minU64Ptr(root.MaxWork, capability.MaxWork),
	}
}

func minU64Ptr(a, b *uint64) *uint64 {
	switch {
	case a == nil && b == nil:
		return nil
	case a == nil:
		value := *b
		return &value
	case b == nil:
		value := *a
		return &value
	default:
		value := *a
		if *b < value {
			value = *b
		}
		return &value
	}
}
