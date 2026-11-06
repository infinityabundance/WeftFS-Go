package store

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	weftcontext "github.com/infinityabundance/WeftCodec-Go/context"
	"github.com/infinityabundance/WeftCodec-Go/hash"
	"github.com/infinityabundance/WeftCodec-Go/limits"
	"github.com/infinityabundance/WeftCodec-Go/selector"
	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/auth"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/resolver"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// Context lineage constants (identical to the Rust store).
const (
	ContextLineagePredicate     = "derived_from"
	ContextLineageContextAttr   = "weft.context"
	ContextLineageContextIDAttr = "weft.context_id"
	ContextLineageSourceIDAttr  = "weft.source_context_id"
)

// BranchContextRoot pins a new Context Root to the source root's commit,
// optionally narrowing it with task/model attribute equality, and records a
// `derived_from` lineage relation. Two commits are published (root, lineage).
func (s *Store) BranchContextRoot(source, name string, task, modelName *string, replace bool) (StoredContextRoot, error) {
	if err := s.requireWritable(); err != nil {
		return StoredContextRoot{}, err
	}
	if err := model.ValidateSnapshotName(name); err != nil {
		return StoredContextRoot{}, err
	}
	stored, err := s.LoadContextRoot(source)
	if err != nil {
		return StoredContextRoot{}, err
	}
	parsed, err := stored.Root.Selector()
	if err != nil {
		return StoredContextRoot{}, werr.FromCodec(err)
	}
	if task != nil {
		parsed.Predicate = conjoinAttribute(parsed.Predicate, "task", *task)
	}
	if modelName != nil {
		parsed.Predicate = conjoinAttribute(parsed.Predicate, "model", *modelName)
	}
	root, err := weftcontext.NewContextRoot(
		parsed, stored.Root.Snapshot, stored.Root.Resolver,
		stored.Root.Causal, stored.Root.CapabilityHash, stored.Root.Budget,
	)
	if err != nil {
		return StoredContextRoot{}, werr.FromCodec(err)
	}
	newID, err := root.ID()
	if err != nil {
		return StoredContextRoot{}, werr.FromCodec(err)
	}
	if _, err := s.SaveContextRoot(name, root, nil, replace); err != nil {
		return StoredContextRoot{}, err
	}
	attrs := map[string]wcb.Value{
		ContextLineageContextAttr:   wcb.TextValue(name),
		ContextLineageContextIDAttr: wcb.TextValue(newID.Hex()),
		ContextLineageSourceIDAttr:  wcb.TextValue(stored.ContextRootID.Hex()),
	}
	if _, err := s.RelationAdd(
		model.RootID, ContextLineagePredicate,
		model.ValueTarget(wcb.TextValue(stored.Name)), nil, attrs,
	); err != nil {
		return StoredContextRoot{}, err
	}
	return s.LoadContextRoot(name)
}

// conjoinAttribute adds `attrs.<field> == value`, flattening an existing And so
// the selector stays canonical.
func conjoinAttribute(predicate *selector.Expr, field, value string) *selector.Expr {
	comparison := &selector.Expr{
		Kind:  selector.ExprCompare,
		Field: selector.Field{Segments: []string{"attrs", field}},
		Op:    selector.OpEq,
		Value: selector.StrLiteral(value),
	}
	if predicate == nil || predicate.Kind == selector.ExprTrue {
		return comparison
	}
	if predicate.Kind == selector.ExprAnd {
		items := append(append([]*selector.Expr(nil), predicate.Items...), comparison)
		return &selector.Expr{Kind: selector.ExprAnd, Items: items}
	}
	return &selector.Expr{Kind: selector.ExprAnd, Items: []*selector.Expr{predicate, comparison}}
}

// StoredContextRoot is a Context Root persisted as a root-subject relation.
type StoredContextRoot struct {
	Name          string
	Root          *weftcontext.ContextRoot
	RecordHex     string
	URI           string
	RelationID    model.Hash32
	ContextRootID model.Hash32
}

// ContextResolution is a resolved Context Root.
type ContextResolution struct {
	Stored          StoredContextRoot
	Selector        *selector.Selector
	Resolution      *resolver.Resolution
	EffectiveBudget *weftcontext.Budget
	CapabilityHash  *model.Hash32
	Truncated       bool
	WorkUnits       uint64
}

// MaterializationReport describes an atomic materialization.
type MaterializationReport struct {
	Out           string
	ManifestPath  string
	Files         uint64
	Bytes         uint64
	ContextRootID model.Hash32
	SnapshotID    model.Hash32
	SelectorID    model.Hash32
	Closure       []model.Hash32
}

type materializeEntry struct {
	relative      string
	displayPath   string
	objectID      model.Hash32
	versionID     model.Hash32
	contentID     model.Hash32
	contentHash   model.Hash32
	size          uint64
	kind          string
	bytes         []byte
	causalClosure []model.Hash32
}

// ---------------------------------------------------------------------------
// Causal closure construction
// ---------------------------------------------------------------------------

// ComputeCausalClosure resolves explicit entries to artifact identities and
// computes the transitive closure available in state. Cycles terminate with a
// visited set and the result is sorted/unique by construction.
func ComputeCausalClosure(state *model.State, entries []model.Hash32, lim limits.Limits) (*weftcontext.CausalClosure, error) {
	maxEntries := int(lim.MaxCausalEntries)
	if maxEntries < 1 {
		maxEntries = 1
	}
	versionToObject := make(map[model.Hash32]model.Hash32, len(state.Objects))
	for _, record := range state.Objects {
		versionToObject[record.Version] = record.ID
	}
	parentsSet := make(map[model.Hash32]bool)
	closureSet := make(map[model.Hash32]bool)
	visited := make(map[model.Hash32]bool)
	queue := make([]model.Hash32, 0, len(entries))
	for _, entry := range entries {
		if entry == model.ZeroHash {
			return nil, werr.Newf(werr.NonCanonical, "causal entry must not be all zero")
		}
		identity := entry
		if record, ok := state.Objects[entry]; ok {
			identity = record.Version
		}
		parentsSet[identity] = true
		closureSet[identity] = true
		queue = append(queue, identity)
	}
	for len(queue) > 0 {
		identity := queue[0]
		queue = queue[1:]
		if visited[identity] {
			continue
		}
		visited[identity] = true
		objectID, ok := versionToObject[identity]
		if !ok {
			continue
		}
		record, ok := state.Objects[objectID]
		if !ok {
			continue
		}
		stored, err := model.ObjectCausalClosure(record)
		if err != nil {
			return nil, err
		}
		if stored == nil {
			continue
		}
		for _, ancestor := range stored.Closure {
			if ancestor == model.ZeroHash {
				return nil, werr.Newf(werr.Corrupt, "stored causal closure contains the zero hash")
			}
			closureSet[ancestor] = true
			queue = append(queue, ancestor)
			if len(closureSet) > maxEntries {
				return nil, werr.LimitExceededf("causal closure exceeds max_causal_entries (%d)", maxEntries)
			}
		}
	}
	parents := SortHashKeys(parentsSet)
	closure := SortHashKeys(closureSet)
	if len(closure) > maxEntries {
		return nil, werr.LimitExceededf("causal closure exceeds max_causal_entries (%d)", maxEntries)
	}
	return weftcontext.NewCausalClosure(parents, closure)
}

// prepareCausal computes causal attrs and the identity mode for new content.
func (s *Store) prepareCausal(attrs map[string]wcb.Value, entries []model.Hash32) (map[string]wcb.Value, weftcontext.IdentityMode, *model.Hash32, *weftcontext.CausalClosure, error) {
	out := model.CloneAttrs(attrs)
	if len(entries) == 0 {
		return out, weftcontext.BytesOnly, nil, nil, nil
	}
	closure, err := ComputeCausalClosure(s.state, entries, limits.Default())
	if err != nil {
		return nil, weftcontext.BytesOnly, nil, nil, err
	}
	causalHash, err := closure.ID()
	if err != nil {
		return nil, weftcontext.BytesOnly, nil, nil, werr.FromCodec(err)
	}
	model.ApplyCausalAttrs(out, closure, weftcontext.CausalExact, causalHash)
	return out, weftcontext.CausalExact, &causalHash, closure, nil
}

func (s *Store) storeCausalClosure(closure *weftcontext.CausalClosure) error {
	bytesValue, err := closure.CanonicalBytes(limits.Default())
	if err != nil {
		return werr.FromCodec(err)
	}
	id, err := closure.ID()
	if err != nil {
		return werr.FromCodec(err)
	}
	if _, err := readBlobVerified(s.blobs, BlobManifest, id, hash.DomainCausal); err == nil {
		return nil
	}
	_, err = s.storeBlob(BlobManifest, hash.DomainCausal, bytesValue)
	return err
}

// ---------------------------------------------------------------------------
// Capability parsing
// ---------------------------------------------------------------------------

// ParseCapabilityText parses a capability record from JSON or canonical hex.
func ParseCapabilityText(text string) (*weftcontext.CapabilityScope, error) {
	trimmed := strings.TrimSpace(text)
	if strings.HasPrefix(trimmed, "{") {
		var raw map[string]any
		if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
			return nil, werr.Newf(werr.Parse, "bad capability JSON: %v", err)
		}
		for key := range raw {
			switch key {
			case "schema", "principal", "namespaces", "roots", "predicates", "budget", "expires_at":
			default:
				return nil, werr.Newf(werr.NonCanonical, "unknown capability key `%s`", key)
			}
		}
		if schema, ok := raw["schema"]; ok {
			if text, _ := schema.(string); text != weftcontext.CapabilitySchema {
				return nil, werr.Newf(werr.UnknownSchema, "capability schema must be %s", weftcontext.CapabilitySchema)
			}
		}
		principal, ok := raw["principal"].(string)
		if !ok {
			return nil, werr.Newf(werr.Parse, "capability `principal` must be text")
		}
		namespaces, err := jsonStringArray(raw["namespaces"], "namespaces")
		if err != nil {
			return nil, err
		}
		var roots []model.Hash32
		if value, ok := raw["roots"]; ok && value != nil {
			items, ok := value.([]any)
			if !ok {
				return nil, werr.Newf(werr.Parse, "capability `roots` must be an array")
			}
			for _, item := range items {
				text, ok := item.(string)
				if !ok {
					return nil, werr.Newf(werr.Parse, "capability roots must be hex text")
				}
				h, err := parseHashHex(text)
				if err != nil {
					return nil, err
				}
				roots = append(roots, h)
			}
		}
		predicates, err := jsonStringArray(raw["predicates"], "predicates")
		if err != nil {
			return nil, err
		}
		var budget *weftcontext.Budget
		if value, ok := raw["budget"]; ok && value != nil {
			object, ok := value.(map[string]any)
			if !ok {
				return nil, werr.Newf(werr.Parse, "capability budget must be an object")
			}
			budget = &weftcontext.Budget{}
			for key, item := range object {
				number, ok := item.(float64)
				if !ok || number < 0 || number != float64(uint64(number)) {
					return nil, werr.Newf(werr.Parse, "budget `%s` must be u64", key)
				}
				value := uint64(number)
				switch key {
				case "max_results":
					budget.MaxResults = &value
				case "max_bytes":
					budget.MaxBytes = &value
				case "max_depth":
					budget.MaxDepth = &value
				case "max_work":
					budget.MaxWork = &value
				default:
					return nil, werr.Newf(werr.NonCanonical, "unknown budget key `%s`", key)
				}
			}
			if err := budget.Validate(); err != nil {
				return nil, werr.FromCodec(err)
			}
		}
		var expiresAt *int64
		if value, ok := raw["expires_at"]; ok && value != nil {
			number, ok := value.(float64)
			if !ok {
				return nil, werr.Newf(werr.Parse, "capability expires_at must be an integer")
			}
			integer := int64(number)
			expiresAt = &integer
		}
		scope, err := weftcontext.NewCapabilityScope(principal, namespaces, roots, predicates, budget, expiresAt)
		if err != nil {
			return nil, werr.FromCodec(err)
		}
		return scope, nil
	}
	bytesValue, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, werr.Newf(werr.Parse, "capability file is neither JSON nor canonical hex")
	}
	return weftcontext.CapabilityScopeFromCanonicalBytes(bytesValue, limits.Default())
}

func jsonStringArray(value any, what string) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, werr.Newf(werr.Parse, "capability `%s` must be an array", what)
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, werr.Newf(werr.Parse, "capability `%s` must be text", what)
		}
		out = append(out, text)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Context Root persistence
// ---------------------------------------------------------------------------

func isContextRootRelation(relation model.RelationRecord) bool {
	return relation.Subject == model.RootID &&
		relation.Predicate == model.ContextRootPredicate &&
		relation.Kind == model.RelationValue &&
		relation.Provenance == nil
}

func isCapabilityRelation(relation model.RelationRecord) bool {
	return relation.Subject == model.RootID &&
		relation.Predicate == model.CapabilityPredicate &&
		relation.Kind == model.RelationValue &&
		relation.Provenance == nil
}

func relationTargetText(relation model.RelationRecord) (string, bool) {
	if relation.Target.Object != nil || relation.Target.Value.Kind != wcb.Text {
		return "", false
	}
	return relation.Target.Value.Str, true
}

func contextRootRelationsAt(state *model.State, name string) ([]model.RelationRecord, error) {
	out := make([]model.RelationRecord, 0, 1)
	for _, relation := range state.Relations {
		if !isContextRootRelation(relation) {
			continue
		}
		text, ok := relationTargetText(relation)
		if !ok {
			return nil, werr.Newf(werr.Corrupt, "context_root target is not text")
		}
		if text == name {
			out = append(out, relation)
		}
	}
	if len(out) > 1 {
		return nil, werr.Newf(werr.Corrupt, "more than one context_root relation has the same name")
	}
	return out, nil
}

func contextRootFromRelation(name string, relation model.RelationRecord) (StoredContextRoot, error) {
	value, ok := relation.Attrs[model.ContextRootRecordAttr]
	if !ok || value.Kind != wcb.Text {
		return StoredContextRoot{}, werr.Newf(werr.Corrupt, "context_root relation has no context.record attribute")
	}
	uriValue, ok := relation.Attrs[model.ContextRootURIAttr]
	if !ok || uriValue.Kind != wcb.Text {
		return StoredContextRoot{}, werr.Newf(werr.Corrupt, "context_root relation has no uri attribute")
	}
	recordBytes, err := hex.DecodeString(value.Str)
	if err != nil {
		return StoredContextRoot{}, werr.Newf(werr.Corrupt, "context_root record is not hex")
	}
	root, err := weftcontext.ContextRootFromCanonicalBytes(recordBytes, limits.Default())
	if err != nil {
		return StoredContextRoot{}, werr.FromCodec(err)
	}
	id, err := root.ID()
	if err != nil {
		return StoredContextRoot{}, werr.FromCodec(err)
	}
	expectedURI, err := root.AuthoritativeURI()
	if err != nil {
		return StoredContextRoot{}, werr.FromCodec(err)
	}
	if expectedURI != uriValue.Str {
		return StoredContextRoot{}, werr.Newf(werr.Corrupt, "context_root uri does not match the canonical record")
	}
	return StoredContextRoot{
		Name: name, Root: root, RecordHex: value.Str, URI: uriValue.Str,
		RelationID: relation.ID, ContextRootID: id,
	}, nil
}

// SaveContextRoot persists a Context Root relation. Duplicate names are Exists
// unless replace is true, in which case delete+add is one commit.
func (s *Store) SaveContextRoot(name string, root *weftcontext.ContextRoot, capability *weftcontext.CapabilityScope, replace bool) (model.Hash32, error) {
	if err := s.requireWritable(); err != nil {
		return model.Hash32{}, err
	}
	if err := model.ValidateSnapshotName(name); err != nil {
		return model.Hash32{}, err
	}
	recordBytes, err := root.CanonicalBytes(limits.Default())
	if err != nil {
		return model.Hash32{}, werr.FromCodec(err)
	}
	uri, err := root.AuthoritativeURI()
	if err != nil {
		return model.Hash32{}, werr.FromCodec(err)
	}
	attrs := map[string]wcb.Value{
		model.ContextRootRecordAttr: wcb.TextValue(hex.EncodeToString(recordBytes)),
		model.ContextRootURIAttr:    wcb.TextValue(uri),
	}
	relation, err := model.NewRelationRecord(
		model.RootID, model.ContextRootPredicate, model.ValueTarget(wcb.TextValue(name)), nil, attrs,
	)
	if err != nil {
		return model.Hash32{}, err
	}
	existing, err := contextRootRelationsAt(s.state, name)
	if err != nil {
		return model.Hash32{}, err
	}
	if len(existing) != 0 && !replace {
		return model.Hash32{}, werr.Newf(werr.Exists, "a context root with this name already exists")
	}
	var ops []model.Op
	if capability != nil {
		capOps, err := s.capabilityOps(capability)
		if err != nil {
			return model.Hash32{}, err
		}
		ops = append(ops, capOps...)
	}
	switch len(existing) {
	case 0:
		ops = append(ops, model.PutRelationOp{Record: relation})
	case 1:
		if existing[0].ID == relation.ID {
			if len(ops) != 0 {
				if _, err := s.commitOps(ops, false); err != nil {
					return model.Hash32{}, err
				}
			}
			return relation.ID, nil
		}
		ops = append(ops, model.DelRelationOp{ID: existing[0].ID}, model.PutRelationOp{Record: relation})
	default:
		return model.Hash32{}, werr.Newf(werr.Corrupt, "more than one context_root relation has the same name")
	}
	if _, err := s.commitOps(ops, false); err != nil {
		return model.Hash32{}, err
	}
	return relation.ID, nil
}

// DeleteContextRoot deletes a named Context Root.
func (s *Store) DeleteContextRoot(name string) error {
	if err := s.requireWritable(); err != nil {
		return err
	}
	existing, err := contextRootRelationsAt(s.state, name)
	if err != nil {
		return err
	}
	if len(existing) == 0 {
		return werr.Newf(werr.NotFound, "no such context root")
	}
	_, err = s.commitOps([]model.Op{model.DelRelationOp{ID: existing[0].ID}}, false)
	return err
}

// ListContextRoots returns all stored Context Roots sorted by name.
func (s *Store) ListContextRoots() ([]StoredContextRoot, error) {
	return s.ListContextRootsAt(s.state)
}

// ListContextRootsAt returns stored Context Roots in an explicit state.
func (s *Store) ListContextRootsAt(state *model.State) ([]StoredContextRoot, error) {
	out := make([]StoredContextRoot, 0)
	for _, relation := range state.Relations {
		if !isContextRootRelation(relation) {
			continue
		}
		name, ok := relationTargetText(relation)
		if !ok {
			return nil, werr.Newf(werr.Corrupt, "context_root target is not text")
		}
		stored, err := contextRootFromRelation(name, relation)
		if err != nil {
			return nil, err
		}
		out = append(out, stored)
	}
	sort.Slice(out, func(i, j int) bool { return bytesCompare([]byte(out[i].Name), []byte(out[j].Name)) < 0 })
	return out, nil
}

// LoadContextRoot loads a Context Root by name or weft:// URI.
func (s *Store) LoadContextRoot(nameOrURI string) (StoredContextRoot, error) {
	return s.LoadContextRootAt(s.state, nameOrURI)
}

// LoadContextRootAt loads a Context Root from an explicit state.
func (s *Store) LoadContextRootAt(state *model.State, nameOrURI string) (StoredContextRoot, error) {
	if strings.HasPrefix(nameOrURI, weftcontext.URIPrefix) {
		parsed, err := weftcontext.ParseContextURI(nameOrURI, limits.Default())
		if err != nil {
			return StoredContextRoot{}, werr.FromCodec(err)
		}
		id := parsed.ID
		var expected *weftcontext.ContextRoot
		if parsed.Form == weftcontext.FormDescriptor {
			expected, err = parsed.ToContextRoot(limits.Default())
			if err != nil {
				return StoredContextRoot{}, werr.FromCodec(err)
			}
			id, err = expected.ID()
			if err != nil {
				return StoredContextRoot{}, werr.FromCodec(err)
			}
		}
		var matches []StoredContextRoot
		for _, relation := range state.Relations {
			if !isContextRootRelation(relation) {
				continue
			}
			name, ok := relationTargetText(relation)
			if !ok {
				return StoredContextRoot{}, werr.Newf(werr.Corrupt, "context_root target is not text")
			}
			stored, err := contextRootFromRelation(name, relation)
			if err != nil {
				return StoredContextRoot{}, err
			}
			if stored.ContextRootID == id {
				matches = append(matches, stored)
			}
		}
		if len(matches) == 0 {
			return StoredContextRoot{}, werr.Newf(werr.NotFound, "no stored context root has this address")
		}
		sort.Slice(matches, func(i, j int) bool {
			return bytesCompare([]byte(matches[i].Name), []byte(matches[j].Name)) < 0
		})
		stored := matches[0]
		if stored.Root.Namespace != parsed.Namespace {
			return StoredContextRoot{}, werr.Newf(werr.Corrupt, "context-root URI namespace does not match the stored record")
		}
		if expected != nil {
			left, _ := expected.CanonicalBytes(limits.Default())
			right, _ := stored.Root.CanonicalBytes(limits.Default())
			if !bytesEqual(left, right) {
				return StoredContextRoot{}, werr.Newf(werr.NonCanonical, "descriptor URI does not canonicalize to the stored context root")
			}
		}
		return stored, nil
	}
	existing, err := contextRootRelationsAt(state, nameOrURI)
	if err != nil {
		return StoredContextRoot{}, err
	}
	if len(existing) == 0 {
		return StoredContextRoot{}, werr.Newf(werr.NotFound, "no such context root")
	}
	return contextRootFromRelation(nameOrURI, existing[0])
}

// SaveCapability persists a capability record (idempotent by hash).
func (s *Store) SaveCapability(scope *weftcontext.CapabilityScope) (model.Hash32, error) {
	if err := s.requireWritable(); err != nil {
		return model.Hash32{}, err
	}
	ops, err := s.capabilityOps(scope)
	if err != nil {
		return model.Hash32{}, err
	}
	if len(ops) != 0 {
		if _, err := s.commitOps(ops, false); err != nil {
			return model.Hash32{}, err
		}
	}
	return scope.ID()
}

func (s *Store) capabilityOps(scope *weftcontext.CapabilityScope) ([]model.Op, error) {
	hashValue, err := scope.ID()
	if err != nil {
		return nil, werr.FromCodec(err)
	}
	target := hashValue.Hex()
	for _, relation := range s.state.Relations {
		if !isCapabilityRelation(relation) {
			continue
		}
		if text, ok := relationTargetText(relation); ok && text == target {
			return nil, nil
		}
	}
	bytesValue, err := scope.CanonicalBytes(limits.Default())
	if err != nil {
		return nil, werr.FromCodec(err)
	}
	attrs := map[string]wcb.Value{
		model.CapabilityRecordAttr: wcb.TextValue(hex.EncodeToString(bytesValue)),
	}
	relation, err := model.NewRelationRecord(
		model.RootID, model.CapabilityPredicate, model.ValueTarget(wcb.TextValue(target)), nil, attrs,
	)
	if err != nil {
		return nil, err
	}
	return []model.Op{model.PutRelationOp{Record: relation}}, nil
}

// LoadCapability loads a stored capability by hash.
func (s *Store) LoadCapability(hashValue model.Hash32) (*weftcontext.CapabilityScope, error) {
	return s.LoadCapabilityAt(s.state, hashValue)
}

// LoadCapabilityAt loads a stored capability from an explicit state.
func (s *Store) LoadCapabilityAt(state *model.State, hashValue model.Hash32) (*weftcontext.CapabilityScope, error) {
	wanted := hashValue.Hex()
	for _, relation := range state.Relations {
		if !isCapabilityRelation(relation) {
			continue
		}
		target, ok := relationTargetText(relation)
		if !ok {
			return nil, werr.Newf(werr.Corrupt, "capability target is not text")
		}
		if target != wanted {
			continue
		}
		value, ok := relation.Attrs[model.CapabilityRecordAttr]
		if !ok || value.Kind != wcb.Text {
			return nil, werr.Newf(werr.Corrupt, "capability relation has no capability.record")
		}
		bytesValue, err := hex.DecodeString(value.Str)
		if err != nil {
			return nil, werr.Newf(werr.Corrupt, "capability record is not hex")
		}
		scope, err := weftcontext.CapabilityScopeFromCanonicalBytes(bytesValue, limits.Default())
		if err != nil {
			return nil, werr.FromCodec(err)
		}
		id, err := scope.ID()
		if err != nil {
			return nil, werr.FromCodec(err)
		}
		if id.Hex() != target {
			return nil, werr.Newf(werr.Corrupt, "stored capability record does not match its target hash")
		}
		return scope, nil
	}
	return nil, werr.Newf(werr.NotFound, "no stored capability has this hash")
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

// ResolveContext resolves a stored Context Root under a capability.
func (s *Store) ResolveContext(nameOrURI string, capability *auth.Capability, principal auth.Principal, lim limits.Limits, nowNS int64) (*ContextResolution, error) {
	return s.ResolveContextAt(s.state, nameOrURI, capability, principal, lim, nowNS)
}

// ResolveContextAt resolves against an explicit metadata state.
func (s *Store) ResolveContextAt(metadataState *model.State, nameOrURI string, capability *auth.Capability, principal auth.Principal, lim limits.Limits, nowNS int64) (*ContextResolution, error) {
	stored, err := s.LoadContextRootAt(metadataState, nameOrURI)
	if err != nil {
		return nil, err
	}
	root := stored.Root
	recomputed, err := root.ID()
	if err != nil {
		return nil, werr.FromCodec(err)
	}
	if recomputed != stored.ContextRootID {
		return nil, werr.Newf(werr.Corrupt, "stored context-root record does not match its address")
	}
	if root.Resolver != weftcontext.DefaultResolver {
		return nil, werr.Newf(werr.Unsupported, "unknown resolver `%s`", root.Resolver)
	}
	snapshotState, err := s.StateAt(root.Snapshot)
	if err != nil {
		return nil, err
	}

	active := capability
	if root.CapabilityHash != nil {
		if capability != nil {
			if capability.Hash != *root.CapabilityHash {
				return nil, werr.Newf(werr.Corrupt, "supplied capability hash does not match the context root binding")
			}
		} else {
			scope, err := s.LoadCapabilityAt(metadataState, *root.CapabilityHash)
			if err != nil {
				return nil, err
			}
			active, err = auth.NewCapability(scope)
			if err != nil {
				return nil, err
			}
		}
	}
	if active != nil {
		if err := active.CheckValidAt(nowNS); err != nil {
			return nil, err
		}
		if len(active.Scope.Roots) != 0 && !active.AllowsRoot(recomputed) {
			return nil, werr.Newf(werr.Unauthorized, "capability does not grant this context root")
		}
	}
	parsed, err := root.Selector()
	if err != nil {
		return nil, werr.FromCodec(err)
	}
	budget := auth.EffectiveBudget(root.Budget, func() *weftcontext.Budget {
		if active == nil {
			return nil
		}
		return active.Scope.Budget
	}())
	resolution, err := resolver.ResolveStateWithBudget(
		parsed, root.Snapshot, snapshotState, principal, lim, active, &recomputed, budget,
	)
	if err != nil {
		return nil, err
	}
	if resolution.SnapshotID != root.Snapshot {
		return nil, werr.Newf(werr.Corrupt, "resolution changed the pinned snapshot")
	}
	if resolution.SelectorID != root.SelectorID {
		return nil, werr.Newf(werr.Corrupt, "resolution changed the selector identity")
	}
	return &ContextResolution{
		Stored: stored, Selector: parsed, Resolution: resolution,
		EffectiveBudget: budget, CapabilityHash: root.CapabilityHash,
		Truncated: false, WorkUnits: resolver.WorkUnits(parsed, snapshotState),
	}, nil
}

// ExactIDObject resolves an ObjectId/VersionId/ContentId under a capability.
// Possession is never authority; denials are NotFound.
func (s *Store) ExactIDObject(id model.Hash32, capability *auth.Capability, principal auth.Principal, nowNS int64) (model.ObjectRecord, error) {
	return s.ExactIDObjectAt(s.state, id, capability, principal, nowNS)
}

// ExactIDObjectAt resolves an exact id against an explicit view state.
func (s *Store) ExactIDObjectAt(state *model.State, id model.Hash32, capability *auth.Capability, principal auth.Principal, nowNS int64) (model.ObjectRecord, error) {
	candidates := make([]model.ObjectRecord, 0, 1)
	for _, record := range state.Objects {
		if record.ID == id || record.Version == id || record.Content == id {
			candidates = append(candidates, record.Clone())
		}
	}
	if len(candidates) == 0 {
		return model.ObjectRecord{}, werr.Newf(werr.NotFound, "no such object")
	}
	if capability != nil {
		if err := capability.CheckValidAt(nowNS); err != nil {
			return model.ObjectRecord{}, err
		}
		namespaceGrant := capability.AllowsNamespace(model.DefaultNamespace)
		for _, record := range candidates {
			if !auth.CanRead(record, principal) {
				continue
			}
			if namespaceGrant {
				return record, nil
			}
			for _, rootID := range capability.Scope.Roots {
				stored, err := s.LoadContextRootAt(s.state, rootID.Hex())
				if err != nil {
					continue
				}
				resolved, err := s.ResolveContextAt(s.state, stored.Name, capability, principal, limits.Default(), nowNS)
				if err != nil {
					continue
				}
				for _, result := range resolved.Resolution.Results {
					if result.ObjectID == record.ID || result.VersionID == id || result.ContentID == id {
						return record, nil
					}
				}
			}
		}
		return model.ObjectRecord{}, werr.Newf(werr.NotFound, "no such object")
	}
	for _, record := range candidates {
		if auth.CanRead(record, principal) {
			return record, nil
		}
	}
	return model.ObjectRecord{}, werr.Newf(werr.NotFound, "no such object")
}

// ResolveSavedContextWithCapability resolves a legacy saved-context view under
// an optional capability. Saved contexts have no ContextRootId, so a root grant
// alone cannot authorize them.
func (s *Store) ResolveSavedContextWithCapability(sel *selector.Selector, snapshotID model.Hash32, state *model.State, principal auth.Principal, lim limits.Limits, capability *auth.Capability, nowNS int64) (*resolver.Resolution, error) {
	if capability != nil {
		if err := capability.CheckValidAt(nowNS); err != nil {
			return nil, err
		}
	}
	return resolver.ResolveStateWithBudget(sel, snapshotID, state, principal, lim, capability, nil, nil)
}

// VisibleSavedContexts filters saved-context views by capability.
func (s *Store) VisibleSavedContexts(state *model.State, capability *auth.Capability, principal auth.Principal, nowNS int64) ([]SavedContext, error) {
	if capability != nil {
		if err := capability.CheckValidAt(nowNS); err != nil {
			return nil, err
		}
	}
	root, ok := state.Objects[model.RootID]
	if !ok {
		return nil, werr.Newf(werr.Corrupt, "namespace root is missing")
	}
	if !auth.CanRead(root, principal) {
		return nil, nil
	}
	all, err := s.ListContextsAt(state)
	if err != nil {
		return nil, err
	}
	out := make([]SavedContext, 0, len(all))
	for _, saved := range all {
		if capability != nil {
			parsed, err := s.LoadContextAt(state, saved.Name)
			if err != nil {
				return nil, err
			}
			if !capability.AllowsNamespace(parsed.Namespace) || !selectorPredicatesAllowed(parsed.Predicate, capability) {
				continue
			}
		}
		out = append(out, saved)
	}
	return out, nil
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

// ---------------------------------------------------------------------------
// Materialization
// ---------------------------------------------------------------------------

// MaterializeContext writes a resolved Context Root atomically. Every content
// hash is verified before the output directory is published.
func (s *Store) MaterializeContext(nameOrURI, out string, capability *auth.Capability, principal auth.Principal, lim limits.Limits, nowNS int64) (*MaterializationReport, error) {
	resolved, err := s.ResolveContext(nameOrURI, capability, principal, lim, nowNS)
	if err != nil {
		return nil, err
	}
	state, err := s.StateAt(resolved.Stored.Root.Snapshot)
	if err != nil {
		return nil, err
	}
	entries := make([]materializeEntry, 0, len(resolved.Resolution.Results))
	seen := make(map[string]bool)
	var totalBytes uint64
	for _, result := range resolved.Resolution.Results {
		record, ok := state.Objects[result.ObjectID]
		if !ok {
			return nil, werr.Newf(werr.Corrupt, "selector result has no object record")
		}
		displayPath := ""
		if path, ok := state.PathFor(result.ObjectID); ok {
			displayPath = string(path)
		} else {
			displayPath = "/objects/" + result.ObjectID.Hex()
		}
		if seen[displayPath] {
			return nil, werr.Newf(werr.Corrupt, "materialization path `%s` is not unique", displayPath)
		}
		seen[displayPath] = true
		var data []byte
		var contentHash model.Hash32
		switch record.Kind {
		case model.KindDir:
			contentHash = model.ContentHash(nil)
		case model.KindSymlink:
			target, ok := record.SymlinkTarget()
			if !ok {
				return nil, werr.Newf(werr.Corrupt, "symlink has no target")
			}
			data = append([]byte(nil), target...)
			contentHash = model.ContentHash(data)
			if contentHash != record.Content {
				return nil, werr.Newf(werr.Corrupt, "symlink content hash mismatch")
			}
		default:
			data, err = s.readObjectState(state, record.ID)
			if err != nil {
				return nil, err
			}
			contentHash = model.ContentHash(data)
		}
		totalBytes += uint64(len(data))
		var closure []model.Hash32
		if stored, err := model.ObjectCausalClosure(record); err != nil {
			return nil, err
		} else if stored != nil {
			closure = stored.Closure
		}
		entries = append(entries, materializeEntry{
			relative: strings.TrimPrefix(displayPath, "/"), displayPath: displayPath,
			objectID: record.ID, versionID: record.Version, contentID: record.Content,
			contentHash: contentHash, size: uint64(len(data)), kind: string(record.Kind),
			bytes: data, causalClosure: closure,
		})
	}
	if resolved.EffectiveBudget != nil && resolved.EffectiveBudget.MaxBytes != nil && totalBytes > *resolved.EffectiveBudget.MaxBytes {
		return nil, werr.LimitExceededf("materialization needs %d bytes, budget is %d", totalBytes, *resolved.EffectiveBudget.MaxBytes)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].displayPath < entries[j].displayPath })

	parent := filepath.Dir(out)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return nil, werr.Wrap(werr.Io, err, "cannot create %s", parent)
	}
	tmp, err := os.MkdirTemp(parent, "."+filepath.Base(out)+".weft-tmp-")
	if err != nil {
		return nil, werr.Wrap(werr.Io, err, "cannot create temporary materialization directory")
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }
	manifest, err := s.writeMaterialization(tmp, resolved, entries, totalBytes)
	if err != nil {
		cleanup()
		return nil, err
	}
	if info, err := os.Stat(out); err == nil {
		if !info.IsDir() {
			cleanup()
			return nil, werr.Newf(werr.Exists, "materialization output exists and is not a directory")
		}
		items, err := os.ReadDir(out)
		if err != nil {
			cleanup()
			return nil, werr.Wrap(werr.Io, err, "cannot read %s", out)
		}
		if len(items) != 0 {
			cleanup()
			return nil, werr.Newf(werr.Exists, "materialization output directory is not empty")
		}
		if err := os.Remove(out); err != nil {
			cleanup()
			return nil, werr.Wrap(werr.Io, err, "cannot replace %s", out)
		}
	}
	if err := os.Rename(tmp, out); err != nil {
		cleanup()
		return nil, werr.Wrap(werr.Io, err, "cannot publish materialization at %s", out)
	}
	manifestPath := filepath.Join(out, ".weft-context.json")
	if err := writeJSONFile(manifestPath, manifest); err != nil {
		return nil, err
	}
	return &MaterializationReport{
		Out: out, ManifestPath: manifestPath, Files: uint64(len(entries)), Bytes: totalBytes,
		ContextRootID: resolved.Stored.ContextRootID, SnapshotID: resolved.Resolution.SnapshotID,
		SelectorID: resolved.Resolution.SelectorID, Closure: resolved.Stored.Root.Causal,
	}, nil
}

func (s *Store) writeMaterialization(tmp string, resolved *ContextResolution, entries []materializeEntry, totalBytes uint64) (map[string]any, error) {
	files := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		relative := entry.relative
		if relative == "" {
			relative = "."
		}
		target := filepath.Join(tmp, filepath.FromSlash(relative))
		switch entry.kind {
		case string(model.KindDir):
			if err := os.MkdirAll(target, 0o755); err != nil {
				return nil, werr.Wrap(werr.Io, err, "cannot create %s", target)
			}
		case string(model.KindSymlink):
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return nil, werr.Wrap(werr.Io, err, "cannot create %s", filepath.Dir(target))
			}
			if err := os.Symlink(string(entry.bytes), target); err != nil {
				return nil, werr.Wrap(werr.Io, err, "cannot create symlink %s", target)
			}
		default:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return nil, werr.Wrap(werr.Io, err, "cannot create %s", filepath.Dir(target))
			}
			if err := os.WriteFile(target, entry.bytes, 0o644); err != nil {
				return nil, werr.Wrap(werr.Io, err, "cannot write %s", target)
			}
			if model.ContentHash(entry.bytes) != entry.contentHash {
				return nil, werr.Newf(werr.Corrupt, "materialization content hash changed")
			}
		}
		closure := make([]string, 0, len(entry.causalClosure))
		for _, item := range entry.causalClosure {
			closure = append(closure, item.Hex())
		}
		files = append(files, map[string]any{
			"path": entry.displayPath, "object_id": entry.objectID.Hex(),
			"version_id": entry.versionID.Hex(), "content_id": entry.contentID.Hex(),
			"content_hash": entry.contentHash.Hex(), "size": entry.size,
			"kind": entry.kind, "causal_closure": closure,
		})
	}
	closure := make([]string, 0, len(resolved.Stored.Root.Causal))
	for _, item := range resolved.Stored.Root.Causal {
		closure = append(closure, item.Hex())
	}
	var capability any
	if resolved.CapabilityHash != nil {
		capability = resolved.CapabilityHash.Hex()
	}
	var budget any
	if resolved.EffectiveBudget != nil {
		budget = resolved.EffectiveBudget.JSON()
	}
	return map[string]any{
		"format":          "weft-context-materialization.v1",
		"context_root_id": resolved.Stored.ContextRootID.Hex(),
		"uri":             resolved.Stored.URI,
		"name":            resolved.Stored.Name,
		"selector_id":     resolved.Resolution.SelectorID.Hex(),
		"snapshot_id":     resolved.Resolution.SnapshotID.Hex(),
		"closure":         closure,
		"capability_hash": capability,
		"budget":          budget,
		"matched_count":   resolved.Resolution.MatchedCount,
		"returned":        len(resolved.Resolution.Results),
		"truncated":       resolved.Truncated,
		"bytes":           totalBytes,
		"files":           files,
	}, nil
}

func writeJSONFile(path string, value any) error {
	bytesValue, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return werr.Wrap(werr.Io, err, "cannot encode materialization manifest")
	}
	bytesValue = append(bytesValue, '\n')
	if err := os.WriteFile(path, bytesValue, 0o644); err != nil {
		return werr.Wrap(werr.Io, err, "cannot create %s", path)
	}
	return nil
}

func bytesCompare(a, b []byte) int {
	if string(a) < string(b) {
		return -1
	}
	if string(a) > string(b) {
		return 1
	}
	return 0
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
