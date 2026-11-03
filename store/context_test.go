package store_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	weftcontext "github.com/infinityabundance/WeftCodec-Go/context"
	"github.com/infinityabundance/WeftCodec-Go/hash"
	"github.com/infinityabundance/WeftCodec-Go/limits"
	"github.com/infinityabundance/WeftCodec-Go/selector"
	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/auth"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

func demoAttrs(project string) map[string]wcb.Value {
	return map[string]wcb.Value{"project": wcb.TextValue(project)}
}

func createDemo(t *testing.T, s *store.Store, name, text, project string) model.Hash32 {
	t.Helper()
	root, err := s.ResolvePath("/")
	if err != nil {
		t.Fatalf("resolve root: %v", err)
	}
	id, err := s.CreateFile(root, []byte(name), []byte(text), 0o644, 0, 0, demoAttrs(project))
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	return id
}

func makeRoot(t *testing.T, source string, snapshot model.Hash32, causal []model.Hash32, budget *weftcontext.Budget) *weftcontext.ContextRoot {
	t.Helper()
	parsed, err := selector.Parse(source)
	if err != nil {
		t.Fatalf("parse selector: %v", err)
	}
	root, err := weftcontext.NewContextRoot(parsed, snapshot, weftcontext.DefaultResolver, causal, nil, budget)
	if err != nil {
		t.Fatalf("new context root: %v", err)
	}
	return root
}

func class(err error) werr.Kind {
	if typed, ok := err.(*werr.Error); ok {
		return typed.Kind
	}
	return ""
}

func TestContextCreateResolveMaterializeCardinality(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, fixedOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()
	createDemo(t, s, "a.txt", "alpha", "demo")
	createDemo(t, s, "b.txt", "beta", "demo")
	createDemo(t, s, "other.txt", "other", "other")
	snapshot, err := s.SnapshotCreate("s1")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	root := makeRoot(t, "select attrs.project == \"demo\" order by size asc", snapshot, nil, nil)
	if _, err := s.SaveContextRoot("demo", root, nil, false); err != nil {
		t.Fatalf("save context: %v", err)
	}
	resolved, err := s.ResolveContext("demo", nil, auth.Root(), limits.Default(), s.ClockNowNS())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.Resolution.MatchedCount != 2 || len(resolved.Resolution.Results) != 2 {
		t.Fatalf("n results = %d/%d", resolved.Resolution.MatchedCount, len(resolved.Resolution.Results))
	}
	if resolved.Resolution.SnapshotID != snapshot {
		t.Fatalf("snapshot changed")
	}
	expectedID, _ := root.ID()
	if resolved.Stored.ContextRootID != expectedID {
		t.Fatalf("context root id mismatch")
	}

	zero := makeRoot(t, "select attrs.project == \"missing\"", snapshot, nil, nil)
	if _, err := s.SaveContextRoot("zero", zero, nil, false); err != nil {
		t.Fatalf("save zero: %v", err)
	}
	resolved, err = s.ResolveContext("zero", nil, auth.Root(), limits.Default(), s.ClockNowNS())
	if err != nil || resolved.Resolution.MatchedCount != 0 {
		t.Fatalf("zero = %v, %v", resolved, err)
	}

	one := makeRoot(t, "select attrs.project == \"other\"", snapshot, nil, nil)
	if _, err := s.SaveContextRoot("one", one, nil, false); err != nil {
		t.Fatalf("save one: %v", err)
	}
	resolved, err = s.ResolveContext("one", nil, auth.Root(), limits.Default(), s.ClockNowNS())
	if err != nil || resolved.Resolution.MatchedCount != 1 {
		t.Fatalf("one = %v, %v", resolved, err)
	}

	out := filepath.Join(dir, "out")
	report, err := s.MaterializeContext("demo", out, nil, auth.Root(), limits.Default(), s.ClockNowNS())
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if report.Files != 2 {
		t.Fatalf("materialized files = %d", report.Files)
	}
	if data, err := os.ReadFile(filepath.Join(out, "a.txt")); err != nil || string(data) != "alpha" {
		t.Fatalf("a.txt = %q, %v", data, err)
	}
	if data, err := os.ReadFile(filepath.Join(out, "b.txt")); err != nil || string(data) != "beta" {
		t.Fatalf("b.txt = %q, %v", data, err)
	}
	manifestBytes, err := os.ReadFile(report.ManifestPath)
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("manifest JSON: %v", err)
	}
	if manifest["context_root_id"] != expectedID.Hex() {
		t.Fatalf("manifest context id = %v", manifest["context_root_id"])
	}
	if len(manifest["files"].([]any)) != 2 {
		t.Fatalf("manifest files = %v", manifest["files"])
	}
}

func TestContextSnapshotPinningAndReplacement(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, fixedOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()
	createDemo(t, s, "a.txt", "alpha", "demo")
	snapshot, err := s.SnapshotCreate("s1")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	root := makeRoot(t, "select attrs.project == \"demo\"", snapshot, nil, nil)
	if _, err := s.SaveContextRoot("demo", root, nil, false); err != nil {
		t.Fatalf("save: %v", err)
	}
	createDemo(t, s, "b.txt", "beta", "demo")
	resolved, err := s.ResolveContext("demo", nil, auth.Root(), limits.Default(), s.ClockNowNS())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.Resolution.MatchedCount != 1 {
		t.Fatalf("pinned snapshot followed the live head: %d", resolved.Resolution.MatchedCount)
	}
	if _, err := s.SaveContextRoot("demo", root, nil, false); class(err) != werr.Exists {
		t.Fatalf("duplicate name error = %v", err)
	}
	before := s.Generation()
	second := makeRoot(t, "select true", snapshot, nil, nil)
	if _, err := s.SaveContextRoot("demo", second, nil, true); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if s.Generation() != before+1 {
		t.Fatalf("replacement was not one commit: %d -> %d", before, s.Generation())
	}
}

func TestContextCapabilityAndBudgetEnforcement(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, fixedOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()
	a := createDemo(t, s, "a.txt", "alpha", "demo")
	rootID, _ := s.ResolvePath("/")
	if _, err := s.RelationAdd(rootID, "derived_from", model.ObjectTarget(a), nil, nil); err != nil {
		t.Fatalf("relation: %v", err)
	}
	snapshot, err := s.SnapshotCreate("s1")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	relationRoot := makeRoot(t, "select relation(derived_from, obj:"+a.Hex()+")", snapshot, nil, nil)
	if _, err := s.SaveContextRoot("relation", relationRoot, nil, false); err != nil {
		t.Fatalf("save relation: %v", err)
	}
	scope, err := weftcontext.NewCapabilityScope("agent", []string{"default"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("capability: %v", err)
	}
	capability, err := auth.NewCapability(scope)
	if err != nil {
		t.Fatalf("new capability: %v", err)
	}
	if _, err := s.ResolveContext("relation", capability, auth.Root(), limits.Default(), s.ClockNowNS()); class(err) != werr.Unauthorized {
		t.Fatalf("predicate denial = %v", err)
	}
	other, err := weftcontext.NewCapabilityScope("agent", []string{"other"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("capability: %v", err)
	}
	otherCapability, _ := auth.NewCapability(other)
	if _, err := s.ResolveContext("relation", otherCapability, auth.Root(), limits.Default(), s.ClockNowNS()); class(err) != werr.Unauthorized {
		t.Fatalf("namespace denial = %v", err)
	}
	foreignRoot := makeRoot(t, "select true", snapshot, nil, nil)
	if _, err := s.SaveContextRoot("demo", foreignRoot, nil, false); err != nil {
		t.Fatalf("save demo: %v", err)
	}
	foreignID, _ := foreignRoot.ID()
	foreignHash := model.Hash32{}
	copy(foreignHash[:], []byte{0x11})
	_ = foreignID
	rootsOnly, err := weftcontext.NewCapabilityScope("agent", nil, []model.Hash32{foreignHash}, []string{"derived_from"}, nil, nil)
	if err != nil {
		t.Fatalf("roots capability: %v", err)
	}
	rootsCapability, _ := auth.NewCapability(rootsOnly)
	if _, err := s.ResolveContext("demo", rootsCapability, auth.Root(), limits.Default(), s.ClockNowNS()); class(err) != werr.Unauthorized {
		t.Fatalf("root denial = %v", err)
	}

	createDemo(t, s, "b.txt", "beta", "demo")
	snapshot2, err := s.SnapshotCreate("s2")
	if err != nil {
		t.Fatalf("snapshot2: %v", err)
	}
	max := uint64(1)
	limited := makeRoot(t, "select attrs.project == \"demo\"", snapshot2, nil, &weftcontext.Budget{MaxResults: &max})
	if _, err := s.SaveContextRoot("limited", limited, nil, false); err != nil {
		t.Fatalf("save limited: %v", err)
	}
	if _, err := s.ResolveContext("limited", nil, auth.Root(), limits.Default(), s.ClockNowNS()); class(err) != werr.LimitExceeded {
		t.Fatalf("budget overrun = %v", err)
	}
}

func TestCapabilityHashParticipatesInIdentity(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, fixedOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()
	createDemo(t, s, "a.txt", "alpha", "demo")
	snapshot, _ := s.SnapshotCreate("s1")
	plain := makeRoot(t, "select attrs.project == \"demo\"", snapshot, nil, nil)
	scope, err := weftcontext.NewCapabilityScope("agent", []string{"default"}, nil, []string{"tagged_as"}, nil, nil)
	if err != nil {
		t.Fatalf("capability: %v", err)
	}
	capability, _ := auth.NewCapability(scope)
	parsed, _ := selector.Parse("select attrs.project == \"demo\"")
	bound, err := weftcontext.NewContextRoot(parsed, snapshot, weftcontext.DefaultResolver, nil, &capability.Hash, nil)
	if err != nil {
		t.Fatalf("bound root: %v", err)
	}
	plainID, _ := plain.ID()
	boundID, _ := bound.ID()
	if plainID == boundID {
		t.Fatalf("capability hash did not change ContextRootId")
	}
	if _, err := s.SaveContextRoot("bound", bound, scope, false); err != nil {
		t.Fatalf("save bound: %v", err)
	}
	storedCapability, err := s.LoadCapability(capability.Hash)
	if err != nil || storedCapability.Principal != "agent" {
		t.Fatalf("stored capability = %v, %v", storedCapability, err)
	}
	resolved, err := s.ResolveContext("bound", nil, auth.Root(), limits.Default(), s.ClockNowNS())
	if err != nil || resolved.CapabilityHash == nil || *resolved.CapabilityHash != capability.Hash {
		t.Fatalf("bound resolve = %v, %v", resolved, err)
	}
}

func TestCausalBytesOnlyAndCausalExact(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, fixedOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()
	parent := createDemo(t, s, "parent.txt", "parent", "demo")
	parentRecord, _ := s.ObjectMeta(parent)
	child := createDemo(t, s, "child.txt", "child", "demo")
	childRecord, _ := s.ObjectMeta(child)
	expected, err := model.DeriveVersionID(childRecord.ID, childRecord.Content, childRecord.Size, childRecord.MtimeNS, nil)
	if err != nil || childRecord.Version != expected {
		t.Fatalf("bytes_only VersionId changed: %v", err)
	}
	version, err := s.WriteFileCausal(child, 0, []byte("child"), []model.Hash32{parent})
	if err != nil {
		t.Fatalf("causal write: %v", err)
	}
	record, _ := s.ObjectMeta(child)
	if record.Version != version || record.Version == childRecord.Version {
		t.Fatalf("causal VersionId did not change")
	}
	closure, err := model.ObjectCausalClosure(record)
	if err != nil || closure == nil {
		t.Fatalf("causal closure: %v", err)
	}
	if len(closure.Parents) != 1 || closure.Parents[0] != parentRecord.Version {
		t.Fatalf("parents = %v", closure.Parents)
	}
	// The closure blob is content addressed.
	id, _ := closure.ID()
	if _, err := store.ReadBlobVerified(s.Root(), store.BlobManifest, id, hash.DomainCausal); err != nil {
		t.Fatalf("closure blob: %v", err)
	}
}

func TestCausalTransitiveAndCycle(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, fixedOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()
	a := createDemo(t, s, "a.txt", "a", "demo")
	aRecord, _ := s.ObjectMeta(a)
	b := createDemo(t, s, "b.txt", "b", "demo")
	bVersion, err := s.WriteFileCausal(b, 0, []byte("b"), []model.Hash32{a})
	if err != nil {
		t.Fatalf("b causal: %v", err)
	}
	c := createDemo(t, s, "c.txt", "c", "demo")
	if _, err := s.WriteFileCausal(c, 0, []byte("c"), []model.Hash32{b}); err != nil {
		t.Fatalf("c causal: %v", err)
	}
	cRecord, _ := s.ObjectMeta(c)
	closure, _ := model.ObjectCausalClosure(cRecord)
	if len(closure.Parents) != 1 || closure.Parents[0] != bVersion {
		t.Fatalf("c parents = %v", closure.Parents)
	}
	expected := []model.Hash32{aRecord.Version, bVersion}
	if expected[0].Hex() > expected[1].Hex() {
		expected[0], expected[1] = expected[1], expected[0]
	}
	if len(closure.Closure) != 2 || closure.Closure[0] != expected[0] || closure.Closure[1] != expected[1] {
		t.Fatalf("c closure = %v, want %v", closure.Closure, expected)
	}

	// Synthetic cycle A -> B -> A terminates.
	state := model.NewState()
	cycleAVersion := mustHash(t, "11"+strings.Repeat("00", 31))
	cycleBVersion := mustHash(t, "22"+strings.Repeat("00", 31))
	aClosure, err := weftcontext.NewCausalClosure([]model.Hash32{cycleBVersion}, []model.Hash32{cycleAVersion, cycleBVersion})
	if err != nil {
		t.Fatalf("a closure: %v", err)
	}
	bClosure, err := weftcontext.NewCausalClosure([]model.Hash32{cycleAVersion}, []model.Hash32{cycleAVersion, cycleBVersion})
	if err != nil {
		t.Fatalf("b closure: %v", err)
	}
	aID := mustHash(t, "01"+strings.Repeat("00", 31))
	bID := mustHash(t, "02"+strings.Repeat("00", 31))
	aAttrs := map[string]wcb.Value{}
	model.ApplyCausalAttrs(aAttrs, aClosure, weftcontext.CausalExact, mustHashID(t, aClosure))
	bAttrs := map[string]wcb.Value{}
	model.ApplyCausalAttrs(bAttrs, bClosure, weftcontext.CausalExact, mustHashID(t, bClosure))
	state.Objects[aID] = model.ObjectRecord{ID: aID, Kind: model.KindFile, Version: cycleAVersion, Content: model.ContentHash([]byte("a")), Size: 1, Attrs: aAttrs}
	state.Objects[bID] = model.ObjectRecord{ID: bID, Kind: model.KindFile, Version: cycleBVersion, Content: model.ContentHash([]byte("b")), Size: 1, Attrs: bAttrs}
	computed, err := store.ComputeCausalClosure(state, []model.Hash32{aID}, limits.Default())
	if err != nil {
		t.Fatalf("cycle closure: %v", err)
	}
	if len(computed.Parents) != 1 || computed.Parents[0] != cycleAVersion {
		t.Fatalf("cycle parents = %v", computed.Parents)
	}
	if len(computed.Closure) != 2 {
		t.Fatalf("cycle closure = %v", computed.Closure)
	}
}

func TestMaterializationMismatchLeavesNoOutput(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, fixedOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()
	a := createDemo(t, s, "a.txt", "alpha", "demo")
	snapshot, _ := s.SnapshotCreate("s1")
	root := makeRoot(t, "select attrs.project == \"demo\"", snapshot, nil, nil)
	if _, err := s.SaveContextRoot("demo", root, nil, false); err != nil {
		t.Fatalf("save: %v", err)
	}
	record, _ := s.ObjectMeta(a)
	manifest, err := store.ReadManifest(s.Root(), record.Content)
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	chunkPath := store.ObjectPath(s.Root(), manifest.Chunks[0].Hash)
	data, err := os.ReadFile(chunkPath)
	if err != nil {
		t.Fatalf("read chunk: %v", err)
	}
	data[0] ^= 0xff
	if err := os.WriteFile(chunkPath, data, 0o644); err != nil {
		t.Fatalf("corrupt chunk: %v", err)
	}
	out := filepath.Join(dir, "out")
	if _, err := s.MaterializeContext("demo", out, nil, auth.Root(), limits.Default(), s.ClockNowNS()); class(err) != werr.Corrupt {
		t.Fatalf("materialization mismatch = %v", err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("failed materialization left output behind")
	}
}

func TestGoldenCausalVectorsMatchBothLanguages(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "conformance", "context", "v1", "causal_versions.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vector struct {
		Closure struct {
			Parents      []string `json:"parents"`
			Closure      []string `json:"closure"`
			CanonicalHex string   `json:"canonical_hex"`
			CausalHash   string   `json:"causal_hash"`
		} `json:"closure"`
		Vectors []struct {
			Name               string  `json:"name"`
			Object             string  `json:"object"`
			Content            string  `json:"content"`
			Size               uint64  `json:"size"`
			MtimeNS            int64   `json:"mtime_ns"`
			Parent             *string `json:"parent"`
			BytesOnlyVersionID string  `json:"bytes_only_version_id"`
			CausalVersionID    string  `json:"causal_exact_version_id"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	parents := make([]model.Hash32, 0, len(vector.Closure.Parents))
	for _, text := range vector.Closure.Parents {
		parents = append(parents, mustHash(t, text))
	}
	entries := make([]model.Hash32, 0, len(vector.Closure.Closure))
	for _, text := range vector.Closure.Closure {
		entries = append(entries, mustHash(t, text))
	}
	record, err := weftcontext.NewCausalClosure(parents, entries)
	if err != nil {
		t.Fatalf("closure: %v", err)
	}
	canonical, err := record.CanonicalBytes(limits.Default())
	if err != nil || hexEncode(canonical) != vector.Closure.CanonicalHex {
		t.Fatalf("closure canonical bytes: %v", err)
	}
	causalHash, err := record.ID()
	if err != nil || causalHash.Hex() != vector.Closure.CausalHash {
		t.Fatalf("causal hash = %v, %v", causalHash, err)
	}
	for _, testCase := range vector.Vectors {
		object := mustHash(t, testCase.Object)
		content := mustHash(t, testCase.Content)
		var parent *model.Hash32
		if testCase.Parent != nil {
			value := mustHash(t, *testCase.Parent)
			parent = &value
		}
		bytesOnly, err := model.DeriveVersionIDWithIdentity(object, content, testCase.Size, testCase.MtimeNS, parent, weftcontext.BytesOnly, nil)
		if err != nil || bytesOnly.Hex() != testCase.BytesOnlyVersionID {
			t.Fatalf("bytes_only %s = %s, %v", testCase.Name, bytesOnly.Hex(), err)
		}
		causal, err := model.DeriveVersionIDWithIdentity(object, content, testCase.Size, testCase.MtimeNS, parent, weftcontext.CausalExact, &causalHash)
		if err != nil || causal.Hex() != testCase.CausalVersionID {
			t.Fatalf("causal_exact %s = %s, %v", testCase.Name, causal.Hex(), err)
		}
	}
}

func hexEncode(data []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(data)*2)
	for _, b := range data {
		out = append(out, digits[b>>4], digits[b&0x0f])
	}
	return string(out)
}

func mustHashID(t *testing.T, closure *weftcontext.CausalClosure) model.Hash32 {
	t.Helper()
	id, err := closure.ID()
	if err != nil {
		t.Fatalf("closure id: %v", err)
	}
	return id
}
