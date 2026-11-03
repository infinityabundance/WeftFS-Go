package store_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	weftcontext "github.com/infinityabundance/WeftCodec-Go/context"
	"github.com/infinityabundance/WeftCodec-Go/limits"
	"github.com/infinityabundance/WeftCodec-Go/selector"
	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/auth"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
)

func rustJSON(t *testing.T, bin, dir string, args ...string) map[string]any {
	t.Helper()
	full := append([]string{"--store", dir}, args...)
	full = append(full, "--json")
	output := runRust(t, bin, full...)
	var parsed map[string]any
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("rust JSON %v: %v\n%s", args, err, output)
	}
	return parsed
}

func TestContextCausalCapabilityHandoffRustThenGo(t *testing.T) {
	bin := rustBinary(t)
	dir := t.TempDir()
	ts := "1700000000000000000"
	runRust(t, bin, "--store", dir, "--fixed-timestamp-ns", ts, "init")
	parent := rustJSON(t, bin, dir, "create", "/parent.txt", "--text", "parent", "--attr", "project=demo", "--seed", "handoff-parent")
	child := rustJSON(t, bin, dir, "create", "/child.txt", "--text", "child", "--attr", "project=demo", "--seed", "handoff-child", "--causal", parent["object_id"].(string))
	_ = child
	snapshot := rustJSON(t, bin, dir, "snapshot", "create", "s1")
	capabilityPath := filepath.Join(dir, "cap.json")
	capabilityJSON := `{
	  "schema": "weft.capability.v1",
	  "principal": "handoff-agent",
	  "namespaces": ["default"],
	  "predicates": ["tagged_as"],
	  "budget": {"max_results": 10}
	}`
	if err := os.WriteFile(capabilityPath, []byte(capabilityJSON), 0o644); err != nil {
		t.Fatalf("capability file: %v", err)
	}
	rustContext := rustJSON(t, bin, dir, "context", "create", "--name", "demo", "--selector", "select attrs.project == \"demo\"", "--snapshot", snapshot["snapshot_id"].(string))
	rustBound := rustJSON(t, bin, dir, "context", "create", "--name", "bound", "--selector", "select attrs.project == \"demo\"", "--snapshot", snapshot["snapshot_id"].(string), "--capability", capabilityPath)
	rustCausal := rustJSON(t, bin, dir, "causal", "show", "/child.txt")

	s, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("go open rust store: %v", err)
	}
	defer s.Close()

	stored, err := s.LoadContextRoot("demo")
	if err != nil {
		t.Fatalf("go load demo: %v", err)
	}
	if stored.ContextRootID.Hex() != rustContext["context_root_id"] {
		t.Fatalf("context id mismatch: go=%s rust=%v", stored.ContextRootID.Hex(), rustContext["context_root_id"])
	}
	resolved, err := s.ResolveContext("demo", nil, auth.Root(), limits.Default(), s.ClockNowNS())
	if err != nil {
		t.Fatalf("go resolve demo: %v", err)
	}
	if resolved.Resolution.MatchedCount != 2 {
		t.Fatalf("go matched = %d", resolved.Resolution.MatchedCount)
	}
	childID, err := s.ResolvePath("/child.txt")
	if err != nil {
		t.Fatalf("resolve child: %v", err)
	}
	childRecord, _ := s.ObjectMeta(childID)
	if childRecord.Version.Hex() != rustCausal["version_id"] {
		t.Fatalf("causal version mismatch: go=%s rust=%v", childRecord.Version.Hex(), rustCausal["version_id"])
	}
	closure, err := model.ObjectCausalClosure(childRecord)
	if err != nil || closure == nil {
		t.Fatalf("go causal closure: %v", err)
	}
	parentID, _ := s.ResolvePath("/parent.txt")
	parentRecord, _ := s.ObjectMeta(parentID)
	if len(closure.Parents) != 1 || closure.Parents[0] != parentRecord.Version {
		t.Fatalf("go closure parents = %v", closure.Parents)
	}

	bound, err := s.LoadContextRoot("bound")
	if err != nil {
		t.Fatalf("go load bound: %v", err)
	}
	if bound.Root.CapabilityHash == nil {
		t.Fatalf("bound root has no capability hash")
	}
	scope, err := s.LoadCapability(*bound.Root.CapabilityHash)
	if err != nil {
		t.Fatalf("go load stored capability: %v", err)
	}
	if scope.Principal != "handoff-agent" {
		t.Fatalf("capability principal = %s", scope.Principal)
	}
	resolvedBound, err := s.ResolveContext("bound", nil, auth.Root(), limits.Default(), s.ClockNowNS())
	if err != nil {
		t.Fatalf("go resolve bound: %v", err)
	}
	if resolvedBound.Resolution.MatchedCount != 2 {
		t.Fatalf("bound matched = %d", resolvedBound.Resolution.MatchedCount)
	}
	_ = rustBound
	report, err := s.Verify(true)
	if err != nil || !report.OK {
		t.Fatalf("go verify rust store: %v, problems=%v", err, report.Problems)
	}
}

func TestContextCausalCapabilityHandoffGoThenRust(t *testing.T) {
	bin := rustBinary(t)
	dir := t.TempDir()
	ts := int64(1_700_000_000_000_000_000)
	opts := store.DefaultOptions()
	opts.FixedTimestampNS = &ts
	s, err := store.Init(dir, opts)
	if err != nil {
		t.Fatalf("go init: %v", err)
	}
	root, _ := s.ResolvePath("/")
	parentID, err := s.CreateFileSeeded(root, []byte("parent.txt"), []byte("parent"), 0o644, 0, 0, map[string]wcb.Value{"project": wcb.TextValue("demo")}, []byte("handoff-parent"))
	if err != nil {
		t.Fatalf("go create parent: %v", err)
	}
	childID, err := s.CreateFileSeededCausal(root, []byte("child.txt"), []byte("child"), 0o644, 0, 0, map[string]wcb.Value{"project": wcb.TextValue("demo")}, []byte("handoff-child"), []model.Hash32{parentID})
	if err != nil {
		t.Fatalf("go create child: %v", err)
	}
	childRecord, _ := s.ObjectMeta(childID)
	snapshot, err := s.SnapshotCreate("s1")
	if err != nil {
		t.Fatalf("go snapshot: %v", err)
	}
	parsed, _ := selector.Parse("select attrs.project == \"demo\"")
	rootContext, err := weftcontext.NewContextRoot(parsed, snapshot, weftcontext.DefaultResolver, nil, nil, nil)
	if err != nil {
		t.Fatalf("go context root: %v", err)
	}
	if _, err := s.SaveContextRoot("demo", rootContext, nil, false); err != nil {
		t.Fatalf("go save demo: %v", err)
	}
	maxResults := uint64(10)
	scope, err := weftcontext.NewCapabilityScope("handoff-agent", []string{"default"}, nil, []string{"tagged_as"}, &weftcontext.Budget{MaxResults: &maxResults}, nil)
	if err != nil {
		t.Fatalf("go capability: %v", err)
	}
	capability, _ := auth.NewCapability(scope)
	bound, err := weftcontext.NewContextRoot(parsed, snapshot, weftcontext.DefaultResolver, nil, &capability.Hash, &weftcontext.Budget{MaxResults: &maxResults})
	if err != nil {
		t.Fatalf("go bound root: %v", err)
	}
	if _, err := s.SaveContextRoot("bound", bound, scope, false); err != nil {
		t.Fatalf("go save bound: %v", err)
	}
	if _, err := s.ResolveContext("demo", nil, auth.Root(), limits.Default(), s.ClockNowNS()); err != nil {
		t.Fatalf("go resolve: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("go close: %v", err)
	}

	rustVerify := runRust(t, bin, "--store", dir, "verify", "--full")
	if !strings.Contains(rustVerify, "ok=true") {
		t.Fatalf("rust verify --full failed:\n%s", rustVerify)
	}
	rustCausal := rustJSON(t, bin, dir, "causal", "show", "/child.txt")
	if rustCausal["version_id"] != childRecord.Version.Hex() {
		t.Fatalf("rust causal version = %v, go = %s", rustCausal["version_id"], childRecord.Version.Hex())
	}
	rootID, _ := rootContext.ID()
	rustContext := rustJSON(t, bin, dir, "context", "show", "demo")
	if rustContext["context_root_id"] != rootID.Hex() {
		t.Fatalf("rust context id = %v, go = %s", rustContext["context_root_id"], rootID.Hex())
	}
	rustResolved := rustJSON(t, bin, dir, "context", "resolve", "demo")
	if rustResolved["matched_count"].(float64) != 2 {
		t.Fatalf("rust matched_count = %v", rustResolved["matched_count"])
	}
	rustBound := rustJSON(t, bin, dir, "context", "resolve", "bound")
	if rustBound["matched_count"].(float64) != 2 {
		t.Fatalf("rust bound matched_count = %v", rustBound["matched_count"])
	}
	if rustBound["capability_hash"] != capability.Hash.Hex() {
		t.Fatalf("rust bound capability hash = %v", rustBound["capability_hash"])
	}
}
