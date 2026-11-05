package store_test

// Branching time-travel courts (P5a, part 2), Go parity plus both-direction
// cross-language reads.

import (
	"os"
	"os/exec"
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
	"github.com/infinityabundance/WeftFS-Go/werr"
)

func branchStore(t *testing.T, dir string) *store.Store {
	t.Helper()
	s, err := store.Init(dir, quotaOptions(1024))
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	return s
}

func createAt(t *testing.T, s *store.Store, path string, body []byte, attrs map[string]wcb.Value) model.Hash32 {
	t.Helper()
	index := strings.LastIndex(path, "/")
	parent, name := "/", path[index+1:]
	if index > 0 {
		parent = path[:index]
	}
	parentID, err := s.ResolvePath(parent)
	if err != nil {
		t.Fatalf("resolve %s: %v", parent, err)
	}
	id, err := s.CreateFile(parentID, []byte(name), body, 0o644, 0, 0, attrs)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	return id
}

func TestSnapshotBranchPinsSourceAndLaterWritesDoNotMoveIt(t *testing.T) {
	dir := t.TempDir()
	s := branchStore(t, dir)
	defer s.Close()
	createAt(t, s, "/history.txt", []byte("version-1"), nil)
	if _, err := s.SnapshotCreate("s1"); err != nil {
		t.Fatalf("snapshot s1: %v", err)
	}
	id, _ := s.ResolvePath("/history.txt")
	for version := 2; version <= 5; version++ {
		if _, err := s.WriteFile(id, 0, []byte("version-"+string(rune('0'+version)))); err != nil {
			t.Fatalf("write %d: %v", version, err)
		}
	}
	source, err := s.SnapshotCreate("s2")
	if err != nil {
		t.Fatalf("snapshot s2: %v", err)
	}
	sourceState, err := s.StateAt(source)
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	sourceID, err := sourceState.Lookup(model.RootID, []byte("history.txt"))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	branch, err := s.SnapshotBranch("s2", "branch-a")
	if err != nil {
		t.Fatalf("branch: %v", err)
	}
	if branch != source {
		t.Fatalf("branch commit %s != source %s", branch.Hex(), source.Hex())
	}
	for version := 6; version <= 9; version++ {
		if _, err := s.WriteFile(id, 0, []byte("version-"+string(rune('0'+version)))); err != nil {
			t.Fatalf("later write %d: %v", version, err)
		}
	}
	data, err := s.ReadObjectAt(&source, sourceID)
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	if string(data) != "version-5" {
		t.Fatalf("source changed to %q", data)
	}
	refs := map[string]model.Hash32{}
	list := s.SnapshotList()
	for _, entry := range list {
		refs[entry.Name] = entry.Commit
	}
	if refs["s2"] != source || refs["branch-a"] != source {
		t.Fatalf("refs moved: %+v", refs)
	}
	if live, _ := s.ResolvePath("/history.txt"); true {
		if data, err := s.ReadObject(live); err != nil || string(data) != "version-9" {
			t.Fatalf("live bytes = %q err=%v", data, err)
		}
	}
	report, err := s.Verify(true)
	if err != nil || !report.OK {
		t.Fatalf("verify: %v %+v", err, report)
	}
}

func TestMergeDisjointBranches(t *testing.T) {
	dir := t.TempDir()
	s := branchStore(t, dir)
	defer s.Close()
	createAt(t, s, "/left.txt", []byte("left"), nil)
	left, err := s.SnapshotCreate("left")
	if err != nil {
		t.Fatalf("snapshot left: %v", err)
	}
	createAt(t, s, "/right.txt", []byte("right"), nil)
	right, err := s.SnapshotCreate("right")
	if err != nil {
		t.Fatalf("snapshot right: %v", err)
	}
	root, _ := s.ResolvePath("/")
	if err := s.Unlink(root, []byte("right.txt")); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	before := s.Generation()
	report, err := s.MergeBranches("left", "right")
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if report.Left != left || report.Right != right || report.Paths != 2 || report.AddedObjects != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.Generation != before+1 {
		t.Fatalf("generation = %d, want %d", report.Generation, before+1)
	}
	id, err := s.ResolvePath("/right.txt")
	if err != nil {
		t.Fatalf("merged path missing: %v", err)
	}
	if data, err := s.ReadObject(id); err != nil || string(data) != "right" {
		t.Fatalf("merged bytes = %q err=%v", data, err)
	}
	generation, head := s.Generation(), s.Head()
	repeat, err := s.MergeBranches("left", "right")
	if err != nil {
		t.Fatalf("repeat merge: %v", err)
	}
	if repeat.AddedObjects != 0 || repeat.AddedEntries != 0 || s.Generation() != generation || s.Head() != head {
		t.Fatalf("repeat merge was not idempotent: %+v", repeat)
	}
	if r, err := s.Verify(true); err != nil || !r.OK {
		t.Fatalf("verify: %v %+v", err, r)
	}
}

func TestMergeConflictNamesThePath(t *testing.T) {
	dir := t.TempDir()
	s := branchStore(t, dir)
	defer s.Close()
	id := createAt(t, s, "/conflict.txt", []byte("one"), nil)
	if _, err := s.SnapshotCreate("one"); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if _, err := s.WriteFile(id, 0, []byte("two")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := s.SnapshotCreate("two"); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	generation, head := s.Generation(), s.Head()
	_, err := s.MergeBranches("one", "two")
	if !werr.Is(err, werr.Conflict) {
		t.Fatalf("class = %v, want Conflict", werr.ClassOf(err))
	}
	if !strings.Contains(err.Error(), "/conflict.txt") {
		t.Fatalf("conflict does not name the path: %v", err)
	}
	if s.Generation() != generation || s.Head() != head {
		t.Fatal("failed merge published a commit")
	}
	if data, _ := s.ReadObject(id); string(data) != "two" {
		t.Fatalf("live bytes changed to %q", data)
	}
}

func TestMergeRefusesToOverwriteTheLiveHead(t *testing.T) {
	dir := t.TempDir()
	s := branchStore(t, dir)
	defer s.Close()
	createAt(t, s, "/head.txt", []byte("branch"), nil)
	branch, err := s.SnapshotCreate("branch")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	id, _ := s.ResolvePath("/head.txt")
	if _, err := s.WriteFile(id, 0, []byte("live!!")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := s.MergeBranches("branch", branch.Hex()); !werr.Is(err, werr.Conflict) {
		t.Fatalf("class = %v, want Conflict", werr.ClassOf(err))
	}
	if data, _ := s.ReadObject(id); string(data) != "live!!" {
		t.Fatalf("live bytes changed to %q", data)
	}
}

func TestContextBranchPinsForkAndRecordsLineage(t *testing.T) {
	dir := t.TempDir()
	s := branchStore(t, dir)
	defer s.Close()
	root, _ := s.ResolvePath("/")
	if _, err := s.Mkdir(root, []byte("logs"), 0o755, 0, 0); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	attrs := map[string]wcb.Value{"task": wcb.TextValue("agent-43")}
	for index := 0; index < 3; index++ {
		createAt(t, s, "/logs/a"+string(rune('0'+index))+".txt", []byte("line"), attrs)
	}
	fork, err := s.SnapshotCreate("s-fork")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	parsed, err := selector.Parse("select attrs.task == \"agent-43\"")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	sourceRoot, err := weftcontext.NewContextRoot(parsed, fork, weftcontext.DefaultResolver, nil, nil, nil)
	if err != nil {
		t.Fatalf("context root: %v", err)
	}
	if _, err := s.SaveContextRoot("base", sourceRoot, nil, false); err != nil {
		t.Fatalf("save context: %v", err)
	}
	task := "agent-43"
	branch, err := s.BranchContextRoot("base", "by:task=agent-43", &task, nil, false)
	if err != nil {
		t.Fatalf("branch context: %v", err)
	}
	if branch.Root.Snapshot != fork {
		t.Fatalf("branch snapshot %s != fork %s", branch.Root.Snapshot.Hex(), fork.Hex())
	}
	found := false
	for _, relation := range s.CurrentState().Relations {
		if relation.Predicate != store.ContextLineagePredicate {
			continue
		}
		found = true
		if relation.Target.Value.Kind != wcb.Text || relation.Target.Value.Str != "base" {
			t.Fatalf("unexpected lineage target: %+v", relation.Target.Value)
		}
		if relation.Attrs[store.ContextLineageContextAttr].Str != "by:task=agent-43" {
			t.Fatalf("lineage does not name the derived context: %+v", relation.Attrs)
		}
	}
	if !found {
		t.Fatal("lineage relation missing")
	}
	// A later write does not move the pinned branch view.
	createAt(t, s, "/logs/late.txt", []byte("late"), attrs)
	resolved, err := s.ResolveContext("by:task=agent-43", nil, auth.Root(), limits.Default(), 0)
	if err != nil {
		t.Fatalf("resolve context: %v", err)
	}
	if resolved.Resolution.MatchedCount != 3 {
		t.Fatalf("branch matched %d, want the pinned 3", resolved.Resolution.MatchedCount)
	}
}

// ---------------------------------------------------------------------------
// Cross-language courts (skipped when the Rust oracle is unavailable)
// ---------------------------------------------------------------------------

func runRustAllowFailure(t *testing.T, bin string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// rustUsable probes the Rust oracle in this court. The Go court has no
// libfuse3, so the Rust binary may be present but not loadable; that is a skip,
// never a failure of the Go implementation.
func rustUsable(t *testing.T, bin string) {
	t.Helper()
	cmd := exec.Command(bin, "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("Rust oracle is not runnable in this court: %v\n%s", err, output)
	}
}

func TestRustWritesQuotaAndBranchGoReads(t *testing.T) {
	bin := rustBinary(t)
	rustUsable(t, bin)
	dir := t.TempDir()
	runRust(t, bin, "--store", dir, "--quota", "0:0:1048576:100", "init")
	runRust(t, bin, "--store", dir, "create", "/history.txt", "--text", "v1")
	runRust(t, bin, "--store", dir, "snapshot", "create", "s1")
	runRust(t, bin, "--store", dir, "write", "/history.txt", "--text", "v2-longer")
	runRust(t, bin, "--store", dir, "snapshot", "create", "s2")
	runRust(t, bin, "--store", dir, "snapshot", "branch", "s2", "branch-go")

	s, err := store.OpenWithOptions(dir, store.ReadWrite, quotaOptions(1024))
	if err != nil {
		t.Fatalf("go open: %v", err)
	}
	defer s.Close()
	if !s.QuotaEnforced() {
		t.Fatal("go did not load the Rust-written policy")
	}
	usage := s.QuotaUsage(store.PosixPrincipal(0, 0))
	if usage.UsedObjects == 0 || usage.UsedBytes == 0 {
		t.Fatalf("go usage is empty: %+v", usage)
	}
	branch := s.CurrentState().Snapshots["branch-go"]
	state, err := s.StateAt(branch)
	if err != nil {
		t.Fatalf("state at branch: %v", err)
	}
	id, err := state.Lookup(model.RootID, []byte("history.txt"))
	if err != nil {
		t.Fatalf("branch path missing: %v", err)
	}
	data, err := s.ReadObjectAt(&branch, id)
	if err != nil || string(data) != "v2-longer" {
		t.Fatalf("branch bytes = %q err=%v", data, err)
	}
	if report, err := s.Verify(true); err != nil || !report.OK {
		t.Fatalf("go verify: %v %+v", err, report)
	}

	// Go enforces the Rust-written budget: a 2 MiB write is refused.
	root, _ := s.ResolvePath("/")
	_, err = s.CreateFile(root, []byte("big.bin"), variedBytes(2*1024*1024), 0o644, 0, 0, nil)
	if !werr.Is(err, werr.BudgetExceeded) {
		t.Fatalf("go class = %v, want BudgetExceeded", werr.ClassOf(err))
	}
	// A small write is accepted and charged.
	if _, err := s.CreateFile(root, []byte("go.txt"), []byte("go"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("go small write: %v", err)
	}
	if after := s.QuotaUsage(store.PosixPrincipal(0, 0)); after.UsedObjects != usage.UsedObjects+1 {
		t.Fatalf("go usage did not advance: %+v -> %+v", usage, after)
	}
}

func TestGoWritesQuotaAndBranchRustVerifies(t *testing.T) {
	bin := rustBinary(t)
	rustUsable(t, bin)
	dir := t.TempDir()
	s, err := store.Init(dir, quotaOptions(1024, store.QuotaBudget{
		Principal: store.PosixPrincipal(0, 0), MaxNewBytes: 1 << 20, MaxObjects: 100,
	}))
	if err != nil {
		t.Fatalf("go init: %v", err)
	}
	createAt(t, s, "/history.txt", []byte("v1"), nil)
	if _, err := s.SnapshotCreate("s1"); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	id, _ := s.ResolvePath("/history.txt")
	if _, err := s.WriteFile(id, 0, []byte("v2-longer")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := s.SnapshotCreate("s2"); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if _, err := s.SnapshotBranch("s2", "branch-rs"); err != nil {
		t.Fatalf("branch: %v", err)
	}
	s.Close()

	verify := runRust(t, bin, "--store", dir, "verify", "--full")
	if !strings.Contains(verify, "ok=true") {
		t.Fatalf("rust verify: %s", verify)
	}
	list := runRust(t, bin, "--store", dir, "snapshot", "list")
	if !strings.Contains(list, "branch-rs") {
		t.Fatalf("rust snapshot list: %s", list)
	}
	show := runRust(t, bin, "--store", dir, "--json", "quota", "show", "--uid", "0", "--gid", "0")
	if !strings.Contains(show, "\"used_objects\"") || !strings.Contains(show, "\"configured\": true") {
		t.Fatalf("rust quota show: %s", show)
	}
	cat := runRust(t, bin, "--store", dir, "cat", "/history.txt")
	if cat != "v2-longer" {
		t.Fatalf("rust cat: %q", cat)
	}
	// Rust enforces the Go-written budget.
	big := filepath.Join(dir, "..", "big-"+filepath.Base(dir)+".bin")
	if err := os.WriteFile(big, variedBytes(2*1024*1024), 0o644); err != nil {
		t.Fatalf("write big: %v", err)
	}
	defer os.Remove(big)
	output, err := runRustAllowFailure(t, bin, "--store", dir, "create", "/big.bin", "--file", big)
	if err == nil {
		t.Fatalf("rust accepted an over-budget write: %s", output)
	}
	if !strings.Contains(output, "BudgetExceeded") || !strings.Contains(output, "write budget exceeded") {
		t.Fatalf("rust denial: %s", output)
	}
}
