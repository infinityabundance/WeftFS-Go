package fusefs_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	weftcontext "github.com/infinityabundance/WeftCodec-Go/context"
	"github.com/infinityabundance/WeftCodec-Go/limits"
	"github.com/infinityabundance/WeftCodec-Go/selector"
	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/auth"
	"github.com/infinityabundance/WeftFS-Go/fusefs"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

var (
	identicalBytes = []byte("identical bytes, two object identities\n")
	otherBytes     = []byte("unrelated content\n")
)

func testOptions() store.Options {
	ts := int64(1_700_000_000_000_000_000)
	opts := store.DefaultOptions()
	opts.FixedTimestampNS = &ts
	return opts
}

func attrsFor(values map[string]string) map[string]wcb.Value {
	out := make(map[string]wcb.Value, len(values))
	for key, value := range values {
		out[key] = wcb.TextValue(value)
	}
	return out
}

func createSeeded(t *testing.T, s *store.Store, name string, bytesValue []byte, seed string, attrs map[string]wcb.Value) model.Hash32 {
	t.Helper()
	root, err := s.ResolvePath("/")
	if err != nil {
		t.Fatalf("resolve root: %v", err)
	}
	id, err := s.CreateFileSeeded(root, []byte(name), bytesValue, 0o644, 0, 0, attrs, []byte(seed))
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	return id
}

func saveContext(t *testing.T, s *store.Store, name, source string, snapshot model.Hash32) model.Hash32 {
	t.Helper()
	parsed, err := selector.Parse(source)
	if err != nil {
		t.Fatalf("parse selector: %v", err)
	}
	root, err := weftcontext.NewContextRoot(parsed, snapshot, weftcontext.DefaultResolver, nil, nil, nil)
	if err != nil {
		t.Fatalf("new context root: %v", err)
	}
	id, err := s.SaveContextRoot(name, root, nil, false)
	if err != nil {
		t.Fatalf("save context: %v", err)
	}
	return id
}

func contextMountFrom(t *testing.T, s *store.Store, name string) *fusefs.ContextMount {
	t.Helper()
	resolved, err := s.ResolveContext(name, nil, auth.Root(), limits.Default(), s.ClockNowNS())
	if err != nil {
		t.Fatalf("resolve context: %v", err)
	}
	results := make([]model.Hash32, 0, len(resolved.Resolution.Results))
	for _, result := range resolved.Resolution.Results {
		results = append(results, result.ObjectID)
	}
	return &fusefs.ContextMount{
		Name:          resolved.Stored.Name,
		ContextRootID: resolved.Stored.ContextRootID,
		Snapshot:      resolved.Stored.Root.Snapshot,
		SelectorID:    resolved.Resolution.SelectorID,
		Results:       results,
	}
}

func visibleNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir %s: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Name() == ".weft" {
			continue
		}
		names = append(names, entry.Name())
	}
	return names
}

func classOf(err error) werr.Kind {
	if typed, ok := err.(*werr.Error); ok {
		return typed.Kind
	}
	return ""
}

func TestContextMountListsAllResultsAndReadsExactBytes(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, testOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	alpha := createSeeded(t, s, "alpha.txt", identicalBytes, "alpha-seed", attrsFor(map[string]string{"project": "demo", "task": "agent-42"}))
	beta := createSeeded(t, s, "beta.txt", identicalBytes, "beta-seed", attrsFor(map[string]string{"project": "demo", "task": "agent-42"}))
	createSeeded(t, s, "other.txt", otherBytes, "other-seed", attrsFor(map[string]string{"project": "other"}))
	alphaRecord, _ := s.ObjectMeta(alpha)
	betaRecord, _ := s.ObjectMeta(beta)
	if alphaRecord.ID == betaRecord.ID {
		t.Fatalf("seeded object ids collided")
	}
	if alphaRecord.Content != betaRecord.Content {
		t.Fatalf("identical bytes have different content ids: %s vs %s", alphaRecord.Content.Hex(), betaRecord.Content.Hex())
	}
	snapshot, err := s.SnapshotCreate("s1")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	saveContext(t, s, "by-project", `select attrs.project == "demo"`, snapshot)
	cm := contextMountFrom(t, s, "by-project")
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	pin := snapshot
	m := mount(t, dir, store.ReadOnly, fusefs.Options{ReadOnly: true, Snapshot: &pin, Context: cm})
	names := visibleNames(t, m.mnt)
	if len(names) != 2 {
		t.Fatalf("context mount names = %v", names)
	}
	for _, name := range names {
		if !strings.Contains(name, "--") {
			t.Fatalf("name %q lacks the deterministic suffix", name)
		}
		data, err := os.ReadFile(filepath.Join(m.mnt, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if string(data) != string(identicalBytes) {
			t.Fatalf("%s = %q", name, data)
		}
	}
	if err := os.WriteFile(filepath.Join(m.mnt, "new.txt"), []byte("x"), 0o644); err == nil {
		t.Fatalf("write to a context mount succeeded")
	}
	existing := filepath.Join(m.mnt, names[0])
	handle, err := os.OpenFile(existing, os.O_WRONLY, 0)
	if err == nil {
		handle.Close()
		t.Fatalf("write-open of an existing context result succeeded")
	}
	if !errors.Is(err, syscall.EROFS) && !errors.Is(err, syscall.EACCES) {
		t.Fatalf("write-open error = %v, want EROFS/EACCES", err)
	}
}

func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}

func TestCapabilityScopedMountIsReadOnlyAndDeniesUnlistedRoots(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, testOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	createSeeded(t, s, "alpha.txt", []byte("alpha"), "alpha-seed", attrsFor(map[string]string{"project": "demo"}))
	snapshot, err := s.SnapshotCreate("s1")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	saveContext(t, s, "by-project", `select attrs.project == "demo"`, snapshot)
	cm := contextMountFrom(t, s, "by-project")

	allowScope, err := store.ParseCapabilityText(`{"schema":"weft.capability.v1","principal":"agent","namespaces":["default"],"predicates":[]}`)
	if err != nil {
		t.Fatalf("allow capability: %v", err)
	}
	allow, err := auth.NewCapability(allowScope)
	if err != nil {
		t.Fatalf("new capability: %v", err)
	}
	denyScope, err := store.ParseCapabilityText(`{"schema":"weft.capability.v1","principal":"agent","namespaces":["default"],"predicates":[],"roots":["1111111111111111111111111111111111111111111111111111111111111111"]}`)
	if err != nil {
		t.Fatalf("deny capability: %v", err)
	}
	deny, err := auth.NewCapability(denyScope)
	if err != nil {
		t.Fatalf("new deny capability: %v", err)
	}
	if _, err := s.ResolveContext("by-project", deny, auth.Root(), limits.Default(), s.ClockNowNS()); classOf(err) != werr.Unauthorized {
		t.Fatalf("denied resolve = %v, want Unauthorized", err)
	}
	if _, err := s.ResolveContext("by-project", allow, auth.Root(), limits.Default(), s.ClockNowNS()); err != nil {
		t.Fatalf("allowed resolve: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	pin := snapshot
	m := mount(t, dir, store.ReadOnly, fusefs.Options{
		ReadOnly: true, Snapshot: &pin, Context: cm, Capability: allow,
	})
	names := visibleNames(t, m.mnt)
	if len(names) != 1 {
		t.Fatalf("capability mount names = %v", names)
	}
	if err := os.WriteFile(filepath.Join(m.mnt, "blocked"), []byte("x"), 0o644); err == nil {
		t.Fatalf("write to a capability-scoped mount succeeded")
	}
}

func TestAtSelectsLatestCommitAndBeforeFirstFails(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, store.DefaultOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	createSeeded(t, s, "first.txt", []byte("first"), "first-seed", attrsFor(map[string]string{"stage": "one"}))
	between := time.Now().UnixNano()
	time.Sleep(20 * time.Millisecond)
	createSeeded(t, s, "second.txt", []byte("second"), "second-seed", attrsFor(map[string]string{"stage": "two"}))
	head := s.Head()
	selected, err := s.CommitAtOrBefore(head, between)
	if err != nil {
		t.Fatalf("commit at or before: %v", err)
	}
	if selected == nil {
		t.Fatalf("no commit selected between the two writes")
	}
	if selected.Commit == head {
		t.Fatalf("selection returned the head, not the earlier commit")
	}
	pinned, err := s.StateAt(selected.Commit)
	if err != nil {
		t.Fatalf("state at selection: %v", err)
	}
	if _, ok := pinned.Objects[mustPath(t, s, "/first.txt")]; !ok {
		t.Fatalf("selected state is missing first.txt")
	}
	if _, ok := pinned.Objects[mustPath(t, s, "/second.txt")]; ok {
		t.Fatalf("selected state contains second.txt")
	}
	none, err := s.CommitAtOrBefore(head, 0)
	if err != nil {
		t.Fatalf("commit at epoch: %v", err)
	}
	if none != nil {
		t.Fatalf("epoch selected %+v, want nil", none)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	commit := selected.Commit
	m := mount(t, dir, store.ReadOnly, fusefs.Options{ReadOnly: true, Snapshot: &commit})
	names := visibleNames(t, m.mnt)
	if len(names) != 1 || names[0] != "first.txt" {
		t.Fatalf("at mount names = %v", names)
	}
	if data, err := os.ReadFile(filepath.Join(m.mnt, "first.txt")); err != nil || string(data) != "first" {
		t.Fatalf("first.txt = %q, %v", data, err)
	}
}

func mustPath(t *testing.T, s *store.Store, path string) model.Hash32 {
	t.Helper()
	id, err := s.ResolvePath(path)
	if err != nil {
		t.Fatalf("resolve %s: %v", path, err)
	}
	return id
}

func TestThreeSimultaneousMountsServeDifferentRoots(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, store.DefaultOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	createSeeded(t, s, "alpha.txt", identicalBytes, "alpha-seed", attrsFor(map[string]string{"project": "demo", "task": "agent-42"}))
	createSeeded(t, s, "beta.txt", identicalBytes, "beta-seed", attrsFor(map[string]string{"project": "demo", "task": "agent-42"}))
	createSeeded(t, s, "other.txt", otherBytes, "other-seed", attrsFor(map[string]string{"project": "other", "task": "agent-99"}))
	s1, err := s.SnapshotCreate("s1")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	saveContext(t, s, "by-task", `select attrs.task == "agent-42"`, s1)
	saveContext(t, s, "by-project", `select attrs.project == "demo"`, s1)
	byTask := contextMountFrom(t, s, "by-task")
	byProject := contextMountFrom(t, s, "by-project")
	time.Sleep(20 * time.Millisecond)
	createSeeded(t, s, "after.txt", []byte("after\n"), "after-seed", attrsFor(map[string]string{"project": "demo"}))
	atNS := time.Now().UnixNano()
	head := s.Head()
	atEntry, err := s.CommitAtOrBefore(head, atNS)
	if err != nil || atEntry == nil {
		t.Fatalf("at selection: %v, %v", atEntry, err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	snap1 := s1
	atCommit := atEntry.Commit
	m1 := mount(t, dir, store.ReadOnly, fusefs.Options{ReadOnly: true, Snapshot: &snap1, Context: byTask})
	m2 := mount(t, dir, store.ReadOnly, fusefs.Options{ReadOnly: true, Snapshot: &snap1, Context: byProject})
	m3 := mount(t, dir, store.ReadOnly, fusefs.Options{ReadOnly: true, Snapshot: &atCommit})

	taskNames := visibleNames(t, m1.mnt)
	projectNames := visibleNames(t, m2.mnt)
	atNames := visibleNames(t, m3.mnt)
	if len(taskNames) != 2 || len(projectNames) != 2 {
		t.Fatalf("context listings = %v / %v", taskNames, projectNames)
	}
	if len(atNames) != 4 {
		t.Fatalf("at listing = %v", atNames)
	}
	for _, name := range taskNames {
		if data, err := os.ReadFile(filepath.Join(m1.mnt, name)); err != nil || string(data) != string(identicalBytes) {
			t.Fatalf("task read %s = %q, %v", name, data, err)
		}
	}
	for _, name := range projectNames {
		if data, err := os.ReadFile(filepath.Join(m2.mnt, name)); err != nil || string(data) != string(identicalBytes) {
			t.Fatalf("project read %s = %q, %v", name, data, err)
		}
	}
	if data, err := os.ReadFile(filepath.Join(m3.mnt, "other.txt")); err != nil || string(data) != string(otherBytes) {
		t.Fatalf("at read other.txt = %q, %v", data, err)
	}

	// Read-only mounts take no writer lock: a mutating open succeeds while all
	// three mounts are live.
	writer, err := store.Open(dir, store.ReadWrite)
	if err != nil {
		t.Fatalf("writer open while three mounts are live: %v", err)
	}
	rootID, err := writer.ResolvePath("/")
	if err != nil {
		t.Fatalf("resolve root: %v", err)
	}
	if _, err := writer.CreateFile(rootID, []byte("while-mounted.txt"), []byte("live"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("write while mounted: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if _, err := os.Stat(filepath.Join(m3.mnt, "while-mounted.txt")); err == nil {
		t.Fatalf("pinned at mount observed a later commit")
	}
}
