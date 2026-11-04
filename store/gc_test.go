package store_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
)

func gcOptions(graceSecs uint64) store.Options {
	options := store.DefaultOptions()
	options.GCGraceSecs = graceSecs
	return options
}

// fileBlobs returns the manifest id and chunk hashes referenced by a file
// record.
func fileBlobs(t *testing.T, root string, record model.ObjectRecord) (model.Hash32, []model.Hash32) {
	t.Helper()
	manifest, err := store.ReadManifest(root, record.Content)
	if err != nil {
		t.Fatalf("read manifest %s: %v", record.Content.Hex(), err)
	}
	chunks := make([]model.Hash32, 0, len(manifest.Chunks))
	for _, chunk := range manifest.Chunks {
		chunks = append(chunks, chunk.Hash)
	}
	return record.Content, chunks
}

func assertExists(t *testing.T, path string, want bool, label string) {
	t.Helper()
	_, err := os.Lstat(path)
	exists := err == nil
	if want && !exists {
		t.Fatalf("%s should exist at %s (err=%v)", label, path, err)
	}
	if !want && exists {
		t.Fatalf("%s should have been swept from %s", label, path)
	}
}

// TestGCReclaimsUnreferencedBlobAndKeepsSnapshot covers the primary contract:
// dry run deletes nothing, apply removes only unreachable blobs, and content
// reachable through a snapshot stays byte-exact.
func TestGCReclaimsUnreferencedBlobAndKeepsSnapshot(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, gcOptions(0))
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()

	const snapshotContent = "snapshot-content"
	const liveContent = "LIVE-CONTENT-123" // same length: no implicit zero-fill
	const goneContent = "garbage-only-content"

	keepID, err := s.CreateFile(model.RootID, []byte("keep.txt"), []byte(snapshotContent), 0o644, 0, 0, nil)
	if err != nil {
		t.Fatalf("create keep: %v", err)
	}
	snapshot, err := s.SnapshotCreate("keep")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	oldManifest, oldChunks := fileBlobs(t, dir, s.CurrentState().Objects[keepID])

	if _, err := s.WriteFile(keepID, 0, []byte(liveContent)); err != nil {
		t.Fatalf("overwrite keep: %v", err)
	}
	goneID, err := s.CreateFile(model.RootID, []byte("gone.txt"), []byte(goneContent), 0o644, 0, 0, nil)
	if err != nil {
		t.Fatalf("create gone: %v", err)
	}
	goneManifest, goneChunks := fileBlobs(t, dir, s.CurrentState().Objects[goneID])
	if err := s.Unlink(model.RootID, []byte("gone.txt")); err != nil {
		t.Fatalf("unlink gone: %v", err)
	}

	dry, err := s.GC(false)
	if err != nil {
		t.Fatalf("dry-run GC: %v", err)
	}
	if dry.Applied {
		t.Fatal("dry run reported applied=true")
	}
	if dry.UnreachableFiles == 0 || len(dry.Candidates) == 0 {
		t.Fatalf("dry run found no candidates: %+v", dry)
	}
	if dry.DeletedFiles != 0 || len(dry.Deleted) != 0 {
		t.Fatalf("dry run deleted files: %+v", dry)
	}
	assertExists(t, store.ManifestPath(dir, goneManifest), true, "unreachable manifest after dry run")
	for _, chunk := range goneChunks {
		assertExists(t, store.ObjectPath(dir, chunk), true, "unreachable chunk after dry run")
	}
	assertExists(t, store.ManifestPath(dir, oldManifest), true, "snapshot manifest after dry run")
	for _, chunk := range oldChunks {
		assertExists(t, store.ObjectPath(dir, chunk), true, "snapshot chunk after dry run")
	}
	if got, err := s.ReadObjectAt(&snapshot, keepID); err != nil || string(got) != snapshotContent {
		t.Fatalf("snapshot read after dry run = %q, %v", string(got), err)
	}

	applied, err := s.GC(true)
	if err != nil {
		t.Fatalf("apply GC: %v", err)
	}
	if !applied.Applied || applied.DeletedFiles == 0 || applied.DeletedBytes == 0 {
		t.Fatalf("apply deleted nothing: %+v", applied)
	}
	assertExists(t, store.ManifestPath(dir, goneManifest), false, "unreachable manifest after apply")
	for _, chunk := range goneChunks {
		assertExists(t, store.ObjectPath(dir, chunk), false, "unreachable chunk after apply")
	}
	assertExists(t, store.ManifestPath(dir, oldManifest), true, "snapshot manifest after apply")
	for _, chunk := range oldChunks {
		assertExists(t, store.ObjectPath(dir, chunk), true, "snapshot chunk after apply")
	}
	if got, err := s.ReadObjectAt(&snapshot, keepID); err != nil || string(got) != snapshotContent {
		t.Fatalf("snapshot read after apply = %q, %v", string(got), err)
	}
	if got, err := s.ReadObject(keepID); err != nil || string(got) != liveContent {
		t.Fatalf("live read after apply = %q, %v", string(got), err)
	}
	if report, err := s.Verify(true); err != nil || !report.OK {
		t.Fatalf("verify after GC: ok=%v err=%v problems=%s", report != nil && report.OK, err, formatProblems(report))
	}
}

// TestGCGraceWindow pins the age gate: a fresh unreachable blob survives the
// default window, and disappears once the grace period is disabled.
func TestGCGraceWindow(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, gcOptions(store.DefaultGCGraceSecs))
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()

	id, err := s.CreateFile(model.RootID, []byte("young.txt"), []byte("young garbage"), 0o644, 0, 0, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	manifest, chunks := fileBlobs(t, dir, s.CurrentState().Objects[id])
	if err := s.Unlink(model.RootID, []byte("young.txt")); err != nil {
		t.Fatalf("unlink: %v", err)
	}

	report, err := s.GC(true)
	if err != nil {
		t.Fatalf("GC with grace: %v", err)
	}
	if report.DeletedFiles != 0 || report.GraceRetained == 0 {
		t.Fatalf("grace window did not retain the fresh blob: %+v", report)
	}
	assertExists(t, store.ManifestPath(dir, manifest), true, "manifest inside grace window")
	for _, chunk := range chunks {
		assertExists(t, store.ObjectPath(dir, chunk), true, "chunk inside grace window")
	}

	if err := s.SetOptions(gcOptions(0)); err != nil {
		t.Fatalf("set options: %v", err)
	}
	report, err = s.GC(true)
	if err != nil {
		t.Fatalf("GC without grace: %v", err)
	}
	if report.DeletedFiles == 0 {
		t.Fatalf("blob survived after the grace window was disabled: %+v", report)
	}
	assertExists(t, store.ManifestPath(dir, manifest), false, "manifest after grace expired")
	for _, chunk := range chunks {
		assertExists(t, store.ObjectPath(dir, chunk), false, "chunk after grace expired")
	}
}

// TestGCRetainsAndSweepsPinnedContent mirrors the Rust content-pin root.
func TestGCRetainsAndSweepsPinnedContent(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, gcOptions(0))
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()

	id, err := s.CreateFile(model.RootID, []byte("pinned.txt"), []byte("keep me"), 0o644, 0, 0, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	content := s.CurrentState().Objects[id].Content
	manifest, chunks := fileBlobs(t, dir, s.CurrentState().Objects[id])
	if err := s.Unlink(model.RootID, []byte("pinned.txt")); err != nil {
		t.Fatalf("unlink: %v", err)
	}

	if count := s.PinContent(content); count != 1 {
		t.Fatalf("pin content count = %d", count)
	}
	report, err := s.GC(true)
	if err != nil {
		t.Fatalf("GC with pinned content: %v", err)
	}
	for _, candidate := range report.Candidates {
		if candidate == "manifests/"+manifest.Hex()[0:2]+"/"+manifest.Hex() {
			t.Fatalf("pinned manifest was a candidate: %v", report.Candidates)
		}
	}
	if got, err := s.ReadContent(content, 0, ^uint64(0)); err != nil || string(got) != "keep me" {
		t.Fatalf("pinned content read = %q, %v", string(got), err)
	}
	assertExists(t, store.ManifestPath(dir, manifest), true, "pinned manifest")
	for _, chunk := range chunks {
		assertExists(t, store.ObjectPath(dir, chunk), true, "pinned chunk")
	}

	if count := s.UnpinContent(content); count != 0 {
		t.Fatalf("unpin content count = %d", count)
	}
	if _, err := s.GC(true); err != nil {
		t.Fatalf("GC after unpin: %v", err)
	}
	if _, err := s.ReadContent(content, 0, ^uint64(0)); err == nil {
		t.Fatal("pinned content still readable after unpin and GC")
	}
	assertExists(t, store.ManifestPath(dir, manifest), false, "manifest after unpin")
}

// TestGCRemovesOrphanRecordsLeftByACrash mirrors the Rust parity case: an
// unlinked object whose only reference was a process-local pin keeps its record
// and tip across a restart. `gc --apply` removes the record in a commit so the
// blobs become unreachable and are swept.
func TestGCRemovesOrphanRecordsLeftByACrash(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, gcOptions(0))
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	id, err := s.CreateFile(model.RootID, []byte("orphan.txt"), []byte("orphan payload"), 0o644, 0, 0, nil)
	if err != nil {
		s.Close()
		t.Fatalf("create: %v", err)
	}
	manifest, chunks := fileBlobs(t, dir, s.CurrentState().Objects[id])
	if _, err := s.PinObject(id); err != nil {
		s.Close()
		t.Fatalf("pin: %v", err)
	}
	if err := s.Unlink(model.RootID, []byte("orphan.txt")); err != nil {
		s.Close()
		t.Fatalf("unlink: %v", err)
	}
	if _, ok := s.CurrentState().Objects[id]; !ok {
		s.Close()
		t.Fatal("pinned object record did not survive unlink")
	}
	// Closing without unpinning drops the process-local pin, exactly as a crash
	// would. The record and its tip remain durable in the commit chain.
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	writer, err := store.OpenWithOptions(dir, store.ReadWrite, gcOptions(0))
	if err != nil {
		t.Fatalf("reopen writer: %v", err)
	}
	defer writer.Close()
	if _, ok := writer.CurrentState().Objects[id]; !ok {
		t.Fatal("orphan record is missing before GC")
	}
	generation := writer.Generation()
	report, err := writer.GC(true)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	found := false
	for _, orphan := range report.RemovedOrphans {
		if orphan == id.Hex() {
			found = true
		}
	}
	if !found {
		t.Fatalf("orphan %s was not removed: %+v", id.Hex(), report)
	}
	if writer.Generation() <= generation {
		t.Fatal("orphan removal did not publish a commit")
	}
	if _, ok := writer.CurrentState().Objects[id]; ok {
		t.Fatal("orphan record survived GC apply")
	}
	if _, err := writer.ObjectMeta(id); err == nil {
		t.Fatal("orphan object is still addressable after GC")
	}
	assertExists(t, store.ManifestPath(dir, manifest), false, "orphan manifest")
	for _, chunk := range chunks {
		assertExists(t, store.ObjectPath(dir, chunk), false, "orphan chunk")
	}
	if verify, err := writer.Verify(true); err != nil || !verify.OK {
		t.Fatalf("verify after orphan GC: ok=%v err=%v problems=%s",
			verify != nil && verify.OK, err, formatProblems(verify))
	}
}

// TestGCInterruptedSweepIsRecoverable deletes one candidate by hand (as a
// crash during sweep would leave it) and shows the next pass converges. No
// persisted mark record is trusted; roots are recomputed.
func TestGCInterruptedSweepIsRecoverable(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, gcOptions(0))
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	id, err := s.CreateFile(model.RootID, []byte("gone.txt"), []byte("interrupted-sweep-garbage"), 0o644, 0, 0, nil)
	if err != nil {
		s.Close()
		t.Fatalf("create: %v", err)
	}
	manifest, chunks := fileBlobs(t, dir, s.CurrentState().Objects[id])
	if err := s.Unlink(model.RootID, []byte("gone.txt")); err != nil {
		s.Close()
		t.Fatalf("unlink: %v", err)
	}
	dry, err := s.GC(false)
	if err != nil {
		s.Close()
		t.Fatalf("dry GC: %v", err)
	}
	if len(dry.Candidates) < 2 {
		s.Close()
		t.Fatalf("expected at least a manifest and a chunk candidate: %+v", dry)
	}
	// Simulate a sweep killed after its first unlink.
	if err := os.Remove(filepath.Join(dir, filepath.FromSlash(dry.Candidates[0]))); err != nil {
		s.Close()
		t.Fatalf("remove first candidate: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	writer, err := store.OpenWithOptions(dir, store.ReadWrite, gcOptions(0))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer writer.Close()
	report, err := writer.GC(true)
	if err != nil {
		t.Fatalf("rerun GC: %v", err)
	}
	if report.DeletedFiles == 0 {
		t.Fatalf("rerun deleted nothing: %+v", report)
	}
	assertExists(t, store.ManifestPath(dir, manifest), false, "manifest after rerun")
	for _, chunk := range chunks {
		assertExists(t, store.ObjectPath(dir, chunk), false, "chunk after rerun")
	}
	if verify, err := writer.Verify(true); err != nil || !verify.OK {
		t.Fatalf("verify after rerun: ok=%v err=%v problems=%s",
			verify != nil && verify.OK, err, formatProblems(verify))
	}
}

// TestGCSweepSkipsSymlinksAndNonRegularEntries creates a symlink and a
// directory with valid-looking blob names. GC must leave both alone, must not
// follow the symlink out of the store, and must still sweep a real regular
// file candidate.
func TestGCSweepSkipsSymlinksAndNonRegularEntries(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, gcOptions(0))
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()

	outsideDir := t.TempDir()
	outside := filepath.Join(outsideDir, "outside.txt")
	if err := os.WriteFile(outside, []byte("must survive"), 0o644); err != nil {
		t.Fatalf("write outside: %v", err)
	}

	symlinkShard := filepath.Join(dir, "objects", "fa")
	dirShard := filepath.Join(dir, "objects", "fb")
	fileShard := filepath.Join(dir, "objects", "fc")
	for _, shard := range []string{symlinkShard, dirShard, fileShard} {
		if err := os.MkdirAll(shard, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", shard, err)
		}
	}
	symlinkName := strings.Repeat("a1", 32)
	dirName := strings.Repeat("b2", 32)
	fileName := strings.Repeat("c3", 32)
	if err := os.Symlink(outside, filepath.Join(symlinkShard, symlinkName)); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := os.Mkdir(filepath.Join(dirShard, dirName), 0o755); err != nil {
		t.Fatalf("mkdir named blob: %v", err)
	}
	regular := filepath.Join(fileShard, fileName)
	if err := os.WriteFile(regular, []byte("sweep me"), 0o644); err != nil {
		t.Fatalf("write regular candidate: %v", err)
	}

	report, err := s.GC(true)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if report.DeletedFiles != 1 || report.DeletedBytes != uint64(len("sweep me")) {
		t.Fatalf("unexpected deletion set: %+v", report)
	}
	for _, candidate := range report.Candidates {
		if strings.Contains(candidate, symlinkName) || strings.Contains(candidate, dirName) {
			t.Fatalf("non-regular entry became a candidate: %s", candidate)
		}
	}
	assertExists(t, regular, false, "regular candidate")
	assertExists(t, filepath.Join(symlinkShard, symlinkName), true, "symlink entry")
	assertExists(t, filepath.Join(dirShard, dirName), true, "directory entry")
	if data, err := os.ReadFile(outside); err != nil || string(data) != "must survive" {
		t.Fatalf("outside file was touched: %q, %v", string(data), err)
	}
}

// TestGCRejectedTailKeepsCheckpoint is the child used to produce a valid but
// unpublished commit that carries a checkpoint. It SIGKILLs itself at the
// requested publication phase.
func TestGCRejectedTailChild(t *testing.T) {
	dir := os.Getenv("WEFT_GC_TAIL_STORE")
	if dir == "" {
		t.Skip("rejected-tail helper process; not run directly")
	}
	options := store.DefaultOptions()
	options.CheckpointInterval = 1 // every commit carries a checkpoint
	options.GCGraceSecs = 0
	s, err := store.OpenWithOptions(dir, store.ReadWrite, options)
	if err != nil {
		t.Fatalf("child open: %v", err)
	}
	defer s.Close()
	content := os.Getenv("WEFT_GC_TAIL_CONTENT")
	if _, err := s.CreateFile(model.RootID, []byte("tail.txt"), []byte(content), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("child create: %v", err)
	}
	t.Fatalf("child survived crash phase %q", os.Getenv("WEFT_CRASH_PHASE"))
}

// TestGCRejectedTailKeepsCheckpoint proves that a valid but unpublished tail
// commit still makes its checkpoint manifest and chunks roots, while unrelated
// garbage is swept; a later generation publishes normally over the tail.
func TestGCRejectedTailKeepsCheckpoint(t *testing.T) {
	dir := t.TempDir()
	options := store.DefaultOptions()
	options.CheckpointInterval = 0 // no checkpoints while creating garbage
	options.GCGraceSecs = 0
	s, err := store.Init(dir, options)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	garbageID, err := s.CreateFile(model.RootID, []byte("garbage.txt"), []byte("checkpoint-free garbage"), 0o644, 0, 0, nil)
	if err != nil {
		t.Fatalf("create garbage: %v", err)
	}
	garbageManifest, garbageChunks := fileBlobs(t, dir, s.CurrentState().Objects[garbageID])
	if err := s.Unlink(model.RootID, []byte("garbage.txt")); err != nil {
		t.Fatalf("unlink garbage: %v", err)
	}
	headBefore := s.Head()
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	const tailContent = "tail-content-retained-by-checkpoint"
	cmd := exec.Command(os.Args[0], "-test.run=TestGCRejectedTailChild")
	cmd.Env = append(os.Environ(),
		"WEFT_GC_TAIL_STORE="+dir,
		"WEFT_CRASH_PHASE=after_commit_file",
		"WEFT_GC_TAIL_CONTENT="+tailContent,
	)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("tail child exited cleanly; output: %s", output)
	}
	if _, ok := err.(*exec.ExitError); !ok {
		t.Fatalf("tail child execution failed: %v (%s)", err, output)
	}

	commits, err := store.AllCommits(dir, ^uint64(0))
	if err != nil {
		t.Fatalf("all commits: %v", err)
	}
	if len(commits) == 0 {
		t.Fatal("no commits parsed after the crash tail")
	}
	var tailCheckpoint *model.Hash32
	for index := range commits {
		if commits[index].Commit.Checkpoint != nil && commits[index].Generation > 1 {
			tailCheckpoint = commits[index].Commit.Checkpoint
		}
	}
	if tailCheckpoint == nil {
		t.Fatalf("unpublished tail commit has no checkpoint: %+v", commits)
	}
	tailState, err := store.ReadStateManifest(dir, *tailCheckpoint)
	if err != nil {
		t.Fatalf("read tail checkpoint: %v", err)
	}
	tailFile, ok := tailState.Objects[mustResolveState(t, tailState, "/tail.txt")]
	if !ok {
		t.Fatal("tail checkpoint does not contain tail.txt")
	}
	tailManifest, tailChunks := fileBlobs(t, dir, tailFile)
	assertExists(t, store.ManifestPath(dir, *tailCheckpoint), true, "tail checkpoint manifest")
	assertExists(t, store.ManifestPath(dir, tailManifest), true, "tail file manifest")

	writer, err := store.OpenWithOptions(dir, store.ReadWrite, gcOptions(0))
	if err != nil {
		t.Fatalf("open writer: %v", err)
	}
	report, err := writer.GC(true)
	if err != nil {
		writer.Close()
		t.Fatalf("GC apply: %v", err)
	}
	if report.DeletedFiles == 0 {
		t.Fatalf("checkpoint-free garbage was not swept: %+v", report)
	}
	assertExists(t, store.ManifestPath(dir, garbageManifest), false, "garbage manifest")
	for _, chunk := range garbageChunks {
		assertExists(t, store.ObjectPath(dir, chunk), false, "garbage chunk")
	}
	assertExists(t, store.ManifestPath(dir, *tailCheckpoint), true, "retained tail checkpoint")
	assertExists(t, store.ManifestPath(dir, tailManifest), true, "retained tail manifest")
	for _, chunk := range tailChunks {
		assertExists(t, store.ObjectPath(dir, chunk), true, "retained tail chunk")
	}
	if _, err := writer.ResolvePath("/tail.txt"); err == nil {
		t.Fatal("unpublished tail commitment became visible")
	}
	if writer.Head() != headBefore {
		t.Fatal("GC apply changed the published head")
	}
	if _, err := writer.CreateFile(model.RootID, []byte("after.txt"), []byte("published after the tail"), 0o644, 0, 0, nil); err != nil {
		writer.Close()
		t.Fatalf("publish new generation: %v", err)
	}
	if writer.Generation() <= commits[len(commits)-1].Generation {
		t.Fatalf("new generation %d did not advance past the tail", writer.Generation())
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	reader, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reader.Close()
	verify, err := reader.Verify(true)
	if err != nil || !verify.OK {
		t.Fatalf("verify after publishing over the tail: ok=%v err=%v problems=%s",
			verify != nil && verify.OK, err, formatProblems(verify))
	}
	if got, err := reader.ReadObject(mustResolveInStore(t, reader, "/after.txt")); err != nil || string(got) != "published after the tail" {
		t.Fatalf("after.txt read = %q, %v", string(got), err)
	}
}

// TestGCRequiresWriter proves the lock contract at the API level (a second
// writer is already refused at open time).
func TestGCRequiresWriter(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, store.DefaultOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	s.Close()

	reader, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("open read-only: %v", err)
	}
	if _, err := reader.GC(false); err == nil {
		reader.Close()
		t.Fatal("GC succeeded on a read-only store")
	} else if !strings.Contains(strings.ToLower(err.Error()), "read-only") {
		reader.Close()
		t.Fatalf("unexpected read-only error: %v", err)
	}
	reader.Close()

	writer, err := store.Open(dir, store.ReadWrite)
	if err != nil {
		t.Fatalf("open writer: %v", err)
	}
	defer writer.Close()
	if _, err := store.Open(dir, store.ReadWrite); err == nil {
		t.Fatal("second writer acquired the lock")
	}
}

// TestGCNeverSweepsFixtureReachability asserts every manifest and chunk named
// by EXPECTED.json (and by the fixture's snapshot states) survives both a dry
// run and an apply pass.
func TestGCNeverSweepsFixtureReachability(t *testing.T) {
	dir := copyFixture(t)
	s, err := store.OpenWithOptions(dir, store.ReadWrite, gcOptions(0))
	if err != nil {
		t.Fatalf("open fixture writer: %v", err)
	}
	defer s.Close()

	expected := loadExpected(t)
	manifests := make(map[model.Hash32]bool)
	chunks := make(map[model.Hash32]bool)
	for _, object := range expected.Objects {
		if object.Kind != "file" {
			continue
		}
		content := mustHash(t, object.ContentID)
		manifests[content] = true
		manifest, err := store.ReadManifest(dir, content)
		if err != nil {
			t.Fatalf("expected manifest %s: %v", object.ContentID, err)
		}
		for _, chunk := range manifest.Chunks {
			chunks[chunk.Hash] = true
		}
	}
	for name, commitText := range expected.Snapshots {
		commit := mustHash(t, commitText)
		state, err := s.StateAt(commit)
		if err != nil {
			t.Fatalf("snapshot %s state: %v", name, err)
		}
		for _, record := range state.Objects {
			if record.Kind != model.KindFile {
				continue
			}
			manifests[record.Content] = true
			manifest, err := store.ReadManifest(dir, record.Content)
			if err != nil {
				t.Fatalf("snapshot %s manifest %s: %v", name, record.Content.Hex(), err)
			}
			for _, chunk := range manifest.Chunks {
				chunks[chunk.Hash] = true
			}
		}
	}
	if len(manifests) == 0 || len(chunks) == 0 {
		t.Fatalf("fixture expectation is empty: manifests=%d chunks=%d", len(manifests), len(chunks))
	}

	if _, err := s.GC(false); err != nil {
		t.Fatalf("fixture dry run: %v", err)
	}
	if _, err := s.GC(true); err != nil {
		t.Fatalf("fixture apply: %v", err)
	}
	for manifest := range manifests {
		assertExists(t, store.ManifestPath(dir, manifest), true, "fixture manifest "+manifest.Hex())
	}
	for chunk := range chunks {
		assertExists(t, store.ObjectPath(dir, chunk), true, "fixture chunk "+chunk.Hex())
	}
	if report, err := s.Verify(true); err != nil || !report.OK {
		t.Fatalf("fixture verify after GC: ok=%v err=%v problems=%s", report != nil && report.OK, err, formatProblems(report))
	}
}

func formatProblems(report *store.VerifyReport) string {
	if report == nil {
		return "<nil>"
	}
	parts := make([]string, 0, len(report.Problems))
	for _, problem := range report.Problems {
		parts = append(parts, problem.Class+": "+problem.Detail)
	}
	return strings.Join(parts, "; ")
}

func mustResolveInStore(t *testing.T, s *store.Store, path string) model.Hash32 {
	t.Helper()
	id, err := s.ResolvePath(path)
	if err != nil {
		t.Fatalf("resolve %s: %v", path, err)
	}
	return id
}

func mustResolveState(t *testing.T, state *model.State, path string) model.Hash32 {
	t.Helper()
	id, err := resolveInState(state, path)
	if err != nil {
		t.Fatalf("resolve %s in state: %v", path, err)
	}
	return id
}
