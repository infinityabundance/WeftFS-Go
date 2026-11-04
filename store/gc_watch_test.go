package store_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// TestGCBoundedRespectsDeletionBudgetAndConverges drives the same pass a
// watcher uses: at most one candidate removed per pass, roots recomputed each
// time, snapshot content untouched, and eventual convergence.
func TestGCBoundedRespectsDeletionBudgetAndConverges(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, gcOptions(0))
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()

	keepID, err := s.CreateFile(model.RootID, []byte("keep.txt"), []byte("snapshot-content"), 0o644, 0, 0, nil)
	if err != nil {
		t.Fatalf("create keep: %v", err)
	}
	snapshot, err := s.SnapshotCreate("keep")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	keepManifest, keepChunks := fileBlobs(t, dir, s.CurrentState().Objects[keepID])

	garbage := make([]model.Hash32, 0)
	for index := 0; index < 6; index++ {
		id, err := s.CreateFile(model.RootID, []byte("garbage-"+itoa(uint64(index))+".txt"),
			[]byte("garbage-content-"+itoa(uint64(index))), 0o644, 0, 0, nil)
		if err != nil {
			t.Fatalf("create garbage %d: %v", index, err)
		}
		garbage = append(garbage, id)
		if err := s.Unlink(model.RootID, []byte("garbage-"+itoa(uint64(index))+".txt")); err != nil {
			t.Fatalf("unlink garbage %d: %v", index, err)
		}
	}

	passes := 0
	for {
		report, err := s.GCBounded(true, 1)
		if err != nil {
			t.Fatalf("bounded pass %d: %v", passes, err)
		}
		if report.DeletedFiles > 1 {
			t.Fatalf("pass %d deleted %d files, budget was 1", passes, report.DeletedFiles)
		}
		if report.RemainingFiles > report.UnreachableFiles {
			t.Fatalf("pass %d remaining=%d unreachable=%d", passes, report.RemainingFiles, report.UnreachableFiles)
		}
		passes++
		if report.RemainingFiles == 0 {
			break
		}
		if passes > 64 {
			t.Fatalf("bounded GC did not converge: %+v", report)
		}
	}
	if passes < 2 {
		t.Fatalf("expected multiple bounded passes, got %d", passes)
	}
	for _, id := range garbage {
		if _, err := s.ObjectMeta(id); err == nil {
			t.Fatalf("garbage object %s survived", id.Hex())
		}
	}
	assertExists(t, store.ManifestPath(dir, keepManifest), true, "snapshot manifest after bounded GC")
	for _, chunk := range keepChunks {
		assertExists(t, store.ObjectPath(dir, chunk), true, "snapshot chunk after bounded GC")
	}
	if got, err := s.ReadObjectAt(&snapshot, keepID); err != nil || string(got) != "snapshot-content" {
		t.Fatalf("snapshot read = %q, %v", string(got), err)
	}
	if report, err := s.Verify(true); err != nil || !report.OK {
		t.Fatalf("verify after bounded GC: ok=%v err=%v problems=%s", report != nil && report.OK, err, formatProblems(report))
	}
}

// TestGCWatchCancellationAndPassBudget shows the watch loop stops promptly
// after cancellation and performs no further passes.
func TestGCWatchCancellationAndPassBudget(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, gcOptions(0))
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()
	if _, err := s.CreateFile(model.RootID, []byte("gone.txt"), []byte("watcher-garbage"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.Unlink(model.RootID, []byte("gone.txt")); err != nil {
		t.Fatalf("unlink: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var passes atomic.Int64
	done := make(chan error, 1)
	go func() {
		done <- s.GCWatch(ctx, 10*time.Millisecond, 2, func(report store.GCReport) {
			passes.Add(1)
		})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for passes.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if passes.Load() == 0 {
		cancel()
		<-done
		t.Fatal("watch performed no pass")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("GCWatch returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("GCWatch did not return after cancellation")
	}
	stopped := passes.Load()
	time.Sleep(50 * time.Millisecond)
	if passes.Load() != stopped {
		t.Fatalf("watch ran %d extra passes after cancellation", passes.Load()-stopped)
	}
	if report, err := s.Verify(true); err != nil || !report.OK {
		t.Fatalf("verify after watch: ok=%v err=%v problems=%s", report != nil && report.OK, err, formatProblems(report))
	}
}

// TestGCWatchRequiresWriterLock fails closed on a read-only store.
func TestGCWatchRequiresWriterLock(t *testing.T) {
	dir := t.TempDir()
	writer, err := store.Init(dir, gcOptions(0))
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	reader, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("open read-only: %v", err)
	}
	defer reader.Close()
	err = reader.GCWatch(context.Background(), time.Millisecond, 1, nil)
	if err == nil {
		t.Fatal("GCWatch succeeded on a read-only store")
	}
	if werr.ClassOf(err) != werr.ReadOnly {
		t.Fatalf("GCWatch on read-only store = %v, want ReadOnly", err)
	}
}

// TestGCWatchPreservesPinnedContentAndSnapshot keeps a snapshot and a content
// pin alive across real watch passes, then shows the pinned garbage is swept
// only after the pin is released.
func TestGCWatchPreservesPinnedContentAndSnapshot(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, gcOptions(0))
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()

	keepID, err := s.CreateFile(model.RootID, []byte("keep.txt"), []byte("keep-v1"), 0o644, 0, 0, nil)
	if err != nil {
		t.Fatalf("create keep: %v", err)
	}
	if _, err := s.SnapshotCreate("keep"); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	keepManifest, keepChunks := fileBlobs(t, dir, s.CurrentState().Objects[keepID])

	pinnedID, err := s.CreateFile(model.RootID, []byte("pinned.txt"), []byte("pinned-garbage"), 0o644, 0, 0, nil)
	if err != nil {
		t.Fatalf("create pinned: %v", err)
	}
	pinnedContent := s.CurrentState().Objects[pinnedID].Content
	pinnedManifest, pinnedChunks := fileBlobs(t, dir, s.CurrentState().Objects[pinnedID])
	if err := s.Unlink(model.RootID, []byte("pinned.txt")); err != nil {
		t.Fatalf("unlink pinned: %v", err)
	}
	if count := s.PinContent(pinnedContent); count != 1 {
		t.Fatalf("pin count = %d", count)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- s.GCWatch(ctx, 10*time.Millisecond, 4, nil)
	}()
	time.Sleep(120 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("watch: %v", err)
	}

	assertExists(t, store.ManifestPath(dir, keepManifest), true, "snapshot manifest")
	for _, chunk := range keepChunks {
		assertExists(t, store.ObjectPath(dir, chunk), true, "snapshot chunk")
	}
	assertExists(t, store.ManifestPath(dir, pinnedManifest), true, "pinned manifest while pin held")
	for _, chunk := range pinnedChunks {
		assertExists(t, store.ObjectPath(dir, chunk), true, "pinned chunk while pin held")
	}
	if got, err := s.ReadContent(pinnedContent, 0, ^uint64(0)); err != nil || string(got) != "pinned-garbage" {
		t.Fatalf("pinned content read = %q, %v", string(got), err)
	}

	if count := s.UnpinContent(pinnedContent); count != 0 {
		t.Fatalf("unpin count = %d", count)
	}
	report, err := s.GCBounded(true, 0)
	if err != nil {
		t.Fatalf("GC after unpin: %v", err)
	}
	if report.DeletedFiles == 0 {
		t.Fatalf("nothing deleted after the pin was released: %+v", report)
	}
	assertExists(t, store.ManifestPath(dir, pinnedManifest), false, "pinned manifest after unpin")
	assertExists(t, store.ManifestPath(dir, keepManifest), true, "snapshot manifest after unpin")
}

// TestGCBoundedInterruptedPassConverges simulates a crash between bounded
// deletion passes: the in-memory state is dropped, the store is reopened, and
// the next passes converge without trusting a persisted mark set.
func TestGCBoundedInterruptedPassConverges(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, gcOptions(0))
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	ids := make([]model.Hash32, 0)
	for index := 0; index < 4; index++ {
		name := "interrupted-" + itoa(uint64(index)) + ".txt"
		id, err := s.CreateFile(model.RootID, []byte(name), []byte("interrupted-garbage-"+itoa(uint64(index))), 0o644, 0, 0, nil)
		if err != nil {
			t.Fatalf("create %d: %v", index, err)
		}
		ids = append(ids, id)
		if err := s.Unlink(model.RootID, []byte(name)); err != nil {
			t.Fatalf("unlink %d: %v", index, err)
		}
	}
	first, err := s.GCBounded(true, 1)
	if err != nil {
		t.Fatalf("first pass: %v", err)
	}
	if first.DeletedFiles != 1 {
		t.Fatalf("first pass deleted %d, want 1", first.DeletedFiles)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	writer, err := store.OpenWithOptions(dir, store.ReadWrite, gcOptions(0))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer writer.Close()
	for pass := 0; pass < 32; pass++ {
		report, err := writer.GCBounded(true, 1)
		if err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
		if report.RemainingFiles == 0 {
			break
		}
	}
	for _, id := range ids {
		if _, err := writer.ObjectMeta(id); err == nil {
			t.Fatalf("garbage %s survived interrupted sweep", id.Hex())
		}
	}
	if report, err := writer.Verify(true); err != nil || !report.OK {
		t.Fatalf("verify after convergence: ok=%v err=%v problems=%s", report != nil && report.OK, err, formatProblems(report))
	}
}
