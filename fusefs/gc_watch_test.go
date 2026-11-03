package fusefs_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/infinityabundance/WeftFS-Go/fusefs"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
)

func mountWithStoreOptions(t *testing.T, dir string, mode store.OpenMode, storeOptions store.Options, opts fusefs.Options) mounted {
	t.Helper()
	st, err := store.OpenWithOptions(dir, mode, storeOptions)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	mnt := t.TempDir()
	opts.Mountpoint = mnt
	server, srv, err := fusefs.Mount(st, opts)
	if err != nil {
		st.Close()
		t.Fatalf("mount: %v", err)
	}
	m := mounted{dir: dir, mnt: mnt, st: st, srv: srv, server: server}
	t.Cleanup(func() {
		srv.StopBackgroundGC()
		_ = server.Unmount()
		server.Wait()
		_ = st.Close()
	})
	return m
}

func backgroundOptions() store.Options {
	options := store.DefaultOptions()
	options.GCGraceSecs = 0
	options.GCBackground = true
	options.GCIntervalSecs = 1
	options.GCWatchMaxDeletes = 8
	return options
}

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

// TestBackgroundGCDuringReadsAndWrites runs the store-option collector while a
// mount serves concurrent reads, writes, creates, and unlinks. The garbage
// manifest and chunks must disappear, live content must stay exact, and
// cancellation must stop future passes.
func TestBackgroundGCDuringReadsAndWrites(t *testing.T) {
	dir := t.TempDir()
	setup, err := store.Init(dir, store.DefaultOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	liveData := bytes.Repeat([]byte("live-data-"), 64)
	if _, err := setup.CreateFile(model.RootID, []byte("live.txt"), liveData, 0o644, 0, 0, nil); err != nil {
		setup.Close()
		t.Fatalf("create live: %v", err)
	}
	victimID, err := setup.CreateFile(model.RootID, []byte("victim.txt"), []byte("background-garbage-payload"), 0o644, 0, 0, nil)
	if err != nil {
		setup.Close()
		t.Fatalf("create victim: %v", err)
	}
	victimManifest, victimChunks := fileBlobs(t, dir, setup.CurrentState().Objects[victimID])
	if err := setup.Unlink(model.RootID, []byte("victim.txt")); err != nil {
		setup.Close()
		t.Fatalf("unlink victim: %v", err)
	}
	if err := setup.Close(); err != nil {
		t.Fatalf("close setup: %v", err)
	}

	m := mountWithStoreOptions(t, dir, store.ReadWrite, backgroundOptions(), fusefs.Options{})

	stop := make(chan struct{})
	var wg sync.WaitGroup
	trafficErr := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for round := 0; ; round++ {
			select {
			case <-stop:
				return
			default:
			}
			payload := bytes.Repeat([]byte{byte('a' + round%26)}, 128+round%97)
			if err := os.WriteFile(filepath.Join(m.mnt, "live.txt"), payload, 0o644); err != nil {
				trafficErr <- fmt.Errorf("round %d write live: %w", round, err)
				return
			}
			got, err := os.ReadFile(filepath.Join(m.mnt, "live.txt"))
			if err != nil {
				trafficErr <- fmt.Errorf("round %d read live: %w", round, err)
				return
			}
			if !bytes.Equal(got, payload) {
				trafficErr <- fmt.Errorf("round %d live read mismatch (%d vs %d bytes)", round, len(got), len(payload))
				return
			}
			temp := filepath.Join(m.mnt, fmt.Sprintf("temp-%d.txt", round%4))
			if err := os.WriteFile(temp, payload, 0o644); err != nil {
				trafficErr <- fmt.Errorf("round %d write temp: %w", round, err)
				return
			}
			if err := os.Remove(temp); err != nil {
				trafficErr <- fmt.Errorf("round %d remove temp: %w", round, err)
				return
			}
			time.Sleep(3 * time.Millisecond)
		}
	}()

	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Lstat(store.ManifestPath(dir, victimManifest)); errors.Is(err, os.ErrNotExist) {
			break
		}
		if time.Now().After(deadline) {
			close(stop)
			wg.Wait()
			t.Fatal("background GC did not delete the unreachable manifest")
		}
		select {
		case err := <-trafficErr:
			close(stop)
			wg.Wait()
			t.Fatal(err)
		default:
		}
		time.Sleep(25 * time.Millisecond)
	}
	for _, chunk := range victimChunks {
		if _, err := os.Lstat(store.ObjectPath(dir, chunk)); !errors.Is(err, os.ErrNotExist) {
			close(stop)
			wg.Wait()
			t.Fatalf("background GC did not delete chunk %s", chunk.Hex())
		}
	}
	close(stop)
	wg.Wait()
	select {
	case err := <-trafficErr:
		t.Fatal(err)
	default:
	}
	if passes := m.srv.BackgroundGCPasses(); passes == 0 {
		t.Fatal("collector completed no pass")
	}
	if err := m.srv.BackgroundGCError(); err != nil {
		t.Fatalf("background GC error: %v", err)
	}
	if report, err := m.srv.Verify(true); err != nil || !report.OK {
		t.Fatalf("verify during background GC: ok=%v err=%v problems=%+v", report != nil && report.OK, err, report.Problems)
	}

	m.srv.StopBackgroundGC()
	stopped := m.srv.BackgroundGCPasses()
	time.Sleep(3 * time.Second)
	if got := m.srv.BackgroundGCPasses(); got != stopped {
		t.Fatalf("collector ran %d extra passes after cancellation", got-stopped)
	}
	if got := readFile(t, filepath.Join(m.mnt, "live.txt")); len(got) == 0 {
		t.Fatal("live file was damaged by background GC")
	}
}

// TestBackgroundGCPreservesSnapshotAndOpenHandle keeps a snapshot root and an
// open unlinked handle alive across real passes, then shows the pinned blobs
// are swept only after the last handle closes.
func TestBackgroundGCPreservesSnapshotAndOpenHandle(t *testing.T) {
	dir := t.TempDir()
	setup, err := store.Init(dir, store.DefaultOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	keepID, err := setup.CreateFile(model.RootID, []byte("keep.txt"), []byte("snapshot-v1"), 0o644, 0, 0, nil)
	if err != nil {
		setup.Close()
		t.Fatalf("create keep: %v", err)
	}
	if _, err := setup.SnapshotCreate("keep"); err != nil {
		setup.Close()
		t.Fatalf("snapshot: %v", err)
	}
	snapshotManifest, snapshotChunks := fileBlobs(t, dir, setup.CurrentState().Objects[keepID])
	if _, err := setup.WriteFile(keepID, 0, []byte("live-v2!!!!")); err != nil {
		setup.Close()
		t.Fatalf("overwrite keep: %v", err)
	}
	pinnedID, err := setup.CreateFile(model.RootID, []byte("pinned.txt"), []byte("pinned-payload"), 0o644, 0, 0, nil)
	if err != nil {
		setup.Close()
		t.Fatalf("create pinned: %v", err)
	}
	pinnedManifest, pinnedChunks := fileBlobs(t, dir, setup.CurrentState().Objects[pinnedID])
	if err := setup.Close(); err != nil {
		t.Fatalf("close setup: %v", err)
	}

	m := mountWithStoreOptions(t, dir, store.ReadWrite, backgroundOptions(), fusefs.Options{})
	handle, err := os.Open(filepath.Join(m.mnt, "pinned.txt"))
	if err != nil {
		t.Fatalf("open pinned: %v", err)
	}
	if err := os.Remove(filepath.Join(m.mnt, "pinned.txt")); err != nil {
		handle.Close()
		t.Fatalf("unlink pinned: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for m.srv.BackgroundGCPasses() < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if m.srv.BackgroundGCPasses() < 2 {
		handle.Close()
		t.Fatal("background collector did not complete two passes")
	}
	assertExists(t, store.ManifestPath(dir, snapshotManifest), true, "snapshot manifest with open handle")
	for _, chunk := range snapshotChunks {
		assertExists(t, store.ObjectPath(dir, chunk), true, "snapshot chunk with open handle")
	}
	assertExists(t, store.ManifestPath(dir, pinnedManifest), true, "pinned manifest while handle open")
	for _, chunk := range pinnedChunks {
		assertExists(t, store.ObjectPath(dir, chunk), true, "pinned chunk while handle open")
	}
	payload := make([]byte, len("pinned-payload"))
	if _, err := handle.ReadAt(payload, 0); err != nil || string(payload) != "pinned-payload" {
		handle.Close()
		t.Fatalf("open handle read = %q, %v", string(payload), err)
	}
	if got := readFile(t, filepath.Join(m.mnt, "keep.txt")); string(got) != "live-v2!!!!" {
		handle.Close()
		t.Fatalf("live keep content = %q", string(got))
	}

	if err := handle.Close(); err != nil {
		t.Fatalf("close pinned handle: %v", err)
	}
	deadline = time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Lstat(store.ManifestPath(dir, pinnedManifest)); errors.Is(err, os.ErrNotExist) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("background GC did not sweep pinned blobs after the last handle closed")
		}
		time.Sleep(25 * time.Millisecond)
	}
	assertExists(t, store.ManifestPath(dir, snapshotManifest), true, "snapshot manifest after handle close")
	for _, chunk := range snapshotChunks {
		assertExists(t, store.ObjectPath(dir, chunk), true, "snapshot chunk after handle close")
	}
	if report, err := m.srv.Verify(true); err != nil || !report.OK {
		t.Fatalf("verify after handle close: ok=%v err=%v problems=%+v", report != nil && report.OK, err, report.Problems)
	}
}
