package store_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
)

// runRustRaw runs the Rust oracle and returns combined output even on failure.
func runRustRaw(t *testing.T, bin string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// rustReadObjectBlobs reads a path's manifest and chunks through the Go reader;
// used only to identify blobs created by the Rust oracle.
func rustReadObjectBlobs(t *testing.T, dir, path string) (model.ObjectRecord, model.Hash32, []model.Hash32) {
	t.Helper()
	reader, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("open for blob capture: %v", err)
	}
	defer reader.Close()
	id, err := reader.ResolvePath(path)
	if err != nil {
		t.Fatalf("resolve %s: %v", path, err)
	}
	record, err := reader.ObjectMeta(id)
	if err != nil {
		t.Fatalf("object meta %s: %v", path, err)
	}
	manifest, chunks := fileBlobs(t, dir, record)
	return record, manifest, chunks
}

// Gate D (GC): Rust creates a snapshot and garbage; the Go background watcher
// (bounded passes, cancellation) sweeps it; Rust verifies --full and mounts the
// snapshot read-only. No Go production path invokes Rust.
func TestGCHandoffGoBackgroundWatchRustVerifies(t *testing.T) {
	bin := rustBinary(t)
	dir := t.TempDir()
	const snapshotContent = "snapshot-content"
	const liveContent = "LIVE-CONTENT-123"

	runRust(t, bin, "--store", dir, "init", "--checkpoint-interval", "0")
	runRust(t, bin, "--store", dir, "create", "/keep.txt", "--text", snapshotContent)
	runRust(t, bin, "--store", dir, "snapshot", "create", "keep")
	runRust(t, bin, "--store", dir, "write", "/keep.txt", "--text", liveContent)
	runRust(t, bin, "--store", dir, "create", "/gone.txt", "--text", "rust-garbage-background-watch")
	_, goneManifest, goneChunks := rustReadObjectBlobs(t, dir, "/gone.txt")
	runRust(t, bin, "--store", dir, "unlink", "/gone.txt")

	reader, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("open snapshot state: %v", err)
	}
	snapshotCommit, err := reader.LookupSnapshot("keep")
	if err != nil {
		reader.Close()
		t.Fatalf("lookup snapshot: %v", err)
	}
	snapshotState, err := reader.StateAt(snapshotCommit)
	if err != nil {
		reader.Close()
		t.Fatalf("snapshot state: %v", err)
	}
	keepID, err := resolveInState(snapshotState, "/keep.txt")
	if err != nil {
		reader.Close()
		t.Fatalf("resolve keep at snapshot: %v", err)
	}
	snapshotManifest, snapshotChunks := fileBlobs(t, dir, snapshotState.Objects[keepID])
	reader.Close()

	writer, err := store.OpenWithOptions(dir, store.ReadWrite, gcOptions(0))
	if err != nil {
		t.Fatalf("open writer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- writer.GCWatch(ctx, 10*time.Millisecond, 2, nil)
	}()
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := os.Lstat(store.ManifestPath(dir, goneManifest)); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			writer.Close()
			t.Fatal("Go background watcher did not delete the Rust garbage manifest")
		}
		time.Sleep(25 * time.Millisecond)
	}
	for _, chunk := range goneChunks {
		if _, err := os.Lstat(store.ObjectPath(dir, chunk)); !os.IsNotExist(err) {
			cancel()
			<-done
			writer.Close()
			t.Fatalf("Go background watcher did not delete Rust chunk %s", chunk.Hex())
		}
	}
	cancel()
	if err := <-done; err != nil {
		writer.Close()
		t.Fatalf("GCWatch: %v", err)
	}
	if report, err := writer.Verify(true); err != nil || !report.OK {
		writer.Close()
		t.Fatalf("Go verify after watch: ok=%v err=%v problems=%s", report != nil && report.OK, err, formatProblems(report))
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	assertExists(t, store.ManifestPath(dir, snapshotManifest), true, "Rust snapshot manifest after Go watch")
	for _, chunk := range snapshotChunks {
		assertExists(t, store.ObjectPath(dir, chunk), true, "Rust snapshot chunk after Go watch")
	}

	rustVerifyFull(t, bin, dir)
	if got := rustCat(t, bin, dir, "/keep.txt"); got != liveContent {
		t.Fatalf("Rust live read after Go watch = %q, want %q", got, liveContent)
	}
	mountpoint, cleanup := rustMount(t, bin, dir, "--snapshot", "keep")
	defer cleanup()
	if data, err := os.ReadFile(filepath.Join(mountpoint, "keep.txt")); err != nil || string(data) != snapshotContent {
		t.Fatalf("Rust snapshot mount after Go watch = %q, %v (want %q)", string(data), err, snapshotContent)
	}
}

// Gate A (GC): Rust creates a store with a snapshot and an unreferenced blob;
// Go sweeps; Rust verifies and reads the snapshot exact.
func TestGCHandoffRustGarbageGoSweeps(t *testing.T) {
	bin := rustBinary(t)
	dir := t.TempDir()
	const snapshotContent = "snapshot-content"
	const liveContent = "LIVE-CONTENT-123"

	runRust(t, bin, "--store", dir, "init", "--checkpoint-interval", "0")
	runRust(t, bin, "--store", dir, "create", "/keep.txt", "--text", snapshotContent)
	runRust(t, bin, "--store", dir, "snapshot", "create", "keep")

	reader, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("open snapshot state: %v", err)
	}
	snapshotCommit, err := reader.LookupSnapshot("keep")
	if err != nil {
		reader.Close()
		t.Fatalf("lookup snapshot: %v", err)
	}
	snapshotState, err := reader.StateAt(snapshotCommit)
	if err != nil {
		reader.Close()
		t.Fatalf("snapshot state: %v", err)
	}
	keepID, err := resolveInState(snapshotState, "/keep.txt")
	if err != nil {
		reader.Close()
		t.Fatalf("resolve keep at snapshot: %v", err)
	}
	keepRecord := snapshotState.Objects[keepID]
	reader.Close()
	snapshotManifest, snapshotChunks := fileBlobs(t, dir, keepRecord)

	runRust(t, bin, "--store", dir, "write", "/keep.txt", "--text", liveContent)
	runRust(t, bin, "--store", dir, "create", "/gone.txt", "--text", "rust-garbage-unreferenced")
	_, goneManifest, goneChunks := rustReadObjectBlobs(t, dir, "/gone.txt")
	runRust(t, bin, "--store", dir, "unlink", "/gone.txt")

	s, err := store.OpenWithOptions(dir, store.ReadWrite, gcOptions(0))
	if err != nil {
		t.Fatalf("go open writer: %v", err)
	}
	dry, err := s.GC(false)
	if err != nil {
		s.Close()
		t.Fatalf("go dry GC: %v", err)
	}
	if dry.UnreachableFiles == 0 {
		s.Close()
		t.Fatalf("go dry GC found no candidates: %+v", dry)
	}
	assertExists(t, store.ManifestPath(dir, goneManifest), true, "rust garbage manifest after dry run")
	for _, chunk := range goneChunks {
		assertExists(t, store.ObjectPath(dir, chunk), true, "rust garbage chunk after dry run")
	}
	applied, err := s.GC(true)
	if err != nil {
		s.Close()
		t.Fatalf("go apply GC: %v", err)
	}
	if applied.DeletedFiles == 0 {
		s.Close()
		t.Fatalf("go apply GC deleted nothing: %+v", applied)
	}
	if report, err := s.Verify(true); err != nil || !report.OK {
		s.Close()
		t.Fatalf("go verify after GC: ok=%v err=%v problems=%s", report != nil && report.OK, err, formatProblems(report))
	}
	s.Close()

	assertExists(t, store.ManifestPath(dir, goneManifest), false, "rust garbage manifest after Go GC")
	for _, chunk := range goneChunks {
		assertExists(t, store.ObjectPath(dir, chunk), false, "rust garbage chunk after Go GC")
	}
	assertExists(t, store.ManifestPath(dir, snapshotManifest), true, "snapshot manifest after Go GC")
	for _, chunk := range snapshotChunks {
		assertExists(t, store.ObjectPath(dir, chunk), true, "snapshot chunk after Go GC")
	}

	rustVerifyFull(t, bin, dir)
	if got := rustCat(t, bin, dir, "/keep.txt"); got != liveContent {
		t.Fatalf("rust live read = %q, want %q", got, liveContent)
	}
	mountpoint, cleanup := rustMount(t, bin, dir, "--snapshot", "keep")
	defer cleanup()
	if data, err := os.ReadFile(filepath.Join(mountpoint, "keep.txt")); err != nil || string(data) != snapshotContent {
		t.Fatalf("rust snapshot read = %q, %v (want %q)", string(data), err, snapshotContent)
	}

	verifyReader, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer verifyReader.Close()
	if got, err := verifyReader.ReadObjectAt(&snapshotCommit, keepID); err != nil || string(got) != snapshotContent {
		t.Fatalf("go snapshot read = %q, %v", string(got), err)
	}
}

// Gate B (GC): Go creates garbage; Rust gc --apply sweeps; Go verifies and
// reads the snapshot exact.
func TestGCHandoffGoGarbageRustSweeps(t *testing.T) {
	bin := rustBinary(t)
	dir := t.TempDir()
	const snapshotContent = "snapshot-content"
	const liveContent = "LIVE-CONTENT-123"

	s, err := store.Init(dir, gcOptions(0))
	if err != nil {
		t.Fatalf("go init: %v", err)
	}
	keepID, err := s.CreateFile(model.RootID, []byte("keep.txt"), []byte(snapshotContent), 0o644, 0, 0, nil)
	if err != nil {
		s.Close()
		t.Fatalf("go create keep: %v", err)
	}
	snapshotCommit, err := s.SnapshotCreate("keep")
	if err != nil {
		s.Close()
		t.Fatalf("go snapshot: %v", err)
	}
	snapshotManifest, snapshotChunks := fileBlobs(t, dir, s.CurrentState().Objects[keepID])
	if _, err := s.WriteFile(keepID, 0, []byte(liveContent)); err != nil {
		s.Close()
		t.Fatalf("go overwrite keep: %v", err)
	}
	goneID, err := s.CreateFile(model.RootID, []byte("gone.txt"), []byte("go-garbage-unreferenced"), 0o644, 0, 0, nil)
	if err != nil {
		s.Close()
		t.Fatalf("go create gone: %v", err)
	}
	goneManifest, goneChunks := fileBlobs(t, dir, s.CurrentState().Objects[goneID])
	if err := s.Unlink(model.RootID, []byte("gone.txt")); err != nil {
		s.Close()
		t.Fatalf("go unlink gone: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("go close: %v", err)
	}

	output := runRust(t, bin, "--store", dir, "gc", "--apply", "--grace-secs", "0")
	if !strings.Contains(output, "applied=true") {
		t.Fatalf("rust GC did not report applied=true:\n%s", output)
	}

	assertExists(t, store.ManifestPath(dir, goneManifest), false, "go garbage manifest after Rust GC")
	for _, chunk := range goneChunks {
		assertExists(t, store.ObjectPath(dir, chunk), false, "go garbage chunk after Rust GC")
	}
	assertExists(t, store.ManifestPath(dir, snapshotManifest), true, "snapshot manifest after Rust GC")
	for _, chunk := range snapshotChunks {
		assertExists(t, store.ObjectPath(dir, chunk), true, "snapshot chunk after Rust GC")
	}

	rustVerifyFull(t, bin, dir)
	if got := rustCat(t, bin, dir, "/keep.txt"); got != liveContent {
		t.Fatalf("rust live read = %q, want %q", got, liveContent)
	}

	reader, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("go reopen: %v", err)
	}
	defer reader.Close()
	report, err := reader.Verify(true)
	if err != nil || !report.OK {
		t.Fatalf("go verify after Rust GC: ok=%v err=%v problems=%s",
			report != nil && report.OK, err, formatProblems(report))
	}
	if got, err := reader.ReadObjectAt(&snapshotCommit, keepID); err != nil || string(got) != snapshotContent {
		t.Fatalf("go snapshot read = %q, %v", string(got), err)
	}
	if got, err := reader.ReadObject(keepID); err != nil || string(got) != liveContent {
		t.Fatalf("go live read = %q, %v", string(got), err)
	}
}

// Gate C (GC): three alternating writer generations with GC between them.
// Object ids, version ids, content ids, and the snapshot stay stable.
func TestGCHandoffAlternatingGenerations(t *testing.T) {
	bin := rustBinary(t)
	dir := t.TempDir()
	const stableContent = "stable-v1"

	s, err := store.Init(dir, gcOptions(0))
	if err != nil {
		t.Fatalf("go init: %v", err)
	}
	stableID, err := s.CreateFile(model.RootID, []byte("stable.txt"), []byte(stableContent), 0o644, 0, 0, nil)
	if err != nil {
		s.Close()
		t.Fatalf("create stable: %v", err)
	}
	snapshotCommit, err := s.SnapshotCreate("base")
	if err != nil {
		s.Close()
		t.Fatalf("snapshot base: %v", err)
	}
	stableRecord := s.CurrentState().Objects[stableID]
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	for round := 0; round < 3; round++ {
		name := "/garbage-" + itoa(uint64(round)) + ".txt"
		content := "round-" + itoa(uint64(round)) + "-garbage"
		if round%2 == 0 {
			writer, err := store.OpenWithOptions(dir, store.ReadWrite, gcOptions(0))
			if err != nil {
				t.Fatalf("round %d go open: %v", round, err)
			}
			id, err := writer.CreateFile(model.RootID, []byte(strings.TrimPrefix(name, "/")), []byte(content), 0o644, 0, 0, nil)
			if err != nil {
				writer.Close()
				t.Fatalf("round %d go create: %v", round, err)
			}
			manifest, chunks := fileBlobs(t, dir, writer.CurrentState().Objects[id])
			if err := writer.Unlink(model.RootID, []byte(strings.TrimPrefix(name, "/"))); err != nil {
				writer.Close()
				t.Fatalf("round %d go unlink: %v", round, err)
			}
			report, err := writer.GC(true)
			if err != nil {
				writer.Close()
				t.Fatalf("round %d go GC: %v", round, err)
			}
			if report.DeletedFiles == 0 {
				writer.Close()
				t.Fatalf("round %d go GC deleted nothing: %+v", round, report)
			}
			writer.Close()
			assertExists(t, store.ManifestPath(dir, manifest), false, "round garbage manifest")
			for _, chunk := range chunks {
				assertExists(t, store.ObjectPath(dir, chunk), false, "round garbage chunk")
			}
		} else {
			runRust(t, bin, "--store", dir, "create", name, "--text", content)
			runRust(t, bin, "--store", dir, "unlink", name)
			runRust(t, bin, "--store", dir, "gc", "--apply", "--grace-secs", "0")
		}

		reader, err := store.Open(dir, store.ReadOnly)
		if err != nil {
			t.Fatalf("round %d reopen: %v", round, err)
		}
		record, err := reader.ObjectMeta(stableID)
		if err != nil {
			reader.Close()
			t.Fatalf("round %d stable meta: %v", round, err)
		}
		if record.ID != stableRecord.ID || record.Version != stableRecord.Version || record.Content != stableRecord.Content {
			reader.Close()
			t.Fatalf("round %d stable identity drifted: %+v vs %+v", round, record, stableRecord)
		}
		if got, err := reader.LookupSnapshot("base"); err != nil || got != snapshotCommit {
			reader.Close()
			t.Fatalf("round %d snapshot moved: %s, %v", round, got.Hex(), err)
		}
		if got, err := reader.ReadObjectAt(&snapshotCommit, stableID); err != nil || string(got) != stableContent {
			reader.Close()
			t.Fatalf("round %d snapshot read = %q, %v", round, string(got), err)
		}
		if got, err := reader.ReadObject(stableID); err != nil || string(got) != stableContent {
			reader.Close()
			t.Fatalf("round %d live read = %q, %v", round, string(got), err)
		}
		verify, err := reader.Verify(true)
		if err != nil || !verify.OK {
			reader.Close()
			t.Fatalf("round %d go verify: ok=%v err=%v problems=%s",
				round, verify != nil && verify.OK, err, formatProblems(verify))
		}
		reader.Close()
		rustVerifyFull(t, bin, dir)
	}
}

// Gate D (GC): SIGKILL during a Go commit, then Go GC, then the Rust oracle.
// The store must present the old or the new state; a valid unpublished tail is
// never swept, and its content is retained only when the commit is published.
func TestGCHandoffKilledGoCommit(t *testing.T) {
	bin := rustBinary(t)
	const content = "killed commit payload"
	cases := []struct {
		phase   string
		publish bool
	}{
		{"after_commit_file", false},
		{"after_superblock_write", true},
	}
	for _, tc := range cases {
		t.Run(tc.phase, func(t *testing.T) {
			dir := t.TempDir()
			s, err := store.Init(dir, gcOptions(0))
			if err != nil {
				t.Fatalf("init: %v", err)
			}
			s.Close()

			cmd := exec.Command(os.Args[0], "-test.run=TestCrashChildProcess")
			cmd.Env = append(os.Environ(),
				"WEFT_CRASH_STORE="+dir,
				"WEFT_CRASH_PHASE="+tc.phase,
				"WEFT_CRASH_CONTENT="+content,
			)
			output, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("child exited cleanly after %s: %s", tc.phase, output)
			}
			if _, ok := err.(*exec.ExitError); !ok {
				t.Fatalf("child execution failed: %v (%s)", err, output)
			}

			chunk := model.ContentHash([]byte(content))
			writer, err := store.OpenWithOptions(dir, store.ReadWrite, gcOptions(0))
			if err != nil {
				t.Fatalf("open writer after crash: %v", err)
			}
			if _, err := writer.GC(true); err != nil {
				writer.Close()
				t.Fatalf("GC after crash: %v", err)
			}
			if tc.publish {
				id, err := writer.ResolvePath("/crash.txt")
				if err != nil {
					writer.Close()
					t.Fatalf("published file missing after GC: %v", err)
				}
				if got, err := writer.ReadObject(id); err != nil || string(got) != content {
					writer.Close()
					t.Fatalf("published read after GC = %q, %v", string(got), err)
				}
			} else if _, err := writer.ResolvePath("/crash.txt"); err == nil {
				writer.Close()
				t.Fatal("unpublished tail became visible after GC")
			}
			if err := writer.Close(); err != nil {
				t.Fatalf("close writer: %v", err)
			}

			assertExists(t, store.ObjectPath(dir, chunk), tc.publish, "crash payload chunk")

			rustOutput, rustErr := runRustRaw(t, bin, "--store", dir, "verify", "--full")
			if tc.publish {
				if rustErr != nil || !strings.Contains(rustOutput, "ok=true") {
					t.Fatalf("rust verify after published crash commit failed: %v\n%s", rustErr, rustOutput)
				}
				if got := rustCat(t, bin, dir, "/crash.txt"); got != content {
					t.Fatalf("rust read after published crash = %q", got)
				}
			} else {
				if !strings.Contains(rustOutput, "ok=false") {
					t.Fatalf("rust verify should flag the unpublished tail: err=%v\n%s", rustErr, rustOutput)
				}
				for _, line := range strings.Split(rustOutput, "\n") {
					if strings.HasPrefix(line, "problem=") &&
						!strings.Contains(line, "above the highest published superblock generation") {
						t.Fatalf("unexpected rust problem after crash+GC: %s", line)
					}
				}
				if _, err := runRustRaw(t, bin, "--store", dir, "cat", "/crash.txt"); err == nil {
					t.Fatal("rust read the unpublished tail after GC")
				}
			}
		})
	}
}
