package store_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

func planeOptions(blobs, commits store.PlaneKind, blobRoot string) store.Options {
	opts := store.DefaultOptions()
	opts.ChunkSize = 4096
	opts.BlobBackend = blobs
	opts.CommitBackend = commits
	opts.BlobRoot = blobRoot
	stamp := overlayFixedTimestamp
	opts.FixedTimestampNS = &stamp
	return opts
}

// splitHistory writes the same deterministic history through whichever planes
// the store was opened with and returns its head, generation, and manifest id.
func splitHistory(t *testing.T, dir string, opts store.Options) (model.Hash32, uint64, model.Hash32) {
	t.Helper()
	s, err := store.Init(dir, opts)
	if err != nil {
		t.Fatalf("init split store: %v", err)
	}
	defer s.Close()
	payload := overlayPattern(9*4096+37, 31)
	id, err := s.CreateFileSeeded(model.RootID, []byte("split.bin"), payload, 0o644, 0, 0, nil, []byte("split-seed"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.WriteFile(id, 123, []byte("split-plane-write")); err != nil {
		t.Fatalf("write: %v", err)
	}
	record, err := s.ObjectMeta(id)
	if err != nil {
		t.Fatalf("meta: %v", err)
	}
	return s.Head(), s.Generation(), record.Content
}

func TestSplitPlanesMatchTheSingleBackendStore(t *testing.T) {
	type layout struct {
		name     string
		blobs    store.PlaneKind
		commits  store.PlaneKind
		separate bool
	}
	layouts := []layout{
		{"local-local", store.PlaneLocal, store.PlaneLocal, false},
		{"object-object", store.PlaneObject, store.PlaneObject, false},
		{"object-blobs-local-commits", store.PlaneObject, store.PlaneLocal, true},
		{"local-blobs-object-commits", store.PlaneLocal, store.PlaneObject, true},
	}
	var wantHead model.Hash32
	var wantGeneration uint64
	var wantManifest model.Hash32
	for index, tc := range layouts {
		dir := t.TempDir()
		blobRoot := ""
		if tc.separate {
			blobRoot = filepath.Join(t.TempDir(), "blobs")
		}
		head, generation, manifest := splitHistory(t, dir, planeOptions(tc.blobs, tc.commits, blobRoot))
		if index == 0 {
			wantHead, wantGeneration, wantManifest = head, generation, manifest
		} else {
			if head != wantHead {
				t.Fatalf("%s head %s != %s", tc.name, head.Hex(), wantHead.Hex())
			}
			if generation != wantGeneration {
				t.Fatalf("%s generation %d != %d", tc.name, generation, wantGeneration)
			}
			if manifest != wantManifest {
				t.Fatalf("%s manifest %s != %s", tc.name, manifest.Hex(), wantManifest.Hex())
			}
		}
		if tc.separate {
			// Blobs live only on the blob plane, control state only on the
			// commit plane. This is the routing rule, checked physically.
			if _, err := os.Stat(filepath.Join(dir, "objects")); !os.IsNotExist(err) {
				t.Fatalf("%s: objects/ exists on the commit root", tc.name)
			}
			if _, err := os.Stat(filepath.Join(dir, "manifests")); !os.IsNotExist(err) {
				t.Fatalf("%s: manifests/ exists on the commit root", tc.name)
			}
			if _, err := os.Stat(filepath.Join(blobRoot, "commits")); !os.IsNotExist(err) {
				t.Fatalf("%s: commits/ exists on the blob root", tc.name)
			}
			if _, err := os.Stat(filepath.Join(blobRoot, "superblock")); !os.IsNotExist(err) {
				t.Fatalf("%s: superblock exists on the blob root", tc.name)
			}
			if _, err := os.Stat(filepath.Join(blobRoot, "objects")); err != nil {
				t.Fatalf("%s: objects/ missing from the blob root: %v", tc.name, err)
			}
		}
		// Reopen each split store and verify the full catalog through the same
		// planes.
		reader, err := store.OpenWithOptions(dir, store.ReadOnly, planeOptions(tc.blobs, tc.commits, blobRoot))
		if err != nil {
			t.Fatalf("%s reopen: %v", tc.name, err)
		}
		object, err := reader.ResolvePath("/split.bin")
		if err != nil {
			t.Fatalf("%s resolve: %v", tc.name, err)
		}
		got, err := reader.ReadObject(object)
		if err != nil {
			t.Fatalf("%s read: %v", tc.name, err)
		}
		want := overlayPattern(9*4096+37, 31)
		copy(want[123:], []byte("split-plane-write"))
		if !bytes.Equal(got, want) {
			t.Fatalf("%s bytes differ after reopen", tc.name)
		}
		report, err := reader.Verify(true)
		if err != nil || !report.OK {
			t.Fatalf("%s verify: ok=%v err=%v problems=%v", tc.name, report != nil && report.OK, err, verifyProblems(report))
		}
		reader.Close()
	}
}

func verifyProblems(report *store.VerifyReport) []store.VerifyProblem {
	if report == nil {
		return nil
	}
	return report.Problems
}

func TestPlaneProbesAreMeasuredOnWritableOpen(t *testing.T) {
	dir := t.TempDir()
	opts := planeOptions(store.PlaneLocal, store.PlaneLocal, "")
	s, err := store.Init(dir, opts)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	s.Close()

	writer, err := store.OpenWithOptions(dir, store.ReadWrite, opts)
	if err != nil {
		t.Fatalf("writable open: %v", err)
	}
	defer writer.Close()
	planes := writer.Planes()
	if planes.BlobProbe == nil || !planes.BlobProbe.Attempted ||
		!planes.BlobProbe.CreateOnceVisible || !planes.BlobProbe.LengthMatch ||
		!planes.BlobProbe.RangeReadMatch || !planes.BlobProbe.DeleteObserved {
		t.Fatalf("blob probe evidence is incomplete: %+v", planes.BlobProbe)
	}
	if planes.CommitProbe == nil || !planes.CommitProbe.Attempted ||
		!planes.CommitProbe.CreateOK || !planes.CommitProbe.MatchingCompareExchangeOK ||
		!planes.CommitProbe.StaleCompareExchangeRejected {
		t.Fatalf("commit probe evidence is incomplete: %+v", planes.CommitProbe)
	}
	if !planes.Blobs.AtomicPublish || !planes.Commits.ConditionalUpdate {
		t.Fatalf("declared capabilities do not match a local plane: %+v", planes)
	}

	// A read-only open never probes and never writes.
	entriesBefore, err := os.ReadDir(filepath.Join(dir, "tmp"))
	if err != nil {
		t.Fatalf("read tmp: %v", err)
	}
	reader, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("read-only open: %v", err)
	}
	defer reader.Close()
	if reader.Planes().BlobProbe != nil || reader.Planes().CommitProbe != nil {
		t.Fatalf("a read-only open performed probes")
	}
	entriesAfter, err := os.ReadDir(filepath.Join(dir, "tmp"))
	if err != nil {
		t.Fatalf("read tmp: %v", err)
	}
	if len(entriesBefore) != len(entriesAfter) {
		t.Fatalf("read-only open left temporary files behind")
	}
}

func TestPosixPlanesAreRefusedForWriting(t *testing.T) {
	dir := t.TempDir()
	opts := planeOptions(store.PlaneLocal, store.PlaneLocal, "")
	s, err := store.Init(dir, opts)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	s.Close()

	for _, tc := range []store.Options{
		planeOptions(store.PlanePosix, store.PlaneLocal, ""),
		planeOptions(store.PlaneLocal, store.PlanePosix, ""),
	} {
		if _, err := store.OpenWithOptions(dir, store.ReadWrite, tc); err == nil {
			t.Fatalf("writable open with %s blob / %s commit plane was accepted",
				tc.BlobBackend, tc.CommitBackend)
		}
	}
	// Init with a weak plane also refuses before publishing anything.
	weakDir := t.TempDir()
	if _, err := store.Init(weakDir, planeOptions(store.PlanePosix, store.PlaneLocal, "")); err == nil {
		t.Fatal("Init with a posix blob plane was accepted")
	}
	if _, err := os.Stat(filepath.Join(weakDir, "FORMAT")); !os.IsNotExist(err) {
		t.Fatal("a refused Init left a FORMAT marker")
	}
	// A read-only open of an existing store is still allowed on the declared
	// weak plane: no capability is exercised.
	reader, err := store.OpenWithOptions(dir, store.ReadOnly, planeOptions(store.PlanePosix, store.PlaneLocal, ""))
	if err != nil {
		t.Fatalf("read-only open on a posix blob plane: %v", err)
	}
	reader.Close()
}

func TestSplitCrashProxyYieldsOldOrNew(t *testing.T) {
	for _, phase := range []string{"after_objects", "after_commit_file", "after_superblock_write"} {
		t.Run(phase, func(t *testing.T) {
			dir := t.TempDir()
			blobRoot := filepath.Join(t.TempDir(), "blobs")
			opts := planeOptions(store.PlaneObject, store.PlaneLocal, blobRoot)
			s, err := store.Init(dir, opts)
			if err != nil {
				t.Fatalf("init: %v", err)
			}
			payload := overlayPattern(6*4096, 32)
			id, err := s.CreateFileSeeded(model.RootID, []byte("crash.bin"), payload, 0o644, 0, 0, nil, []byte("split-crash"))
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			head := s.Head()
			generation := s.Generation()
			s.Close()

			cmd := exec.Command(os.Args[0], "-test.run=TestSplitCrashChildProcess")
			cmd.Env = append(os.Environ(),
				"WEFT_SPLIT_CRASH_STORE="+dir,
				"WEFT_SPLIT_CRASH_BLOBS="+blobRoot,
				"WEFT_CRASH_PHASE="+phase,
			)
			output, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("child exited cleanly after %s: %s", phase, output)
			}
			reader, err := store.OpenWithOptions(dir, store.ReadOnly, opts)
			if err != nil {
				t.Fatalf("reopen after crash at %s: %v", phase, err)
			}
			defer reader.Close()
			got, err := reader.ReadObject(id)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("bytes after crash at %s: %v", phase, err)
			}
			if reader.Head() != head || reader.Generation() != generation {
				if phase != "after_superblock_write" || reader.Generation() != generation+1 {
					t.Fatalf("head changed after crash at %s (generation %d)", phase, reader.Generation())
				}
			}
			report, err := reader.Verify(true)
			if err != nil {
				t.Fatalf("verify after crash at %s: %v", phase, err)
			}
			for _, problem := range report.Problems {
				// A commit file durable without a published superblock slot is an
				// unpublished tail; verify reports it and nothing else.
				if !strings.Contains(problem.Detail, "above the highest published superblock generation") {
					t.Fatalf("unexpected integrity problem after crash at %s: %+v", phase, problem)
				}
			}
		})
	}
}

func TestSplitCrashChildProcess(t *testing.T) {
	dir := os.Getenv("WEFT_SPLIT_CRASH_STORE")
	if dir == "" {
		t.Skip("split crash helper process; not run directly")
	}
	blobRoot := os.Getenv("WEFT_SPLIT_CRASH_BLOBS")
	opts := planeOptions(store.PlaneObject, store.PlaneLocal, blobRoot)
	s, err := store.OpenWithOptions(dir, store.ReadWrite, opts)
	if err != nil {
		t.Fatalf("child open: %v", err)
	}
	defer s.Close()
	content := overlayPattern(1024, 33)
	if _, err := s.CreateFile(model.RootID, []byte("second.bin"), content, 0o644, 0, 0, nil); err != nil {
		t.Fatalf("child create: %v", err)
	}
	t.Fatalf("child survived crash phase %q; the crash hook did not fire", os.Getenv("WEFT_CRASH_PHASE"))
}

// ---- cross-language split stores -----------------------------------------

func splitRustArgs(dir, blobRoot string) []string {
	return []string{
		"--store", dir,
		"--blob-backend", "local",
		"--commit-backend", "local",
		"--blob-root", blobRoot,
		"--fixed-timestamp-ns", "1700000000000000000",
	}
}

func TestRustSplitStoreGoReadsAndVerifies(t *testing.T) {
	bin := rustBinary(t)
	dir := t.TempDir()
	blobRoot := filepath.Join(t.TempDir(), "blobs")
	payloadDir := t.TempDir()
	payload := overlayPattern(7*65536+11, 41)
	payloadPath := filepath.Join(payloadDir, "payload.bin")
	if err := os.WriteFile(payloadPath, payload, 0o644); err != nil {
		t.Fatalf("payload: %v", err)
	}
	args := splitRustArgs(dir, blobRoot)
	runRust(t, bin, append(args, "init")...)
	runRust(t, bin, append(args, "create", "/split.bin", "--file", payloadPath, "--seed", "rust-split-seed")...)
	runRust(t, bin, append(args, "write", "/split.bin", "--offset", "1000", "--text", "rust-split")...)
	want := append([]byte(nil), payload...)
	copy(want[1000:], []byte("rust-split"))
	stat := decodeJSONObject(t, runRust(t, bin, append(args, "stat", "/split.bin", "--json")...))
	rustHead := rustInfoSplit(t, bin, args)

	reader, err := store.OpenWithOptions(dir, store.ReadOnly, planeOptions(store.PlaneLocal, store.PlaneLocal, blobRoot))
	if err != nil {
		t.Fatalf("go open rust split store: %v", err)
	}
	defer reader.Close()
	id, err := reader.ResolvePath("/split.bin")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got, err := reader.ReadObject(id)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("go read of rust split store: %v", err)
	}
	record, err := reader.ObjectMeta(id)
	if err != nil {
		t.Fatalf("meta: %v", err)
	}
	if record.Content.Hex() != stat["content_id"].(string) {
		t.Fatalf("manifest id differs: go %s rust %v", record.Content.Hex(), stat["content_id"])
	}
	if reader.Head().Hex() != rustHead {
		t.Fatalf("head differs: go %s rust %s", reader.Head().Hex(), rustHead)
	}
	report, err := reader.Verify(true)
	if err != nil || !report.OK {
		t.Fatalf("go verify of rust split store: %v", err)
	}
}

func rustInfoSplit(t *testing.T, bin string, args []string) string {
	t.Helper()
	command := append([]string{}, args...)
	command = append(command, "--json", "info")
	out := runRust(t, bin, command...)
	info := decodeJSONObject(t, out)
	head, ok := info["snapshot_root"].(string)
	if !ok || len(head) != 64 {
		t.Fatalf("rust info has no snapshot_root: %s", out)
	}
	return head
}

func TestGoSplitStoreRustReadsAndVerifies(t *testing.T) {
	bin := rustBinary(t)
	dir := t.TempDir()
	blobRoot := filepath.Join(t.TempDir(), "blobs")
	opts := planeOptions(store.PlaneObject, store.PlaneLocal, blobRoot)
	payload := overlayPattern(7*65536+11, 42)
	s, err := store.Init(dir, opts)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	id, err := s.CreateFileSeeded(model.RootID, []byte("split.bin"), payload, 0o644, 0, 0, nil, []byte("go-split-seed"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.WriteFile(id, 1000, []byte("go-split")); err != nil {
		t.Fatalf("write: %v", err)
	}
	record, err := s.ObjectMeta(id)
	if err != nil {
		t.Fatalf("meta: %v", err)
	}
	head := s.Head()
	s.Close()
	want := append([]byte(nil), payload...)
	copy(want[1000:], []byte("go-split"))

	args := []string{
		"--store", dir,
		"--blob-backend", "local",
		"--commit-backend", "local",
		"--blob-root", blobRoot,
	}
	runRust(t, bin, append(args, "verify", "--full")...)
	rustBytes := runRustBytes(t, bin, append(args, "cat", "/split.bin")...)
	if !bytes.Equal(rustBytes, want) {
		t.Fatalf("rust read of the go split store differs")
	}
	rustStat := decodeJSONObject(t, runRust(t, bin, append(args, "stat", "/split.bin", "--json")...))
	if rustStat["content_id"].(string) != record.Content.Hex() {
		t.Fatalf("manifest id differs: rust %v go %s", rustStat["content_id"], record.Content.Hex())
	}
	if rustInfoSplit(t, bin, args) != head.Hex() {
		t.Fatalf("rust head differs from the go head")
	}
}

func TestPosixBlobPlaneRefusalIsTyped(t *testing.T) {
	dir := t.TempDir()
	opts := planeOptions(store.PlaneLocal, store.PlaneLocal, "")
	s, err := store.Init(dir, opts)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	s.Close()
	_, err = store.OpenWithOptions(dir, store.ReadWrite, planeOptions(store.PlanePosix, store.PlaneLocal, ""))
	if err == nil {
		t.Fatal("posix blob plane accepted for writing")
	}
	typed, ok := err.(*werr.Error)
	if !ok || typed.Kind != werr.Unsupported {
		t.Fatalf("refusal class = %v, want Unsupported", err)
	}
}
