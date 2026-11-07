package store

// GCS integration court. These tests run only when WEFT_GCS_TEST_ENDPOINT
// names a reachable GCS-compatible endpoint; otherwise they skip with a reason.
// They are in `package store` so the generation-precondition contract can be
// exercised directly (create-once conflict, matching/stale generation CAS,
// ranged reads, listing paging) without inventing an exported test surface.
//
// Environment (set by scripts/go-gcs-court.sh):
//
//	WEFT_GCS_TEST_ENDPOINT  e.g. http://weft-gcs-emulator:4443
//	WEFT_GCS_TEST_BUCKET    unique-per-court bucket prefix
//	WEFT_GCS_PROJECT        project used for bucket creation
//	WEFT_GCS_ANONYMOUS=1    emulator mode
//	WEFT_GCS_LOCK_LEASE_SECS / WEFT_GCS_FENCE_LEASE_SECS
//
// Every test uses its own bucket so a failed test cannot corrupt another's
// control state. The emulator's data backend is memory and the court destroys
// the container on exit.

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/infinityabundance/WeftCodec-Go/hash"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

var gcsTestCounter atomic.Uint64

func requireGCSEndpoint(t *testing.T) string {
	t.Helper()
	endpoint := os.Getenv("WEFT_GCS_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("WEFT_GCS_TEST_ENDPOINT is not set; the GCS court is not running")
	}
	return endpoint
}

func gcsTestBucket(t *testing.T) string {
	t.Helper()
	prefix := os.Getenv("WEFT_GCS_TEST_BUCKET")
	if prefix == "" {
		prefix = "weft-go"
	}
	name := strings.ToLower(prefix)
	cleaned := make([]byte, 0, len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			cleaned = append(cleaned, c)
		} else {
			cleaned = append(cleaned, '-')
		}
	}
	if len(cleaned) == 0 || cleaned[0] < 'a' || cleaned[0] > 'z' {
		cleaned = append([]byte("weft-"), cleaned...)
	}
	return fmt.Sprintf("%s-%d-%d", string(cleaned), os.Getpid(), gcsTestCounter.Add(1))
}

func gcsTestConfig(t *testing.T, bucket string, lease time.Duration) GCSConfig {
	t.Helper()
	endpoint := requireGCSEndpoint(t)
	project := os.Getenv("WEFT_GCS_PROJECT")
	if project == "" {
		project = "weft-court"
	}
	if lease <= 0 {
		lease = 60 * time.Second
	}
	config := GCSConfig{
		Endpoint: endpoint, Bucket: bucket, Project: project,
		Scope: GCSScopeStorageReadWrite, LockLease: lease, RequestTimeout: 30 * time.Second,
	}
	// Exactly one credential form, in the same precedence the court uses.
	if credentials := os.Getenv("WEFT_GCS_CREDENTIALS"); credentials != "" {
		config.ServiceAccountPath = credentials
	} else if token := os.Getenv("WEFT_GCS_ACCESS_TOKEN"); token != "" {
		config.Token = token
	} else {
		config.Anonymous = true
	}
	return config
}

func gcsTestOptions(t *testing.T, bucket string, lease time.Duration) Options {
	t.Helper()
	config := gcsTestConfig(t, bucket, lease)
	options := DefaultOptions()
	options.BlobBackend = PlaneGCS
	options.CommitBackend = PlaneGCS
	options.GCS = &config
	options.GCGraceSecs = 0
	return options
}

func gcsTestClient(t *testing.T, bucket string, lease time.Duration) *gcsClient {
	t.Helper()
	client, err := newGCSClient(gcsTestConfig(t, bucket, lease))
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	return client
}

// TestGCSBlobPlaneCreateOnceRangesListingAndPaging covers the blob-plane
// contract the store depends on, and proves the listing follows page tokens.
func TestGCSBlobPlaneCreateOnceRangesListingAndPaging(t *testing.T) {
	bucket := gcsTestBucket(t)
	client := gcsTestClient(t, bucket, 0)
	if err := client.ensureBucket(); err != nil {
		t.Fatalf("ensure bucket: %v", err)
	}
	plane := newGCSBlobPlane(client)

	payload := []byte("weft-gcs-blob-plane-payload-0123456789")
	id := hash.Domain("weft/chunk/v1", payload)
	if err := plane.Put(BlobObject, id, payload); err != nil {
		t.Fatalf("create-once put: %v", err)
	}
	if err := plane.Put(BlobObject, id, payload); err != nil {
		t.Fatalf("identical repeat must be idempotent: %v", err)
	}
	expectClass(t, plane.Put(BlobObject, id, []byte("different bytes under the same content key")),
		werr.Exists, "different bytes under an existing content key")

	whole, err := plane.Get(BlobObject, id)
	if err != nil || string(whole) != string(payload) {
		t.Fatalf("whole read: %q err=%v", whole, err)
	}
	length, err := plane.Length(BlobObject, id)
	if err != nil || length != uint64(len(payload)) {
		t.Fatalf("length = %d err=%v", length, err)
	}
	start := uint64(7)
	ranged, err := plane.GetRange(BlobObject, id, start, 11)
	if err != nil {
		t.Fatalf("ranged read: %v", err)
	}
	if string(ranged) != string(payload[start:start+11]) {
		t.Fatalf("ranged read = %q, want %q", ranged, payload[start:start+11])
	}
	if tail, err := plane.GetRange(BlobObject, id, uint64(len(payload)), 4); err != nil || len(tail) != 0 {
		t.Fatalf("end-of-object range: %q err=%v", tail, err)
	}
	if exists, err := plane.Exists(BlobObject, id); err != nil || !exists {
		t.Fatalf("exists = %t err=%v", exists, err)
	}

	// Add four more objects and verify the listing follows `nextPageToken` with a
	// two-object page. The page size is a test-only client knob.
	for index := 0; index < 4; index++ {
		extra := []byte(fmt.Sprintf("paging-payload-%d", index))
		extraID := hash.Domain("weft/chunk/v1", extra)
		if err := plane.Put(BlobObject, extraID, extra); err != nil {
			t.Fatalf("paging put %d: %v", index, err)
		}
	}
	client.pageSize = 2
	entries, problems, err := plane.List("objects")
	client.pageSize = 0
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(problems) != 0 {
		t.Fatalf("listing problems: %v", problems)
	}
	seen := map[model.Hash32]bool{}
	for _, entry := range entries {
		if entry.Kind == BlobObject {
			seen[entry.ID] = true
		}
	}
	if !seen[id] || len(seen) != 5 {
		t.Fatalf("paged listing returned %d distinct objects, want 5", len(seen))
	}

	// Cold read from a second connection.
	coldPlane := newGCSBlobPlane(gcsTestClient(t, bucket, 0))
	cold, err := coldPlane.Get(BlobObject, id)
	if err != nil || string(cold) != string(payload) {
		t.Fatalf("cold read: %q err=%v", cold, err)
	}

	probe, err := plane.probe()
	if err != nil {
		t.Fatalf("blob probe: %v", err)
	}
	if !probe.CreateOnceVisible || !probe.LengthMatch || !probe.RangeReadMatch || !probe.DeleteObserved {
		t.Fatalf("blob probe evidence incomplete: %+v", probe)
	}

	if err := plane.Delete(BlobObject, id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if exists, err := plane.Exists(BlobObject, id); err != nil || exists {
		t.Fatalf("exists after delete = %t err=%v", exists, err)
	}
	expectClass(t, func() error { _, err := plane.Get(BlobObject, id); return err }(), werr.NotFound, "get after delete")
	expectClass(t, plane.Delete(BlobObject, id), werr.NotFound, "delete twice")
}

// TestGCSResumableUpload exercises the >5 MiB two-step upload path, reads the
// bytes back with the generation that was assigned, and deletes them.
func TestGCSResumableUpload(t *testing.T) {
	bucket := gcsTestBucket(t)
	client := gcsTestClient(t, bucket, 0)
	if err := client.ensureBucket(); err != nil {
		t.Fatalf("ensure bucket: %v", err)
	}
	payload := bytes.Repeat([]byte("weft-resumable-upload-"), 300000) // 6.3 MB > 5 MiB
	if uint64(len(payload)) <= gcsSimpleUploadMax {
		t.Fatalf("fixture is %d bytes, not above the %d-byte simple bound", len(payload), gcsSimpleUploadMax)
	}
	name := "tmp/resumable-" + strconv.Itoa(os.Getpid())
	generation, ok, err := client.upload(name, payload, gcsMissing())
	if err != nil || !ok {
		t.Fatalf("resumable upload: ok=%t err=%v", ok, err)
	}
	read, readGeneration, present, err := client.readWithGeneration(name)
	if err != nil || !present {
		t.Fatalf("read back: present=%t err=%v", present, err)
	}
	if !bytes.Equal(read, payload) {
		t.Fatalf("resumable payload differs (%d vs %d bytes)", len(read), len(payload))
	}
	if readGeneration != generation {
		t.Fatalf("generation = %d, want %d", readGeneration, generation)
	}
	if err := client.deleteObject(name); err != nil {
		t.Fatalf("delete: %v", err)
	}
	t.Logf("resumable upload: %d bytes at generation %d, read back byte-identically", len(payload), generation)
}

// TestGCSCommitVolumeAndGenerationPreconditions measures create-once,
// matching/stale compare-and-swap, strict generation comparison, commit
// enumeration, and the diagnostics the court records.
func TestGCSCommitVolumeAndGenerationPreconditions(t *testing.T) {
	bucket := gcsTestBucket(t)
	client := gcsTestClient(t, bucket, 0)
	control := newGCSControl(client)
	if err := control.EnsureLayout(); err != nil {
		t.Fatalf("ensure layout: %v", err)
	}
	if err := control.probeConditionalWrites(); err != nil {
		t.Fatalf("generation probe: %v", err)
	}
	diagnostics := strings.Join(client.diagnostics(), "\n")
	if !strings.Contains(diagnostics, "generation preconditions measured at open") {
		t.Fatalf("diagnostics do not record the measured preconditions: %v", diagnostics)
	}
	t.Logf("measured GCS precondition behaviour: ifGenerationMatch=0 create-once, matching generation accepted, stale generation refused")

	if err := control.CreateFormat(); err != nil {
		t.Fatalf("create FORMAT: %v", err)
	}
	if err := control.CreateFormat(); err != nil {
		t.Fatalf("identical FORMAT repeat must be idempotent: %v", err)
	}
	format, err := control.ReadFormat()
	if err != nil || string(format) != model.FormatContents {
		t.Fatalf("FORMAT = %q err=%v", format, err)
	}

	if err := control.WriteRecordNew("refs/snapshots/s1", []byte("abc\n")); err != nil {
		t.Fatalf("record create: %v", err)
	}
	if err := control.WriteRecordNew("refs/snapshots/s1", []byte("abc\n")); err != nil {
		t.Fatalf("identical record repeat must be idempotent: %v", err)
	}
	expectClass(t, control.WriteRecordNew("refs/snapshots/s1", []byte("zzz\n")),
		werr.Exists, "different bytes under a create-once record")

	// Record generation behaviour directly: matching succeeds, the old
	// generation is stale, and the winner's bytes survive the refused write.
	firstMeta, err := client.metadata("refs/snapshots/s1")
	if err != nil || firstMeta == nil {
		t.Fatalf("metadata: %+v err=%v", firstMeta, err)
	}
	secondGeneration, ok, err := client.upload("refs/snapshots/s1", []byte("second\n"), gcsMatches(firstMeta.Generation))
	if err != nil || !ok {
		t.Fatalf("matching generation upload: ok=%t err=%v", ok, err)
	}
	if secondGeneration <= firstMeta.Generation {
		t.Fatalf("generation did not advance: %d -> %d", firstMeta.Generation, secondGeneration)
	}
	if _, ok, err := client.upload("refs/snapshots/s1", []byte("stale-write\n"), gcsMatches(firstMeta.Generation)); err != nil {
		t.Fatalf("stale generation upload: %v", err)
	} else if ok {
		t.Fatal("a stale generation was accepted")
	}
	t.Logf("generation CAS measured: create generation %d, matching write accepted at generation %d, stale precondition %d refused",
		firstMeta.Generation, secondGeneration, firstMeta.Generation)
	stored, present, err := control.ReadRecord("refs/snapshots/s1")
	if err != nil || !present || string(stored) != "second\n" {
		t.Fatalf("refused stale write changed the bytes: %q present=%t err=%v", stored, present, err)
	}

	// Token CAS: matching succeeds, the old token is refused with Busy.
	token, err := control.CompareExchange("catalog", nil, []byte("one"))
	if err != nil {
		t.Fatalf("create CAS: %v", err)
	}
	if _, err := control.CompareExchange("catalog", &token, []byte("two")); err != nil {
		t.Fatalf("matching CAS: %v", err)
	}
	expectClass(t, func() error {
		_, err := control.CompareExchange("catalog", &token, []byte("three"))
		return err
	}(), werr.Busy, "stale CAS token")

	commitBytes := EncodeCommitFile([]byte("not a real commit body, but the key path is what this checks"))
	if err := control.CreateCommit(7, commitBytes); err != nil {
		t.Fatalf("create commit: %v", err)
	}
	if err := control.CreateCommit(7, commitBytes); err != nil {
		t.Fatalf("identical commit repeat must be idempotent: %v", err)
	}
	expectClass(t, control.CreateCommit(7, []byte("different")), werr.Exists, "different commit bytes")
	generations, err := control.ListCommitGenerations()
	if err != nil {
		t.Fatalf("list commits: %v", err)
	}
	found := false
	for _, generation := range generations {
		if generation == 7 {
			found = true
		}
	}
	if !found {
		t.Fatalf("generation 7 is not listed: %v", generations)
	}
	if _, err := control.ReadCommit(7); err == nil {
		t.Fatal("a malformed commit record was accepted")
	}
}

// TestGCSFencedWriterTakeover drives the lease protocol: a live lock refuses a
// second writer, an expired lease is reclaimed with the next fence, the stale
// writer cannot publish, and release is a conditional tombstone.
func TestGCSFencedWriterTakeover(t *testing.T) {
	bucket := gcsTestBucket(t)
	options := gcsTestOptions(t, bucket, 1*time.Second)

	first, err := Init("", options)
	if err != nil {
		t.Fatalf("init first writer: %v", err)
	}
	if _, err := first.CreateFile(model.RootID, []byte("a.txt"), []byte("first"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("first write: %v", err)
	}
	firstHead := first.Head()

	_, err = OpenWithOptions("", ReadWrite, options)
	expectClass(t, err, werr.Busy, "second writer while the lease is live")

	time.Sleep(1200 * time.Millisecond)
	second, err := OpenWithOptions("", ReadWrite, options)
	if err != nil {
		t.Fatalf("takeover open: %v", err)
	}
	if second.Generation() != first.Generation() {
		t.Fatalf("successor generation = %d, want %d", second.Generation(), first.Generation())
	}
	lock, err := newGCSControl(gcsTestClient(t, bucket, 0)).ReadLockRecord()
	if err != nil || lock == nil {
		t.Fatalf("read lock: %+v err=%v", lock, err)
	}
	if lock.fence < 2 {
		t.Fatalf("takeover did not advance the fence: %+v", lock)
	}
	if lock.schemaVersion != 3 {
		t.Fatalf("lock schema version = %d, want 3", lock.schemaVersion)
	}

	_, err = first.CreateFile(model.RootID, []byte("stale.txt"), []byte("stale"), 0o644, 0, 0, nil)
	expectClass(t, err, werr.Busy, "stale writer publication")
	if second.Generation() != first.Generation() {
		t.Fatalf("stale publication moved the head: %d -> %d", first.Generation(), second.Generation())
	}
	if _, err := second.ResolvePath("/stale.txt"); err == nil {
		t.Fatal("the stale writer's file became visible")
	}
	_ = firstHead

	if err := first.Close(); err != nil {
		t.Fatalf("closing the stale writer must not replace the successor's lock: %v", err)
	}
	if _, err := second.CreateFile(model.RootID, []byte("b.txt"), []byte("second"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("successor write after stale close: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("release successor: %v", err)
	}
	record, err := newGCSControl(gcsTestClient(t, bucket, 0)).ReadLockRecord()
	if err != nil || record == nil {
		t.Fatalf("read released lock: %+v err=%v", record, err)
	}
	if !record.released {
		t.Fatalf("release did not publish a tombstone: %+v", record)
	}
	third, err := OpenWithOptions("", ReadWrite, options)
	if err != nil {
		t.Fatalf("reclaim after release: %v", err)
	}
	if third.Generation() != second.Generation() {
		t.Fatalf("reclaim changed the head: %d -> %d", second.Generation(), third.Generation())
	}
	third.Close()
}

// TestGCSStoreRoundTrip runs init, writes, snapshot, verify --full, a
// read-only reopen with exact bytes, unlink plus GC, and a final verify.
func TestGCSStoreRoundTrip(t *testing.T) {
	bucket := gcsTestBucket(t)
	options := gcsTestOptions(t, bucket, 60*time.Second)
	writer, err := Init("", options)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if writer.Root() != "gcs://"+bucket {
		t.Fatalf("store root label = %q", writer.Root())
	}
	planes := writer.Planes()
	if planes.Blobs.Backend != "gcs" || planes.Commits.Backend != "gcs" {
		t.Fatalf("planes = %+v", planes)
	}
	if planes.BlobProbe == nil || planes.CommitProbe == nil {
		t.Fatalf("writable open did not record probe evidence: %+v", planes)
	}

	payloads := map[string][]byte{
		"/alpha.txt": []byte(strings.Repeat("alpha-", 4096)),
		"/beta.bin":  []byte(strings.Repeat("beta-0123456789", 2048)),
		"/gamma.txt": []byte("gamma"),
	}
	for path, data := range payloads {
		if _, err := writer.CreateFile(model.RootID, []byte(path[1:]), data, 0o644, 0, 0, nil); err != nil {
			t.Fatalf("create %s: %v", path, err)
		}
	}
	report, err := writer.Verify(true)
	if err != nil || !report.OK {
		t.Fatalf("verify on the writer: %v %+v", err, report)
	}
	if stats, ok := writer.GCSStats(); ok {
		t.Logf("host-local GCS counters (writer, emulator): requests=%d reads=%d range_reads=%d bytes_read=%d writes=%d bytes_written=%d conflicts=%d",
			stats.Requests, stats.Reads, stats.RangeReads, stats.BytesRead, stats.Writes, stats.BytesWritten, stats.ConditionalConflict)
	}
	generation := writer.Generation()
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	reader, err := OpenWithOptions("", ReadOnly, options)
	if err != nil {
		t.Fatalf("read-only reopen: %v", err)
	}
	if reader.Generation() != generation {
		t.Fatalf("reopen generation = %d, want %d", reader.Generation(), generation)
	}
	for path, want := range payloads {
		id, err := reader.ResolvePath(path)
		if err != nil {
			t.Fatalf("resolve %s: %v", path, err)
		}
		got, err := reader.ReadObject(id)
		if err != nil || string(got) != string(want) {
			t.Fatalf("read %s returned %d bytes, want %d (err=%v)", path, len(got), len(want), err)
		}
	}
	report, err = reader.Verify(true)
	if err != nil || !report.OK {
		t.Fatalf("verify on the reader: %v %+v", err, report)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close reader: %v", err)
	}

	cleaner, err := OpenWithOptions("", ReadWrite, options)
	if err != nil {
		t.Fatalf("writable reopen for GC: %v", err)
	}
	if err := cleaner.Unlink(model.RootID, []byte("alpha.txt")); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	if _, err := cleaner.SnapshotCreate("s1"); err != nil {
		t.Fatalf("snapshot after unlink: %v", err)
	}
	gc, err := cleaner.GC(true)
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if gc.DeletedFiles == 0 {
		t.Fatalf("gc collected nothing after an unlink: %+v", gc)
	}
	report, err = cleaner.Verify(true)
	if err != nil || !report.OK {
		t.Fatalf("verify after GC: %v %+v", err, report)
	}
	if _, err := cleaner.ResolvePath("/alpha.txt"); err == nil {
		t.Fatal("unlinked file is still visible")
	}
	if err := cleaner.Close(); err != nil {
		t.Fatalf("close cleaner: %v", err)
	}
}

// TestGCSCrashChildProcess is the child half of the crash proxy.
func TestGCSCrashChildProcess(t *testing.T) {
	bucket := os.Getenv("WEFT_GCS_CRASH_BUCKET")
	if bucket == "" {
		t.Skip("GCS crash helper process; not run directly")
	}
	phase := os.Getenv("WEFT_CRASH_PHASE")
	if phase == "" {
		t.Fatal("WEFT_GCS_CRASH_BUCKET set without WEFT_CRASH_PHASE")
	}
	options := gcsTestOptions(t, bucket, 0)
	store, err := OpenWithOptions("", ReadWrite, options)
	if err != nil {
		t.Fatalf("child open: %v", err)
	}
	defer store.Close()
	if _, err := store.CreateFile(model.RootID, []byte("crash.txt"), []byte(os.Getenv("WEFT_CRASH_CONTENT")), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("child create: %v", err)
	}
	t.Fatalf("child survived crash phase %q; the crash hook did not fire", phase)
}

// TestGCSCrashProxy kills a real child process at each publication step and
// proves the reopened store sees old-whole or new-whole, never a mixture.
func TestGCSCrashProxy(t *testing.T) {
	requireGCSEndpoint(t)
	const content = "gcs-whole-or-nothing"
	cases := []struct {
		phase   string
		mustSee bool
	}{
		{"after_objects", false},
		{"after_commit_file", false},
		{"after_superblock_write", true},
	}
	for _, tc := range cases {
		t.Run(tc.phase, func(t *testing.T) {
			bucket := gcsTestBucket(t)
			options := gcsTestOptions(t, bucket, 60*time.Second)
			setup, err := Init("", options)
			if err != nil {
				t.Fatalf("init: %v", err)
			}
			baseline := setup.Head()
			setup.Close()

			cmd := exec.Command(os.Args[0], "-test.run=TestGCSCrashChildProcess")
			cmd.Env = append(os.Environ(),
				"WEFT_GCS_CRASH_BUCKET="+bucket,
				"WEFT_CRASH_PHASE="+tc.phase,
				"WEFT_CRASH_CONTENT="+content,
			)
			output, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("child exited cleanly after %s: %s", tc.phase, output)
			}
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				t.Fatalf("child execution failed: %v (%s)", err, output)
			}

			reader, err := OpenWithOptions("", ReadOnly, options)
			if err != nil {
				t.Fatalf("reopen after %s: %v", tc.phase, err)
			}
			defer reader.Close()
			report, err := reader.Verify(true)
			if err != nil {
				t.Fatalf("verify after %s: %v", tc.phase, err)
			}
			if tc.mustSee {
				if !report.OK {
					t.Fatalf("store is not whole after %s: %+v", tc.phase, report.Problems)
				}
			} else {
				for _, problem := range report.Problems {
					if !strings.Contains(problem.Detail, "above the highest published superblock generation") {
						t.Fatalf("unexpected integrity problem after %s: %+v", tc.phase, problem)
					}
				}
			}
			id, resolveErr := reader.ResolvePath("/crash.txt")
			if tc.mustSee {
				if resolveErr != nil {
					t.Fatalf("published file missing after %s: %v", tc.phase, resolveErr)
				}
				data, err := reader.ReadObject(id)
				if err != nil || string(data) != content {
					t.Fatalf("read after %s: %q err=%v", tc.phase, data, err)
				}
			} else {
				if resolveErr == nil {
					t.Fatalf("unpublished commit is visible after %s", tc.phase)
				}
				if reader.Head() != baseline {
					t.Fatalf("head changed after an unpublished crash at %s: %s -> %s",
						tc.phase, baseline.Hex(), reader.Head().Hex())
				}
			}
		})
	}
}

// TestGCSFencedWriterPausedAfterFenceCannotPublish injects the takeover
// interleaving with the shared FIFO hook:
//
//  1. writer A fences (one generation-conditioned upload of LOCK);
//  2. A blocks after the fence and before the head publication;
//  3. A's lease expires; writer B reclaims the fence without publishing a head;
//  4. A resumes; its publication must fail Busy and the head must not move;
//  5. B then publishes and succeeds.
func TestGCSFencedWriterPausedAfterFenceCannotPublish(t *testing.T) {
	bucket := gcsTestBucket(t)
	lease := 2 * time.Second
	options := gcsTestOptions(t, bucket, lease)
	config := *options.GCS

	first, err := Init("", options)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if _, err := first.CreateFile(model.RootID, []byte("seed"), []byte("seed"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("seed write: %v", err)
	}
	seedGeneration := first.Generation()
	seedHead := first.Head()
	if err := first.Close(); err != nil {
		t.Fatalf("close seed writer: %v", err)
	}

	work := t.TempDir()
	ready := filepath.Join(work, "after-fence.ready.json")
	statusPath := filepath.Join(work, "after-fence.status.json")
	gate := filepath.Join(work, "after-fence.gate")
	if err := syscall.Mkfifo(gate, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	command := exec.Command(os.Args[0], "-test.run=^TestGCSFenceChildAfterFence$", "-test.v", "-test.timeout=300s")
	command.Env = append(os.Environ(),
		"WEFT_FENCE_CHILD=after-fence",
		"WEFT_FENCE_PAUSE_AFTER_FENCE=1",
		"WEFT_FENCE_AFTER_FENCE_READY="+ready,
		"WEFT_FENCE_AFTER_FENCE_GATE="+gate,
		"WEFT_FENCE_STATUS="+statusPath,
		"WEFT_FENCE_BUCKET="+bucket,
		"WEFT_FENCE_ENDPOINT="+config.Endpoint,
		"WEFT_FENCE_PROJECT="+config.Project,
		"WEFT_FENCE_ANONYMOUS="+strconv.FormatBool(config.Anonymous),
		"WEFT_FENCE_CREDENTIALS="+config.ServiceAccountPath,
		"WEFT_FENCE_SCOPE="+config.Scope,
		"WEFT_FENCE_LEASE_SECS="+strconv.Itoa(int(lease/time.Second)),
	)
	var childLog bytes.Buffer
	command.Stdout = &childLog
	command.Stderr = &childLog
	if err := command.Start(); err != nil {
		t.Fatalf("spawn the after-fence writer: %v", err)
	}
	childDone := false
	defer func() {
		if !childDone {
			_ = command.Process.Kill()
			_, _ = command.Process.Wait()
		}
	}()

	var readyValue struct {
		PID        int    `json:"pid"`
		Generation uint64 `json:"generation"`
		Head       string `json:"head"`
	}
	waitForJSONFile(t, ready, &readyValue, 120*time.Second)
	if readyValue.Generation != seedGeneration || readyValue.Head != seedHead.Hex() {
		t.Fatalf("child pre-publication state = %d/%s, want %d/%s",
			readyValue.Generation, readyValue.Head, seedGeneration, seedHead.Hex())
	}
	fenced, err := newGCSControl(gcsTestClient(t, bucket, 0)).ReadLockRecord()
	if err != nil || fenced == nil {
		t.Fatalf("read LOCK after the fence: %+v err=%v", fenced, err)
	}
	if fenced.pendingGeneration != seedGeneration {
		t.Fatalf("the fence record must attest the published head: %+v", fenced)
	}
	childFence := fenced.fence

	time.Sleep(lease + 500*time.Millisecond)
	second, err := OpenWithOptions("", ReadWrite, options)
	if err != nil {
		t.Fatalf("takeover open: %v", err)
	}
	if second.Generation() != seedGeneration {
		t.Fatalf("the takeover itself moved the head: %d -> %d", seedGeneration, second.Generation())
	}
	reclaimed, err := newGCSControl(gcsTestClient(t, bucket, 0)).ReadLockRecord()
	if err != nil || reclaimed == nil {
		t.Fatalf("read LOCK after takeover: %+v err=%v", reclaimed, err)
	}
	if reclaimed.fence != childFence+1 {
		t.Fatalf("takeover fence = %d, want %d", reclaimed.fence, childFence+1)
	}

	gateFile, err := os.OpenFile(gate, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open gate: %v", err)
	}
	if _, err := gateFile.Write([]byte{1}); err != nil {
		t.Fatalf("release the gate: %v", err)
	}
	_ = gateFile.Close()
	var status struct {
		OK         bool   `json:"ok"`
		Phase      string `json:"phase"`
		Class      string `json:"class"`
		Message    string `json:"message"`
		Generation uint64 `json:"generation"`
		Head       string `json:"head"`
	}
	waitForJSONFile(t, statusPath, &status, 120*time.Second)
	_ = command.Wait()
	childDone = true
	t.Logf("after-fence child: ok=%t phase=%s class=%s generation=%d head=%s message=%q",
		status.OK, status.Phase, status.Class, status.Generation, status.Head, status.Message)
	if status.OK {
		t.Fatalf("the after-fence writer published after being fenced; child log:\n%s", childLog.String())
	}
	if status.Class != "Busy" {
		t.Fatalf("stale publication class = %q, want Busy (message %q)", status.Class, status.Message)
	}
	if status.Generation != seedGeneration || status.Head != seedHead.Hex() {
		t.Fatalf("the fenced writer moved its own view: generation %d head %s", status.Generation, status.Head)
	}
	if !strings.Contains(status.Message, "LOCK now names") && !strings.Contains(status.Message, "taken over") {
		t.Fatalf("the refusal must name the takeover: %q", status.Message)
	}
	if second.Head() != seedHead || second.Generation() != seedGeneration {
		t.Fatalf("the head moved while the writers interleaved")
	}
	if _, err := second.ResolvePath("/fenced"); err == nil {
		t.Fatal("the fenced writer's file became visible")
	}
	if _, err := second.CreateFile(model.RootID, []byte("successor"), []byte("successor"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("successor publish: %v", err)
	}
	report, err := second.Verify(true)
	if err != nil || !report.OK {
		t.Fatalf("verify after the interleaving: %v %+v", err, report)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("close successor: %v", err)
	}
}

// TestGCSFenceChildAfterFence is the child half. It returns immediately unless
// WEFT_FENCE_CHILD is set.
func TestGCSFenceChildAfterFence(t *testing.T) {
	if os.Getenv("WEFT_FENCE_CHILD") != "after-fence" {
		return
	}
	leaseSecs := 2
	if text := os.Getenv("WEFT_FENCE_LEASE_SECS"); text != "" {
		if parsed, err := strconv.Atoi(text); err == nil && parsed > 0 {
			leaseSecs = parsed
		}
	}
	config := GCSConfig{
		Endpoint:           os.Getenv("WEFT_FENCE_ENDPOINT"),
		Bucket:             os.Getenv("WEFT_FENCE_BUCKET"),
		Project:            os.Getenv("WEFT_FENCE_PROJECT"),
		Anonymous:          strings.EqualFold(os.Getenv("WEFT_FENCE_ANONYMOUS"), "true"),
		ServiceAccountPath: os.Getenv("WEFT_FENCE_CREDENTIALS"),
		Scope:              os.Getenv("WEFT_FENCE_SCOPE"),
		LockLease:          time.Duration(leaseSecs) * time.Second,
		RequestTimeout:     30 * time.Second,
	}
	if config.Scope == "" {
		config.Scope = GCSScopeStorageReadWrite
	}
	options := DefaultOptions()
	options.BlobBackend = PlaneGCS
	options.CommitBackend = PlaneGCS
	options.GCS = &config
	options.GCGraceSecs = 0
	writer, err := OpenWithOptions("", ReadWrite, options)
	if err != nil {
		writeFenceStatus(t, map[string]any{"ok": false, "phase": "open", "class": string(werr.ClassOf(err)), "message": err.Error(), "generation": 0, "head": ""})
		return
	}
	generation := writer.Generation()
	head := writer.Head()
	_, writeErr := writer.CreateFile(model.RootID, []byte("fenced"), []byte("must-not-publish"), 0o644, 0, 0, nil)
	status := map[string]any{
		"generation": writer.Generation(),
		"head":       writer.Head().Hex(),
	}
	if writeErr != nil {
		status["ok"] = false
		status["phase"] = "publish"
		status["class"] = string(werr.ClassOf(writeErr))
		status["message"] = writeErr.Error()
	} else {
		status["ok"] = true
		status["phase"] = "published"
		status["class"] = ""
		status["message"] = fmt.Sprintf("published from generation %d head %s", generation, head.Hex())
	}
	writeFenceStatus(t, status)
	_ = writer.Close()
}

// TestGCSSplitLayouts proves all four plane layouts: GCS/GCS, GCS blobs with a
// local commit plane, local blobs with a GCS commit plane, and the local
// baseline. Logical state and head must be identical.
func TestGCSSplitLayouts(t *testing.T) {
	fixed := int64(1700000000000000000)
	seed := []byte("weft-gcs-split-seed")
	type layout struct {
		name    string
		blob    PlaneKind
		commit  PlaneKind
		path    string
		blobDir string
		config  *GCSConfig
	}
	build := func(name string, blob, commit PlaneKind, useGCS bool, dir string) layout {
		item := layout{name: name, blob: blob, commit: commit, path: dir}
		if useGCS {
			bucket := gcsTestBucket(t)
			cfg := gcsTestConfig(t, bucket, 0)
			item.config = &cfg
			if blob == PlaneGCS && commit != PlaneGCS {
				item.path = dir
			}
			if blob != PlaneGCS {
				item.blobDir = filepath.Join(dir, "blobs")
			}
		}
		return item
	}
	root := t.TempDir()
	layouts := []layout{
		build("local/local", PlaneLocal, PlaneLocal, false, filepath.Join(root, "local")),
		build("gcs/gcs", PlaneGCS, PlaneGCS, true, ""),
		build("gcs-blobs/local-commits", PlaneGCS, PlaneLocal, true, filepath.Join(root, "gcsblob")),
		build("local-blobs/gcs-commits", PlaneLocal, PlaneGCS, true, ""),
	}
	// The last layout needs a blob directory but no commit directory.
	layouts[3].blobDir = filepath.Join(root, "localblob")

	heads := map[string]model.Hash32{}
	generations := map[string]uint64{}
	contents := map[string][]byte{}
	for _, item := range layouts {
		t.Run(item.name, func(t *testing.T) {
			options := DefaultOptions()
			options.BlobBackend = item.blob
			options.CommitBackend = item.commit
			options.BlobRoot = item.blobDir
			options.GCS = item.config
			options.GCGraceSecs = 0
			options.FixedTimestampNS = &fixed
			writer, err := Init(item.path, options)
			if err != nil {
				t.Fatalf("init: %v", err)
			}
			payloads := map[string][]byte{
				"one": bytes.Repeat(seed, 10),
				"two": []byte("second"),
				"dir": nil,
			}
			parent := model.RootID
			for _, name := range []string{"one", "two", "dir"} {
				if name == "dir" {
					id, err := writer.MkdirSeeded(parent, []byte(name), 0o755, 0, 0, []byte("dir-seed"))
					if err != nil {
						t.Fatalf("mkdir: %v", err)
					}
					parent = id
					continue
				}
				seed := []byte("seed-" + name)
				if _, err := writer.CreateFileSeeded(parent, []byte(name), payloads[name], 0o644, 0, 0, nil, seed); err != nil {
					t.Fatalf("create %s: %v", name, err)
				}
			}
			report, err := writer.Verify(true)
			if err != nil || !report.OK {
				t.Fatalf("verify: %v %+v", err, report)
			}
			heads[item.name] = writer.Head()
			generations[item.name] = writer.Generation()
			id, err := writer.ResolvePath("/one")
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			data, err := writer.ReadObject(id)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			contents[item.name] = data
			if err := writer.Close(); err != nil {
				t.Fatalf("close: %v", err)
			}
		})
	}
	baselineHead := heads["local/local"]
	baselineGeneration := generations["local/local"]
	for name, head := range heads {
		if head != baselineHead {
			t.Fatalf("%s head %s differs from local/local %s", name, head.Hex(), baselineHead.Hex())
		}
		if generations[name] != baselineGeneration {
			t.Fatalf("%s generation %d differs from local/local %d", name, generations[name], baselineGeneration)
		}
	}
	for name, data := range contents {
		if !bytes.Equal(data, contents["local/local"]) {
			t.Fatalf("%s content differs from local/local", name)
		}
	}
}
