package store

// S3 integration court. These tests run only when WEFT_S3_TEST_ENDPOINT names a
// reachable S3-compatible endpoint; otherwise they skip with a reason. They are
// in `package store` so the conditional-write contract can be exercised
// directly (create-once conflict, matching/stale CAS, ranged reads, listing)
// without inventing an exported test surface.
//
// Environment (set by scripts/go-s3-court.sh):
//
//	WEFT_S3_TEST_ENDPOINT  e.g. http://weft-s3-minio-1:9000
//	WEFT_S3_ACCESS_KEY / WEFT_S3_SECRET_KEY
//	WEFT_S3_REGION         default us-east-1
//	WEFT_S3_TEST_PREFIX     unique per court run, used to build bucket names
//
// Every test uses its own bucket so a failed test cannot corrupt another's
// control state. The court destroys the server (tmpfs data) on exit.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/infinityabundance/WeftCodec-Go/hash"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

var s3TestCounter atomic.Uint64

func requireS3Endpoint(t *testing.T) string {
	t.Helper()
	endpoint := os.Getenv("WEFT_S3_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("WEFT_S3_TEST_ENDPOINT is not set; the S3 court is not running")
	}
	return endpoint
}

func s3TestBucket(t *testing.T) string {
	t.Helper()
	prefix := os.Getenv("WEFT_S3_TEST_PREFIX")
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
	return fmt.Sprintf("%s-%d-%d", string(cleaned), os.Getpid(), s3TestCounter.Add(1))
}

func s3TestConfig(t *testing.T, bucket string, lease time.Duration) S3Config {
	t.Helper()
	endpoint := requireS3Endpoint(t)
	access := os.Getenv("WEFT_S3_ACCESS_KEY")
	if access == "" {
		access = "weftcourt"
	}
	secret := os.Getenv("WEFT_S3_SECRET_KEY")
	if secret == "" {
		secret = "weftcourt-secret"
	}
	region := os.Getenv("WEFT_S3_REGION")
	if region == "" {
		region = "us-east-1"
	}
	if lease <= 0 {
		lease = 60 * time.Second
	}
	return S3Config{
		Endpoint: endpoint, Bucket: bucket, Region: region,
		AccessKey: access, SecretKey: secret,
		PathStyle: true, LockLease: lease, RequestTimeout: 30 * time.Second,
	}
}

func s3TestOptions(t *testing.T, bucket string, lease time.Duration) Options {
	t.Helper()
	config := s3TestConfig(t, bucket, lease)
	options := DefaultOptions()
	options.BlobBackend = PlaneS3
	options.CommitBackend = PlaneS3
	options.S3 = &config
	options.GCGraceSecs = 0
	return options
}

func expectClass(t *testing.T, err error, class werr.Kind, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected %s, got success", what, class)
	}
	typed, ok := err.(*werr.Error)
	if !ok || typed.Kind != class {
		t.Fatalf("%s: expected %s, got %v (%T)", what, class, err, err)
	}
}

// TestS3BlobPlaneCreateOnceRangesAndListing covers the blob-plane contract the
// store depends on: create-once, identical-byte idempotence, different-byte
// conflict, ranged reads, listing, cold reads from a second connection, and an
// honest NotFound after delete.
func TestS3BlobPlaneCreateOnceRangesAndListing(t *testing.T) {
	bucket := s3TestBucket(t)
	client, err := newS3Client(s3TestConfig(t, bucket, 0))
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	if err := client.ensureBucket(); err != nil {
		t.Fatalf("ensure bucket: %v", err)
	}
	plane := newS3BlobPlane(client)

	payload := []byte("weft-s3-blob-plane-payload-0123456789")
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
	// A range that starts exactly at EOF is empty, not an error.
	if tail, err := plane.GetRange(BlobObject, id, uint64(len(payload)), 4); err != nil || len(tail) != 0 {
		t.Fatalf("end-of-object range: %q err=%v", tail, err)
	}
	if exists, err := plane.Exists(BlobObject, id); err != nil || !exists {
		t.Fatalf("exists = %t err=%v", exists, err)
	}

	entries, problems, err := plane.List("objects")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(problems) != 0 {
		t.Fatalf("listing problems: %v", problems)
	}
	found := false
	for _, entry := range entries {
		if entry.ID == id && entry.Kind == BlobObject && entry.Size == uint64(len(payload)) {
			found = true
		}
	}
	if !found {
		t.Fatalf("listed objects do not contain the published blob: %+v", entries)
	}

	// Cold read: a second connection and a second plane have no local cache.
	coldClient, err := newS3Client(s3TestConfig(t, bucket, 0))
	if err != nil {
		t.Fatalf("cold client: %v", err)
	}
	coldPlane := newS3BlobPlane(coldClient)
	cold, err := coldPlane.Get(BlobObject, id)
	if err != nil || string(cold) != string(payload) {
		t.Fatalf("cold read: %q err=%v", cold, err)
	}
	if coldClient.stats.reads.Load() != 1 {
		t.Fatalf("cold read count = %d, want 1", coldClient.stats.reads.Load())
	}

	// Probe evidence, and a second probe must not claim anything new.
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
	entries, _, err = plane.List("objects")
	if err != nil {
		t.Fatalf("list after delete: %v", err)
	}
	for _, entry := range entries {
		if entry.ID == id {
			t.Fatalf("deleted blob is still listed: %+v", entry)
		}
	}
}

// TestS3CommitVolumeConditionalRecords measures the If-Match form and proves
// create-once records, matching/stale compare-and-swap, and commit enumeration.
func TestS3CommitVolumeConditionalRecords(t *testing.T) {
	bucket := s3TestBucket(t)
	client, err := newS3Client(s3TestConfig(t, bucket, 0))
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	control := newS3Control(client)
	if err := control.EnsureLayout(); err != nil {
		t.Fatalf("ensure layout: %v", err)
	}
	if err := control.probeConditionalWrites(); err != nil {
		t.Fatalf("conditional probe: %v", err)
	}
	form := client.headIfMatchForm()
	if form != IfMatchAsReturned && form != IfMatchDequoted {
		t.Fatalf("unknown If-Match form %d", form)
	}
	diagnostics := client.diagnostics()
	measured := false
	for _, line := range diagnostics {
		if strings.Contains(line, "If-Match form measured at open: "+form.String()) {
			measured = true
		}
	}
	if !measured {
		t.Fatalf("diagnostics do not record the measured form %q: %v", form.String(), diagnostics)
	}
	t.Logf("measured If-Match form: %s", form.String())

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

	// Records: create-once, idempotent repeat, conflict, conditional replace.
	if err := control.WriteRecordNew("refs/snapshots/s1", []byte("abc\n")); err != nil {
		t.Fatalf("record create: %v", err)
	}
	if err := control.WriteRecordNew("refs/snapshots/s1", []byte("abc\n")); err != nil {
		t.Fatalf("identical record repeat must be idempotent: %v", err)
	}
	expectClass(t, control.WriteRecordNew("refs/snapshots/s1", []byte("zzz\n")),
		werr.Exists, "different bytes under a create-once record")
	if err := control.WriteRecordReplace("quota", []byte("first")); err != nil {
		t.Fatalf("record replace create: %v", err)
	}
	if err := control.WriteRecordReplace("quota", []byte("second")); err != nil {
		t.Fatalf("record replace overwrite: %v", err)
	}
	stored, present, err := control.ReadRecord("quota")
	if err != nil || !present || string(stored) != "second" {
		t.Fatalf("record replace result: %q present=%t err=%v", stored, present, err)
	}
	records, err := control.ListRecords("refs/snapshots")
	if err != nil || len(records) != 1 || records[0] != "refs/snapshots/s1" {
		t.Fatalf("record listing: %v err=%v", records, err)
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

	// Commit records: create-once, read, enumerate, and refuse a different body.
	commitBytes := EncodeCommitFile([]byte("not a real commit body, but the key path is what this checks"))
	if err := control.CreateCommit(7, commitBytes); err != nil {
		t.Fatalf("create commit: %v", err)
	}
	if err := control.CreateCommit(7, commitBytes); err != nil {
		t.Fatalf("identical commit repeat must be idempotent: %v", err)
	}
	expectClass(t, control.CreateCommit(7, []byte("different")), werr.Exists, "different commit bytes")
	if present, err := control.HasCommit(7); err != nil || !present {
		t.Fatalf("has commit 7 = %t err=%v", present, err)
	}
	if present, err := control.HasCommit(8); err != nil || present {
		t.Fatalf("has commit 8 = %t err=%v", present, err)
	}
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
	// 7 does not name a parseable commit, so ReadCommit must fail closed. The
	// exact class (Corrupt, Malformed, or NonCanonical) is the parser's call;
	// what matters is that it never returns a commit.
	if _, err := control.ReadCommit(7); err == nil {
		t.Fatal("a malformed commit record was accepted")
	} else {
		class := werr.ClassOf(err)
		if class != werr.Corrupt && class != werr.Malformed && class != werr.NonCanonical {
			t.Fatalf("malformed commit returned class %s: %v", class, err)
		}
	}
}

// TestS3FencedWriterTakeover drives the real lease protocol: a live lock
// refuses a second writer, an expired lease is reclaimed with the next fence,
// the stale writer cannot publish, and release is a tombstone.
func TestS3FencedWriterTakeover(t *testing.T) {
	bucket := s3TestBucket(t)
	options := s3TestOptions(t, bucket, 1*time.Second)

	first, err := Init("", options)
	if err != nil {
		t.Fatalf("init first writer: %v", err)
	}
	if _, err := first.CreateFile(model.RootID, []byte("a.txt"), []byte("first"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("first write: %v", err)
	}
	firstHead := first.Head()

	// A live lease must refuse a second writer with the fixed non-disclosing text.
	_, err = OpenWithOptions("", ReadWrite, options)
	expectClass(t, err, werr.Busy, "second writer while the lease is live")

	// Let the lease expire, then take over. The successor's fence must advance.
	time.Sleep(1200 * time.Millisecond)
	second, err := OpenWithOptions("", ReadWrite, options)
	if err != nil {
		t.Fatalf("takeover open: %v", err)
	}
	if second.Generation() != first.Generation() {
		t.Fatalf("successor generation = %d, want %d", second.Generation(), first.Generation())
	}
	lock, err := newS3Control(mustClient(t, options)).ReadLockRecord()
	if err != nil || lock == nil {
		t.Fatalf("read lock: %+v err=%v", lock, err)
	}
	if lock.fence < 2 {
		t.Fatalf("takeover did not advance the fence: %+v", lock)
	}

	// The stale writer must fail before touching the head. Its own deadline has
	// passed, which is the first gate; the successor having rewritten LOCK is
	// the second.
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
		t.Fatalf("closing the stale writer must not delete the successor's lock: %v", err)
	}
	// The successor still holds its lease and can publish.
	if _, err := second.CreateFile(model.RootID, []byte("b.txt"), []byte("second"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("successor write after stale close: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("release successor: %v", err)
	}
	released := mustClient(t, options)
	record, err := newS3Control(released).ReadLockRecord()
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

func mustClient(t *testing.T, options Options) *s3Client {
	t.Helper()
	client, err := newS3Client(*options.S3)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	return client
}

// TestS3StoreRoundTrip runs the full store: init, writes, snapshot, verify
// --full, read-only reopen with exact bytes, unlink plus GC, and a final verify.
func TestS3StoreRoundTrip(t *testing.T) {
	bucket := s3TestBucket(t)
	options := s3TestOptions(t, bucket, 60*time.Second)
	writer, err := Init("", options)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if writer.Root() != "s3://"+bucket {
		t.Fatalf("store root label = %q", writer.Root())
	}
	planes := writer.Planes()
	if planes.Blobs.Backend != "s3" || planes.Commits.Backend != "s3" {
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
	ids := map[string]model.Hash32{}
	for path, data := range payloads {
		name := path[1:]
		id, err := writer.CreateFile(model.RootID, []byte(name), data, 0o644, 0, 0, nil)
		if err != nil {
			t.Fatalf("create %s: %v", path, err)
		}
		ids[path] = id
	}
	report, err := writer.Verify(true)
	if err != nil {
		t.Fatalf("verify on the writer: %v", err)
	}
	if !report.OK {
		t.Fatalf("verify on the writer reports problems: %+v", report.Problems)
	}
	if stats, ok := writer.S3Stats(); ok {
		t.Logf("host-local S3 counters (writer, loopback): requests=%d writes=%d bytes_written=%d reads=%d bytes_read=%d conflicts=%d",
			stats.Requests, stats.Writes, stats.BytesWritten, stats.Reads, stats.BytesRead, stats.ConditionalConflict)
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
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if string(got) != string(want) {
			t.Fatalf("read %s returned %d bytes, want %d", path, len(got), len(want))
		}
	}
	report, err = reader.Verify(true)
	if err != nil || !report.OK {
		t.Fatalf("verify on the reader: %v %+v", err, report)
	}
	if stats, ok := reader.S3Stats(); ok {
		t.Logf("host-local S3 counters (reader handle, loopback): requests=%d reads=%d bytes_read=%d",
			stats.Requests, stats.Reads, stats.BytesRead)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close reader: %v", err)
	}

	// GC: unlink one file on a writable open. The snapshot is taken *after* the
	// unlink, so it does not pin the unlinked file's blobs; a snapshot taken
	// before would correctly retain them (that is the GC root rule, exercised by
	// the local GC suite).
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

// TestS3SplitLayouts proves both mixed configurations: S3 blobs with a local
// commit plane, and local blobs with an S3 commit plane. The logical state and
// head must be identical to a pure local store.
func TestS3SplitLayouts(t *testing.T) {
	fixed := int64(1700000000000000000)
	seed := []byte("weft-s3-split-seed")
	bucketBlobs := s3TestBucket(t)
	options := DefaultOptions()
	options.BlobBackend = PlaneS3
	options.CommitBackend = PlaneLocal
	blobConfig := s3TestConfig(t, bucketBlobs, 0)
	options.S3 = &blobConfig
	options.GCGraceSecs = 0
	options.FixedTimestampNS = &fixed

	dir := t.TempDir()
	writer, err := Init(dir, options)
	if err != nil {
		t.Fatalf("init s3-blobs/local-commits: %v", err)
	}
	if writer.Planes().Blobs.Backend != "s3" || writer.Planes().Commits.Backend != "local" {
		t.Fatalf("split planes = %+v", writer.Planes())
	}
	data := []byte("split-layout payload")
	if _, err := writer.CreateFileSeeded(model.RootID, []byte("split.txt"), data, 0o644, 0, 0, nil, seed); err != nil {
		t.Fatalf("split write: %v", err)
	}
	splitHead := writer.Head()
	report, err := writer.Verify(true)
	if err != nil || !report.OK {
		t.Fatalf("split verify: %v %+v", err, report)
	}
	writer.Close()

	localOptions := DefaultOptions()
	localOptions.GCGraceSecs = 0
	localOptions.FixedTimestampNS = &fixed
	localDir := t.TempDir()
	local, err := Init(localDir, localOptions)
	if err != nil {
		t.Fatalf("init local: %v", err)
	}
	if _, err := local.CreateFileSeeded(model.RootID, []byte("split.txt"), data, 0o644, 0, 0, nil, seed); err != nil {
		t.Fatalf("local write: %v", err)
	}
	if local.Head() != splitHead {
		t.Fatalf("split head %s != local head %s (same logical operation)", splitHead.Hex(), local.Head().Hex())
	}
	local.Close()

	// Local blobs with S3 commits.
	bucketCommits := s3TestBucket(t)
	mixed := DefaultOptions()
	mixed.BlobBackend = PlaneLocal
	mixed.CommitBackend = PlaneS3
	commitConfig := s3TestConfig(t, bucketCommits, 0)
	mixed.S3 = &commitConfig
	mixed.FixedTimestampNS = &fixed
	mixedDir := t.TempDir()
	mixedStore, err := Init(mixedDir, mixed)
	if err != nil {
		t.Fatalf("init local-blobs/s3-commits: %v", err)
	}
	if mixedStore.Planes().Blobs.Backend != "local" || mixedStore.Planes().Commits.Backend != "s3" {
		t.Fatalf("mixed planes = %+v", mixedStore.Planes())
	}
	if _, err := mixedStore.CreateFileSeeded(model.RootID, []byte("split.txt"), data, 0o644, 0, 0, nil, seed); err != nil {
		t.Fatalf("mixed write: %v", err)
	}
	if mixedStore.Head() != splitHead {
		t.Fatalf("mixed head %s != local head %s", mixedStore.Head().Hex(), splitHead.Hex())
	}
	report, err = mixedStore.Verify(true)
	if err != nil || !report.OK {
		t.Fatalf("mixed verify: %v %+v", err, report)
	}
	mixedStore.Close()
}

// TestS3CrashChildProcess is the re-executed child of TestS3CrashProxy. It is
// not a test of its own.
func TestS3CrashChildProcess(t *testing.T) {
	bucket := os.Getenv("WEFT_S3_CRASH_BUCKET")
	if bucket == "" {
		t.Skip("S3 crash helper process; not run directly")
	}
	phase := os.Getenv("WEFT_CRASH_PHASE")
	if phase == "" {
		t.Fatal("WEFT_S3_CRASH_BUCKET set without WEFT_CRASH_PHASE")
	}
	config := s3TestConfig(t, bucket, 0)
	options := DefaultOptions()
	options.BlobBackend = PlaneS3
	options.CommitBackend = PlaneS3
	options.S3 = &config
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

// TestS3CrashProxy kills a real child process at each publication step and
// proves the reopened store sees the old whole state or the new whole state,
// never a mixture. This is a process-fault proxy, not a power-loss claim.
func TestS3CrashProxy(t *testing.T) {
	requireS3Endpoint(t)
	const content = "s3-whole-or-nothing"
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
			bucket := s3TestBucket(t)
			options := s3TestOptions(t, bucket, 60*time.Second)
			setup, err := Init("", options)
			if err != nil {
				t.Fatalf("init: %v", err)
			}
			baseline := setup.Head()
			setup.Close()

			cmd := exec.Command(os.Args[0], "-test.run=TestS3CrashChildProcess")
			cmd.Env = append(os.Environ(),
				"WEFT_S3_CRASH_BUCKET="+bucket,
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
