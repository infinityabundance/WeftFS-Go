// Azure integration court (subphase R14).
//
// Two layers, both in `package store` so the conditional-write contract can be
// exercised directly:
//
//   - a deterministic in-process Azure double (`azurefake_test.go`) that proves
//     the client's SharedKey signature against an independently written
//     string-to-sign, the create-once/ETag contract, and — the part a
//     well-behaved emulator cannot show — that an endpoint which ignores
//     `If-Match` or `If-None-Match: *`, or compares ETags literally, is
//     negotiated or refused rather than silently trusted;
//   - live tests against a real Azurite release when
//     `WEFT_AZURE_TEST_ENDPOINT` is set by `bench/scripts/azure_court.sh`.
//     Without it they skip with a reason; a skip is never a pass.
//
// Every live test uses its own container so a failed test cannot corrupt
// another's control state. The court destroys the emulator (tmpfs data) on exit.
package store

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

var azureTestCounter atomic.Uint64

func azureFakeOptions(t *testing.T, fake *azureFake) Options {
	t.Helper()
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	config := AzureConfig{
		Endpoint:       server.URL + "/" + azureFakeAccount,
		Container:      azureFakeContainer,
		Account:        azureFakeAccount,
		Key:            azureFakeKey,
		LockLease:      60 * time.Second,
		RequestTimeout: 10 * time.Second,
	}
	options := DefaultOptions()
	options.BlobBackend = PlaneAzure
	options.CommitBackend = PlaneAzure
	options.Azure = &config
	options.GCGraceSecs = 0
	return options
}

// TestAzureStoreRoundTripOnDouble runs the whole store over the double: init,
// three writes, verify --full, close, read-only reopen with exact bytes, then
// unlink plus GC with a final verify.
func TestAzureStoreRoundTripOnDouble(t *testing.T) {
	options := azureFakeOptions(t, newAzureFake())
	writer, err := Init("", options)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if writer.Root() != "azure://"+azureFakeContainer {
		t.Fatalf("store root label = %q", writer.Root())
	}
	planes := writer.Planes()
	if planes.Blobs.Backend != "azure" || planes.Commits.Backend != "azure" {
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
	if stats, ok := writer.AzureStats(); ok {
		t.Logf("Azure double counters (writer): requests=%d reads=%d range_reads=%d bytes_read=%d writes=%d bytes_written=%d conflicts=%d fences=%d heads=%d",
			stats.Requests, stats.Reads, stats.RangeReads, stats.BytesRead, stats.Writes,
			stats.BytesWritten, stats.ConditionalConflict, stats.FenceChecks, stats.HeadPublications)
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
		if !bytes.Equal(got, want) {
			t.Fatalf("read %s returned %d bytes, want %d", path, len(got), len(want))
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
	if err := cleaner.Close(); err != nil {
		t.Fatalf("close cleaner: %v", err)
	}
}

// TestAzureBlobPlaneCreateOnceRangesAndListing covers the blob-plane contract:
// create-once, identical-byte idempotence, different-byte conflict, ranged
// reads, listing, and an honest NotFound after delete.
func TestAzureBlobPlaneCreateOnceRangesAndListing(t *testing.T) {
	client := azureFakeClient(t, newAzureFake())
	if err := client.ensureContainer(); err != nil {
		t.Fatalf("ensure container: %v", err)
	}
	plane := newAzureBlobPlane(client)
	probe, err := plane.probe()
	if err != nil {
		t.Fatalf("blob probe: %v", err)
	}
	if !probe.CreateOnceVisible || !probe.LengthMatch || !probe.RangeReadMatch || !probe.DeleteObserved {
		t.Fatalf("blob probe evidence = %+v", probe)
	}

	data := bytes.Repeat([]byte("weft-azure-"), 5120)
	if _, _, err := client.putConditional("objects/ab/"+strings.Repeat("0", 62), data, nil, false); err != nil {
		t.Fatalf("first create: %v", err)
	}
	// Identical bytes are idempotent at the store layer, but the transport still
	// reports the lost precondition; the plane resolves it by comparison.
	if _, ok, err := client.putConditional("objects/ab/"+strings.Repeat("0", 62), data, nil, true); err != nil {
		t.Fatalf("second create: %v", err)
	} else if ok {
		t.Fatal("create-once accepted a second write")
	}
	ranged, err := client.get("objects/ab/"+strings.Repeat("0", 62), 4096, 17)
	if err != nil {
		t.Fatalf("ranged read: %v", err)
	}
	if ranged.Status != http.StatusPartialContent {
		t.Fatalf("ranged read status = %d", ranged.Status)
	}
	if !bytes.Equal(ranged.Body, data[4096:4113]) {
		t.Fatal("ranged read returned the wrong bytes")
	}
	if _, err := client.delete("objects/ab/" + strings.Repeat("0", 62)); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if head, err := client.head("objects/ab/" + strings.Repeat("0", 62)); err != nil {
		t.Fatalf("head after delete: %v", err)
	} else if head.Status != http.StatusNotFound {
		t.Fatalf("head after delete = %d", head.Status)
	}
}

// TestAzureEndpointThatIgnoresIfNoneMatchIsRefused proves create-once is not
// assumed: an endpoint that ignores the header cannot back a writable store.
func TestAzureEndpointThatIgnoresIfNoneMatchIsRefused(t *testing.T) {
	fake := newAzureFake()
	fake.ignoreIfNoneMatch = true
	options := azureFakeOptions(t, fake)
	_, err := Init("", options)
	expectClass(t, err, werr.Unsupported, "writable open against an endpoint that ignores If-None-Match")
}

// TestAzureEndpointThatIgnoresIfMatchIsRefused proves the load-bearing check: an
// endpoint that accepts a stale ETag could lose a head publication silently.
func TestAzureEndpointThatIgnoresIfMatchIsRefused(t *testing.T) {
	fake := newAzureFake()
	fake.ignoreIfMatch = true
	options := azureFakeOptions(t, fake)
	_, err := Init("", options)
	expectClass(t, err, werr.Unsupported, "writable open against an endpoint that accepts a stale ETag")
}

// TestAzureLiteralETagEndpointIsNegotiated covers an endpoint that returns
// unquoted ETags and compares If-Match literally. The probe must measure the
// dequoted form and keep it, not guess.
func TestAzureLiteralETagEndpointIsNegotiated(t *testing.T) {
	fake := newAzureFake()
	fake.literalCompare = true
	client := azureFakeClient(t, fake)
	if err := client.ensureContainer(); err != nil {
		t.Fatalf("ensure container: %v", err)
	}
	control := newAzureControl(client)
	if err := control.probeConditionalWrites(); err != nil {
		t.Fatalf("probe against a literal-ETag endpoint: %v", err)
	}
	if form := client.headIfMatchForm(); form != IfMatchDequoted {
		t.Fatalf("negotiated form = %s, want dequoted", form)
	}
	joined := strings.Join(client.diagnostics(), " | ")
	if !strings.Contains(joined, "dequoted") {
		t.Fatalf("diagnostics did not record the negotiated dequoted form: %s", joined)
	}

	options := azureFakeOptions(t, fake)
	writer, err := Init("", options)
	if err != nil {
		t.Fatalf("init against a literal-ETag endpoint: %v", err)
	}
	if _, err := writer.CreateFile(model.RootID, []byte("literal.txt"), []byte("bytes"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("write: %v", err)
	}
	if report, err := writer.Verify(true); err != nil || !report.OK {
		t.Fatalf("verify: %v %+v", err, report)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestAzureWrongKeyIsUnauthorized proves a credential failure stays
// `Unauthorized` and is not reported as a damaged store.
func TestAzureWrongKeyIsUnauthorized(t *testing.T) {
	fake := newAzureFake()
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	config := AzureConfig{
		Endpoint:  server.URL + "/" + azureFakeAccount,
		Container: azureFakeContainer,
		Account:   azureFakeAccount,
		// A syntactically valid key that is not the account key.
		Key:            "d2VmdC1jb3VydC13cm9uZy1rZXktMDEyMzQ1Njc4OQ==",
		LockLease:      60 * time.Second,
		RequestTimeout: 10 * time.Second,
	}
	options := DefaultOptions()
	options.BlobBackend = PlaneAzure
	options.CommitBackend = PlaneAzure
	options.Azure = &config
	options.GCGraceSecs = 0
	_, err := Init("", options)
	expectClass(t, err, werr.Unauthorized, "writable open with the wrong account key")
}

// ---- MW2 over the Azure commit plane (subphase R14d) --------------------
//
// Azure Blob has a real compare-and-swap, so the head is published with one
// conditional `Put Blob` whose `If-Match` is the ETag read with the head
// check. These tests use the shipped transaction API: two independent handles
// publishing disjoint files, then a fresh open that must see both.

func azureMW2Options(t *testing.T, fake *azureFake) Options {
	t.Helper()
	options := azureFakeOptions(t, fake)
	now := int64(1_700_000_000_000_000_000)
	options.FixedTimestampNS = &now
	options.CheckpointInterval = 4
	options.GCGraceSecs = 0
	return options
}

type azureMW2FilePlan struct {
	record model.ObjectRecord
	entry  model.EntryRecord
}

func azureMW2PlanFile(t *testing.T, s *Store, name, data, seed []byte) azureMW2FilePlan {
	t.Helper()
	manifest, _, size, err := s.PrepareContent(data)
	if err != nil {
		t.Fatalf("prepare content: %v", err)
	}
	now := int64(1_700_000_000_000_000_000)
	id := model.ObjectIDFromSeed(seed)
	version, err := model.DeriveVersionID(id, manifest, size, now, nil)
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	record := model.ObjectRecord{
		ID: id, Kind: model.KindFile, Mode: 0o644, UID: 0, GID: 0,
		MtimeNS: now, Version: version, Content: manifest, Size: size,
		Attrs: map[string]wcb.Value{},
	}
	entryID, err := model.DeriveEntryID(model.RootID, name)
	if err != nil {
		t.Fatalf("entry id: %v", err)
	}
	entry := model.EntryRecord{ID: entryID, Parent: model.RootID, Name: append([]byte(nil), name...), Target: id}
	return azureMW2FilePlan{record: record, entry: entry}
}

func azureMW2Stage(t *testing.T, s *Store, id string, plan azureMW2FilePlan) *Transaction {
	t.Helper()
	tx, err := s.BeginTransaction(id)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := tx.PutObject(s.CurrentState(), plan.record); err != nil {
		t.Fatalf("put object: %v", err)
	}
	if err := tx.PutEntry(s.CurrentState(), plan.entry); err != nil {
		t.Fatalf("put entry: %v", err)
	}
	if err := tx.SetTip(s.CurrentState(), plan.record.ID, plan.record.Version); err != nil {
		t.Fatalf("set tip: %v", err)
	}
	return tx
}

func TestAzureOptimisticTwoDisjointCommitters(t *testing.T) {
	fake := newAzureFake()
	single := azureMW2Options(t, fake)
	single.WriterMode = WriterModeSingle
	init, err := Init("", single)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := init.Close(); err != nil {
		t.Fatalf("close init: %v", err)
	}

	optimistic := single
	optimistic.WriterMode = WriterModeOptimistic
	a, err := OpenWithOptions("", ReadWrite, optimistic)
	if err != nil {
		t.Fatalf("open A: %v", err)
	}
	defer a.Close()
	b, err := OpenWithOptions("", ReadWrite, optimistic)
	if err != nil {
		t.Fatalf("open B: %v", err)
	}
	defer b.Close()

	planA := azureMW2PlanFile(t, a, []byte("azure-a.txt"), []byte("alpha-azure"), []byte("mw2-az-a"))
	planB := azureMW2PlanFile(t, a, []byte("azure-b.txt"), []byte("beta-azure"), []byte("mw2-az-b"))
	txA := azureMW2Stage(t, a, "000000000000000000000000000000a1", planA)
	txB := azureMW2Stage(t, b, "000000000000000000000000000000b1", planB)

	outA, err := a.ExecuteTransaction(txA, DefaultTransactionOptions())
	if err != nil {
		t.Fatalf("A: %v", err)
	}
	outB, err := b.ExecuteTransaction(txB, DefaultTransactionOptions())
	if err != nil {
		t.Fatalf("B: %v", err)
	}
	if outA.Commit == outB.Commit || outA.Idempotent || outB.Idempotent {
		t.Fatalf("outcomes: %+v %+v", outA, outB)
	}
	if outB.Attempts < 1 {
		t.Fatalf("B did not retry onto A's head: attempts=%d", outB.Attempts)
	}
	if outB.Generation != outA.Generation+1 {
		t.Fatalf("generations A=%d B=%d", outA.Generation, outB.Generation)
	}

	check, err := OpenWithOptions("", ReadWrite, optimistic)
	if err != nil {
		t.Fatalf("fresh open: %v", err)
	}
	defer check.Close()
	report, err := check.Verify(true)
	if err != nil || !report.OK {
		t.Fatalf("verify: ok=%v err=%v problems=%v", report.OK, err, report.Problems)
	}
	entries, err := check.ListDir(model.RootID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		seen[string(entry.Name)] = true
	}
	if !seen["azure-a.txt"] || !seen["azure-b.txt"] {
		t.Fatalf("entries: %v", seen)
	}
	for _, plan := range []azureMW2FilePlan{planA, planB} {
		if _, err := check.ReadObject(plan.record.ID); err != nil {
			t.Fatalf("read %s: %v", string(plan.entry.Name), err)
		}
	}
	if body, err := check.ReadObject(planA.record.ID); err != nil || !bytes.Equal(body, []byte("alpha-azure")) {
		t.Fatalf("A body: %q %v", body, err)
	}
	if body, err := check.ReadObject(planB.record.ID); err != nil || !bytes.Equal(body, []byte("beta-azure")) {
		t.Fatalf("B body: %q %v", body, err)
	}
	if check.Generation() != outB.Generation {
		t.Fatalf("reopened generation %d, want %d", check.Generation(), outB.Generation)
	}
}

// TestAzureSingleWriterRefusesAnOptimisticStore keeps the writer-mode policy
// honest: mixing an exclusive writer with optimistic committers is refused, on
// Azure exactly as on the local plane.
func TestAzureSingleWriterRefusesAnOptimisticStore(t *testing.T) {
	fake := newAzureFake()
	single := azureMW2Options(t, fake)
	single.WriterMode = WriterModeSingle
	init, err := Init("", single)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := init.Close(); err != nil {
		t.Fatalf("close init: %v", err)
	}

	optimistic := single
	optimistic.WriterMode = WriterModeOptimistic
	s, err := OpenWithOptions("", ReadWrite, optimistic)
	if err != nil {
		t.Fatalf("optimistic open: %v", err)
	}
	plan := azureMW2PlanFile(t, s, []byte("mw2.txt"), []byte("mw2"), []byte("mw2-refusal"))
	tx := azureMW2Stage(t, s, "000000000000000000000000000000c1", plan)
	if _, err := s.ExecuteTransaction(tx, DefaultTransactionOptions()); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	_, err = OpenWithOptions("", ReadWrite, single)
	expectClass(t, err, werr.Unsupported, "single writer opening an optimistic azure store")
}

// TestAzurePlaneStaleHeadIsBusyAndChangesNothing exercises the plane contract
// directly, without a store: a conditional head publication whose expectation
// is stale must be refused `Busy` and must leave every superblock byte as it
// was. This is the property a lost-update-free MW2 head depends on, and it is
// checked on the same control volume a real committer uses.
func TestAzurePlaneStaleHeadIsBusyAndChangesNothing(t *testing.T) {
	fake := newAzureFake()
	options := azureMW2Options(t, fake)
	options.WriterMode = WriterModeSingle
	init, err := Init("", options)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := init.Close(); err != nil {
		t.Fatalf("close init: %v", err)
	}

	control := newAzureControl(azureFakeClient(t, fake))
	view, err := control.ReadSuperblock()
	if err != nil {
		t.Fatalf("read superblock: %v", err)
	}
	headGeneration, headCommit, ok := highestSlot(view)
	if !ok {
		t.Fatalf("no published head after init")
	}
	before, present, err := control.ReadRecord(azureSuperblockKey)
	if err != nil || !present {
		t.Fatalf("read superblock bytes: present=%v err=%v", present, err)
	}

	next := func(generation uint64, marker byte) SuperblockSlot {
		var commit model.Hash32
		for index := range commit {
			commit[index] = marker
		}
		return SuperblockSlot{
			Generation: generation, Commit: commit, CommitLen: 64, TimestampNS: 1_700_000_000_000_000_000,
		}
	}
	// A matching expectation publishes.
	if _, err := control.PublishHeadConditional(headGeneration, headCommit, next(headGeneration+1, 0x42)); err != nil {
		t.Fatalf("matching head publication: %v", err)
	}
	advanced, advancedPresent, err := control.ReadRecord(azureSuperblockKey)
	if err != nil || !advancedPresent {
		t.Fatalf("read advanced superblock: present=%v err=%v", advancedPresent, err)
	}
	if bytes.Equal(before, advanced) {
		t.Fatalf("a matching head publication did not change the superblock")
	}

	// The old expectation is now stale: Busy, and not one byte changes.
	_, err = control.PublishHeadConditional(headGeneration, headCommit, next(headGeneration+2, 0x43))
	expectClass(t, err, werr.Busy, "stale conditional head publication")
	after, afterPresent, err := control.ReadRecord(azureSuperblockKey)
	if err != nil || !afterPresent {
		t.Fatalf("read superblock after refusal: present=%v err=%v", afterPresent, err)
	}
	if !bytes.Equal(advanced, after) {
		t.Fatalf("a refused head publication changed the superblock bytes")
	}
	freshView, err := control.ReadSuperblock()
	if err != nil {
		t.Fatalf("read superblock after refusal: %v", err)
	}
	freshGeneration, freshCommit, ok := highestSlot(freshView)
	if !ok || freshGeneration != headGeneration+1 {
		t.Fatalf("head generation after refusal = %d (ok=%v), want %d", freshGeneration, ok, headGeneration+1)
	}
	if freshCommit != next(headGeneration+1, 0x42).Commit {
		t.Fatalf("head commit after refusal moved")
	}
}

// ---- live Azurite court --------------------------------------------------

func requireAzureEndpoint(t *testing.T) string {
	t.Helper()
	endpoint := os.Getenv("WEFT_AZURE_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("WEFT_AZURE_TEST_ENDPOINT is not set; the Azure court is not running")
	}
	return endpoint
}

func azureLiveContainer(t *testing.T) string {
	t.Helper()
	prefix := os.Getenv("WEFT_AZURE_TEST_CONTAINER")
	if prefix == "" {
		prefix = "weft-az"
	}
	cleaned := strings.Builder{}
	for i := 0; i < len(prefix); i++ {
		c := prefix[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			cleaned.WriteByte(c)
		} else {
			cleaned.WriteByte('-')
		}
	}
	name := fmt.Sprintf("%s-%d-%d", cleaned.String(), os.Getpid(), azureTestCounter.Add(1))
	name = strings.Trim(name, "-")
	if len(name) > 63 {
		name = name[:63]
	}
	return name
}

func azureLiveOptions(t *testing.T, container string, lease time.Duration) Options {
	t.Helper()
	endpoint := requireAzureEndpoint(t)
	account := os.Getenv("WEFT_AZURE_ACCOUNT")
	if account == "" {
		account = "devstoreaccount1"
	}
	key := os.Getenv("WEFT_AZURE_KEY")
	if key == "" {
		t.Fatal("WEFT_AZURE_KEY is not set; the Azure court supplies the development key")
	}
	if lease <= 0 {
		lease = 60 * time.Second
	}
	config, err := ResolveAzure(endpoint, container, account, key, "", nil, uint64(lease/time.Second))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if config.Account != account {
		t.Fatalf("account resolved to %q", config.Account)
	}
	options := DefaultOptions()
	options.BlobBackend = PlaneAzure
	options.CommitBackend = PlaneAzure
	options.Azure = &config
	options.GCGraceSecs = 0
	return options
}

// TestAzureLiveStoreRoundTrip is the same full-store path as the double, over
// a real Azurite release: create-once, ETag CAS, listing, reopen, and GC.
func TestAzureLiveStoreRoundTrip(t *testing.T) {
	container := azureLiveContainer(t)
	options := azureLiveOptions(t, container, 60*time.Second)
	writer, err := Init("", options)
	if err != nil {
		t.Fatalf("init: %v", err)
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
	if stats, ok := writer.AzureStats(); ok {
		t.Logf("host-local Azure counters (Writer, live emulator): requests=%d reads=%d bytes_read=%d writes=%d bytes_written=%d conflicts=%d fences=%d",
			stats.Requests, stats.Reads, stats.BytesRead, stats.Writes, stats.BytesWritten,
			stats.ConditionalConflict, stats.FenceChecks)
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
		if !bytes.Equal(got, want) {
			t.Fatalf("read %s returned %d bytes, want %d", path, len(got), len(want))
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
	if gc, err := cleaner.GC(true); err != nil {
		t.Fatalf("gc: %v", err)
	} else if gc.DeletedFiles == 0 {
		t.Fatalf("gc collected nothing after an unlink: %+v", gc)
	}
	if report, err := cleaner.Verify(true); err != nil || !report.OK {
		t.Fatalf("verify after GC: %v %+v", err, report)
	}
	if err := cleaner.Close(); err != nil {
		t.Fatalf("close cleaner: %v", err)
	}
}

// TestAzureLiveConditionalCreateAndCAS proves the two conditional forms against
// the emulator directly, including that a stale ETag is refused.
func TestAzureLiveConditionalCreateAndCAS(t *testing.T) {
	container := azureLiveContainer(t)
	options := azureLiveOptions(t, container, 60*time.Second)
	client, err := newAzureClient(*options.Azure)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	if err := client.ensureContainer(); err != nil {
		t.Fatalf("ensure container: %v", err)
	}
	key := "control/cas-probe"
	etag, ok, err := client.putConditional(key, []byte("one"), nil, true)
	if err != nil || !ok {
		t.Fatalf("create-once: ok=%t err=%v", ok, err)
	}
	if _, ok, err := client.putConditional(key, []byte("two"), nil, true); err != nil {
		t.Fatalf("second create: %v", err)
	} else if ok {
		t.Fatal("create-once accepted a second write")
	}
	if _, ok, err := client.putConditional(key, []byte("two"), &etag, true); err != nil || !ok {
		t.Fatalf("matching CAS: ok=%t err=%v", ok, err)
	}
	if _, ok, err := client.putConditional(key, []byte("three"), &etag, true); err != nil {
		t.Fatalf("stale CAS: %v", err)
	} else if ok {
		t.Fatal("a stale ETag was accepted")
	}
	stored, err := client.get(key, 0, 0)
	if err != nil || stored.Status != http.StatusOK {
		t.Fatalf("read after stale CAS: %v %d", err, stored.Status)
	}
	if string(stored.Body) != "two" {
		t.Fatalf("a refused stale CAS changed the bytes to %q", stored.Body)
	}
	if _, err := client.delete(key); err != nil {
		t.Fatalf("delete: %v", err)
	}
}
