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

// TestAzureOptimisticWriterModeIsRefused records the Go scope boundary: MW2
// uses the POSIX publication lock and is implemented for the local and object
// commit planes only. Refusing here is explicit, never a silent downgrade.
func TestAzureOptimisticWriterModeIsRefused(t *testing.T) {
	options := azureFakeOptions(t, newAzureFake())
	options.WriterMode = WriterModeOptimistic
	_, err := Init("", options)
	expectClass(t, err, werr.Unsupported, "azure commit plane with --writer-mode optimistic")
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
