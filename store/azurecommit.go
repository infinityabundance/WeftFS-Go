// Azure Blob commit plane (subphase R14): control records, commit records,
// and the fenced single-writer protocol over an Azure Blob-compatible
// endpoint.
//
// The head is published by one conditional write of the `LOCK` blob that
// carries both the fencing token and the new head; the two-slot `superblock`
// is only a cache afterwards. That is the same protocol the S3 and GCS planes
// use, with the same record body (see `fence_record.go`), so a receipt can
// compare the three field for field.
//
// Every conditional write is a `Put Blob` with `If-Match: <ETag>`. The ETag
// form is *measured* at a writable open by `probeConditionalWrites`, never
// assumed. A writer whose lease has expired refuses to publish before touching
// any head object, and release is a content-addressed tombstone published
// under `If-Match` — never an unconditional delete after a read.
package store

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// azureSuperblockKey is the two-slot head object.
const azureSuperblockKey = "superblock"

type azureControl struct {
	client *azureClient
}

func newAzureControl(client *azureClient) *azureControl {
	return &azureControl{client: client}
}

func (c *azureControl) Label() string { return "azure" }

func (c *azureControl) Root() string { return "azure://" + c.client.config.Container }

func (c *azureControl) Capabilities() CommitCapabilities {
	return CommitCapabilities{
		Backend:           "azure",
		ConditionalUpdate: true,
		AtomicPublish:     true,
		DurableFSync:      true,
		MaxControlBytes:   azureMaxObjectBytes,
		Consistency: "single-endpoint Azure Blob-compatible store; read-after-write " +
			"and list-after-write for published blobs; conditional writes " +
			"(If-None-Match: */If-Match: <ETag>) are required and measured at " +
			"writable open; a monotonic fencing token is carried in the LOCK blob",
		Publication: "Azure Put Blob (x-ms-blob-type: BlockBlob) with If-None-Match: * " +
			"(create-once); superblock slot via GET + If-Match PUT; every head " +
			"publication is one conditional write on LOCK that carries the " +
			"fencing token and names the head; release is a conditional tombstone",
	}
}

func (c *azureControl) Diagnostics() []string { return c.client.diagnostics() }

// AzureStats returns the HTTP counters of the shared Azure client. It is
// diagnostic evidence (requests and bytes on the wire), never a correctness
// input.
func (c *azureControl) AzureStats() AzureStatsSnapshot {
	return AzureStatsSnapshot{
		Requests:                c.client.stats.requests.Load(),
		Reads:                   c.client.stats.reads.Load(),
		RangeReads:              c.client.stats.rangeReads.Load(),
		BytesRead:               c.client.stats.bytesRead.Load(),
		Writes:                  c.client.stats.writes.Load(),
		BytesWritten:            c.client.stats.bytesWritten.Load(),
		ConditionalConflict:     c.client.stats.conflicts.Load(),
		LockAcquires:            c.client.stats.lockAcquires.Load(),
		FenceChecks:             c.client.stats.fenceChecks.Load(),
		LeaseRenewals:           c.client.stats.leaseRenewals.Load(),
		FenceRefusals:           c.client.stats.fenceRefusals.Load(),
		LeaseExpiredPublication: c.client.stats.leaseExpiredPublication.Load(),
		HeadPublications:        c.client.stats.headPublications.Load(),
	}
}

func (c *azureControl) EnsureLayout() error { return c.client.ensureContainer() }

// CleanTmp removes leftover probe blobs older than the grace window.
//
// Every upload is atomic under its final key, so the only `tmp/` blobs are
// capability-probe keys. That does not make them disposable: an optimistic
// (MW2) open runs concurrently with other writers, and a live writer's probe
// lives under `tmp/` for the duration of its open. Deleting it made the second
// create-once probe succeed and a healthy endpoint look as though it ignored
// `If-None-Match: *` (X13/N14, caught by four concurrent Rust writers against
// Azurite). Only an entry older than `graceSecs` is swept; an entry whose age
// cannot be established is kept.
func (c *azureControl) CleanTmp(graceSecs uint64) error {
	blobs, err := c.client.listBlobs("tmp/")
	if err != nil {
		return err
	}
	now := time.Now()
	for _, blob := range blobs {
		modified, err := http.ParseTime(blob.Properties.LastModified)
		if err != nil {
			continue
		}
		if graceSecs > 0 && now.Sub(modified) < time.Duration(graceSecs)*time.Second {
			continue
		}
		if _, err := c.client.delete(blob.Name); err != nil {
			return err
		}
	}
	return nil
}

// Sync is a no-op: a successful Put Blob is acknowledged by the service.
func (c *azureControl) Sync() error { return nil }

func (c *azureControl) Close() error {
	err := c.ReleaseWriterLock()
	c.client.http.CloseIdleConnections()
	return err
}

func (c *azureControl) ReadFormat() ([]byte, error) {
	response, err := c.client.get("FORMAT", 0, 0)
	if err != nil {
		return nil, err
	}
	switch response.Status {
	case http.StatusOK:
		return response.Body, nil
	case http.StatusNotFound:
		return nil, werr.Newf(werr.Corrupt, "cannot read FORMAT: azure://%s/FORMAT does not exist", c.client.config.Container)
	case http.StatusForbidden:
		return nil, werr.Newf(werr.Unauthorized, "Azure denied GET azure://%s/FORMAT", c.client.config.Container)
	default:
		return nil, werr.Newf(werr.Io, "Azure GET FORMAT returned HTTP %d", response.Status)
	}
}

func (c *azureControl) CreateFormat() error {
	if err := c.client.ensureContainer(); err != nil {
		return err
	}
	body := []byte(model.FormatContents)
	if _, ok, err := c.client.putConditional("FORMAT", body, nil, true); err != nil {
		return err
	} else if ok {
		return nil
	}
	existing, err := c.ReadFormat()
	if err != nil {
		return err
	}
	if overlayBytesSame(existing, body) {
		return nil
	}
	return werr.Newf(werr.Exists, "a WeftFS store already exists at azure://%s", c.client.config.Container)
}

func (c *azureControl) ReadSuperblock() (SuperblockView, error) {
	response, err := c.client.get(azureSuperblockKey, 0, 0)
	if err != nil {
		return SuperblockView{}, err
	}
	switch response.Status {
	case http.StatusOK:
		return decodeSuperblockView(response.Body)
	case http.StatusNotFound:
		return SuperblockView{}, werr.Newf(werr.Corrupt,
			"cannot read superblock azure://%s/superblock", c.client.config.Container)
	case http.StatusForbidden:
		return SuperblockView{}, werr.Newf(werr.Unauthorized, "Azure denied GET azure://%s/superblock", c.client.config.Container)
	default:
		return SuperblockView{}, werr.Newf(werr.Io, "Azure GET superblock returned HTTP %d", response.Status)
	}
}

func (c *azureControl) CreateSuperblock() error {
	body := make([]byte, model.SuperblockBytes)
	if _, ok, err := c.client.putConditional(azureSuperblockKey, body, nil, true); err != nil {
		return err
	} else if ok {
		return nil
	}
	return werr.Newf(werr.Exists, "superblock already exists at azure://%s/superblock", c.client.config.Container)
}

// PublishSuperblockSlot patches one slot and publishes it with a single
// conditional write. The writer fence is refreshed immediately before each
// attempt, so a stale writer cannot reach the head at all.
func (c *azureControl) PublishSuperblockSlot(slot SuperblockSlot, index int) error {
	if index != 0 && index != 1 {
		return werr.Newf(werr.InvalidArgument, "superblock slot index must be 0 or 1")
	}
	for attempt := 0; attempt < 8; attempt++ {
		current, err := c.client.get(azureSuperblockKey, 0, 0)
		if err != nil {
			return err
		}
		if current.Status == http.StatusForbidden {
			return werr.Newf(werr.Unauthorized, "Azure denied GET azure://%s/superblock", c.client.config.Container)
		}
		if current.Status != http.StatusOK {
			return werr.Newf(werr.Io, "Azure read-modify-write superblock returned HTTP %d", current.Status)
		}
		if len(current.Body) != model.SuperblockBytes {
			return werr.Newf(werr.Corrupt, "superblock is %d bytes, expected %d", len(current.Body), model.SuperblockBytes)
		}
		if current.ETag == "" {
			return werr.Newf(werr.Unsupported,
				"Azure endpoint did not return an ETag for the superblock; refusing an unconditional head update")
		}
		updated := append([]byte(nil), current.Body...)
		offset := index * model.SlotBytes
		copy(updated[offset:offset+model.SlotBytes], slot.Encode())
		if err := c.fenceLock(slot.Generation, slot.Commit, slot.CommitLen); err != nil {
			return err
		}
		etag := current.ETag
		if _, ok, err := c.client.putConditional(azureSuperblockKey, updated, &etag, true); err != nil {
			return err
		} else if ok {
			return nil
		}
		c.client.note("conditional superblock update lost a race; retrying from a fresh read")
	}
	return werr.Newf(werr.Busy, "superblock conditional update kept losing to another writer")
}

// PublishFencedHead publishes a head through the LOCK record in one
// conditional write that carries both the fence and the head. It is the
// publication point for an object-store commit plane; the superblock is only a
// cache afterwards.
func (c *azureControl) PublishFencedHead(generation uint64, commit model.Hash32, commitLen uint64) (bool, error) {
	if err := c.fenceLock(generation, commit, commitLen); err != nil {
		return true, err
	}
	return true, nil
}

// SupportsConditionalHeadPublication: Azure Blob has a real compare-and-swap
// (`If-Match: <ETag>`), so MW2 publishes the head with one conditional write
// instead of the POSIX publication lock. No writer lease is used on this path.
func (c *azureControl) SupportsConditionalHeadPublication() bool { return true }

// PublishHeadConditional advances the two-slot superblock in one `Put Blob`
// whose `If-Match` is the ETag the head check was made against.
//
// The comparison and the write deliberately share one request pair rather than
// going through PublishSuperblockSlot: that method retries from a fresh read
// and re-fences the writer lock, which would let a stale committer re-apply its
// slot to a head somebody else already moved. Here a lost ETag is `Busy` and is
// never retried. No lease is taken or renewed on this path; MW2 does not use the
// writer lock at all.
func (c *azureControl) PublishHeadConditional(expectedGeneration uint64, expectedCommit model.Hash32, slot SuperblockSlot) (bool, error) {
	response, err := c.client.get(azureSuperblockKey, 0, 0)
	if err != nil {
		return true, err
	}
	switch response.Status {
	case http.StatusOK:
	case http.StatusNotFound:
		return true, werr.New(werr.NotFound, "superblock does not exist")
	case http.StatusForbidden:
		return true, werr.Newf(werr.Unauthorized, "Azure denied GET azure://%s/superblock", c.client.config.Container)
	default:
		return true, werr.Newf(werr.Io, "Azure GET superblock returned HTTP %d", response.Status)
	}
	if len(response.Body) != model.SuperblockBytes {
		return true, werr.Newf(werr.Corrupt, "superblock is %d bytes, expected %d", len(response.Body), model.SuperblockBytes)
	}
	if response.ETag == "" {
		return true, werr.Newf(werr.Unsupported,
			"Azure endpoint did not return an ETag for the superblock; refusing a head write without a compare-and-swap token")
	}
	view, err := decodeSuperblockView(response.Body)
	if err != nil {
		return true, err
	}
	observedGeneration, observedCommit, ok := highestSlot(view)
	if !ok || observedGeneration != expectedGeneration || observedCommit != expectedCommit {
		return true, werr.Newf(werr.Busy,
			"head publication refused: expected generation %d commit %s, observed generation %d commit %s",
			expectedGeneration, expectedCommit.Hex(), observedGeneration, observedCommit.Hex())
	}
	updated := append([]byte(nil), response.Body...)
	offset := int(slot.Generation%2) * model.SlotBytes
	copy(updated[offset:offset+model.SlotBytes], slot.Encode())
	etag := response.ETag
	if _, published, err := c.client.putConditional(azureSuperblockKey, updated, &etag, true); err != nil {
		return true, err
	} else if !published {
		return true, werr.New(werr.Busy,
			"head publication lost the conditional write race; the move is not retried")
	}
	c.client.stats.headPublications.Add(1)
	return true, nil
}

// AttestedHead returns the head the published LOCK record names.
func (c *azureControl) AttestedHead() (uint64, model.Hash32, uint64, bool, error) {
	response, err := c.client.get("LOCK", 0, 0)
	if err != nil {
		return 0, model.Hash32{}, 0, false, err
	}
	if response.Status == http.StatusNotFound {
		return 0, model.Hash32{}, 0, false, nil
	}
	if response.Status != http.StatusOK {
		return 0, model.Hash32{}, 0, false,
			werr.Newf(werr.Io, "Azure LOCK read returned HTTP %d", response.Status)
	}
	record, ok := parseAzureLock(response.Body)
	if !ok {
		return 0, model.Hash32{}, 0, false, nil
	}
	generation, commit, ok := record.attestedHead()
	if !ok {
		return 0, model.Hash32{}, 0, false, nil
	}
	return generation, commit, record.pendingCommitLen, true, nil
}

// RefreshHeadCache keeps the two-slot superblock cache current after a LOCK
// publication. It never moves the cache backwards, and a lost race is retried
// from a fresh read. A failure is a diagnostic, never a publication failure
// (the LOCK write is the publication).
func (c *azureControl) RefreshHeadCache(generation uint64, commit model.Hash32, commitLen uint64, timestampNS int64) error {
	if commitLen == 0 {
		c.client.note("superblock cache not refreshed: the lock record does not attest the commit length")
		return nil
	}
	for attempt := 0; attempt < 8; attempt++ {
		current, err := c.client.get(azureSuperblockKey, 0, 0)
		if err != nil {
			return err
		}
		if current.Status != http.StatusOK {
			return werr.Newf(werr.Io, "Azure cache read superblock returned HTTP %d", current.Status)
		}
		if len(current.Body) != model.SuperblockBytes {
			return werr.Newf(werr.Corrupt, "superblock is %d bytes, expected %d", len(current.Body), model.SuperblockBytes)
		}
		view, err := decodeSuperblockView(current.Body)
		if err != nil {
			return err
		}
		highest := uint64(0)
		for index := 0; index < 2; index++ {
			if view.Valid[index] && view.Slots[index].Generation > highest {
				highest = view.Slots[index].Generation
			}
		}
		if highest >= generation {
			return nil
		}
		if current.ETag == "" {
			return werr.Newf(werr.Unsupported, "Azure endpoint did not return an ETag for a cache update")
		}
		updated := append([]byte(nil), current.Body...)
		g := SuperblockSlot{Generation: generation, Commit: commit, CommitLen: commitLen, TimestampNS: timestampNS}
		offset := int(generation%2) * model.SlotBytes
		copy(updated[offset:offset+model.SlotBytes], g.Encode())
		etag := current.ETag
		if _, ok, err := c.client.putConditional(azureSuperblockKey, updated, &etag, true); err != nil {
			return err
		} else if ok {
			return nil
		}
		c.client.note("conditional superblock cache update lost a race; retrying from a fresh read")
	}
	return werr.Newf(werr.Busy, "superblock cache update kept losing to another writer")
}

func (c *azureControl) commitKey(generation uint64) string {
	return "commits/" + strconv.FormatUint(generation, 10) + ".commit"
}

func (c *azureControl) CreateCommit(generation uint64, data []byte) error {
	key := c.commitKey(generation)
	if _, ok, err := c.client.putConditional(key, data, nil, true); err != nil {
		return err
	} else if ok {
		return nil
	}
	existing, err := c.client.get(key, 0, 0)
	if err != nil {
		return err
	}
	if existing.Status == http.StatusOK && overlayBytesSame(existing.Body, data) {
		return nil
	}
	return werr.Newf(werr.Exists, "commit azure://%s/%s already exists with different bytes", c.client.config.Container, key)
}

func (c *azureControl) ReadCommit(generation uint64) (LoadedCommit, error) {
	key := c.commitKey(generation)
	response, err := c.client.get(key, 0, 0)
	if err != nil {
		return LoadedCommit{}, err
	}
	switch response.Status {
	case http.StatusOK:
		expected := generation
		return ParseCommitBytes(response.Body, &expected)
	case http.StatusNotFound:
		return LoadedCommit{}, werr.Newf(werr.Corrupt, "cannot read azure://%s/%s", c.client.config.Container, key)
	case http.StatusForbidden:
		return LoadedCommit{}, werr.Newf(werr.Unauthorized, "Azure denied GET azure://%s/%s", c.client.config.Container, key)
	default:
		return LoadedCommit{}, werr.Newf(werr.Io, "Azure GET azure://%s/%s returned HTTP %d",
			c.client.config.Container, key, response.Status)
	}
}

func (c *azureControl) HasCommit(generation uint64) (bool, error) {
	key := c.commitKey(generation)
	response, err := c.client.head(key)
	if err != nil {
		return false, err
	}
	switch response.Status {
	case http.StatusOK, http.StatusNoContent:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	case http.StatusForbidden:
		return false, werr.Newf(werr.Unauthorized, "Azure denied HEAD azure://%s/%s", c.client.config.Container, key)
	default:
		return false, werr.Newf(werr.Io, "Azure HEAD azure://%s/%s returned HTTP %d",
			c.client.config.Container, key, response.Status)
	}
}

func (c *azureControl) ListCommitGenerations() ([]uint64, error) {
	blobs, err := c.client.listBlobs("commits/")
	if err != nil {
		return nil, err
	}
	out := make([]uint64, 0, len(blobs))
	for _, blob := range blobs {
		name := strings.TrimPrefix(blob.Name, "commits/")
		if generation, ok := ParseCommitFilename(name); ok {
			out = append(out, generation)
		}
	}
	return out, nil
}

func (c *azureControl) ReadRecord(name string) ([]byte, bool, error) {
	response, err := c.client.get(name, 0, 0)
	if err != nil {
		return nil, false, err
	}
	switch response.Status {
	case http.StatusOK:
		return response.Body, true, nil
	case http.StatusNotFound:
		return nil, false, nil
	case http.StatusForbidden:
		return nil, false, werr.Newf(werr.Unauthorized, "Azure denied GET azure://%s/%s", c.client.config.Container, name)
	default:
		return nil, false, werr.Newf(werr.Io, "Azure GET azure://%s/%s returned HTTP %d",
			c.client.config.Container, name, response.Status)
	}
}

// ReadControl is the pack-plane view: record bytes and the content token.
func (c *azureControl) ReadControl(name string) ([]byte, string, bool, error) {
	data, present, err := c.ReadRecord(name)
	if err != nil || !present {
		return data, "", present, err
	}
	return data, ControlToken(data), true, nil
}

func (c *azureControl) WriteRecordNew(name string, data []byte) error {
	if _, ok, err := c.client.putConditional(name, data, nil, true); err != nil {
		return err
	} else if ok {
		return nil
	}
	existing, present, err := c.ReadRecord(name)
	if err != nil {
		return err
	}
	if present && overlayBytesSame(existing, data) {
		return nil
	}
	return werr.Newf(werr.Exists, "record azure://%s/%s already exists with different bytes", c.client.config.Container, name)
}

func (c *azureControl) WriteRecordReplace(name string, data []byte) error {
	return c.client.putReplace(name, data)
}

// CompareExchange is the token-based conditional write the pack catalog uses.
func (c *azureControl) CompareExchange(name string, expected *string, data []byte) (string, error) {
	_, token, present, err := c.ReadControl(name)
	if err != nil {
		return "", err
	}
	if expected == nil {
		if present {
			return "", werr.Newf(werr.Busy, "control record %s appeared before the compare-and-swap", name)
		}
	} else if !present || token != *expected {
		return "", werr.Newf(werr.Busy, "control record %s changed since it was read; compare-and-swap refused", name)
	}
	if expected == nil {
		_, ok, err := c.client.putConditional(name, data, nil, true)
		if err != nil {
			return "", err
		}
		if !ok {
			return "", werr.Newf(werr.Busy, "control record %s appeared during the compare-and-swap", name)
		}
		return ControlToken(data), nil
	}
	// Re-read to obtain the current ETag for the conditional write. A change
	// between the token read and this read is caught by the ETag CAS.
	response, err := c.client.get(name, 0, 0)
	if err != nil {
		return "", err
	}
	if response.Status != http.StatusOK || response.ETag == "" {
		return "", werr.Newf(werr.Busy, "control record %s disappeared during the compare-and-swap", name)
	}
	etag := response.ETag
	if _, ok, err := c.client.putConditional(name, data, &etag, true); err != nil {
		return "", err
	} else if !ok {
		return "", werr.Newf(werr.Busy, "control record %s changed during the compare-and-swap", name)
	}
	return ControlToken(data), nil
}

func (c *azureControl) DeleteRecord(name string) error {
	head, err := c.client.head(name)
	if err != nil {
		return err
	}
	switch head.Status {
	case http.StatusOK, http.StatusNoContent:
	case http.StatusNotFound:
		return werr.Newf(werr.NotFound, "control record azure://%s/%s does not exist", c.client.config.Container, name)
	default:
		return werr.Newf(werr.Io, "Azure HEAD azure://%s/%s returned HTTP %d", c.client.config.Container, name, head.Status)
	}
	response, err := c.client.delete(name)
	if err != nil {
		return err
	}
	if response.Status != http.StatusOK && response.Status != http.StatusAccepted &&
		response.Status != http.StatusNoContent && response.Status != http.StatusNotFound {
		return werr.Newf(werr.Io, "Azure DELETE azure://%s/%s returned HTTP %d",
			c.client.config.Container, name, response.Status)
	}
	return nil
}

// ListRecords returns the full relative keys directly under `prefix`.
func (c *azureControl) ListRecords(prefix string) ([]string, error) {
	normalized := strings.TrimSuffix(prefix, "/") + "/"
	blobs, err := c.client.listBlobs(normalized)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(blobs))
	for _, blob := range blobs {
		rest := strings.TrimPrefix(blob.Name, normalized)
		if rest == "" || strings.Contains(rest, "/") {
			continue
		}
		out = append(out, blob.Name)
	}
	return out, nil
}

func (c *azureControl) leaseNS() int64 {
	nanos := int64(c.client.config.LockLease / time.Nanosecond)
	if nanos <= 0 {
		return 1
	}
	return nanos
}

func (c *azureControl) publicationBudgetNS() int64 {
	budget := c.leaseNS() / 2
	if budget < 1 {
		return 1
	}
	return budget
}

func (c *azureControl) nextOwner() string {
	seq := c.client.counter.Add(1)
	return strconv.Itoa(os.Getpid()) + "-" + strconv.FormatUint(seq, 10) + "-" + strconv.FormatInt(nowNS(), 10)
}

func (c *azureControl) installLease(lease *azureLockLease) {
	c.client.lockMu.Lock()
	c.client.lease = lease
	c.client.lockMu.Unlock()
}

// AcquireWriterLock takes or reclaims the fenced lease. The refusal text is a
// fixed sentence on purpose: a live lock never discloses the holder.
func (c *azureControl) AcquireWriterLock() error {
	if err := c.probeConditionalWrites(); err != nil {
		return err
	}
	now := nowNS()
	owner := c.nextOwner()
	deadline := now + c.leaseNS()
	for attempt := 0; attempt < 4; attempt++ {
		existing, err := c.client.get("LOCK", 0, 0)
		if err != nil {
			return err
		}
		switch existing.Status {
		case http.StatusNotFound:
			headGen, headCommit, headLen, headOK := c.superblockHead()
			body := encodeAzureLockHead(owner, 1, 1, deadline, now, headGen, headCommit, headLen, headOK)
			etag, ok, err := c.client.putConditional("LOCK", []byte(body), nil, true)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			c.client.stats.lockAcquires.Add(1)
			c.installLease(&azureLockLease{
				owner: owner, fence: 1, sequence: 1, deadlineNS: deadline, renewedNS: now,
				etag: etag, headGeneration: headGen, headCommit: headCommit, headCommitLen: headLen,
			})
			return nil
		case http.StatusOK:
			observed, ok := parseAzureLock(existing.Body)
			if !ok {
				return werr.Newf(werr.Busy,
					"store LOCK blob is unreadable; refusing a writable open rather than guessing whether a writer holds it")
			}
			if observed.isLive(now) {
				c.client.note("writable open refused: the LOCK is live (owner " + observed.owner +
					" fence " + strconv.FormatUint(observed.fence, 10) + ", lease ends in " +
					strconv.FormatInt((observed.deadlineNS-now)/1_000_000, 10) + " ms)")
				return werr.Newf(werr.Busy, "store is locked by another Azure writer (live LOCK blob)")
			}
			if observed.fence == ^uint64(0) {
				return werr.Newf(werr.LimitExceeded, "Azure fencing token would overflow u64")
			}
			fence := observed.fence + 1
			// Carry the head the old record names forward. A v1/v2 tombstone has
			// no head, so fall back to the superblock cache. The same conditional
			// write upgrades an expired v2/v1 record to v3.
			headGen, headCommit, headLen := observed.pendingGeneration, observed.pendingCommit, observed.pendingCommitLen
			headOK := headGen != 0 && headCommit != "" && headCommit != "-"
			if !headOK {
				headGen, headCommit, headLen, headOK = c.superblockHead()
			}
			body := encodeAzureLockHead(owner, fence, 1, deadline, now, headGen, headCommit, headLen, headOK)
			if existing.ETag == "" {
				return werr.Newf(werr.Unsupported,
					"Azure-compatible endpoint did not return an ETag for the writer lock; refusing a writable store because a fenced reclaim cannot be proven")
			}
			etag := existing.ETag
			newETag, ok, err := c.client.putConditional("LOCK", []byte(body), &etag, true)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			verb := "reclaimed an expired"
			if observed.released {
				verb = "reclaimed a released"
			}
			c.client.note(verb + " Azure writer lock: fence " + strconv.FormatUint(observed.fence, 10) +
				" -> " + strconv.FormatUint(fence, 10))
			if observed.schemaVersion < 3 {
				c.client.note("upgraded the Azure writer lock record to v3 (single conditional write; the head it attests is carried forward)")
			}
			c.client.stats.lockAcquires.Add(1)
			c.installLease(&azureLockLease{
				owner: owner, fence: fence, sequence: 1, deadlineNS: deadline, renewedNS: now,
				etag: newETag, headGeneration: headGen, headCommit: headCommit, headCommitLen: headLen,
			})
			return nil
		case http.StatusForbidden:
			return werr.Newf(werr.Unauthorized, "Azure denied GET azure://%s/LOCK", c.client.config.Container)
		default:
			return werr.Newf(werr.Io, "Azure LOCK read returned HTTP %d", existing.Status)
		}
	}
	return werr.Newf(werr.Busy, "could not acquire the Azure writer lock after four conditional attempts")
}

// VerifyWriteLease proves this handle may publish right now, renewing when one
// publication budget remains. The conditional write carries forward the head
// this handle last published, so a pre-publication fence never erases the
// record's attestation.
func (c *azureControl) VerifyWriteLease() error { return c.fenceLock(0, model.ZeroHash, 0) }

// CheckLeaseDeadline is a local own-deadline check: no network write and no
// renewal. It refuses before a commit record is written, so a writer suspended
// past its own deadline leaves no unpublished commit tail.
func (c *azureControl) CheckLeaseDeadline() error {
	c.client.lockMu.Lock()
	lease := c.client.lease
	c.client.lockMu.Unlock()
	if lease == nil {
		return werr.Newf(werr.Busy, "Azure writer holds no lease; refusing to publish without a fenced lease")
	}
	now := nowNS()
	if now >= lease.deadlineNS {
		expired := (now - lease.deadlineNS) / 1_000_000
		observed := c.readLockRecordNoFail()
		c.client.stats.leaseExpiredPublication.Add(1)
		return werr.Newf(werr.Busy,
			"Azure writer lease deadline passed %d ms ago (owner %s fence %d); publication refused before the head was touched%s",
			expired, lease.owner, lease.fence, describeObserved(observed, lease.owner, lease.fence))
	}
	return nil
}

// fenceLock is the conditional rewrite of LOCK that gates every publication.
// With `pendingGeneration != 0` it is also the publication point: the same
// `If-Match` write carries the fence and the new head.
func (c *azureControl) fenceLock(pendingGeneration uint64, pendingCommit model.Hash32, pendingCommitLen uint64) error {
	c.client.lockMu.Lock()
	defer c.client.lockMu.Unlock()
	lease := c.client.lease
	if lease == nil {
		return werr.Newf(werr.Busy, "Azure writer holds no lease; refusing to publish without a fenced lease")
	}
	now := nowNS()
	if now >= lease.deadlineNS {
		expired := (now - lease.deadlineNS) / 1_000_000
		observed := c.readLockRecordNoFail()
		c.client.stats.leaseExpiredPublication.Add(1)
		return werr.Newf(werr.Busy,
			"Azure writer lease deadline passed %d ms ago (owner %s fence %d); publication refused before the head was touched%s",
			expired, lease.owner, lease.fence, describeObserved(observed, lease.owner, lease.fence))
	}
	renew := now+c.publicationBudgetNS() >= lease.deadlineNS
	deadline := lease.deadlineNS
	if renew {
		deadline = now + c.leaseNS()
	}
	sequence := lease.sequence + 1
	// The head this record will attest: the new one when publishing, or the one
	// already published when this is only a pre-publication fence.
	headGeneration, headCommit, headCommitLen := lease.headGeneration, lease.headCommit, lease.headCommitLen
	if pendingGeneration != 0 {
		headGeneration, headCommit, headCommitLen = pendingGeneration, pendingCommit.Hex(), pendingCommitLen
	}
	body := encodeAzureLock(lease.owner, lease.fence, sequence, deadline, now, headGeneration, headCommit, headCommitLen)
	etag := lease.etag
	newETag, ok, err := c.client.putConditional("LOCK", []byte(body), &etag, true)
	if err != nil {
		return err
	}
	if !ok {
		observed := c.readLockRecordNoFail()
		c.client.stats.fenceRefusals.Add(1)
		return werr.Newf(werr.Busy,
			"Azure writer lease was taken over: the conditional fence CAS for owner %s fence %d was refused, so the publication was abandoned without writing the head%s",
			lease.owner, lease.fence, describeObserved(observed, lease.owner, lease.fence))
	}
	lease.sequence = sequence
	lease.deadlineNS = deadline
	lease.renewedNS = now
	lease.etag = newETag
	lease.headGeneration = headGeneration
	lease.headCommit = headCommit
	lease.headCommitLen = headCommitLen
	c.client.stats.fenceChecks.Add(1)
	if renew {
		c.client.stats.leaseRenewals.Add(1)
	}
	if pendingGeneration != 0 {
		c.client.stats.headPublications.Add(1)
	}
	return nil
}

// superblockHead reads the head the two-slot cache attests. Used only to carry
// a head forward when the LOCK record does not name one.
func (c *azureControl) superblockHead() (uint64, string, uint64, bool) {
	response, err := c.client.get(azureSuperblockKey, 0, 0)
	if err != nil || response.Status != http.StatusOK {
		return 0, "", 0, false
	}
	view, err := decodeSuperblockView(response.Body)
	if err != nil {
		return 0, "", 0, false
	}
	var best SuperblockSlot
	found := false
	for index := 0; index < 2; index++ {
		if !view.Valid[index] || view.Slots[index].Generation == 0 {
			continue
		}
		if !found || view.Slots[index].Generation > best.Generation {
			best = view.Slots[index]
			found = true
		}
	}
	if !found {
		return 0, "", 0, false
	}
	return best.Generation, best.Commit.Hex(), best.CommitLen, true
}

func encodeAzureLockHead(owner string, fence, sequence uint64, deadlineNS, renewedNS int64, generation uint64, commit string, commitLen uint64, ok bool) string {
	if !ok {
		return encodeAzureLock(owner, fence, sequence, deadlineNS, renewedNS, 0, "", 0)
	}
	return encodeAzureLock(owner, fence, sequence, deadlineNS, renewedNS, generation, commit, commitLen)
}

func (c *azureControl) readLockRecordNoFail() *publishedLock {
	response, err := c.client.get("LOCK", 0, 0)
	if err != nil || response.Status != http.StatusOK {
		return nil
	}
	record, ok := parseAzureLock(response.Body)
	if !ok {
		return nil
	}
	return &record
}

// ReadLockRecord returns the published LOCK, read fresh. Read-only.
func (c *azureControl) ReadLockRecord() (*publishedLock, error) {
	response, err := c.client.get("LOCK", 0, 0)
	if err != nil {
		return nil, err
	}
	switch response.Status {
	case http.StatusOK:
		record, ok := parseAzureLock(response.Body)
		if !ok {
			return nil, werr.Newf(werr.Corrupt, "published LOCK record is unreadable")
		}
		return &record, nil
	case http.StatusNotFound:
		return nil, nil
	default:
		return nil, werr.Newf(werr.Io, "Azure LOCK read returned HTTP %d", response.Status)
	}
}

// ReleaseWriterLock publishes a content-addressed tombstone under a conditional
// write. It never deletes the lock after a read.
func (c *azureControl) ReleaseWriterLock() error {
	c.client.lockMu.Lock()
	lease := c.client.lease
	c.client.lease = nil
	c.client.lockMu.Unlock()
	if lease == nil {
		return nil
	}
	observed, err := c.client.get("LOCK", 0, 0)
	if err != nil {
		c.client.note("could not read LOCK to release it: " + err.Error())
		return nil
	}
	if observed.Status == http.StatusNotFound {
		return nil
	}
	if observed.Status != http.StatusOK {
		c.client.note("could not read LOCK to release it: HTTP " + strconv.Itoa(observed.Status))
		return nil
	}
	record, ok := parseAzureLock(observed.Body)
	if !ok {
		c.client.note("refusing to release an unreadable LOCK record")
		return nil
	}
	if record.owner != lease.owner || record.fence != lease.fence {
		c.client.note("refusing to release the Azure writer lock: it now names owner " + record.owner +
			" fence " + strconv.FormatUint(record.fence, 10) + " and this handle holds fence " +
			strconv.FormatUint(lease.fence, 10) + "; the conditional release was not attempted")
		return nil
	}
	if observed.ETag == "" {
		c.client.note("refusing to release the Azure writer lock: no ETag to condition on")
		return nil
	}
	// Carry the head forward so a crash between the publication and the
	// superblock cache can still be recovered from the tombstone.
	headGeneration, headCommit, headCommitLen := record.pendingGeneration, record.pendingCommit, record.pendingCommitLen
	if headGeneration == 0 || headCommit == "-" {
		headGeneration, headCommit, headCommitLen = lease.headGeneration, lease.headCommit, lease.headCommitLen
	}
	tombstone := encodeAzureReleased(lease.owner, lease.fence, lease.sequence+1, nowNS(), sha256HexBytes(observed.Body), headGeneration, headCommit, headCommitLen)
	etag := observed.ETag
	if _, ok, err := c.client.putConditional("LOCK", []byte(tombstone), &etag, true); err != nil {
		c.client.note("conditional release of the Azure writer lock failed, nothing was deleted: " + err.Error())
		return nil
	} else if !ok {
		c.client.note("refusing to release the Azure writer lock: it was replaced between the read and the conditional tombstone (this writer held fence " +
			strconv.FormatUint(lease.fence, 10) + "); the successor's lock is intact")
		return nil
	}
	c.client.note("released the Azure writer lock with a conditional tombstone (fence " +
		strconv.FormatUint(lease.fence, 10) + ")")
	return nil
}

// probeConditionalWrites proves the endpoint honours both conditional forms
// the store depends on and measures the If-Match form in use.
func (c *azureControl) probeConditionalWrites() error {
	c.client.probeMu.Lock()
	defer c.client.probeMu.Unlock()
	if c.client.probed {
		return c.client.probeErr
	}
	err := c.runConditionalProbe()
	c.client.probed = true
	c.client.probeErr = err
	if err == nil {
		c.client.note("Azure conditional-write probe passed; If-Match form is " + c.client.headIfMatchForm().String())
	}
	return err
}

func (c *azureControl) runConditionalProbe() error {
	key := probeRelPath("conditional")
	cleanup := func() { _, _ = c.client.delete(key) }

	if _, ok, err := c.client.putConditional(key, []byte("probe-one"), nil, false); err != nil {
		return err
	} else if !ok {
		cleanup()
		return werr.Newf(werr.Io, "Azure conditional probe: unexpected existing blob")
	}
	if _, ok, err := c.client.putConditional(key, []byte("probe-two"), nil, false); err != nil {
		cleanup()
		return err
	} else if ok {
		cleanup()
		return werr.Newf(werr.Unsupported,
			"Azure-compatible endpoint ignored If-None-Match: *; refusing a writable store because create-once publication cannot be guaranteed")
	}
	current, err := c.client.get(key, 0, 0)
	if err != nil {
		cleanup()
		return err
	}
	if current.Status != http.StatusOK || string(current.Body) != "probe-one" {
		cleanup()
		return werr.Newf(werr.Io, "Azure conditional probe: first writer's bytes are not readable")
	}
	if current.ETag == "" {
		cleanup()
		return werr.Newf(werr.Unsupported,
			"Azure-compatible endpoint did not return an ETag; refusing a writable store")
	}
	etag := current.ETag
	dequoted := stripETagQuotes(etag)
	var form IfMatchForm
	var matching string
	if _, ok, err := c.client.putConditionalHeader(key, []byte("probe-three"), etag, false); err != nil {
		cleanup()
		return err
	} else if ok {
		form = IfMatchAsReturned
		matching = etag
	} else if dequoted != etag {
		if _, ok, err := c.client.putConditionalHeader(key, []byte("probe-three"), dequoted, false); err != nil {
			cleanup()
			return err
		} else if ok {
			form = IfMatchDequoted
			matching = dequoted
		} else {
			cleanup()
			return werr.Newf(werr.Unsupported,
				"Azure-compatible endpoint rejected a matching If-Match in both forms (as returned %q and dequoted %q); refusing a writable store because head publication cannot be proven",
				etag, dequoted)
		}
	} else {
		cleanup()
		return werr.Newf(werr.Io, "Azure conditional probe: a matching If-Match was unexpectedly rejected")
	}
	before, err := c.client.get(key, 0, 0)
	if err != nil {
		cleanup()
		return err
	}
	if before.Status != http.StatusOK || string(before.Body) != "probe-three" {
		cleanup()
		return werr.Newf(werr.Io, "Azure conditional probe: the matching conditional write is not readable")
	}
	if _, ok, err := c.client.putConditionalHeader(key, []byte("probe-four"), matching, false); err != nil {
		cleanup()
		return err
	} else if ok {
		cleanup()
		return werr.Newf(werr.Unsupported,
			"Azure-compatible endpoint accepted a stale If-Match; refusing a writable store because head publication could lose a race silently")
	}
	after, err := c.client.get(key, 0, 0)
	if err != nil {
		cleanup()
		return err
	}
	if after.Status != http.StatusOK || string(after.Body) != "probe-three" {
		cleanup()
		return werr.Newf(werr.Io, "Azure conditional probe: a refused stale If-Match changed the blob")
	}
	c.client.mu.Lock()
	c.client.form = form
	c.client.mu.Unlock()
	if form == IfMatchDequoted {
		c.client.note("endpoint compares If-Match literally: ETag " + etag +
			" is accepted only when the surrounding quotes are stripped; using the dequoted form for every conditional write (matching accepted, stale refused, winner bytes kept)")
	}
	cleanup()
	return nil
}

func (c *azureControl) probe() (CommitProbe, error) {
	probe := CommitProbe{Backend: "azure", TokenKind: "content-token"}
	if err := c.probeConditionalWrites(); err != nil {
		return probe, err
	}
	probe.Attempted = true
	name := probeRelPath("commit")
	first, err := c.CompareExchange(name, nil, []byte("plane-probe-a"))
	if err != nil {
		return probe, err
	}
	data, _, _, err := c.ReadControl(name)
	if err != nil {
		return probe, err
	}
	probe.CreateOK = overlayBytesSame(data, []byte("plane-probe-a"))
	second, err := c.CompareExchange(name, &first, []byte("plane-probe-b"))
	if err != nil {
		return probe, err
	}
	data, _, _, err = c.ReadControl(name)
	if err != nil {
		return probe, err
	}
	probe.MatchingCompareExchangeOK = overlayBytesSame(data, []byte("plane-probe-b"))
	if _, err := c.CompareExchange(name, &first, []byte("plane-probe-c")); err != nil {
		if typed, ok := err.(*werr.Error); ok && typed.Kind == werr.Busy {
			probe.StaleCompareExchangeRejected = true
		}
	}
	_ = second
	_ = c.DeleteRecord(name)
	if !probe.CreateOK || !probe.MatchingCompareExchangeOK {
		return probe, werr.Newf(werr.Io,
			"commit plane `azure` failed its capability probe (create_ok=%t, matching_compare_exchange_ok=%t)",
			probe.CreateOK, probe.MatchingCompareExchangeOK)
	}
	if !probe.StaleCompareExchangeRejected {
		return probe, werr.Newf(werr.Unsupported,
			"commit plane `azure` accepted a stale compare-and-swap token; refusing a writable store")
	}
	probe.Detail = "create-once CAS, matching CAS, and stale-token rejection all observed on a private control record; durability is the service acknowledgement and is not proved here"
	return probe, nil
}
