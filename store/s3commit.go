// S3 control volume: FORMAT, the fenced writer lock, the two-slot superblock,
// commit records, refs, and mutable store records over an S3-compatible
// endpoint.
//
// # Protocol mapping
//
//   - FORMAT, commit records, snapshot pointers: PUT with `If-None-Match: *`.
//     Identical bytes under an existing key are idempotent; different bytes are
//     `Exists`.
//   - superblock: one 8192-byte object holding the same two 4096-byte slots as
//     the local layout. Updating one slot is a whole-object read-modify-write
//     with `If-Match: <current ETag>`. A lost race returns 412 and the update
//     is retried from a fresh read; it never overwrites a head it did not read.
//   - mutable records (quota, access counters, the pack catalog root): the same
//     conditional replace, creating the key once when it is absent.
//   - writer lock: a `LOCK` object carrying an owner, a monotonic fencing
//     token, a bounded lease deadline, and the head being published.
//
// # Fenced single-writer protocol
//
// Every head publication performs one conditional write on `LOCK` immediately
// before the superblock slot CAS. That write is `If-Match: <ETag of the bytes
// this handle last published>`, so it succeeds only while the object still
// holds this writer's fencing token: a successor that reclaimed the lease
// rewrote the object, which changes its ETag, so the stale writer gets 412 and
// its publication fails `Busy` without touching the head. The same write names
// the head (`pending_generation`, `pending_commit`) and renews the lease when
// one publication budget remains. A writer stops publishing as soon as its own
// deadline passes, even if nobody took over.
//
// Release is never an unconditional DELETE after a read. It is a
// content-addressed tombstone published with `If-Match` on the ETag the writer
// observed, so a successor's lock can never be deleted by the writer it
// replaced. A tombstone keeps the fencing token monotonic; deleting the object
// would reset it.
//
// This is two conditional writes on two objects, not one atomic operation:
// S3 has no primitive that fences and publishes a head atomically. The fence
// still makes a stale publication impossible, because a successor cannot take
// the lease without rewriting LOCK, and the writer then fails its own fence.
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

// s3SuperblockKey is the two-slot head object.
const s3SuperblockKey = "superblock"

type s3Control struct {
	client *s3Client
}

func newS3Control(client *s3Client) *s3Control {
	return &s3Control{client: client}
}

func (c *s3Control) Label() string { return "s3" }

func (c *s3Control) Root() string { return "s3://" + c.client.config.Bucket }

func (c *s3Control) Capabilities() CommitCapabilities {
	return CommitCapabilities{
		Backend:           "s3",
		ConditionalUpdate: true,
		AtomicPublish:     true,
		DurableFSync:      true,
		MaxControlBytes:   s3MaxObjectBytes,
		Consistency: "single-node S3-compatible endpoint; read-after-write and " +
			"list-after-write for published keys; conditional writes are required " +
			"and measured at writable open; a monotonic fencing token is carried " +
			"in the LOCK object",
		Publication: "S3 PUT with If-None-Match: * (create-once); superblock slot " +
			"via GET + If-Match PUT; every head publication is preceded by one " +
			"conditional write on LOCK that carries the fencing token and names " +
			"the head; release is a conditional tombstone",
	}
}

func (c *s3Control) Diagnostics() []string { return c.client.diagnostics() }

// S3Stats returns the HTTP counters of the shared S3 client. It is diagnostic
// evidence (requests and bytes on the wire), never a correctness input.
func (c *s3Control) S3Stats() S3StatsSnapshot {
	return S3StatsSnapshot{
		Requests:            c.client.stats.requests.Load(),
		Reads:               c.client.stats.reads.Load(),
		RangeReads:          c.client.stats.rangeReads.Load(),
		BytesRead:           c.client.stats.bytesRead.Load(),
		Writes:              c.client.stats.writes.Load(),
		BytesWritten:        c.client.stats.bytesWritten.Load(),
		ConditionalConflict: c.client.stats.conflicts.Load(),
	}
}

func (c *s3Control) EnsureLayout() error { return c.client.ensureBucket() }

// CleanTmp removes leftover probe keys. The writer lock is held here, so no
// other writer can be using them.
func (c *s3Control) CleanTmp(graceSecs uint64) error {
	objects, err := c.client.listPrefix("tmp/")
	if err != nil {
		return err
	}
	for _, object := range objects {
		if _, err := c.client.delete(object.Key); err != nil {
			return err
		}
	}
	return nil
}

// Sync is a no-op: a successful S3 PUT is acknowledged by the provider.
func (c *s3Control) Sync() error { return nil }

func (c *s3Control) Close() error {
	err := c.ReleaseWriterLock()
	c.client.http.CloseIdleConnections()
	return err
}

func (c *s3Control) ReadFormat() ([]byte, error) {
	response, err := c.client.get("FORMAT", 0, 0)
	if err != nil {
		return nil, err
	}
	switch response.Status {
	case http.StatusOK:
		return response.Body, nil
	case http.StatusNotFound:
		return nil, werr.Newf(werr.Corrupt, "cannot read FORMAT: s3://%s/FORMAT does not exist", c.client.config.Bucket)
	case http.StatusForbidden:
		return nil, werr.Newf(werr.Unauthorized, "S3 denied GET s3://%s/FORMAT", c.client.config.Bucket)
	default:
		return nil, werr.Newf(werr.Io, "S3 GET FORMAT returned HTTP %d", response.Status)
	}
}

func (c *s3Control) CreateFormat() error {
	if err := c.client.ensureBucket(); err != nil {
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
	return werr.Newf(werr.Exists, "a WeftFS store already exists at s3://%s", c.client.config.Bucket)
}

func (c *s3Control) ReadSuperblock() (SuperblockView, error) {
	response, err := c.client.get(s3SuperblockKey, 0, 0)
	if err != nil {
		return SuperblockView{}, err
	}
	switch response.Status {
	case http.StatusOK:
		return decodeSuperblockView(response.Body)
	case http.StatusNotFound:
		return SuperblockView{}, werr.Newf(werr.Corrupt,
			"cannot read superblock s3://%s/superblock", c.client.config.Bucket)
	case http.StatusForbidden:
		return SuperblockView{}, werr.Newf(werr.Unauthorized, "S3 denied GET s3://%s/superblock", c.client.config.Bucket)
	default:
		return SuperblockView{}, werr.Newf(werr.Io, "S3 GET superblock returned HTTP %d", response.Status)
	}
}

func (c *s3Control) CreateSuperblock() error {
	body := make([]byte, model.SuperblockBytes)
	if _, ok, err := c.client.putConditional(s3SuperblockKey, body, nil, true); err != nil {
		return err
	} else if ok {
		return nil
	}
	return werr.Newf(werr.Exists, "superblock already exists at s3://%s/superblock", c.client.config.Bucket)
}

// PublishSuperblockSlot patches one slot and publishes it with a single
// conditional write. The writer fence is refreshed immediately before each
// attempt, so a stale writer cannot reach the head at all.
func (c *s3Control) PublishSuperblockSlot(slot SuperblockSlot, index int) error {
	if index != 0 && index != 1 {
		return werr.Newf(werr.InvalidArgument, "superblock slot index must be 0 or 1")
	}
	for attempt := 0; attempt < 8; attempt++ {
		current, err := c.client.get(s3SuperblockKey, 0, 0)
		if err != nil {
			return err
		}
		if current.Status == http.StatusForbidden {
			return werr.Newf(werr.Unauthorized, "S3 denied GET s3://%s/superblock", c.client.config.Bucket)
		}
		if current.Status != http.StatusOK {
			return werr.Newf(werr.Io, "S3 read-modify-write superblock returned HTTP %d", current.Status)
		}
		if len(current.Body) != model.SuperblockBytes {
			return werr.Newf(werr.Corrupt, "superblock is %d bytes, expected %d", len(current.Body), model.SuperblockBytes)
		}
		if current.ETag == "" {
			return werr.Newf(werr.Unsupported,
				"S3 endpoint did not return an ETag for the superblock; refusing an unconditional head update")
		}
		updated := append([]byte(nil), current.Body...)
		offset := index * model.SlotBytes
		copy(updated[offset:offset+model.SlotBytes], slot.Encode())
		if err := c.fenceLock(slot.Generation, slot.Commit); err != nil {
			return err
		}
		etag := current.ETag
		if _, ok, err := c.client.putConditional(s3SuperblockKey, updated, &etag, true); err != nil {
			return err
		} else if ok {
			return nil
		}
		c.client.note("conditional superblock update lost a race; retrying from a fresh read")
	}
	return werr.Newf(werr.Busy, "superblock conditional update kept losing to another writer")
}

func (c *s3Control) commitKey(generation uint64) string {
	return "commits/" + strconv.FormatUint(generation, 10) + ".commit"
}

func (c *s3Control) CreateCommit(generation uint64, data []byte) error {
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
	return werr.Newf(werr.Exists, "commit s3://%s/%s already exists with different bytes", c.client.config.Bucket, key)
}

func (c *s3Control) ReadCommit(generation uint64) (LoadedCommit, error) {
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
		return LoadedCommit{}, werr.Newf(werr.Corrupt, "cannot read s3://%s/%s", c.client.config.Bucket, key)
	case http.StatusForbidden:
		return LoadedCommit{}, werr.Newf(werr.Unauthorized, "S3 denied GET s3://%s/%s", c.client.config.Bucket, key)
	default:
		return LoadedCommit{}, werr.Newf(werr.Io, "S3 GET s3://%s/%s returned HTTP %d",
			c.client.config.Bucket, key, response.Status)
	}
}

func (c *s3Control) HasCommit(generation uint64) (bool, error) {
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
		return false, werr.Newf(werr.Unauthorized, "S3 denied HEAD s3://%s/%s", c.client.config.Bucket, key)
	default:
		return false, werr.Newf(werr.Io, "S3 HEAD s3://%s/%s returned HTTP %d",
			c.client.config.Bucket, key, response.Status)
	}
}

func (c *s3Control) ListCommitGenerations() ([]uint64, error) {
	objects, err := c.client.listPrefix("commits/")
	if err != nil {
		return nil, err
	}
	out := make([]uint64, 0, len(objects))
	for _, object := range objects {
		name := strings.TrimPrefix(object.Key, "commits/")
		if generation, ok := ParseCommitFilename(name); ok {
			out = append(out, generation)
		}
	}
	return out, nil
}

func (c *s3Control) ReadRecord(name string) ([]byte, bool, error) {
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
		return nil, false, werr.Newf(werr.Unauthorized, "S3 denied GET s3://%s/%s", c.client.config.Bucket, name)
	default:
		return nil, false, werr.Newf(werr.Io, "S3 GET s3://%s/%s returned HTTP %d",
			c.client.config.Bucket, name, response.Status)
	}
}

// ReadControl is the pack-plane view: record bytes and the content token.
func (c *s3Control) ReadControl(name string) ([]byte, string, bool, error) {
	data, present, err := c.ReadRecord(name)
	if err != nil || !present {
		return data, "", present, err
	}
	return data, ControlToken(data), true, nil
}

func (c *s3Control) WriteRecordNew(name string, data []byte) error {
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
	return werr.Newf(werr.Exists, "record s3://%s/%s already exists with different bytes", c.client.config.Bucket, name)
}

func (c *s3Control) WriteRecordReplace(name string, data []byte) error {
	return c.client.putReplace(name, data)
}

// CompareExchange is the token-based conditional write the pack catalog uses.
func (c *s3Control) CompareExchange(name string, expected *string, data []byte) (string, error) {
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

func (c *s3Control) DeleteRecord(name string) error {
	head, err := c.client.head(name)
	if err != nil {
		return err
	}
	switch head.Status {
	case http.StatusOK, http.StatusNoContent:
	case http.StatusNotFound:
		return werr.Newf(werr.NotFound, "control record s3://%s/%s does not exist", c.client.config.Bucket, name)
	default:
		return werr.Newf(werr.Io, "S3 HEAD s3://%s/%s returned HTTP %d", c.client.config.Bucket, name, head.Status)
	}
	response, err := c.client.delete(name)
	if err != nil {
		return err
	}
	if response.Status != http.StatusOK && response.Status != http.StatusNoContent && response.Status != http.StatusNotFound {
		return werr.Newf(werr.Io, "S3 DELETE s3://%s/%s returned HTTP %d", c.client.config.Bucket, name, response.Status)
	}
	return nil
}

// ListRecords returns the full relative keys directly under `prefix`.
func (c *s3Control) ListRecords(prefix string) ([]string, error) {
	normalized := strings.TrimSuffix(prefix, "/") + "/"
	objects, err := c.client.listPrefix(normalized)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(objects))
	for _, object := range objects {
		rest := strings.TrimPrefix(object.Key, normalized)
		if rest == "" || strings.Contains(rest, "/") {
			continue
		}
		out = append(out, object.Key)
	}
	return out, nil
}

func (c *s3Control) leaseNS() int64 {
	nanos := int64(c.client.config.LockLease / time.Nanosecond)
	if nanos <= 0 {
		return 1
	}
	return nanos
}

func (c *s3Control) publicationBudgetNS() int64 {
	budget := c.leaseNS() / 2
	if budget < 1 {
		return 1
	}
	return budget
}

func (c *s3Control) nextOwner() string {
	seq := c.client.counter.Add(1)
	return strconv.Itoa(os.Getpid()) + "-" + strconv.FormatUint(seq, 10) + "-" + strconv.FormatInt(nowNS(), 10)
}

func (c *s3Control) installLease(lease *s3LockLease) {
	c.client.lockMu.Lock()
	c.client.lease = lease
	c.client.lockMu.Unlock()
}

// AcquireWriterLock takes or reclaims the fenced lease. The refusal text is a
// fixed sentence on purpose: a live lock never discloses the holder.
func (c *s3Control) AcquireWriterLock() error {
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
			body := encodeS3Lock(owner, 1, 1, deadline, now, 0, "")
			etag, ok, err := c.client.putConditional("LOCK", []byte(body), nil, true)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			c.installLease(&s3LockLease{owner: owner, fence: 1, sequence: 1, deadlineNS: deadline, renewedNS: now, etag: etag})
			return nil
		case http.StatusOK:
			observed, ok := parseS3Lock(existing.Body)
			if !ok {
				return werr.Newf(werr.Busy,
					"store LOCK object is unreadable; refusing a writable open rather than guessing whether a writer holds it")
			}
			if observed.isLive(now) {
				c.client.note("writable open refused: the LOCK is live (owner " + observed.owner +
					" fence " + strconv.FormatUint(observed.fence, 10) + ", lease ends in " +
					strconv.FormatInt((observed.deadlineNS-now)/1_000_000, 10) + " ms)")
				return werr.Newf(werr.Busy, "store is locked by another S3 writer (live LOCK object)")
			}
			if observed.fence == ^uint64(0) {
				return werr.Newf(werr.LimitExceeded, "S3 fencing token would overflow u64")
			}
			fence := observed.fence + 1
			body := encodeS3Lock(owner, fence, 1, deadline, now, 0, "")
			if existing.ETag == "" {
				return werr.Newf(werr.Unsupported,
					"S3-compatible endpoint did not return an ETag for the writer lock; refusing a writable store because a fenced reclaim cannot be proven")
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
			c.client.note(verb + " S3 writer lock: fence " + strconv.FormatUint(observed.fence, 10) +
				" -> " + strconv.FormatUint(fence, 10))
			c.installLease(&s3LockLease{owner: owner, fence: fence, sequence: 1, deadlineNS: deadline, renewedNS: now, etag: newETag})
			return nil
		case http.StatusForbidden:
			return werr.Newf(werr.Unauthorized, "S3 denied GET s3://%s/LOCK", c.client.config.Bucket)
		default:
			return werr.Newf(werr.Io, "S3 LOCK read returned HTTP %d", existing.Status)
		}
	}
	return werr.Newf(werr.Busy, "could not acquire the S3 writer lock after four conditional attempts")
}

// VerifyWriteLease proves this handle may publish right now, renewing when one
// publication budget remains.
func (c *s3Control) VerifyWriteLease() error { return c.fenceLock(0, model.ZeroHash) }

// fenceLock is the conditional rewrite of LOCK that gates every publication.
func (c *s3Control) fenceLock(pendingGeneration uint64, pendingCommit model.Hash32) error {
	c.client.lockMu.Lock()
	defer c.client.lockMu.Unlock()
	lease := c.client.lease
	if lease == nil {
		return werr.Newf(werr.Busy, "S3 writer holds no lease; refusing to publish without a fenced lease")
	}
	now := nowNS()
	if now >= lease.deadlineNS {
		expired := (now - lease.deadlineNS) / 1_000_000
		observed := c.readLockRecordNoFail()
		return werr.Newf(werr.Busy,
			"S3 writer lease deadline passed %d ms ago (owner %s fence %d); publication refused before the head was touched%s",
			expired, lease.owner, lease.fence, describeObserved(observed, lease.owner, lease.fence))
	}
	renew := now+c.publicationBudgetNS() >= lease.deadlineNS
	deadline := lease.deadlineNS
	if renew {
		deadline = now + c.leaseNS()
	}
	sequence := lease.sequence + 1
	pendingText := ""
	if pendingGeneration != 0 {
		pendingText = pendingCommit.Hex()
	}
	body := encodeS3Lock(lease.owner, lease.fence, sequence, deadline, now, pendingGeneration, pendingText)
	etag := lease.etag
	newETag, ok, err := c.client.putConditional("LOCK", []byte(body), &etag, true)
	if err != nil {
		return err
	}
	if !ok {
		observed := c.readLockRecordNoFail()
		return werr.Newf(werr.Busy,
			"S3 writer lease was taken over: the conditional fence CAS for owner %s fence %d was refused, so the publication was abandoned without writing the head%s",
			lease.owner, lease.fence, describeObserved(observed, lease.owner, lease.fence))
	}
	lease.sequence = sequence
	lease.deadlineNS = deadline
	lease.renewedNS = now
	lease.etag = newETag
	return nil
}

func (c *s3Control) readLockRecordNoFail() *publishedLock {
	response, err := c.client.get("LOCK", 0, 0)
	if err != nil || response.Status != http.StatusOK {
		return nil
	}
	record, ok := parseS3Lock(response.Body)
	if !ok {
		return nil
	}
	return &record
}

// ReadLockRecord returns the published LOCK, read fresh. Read-only.
func (c *s3Control) ReadLockRecord() (*publishedLock, error) {
	response, err := c.client.get("LOCK", 0, 0)
	if err != nil {
		return nil, err
	}
	switch response.Status {
	case http.StatusOK:
		record, ok := parseS3Lock(response.Body)
		if !ok {
			return nil, werr.Newf(werr.Corrupt, "published LOCK record is unreadable")
		}
		return &record, nil
	case http.StatusNotFound:
		return nil, nil
	default:
		return nil, werr.Newf(werr.Io, "S3 LOCK read returned HTTP %d", response.Status)
	}
}

// ReleaseWriterLock publishes a content-addressed tombstone under a conditional
// write. It never deletes the lock after a read.
func (c *s3Control) ReleaseWriterLock() error {
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
	record, ok := parseS3Lock(observed.Body)
	if !ok {
		c.client.note("refusing to release an unreadable LOCK record")
		return nil
	}
	if record.owner != lease.owner || record.fence != lease.fence {
		c.client.note("refusing to release the S3 writer lock: it now names owner " + record.owner +
			" fence " + strconv.FormatUint(record.fence, 10) + " and this handle holds fence " +
			strconv.FormatUint(lease.fence, 10) + "; the conditional release was not attempted")
		return nil
	}
	if observed.ETag == "" {
		c.client.note("refusing to release the S3 writer lock: no ETag to condition on")
		return nil
	}
	tombstone := encodeS3Released(lease.owner, lease.fence, lease.sequence+1, nowNS(), sha256HexBytes(observed.Body))
	etag := observed.ETag
	if _, ok, err := c.client.putConditional("LOCK", []byte(tombstone), &etag, true); err != nil {
		c.client.note("conditional release of the S3 writer lock failed, nothing was deleted: " + err.Error())
		return nil
	} else if !ok {
		c.client.note("refusing to release the S3 writer lock: it was replaced between the read and the conditional tombstone (this writer held fence " +
			strconv.FormatUint(lease.fence, 10) + "); the successor's lock is intact")
		return nil
	}
	c.client.note("released the S3 writer lock with a conditional tombstone (fence " +
		strconv.FormatUint(lease.fence, 10) + ")")
	return nil
}

// probeConditionalWrites proves the endpoint honours both conditional forms
// the store depends on and measures the If-Match form in use.
func (c *s3Control) probeConditionalWrites() error {
	c.client.probeMu.Lock()
	defer c.client.probeMu.Unlock()
	if c.client.probed {
		return c.client.probeErr
	}
	err := c.runConditionalProbe()
	c.client.probed = true
	c.client.probeErr = err
	if err == nil {
		c.client.note("S3 conditional-write probe passed; If-Match form is " + c.client.headIfMatchForm().String())
	}
	return err
}

func (c *s3Control) runConditionalProbe() error {
	key := probeRelPath("conditional")
	cleanup := func() { _, _ = c.client.delete(key) }

	if _, ok, err := c.client.putConditional(key, []byte("probe-one"), nil, false); err != nil {
		return err
	} else if !ok {
		cleanup()
		return werr.Newf(werr.Io, "S3 conditional probe: unexpected existing key")
	}
	if _, ok, err := c.client.putConditional(key, []byte("probe-two"), nil, false); err != nil {
		cleanup()
		return err
	} else if ok {
		cleanup()
		return werr.Newf(werr.Unsupported,
			"S3-compatible endpoint ignored If-None-Match: *; refusing a writable store because create-once publication cannot be guaranteed")
	}
	current, err := c.client.get(key, 0, 0)
	if err != nil {
		cleanup()
		return err
	}
	if current.Status != http.StatusOK || string(current.Body) != "probe-one" {
		cleanup()
		return werr.Newf(werr.Io, "S3 conditional probe: first writer's bytes are not readable")
	}
	if current.ETag == "" {
		cleanup()
		return werr.Newf(werr.Unsupported,
			"S3-compatible endpoint did not return an ETag; refusing a writable store")
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
				"S3-compatible endpoint rejected a matching If-Match in both forms (as returned %q and dequoted %q); refusing a writable store because head publication cannot be proven",
				etag, dequoted)
		}
	} else {
		cleanup()
		return werr.Newf(werr.Io, "S3 conditional probe: a matching If-Match was unexpectedly rejected")
	}
	before, err := c.client.get(key, 0, 0)
	if err != nil {
		cleanup()
		return err
	}
	if before.Status != http.StatusOK || string(before.Body) != "probe-three" {
		cleanup()
		return werr.Newf(werr.Io, "S3 conditional probe: the matching conditional write is not readable")
	}
	if _, ok, err := c.client.putConditionalHeader(key, []byte("probe-four"), matching, false); err != nil {
		cleanup()
		return err
	} else if ok {
		cleanup()
		return werr.Newf(werr.Unsupported,
			"S3-compatible endpoint ignored If-Match; refusing a writable store because head publication could lose a race silently")
	}
	after, err := c.client.get(key, 0, 0)
	if err != nil {
		cleanup()
		return err
	}
	if after.Status != http.StatusOK || string(after.Body) != "probe-three" {
		cleanup()
		return werr.Newf(werr.Io, "S3 conditional probe: a refused stale If-Match changed the object")
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

func (c *s3Control) probe() (CommitProbe, error) {
	probe := CommitProbe{Backend: "s3", TokenKind: "content-token"}
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
			"commit plane `s3` failed its capability probe (create_ok=%t, matching_compare_exchange_ok=%t)",
			probe.CreateOK, probe.MatchingCompareExchangeOK)
	}
	if !probe.StaleCompareExchangeRejected {
		return probe, werr.Newf(werr.Unsupported,
			"commit plane `s3` accepted a stale compare-and-swap token; refusing a writable store")
	}
	probe.Detail = "create-once CAS, matching CAS, and stale-token rejection all observed on a private control record; durability is the provider acknowledgement and is not proved here"
	return probe, nil
}
