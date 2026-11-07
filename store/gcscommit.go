// GCS control volume: FORMAT, the fenced writer lock, the two-slot superblock,
// commit records, refs, and mutable store records over the GCS JSON API.
//
// # Protocol mapping
//
//   - FORMAT, commit records, snapshot pointers: upload with
//     `ifGenerationMatch=0`. Identical bytes under an existing key are
//     idempotent; different bytes are `Exists`.
//   - superblock: one 8192-byte object holding the same two 4096-byte slots as
//     the local layout. Updating one slot is a whole-object read-modify-write
//     conditioned on the generation observed at read. A lost race is HTTP 412
//     and is retried from a fresh read; it never overwrites a head it did not
//     read.
//   - mutable records (quota, access counters, the pack catalog root): the same
//     generation-conditioned replace, creating the key once when it is absent.
//   - writer lock: a `LOCK` object carrying an owner, a monotonic fencing token,
//     a bounded lease deadline, and the head being published. The record schema
//     is `weftfs-gcs-lock v3`.
//
// # Fenced single-writer protocol
//
// Every head publication performs one conditional upload of `LOCK` immediately
// before the superblock slot CAS. That upload is
// `ifGenerationMatch=<the generation this handle last published>`, so it
// succeeds only while the object still holds this writer's fencing token: a
// successor that reclaimed the lease rewrote the object, which changes its
// generation, so the stale writer gets 412 and its publication fails `Busy`
// without touching the head. The same write names the head
// (`pending_generation`, `pending_commit`, `pending_commit_len`) and renews the
// lease when one publication budget remains. A writer stops publishing as soon
// as its own deadline passes, even if nobody took over.
//
// Release is never an unconditional delete after a read. It is a
// content-addressed tombstone uploaded with the generation the writer observed,
// so a successor's lock can never be replaced by the writer it replaced. A
// tombstone keeps the fencing token monotonic; deleting the object would reset
// it.
//
// This is two conditional writes on two objects, not one atomic operation: GCS
// has no primitive that fences and publishes a head atomically. The fence still
// makes a stale publication impossible, because a successor cannot take the
// lease without rewriting LOCK, and the writer then fails its own fence.
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

// gcsSuperblockKey is the two-slot head object.
const gcsSuperblockKey = "superblock"

type gcsControl struct {
	client *gcsClient
}

func newGCSControl(client *gcsClient) *gcsControl {
	return &gcsControl{client: client}
}

func (c *gcsControl) Label() string { return "gcs" }

func (c *gcsControl) Root() string { return "gcs://" + c.client.config.Bucket }

func (c *gcsControl) Capabilities() CommitCapabilities {
	return CommitCapabilities{
		Backend:           "gcs",
		ConditionalUpdate: true,
		AtomicPublish:     true,
		DurableFSync:      true,
		MaxControlBytes:   gcsMaxObjectBytes,
		Consistency: "single-endpoint GCS-compatible store; read-after-write and " +
			"list-after-write for published keys; generation preconditions " +
			"(ifGenerationMatch) are required and measured at writable open; a " +
			"monotonic fencing token is carried in the LOCK object",
		Publication: "GCS JSON API upload with ifGenerationMatch=0 (create-once); " +
			"superblock slot via read + ifGenerationMatch upload; every head " +
			"publication is preceded by one conditional upload of LOCK that " +
			"carries the fencing token and names the head; release is a " +
			"conditional tombstone",
	}
}

func (c *gcsControl) Diagnostics() []string { return c.client.diagnostics() }

// GCSStats returns the HTTP counters of the shared GCS client. Diagnostic
// evidence only, never a correctness input.
func (c *gcsControl) GCSStats() GCSStatsSnapshot {
	return GCSStatsSnapshot{
		Requests:            c.client.stats.requests.Load(),
		Reads:               c.client.stats.reads.Load(),
		RangeReads:          c.client.stats.rangeReads.Load(),
		BytesRead:           c.client.stats.bytesRead.Load(),
		Writes:              c.client.stats.writes.Load(),
		BytesWritten:        c.client.stats.bytesWritten.Load(),
		ConditionalConflict: c.client.stats.conflicts.Load(),
	}
}

func (c *gcsControl) EnsureLayout() error { return c.client.ensureBucket() }

// CleanTmp removes leftover probe keys. The writer lock is held here, so no
// other writer can be using them.
func (c *gcsControl) CleanTmp(graceSecs uint64) error {
	objects, err := c.client.listObjects("tmp/")
	if err != nil {
		return err
	}
	for _, object := range objects {
		if err := c.client.deleteObject(object.Name); err != nil {
			return err
		}
	}
	return nil
}

// Sync is a no-op: a successful upload is acknowledged by the provider.
func (c *gcsControl) Sync() error { return nil }

func (c *gcsControl) Close() error {
	err := c.ReleaseWriterLock()
	c.client.http.CloseIdleConnections()
	return err
}

func (c *gcsControl) ReadFormat() ([]byte, error) {
	response, err := c.client.media("FORMAT", nil)
	if err != nil {
		return nil, err
	}
	switch response.Status {
	case http.StatusOK:
		return response.Body, nil
	case http.StatusNotFound:
		return nil, werr.Newf(werr.Corrupt, "cannot read FORMAT: gcs://%s/FORMAT does not exist", c.client.config.Bucket)
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, werr.Newf(werr.Unauthorized, "GCS denied reading gcs://%s/FORMAT", c.client.config.Bucket)
	default:
		return nil, werr.Newf(werr.Io, "GCS read FORMAT returned HTTP %d", response.Status)
	}
}

func (c *gcsControl) CreateFormat() error {
	if err := c.client.ensureBucket(); err != nil {
		return err
	}
	body := []byte(model.FormatContents)
	if _, ok, err := c.client.upload("FORMAT", body, gcsMissing()); err != nil {
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
	return werr.Newf(werr.Exists, "a WeftFS store already exists at gcs://%s", c.client.config.Bucket)
}

func (c *gcsControl) ReadSuperblock() (SuperblockView, error) {
	response, err := c.client.media(gcsSuperblockKey, nil)
	if err != nil {
		return SuperblockView{}, err
	}
	switch response.Status {
	case http.StatusOK:
		return decodeSuperblockView(response.Body)
	case http.StatusNotFound:
		return SuperblockView{}, werr.Newf(werr.Corrupt,
			"cannot read superblock gcs://%s/superblock", c.client.config.Bucket)
	case http.StatusUnauthorized, http.StatusForbidden:
		return SuperblockView{}, werr.Newf(werr.Unauthorized, "GCS denied reading gcs://%s/superblock", c.client.config.Bucket)
	default:
		return SuperblockView{}, werr.Newf(werr.Io, "GCS read superblock returned HTTP %d", response.Status)
	}
}

func (c *gcsControl) CreateSuperblock() error {
	body := make([]byte, model.SuperblockBytes)
	if _, ok, err := c.client.upload(gcsSuperblockKey, body, gcsMissing()); err != nil {
		return err
	} else if ok {
		return nil
	}
	return werr.Newf(werr.Exists, "superblock already exists at gcs://%s/superblock", c.client.config.Bucket)
}

// PublishSuperblockSlot patches one slot and publishes it with a single
// generation-conditioned upload. The writer fence is refreshed immediately
// before each attempt, so a stale writer cannot reach the head at all.
func (c *gcsControl) PublishSuperblockSlot(slot SuperblockSlot, index int) error {
	if index != 0 && index != 1 {
		return werr.Newf(werr.InvalidArgument, "superblock slot index must be 0 or 1")
	}
	for attempt := 0; attempt < 8; attempt++ {
		current, generation, present, err := c.client.readWithGeneration(gcsSuperblockKey)
		if err != nil {
			return err
		}
		if !present {
			return werr.Newf(werr.Io, "GCS read-modify-write superblock is absent")
		}
		if len(current) != model.SuperblockBytes {
			return werr.Newf(werr.Corrupt, "superblock is %d bytes, expected %d", len(current), model.SuperblockBytes)
		}
		updated := append([]byte(nil), current...)
		offset := index * model.SlotBytes
		copy(updated[offset:offset+model.SlotBytes], slot.Encode())
		if err := c.fenceLock(slot.Generation, slot.Commit, slot.CommitLen); err != nil {
			return err
		}
		if _, ok, err := c.client.upload(gcsSuperblockKey, updated, gcsMatches(generation)); err != nil {
			return err
		} else if ok {
			return nil
		}
		c.client.note("conditional superblock update lost a race; retrying from a fresh read")
	}
	return werr.Newf(werr.Busy, "superblock conditional update kept losing to another writer")
}

// PublishFencedHead publishes a head through the LOCK record in one conditional
// upload that carries both the fence and the head. It is the publication point
// for an object-store commit plane; the superblock is only a cache afterwards.
func (c *gcsControl) PublishFencedHead(generation uint64, commit model.Hash32, commitLen uint64) (bool, error) {
	if err := c.fenceLock(generation, commit, commitLen); err != nil {
		return true, err
	}
	return true, nil
}

// AttestedHead returns the head the published LOCK record names.
func (c *gcsControl) AttestedHead() (uint64, model.Hash32, uint64, bool, error) {
	response, err := c.client.media("LOCK", nil)
	if err != nil {
		return 0, model.Hash32{}, 0, false, err
	}
	if response.Status == http.StatusNotFound {
		return 0, model.Hash32{}, 0, false, nil
	}
	if response.Status != http.StatusOK {
		return 0, model.Hash32{}, 0, false,
			werr.Newf(werr.Io, "GCS LOCK read returned HTTP %d", response.Status)
	}
	record, ok := parseGCSLock(response.Body)
	if !ok {
		return 0, model.Hash32{}, 0, false, nil
	}
	generation, commit, ok := record.attestedHead()
	if !ok {
		return 0, model.Hash32{}, 0, false, nil
	}
	return generation, commit, record.pendingCommitLen, true, nil
}

// RefreshHeadCache keeps the two-slot superblock cache current after a
// lock-record publication. It never moves the cache backwards, and a lost race
// is retried from a fresh read. A failure is a diagnostic, never a publication
// failure (the LOCK write is the publication).
func (c *gcsControl) RefreshHeadCache(generation uint64, commit model.Hash32, commitLen uint64, timestampNS int64) error {
	if commitLen == 0 {
		c.client.note("superblock cache not refreshed: the lock record does not attest the commit length")
		return nil
	}
	for attempt := 0; attempt < 8; attempt++ {
		current, token, present, err := c.client.readWithGeneration(gcsSuperblockKey)
		if err != nil {
			return err
		}
		if !present {
			return werr.Newf(werr.Corrupt, "superblock cache is missing; the store layout is incomplete")
		}
		if len(current) != model.SuperblockBytes {
			return werr.Newf(werr.Corrupt, "superblock is %d bytes, expected %d", len(current), model.SuperblockBytes)
		}
		view, err := decodeSuperblockView(current)
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
		updated := append([]byte(nil), current...)
		slot := SuperblockSlot{Generation: generation, Commit: commit, CommitLen: commitLen, TimestampNS: timestampNS}
		offset := int(generation%2) * model.SlotBytes
		copy(updated[offset:offset+model.SlotBytes], slot.Encode())
		if _, ok, err := c.client.upload(gcsSuperblockKey, updated, gcsMatches(token)); err != nil {
			return err
		} else if ok {
			return nil
		}
		c.client.note("conditional superblock cache update lost a race; retrying from a fresh read")
	}
	return werr.Newf(werr.Busy, "superblock cache update kept losing to another writer")
}

func (c *gcsControl) commitKey(generation uint64) string {
	return "commits/" + strconv.FormatUint(generation, 10) + ".commit"
}

func (c *gcsControl) CreateCommit(generation uint64, data []byte) error {
	key := c.commitKey(generation)
	if _, ok, err := c.client.upload(key, data, gcsMissing()); err != nil {
		return err
	} else if ok {
		return nil
	}
	existing, err := c.client.media(key, nil)
	if err != nil {
		return err
	}
	if existing.Status == http.StatusOK && overlayBytesSame(existing.Body, data) {
		return nil
	}
	return werr.Newf(werr.Exists, "commit gcs://%s/%s already exists with different bytes", c.client.config.Bucket, key)
}

func (c *gcsControl) ReadCommit(generation uint64) (LoadedCommit, error) {
	key := c.commitKey(generation)
	response, err := c.client.media(key, nil)
	if err != nil {
		return LoadedCommit{}, err
	}
	switch response.Status {
	case http.StatusOK:
		expected := generation
		return ParseCommitBytes(response.Body, &expected)
	case http.StatusNotFound:
		return LoadedCommit{}, werr.Newf(werr.Corrupt, "cannot read gcs://%s/%s", c.client.config.Bucket, key)
	case http.StatusUnauthorized, http.StatusForbidden:
		return LoadedCommit{}, werr.Newf(werr.Unauthorized, "GCS denied reading gcs://%s/%s", c.client.config.Bucket, key)
	default:
		return LoadedCommit{}, werr.Newf(werr.Io, "GCS read gcs://%s/%s returned HTTP %d",
			c.client.config.Bucket, key, response.Status)
	}
}

func (c *gcsControl) HasCommit(generation uint64) (bool, error) {
	meta, err := c.client.metadata(c.commitKey(generation))
	if err != nil {
		return false, err
	}
	return meta != nil, nil
}

func (c *gcsControl) ListCommitGenerations() ([]uint64, error) {
	objects, err := c.client.listObjects("commits/")
	if err != nil {
		return nil, err
	}
	out := make([]uint64, 0, len(objects))
	for _, object := range objects {
		name := strings.TrimPrefix(object.Name, "commits/")
		if generation, ok := ParseCommitFilename(name); ok {
			out = append(out, generation)
		}
	}
	return out, nil
}

func (c *gcsControl) ReadRecord(name string) ([]byte, bool, error) {
	response, err := c.client.media(name, nil)
	if err != nil {
		return nil, false, err
	}
	switch response.Status {
	case http.StatusOK:
		return response.Body, true, nil
	case http.StatusNotFound:
		return nil, false, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, false, werr.Newf(werr.Unauthorized, "GCS denied reading gcs://%s/%s", c.client.config.Bucket, name)
	default:
		return nil, false, werr.Newf(werr.Io, "GCS read gcs://%s/%s returned HTTP %d",
			c.client.config.Bucket, name, response.Status)
	}
}

// ReadControl is the pack-plane view: record bytes and the content token.
func (c *gcsControl) ReadControl(name string) ([]byte, string, bool, error) {
	data, present, err := c.ReadRecord(name)
	if err != nil || !present {
		return data, "", present, err
	}
	return data, ControlToken(data), true, nil
}

func (c *gcsControl) WriteRecordNew(name string, data []byte) error {
	if _, ok, err := c.client.upload(name, data, gcsMissing()); err != nil {
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
	return werr.Newf(werr.Exists, "record gcs://%s/%s already exists with different bytes", c.client.config.Bucket, name)
}

// WriteRecordReplace is an unconditional replacement conditioned on the
// observed generation so a concurrent update is retried rather than clobbered.
func (c *gcsControl) WriteRecordReplace(name string, data []byte) error {
	for attempt := 0; attempt < 8; attempt++ {
		_, generation, present, err := c.client.readWithGeneration(name)
		if err != nil {
			return err
		}
		precondition := gcsMissing()
		if present {
			precondition = gcsMatches(generation)
		}
		if _, ok, err := c.client.upload(name, data, precondition); err != nil {
			return err
		} else if ok {
			return nil
		}
	}
	return werr.Newf(werr.Busy, "conditional replacement of gcs://%s/%s kept losing", c.client.config.Bucket, name)
}

// CompareExchange is the token-based conditional write the pack catalog uses.
func (c *gcsControl) CompareExchange(name string, expected *string, data []byte) (string, error) {
	_, generation, present, err := c.client.readWithGeneration(name)
	if err != nil {
		return "", err
	}
	if expected == nil {
		if present {
			return "", werr.Newf(werr.Busy, "control record %s appeared before the compare-and-swap", name)
		}
	} else {
		_, token, observed, err := c.ReadControl(name)
		if err != nil {
			return "", err
		}
		if !observed || token != *expected {
			return "", werr.Newf(werr.Busy, "control record %s changed since it was read; compare-and-swap refused", name)
		}
	}
	precondition := gcsMissing()
	if present {
		precondition = gcsMatches(generation)
	}
	if _, ok, err := c.client.upload(name, data, precondition); err != nil {
		return "", err
	} else if !ok {
		return "", werr.Newf(werr.Busy, "control record %s changed during the compare-and-swap", name)
	}
	return ControlToken(data), nil
}

func (c *gcsControl) DeleteRecord(name string) error {
	meta, err := c.client.metadata(name)
	if err != nil {
		return err
	}
	if meta == nil {
		return werr.Newf(werr.NotFound, "control record gcs://%s/%s does not exist", c.client.config.Bucket, name)
	}
	return c.client.deleteObject(name)
}

// ListRecords returns the full relative keys directly under `prefix`.
func (c *gcsControl) ListRecords(prefix string) ([]string, error) {
	normalized := strings.TrimSuffix(prefix, "/") + "/"
	objects, err := c.client.listObjects(normalized)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(objects))
	for _, object := range objects {
		rest := strings.TrimPrefix(object.Name, normalized)
		if rest == "" || strings.Contains(rest, "/") {
			continue
		}
		out = append(out, object.Name)
	}
	return out, nil
}

func (c *gcsControl) leaseNS() int64 {
	nanos := int64(c.client.config.LockLease / time.Nanosecond)
	if nanos <= 0 {
		return 1
	}
	return nanos
}

func (c *gcsControl) publicationBudgetNS() int64 {
	budget := c.leaseNS() / 2
	if budget < 1 {
		return 1
	}
	return budget
}

func (c *gcsControl) nextOwner() string {
	seq := c.client.counter.Add(1)
	return strconv.Itoa(os.Getpid()) + "-" + strconv.FormatUint(seq, 10) + "-" + strconv.FormatInt(nowNS(), 10)
}

func (c *gcsControl) installLease(lease *gcsLockLease) {
	c.client.lockMu.Lock()
	c.client.lease = lease
	c.client.lockMu.Unlock()
}

// AcquireWriterLock takes or reclaims the fenced lease. The refusal text is a
// fixed sentence on purpose: a live lock never discloses the holder.
func (c *gcsControl) AcquireWriterLock() error {
	if err := c.probeConditionalWrites(); err != nil {
		return err
	}
	now := nowNS()
	owner := c.nextOwner()
	deadline := now + c.leaseNS()
	for attempt := 0; attempt < 4; attempt++ {
		body, generation, present, err := c.client.readWithGeneration("LOCK")
		if err != nil {
			return err
		}
		if !present {
			headGen, headCommit, headLen, headOK := c.superblockHead()
			record := encodeGCSLockHead(owner, 1, 1, deadline, now, headGen, headCommit, headLen, headOK)
			newGeneration, ok, err := c.client.upload("LOCK", []byte(record), gcsMissing())
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			c.installLease(&gcsLockLease{
				owner: owner, fence: 1, sequence: 1, deadlineNS: deadline, renewedNS: now,
				generation: newGeneration, headGeneration: headGen, headCommit: headCommit, headCommitLen: headLen,
			})
			return nil
		}
		observed, ok := parseGCSLock(body)
		if !ok {
			return werr.Newf(werr.Busy,
				"store LOCK object is unreadable; refusing a writable open rather than guessing whether a writer holds it")
		}
		if observed.isLive(now) {
			c.client.note("writable open refused: the LOCK is live (owner " + observed.owner +
				" fence " + strconv.FormatUint(observed.fence, 10) + ", lease ends in " +
				strconv.FormatInt((observed.deadlineNS-now)/1_000_000, 10) + " ms)")
			return werr.Newf(werr.Busy, "store is locked by another GCS writer (live LOCK object)")
		}
		if observed.fence == ^uint64(0) {
			return werr.Newf(werr.LimitExceeded, "GCS fencing token would overflow u64")
		}
		fence := observed.fence + 1
		headGen, headCommit, headLen := observed.pendingGeneration, observed.pendingCommit, observed.pendingCommitLen
		headOK := headGen != 0 && headCommit != "" && headCommit != "-"
		if !headOK {
			headGen, headCommit, headLen, headOK = c.superblockHead()
		}
		record := encodeGCSLockHead(owner, fence, 1, deadline, now, headGen, headCommit, headLen, headOK)
		newGeneration, ok, err := c.client.upload("LOCK", []byte(record), gcsMatches(generation))
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
		c.client.note(verb + " GCS writer lock: fence " + strconv.FormatUint(observed.fence, 10) +
			" -> " + strconv.FormatUint(fence, 10))
		if observed.schemaVersion < 3 {
			c.client.note("upgraded the GCS writer lock record to v3 (single conditional write; the head it attests is carried forward)")
		}
		c.installLease(&gcsLockLease{
			owner: owner, fence: fence, sequence: 1, deadlineNS: deadline, renewedNS: now,
			generation: newGeneration, headGeneration: headGen, headCommit: headCommit, headCommitLen: headLen,
		})
		return nil
	}
	return werr.Newf(werr.Busy, "could not acquire the GCS writer lock after four conditional attempts")
}

// VerifyWriteLease proves this handle may publish right now, renewing when one
// publication budget remains. The conditional upload carries forward the head
// this handle last published, so a pre-publication fence never erases the
// record's attestation.
func (c *gcsControl) VerifyWriteLease() error { return c.fenceLock(0, model.ZeroHash, 0) }

// CheckLeaseDeadline is a local own-deadline check: no network write and no
// renewal. It refuses before a commit record is written, so a writer suspended
// past its own deadline leaves no unpublished commit tail.
func (c *gcsControl) CheckLeaseDeadline() error {
	c.client.lockMu.Lock()
	lease := c.client.lease
	c.client.lockMu.Unlock()
	if lease == nil {
		return werr.Newf(werr.Busy, "GCS writer holds no lease; refusing to publish without a fenced lease")
	}
	now := nowNS()
	if now >= lease.deadlineNS {
		expired := (now - lease.deadlineNS) / 1_000_000
		observed := c.readLockRecordNoFail()
		return werr.Newf(werr.Busy,
			"GCS writer lease deadline passed %d ms ago (owner %s fence %d); publication refused before the head was touched%s",
			expired, lease.owner, lease.fence, describeObserved(observed, lease.owner, lease.fence))
	}
	return nil
}

// fenceLock is the conditional rewrite of LOCK that gates every publication.
// With `pendingGeneration != 0` it is also the publication point: the same
// generation-conditioned upload carries the fence and the new head.
func (c *gcsControl) fenceLock(pendingGeneration uint64, pendingCommit model.Hash32, pendingCommitLen uint64) error {
	c.client.lockMu.Lock()
	defer c.client.lockMu.Unlock()
	lease := c.client.lease
	if lease == nil {
		return werr.Newf(werr.Busy, "GCS writer holds no lease; refusing to publish without a fenced lease")
	}
	now := nowNS()
	if now >= lease.deadlineNS {
		expired := (now - lease.deadlineNS) / 1_000_000
		observed := c.readLockRecordNoFail()
		return werr.Newf(werr.Busy,
			"GCS writer lease deadline passed %d ms ago (owner %s fence %d); publication refused before the head was touched%s",
			expired, lease.owner, lease.fence, describeObserved(observed, lease.owner, lease.fence))
	}
	renew := now+c.publicationBudgetNS() >= lease.deadlineNS
	deadline := lease.deadlineNS
	if renew {
		deadline = now + c.leaseNS()
	}
	sequence := lease.sequence + 1
	headGeneration, headCommit, headCommitLen := lease.headGeneration, lease.headCommit, lease.headCommitLen
	if pendingGeneration != 0 {
		headGeneration, headCommit, headCommitLen = pendingGeneration, pendingCommit.Hex(), pendingCommitLen
	}
	body := encodeGCSLock(lease.owner, lease.fence, sequence, deadline, now, headGeneration, headCommit, headCommitLen)
	newGeneration, ok, err := c.client.upload("LOCK", []byte(body), gcsMatches(lease.generation))
	if err != nil {
		return err
	}
	if !ok {
		observed := c.readLockRecordNoFail()
		return werr.Newf(werr.Busy,
			"GCS writer lease was taken over: the conditional fence CAS for owner %s fence %d was refused, so the publication was abandoned without writing the head%s",
			lease.owner, lease.fence, describeObserved(observed, lease.owner, lease.fence))
	}
	lease.sequence = sequence
	lease.deadlineNS = deadline
	lease.renewedNS = now
	lease.generation = newGeneration
	lease.headGeneration = headGeneration
	lease.headCommit = headCommit
	lease.headCommitLen = headCommitLen
	return nil
}

// superblockHead reads the head the two-slot cache attests. Used only to carry
// a head forward when the LOCK record does not name one.
func (c *gcsControl) superblockHead() (uint64, string, uint64, bool) {
	body, _, present, err := c.client.readWithGeneration(gcsSuperblockKey)
	if err != nil || !present {
		return 0, "", 0, false
	}
	view, err := decodeSuperblockView(body)
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

func encodeGCSLock(owner string, fence, sequence uint64, deadlineNS, renewedNS int64, pendingGeneration uint64, pendingCommit string, pendingCommitLen uint64) string {
	return encodeFenceLock(gcsFenceSchemas, owner, fence, sequence, deadlineNS, renewedNS, pendingGeneration, pendingCommit, pendingCommitLen)
}

func encodeGCSReleased(owner string, fence, sequence uint64, releasedNS int64, releasedFrom string, pendingGeneration uint64, pendingCommit string, pendingCommitLen uint64) string {
	return encodeFenceReleased(gcsFenceSchemas, owner, fence, sequence, releasedNS, releasedFrom, pendingGeneration, pendingCommit, pendingCommitLen)
}

func parseGCSLock(bytes []byte) (publishedLock, bool) {
	return parseFenceLock(bytes, gcsFenceSchemas)
}

func encodeGCSLockHead(owner string, fence, sequence uint64, deadlineNS, renewedNS int64, generation uint64, commit string, commitLen uint64, ok bool) string {
	if !ok {
		return encodeGCSLock(owner, fence, sequence, deadlineNS, renewedNS, 0, "", 0)
	}
	return encodeGCSLock(owner, fence, sequence, deadlineNS, renewedNS, generation, commit, commitLen)
}

func (c *gcsControl) readLockRecordNoFail() *publishedLock {
	response, err := c.client.media("LOCK", nil)
	if err != nil || response.Status != http.StatusOK {
		return nil
	}
	record, ok := parseGCSLock(response.Body)
	if !ok {
		return nil
	}
	return &record
}

// ReadLockRecord returns the published LOCK, read fresh. Read-only.
func (c *gcsControl) ReadLockRecord() (*publishedLock, error) {
	response, err := c.client.media("LOCK", nil)
	if err != nil {
		return nil, err
	}
	switch response.Status {
	case http.StatusOK:
		record, ok := parseGCSLock(response.Body)
		if !ok {
			return nil, werr.Newf(werr.Corrupt, "published LOCK record is unreadable")
		}
		return &record, nil
	case http.StatusNotFound:
		return nil, nil
	default:
		return nil, werr.Newf(werr.Io, "GCS LOCK read returned HTTP %d", response.Status)
	}
}

// ReleaseWriterLock publishes a content-addressed tombstone conditioned on the
// generation this writer observed. It never deletes the lock after a read.
func (c *gcsControl) ReleaseWriterLock() error {
	c.client.lockMu.Lock()
	lease := c.client.lease
	c.client.lease = nil
	c.client.lockMu.Unlock()
	if lease == nil {
		return nil
	}
	body, generation, present, err := c.client.readWithGeneration("LOCK")
	if err != nil {
		c.client.note("could not read LOCK to release it: " + err.Error())
		return nil
	}
	if !present {
		return nil
	}
	record, ok := parseGCSLock(body)
	if !ok {
		c.client.note("refusing to release an unreadable LOCK record")
		return nil
	}
	if record.owner != lease.owner || record.fence != lease.fence {
		c.client.note("refusing to release the GCS writer lock: it now names owner " + record.owner +
			" fence " + strconv.FormatUint(record.fence, 10) + " and this handle holds fence " +
			strconv.FormatUint(lease.fence, 10) + "; the conditional release was not attempted")
		return nil
	}
	headGeneration, headCommit, headCommitLen := record.pendingGeneration, record.pendingCommit, record.pendingCommitLen
	if headGeneration == 0 || headCommit == "-" {
		headGeneration, headCommit, headCommitLen = lease.headGeneration, lease.headCommit, lease.headCommitLen
	}
	tombstone := encodeGCSReleased(lease.owner, lease.fence, lease.sequence+1, nowNS(),
		sha256HexBytes(body), headGeneration, headCommit, headCommitLen)
	if _, ok, err := c.client.upload("LOCK", []byte(tombstone), gcsMatches(generation)); err != nil {
		c.client.note("conditional release of the GCS writer lock failed, nothing was deleted: " + err.Error())
		return nil
	} else if !ok {
		c.client.note("refusing to release the GCS writer lock: it was replaced between the read and the conditional tombstone (this writer held fence " +
			strconv.FormatUint(lease.fence, 10) + "); the successor's lock is intact")
		return nil
	}
	c.client.note("released the GCS writer lock with a conditional tombstone (fence " +
		strconv.FormatUint(lease.fence, 10) + ")")
	return nil
}

// probeConditionalWrites proves the endpoint honours both generation
// preconditions the store depends on.
func (c *gcsControl) probeConditionalWrites() error {
	return c.client.probeGenerationPreconditions()
}

func (c *gcsControl) probe() (CommitProbe, error) {
	probe := CommitProbe{Backend: "gcs", TokenKind: "content-token"}
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
			"commit plane `gcs` failed its capability probe (create_ok=%t, matching_compare_exchange_ok=%t)",
			probe.CreateOK, probe.MatchingCompareExchangeOK)
	}
	if !probe.StaleCompareExchangeRejected {
		return probe, werr.Newf(werr.Unsupported,
			"commit plane `gcs` accepted a stale compare-and-swap token; refusing a writable store")
	}
	probe.Detail = "create-once CAS, matching CAS, and stale-token rejection all observed on a private control record; durability is the provider acknowledgement and is not proved here"
	return probe, nil
}
