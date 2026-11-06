// Advisory read-access counters (Go parity with src/access.rs).
//
// One counter per object, bounded, persisted as `access/counts.v1` (snapshot)
// plus `access/journal.v1` (epoch-tagged deltas). The snapshot is rebuildable
// from the journal; deleting both only resets counters. They never affect
// exactness, commits, verification, GC, or any frozen format.
package store

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/infinityabundance/WeftCodec-Go/hash"
	"github.com/infinityabundance/WeftFS-Go/model"
)

const (
	accessSnapshotMagic  = "WFA1"
	accessJournalMagic   = "WFAJ"
	accessFormatVersion  = 1
	AccessDomain         = "weft/access/v1"
	MaxTrackedObjects    = 1_000_000
	MaxJournalRecords    = 8192
	CompactAfterRecords  = 2048
	FlushEveryReads      = 256
	accessRecordBytes    = 40
	accessSnapshotHeader = 16
)

type accessCounts struct {
	mu            sync.Mutex
	counts        map[model.Hash32]uint64
	journal       []byte
	epoch         uint64
	pending       map[model.Hash32]uint64
	pendingReads  uint64
	notes         []string
	boundedOut    bool
	forceCompact  bool
	loadedFromDir string
}

func newAccessCounts() *accessCounts {
	return &accessCounts{
		counts:  map[model.Hash32]uint64{},
		journal: accessJournalHeader(0),
		pending: map[model.Hash32]uint64{},
	}
}

func accessSnapshotHeaderBytes(epoch uint64) []byte {
	out := make([]byte, accessSnapshotHeader)
	copy(out[0:4], accessSnapshotMagic)
	binary.LittleEndian.PutUint32(out[4:8], accessFormatVersion)
	binary.LittleEndian.PutUint64(out[8:16], epoch)
	return out
}

func accessJournalHeader(epoch uint64) []byte {
	out := make([]byte, accessSnapshotHeader)
	copy(out[0:4], accessJournalMagic)
	binary.LittleEndian.PutUint32(out[4:8], accessFormatVersion)
	binary.LittleEndian.PutUint64(out[8:16], epoch)
	return out
}

func encodeAccessSnapshot(counts map[model.Hash32]uint64, epoch uint64) []byte {
	out := accessSnapshotHeaderBytes(epoch)
	out = binary.LittleEndian.AppendUint64(out, uint64(len(counts)))
	keys := make([]model.Hash32, 0, len(counts))
	for id := range counts {
		keys = append(keys, id)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Less(keys[j]) })
	for _, id := range keys {
		out = append(out, id.Bytes()...)
		out = binary.LittleEndian.AppendUint64(out, counts[id])
	}
	digest := hash.Domain(AccessDomain, out)
	return append(out, digest.Bytes()...)
}

func parseAccessSnapshot(data []byte) (map[model.Hash32]uint64, uint64, bool) {
	if len(data) < 24+32 {
		return nil, 0, false
	}
	if string(data[0:4]) != accessSnapshotMagic ||
		binary.LittleEndian.Uint32(data[4:8]) != accessFormatVersion {
		return nil, 0, false
	}
	epoch := binary.LittleEndian.Uint64(data[8:16])
	bodyEnd := len(data) - 32
	digest, err := hash.FromSlice(data[bodyEnd:])
	if err != nil || hash.Domain(AccessDomain, data[:bodyEnd]) != digest {
		return nil, 0, false
	}
	count := binary.LittleEndian.Uint64(data[16:24])
	if count > MaxTrackedObjects {
		return nil, 0, false
	}
	expected := 24 + int(count)*accessRecordBytes
	if expected != bodyEnd {
		return nil, 0, false
	}
	counts := make(map[model.Hash32]uint64, count)
	offset := 24
	for index := uint64(0); index < count; index++ {
		id, err := hash.FromSlice(data[offset : offset+32])
		if err != nil {
			return nil, 0, false
		}
		counts[id] = binary.LittleEndian.Uint64(data[offset+32 : offset+40])
		offset += accessRecordBytes
	}
	return counts, epoch, true
}

type accessJournalRecord struct {
	id    model.Hash32
	delta uint64
}

func parseAccessJournal(data []byte) (uint64, []accessJournalRecord, bool) {
	if len(data) < accessSnapshotHeader ||
		string(data[0:4]) != accessJournalMagic ||
		binary.LittleEndian.Uint32(data[4:8]) != accessFormatVersion {
		return 0, nil, false
	}
	epoch := binary.LittleEndian.Uint64(data[8:16])
	body := data[accessSnapshotHeader:]
	usable := len(body) - len(body)%accessRecordBytes
	records := make([]accessJournalRecord, 0, usable/accessRecordBytes)
	for offset := 0; offset+accessRecordBytes <= usable; offset += accessRecordBytes {
		if len(records) >= MaxJournalRecords {
			break
		}
		id, err := hash.FromSlice(body[offset : offset+32])
		if err != nil {
			return 0, nil, false
		}
		delta := binary.LittleEndian.Uint64(body[offset+32 : offset+40])
		records = append(records, accessJournalRecord{id: id, delta: delta})
	}
	return epoch, records, true
}

func accessDir(root string) string { return filepath.Join(root, "access") }

// loadAccessCounts reads the snapshot and journal. Every failure is a note.
func loadAccessCounts(root string) *accessCounts {
	out := newAccessCounts()
	out.loadedFromDir = accessDir(root)
	var snapshotEpoch uint64
	if data, err := os.ReadFile(filepath.Join(accessDir(root), "counts.v1")); err == nil {
		if counts, epoch, ok := parseAccessSnapshot(data); ok {
			out.counts = counts
			out.epoch = epoch
			snapshotEpoch = epoch
		} else {
			out.notes = append(out.notes, "access counters: counts snapshot rejected; starting empty")
		}
	}
	if data, err := os.ReadFile(filepath.Join(accessDir(root), "journal.v1")); err == nil {
		if epoch, records, ok := parseAccessJournal(data); ok && epoch == snapshotEpoch {
			for _, record := range records {
				out.counts[record.id] = saturatingAdd(out.counts[record.id], record.delta)
			}
			usable := len(data) - accessSnapshotHeader
			usable -= usable % accessRecordBytes
			out.journal = append([]byte(nil), data[:accessSnapshotHeader+usable]...)
			if usable/accessRecordBytes >= CompactAfterRecords {
				out.forceCompact = true
			}
		} else if ok {
			out.notes = append(out.notes,
				"access counters: journal epoch is not the snapshot epoch; journal ignored")
		} else {
			out.notes = append(out.notes, "access counters: journal rejected; counts snapshot only")
		}
	}
	if len(out.counts) > MaxTrackedObjects {
		out.counts = map[model.Hash32]uint64{}
		out.boundedOut = true
		out.notes = append(out.notes, "access counters: object bound reached; counters truncated")
	}
	return out
}

func (c *accessCounts) noteRead(id model.Hash32) {
	if id == model.ZeroHash {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.counts[id]; !ok && len(c.counts) >= MaxTrackedObjects {
		if !c.boundedOut {
			c.boundedOut = true
			c.notes = append(c.notes, "access counters: object bound reached")
		}
		return
	}
	c.counts[id] = saturatingAdd(c.counts[id], 1)
	c.pending[id] = saturatingAdd(c.pending[id], 1)
	c.pendingReads = saturatingAdd(c.pendingReads, 1)
}

func (c *accessCounts) reads(id model.Hash32) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[id]
}

func (c *accessCounts) entries() map[model.Hash32]uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[model.Hash32]uint64, len(c.counts))
	for id, value := range c.counts {
		out[id] = value
	}
	return out
}

func (c *accessCounts) consume(id model.Hash32) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	previous := c.counts[id]
	delete(c.counts, id)
	if previous > 0 {
		// Keep a zero-delta pending entry so flush cannot early-return: a pure consumption must still publish the compacted snapshot.
		c.pending[id] = 0
		c.pendingReads = saturatingAdd(c.pendingReads, 1)
		c.forceCompact = true
	}
	return previous
}

func (c *accessCounts) shouldFlush() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pendingReads >= FlushEveryReads
}

func (c *accessCounts) hasPending() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pending) > 0
}

func (c *accessCounts) noteList() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.notes...)
}

// flush persists pending increments. A compaction writes a new snapshot epoch
// and an empty journal; a stale journal is ignored by epoch on the next open.
func (c *accessCounts) flush(root string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.pending) == 0 {
		return nil
	}
	if err := makeDir(accessDir(root)); err != nil {
		return err
	}
	compact := c.forceCompact ||
		(len(c.journal)-accessSnapshotHeader)/accessRecordBytes >= CompactAfterRecords
	if compact {
		c.epoch = saturatingAdd(c.epoch, 1)
		if err := writeAccessFile(root, "counts.v1", encodeAccessSnapshot(c.counts, c.epoch)); err != nil {
			return err
		}
		c.journal = accessJournalHeader(c.epoch)
	} else {
		keys := make([]model.Hash32, 0, len(c.pending))
		for id := range c.pending {
			keys = append(keys, id)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i].Less(keys[j]) })
		for _, id := range keys {
			c.journal = append(c.journal, id.Bytes()...)
			c.journal = binary.LittleEndian.AppendUint64(c.journal, c.pending[id])
		}
		if err := writeAccessFile(root, "journal.v1", c.journal); err != nil {
			return err
		}
	}
	c.pending = map[model.Hash32]uint64{}
	c.pendingReads = 0
	c.forceCompact = false
	return nil
}

func writeAccessFile(root, name string, data []byte) error {
	dir := accessDir(root)
	tmpDir := filepath.Join(root, "tmp")
	if err := makeDir(tmpDir); err != nil {
		return err
	}
	tmp := filepath.Join(tmpDir, "access-"+itoa(uint64(os.Getpid()))+"-"+name)
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return fsyncDir(dir)
}

// AccessReads returns the retained read counter for one object.
func (s *Store) AccessReads(id model.Hash32) uint64 { return s.access.reads(id) }

// AccessEntries returns every retained counter.
func (s *Store) AccessEntries() map[model.Hash32]uint64 { return s.access.entries() }

// AccessNotes returns load/accounting diagnostics.
func (s *Store) AccessNotes() []string { return s.access.noteList() }

// ConsumeAccessReads resets one counter (rebase idempotence).
func (s *Store) ConsumeAccessReads(id model.Hash32) uint64 { return s.access.consume(id) }

// FlushAccessCounts persists pending counters. Read-only opens never write.
func (s *Store) FlushAccessCounts() error {
	if s.mode != ReadWrite {
		return nil
	}
	return s.access.flush(s.root)
}

func (s *Store) noteObjectRead(id model.Hash32) {
	s.access.noteRead(id)
	if s.access.shouldFlush() && s.mode == ReadWrite {
		_ = s.access.flush(s.root)
	}
}
