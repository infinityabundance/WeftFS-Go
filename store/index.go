package store

// On-disk selector-index persistence (the Go port of Rust's `src/index.rs`
// persistence path and `store::state_index`).
//
// After every published commit the store writes the advisory segment
// `indexes/<ab>/<commit>.idx` in the exact WFX2 layout Rust writes. On a cache
// miss a subsequent resolution tries that segment before rebuilding from
// replayed state. The segment is derived data: a read or write failure is a
// diagnostic note and never a commit failure, and a segment that fails any
// validation is discarded and rebuilt.
//
// Only complete indexes are written, so a loaded index is marked complete. A
// read-only open never writes a segment. `verify` ignores segments entirely.

import (
	"sort"
	"sync"
	"time"

	weftindex "github.com/infinityabundance/WeftFS-Go/index"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// defaultIndexCacheCapacity is the number of replayed states whose derived
// index is retained by one Store handle. Eviction is oldest-first.
const defaultIndexCacheCapacity = 8

// IndexStats is advisory index diagnostics. Exported for tests and receipts;
// it is never part of a commit or a format.
type IndexStats struct {
	DiskLoads   uint64
	Builds      uint64
	Rejects     uint64
	Writes      uint64
	WriteErrors uint64
	GCDeleted   uint64
	Notes       []string
}

// indexState is the per-Store index cache and counters.
type indexState struct {
	mu     sync.Mutex
	cache  map[model.Hash32]*weftindex.StateIndex
	order  []model.Hash32
	stats  IndexStats
	loaded bool
}

func (x *indexState) resetStats() {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.stats = IndexStats{}
}

func (x *indexState) snapshotStats() IndexStats {
	x.mu.Lock()
	defer x.mu.Unlock()
	out := x.stats
	out.Notes = append([]string(nil), x.stats.Notes...)
	return out
}

func (x *indexState) bump(update func(*IndexStats)) {
	x.mu.Lock()
	defer x.mu.Unlock()
	update(&x.stats)
}

func (x *indexState) noteReject(note string) {
	x.bump(func(stats *IndexStats) {
		stats.Rejects++
		if len(stats.Notes) < 64 {
			stats.Notes = append(stats.Notes, note)
		}
	})
}

func (x *indexState) noteWriteError(note string) {
	x.bump(func(stats *IndexStats) {
		stats.WriteErrors++
		if len(stats.Notes) < 64 {
			stats.Notes = append(stats.Notes, note)
		}
	})
}

func (x *indexState) get(key model.Hash32) *weftindex.StateIndex {
	x.mu.Lock()
	defer x.mu.Unlock()
	entry, ok := x.cache[key]
	if !ok {
		return nil
	}
	// Refresh recency.
	for position, candidate := range x.order {
		if candidate == key {
			x.order = append(x.order[:position], x.order[position+1:]...)
			break
		}
	}
	x.order = append(x.order, key)
	return entry
}

func (x *indexState) put(key model.Hash32, entry *weftindex.StateIndex) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.cache == nil {
		x.cache = make(map[model.Hash32]*weftindex.StateIndex)
	}
	if _, exists := x.cache[key]; exists {
		for position, candidate := range x.order {
			if candidate == key {
				x.order = append(x.order[:position], x.order[position+1:]...)
				break
			}
		}
	}
	for len(x.order) >= defaultIndexCacheCapacity {
		oldest := x.order[0]
		x.order = x.order[1:]
		delete(x.cache, oldest)
	}
	x.cache[key] = entry
	x.order = append(x.order, key)
}

// stateIndex returns the selector index for `state`, cached under `snapshot`
// (the commit whose replay produced it).
//
// Inside a group the live state changes while the head does not, so a cached
// index keyed by the commit hash can no longer be validated by the structural
// guard. Rebuild per call there; the index may only ever over-approximate.
func (s *Store) stateIndex(snapshot model.Hash32, state *model.State) *weftindex.StateIndex {
	if s.groupDepth != 0 {
		s.indexes.bump(func(stats *IndexStats) { stats.Builds++ })
		return weftindex.Build(state)
	}
	if cached := s.indexes.get(snapshot); cached != nil && cached.MatchesState(state) {
		return cached
	}
	if loaded := s.loadPersistedIndex(snapshot, state); loaded != nil {
		s.indexes.put(snapshot, loaded)
		return loaded
	}
	built := weftindex.Build(state)
	s.indexes.bump(func(stats *IndexStats) { stats.Builds++ })
	s.indexes.put(snapshot, built)
	return built
}

// loadPersistedIndex loads, validates, and returns the advisory segment for
// `commit`. A nil result means "rebuild from state": the segment is absent,
// unreadable, truncated, fails its digest, decodes non-canonically, names a
// different commit, or disagrees with the state's generation/counts.
func (s *Store) loadPersistedIndex(commit model.Hash32, state *model.State) *weftindex.StateIndex {
	displayed := blobRelPath(BlobIndex, commit)
	data, err := s.blobs.Get(BlobIndex, commit)
	if err != nil {
		if werr.Is(err, werr.NotFound) {
			return nil
		}
		s.indexes.noteReject("cannot read index " + displayed + ": " + err.Error())
		return nil
	}
	if uint64(len(data)) > weftindex.MaxFileBytes {
		s.indexes.noteReject(displayed + " is above the " +
			model.FormatU64(weftindex.MaxFileBytes) + "-byte cap")
		return nil
	}
	loaded, err := weftindex.DecodeFile(data)
	if err != nil {
		s.indexes.noteReject("ignoring index " + displayed + ": " + err.Error())
		return nil
	}
	if loaded.Commit() != commit {
		s.indexes.noteReject("ignoring index " + displayed + ": declares commit " +
			loaded.Commit().Hex() + " but is stored under " + commit.Hex())
		return nil
	}
	if !loaded.MatchesState(state) {
		s.indexes.noteReject("ignoring index " + displayed +
			": generation/counts disagree with the replayed state")
		return nil
	}
	s.indexes.bump(func(stats *IndexStats) { stats.DiskLoads++ })
	return loaded
}

// writeStateIndex writes the advisory segment for a published commit. The
// index is derived data: a failure here is recorded but must never fail the
// commit that already published.
func (s *Store) writeStateIndex(commit model.Hash32, state *model.State) (uint64, error) {
	if s.mode != ReadWrite {
		return 0, nil
	}
	derived := weftindex.Build(state)
	if !derived.Complete() {
		// Persisting an incomplete index would later be loaded as exact and
		// could under-select. Keep it in memory only; the commit stands.
		return 0, nil
	}
	derived.WithCommit(commit)
	data, err := derived.EncodeFile()
	if err != nil {
		return 0, err
	}
	if uint64(len(data)) > weftindex.MaxFileBytes {
		return 0, werr.Newf(werr.LimitExceeded,
			"index encoding is %d bytes, above the %d-byte cap", len(data), weftindex.MaxFileBytes)
	}
	if err := s.blobs.Put(BlobIndex, commit, data); err != nil {
		return 0, werr.Wrap(werr.Io, err, "cannot publish index %s", blobRelPath(BlobIndex, commit))
	}
	s.indexes.put(commit, derived)
	s.indexes.bump(func(stats *IndexStats) { stats.Writes++ })
	return uint64(len(data)), nil
}

// persistIndexAfterCommit is the best-effort write after a commit published.
func (s *Store) persistIndexAfterCommit(commit model.Hash32, state *model.State) {
	if _, err := s.writeStateIndex(commit, state); err != nil {
		s.indexes.noteWriteError("index for " + commit.Hex() + " was not written: " + err.Error())
	}
}

// IndexStats returns the advisory index diagnostics for this handle.
func (s *Store) IndexStats() IndexStats { return s.indexes.snapshotStats() }

// ResetIndexStats zeroes the advisory index diagnostics (tests and benchmarks).
func (s *Store) ResetIndexStats() { s.indexes.resetStats() }

// WriteIndexForBench writes the advisory segment for the current head and
// returns its size. Test/receipt hook only.
func (s *Store) WriteIndexForBench() (uint64, error) {
	if err := s.requireWritable(); err != nil {
		return 0, err
	}
	return s.writeStateIndex(s.head, s.state)
}

// BuildIndexForBench builds an index from `state` without writing it and
// returns its object count. Test/receipt hook only.
func (s *Store) BuildIndexForBench(state *model.State) int {
	built := weftindex.Build(state)
	s.indexes.bump(func(stats *IndexStats) { stats.Builds++ })
	return built.ObjectCount()
}

// gcIndexSegments deletes advisory segments whose commit is not named by the
// head, a snapshot, or a checkpoint-carrying commit. A removal never removes
// data: the next query rebuilds.
func (s *Store) gcIndexSegments(retained map[model.Hash32]struct{}, now time.Time, graceSecs uint64, apply bool) (candidates, deleted []string, deletedBytes uint64, problems []string) {
	entries, listProblems, err := s.blobs.List("indexes")
	if err != nil {
		return nil, nil, 0, []string{"cannot list index segments: " + err.Error()}
	}
	problems = append(problems, listProblems...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Rel < entries[j].Rel })
	for _, entry := range entries {
		if _, keep := retained[entry.ID]; keep {
			continue
		}
		if graceSecs > 0 {
			age := uint64(0)
			if now.After(entry.ModTime) {
				age = uint64(now.Sub(entry.ModTime) / time.Second)
			}
			if age < graceSecs {
				continue
			}
		}
		candidates = append(candidates, entry.Rel)
		if !apply {
			continue
		}
		if err := s.blobs.DeleteEntry(entry); err != nil {
			problems = append(problems, "cannot delete index "+entry.Rel+": "+err.Error())
			continue
		}
		deleted = append(deleted, entry.Rel)
		deletedBytes += entry.Size
		s.indexes.bump(func(stats *IndexStats) { stats.GCDeleted++ })
	}
	return candidates, deleted, deletedBytes, problems
}
