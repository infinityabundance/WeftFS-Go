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

	"github.com/infinityabundance/WeftCodec-Go/hash"
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
	// Trust requires the commit to attest this index. A self-consistent
	// segment (valid digest, matching generation and counts) can still be a
	// forged *subset*; only the commit's CandidatesRoot can refute that.
	record, err := s.commits.ReadCommit(loaded.Generation())
	if err != nil {
		s.indexes.noteReject("ignoring index " + displayed + ": cannot re-read its commit record")
		return nil
	}
	if id, err := record.Commit.ID(); err != nil || id != commit {
		s.indexes.noteReject("ignoring index " + displayed + ": commit record hash mismatch")
		return nil
	}
	attestation := record.Commit.IndexAttestation
	if attestation == nil {
		s.indexes.noteReject("ignoring index " + displayed +
			": the commit carries no index attestation (v1 commit); rebuild-only")
		return nil
	}
	if attestation.ObjectCount != uint64(loaded.ObjectCount()) ||
		attestation.RelationCount != uint64(loaded.RelationCount()) ||
		attestation.EntryCount != uint64(loaded.EntryCount()) {
		s.indexes.noteReject("ignoring index " + displayed +
			": counts disagree with the commit attestation")
		return nil
	}
	candidates, err := loaded.CandidatesRoot()
	if err != nil {
		s.indexes.noteReject("ignoring index " + displayed +
			": cannot re-derive its candidate root: " + err.Error())
		return nil
	}
	if candidates != attestation.CandidatesRoot {
		s.indexes.noteReject("ignoring index " + displayed +
			": candidate root disagrees with the commit attestation (forged or incomplete index); rebuild-only")
		return nil
	}
	preimage, err := record.Commit.FieldsWCB()
	if err != nil {
		s.indexes.noteReject("ignoring index " + displayed +
			": cannot recompute the attested state root: " + err.Error())
		return nil
	}
	if hash.Domain(weftindex.DomainState, preimage) != attestation.StateRoot {
		s.indexes.noteReject("ignoring index " + displayed +
			": attested state root disagrees with the commit record")
		return nil
	}
	s.indexes.bump(func(stats *IndexStats) { stats.DiskLoads++ })
	return loaded
}

// indexAttestationFor builds the attestation for a commit that is about to
// publish (`commit` must not carry one yet) and returns the index it describes
// so the segment write does not rebuild it.
func (s *Store) indexAttestationFor(
	state *model.State,
	generation uint64,
	commit *model.Commit,
) (*model.IndexAttestation, *weftindex.StateIndex, error) {
	if !s.options.AttestIndexes || s.mode != ReadWrite {
		return nil, nil, nil
	}
	derived := weftindex.Build(state).WithGeneration(generation)
	if !derived.Complete() {
		// An incomplete index is never persisted; without an attestation the
		// commit is v1 and no segment can be trusted.
		return nil, nil, nil
	}
	preimage, err := commit.FieldsWCB()
	if err != nil {
		return nil, nil, err
	}
	candidates, err := derived.CandidatesRoot()
	if err != nil {
		return nil, nil, err
	}
	return &model.IndexAttestation{
		ObjectCount:    uint64(derived.ObjectCount()),
		RelationCount:  uint64(derived.RelationCount()),
		EntryCount:     uint64(derived.EntryCount()),
		StateRoot:      hash.Domain(weftindex.DomainState, preimage),
		CandidatesRoot: candidates,
	}, derived, nil
}

// writeBuiltIndex publishes an index that was built for the attestation.
func (s *Store) writeBuiltIndex(commit model.Hash32, derived *weftindex.StateIndex) (uint64, error) {
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

// persistBuiltIndex is the best-effort write after a commit published.
func (s *Store) persistBuiltIndex(commit model.Hash32, derived *weftindex.StateIndex) {
	if s.mode != ReadWrite {
		return
	}
	if _, err := s.writeBuiltIndex(commit, derived); err != nil {
		s.indexes.noteWriteError("index for " + commit.Hex() + " was not written: " + err.Error())
	}
}

// IndexStats returns the advisory index diagnostics for this handle.
func (s *Store) IndexStats() IndexStats { return s.indexes.snapshotStats() }

// ResetIndexStats zeroes the advisory index diagnostics (tests and benchmarks).
func (s *Store) ResetIndexStats() { s.indexes.resetStats() }

// WriteIndexForBench writes the advisory segment for the current head and
// returns its size. It writes a *loadable* segment, so the head commit must
// already carry its attestation. Test/receipt hook only.
func (s *Store) WriteIndexForBench() (uint64, error) {
	if err := s.requireWritable(); err != nil {
		return 0, err
	}
	record, err := s.commits.ReadCommit(s.generation)
	if err != nil {
		return 0, err
	}
	attestation := record.Commit.IndexAttestation
	if attestation == nil {
		return 0, werr.Newf(werr.InvalidArgument, "a loadable index needs an attested head commit")
	}
	derived := weftindex.Build(s.state)
	if candidates, err := derived.CandidatesRoot(); err != nil || candidates != attestation.CandidatesRoot {
		return 0, werr.Newf(werr.Corrupt, "rebuilt index differs from the head commit's attestation")
	}
	return s.writeBuiltIndex(s.head, derived)
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
