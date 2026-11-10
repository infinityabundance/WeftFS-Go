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

// preparedSegment is a fully encoded WFX3 segment plus the index it resolves
// to. WFX3 carries no commit field, so the bytes are prepared before the
// commit exists and published after it.
type preparedSegment struct {
	data  []byte
	index *weftindex.StateIndex
}

// loadPersistedIndex loads, validates, and returns the advisory segment for
// `commit`. A nil result means "rebuild from state".
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
	if len(data) >= 4 && string(data[0:4]) == weftindex.MagicV3 {
		return s.loadWfx3Index(commit, state, data, displayed)
	}
	return s.loadWfx2Index(commit, state, data, displayed)
}

// loadWfx2Index is the legacy full-segment path.
func (s *Store) loadWfx2Index(commit model.Hash32, state *model.State, data []byte, displayed string) *weftindex.StateIndex {
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
	if attestation.IsV3() {
		s.indexes.noteReject("ignoring index " + displayed +
			": a v3 commit names a segment chain, not a WFX2 file")
		return nil
	}
	if !s.attestationMatches(loaded, &record.Commit, attestation, displayed) {
		return nil
	}
	s.indexes.bump(func(stats *IndexStats) { stats.DiskLoads++ })
	return loaded
}

// loadWfx3Index resolves a full or delta segment against its attested chain.
func (s *Store) loadWfx3Index(commit model.Hash32, state *model.State, data []byte, displayed string) *weftindex.StateIndex {
	if uint64(len(data)) > weftindex.MaxFileBytes {
		s.indexes.noteReject(displayed + " is above the " +
			model.FormatU64(weftindex.MaxFileBytes) + "-byte cap")
		return nil
	}
	segment, err := weftindex.DecodeSegment(data)
	if err != nil {
		s.indexes.noteReject("ignoring index " + displayed + ": " + err.Error())
		return nil
	}
	resolved, err := weftindex.ResolveChainSegment(segment, func(baseCommit, _ model.Hash32) ([]byte, error) {
		return s.blobs.Get(BlobIndex, baseCommit)
	})
	if err != nil {
		s.indexes.noteReject("ignoring index " + displayed +
			": cannot resolve its segment chain: " + err.Error())
		return nil
	}
	resolved.Index.WithCommit(commit)
	if segment.Header.Generation != resolved.Index.Generation() {
		s.indexes.noteReject("ignoring index " + displayed +
			": header generation differs from the resolved index")
		return nil
	}
	if !resolved.Index.MatchesState(state) {
		s.indexes.noteReject("ignoring index " + displayed +
			": generation/counts disagree with the replayed state")
		return nil
	}
	record, err := s.commits.ReadCommit(resolved.Index.Generation())
	if err != nil {
		s.indexes.noteReject("ignoring index " + displayed + ": cannot re-read its commit record")
		return nil
	}
	if id, err := record.Commit.ID(); err != nil || id != commit {
		s.indexes.noteReject("ignoring index " + displayed + ": commit record hash mismatch")
		return nil
	}
	attestation := record.Commit.IndexAttestation
	if attestation == nil || !attestation.IsV3() {
		s.indexes.noteReject("ignoring index " + displayed +
			": the commit carries no v3 index attestation")
		return nil
	}
	if !s.attestationMatches(resolved.Index, &record.Commit, attestation, displayed) {
		return nil
	}
	base := resolved.Chain.Base()
	baseOK := (attestation.SegmentBase == nil && base == nil) ||
		(attestation.SegmentBase != nil && base != nil && *attestation.SegmentBase == *base)
	if attestation.SegmentKind != string(resolved.Chain.Kind) ||
		!baseOK || attestation.SegmentDepth != resolved.Chain.Depth() {
		s.indexes.noteReject("ignoring index " + displayed +
			": segment chain shape disagrees with the commit attestation (forged or partial chain); rebuild-only")
		return nil
	}
	root, err := resolved.Chain.Root(resolved.Index.Generation())
	if err != nil {
		s.indexes.noteReject("ignoring index " + displayed +
			": cannot derive the chain root: " + err.Error())
		return nil
	}
	if root != attestation.SegmentRoot {
		s.indexes.noteReject("ignoring index " + displayed +
			": segment root disagrees with the commit attestation (forged or partial chain); rebuild-only")
		return nil
	}
	s.indexes.bump(func(stats *IndexStats) { stats.DiskLoads++ })
	return resolved.Index
}

// attestationMatches checks counts, candidates root, and the state root.
func (s *Store) attestationMatches(index *weftindex.StateIndex, commit *model.Commit, attestation *model.IndexAttestation, displayed string) bool {
	if attestation.ObjectCount != uint64(index.ObjectCount()) ||
		attestation.RelationCount != uint64(index.RelationCount()) ||
		attestation.EntryCount != uint64(index.EntryCount()) {
		s.indexes.noteReject("ignoring index " + displayed +
			": counts disagree with the commit attestation")
		return false
	}
	candidates, err := index.CandidatesRoot()
	if err != nil {
		s.indexes.noteReject("ignoring index " + displayed +
			": cannot re-derive its candidate root: " + err.Error())
		return false
	}
	if candidates != attestation.CandidatesRoot {
		s.indexes.noteReject("ignoring index " + displayed +
			": candidate root disagrees with the commit attestation (forged or incomplete index); rebuild-only")
		return false
	}
	preimage, err := commit.FieldsWCB()
	if err != nil {
		s.indexes.noteReject("ignoring index " + displayed +
			": cannot recompute the attested state root: " + err.Error())
		return false
	}
	if hash.Domain(weftindex.DomainState, preimage) != attestation.StateRoot {
		s.indexes.noteReject("ignoring index " + displayed +
			": attested state root disagrees with the commit record")
		return false
	}
	return true
}

// indexAttestationFor builds the attestation for a commit that is about to
// publish (`commit` must not carry one yet) and returns the index it describes
// so the segment write does not rebuild it.
func (s *Store) indexAttestationFor(
	state *model.State,
	generation uint64,
	commit *model.Commit,
) (*model.IndexAttestation, *preparedSegment, error) {
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

	full, err := weftindex.EncodeFull(derived)
	if err != nil {
		return nil, nil, err
	}
	fullID, err := weftindex.FileSegmentID(full)
	if err != nil {
		return nil, nil, err
	}
	maxDeltas := s.options.IndexChainMaxDeltas
	if maxDeltas == 0 {
		maxDeltas = weftindex.DefaultMaxChainDeltas
	}
	forceFull := s.forceFullIndex || s.options.NoIncrementalIndex ||
		s.head == (model.Hash32{}) || generation <= 1
	var chosen []byte
	var chain weftindex.IndexChain
	if !forceFull {
		if base := s.loadAttestedChain(s.head); base != nil &&
			base.Index.Generation()+1 == generation &&
			base.Chain.Depth() < uint64(maxDeltas) {
			delta, err := weftindex.EncodeDelta(base.Index, derived, base.Chain.Chain[0], s.head)
			if err != nil {
				return nil, nil, err
			}
			if len(delta) < len(full) {
				deltaID, err := weftindex.FileSegmentID(delta)
				if err != nil {
					return nil, nil, err
				}
				ids := make([]model.Hash32, 0, len(base.Chain.Chain)+1)
				ids = append(ids, deltaID)
				ids = append(ids, base.Chain.Chain...)
				chosen = delta
				chain = weftindex.IndexChain{Kind: weftindex.SegmentDelta, Chain: ids}
			}
		}
	}
	if chosen == nil {
		chosen = full
		chain = weftindex.IndexChain{Kind: weftindex.SegmentFull, Chain: []model.Hash32{fullID}}
	}
	if s.options.IndexBytesBudget != nil {
		total, err := s.IndexBytesTotal()
		if err != nil {
			total = ^uint64(0)
		}
		if total+uint64(len(chosen)) > *s.options.IndexBytesBudget {
			s.indexes.noteWriteError(model.FormatU64(generation) +
				" index skipped: " + model.FormatU64(uint64(len(chosen))) +
				" bytes would exceed the index byte budget")
			return nil, nil, nil
		}
	}
	root, err := chain.Root(generation)
	if err != nil {
		return nil, nil, err
	}
	attestation := &model.IndexAttestation{
		ObjectCount:    uint64(derived.ObjectCount()),
		RelationCount:  uint64(derived.RelationCount()),
		EntryCount:     uint64(derived.EntryCount()),
		StateRoot:      hash.Domain(weftindex.DomainState, preimage),
		CandidatesRoot: candidates,
		SegmentKind:    string(chain.Kind),
		SegmentBase:    chain.Base(),
		SegmentDepth:   chain.Depth(),
		SegmentRoot:    root,
	}
	return attestation, &preparedSegment{data: chosen, index: derived}, nil
}

// loadAttestedChain resolves the chain named by an already-published commit.
func (s *Store) loadAttestedChain(commit model.Hash32) *weftindex.ResolvedChain {
	record, err := s.commits.ReadCommit(s.generation)
	if err != nil {
		return nil
	}
	if id, err := record.Commit.ID(); err != nil || id != commit {
		return nil
	}
	attestation := record.Commit.IndexAttestation
	if attestation == nil || !attestation.IsV3() {
		return nil
	}
	data, err := s.blobs.Get(BlobIndex, commit)
	if err != nil {
		return nil
	}
	resolved, err := weftindex.ResolveChain(data, func(baseCommit, _ model.Hash32) ([]byte, error) {
		return s.blobs.Get(BlobIndex, baseCommit)
	})
	if err != nil {
		return nil
	}
	base := resolved.Chain.Base()
	baseOK := (attestation.SegmentBase == nil && base == nil) ||
		(attestation.SegmentBase != nil && base != nil && *attestation.SegmentBase == *base)
	if uint64(resolved.Index.ObjectCount()) != attestation.ObjectCount ||
		uint64(resolved.Index.RelationCount()) != attestation.RelationCount ||
		uint64(resolved.Index.EntryCount()) != attestation.EntryCount ||
		attestation.SegmentKind != string(resolved.Chain.Kind) || !baseOK ||
		attestation.SegmentDepth != resolved.Chain.Depth() {
		return nil
	}
	root, err := resolved.Chain.Root(resolved.Index.Generation())
	if err != nil || root != attestation.SegmentRoot {
		return nil
	}
	return resolved
}

// IndexBytesTotal sums the bytes held in `indexes/`.
func (s *Store) IndexBytesTotal() (uint64, error) {
	entries, problems, err := s.blobs.List("indexes")
	if err != nil {
		return 0, err
	}
	if len(problems) > 0 {
		return 0, werr.Newf(werr.Corrupt, "index listing had %d problems", len(problems))
	}
	var total uint64
	for _, entry := range entries {
		total += entry.Size
	}
	return total, nil
}

// IndexHeadChain reports the head segment kind and chain depth.
func (s *Store) IndexHeadChain() (string, uint64, error) {
	data, err := s.blobs.Get(BlobIndex, s.head)
	if err != nil {
		if werr.Is(err, werr.NotFound) {
			return "none", 0, nil
		}
		return "", 0, err
	}
	if len(data) < 4 || string(data[0:4]) != weftindex.MagicV3 {
		return "wfx2", 0, nil
	}
	segment, err := weftindex.DecodeSegment(data)
	if err != nil {
		return "", 0, err
	}
	header := segment.Header
	var depth uint64
	for header.Kind == weftindex.SegmentDelta {
		depth++
		if depth > uint64(weftindex.HardMaxChainDeltas) {
			return "", 0, werr.Newf(werr.LimitExceeded, "index head chain exceeds the hard depth bound")
		}
		baseData, err := s.blobs.Get(BlobIndex, header.BaseCommit)
		if err != nil {
			return "", 0, err
		}
		base, err := weftindex.DecodeSegment(baseData)
		if err != nil {
			return "", 0, err
		}
		header = base.Header
	}
	return string(segment.Header.Kind), depth, nil
}

// writeBuiltIndex publishes a prepared segment.
func (s *Store) writeBuiltIndex(commit model.Hash32, prepared *preparedSegment) (uint64, error) {
	data := prepared.data
	if uint64(len(data)) > weftindex.MaxFileBytes {
		return 0, werr.Newf(werr.LimitExceeded,
			"index encoding is %d bytes, above the %d-byte cap", len(data), weftindex.MaxFileBytes)
	}
	if err := s.blobs.Put(BlobIndex, commit, data); err != nil {
		return 0, werr.Wrap(werr.Io, err, "cannot publish index %s", blobRelPath(BlobIndex, commit))
	}
	prepared.index.WithCommit(commit)
	s.indexes.put(commit, prepared.index)
	s.indexes.bump(func(stats *IndexStats) { stats.Writes++ })
	return uint64(len(data)), nil
}

// persistBuiltIndex is the best-effort write after a commit published.
func (s *Store) persistBuiltIndex(commit model.Hash32, prepared *preparedSegment) {
	if s.mode != ReadWrite {
		return
	}
	if _, err := s.writeBuiltIndex(commit, prepared); err != nil {
		s.indexes.noteWriteError("index for " + commit.Hex() + " was not written: " + err.Error())
	}
}

// CompactIndex publishes a no-op commit with a full segment, so GC can drop the
// previous chain. A snapshot of the old head keeps the old chain.
func (s *Store) CompactIndex() (model.Hash32, error) {
	s.forceFullIndex = true
	defer func() { s.forceFullIndex = false }()
	return s.commitOps(nil, false)
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
	// Rewrite the attested head segment; this measures the write without
	// changing the attestation.
	data, err := s.blobs.Get(BlobIndex, s.head)
	if err != nil {
		return 0, err
	}
	if err := s.blobs.Put(BlobIndex, s.head, data); err != nil {
		return 0, err
	}
	s.indexes.bump(func(stats *IndexStats) { stats.Writes++ })
	return uint64(len(data)), nil
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
	if err := s.expandRetainedChains(retained); err != nil {
		// Never guess: if a retained chain cannot be resolved, delete nothing.
		problems = append(problems, "index GC skipped: cannot resolve a retained segment chain: "+err.Error())
		return nil, nil, 0, problems
	}
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

// expandRetainedChains adds every ancestor segment named by a retained commit.
func (s *Store) expandRetainedChains(retained map[model.Hash32]struct{}) error {
	queue := make([]model.Hash32, 0, len(retained))
	for commit := range retained {
		queue = append(queue, commit)
	}
	visited := map[model.Hash32]struct{}{}
	for len(queue) > 0 {
		commit := queue[0]
		queue = queue[1:]
		if _, ok := visited[commit]; ok {
			continue
		}
		visited[commit] = struct{}{}
		data, err := s.blobs.Get(BlobIndex, commit)
		if err != nil {
			if werr.Is(err, werr.NotFound) {
				continue
			}
			return err
		}
		if len(data) < 4 || string(data[0:4]) != weftindex.MagicV3 {
			continue
		}
		segment, err := weftindex.DecodeSegment(data)
		if err != nil {
			return err
		}
		if segment.Header.Kind == weftindex.SegmentFull {
			continue
		}
		if len(visited) > int(weftindex.HardMaxChainDeltas) {
			return werr.Newf(werr.LimitExceeded, "index segment chain exceeds the hard depth bound")
		}
		retained[segment.Header.BaseCommit] = struct{}{}
		queue = append(queue, segment.Header.BaseCommit)
	}
	return nil
}
