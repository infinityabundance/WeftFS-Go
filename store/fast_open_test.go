// Fast-open courts: generation-addressed bounded replay.
//
// These tests compare store.Open (bounded, directory-addressed replay) against
// the original full-scan oracle (store.LoadStateAt) and against
// store.OpenFullScanForBench, which forces the pre-optimisation path. They also
// prove the fast path is actually taken via the process-wide
// store.CommitFileReads counter, and that every structural corruption either
// falls back to the authoritative full recovery (with a note) or fails closed.
// No case may return a silently shorter state.

package store_test

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
)

const fastOpenInterval = 128

// fastOpenOptions is the deterministic store shape used by these tests: small
// chunks, a fixed timestamp, and a caller-chosen checkpoint interval.
func fastOpenOptions(interval uint64) store.Options {
	opts := store.DefaultOptions()
	opts.ChunkSize = 1024
	opts.CheckpointInterval = interval
	opts.GCGraceSecs = 0
	fixed := int64(1_700_000_000_000_000_000)
	opts.FixedTimestampNS = &fixed
	return opts
}

// buildFastOpenStore creates exactly `generations` committed generations over a
// small fixed file set, populating objects, entries, relations, snapshots, and
// tips.
func buildFastOpenStore(t *testing.T, dir string, generations, interval uint64) []model.Hash32 {
	t.Helper()
	s, err := store.Init(dir, fastOpenOptions(interval))
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	ids := make([]model.Hash32, 0, 8)
	for index := 0; index < 8; index++ {
		id, err := s.CreateFile(model.RootID, []byte("f"+model.FormatU64(uint64(index))),
			[]byte("seed body "+model.FormatU64(uint64(index))), 0o644, 0, 0, nil)
		if err != nil {
			t.Fatalf("create file %d: %v", index, err)
		}
		ids = append(ids, id)
	}
	if _, err := s.RelationAdd(ids[0], "links", model.ValueTarget(wcb.TextValue("target")), nil, nil); err != nil {
		t.Fatalf("relation: %v", err)
	}
	if _, err := s.SnapshotCreate("initial"); err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	for s.Generation() < generations {
		generation := s.Generation()
		index := int(generation % uint64(len(ids)))
		body := []byte("generation " + model.FormatU64(generation) + " body " +
			model.FormatU64(generation%17))
		if _, err := s.WriteFile(ids[index], 0, body); err != nil {
			t.Fatalf("write generation %d: %v", generation+1, err)
		}
		switch s.Generation() {
		case 400:
			if _, err := s.SnapshotCreate("mid"); err != nil {
				t.Fatalf("snapshot 400: %v", err)
			}
		case 1200:
			if _, err := s.SnapshotCreate("late"); err != nil {
				t.Fatalf("snapshot 1200: %v", err)
			}
		}
	}
	if s.Generation() != generations {
		t.Fatalf("built generation %d, want %d", s.Generation(), generations)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return ids
}

// fastOpenOracle is the full-scan replay oracle: it enumerates every commit
// file and replays from generation 1.
func fastOpenOracle(t *testing.T, dir string) (*model.State, uint64, model.Hash32, []string) {
	t.Helper()
	view, err := store.ReadSuperblock(dir)
	if err != nil {
		t.Fatalf("superblock: %v", err)
	}
	var maxVisible uint64
	for index := 0; index < 2; index++ {
		if view.Valid[index] && view.Slots[index].Generation > maxVisible {
			maxVisible = view.Slots[index].Generation
		}
	}
	if maxVisible == 0 {
		t.Fatal("no valid superblock slot")
	}
	expected := maxVisible
	loaded, err := store.LoadCommitFile(store.CommitPath(dir, maxVisible), &expected)
	if err != nil {
		t.Fatalf("head commit: %v", err)
	}
	state, notes, err := store.LoadStateAt(dir, loaded.Hash, maxVisible, true)
	if err != nil {
		t.Fatalf("full replay oracle: %v", err)
	}
	return state, loaded.Generation, loaded.Hash, notes
}

// newestCheckpointGeneration reports the highest generation carrying a
// checkpoint. It enumerates every commit file, so tests call it outside any
// counter assertion.
func newestCheckpointGeneration(t *testing.T, dir string) uint64 {
	t.Helper()
	view, err := store.ReadSuperblock(dir)
	if err != nil {
		t.Fatalf("superblock: %v", err)
	}
	var maxVisible uint64
	for index := 0; index < 2; index++ {
		if view.Valid[index] && view.Slots[index].Generation > maxVisible {
			maxVisible = view.Slots[index].Generation
		}
	}
	commits, err := store.AllCommits(dir, maxVisible)
	if err != nil {
		t.Fatalf("all commits: %v", err)
	}
	var newest uint64
	for _, commit := range commits {
		if commit.Commit.Checkpoint != nil && commit.Generation > newest {
			newest = commit.Generation
		}
	}
	if newest == 0 {
		t.Fatal("store has no checkpoint")
	}
	return newest
}

func assertFastOpenStatesEqual(t *testing.T, left, right *model.State, context string) {
	t.Helper()
	if left.Generation != right.Generation {
		t.Fatalf("%s: generation %d != %d", context, left.Generation, right.Generation)
	}
	if !reflect.DeepEqual(left.Objects, right.Objects) {
		t.Fatalf("%s: objects differ", context)
	}
	if !reflect.DeepEqual(left.Entries, right.Entries) {
		t.Fatalf("%s: entries differ", context)
	}
	if !reflect.DeepEqual(left.Relations, right.Relations) {
		t.Fatalf("%s: relations differ", context)
	}
	if !reflect.DeepEqual(left.Snapshots, right.Snapshots) {
		t.Fatalf("%s: snapshots differ", context)
	}
	if !reflect.DeepEqual(left.Tips, right.Tips) {
		t.Fatalf("%s: tips differ", context)
	}
}

func flipLastByteInFile(t *testing.T, path string) {
	t.Helper()
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	bytes[len(bytes)-1] ^= 0xff
	if err := os.WriteFile(path, bytes, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestFastOpenMatchesFullReplayAndReadsABoundedWindow proves the bounded path
// against the full oracle, proves via the read counter that it decoded far
// fewer commits, and asserts the exact resumption note.
func TestFastOpenMatchesFullReplayAndReadsABoundedWindow(t *testing.T) {
	dir := t.TempDir()
	buildFastOpenStore(t, dir, 2_000, fastOpenInterval)

	oracleState, oracleGeneration, oracleHead, oracleNotes := fastOpenOracle(t, dir)
	if len(oracleNotes) != 0 {
		t.Fatalf("oracle notes: %v", oracleNotes)
	}
	if len(oracleState.Snapshots) == 0 {
		t.Fatal("snapshots must be populated")
	}
	if len(oracleState.Tips) == 0 {
		t.Fatal("tips must be populated")
	}
	if len(oracleState.Relations) == 0 {
		t.Fatal("relations must be populated")
	}
	checkpointGeneration := newestCheckpointGeneration(t, dir)

	// ReadOnly: directory-free fast path.
	store.ResetCommitFileReads()
	readonly, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("read-only open: %v", err)
	}
	readonlyReads := store.CommitFileReads()
	if readonly.Generation() != oracleGeneration || readonly.SnapshotRoot() != oracleHead {
		t.Fatalf("read-only open selected gen %d head %s, want %d %s",
			readonly.Generation(), readonly.SnapshotRoot().Hex(), oracleGeneration, oracleHead.Hex())
	}
	assertFastOpenStatesEqual(t, readonly.CurrentState(), oracleState, "read-only fast open")
	if rejected := readonly.RejectedGenerations(); len(rejected) != 0 {
		t.Fatalf("read-only fast open rejected %v", rejected)
	}
	wantNote := "bounded replay resumed from the checkpoint at generation " +
		model.FormatU64(checkpointGeneration) + "; commit files below it were not enumerated"
	notes := readonly.RecoveryNotes()
	if len(notes) != 1 || notes[0] != wantNote {
		t.Fatalf("read-only notes = %q, want exactly %q", notes, wantNote)
	}
	if readonlyReads > fastOpenInterval+2 {
		t.Fatalf("read-only open decoded %d commit files; expected the head-to-checkpoint window",
			readonlyReads)
	}
	if err := readonly.Close(); err != nil {
		t.Fatalf("close read-only: %v", err)
	}

	// ReadWrite: one directory enumeration is still needed to preserve
	// next_generation semantics, but commit decodes stay bounded.
	store.ResetCommitFileReads()
	readwrite, err := store.Open(dir, store.ReadWrite)
	if err != nil {
		t.Fatalf("read-write open: %v", err)
	}
	readwriteReads := store.CommitFileReads()
	if readwrite.Generation() != oracleGeneration || readwrite.SnapshotRoot() != oracleHead {
		t.Fatalf("read-write open selected gen %d head %s", readwrite.Generation(), readwrite.SnapshotRoot().Hex())
	}
	assertFastOpenStatesEqual(t, readwrite.CurrentState(), oracleState, "read-write fast open")
	if rejected := readwrite.RejectedGenerations(); len(rejected) != 0 {
		t.Fatalf("read-write fast open rejected %v", rejected)
	}
	if readwriteReads > fastOpenInterval+2 {
		t.Fatalf("read-write open decoded %d commit files; expected the head-to-checkpoint window",
			readwriteReads)
	}
	if err := readwrite.Close(); err != nil {
		t.Fatalf("close read-write: %v", err)
	}

	// The forced old path is the full scan and produces the same state.
	store.ResetCommitFileReads()
	full, err := store.OpenFullScanForBench(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("full-scan open: %v", err)
	}
	fullReads := store.CommitFileReads()
	if fullReads < 2_000 {
		t.Fatalf("the forced full path must decode every commit file, decoded %d", fullReads)
	}
	if full.Generation() != oracleGeneration || full.SnapshotRoot() != oracleHead {
		t.Fatalf("full-scan open selected gen %d head %s", full.Generation(), full.SnapshotRoot().Hex())
	}
	assertFastOpenStatesEqual(t, full.CurrentState(), oracleState, "forced full open")
	if err := full.Close(); err != nil {
		t.Fatalf("close full: %v", err)
	}
}

// assertFastOpenMatchesFull opens the same (possibly corrupted) store through
// the fast path and through the forced full path, then requires identical
// recovered semantics. The fast path may carry extra "fell back" and checkpoint
// resumption notes; after filtering those, the notes must be identical too.
func assertFastOpenMatchesFull(t *testing.T, dir string) *store.Store {
	t.Helper()
	fast, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("fast open: %v", err)
	}
	fastState := fast.CurrentState()
	fastHead := fast.SnapshotRoot()
	fastGeneration := fast.Generation()
	fastRejected := fast.RejectedGenerations()
	fastNotes := fast.RecoveryNotes()
	if err := fast.Close(); err != nil {
		t.Fatalf("close fast: %v", err)
	}

	full, err := store.OpenFullScanForBench(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("full open: %v", err)
	}
	if fastGeneration != full.Generation() {
		t.Fatalf("generation diverged: fast %d, full %d", fastGeneration, full.Generation())
	}
	if fastHead != full.SnapshotRoot() {
		t.Fatalf("head diverged: fast %s, full %s", fastHead.Hex(), full.SnapshotRoot().Hex())
	}
	assertFastOpenStatesEqual(t, fastState, full.CurrentState(), "recovered state")
	if !reflect.DeepEqual(fastRejected, full.RejectedGenerations()) {
		t.Fatalf("rejected set diverged: fast %v, full %v", fastRejected, full.RejectedGenerations())
	}
	filtered := make([]string, 0, len(fastNotes))
	for _, note := range fastNotes {
		if strings.Contains(note, "fell back") || strings.Contains(note, "bounded replay resumed from the checkpoint") {
			continue
		}
		filtered = append(filtered, note)
	}
	if !reflect.DeepEqual(filtered, full.RecoveryNotes()) {
		t.Fatalf("notes diverged beyond fallback notes: fast %q, full %q", filtered, full.RecoveryNotes())
	}
	fellBack := false
	for _, note := range fastNotes {
		if strings.Contains(note, "fell back") {
			fellBack = true
		}
	}
	if !fellBack {
		t.Fatalf("a fallback must be recorded: %v", fastNotes)
	}
	return full
}

// TestCorruptedChainsFallBackToTheAuthoritativeFullRecovery covers a deleted
// mid-chain commit, corrupted mid-chain bytes, a truncated head, and a
// generation/name disagreement. Every case must either fall back with a note and
// match the full oracle or fail with Corrupt; a silently shorter state is never
// acceptable.
func TestCorruptedChainsFallBackToTheAuthoritativeFullRecovery(t *testing.T) {
	pristine := t.TempDir()
	buildFastOpenStore(t, pristine, 600, fastOpenInterval)

	// (a) delete a mid-chain commit.
	deleted := t.TempDir()
	copyTree(t, pristine, deleted)
	if err := os.Remove(store.CommitPath(deleted, 550)); err != nil {
		t.Fatalf("delete mid-chain commit: %v", err)
	}
	s := assertFastOpenMatchesFull(t, deleted)
	if s.Generation() != 549 {
		t.Fatalf("recovered generation %d, want 549 (below the hole)", s.Generation())
	}
	if !containsU64(s.RejectedGenerations(), 600) {
		t.Fatalf("rejected %v, expected to name 600", s.RejectedGenerations())
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// (b) corrupt a mid-chain commit's bytes so its CRC/hash cannot match.
	corrupt := t.TempDir()
	copyTree(t, pristine, corrupt)
	flipLastByteInFile(t, store.CommitPath(corrupt, 550))
	s = assertFastOpenMatchesFull(t, corrupt)
	if s.Generation() != 549 {
		t.Fatalf("recovered generation %d, want 549 (below the corrupt commit)", s.Generation())
	}
	if !containsU64(s.RejectedGenerations(), 550) {
		t.Fatalf("rejected %v, expected to name 550", s.RejectedGenerations())
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// (c) truncate the head commit file.
	truncated := t.TempDir()
	copyTree(t, pristine, truncated)
	headPath := store.CommitPath(truncated, 600)
	bytes, err := os.ReadFile(headPath)
	if err != nil {
		t.Fatalf("read head commit: %v", err)
	}
	if err := os.WriteFile(headPath, bytes[:len(bytes)/2], 0o644); err != nil {
		t.Fatalf("truncate head commit: %v", err)
	}
	s = assertFastOpenMatchesFull(t, truncated)
	if s.Generation() != 599 {
		t.Fatalf("recovered generation %d, want 599", s.Generation())
	}
	if !containsU64(s.RejectedGenerations(), 600) {
		t.Fatalf("rejected %v, expected to name 600", s.RejectedGenerations())
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// (d) plant a commit whose declared generation disagrees with its name.
	mislabelled := t.TempDir()
	copyTree(t, pristine, mislabelled)
	source, err := os.ReadFile(store.CommitPath(mislabelled, 551))
	if err != nil {
		t.Fatalf("read generation 551: %v", err)
	}
	if err := os.WriteFile(store.CommitPath(mislabelled, 550), source, 0o644); err != nil {
		t.Fatalf("plant mislabelled commit: %v", err)
	}
	s = assertFastOpenMatchesFull(t, mislabelled)
	if s.Generation() != 549 {
		t.Fatalf("recovered generation %d, want 549", s.Generation())
	}
	if !containsU64(s.RejectedGenerations(), 550) {
		t.Fatalf("rejected %v, expected to name 550", s.RejectedGenerations())
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestOpenStopsAtTheNearestCheckpointAndFallsBackWhenItIsCorrupt proves the
// checkpoint note names the newest verified checkpoint and that a corrupt
// checkpoint manifest forces the full fallback without changing the state.
func TestOpenStopsAtTheNearestCheckpointAndFallsBackWhenItIsCorrupt(t *testing.T) {
	dir := t.TempDir()
	// Interval 1280 leaves exactly one checkpoint below the 2,000-commit head:
	// generation 1280. The bounded window is therefore 721 commits.
	buildFastOpenStore(t, dir, 2_000, 1_280)

	checkpointGeneration := newestCheckpointGeneration(t, dir)
	if checkpointGeneration != 1_280 {
		t.Fatalf("newest checkpoint is generation %d, want 1280", checkpointGeneration)
	}
	expected := checkpointGeneration
	checkpointCommit, err := store.LoadCommitFile(store.CommitPath(dir, checkpointGeneration), &expected)
	if err != nil {
		t.Fatalf("checkpoint commit: %v", err)
	}
	if checkpointCommit.Commit.Checkpoint == nil {
		t.Fatal("generation 1280 carries no checkpoint")
	}
	checkpointManifest := *checkpointCommit.Commit.Checkpoint

	oracleState, oracleGeneration, oracleHead, oracleNotes := fastOpenOracle(t, dir)
	if len(oracleNotes) != 0 {
		t.Fatalf("oracle notes: %v", oracleNotes)
	}

	store.ResetCommitFileReads()
	fast, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("fast open: %v", err)
	}
	reads := store.CommitFileReads()
	if fast.Generation() != oracleGeneration || fast.SnapshotRoot() != oracleHead {
		t.Fatalf("fast open selected gen %d head %s", fast.Generation(), fast.SnapshotRoot().Hex())
	}
	assertFastOpenStatesEqual(t, fast.CurrentState(), oracleState, "checkpoint-bounded open")
	wantNote := "bounded replay resumed from the checkpoint at generation 1280; commit files below it were not enumerated"
	notes := fast.RecoveryNotes()
	if len(notes) != 1 || notes[0] != wantNote {
		t.Fatalf("notes = %q, want exactly %q", notes, wantNote)
	}
	if reads > 1_280+2 {
		t.Fatalf("open decoded %d commits; expected at most the checkpoint interval plus the head", reads)
	}
	if err := fast.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Corrupt the checkpoint manifest: the bounded path must not silently
	// accept the window. It falls back to full replay, which ignores the
	// invalid checkpoint and still produces the exact same state.
	flipLastByteInFile(t, store.ManifestPath(dir, checkpointManifest))
	fallback, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("fallback open: %v", err)
	}
	defer fallback.Close()
	if fallback.Generation() != oracleGeneration || fallback.SnapshotRoot() != oracleHead {
		t.Fatalf("fallback open selected gen %d head %s", fallback.Generation(), fallback.SnapshotRoot().Hex())
	}
	assertFastOpenStatesEqual(t, fallback.CurrentState(), oracleState, "corrupt-checkpoint fallback")
	fallbackNotes := fallback.RecoveryNotes()
	if !anyNoteContains(fallbackNotes, "checkpoint") {
		t.Fatalf("the ignored checkpoint must be reported: %v", fallbackNotes)
	}
	if !anyNoteContains(fallbackNotes, "fell back") {
		t.Fatalf("the fallback must be reported: %v", fallbackNotes)
	}
}

func anyNoteContains(notes []string, needle string) bool {
	for _, note := range notes {
		if strings.Contains(note, needle) {
			return true
		}
	}
	return false
}

// TestFastOpenFailsClosedOnADamagedCheckpointManifest deletes the checkpoint
// blob entirely: the bounded path falls back, the full path notes the invalid
// checkpoint, and both still agree on the recovered state.
func TestFastOpenFailsClosedOnADamagedCheckpointManifest(t *testing.T) {
	pristine := t.TempDir()
	buildFastOpenStore(t, pristine, 600, fastOpenInterval)
	checkpointGeneration := newestCheckpointGeneration(t, pristine)
	expected := checkpointGeneration
	loaded, err := store.LoadCommitFile(store.CommitPath(pristine, checkpointGeneration), &expected)
	if err != nil {
		t.Fatalf("checkpoint commit: %v", err)
	}
	if loaded.Commit.Checkpoint == nil {
		t.Fatal("checkpoint commit carries no checkpoint")
	}

	dir := t.TempDir()
	copyTree(t, pristine, dir)
	if err := os.Remove(store.ManifestPath(dir, *loaded.Commit.Checkpoint)); err != nil {
		t.Fatalf("remove checkpoint manifest: %v", err)
	}
	s := assertFastOpenMatchesFull(t, dir)
	if s.Generation() != 600 {
		t.Fatalf("recovered generation %d, want 600", s.Generation())
	}
	if !anyNoteContains(s.RecoveryNotes(), "checkpoint") {
		t.Fatalf("the missing checkpoint must be reported: %v", s.RecoveryNotes())
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}
