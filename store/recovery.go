package store

import (
	"os"
	"sort"
	"sync/atomic"

	"github.com/infinityabundance/WeftCodec-Go/hash"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// commitFileReads counts commit files decoded by LoadCommitFile for the whole
// process. It is a diagnostic for tests and benchmarks that need to prove the
// bounded open path reads O(checkpoint interval) commits rather than every
// commit in the store. It is never used for correctness.
var commitFileReads atomic.Uint64

// CommitFileReads reports commit files decoded since the process started.
func CommitFileReads() uint64 { return commitFileReads.Load() }

// ResetCommitFileReads resets the process-wide commit-file read counter.
func ResetCommitFileReads() { commitFileReads.Store(0) }

// replayStrategy selects how open-time recovery resolves the committed state.
type replayStrategy int

const (
	// replayBounded is the generation-addressed walk from the head down to the
	// nearest verified checkpoint, falling back to the full scan on any
	// inconsistency.
	replayBounded replayStrategy = iota
	// replayFullScan is the original full commit-directory scan and replay.
	replayFullScan
)

// BlobKind selects the content-addressed namespace.
type BlobKind int

const (
	// BlobObject is objects/<ab>/<hash>.
	BlobObject BlobKind = iota
	// BlobManifest is manifests/<ab>/<hash>, including checkpoint state
	// manifests.
	BlobManifest
)

// BlobPath returns the path for a blob.
func BlobPath(root string, kind BlobKind, id model.Hash32) string {
	if kind == BlobObject {
		return ObjectPath(root, id)
	}
	return ManifestPath(root, id)
}

// ReadBlobVerified reads a blob and verifies its domain-separated hash.
func ReadBlobVerified(root string, kind BlobKind, id model.Hash32, domain string) ([]byte, error) {
	path := BlobPath(root, kind, id)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, werr.Wrap(werr.Corrupt, err, "missing blob %s", path)
	}
	actual := hash.Domain(domain, b)
	if actual != id {
		return nil, werr.Newf(werr.Corrupt, "blob %s fails its hash check (expected %s, got %s)", path, id.Hex(), actual.Hex())
	}
	return b, nil
}

// ReadManifest reads a file manifest by its manifest id.
func ReadManifest(root string, manifestID model.Hash32) (model.Manifest, error) {
	b, err := ReadBlobVerified(root, BlobManifest, manifestID, model.DomainManifest)
	if err != nil {
		return model.Manifest{}, err
	}
	value, err := model.DecodeWCB(b)
	if err != nil {
		return model.Manifest{}, err
	}
	manifest, err := model.ManifestFromWCB(value)
	if err != nil {
		return model.Manifest{}, err
	}
	// Reject a manifest above the v1 file bound before it can force a larger
	// allocation; this is a decoder limit, not a lossy fallback.
	if manifest.Size > MaxFileBytes {
		return model.Manifest{}, werr.Newf(werr.LimitExceeded, "manifest size %d exceeds the %d-byte v1 bound", manifest.Size, MaxFileBytes)
	}
	return manifest, nil
}

// ReadStateManifest reads and verifies a checkpoint state manifest.
func ReadStateManifest(root string, manifestID model.Hash32) (*model.State, error) {
	b, err := ReadBlobVerified(root, BlobManifest, manifestID, model.DomainManifest)
	if err != nil {
		return nil, err
	}
	value, err := model.DecodeWCB(b)
	if err != nil {
		return nil, err
	}
	return model.DecodeState(value)
}

// CommitIndex parses every commit file up to maxGeneration (inclusive),
// ignoring files that fail to parse. The index is keyed by commit hash.
func CommitIndex(root string, maxGeneration uint64) (map[model.Hash32]LoadedCommit, error) {
	files, err := ScanCommitFiles(root)
	if err != nil {
		return nil, err
	}
	index := make(map[model.Hash32]LoadedCommit, len(files))
	for generation, path := range files {
		if generation > maxGeneration {
			continue
		}
		expected := generation
		loaded, err := LoadCommitFile(path, &expected)
		if err != nil {
			continue
		}
		index[loaded.Hash] = loaded
	}
	return index, nil
}

// LoadStateAt rebuilds state by replaying the parent chain ending at headHash.
// When checkCatalog is true, every file object's manifest and chunk files are
// checked for existence, hash, and length.
func LoadStateAt(root string, headHash model.Hash32, maxGeneration uint64, checkCatalog bool) (*model.State, []string, error) {
	index, err := CommitIndex(root, maxGeneration)
	if err != nil {
		return nil, nil, err
	}
	var notes []string

	chain := make([]LoadedCommit, 0)
	cursor := headHash
	seen := make(map[model.Hash32]bool)
	for {
		if seen[cursor] {
			return nil, nil, werr.Newf(werr.Corrupt, "commit parent chain contains a cycle")
		}
		seen[cursor] = true
		loaded, ok := index[cursor]
		if !ok {
			return nil, nil, werr.Newf(werr.Corrupt, "commit parent chain refers to a missing commit")
		}
		chain = append(chain, loaded)
		if loaded.Commit.Parent == nil {
			break
		}
		cursor = *loaded.Commit.Parent
	}
	// reverse
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}

	for i := 0; i+1 < len(chain); i++ {
		if chain[i+1].Generation <= chain[i].Generation {
			return nil, nil, werr.Newf(werr.Corrupt, "commit generations do not increase along the parent chain")
		}
		expectedParent := chain[i].Hash
		if chain[i+1].Commit.Parent == nil || *chain[i+1].Commit.Parent != expectedParent {
			return nil, nil, werr.Newf(werr.Corrupt, "commit parent hash does not match the previous commit")
		}
	}
	if len(chain) == 0 || chain[0].Generation != 1 {
		return nil, nil, werr.Newf(werr.Corrupt, "commit chain does not start at generation 1")
	}
	if chain[0].Commit.Parent != nil {
		return nil, nil, werr.Newf(werr.Corrupt, "generation 1 has a parent")
	}

	state := model.NewState()
	for _, loaded := range chain {
		if loaded.Commit.Checkpoint != nil {
			checkpointState, err := ReadStateManifest(root, *loaded.Commit.Checkpoint)
			if err != nil {
				notes = append(notes, "checkpoint "+loaded.Commit.Checkpoint.Hex()+" in generation "+
					itoa(loaded.Generation)+" is invalid ("+err.Error()+"); replayed ops instead")
			} else if checkpointState.Generation != loaded.Generation {
				notes = append(notes, "checkpoint "+loaded.Commit.Checkpoint.Hex()+" in generation "+
					itoa(loaded.Generation)+" declares generation "+itoa(checkpointState.Generation)+"; ignored")
			} else {
				state = checkpointState
				continue
			}
		}
		if err := state.ApplyOps(loaded.Commit.Ops); err != nil {
			return nil, nil, werr.Newf(werr.Corrupt, "generation %d ops cannot be applied: %s", loaded.Generation, err)
		}
		state.Generation = loaded.Generation
	}

	if checkCatalog {
		if err := ValidateCatalog(root, state); err != nil {
			return nil, nil, err
		}
	}
	return state, notes, nil
}

// ValidateCatalog checks final-state referential integrity and content-file
// existence: entry parents/targets, tip objects, manifest identity, and chunk
// existence/length. Chunk bytes are verified by materialization and --full.
func ValidateCatalog(root string, state *model.State) error {
	rootObject, ok := state.Objects[model.RootID]
	if !ok {
		return werr.Newf(werr.Corrupt, "namespace root object is missing")
	}
	if rootObject.Kind != model.KindDir {
		return werr.Newf(werr.Corrupt, "namespace root object is not a directory")
	}
	for _, entry := range state.Entries {
		parent, ok := state.Objects[entry.Parent]
		if !ok {
			return werr.Newf(werr.Corrupt, "entry parent object is missing")
		}
		if parent.Kind != model.KindDir {
			return werr.Newf(werr.Corrupt, "entry parent is not a directory")
		}
		if _, ok := state.Objects[entry.Target]; !ok {
			return werr.Newf(werr.Corrupt, "entry target object is missing")
		}
	}
	for object := range state.Tips {
		if _, ok := state.Objects[object]; !ok {
			return werr.Newf(werr.Corrupt, "tip refers to a missing object")
		}
	}
	for _, record := range state.Objects {
		if record.Kind != model.KindFile {
			continue
		}
		manifest, err := ReadManifest(root, record.Content)
		if err != nil {
			return err
		}
		if manifest.Size != record.Size {
			return werr.Newf(werr.Corrupt, "object %s size %d disagrees with manifest size %d", record.ID.Hex(), record.Size, manifest.Size)
		}
		for _, chunk := range manifest.Chunks {
			path := ObjectPath(root, chunk.Hash)
			info, err := os.Stat(path)
			if err != nil {
				return werr.Wrap(werr.Corrupt, err, "missing chunk %s", path)
			}
			if uint64(info.Size()) != chunk.Len {
				return werr.Newf(werr.Corrupt, "chunk %s is %d bytes, manifest says %d", path, info.Size(), chunk.Len)
			}
		}
	}
	return nil
}

// Recovery is the result of the full open-time recovery pass.
type Recovery struct {
	Head       model.Hash32
	Generation uint64
	State      *model.State
	Rejected   []uint64
	Notes      []string
	// HighestFileGeneration is the highest commit-file generation present on
	// disk (including unpublished files above the selected head). The
	// directory-free fast path cannot enumerate the commit directory, so it
	// reports the selected generation instead; the value only advances
	// next_generation on a writable open.
	HighestFileGeneration uint64
}

// Recover selects the highest valid published generation using
// generation-addressed bounded replay. It never invents data and never deletes
// rejected generations.
func Recover(root string) (*Recovery, error) {
	return recoverWithStrategy(root, replayBounded, true)
}

// recoverForWrite is the writable-open path. It needs one commit-directory
// enumeration so next_generation never reuses a rejected generation; the commit
// decode window is still bounded by the checkpoint interval.
func recoverForWrite(root string) (*Recovery, error) {
	return recoverWithStrategy(root, replayBounded, false)
}

// recoverFullScan is the original full commit-directory recovery. It stays
// authoritative for its rejected set and notes, and is the fallback for every
// bounded-replay inconsistency.
func recoverFullScan(root string) (*Recovery, error) {
	return recoverWithStrategy(root, replayFullScan, false)
}

func recoverWithStrategy(root string, strategy replayStrategy, allowDirectoryFree bool) (*Recovery, error) {
	view, err := ReadSuperblock(root)
	if err != nil {
		return nil, err
	}
	notes := append([]string(nil), view.Notes...)
	validSlots := make([]SuperblockSlot, 0, 2)
	for index := 0; index < 2; index++ {
		if view.Valid[index] {
			validSlots = append(validSlots, view.Slots[index])
		}
	}
	if len(validSlots) == 0 {
		return nil, werr.Newf(werr.Corrupt, "no valid superblock slot")
	}
	sort.Slice(validSlots, func(i, j int) bool { return validSlots[i].Generation < validSlots[j].Generation })
	maxVisible := validSlots[len(validSlots)-1].Generation
	slotByGen := make(map[uint64]SuperblockSlot, len(validSlots))
	for _, slot := range validSlots {
		slotByGen[slot.Generation] = slot
	}

	if allowDirectoryFree && strategy == replayBounded {
		recovery, err := recoverDirectoryFree(root, view, validSlots, maxVisible, slotByGen)
		if err == nil {
			return recovery, nil
		}
		// Do not reuse anything from the fast attempt: the scan-based recovery
		// is authoritative, including its rejected set and notes. Record that
		// the fallback happened.
		recovery, fallbackErr := recoverWithStrategy(root, replayBounded, false)
		if fallbackErr != nil {
			return nil, fallbackErr
		}
		recovery.Notes = append(recovery.Notes, "open fast path fell back to full commit-directory recovery: "+err.Error())
		return recovery, nil
	}

	files, err := ScanCommitFiles(root)
	if err != nil {
		return nil, err
	}
	candidates := make([]uint64, 0, len(files))
	highestFileGeneration := uint64(0)
	for generation := range files {
		if generation > highestFileGeneration {
			highestFileGeneration = generation
		}
		if generation <= maxVisible {
			candidates = append(candidates, generation)
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i] > candidates[j] })

	rejected := make([]uint64, 0)
	// Iterate the sorted slots so the notes are deterministic. A published
	// generation whose commit file is absent is a rejection, never an
	// invitation to invent a head.
	for _, slot := range validSlots {
		if _, ok := files[slot.Generation]; !ok {
			notes = append(notes, "generation "+itoa(slot.Generation)+" rejected: published slot has no commit file")
			rejected = append(rejected, slot.Generation)
		}
	}

	for _, generation := range candidates {
		path := CommitPath(root, generation)
		expected := generation
		loaded, err := LoadCommitFile(path, &expected)
		if err != nil {
			notes = append(notes, "generation "+itoa(generation)+" rejected: "+err.Error())
			rejected = append(rejected, generation)
			continue
		}
		if slot, ok := slotByGen[generation]; ok {
			if slot.Commit != loaded.Hash {
				notes = append(notes, "generation "+itoa(generation)+" rejected: superblock hash "+slot.Commit.Hex()+" does not match commit hash "+loaded.Hash.Hex())
				rejected = append(rejected, generation)
				continue
			}
			if slot.CommitLen != loaded.WCBLength {
				notes = append(notes, "generation "+itoa(generation)+" rejected: superblock length "+itoa(slot.CommitLen)+" does not match commit length "+itoa(loaded.WCBLength))
				rejected = append(rejected, generation)
				continue
			}
		}
		var state *model.State
		var loadNotes []string
		if strategy == replayBounded {
			state, loadNotes, err = loadStateBounded(root, loaded.Hash, loaded.Generation, maxVisible)
			if err != nil {
				notes = append(notes, "generation "+itoa(generation)+": bounded replay fell back to full scan: "+err.Error())
				state, loadNotes, err = LoadStateAt(root, loaded.Hash, maxVisible, true)
			}
		} else {
			state, loadNotes, err = LoadStateAt(root, loaded.Hash, maxVisible, true)
		}
		if err != nil {
			notes = append(notes, "generation "+itoa(generation)+" rejected: "+err.Error())
			rejected = append(rejected, generation)
			continue
		}
		notes = append(notes, loadNotes...)
		return &Recovery{
			Head: loaded.Hash, Generation: loaded.Generation, State: state,
			Rejected: rejected, Notes: notes,
			HighestFileGeneration: highestFileGeneration,
		}, nil
	}
	return nil, werr.Newf(werr.Corrupt, "no valid generation at or below %d; rejected %v", maxVisible, rejected)
}

// recoverDirectoryFree is the read-only fast open: the highest published slot
// must be the head, its commit file must exist and match the slot hash and
// length, and the bounded chain replay must complete. Anything else returns an
// error so the caller can fall back to the full directory scan.
func recoverDirectoryFree(root string, view SuperblockView, validSlots []SuperblockSlot, maxVisible uint64, slotByGen map[uint64]SuperblockSlot) (*Recovery, error) {
	// The scan-based path records a rejection for every published slot whose
	// commit file is missing. Reproducing that note without enumerating is not
	// possible, so fall back when it happens.
	for _, slot := range validSlots {
		path := CommitPath(root, slot.Generation)
		info, err := os.Stat(path)
		if err != nil {
			return nil, werr.Wrap(werr.Corrupt, err, "published generation %d has no commit file", slot.Generation)
		}
		if !info.Mode().IsRegular() {
			return nil, werr.Newf(werr.Corrupt, "published generation %d commit path %s is not a regular file", slot.Generation, path)
		}
	}

	expected := maxVisible
	loaded, err := LoadCommitFile(CommitPath(root, maxVisible), &expected)
	if err != nil {
		return nil, err
	}
	if slot, ok := slotByGen[maxVisible]; ok {
		if slot.Commit != loaded.Hash {
			return nil, werr.Newf(werr.Corrupt, "superblock hash for generation %d does not match the commit record", maxVisible)
		}
		if slot.CommitLen != loaded.WCBLength {
			return nil, werr.Newf(werr.Corrupt, "superblock length for generation %d does not match the commit record", maxVisible)
		}
	}

	state, loadNotes, err := loadStateBounded(root, loaded.Hash, loaded.Generation, maxVisible)
	if err != nil {
		return nil, err
	}
	notes := append([]string(nil), view.Notes...)
	notes = append(notes, loadNotes...)
	return &Recovery{
		Head: loaded.Hash, Generation: loaded.Generation, State: state,
		Notes: notes, HighestFileGeneration: loaded.Generation,
	}, nil
}

// loadStateBounded is generation-addressed bounded replay from headHash.
//
// Unlike LoadStateAt, it never scans the commit directory and never decodes
// more than the chain window between the head and the nearest usable
// checkpoint:
//
//  1. Read commits/<headGeneration>.commit directly, require its declared
//     generation to equal the path generation, and require its identity hash to
//     equal headHash.
//  2. Walk parent down one generation at a time (commits/<gen-1>.commit),
//     requiring every loaded commit's hash to equal the child's declared parent
//     hash and every generation to be exactly one lower.
//  3. Stop at the newest commit that carries a checkpoint whose state manifest
//     is readable and declares the same generation. Apply that checkpoint state
//     and then the commits above it exactly as LoadStateAt does.
//  4. Validate the catalog (manifest identity, chunk existence and length).
//
// Any surprise - a missing file, a generation that disagrees with its name, a
// hash or parent mismatch, a non-contiguous generation, an unreadable or
// mislabelled checkpoint - is returned as an error. The caller must then fall
// back to LoadStateAt; this function never accepts a shorter or partial chain
// as a substitute. The walk is bounded by headGeneration steps and by
// maxGeneration, so a hostile chain cannot force unbounded work.
func loadStateBounded(root string, headHash model.Hash32, headGeneration, maxGeneration uint64) (*model.State, []string, error) {
	if headGeneration == 0 {
		return nil, nil, werr.Newf(werr.Corrupt, "bounded replay requires a non-zero head generation")
	}
	if headGeneration > maxGeneration {
		return nil, nil, werr.Newf(werr.Corrupt, "bounded replay head generation %d exceeds max_generation %d", headGeneration, maxGeneration)
	}

	// Newest-first window. It holds only the head-to-checkpoint commits, so its
	// length is bounded by the checkpoint interval when a checkpoint exists.
	chain := make([]LoadedCommit, 0)
	cursorHash := headHash
	cursorGeneration := headGeneration
	seen := make(map[model.Hash32]bool)
	var steps uint64
	var checkpointState *model.State
	var resumedAtCheckpoint uint64
	var resumed bool

	for {
		if seen[cursorHash] {
			return nil, nil, werr.Newf(werr.Corrupt, "commit parent chain contains a cycle")
		}
		seen[cursorHash] = true
		expected := cursorGeneration
		loaded, err := LoadCommitFile(CommitPath(root, cursorGeneration), &expected)
		if err != nil {
			return nil, nil, err
		}
		if loaded.Hash != cursorHash {
			return nil, nil, werr.Newf(werr.Corrupt, "commit %s hashes to %s but the child or superblock declares %s",
				CommitPath(root, cursorGeneration), loaded.Hash.Hex(), cursorHash.Hex())
		}
		steps++
		if steps > headGeneration {
			return nil, nil, werr.Newf(werr.Corrupt, "bounded commit walk exceeded its %d-generation bound", headGeneration)
		}

		if loaded.Commit.Checkpoint != nil {
			// A checkpoint that cannot be verified is not silently ignored
			// here: the caller replays through the full path instead.
			state, err := ReadStateManifest(root, *loaded.Commit.Checkpoint)
			if err != nil {
				return nil, nil, err
			}
			if state.Generation != loaded.Generation {
				return nil, nil, werr.Newf(werr.Corrupt, "checkpoint %s in generation %d declares generation %d",
					loaded.Commit.Checkpoint.Hex(), loaded.Generation, state.Generation)
			}
			chain = append(chain, loaded)
			checkpointState = state
			resumedAtCheckpoint = loaded.Generation
			resumed = true
			break
		}

		parent := loaded.Commit.Parent
		chain = append(chain, loaded)
		if parent == nil {
			break
		}
		if cursorGeneration == 0 {
			return nil, nil, werr.Newf(werr.Corrupt, "commit chain descends below generation 1")
		}
		cursorHash = *parent
		cursorGeneration--
	}
	// reverse newest-first into oldest-first
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}

	// Mirror the structural checks LoadStateAt performs on the materialised
	// window. The window either starts at generation 1 or at a verified
	// checkpoint, so nothing below it is needed to replay state.
	for i := 0; i+1 < len(chain); i++ {
		if chain[i+1].Generation <= chain[i].Generation {
			return nil, nil, werr.Newf(werr.Corrupt, "commit generations do not increase along the parent chain")
		}
		expectedParent := chain[i].Hash
		if chain[i+1].Commit.Parent == nil || *chain[i+1].Commit.Parent != expectedParent {
			return nil, nil, werr.Newf(werr.Corrupt, "commit parent hash does not match the previous commit")
		}
	}
	if !resumed {
		if len(chain) == 0 || chain[0].Generation != 1 {
			return nil, nil, werr.Newf(werr.Corrupt, "commit chain does not start at generation 1")
		}
		if chain[0].Commit.Parent != nil {
			return nil, nil, werr.Newf(werr.Corrupt, "generation 1 has a parent")
		}
	}

	state := model.NewState()
	for _, loaded := range chain {
		if loaded.Commit.Checkpoint != nil {
			if checkpointState == nil {
				return nil, nil, werr.Newf(werr.Corrupt, "commit window carries an unverified checkpoint")
			}
			state = checkpointState
			checkpointState = nil
			continue
		}
		if err := state.ApplyOps(loaded.Commit.Ops); err != nil {
			return nil, nil, werr.Newf(werr.Corrupt, "generation %d ops cannot be applied: %s", loaded.Generation, err)
		}
		state.Generation = loaded.Generation
	}

	if err := ValidateCatalog(root, state); err != nil {
		return nil, nil, err
	}
	// Honest recovery note: a bounded open does not enumerate commit files below
	// the checkpoint. The checkpoint state is hash-verified and its generation is
	// matched, so the recovered state is exact for the head; but a gap in older
	// history is not detected here. verify --full still enumerates every commit
	// file and reports such gaps.
	var notes []string
	if resumed {
		notes = append(notes, "bounded replay resumed from the checkpoint at generation "+
			itoa(resumedAtCheckpoint)+"; commit files below it were not enumerated")
	}
	return state, notes, nil
}

// AllCommits lists every valid parsed commit file up to maxGeneration. It
// always enumerates the commit directory; verify --full and GC roots rely on
// it and must never inherit the bounded open's window.
func AllCommits(root string, maxGeneration uint64) ([]LoadedCommit, error) {
	files, err := ScanCommitFiles(root)
	if err != nil {
		return nil, err
	}
	out := make([]LoadedCommit, 0, len(files))
	for generation, path := range files {
		if generation > maxGeneration {
			continue
		}
		expected := generation
		loaded, err := LoadCommitFile(path, &expected)
		if err != nil {
			continue
		}
		out = append(out, loaded)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Generation < out[j].Generation })
	return out, nil
}

// ReadRange assembles a byte range from a manifest, verifying every chunk or
// codec chunk it touches. When verifyWhole is true and the range is the whole
// file, the whole-content hash is verified too. v1 and v2 `kind:"raw"`
// manifests read through the chunk path; v2 `kind:"codec"` manifests decode
// the named frame.
func ReadRange(root string, manifest model.Manifest, offset, length uint64, verifyWhole bool) ([]byte, error) {
	return readManifestRange(root, nil, manifest, offset, length, verifyWhole)
}

// itoa formats a generation for recovery notes.
func itoa(v uint64) string {
	return model.FormatU64(v)
}
