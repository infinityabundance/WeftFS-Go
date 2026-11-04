package store

import (
	"os"
	"sort"

	"github.com/infinityabundance/WeftCodec-Go/hash"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
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
}

// Recover selects the highest valid published generation. It never invents
// data and never deletes rejected generations.
func Recover(root string) (*Recovery, error) {
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

	files, err := ScanCommitFiles(root)
	if err != nil {
		return nil, err
	}
	candidates := make([]uint64, 0, len(files))
	for generation := range files {
		if generation <= maxVisible {
			candidates = append(candidates, generation)
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i] > candidates[j] })

	rejected := make([]uint64, 0)
	for slotGeneration := range slotByGen {
		if _, ok := files[slotGeneration]; !ok {
			notes = append(notes, "generation "+itoa(slotGeneration)+" rejected: published slot has no commit file")
			rejected = append(rejected, slotGeneration)
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
		state, loadNotes, err := LoadStateAt(root, loaded.Hash, maxVisible, true)
		if err != nil {
			notes = append(notes, "generation "+itoa(generation)+" rejected: "+err.Error())
			rejected = append(rejected, generation)
			continue
		}
		notes = append(notes, loadNotes...)
		return &Recovery{
			Head: loaded.Hash, Generation: loaded.Generation, State: state,
			Rejected: rejected, Notes: notes,
		}, nil
	}
	return nil, werr.Newf(werr.Corrupt, "no valid generation at or below %d; rejected %v", maxVisible, rejected)
}

// AllCommits lists every valid parsed commit file up to maxGeneration.
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

// ReadRange assembles a byte range from a manifest, verifying every chunk it
// touches. When verifyWhole is true and the range is the whole file, the
// whole-content hash is verified too.
func ReadRange(root string, manifest model.Manifest, offset, length uint64, verifyWhole bool) ([]byte, error) {
	if manifest.Size > MaxFileBytes {
		return nil, werr.Newf(werr.LimitExceeded, "manifest size %d exceeds the %d-byte v1 bound", manifest.Size, MaxFileBytes)
	}
	if offset >= manifest.Size {
		return []byte{}, nil
	}
	end := offset + length
	if end < offset || end > manifest.Size {
		end = manifest.Size
	}
	capacity, err := checkedSize(end - offset)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, capacity)
	var cursor uint64
	for _, chunk := range manifest.Chunks {
		chunkStart := cursor
		chunkEnd := cursor + chunk.Len
		if chunkEnd < cursor {
			return nil, werr.Newf(werr.Corrupt, "chunk offset overflow")
		}
		cursor = chunkEnd
		if chunkEnd <= offset || chunkStart >= end {
			continue
		}
		bytesValue, err := ReadBlobVerified(root, BlobObject, chunk.Hash, model.DomainChunk)
		if err != nil {
			return nil, err
		}
		if uint64(len(bytesValue)) != chunk.Len {
			return nil, werr.Newf(werr.Corrupt, "chunk length disagrees with manifest")
		}
		localStart := uint64(0)
		if offset > chunkStart {
			localStart = offset - chunkStart
		}
		localEnd := end - chunkStart
		if localEnd > chunk.Len {
			localEnd = chunk.Len
		}
		out = append(out, bytesValue[localStart:localEnd]...)
	}
	if uint64(len(out)) != end-offset {
		return nil, werr.Newf(werr.Corrupt, "assembled range length mismatch")
	}
	if verifyWhole && offset == 0 && end == manifest.Size {
		if model.ContentHash(out) != manifest.ContentHash {
			return nil, werr.Newf(werr.Corrupt, "whole-content hash mismatch")
		}
	}
	return out, nil
}

// itoa formats a generation for recovery notes.
func itoa(v uint64) string {
	return model.FormatU64(v)
}
