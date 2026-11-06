package store

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	weftcontext "github.com/infinityabundance/WeftCodec-Go/context"
	"github.com/infinityabundance/WeftCodec-Go/hash"
	"github.com/infinityabundance/WeftCodec-Go/limits"
	"github.com/infinityabundance/WeftFS-Go/auth"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// VerifyProblem is one verification finding.
type VerifyProblem struct {
	Class  string
	Detail string
}

// VerifyReport is the result of Verify.
type VerifyReport struct {
	OK                  bool
	Full                bool
	Generation          uint64
	Commit              *model.Hash32
	CheckedCommits      uint64
	CheckedObjects      uint64
	CheckedManifests    uint64
	CheckedChunks       uint64
	CheckedContextRoots uint64
	CheckedCausal       uint64
	// CheckedRepresentations counts codec representations fully decoded and
	// re-hashed by Verify(true).
	CheckedRepresentations uint64
	CheckedCapabilities    uint64
	// CheckedQuotaCommits counts commits replayed by Verify(true)'s quota
	// assertion check.
	CheckedQuotaCommits uint64
	RejectedGenerations []uint64
	Problems            []VerifyProblem
}

func (r *VerifyReport) problem(class, detail string) {
	r.Problems = append(r.Problems, VerifyProblem{Class: class, Detail: detail})
}

// Verify checks the superblock, commit chain, manifests, and (when full)
// every chunk and whole-file content hash. It operates on disk, so it is valid
// for read-only stores and after recovery fell back.
func (s *Store) Verify(full bool) (*VerifyReport, error) {
	report := &VerifyReport{Full: full, Generation: s.generation, Commit: hashPtr(s.head)}

	view, err := ReadSuperblock(s.root)
	if err != nil {
		return nil, err
	}
	for _, note := range view.Notes {
		report.problem(string(werr.Corrupt), note)
	}
	validSlots := make([]SuperblockSlot, 0, 2)
	slotByGen := make(map[uint64]SuperblockSlot, 2)
	var maxVisible uint64
	for index := 0; index < 2; index++ {
		if !view.Valid[index] {
			continue
		}
		slot := view.Slots[index]
		validSlots = append(validSlots, slot)
		slotByGen[slot.Generation] = slot
		if slot.Generation > maxVisible {
			maxVisible = slot.Generation
		}
	}
	if len(validSlots) == 0 {
		report.problem(string(werr.Corrupt), "no valid superblock slot")
	}

	files, err := ScanCommitFiles(s.root)
	if err != nil {
		return nil, err
	}
	generations := make([]uint64, 0, len(files))
	for generation := range files {
		generations = append(generations, generation)
	}
	sort.Slice(generations, func(i, j int) bool { return generations[i] < generations[j] })
	for _, generation := range generations {
		path := files[generation]
		expected := generation
		loaded, err := LoadCommitFile(path, &expected)
		if err != nil {
			report.problem(string(werr.ClassOf(err)), "commit file "+path+": "+err.Error())
			continue
		}
		report.CheckedCommits++
		if generation > maxVisible {
			report.problem(string(werr.Corrupt), "commit file for generation "+itoa(generation)+
				" exists above the highest published superblock generation "+itoa(maxVisible))
		}
		if slot, ok := slotByGen[generation]; ok {
			if slot.Commit != loaded.Hash {
				report.problem(string(werr.Corrupt), "superblock hash for generation "+itoa(generation)+
					" does not match the commit record")
			}
			if slot.CommitLen != loaded.WCBLength {
				report.problem(string(werr.Corrupt), "superblock length for generation "+itoa(generation)+
					" does not match the commit record")
			}
		}
	}

	recovered, err := Recover(s.root)
	if err != nil {
		report.problem(string(werr.ClassOf(err)), "recovery failed: "+err.Error())
	} else {
		report.RejectedGenerations = recovered.Rejected
		for _, note := range recovered.Notes {
			if strings.Contains(note, "rejected:") {
				report.problem(string(werr.Corrupt), note)
			}
		}
		if recovered.Generation < maxVisible {
			report.problem(string(werr.Corrupt), "recovery selected generation "+itoa(recovered.Generation)+
				" but the superblock published "+itoa(maxVisible))
			// Recovery validated catalog integrity strictly and fell back. Verify
			// the highest published state too, without the catalog gate, so a
			// representation decode failure names the affected object instead of
			// only the resulting generation gap.
			if path, ok := files[maxVisible]; ok {
				expected := maxVisible
				if loaded, loadErr := LoadCommitFile(path, &expected); loadErr == nil {
					if highest, loadNotes, stateErr := LoadStateAt(s.root, loaded.Hash, maxVisible, false); stateErr == nil {
						for _, note := range loadNotes {
							report.problem(string(werr.Corrupt), note)
						}
						s.verifyState(highest, full, report)
						s.verifyContextState(highest, full, report)
					}
				}
			}
		}
		state, notes, err := LoadStateAt(s.root, recovered.Head, maxVisible, true)
		if err != nil {
			report.problem(string(werr.ClassOf(err)), "state replay failed: "+err.Error())
		} else {
			for _, note := range notes {
				report.problem(string(werr.Corrupt), note)
			}
			s.verifyState(state, full, report)
			s.verifyContextState(state, full, report)
		}
	}

	commits, err := AllCommits(s.root, maxVisible)
	if err != nil {
		return nil, err
	}
	for _, commit := range commits {
		if commit.Commit.Checkpoint == nil {
			continue
		}
		report.CheckedManifests++
		checkpointState, err := ReadStateManifest(s.root, *commit.Commit.Checkpoint)
		if err != nil {
			report.problem(string(werr.ClassOf(err)), "checkpoint "+commit.Commit.Checkpoint.Hex()+": "+err.Error())
			continue
		}
		if checkpointState.Generation != commit.Generation {
			report.problem(string(werr.Corrupt), "checkpoint "+commit.Commit.Checkpoint.Hex()+
				" declares generation "+itoa(checkpointState.Generation)+
				" but is named by generation "+itoa(commit.Generation))
		}
	}

	// Snapshot pointer files are caches; report mismatches, not absence.
	for name, hash := range s.state.Snapshots {
		path := filepath.Join(s.root, "refs", "snapshots", name)
		text, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		parsed, err := parseHashHex(strings.TrimSpace(string(text)))
		if err != nil || parsed != hash {
			report.problem(string(werr.Corrupt), "snapshot pointer `"+name+"` does not match state")
		}
	}

	// A present-but-unusable quota record is reported: enforcement fails closed,
	// so verification must not claim the store is fully healthy.
	if s.quota.RecordPresent && !s.quota.Valid {
		detail := s.quota.Reason
		if detail == "" {
			detail = "no reason recorded"
		}
		report.problem(string(werr.Corrupt), "quota state is unusable: "+detail)
	}

	// Full verification replays the chain and validates every committed usage
	// assertion against the recomputed admission totals.
	if full && (s.quota.enforced() || s.quota.UsageCommitted) {
		usage, _, commits, err := s.replayQuotaUsageWithCount()
		if err != nil {
			report.problem(string(werr.ClassOf(err)), "quota replay: "+err.Error())
		} else {
			report.CheckedQuotaCommits = commits
			if !quotaUsageEqual(usage, s.quota.Usage) {
				report.problem(string(werr.Corrupt), "committed quota usage disagrees with in-memory counters")
			}
		}
	}

	report.OK = len(report.Problems) == 0
	return report, nil
}

func (s *Store) verifyContextState(state *model.State, full bool, report *VerifyReport) {
	lim := limits.Default()
	root, ok := state.Objects[model.RootID]
	if !ok {
		report.problem(string(werr.Corrupt), "context verification: namespace root is missing")
		return
	}
	principal := auth.New(root.UID, root.GID, nil)
	now := s.nowNS()

	for _, relation := range state.Relations {
		if !isCapabilityRelation(relation) {
			continue
		}
		target, ok := relationTargetText(relation)
		if !ok {
			report.problem(string(werr.Corrupt), "capability relation target is not text")
			continue
		}
		hashValue, err := parseHashHex(target)
		if err != nil {
			report.problem(string(werr.Corrupt), "capability target is not a hash")
			continue
		}
		scope, err := s.LoadCapabilityAt(state, hashValue)
		if err != nil {
			report.problem(string(werr.ClassOf(err)), "capability "+hashValue.Hex()+": "+err.Error())
			continue
		}
		report.CheckedCapabilities++
		id, err := scope.ID()
		if err != nil || id != hashValue {
			report.problem(string(werr.Corrupt), "stored capability hash does not match its record")
		}
	}

	contexts, err := s.ListContextRootsAt(state)
	if err != nil {
		report.problem(string(werr.ClassOf(err)), "context-root records: "+err.Error())
		return
	}
	for _, stored := range contexts {
		report.CheckedContextRoots++
		id, err := stored.Root.ID()
		if err != nil || id != stored.ContextRootID {
			report.problem(string(werr.Corrupt), "context root `"+stored.Name+"` id does not match its record")
			continue
		}
		if _, err := s.StateAt(stored.Root.Snapshot); err != nil {
			report.problem("SnapshotMissing", "context root `"+stored.Name+"` pins an unavailable snapshot: "+err.Error())
			continue
		}
		if !full {
			if stored.Root.CapabilityHash != nil {
				if _, err := s.LoadCapabilityAt(state, *stored.Root.CapabilityHash); err == nil {
					report.CheckedCapabilities++
				}
			}
			continue
		}
		var capability *auth.Capability
		if stored.Root.CapabilityHash != nil {
			scope, err := s.LoadCapabilityAt(state, *stored.Root.CapabilityHash)
			if err != nil {
				report.problem("CapabilityMissing", "context root `"+stored.Name+"` binds an unavailable capability: "+err.Error())
				continue
			}
			capability, err = auth.NewCapability(scope)
			if err != nil {
				report.problem(string(werr.ClassOf(err)), "context root `"+stored.Name+"`: "+err.Error())
				continue
			}
		}
		resolved, err := s.ResolveContextAt(state, stored.Name, capability, principal, lim, now)
		if err != nil {
			report.problem(string(werr.ClassOf(err)), "context root `"+stored.Name+"` resolution failed: "+err.Error())
			continue
		}
		if resolved.Resolution.SelectorID != stored.Root.SelectorID ||
			resolved.Resolution.SnapshotID != stored.Root.Snapshot ||
			resolved.Stored.ContextRootID != stored.ContextRootID {
			report.problem(string(werr.Corrupt), "context root `"+stored.Name+"` resolution does not reproduce its recorded ids")
		}
	}

	for _, id := range model.SortHashKeys(state.Objects) {
		record := state.Objects[id]
		closure, err := model.ObjectCausalClosure(record)
		if err != nil {
			report.problem(string(werr.ClassOf(err)), "object "+id.Hex()+" causal attrs: "+err.Error())
			continue
		}
		if closure == nil {
			continue
		}
		report.CheckedCausal++
		if !full {
			continue
		}
		causalHash, err := closure.ID()
		if err != nil {
			report.problem(string(werr.Corrupt), "object "+id.Hex()+" causal hash: "+err.Error())
			continue
		}
		bytesValue, err := ReadBlobVerified(s.root, BlobManifest, causalHash, hash.DomainCausal)
		if err != nil {
			report.problem(string(werr.ClassOf(err)), "object "+id.Hex()+" causal closure blob: "+err.Error())
			continue
		}
		storedClosure, err := weftcontext.CausalClosureFromCanonicalBytes(bytesValue, lim)
		if err != nil || !storedClosure.Equal(closure) {
			report.problem(string(werr.Corrupt), "object "+id.Hex()+" causal closure blob disagrees with its attrs")
		}
	}
}

func (s *Store) verifyState(state *model.State, full bool, report *VerifyReport) {
	ids := model.SortHashKeys(state.Objects)
	for _, id := range ids {
		record := state.Objects[id]
		if record.Kind != model.KindFile {
			continue
		}
		report.CheckedObjects++
		manifest, err := ReadManifest(s.root, record.Content)
		if err != nil {
			report.problem(string(werr.ClassOf(err)), "manifest for object "+id.Hex()+": "+err.Error())
			continue
		}
		report.CheckedManifests++
		if manifest.Size != record.Size {
			report.problem(string(werr.Corrupt), "object "+id.Hex()+" size disagrees with manifest")
		}
		if manifest.Representation != nil && manifest.Representation.Kind == model.RepresentationOverlay {
			contentRoot := record.Content
			table, tableErr := overlayChunkTable(s.root, record.Content, manifest,
				manifest.Representation.Overlay, 0, make(map[model.Hash32]struct{}))
			if tableErr != nil {
				report.problem(string(werr.ClassOf(tableErr)),
					"overlay representation for object "+id.Hex()+" manifest "+record.Content.Hex()+": "+tableErr.Error())
				continue
			}
			if full {
				if _, err := readManifestRange(s.root, &contentRoot, manifest, 0, manifest.Size, true); err != nil {
					report.problem(string(werr.ClassOf(err)),
						"overlay representation for object "+id.Hex()+" manifest "+record.Content.Hex()+": "+err.Error())
				} else {
					report.CheckedRepresentations++
					report.CheckedChunks += uint64(len(table))
				}
			}
			continue
		}
		if manifest.Representation != nil &&
			(manifest.Representation.Kind == model.RepresentationCodec ||
				manifest.Representation.Kind == model.RepresentationTensor) {
			if full {
				frame := "<none>"
				if manifest.Representation.Frame != nil {
					frame = manifest.Representation.Frame.Hex()
				}
				kind := manifest.Representation.Kind
				contentRoot := record.Content
				if _, err := readManifestRange(s.root, &contentRoot, manifest, 0, manifest.Size, true); err != nil {
					report.problem(string(werr.ClassOf(err)),
						string(kind)+" representation for object "+id.Hex()+" manifest "+record.Content.Hex()+" frame "+frame+": "+err.Error())
				} else {
					report.CheckedRepresentations++
				}
			}
			continue
		}
		if !full {
			continue
		}
		capacity, err := checkedSize(manifest.Size)
		if err != nil {
			report.problem(string(werr.ClassOf(err)), "object "+id.Hex()+": "+err.Error())
			continue
		}
		merkle := manifest.Identity == model.ContentIdentityMerkleV1
		var assembled []byte
		if !merkle {
			assembled = make([]byte, 0, capacity)
		}
		leaves := make([]model.ChunkRef, 0, len(manifest.Chunks))
		for index, chunk := range manifest.Chunks {
			report.CheckedChunks++
			bytesValue, err := ReadBlobVerified(s.root, BlobObject, chunk.Hash, model.DomainChunk)
			if err != nil {
				report.problem(string(werr.ClassOf(err)), "chunk "+itoa(uint64(index))+" ("+chunk.Hash.Hex()+"): "+err.Error())
				continue
			}
			if uint64(len(bytesValue)) != chunk.Len {
				report.problem(string(werr.Corrupt), "chunk "+itoa(uint64(index))+" length disagrees with manifest")
			}
			if merkle {
				leaves = append(leaves, model.ChunkRef{Hash: chunk.Hash, Len: chunk.Len})
			} else {
				assembled = append(assembled, bytesValue...)
			}
		}
		if merkle {
			if model.MerkleRootChunks(leaves) != manifest.ContentHash {
				report.problem(string(werr.Corrupt), "object "+id.Hex()+" merkle content root mismatch")
			}
		} else if uint64(len(assembled)) == manifest.Size && model.ContentHash(assembled) != manifest.ContentHash {
			report.problem(string(werr.Corrupt), "object "+id.Hex()+" whole-content hash mismatch")
		}
	}
}

// RegionVerification reports the outcome of VerifyContentRegion.
type RegionVerification struct {
	ContentRoot    model.Hash32
	ChunksVerified int
	BytesVerified  uint64
}

// VerifyContentRegion verifies only the chunks a range touches for a
// `weft.manifest.v3` file.
//
// contentRoot is the store's content root (the manifest id stored in
// ObjectRecord.Content), matching every other ReadContent entry point. The
// manifest's ContentHash is the Merkle root and is returned in the report.
// The touched blobs are re-hashed from their bytes, their lengths are checked,
// and the root is recomputed from all manifest chunk hashes. No explicit
// sibling table is needed: the manifest carries every leaf preimage.
//
// A whole-file (v1/v2) content root is rejected with InvalidArgument; use
// Verify with full=true for those. A tampered blob or hash names the chunk
// index.
func (s *Store) VerifyContentRegion(contentRoot model.Hash32, offset, length uint64) (RegionVerification, error) {
	manifest, err := ReadManifest(s.root, contentRoot)
	if err != nil {
		return RegionVerification{}, err
	}
	if manifest.Identity != model.ContentIdentityMerkleV1 {
		return RegionVerification{}, werr.Newf(werr.InvalidArgument,
			"verify_region requires a weft.manifest.v3 Merkle content root")
	}
	declared := model.MerkleRootChunks(manifest.Chunks)
	if declared != manifest.ContentHash {
		return RegionVerification{}, werr.Newf(werr.Corrupt,
			"merkle content_root does not match the manifest chunk hashes")
	}
	if offset >= manifest.Size || length == 0 {
		return RegionVerification{ContentRoot: declared}, nil
	}
	end := offset + length
	if end < offset || end > manifest.Size {
		end = manifest.Size
	}
	var cursor uint64
	report := RegionVerification{ContentRoot: declared}
	for index, chunk := range manifest.Chunks {
		chunkStart := cursor
		chunkEnd := cursor + chunk.Len
		if chunkEnd < cursor {
			return RegionVerification{}, werr.Newf(werr.Corrupt, "chunk offset overflow")
		}
		cursor = chunkEnd
		if chunkEnd <= offset || chunkStart >= end {
			continue
		}
		bytesValue, err := ReadBlobVerified(s.root, BlobObject, chunk.Hash, model.DomainChunk)
		if err != nil {
			return RegionVerification{}, werr.Newf(werr.Corrupt, "chunk %d (%s): %s", index, chunk.Hash.Hex(), err.Error())
		}
		if uint64(len(bytesValue)) != chunk.Len {
			return RegionVerification{}, werr.Newf(werr.Corrupt, "chunk %d length disagrees with manifest", index)
		}
		report.ChunksVerified++
		report.BytesVerified += chunk.Len
	}
	return report, nil
}
