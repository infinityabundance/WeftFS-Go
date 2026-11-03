package store

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

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
		if recovered.Generation < maxVisible {
			report.problem(string(werr.Corrupt), "recovery selected generation "+itoa(recovered.Generation)+
				" but the superblock published "+itoa(maxVisible))
		}
		state, notes, err := LoadStateAt(s.root, recovered.Head, maxVisible, true)
		if err != nil {
			report.problem(string(werr.ClassOf(err)), "state replay failed: "+err.Error())
		} else {
			for _, note := range notes {
				report.problem(string(werr.Corrupt), note)
			}
			s.verifyState(state, full, report)
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

	report.OK = len(report.Problems) == 0
	return report, nil
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
		if !full {
			continue
		}
		assembled := make([]byte, 0, int(manifest.Size))
		for _, chunk := range manifest.Chunks {
			report.CheckedChunks++
			bytesValue, err := ReadBlobVerified(s.root, BlobObject, chunk.Hash, model.DomainChunk)
			if err != nil {
				report.problem(string(werr.ClassOf(err)), "chunk "+chunk.Hash.Hex()+": "+err.Error())
				continue
			}
			if uint64(len(bytesValue)) != chunk.Len {
				report.problem(string(werr.Corrupt), "chunk "+chunk.Hash.Hex()+" length disagrees with manifest")
			}
			assembled = append(assembled, bytesValue...)
		}
		if uint64(len(assembled)) == manifest.Size && model.ContentHash(assembled) != manifest.ContentHash {
			report.problem(string(werr.Corrupt), "object "+id.Hex()+" whole-content hash mismatch")
		}
	}
}
