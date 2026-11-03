package store

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// GCReport records one mark-and-sweep pass. Dry runs (the default) populate the
// candidate counts but never delete. Fields mirror the Rust reference report
// and add explicit reachable/unreachable byte and file counts.
type GCReport struct {
	Applied bool
	// MarkedManifests and MarkedChunks are the sizes of the reachable hash
	// sets, including hashes whose files are already missing.
	MarkedManifests uint64
	MarkedChunks    uint64
	// ReachableFiles/Bytes count marked files that exist on disk.
	ReachableFiles uint64
	ReachableBytes uint64
	// UnreachableFiles/Bytes count sweep candidates (after the grace gate).
	UnreachableFiles uint64
	UnreachableBytes uint64
	// Candidates and Deleted are store-relative slash-separated paths.
	Candidates   []string
	Deleted      []string
	DeletedFiles uint64
	DeletedBytes uint64
	// Retained counts marked files plus unmarked files kept by the grace gate.
	Retained      uint64
	GraceRetained uint64
	// RemovedOrphans lists unreferenced object records removed in a commit
	// (left behind by a crash while an unlinked object was pinned).
	RemovedOrphans []string
	Problems       []string
}

type gcCandidate struct {
	path string
	rel  string
	size uint64
}

// GC performs mark-and-sweep collection of unreachable chunks and manifests.
//
// Roots: the current state, every snapshot commit state, every checkpoint
// manifest named by any parseable commit (including valid but unpublished or
// rejected tail commits), and in-process content pins. Object pins are roots
// implicitly because their records remain in state until the final unpin.
//
// It is a no-op on a read-only store. Apply requires the exclusive writer lock
// that opening the store in ReadWrite mode already holds; a second writer is
// refused at open time with Busy. A dry run is the default.
func (s *Store) GC(apply bool) (GCReport, error) {
	report := GCReport{Applied: apply}
	if err := s.requireWritable(); err != nil {
		return report, err
	}
	if s.lock == nil {
		return report, werr.Newf(werr.Busy, "store writer lock is not held")
	}

	// An unlinked object record can survive a crash while an open handle pinned
	// it (pins are process-local and never persisted). `gc --apply` removes
	// those records in a commit; pinned and still-referenced records are never
	// touched. This runs before marking so the updated state is authoritative.
	if apply {
		orphans := s.orphanObjectIDs()
		if len(orphans) > 0 {
			ops := make([]model.Op, 0, len(orphans))
			for _, id := range orphans {
				ops = append(ops, model.DeleteObjectOp{ID: id})
			}
			if _, err := s.commitOps(ops, false); err != nil {
				return report, err
			}
			report.RemovedOrphans = make([]string, 0, len(orphans))
			for _, id := range orphans {
				report.RemovedOrphans = append(report.RemovedOrphans, id.Hex())
			}
		}
	}

	markedManifests := make(map[model.Hash32]struct{})
	markedChunks := make(map[model.Hash32]struct{})

	markState(s.root, s.state, markedManifests, markedChunks, &report.Problems)

	snapshotNames := make([]string, 0, len(s.state.Snapshots))
	for name := range s.state.Snapshots {
		snapshotNames = append(snapshotNames, name)
	}
	sort.Strings(snapshotNames)
	for _, name := range snapshotNames {
		commit := s.state.Snapshots[name]
		snapshotState, err := s.StateAt(commit)
		if err != nil {
			report.Problems = append(report.Problems,
				"snapshot "+name+" ("+commit.Hex()+") state is unreadable: "+err.Error())
			continue
		}
		markState(s.root, snapshotState, markedManifests, markedChunks, &report.Problems)
	}

	// Checkpoints are immutable evidence. They are roots even when the commit
	// that names them is a valid but unpublished (rejected) tail, so the scan
	// deliberately ignores the published generation ceiling.
	commits, err := AllCommits(s.root, ^uint64(0))
	if err != nil {
		return report, err
	}
	for _, commit := range commits {
		if commit.Commit.Checkpoint == nil {
			continue
		}
		checkpoint := *commit.Commit.Checkpoint
		markedManifests[checkpoint] = struct{}{}
		checkpointState, err := ReadStateManifest(s.root, checkpoint)
		if err != nil {
			report.Problems = append(report.Problems,
				"checkpoint "+checkpoint.Hex()+" is unreadable: "+err.Error())
			continue
		}
		markState(s.root, checkpointState, markedManifests, markedChunks, &report.Problems)
	}

	// Content pins held by open read handles are roots even after the object
	// record has been removed from state.
	contentPins := make([]model.Hash32, 0, len(s.contentPins))
	for content := range s.contentPins {
		contentPins = append(contentPins, content)
	}
	sort.Slice(contentPins, func(i, j int) bool { return contentPins[i].Less(contentPins[j]) })
	for _, content := range contentPins {
		markedManifests[content] = struct{}{}
		manifest, err := ReadManifest(s.root, content)
		if err != nil {
			report.Problems = append(report.Problems,
				"pinned content "+content.Hex()+" is unreadable: "+err.Error())
			continue
		}
		for _, chunk := range manifest.Chunks {
			markedChunks[chunk.Hash] = struct{}{}
		}
	}

	report.MarkedManifests = uint64(len(markedManifests))
	report.MarkedChunks = uint64(len(markedChunks))

	now := time.Now()
	grace := s.options.GCGraceSecs
	candidates := make([]gcCandidate, 0)
	manifestCandidates, err := collectUnmarked(s.root, "manifests", markedManifests, now, grace, &report)
	if err != nil {
		return report, err
	}
	candidates = append(candidates, manifestCandidates...)
	objectCandidates, err := collectUnmarked(s.root, "objects", markedChunks, now, grace, &report)
	if err != nil {
		return report, err
	}
	candidates = append(candidates, objectCandidates...)
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].rel < candidates[j].rel })

	report.UnreachableFiles = uint64(len(candidates))
	for _, candidate := range candidates {
		report.UnreachableBytes += candidate.size
		report.Candidates = append(report.Candidates, candidate.rel)
	}

	if apply {
		for _, candidate := range candidates {
			if err := os.Remove(candidate.path); err != nil {
				return report, werr.Wrap(werr.Io, err, "cannot delete %s", candidate.path)
			}
			report.Deleted = append(report.Deleted, candidate.rel)
			report.DeletedFiles++
			report.DeletedBytes += candidate.size
		}
	}
	return report, nil
}

// orphanObjectIDs returns object records that no entry, relation, or pin
// references. A stale tip alone does not retain a record: that is exactly the
// crash case Rust removes. The namespace root is never an orphan.
func (s *Store) orphanObjectIDs() []model.Hash32 {
	ids := model.SortHashKeys(s.state.Objects)
	out := make([]model.Hash32, 0)
	for _, id := range ids {
		if id == model.RootID || s.isObjectPinned(id) {
			continue
		}
		referenced := false
		for _, entry := range s.state.Entries {
			if entry.Target == id || entry.Parent == id {
				referenced = true
				break
			}
		}
		if !referenced {
			for _, relation := range s.state.Relations {
				if relation.Target.Object != nil && *relation.Target.Object == id {
					referenced = true
					break
				}
			}
		}
		if !referenced {
			out = append(out, id)
		}
	}
	return out
}

// markState marks the manifest and chunks of every file object in a state.
// Non-file objects carry a content digest that is not a manifest.
func markState(root string, state *model.State, manifests, chunks map[model.Hash32]struct{}, problems *[]string) {
	for _, id := range model.SortHashKeys(state.Objects) {
		record := state.Objects[id]
		if record.Kind != model.KindFile {
			continue
		}
		manifests[record.Content] = struct{}{}
		manifest, err := ReadManifest(root, record.Content)
		if err != nil {
			*problems = append(*problems,
				"cannot read manifest "+record.Content.Hex()+" for object "+id.Hex()+": "+err.Error())
			continue
		}
		for _, chunk := range manifest.Chunks {
			chunks[chunk.Hash] = struct{}{}
		}
	}
}

// collectUnmarked walks exactly <root>/<kind>/<shard>/<hash>. It never follows
// symlinks, only considers regular files, and applies the Rust grace rule: with
// grace_secs > 0 an unmarked file whose age is below the window is retained
// (a future mtime counts as age zero).
func collectUnmarked(root, kindDir string, marked map[model.Hash32]struct{}, now time.Time, graceSecs uint64, report *GCReport) ([]gcCandidate, error) {
	dir := filepath.Join(root, kindDir)
	shards, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, werr.Wrap(werr.Io, err, "cannot read %s", dir)
	}
	out := make([]gcCandidate, 0)
	for _, shard := range shards {
		shardPath := filepath.Join(dir, shard.Name())
		shardInfo, err := os.Lstat(shardPath)
		if err != nil {
			return nil, werr.Wrap(werr.Io, err, "cannot stat %s", shardPath)
		}
		if !shardInfo.IsDir() || shardInfo.Mode()&os.ModeSymlink != 0 {
			continue
		}
		files, err := os.ReadDir(shardPath)
		if err != nil {
			return nil, werr.Wrap(werr.Io, err, "cannot read %s", shardPath)
		}
		for _, file := range files {
			name := file.Name()
			path := filepath.Join(shardPath, name)
			info, err := os.Lstat(path)
			if err != nil {
				return nil, werr.Wrap(werr.Io, err, "cannot stat %s", path)
			}
			if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				continue
			}
			hash, ok := parseLowerHash(name)
			if !ok {
				report.Problems = append(report.Problems, "unrecognized blob filename "+path)
				continue
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				rel = path
			}
			rel = filepath.ToSlash(rel)
			if _, ok := marked[hash]; ok {
				report.ReachableFiles++
				report.ReachableBytes += uint64(info.Size())
				report.Retained++
				continue
			}
			if graceSecs > 0 {
				age := uint64(0)
				if now.After(info.ModTime()) {
					age = uint64(now.Sub(info.ModTime()) / time.Second)
				}
				if age < graceSecs {
					report.GraceRetained++
					report.Retained++
					continue
				}
			}
			out = append(out, gcCandidate{path: path, rel: rel, size: uint64(info.Size())})
		}
	}
	return out, nil
}

// parseLowerHash accepts exactly 64 lowercase hexadecimal characters, matching
// the Rust from_lower_hex blob-name rule.
func parseLowerHash(name string) (model.Hash32, bool) {
	var hash model.Hash32
	if len(name) != 64 {
		return hash, false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return hash, false
	}
	parsed, err := parseHashHex(name)
	if err != nil {
		return hash, false
	}
	return parsed, true
}
