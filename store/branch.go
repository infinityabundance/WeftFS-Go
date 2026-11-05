package store

// Branching time travel (P5a, part 2).
//
// A snapshot branch is a second name for an immutable commit: history is never
// rewritten, so later writes cannot move the source. A merge is deliberately a
// *union* of path sets, not a three-way content merge: a path present in both
// inputs, or already at the live head, must have identical content or the merge
// fails closed with `Conflict` naming the path.

import (
	"fmt"
	"sort"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// MaxMergePaths bounds one branch's enumerated path set.
const MaxMergePaths = 1_000_000

// MergeReport is the result of a union merge.
type MergeReport struct {
	Left         model.Hash32
	Right        model.Hash32
	Paths        uint64
	AddedObjects uint64
	AddedEntries uint64
	Head         model.Hash32
	Generation   uint64
}

type pathNode struct {
	ID     model.Hash32
	Record model.ObjectRecord
}

// SnapshotBranch points a new snapshot name at an existing snapshot's commit.
func (s *Store) SnapshotBranch(source, name string) (model.Hash32, error) {
	if err := s.requireWritable(); err != nil {
		return model.Hash32{}, err
	}
	if err := model.ValidateSnapshotName(name); err != nil {
		return model.Hash32{}, err
	}
	if _, exists := s.state.Snapshots[name]; exists {
		return model.Hash32{}, werr.Newf(werr.Exists, "snapshot name already exists")
	}
	commit, err := s.resolveCommitRef(source)
	if err != nil {
		return model.Hash32{}, err
	}
	if _, err := s.commitOps([]model.Op{model.SetSnapshotOp{SnapshotName: name, Commit: commit}}, false); err != nil {
		return model.Hash32{}, err
	}
	if err := s.writeSnapshotPointer(name, commit); err != nil {
		return model.Hash32{}, err
	}
	return commit, nil
}

// resolveCommitRef resolves a snapshot name or a published commit hex.
func (s *Store) resolveCommitRef(ref string) (model.Hash32, error) {
	if commit, ok := s.state.Snapshots[ref]; ok {
		return commit, nil
	}
	hash, err := parseHashHex(ref)
	if err != nil {
		return model.Hash32{}, werr.Newf(werr.NotFound, "no such snapshot or commit")
	}
	published, err := s.isPublishedAncestor(hash)
	if err != nil {
		return model.Hash32{}, err
	}
	if !published {
		return model.Hash32{}, werr.Newf(werr.NotFound, "commit is not on the published parent chain")
	}
	return hash, nil
}

// MergeBranches union-merges two snapshot refs (or commits) onto the live head.
func (s *Store) MergeBranches(left, right string) (MergeReport, error) {
	if err := s.requireWritable(); err != nil {
		return MergeReport{}, err
	}
	leftCommit, err := s.resolveCommitRef(left)
	if err != nil {
		return MergeReport{}, err
	}
	rightCommit, err := s.resolveCommitRef(right)
	if err != nil {
		return MergeReport{}, err
	}
	leftState, err := s.StateAt(leftCommit)
	if err != nil {
		return MergeReport{}, err
	}
	rightState, err := s.StateAt(rightCommit)
	if err != nil {
		return MergeReport{}, err
	}
	headPaths, err := collectStatePaths(s.state)
	if err != nil {
		return MergeReport{}, err
	}
	leftPaths, err := collectStatePaths(leftState)
	if err != nil {
		return MergeReport{}, err
	}
	rightPaths, err := collectStatePaths(rightState)
	if err != nil {
		return MergeReport{}, err
	}

	// Reject overlapping content before writing any blob or commit.
	for path, node := range leftPaths {
		if other, ok := rightPaths[path]; ok && !samePathContent(node, other) {
			return MergeReport{}, werr.Newf(werr.Conflict,
				"path `%s` has different content in the two branches", path)
		}
	}
	for path, node := range leftPaths {
		if existing, ok := headPaths[path]; ok && !samePathContent(existing, node) {
			return MergeReport{}, werr.Newf(werr.Conflict,
				"path `%s` already exists with different content", path)
		}
	}
	for path, node := range rightPaths {
		if existing, ok := headPaths[path]; ok && !samePathContent(existing, node) {
			return MergeReport{}, werr.Newf(werr.Conflict,
				"path `%s` already exists with different content", path)
		}
	}

	union := map[string]pathNode{}
	for path, node := range leftPaths {
		union[path] = node
	}
	for path, node := range rightPaths {
		if _, ok := union[path]; !ok {
			union[path] = node
		}
	}
	paths := make([]string, 0, len(union))
	for path := range union {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	var ops []model.Op
	merged := map[string]model.Hash32{"/": model.RootID}
	newIDs := map[model.Hash32]bool{}
	var addedObjects, addedEntries uint64
	for _, path := range paths {
		if path == "/" {
			continue
		}
		node := union[path]
		if existing, ok := headPaths[path]; ok {
			merged[path] = existing.ID
			continue
		}
		parentPath, name, err := splitPath(path)
		if err != nil {
			return MergeReport{}, err
		}
		parentID, ok := merged[parentPath]
		if !ok {
			return MergeReport{}, werr.Newf(werr.Conflict,
				"merge would place `%s` under a missing parent", path)
		}
		parent, ok := s.state.Objects[parentID]
		if !ok {
			return MergeReport{}, werr.Newf(werr.Corrupt, "merged parent object is missing")
		}
		if parent.Kind != model.KindDir {
			return MergeReport{}, werr.Newf(werr.Conflict,
				"merge needs `%s` to be a directory", parentPath)
		}
		record := node.Record.Clone()
		if existing, ok := s.state.Objects[record.ID]; ok {
			if !objectRecordsEqual(existing, record) {
				seed := append([]byte("weft/merge/v1"), []byte(path)...)
				seed = append(seed, record.Content.Bytes()...)
				record.ID = model.ObjectIDFromSeed(seed)
				if newIDs[record.ID] {
					return MergeReport{}, werr.Newf(werr.Corrupt, "merge id derivation collided")
				}
				newIDs[record.ID] = true
			}
		} else {
			newIDs[record.ID] = true
		}
		if _, ok := s.state.Objects[record.ID]; !ok {
			ops = append(ops, model.PutObjectOp{Record: record})
			ops = append(ops, model.SetTipOp{Object: record.ID, Version: record.Version})
			addedObjects++
		}
		entryID, err := model.DeriveEntryID(parentID, []byte(name))
		if err != nil {
			return MergeReport{}, err
		}
		if _, exists := s.state.Entries[entryID]; !exists {
			ops = append(ops, model.PutEntryOp{Record: model.EntryRecord{
				ID: entryID, Parent: parentID, Name: []byte(name), Target: record.ID,
			}})
			addedEntries++
		}
		merged[path] = record.ID
	}

	head := s.head
	if len(ops) > 0 {
		head, err = s.commitOps(ops, false)
		if err != nil {
			return MergeReport{}, err
		}
	}
	pathsCount := uint64(0)
	if len(union) > 1 {
		pathsCount = uint64(len(union) - 1)
	}
	return MergeReport{
		Left: leftCommit, Right: rightCommit, Paths: pathsCount,
		AddedObjects: addedObjects, AddedEntries: addedEntries,
		Head: head, Generation: s.generation,
	}, nil
}

func collectStatePaths(state *model.State) (map[string]pathNode, error) {
	root, ok := state.Objects[model.RootID]
	if !ok {
		return nil, werr.Newf(werr.Corrupt, "state has no namespace root")
	}
	out := map[string]pathNode{"/": {ID: model.RootID, Record: root.Clone()}}
	type item struct {
		path string
		id   model.Hash32
	}
	queue := []item{{path: "/", id: model.RootID}}
	visited := map[model.Hash32]bool{model.RootID: true}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		var children []model.EntryRecord
		for _, entry := range state.Entries {
			if entry.Parent == current.id {
				children = append(children, entry)
			}
		}
		sort.Slice(children, func(i, j int) bool {
			return string(children[i].Name) < string(children[j].Name)
		})
		for _, entry := range children {
			record, ok := state.Objects[entry.Target]
			if !ok {
				return nil, werr.Newf(werr.Corrupt, "directory entry targets a missing object")
			}
			path := current.path
			if path != "/" {
				path += "/"
			}
			path += string(entry.Name)
			if len(out) >= MaxMergePaths {
				return nil, werr.Newf(werr.LimitExceeded,
					"branch has more than %d paths", MaxMergePaths)
			}
			out[path] = pathNode{ID: entry.Target, Record: record.Clone()}
			if record.Kind == model.KindDir && !visited[entry.Target] {
				visited[entry.Target] = true
				queue = append(queue, item{path: path, id: entry.Target})
			}
		}
	}
	return out, nil
}

func samePathContent(left, right pathNode) bool {
	if left.Record.Kind != right.Record.Kind {
		return false
	}
	switch left.Record.Kind {
	case model.KindDir:
		return true
	case model.KindFile:
		return left.Record.Content == right.Record.Content && left.Record.Size == right.Record.Size
	case model.KindSymlink:
		leftTarget, leftOK := left.Record.SymlinkTarget()
		rightTarget, rightOK := right.Record.SymlinkTarget()
		return leftOK == rightOK && string(leftTarget) == string(rightTarget)
	default:
		return false
	}
}

func splitPath(path string) (string, string, error) {
	if path == "/" || path == "" {
		return "", "", werr.Newf(werr.InvalidArgument, "the root path has no name")
	}
	index := -1
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			index = i
			break
		}
	}
	if index < 0 {
		return "", "", werr.Newf(werr.Corrupt, "absolute path has no separator")
	}
	parent := path[:index]
	if parent == "" {
		parent = "/"
	}
	return parent, path[index+1:], nil
}

// FormatMergeReport is the human-readable CLI form.
func FormatMergeReport(report MergeReport) string {
	return fmt.Sprintf("paths=%d added_objects=%d added_entries=%d merged=%s generation=%d",
		report.Paths, report.AddedObjects, report.AddedEntries, report.Head.Hex(), report.Generation)
}
