package store

import (
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// Group commit (non-closure form).
//
// A group buffers the ops of several independent mutations and publishes them
// as exactly one durable commit. Mutations still apply to the live in-memory
// state immediately, so reads inside the group (and FUSE lookups) see them;
// nothing is durable or visible to a crashed/reopened process until
// CommitGroup publishes. This is the Go equivalent of the Rust
// `Store::begin_group` / `commit_group` / `abort_group` API and has the same
// durability rule: a crash yields the previous whole generation.

// groupJournal holds the pre-group value of every state key the open group has
// touched. A nil pointer means "absent before the group".
type groupJournal struct {
	objects   map[model.Hash32]*model.ObjectRecord
	entries   map[model.Hash32]*model.EntryRecord
	relations map[model.Hash32]*model.RelationRecord
	snapshots map[string]*model.Hash32
	tips      map[model.Hash32]*model.Hash32
}

func (j *groupJournal) empty() bool {
	return j.objects == nil && j.entries == nil && j.relations == nil &&
		j.snapshots == nil && j.tips == nil
}

// BeginGroup opens a group. Mutations buffer until CommitGroup or AbortGroup.
func (s *Store) BeginGroup() error {
	if err := s.requireWritable(); err != nil {
		return err
	}
	if s.groupDepth != 0 {
		return werr.Newf(werr.InvalidArgument, "group commit cannot be nested inside another group")
	}
	// The committed blob set must be captured while live state still equals it.
	if s.quota.enforced() {
		if err := s.ensureBlobIndex(); err != nil {
			return err
		}
	}
	s.groupDepth = 1
	s.pendingOps = nil
	s.groupForceCheckpoint = false
	s.groupUndo = groupJournal{}
	return nil
}

// GroupOpen reports whether a group is buffering.
func (s *Store) GroupOpen() bool { return s.groupDepth != 0 }

// CommitGroup publishes every buffered op as one commit and closes the group.
// With no buffered op it publishes nothing and returns the current head. On a
// publish error the pre-group state is restored and the group is closed.
func (s *Store) CommitGroup() (model.Hash32, error) {
	if s.groupDepth == 0 {
		return model.Hash32{}, werr.Newf(werr.InvalidArgument, "no group commit is open")
	}
	ops := s.pendingOps
	forceCheckpoint := s.groupForceCheckpoint
	s.pendingOps = nil
	s.groupForceCheckpoint = false
	s.groupDepth = 0
	if len(ops) == 0 {
		s.groupUndo = groupJournal{}
		return s.head, nil
	}
	hash, err := s.publishGroupOps(ops, forceCheckpoint)
	if err != nil {
		s.restoreJournalLocked()
		s.groupUndo = groupJournal{}
		return model.Hash32{}, err
	}
	s.groupUndo = groupJournal{}
	return hash, nil
}

// AbortGroup discards the buffered ops and restores the pre-group state.
func (s *Store) AbortGroup() {
	if s.groupDepth == 0 {
		return
	}
	s.restoreJournalLocked()
	s.pendingOps = nil
	s.groupForceCheckpoint = false
	s.groupDepth = 0
	s.groupUndo = groupJournal{}
}

// journalOps records the pre-group value of every key the batch touches. The
// first record for a key wins, so it is always the value before the group.
func (s *Store) journalOps(ops []model.Op) {
	for _, op := range ops {
		switch typed := op.(type) {
		case model.PutObjectOp:
			if s.groupUndo.objects == nil {
				s.groupUndo.objects = map[model.Hash32]*model.ObjectRecord{}
			}
			if _, seen := s.groupUndo.objects[typed.Record.ID]; !seen {
				if existing, ok := s.state.Objects[typed.Record.ID]; ok {
					copied := existing.Clone()
					s.groupUndo.objects[typed.Record.ID] = &copied
				} else {
					s.groupUndo.objects[typed.Record.ID] = nil
				}
			}
		case model.DeleteObjectOp:
			if s.groupUndo.objects == nil {
				s.groupUndo.objects = map[model.Hash32]*model.ObjectRecord{}
			}
			if _, seen := s.groupUndo.objects[typed.ID]; !seen {
				if existing, ok := s.state.Objects[typed.ID]; ok {
					copied := existing.Clone()
					s.groupUndo.objects[typed.ID] = &copied
				} else {
					s.groupUndo.objects[typed.ID] = nil
				}
			}
			if s.groupUndo.tips == nil {
				s.groupUndo.tips = map[model.Hash32]*model.Hash32{}
			}
			if _, seen := s.groupUndo.tips[typed.ID]; !seen {
				version, ok := s.state.Tips[typed.ID]
				if ok {
					copied := version
					s.groupUndo.tips[typed.ID] = &copied
				} else {
					s.groupUndo.tips[typed.ID] = nil
				}
			}
		case model.PutEntryOp:
			if s.groupUndo.entries == nil {
				s.groupUndo.entries = map[model.Hash32]*model.EntryRecord{}
			}
			if _, seen := s.groupUndo.entries[typed.Record.ID]; !seen {
				if existing, ok := s.state.Entries[typed.Record.ID]; ok {
					copied := existing
					copied.Name = append([]byte(nil), existing.Name...)
					s.groupUndo.entries[typed.Record.ID] = &copied
				} else {
					s.groupUndo.entries[typed.Record.ID] = nil
				}
			}
		case model.DelEntryOp:
			if s.groupUndo.entries == nil {
				s.groupUndo.entries = map[model.Hash32]*model.EntryRecord{}
			}
			if _, seen := s.groupUndo.entries[typed.ID]; !seen {
				if existing, ok := s.state.Entries[typed.ID]; ok {
					copied := existing
					copied.Name = append([]byte(nil), existing.Name...)
					s.groupUndo.entries[typed.ID] = &copied
				} else {
					s.groupUndo.entries[typed.ID] = nil
				}
			}
		case model.PutRelationOp:
			if s.groupUndo.relations == nil {
				s.groupUndo.relations = map[model.Hash32]*model.RelationRecord{}
			}
			if _, seen := s.groupUndo.relations[typed.Record.ID]; !seen {
				if existing, ok := s.state.Relations[typed.Record.ID]; ok {
					copied := existing.Clone()
					s.groupUndo.relations[typed.Record.ID] = &copied
				} else {
					s.groupUndo.relations[typed.Record.ID] = nil
				}
			}
		case model.DelRelationOp:
			if s.groupUndo.relations == nil {
				s.groupUndo.relations = map[model.Hash32]*model.RelationRecord{}
			}
			if _, seen := s.groupUndo.relations[typed.ID]; !seen {
				if existing, ok := s.state.Relations[typed.ID]; ok {
					copied := existing.Clone()
					s.groupUndo.relations[typed.ID] = &copied
				} else {
					s.groupUndo.relations[typed.ID] = nil
				}
			}
		case model.SetSnapshotOp:
			if s.groupUndo.snapshots == nil {
				s.groupUndo.snapshots = map[string]*model.Hash32{}
			}
			if _, seen := s.groupUndo.snapshots[typed.SnapshotName]; !seen {
				commit, ok := s.state.Snapshots[typed.SnapshotName]
				if ok {
					copied := commit
					s.groupUndo.snapshots[typed.SnapshotName] = &copied
				} else {
					s.groupUndo.snapshots[typed.SnapshotName] = nil
				}
			}
		case model.SetTipOp:
			if s.groupUndo.tips == nil {
				s.groupUndo.tips = map[model.Hash32]*model.Hash32{}
			}
			if _, seen := s.groupUndo.tips[typed.Object]; !seen {
				version, ok := s.state.Tips[typed.Object]
				if ok {
					copied := version
					s.groupUndo.tips[typed.Object] = &copied
				} else {
					s.groupUndo.tips[typed.Object] = nil
				}
			}
		}
	}
}

// restoreJournalLocked puts every journalled key back to its pre-group value.
func (s *Store) restoreJournalLocked() {
	for id, record := range s.groupUndo.objects {
		if record == nil {
			delete(s.state.Objects, id)
		} else {
			s.state.Objects[id] = record.Clone()
		}
	}
	for id, record := range s.groupUndo.entries {
		if record == nil {
			delete(s.state.Entries, id)
		} else {
			copied := *record
			copied.Name = append([]byte(nil), record.Name...)
			s.state.Entries[id] = copied
		}
	}
	for id, record := range s.groupUndo.relations {
		if record == nil {
			delete(s.state.Relations, id)
		} else {
			s.state.Relations[id] = record.Clone()
		}
	}
	for name, commit := range s.groupUndo.snapshots {
		if commit == nil {
			delete(s.state.Snapshots, name)
		} else {
			s.state.Snapshots[name] = *commit
		}
	}
	for id, version := range s.groupUndo.tips {
		if version == nil {
			delete(s.state.Tips, id)
		} else {
			s.state.Tips[id] = *version
		}
	}
}

// publishGroupOps publishes the buffered ops as exactly one commit. The live
// state already contains them.
func (s *Store) publishGroupOps(ops []model.Op, forceCheckpoint bool) (model.Hash32, error) {
	newGeneration := s.nextGeneration
	timestamp := s.nowNS()
	// Quota is charged against the pre-group object records, not the live state
	// that already contains the group's objects.
	pre := map[model.Hash32]*model.ObjectRecord{}
	for id, record := range s.groupUndo.objects {
		if record == nil {
			pre[id] = nil
		} else {
			copied := record.Clone()
			pre[id] = &copied
		}
	}
	for _, op := range ops {
		if put, ok := op.(model.PutObjectOp); ok {
			if _, exists := pre[put.Record.ID]; !exists {
				if existing, ok := s.state.Objects[put.Record.ID]; ok {
					copied := existing.Clone()
					pre[put.Record.ID] = &copied
				} else {
					pre[put.Record.ID] = nil
				}
			}
		}
	}
	quotaPlan, err := s.quotaPreflight(ops, pre)
	if err != nil {
		return model.Hash32{}, err
	}
	if quotaPlan != nil {
		ops = append(ops, quotaUsageOpFromMap(quotaPlan.usageAfter))
	}
	interval := s.options.CheckpointInterval
	wantsCheckpoint := forceCheckpoint || (interval > 0 && newGeneration%interval == 0)
	var checkpoint *model.Hash32
	if wantsCheckpoint {
		encoded, err := model.EncodeState(s.state, newGeneration)
		if err != nil {
			return model.Hash32{}, err
		}
		id, err := s.storeBlob(BlobManifest, model.DomainManifest, encoded)
		if err != nil {
			return model.Hash32{}, err
		}
		checkpoint = &id
	}
	crashPoint("after_objects")
	commit := model.Commit{
		Generation: newGeneration, Parent: hashPtr(s.head), TimestampNS: timestamp,
		Ops: ops, Checkpoint: checkpoint,
	}
	attestation, builtIndex, err := s.indexAttestationFor(s.state, newGeneration, &commit)
	if err != nil {
		return model.Hash32{}, err
	}
	commit.IndexAttestation = attestation
	hash, err := s.publishCommit(commit)
	if err != nil {
		return model.Hash32{}, err
	}
	s.state.Generation = newGeneration
	s.head = hash
	s.generation = newGeneration
	if newGeneration == ^uint64(0) {
		return model.Hash32{}, werr.Newf(werr.LimitExceeded, "generation counter overflow")
	}
	s.nextGeneration = newGeneration + 1
	// Advisory only: the commit is already durable and visible.
	if builtIndex != nil {
		s.persistBuiltIndex(hash, builtIndex)
	}
	if quotaPlan != nil {
		s.recordQuotaAfterCommit(quotaPlan)
	}
	return hash, nil
}

// ManifestOf reads and validates a manifest by content id. It seeds a
// ManifestCache for WriteFileCached.
func (s *Store) ManifestOf(content model.Hash32) (model.Manifest, error) {
	return readManifest(s.blobs, content)
}
