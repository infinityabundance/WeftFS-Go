package fusefs

import (
	"time"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// Write-back and group commit.
//
// Both are opt-in mount modes and have the same durability rule: buffered
// writes become visible to other readers and durable only when the buffer is
// published (flush/fsync/release), and a grouped mutation is durable only when
// its group is published. A crash before publication leaves the previous whole
// generation. Every mutation still applies to the live in-memory state, so
// reads in the same process see it.

const (
	// groupCommitWindow is the maximum time a buffered mutation waits for
	// company before the group is published.
	groupCommitWindow = 10 * time.Millisecond
	// groupCommitMaxOps bounds one group.
	groupCommitMaxOps = 256
	// writeBackMaxBytes bounds one handle's buffered writes. Reaching it
	// publishes early (an earlier durable commit is always allowed).
	writeBackMaxBytes = 32 * 1024 * 1024
)

type pendingWrite struct {
	offset uint64
	data   []byte
}

func (h *fileHandle) pendingEnd() uint64 {
	end := h.size
	for _, write := range h.pending {
		if write.offset+uint64(len(write.data)) > end {
			end = write.offset + uint64(len(write.data))
		}
	}
	return end
}

func (h *fileHandle) pendingBytes() int {
	total := 0
	for _, write := range h.pending {
		total += len(write.data)
	}
	return total
}

// StartGroupCommit starts the background publisher. It is a no-op when group
// commit is disabled.
func (s *Server) StartGroupCommit() {
	if !s.groupCommit {
		return
	}
	s.groupLifecycle.Lock()
	if s.groupStop != nil {
		s.groupLifecycle.Unlock()
		return
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	s.groupStop = stop
	s.groupDone = done
	s.groupLifecycle.Unlock()
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				s.mu.Lock()
				_ = s.publishGroupLocked()
				s.mu.Unlock()
				return
			case <-ticker.C:
				s.mu.Lock()
				if s.groupOpen && time.Since(s.groupOpenedAt) >= groupCommitWindow {
					_ = s.publishGroupLocked()
				}
				s.mu.Unlock()
			}
		}
	}()
}

// StopGroupCommit stops the publisher and publishes any open group.
func (s *Server) StopGroupCommit() {
	s.groupLifecycle.Lock()
	stop := s.groupStop
	done := s.groupDone
	if stop != nil {
		close(stop)
		s.groupStop = nil
	}
	s.groupLifecycle.Unlock()
	// Wait for the publisher to exit even if another caller already closed the
	// stop channel: `done` is closed once, and receiving from it is idempotent.
	// This is what makes verification after StopGroupCommit race-free.
	if done != nil {
		<-done
	}
}

// beginGroupedMutationLocked joins or opens a group. Caller holds mu.
func (s *Server) beginGroupedMutationLocked() error {
	if !s.groupCommit || s.readOnly {
		return nil
	}
	if s.groupErr != nil {
		return s.groupErr
	}
	if !s.store.GroupOpen() {
		if err := s.store.BeginGroup(); err != nil {
			return err
		}
		s.groupOpen = true
		s.groupOpenedAt = time.Now()
		s.groupOps = 0
	}
	return nil
}

// finishGroupedMutationLocked counts a finished mutation and publishes the
// group when it is full or its window elapsed. Caller holds mu.
func (s *Server) finishGroupedMutationLocked() error {
	if !s.groupCommit || s.readOnly {
		return nil
	}
	s.groupOps++
	if s.groupOps >= groupCommitMaxOps || time.Since(s.groupOpenedAt) >= groupCommitWindow {
		return s.publishGroupLocked()
	}
	return nil
}

// publishGroupLocked publishes the open group, if any. Caller holds mu.
func (s *Server) publishGroupLocked() error {
	if !s.store.GroupOpen() {
		s.groupOpen = false
		return nil
	}
	_, err := s.store.CommitGroup()
	s.groupOpen = false
	if err != nil {
		s.groupErr = werr.Wrap(werr.Io, err, "group commit failed to publish; remount to continue")
		return s.groupErr
	}
	return nil
}

// flushHandleLocked publishes one handle's buffered writes as one durable
// commit. Caller holds mu.
func (s *Server) flushHandleLocked(h *fileHandle) error {
	// A prior open group is published first so this flush's own commit is the
	// last thing the caller observes.
	if err := s.publishGroupLocked(); err != nil {
		return err
	}
	if len(h.pending) == 0 {
		return nil
	}
	ranges := make([]store.RangeWrite, 0, len(h.pending))
	for _, write := range h.pending {
		ranges = append(ranges, store.RangeWrite{Offset: write.offset, Data: write.data})
	}
	outcome, err := s.store.WriteFileRanges(h.id, ranges)
	if err != nil {
		// Keep the buffer so the caller can retry.
		return err
	}
	h.pending = nil
	h.content = outcome.Content
	h.size = outcome.Size
	h.manifest = nil
	return nil
}

// flushAllPendingLocked publishes every buffered handle. Caller holds mu.
func (s *Server) flushAllPendingLocked() error {
	for h := range s.handles {
		if len(h.pending) == 0 {
			continue
		}
		if err := s.flushHandleLocked(h); err != nil {
			return err
		}
	}
	return nil
}

// flushNodePendingLocked publishes buffered handles for one object id.
func (s *Server) flushNodePendingLocked(id model.Hash32) error {
	for h := range s.handles {
		if h.id != id || len(h.pending) == 0 {
			continue
		}
		if err := s.flushHandleLocked(h); err != nil {
			return err
		}
	}
	return nil
}
