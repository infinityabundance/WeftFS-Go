package fusefs

import (
	"context"
	"time"

	"github.com/infinityabundance/WeftFS-Go/store"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// StartBackgroundGC starts the server-owned online collector. It refuses a
// read-only/snapshot mount and a store that does not hold the writer lock.
// Passes are serialized with every FUSE request through srv.mu, so GC cannot
// race a read, write, pin, snapshot, or unmount. The collector is opt-in
// through store.Options.GCBackground (CLI: mount --gc-watch).
func (s *Server) StartBackgroundGC(interval time.Duration, maxDeletes int) error {
	if s.readOnly {
		return werr.Newf(werr.ReadOnly, "background GC requires a writable live mount")
	}
	if s.store.Mode() != store.ReadWrite {
		return werr.Newf(werr.ReadOnly, "background GC requires the exclusive writer lock")
	}
	if interval <= 0 {
		interval = time.Duration(store.DefaultGCIntervalSecs) * time.Second
	}
	if maxDeletes <= 0 {
		maxDeletes = int(store.DefaultGCWatchMaxDeletes)
	}
	s.gcMu.Lock()
	defer s.gcMu.Unlock()
	if s.gcCancel != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	s.gcCancel = cancel
	s.gcDone = done
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			s.mu.Lock()
			if s.readOnly {
				s.mu.Unlock()
				return
			}
			_, err := s.store.GCBounded(true, maxDeletes)
			s.mu.Unlock()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				s.gcErrMu.Lock()
				s.gcErr = err
				s.gcErrMu.Unlock()
				return
			}
			s.gcPasses.Add(1)
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	return nil
}

// StopBackgroundGC cancels the collector and waits for the in-flight pass to
// finish. It must not be called while holding srv.mu. It is idempotent and is
// also invoked by the root node's OnForget during unmount.
func (s *Server) StopBackgroundGC() {
	s.gcMu.Lock()
	cancel := s.gcCancel
	done := s.gcDone
	s.gcCancel = nil
	s.gcDone = nil
	s.gcMu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

// BackgroundGCPasses reports completed passes (tests and diagnostics).
func (s *Server) BackgroundGCPasses() uint64 { return s.gcPasses.Load() }

// BackgroundGCError reports the error that stopped the collector, if any.
func (s *Server) BackgroundGCError() error {
	s.gcErrMu.Lock()
	defer s.gcErrMu.Unlock()
	return s.gcErr
}
