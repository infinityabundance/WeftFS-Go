// Process-fault hook for the fenced-writer court (subphase R27), the Go half
// of Rust `src/fence_pause.rs`.
//
// The court needs to suspend a writer at one exact point: after it has proven
// its lease with a conditional write on the LOCK record and before it publishes
// a head. The hook is inert unless `WEFT_FENCE_PAUSE_AFTER_FENCE` is set.
//
// When armed, the process writes `WEFT_FENCE_AFTER_FENCE_READY` with its pid and
// the pre-publication state, then sends itself `SIGSTOP`. The parent lets the
// lease expire, takes it over with a second writer that publishes no head, and
// sends `SIGCONT`. The resumed writer must fail `Busy` and leave the head
// unchanged.
package store

import (
	"fmt"
	"os"
	"sync/atomic"
	"syscall"

	"github.com/infinityabundance/WeftFS-Go/model"
)

var fencePausedOnce atomic.Bool

// fencePauseAfterFence is the test hook. It fires at most once per process.
func fencePauseAfterFence(generation uint64, head model.Hash32) {
	if os.Getenv("WEFT_FENCE_PAUSE_AFTER_FENCE") == "" {
		return
	}
	if !fencePausedOnce.CompareAndSwap(false, true) {
		return
	}
	if path := os.Getenv("WEFT_FENCE_AFTER_FENCE_READY"); path != "" {
		line := fmt.Sprintf("{\"pid\":%d,\"generation\":%d,\"head\":\"%s\"}\n",
			os.Getpid(), generation, head.Hex())
		_ = os.WriteFile(path, []byte(line), 0o644)
	}
	// SIGSTOP is not catchable and does not release the process's resources.
	_ = syscall.Kill(os.Getpid(), syscall.SIGSTOP)
}
