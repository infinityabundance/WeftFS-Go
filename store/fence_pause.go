// Process-fault hook for the fenced-writer court (subphase R27), the Go half
// of Rust `src/fence_pause.rs`.
//
// The court needs to suspend a writer at one exact point: after it has proven
// its lease with a conditional write on the LOCK record and before it publishes
// a head. The hook is inert unless `WEFT_FENCE_PAUSE_AFTER_FENCE` is set.
//
// When armed, the process writes `WEFT_FENCE_AFTER_FENCE_READY` with its pid and
// the pre-publication state, then blocks on the named FIFO
// `WEFT_FENCE_AFTER_FENCE_GATE` until the parent releases it. The parent lets
// the lease expire, takes it over with a second writer that publishes no head,
// and then writes one byte to the FIFO. The resumed writer must fail `Busy` and
// leave the head unchanged.
//
// The Rust court uses `raise(SIGSTOP)`/`SIGCONT` for the same boundary (see
// `src/fence_pause.rs`). Go's runtime does not deliver a self-sent `SIGSTOP` as
// a group stop in this court (measured: `syscall.Kill(os.Getpid(),
// SIGSTOP)` returns nil and the goroutine continues within microseconds), so
// the Go court uses a named FIFO, which blocks the caller just as exactly. The
// interleaving being tested is identical; only the suspension primitive differs.
package store

import (
	"fmt"
	"os"
	"sync/atomic"

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
	if gate := os.Getenv("WEFT_FENCE_AFTER_FENCE_GATE"); gate != "" {
		if file, err := os.OpenFile(gate, os.O_RDONLY, 0); err == nil {
			var byte [1]byte
			_, _ = file.Read(byte[:])
			_ = file.Close()
		}
	}
}
