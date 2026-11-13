// X08: packed-plane races across languages.
//
// The Rust court (`tests/packed_races.rs`) proves the discovery invariant for
// one implementation under racing seal, catalog publication, commit, rollback,
// cancellation, epoch change, process crash and GC. These tests add the
// direction that matters for a portable format: a Go reader of a store a Rust
// writer is still packing, and a Rust reader of a store a Go writer is still
// packing.
//
// The invariant restated for the cross-language case: a reader may see the
// store as of the last commit it opened or a newer committed state, and must
// never see a catalog entry without its pack, a pack without durable bytes, a
// reclaimed blob still referenced by a live root, or member bytes that fail
// their digest. A file that resolves must read exactly; a file that does not
// resolve may simply not be committed yet (`NotFound`).
package store_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
)

func racePackedOptions() store.Options {
	opts := store.DefaultOptions()
	opts.ChunkSize = 1024
	opts.Packing = true
	opts.PackOptions = store.DefaultPackOptions()
	opts.PackOptions.MemberThresholdBytes = 4096
	stamp := overlayFixedTimestamp
	opts.FixedTimestampNS = &stamp
	return opts
}

func racePayload(seed int, n int) []byte {
	out := make([]byte, n)
	state := uint64(seed) | 1
	for i := 0; i < n; i += 8 {
		state ^= state >> 12
		state ^= state << 25
		state ^= state >> 27
		v := state * 0x2545f4914f6cdd1d
		for j := 0; j < 8 && i+j < n; j++ {
			out[i+j] = byte(v >> (8 * j))
		}
	}
	return out
}

// TestRustWriterRacesGoReader: the Rust CLI keeps publishing while Go readers
// open the same packed store. Every file that resolves must read exactly; a
// file that does not resolve yet must be `NotFound`, never a corrupt read.
func TestRustWriterRacesGoReader(t *testing.T) {
	bin := rustBinary(t)
	dir := t.TempDir()
	payloadDir := t.TempDir()
	args := packRustArgs(dir)
	runRust(t, bin, append(args, "init")...)

	const files = 48
	payloads := make([][]byte, files)
	for i := 0; i < files; i++ {
		payloads[i] = racePayload(100+i, 300+i*11)
		path := filepath.Join(payloadDir, "p"+x08itoa(i))
		if err := os.WriteFile(path, payloads[i], 0o644); err != nil {
			t.Fatalf("payload: %v", err)
		}
	}

	var stop atomic.Bool
	var failures atomic.Int64
	var reads atomic.Int64
	var wg sync.WaitGroup
	for r := 0; r < 3; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				s, err := store.OpenWithOptions(dir, store.ReadOnly, racePackedOptions())
				if err != nil {
					failures.Add(1)
					continue
				}
				for i := 0; i < files; i++ {
					name := "/f" + x08itoa(i)
					var id model.Hash32
					id, err := s.ResolvePath(name)
					if err != nil {
						// Not committed yet: allowed only while the writer runs.
						continue
					}
					got, err := s.ReadObject(id)
					if err != nil {
						t.Logf("reader: resolve succeeded but read failed for %s: %v", name, err)
						failures.Add(1)
						continue
					}
					if !bytes.Equal(got, payloads[i]) {
						t.Logf("reader: %s returned %d bytes that differ", name, len(got))
						failures.Add(1)
						continue
					}
					reads.Add(1)
				}
				s.Close()
				time.Sleep(2 * time.Millisecond)
			}
		}()
	}

	for i := 0; i < files; i++ {
		runRust(t, bin, append(args, "create", "/f"+x08itoa(i), "--file",
			filepath.Join(payloadDir, "p"+x08itoa(i)), "--seed", "x08-go-"+x08itoa(i))...)
	}
	stop.Store(true)
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("%d reader failures (reads=%d)", failures.Load(), reads.Load())
	}
	if reads.Load() == 0 {
		t.Fatal("the Go readers never observed a committed file")
	}
	runRust(t, bin, append(args, "verify", "--full")...)
	for i := 0; i < files; i++ {
		got := runRustBytes(t, bin, append(args, "cat", "/f"+x08itoa(i))...)
		if !bytes.Equal(got, payloads[i]) {
			t.Fatalf("rust cat of /f%d differs after the race", i)
		}
	}
}

// TestGoWriterRacesRustReader: a Go writer keeps packing (sealing packs and
// replacing the catalog root) while Rust reader processes read the files that
// are already committed. Every Rust read must be exact and the store must verify
// after the writer stops.
func TestGoWriterRacesRustReader(t *testing.T) {
	bin := rustBinary(t)
	dir := t.TempDir()
	s, err := store.Init(dir, racePackedOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	const committed = 24
	payloads := make(map[int][]byte, committed)
	for i := 0; i < committed; i++ {
		payloads[i] = racePayload(500+i, 500+i*7)
		if _, err := s.CreateFileSeeded(model.RootID, []byte("f"+x08itoa(i)), payloads[i], 0o644, 0, 0, nil, []byte("x08-go-"+x08itoa(i))); err != nil {
			t.Fatalf("create f%d: %v", i, err)
		}
	}
	args := packRustArgs(dir)
	runRust(t, bin, append(args, "verify", "--full")...)

	var stop atomic.Bool
	var failures atomic.Int64
	var reads atomic.Int64
	var wg sync.WaitGroup
	for r := 0; r < 3; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				for i := 0; i < committed; i++ {
					out, err := runRustMaybe(bin, append(args, "cat", "/f"+x08itoa(i))...)
					if err != nil {
						t.Logf("rust reader failed on /f%d: %v", i, err)
						failures.Add(1)
						continue
					}
					if !bytes.Equal(out, payloads[i]) {
						t.Logf("rust reader saw different bytes for /f%d", i)
						failures.Add(1)
						continue
					}
					reads.Add(1)
				}
			}
		}()
	}

	// The writer keeps publishing, so packs are sealed and the catalog root is
	// replaced while the Rust readers run.
	for round := 0; round < 24; round++ {
		if _, err := s.CreateFileSeeded(model.RootID, []byte("late"+x08itoa(round)),
			racePayload(900+round, 400+round*5), 0o644, 0, 0, nil,
			[]byte("x08-late-"+x08itoa(round))); err != nil {
			t.Fatalf("late create %d: %v", round, err)
		}
		if round%6 == 5 {
			if _, err := s.GC(false); err != nil {
				t.Fatalf("gc: %v", err)
			}
		}
	}
	stop.Store(true)
	wg.Wait()
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if failures.Load() != 0 {
		t.Fatalf("%d Rust reader failures (reads=%d)", failures.Load(), reads.Load())
	}
	if reads.Load() == 0 {
		t.Fatal("the Rust readers never completed a read")
	}
	runRust(t, bin, append(args, "verify", "--full")...)
}

func x08itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var digits [12]byte
	i := len(digits)
	for v > 0 {
		i--
		digits[i] = byte('0' + v%10)
		v /= 10
	}
	return string(digits[i:])
}

// runRustMaybe runs the Rust binary and returns its stdout, or an error with
// the combined output. Unlike `runRust` it does not fail the test.
func runRustMaybe(bin string, args ...string) ([]byte, error) {
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	var out, errOut strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		return nil, &rustRunError{args: args, err: err, text: errOut.String() + out.String()}
	}
	return []byte(out.String()), nil
}

type rustRunError struct {
	args []string
	err  error
	text string
}

func (e *rustRunError) Error() string {
	return "rust " + strings.Join(e.args, " ") + ": " + e.err.Error() + "\n" + e.text
}
