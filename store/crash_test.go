package store_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
)

// TestCrashChildProcess is not a test of its own: it is the re-executed child
// used by TestCrashProxy. WEFT_CRASH_PHASE makes the store SIGKILL the process
// at a defined publication step (a process-fault proxy, not a power-loss
// claim).
func TestCrashChildProcess(t *testing.T) {
	dir := os.Getenv("WEFT_CRASH_STORE")
	if dir == "" {
		t.Skip("crash helper process; not run directly")
	}
	phase := os.Getenv("WEFT_CRASH_PHASE")
	if phase == "" {
		t.Fatal("WEFT_CRASH_STORE set without WEFT_CRASH_PHASE")
	}
	if err := os.Setenv("WEFT_CRASH_PHASE", phase); err != nil {
		t.Fatalf("set env: %v", err)
	}
	s, err := store.Open(dir, store.ReadWrite)
	if err != nil {
		t.Fatalf("child open: %v", err)
	}
	defer s.Close()
	content := os.Getenv("WEFT_CRASH_CONTENT")
	if _, err := s.CreateFile(model.RootID, []byte("crash.txt"), []byte(content), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("child create: %v", err)
	}
	t.Fatalf("child survived crash phase %q; the crash hook did not fire", phase)
}

func TestCrashProxy(t *testing.T) {
	const content = "whole-or-nothing payload"
	cases := []struct {
		phase   string
		mustSee bool
		reason  string
	}{
		{"after_objects", false, "content blobs durable, commit not written"},
		{"after_commit_file", false, "commit file durable, superblock not published"},
		{"after_superblock_write", true, "superblock slot durable before root fsync"},
	}
	for _, tc := range cases {
		t.Run(tc.phase, func(t *testing.T) {
			dir := t.TempDir()
			s, err := store.Init(dir, store.DefaultOptions())
			if err != nil {
				t.Fatalf("init: %v", err)
			}
			s.Close()

			cmd := exec.Command(os.Args[0], "-test.run=TestCrashChildProcess")
			cmd.Env = append(os.Environ(),
				"WEFT_CRASH_STORE="+dir,
				"WEFT_CRASH_PHASE="+tc.phase,
				"WEFT_CRASH_CONTENT="+content,
			)
			output, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("child exited cleanly after crash phase %s; output: %s", tc.phase, output)
			}
			if _, ok := err.(*exec.ExitError); !ok {
				t.Fatalf("child execution failed: %v (%s)", err, output)
			}

			reader, err := store.Open(dir, store.ReadOnly)
			if err != nil {
				t.Fatalf("reopen after crash at %s: %v", tc.phase, err)
			}
			defer reader.Close()
			report, err := reader.Verify(true)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if tc.mustSee {
				if !report.OK {
					t.Fatalf("store is not whole after crash at %s: %+v", tc.phase, report.Problems)
				}
			} else {
				// The unpublished commit tail is reported by verify (the Rust
				// reference documents the same behaviour); any other problem is
				// a real integrity failure.
				for _, problem := range report.Problems {
					if !strings.Contains(problem.Detail, "above the highest published superblock generation") {
						t.Fatalf("unexpected integrity problem after crash at %s: %+v", tc.phase, problem)
					}
				}
			}
			id, resolveErr := reader.ResolvePath("/crash.txt")
			if tc.mustSee {
				if resolveErr != nil {
					t.Fatalf("file missing after published commit at %s: %v", tc.phase, resolveErr)
				}
				data, err := reader.ReadObject(id)
				if err != nil {
					t.Fatalf("read after crash at %s: %v", tc.phase, err)
				}
				if string(data) != content {
					t.Fatalf("content = %q, want %q", string(data), content)
				}
			} else {
				if resolveErr == nil {
					t.Fatalf("unpublished commit became visible after crash at %s (%s)", tc.phase, tc.reason)
				}
			}
		})
	}
}

func TestRejectedTailIsNotOverwritten(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, store.DefaultOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	s.Close()

	cmd := exec.Command(os.Args[0], "-test.run=TestCrashChildProcess")
	cmd.Env = append(os.Environ(),
		"WEFT_CRASH_STORE="+dir,
		"WEFT_CRASH_PHASE=after_commit_file",
		"WEFT_CRASH_CONTENT=never-published",
	)
	if output, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("child exited cleanly: %s", output)
	}

	tornPath := filepath.Join(dir, "commits", "2.commit")
	before, err := os.Stat(tornPath)
	if err != nil {
		t.Fatalf("torn commit file missing: %v", err)
	}

	writer, err := store.Open(dir, store.ReadWrite)
	if err != nil {
		t.Fatalf("writer open after torn tail: %v", err)
	}
	if writer.Generation() != 1 {
		t.Fatalf("generation = %d, want 1", writer.Generation())
	}
	if _, err := writer.CreateFile(model.RootID, []byte("after-crash.txt"), []byte("ok"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("create after recovery: %v", err)
	}
	if writer.Generation() != 3 {
		t.Fatalf("new generation = %d, want 3 (skip the unpublished tail)", writer.Generation())
	}
	writer.Close()

	after, err := os.Stat(tornPath)
	if err != nil {
		t.Fatalf("rejected commit file was deleted: %v", err)
	}
	if after.Size() != before.Size() {
		t.Fatalf("rejected commit file was rewritten: %d -> %d bytes", before.Size(), after.Size())
	}

	reader, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("final reopen: %v", err)
	}
	defer reader.Close()
	if reader.Generation() != 3 {
		t.Fatalf("final generation = %d, want 3", reader.Generation())
	}
	report, err := reader.Verify(true)
	if err != nil || !report.OK {
		t.Fatalf("verify: ok=%v err=%v problems=%+v", report != nil && report.OK, err, reportProblems(report))
	}
	if _, err := reader.ResolvePath("/after-crash.txt"); err != nil {
		t.Fatalf("post-recovery file missing: %v", err)
	}
}
