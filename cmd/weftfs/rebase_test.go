package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
)

// rebaseFixture builds a store with a mode-9 base, a mode-11 weight-delta
// child, twelve reads on the child, flushed access counters, and a snapshot.
// It returns the store directory, the delta id, the target bytes, and the
// pre-rebase logical root.
func rebaseFixture(t *testing.T) (string, model.Hash32, []byte, model.Hash32) {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Init(dir, store.DefaultOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	shape := []uint64{256, 512} // 256 KiB BF16
	elements := 256 * 512
	base := cliSmoothBf16(elements)
	target := append([]byte(nil), base...)
	for index := 0; index < elements; index += 4096 {
		target[index*2] ^= 1
	}
	floatHint := store.TensorStrategyFloatTensor
	baseID, err := s.WriteTensorFileWithSpec(model.RootID, []byte("base"), "bf16", shape,
		base, store.RowMajorTensorLayout(), store.TensorWriteSpec{StrategyHint: &floatHint})
	if err != nil {
		t.Fatalf("write base: %v", err)
	}
	baseRecord, err := s.ObjectMeta(baseID)
	if err != nil {
		t.Fatalf("base meta: %v", err)
	}
	deltaHint := store.TensorStrategyWeightDelta
	deltaID, err := s.WriteTensorFileWithSpec(model.RootID, []byte("instruct"), "bf16", shape,
		target, store.RowMajorTensorLayout(), store.TensorWriteSpec{
			StrategyHint: &deltaHint,
			Causal:       []model.Hash32{baseRecord.Version},
		})
	if err != nil {
		t.Fatalf("write delta: %v", err)
	}
	meta, err := s.TensorMetadata(deltaID)
	if err != nil {
		t.Fatalf("delta meta: %v", err)
	}
	if meta.Strategy != "weight-delta" {
		t.Fatalf("delta strategy = %s, want weight-delta", meta.Strategy)
	}
	for index := 0; index < 12; index++ {
		data, err := s.ReadTensor(deltaID)
		if err != nil || !bytes.Equal(data, target) {
			t.Fatalf("read %d: %v", index, err)
		}
	}
	if err := s.FlushAccessCounts(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if _, err := s.SnapshotCreate("before-rebase"); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return dir, deltaID, target, meta.LogicalRoot
}

// rustBinaryCLI locates the Rust reference binary. It is used only as a test
// oracle; no production code invokes Rust from Go.
func rustBinaryCLI(t *testing.T) string {
	t.Helper()
	candidates := []string{
		os.Getenv("WEFTFS_RUST_BIN"),
		"/work/.docker-cache/target-rust/release/weftfs",
		filepath.Join("..", "..", "..", ".docker-cache", "target-rust", "release", "weftfs"),
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		info, err := os.Stat(candidate)
		if err != nil || info.IsDir() {
			continue
		}
		abs, err := filepath.Abs(candidate)
		if err != nil {
			abs = candidate
		}
		probe := exec.Command(abs, "--version")
		if output, probeErr := probe.CombinedOutput(); probeErr != nil {
			t.Skipf("Rust oracle at %s is not runnable in this court: %v\n%s", abs, probeErr, output)
		}
		return abs
	}
	t.Skip("Rust oracle binary not found; build it in the Rust court with: " +
		"scripts/docker-court.sh rust \"cargo build --release --features fuse --locked --bin weftfs\"")
	return ""
}

func runRustCLI(t *testing.T, bin string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("rust %s failed: %v\n%s", strings.Join(args, " "), err, output)
	}
	return string(output)
}

func TestRebaseCLIDryRunDoesNotWrite(t *testing.T) {
	dir, deltaID, _, _ := rebaseFixture(t)

	before, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	beforeGen := before.Generation()
	beforeHead := before.Head()
	beforeVersion, err := before.ObjectMeta(deltaID)
	if err != nil {
		t.Fatalf("meta: %v", err)
	}
	beforeReads := before.AccessReads(deltaID)
	if beforeReads < 12 {
		t.Fatalf("reads = %d, want >= 12", beforeReads)
	}
	if err := before.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	out := captureStdout(t, func() error {
		return run("rebase", []string{"--root", "/", "--threshold", "1000000", "--dry-run"}, dir, false)
	})
	if !strings.Contains(out, "candidates=1") || !strings.Contains(out, "applied=0") {
		t.Fatalf("dry run did not report one candidate and no writes:\n%s", out)
	}
	if !strings.Contains(out, deltaID.Hex()) {
		t.Fatalf("dry run did not name the hot delta:\n%s", out)
	}

	after, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer after.Close()
	if after.Generation() != beforeGen || after.Head() != beforeHead {
		t.Fatalf("dry run moved the store: generation %d->%d head %s->%s",
			beforeGen, after.Generation(), beforeHead.Hex(), after.Head().Hex())
	}
	afterVersion, err := after.ObjectMeta(deltaID)
	if err != nil {
		t.Fatalf("meta: %v", err)
	}
	if afterVersion.Version != beforeVersion.Version {
		t.Fatal("dry run published a new version")
	}
	if reads := after.AccessReads(deltaID); reads != beforeReads {
		t.Fatalf("dry run changed reads: %d -> %d", beforeReads, reads)
	}
}

func TestRebaseCLIAppliesAndRustAccepts(t *testing.T) {
	bin := rustBinaryCLI(t)
	dir, deltaID, target, logicalRoot := rebaseFixture(t)

	out := captureStdout(t, func() error {
		return run("rebase", []string{"--root", "/", "--threshold", "1000000"}, dir, false)
	})
	if !strings.Contains(out, "applied=1") {
		t.Fatalf("apply did not report one write:\n%s", out)
	}
	if !strings.Contains(out, "float-tensor") {
		t.Fatalf("apply did not record the standalone strategy:\n%s", out)
	}
	var provenance string
	for _, field := range strings.Fields(out) {
		if strings.HasPrefix(field, "provenance=") {
			provenance = strings.TrimPrefix(field, "provenance=")
		}
	}
	if len(provenance) != 64 {
		t.Fatalf("no 64-hex provenance id in output:\n%s", out)
	}

	verify := runRustCLI(t, bin, "--store", dir, "verify", "--full", "--json")
	if !strings.Contains(verify, `"ok": true`) {
		t.Fatalf("Rust verify did not accept the Go rebase:\n%s", verify)
	}
	show := runRustCLI(t, bin, "--store", dir, "provenance", "show", deltaID.Hex(), "--json")
	if !strings.Contains(show, provenance) {
		t.Fatalf("Rust did not read the Go provenance receipt %s:\n%s", provenance, show)
	}

	// Byte-level checks on the reopened store.
	reopened, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	report, err := reopened.Verify(true)
	if err != nil {
		t.Fatalf("Go verify: %v", err)
	}
	if !report.OK || len(report.Problems) != 0 {
		t.Fatalf("Go verify: ok=%v problems=%+v", report.OK, report.Problems)
	}
	data, err := reopened.ReadTensor(deltaID)
	if err != nil || !bytes.Equal(data, target) {
		t.Fatalf("post-rebase read: %v", err)
	}
	meta, err := reopened.TensorMetadata(deltaID)
	if err != nil {
		t.Fatalf("meta: %v", err)
	}
	if meta.Strategy != "float-tensor" {
		t.Fatalf("strategy = %s, want float-tensor", meta.Strategy)
	}
	if meta.LogicalRoot != logicalRoot {
		t.Fatalf("logical root changed: %s -> %s", logicalRoot.Hex(), meta.LogicalRoot.Hex())
	}
}

func TestRebaseCLIIsIdempotent(t *testing.T) {
	dir, deltaID, _, _ := rebaseFixture(t)
	first := captureStdout(t, func() error {
		return run("rebase", []string{"--root", "/", "--threshold", "1000000"}, dir, false)
	})
	if !strings.Contains(first, "applied=1") {
		t.Fatalf("first run applied nothing:\n%s", first)
	}
	// No intervening reads: the consumed counter must make the second run a
	// no-op.
	second := captureStdout(t, func() error {
		return run("rebase", []string{"--root", "/", "--threshold", "1000000"}, dir, false)
	})
	if !strings.Contains(second, "applied=0") {
		t.Fatalf("second run wrote again:\n%s", second)
	}
	if strings.Contains(second, deltaID.Hex()+" ") {
		t.Fatalf("second run selected the rebased object:\n%s", second)
	}
}

func TestRebaseCLIThresholdNotMet(t *testing.T) {
	dir, _, _, _ := rebaseFixture(t)
	out := captureStdout(t, func() error {
		return run("rebase", []string{"--root", "/", "--threshold", "1000000000000000"}, dir, false)
	})
	if !strings.Contains(out, "candidates=0") || !strings.Contains(out, "applied=0") {
		t.Fatalf("high threshold still selected a candidate:\n%s", out)
	}
}

func TestRebaseCLIUnsupportedStrategyIsRefused(t *testing.T) {
	dir, _, _, _ := rebaseFixture(t)
	err := run("rebase", []string{
		"--root", "/", "--threshold", "1000000", "--strategy", "weight-delta",
	}, dir, false)
	if err == nil {
		t.Fatal("a dependency strategy was accepted as the rebase target")
	}
	if !strings.Contains(err.Error(), "standalone") {
		t.Fatalf("refusal does not explain the constraint: %v", err)
	}
	// A standalone strategy is accepted (it may select nothing).
	_ = captureStdout(t, func() error {
		return run("rebase", []string{
			"--root", "/", "--threshold", "1000000", "--strategy", "float-tensor", "--dry-run",
		}, dir, false)
	})
}

func TestRustRebaseReadableByGo(t *testing.T) {
	bin := rustBinaryCLI(t)
	dir, deltaID, target, logicalRoot := rebaseFixture(t)

	out := runRustCLI(t, bin, "--store", dir, "rebase", "--root", "/", "--threshold", "1000000")
	if !strings.Contains(out, "applied") {
		t.Fatalf("Rust rebase applied nothing:\n%s", out)
	}

	reopened, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	report, err := reopened.Verify(true)
	if err != nil {
		t.Fatalf("Go verify after Rust rebase: %v", err)
	}
	if !report.OK || len(report.Problems) != 0 {
		t.Fatalf("Go verify after Rust rebase: ok=%v problems=%+v", report.OK, report.Problems)
	}
	data, err := reopened.ReadTensor(deltaID)
	if err != nil || !bytes.Equal(data, target) {
		t.Fatalf("Go read after Rust rebase: %v", err)
	}
	meta, err := reopened.TensorMetadata(deltaID)
	if err != nil {
		t.Fatalf("meta: %v", err)
	}
	if meta.Strategy != "float-tensor" {
		t.Fatalf("strategy = %s, want float-tensor", meta.Strategy)
	}
	if meta.LogicalRoot != logicalRoot {
		t.Fatalf("logical root changed: %s -> %s", logicalRoot.Hex(), meta.LogicalRoot.Hex())
	}
	// The pinned snapshot is untouched by the rebase.
	snapshot, err := reopened.LookupSnapshot("before-rebase")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	pinned, err := reopened.ReadObjectAt(&snapshot, deltaID)
	if err != nil || !bytes.Equal(pinned, target) {
		t.Fatalf("snapshot read after rebase: %v", err)
	}
	// The Rust receipt is a first-class relation in the Go state.
	found := false
	for _, relation := range reopened.CurrentState().Relations {
		if relation.Subject == deltaID && relation.Predicate == "provenance" {
			found = true
		}
	}
	if !found {
		t.Fatal("no provenance relation after the Rust rebase")
	}
}
