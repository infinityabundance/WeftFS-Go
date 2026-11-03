package store_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
)

// rustBinary locates the Rust reference binary. It is used only as a test
// oracle; no production package invokes it.
func rustBinary(t *testing.T) string {
	t.Helper()
	candidates := []string{
		os.Getenv("WEFTFS_RUST_BIN"),
		filepath.Join("..", "..", ".docker-cache", "target-rust", "release", "weftfs"),
		filepath.Join("..", ".docker-cache", "target-rust", "release", "weftfs"),
		"/work/.docker-cache/target-rust/release/weftfs",
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			abs, err := filepath.Abs(candidate)
			if err == nil {
				return abs
			}
			return candidate
		}
	}
	t.Skip("Rust oracle binary not found; build it in the Rust court with: " +
		"scripts/docker-court.sh rust \"cargo build --release --features fuse --locked --bin weftfs\"")
	return ""
}

func runRust(t *testing.T, bin string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("rust %s failed: %v\n%s", strings.Join(args, " "), err, output)
	}
	return string(output)
}

// rustMount starts the Rust FUSE frontend, waits for the mount, and returns a
// cleanup function. If the mount never appears the test is skipped with the
// captured daemon output (never a fabricated pass).
func rustMount(t *testing.T, bin, storeDir string, extra ...string) (string, func()) {
	t.Helper()
	mountpoint := t.TempDir()
	args := []string{"--store", storeDir, "mount", "--mountpoint", mountpoint, "--foreground"}
	args = append(args, extra...)
	cmd := exec.Command(bin, args...)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start rust mount: %v", err)
	}
	absMount, _ := filepath.Abs(mountpoint)
	deadline := time.Now().Add(15 * time.Second)
	mounted := false
	for time.Now().Before(deadline) {
		if mountInfoContains(absMount) {
			mounted = true
			break
		}
		if cmd.ProcessState != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cleanup := func() {
		_ = syscall.Unmount(mountpoint, 0)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	}
	if !mounted {
		cleanup()
		t.Skipf("Rust FUSE mount did not appear in this court; daemon output:\n%s", output.String())
	}
	return mountpoint, cleanup
}

func mountInfoContains(mountpoint string) bool {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 4 && fields[4] == mountpoint {
			return true
		}
	}
	return false
}

func rustVerifyFull(t *testing.T, bin, dir string) {
	t.Helper()
	output := runRust(t, bin, "--store", dir, "verify", "--full")
	if !strings.Contains(output, "ok=true") {
		t.Fatalf("rust verify --full did not report ok=true:\n%s", output)
	}
}

func rustCat(t *testing.T, bin, dir, path string) string {
	t.Helper()
	return runRust(t, bin, "--store", dir, "cat", path)
}

func readObjectContent(t *testing.T, s *store.Store, state *model.State, path string) string {
	t.Helper()
	id, err := resolveInState(state, path)
	if err != nil {
		t.Fatalf("resolve %s: %v", path, err)
	}
	record, ok := state.Objects[id]
	if !ok {
		t.Fatalf("object %s missing", path)
	}
	manifest, err := store.ReadManifest(s.Root(), record.Content)
	if err != nil {
		t.Fatalf("manifest %s: %v", path, err)
	}
	data, err := store.ReadRange(s.Root(), manifest, 0, manifest.Size, true)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func resolveInState(state *model.State, path string) (model.Hash32, error) {
	current := model.RootID
	for _, part := range strings.Split(path, "/") {
		if part == "" {
			continue
		}
		next, err := state.Lookup(current, []byte(part))
		if err != nil {
			return model.Hash32{}, err
		}
		current = next
	}
	return current, nil
}

// Gate 1: Rust fixture -> Go mutations -> Rust reads exact bytes, graph, and
// snapshot.
func TestHandoffRustFixtureThenGoMutations(t *testing.T) {
	bin := rustBinary(t)
	dir := copyFixture(t)

	s, err := store.Open(dir, store.ReadWrite)
	if err != nil {
		t.Fatalf("go open: %v", err)
	}
	root, err := s.ResolvePath("/")
	if err != nil {
		t.Fatalf("resolve root: %v", err)
	}
	if _, err := s.CreateFile(root, []byte("go-added.txt"), []byte("added by Go\n"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("go create: %v", err)
	}
	hello, err := s.ResolvePath("/hello.txt")
	if err != nil {
		t.Fatalf("resolve hello: %v", err)
	}
	readme, err := s.ResolvePath("/docs/readme.md")
	if err != nil {
		t.Fatalf("resolve readme: %v", err)
	}
	if _, err := s.RelationAdd(hello, "go_provenance", model.ObjectTarget(readme), nil, nil); err != nil {
		t.Fatalf("go relation: %v", err)
	}
	snapshotCommit, err := s.SnapshotCreate("go-snap")
	if err != nil {
		t.Fatalf("go snapshot: %v", err)
	}
	goGeneration := s.Generation()
	head := s.Head().Hex()
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	rustVerifyFull(t, bin, dir)
	if got := rustCat(t, bin, dir, "/go-added.txt"); got != "added by Go\n" {
		t.Fatalf("rust cat go-added.txt = %q", got)
	}
	if got := rustCat(t, bin, dir, "/hello.txt"); got != "hello weft\n" {
		t.Fatalf("rust cat hello.txt = %q", got)
	}
	if got := rustCat(t, bin, dir, "/docs/readme.md"); got != "# WeftFS fixture\n\nDeterministic store for cross-language handoff.\n" {
		t.Fatalf("rust cat readme = %q", got)
	}

	graph := runRust(t, bin, "--store", dir, "--json", "query",
		"select relation(go_provenance, obj:"+readme.Hex()+")")
	var resolution struct {
		MatchedCount uint64 `json:"matched_count"`
		Results      []struct {
			ObjectID string `json:"object_id"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(graph), &resolution); err != nil {
		t.Fatalf("parse rust query json: %v\n%s", err, graph)
	}
	if resolution.MatchedCount != 1 || len(resolution.Results) != 1 || resolution.Results[0].ObjectID != hello.Hex() {
		t.Fatalf("rust graph query = %+v", resolution)
	}

	snapshots := runRust(t, bin, "--store", dir, "--json", "snapshot", "list")
	var snapshotList struct {
		Snapshots map[string]string `json:"snapshots"`
	}
	if err := json.Unmarshal([]byte(snapshots), &snapshotList); err != nil {
		t.Fatalf("parse snapshot list: %v\n%s", err, snapshots)
	}
	if snapshotList.Snapshots["go-snap"] != snapshotCommit.Hex() {
		t.Fatalf("rust snapshot list = %+v, want go-snap=%s", snapshotList.Snapshots, snapshotCommit.Hex())
	}

	info := runRust(t, bin, "--store", dir, "--json", "info")
	if !strings.Contains(info, `"generation": `+itoa(goGeneration)) || !strings.Contains(info, `"snapshot_root": "`+head+`"`) {
		t.Fatalf("rust info disagrees with Go head/generation:\n%s", info)
	}

	// Rust can mount the Go-mutated store and read the new file.
	mountpoint, cleanup := rustMount(t, bin, dir)
	defer cleanup()
	data, err := os.ReadFile(filepath.Join(mountpoint, "go-added.txt"))
	if err != nil {
		t.Fatalf("read through Rust mount: %v", err)
	}
	if string(data) != "added by Go\n" {
		t.Fatalf("Rust mount read = %q", string(data))
	}
}

func itoa(v uint64) string { return model.FormatU64(v) }

// Gate 2: Go init + mutations -> Rust verify and mount/read.
func TestHandoffGoInitThenRust(t *testing.T) {
	bin := rustBinary(t)
	dir := t.TempDir()
	s, err := store.Init(dir, store.DefaultOptions())
	if err != nil {
		t.Fatalf("go init: %v", err)
	}
	root := model.RootID
	if _, err := s.CreateFile(root, []byte("gate2.txt"), []byte("gate two\n"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	dirID, err := s.Mkdir(root, []byte("dir"), 0o755, 0, 0)
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := s.CreateFile(dirID, []byte("nested.txt"), []byte("nested\n"), 0o600, 0, 0, nil); err != nil {
		t.Fatalf("nested create: %v", err)
	}
	if _, err := s.RelationAdd(dirID, "contains", model.ValueTarget(wcb.U64Value(7)), nil, nil); err != nil {
		t.Fatalf("relation: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	rustVerifyFull(t, bin, dir)
	if got := rustCat(t, bin, dir, "/gate2.txt"); got != "gate two\n" {
		t.Fatalf("rust cat = %q", got)
	}
	if got := rustCat(t, bin, dir, "/dir/nested.txt"); got != "nested\n" {
		t.Fatalf("rust cat nested = %q", got)
	}

	mountpoint, cleanup := rustMount(t, bin, dir)
	defer cleanup()
	data, err := os.ReadFile(filepath.Join(mountpoint, "gate2.txt"))
	if err != nil {
		t.Fatalf("read through Rust mount: %v", err)
	}
	if string(data) != "gate two\n" {
		t.Fatalf("Rust mount read = %q", string(data))
	}
	if data, err := os.ReadFile(filepath.Join(mountpoint, "dir", "nested.txt")); err != nil || string(data) != "nested\n" {
		t.Fatalf("Rust mount nested read = %q, %v", string(data), err)
	}
}

// Gate 3: alternating five generations of Go and Rust writes with integrity
// checks after every step.
func TestHandoffAlternatingGenerations(t *testing.T) {
	bin := rustBinary(t)
	dir := t.TempDir()
	s, err := store.Init(dir, store.DefaultOptions())
	if err != nil {
		t.Fatalf("go init: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	for round := 0; round < 5; round++ {
		goContent := "go-round-" + itoa(uint64(round)) + "\n"
		goName := "/go-" + itoa(uint64(round)) + ".txt"
		writer, err := store.Open(dir, store.ReadWrite)
		if err != nil {
			t.Fatalf("go writer open round %d: %v", round, err)
		}
		root, err := writer.ResolvePath("/")
		if err != nil {
			t.Fatalf("resolve root: %v", err)
		}
		if _, err := writer.CreateFile(root, []byte(strings.TrimPrefix(goName, "/")), []byte(goContent), 0o644, 0, 0, nil); err != nil {
			t.Fatalf("go create round %d: %v", round, err)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}

		rustVerifyFull(t, bin, dir)
		if got := rustCat(t, bin, dir, goName); got != goContent {
			t.Fatalf("rust read %s = %q, want %q", goName, got, goContent)
		}

		rustContent := "rust-round-" + itoa(uint64(round)) + "\n"
		rustName := "/rust-" + itoa(uint64(round)) + ".txt"
		runRust(t, bin, "--store", dir, "create", rustName, "--text", rustContent)
		// Force a Rust checkpoint so the next Go open replays from a
		// checkpoint manifest produced by the other implementation.
		runRust(t, bin, "--store", dir, "checkpoint")

		reader, err := store.Open(dir, store.ReadOnly)
		if err != nil {
			t.Fatalf("go reader open round %d: %v", round, err)
		}
		report, err := reader.Verify(true)
		if err != nil || !report.OK {
			reader.Close()
			t.Fatalf("go verify after rust round %d: ok=%v err=%v problems=%+v", round, report != nil && report.OK, err, reportProblems(report))
		}
		for _, note := range reader.RecoveryNotes() {
			if strings.Contains(note, "checkpoint") {
				reader.Close()
				t.Fatalf("go ignored a Rust checkpoint in round %d: %s", round, note)
			}
		}
		data := readObjectContent(t, reader, reader.CurrentState(), rustName)
		if data != rustContent {
			reader.Close()
			t.Fatalf("go read %s = %q, want %q", rustName, data, rustContent)
		}
		if data := readObjectContent(t, reader, reader.CurrentState(), goName); data != goContent {
			reader.Close()
			t.Fatalf("go reread %s = %q", goName, data)
		}
		if err := reader.Close(); err != nil {
			t.Fatalf("close reader: %v", err)
		}
	}

	final, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("final open: %v", err)
	}
	defer final.Close()
	report, err := final.Verify(true)
	if err != nil || !report.OK {
		t.Fatalf("final verify: ok=%v err=%v problems=%+v", report != nil && report.OK, err, reportProblems(report))
	}
	state := final.CurrentState()
	for round := 0; round < 5; round++ {
		goName := "/go-" + itoa(uint64(round)) + ".txt"
		if data := readObjectContent(t, final, state, goName); data != "go-round-"+itoa(uint64(round))+"\n" {
			t.Fatalf("%s = %q", goName, data)
		}
		rustName := "/rust-" + itoa(uint64(round)) + ".txt"
		if data := readObjectContent(t, final, state, rustName); data != "rust-round-"+itoa(uint64(round))+"\n" {
			t.Fatalf("%s = %q", rustName, data)
		}
	}
}

// Gate 5: checkpoint state manifests are understood in both directions.
func TestHandoffCheckpointsBothWays(t *testing.T) {
	bin := rustBinary(t)
	dir := t.TempDir()
	opts := store.DefaultOptions()
	opts.CheckpointInterval = 1 // every Go commit writes a checkpoint
	s, err := store.Init(dir, opts)
	if err != nil {
		t.Fatalf("go init: %v", err)
	}
	if _, err := s.CreateFile(model.RootID, []byte("ck.txt"), []byte("checkpointed"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	goGeneration := s.Generation()
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	rustVerifyFull(t, bin, dir)
	if got := rustCat(t, bin, dir, "/ck.txt"); got != "checkpointed" {
		t.Fatalf("rust cat = %q", got)
	}
	// Rust must accept the Go checkpoint, not ignore it and replay ops.
	info := runRust(t, bin, "--store", dir, "--json", "info")
	var rustInfo struct {
		RecoveryNotes []string `json:"recovery_notes"`
	}
	if err := json.Unmarshal([]byte(info), &rustInfo); err != nil {
		t.Fatalf("parse rust info: %v\n%s", err, info)
	}
	for _, note := range rustInfo.RecoveryNotes {
		if strings.Contains(note, "checkpoint") {
			t.Fatalf("rust ignored the Go checkpoint: %s", note)
		}
	}
	// A Rust writer replays from the Go checkpoint and commits on top.
	runRust(t, bin, "--store", dir, "create", "/from-rust.txt", "--text", "rust-on-go-checkpoint")
	// A Rust checkpoint is then read by Go.
	runRust(t, bin, "--store", dir, "checkpoint")

	reader, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("go reopen: %v", err)
	}
	defer reader.Close()
	if reader.Generation() <= goGeneration {
		t.Fatalf("generation = %d, want > %d", reader.Generation(), goGeneration)
	}
	report, err := reader.Verify(true)
	if err != nil || !report.OK {
		t.Fatalf("go verify: ok=%v err=%v problems=%+v", report != nil && report.OK, err, reportProblems(report))
	}
	for _, note := range reader.RecoveryNotes() {
		if strings.Contains(note, "checkpoint") {
			t.Fatalf("go ignored the Rust checkpoint: %s", note)
		}
	}
	state := reader.CurrentState()
	if got := readObjectContent(t, reader, state, "/ck.txt"); got != "checkpointed" {
		t.Fatalf("ck.txt = %q", got)
	}
	if got := readObjectContent(t, reader, state, "/from-rust.txt"); got != "rust-on-go-checkpoint" {
		t.Fatalf("from-rust.txt = %q", got)
	}
}

// Gate 4: snapshots created by Go are read by Rust and vice versa.
func TestHandoffSnapshotsBidirectional(t *testing.T) {
	bin := rustBinary(t)
	dir := t.TempDir()
	s, err := store.Init(dir, store.DefaultOptions())
	if err != nil {
		t.Fatalf("go init: %v", err)
	}
	id, err := s.CreateFile(model.RootID, []byte("snap.txt"), []byte("v1"), 0o644, 0, 0, nil)
	if err != nil {
		t.Fatalf("create v1: %v", err)
	}
	goSnapshot, err := s.SnapshotCreate("go-snap")
	if err != nil {
		t.Fatalf("go snapshot: %v", err)
	}
	snapshotState, err := s.StateAt(goSnapshot)
	if err != nil {
		t.Fatalf("state at go snapshot: %v", err)
	}
	snapshotRecord := snapshotState.Objects[id]
	if _, err := s.WriteFile(id, 0, []byte("v2")); err != nil {
		t.Fatalf("write v2: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Rust reopens the Go snapshot by name and reports the exact identities.
	pin := runRust(t, bin, "--store", dir, "--json", "pin", "/snap.txt", "--snapshot", "go-snap")
	var pinned struct {
		SnapshotID string `json:"snapshot_id"`
		ObjectID   string `json:"object_id"`
		VersionID  string `json:"version_id"`
		ContentID  string `json:"content_id"`
	}
	if err := json.Unmarshal([]byte(pin), &pinned); err != nil {
		t.Fatalf("parse rust pin: %v\n%s", err, pin)
	}
	if pinned.SnapshotID != goSnapshot.Hex() || pinned.ObjectID != id.Hex() ||
		pinned.VersionID != snapshotRecord.Version.Hex() || pinned.ContentID != snapshotRecord.Content.Hex() {
		t.Fatalf("rust pin at go-snap = %+v, want snapshot=%s version=%s content=%s",
			pinned, goSnapshot.Hex(), snapshotRecord.Version.Hex(), snapshotRecord.Content.Hex())
	}

	// Rust mounts the Go snapshot and reads the old bytes.
	mountpoint, cleanup := rustMount(t, bin, dir, "--snapshot", "go-snap")
	data, err := os.ReadFile(filepath.Join(mountpoint, "snap.txt"))
	cleanup()
	if err != nil {
		t.Fatalf("read through Rust snapshot mount: %v", err)
	}
	if string(data) != "v1" {
		t.Fatalf("Rust snapshot mount read = %q, want v1", string(data))
	}

	// Rust creates a snapshot; Go reopens it and reads the pinned state.
	runRust(t, bin, "--store", dir, "snapshot", "create", "rust-snap")
	reader, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("go reopen: %v", err)
	}
	defer reader.Close()
	rustSnapshot, err := reader.LookupSnapshot("rust-snap")
	if err != nil {
		t.Fatalf("go lookup rust-snap: %v", err)
	}
	state, err := reader.StateAt(rustSnapshot)
	if err != nil {
		t.Fatalf("go state at rust-snap: %v", err)
	}
	if got := readObjectContent(t, reader, state, "/snap.txt"); got != "v2" {
		t.Fatalf("go read rust-snap content = %q, want v2", got)
	}
	if got := readObjectContent(t, reader, reader.CurrentState(), "/snap.txt"); got != "v2" {
		t.Fatalf("go live content = %q, want v2", got)
	}
}
