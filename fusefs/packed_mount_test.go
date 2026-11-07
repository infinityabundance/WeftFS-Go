package fusefs_test

// CLI-layout mount coverage: stores built by the Go CLI with `--pack`, with the
// blob/commit plane split, and with both, are mounted by the Go FUSE daemon and
// every file is read back byte-exactly. The Go CLI expresses all three layouts;
// no layout needed a workaround.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type cliLayout struct {
	name   string
	flags  []string
	packed bool
	split  bool
}

func goCLIBinary(t *testing.T) string {
	t.Helper()
	base := os.Getenv("GOTMPDIR")
	if base == "" {
		base = os.TempDir()
	}
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatalf("prepare CLI build directory: %v", err)
	}
	dir, err := os.MkdirTemp(base, "weft-cli-")
	if err != nil {
		t.Fatalf("create CLI build directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	bin := filepath.Join(dir, "weftfs")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/weftfs")
	cmd.Dir = ".."
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, buildErr := cmd.CombinedOutput(); buildErr != nil {
		t.Fatalf("build the Go CLI: %v\n%s", buildErr, output)
	}
	return bin
}

func cliArgs(storeDir string, flags []string, rest ...string) []string {
	args := []string{"--store", storeDir}
	args = append(args, flags...)
	return append(args, rest...)
}

func runGoCLI(t *testing.T, bin string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("weftfs %s failed: %v\n%s", strings.Join(args, " "), err, output)
	}
	return string(output)
}

// cliMountFixtureFiles is deterministic so every layout writes identical
// logical bytes and can be compared against identical SHA-256 sums.
func cliMountFixtureFiles() map[string][]byte {
	notes := strings.Repeat("packed mount notes: exact bytes survive the CLI layout.\n", 48)
	return map[string][]byte{
		"/small.txt":       []byte("packed hello\n"),
		"/docs/readme.md":  []byte("# packed mount\n\nbuilt by the Go CLI\n"),
		"/docs/notes.md":   []byte(notes),
		"/packed/a.txt":    patternFixtureBytes(1024, 0xa1),
		"/packed/b.txt":    patternFixtureBytes(2048, 0xb2),
		"/packed/c.txt":    patternFixtureBytes(777, 0xc3),
		"/packed/d.txt":    patternFixtureBytes(4096, 0xd4),
		"/data/medium.bin": patternFixtureBytes(70_000, 0xe5),
		"/data/large.bin":  patternFixtureBytes(300_000, 0xf6),
	}
}

func patternFixtureBytes(size int, seed uint32) []byte {
	out := make([]byte, size)
	state := seed
	for index := range out {
		state = state*1664525 + 1013904223
		out[index] = byte(state >> 24)
	}
	return out
}

// startCLIMount runs the Go CLI mount daemon and waits for the kernel to
// publish the mountpoint. The returned cleanup is idempotent.
func startCLIMount(t *testing.T, bin, storeDir string, flags []string) (string, func()) {
	t.Helper()
	mountpoint := t.TempDir()
	args := cliArgs(storeDir, flags, "mount", "--mountpoint", mountpoint, "--read-only")
	cmd := exec.Command(bin, args...)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start mount daemon: %v", err)
	}
	absMount, err := filepath.Abs(mountpoint)
	if err != nil {
		absMount = mountpoint
	}
	deadline := time.Now().Add(30 * time.Second)
	mounted := false
	for time.Now().Before(deadline) {
		if cliMountInfoContains(absMount) {
			mounted = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			_ = syscall.Unmount(mountpoint, 0)
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				_ = cmd.Process.Kill()
				<-done
			}
		})
	}
	if !mounted {
		cleanup()
		t.Fatalf("mount did not appear; daemon output:\n%s", output.String())
	}
	return mountpoint, cleanup
}

func cliMountInfoContains(mountpoint string) bool {
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

func listingDigest(names []string) string {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(strings.Join(sorted, "\n") + "\n"))
	return hex.EncodeToString(sum[:])
}

func TestCLIPackedAndSplitMounts(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skipf("/dev/fuse is unavailable; run this in the fuse court: %v", err)
	}
	bin := goCLIBinary(t)
	layouts := []cliLayout{
		{name: "pack", flags: []string{"--pack"}, packed: true},
		{name: "split", flags: []string{"--blob-backend", "object", "--commit-backend", "local"}, split: true},
		{
			name:   "packed-split",
			flags:  []string{"--pack", "--blob-backend", "object", "--commit-backend", "local"},
			packed: true, split: true,
		},
	}
	files := cliMountFixtureFiles()
	for _, layout := range layouts {
		layout := layout
		t.Run(layout.name, func(t *testing.T) {
			storeDir := t.TempDir()
			runGoCLI(t, bin, cliArgs(storeDir, layout.flags, "init")...)
			for _, dir := range []string{"/docs", "/data", "/packed"} {
				runGoCLI(t, bin, cliArgs(storeDir, layout.flags, "mkdir", dir)...)
			}
			inputDir := t.TempDir()
			for path, data := range files {
				input := filepath.Join(inputDir, strings.ReplaceAll(strings.TrimPrefix(path, "/"), "/", "_"))
				if err := os.WriteFile(input, data, 0o644); err != nil {
					t.Fatalf("write fixture input %s: %v", path, err)
				}
				runGoCLI(t, bin, cliArgs(storeDir, layout.flags, "create", path, "--file", input)...)
			}

			// The layout must be the one the flags asked for.
			var info struct {
				Planes struct {
					Blobs struct {
						Backend string `json:"backend"`
					} `json:"blobs"`
					Commits struct {
						Backend string `json:"backend"`
					} `json:"commits"`
					Packing bool `json:"packing"`
				} `json:"planes"`
				Packs *struct {
					SealedPacks   uint64 `json:"sealed_packs"`
					PackedMembers uint64 `json:"packed_members"`
					PackedBytes   uint64 `json:"packed_bytes"`
					FlatMembers   uint64 `json:"flat_members"`
				} `json:"packs"`
			}
			if err := json.Unmarshal([]byte(runGoCLI(t, bin,
				cliArgs(storeDir, layout.flags, "--json", "info")...)), &info); err != nil {
				t.Fatalf("info --json: %v", err)
			}
			if info.Planes.Packing != layout.packed {
				t.Fatalf("planes.packing = %v, want %v", info.Planes.Packing, layout.packed)
			}
			if layout.packed {
				if info.Packs == nil || info.Packs.SealedPacks == 0 || info.Packs.PackedMembers == 0 {
					t.Fatalf("packed layout has no packs: %+v", info.Packs)
				}
				if info.Packs.PackedBytes == 0 {
					t.Fatalf("packed layout recorded zero packed bytes")
				}
				t.Logf("packs: sealed=%d members=%d packed_bytes=%d flat_members=%d",
					info.Packs.SealedPacks, info.Packs.PackedMembers,
					info.Packs.PackedBytes, info.Packs.FlatMembers)
			}
			if layout.split {
				// The pack plane wraps the blob plane and reports
				// `packed-object`, so accept either form; the commit plane must be
				// local in all split layouts.
				if !strings.HasSuffix(info.Planes.Blobs.Backend, "object") || info.Planes.Commits.Backend != "local" {
					t.Fatalf("split layout reported blobs=%s commits=%s",
						info.Planes.Blobs.Backend, info.Planes.Commits.Backend)
				}
				t.Logf("split: blobs=%s commits=%s", info.Planes.Blobs.Backend, info.Planes.Commits.Backend)
			}

			mountpoint, cleanup := startCLIMount(t, bin, storeDir, layout.flags)
			defer cleanup()

			for path, want := range files {
				got, err := os.ReadFile(filepath.Join(mountpoint, filepath.FromSlash(strings.TrimPrefix(path, "/"))))
				if err != nil {
					t.Fatalf("read %s: %v", path, err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("%s bytes differ (%d vs %d bytes)", path, len(got), len(want))
				}
				gotSum := sha256.Sum256(got)
				wantSum := sha256.Sum256(want)
				if gotSum != wantSum {
					t.Fatalf("%s sha256 %x != %x", path, gotSum, wantSum)
				}
			}
			// One ranged read (the kernel may serve it from page cache; the
			// bytes are still compared against the writer's slice).
			large := files["/data/large.bin"]
			handle, err := os.Open(filepath.Join(mountpoint, "data", "large.bin"))
			if err != nil {
				t.Fatalf("open large.bin: %v", err)
			}
			buffer := make([]byte, 8192)
			if _, err := handle.ReadAt(buffer, 100_000); err != nil {
				handle.Close()
				t.Fatalf("ReadAt large.bin: %v", err)
			}
			handle.Close()
			if !bytes.Equal(buffer, large[100_000:108_192]) {
				t.Fatalf("ranged read of large.bin differs")
			}

			// Directory listing digests, equal across layouts.
			rootNames := readNames(t, mountpoint)
			docsNames := readNames(t, filepath.Join(mountpoint, "docs"))
			rootDigest := listingDigest(rootNames)
			docsDigest := listingDigest(docsNames)
			if want := listingDigest([]string{".weft", "data", "docs", "packed", "small.txt"}); rootDigest != want {
				t.Fatalf("root listing digest %s != %s (%v)", rootDigest, want, rootNames)
			}
			if want := listingDigest([]string{"notes.md", "readme.md"}); docsDigest != want {
				t.Fatalf("docs listing digest %s != %s (%v)", docsDigest, want, docsNames)
			}
			t.Logf("%s: files=%d root_digest=%s docs_digest=%s", layout.name, len(files), rootDigest, docsDigest)

			cleanup()

			var report struct {
				OK   bool
				Full bool
			}
			if err := json.Unmarshal([]byte(runGoCLI(t, bin,
				cliArgs(storeDir, layout.flags, "--json", "verify", "--full")...)), &report); err != nil {
				t.Fatalf("verify --full --json: %v", err)
			}
			if !report.OK || !report.Full {
				t.Fatalf("verify --full reported ok=%v full=%v", report.OK, report.Full)
			}
			t.Logf("%s: verify --full ok=%v", layout.name, report.OK)
		})
	}
}

func readNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir %s: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}
