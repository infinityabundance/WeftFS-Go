package fusefs_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/infinityabundance/WeftCodec-Go/limits"
	"github.com/infinityabundance/WeftCodec-Go/selector"
	"github.com/infinityabundance/WeftFS-Go/auth"
	"github.com/infinityabundance/WeftFS-Go/fusefs"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
)

const fixtureRel = "../conformance/store/v1"

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	})
	if err != nil {
		t.Fatalf("copy tree: %v", err)
	}
}

type mounted struct {
	dir    string
	mnt    string
	st     *store.Store
	srv    *fusefs.Server
	server *fuse.Server
}

func mount(t *testing.T, dir string, mode store.OpenMode, opts fusefs.Options) mounted {
	t.Helper()
	st, err := store.Open(dir, mode)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	mnt := t.TempDir()
	opts.Mountpoint = mnt
	server, srv, err := fusefs.Mount(st, opts)
	if err != nil {
		st.Close()
		t.Fatalf("mount: %v", err)
	}
	m := mounted{dir: dir, mnt: mnt, st: st, srv: srv, server: server}
	t.Cleanup(func() {
		_ = server.Unmount()
		server.Wait()
		_ = st.Close()
	})
	return m
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func inoOf(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat %s: %v", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("no syscall.Stat_t for %s", path)
	}
	return stat.Ino
}

func TestFixtureMountReadOnly(t *testing.T) {
	dir := t.TempDir()
	copyTree(t, fixtureRel, dir)
	m := mount(t, dir, store.ReadOnly, fusefs.Options{ReadOnly: true})

	if got := readFile(t, filepath.Join(m.mnt, "hello.txt")); string(got) != "hello weft\n" {
		t.Fatalf("hello.txt = %q", string(got))
	}
	if got := readFile(t, filepath.Join(m.mnt, "docs/readme.md")); string(got) != "# WeftFS fixture\n\nDeterministic store for cross-language handoff.\n" {
		t.Fatalf("readme.md = %q", string(got))
	}
	binaryPath := filepath.Join(m.mnt, "data/binary.bin")
	binary := readFile(t, binaryPath)
	expected := make([]byte, 4096)
	for index := 0; index < 4096; index++ {
		expected[index] = byte((uint32(index)*37 + 11) % 256)
	}
	if !bytes.Equal(binary, expected) {
		t.Fatal("binary.bin bytes differ from the fixture contract")
	}

	target, err := os.Readlink(filepath.Join(m.mnt, "link"))
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if target != "hello.txt" {
		t.Fatalf("symlink target = %q", target)
	}

	if inoOf(t, filepath.Join(m.mnt, "hello.txt")) != inoOf(t, filepath.Join(m.mnt, "hello.txt-hard")) {
		t.Fatal("hard links report different inode numbers")
	}
	info, err := os.Stat(filepath.Join(m.mnt, "hello.txt"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if stat.Nlink != 2 {
		t.Fatalf("nlink = %d, want 2", stat.Nlink)
	}
	if inoOf(t, m.mnt) != 1 {
		t.Fatalf("root ino = %d, want 1", inoOf(t, m.mnt))
	}

	// readdir and lookup agree for a directory.
	entries, err := os.ReadDir(m.mnt)
	if err != nil {
		t.Fatalf("readdir root: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	for _, want := range []string{".weft", "data", "docs", "hello.txt", "hello.txt-hard", "link"} {
		found := false
		for _, name := range names {
			if name == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("root listing %v is missing %q", names, want)
		}
	}

	// Exact object access.
	helloID := "e1295a99361e040c88a81186ad25bb6fe9f224467f24ce597f9cdfb68d0407b6"
	exact := filepath.Join(m.mnt, ".weft", "id", helloID)
	if got := readFile(t, exact); string(got) != "hello weft\n" {
		t.Fatalf("exact-id read = %q", string(got))
	}
	dataDirID := "59a74318a4a42b2ddf57755adc103a47d84647f0fbbdf93543a704e898442b72"
	children, err := os.ReadDir(filepath.Join(m.mnt, ".weft", "id", dataDirID))
	if err != nil {
		t.Fatalf("readdir exact id dir: %v", err)
	}
	if len(children) != 1 || children[0].Name() != "binary.bin" {
		t.Fatalf("exact id dir = %v", children)
	}
	if _, err := os.Stat(filepath.Join(m.mnt, ".weft", "id", strings.Repeat("0", 63)+"1")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing exact id did not return ENOENT: %v", err)
	}

	// Read-only mount refuses writes.
	if err := os.WriteFile(filepath.Join(m.mnt, "new.txt"), []byte("x"), 0o644); !errors.Is(err, syscall.EROFS) {
		t.Fatalf("write on read-only mount = %v, want EROFS", err)
	}
	if err := os.Mkdir(filepath.Join(m.mnt, "newdir"), 0o755); !errors.Is(err, syscall.EROFS) {
		t.Fatalf("mkdir on read-only mount = %v, want EROFS", err)
	}
}

func newEmptyStore(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Init(dir, store.DefaultOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return dir
}

func TestMountWritesAndPosixSurface(t *testing.T) {
	dir := newEmptyStore(t)
	m := mount(t, dir, store.ReadWrite, fusefs.Options{})

	// create + read
	if err := os.WriteFile(filepath.Join(m.mnt, "a.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := readFile(t, filepath.Join(m.mnt, "a.txt")); string(got) != "hello" {
		t.Fatalf("read = %q", string(got))
	}
	if err := os.Mkdir(filepath.Join(m.mnt, "d"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// The kernel may split writes; each is one atomic commit.
	file, err := os.OpenFile(filepath.Join(m.mnt, "d", "b.txt"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatalf("create nested: %v", err)
	}
	if _, err := file.Write([]byte("0123456789")); err != nil {
		t.Fatalf("write nested: %v", err)
	}
	if _, err := file.WriteAt([]byte("AB"), 2); err != nil {
		t.Fatalf("pwrite nested: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close nested: %v", err)
	}
	if got := readFile(t, filepath.Join(m.mnt, "d", "b.txt")); string(got) != "01AB456789" {
		t.Fatalf("nested content = %q", string(got))
	}

	// rename, link, symlink
	if err := os.Rename(filepath.Join(m.mnt, "a.txt"), filepath.Join(m.mnt, "d", "moved.txt")); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if _, err := os.Stat(filepath.Join(m.mnt, "a.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old name still resolves: %v", err)
	}
	if err := os.Link(filepath.Join(m.mnt, "d", "moved.txt"), filepath.Join(m.mnt, "hard.txt")); err != nil {
		t.Fatalf("link: %v", err)
	}
	if inoOf(t, filepath.Join(m.mnt, "d", "moved.txt")) != inoOf(t, filepath.Join(m.mnt, "hard.txt")) {
		t.Fatal("hard link inode numbers differ")
	}
	if err := os.Symlink("d/moved.txt", filepath.Join(m.mnt, "sym")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if target, err := os.Readlink(filepath.Join(m.mnt, "sym")); err != nil || target != "d/moved.txt" {
		t.Fatalf("readlink = %q, %v", target, err)
	}

	// truncate via setattr
	if err := os.Truncate(filepath.Join(m.mnt, "d", "moved.txt"), 3); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if got := readFile(t, filepath.Join(m.mnt, "d", "moved.txt")); string(got) != "hel" {
		t.Fatalf("truncated = %q", string(got))
	}

	// chmod via setattr
	if err := os.Chmod(filepath.Join(m.mnt, "d", "moved.txt"), 0o600); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if info, err := os.Stat(filepath.Join(m.mnt, "d", "moved.txt")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("chmod did not stick: %v %v", info.Mode(), err)
	}

	// extended attributes
	xpath := filepath.Join(m.mnt, "hard.txt")
	if err := syscall.Setxattr(xpath, "user.demo", []byte("v1"), 0); err != nil {
		t.Fatalf("setxattr: %v", err)
	}
	buf := make([]byte, 16)
	n, err := syscall.Getxattr(xpath, "user.demo", buf)
	if err != nil || string(buf[:n]) != "v1" {
		t.Fatalf("getxattr = %q, %v", string(buf[:n]), err)
	}
	size, err := syscall.Listxattr(xpath, nil)
	if err != nil {
		t.Fatalf("listxattr size: %v", err)
	}
	listBuf := make([]byte, size)
	n, err = syscall.Listxattr(xpath, listBuf)
	if err != nil {
		t.Fatalf("listxattr: %v", err)
	}
	if !bytes.Contains(listBuf[:n], []byte("user.demo\x00")) {
		t.Fatalf("listxattr = %q", string(listBuf[:n]))
	}
	if err := syscall.Removexattr(xpath, "user.demo"); err != nil {
		t.Fatalf("removexattr: %v", err)
	}
	if _, err := syscall.Getxattr(xpath, "user.demo", buf); !errors.Is(err, syscall.ENODATA) {
		t.Fatalf("getxattr after remove = %v, want ENODATA", err)
	}

	// remove
	if err := os.Remove(filepath.Join(m.mnt, "hard.txt")); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	if err := os.Remove(filepath.Join(m.mnt, "d", "moved.txt")); err != nil {
		t.Fatalf("unlink second link: %v", err)
	}
	if err := os.Remove(filepath.Join(m.mnt, "sym")); err != nil {
		t.Fatalf("unlink symlink: %v", err)
	}
	if err := os.Remove(filepath.Join(m.mnt, "d", "b.txt")); err != nil {
		t.Fatalf("unlink b: %v", err)
	}
	if err := os.Remove(filepath.Join(m.mnt, "d")); err != nil {
		t.Fatalf("rmdir: %v", err)
	}

	report, err := m.srv.Verify(true)
	if err != nil || !report.OK {
		t.Fatalf("verify while mounted: ok=%v err=%v problems=%+v", report != nil && report.OK, err, report.Problems)
	}
}

func TestSnapshotMountIsReadOnlyAtOldVersion(t *testing.T) {
	dir := newEmptyStore(t)
	writer, err := store.Open(dir, store.ReadWrite)
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	if _, err := writer.CreateFile(model.RootID, []byte("snap.txt"), []byte("v1"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("create v1: %v", err)
	}
	snapshot, err := writer.SnapshotCreate("one")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	id, err := writer.ResolvePath("/snap.txt")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if _, err := writer.WriteFile(id, 0, []byte("v2!")); err != nil {
		t.Fatalf("write v2: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	snapMount := mount(t, dir, store.ReadOnly, fusefs.Options{Snapshot: &snapshot})
	if got := readFile(t, filepath.Join(snapMount.mnt, "snap.txt")); string(got) != "v1" {
		t.Fatalf("snapshot content = %q, want v1", string(got))
	}
	if err := os.WriteFile(filepath.Join(snapMount.mnt, "snap.txt"), []byte("nope"), 0o644); !errors.Is(err, syscall.EROFS) {
		t.Fatalf("snapshot write = %v, want EROFS", err)
	}
	_ = snapMount.server.Unmount()

	live := mount(t, dir, store.ReadOnly, fusefs.Options{ReadOnly: true})
	if got := readFile(t, filepath.Join(live.mnt, "snap.txt")); string(got) != "v2!" {
		t.Fatalf("live content = %q, want v2!", string(got))
	}
}

func TestContextViewNamesAndLookupAgree(t *testing.T) {
	dir := newEmptyStore(t)
	writer, err := store.Open(dir, store.ReadWrite)
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	root := model.RootID
	a, err := writer.Mkdir(root, []byte("a"), 0o755, 0, 0)
	if err != nil {
		t.Fatalf("mkdir a: %v", err)
	}
	b, err := writer.Mkdir(root, []byte("b"), 0o755, 0, 0)
	if err != nil {
		t.Fatalf("mkdir b: %v", err)
	}
	if _, err := writer.CreateFile(a, []byte("same.txt"), []byte("content-a"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("file a: %v", err)
	}
	if _, err := writer.CreateFile(b, []byte("same.txt"), []byte("content-b"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("file b: %v", err)
	}
	if _, err := writer.CreateFile(root, []byte("hello.txt"), []byte("hello"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("hello: %v", err)
	}
	parsed, err := selector.Parse(`select kind == "file"`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := writer.SaveContext("demo", parsed); err != nil {
		t.Fatalf("save context: %v", err)
	}
	resolution, err := writer.Resolve(parsed, nil, auth.Root(), limits.Default())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolution.MatchedCount != 3 {
		t.Fatalf("matched = %d, want 3", resolution.MatchedCount)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	m := mount(t, dir, store.ReadOnly, fusefs.Options{ReadOnly: true})
	contextDir := filepath.Join(m.mnt, ".weft", "contexts", "demo")
	entries, err := os.ReadDir(contextDir)
	if err != nil {
		t.Fatalf("readdir context: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("context has %d entries, want 3 (no silent singleton)", len(entries))
	}
	names := make([]string, 0, len(entries))
	seen := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		names = append(names, name)
		if seen[name] {
			t.Fatalf("duplicate context display name %q", name)
		}
		seen[name] = true
		index := strings.LastIndex(name, "--")
		if index < 0 {
			t.Fatalf("context entry %q lacks the --<hex> suffix", name)
		}
		suffix := name[index+2:]
		if len(suffix) != 8 {
			t.Fatalf("context entry %q suffix %q is not 8 hex characters", name, suffix)
		}
		for _, c := range suffix {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Fatalf("context entry %q suffix is not lowercase hex", name)
			}
		}
		// readdir and lookup agree: the same name opens and yields one of the
		// exact authorized contents.
		data := readFile(t, filepath.Join(contextDir, name))
		if string(data) != "content-a" && string(data) != "content-b" && string(data) != "hello" {
			t.Fatalf("context entry %q content = %q", name, string(data))
		}
	}
	if !sort.StringsAreSorted(names) {
		t.Fatalf("context listing is not deterministic: %v", names)
	}
	if len(seen) != 3 {
		t.Fatal("context names do not cover every authorized result")
	}

	// Saved-context listing and lookup agree.
	if entries, err := os.ReadDir(filepath.Join(m.mnt, ".weft", "contexts")); err != nil || len(entries) != 1 || entries[0].Name() != "demo" {
		t.Fatalf("contexts listing = %v, %v", entries, err)
	}
	if _, err := os.Stat(filepath.Join(m.mnt, ".weft", "contexts", "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing context = %v, want ENOENT", err)
	}

	// Exact-id access to a hard-to-name object.
	state := m.srv.SnapshotState()
	var sameID model.Hash32
	for _, entry := range state.Entries {
		if string(entry.Name) == "same.txt" {
			sameID = entry.Target
			break
		}
	}
	exactPath := filepath.Join(m.mnt, ".weft", "id", sameID.Hex())
	data := readFile(t, exactPath)
	if string(data) != "content-a" && string(data) != "content-b" {
		t.Fatalf("exact id content = %q", string(data))
	}
}

func TestOpenUnlinkedHandle(t *testing.T) {
	dir := newEmptyStore(t)
	m := mount(t, dir, store.ReadWrite, fusefs.Options{})
	path := filepath.Join(m.mnt, "open-unlinked.txt")
	if err := os.WriteFile(path, []byte("payload"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	data := make([]byte, 7)
	if _, err := file.ReadAt(data, 0); err != nil {
		t.Fatalf("read unlinked: %v", err)
	}
	if string(data) != "payload" {
		t.Fatalf("unlinked read = %q", string(data))
	}
	if _, err := file.WriteAt([]byte("PAY"), 0); err != nil {
		t.Fatalf("write unlinked: %v", err)
	}
	updated := make([]byte, 7)
	if _, err := file.ReadAt(updated, 0); err != nil {
		t.Fatalf("read updated: %v", err)
	}
	if string(updated) != "PAYload" {
		t.Fatalf("updated unlinked content = %q", string(updated))
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		found := false
		for _, record := range m.srv.SnapshotState().Objects {
			if record.Kind == model.KindFile && record.Size == 7 {
				found = true
			}
		}
		if !found {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("open-unlinked object record was not reclaimed after release")
}

func TestSeparateFileConcurrency(t *testing.T) {
	dir := newEmptyStore(t)
	m := mount(t, dir, store.ReadWrite, fusefs.Options{})
	const workers = 6
	const rounds = 12
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			path := filepath.Join(m.mnt, "worker-"+string(rune('a'+worker))+".txt")
			expected := ""
			for round := 0; round < rounds; round++ {
				expected += string(rune('A' + worker))
				file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
				if err != nil {
					errs <- err
					return
				}
				if _, err := file.Write([]byte(expected)); err != nil {
					file.Close()
					errs <- err
					return
				}
				if err := file.Close(); err != nil {
					errs <- err
					return
				}
				data, err := os.ReadFile(path)
				if err != nil {
					errs <- err
					return
				}
				if string(data) != expected {
					errs <- errors.New("read-back mismatch on " + path)
					return
				}
			}
		}(worker)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent traffic: %v", err)
	}
	report, err := m.srv.Verify(true)
	if err != nil || !report.OK {
		t.Fatalf("verify after concurrency: ok=%v err=%v problems=%+v", report != nil && report.OK, err, report.Problems)
	}
}
