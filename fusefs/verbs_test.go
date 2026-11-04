package fusefs_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/infinityabundance/WeftFS-Go/fusefs"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
)

const (
	seekData = 3
	seekHole = 4

	fallocKeepSize  = 0x01
	fallocPunchHole = 0x02
	fallocCollapse  = 0x08
	fallocZeroRange = 0x10
	fallocInsert    = 0x20
)

func TestMknodRegularFilesOnly(t *testing.T) {
	dir := newEmptyStore(t)
	m := mount(t, dir, store.ReadWrite, fusefs.Options{})

	path := filepath.Join(m.mnt, "node.txt")
	if err := syscall.Mknod(path, syscall.S_IFREG|0o640, 0); err != nil {
		t.Fatalf("mknod regular: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if info.Mode()&os.ModeType != 0 {
		t.Fatalf("mknod regular mode = %v", info.Mode())
	}
	if err := os.WriteFile(path, []byte("mknod-body"), 0o640); err != nil {
		t.Fatalf("write mknod file: %v", err)
	}
	if got := readFile(t, path); string(got) != "mknod-body" {
		t.Fatalf("mknod content = %q", string(got))
	}

	for name, mode := range map[string]uint32{
		"fifo":   syscall.S_IFIFO,
		"socket": syscall.S_IFSOCK,
		"char":   syscall.S_IFCHR,
		"block":  syscall.S_IFBLK,
	} {
		err := syscall.Mknod(filepath.Join(m.mnt, name), mode|0o644, 0)
		if !errors.Is(err, syscall.EPERM) {
			t.Fatalf("mknod %s = %v, want EPERM (v1 has no FIFO/socket/device kind)", name, err)
		}
	}

	ro := mount(t, dir, store.ReadOnly, fusefs.Options{ReadOnly: true})
	err = syscall.Mknod(filepath.Join(ro.mnt, "readonly.txt"), syscall.S_IFREG|0o644, 0)
	if !errors.Is(err, syscall.EROFS) {
		t.Fatalf("mknod on read-only mount = %v, want EROFS", err)
	}
}

func TestTmpfileWriteLinkAndRelease(t *testing.T) {
	dir := newEmptyStore(t)
	m := mount(t, dir, store.ReadWrite, fusefs.Options{})

	file, err := os.OpenFile(m.mnt, unix.O_TMPFILE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("O_TMPFILE: %v", err)
	}
	if _, err := file.WriteAt([]byte("tmp-body"), 0); err != nil {
		t.Fatalf("write tmpfile: %v", err)
	}
	readBack := make([]byte, 8)
	if _, err := file.ReadAt(readBack, 0); err != nil {
		t.Fatalf("read tmpfile: %v", err)
	}
	if string(readBack) != "tmp-body" {
		t.Fatalf("tmpfile read = %q", string(readBack))
	}
	procPath := fmt.Sprintf("/proc/self/fd/%d", file.Fd())
	linked := filepath.Join(m.mnt, "linked.txt")
	if err := unix.Linkat(unix.AT_FDCWD, procPath, unix.AT_FDCWD, linked, unix.AT_SYMLINK_FOLLOW); err != nil {
		file.Close()
		t.Fatalf("linkat O_TMPFILE: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close linked tmpfile: %v", err)
	}
	if got := readFile(t, linked); string(got) != "tmp-body" {
		t.Fatalf("linked tmpfile content = %q", string(got))
	}

	before := countFileObjects(m.srv.SnapshotState())
	unlinked, err := os.OpenFile(m.mnt, unix.O_TMPFILE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("second O_TMPFILE: %v", err)
	}
	if _, err := unlinked.WriteAt([]byte("ephemeral"), 0); err != nil {
		t.Fatalf("write unlinked tmpfile: %v", err)
	}
	if err := unlinked.Close(); err != nil {
		t.Fatalf("close unlinked tmpfile: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if countFileObjects(m.srv.SnapshotState()) == before {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := countFileObjects(m.srv.SnapshotState()); got != before {
		t.Fatalf("unlinked tmpfile record survived release: files=%d want %d", got, before)
	}
	if report, err := m.srv.Verify(true); err != nil || !report.OK {
		t.Fatalf("verify after tmpfile: ok=%v err=%v problems=%+v", report != nil && report.OK, err, report.Problems)
	}
}

func countFileObjects(state *model.State) int {
	count := 0
	for _, record := range state.Objects {
		if record.Kind == model.KindFile {
			count++
		}
	}
	return count
}

func TestFallocateModesOnDenseFiles(t *testing.T) {
	dir := newEmptyStore(t)
	m := mount(t, dir, store.ReadWrite, fusefs.Options{})
	path := filepath.Join(m.mnt, "fallocate.bin")
	if err := os.WriteFile(path, []byte("abcdef"), 0o644); err != nil {
		t.Fatalf("create: %v", err)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer file.Close()
	fd := int(file.Fd())

	if err := unix.Fallocate(fd, 0, 0, 10); err != nil {
		t.Fatalf("fallocate mode 0: %v", err)
	}
	want := append([]byte("abcdef"), make([]byte, 4)...)
	if got := readFile(t, path); !bytes.Equal(got, want) {
		t.Fatalf("after mode 0 = %q, want %q", got, want)
	}

	if err := unix.Fallocate(fd, fallocPunchHole|fallocKeepSize, 1, 2); err != nil {
		t.Fatalf("fallocate punch hole: %v", err)
	}
	want = []byte{'a', 0, 0, 'd', 'e', 'f', 0, 0, 0, 0}
	if got := readFile(t, path); !bytes.Equal(got, want) {
		t.Fatalf("after PUNCH_HOLE = %q, want %q", got, want)
	}

	if err := unix.Fallocate(fd, fallocZeroRange|fallocKeepSize, 0, 3); err != nil {
		t.Fatalf("fallocate zero range: %v", err)
	}
	want = []byte{0, 0, 0, 'd', 'e', 'f', 0, 0, 0, 0}
	if got := readFile(t, path); !bytes.Equal(got, want) {
		t.Fatalf("after ZERO_RANGE = %q, want %q", got, want)
	}

	// The 7.3.1 FUSE kernel boundary refuses COLLAPSE_RANGE/INSERT_RANGE
	// before sending FUSE_FALLOCATE (observed with go-fuse debug: no request).
	// The store implementation is covered directly by
	// TestCollapseAndInsertRangeStoreLevel; here we only assert that the
	// refusal is EOPNOTSUPP and that content is unchanged if it happens.
	collapseErr := unix.Fallocate(fd, fallocCollapse, 1, 2)
	switch {
	case collapseErr == nil:
		want = []byte{0, 'd', 'e', 'f', 0, 0, 0, 0}
		if got := readFile(t, path); !bytes.Equal(got, want) {
			t.Fatalf("after COLLAPSE_RANGE = %q, want %q", got, want)
		}
		if err := unix.Fallocate(fd, fallocInsert, 1, 2); err != nil {
			t.Fatalf("fallocate insert: %v", err)
		}
		want = []byte{0, 0, 0, 'd', 'e', 'f', 0, 0, 0, 0}
		if got := readFile(t, path); !bytes.Equal(got, want) {
			t.Fatalf("after INSERT_RANGE = %q, want %q", got, want)
		}
	case errors.Is(collapseErr, syscall.EOPNOTSUPP):
		t.Log("kernel FUSE boundary refused COLLAPSE_RANGE before forwarding; store-level test covers insertion/collapse")
	default:
		t.Fatalf("fallocate collapse = %v, want success or EOPNOTSUPP", collapseErr)
	}

	if err := unix.Fallocate(fd, 0, 0, 0); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("zero-length fallocate = %v, want EINVAL", err)
	}
	if err := unix.Fallocate(fd, fallocPunchHole, 0, 1); !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.EOPNOTSUPP) {
		t.Fatalf("PUNCH_HOLE without KEEP_SIZE = %v, want EINVAL or the kernel-boundary EOPNOTSUPP", err)
	}
	if err := unix.Fallocate(fd, 0x40, 0, 1); !errors.Is(err, syscall.EOPNOTSUPP) {
		t.Fatalf("unknown fallocate mode = %v, want EOPNOTSUPP", err)
	}
	if err := unix.Fallocate(fd, 0, 1<<40, 1<<40); !errors.Is(err, syscall.EFBIG) {
		t.Fatalf("oversized fallocate = %v, want EFBIG", err)
	}
	if report, err := m.srv.Verify(true); err != nil || !report.OK {
		t.Fatalf("verify after fallocate: ok=%v err=%v problems=%+v", report != nil && report.OK, err, report.Problems)
	}
}

func TestCopyFileRangeServerSide(t *testing.T) {
	dir := newEmptyStore(t)
	m := mount(t, dir, store.ReadWrite, fusefs.Options{})
	sourcePath := filepath.Join(m.mnt, "source.bin")
	destPath := filepath.Join(m.mnt, "dest.bin")
	if err := os.WriteFile(sourcePath, []byte("0123456789"), 0o644); err != nil {
		t.Fatalf("source: %v", err)
	}
	if err := os.WriteFile(destPath, nil, 0o644); err != nil {
		t.Fatalf("dest: %v", err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatalf("open source: %v", err)
	}
	defer source.Close()
	dest, err := os.OpenFile(destPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open dest: %v", err)
	}
	defer dest.Close()

	offIn, offOut := int64(0), int64(0)
	copied, err := unix.CopyFileRange(int(source.Fd()), &offIn, int(dest.Fd()), &offOut, 5, 0)
	if err != nil || copied != 5 {
		t.Fatalf("copy_file_range = %d, %v", copied, err)
	}
	if got := readFile(t, destPath); string(got) != "01234" {
		t.Fatalf("after first copy = %q", string(got))
	}

	offIn, offOut = 5, 3
	copied, err = unix.CopyFileRange(int(source.Fd()), &offIn, int(dest.Fd()), &offOut, 100, 0)
	if err != nil || copied != 5 {
		t.Fatalf("short copy_file_range = %d, %v", copied, err)
	}
	if got := readFile(t, destPath); string(got) != "01256789" {
		t.Fatalf("after short copy = %q", string(got))
	}

	offIn, offOut = 100, 0
	copied, err = unix.CopyFileRange(int(source.Fd()), &offIn, int(dest.Fd()), &offOut, 10, 0)
	if err != nil || copied != 0 {
		t.Fatalf("EOF copy_file_range = %d, %v", copied, err)
	}
	offIn, offOut = 0, 0
	if _, err := unix.CopyFileRange(int(source.Fd()), &offIn, int(dest.Fd()), &offOut, 1, 1); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("copy_file_range with flags = %v, want EINVAL", err)
	}
	if report, err := m.srv.Verify(true); err != nil || !report.OK {
		t.Fatalf("verify after copy_file_range: ok=%v err=%v problems=%+v", report != nil && report.OK, err, report.Problems)
	}
}

func TestLseekDataAndHole(t *testing.T) {
	dir := newEmptyStore(t)
	m := mount(t, dir, store.ReadWrite, fusefs.Options{})
	path := filepath.Join(m.mnt, "seek.bin")
	if err := os.WriteFile(path, make([]byte, 10), 0o644); err != nil {
		t.Fatalf("create: %v", err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer file.Close()
	fd := int(file.Fd())

	if offset, err := syscall.Seek(fd, 3, seekData); err != nil || offset != 3 {
		t.Fatalf("SEEK_DATA 3 = %d, %v", offset, err)
	}
	if _, err := syscall.Seek(fd, 10, seekData); !errors.Is(err, syscall.ENXIO) {
		t.Fatalf("SEEK_DATA at EOF = %v, want ENXIO", err)
	}
	if offset, err := syscall.Seek(fd, 0, seekHole); err != nil || offset != 10 {
		t.Fatalf("SEEK_HOLE 0 = %d, %v", offset, err)
	}
	if offset, err := syscall.Seek(fd, 10, seekHole); err != nil || offset != 10 {
		t.Fatalf("SEEK_HOLE at EOF = %d, %v", offset, err)
	}
	if _, err := syscall.Seek(fd, 11, seekHole); !errors.Is(err, syscall.ENXIO) {
		t.Fatalf("SEEK_HOLE past EOF = %v, want ENXIO", err)
	}

	emptyPath := filepath.Join(m.mnt, "empty.bin")
	if err := os.WriteFile(emptyPath, nil, 0o644); err != nil {
		t.Fatalf("empty: %v", err)
	}
	empty, err := os.Open(emptyPath)
	if err != nil {
		t.Fatalf("open empty: %v", err)
	}
	defer empty.Close()
	if _, err := syscall.Seek(int(empty.Fd()), 0, seekData); !errors.Is(err, syscall.ENXIO) {
		t.Fatalf("SEEK_DATA on empty file = %v, want ENXIO", err)
	}
	if offset, err := syscall.Seek(int(empty.Fd()), 0, seekHole); err != nil || offset != 0 {
		t.Fatalf("SEEK_HOLE on empty file = %d, %v", offset, err)
	}
}

func newOFDFlock(typ int16, start, length int64) *unix.Flock_t {
	return &unix.Flock_t{Type: typ, Whence: int16(0), Start: start, Len: length}
}

func TestByteRangeAndFlockLocks(t *testing.T) {
	dir := newEmptyStore(t)
	m := mount(t, dir, store.ReadWrite, fusefs.Options{})
	path := filepath.Join(m.mnt, "locked.bin")
	if err := os.WriteFile(path, make([]byte, 64), 0o644); err != nil {
		t.Fatalf("create: %v", err)
	}
	first, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open first: %v", err)
	}
	defer first.Close()
	second, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open second: %v", err)
	}
	defer second.Close()

	// OFD byte-range locks use distinct owners per open file description, so a
	// conflict is visible inside one process.
	if err := unix.FcntlFlock(first.Fd(), unix.F_OFD_SETLK, newOFDFlock(unix.F_WRLCK, 0, 10)); err != nil {
		t.Fatalf("first OFD write lock: %v", err)
	}
	if err := unix.FcntlFlock(second.Fd(), unix.F_OFD_SETLK, newOFDFlock(unix.F_WRLCK, 5, 10)); !errors.Is(err, syscall.EAGAIN) {
		t.Fatalf("overlapping OFD write lock = %v, want EAGAIN", err)
	}
	if err := unix.FcntlFlock(second.Fd(), unix.F_OFD_SETLK, newOFDFlock(unix.F_RDLCK, 20, 10)); err != nil {
		t.Fatalf("non-overlapping OFD read lock: %v", err)
	}
	query := newOFDFlock(unix.F_WRLCK, 5, 10)
	if err := unix.FcntlFlock(second.Fd(), unix.F_OFD_GETLK, query); err != nil {
		t.Fatalf("OFD_GETLK: %v", err)
	}
	if query.Type != unix.F_WRLCK || query.Start != 0 || query.Len != 10 {
		t.Fatalf("OFD_GETLK conflict = %+v, want WRLCK [0,10)", query)
	}
	if err := unix.FcntlFlock(first.Fd(), unix.F_OFD_SETLK, newOFDFlock(unix.F_UNLCK, 0, 10)); err != nil {
		t.Fatalf("unlock first: %v", err)
	}
	if err := unix.FcntlFlock(second.Fd(), unix.F_OFD_SETLK, newOFDFlock(unix.F_WRLCK, 5, 10)); err != nil {
		t.Fatalf("write lock after unlock: %v", err)
	}

	// POSIX/OFD locks share one namespace, so an OFD write lock conflicts with
	// a POSIX write lock from another owner.
	posix := &syscall.Flock_t{Type: syscall.F_WRLCK, Whence: 0, Start: 0, Len: 6}
	if err := syscall.FcntlFlock(first.Fd(), syscall.F_SETLK, posix); !errors.Is(err, syscall.EAGAIN) {
		t.Fatalf("POSIX over overlapping OFD lock = %v, want EAGAIN", err)
	}
	if err := unix.FcntlFlock(second.Fd(), unix.F_OFD_SETLK, newOFDFlock(unix.F_UNLCK, 5, 10)); err != nil {
		t.Fatalf("unlock second OFD write: %v", err)
	}

	// POSIX locks owned by one process do not conflict with themselves.
	if err := syscall.FcntlFlock(first.Fd(), syscall.F_SETLK, posix); err != nil {
		t.Fatalf("POSIX setlk: %v", err)
	}
	if err := syscall.FcntlFlock(first.Fd(), syscall.F_SETLK, posix); err != nil {
		t.Fatalf("repeat POSIX setlk (same owner): %v", err)
	}
	probe := &syscall.Flock_t{Type: syscall.F_WRLCK, Whence: 0, Start: 0, Len: 6}
	if err := syscall.FcntlFlock(second.Fd(), syscall.F_GETLK, probe); err != nil {
		t.Fatalf("POSIX getlk: %v", err)
	}
	if probe.Type != syscall.F_UNLCK {
		t.Fatalf("same-process POSIX getlk reported conflict %+v", probe)
	}
	posix.Type = syscall.F_UNLCK
	if err := syscall.FcntlFlock(first.Fd(), syscall.F_SETLK, posix); err != nil {
		t.Fatalf("POSIX unlock: %v", err)
	}

	// flock is a separate whole-file namespace and conflicts across open file
	// descriptions even in one process.
	if err := syscall.Flock(int(first.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("flock exclusive: %v", err)
	}
	if err := syscall.Flock(int(second.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); !errors.Is(err, syscall.EWOULDBLOCK) {
		t.Fatalf("conflicting flock = %v, want EWOULDBLOCK", err)
	}
	if err := syscall.Flock(int(second.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); !errors.Is(err, syscall.EWOULDBLOCK) {
		t.Fatalf("shared flock over exclusive = %v, want EWOULDBLOCK", err)
	}
	if err := syscall.Flock(int(first.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatalf("flock unlock: %v", err)
	}
	if err := syscall.Flock(int(second.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("flock after unlock: %v", err)
	}
	if err := syscall.Flock(int(second.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatalf("second flock unlock: %v", err)
	}

	// A blocking OFD lock must wait for the conflicting owner and then wake.
	if err := unix.FcntlFlock(first.Fd(), unix.F_OFD_SETLK, newOFDFlock(unix.F_WRLCK, 0, 10)); err != nil {
		t.Fatalf("blocking-lock setup: %v", err)
	}
	blocked := make(chan error, 1)
	go func() {
		blocked <- unix.FcntlFlock(second.Fd(), unix.F_OFD_SETLKW, newOFDFlock(unix.F_WRLCK, 0, 10))
	}()
	select {
	case err := <-blocked:
		t.Fatalf("blocking lock returned before unlock: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	if err := unix.FcntlFlock(first.Fd(), unix.F_OFD_SETLK, newOFDFlock(unix.F_UNLCK, 0, 10)); err != nil {
		t.Fatalf("blocking-lock unlock: %v", err)
	}
	select {
	case err := <-blocked:
		if err != nil {
			t.Fatalf("blocking lock after unlock: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocking lock did not wake after unlock")
	}
	if err := unix.FcntlFlock(second.Fd(), unix.F_OFD_SETLK, newOFDFlock(unix.F_UNLCK, 0, 10)); err != nil {
		t.Fatalf("blocking lock cleanup: %v", err)
	}
	if report, err := m.srv.Verify(true); err != nil || !report.OK {
		t.Fatalf("verify after locks: ok=%v err=%v problems=%+v", report != nil && report.OK, err, report.Problems)
	}
}
