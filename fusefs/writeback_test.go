package fusefs_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/infinityabundance/WeftFS-Go/fusefs"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
)

// newWritableStore initializes a store with the mount's default Merkle
// identity and closes it so the mount helper can take the writer lock.
func newWritableStore(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	opts := store.DefaultOptions()
	ts := int64(1_700_000_000_000_000_000)
	opts.FixedTimestampNS = &ts
	opts.ContentIdentity = model.ContentIdentityMerkleV1
	st, err := store.Init(dir, opts)
	if err != nil {
		t.Fatalf("init store: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close init store: %v", err)
	}
	return dir
}

// unmountAndVerify stops the daemon (and its group-commit goroutine) before
// verifying the store, so verification never races a live request.
func unmountAndVerify(t *testing.T, m mounted) {
	t.Helper()
	_ = m.server.Unmount()
	m.server.Wait()
	m.srv.StopGroupCommit()
	report, err := m.st.Verify(true)
	if err != nil || !report.OK {
		t.Fatalf("verify: %v %+v", err, report)
	}
}

func TestWriteBackBufferedReadAndFsyncDurability(t *testing.T) {
	dir := newWritableStore(t)
	m := mount(t, dir, store.ReadWrite, fusefs.Options{WriteBack: true})
	path := filepath.Join(m.mnt, "buf.bin")

	writer, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatalf("open writer: %v", err)
	}
	if _, err := writer.Write([]byte("hello buffered")); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Read-after-write on the same descriptor sees the buffered bytes.
	if _, err := writer.Seek(0, 0); err != nil {
		t.Fatalf("seek: %v", err)
	}
	seen := make([]byte, 14)
	if _, err := writer.Read(seen); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(seen, []byte("hello buffered")) {
		t.Fatalf("buffered read = %q", seen)
	}

	// Nothing is committed yet, so an independent read-only store sees an empty
	// file. (A Store instance pins the generation it opened, so the check opens
	// a fresh instance each time.)
	readCommitted := func() []byte {
		t.Helper()
		ro, err := store.Open(dir, store.ReadOnly)
		if err != nil {
			t.Fatalf("open read-only store: %v", err)
		}
		defer ro.Close()
		id, err := ro.ResolvePath("/buf.bin")
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		data, err := ro.ReadObject(id)
		if err != nil {
			t.Fatalf("store read: %v", err)
		}
		return data
	}
	if before := readCommitted(); len(before) != 0 {
		t.Fatalf("pre-flush store read = %q", before)
	}

	if err := writer.Sync(); err != nil {
		t.Fatalf("fsync: %v", err)
	}
	if after := readCommitted(); !bytes.Equal(after, []byte("hello buffered")) {
		t.Fatalf("post-fsync store read = %q", after)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// A fresh POSIX reader sees the published bytes.
	if data, err := os.ReadFile(path); err != nil || !bytes.Equal(data, []byte("hello buffered")) {
		t.Fatalf("posix read = %q, err %v", data, err)
	}
	unmountAndVerify(t, m)
}

func TestWriteBackReleasePublishes(t *testing.T) {
	dir := newWritableStore(t)
	m := mount(t, dir, store.ReadWrite, fusefs.Options{WriteBack: true})
	path := filepath.Join(m.mnt, "close.bin")
	if err := os.WriteFile(path, []byte("published at close"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "published at close" {
		t.Fatalf("read = %q err %v", data, err)
	}
	unmountAndVerify(t, m)
}

func TestGroupCommitMetadataStorm(t *testing.T) {
	dir := newWritableStore(t)
	m := mount(t, dir, store.ReadWrite, fusefs.Options{GroupCommit: true})
	for index := 0; index < 40; index++ {
		path := filepath.Join(m.mnt, fmt.Sprintf("g-%03d.txt", index))
		if err := os.WriteFile(path, []byte("payload"), 0o644); err != nil {
			t.Fatalf("create %d: %v", index, err)
		}
	}
	entries, err := os.ReadDir(m.mnt)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var names []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "g-") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	if len(names) != 40 {
		t.Fatalf("listed %d files", len(names))
	}
	unmountAndVerify(t, m)
}

func TestWriteBackAndGroupCommitTogether(t *testing.T) {
	dir := newWritableStore(t)
	m := mount(t, dir, store.ReadWrite, fusefs.Options{WriteBack: true, GroupCommit: true})
	path := filepath.Join(m.mnt, "both.bin")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	for chunk := 0; chunk < 8; chunk++ {
		if _, err := file.Write(bytes.Repeat([]byte{byte(chunk)}, 4096)); err != nil {
			t.Fatalf("write %d: %v", chunk, err)
		}
	}
	if err := file.Sync(); err != nil {
		t.Fatalf("fsync: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(data) != 8*4096 {
		t.Fatalf("size %d", len(data))
	}
	for chunk := 0; chunk < 8; chunk++ {
		for _, b := range data[chunk*4096 : (chunk+1)*4096] {
			if b != byte(chunk) {
				t.Fatalf("chunk %d has %d", chunk, b)
			}
		}
	}
	unmountAndVerify(t, m)
}
