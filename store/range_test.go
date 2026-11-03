package store_test

import (
	"bytes"
	"testing"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// TestCollapseInsertAndZeroRangeStoreLevel exercises the fallocate backends
// directly. The 7.3.1 FUSE kernel boundary refuses COLLAPSE_RANGE/INSERT_RANGE
// before forwarding, so the mount test asserts that refusal and this test
// proves the store semantics those verbs would reach on a forwarding kernel.
func TestCollapseInsertAndZeroRangeStoreLevel(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, gcOptions(0))
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()

	id, err := s.CreateFile(model.RootID, []byte("range.bin"), []byte("abcdef"), 0o644, 0, 0, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	assertContent := func(want []byte, label string) {
		t.Helper()
		got, err := s.ReadObject(id)
		if err != nil {
			t.Fatalf("%s read: %v", label, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s = %q, want %q", label, got, want)
		}
	}

	if _, err := s.CollapseRange(id, 2, 2); err != nil {
		t.Fatalf("collapse: %v", err)
	}
	assertContent([]byte("abef"), "after collapse")

	if _, err := s.InsertRange(id, 2, 2); err != nil {
		t.Fatalf("insert: %v", err)
	}
	assertContent([]byte{'a', 'b', 0, 0, 'e', 'f'}, "after insert")

	if _, err := s.ZeroRange(id, 0, 2, false); err != nil {
		t.Fatalf("zero range: %v", err)
	}
	assertContent([]byte{0, 0, 0, 0, 'e', 'f'}, "after zero range")

	if _, err := s.ZeroRange(id, 6, 4, true); err != nil {
		t.Fatalf("zero range extend: %v", err)
	}
	assertContent([]byte{0, 0, 0, 0, 'e', 'f', 0, 0, 0, 0}, "after extending zero range")
	if record, err := s.ObjectMeta(id); err != nil || record.Size != 10 {
		t.Fatalf("size after extending zero range = %d, %v", record.Size, err)
	}

	if _, err := s.CollapseRange(id, 5, 10); werr.ClassOf(err) != werr.InvalidArgument {
		t.Fatalf("collapse past EOF = %v, want InvalidArgument", err)
	}
	if _, err := s.InsertRange(id, 100, 1); werr.ClassOf(err) != werr.InvalidArgument {
		t.Fatalf("insert past EOF = %v, want InvalidArgument", err)
	}
	if report, err := s.Verify(true); err != nil || !report.OK {
		t.Fatalf("verify: ok=%v err=%v problems=%s", report != nil && report.OK, err, formatProblems(report))
	}
}
