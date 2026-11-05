package store_test

import (
	"bytes"
	"testing"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
)

func groupMerkleOptions() store.Options {
	opts := fixedOptions()
	opts.ContentIdentity = model.ContentIdentityMerkleV1
	return opts
}

func createSeededFile(t *testing.T, s *store.Store, name string, data []byte) model.Hash32 {
	t.Helper()
	root, err := s.ResolvePath("/")
	if err != nil {
		t.Fatalf("resolve root: %v", err)
	}
	id, err := s.CreateFileSeeded(root, []byte(name), data, 0o644, 0, 0, nil, []byte("seed-"+name))
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	return id
}

func TestBeginCommitGroupPublishesOneCommit(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, fixedOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()
	root, err := s.ResolvePath("/")
	if err != nil {
		t.Fatalf("resolve root: %v", err)
	}
	before := s.Generation()
	if err := s.BeginGroup(); err != nil {
		t.Fatalf("begin: %v", err)
	}
	for index := 0; index < 5; index++ {
		name := []byte{byte('a' + index)}
		if _, err := s.CreateFileSeeded(root, name, []byte{byte(index)}, 0o644, 0, 0, nil, append([]byte("g-"), name...)); err != nil {
			t.Fatalf("create %d: %v", index, err)
		}
		// Live state sees the buffered object.
		if _, err := s.Lookup(root, name); err != nil {
			t.Fatalf("buffered lookup %d: %v", index, err)
		}
	}
	if s.Generation() != before {
		t.Fatalf("generation advanced inside the group: %d -> %d", before, s.Generation())
	}
	if _, err := s.CommitGroup(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if s.Generation() != before+1 {
		t.Fatalf("group published %d generations", s.Generation()-before)
	}
	if s.GroupOpen() {
		t.Fatal("group still open after commit")
	}
	report, err := s.Verify(true)
	if err != nil || !report.OK {
		t.Fatalf("verify: %v %+v", err, report)
	}
}

func TestAbortGroupRestoresState(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, fixedOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()
	id := createSeededFile(t, s, "base", []byte("base"))
	head, generation := s.Head(), s.Generation()
	root, _ := s.ResolvePath("/")
	if err := s.BeginGroup(); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := s.CreateFileSeeded(root, []byte("extra"), []byte("x"), 0o644, 0, 0, nil, []byte("abort-seed")); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.WriteFile(id, 0, []byte("changed")); err != nil {
		t.Fatalf("write: %v", err)
	}
	s.AbortGroup()
	if s.Head() != head || s.Generation() != generation {
		t.Fatalf("abort changed head/generation: %v %d", s.Head(), s.Generation())
	}
	if _, err := s.Lookup(root, []byte("extra")); err == nil {
		t.Fatal("aborted object still present")
	}
	data, err := s.ReadObject(id)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(data, []byte("base")) {
		t.Fatalf("abort left bytes %q", data)
	}
	report, err := s.Verify(true)
	if err != nil || !report.OK {
		t.Fatalf("verify: %v %+v", err, report)
	}
}

func TestEmptyGroupCommitPublishesNothing(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, fixedOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()
	head, generation := s.Head(), s.Generation()
	if err := s.BeginGroup(); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := s.CommitGroup(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if s.Head() != head || s.Generation() != generation {
		t.Fatalf("empty group published something")
	}
}

func TestWriteFileRangesMatchesSequentialWrites(t *testing.T) {
	base := make([]byte, 20_000)
	for i := range base {
		base[i] = byte(i % 251)
	}
	ranges := make([]store.RangeWrite, 0, 40)
	for i := 0; i < 40; i++ {
		length := 1 + (i*37)%2_000
		offset := (i * 4_111) % (len(base) - length)
		data := bytes.Repeat([]byte{byte(i * 13)}, length)
		ranges = append(ranges, store.RangeWrite{Offset: uint64(offset), Data: data})
	}

	sequentialDir := t.TempDir()
	sequential, err := store.Init(sequentialDir, groupMerkleOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer sequential.Close()
	sequentialID := createSeededFile(t, sequential, "f", base)
	for _, r := range ranges {
		if _, err := sequential.WriteFile(sequentialID, r.Offset, r.Data); err != nil {
			t.Fatalf("sequential write: %v", err)
		}
	}
	want, err := sequential.ReadObject(sequentialID)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	batchedDir := t.TempDir()
	batched, err := store.Init(batchedDir, groupMerkleOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer batched.Close()
	batchedID := createSeededFile(t, batched, "f", base)
	before := batched.Generation()
	outcome, err := batched.WriteFileRanges(batchedID, ranges)
	if err != nil {
		t.Fatalf("ranges write: %v", err)
	}
	if batched.Generation() != before+1 {
		t.Fatalf("multi-range write published %d commits", batched.Generation()-before)
	}
	got, err := batched.ReadObject(batchedID)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("batched ranges differ from sequential writes")
	}
	if uint64(len(got)) != outcome.Size {
		t.Fatalf("outcome size %d, bytes %d", outcome.Size, len(got))
	}
}

func TestOverlappingRangesApplyInOrder(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, groupMerkleOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()
	id := createSeededFile(t, s, "f", make([]byte, 128))
	ranges := []store.RangeWrite{
		{Offset: 16, Data: bytes.Repeat([]byte{1}, 64)},
		{Offset: 32, Data: bytes.Repeat([]byte{2}, 32)},
		{Offset: 40, Data: bytes.Repeat([]byte{3}, 8)},
	}
	if _, err := s.WriteFileRanges(id, ranges); err != nil {
		t.Fatalf("write: %v", err)
	}
	data, err := s.ReadObject(id)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	check := func(start, end int, value byte) {
		for i := start; i < end; i++ {
			if data[i] != value {
				t.Fatalf("byte %d = %d, want %d", i, data[i], value)
			}
		}
	}
	check(16, 32, 1)
	check(32, 40, 2)
	check(40, 48, 3)
	check(48, 64, 2)
	check(64, 80, 1)
	check(80, 128, 0)
}

func TestManifestCacheIsAdvisoryOnly(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, groupMerkleOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()
	id := createSeededFile(t, s, "f", bytes.Repeat([]byte{7}, 4096))
	record, err := s.ObjectMeta(id)
	if err != nil {
		t.Fatalf("meta: %v", err)
	}
	manifest, err := s.ManifestOf(record.Content)
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	cache := &store.ManifestCache{Content: record.Content, Manifest: manifest}
	outcome, err := s.WriteFileCached(id, 100, []byte("cached"), cache)
	if err != nil {
		t.Fatalf("cached write: %v", err)
	}
	if outcome.Content == record.Content {
		t.Fatal("cached write did not change content")
	}
	// Stale cache: truncate makes it name an old version.
	if _, err := s.Truncate(id, 1024); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	outcome, err = s.WriteFileCached(id, 0, []byte("fresh"), cache)
	if err != nil {
		t.Fatalf("stale cached write: %v", err)
	}
	data, err := s.ReadObject(id)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.HasPrefix(data, []byte("fresh")) || len(data) != 1024 {
		t.Fatalf("stale-cache write produced %d bytes", len(data))
	}
	if outcome.Size != 1024 {
		t.Fatalf("outcome size %d", outcome.Size)
	}
	report, err := s.Verify(true)
	if err != nil || !report.OK {
		t.Fatalf("verify: %v %+v", err, report)
	}
}
