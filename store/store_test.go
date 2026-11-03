package store_test

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/infinityabundance/WeftCodec-Go/limits"
	"github.com/infinityabundance/WeftCodec-Go/selector"
	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/auth"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

func fixedOptions() store.Options {
	ts := int64(1_700_000_000_000_000_000)
	opts := store.DefaultOptions()
	opts.FixedTimestampNS = &ts
	return opts
}

// TestFixtureSequenceReproducesRustIdentities performs the exact operation
// sequence used to generate conformance/store/v1 and asserts every identity,
// path, relation, snapshot, selector result, and the commit head recorded in
// EXPECTED.json. It is the strongest same-bytes check available without
// invoking Rust.
func TestFixtureSequenceReproducesRustIdentities(t *testing.T) {
	want := loadExpected(t)
	dir := t.TempDir()
	s, err := store.Init(dir, fixedOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}

	root, err := s.ResolvePath("/")
	if err != nil {
		t.Fatalf("resolve root: %v", err)
	}
	docs, err := s.MkdirSeeded(root, []byte("docs"), 0o755, 0, 0, []byte("fixture-dir-docs"))
	if err != nil {
		t.Fatalf("mkdir docs: %v", err)
	}
	data, err := s.MkdirSeeded(root, []byte("data"), 0o755, 0, 0, []byte("fixture-dir-data"))
	if err != nil {
		t.Fatalf("mkdir data: %v", err)
	}
	hello, err := s.CreateFileSeeded(root, []byte("hello.txt"), []byte("hello weft\n"), 0o644, 0, 0, nil, []byte("fixture-object-1"))
	if err != nil {
		t.Fatalf("create hello: %v", err)
	}
	readme, err := s.CreateFileSeeded(docs, []byte("readme.md"), []byte("# WeftFS fixture\n\nDeterministic store for cross-language handoff.\n"), 0o644, 0, 0, nil, []byte("fixture-object-2"))
	if err != nil {
		t.Fatalf("create readme: %v", err)
	}
	binary := make([]byte, 4096)
	for index := 0; index < 4096; index++ {
		binary[index] = byte((uint32(index)*37 + 11) % 256)
	}
	binaryID, err := s.CreateFileSeeded(data, []byte("binary.bin"), binary, 0o644, 0, 0, nil, []byte("fixture-object-3"))
	if err != nil {
		t.Fatalf("create binary: %v", err)
	}
	if _, err := s.SymlinkSeeded(root, []byte("link"), []byte("hello.txt"), 0, 0, []byte("fixture-symlink")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := s.Link(hello, root, []byte("hello.txt-hard")); err != nil {
		t.Fatalf("link: %v", err)
	}
	if _, err := s.RelationAdd(hello, "tagged_as", model.ValueTarget(wcb.TextValue("greeting")), map[string]wcb.Value{
		"source": wcb.TextValue("fixture"),
	}, nil); err != nil {
		t.Fatalf("relation tagged_as: %v", err)
	}
	if _, err := s.RelationAdd(hello, "derived_from", model.ObjectTarget(readme), nil, nil); err != nil {
		t.Fatalf("relation derived_from: %v", err)
	}
	snapshotID, err := s.SnapshotCreate("v1")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	if s.Generation() != want.Generation {
		t.Fatalf("generation = %d, want %d", s.Generation(), want.Generation)
	}
	if s.Head().Hex() != want.SnapshotRoot {
		t.Fatalf("head = %s, want %s", s.Head().Hex(), want.SnapshotRoot)
	}
	if snapshotID.Hex() != want.Snapshots["v1"] {
		t.Fatalf("snapshot v1 = %s, want %s", snapshotID.Hex(), want.Snapshots["v1"])
	}
	_ = binaryID

	state := s.CurrentState()
	for _, object := range want.Objects {
		id := mustHash(t, object.ObjectID)
		record, ok := state.Objects[id]
		if !ok {
			t.Fatalf("object %s (%s) missing after Go build", object.ObjectID, object.Path)
		}
		if record.Version.Hex() != object.VersionID {
			t.Fatalf("object %s version = %s, want %s", object.Path, record.Version.Hex(), object.VersionID)
		}
		if record.Content.Hex() != object.ContentID {
			t.Fatalf("object %s content = %s, want %s", object.Path, record.Content.Hex(), object.ContentID)
		}
		if object.Kind == "file" {
			manifest, err := store.ReadManifest(dir, record.Content)
			if err != nil {
				t.Fatalf("manifest %s: %v", object.Path, err)
			}
			if manifest.ContentHash.Hex() != object.ContentHash {
				t.Fatalf("object %s content hash = %s, want %s", object.Path, manifest.ContentHash.Hex(), object.ContentHash)
			}
		}
	}
	for _, entry := range want.Entries {
		parent, err := s.ResolvePath(filepath.Dir(entry.Path))
		if err != nil {
			t.Fatalf("resolve parent %s: %v", entry.Path, err)
		}
		id, err := model.DeriveEntryID(parent, []byte(filepath.Base(entry.Path)))
		if err != nil {
			t.Fatalf("derive entry %s: %v", entry.Path, err)
		}
		if id.Hex() != entry.EntryID {
			t.Fatalf("entry %s = %s, want %s", entry.Path, id.Hex(), entry.EntryID)
		}
	}
	for _, relation := range want.Relations {
		if _, ok := state.Relations[mustHash(t, relation)]; !ok {
			t.Fatalf("relation %s missing after Go build", relation)
		}
	}
	for _, wantSel := range want.Selectors {
		parsed, err := selector.Parse(wantSel.Source)
		if err != nil {
			t.Fatalf("parse %q: %v", wantSel.Source, err)
		}
		snapshot := mustHash(t, wantSel.SnapshotID)
		resolution, err := s.Resolve(parsed, &snapshot, auth.Root(), limits.Default())
		if err != nil {
			t.Fatalf("resolve %q: %v", wantSel.Source, err)
		}
		if resolution.SelectorID.Hex() != wantSel.SelectorID || resolution.MatchedCount != wantSel.MatchedCount {
			t.Fatalf("selector %q: id=%s count=%d, want %s/%d", wantSel.Source, resolution.SelectorID.Hex(), resolution.MatchedCount, wantSel.SelectorID, wantSel.MatchedCount)
		}
		for index, result := range resolution.Results {
			if result.ObjectID.Hex() != wantSel.ObjectIDs[index] {
				t.Fatalf("selector %q result %d = %s, want %s", wantSel.Source, index, result.ObjectID.Hex(), wantSel.ObjectIDs[index])
			}
		}
	}
	report, err := s.Verify(true)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !report.OK {
		t.Fatalf("verify problems: %+v", report.Problems)
	}
	_ = s.Close()

	// Strongest possible byte check: with the fixture's fixed timestamp and
	// explicit seeds, the Go writer must produce the same commit files,
	// manifests, chunks, superblock, and snapshot pointer bytes as Rust.
	compareStoreBytes(t, filepath.Join(fixtureRel), dir)
}

// compareStoreBytes asserts byte equality for every data-bearing file the
// fixture and the Go-built store share.
func compareStoreBytes(t *testing.T, rustDir, goDir string) {
	t.Helper()
	for _, name := range []string{"FORMAT", "superblock"} {
		want, err := os.ReadFile(filepath.Join(rustDir, name))
		if err != nil {
			t.Fatalf("read rust %s: %v", name, err)
		}
		got, err := os.ReadFile(filepath.Join(goDir, name))
		if err != nil {
			t.Fatalf("read go %s: %v", name, err)
		}
		if !bytes.Equal(want, got) {
			t.Fatalf("%s bytes differ: rust %d bytes, go %d bytes", name, len(want), len(got))
		}
	}
	for _, sub := range []string{"commits", "manifests", "objects", "refs/snapshots"} {
		rustFiles := listRelativeFiles(t, filepath.Join(rustDir, sub))
		goFiles := listRelativeFiles(t, filepath.Join(goDir, sub))
		if !equalStrings(rustFiles, goFiles) {
			t.Fatalf("%s file set differs:\n rust=%v\n go=%v", sub, rustFiles, goFiles)
		}
		for _, rel := range rustFiles {
			want, err := os.ReadFile(filepath.Join(rustDir, sub, rel))
			if err != nil {
				t.Fatalf("read rust %s/%s: %v", sub, rel, err)
			}
			got, err := os.ReadFile(filepath.Join(goDir, sub, rel))
			if err != nil {
				t.Fatalf("read go %s/%s: %v", sub, rel, err)
			}
			if !bytes.Equal(want, got) {
				t.Fatalf("%s/%s bytes differ (rust %d, go %d)", sub, rel, len(want), len(got))
			}
		}
	}
}

func listRelativeFiles(t *testing.T, root string) []string {
	t.Helper()
	files := make([]string, 0)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files = append(files, rel)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	sort.Strings(files)
	return files
}

func TestWriterLockAndReadOnlyOpen(t *testing.T) {
	dir := t.TempDir()
	writer, err := store.Init(dir, store.DefaultOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer writer.Close()
	if _, err := store.Open(dir, store.ReadWrite); err == nil {
		t.Fatal("second writer unexpectedly acquired the lock")
	} else if !werr.Is(err, werr.Busy) {
		t.Fatalf("second writer class = %s, want Busy", werr.ClassOf(err))
	}
	reader, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("read-only open while a writer is active: %v", err)
	}
	defer reader.Close()
	if reader.Generation() != writer.Generation() {
		t.Fatalf("reader generation %d != writer %d", reader.Generation(), writer.Generation())
	}
	if _, err := reader.CreateFile(model.RootID, []byte("nope"), nil, 0o644, 0, 0, nil); err == nil {
		t.Fatal("read-only store accepted a mutation")
	} else if !werr.Is(err, werr.ReadOnly) {
		t.Fatalf("read-only mutation class = %s, want ReadOnly", werr.ClassOf(err))
	}
}

func TestMutationsRoundTripAndVerify(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, store.DefaultOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	root := model.RootID
	fileID, err := s.CreateFile(root, []byte("a.txt"), []byte("abcdef"), 0o644, 7, 8, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.WriteFile(fileID, 3, []byte("XYZ")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got, _ := s.ReadObject(fileID); string(got) != "abcXYZ" {
		t.Fatalf("content = %q", string(got))
	}
	if _, err := s.Truncate(fileID, 2); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if got, _ := s.ReadObject(fileID); string(got) != "ab" {
		t.Fatalf("truncated content = %q", string(got))
	}
	dirID, err := s.Mkdir(root, []byte("dir"), 0o755, 0, 0)
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := s.CreateFile(dirID, []byte("nested"), []byte("x"), 0o600, 0, 0, nil); err != nil {
		t.Fatalf("create nested: %v", err)
	}
	if err := s.Rename(root, []byte("a.txt"), dirID, []byte("moved.txt")); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if _, err := s.Lookup(root, []byte("a.txt")); err == nil {
		t.Fatal("old name still resolves after rename")
	}
	movedID, err := s.Lookup(dirID, []byte("moved.txt"))
	if err != nil {
		t.Fatalf("lookup moved: %v", err)
	}
	if movedID != fileID {
		t.Fatal("rename changed the ObjectId")
	}
	if err := s.Link(fileID, root, []byte("hard")); err != nil {
		t.Fatalf("link: %v", err)
	}
	if links, _ := s.NLink(fileID); links != 2 {
		t.Fatalf("nlink = %d, want 2", links)
	}
	linkID, err := s.Symlink(root, []byte("sym"), []byte("dir/moved.txt"), 0, 0)
	if err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if target, err := s.ReadObject(linkID); err != nil || string(target) != "dir/moved.txt" {
		t.Fatalf("symlink read = %q, %v", string(target), err)
	}
	if err := s.SetXattr(fileID, "user.demo", []byte("v1")); err != nil {
		t.Fatalf("setxattr: %v", err)
	}
	if value, ok, err := s.GetXattr(fileID, "user.demo"); err != nil || !ok || string(value) != "v1" {
		t.Fatalf("getxattr = %q ok=%v err=%v", string(value), ok, err)
	}
	names, err := s.ListXattr(fileID)
	if err != nil || len(names) != 1 || names[0] != "user.demo" {
		t.Fatalf("listxattr = %v, %v", names, err)
	}
	if _, err := s.RelationAdd(fileID, "related_to", model.ValueTarget(wcb.U64Value(42)), nil, nil); err != nil {
		t.Fatalf("relation: %v", err)
	}
	snapshotID, err := s.SnapshotCreate("snap")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if _, err := s.Checkpoint(); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if _, err := s.Setattr(fileID, store.SetAttr{Mode: uint64Ptr(0o600), MtimeNS: int64Ptr(123)}); err != nil {
		t.Fatalf("setattr: %v", err)
	}
	report, err := s.Verify(true)
	if err != nil || !report.OK {
		t.Fatalf("verify: ok=%v err=%v problems=%+v", report != nil && report.OK, err, reportProblems(report))
	}
	head := s.Head()
	_ = s.Close()

	reader, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("reopen read-only: %v", err)
	}
	defer reader.Close()
	if reader.Head() != head {
		t.Fatal("reopened head differs")
	}
	if reader.CurrentState().Snapshots["snap"] != snapshotID {
		t.Fatal("snapshot name did not survive reopen")
	}
	state, err := reader.StateAt(snapshotID)
	if err != nil {
		t.Fatalf("StateAt snapshot: %v", err)
	}
	record, ok := state.Objects[fileID]
	if !ok {
		t.Fatal("object missing at snapshot")
	}
	if record.Size != 2 {
		t.Fatalf("snapshot object size = %d, want 2", record.Size)
	}
	if _, err := reader.Verify(true); err != nil {
		t.Fatalf("reopen verify: %v", err)
	}
}

func TestOpenUnlinkedPinnedReadAndWrite(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, store.DefaultOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()
	id, err := s.CreateFile(model.RootID, []byte("doomed"), []byte("payload"), 0o644, 0, 0, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.PinObject(id); err != nil {
		t.Fatalf("pin: %v", err)
	}
	if err := s.Unlink(model.RootID, []byte("doomed")); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	if _, ok := s.CurrentState().Objects[id]; !ok {
		t.Fatal("pinned object record was deleted by unlink")
	}
	if got, err := s.ReadObject(id); err != nil || string(got) != "payload" {
		t.Fatalf("pinned read = %q, %v", string(got), err)
	}
	if _, err := s.WriteFile(id, 7, []byte("!")); err != nil {
		t.Fatalf("pinned write: %v", err)
	}
	if count, err := s.UnpinObject(id); err != nil || count != 0 {
		t.Fatalf("unpin = %d, %v", count, err)
	}
	if _, ok := s.CurrentState().Objects[id]; ok {
		t.Fatal("object record survived the final unpin")
	}
}

func TestCheckpointGenerationRule(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, store.DefaultOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if _, err := s.CreateFile(model.RootID, []byte("one"), []byte("1"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	checkpointHead, err := s.Checkpoint()
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	generation := s.Generation()
	_ = s.Close()

	reader, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reader.Close()
	if reader.Generation() != generation || reader.Head() != checkpointHead {
		t.Fatalf("checkpoint head not selected: gen=%d head=%s", reader.Generation(), reader.Head().Hex())
	}
	if got, err := reader.ReadObject(mustResolve(t, reader, "/one")); err != nil || string(got) != "1" {
		t.Fatalf("checkpoint state read = %q, %v", string(got), err)
	}

	// Corrupt the checkpoint manifest: replay must ignore it, keep the
	// generation published, and still reconstruct the same state.
	commits, err := store.AllCommits(dir, generation)
	if err != nil {
		t.Fatalf("all commits: %v", err)
	}
	var checkpointManifest model.Hash32
	found := false
	for _, commit := range commits {
		if commit.Commit.Checkpoint != nil {
			checkpointManifest = *commit.Commit.Checkpoint
			found = true
		}
	}
	if !found {
		t.Fatal("no checkpoint commit found")
	}
	path := store.ManifestPath(dir, checkpointManifest)
	if err := flipFileByte(path); err != nil {
		t.Fatalf("corrupt checkpoint: %v", err)
	}
	reader2, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("reopen with corrupt checkpoint: %v", err)
	}
	defer reader2.Close()
	if reader2.Generation() != generation {
		t.Fatalf("generation = %d, want %d", reader2.Generation(), generation)
	}
	foundNote := false
	for _, note := range reader2.RecoveryNotes() {
		if bytes.Contains([]byte(note), []byte("checkpoint")) {
			foundNote = true
		}
	}
	if !foundNote {
		t.Fatalf("recovery notes do not mention the ignored checkpoint: %v", reader2.RecoveryNotes())
	}
	if got, err := reader2.ReadObject(mustResolve(t, reader2, "/one")); err != nil || string(got) != "1" {
		t.Fatalf("replayed state read = %q, %v", string(got), err)
	}
	report, err := reader2.Verify(false)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.OK {
		t.Fatal("verify must report the corrupt checkpoint")
	}
}

func mustResolve(t *testing.T, s *store.Store, path string) model.Hash32 {
	t.Helper()
	id, err := s.ResolvePath(path)
	if err != nil {
		t.Fatalf("resolve %s: %v", path, err)
	}
	return id
}

func flipFileByte(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	b[len(b)-1] ^= 0xff
	return os.WriteFile(path, b, 0o644)
}

func uint64Ptr(v uint64) *uint64 { return &v }
func int64Ptr(v int64) *int64    { return &v }

func reportProblems(r *store.VerifyReport) []store.VerifyProblem {
	if r == nil {
		return nil
	}
	return r.Problems
}
