package store_test

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/infinityabundance/WeftCodec-Go/limits"
	"github.com/infinityabundance/WeftCodec-Go/selector"
	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftCodec-Go/werrors"
	"github.com/infinityabundance/WeftFS-Go/auth"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

const fixtureRel = "../conformance/store/v1"

type expectedObject struct {
	ContentHash string `json:"content_hash"`
	ContentID   string `json:"content_id"`
	Kind        string `json:"kind"`
	ObjectID    string `json:"object_id"`
	Path        string `json:"path"`
	Size        uint64 `json:"size"`
	VersionID   string `json:"version_id"`
}

type expectedEntry struct {
	EntryID string `json:"entry_id"`
	Path    string `json:"path"`
	Target  string `json:"target"`
}

type expectedSelector struct {
	MatchedCount uint64   `json:"matched_count"`
	ObjectIDs    []string `json:"object_ids"`
	SelectorID   string   `json:"selector_id"`
	SnapshotID   string   `json:"snapshot_id"`
	Source       string   `json:"source"`
}

type expectedFixture struct {
	Format       string             `json:"format"`
	Generation   uint64             `json:"generation"`
	Objects      []expectedObject   `json:"objects"`
	Entries      []expectedEntry    `json:"entries"`
	Relations    []string           `json:"relations"`
	Selectors    []expectedSelector `json:"selectors"`
	SnapshotRoot string             `json:"snapshot_root"`
	Snapshots    map[string]string  `json:"snapshots"`
}

func loadExpected(t *testing.T) expectedFixture {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureRel, "EXPECTED.json"))
	if err != nil {
		t.Fatalf("read EXPECTED.json: %v", err)
	}
	var want expectedFixture
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatalf("parse EXPECTED.json: %v", err)
	}
	return want
}

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
		t.Fatalf("copy fixture: %v", err)
	}
}

func openFixture(t *testing.T) (*store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	copyTree(t, fixtureRel, dir)
	s, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, dir
}

func mustHash(t *testing.T, hex string) model.Hash32 {
	t.Helper()
	h, err := modelHash(hex)
	if err != nil {
		t.Fatalf("bad hash %q: %v", hex, err)
	}
	return h
}

func modelHash(hexText string) (model.Hash32, error) {
	var h model.Hash32
	if len(hexText) != 64 {
		return h, errors.New("hash length")
	}
	for i := 0; i < 32; i++ {
		hi := hexNibble(hexText[i*2])
		lo := hexNibble(hexText[i*2+1])
		if hi < 0 || lo < 0 {
			return h, errors.New("hex digit")
		}
		h[i] = byte(hi<<4 | lo)
	}
	return h, nil
}

func hexNibble(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	default:
		return -1
	}
}

// TestRustFixtureOpensExactly asserts every identity and every selector in the
// Rust-generated EXPECTED.json contract.
func TestRustFixtureOpensExactly(t *testing.T) {
	want := loadExpected(t)
	s, dir := openFixture(t)

	format, err := os.ReadFile(filepath.Join(dir, "FORMAT"))
	if err != nil {
		t.Fatalf("read FORMAT: %v", err)
	}
	if string(format) != model.FormatContents {
		t.Fatalf("FORMAT = %q", string(format))
	}
	if s.Generation() != want.Generation {
		t.Fatalf("generation = %d, want %d", s.Generation(), want.Generation)
	}
	if s.Head().Hex() != want.SnapshotRoot {
		t.Fatalf("head = %s, want %s", s.Head().Hex(), want.SnapshotRoot)
	}
	for name, commit := range want.Snapshots {
		got, ok := s.CurrentState().Snapshots[name]
		if !ok {
			t.Fatalf("snapshot %q missing", name)
		}
		if got.Hex() != commit {
			t.Fatalf("snapshot %q = %s, want %s", name, got.Hex(), commit)
		}
		state, err := s.StateAt(got)
		if err != nil {
			t.Fatalf("StateAt(%s): %v", commit, err)
		}
		if state.Generation == 0 || state.Generation > s.Generation() {
			t.Fatalf("snapshot state generation %d out of range", state.Generation)
		}
	}

	state := s.CurrentState()
	for _, object := range want.Objects {
		id := mustHash(t, object.ObjectID)
		record, ok := state.Objects[id]
		if !ok {
			t.Fatalf("object %s (%s) missing", object.ObjectID, object.Path)
		}
		if string(record.Kind) != object.Kind {
			t.Fatalf("object %s kind = %s, want %s", object.Path, record.Kind, object.Kind)
		}
		if record.Size != object.Size {
			t.Fatalf("object %s size = %d, want %d", object.Path, record.Size, object.Size)
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
				t.Fatalf("manifest for %s: %v", object.Path, err)
			}
			if manifest.ContentHash.Hex() != object.ContentHash {
				t.Fatalf("object %s content hash = %s, want %s", object.Path, manifest.ContentHash.Hex(), object.ContentHash)
			}
			bytesRead, err := s.ReadObject(id)
			if err != nil {
				t.Fatalf("read %s: %v", object.Path, err)
			}
			if model.ContentHash(bytesRead).Hex() != object.ContentHash {
				t.Fatalf("object %s assembled content hash mismatch", object.Path)
			}
		} else if record.Content.Hex() != object.ContentHash {
			t.Fatalf("object %s content hash = %s, want %s", object.Path, record.Content.Hex(), object.ContentHash)
		}
		if object.Path != "/" {
			resolved, err := s.ResolvePath(object.Path)
			if err != nil {
				t.Fatalf("resolve %s: %v", object.Path, err)
			}
			if resolved != id {
				t.Fatalf("resolve %s = %s, want %s", object.Path, resolved.Hex(), object.ObjectID)
			}
		}
	}

	for _, entry := range want.Entries {
		path := entry.Path
		parentPath := filepath.Dir(path)
		name := filepath.Base(path)
		parent, err := s.ResolvePath(parentPath)
		if err != nil {
			t.Fatalf("resolve parent %s: %v", parentPath, err)
		}
		target, err := s.Lookup(parent, []byte(name))
		if err != nil {
			t.Fatalf("lookup %s: %v", path, err)
		}
		if target.Hex() != entry.Target {
			t.Fatalf("entry %s target = %s, want %s", path, target.Hex(), entry.Target)
		}
		entryID, err := model.DeriveEntryID(parent, []byte(name))
		if err != nil {
			t.Fatalf("derive entry id %s: %v", path, err)
		}
		if entryID.Hex() != entry.EntryID {
			t.Fatalf("entry %s id = %s, want %s", path, entryID.Hex(), entry.EntryID)
		}
	}

	for _, relation := range want.Relations {
		id := mustHash(t, relation)
		if _, ok := state.Relations[id]; !ok {
			t.Fatalf("relation %s missing", relation)
		}
	}

	// Exact small-file bytes and the symlink target.
	helloID := mustHash(t, "e1295a99361e040c88a81186ad25bb6fe9f224467f24ce597f9cdfb68d0407b6")
	hello, err := s.ReadObject(helloID)
	if err != nil {
		t.Fatalf("read hello: %v", err)
	}
	if string(hello) != "hello weft\n" {
		t.Fatalf("hello = %q", string(hello))
	}
	linkID := mustHash(t, "3884b9e44ef113fc380f4d5517b74544bf0280bdb0270391170be352354ab8b0")
	link, err := s.ReadObject(linkID)
	if err != nil {
		t.Fatalf("read link: %v", err)
	}
	if string(link) != "hello.txt" {
		t.Fatalf("symlink target = %q", string(link))
	}

	// Selectors at the pinned snapshot recorded in EXPECTED.json.
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
		if resolution.SelectorID.Hex() != wantSel.SelectorID {
			t.Fatalf("selector id for %q = %s, want %s", wantSel.Source, resolution.SelectorID.Hex(), wantSel.SelectorID)
		}
		if resolution.SnapshotID.Hex() != wantSel.SnapshotID {
			t.Fatalf("snapshot id for %q = %s, want %s", wantSel.Source, resolution.SnapshotID.Hex(), wantSel.SnapshotID)
		}
		if resolution.MatchedCount != wantSel.MatchedCount {
			t.Fatalf("matched count for %q = %d, want %d", wantSel.Source, resolution.MatchedCount, wantSel.MatchedCount)
		}
		gotIDs := make([]string, 0, len(resolution.Results))
		for _, result := range resolution.Results {
			gotIDs = append(gotIDs, result.ObjectID.Hex())
		}
		if !equalStrings(gotIDs, wantSel.ObjectIDs) {
			t.Fatalf("selector %q ids = %v, want %v", wantSel.Source, gotIDs, wantSel.ObjectIDs)
		}
	}

	report, err := s.Verify(true)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !report.OK {
		t.Fatalf("verify --full reported problems: %+v", report.Problems)
	}
	if report.CheckedObjects < 3 || report.CheckedChunks < 3 {
		t.Fatalf("verify counts too low: objects=%d chunks=%d", report.CheckedObjects, report.CheckedChunks)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func copyFixture(t *testing.T) string {
	dir := t.TempDir()
	copyTree(t, fixtureRel, dir)
	return dir
}

func truncateFile(t *testing.T, path string, keep int64) {
	t.Helper()
	if err := os.Truncate(path, keep); err != nil {
		t.Fatalf("truncate %s: %v", path, err)
	}
}

func flipLastByte(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	b[len(b)-1] ^= 0xff
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestTruncatedCommitFallsBack(t *testing.T) {
	dir := copyFixture(t)
	path := filepath.Join(dir, "commits", "11.commit")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat commit: %v", err)
	}
	truncateFile(t, path, info.Size()/2)
	s, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("open after torn head: %v", err)
	}
	defer s.Close()
	if s.Generation() >= 11 {
		t.Fatalf("generation = %d, expected fallback below 11", s.Generation())
	}
	if !containsU64(s.RejectedGenerations(), 11) {
		t.Fatalf("rejected = %v, expected to name 11", s.RejectedGenerations())
	}
	if _, err := s.ResolvePath("/hello.txt"); err != nil {
		t.Fatalf("resolve hello after fallback: %v", err)
	}
}

func TestCommitCRCFlipFallsBack(t *testing.T) {
	dir := copyFixture(t)
	flipLastByte(t, filepath.Join(dir, "commits", "11.commit"))
	s, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	if s.Generation() >= 11 || !containsU64(s.RejectedGenerations(), 11) {
		t.Fatalf("generation=%d rejected=%v", s.Generation(), s.RejectedGenerations())
	}
}

func TestCorruptSuperblockSlotFallsBack(t *testing.T) {
	dir := copyFixture(t)
	superblock := filepath.Join(dir, "superblock")
	b, err := os.ReadFile(superblock)
	if err != nil {
		t.Fatalf("read superblock: %v", err)
	}
	for i := 4096; i < 8192; i++ {
		b[i] = 0
	}
	if err := os.WriteFile(superblock, b, 0o644); err != nil {
		t.Fatalf("write superblock: %v", err)
	}
	s, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	if s.Generation() != 10 {
		t.Fatalf("generation = %d, want 10 (other slot)", s.Generation())
	}
}

func TestBadSlotCRCAndWrongSlotHashFallBack(t *testing.T) {
	for _, mutation := range []string{"crc", "hash"} {
		t.Run(mutation, func(t *testing.T) {
			dir := copyFixture(t)
			superblock := filepath.Join(dir, "superblock")
			b, err := os.ReadFile(superblock)
			if err != nil {
				t.Fatalf("read superblock: %v", err)
			}
			slot := b[4096:8192]
			if mutation == "crc" {
				slot[64] ^= 0xff
			} else {
				// A syntactically valid slot whose commit hash does not match
				// the commit file.
				slot[16] ^= 0xff
				crc := store.CRC32C(slot[0:64])
				slot[64] = byte(crc)
				slot[65] = byte(crc >> 8)
				slot[66] = byte(crc >> 16)
				slot[67] = byte(crc >> 24)
			}
			if err := os.WriteFile(superblock, b, 0o644); err != nil {
				t.Fatalf("write superblock: %v", err)
			}
			s, err := store.Open(dir, store.ReadOnly)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			defer s.Close()
			if s.Generation() != 10 {
				t.Fatalf("generation = %d, want 10", s.Generation())
			}
			if mutation == "hash" && !containsU64(s.RejectedGenerations(), 11) {
				t.Fatalf("rejected = %v, expected 11", s.RejectedGenerations())
			}
		})
	}
}

func TestWrongChunkHashFailsClosedAtRead(t *testing.T) {
	dir := copyFixture(t)
	binaryID := mustHash(t, "d2578f5a77014c7fcc6fc27ec92e7ebd47f60156f2b634d86b3fde3bb8e0d206")
	// Read-only open validates manifest identity and chunk length, not chunk
	// bytes; the failure must surface when content is materialized.
	s, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	record, err := s.ObjectMeta(binaryID)
	if err != nil {
		t.Fatalf("object meta: %v", err)
	}
	manifest, err := store.ReadManifest(dir, record.Content)
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	chunkPath := store.ObjectPath(dir, manifest.Chunks[0].Hash)
	b, err := os.ReadFile(chunkPath)
	if err != nil {
		t.Fatalf("read chunk: %v", err)
	}
	b[0] ^= 0xff
	if err := os.WriteFile(chunkPath, b, 0o644); err != nil {
		t.Fatalf("write chunk: %v", err)
	}
	_, err = s.ReadObject(binaryID)
	if err == nil {
		t.Fatal("read of corrupted chunk unexpectedly succeeded")
	}
	if !werr.Is(err, werr.Corrupt) {
		t.Fatalf("read error class = %s, want Corrupt (%v)", werr.ClassOf(err), err)
	}
	report, err := s.Verify(true)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.OK {
		t.Fatal("verify --full must report the corrupted chunk")
	}
}

func TestCorruptManifestFallsBack(t *testing.T) {
	dir := copyFixture(t)
	// Corrupt the manifest for hello.txt (created at generation 4). Recovery
	// must reject every generation whose catalog references it, down to 3.
	manifestPath := store.ManifestPath(dir, mustHash(t, "c0be8b5faa824eeeb5107b124c35d56e1fe589cf6c47009b732769f6dd956f01"))
	flipLastByte(t, manifestPath)
	s, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("open with corrupt manifest: %v", err)
	}
	defer s.Close()
	if s.Generation() >= 11 {
		t.Fatalf("generation = %d, expected a fallback", s.Generation())
	}
	if _, err := s.ResolvePath("/hello.txt"); err == nil {
		t.Fatal("hello.txt must not be visible after falling back before its commit")
	}
	report, err := s.Verify(true)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.OK {
		t.Fatal("verify must report the corrupt manifest")
	}
}

func TestBothSuperblockSlotsZeroFailsClosed(t *testing.T) {
	dir := copyFixture(t)
	if err := os.WriteFile(filepath.Join(dir, "superblock"), make([]byte, model.SuperblockBytes), 0o644); err != nil {
		t.Fatalf("write superblock: %v", err)
	}
	_, err := store.Open(dir, store.ReadOnly)
	if err == nil {
		t.Fatal("open unexpectedly succeeded")
	}
	if !werr.Is(err, werr.Corrupt) {
		t.Fatalf("error class = %s, want Corrupt (%v)", werr.ClassOf(err), err)
	}
}

func TestUnpublishedCommitTailIsNotVisible(t *testing.T) {
	dir := copyFixture(t)
	source := filepath.Join(dir, "commits", "11.commit")
	target := filepath.Join(dir, "commits", "12.commit")
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read source commit: %v", err)
	}
	if err := os.WriteFile(target, data, 0o644); err != nil {
		t.Fatalf("write tail: %v", err)
	}
	s, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	if s.Generation() != 11 {
		t.Fatalf("generation = %d, want 11", s.Generation())
	}
	report, err := s.Verify(false)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.OK {
		t.Fatal("verify must flag a commit file above the published superblock")
	}
}

func TestAuthorizationDoesNotDiscloseCounts(t *testing.T) {
	dir := copyFixture(t)
	s, err := store.Open(dir, store.ReadWrite)
	if err != nil {
		t.Fatalf("writer open: %v", err)
	}
	defer s.Close()

	helloID := mustHash(t, "e1295a99361e040c88a81186ad25bb6fe9f224467f24ce597f9cdfb68d0407b6")
	record, err := s.ObjectMeta(helloID)
	if err != nil {
		t.Fatalf("object meta: %v", err)
	}
	attrs := model.CloneAttrs(record.Attrs)
	attrs[model.AttrACLRead] = wcb.ArrayValue([]wcb.Value{wcb.U64Value(0)}) // only uid 0 may read
	if _, err := s.Setattr(helloID, store.SetAttr{Attrs: attrs}); err != nil {
		t.Fatalf("set attr: %v", err)
	}

	parsed, err := selector.Parse(`select kind == "file"`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	rootResolution, err := s.Resolve(parsed, nil, auth.Root(), limits.Default())
	if err != nil {
		t.Fatalf("root resolve: %v", err)
	}
	userResolution, err := s.Resolve(parsed, nil, auth.New(1000, 1000, nil), limits.Default())
	if err != nil {
		t.Fatalf("user resolve: %v", err)
	}
	if rootResolution.MatchedCount != 3 {
		t.Fatalf("root matched = %d, want 3", rootResolution.MatchedCount)
	}
	if userResolution.MatchedCount != 2 {
		t.Fatalf("user matched = %d, want 2 (authorized only)", userResolution.MatchedCount)
	}
	for _, result := range userResolution.Results {
		if result.ObjectID == helloID {
			t.Fatal("unauthorized object disclosed in results")
		}
	}
	for _, evidence := range userResolution.Evidence {
		if evidence.ObjectID == helloID {
			t.Fatal("unauthorized object disclosed in evidence")
		}
	}
}

func containsU64(values []uint64, want uint64) bool {
	sorted := append([]uint64(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	for _, value := range sorted {
		if value == want {
			return true
		}
	}
	return false
}

func TestErrorClassesAreNormative(t *testing.T) {
	// The class strings are the interoperable contract.
	cases := map[werr.Kind]string{
		werr.Corrupt:   string(werrors.Corrupt),
		werr.Malformed: string(werrors.Malformed),
		werr.NotFound:  "NotFound",
		werr.Busy:      "Busy",
	}
	for kind, want := range cases {
		if string(kind) != want {
			t.Fatalf("class %q != %q", kind, want)
		}
	}
	if !strings.Contains(werr.Newf(werr.Corrupt, "x").Error(), "Corrupt") {
		t.Fatal("error text must carry the class")
	}
}
