// Cross-language index-segment tests.
//
// Rust's WFX2 segment is internal advisory data, so the only honest question is
// whether the two implementations can consume each other's bytes. These tests
// answer it with real processes:
//
//   * Go writes the segments, Rust must load the Go bytes rather than reject
//     and rebuild. A load is proved by a *control* segment with one section
//     emptied: Rust can only return zero matches if it trusted the file.
//   * Rust writes the segments, Go must load them with DiskLoads=1/Builds=0
//     and reproduce the scan oracle exactly.

package store_test

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/infinityabundance/WeftCodec-Go/limits"
	"github.com/infinityabundance/WeftCodec-Go/selector"
	"github.com/infinityabundance/WeftFS-Go/auth"
	weftindex "github.com/infinityabundance/WeftFS-Go/index"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/resolver"
	"github.com/infinityabundance/WeftFS-Go/store"
)

type rustQueryResult struct {
	MatchedCount uint64 `json:"matched_count"`
	Results      []struct {
		ObjectID string `json:"object_id"`
	} `json:"results"`
}

func runRustQuery(t *testing.T, bin, dir, text string) rustQueryResult {
	t.Helper()
	output := runRust(t, bin, "--store", dir, "--json", "query", text, "--uid", "0", "--gid", "0")
	var parsed rustQueryResult
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("rust query %q output is not JSON: %v\n%s", text, err, output)
	}
	return parsed
}

func rustObjectIDs(result rustQueryResult) []string {
	out := make([]string, 0, len(result.Results))
	for _, item := range result.Results {
		out = append(out, item.ObjectID)
	}
	sort.Strings(out)
	return out
}

// TestRustLoadsGoWrittenIndexSegment proves both directions of the section
// layout: Rust answers correctly from a Go segment, and it really read it.
func TestRustLoadsGoWrittenIndexSegment(t *testing.T) {
	bin := rustBinary(t)
	rustUsable(t, bin)

	dir := t.TempDir()
	fixture := buildIndexFixture(t, dir, 256)
	if err := fixture.store.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	tagQuery := "select tag(\"alpha\")"
	attrQuery := "select attrs.team == \"red\""

	// 1. Sanity: Rust and Go agree on the same store bytes.
	rustTag := runRustQuery(t, bin, dir, tagQuery)
	if rustTag.MatchedCount == 0 {
		t.Fatal("rust found no tagged objects")
	}
	parsed, err := selector.Parse(tagQuery)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	reader, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("go open: %v", err)
	}
	defer reader.Close()
	goResult, err := reader.Resolve(parsed, nil, auth.New(0, 0, nil), limits.Default())
	if err != nil {
		t.Fatalf("go resolve: %v", err)
	}
	if goResult.MatchedCount != rustTag.MatchedCount {
		t.Fatalf("tag matched_count: go=%d rust=%d", goResult.MatchedCount, rustTag.MatchedCount)
	}
	goIDs := make([]string, 0, len(goResult.Results))
	for _, result := range goResult.Results {
		goIDs = append(goIDs, result.ObjectID.Hex())
	}
	sort.Strings(goIDs)
	if strings.Join(goIDs, ",") != strings.Join(rustObjectIDs(rustTag), ",") {
		t.Fatalf("tag results differ:\ngo=%v\nrust=%v", goIDs, rustObjectIDs(rustTag))
	}

	// 2. Control: clear the tag section of the *Go-written head segment*, keep
	// the digest valid, and ask Rust again. A rebuild would still see the
	// relation and return matches; zero matches proves Rust loaded and trusted
	// only the Go bytes.
	headPath := store.BlobPath(dir, store.BlobIndex, reader.Head())
	original, err := os.ReadFile(headPath)
	if err != nil {
		t.Fatalf("read go segment: %v", err)
	}
	decoded, err := weftindex.DecodeFile(original)
	if err != nil {
		t.Fatalf("go segment did not decode: %v", err)
	}
	decoded.Tags = map[string]weftindex.IDSet{}
	mutated, err := decoded.EncodeFile()
	if err != nil {
		t.Fatalf("reaencode control segment: %v", err)
	}
	if strings.HasPrefix(string(mutated), weftindex.MagicV1) {
		t.Fatal("control segment lost its magic")
	}
	if err := os.WriteFile(headPath, mutated, 0o644); err != nil {
		t.Fatalf("write control segment: %v", err)
	}
	controlTag := runRustQuery(t, bin, dir, tagQuery)
	if controlTag.MatchedCount != 0 || len(controlTag.Results) != 0 {
		t.Fatalf("rust rebuilt instead of loading the Go segment: matched=%d results=%v",
			controlTag.MatchedCount, rustObjectIDs(controlTag))
	}

	// 3. Restore, then repeat the control for the attr_eq section.
	if err := os.WriteFile(headPath, original, 0o644); err != nil {
		t.Fatalf("restore go segment: %v", err)
	}
	if before := runRustQuery(t, bin, dir, attrQuery); before.MatchedCount == 0 {
		t.Fatal("rust found no attr-equality matches before the control")
	}
	decoded, err = weftindex.DecodeFile(original)
	if err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	decoded.ObjectsByAttrEq = map[weftindex.AttrEqKey]weftindex.IDSet{}
	mutated, err = decoded.EncodeFile()
	if err != nil {
		t.Fatalf("reenecode attr control: %v", err)
	}
	if err := os.WriteFile(headPath, mutated, 0o644); err != nil {
		t.Fatalf("write attr control: %v", err)
	}
	controlAttr := runRustQuery(t, bin, dir, attrQuery)
	if controlAttr.MatchedCount != 0 || len(controlAttr.Results) != 0 {
		t.Fatalf("rust rebuilt instead of loading the Go attr_eq section: matched=%d",
			controlAttr.MatchedCount)
	}
	if err := os.WriteFile(headPath, original, 0o644); err != nil {
		t.Fatalf("final restore: %v", err)
	}
	// And with the real segment restored, Rust answers again.
	if after := runRustQuery(t, bin, dir, attrQuery); after.MatchedCount == 0 {
		t.Fatal("rust did not see the restored Go segment")
	}
}

// TestGoLoadsRustWrittenIndexSegment proves Go decodes Rust's bytes: no state
// rebuild, no reject, exact answers, and a byte-level re-encode identity.
func TestGoLoadsRustWrittenIndexSegment(t *testing.T) {
	bin := rustBinary(t)
	rustUsable(t, bin)
	dir := t.TempDir()

	runRust(t, bin, "--store", dir, "init")
	runRust(t, bin, "--store", dir, "create", "/f0", "--text", "body-0",
		"--attr", "team=red", "--attr-int", "score=3")
	runRust(t, bin, "--store", dir, "create", "/f1", "--text", "body-1",
		"--attr", "team=green", "--attr-int", "score=7")
	runRust(t, bin, "--store", dir, "create", "/f2", "--text", "body-2",
		"--attr", "team=red", "--attr-int", "score=9")
	runRust(t, bin, "--store", dir, "relation", "add", "--subject", "/f0",
		"--predicate", "tagged_as", "--value", "alpha")
	runRust(t, bin, "--store", dir, "relation", "add", "--subject", "/f2",
		"--predicate", "tagged_as", "--value", "alpha")
	runRust(t, bin, "--store", dir, "relation", "add", "--subject", "/f1",
		"--predicate", "links", "--object", "/f2")
	runRust(t, bin, "--store", dir, "snapshot", "create", "pinned")

	reader, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("go open: %v", err)
	}
	defer reader.Close()

	// The Rust writer wrote a segment for every commit, including the head.
	headPath := store.BlobPath(dir, store.BlobIndex, reader.Head())
	rustBytes, err := os.ReadFile(headPath)
	if err != nil {
		t.Fatalf("rust-written head segment: %v", err)
	}
	if string(rustBytes[0:4]) != weftindex.MagicV2 {
		t.Fatalf("rust segment magic = %q", rustBytes[0:4])
	}
	decoded, err := weftindex.DecodeFile(rustBytes)
	if err != nil {
		t.Fatalf("Go rejected the Rust-written segment: %v", err)
	}
	if decoded.Commit() != reader.Head() {
		t.Fatalf("segment names %s, head is %s", decoded.Commit().Hex(), reader.Head().Hex())
	}
	reencoded, err := decoded.EncodeFile()
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if string(reencoded) != string(rustBytes) {
		t.Fatalf("Go re-encode is not byte-identical to the Rust segment: go %d bytes, rust %d bytes",
			len(reencoded), len(rustBytes))
	}

	principals := []auth.Principal{auth.New(0, 0, nil), auth.Root()}
	queries := []string{
		"select tag(\"alpha\")",
		"select attrs.team == \"red\"",
		"select attrs.score == 3",
		"select attrs.score > 5",
		"select relation(links, obj:" + mustObjectID(t, reader, "/f2").Hex() + ")",
		"select true",
	}
	for position, principal := range principals {
		reader.ResetIndexStats()
		for _, text := range queries {
			parsed, err := selector.Parse(text)
			if err != nil {
				t.Fatalf("parse %q: %v", text, err)
			}
			got, err := reader.Resolve(parsed, nil, principal, limits.Default())
			if err != nil {
				t.Fatalf("go resolve %q: %v", text, err)
			}
			scan, err := resolver.ResolveState(parsed, reader.Head(), reader.CurrentState(),
				principal, limits.Default())
			if err != nil {
				t.Fatalf("scan %q: %v", text, err)
			}
			compareResolution(t, "rust segment: "+text, got, scan)
		}
		stats := reader.IndexStats()
		if position == 0 {
			if stats.DiskLoads != 1 || stats.Builds != 0 || stats.Rejects != 0 {
				t.Fatalf("Go must load the Rust segment: %+v", stats)
			}
		} else if stats.DiskLoads != 0 || stats.Builds != 0 || stats.Rejects != 0 {
			t.Fatalf("second principal must reuse the cached index: %+v", stats)
		}
	}
	// The pinned view also has its own Rust-written segment.
	pinned := reader.CurrentState().Snapshots["pinned"]
	reader.ResetIndexStats()
	query, err := selector.Parse("select tag(\"alpha\")")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := reader.Resolve(query, &pinned, auth.New(0, 0, nil), limits.Default()); err != nil {
		t.Fatalf("resolve pinned: %v", err)
	}
	stats := reader.IndexStats()
	if stats.DiskLoads != 1 || stats.Builds != 0 || stats.Rejects != 0 {
		t.Fatalf("Go must load the pinned view's Rust segment: %+v", stats)
	}
}

func mustObjectID(t *testing.T, s *store.Store, path string) model.Hash32 {
	t.Helper()
	id, err := s.ResolvePath(path)
	if err != nil {
		t.Fatalf("resolve %s: %v", path, err)
	}
	return id
}
