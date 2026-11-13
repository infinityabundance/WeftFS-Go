// Cross-language check on an aged Rust-written store.
//
// The aged court (`examples/index_aged_bench.rs`) builds stores at 10k and
// 100k live objects with a persisted WFX3 chain. This test opens those stores
// with the Go implementation and requires:
//
//   * Go loads the Rust-written segment (`DiskLoads>0`, `Builds==0`),
//   * every ordered query answer equals the Rust CLI's answer on the same bytes,
//   * the same answers equal Go's own scan oracle.
//
// It is opt-in through `WEFT_AGED_CROSS_DIRS` (colon-separated store roots)
// because it needs the Rust binary and a store built by the aged court. Without
// it the test skips explicitly: there is no fixture to read.

package store_test

import (
	"os"
	"strings"
	"testing"

	"github.com/infinityabundance/WeftCodec-Go/limits"
	"github.com/infinityabundance/WeftCodec-Go/selector"
	"github.com/infinityabundance/WeftFS-Go/auth"
	"github.com/infinityabundance/WeftFS-Go/resolver"
	"github.com/infinityabundance/WeftFS-Go/store"
)

func TestGoReadsAgedRustStore(t *testing.T) {
	dirs := strings.TrimSpace(os.Getenv("WEFT_AGED_CROSS_DIRS"))
	if dirs == "" {
		t.Skip("WEFT_AGED_CROSS_DIRS is not set: no aged Rust store to read")
	}
	bin := rustBinary(t)
	rustUsable(t, bin)
	principal := auth.New(0, 0, nil)

	for _, dir := range strings.Split(dirs, ":") {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		reader, err := store.Open(dir, store.ReadOnly)
		if err != nil {
			t.Fatalf("%s: go open: %v", dir, err)
		}
		first, err := reader.ResolvePath("/f0")
		if err != nil {
			t.Fatalf("%s: resolve /f0: %v", dir, err)
		}
		queries := []string{
			"select relation(links, obj:" + first.Hex() + ")",
			`select tag("alpha")`,
			`select attrs.team == "red"`,
			"select has(attrs.score)",
		}
		for position, text := range queries {
			parsed, err := selector.Parse(text)
			if err != nil {
				t.Fatalf("%s: parse %q: %v", dir, text, err)
			}
			if position == 0 {
				reader.ResetIndexStats()
			}
			got, err := reader.Resolve(parsed, nil, principal, limits.Default())
			if err != nil {
				t.Fatalf("%s: go resolve %q: %v", dir, text, err)
			}
			scan, err := resolver.ResolveState(parsed, reader.Head(), reader.CurrentState(),
				principal, limits.Default())
			if err != nil {
				t.Fatalf("%s: go scan %q: %v", dir, text, err)
			}
			compareResolution(t, dir+" go index vs scan: "+text, got, scan)

			rust := runRustQuery(t, bin, dir, text)
			if rust.MatchedCount != got.MatchedCount {
				t.Fatalf("%s: %q matched rust=%d go=%d", dir, text, rust.MatchedCount, got.MatchedCount)
			}
			rustIDs := make([]string, 0, len(rust.Results))
			for _, item := range rust.Results {
				rustIDs = append(rustIDs, item.ObjectID)
			}
			goIDs := make([]string, 0, len(got.Results))
			for _, item := range got.Results {
				goIDs = append(goIDs, item.ObjectID.Hex())
			}
			if !orderedEqual(rustIDs, goIDs) {
				t.Fatalf("%s: %q rust and go disagree on order or membership: rust=%d go=%d",
					dir, text, len(rustIDs), len(goIDs))
			}
			if position == 0 {
				stats := reader.IndexStats()
				if stats.DiskLoads == 0 || stats.Builds != 0 || stats.Rejects != 0 {
					t.Fatalf("%s: Go must load the Rust segment and rebuild nothing: %+v", dir, stats)
				}
			}
		}
		if err := reader.Close(); err != nil {
			t.Fatalf("%s: close: %v", dir, err)
		}
	}
}

func orderedEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for position := range left {
		if left[position] != right[position] {
			return false
		}
	}
	return true
}
