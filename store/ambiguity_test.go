package store_test

import (
	"strings"
	"testing"

	"github.com/infinityabundance/WeftCodec-Go/limits"
	"github.com/infinityabundance/WeftCodec-Go/selector"
	"github.com/infinityabundance/WeftFS-Go/auth"
	"github.com/infinityabundance/WeftFS-Go/store"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

func TestRequireOneAmbiguityListsEveryCompetingObjectID(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, fixedOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()
	a := createDemo(t, s, "a.txt", "alpha", "demo")
	b := createDemo(t, s, "b.txt", "beta", "demo")
	parsed, err := selector.Parse(`select kind == "file"`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	full, err := s.Resolve(parsed, nil, auth.Root(), limits.Default())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if full.MatchedCount != 2 || len(full.Results) != 2 {
		t.Fatalf("full matches = %d/%d", full.MatchedCount, len(full.Results))
	}
	_, err = s.RequireOne(parsed, nil, auth.Root(), limits.Default())
	typed, ok := err.(*werr.Error)
	if !ok || typed.Kind != werr.Ambiguous {
		t.Fatalf("require-one error = %v, want Ambiguous", err)
	}
	for _, id := range []string{a.Hex(), b.Hex()} {
		if !strings.Contains(typed.Msg, id) {
			t.Fatalf("ambiguity message %q does not list %s", typed.Msg, id)
		}
	}
}
