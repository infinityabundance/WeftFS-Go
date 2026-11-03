package fusefs

import (
	"bytes"
	"testing"

	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/model"
)

func TestEscapeComponentMatchesRustRules(t *testing.T) {
	cases := map[string]string{
		"hello.txt":  "hello.txt",
		"a/b":        "a%2Fb",
		"new\nline":  "new%0Aline",
		"%41":        "%2541",
		"\xff":       "%FF",
		"":           "object",
		".":          "%2E",
		"..":         "%2E",
		"plain-name": "plain-name",
	}
	for input, want := range cases {
		if got := string(escapeComponent([]byte(input))); got != want {
			t.Fatalf("escapeComponent(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestContextNamesExtendPrefixOnCollision(t *testing.T) {
	state := model.NewState()
	emptyContent := model.ContentHash(nil)
	version, err := model.DeriveVersionID(model.RootID, emptyContent, 0, 0, nil)
	if err != nil {
		t.Fatalf("derive version: %v", err)
	}
	root := model.ObjectRecord{
		ID: model.RootID, Kind: model.KindDir, Mode: 0o755, Version: version,
		Content: emptyContent, Attrs: map[string]wcb.Value{},
	}
	state.Objects[model.RootID] = root

	mkdir := func(id model.Hash32, parent model.Hash32, name string) {
		version, err := model.DeriveVersionID(id, emptyContent, 0, 0, nil)
		if err != nil {
			t.Fatalf("derive version: %v", err)
		}
		state.Objects[id] = model.ObjectRecord{
			ID: id, Kind: model.KindDir, Mode: 0o755, Version: version,
			Content: emptyContent, Attrs: map[string]wcb.Value{},
		}
		entryID, err := model.DeriveEntryID(parent, []byte(name))
		if err != nil {
			t.Fatalf("derive entry: %v", err)
		}
		state.Entries[entryID] = model.EntryRecord{
			ID: entryID, Parent: parent, Name: []byte(name), Target: id,
		}
	}

	var dirA, dirB model.Hash32
	dirA[0], dirB[1] = 0xa1, 0xb2
	mkdir(dirA, model.RootID, "a")
	mkdir(dirB, model.RootID, "b")

	// Two file ids whose first eight bytes are identical, so an 8-hex prefix
	// collides and the rule must extend to 16 hex characters.
	var first, second model.Hash32
	for i := 0; i < 8; i++ {
		first[i] = 0x11
		second[i] = 0x11
	}
	for i := 8; i < 32; i++ {
		first[i] = 0x11
		second[i] = 0x22
	}
	addFile := func(id model.Hash32, parent model.Hash32, name string) {
		version, err := model.DeriveVersionID(id, emptyContent, 0, 0, nil)
		if err != nil {
			t.Fatalf("derive version: %v", err)
		}
		state.Objects[id] = model.ObjectRecord{
			ID: id, Kind: model.KindFile, Mode: 0o644, Version: version,
			Content: emptyContent, Attrs: map[string]wcb.Value{},
		}
		entryID, err := model.DeriveEntryID(parent, []byte(name))
		if err != nil {
			t.Fatalf("derive entry: %v", err)
		}
		state.Entries[entryID] = model.EntryRecord{
			ID: entryID, Parent: parent, Name: []byte(name), Target: id,
		}
	}
	addFile(first, dirA, "same.txt")
	addFile(second, dirB, "same.txt")

	names := contextEntryNames([]model.Hash32{second, first}, state)
	if len(names) != 2 {
		t.Fatalf("names = %v", names)
	}
	seen := map[string]bool{}
	for _, entry := range names {
		name := string(entry.Name)
		if seen[name] {
			t.Fatalf("duplicate name %q", name)
		}
		seen[name] = true
	}
	want := []string{"same.txt--11111111", "same.txt--1111111111111111"}
	for _, expected := range want {
		if !seen[expected] {
			t.Fatalf("names = %v, want %v", seen, want)
		}
	}
	if !bytes.Equal(names[0].Name, []byte(want[0])) {
		t.Fatalf("name order = %v, want %v", names[0].Name, want[0])
	}
}
