package store_test

import (
	"testing"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
)

// A rebase consumes a read counter and writes nothing else. That pure
// consumption used to leave `pending` empty, so flush early-returned and the
// counter survived a reopen; the second rebase then matched Rust's idempotence
// only inside one process. This test pins the persistence.
func TestPureConsumptionPersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, store.DefaultOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	id, err := s.CreateFile(model.RootID, []byte("hot"), []byte("payload"), 0o644, 0, 0, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	for index := 0; index < 3; index++ {
		if _, err := s.ReadObject(id); err != nil {
			t.Fatalf("read: %v", err)
		}
	}
	if err := s.FlushAccessCounts(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	writer, err := store.Open(dir, store.ReadWrite)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if reads := writer.AccessReads(id); reads != 3 {
		t.Fatalf("reads after reopen = %d, want 3", reads)
	}
	if consumed := writer.ConsumeAccessReads(id); consumed != 3 {
		t.Fatalf("consumed = %d, want 3", consumed)
	}
	if err := writer.FlushAccessCounts(); err != nil {
		t.Fatalf("flush after consume: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reader, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("third open: %v", err)
	}
	defer reader.Close()
	if reads := reader.AccessReads(id); reads != 0 {
		t.Fatalf("consumed counter came back after reopen: %d", reads)
	}
}
