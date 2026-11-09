package store_test

// MW2 multi-committer tests (subphase R4). These mirror the Rust suite and use
// only the public store API: two independent handles, one shared local store.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/auth"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

const mw2Now int64 = 1_700_000_000_000_000_000

func mw2Options(mode store.WriterMode) store.Options {
	opts := store.DefaultOptions()
	now := mw2Now
	opts.FixedTimestampNS = &now
	opts.CheckpointInterval = 0
	opts.WriterMode = mode
	return opts
}

func newMW2Store(t *testing.T) (string, func()) {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Init(dir, mw2Options(store.WriterModeSingle))
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return dir, func() {}
}

func openMW2(t *testing.T, dir string) *store.Store {
	t.Helper()
	s, err := store.OpenWithOptions(dir, store.ReadWrite, mw2Options(store.WriterModeOptimistic))
	if err != nil {
		t.Fatalf("open optimistic: %v", err)
	}
	return s
}

type filePlan struct {
	record model.ObjectRecord
	entry  model.EntryRecord
}

func planMW2File(t *testing.T, s *store.Store, parent model.Hash32, name []byte, data []byte, seed []byte) filePlan {
	t.Helper()
	manifest, _, size, err := s.PrepareContent(data)
	if err != nil {
		t.Fatalf("prepare content: %v", err)
	}
	id := model.ObjectIDFromSeed(seed)
	version, err := model.DeriveVersionID(id, manifest, size, mw2Now, nil)
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	record := model.ObjectRecord{
		ID: id, Kind: model.KindFile, Mode: 0o644, UID: 0, GID: 0,
		MtimeNS: mw2Now, Version: version, Content: manifest, Size: size,
		Attrs: map[string]wcb.Value{},
	}
	entryID, err := model.DeriveEntryID(parent, name)
	if err != nil {
		t.Fatalf("entry id: %v", err)
	}
	entry := model.EntryRecord{ID: entryID, Parent: parent, Name: append([]byte(nil), name...), Target: id}
	return filePlan{record: record, entry: entry}
}

func stageMW2(t *testing.T, s *store.Store, id string, plan filePlan) *store.Transaction {
	t.Helper()
	tx, err := s.BeginTransaction(id)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := tx.PutObject(s.CurrentState(), plan.record); err != nil {
		t.Fatalf("put object: %v", err)
	}
	if err := tx.PutEntry(s.CurrentState(), plan.entry); err != nil {
		t.Fatalf("put entry: %v", err)
	}
	if err := tx.SetTip(s.CurrentState(), plan.record.ID, plan.record.Version); err != nil {
		t.Fatalf("set tip: %v", err)
	}
	return tx
}

func TestMW2OptimisticPolicyAndSingleRefusal(t *testing.T) {
	dir, _ := newMW2Store(t)
	s := openMW2(t, dir)
	if s.Options().WriterMode != store.WriterModeOptimistic {
		t.Fatalf("writer mode = %q", s.Options().WriterMode)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "writers")); err != nil {
		t.Fatalf("writers record: %v", err)
	}
	_, err := store.OpenWithOptions(dir, store.ReadWrite, mw2Options(store.WriterModeSingle))
	if err == nil || werr.ClassOf(err) != werr.Unsupported {
		t.Fatalf("single open err = %v", err)
	}
}

func TestMW2DisjointTransactionsBothCommit(t *testing.T) {
	dir, _ := newMW2Store(t)
	a := openMW2(t, dir)
	defer a.Close()
	b := openMW2(t, dir)
	defer b.Close()

	planA := planMW2File(t, a, model.RootID, []byte("a.txt"), []byte("alpha"), []byte("seed-a"))
	planB := planMW2File(t, a, model.RootID, []byte("b.txt"), []byte("beta"), []byte("seed-b"))
	txA := stageMW2(t, a, "0000000000000000000000000000000a", planA)
	txB := stageMW2(t, b, "0000000000000000000000000000000b", planB)

	outA, err := a.ExecuteTransaction(txA, store.DefaultTransactionOptions())
	if err != nil {
		t.Fatalf("A: %v", err)
	}
	outB, err := b.ExecuteTransaction(txB, store.DefaultTransactionOptions())
	if err != nil {
		t.Fatalf("B: %v", err)
	}
	if outA.Commit == outB.Commit || outA.Idempotent || outB.Idempotent {
		t.Fatalf("outcomes: %+v %+v", outA, outB)
	}

	check, err := store.OpenWithOptions(dir, store.ReadOnly, store.DefaultOptions())
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer check.Close()
	report, err := check.Verify(true)
	if err != nil || !report.OK {
		t.Fatalf("verify: ok=%v err=%v problems=%v", report.OK, err, report.Problems)
	}
	entries, err := check.ListDir(model.RootID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		seen[string(entry.Name)] = true
	}
	if !seen["a.txt"] || !seen["b.txt"] {
		t.Fatalf("entries: %v", seen)
	}
}

func TestMW2SameNameIsATypedConflict(t *testing.T) {
	dir, _ := newMW2Store(t)
	a := openMW2(t, dir)
	defer a.Close()
	b := openMW2(t, dir)
	defer b.Close()

	planA := planMW2File(t, a, model.RootID, []byte("same"), []byte("one"), []byte("seed-1"))
	planB := planMW2File(t, a, model.RootID, []byte("same"), []byte("two"), []byte("seed-2"))
	txA := stageMW2(t, a, "0000000000000000000000000000001a", planA)
	txB := stageMW2(t, b, "0000000000000000000000000000001b", planB)
	if _, err := a.ExecuteTransaction(txA, store.DefaultTransactionOptions()); err != nil {
		t.Fatalf("A: %v", err)
	}
	_, err := b.ExecuteTransaction(txB, store.DefaultTransactionOptions())
	if err == nil || werr.ClassOf(err) != werr.Conflict {
		t.Fatalf("B err = %v", err)
	}
}

func TestMW2SameObjectUpdateIsRejected(t *testing.T) {
	dir, _ := newMW2Store(t)
	a := openMW2(t, dir)
	defer a.Close()
	plan := planMW2File(t, a, model.RootID, []byte("f"), []byte("v1"), []byte("seed-f"))
	tx := stageMW2(t, a, "0000000000000000000000000000002a", plan)
	if _, err := a.ExecuteTransaction(tx, store.DefaultTransactionOptions()); err != nil {
		t.Fatalf("create: %v", err)
	}

	b := openMW2(t, dir)
	defer b.Close()
	manifestA, _, sizeA, err := a.PrepareContent([]byte("v2-a"))
	if err != nil {
		t.Fatalf("content A: %v", err)
	}
	manifestB, _, sizeB, err := b.PrepareContent([]byte("v2-b"))
	if err != nil {
		t.Fatalf("content B: %v", err)
	}
	versionA, _ := model.DeriveVersionID(plan.record.ID, manifestA, sizeA, mw2Now+1, nil)
	versionB, _ := model.DeriveVersionID(plan.record.ID, manifestB, sizeB, mw2Now+2, nil)
	recA := plan.record
	recA.Content, recA.Size, recA.Version, recA.MtimeNS = manifestA, sizeA, versionA, mw2Now+1
	recB := plan.record
	recB.Content, recB.Size, recB.Version, recB.MtimeNS = manifestB, sizeB, versionB, mw2Now+2

	txA, _ := a.BeginTransaction("0000000000000000000000000000002b")
	if err := txA.PutObject(a.CurrentState(), recA); err != nil {
		t.Fatalf("put A: %v", err)
	}
	txB, _ := b.BeginTransaction("0000000000000000000000000000002c")
	if err := txB.PutObject(b.CurrentState(), recB); err != nil {
		t.Fatalf("put B: %v", err)
	}
	if _, err := a.ExecuteTransaction(txA, store.DefaultTransactionOptions()); err != nil {
		t.Fatalf("A: %v", err)
	}
	if _, err := b.ExecuteTransaction(txB, store.DefaultTransactionOptions()); err == nil || werr.ClassOf(err) != werr.Conflict {
		t.Fatalf("B err = %v", err)
	}
}

func TestMW2ReplayIsIdempotent(t *testing.T) {
	dir, _ := newMW2Store(t)
	s := openMW2(t, dir)
	defer s.Close()
	plan := planMW2File(t, s, model.RootID, []byte("once"), []byte("bytes"), []byte("seed-once"))
	tx := stageMW2(t, s, "0000000000000000000000000000003a", plan)
	first, err := s.ExecuteTransaction(tx, store.DefaultTransactionOptions())
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	head := s.Head()
	second, err := s.ExecuteTransaction(tx, store.DefaultTransactionOptions())
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first.Commit != second.Commit || !second.Idempotent || s.Head() != head {
		t.Fatalf("first=%+v second=%+v head=%s/%s", first, second, head.Hex(), s.Head().Hex())
	}
}

func TestMW2AmbiguousOutcomeResolvedByDigest(t *testing.T) {
	dir, _ := newMW2Store(t)
	s := openMW2(t, dir)
	defer s.Close()
	id := "0000000000000000000000000000004a"
	plan := planMW2File(t, s, model.RootID, []byte("amb"), []byte("payload"), []byte("seed-amb"))
	tx := stageMW2(t, s, id, plan)
	first, err := s.ExecuteTransaction(tx, store.DefaultTransactionOptions())
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	digest, _ := tx.Digest()
	record := store.TxRecord{
		ID: id, State: store.TxPrepared, Digest: digest,
		ParentGeneration: tx.BaseGeneration, UpdatedNS: mw2Now,
	}
	data, err := store.EncodeTxRecord(record)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "txs", id), data, 0o644); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	recovered, err := s.ExecuteTransaction(tx, store.DefaultTransactionOptions())
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if recovered.Commit != first.Commit || !recovered.Idempotent || recovered.Attempts != 0 {
		t.Fatalf("recovered=%+v first=%+v", recovered, first)
	}
}

func TestMW2GCKeepsPreparedPins(t *testing.T) {
	dir, _ := newMW2Store(t)
	s := openMW2(t, dir)
	defer s.Close()
	plan := planMW2File(t, s, model.RootID, []byte("gc"), []byte("pinned-content"), []byte("seed-gc"))
	tx := stageMW2(t, s, "0000000000000000000000000000005a", plan)
	if err := s.PrepareTransaction(tx); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if _, err := s.GC(true); err != nil {
		t.Fatalf("gc: %v", err)
	}
	if _, err := s.ExecuteTransaction(tx, store.DefaultTransactionOptions()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	report, err := s.Verify(true)
	if err != nil || !report.OK {
		t.Fatalf("verify: ok=%v err=%v problems=%v", report.OK, err, report.Problems)
	}
}

func TestMW2AuthRaceDeniesPublication(t *testing.T) {
	dir, _ := newMW2Store(t)
	a := openMW2(t, dir)
	defer a.Close()
	protected := planMW2File(t, a, model.RootID, []byte("protected"), []byte("secret"), []byte("seed-prot"))
	tx := stageMW2(t, a, "0000000000000000000000000000006a", protected)
	if _, err := a.ExecuteTransaction(tx, store.DefaultTransactionOptions()); err != nil {
		t.Fatalf("create: %v", err)
	}

	b := openMW2(t, dir)
	defer b.Close()
	unrelated := planMW2File(t, b, model.RootID, []byte("other"), []byte("x"), []byte("seed-other"))
	txB := stageMW2(t, b, "0000000000000000000000000000006b", unrelated)
	txB.RequireReadable(protected.record.ID, auth.Principal{UID: 2, GID: 2})

	rec := protected.record
	rec.Mode = 0o600
	version, _ := model.DeriveVersionID(rec.ID, rec.Content, rec.Size, mw2Now+9, nil)
	rec.Version, rec.MtimeNS = version, mw2Now+9
	txA, _ := a.BeginTransaction("0000000000000000000000000000006c")
	if err := txA.PutObject(a.CurrentState(), rec); err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, err := a.ExecuteTransaction(txA, store.DefaultTransactionOptions()); err != nil {
		t.Fatalf("A: %v", err)
	}
	if _, err := b.ExecuteTransaction(txB, store.DefaultTransactionOptions()); err == nil || werr.ClassOf(err) != werr.Unauthorized {
		t.Fatalf("B err = %v", err)
	}
}

func TestMW2QuotaRaceAtLimitRejectsLoser(t *testing.T) {
	dir := t.TempDir()
	opts := mw2Options(store.WriterModeSingle)
	opts.Quotas = []store.QuotaBudget{{
		Principal: store.PosixPrincipal(0, 0), MaxNewBytes: ^uint64(0), MaxObjects: 1,
	}}
	s, err := store.Init(dir, opts)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	a := openMW2(t, dir)
	defer a.Close()
	b := openMW2(t, dir)
	defer b.Close()
	planA := planMW2File(t, a, model.RootID, []byte("qa"), []byte("one"), []byte("seed-qa"))
	planB := planMW2File(t, a, model.RootID, []byte("qb"), []byte("two"), []byte("seed-qb"))
	txA := stageMW2(t, a, "0000000000000000000000000000009a", planA)
	txB := stageMW2(t, b, "0000000000000000000000000000009b", planB)
	if _, err := a.ExecuteTransaction(txA, store.DefaultTransactionOptions()); err != nil {
		t.Fatalf("A: %v", err)
	}
	if _, err := b.ExecuteTransaction(txB, store.DefaultTransactionOptions()); err == nil || werr.ClassOf(err) != werr.BudgetExceeded {
		t.Fatalf("B err = %v", err)
	}
}
