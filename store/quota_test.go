package store_test

// Write-budget courts (P5a, part 1), Go parity with the Rust store.

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

func quotaOptions(chunkSize uint64, budgets ...store.QuotaBudget) store.Options {
	opts := store.DefaultOptions()
	opts.ChunkSize = chunkSize
	opts.GCGraceSecs = 0
	opts.CheckpointInterval = 256
	opts.Quotas = budgets
	return opts
}

func variedBytes(size int) []byte {
	out := make([]byte, size)
	state := uint64(0x9E3779B97F4A7C15)
	for i := range out {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		out[i] = byte(state & 0xff)
	}
	return out
}

func TestQuotaDeniesOverBudgetWriteAndPublishesNothing(t *testing.T) {
	dir := t.TempDir()
	opts := quotaOptions(1024, store.QuotaBudget{
		Principal: store.PosixPrincipal(0, 0), MaxNewBytes: 8192, MaxObjects: 100,
	})
	s, err := store.Init(dir, opts)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()
	root, err := s.ResolvePath("/")
	if err != nil {
		t.Fatalf("resolve root: %v", err)
	}
	if _, err := s.CreateFile(root, []byte("small.txt"), []byte("hello"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("small write: %v", err)
	}
	generation := s.Generation()
	head := s.Head()
	objects := len(s.CurrentState().Objects)
	entries := len(s.CurrentState().Entries)
	before := s.QuotaUsage(store.PosixPrincipal(0, 0))
	if before.UsedObjects != 1 || before.UsedBytes == 0 {
		t.Fatalf("unexpected usage after first write: %+v", before)
	}

	_, err = s.CreateFile(root, []byte("big.bin"), variedBytes(512*1024), 0o644, 0, 0, nil)
	if err == nil {
		t.Fatal("512 KiB was accepted under an 8 KiB budget")
	}
	if !werr.Is(err, werr.BudgetExceeded) {
		t.Fatalf("class = %v, want BudgetExceeded", werr.ClassOf(err))
	}
	if err.Error() != "BudgetExceeded: write budget exceeded" {
		t.Fatalf("denial leaked detail: %q", err.Error())
	}
	if s.Generation() != generation || s.Head() != head {
		t.Fatalf("generation/head moved on denial: %d/%s", s.Generation(), s.Head().Hex())
	}
	if len(s.CurrentState().Objects) != objects || len(s.CurrentState().Entries) != entries {
		t.Fatal("state moved on denial")
	}
	if s.QuotaUsage(store.PosixPrincipal(0, 0)) != before {
		t.Fatal("a denied commit was charged")
	}
	report, err := s.Verify(true)
	if err != nil || !report.OK {
		t.Fatalf("verify: %v %+v", err, report)
	}
}

func TestQuotaReusedContentCostsOnlyTheNewRecord(t *testing.T) {
	dir := t.TempDir()
	opts := quotaOptions(4096, store.QuotaBudget{
		Principal: store.PosixPrincipal(0, 0), MaxNewBytes: ^uint64(0), MaxObjects: ^uint64(0),
	})
	s, err := store.Init(dir, opts)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()
	root, _ := s.ResolvePath("/")
	body := variedBytes(64 * 1024)
	if _, err := s.CreateFile(root, []byte("first.bin"), body, 0o644, 0, 0, nil); err != nil {
		t.Fatalf("first: %v", err)
	}
	afterFirst := s.QuotaUsage(store.PosixPrincipal(0, 0))
	if _, err := s.Mkdir(root, []byte("dir"), 0o755, 0, 0); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	afterDir := s.QuotaUsage(store.PosixPrincipal(0, 0))
	child, _ := s.ResolvePath("/dir")
	if _, err := s.CreateFile(child, []byte("second.bin"), body, 0o644, 0, 0, nil); err != nil {
		t.Fatalf("second: %v", err)
	}
	afterSecond := s.QuotaUsage(store.PosixPrincipal(0, 0))
	delta := afterSecond.UsedBytes - afterDir.UsedBytes
	if delta == 0 || delta >= uint64(len(body)) {
		t.Fatalf("identical content was charged again: delta=%d body=%d", delta, len(body))
	}
	if afterSecond.UsedObjects-afterDir.UsedObjects != 1 {
		t.Fatalf("object delta = %d", afterSecond.UsedObjects-afterDir.UsedObjects)
	}
	if afterFirst.UsedBytes < uint64(len(body)) {
		t.Fatalf("first write did not pay for content: %d", afterFirst.UsedBytes)
	}
}

func TestQuotaSurvivesReopenAndStillDenies(t *testing.T) {
	dir := t.TempDir()
	opts := quotaOptions(1024, store.QuotaBudget{
		Principal: store.PosixPrincipal(0, 0), MaxNewBytes: 16 * 1024, MaxObjects: 3,
	})
	s, err := store.Init(dir, opts)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	root, _ := s.ResolvePath("/")
	for index := 0; index < 2; index++ {
		body := []byte{byte('a' + index)}
		if _, err := s.CreateFile(root, []byte{byte('a' + index)}, body, 0o644, 0, 0, nil); err != nil {
			t.Fatalf("create %d: %v", index, err)
		}
	}
	before := s.QuotaUsage(store.PosixPrincipal(0, 0))
	s.Close()

	// Reopen without restating the policy: the persisted record enforces it.
	reopened, err := store.OpenWithOptions(dir, store.ReadWrite, quotaOptions(1024))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	if !reopened.QuotaEnforced() {
		t.Fatal("persisted policy is not enforced after reopen")
	}
	if reopened.QuotaUsage(store.PosixPrincipal(0, 0)) != before {
		t.Fatalf("usage changed across reopen: %+v vs %+v", reopened.QuotaUsage(store.PosixPrincipal(0, 0)), before)
	}
	if _, err := reopened.CreateFile(root, []byte("c"), []byte("c"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("third object should fit: %v", err)
	}
	if _, err := reopened.CreateFile(root, []byte("d"), []byte("d"), 0o644, 0, 0, nil); !werr.Is(err, werr.BudgetExceeded) {
		t.Fatalf("fourth object class = %v, want BudgetExceeded", werr.ClassOf(err))
	}
	if usage := reopened.QuotaUsage(store.PosixPrincipal(0, 0)); usage.UsedObjects != 3 {
		t.Fatalf("used objects = %d, want 3", usage.UsedObjects)
	}
}

func TestQuotaMismatchedRecordFailsClosed(t *testing.T) {
	dir := t.TempDir()
	opts := quotaOptions(1024, store.QuotaBudget{
		Principal: store.PosixPrincipal(0, 0), MaxNewBytes: 64 * 1024, MaxObjects: 10,
	})
	s, err := store.Init(dir, opts)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	root, _ := s.ResolvePath("/")
	if _, err := s.CreateFile(root, []byte("one.txt"), []byte("one"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	s.Close()

	path := filepath.Join(dir, "quota")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read quota: %v", err)
	}
	data[len(data)-1] ^= 0xff
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	reopened, err := store.OpenWithOptions(dir, store.ReadWrite, quotaOptions(1024))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if reopened.QuotaProblem() == "" {
		t.Fatal("tampered record was accepted")
	}
	generation := reopened.Generation()
	if _, err := reopened.CreateFile(root, []byte("two.txt"), []byte("two"), 0o644, 0, 0, nil); !werr.Is(err, werr.Corrupt) {
		t.Fatalf("class = %v, want Corrupt", werr.ClassOf(err))
	}
	if reopened.Generation() != generation {
		t.Fatal("generation moved on a fail-closed write")
	}
	if _, err := reopened.QuotaRebuild(); !werr.Is(err, werr.Corrupt) {
		t.Fatalf("rebuild without a policy was accepted: %v", err)
	}
	if err := reopened.InstallQuotaPolicy([]store.QuotaBudget{{
		Principal: store.PosixPrincipal(0, 0), MaxNewBytes: 64 * 1024, MaxObjects: 10,
	}}); err != nil {
		t.Fatalf("install policy: %v", err)
	}
	if reopened.QuotaProblem() != "" {
		t.Fatal("record was not repaired")
	}
	if _, err := reopened.CreateFile(root, []byte("two.txt"), []byte("two"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("write after repair: %v", err)
	}
	reopened.Close()
}

func TestQuotaTenantAttribution(t *testing.T) {
	dir := t.TempDir()
	opts := quotaOptions(1024, store.QuotaBudget{
		Principal: store.TenantPrincipal("acme"), MaxNewBytes: ^uint64(0), MaxObjects: 1,
	})
	s, err := store.Init(dir, opts)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()
	root, _ := s.ResolvePath("/")
	attrs := map[string]wcb.Value{model.AttrTenant: wcb.TextValue("acme")}
	if _, err := s.CreateFile(root, []byte("a.txt"), []byte("a"), 0o644, 0, 0, attrs); err != nil {
		t.Fatalf("tenant write: %v", err)
	}
	if _, err := s.CreateFile(root, []byte("b.txt"), []byte("b"), 0o644, 0, 0, attrs); !werr.Is(err, werr.BudgetExceeded) {
		t.Fatalf("tenant budget class = %v, want BudgetExceeded", werr.ClassOf(err))
	}
	if _, err := s.CreateFile(root, []byte("c.txt"), []byte("c"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("untagged write: %v", err)
	}
	if usage := s.QuotaUsage(store.TenantPrincipal("acme")); usage.UsedObjects != 1 {
		t.Fatalf("tenant objects = %d", usage.UsedObjects)
	}
	if usage := s.QuotaUsage(store.PosixPrincipal(0, 0)); usage.UsedObjects != 2 {
		t.Fatalf("posix objects = %d", usage.UsedObjects)
	}
}

func TestQuotaRecordBytesMatchRustEncoding(t *testing.T) {
	record := store.QuotaRecord{
		Generation: 7,
		Commit:     model.Hash32{},
		Budgets: []store.QuotaBudget{
			{Principal: store.PosixPrincipal(0, 0), MaxNewBytes: 3, MaxObjects: 4},
			{Principal: store.TenantPrincipal("zeta"), MaxNewBytes: 5, MaxObjects: 6},
		},
		Usage: []store.QuotaUsageEntry{
			{Principal: store.PosixPrincipal(0, 0), Counters: store.QuotaCounters{UsedBytes: 10, UsedObjects: 1}},
		},
	}
	encoded, err := record.EncodeBytes()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := store.DecodeQuotaRecord(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Generation != 7 || len(decoded.Budgets) != 2 {
		t.Fatalf("round trip mismatch: %+v", decoded)
	}
	if !bytes.Equal(encoded[:4], []byte("WFQ1")) {
		t.Fatal("wrong magic")
	}
	broken := append([]byte(nil), encoded...)
	broken[20] ^= 1
	if _, err := store.DecodeQuotaRecord(broken); !werr.Is(err, werr.Corrupt) {
		t.Fatalf("corrupt class = %v", werr.ClassOf(err))
	}
}

func TestQuotaArgumentParsing(t *testing.T) {
	budget, err := store.ParseQuotaBudget("1000:1000:1048576:16")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if budget.Principal != store.PosixPrincipal(1000, 1000) || budget.MaxNewBytes != 1_048_576 || budget.MaxObjects != 16 {
		t.Fatalf("parsed %+v", budget)
	}
	tenant, err := store.ParseQuotaBudget("tenant:acme:100:2")
	if err != nil || tenant.Principal != store.TenantPrincipal("acme") {
		t.Fatalf("tenant parse: %v %+v", err, tenant)
	}
	if _, err := store.ParseQuotaBudget("nonsense"); err == nil {
		t.Fatal("bad directive accepted")
	}
	budgets, err := store.ParseQuotaFile("# comment\n\n0:0:10:1\ntenant:acme:20:2\n")
	if err != nil || len(budgets) != 2 {
		t.Fatalf("file parse: %v %d", err, len(budgets))
	}
	dir := t.TempDir()
	opts := quotaOptions(1024,
		store.QuotaBudget{Principal: store.PosixPrincipal(0, 0), MaxNewBytes: 1, MaxObjects: 1},
		store.QuotaBudget{Principal: store.PosixPrincipal(0, 0), MaxNewBytes: 2, MaxObjects: 2})
	if _, err := store.Init(dir, opts); err == nil {
		t.Fatal("duplicate principals were accepted")
	}
}
