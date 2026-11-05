package store_test

// Q3 court: quota usage is carried by the commit itself (Go parity).

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

func TestQuotaUsageIsACommittedOpAndPolicyFileIsV2(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, quotaOptions(1024, store.QuotaBudget{
		Principal: store.PosixPrincipal(0, 0), MaxNewBytes: 1 << 20, MaxObjects: 100,
	}))
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	root, _ := s.ResolvePath("/")
	if _, err := s.CreateFile(root, []byte("a.txt"), []byte("alpha"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.CreateFile(root, []byte("b.txt"), []byte("beta"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	usage := s.QuotaUsage(store.PosixPrincipal(0, 0))
	generation := s.Generation()
	loaded, err := store.LoadCommitFile(store.CommitPath(dir, generation), &generation)
	if err != nil {
		t.Fatalf("load head: %v", err)
	}
	if len(loaded.Commit.Ops) == 0 {
		t.Fatal("empty head commit")
	}
	declared, ok := loaded.Commit.Ops[len(loaded.Commit.Ops)-1].(model.SetQuotaUsageOp)
	if !ok {
		t.Fatalf("head does not end with a usage op: %T", loaded.Commit.Ops[len(loaded.Commit.Ops)-1])
	}
	if declared.Reset || len(declared.Usage) != 1 {
		t.Fatalf("unexpected usage op: %+v", declared)
	}
	if declared.Usage[0].UsedObjects != usage.UsedObjects || declared.Usage[0].UsedBytes != usage.UsedBytes {
		t.Fatalf("declared %+v != runtime %+v", declared.Usage[0], usage)
	}
	policyBytes, err := os.ReadFile(filepath.Join(dir, "quota"))
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	if !bytes.HasPrefix(policyBytes, []byte("WFQ2")) {
		t.Fatal("quota file is not the policy-only v2 format")
	}
	if _, err := os.Stat(filepath.Join(dir, "quota.migrated")); !os.IsNotExist(err) {
		t.Fatal("unexpected quota.migrated")
	}
	s.Close()

	reopened, err := store.OpenWithOptions(dir, store.ReadWrite, quotaOptions(1024))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	if !reopened.QuotaEnforced() {
		t.Fatal("policy did not survive reopen")
	}
	if got := reopened.QuotaUsage(store.PosixPrincipal(0, 0)); got != usage {
		t.Fatalf("usage after reopen = %+v, want %+v", got, usage)
	}
	if report, err := reopened.Verify(true); err != nil || !report.OK {
		t.Fatalf("verify: %v %+v", err, report)
	}
}

func TestQuotaUsageSurvivesReopenWithoutPerCommitFileWrite(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, quotaOptions(1024, store.QuotaBudget{
		Principal: store.PosixPrincipal(0, 0), MaxNewBytes: 1 << 20, MaxObjects: 100,
	}))
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	root, _ := s.ResolvePath("/")
	if _, err := s.CreateFile(root, []byte("a.txt"), []byte("alpha"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	policyBefore, err := os.ReadFile(filepath.Join(dir, "quota"))
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	for i := 0; i < 20; i++ {
		name := []byte("f" + string(rune('a'+i)) + ".bin")
		if _, err := s.CreateFile(root, name, []byte("payload"), 0o644, 0, 0, nil); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}
	policyAfter, err := os.ReadFile(filepath.Join(dir, "quota"))
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	if !bytes.Equal(policyBefore, policyAfter) {
		t.Fatal("the policy file was rewritten by a commit")
	}
	usage := s.QuotaUsage(store.PosixPrincipal(0, 0))
	if usage.UsedObjects != 21 {
		t.Fatalf("used objects = %d, want 21", usage.UsedObjects)
	}
	s.Close()

	reopened, err := store.OpenWithOptions(dir, store.ReadWrite, quotaOptions(1024))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	if got := reopened.QuotaUsage(store.PosixPrincipal(0, 0)); got != usage {
		t.Fatalf("usage after reopen = %+v, want %+v", got, usage)
	}
}

func TestQuotaTamperedUsageAssertionFailsVerify(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, quotaOptions(1024, store.QuotaBudget{
		Principal: store.PosixPrincipal(0, 0), MaxNewBytes: 1 << 20, MaxObjects: 100,
	}))
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()
	root, _ := s.ResolvePath("/")
	if _, err := s.CreateFile(root, []byte("a.txt"), []byte("alpha"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	usage := s.QuotaUsage(store.PosixPrincipal(0, 0))
	wrong := usage
	wrong.UsedBytes++
	if _, err := s.PublishQuotaUsageForTest(model.SetQuotaUsageOp{Usage: []model.QuotaUsageEntry{{
		Kind: "posix", UID: 0, GID: 0,
		UsedBytes: wrong.UsedBytes, UsedObjects: wrong.UsedObjects,
	}}}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	report, err := s.Verify(true)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.OK {
		t.Fatal("full verify accepted an inconsistent assertion")
	}
	found := false
	for _, problem := range report.Problems {
		if containsText(problem.Detail, "quota") {
			found = true
		}
	}
	if !found {
		t.Fatalf("problems: %+v", report.Problems)
	}
	if _, err := s.QuotaRebuild(); !werr.Is(err, werr.Corrupt) {
		t.Fatalf("rebuild class = %v, want Corrupt", werr.ClassOf(err))
	}
}

func containsText(text, needle string) bool {
	return bytes.Contains([]byte(text), []byte(needle))
}

func TestQuotaGroupCommitUsageIsAtomic(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, quotaOptions(1024, store.QuotaBudget{
		Principal: store.PosixPrincipal(0, 0), MaxNewBytes: 64 * 1024, MaxObjects: 2,
	}))
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()
	root, _ := s.ResolvePath("/")
	if _, err := s.CreateFile(root, []byte("first.txt"), []byte("first"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("first: %v", err)
	}
	before := s.QuotaUsage(store.PosixPrincipal(0, 0))
	generation := s.Generation()
	head := s.Head()

	if err := s.BeginGroup(); err != nil {
		t.Fatalf("begin group: %v", err)
	}
	if _, err := s.CreateFile(root, []byte("second.txt"), []byte("second"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("second: %v", err)
	}
	if _, err := s.CreateFile(root, []byte("third.txt"), []byte("third"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("third: %v", err)
	}
	if _, err := s.CommitGroup(); !werr.Is(err, werr.BudgetExceeded) {
		t.Fatalf("commit class = %v, want BudgetExceeded", werr.ClassOf(err))
	}
	if s.Generation() != generation || s.Head() != head {
		t.Fatal("a denied group moved generation/head")
	}
	if got := s.QuotaUsage(store.PosixPrincipal(0, 0)); got != before {
		t.Fatalf("a denied group was charged: %+v -> %+v", before, got)
	}
	if report, err := s.Verify(true); err != nil || !report.OK {
		t.Fatalf("verify: %v %+v", err, report)
	}

	// A group that fits publishes one commit and one usage op.
	if err := s.BeginGroup(); err != nil {
		t.Fatalf("begin group: %v", err)
	}
	if _, err := s.CreateFile(root, []byte("second.txt"), []byte("second"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("second: %v", err)
	}
	if _, err := s.CommitGroup(); err != nil {
		t.Fatalf("commit group: %v", err)
	}
	if s.Generation() != generation+1 {
		t.Fatalf("generation = %d, want %d", s.Generation(), generation+1)
	}
	if got := s.QuotaUsage(store.PosixPrincipal(0, 0)); got.UsedObjects != 2 {
		t.Fatalf("used objects = %d, want 2", got.UsedObjects)
	}
	headGeneration := s.Generation()
	loaded, err := store.LoadCommitFile(store.CommitPath(dir, headGeneration), &headGeneration)
	if err != nil {
		t.Fatalf("load head: %v", err)
	}
	if _, ok := loaded.Commit.Ops[len(loaded.Commit.Ops)-1].(model.SetQuotaUsageOp); !ok {
		t.Fatal("group head does not end with a usage op")
	}
}

func TestQuotaLegacyRecordMigratesOnce(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, quotaOptions(1024))
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	root, _ := s.ResolvePath("/")
	if _, err := s.CreateFile(root, []byte("a.txt"), []byte("alpha"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	generation := s.Generation()
	head := s.Head()
	s.Close()

	legacy := store.QuotaRecord{
		Generation: generation - 1,
		Commit:     head,
		Budgets: []store.QuotaBudget{{
			Principal: store.PosixPrincipal(0, 0), MaxNewBytes: 1 << 20, MaxObjects: 100,
		}},
		Usage: []store.QuotaUsageEntry{{
			Principal: store.PosixPrincipal(0, 0), Counters: store.QuotaCounters{},
		}},
	}
	raw, err := legacy.EncodeBytes()
	if err != nil {
		t.Fatalf("encode legacy: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "quota"), raw, 0o644); err != nil {
		t.Fatalf("write legacy: %v", err)
	}

	reopened, err := store.OpenWithOptions(dir, store.ReadWrite, quotaOptions(1024))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !reopened.QuotaEnforced() || reopened.QuotaProblem() != "" {
		t.Fatalf("migration failed: enforced=%v problem=%s", reopened.QuotaEnforced(), reopened.QuotaProblem())
	}
	usage := reopened.QuotaUsage(store.PosixPrincipal(0, 0))
	if usage.UsedObjects != 1 {
		t.Fatalf("migrated usage = %+v, want 1 object", usage)
	}
	policyBytes, err := os.ReadFile(filepath.Join(dir, "quota"))
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	if !bytes.HasPrefix(policyBytes, []byte("WFQ2")) {
		t.Fatal("quota file was not migrated to v2")
	}
	preserved, err := os.ReadFile(filepath.Join(dir, "quota.migrated"))
	if err != nil {
		t.Fatalf("read migrated: %v", err)
	}
	if !bytes.Equal(preserved, raw) {
		t.Fatal("legacy bytes were not preserved verbatim")
	}
	if _, err := reopened.CreateFile(root, []byte("b.txt"), []byte("beta"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("write after migration: %v", err)
	}
	if got := reopened.QuotaUsage(store.PosixPrincipal(0, 0)); got.UsedObjects != 2 {
		t.Fatalf("usage after write = %+v, want 2 objects", got)
	}
	if report, err := reopened.Verify(true); err != nil || !report.OK {
		t.Fatalf("verify: %v %+v", err, report)
	}
	reopened.Close()

	again, err := store.OpenWithOptions(dir, store.ReadWrite, quotaOptions(1024))
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	defer again.Close()
	if got := again.QuotaUsage(store.PosixPrincipal(0, 0)); got.UsedObjects != 2 {
		t.Fatalf("usage after second open = %+v", got)
	}
}

func TestQuotaMigratedRecordDisagreementFailsClosed(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, quotaOptions(1024, store.QuotaBudget{
		Principal: store.PosixPrincipal(0, 0), MaxNewBytes: 1 << 20, MaxObjects: 100,
	}))
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	root, _ := s.ResolvePath("/")
	if _, err := s.CreateFile(root, []byte("a.txt"), []byte("alpha"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	generation := s.Generation()
	head := s.Head()
	usage := s.QuotaUsage(store.PosixPrincipal(0, 0))
	s.Close()

	wrong := store.QuotaRecord{
		Generation: generation,
		Commit:     head,
		Budgets: []store.QuotaBudget{{
			Principal: store.PosixPrincipal(0, 0), MaxNewBytes: 1 << 20, MaxObjects: 100,
		}},
		Usage: []store.QuotaUsageEntry{{
			Principal: store.PosixPrincipal(0, 0),
			Counters:  store.QuotaCounters{UsedBytes: usage.UsedBytes + 1, UsedObjects: usage.UsedObjects},
		}},
	}
	raw, err := wrong.EncodeBytes()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "quota.migrated"), raw, 0o644); err != nil {
		t.Fatalf("write migrated: %v", err)
	}

	reopened, err := store.OpenWithOptions(dir, store.ReadWrite, quotaOptions(1024))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer reopened.Close()
	if reopened.QuotaProblem() == "" {
		t.Fatal("disagreement was not reported")
	}
	if _, err := reopened.CreateFile(root, []byte("blocked.txt"), []byte("blocked"), 0o644, 0, 0, nil); !werr.Is(err, werr.Corrupt) {
		t.Fatalf("class = %v, want Corrupt", werr.ClassOf(err))
	}
}
