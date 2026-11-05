package store_test

// Cross-language quota-usage court (Q3): Rust-written usage ops are read and
// enforced by Go, and Go-written usage ops are read and enforced by Rust.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/infinityabundance/WeftFS-Go/store"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

type rustQuotaShow struct {
	Principal   string  `json:"principal"`
	Configured  bool    `json:"configured"`
	UsedBytes   *uint64 `json:"used_bytes"`
	UsedObjects *uint64 `json:"used_objects"`
}

func readRustQuota(t *testing.T, bin, dir string) rustQuotaShow {
	t.Helper()
	output := runRust(t, bin, "--store", dir, "--json", "quota", "show", "--uid", "0", "--gid", "0")
	var parsed rustQuotaShow
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("parse rust quota show %q: %v", output, err)
	}
	return parsed
}

func TestQuotaUsageOpCrossLanguageEquality(t *testing.T) {
	bin := rustBinary(t)
	rustUsable(t, bin)
	dir := t.TempDir()

	runRust(t, bin, "--store", dir, "--quota", "0:0:1048576:100", "init")
	runRust(t, bin, "--store", dir, "create", "/a.txt", "--text", "alpha")
	rustUsage := readRustQuota(t, bin, dir)
	if rustUsage.UsedBytes == nil || rustUsage.UsedObjects == nil {
		t.Fatalf("rust quota show missing counters: %+v", rustUsage)
	}

	s, err := store.OpenWithOptions(dir, store.ReadWrite, quotaOptions(1024))
	if err != nil {
		t.Fatalf("go open: %v", err)
	}
	goUsage := s.QuotaUsage(store.PosixPrincipal(0, 0))
	if goUsage.UsedBytes != *rustUsage.UsedBytes || goUsage.UsedObjects != *rustUsage.UsedObjects {
		t.Fatalf("go %+v != rust %+v", goUsage, rustUsage)
	}

	// Go appends to a Rust-written store. Rust must read the same committed
	// usage from the Go-written commit and still verify the whole chain.
	root, _ := s.ResolvePath("/")
	if _, err := s.CreateFile(root, []byte("b.txt"), []byte("beta"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("go create: %v", err)
	}
	goAfter := s.QuotaUsage(store.PosixPrincipal(0, 0))
	if report, err := s.Verify(true); err != nil || !report.OK {
		t.Fatalf("go verify: %v %+v", err, report)
	}
	s.Close()

	rustAfter := readRustQuota(t, bin, dir)
	if rustAfter.UsedBytes == nil || *rustAfter.UsedBytes != goAfter.UsedBytes ||
		*rustAfter.UsedObjects != goAfter.UsedObjects {
		t.Fatalf("rust %+v != go %+v", rustAfter, goAfter)
	}
	verify := runRust(t, bin, "--store", dir, "verify", "--full")
	if !strings.Contains(verify, "ok=true") {
		t.Fatalf("rust verify: %s", verify)
	}

	// Rust enforces the Go-written committed usage: an oversized write fails.
	big := filepath.Join(dir, "..", "big-"+filepath.Base(dir)+".bin")
	if err := os.WriteFile(big, variedBytes(2*1024*1024), 0o644); err != nil {
		t.Fatalf("write big: %v", err)
	}
	output, err := runRustAllowFailure(t, bin, "--store", dir, "create", "/big.bin", "--file", big)
	if err == nil || !strings.Contains(output, "write budget exceeded") {
		t.Fatalf("rust did not enforce the Go-written usage: err=%v output=%s", err, output)
	}

	// Go enforces a Rust-written budget and the Rust-written usage.
	rustDir := t.TempDir()
	runRust(t, bin, "--store", rustDir, "--quota", "0:0:1048576:2", "init")
	runRust(t, bin, "--store", rustDir, "create", "/one.txt", "--text", "one")
	runRust(t, bin, "--store", rustDir, "create", "/two.txt", "--text", "two")
	goStore, err := store.OpenWithOptions(rustDir, store.ReadWrite, quotaOptions(1024))
	if err != nil {
		t.Fatalf("go open rust store: %v", err)
	}
	defer goStore.Close()
	goRoot, _ := goStore.ResolvePath("/")
	if _, err := goStore.CreateFile(goRoot, []byte("three.txt"), []byte("three"), 0o644, 0, 0, nil); !werr.Is(err, werr.BudgetExceeded) {
		t.Fatalf("go class = %v, want BudgetExceeded", werr.ClassOf(err))
	}
}
