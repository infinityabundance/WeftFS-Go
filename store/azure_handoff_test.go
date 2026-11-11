package store_test

// Cross-language Azure handoff (subphase R14): the Go store and the Rust
// oracle build the same store on one real Azurite container and read each
// other's records. The logical key layout, the commit protocol, and the fenced
// LOCK record are all wire-visible, so this is the parity claim that matters:
// not "both compile", but "each implementation accepts what the other wrote".
//
// The test skips unless WEFT_AZURE_TEST_ENDPOINT is set by the Azure court, and
// it skips (never fails) when the Rust oracle cannot run in this court.

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
)

var azureHandoffCounter atomic.Uint64

func azureHandoffContainer(t *testing.T) string {
	t.Helper()
	prefix := os.Getenv("WEFT_AZURE_TEST_CONTAINER")
	if prefix == "" {
		prefix = "weft-az"
	}
	cleaned := strings.Builder{}
	for i := 0; i < len(prefix); i++ {
		c := prefix[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			cleaned.WriteByte(c)
		} else {
			cleaned.WriteByte('-')
		}
	}
	name := cleaned.String()
	if len(name) > 40 {
		name = name[:40]
	}
	name = strings.Trim(name, "-")
	return fmt.Sprintf("%s-xl-%d-%d", name, os.Getpid(), azureHandoffCounter.Add(1))
}

func azureHandoffOptions(t *testing.T, container string) store.Options {
	t.Helper()
	account := os.Getenv("WEFT_AZURE_ACCOUNT")
	if account == "" {
		account = "devstoreaccount1"
	}
	key := os.Getenv("WEFT_AZURE_KEY")
	if key == "" {
		t.Fatal("WEFT_AZURE_KEY is not set; the Azure court supplies the development key")
	}
	config, err := store.ResolveAzure(os.Getenv("WEFT_AZURE_TEST_ENDPOINT"), container, account, key, "", nil, 120)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	options := store.DefaultOptions()
	options.BlobBackend = store.PlaneAzure
	options.CommitBackend = store.PlaneAzure
	options.Azure = &config
	options.GCGraceSecs = 0
	return options
}

// azureRustArgs is the shared flag set that points the Rust oracle at the same
// container.
func azureRustArgs(container string) []string {
	account := os.Getenv("WEFT_AZURE_ACCOUNT")
	if account == "" {
		account = "devstoreaccount1"
	}
	return []string{
		"--backend", "azure",
		"--azure-endpoint", os.Getenv("WEFT_AZURE_TEST_ENDPOINT"),
		"--azure-container", container,
		"--azure-account", account,
		"--azure-key", os.Getenv("WEFT_AZURE_KEY"),
	}
}

// TestAzureCrossLanguageHandoff runs Go-write -> Rust verify/read -> Rust write
// -> Go read, all on one container.
func TestAzureCrossLanguageHandoff(t *testing.T) {
	if os.Getenv("WEFT_AZURE_TEST_ENDPOINT") == "" {
		t.Skip("WEFT_AZURE_TEST_ENDPOINT is not set; the Azure court is not running")
	}
	bin := rustBinary(t)
	container := azureHandoffContainer(t)
	options := azureHandoffOptions(t, container)
	rust := azureRustArgs(container)

	goContent := strings.Repeat("go-to-rust-", 2048)
	writer, err := store.Init("", options)
	if err != nil {
		t.Fatalf("go init: %v", err)
	}
	if _, err := writer.CreateFile(model.RootID, []byte("go-alpha.txt"), []byte(goContent), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("go create: %v", err)
	}
	if report, err := writer.Verify(true); err != nil || !report.OK {
		t.Fatalf("go verify: %v %+v", err, report)
	}
	generation := writer.Generation()
	if err := writer.Close(); err != nil {
		t.Fatalf("go close: %v", err)
	}

	// Rust reads the Go-written store and verifies every blob.
	args := append(append([]string{}, rust...), "--json", "info")
	info := runRust(t, bin, args...)
	if !strings.Contains(info, "\"backend\": \"azure\"") {
		t.Fatalf("rust info did not report the azure backend:\n%s", info)
	}
	if !strings.Contains(info, fmt.Sprintf("\"generation\": %d", generation)) {
		t.Fatalf("rust info reported a different generation than the Go writer (want %d):\n%s", generation, info)
	}
	args = append(append([]string{}, rust...), "verify", "--full")
	runRust(t, bin, args...)
	args = append(append([]string{}, rust...), "cat", "/go-alpha.txt")
	if got := runRust(t, bin, args...); strings.TrimSpace(got) != goContent {
		t.Fatalf("rust read a different byte sequence for /go-alpha.txt")
	}

	// Rust writes into the same store; Go must see exactly those bytes.
	rustContent := strings.Repeat("rust-to-go-", 1024)
	args = append(append([]string{}, rust...), "create", "/rust-beta.txt", "--text", rustContent)
	runRust(t, bin, args...)
	args = append(append([]string{}, rust...), "checkpoint")
	runRust(t, bin, args...)

	reader, err := store.OpenWithOptions("", store.ReadOnly, options)
	if err != nil {
		t.Fatalf("go reopen: %v", err)
	}
	if reader.Generation() <= generation {
		t.Fatalf("go did not observe the Rust write: generation %d, was %d", reader.Generation(), generation)
	}
	id, err := reader.ResolvePath("/rust-beta.txt")
	if err != nil {
		t.Fatalf("go resolve rust file: %v", err)
	}
	got, err := reader.ReadObject(id)
	if err != nil {
		t.Fatalf("go read rust file: %v", err)
	}
	if !bytes.Equal(got, []byte(rustContent)) {
		t.Fatalf("go read %d bytes from /rust-beta.txt, want %d", len(got), len(rustContent))
	}
	if report, err := reader.Verify(true); err != nil || !report.OK {
		t.Fatalf("go verify after the Rust write: %v %+v", err, report)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("go close reader: %v", err)
	}

	// A Go writable reopen after the Rust close must reclaim the released lock
	// and publish a new generation without changing either file.
	writer, err = store.OpenWithOptions("", store.ReadWrite, options)
	if err != nil {
		t.Fatalf("go writable reopen after Rust: %v (the Rust tombstone may not have been reclaimed)", err)
	}
	if _, err := writer.CreateFile(model.RootID, []byte("go-gamma.txt"), []byte("gamma"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("go create after Rust: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("go close after Rust: %v", err)
	}

	args = append(append([]string{}, rust...), "verify", "--full")
	runRust(t, bin, args...)
}
