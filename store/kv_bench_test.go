// Microbenchmarks for the Go KV store path. These measure the Go
// implementation on the court's CPU only; they are not a Rust-vs-Go claim
// because the Rust numbers in bench/RESULTS-kv-provenance.md come from a
// different harness and different page fixtures. Fixtures are shared with
// kv_test.go so the geometry is the one the parity court uses.
package store_test

import (
	"fmt"
	"testing"

	weftcontext "github.com/infinityabundance/WeftCodec-Go/context"
	"github.com/infinityabundance/WeftCodec-Go/modes"
	"github.com/infinityabundance/WeftFS-Go/auth"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
)

// kvBenchElements builds a deterministic word stream of exactly n bytes.
func kvBenchElements(n int) []byte {
	out := make([]byte, 0, n)
	state := uint64(0x9E3779B97F4A7C15)
	for len(out) < n {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		out = append(out, byte(state), byte(state>>8))
	}
	return out[:n]
}

func kvBenchProvenance() modes.KvProvenanceInput {
	return kvTestProvenance(0x21)
}

// kvBenchReader builds the capability the read path requires without a
// testing.T, so it can be shared by benchmarks.
func kvBenchReader(b *testing.B, roots ...model.Hash32) store.KvPrincipal {
	b.Helper()
	expires := kvExpiresNS
	scope, err := weftcontext.NewCapabilityScope(kvTenant, []string{"kv." + kvTenant}, roots, nil, nil, &expires)
	if err != nil {
		b.Fatalf("capability scope: %v", err)
	}
	capability, err := auth.NewCapability(scope)
	if err != nil {
		b.Fatalf("capability: %v", err)
	}
	return store.NewKvPrincipal(auth.New(1000, 1000, nil), capability)
}

func BenchmarkWriteKvProvPage4KiB(b *testing.B) {
	s, err := store.Init(b.TempDir(), kvTestOptions())
	if err != nil {
		b.Fatalf("init: %v", err)
	}
	defer s.Close()
	root, err := s.ResolvePath("/")
	if err != nil {
		b.Fatalf("root: %v", err)
	}
	elements := kvBenchElements(4096)
	input := kvTestInput()
	provenance := kvBenchProvenance()
	b.SetBytes(int64(len(elements)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		name := fmt.Sprintf("page-%08d.kv", i)
		if _, err := s.WriteKvProvPage(root, []byte(name), kvTenant, input, elements, provenance, 1000, 1000); err != nil {
			b.Fatalf("write: %v", err)
		}
	}
}

func BenchmarkReadKvProvPage4KiB(b *testing.B) {
	s, err := store.Init(b.TempDir(), kvTestOptions())
	if err != nil {
		b.Fatalf("init: %v", err)
	}
	defer s.Close()
	root, err := s.ResolvePath("/")
	if err != nil {
		b.Fatalf("root: %v", err)
	}
	elements := kvBenchElements(4096)
	written, err := s.WriteKvProvPage(root, []byte("page.kv"), kvTenant, kvTestInput(), elements, kvBenchProvenance(), 1000, 1000)
	if err != nil {
		b.Fatalf("write: %v", err)
	}
	id, err := s.ResolvePath("/page.kv")
	if err != nil {
		b.Fatalf("resolve: %v", err)
	}
	reader := kvBenchReader(b, written.DescriptorID)
	b.SetBytes(int64(len(elements)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		page, err := s.ReadKvProvPage(id, reader, kvNowNS)
		if err != nil {
			b.Fatalf("read: %v", err)
		}
		if len(page.Bytes) != len(elements) {
			b.Fatalf("read %d bytes, want %d", len(page.Bytes), len(elements))
		}
	}
}

func BenchmarkReadKvProvPage64KiB(b *testing.B) {
	s, err := store.Init(b.TempDir(), kvTestOptions())
	if err != nil {
		b.Fatalf("init: %v", err)
	}
	defer s.Close()
	root, err := s.ResolvePath("/")
	if err != nil {
		b.Fatalf("root: %v", err)
	}
	input := kvTestInput()
	input.SeqEnd = 128 // 128 rows * 4 heads * 64 dims * 2 bytes = 65,536
	provenance := kvBenchProvenance()
	provenance.Layout.PageRows = 128
	elements := kvBenchElements(65536)
	written, err := s.WriteKvProvPage(root, []byte("page.kv"), kvTenant, input, elements, provenance, 1000, 1000)
	if err != nil {
		b.Fatalf("write: %v", err)
	}
	id, err := s.ResolvePath("/page.kv")
	if err != nil {
		b.Fatalf("resolve: %v", err)
	}
	reader := kvBenchReader(b, written.DescriptorID)
	b.SetBytes(int64(len(elements)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		page, err := s.ReadKvProvPage(id, reader, kvNowNS)
		if err != nil {
			b.Fatalf("read: %v", err)
		}
		if len(page.Bytes) != len(elements) {
			b.Fatalf("read %d bytes, want %d", len(page.Bytes), len(elements))
		}
	}
}
