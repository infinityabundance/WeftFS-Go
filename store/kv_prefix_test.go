package store_test

// KV prefix parity court (subphase T068): the Go prefix tier, its scope
// checks, Ed25519 envelope verification, and a bidirectional handoff with the
// Rust implementation.
//
// The cross-language tests need the Rust reference binary; they skip (never
// fail) when it is absent, which is the established handoff-court pattern.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/infinityabundance/WeftCodec-Go/capability"
	"github.com/infinityabundance/WeftCodec-Go/hash"
	"github.com/infinityabundance/WeftCodec-Go/modes"
	"github.com/infinityabundance/WeftCodec-Go/wcb"

	"github.com/infinityabundance/WeftFS-Go/auth"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
)

const (
	kvNow    = int64(1_700_000_000_000_000_000)
	kvExpiry = int64(2_000_000_000_000_000_000)
)

var kvSeedBytes = [32]byte{
	7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
}

// kvTokenIDs mirrors Rust `kv_token_ids`.
func kvTokenIDs(seed, count uint64) []uint64 {
	state := seed | 1
	out := make([]uint64, 0, count)
	for index := uint64(0); index < count; index++ {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		out = append(out, state%32_000)
	}
	return out
}

// kvPageBytes mirrors Rust `kv_page_bytes`.
func kvPageBytes(seed uint64, layer uint32, index, length uint64) []byte {
	state := seed*0x9E37_79B9_7F4A_7C15 + (uint64(layer) << 17) ^ (index << 41)
	state |= 1
	out := make([]byte, 0, length+8)
	for uint64(len(out)) < length {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		for byteIndex := 0; byteIndex < 8; byteIndex++ {
			out = append(out, byte(state>>(8*byteIndex)))
		}
	}
	return out[:length]
}

func kvDigest(t *testing.T, text string) model.Hash32 {
	t.Helper()
	return hash.Domain("weft/kv/tokenizer/v1", []byte(text))
}

func kvAttention(text string) model.Hash32 {
	return hash.Domain("weft/kv/attention/v1", []byte(text))
}

func kvSpec(t *testing.T) store.KvPrefixSpec {
	t.Helper()
	return store.KvPrefixSpec{
		Tenant:        "tenant-a",
		Model:         "m",
		TokenizerHash: kvDigest(t, "tok"),
		AttentionHash: kvAttention("attn"),
		Dtype:         "bf16",
		HeadCount:     1,
		HeadDim:       4,
		LayerCount:    1,
		PageRows:      8,
	}
}

func kvPayloads(tokens, fromPage, seed uint64) [][][]byte {
	pageRows := uint64(8)
	pageCount := (tokens + pageRows - 1) / pageRows
	pages := make([][]byte, 0, pageCount)
	for index := fromPage; index < pageCount; index++ {
		start := index * pageRows
		end := tokens
		if (index+1)*pageRows < tokens {
			end = (index + 1) * pageRows
		}
		pages = append(pages, kvPageBytes(seed, 0, index, (end-start)*1*4*2))
	}
	return [][][]byte{pages}
}

func newKvStore(t *testing.T) (string, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Init(dir, store.Options{ChunkSize: 4096, CheckpointInterval: 256, Representation: store.RepresentationModeRaw})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	return dir, st
}

func kvRequest(t *testing.T, tokens []uint64) store.KvPrefixRequest {
	t.Helper()
	spec := kvSpec(t)
	return store.KvPrefixRequest{
		Tenant: spec.Tenant, Model: spec.Model,
		TokenizerHash: spec.TokenizerHash, AttentionHash: spec.AttentionHash,
		Dtype: spec.Dtype, HeadCount: spec.HeadCount, HeadDim: spec.HeadDim,
		LayerCount: spec.LayerCount, PageRows: spec.PageRows, Tokens: tokens,
	}
}

func TestKvPrefixTierRoundTripsAndRevokes(t *testing.T) {
	_, st := newKvStore(t)
	spec := kvSpec(t)
	tokens := kvTokenIDs(11, 16)
	write, err := st.KvPrefixPut("root", spec, tokens, nil, kvPayloads(16, 0, 5), 0, 0)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if write.Record.PositionEnd != 16 || write.Record.PageCount != 2 {
		t.Fatalf("record shape: %+v", write.Record)
	}
	loaded, err := st.KvPrefix("root")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.TokenChainRoot != store.KvTokenChainRoot(tokens) {
		t.Fatalf("chain root mismatch")
	}
	canonical, err := loaded.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	reparsed, err := store.ParseKvPrefixRecord(canonical)
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	id, _ := reparsed.ID()
	if id != write.PrefixID {
		t.Fatalf("record id changed across canonical round trip")
	}

	lookup, err := st.KvPrefixLookup(kvRequest(t, kvTokenIDs(11, 16)))
	if err != nil || !lookup.Reusable || lookup.Record.PositionEnd != 16 {
		t.Fatalf("lookup: %+v %v", lookup, err)
	}
	mismatch, err := st.KvPrefixLookup(kvRequest(t, kvTokenIDs(12, 16)))
	if err != nil || mismatch.Reusable {
		t.Fatalf("a different token sequence was accepted: %+v", mismatch)
	}

	if _, created, err := st.KvPrefixRevoke("root", "court", kvNow, 0, 0); err != nil || !created {
		t.Fatalf("revoke: %v %v", created, err)
	}
	epoch, err := st.KvRevocationEpoch()
	if err != nil || epoch != 1 {
		t.Fatalf("epoch: %d %v", epoch, err)
	}
	after, err := st.KvPrefixLookup(kvRequest(t, kvTokenIDs(11, 16)))
	if err != nil || after.Reusable {
		t.Fatalf("a revoked prefix was returned: %+v", after)
	}
}

func TestKvBatchIsOneCommitAndAllOrNothing(t *testing.T) {
	_, st := newKvStore(t)
	spec := kvSpec(t)
	before := st.Generation()
	items := make([]store.KvPrefixBatchItem, 0, 8)
	for index := 0; index < 8; index++ {
		items = append(items, store.KvPrefixBatchItem{
			Name:         fmt.Sprintf("b%d", index),
			Spec:         spec,
			Tokens:       kvTokenIDs(100+uint64(index), 16),
			NewPageBytes: kvPayloads(16, 0, 200+uint64(index)),
		})
	}
	writes, err := st.KvPrefixPutBatch(items, 0, 0)
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	if len(writes) != 8 || st.Generation() != before+1 {
		t.Fatalf("batch did not publish one commit: %d writes, gen %d->%d", len(writes), before, st.Generation())
	}
	before = st.Generation()
	bad := []store.KvPrefixBatchItem{
		{Name: "ok", Spec: spec, Tokens: kvTokenIDs(500, 16), NewPageBytes: kvPayloads(16, 0, 900)},
		{Name: "bad", Spec: spec, Tokens: kvTokenIDs(501, 16), NewPageBytes: [][][]byte{{{1, 2, 3}}}},
	}
	if _, err := st.KvPrefixPutBatch(bad, 0, 0); err == nil {
		t.Fatalf("a malformed batch item was accepted")
	}
	if st.Generation() != before {
		t.Fatalf("a failed batch published a commit")
	}
	if _, err := st.KvPrefix("ok"); err == nil {
		t.Fatalf("a failed batch published a prefix")
	}
}

// mintEnvelope signs a grant that names `roots` and stores the blob, returning
// its name. The signature is Ed25519 over the codec's canonical sign input.
func mintEnvelope(t *testing.T, st *store.Store, roots []model.Hash32) string {
	t.Helper()
	expires := kvExpiry
	grantor, err := capability.PublicKeyForSeed(kvSeedBytes[:])
	if err != nil {
		t.Fatal(err)
	}
	grantee := hash.FromBytes([32]byte{9})
	revocation := hash.FromBytes([32]byte{0xA1})
	nonce := hash.FromBytes([32]byte{0x31})
	sorted := append([]model.Hash32(nil), roots...)
	sortHashes(sorted)
	envelope, err := capability.New(grantor, grantee, "tenant-a", sorted,
		[]string{"kv.tenant-a"}, nil, &expires, nil, revocation, kvNow, nonce)
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}
	blob, err := capability.Sign(envelope, kvSeedBytes[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	encoded, err := blob.Encode()
	if err != nil {
		t.Fatalf("blob encode: %v", err)
	}
	name := fmt.Sprintf("grant-%d", len(encoded))
	if _, err := st.SaveCapabilityBlob(name, encoded); err != nil {
		t.Fatalf("save blob: %v", err)
	}
	return name
}

func sortHashes(values []model.Hash32) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j].Less(values[j-1]); j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

func TestKvPrefixGetVerifiesEd25519InGo(t *testing.T) {
	_, st := newKvStore(t)
	spec := kvSpec(t)
	tokens := kvTokenIDs(21, 16)
	write, err := st.KvPrefixPut("signed", spec, tokens, nil, kvPayloads(16, 0, 33), 0, 0)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	var roots []model.Hash32
	for _, layer := range write.Record.Pages {
		for _, id := range layer {
			descriptor, err := st.KvDescriptor(id)
			if err != nil {
				t.Fatalf("descriptor: %v", err)
			}
			descriptorID, err := descriptor.ID()
			if err != nil {
				t.Fatal(err)
			}
			roots = append(roots, descriptorID)
		}
	}
	envelopeName := mintEnvelope(t, st, roots)
	read, err := st.KvPrefixGetVerified("signed", envelopeName, nil, kvNow)
	if err != nil {
		t.Fatalf("verified get: %v", err)
	}
	if len(read.Pages) != 2 {
		t.Fatalf("pages: %d", len(read.Pages))
	}
	if read.Pages[0].Bytes == nil || len(read.Pages[0].Bytes) == 0 {
		t.Fatalf("empty page")
	}
	// A tampered blob is refused with the same non-disclosing denial.
	blob, err := st.ReadObject(kvMustLookup(t, st, envelopeName))
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), blob...)
	tampered[len(tampered)-1] ^= 0xFF
	if _, err := st.SaveCapabilityBlob("tampered", tampered); err != nil {
		t.Fatal(err)
	}
	if _, err := st.KvPrefixGetVerified("signed", "tampered", nil, kvNow); err == nil {
		t.Fatalf("a tampered envelope was accepted")
	}
	// A grant that names no page is refused too.
	other := mintEnvelope(t, st, []model.Hash32{kvDigest(t, "unrelated")})
	if _, err := st.KvPrefixGetVerified("signed", other, nil, kvNow); err == nil {
		t.Fatalf("a grant with unrelated roots was accepted")
	}
}

func kvMustLookup(t *testing.T, st *store.Store, name string) model.Hash32 {
	t.Helper()
	root, err := st.ResolvePath("/")
	if err != nil {
		t.Fatal(err)
	}
	kv, err := st.Lookup(root, []byte("kv"))
	if err != nil {
		t.Fatal(err)
	}
	dir, err := st.Lookup(kv, []byte(store.KvCapabilityBlobDir))
	if err != nil {
		t.Fatal(err)
	}
	id, err := st.Lookup(dir, []byte(name))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// ---- bidirectional handoff --------------------------------------------------

// TestKvPrefixCrossLanguageReadsBothWays proves that a Rust-written prefix is
// looked up and read by Go (with a Go-verified Ed25519 grant), and that a
// Go-written prefix is read by Rust (with a Go-signed grant Rust verifies).
func TestKvPrefixCrossLanguageReadsBothWays(t *testing.T) {
	bin := rustBinary(t)
	dir := t.TempDir()

	// --- Rust writes, Go reads ---------------------------------------------
	runRust(t, bin, "--store", dir, "init")
	runRust(t, bin, "--store", dir, "kv", "put",
		"--name", "rust-sys", "--tenant", "tenant-a", "--model", "m",
		"--tokens", "16", "--token-seed", "11", "--page-rows", "8",
		"--layers", "1", "--heads", "1", "--head-dim", "4",
		"--tokenizer", "tok", "--attention", "attn", "--payload-seed", "5")
	st, err := store.Open(dir, store.ReadWrite)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	record, err := st.KvPrefix("rust-sys")
	if err != nil {
		t.Fatalf("Go reads Rust record: %v", err)
	}
	if record.PositionEnd != 16 || record.TokenChainRoot != store.KvTokenChainRoot(kvTokenIDs(11, 16)) {
		t.Fatalf("Go parsed a different record: %+v", record)
	}
	lookup, err := st.KvPrefixLookup(kvRequest(t, kvTokenIDs(11, 16)))
	if err != nil || !lookup.Reusable {
		t.Fatalf("Go lookup of a Rust prefix: %+v %v", lookup, err)
	}
	var roots []model.Hash32
	for _, layer := range record.Pages {
		for _, id := range layer {
			descriptor, err := st.KvDescriptor(id)
			if err != nil {
				t.Fatalf("descriptor: %v", err)
			}
			descriptorID, _ := descriptor.ID()
			roots = append(roots, descriptorID)
		}
	}
	envelopeName := mintEnvelope(t, st, roots)
	goRead, err := st.KvPrefixGetVerified("rust-sys", envelopeName, nil, kvNow)
	if err != nil {
		t.Fatalf("Go verified read of a Rust prefix: %v", err)
	}
	if len(goRead.Pages) != 2 {
		t.Fatalf("Go read %d pages", len(goRead.Pages))
	}

	// --- Go writes, Rust reads ---------------------------------------------
	spec := kvSpec(t)
	childTokens := kvTokenIDs(11, 32)
	child, err := st.KvPrefixPut("go-child", spec, childTokens, ptr("rust-sys"),
		kvPayloads(32, 2, 77), 0, 0)
	if err != nil {
		t.Fatalf("Go put: %v", err)
	}
	var childRoots []model.Hash32
	for _, layer := range child.Record.Pages {
		for _, id := range layer {
			descriptor, err := st.KvDescriptor(id)
			if err != nil {
				t.Fatalf("child descriptor: %v", err)
			}
			descriptorID, _ := descriptor.ID()
			childRoots = append(childRoots, descriptorID)
		}
	}
	childGrant := mintEnvelope(t, st, childRoots)
	rustRead := runRust(t, bin, "--store", dir, "kv", "get", "--name", "go-child",
		"--envelope", writeBlob(t, st, childGrant), "--now-ns", "1700000000000000000", "--json")
	if !strings.Contains(rustRead, "\"page_count\": 4") {
		t.Fatalf("Rust read a different page count:\n%s", rustRead)
	}
	if !strings.Contains(rustRead, child.PrefixID.Hex()) {
		t.Fatalf("Rust computed a different prefix id than Go:\n%s", rustRead)
	}
	// Rust's listing sees both records.
	listing := runRust(t, bin, "--store", dir, "kv", "list", "--json")
	for _, name := range []string{"rust-sys", "go-child"} {
		if !strings.Contains(listing, name) {
			t.Fatalf("Rust listing is missing %s:\n%s", name, listing)
		}
	}
}

func ptr(value string) *string { return &value }

func writeBlob(t *testing.T, st *store.Store, name string) string {
	t.Helper()
	blob, err := st.ReadObject(kvMustLookup(t, st, name))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "grant.blob")
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// ---- per-page cost ----------------------------------------------------------

// TestKvGoCost records the Go per-page write/read cost and allocation counts.
// When WEFT_KV_GO_RECEIPT is set the JSON is written there for the court.
func TestKvGoCost(t *testing.T) {
	_, st := newKvStore(t)
	spec := kvSpec(t)
	spec.PageRows = 64

	// Write: 4 MiB of pages (one 512 B page per prefix), one commit.
	rows := uint64(64)
	pageBytes := rows * 1 * 4 * 2
	pages := (4 * 1024 * 1024) / pageBytes
	items := make([]store.KvPrefixBatchItem, 0, pages)
	for index := uint64(0); index < pages; index++ {
		items = append(items, store.KvPrefixBatchItem{
			Name:         fmt.Sprintf("cost-%05d", index),
			Spec:         spec,
			Tokens:       kvTokenIDs(1000+index, rows),
			NewPageBytes: [][][]byte{{kvPageBytes(2000+index, 0, 0, pageBytes)}},
		})
	}
	before := st.Generation()
	writeStart := testingNow()
	writes, err := st.KvPrefixPutBatch(items, 0, 0)
	writeElapsed := testingSince(writeStart)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(writes) != len(items) {
		t.Fatalf("write count: %d vs %d", len(writes), len(items))
	}
	commits := st.Generation() - before

	// Read: every page of one prefix, with a verified grant.
	record, err := st.KvPrefix(items[0].Name)
	if err != nil {
		t.Fatal(err)
	}
	var roots []model.Hash32
	for _, layer := range record.Pages {
		for _, id := range layer {
			descriptor, err := st.KvDescriptor(id)
			if err != nil {
				t.Fatal(err)
			}
			descriptorID, _ := descriptor.ID()
			roots = append(roots, descriptorID)
		}
	}
	envelopeName := mintEnvelope(t, st, roots)
	// Warm.
	if _, err := st.KvPrefixGetVerified(items[0].Name, envelopeName, nil, kvNow); err != nil {
		t.Fatalf("warm read: %v", err)
	}
	const reps = 200
	readStart := testingNow()
	for index := 0; index < reps; index++ {
		if _, err := st.KvPrefixGetVerified(items[0].Name, envelopeName, nil, kvNow); err != nil {
			t.Fatalf("read: %v", err)
		}
	}
	readElapsed := testingSince(readStart)
	perRead := readElapsed.Seconds() * 1000 / float64(reps)

	allocWrite := testingAllocs(func() {
		_, _ = st.KvPrefixPutBatch(items[:1], 0, 0)
	})
	allocRead := testingAllocs(func() {
		_, _ = st.KvPrefixGetVerified(items[1].Name, envelopeName, nil, kvNow)
	})

	// Batching effect on a smaller population (256 prefixes, one page each).
	compare := uint64(256)
	singleItems := make([]store.KvPrefixBatchItem, 0, compare)
	for index := uint64(0); index < compare; index++ {
		singleItems = append(singleItems, store.KvPrefixBatchItem{
			Name:         fmt.Sprintf("single-%05d", index),
			Spec:         spec,
			Tokens:       kvTokenIDs(3000+index, rows),
			NewPageBytes: [][][]byte{{kvPageBytes(4000+index, 0, 0, pageBytes)}},
		})
	}
	_, singleStore := newKvStore(t)
	singleStart := testingNow()
	for _, item := range singleItems {
		if _, err := singleStore.KvPrefixPut(item.Name, item.Spec, item.Tokens, item.ParentName, item.NewPageBytes, 0, 0); err != nil {
			t.Fatalf("single write %s: %v", item.Name, err)
		}
	}
	singleElapsed := testingSince(singleStart)
	freshBatch := []store.KvPrefixBatchItem{{
		Name:         "batch-fresh",
		Spec:         spec,
		Tokens:       kvTokenIDs(9000, rows),
		NewPageBytes: [][][]byte{{kvPageBytes(9100, 0, 0, pageBytes)}},
	}}
	batchStart := testingNow()
	if _, err := st.KvPrefixPutBatch(freshBatch, 0, 0); err != nil {
		t.Fatalf("batch write: %v", err)
	}
	batchElapsed := testingSince(batchStart)

	receipt := map[string]any{
		"single_write_per_prefix_us":   round3(singleElapsed.Seconds() * 1e6 / float64(compare)),
		"single_write_wall_ms":         round3(singleElapsed.Seconds() * 1000),
		"one_batch_write_ms":           round3(batchElapsed.Seconds() * 1000),
		"schema":                       "weft.kv.go.cost.v1",
		"label":                        "Go per-page cost: batched publication and scoped reads; one host",
		"write_bytes":                  4 * 1024 * 1024,
		"write_pages":                  pages,
		"write_commits":                commits,
		"write_wall_ms":                round3(writeElapsed.Seconds() * 1000),
		"write_per_page_us":            round3(writeElapsed.Seconds() * 1e6 / float64(pages)),
		"read_page_bytes":              pageBytes,
		"read_reps":                    reps,
		"read_per_prefix_ms":           round3(perRead),
		"alloc_bytes_per_write_prefix": round3(float64(allocWrite)),
		"alloc_bytes_per_read_prefix":  round3(float64(allocRead)),
		"generation":                   st.Generation(),
	}
	t.Logf("kv go cost: %s", jsonText(receipt))
	if path := os.Getenv("WEFT_KV_GO_RECEIPT"); path != "" {
		if err := os.WriteFile(path, []byte(jsonText(receipt)+"\n"), 0o644); err != nil {
			t.Fatalf("receipt: %v", err)
		}
	}
}

func jsonText(value any) string {
	encoded, _ := json.MarshalIndent(value, "", "  ")
	return string(encoded)
}

func testingNow() time.Time                      { return time.Now() }
func testingSince(start time.Time) time.Duration { return time.Since(start) }

// testingAllocs returns allocated bytes per invocation (process-wide, so it is
// a coarse bound; it is reported as such).
func testingAllocs(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func round3(value float64) float64 {
	return float64(int64(value*1000+0.5)) / 1000
}

var _ = auth.Root
var _ = modes.KvCacheInput{}
var _ = wcb.TextValue
