package store_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/infinityabundance/WeftCodec-Go/hash"
	"github.com/infinityabundance/WeftCodec-Go/tensor"
	"github.com/infinityabundance/WeftFS-Go/store"
)

type engramHandoffExpected struct {
	ObjectID       string `json:"object_id"`
	OldVersion     string `json:"old_version"`
	NewVersion     string `json:"new_version"`
	Snapshot       string `json:"snapshot"`
	LogicalRoot    string `json:"logical_root"`
	TableSHA256    string `json:"table_sha256"`
	OriginalSHA256 string `json:"original_sha256"`
	TableHex       string `json:"table_hex"`
	Region         struct {
		Start         []uint64 `json:"start"`
		End           []uint64 `json:"end"`
		SHA256        string   `json:"sha256"`
		GroupsTouched uint64   `json:"groups_touched"`
	} `json:"region"`
}

// TestEngramHandoffReadVerifyRegion reads the committed Rust-written engram
// store fixture. It proves the independent Go store decodes the full table,
// verifies the logical root and whole-content hash, and decodes only the
// groups intersecting a row region.
func TestEngramHandoffReadVerifyRegion(t *testing.T) {
	dir := filepath.Join("..", "..", "conformance", "engram-store", "v1")
	raw, err := os.ReadFile(filepath.Join(dir, "EXPECTED.json"))
	if err != nil {
		t.Fatalf("read EXPECTED.json: %v", err)
	}
	var expected engramHandoffExpected
	if err := json.Unmarshal(raw, &expected); err != nil {
		t.Fatalf("decode EXPECTED.json: %v", err)
	}
	id, err := hash.FromHex(expected.ObjectID)
	if err != nil {
		t.Fatalf("object id: %v", err)
	}
	s, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer s.Close()

	meta, err := s.TensorMetadata(id)
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	if meta.Strategy != "engram-shard" {
		t.Fatalf("strategy = %s, want engram-shard", meta.Strategy)
	}
	if meta.LogicalRoot.Hex() != expected.LogicalRoot {
		t.Fatalf("logical root = %s, want %s", meta.LogicalRoot, expected.LogicalRoot)
	}

	got, err := s.ReadTensor(id)
	if err != nil {
		t.Fatalf("read tensor: %v", err)
	}
	if sum := sha256.Sum256(got); hex.EncodeToString(sum[:]) != expected.TableSHA256 {
		t.Fatalf("table sha256 mismatch")
	}
	if hex.EncodeToString(got) != expected.TableHex {
		t.Fatalf("table bytes mismatch")
	}
	root, err := s.TensorLogicalRoot(id)
	if err != nil {
		t.Fatalf("logical root verify: %v", err)
	}
	if root.Hex() != expected.LogicalRoot {
		t.Fatalf("recomputed logical root = %s", root)
	}

	// A row region strictly inside group 1 decodes only that group.
	region := tensor.NewRegion(expected.Region.Start, expected.Region.End)
	read, err := s.ReadTensorRegion(id, region)
	if err != nil {
		t.Fatalf("region read: %v", err)
	}
	if read.UnitsTouched != expected.Region.GroupsTouched {
		t.Fatalf("groups touched = %d, want %d", read.UnitsTouched, expected.Region.GroupsTouched)
	}
	if sum := sha256.Sum256(read.Bytes); hex.EncodeToString(sum[:]) != expected.Region.SHA256 {
		t.Fatalf("region sha256 mismatch")
	}

	// The incremental version references the original artifact; that original
	// must still be readable from the snapshot.
	snapshot, err := hash.FromHex(expected.Snapshot)
	if err != nil {
		t.Fatalf("snapshot id: %v", err)
	}
	original, err := s.ReadObjectAt(&snapshot, id)
	if err != nil {
		t.Fatalf("snapshot read: %v", err)
	}
	if sum := sha256.Sum256(original); hex.EncodeToString(sum[:]) != expected.OriginalSHA256 {
		t.Fatalf("original table sha256 mismatch")
	}
}
