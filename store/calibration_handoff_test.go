package store_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/infinityabundance/WeftFS-Go/store"
)

// A calibration document produced by the Rust `calibrate` command must load in
// Go with the same digest and the same ten rows. Loading re-computes the digest
// over the compact key-sorted document, so success is evidence that Go's JSON
// canonicalisation matches serde_json's.
func TestRustCalibrationDocumentIsAccepted(t *testing.T) {
	bin := rustBinary(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "calibration.json")
	runRust(t, bin,
		"--store", filepath.Join(dir, "calibrate-store"),
		"calibrate",
		"--out", path,
		"--reps", "5",
		"--small-kib", "64",
		"--large-mib", "8",
		"--json",
	)
	info, err := os.Stat(path)
	if err != nil || info.Size() == 0 {
		t.Fatalf("rust produced no calibration document: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read calibration: %v", err)
	}
	var document map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		t.Fatalf("parse rust calibration: %v", err)
	}
	digest, _ := document["digest"].(string)
	if len(digest) != 64 {
		t.Fatalf("rust calibration has no digest: %v", document["digest"])
	}
	rows, _ := document["rows"].([]any)
	if len(rows) != 10 {
		t.Fatalf("rust calibration has %d rows", len(rows))
	}

	calibration, err := store.LoadCalibration(path)
	if err != nil {
		t.Fatalf("Go rejected a Rust-written calibration: %v", err)
	}
	if calibration.ID != digest {
		t.Fatalf("Go digest %s != rust digest %s", calibration.ID, digest)
	}
	if calibration.Method.Reps != 5 {
		t.Fatalf("method.reps = %d", calibration.Method.Reps)
	}
	measured := 0
	for index := 0; index < 10; index++ {
		row := calibration.Row(store.CostClassAll[index])
		if row.Class != store.CostClassAll[index] {
			t.Fatalf("row %d class = %s", index, row.Class)
		}
		if row.Origin == store.OriginMeasured {
			measured++
			if row.Samples < store.MinCalibrationSamples {
				t.Fatalf("measured row has %d samples", row.Samples)
			}
		}
		if got, want := calibration.EstimateNS(row.Class, 1<<20), calibration.Table().EstimateNS(row.Class, 1<<20); got != want {
			t.Fatalf("estimate mismatch for %s", row.Class)
		}
		if calibration.EstimateNS(row.Class, 64<<20) <= calibration.EstimateNS(row.Class, 1<<20) {
			t.Fatalf("%s is not monotonic", row.Class)
		}
	}
	if measured < 6 {
		t.Fatalf("only %d rows were measured; the calibration does not look real", measured)
	}
	t.Logf("calibration id=%s measured_rows=%d chained_row_ns=%s",
		calibration.ID, measured,
		strconv.FormatUint(calibration.EstimateNS(store.CostClassTensorSharded, 8<<20), 10))
}
