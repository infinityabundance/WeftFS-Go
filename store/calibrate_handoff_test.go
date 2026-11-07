package store_test

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/infinityabundance/WeftFS-Go/store"
)

// The acceptance test for the Go calibrate command: the document Go measures
// must load in the Rust reference loader (`weftfs calibrate --from`). The Rust
// CLI reports the calibration id it computed from the document digest, so an
// equal id proves Go's compact key-sorted JSON is byte-identical to
// serde_json's for this record.
func TestRustAcceptsGoCalibrationDocument(t *testing.T) {
	bin := rustBinary(t)
	options := store.MeasurementOptions{Reps: 5, LargeMiB: 8, SmallKiB: 64}
	outcome, err := store.MeasureDecodeCosts(options)
	if err != nil {
		t.Fatalf("go measure: %v", err)
	}
	if len(outcome.Errors) != 0 {
		t.Fatalf("go measurement errors: %v", outcome.Errors)
	}
	record, err := store.CalibrationFromMeasurement(
		outcome, options, store.CurrentHostIdentity(), 1_700_000_000_000_000_000)
	if err != nil {
		t.Fatalf("go assemble: %v", err)
	}
	path := filepath.Join(t.TempDir(), "go-calibration.json")
	if err := record.WriteFile(path); err != nil {
		t.Fatalf("go write: %v", err)
	}

	output := runRust(t, bin, "--json", "calibrate", "--from", path)
	var parsed struct {
		Schema        string `json:"schema"`
		CalibrationID string `json:"calibration_id"`
		Rows          []struct {
			Class  string `json:"class"`
			Origin string `json:"origin"`
		} `json:"rows"`
		Divergence []struct {
			Class string `json:"class"`
		} `json:"divergence"`
	}
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("rust calibrate --from printed non-JSON: %v\n%s", err, output)
	}
	if parsed.Schema != store.CalibrationSchema {
		t.Fatalf("rust schema = %q", parsed.Schema)
	}
	if parsed.CalibrationID != record.ID {
		t.Fatalf("rust calibration id %s != go id %s", parsed.CalibrationID, record.ID)
	}
	if len(parsed.Rows) != len(store.CostClassAll) {
		t.Fatalf("rust reported %d rows", len(parsed.Rows))
	}
	if len(parsed.Divergence) != len(store.CostClassAll) {
		t.Fatalf("rust reported %d divergence rows", len(parsed.Divergence))
	}
	measured := 0
	for _, row := range parsed.Rows {
		if row.Origin == string(store.OriginMeasured) {
			measured++
		}
	}
	if measured != 7 {
		t.Fatalf("rust saw %d measured rows, want 7", measured)
	}
	t.Logf("rust accepted the Go calibration id=%s measured_rows=%d", parsed.CalibrationID, measured)
}
