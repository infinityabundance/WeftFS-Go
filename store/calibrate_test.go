package store

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
)

// calibrateTestOptions uses the minimum accepted sizes and sample count so the
// suite spends seconds, not minutes, on measurement.
func calibrateTestOptions() MeasurementOptions {
	return MeasurementOptions{Reps: 5, LargeMiB: 8, SmallKiB: 64}
}

func measureCalibrationForTest(t *testing.T) *Calibration {
	t.Helper()
	options := calibrateTestOptions()
	outcome, err := MeasureDecodeCosts(options)
	if err != nil {
		t.Fatalf("measure: %v", err)
	}
	if len(outcome.Errors) != 0 {
		t.Fatalf("measurement errors: %v", outcome.Errors)
	}
	record, err := CalibrationFromMeasurement(
		outcome, options, CurrentHostIdentity(), 1_700_000_000_000_000_000)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	return record
}

func TestCalibrationMeasurementDocumentRoundTrips(t *testing.T) {
	record := measureCalibrationForTest(t)
	path := filepath.Join(t.TempDir(), "calibration.json")
	if err := record.WriteFile(path); err != nil {
		t.Fatalf("write: %v", err)
	}
	if info, err := os.Stat(path); err != nil || info.Size() == 0 {
		t.Fatalf("written calibration: %v", err)
	}
	loaded, err := LoadCalibration(path)
	if err != nil {
		t.Fatalf("strict loader rejected the measured document: %v", err)
	}
	if loaded.ID != record.ID {
		t.Fatalf("loaded id %s != produced id %s", loaded.ID, record.ID)
	}
	if loaded.Method.Reps != 5 || loaded.Method.WarmupReads != 1 ||
		loaded.Method.SmallBytes != 64*1024 || loaded.Method.LargeBytes != 8*mib {
		t.Fatalf("method = %+v", loaded.Method)
	}
	measured := 0
	for _, class := range CostClassAll {
		row := loaded.Row(class)
		if row.Class != class {
			t.Fatalf("row %s decoded as %s", class, row.Class)
		}
		estimateSmall := loaded.EstimateNS(class, mib)
		estimateLarge := loaded.EstimateNS(class, 64*mib)
		if estimateLarge <= estimateSmall {
			t.Fatalf("%s is not monotonic: %d then %d", class, estimateSmall, estimateLarge)
		}
		switch row.Origin {
		case OriginMeasured:
			measured++
			if row.Samples != uint64(calibrateTestOptions().Reps*2) {
				t.Fatalf("%s measured with %d samples, want %d",
					class, row.Samples, calibrateTestOptions().Reps*2)
			}
		case OriginReused, OriginDeclared:
			if row.Samples != 0 {
				t.Fatalf("%s is %s with %d samples", class, row.Origin, row.Samples)
			}
		}
	}
	if measured != 7 {
		t.Fatalf("measured rows = %d, want 7 (raw, zstd, float-tensor, tensor-sharded, tensor-tiled, weight-delta, semantic-delta)", measured)
	}
	if got, want := loaded.Row(CostClassSparseDelta), loaded.Row(CostClassWeightDelta); got.NSperMiB != want.NSperMiB || got.FixedNS != want.FixedNS {
		t.Fatalf("sparse-delta does not reuse weight-delta: %+v vs %+v", got, want)
	}
	if loaded.Row(CostClassSparseDelta).Origin != OriginReused {
		t.Fatalf("sparse-delta origin = %s, want reused", loaded.Row(CostClassSparseDelta).Origin)
	}
	for _, class := range []CostClass{CostClassKvCache, CostClassActivation} {
		row := loaded.Row(class)
		declared := DeclaredCoefficients[class]
		if row.Origin != OriginDeclared || row.FixedNS != declared.FixedNS || row.NSperMiB != declared.NSperMiB {
			t.Fatalf("%s row = %+v, want the declared row %+v", class, row, declared)
		}
	}
	// The in-memory document must re-validate (digest included).
	if _, err := CalibrationFromDocument(loaded.Document()); err != nil {
		t.Fatalf("document does not re-validate: %v", err)
	}
	t.Logf("calibration id=%s measured=%d tensor-tiled_ns_per_mib=%d",
		loaded.ID, measured, loaded.Row(CostClassTensorTiled).NSperMiB)
}

// The two measurements are independent; only the per-MiB slope is stable
// enough to compare. Observed worst case on the 4-CPU court is ~11 % on the
// slope and ~58 µs on the intercept, so the stated tolerance is 25 % relative
// for ns_per_mib and max(100 % of the larger value, 150 µs) for fixed_ns.
// Declared and reused rows must be identical byte for byte.
func TestCalibrationMeasurementIsDeterministicWithinTolerance(t *testing.T) {
	first := measureCalibrationForTest(t)
	second := measureCalibrationForTest(t)
	for _, class := range CostClassAll {
		left := first.Row(class)
		right := second.Row(class)
		if left.Class != right.Class || left.Origin != right.Origin || left.Samples != right.Samples {
			t.Fatalf("%s metadata changed: %+v vs %+v", class, left, right)
		}
		if left.Origin == OriginDeclared {
			if left != right {
				t.Fatalf("%s declared row changed: %+v vs %+v", class, left, right)
			}
			continue
		}
		// Reused rows are copies of a measured row (sparse-delta follows
		// weight-delta), so they move with it and get the same tolerance.
		if !withinTolerance(right.NSperMiB, left.NSperMiB, 0.25, 0) {
			t.Fatalf("%s ns_per_mib drifted: %d vs %d", class, left.NSperMiB, right.NSperMiB)
		}
		if !withinTolerance(right.FixedNS, left.FixedNS, 1.0, 150_000) {
			t.Fatalf("%s fixed_ns drifted: %d vs %d", class, left.FixedNS, right.FixedNS)
		}
	}
	if first.ID == second.ID {
		t.Logf("two measurements hashed identically (%s); rows were equal within machine resolution", first.ID)
	}
}

func withinTolerance(value, reference uint64, relative float64, floor uint64) bool {
	larger := value
	if reference > larger {
		larger = reference
	}
	allowed := uint64(math.Ceil(float64(larger) * relative))
	if allowed < floor {
		allowed = floor
	}
	difference := int64(value) - int64(reference)
	if difference < 0 {
		difference = -difference
	}
	return uint64(difference) <= allowed
}

func cloneCalibrationTestDocument(t *testing.T, document map[string]any) map[string]any {
	t.Helper()
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal document: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var clone map[string]any
	if err := decoder.Decode(&clone); err != nil {
		t.Fatalf("decode clone: %v", err)
	}
	return clone
}

func signCalibrationTestDocument(t *testing.T, document map[string]any) {
	t.Helper()
	digest, err := calibrationDigest(documentWithoutDigest(document))
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	document["digest"] = digest.Hex()
}

func TestCalibrationMeasurementDocumentRejectsCorruption(t *testing.T) {
	record := measureCalibrationForTest(t)
	// A valid copy must pass, so each rejection below is attributable.
	if _, err := CalibrationFromDocument(cloneCalibrationTestDocument(t, record.Document())); err != nil {
		t.Fatalf("valid document rejected: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(document map[string]any)
	}{
		{"tampered coefficient without re-signing", func(d map[string]any) {
			rows := d["rows"].([]any)
			row := rows[0].(map[string]any)
			row["ns_per_mib"] = json.Number("123")
		}},
		{"re-signed measured row with too few samples", func(d map[string]any) {
			rows := d["rows"].([]any)
			row := rows[0].(map[string]any)
			row["samples"] = json.Number("4")
			signCalibrationTestDocument(t, d)
		}},
		{"re-signed declared row with samples", func(d map[string]any) {
			rows := d["rows"].([]any)
			row := rows[len(rows)-1].(map[string]any)
			row["samples"] = json.Number("5")
			signCalibrationTestDocument(t, d)
		}},
		{"zero digest", func(d map[string]any) {
			d["digest"] = "0000000000000000000000000000000000000000000000000000000000000000"
		}},
		{"missing row", func(d map[string]any) {
			rows := d["rows"].([]any)
			d["rows"] = rows[:len(rows)-1]
			signCalibrationTestDocument(t, d)
		}},
		{"unknown origin", func(d map[string]any) {
			rows := d["rows"].([]any)
			rows[1].(map[string]any)["origin"] = "guessed"
			signCalibrationTestDocument(t, d)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			document := cloneCalibrationTestDocument(t, record.Document())
			tc.mutate(document)
			if _, err := CalibrationFromDocument(document); err == nil {
				t.Fatalf("corrupted calibration was accepted")
			}
		})
	}
}

func TestMeasurementOptionsRejectUnusableSizes(t *testing.T) {
	cases := []MeasurementOptions{
		{Reps: 4, LargeMiB: 8, SmallKiB: 64},
		{Reps: 5, LargeMiB: 7, SmallKiB: 64},
		{Reps: 5, LargeMiB: 8, SmallKiB: 32},
		{Reps: 5, LargeMiB: 8, SmallKiB: 8192},
	}
	for _, options := range cases {
		if err := options.Validate(); err == nil {
			t.Fatalf("invalid measurement options accepted: %+v", options)
		}
	}
	if err := calibrateTestOptions().Validate(); err != nil {
		t.Fatalf("minimum valid options rejected: %v", err)
	}
	// A size that cannot form the measuring shape is refused, not truncated.
	if _, err := MeasureDecodeCosts(MeasurementOptions{Reps: 5, LargeMiB: 8, SmallKiB: 65}); err == nil {
		t.Fatal("odd payload size accepted")
	}
}
