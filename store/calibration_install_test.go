package store

// Calibration installation (Rust `weftfs calibrate --install` parity) and the
// proof that an installed document changes the planner's choice.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCalibrationInstallRoundTripsAndIsIdempotent(t *testing.T) {
	document := signCalibrationDocument(t, calibrationTestDocument())
	record, err := CalibrationFromDocument(document)
	if err != nil {
		t.Fatalf("load document: %v", err)
	}
	storeDir := t.TempDir()
	path, err := record.Install(storeDir)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	want := filepath.Join(storeDir, "calibrations", record.ID+".json")
	if path != want {
		t.Fatalf("install path = %q, want %q", path, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("installed document: %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("installed mode = %o, want 644", info.Mode().Perm())
	}
	loaded, err := LoadCalibration(path)
	if err != nil {
		t.Fatalf("the installed document does not load: %v", err)
	}
	if loaded.ID != record.ID {
		t.Fatalf("installed id %s != %s", loaded.ID, record.ID)
	}
	for _, class := range CostClassAll {
		if loaded.Row(class) != record.Row(class) {
			t.Fatalf("row %s differs after install: %+v vs %+v", class, loaded.Row(class), record.Row(class))
		}
	}
	// Re-installing the same document must be a no-op that succeeds.
	again, err := record.Install(storeDir)
	if err != nil || again != path {
		t.Fatalf("re-install = %q err=%v, want %q", again, err, path)
	}
	entries, err := os.ReadDir(filepath.Join(storeDir, "calibrations"))
	if err != nil {
		t.Fatalf("read calibration directory: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != record.ID+".json" {
		t.Fatalf("calibration directory = %v, want exactly %s.json", entries, record.ID)
	}
}

// TestInstalledCalibrationChangesPlannerSelection builds two validated
// documents whose decode rows disagree, installs one, loads it through the
// strict loader, and proves the tensor planner chooses a different strategy
// than it does with the baked measured table.
func TestInstalledCalibrationChangesPlannerSelection(t *testing.T) {
	s, err := Init(t.TempDir(), DefaultOptions())
	if err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer s.Close()

	shape, payload, err := bf16MeasurementShape(2 << 20)
	if err != nil {
		t.Fatalf("build bf16 fixture: %v", err)
	}

	// Installed rows: zstd is made ~50 ms/MiB to decode and float-tensor ~1 ns.
	// Every other row keeps the test document's small values. The document is
	// signed after the mutation, so the strict loader accepts it.
	document := calibrationTestDocument()
	rows := document["rows"].([]any)
	for _, raw := range rows {
		row := raw.(map[string]any)
		switch row["class"] {
		case string(CostClassZstd):
			row["fixed_ns"] = json.Number("0")
			row["ns_per_mib"] = json.Number("50000000")
		case string(CostClassFloatTensor):
			row["fixed_ns"] = json.Number("0")
			row["ns_per_mib"] = json.Number("1")
		}
	}
	document = signCalibrationDocument(t, document)

	storeDir := t.TempDir()
	record, err := CalibrationFromDocument(document)
	if err != nil {
		t.Fatalf("installed document rejected: %v", err)
	}
	installedPath, err := record.Install(storeDir)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	installed, err := LoadCalibration(installedPath)
	if err != nil {
		t.Fatalf("installed document does not load: %v", err)
	}

	const lambdaNS = uint64(1)
	bakedOptions := TensorPlanOptions{LambdaNS: lambdaNS, CostModel: CostModelMeasured}
	installedOptions := TensorPlanOptions{LambdaNS: lambdaNS, CostModel: CostModelMeasured, Cost: installed.Table()}

	bakedPlan, err := s.PlanTensor("bf16", shape, payload, RowMajorTensorLayout(), nil, bakedOptions)
	if err != nil {
		t.Fatalf("baked plan: %v", err)
	}
	installedPlan, err := s.PlanTensor("bf16", shape, payload, RowMajorTensorLayout(), nil, installedOptions)
	if err != nil {
		t.Fatalf("installed plan: %v", err)
	}
	t.Logf("planner selection baked=%s (bytes=%d ns=%d) installed=%s (bytes=%d ns=%d)",
		bakedPlan.Chosen, bakedPlan.ChosenPhysicalBytes, bakedPlan.ChosenEstimatedDecodeNS,
		installedPlan.Chosen, installedPlan.ChosenPhysicalBytes, installedPlan.ChosenEstimatedDecodeNS)

	if bakedPlan.Chosen == installedPlan.Chosen {
		t.Fatalf("installed calibration did not change the planner selection: both chose %s", bakedPlan.Chosen)
	}
	if installedPlan.Chosen != TensorStrategyFloatTensor {
		t.Fatalf("installed planner chose %s, want %s", installedPlan.Chosen, TensorStrategyFloatTensor)
	}
	// The installed estimate must be the installed document's row, not the
	// baked table's.
	want := installed.EstimateNS(CostClassFloatTensor, uint64(len(payload)))
	if installedPlan.ChosenEstimatedDecodeNS != want {
		t.Fatalf("installed estimate = %d, want %d", installedPlan.ChosenEstimatedDecodeNS, want)
	}
	if bakedPlan.ChosenEstimatedDecodeNS != EstimateDecodeNS(bakedPlan.Chosen.costClass(), uint64(len(payload)), CostModelMeasured) {
		t.Fatalf("baked estimate = %d", bakedPlan.ChosenEstimatedDecodeNS)
	}
}
