package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/infinityabundance/WeftFS-Go/store"
)

func resetCalibrateGlobals(t *testing.T) {
	t.Helper()
	previousTimestamp := fixedTimestampNS
	previousCalibration := calibration
	previousCalibrationPath := calibrationPath
	previousModel := plannerCostModel
	t.Cleanup(func() {
		fixedTimestampNS = previousTimestamp
		calibration = previousCalibration
		calibrationPath = previousCalibrationPath
		plannerCostModel = previousModel
	})
	fixedTimestampNS = nil
	calibration = nil
	calibrationPath = ""
	plannerCostModel = store.DefaultCostModel
}

func runCalibrateCLI(t *testing.T, args []string) string {
	t.Helper()
	return captureStdout(t, func() error {
		rest, storeDir, jsonOut, err := globals(args)
		if err != nil {
			return err
		}
		if len(rest) == 0 {
			t.Fatal("globals returned no command")
		}
		return run(rest[0], rest[1:], storeDir, jsonOut)
	})
}

func TestCalibrateCLIWritesMeasuredDocument(t *testing.T) {
	resetCalibrateGlobals(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "calibration.json")
	output := runCalibrateCLI(t, []string{
		"--fixed-timestamp-ns", "1700000000000000000", "--json",
		"calibrate", "--out", out,
		"--reps", "5", "--small-kib", "64", "--large-mib", "8",
	})
	var report struct {
		Schema        string `json:"schema"`
		CalibrationID string `json:"calibration_id"`
		CreatedUnixNS uint64 `json:"created_unix_ns"`
		Out           string `json:"out"`
		Rows          []struct {
			Class  string `json:"class"`
			Origin string `json:"origin"`
		} `json:"rows"`
		Divergence []struct {
			Class                string `json:"class"`
			Estimate1MiBDeltaPPM int64  `json:"estimate_1mib_delta_ppm"`
		} `json:"divergence"`
	}
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("calibrate --json output is not JSON: %v\n%s", err, output)
	}
	if report.Schema != store.CalibrationSchema {
		t.Fatalf("schema = %q", report.Schema)
	}
	if len(report.CalibrationID) != 64 {
		t.Fatalf("calibration_id = %q", report.CalibrationID)
	}
	if report.CreatedUnixNS != 1_700_000_000_000_000_000 {
		t.Fatalf("created_unix_ns = %d; --fixed-timestamp-ns was not honoured", report.CreatedUnixNS)
	}
	if report.Out != out {
		t.Fatalf("out = %q, want %q", report.Out, out)
	}
	if len(report.Rows) != len(store.CostClassAll) || len(report.Divergence) != len(store.CostClassAll) {
		t.Fatalf("rows=%d divergence=%d", len(report.Rows), len(report.Divergence))
	}
	measured := 0
	for _, row := range report.Rows {
		if row.Origin == string(store.OriginMeasured) {
			measured++
		}
	}
	if measured != 7 {
		t.Fatalf("measured rows = %d, want 7", measured)
	}

	loaded, err := store.LoadCalibration(out)
	if err != nil {
		t.Fatalf("the CLI document does not load: %v", err)
	}
	if loaded.ID != report.CalibrationID {
		t.Fatalf("loaded id %s != reported %s", loaded.ID, report.CalibrationID)
	}

	// `--from` reports the same document without measuring again.
	again := runCalibrateCLI(t, []string{"--json", "calibrate", "--from", out})
	var fromReport struct {
		CalibrationID string `json:"calibration_id"`
		Out           string `json:"out"`
	}
	if err := json.Unmarshal([]byte(again), &fromReport); err != nil {
		t.Fatalf("calibrate --from --json output is not JSON: %v\n%s", err, again)
	}
	if fromReport.CalibrationID != report.CalibrationID {
		t.Fatalf("--from id %s != measured id %s", fromReport.CalibrationID, report.CalibrationID)
	}
	if fromReport.Out != "" {
		t.Fatalf("--from without --out reported out=%q", fromReport.Out)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("calibration file disappeared: %v", err)
	}
}

func TestCalibrateCLIRejectsInvalidUse(t *testing.T) {
	resetCalibrateGlobals(t)
	if err := runCalibrateCLIError(t, []string{"calibrate", "--reps", "4", "--out", filepath.Join(t.TempDir(), "x.json")}); err == nil {
		t.Fatal("--reps 4 was accepted")
	}
	if err := runCalibrateCLIError(t, []string{"calibrate", "--large-mib", "4", "--out", filepath.Join(t.TempDir(), "x.json")}); err == nil {
		t.Fatal("--large-mib 4 was accepted")
	}
	if err := runCalibrateCLIError(t, []string{"calibrate", "extra"}); err == nil {
		t.Fatal("a positional argument was accepted")
	}
}

func runCalibrateCLIError(t *testing.T, args []string) error {
	t.Helper()
	rest, storeDir, jsonOut, err := globals(args)
	if err != nil {
		return err
	}
	return run(rest[0], rest[1:], storeDir, jsonOut)
}

func TestCalibrateCLIInstallsValidatedDocument(t *testing.T) {
	resetCalibrateGlobals(t)
	dir := t.TempDir()
	storeDir := filepath.Join(dir, "store")
	if err := os.MkdirAll(storeDir, 0o755); err != nil {
		t.Fatalf("store dir: %v", err)
	}
	measured := filepath.Join(dir, "calibration.json")
	runCalibrateCLI(t, []string{
		"--fixed-timestamp-ns", "1700000000000000000",
		"calibrate", "--out", measured,
		"--reps", "5", "--small-kib", "64", "--large-mib", "8",
	})

	output := runCalibrateCLI(t, []string{
		"--store", storeDir, "--json",
		"calibrate", "--from", measured, "--install",
	})
	var report struct {
		CalibrationID string `json:"calibration_id"`
		Installed     string `json:"installed"`
	}
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("calibrate --install --json output is not JSON: %v\n%s", err, output)
	}
	want := filepath.Join(storeDir, "calibrations", report.CalibrationID+".json")
	if report.Installed != want {
		t.Fatalf("installed = %q, want %q", report.Installed, want)
	}
	loaded, err := store.LoadCalibration(report.Installed)
	if err != nil {
		t.Fatalf("the installed document does not load: %v", err)
	}
	if loaded.ID != report.CalibrationID {
		t.Fatalf("installed id %s != %s", loaded.ID, report.CalibrationID)
	}

	// Text output carries the same path.
	text := runCalibrateCLI(t, []string{
		"--store", storeDir, "calibrate", "--from", measured, "--install",
	})
	if !strings.Contains(text, "installed="+want) {
		t.Fatalf("text output does not name the installed path: %s", text)
	}
}

func TestCalibrateCLIInstallRejectsMalformedAndWritesNothing(t *testing.T) {
	resetCalibrateGlobals(t)
	dir := t.TempDir()
	storeDir := filepath.Join(dir, "store")
	if err := os.MkdirAll(storeDir, 0o755); err != nil {
		t.Fatalf("store dir: %v", err)
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"schema":"weft.calibration.v1"}`), 0o644); err != nil {
		t.Fatalf("write bad document: %v", err)
	}
	if err := runCalibrateCLIError(t, []string{
		"--store", storeDir, "calibrate", "--from", bad, "--install",
	}); err == nil {
		t.Fatal("a malformed calibration was installed")
	}
	if _, err := os.Stat(filepath.Join(storeDir, "calibrations")); !os.IsNotExist(err) {
		t.Fatalf("a malformed document created the calibration directory (err=%v)", err)
	}
}

func TestCalibrateCLIInstallRefusesARemoteStore(t *testing.T) {
	resetCalibrateGlobals(t)
	if err := runCalibrateCLIError(t, []string{
		"--backend", "gcs", "calibrate", "--install",
	}); err == nil {
		t.Fatal("calibrate --install accepted a remote backend")
	}
	if err := runCalibrateCLIError(t, []string{"calibrate", "--install"}); err == nil {
		t.Fatal("calibrate --install accepted an empty store")
	}
}
