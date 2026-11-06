package store

import (
	"bytes"
	"encoding/json"
	"strconv"
	"testing"
)

func calibrationTestDocument() map[string]any {
	rows := make([]any, 0, len(CostClassAll))
	for index, class := range CostClassAll {
		rows = append(rows, map[string]any{
			"class":      string(class),
			"fixed_ns":   json.Number(strconv.Itoa(1000 + index)),
			"ns_per_mib": json.Number(strconv.Itoa(2_000_000 + index*1000)),
			"samples":    json.Number("14"),
			"origin":     "measured",
		})
	}
	return map[string]any{
		"schema":          CalibrationSchema,
		"created_unix_ns": json.Number("1700000000000000000"),
		"host": map[string]any{
			"hostname": "court", "kernel": "test", "arch": "amd64",
			"cpus": json.Number("4"), "image": "weft/go-court:1",
			"image_id": "sha256:test", "memory_limit": "3g", "pids_limit": "1024",
			"weftfs_revision": "abc", "weftcodec_revision": "def",
		},
		"method": map[string]any{
			"reps": json.Number("7"), "warmup_reads": json.Number("1"),
			"small_bytes": json.Number("131072"), "large_bytes": json.Number("16777216"),
			"fit": calibrationFitText,
		},
		"rows": rows,
	}
}

func cloneCalibrationDocument(t *testing.T, document map[string]any) map[string]any {
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

func signCalibrationDocument(t *testing.T, document map[string]any) map[string]any {
	t.Helper()
	withoutDigest := make(map[string]any, len(document))
	for key, value := range document {
		if key != "digest" {
			withoutDigest[key] = value
		}
	}
	digest, err := calibrationDigest(withoutDigest)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	document["digest"] = digest.Hex()
	return document
}

func TestCalibrationDocumentRoundTrip(t *testing.T) {
	document := signCalibrationDocument(t, calibrationTestDocument())
	calibration, err := CalibrationFromDocument(document)
	if err != nil {
		t.Fatalf("valid calibration rejected: %v", err)
	}
	if calibration.CreatedUnixNS != 1_700_000_000_000_000_000 {
		t.Fatalf("created_unix_ns lost precision: %d", calibration.CreatedUnixNS)
	}
	if calibration.Host.CPUs != 4 || calibration.Method.Reps != 7 {
		t.Fatalf("host/method not decoded: %+v %+v", calibration.Host, calibration.Method)
	}
	for index, class := range CostClassAll {
		row := calibration.Row(class)
		if row.FixedNS != uint64(1000+index) || row.NSperMiB != uint64(2_000_000+index*1000) {
			t.Fatalf("row %s = %+v", class, row)
		}
		want := uint64(1000+index) + ((1<<20)*uint64(2_000_000+index*1000))>>20
		if got := calibration.EstimateNS(class, 1<<20); got != want {
			t.Fatalf("estimate %s = %d, want %d", class, got, want)
		}
	}
}

func TestCalibrationRejectsMalformedDocuments(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(document map[string]any)
	}{
		{"unknown top-level key", func(d map[string]any) { d["extra"] = "x" }},
		{"missing schema", func(d map[string]any) { delete(d, "schema") }},
		{"wrong schema", func(d map[string]any) { d["schema"] = "weft.calibration.v2" }},
		{"zero created", func(d map[string]any) { d["created_unix_ns"] = json.Number("0") }},
		{"created as string", func(d map[string]any) { d["created_unix_ns"] = "123" }},
		{"host unknown key", func(d map[string]any) { d["host"].(map[string]any)["os"] = "linux" }},
		{"host missing field", func(d map[string]any) { delete(d["host"].(map[string]any), "kernel") }},
		{"cpus negative", func(d map[string]any) { d["host"].(map[string]any)["cpus"] = json.Number("-1") }},
		{"cpus float", func(d map[string]any) { d["host"].(map[string]any)["cpus"] = json.Number("4.5") }},
		{"method unknown key", func(d map[string]any) { d["method"].(map[string]any)["mode"] = "fast" }},
		{"method fit text", func(d map[string]any) { d["method"].(map[string]any)["fit"] = "linear" }},
		{"method reps", func(d map[string]any) { d["method"].(map[string]any)["reps"] = json.Number("4") }},
		{"method warmup", func(d map[string]any) { d["method"].(map[string]any)["warmup_reads"] = json.Number("0") }},
		{"method small", func(d map[string]any) { d["method"].(map[string]any)["small_bytes"] = json.Number("1024") }},
		{"method large", func(d map[string]any) { d["method"].(map[string]any)["large_bytes"] = json.Number("1048576") }},
		{"method ordering", func(d map[string]any) {
			d["method"].(map[string]any)["small_bytes"] = json.Number("16777216")
		}},
		{"rows not an array", func(d map[string]any) { d["rows"] = "rows" }},
		{"rows too short", func(d map[string]any) {
			rows := d["rows"].([]any)
			d["rows"] = rows[:9]
		}},
		{"duplicate class", func(d map[string]any) {
			rows := d["rows"].([]any)
			rows[1].(map[string]any)["class"] = rows[0].(map[string]any)["class"]
		}},
		{"unknown class", func(d map[string]any) {
			d["rows"].([]any)[0].(map[string]any)["class"] = "nonsense"
		}},
		{"row unknown key", func(d map[string]any) {
			d["rows"].([]any)[0].(map[string]any)["extra"] = json.Number("1")
		}},
		{"row missing samples", func(d map[string]any) {
			delete(d["rows"].([]any)[0].(map[string]any), "samples")
		}},
		{"measured samples", func(d map[string]any) {
			d["rows"].([]any)[0].(map[string]any)["samples"] = json.Number("4")
		}},
		{"reused with samples", func(d map[string]any) {
			row := d["rows"].([]any)[0].(map[string]any)
			row["origin"] = "reused"
			row["samples"] = json.Number("2")
		}},
		{"declared with samples", func(d map[string]any) {
			row := d["rows"].([]any)[0].(map[string]any)
			row["origin"] = "declared"
			row["samples"] = json.Number("2")
		}},
		{"unknown origin", func(d map[string]any) {
			d["rows"].([]any)[0].(map[string]any)["origin"] = "guessed"
		}},
		{"fixed bound", func(d map[string]any) {
			d["rows"].([]any)[0].(map[string]any)["fixed_ns"] = json.Number("60000000001")
		}},
		{"zero ns_per_mib", func(d map[string]any) {
			d["rows"].([]any)[0].(map[string]any)["ns_per_mib"] = json.Number("0")
		}},
		{"ns_per_mib bound", func(d map[string]any) {
			d["rows"].([]any)[0].(map[string]any)["ns_per_mib"] = json.Number("100000000001")
		}},
		{"digest missing", func(d map[string]any) { delete(d, "digest") }},
		{"digest short", func(d map[string]any) { d["digest"] = "abc" }},
		{"digest mismatch", func(d map[string]any) {
			// Re-sign, then alter a bounded field without re-signing.
			signCalibrationDocument(t, d)
			d["rows"].([]any)[0].(map[string]any)["fixed_ns"] = json.Number("4242")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			document := signCalibrationDocument(t, calibrationTestDocument())
			tc.mutate(document)
			if _, err := CalibrationFromDocument(document); err == nil {
				t.Fatalf("malformed calibration was accepted")
			}
		})
	}
	// A signed document with a tampered digest must also fail.
	document := signCalibrationDocument(t, calibrationTestDocument())
	document["digest"] = "0000000000000000000000000000000000000000000000000000000000000000"
	if _, err := CalibrationFromDocument(document); err == nil {
		t.Fatal("a wrong digest was accepted")
	}
}

func TestCalibrationTableDrivesPricing(t *testing.T) {
	document := signCalibrationDocument(t, calibrationTestDocument())
	calibration, err := CalibrationFromDocument(document)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	table := calibration.Table()
	if got, want := table.EstimateNS(CostClassTensorSharded, 64<<20),
		calibration.EstimateNS(CostClassTensorSharded, 64<<20); got != want {
		t.Fatalf("table and calibration disagree: %d vs %d", got, want)
	}
	stale := TensorPlanOptions{CostModel: CostModelDeclared}
	fresh := TensorPlanOptions{CostModel: CostModelMeasured, Cost: table}
	if estimatedDecodeNS(TensorStrategySharded, 8<<20, stale) ==
		estimatedDecodeNS(TensorStrategySharded, 8<<20, fresh) {
		t.Fatalf("calibration did not change the planner estimate")
	}
	if got, want := estimatedDecodeNS(TensorStrategySharded, 8<<20, fresh),
		table.EstimateNS(CostClassTensorSharded, 8<<20); got != want {
		t.Fatalf("planner estimate = %d, table = %d", got, want)
	}
}
