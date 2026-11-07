// `weftfs calibrate` — measure this host's decode-cost table.
//
// The Rust reference (`weftfs calibrate`) measures through the store; Go
// measures at the shipped-codec frame layer (see store/calibrate.go for the
// exact method and its stated limits). The document schema, digest, bounds and
// divergence report are identical, so the Rust loader accepts a Go document.
//
// `--install` validates the document through the strict loader (either the
// measured record or `--from FILE`) and atomically writes it to
// `<store>/calibrations/<id>.json`. The directory is advisory, exactly as in
// Rust: replay, verify, and GC ignore it. The planner consumes an installed
// document explicitly with `--calibration <path>`; installation does not
// silently change a later command's cost table.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"time"

	"github.com/infinityabundance/WeftFS-Go/store"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

const calibrationMib = 1 << 20

func cmdCalibrate(args []string, storeDir string, jsonOut bool) error {
	fs := flag.NewFlagSet("calibrate", flag.ContinueOnError)
	out := fs.String("out", "", "write the calibration document here")
	from := fs.String("from", "", "load an existing document and report divergence")
	install := fs.Bool("install", false, "install the validated document into <store>/calibrations/<id>.json")
	reps := fs.Int("reps", 7, "timed repetitions per representation and size (at least 5)")
	largeMiB := fs.Uint64("large-mib", 16, "large payload size in MiB (at least 8)")
	smallKiB := fs.Uint64("small-kib", 128, "small payload size in KiB (at least 64)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return werr.Newf(werr.InvalidArgument, "calibrate takes no positional arguments")
	}
	// `--store` is accepted (and ignored) so the global flag is usable in one
	// command line, exactly like Rust. `--install` needs a local store: the
	// advisory `calibrations/` directory lives inside one.
	if *install {
		if storeDir == "" || remotePlaneConfigured() {
			return werr.Newf(werr.InvalidArgument,
				"calibrate --install requires a local --store <DIR>")
		}
	}

	options := store.MeasurementOptions{
		Reps:     *reps,
		LargeMiB: *largeMiB,
		SmallKiB: *smallKiB,
	}
	var record *store.Calibration
	var outputPath *string
	if *from != "" {
		loaded, err := store.LoadCalibration(*from)
		if err != nil {
			return err
		}
		record = loaded
		if *out != "" {
			if err := record.WriteFile(*out); err != nil {
				return err
			}
			outputPath = out
		}
	} else {
		if err := options.Validate(); err != nil {
			return err
		}
		outcome, err := store.MeasureDecodeCosts(options)
		if err != nil {
			return err
		}
		created := uint64(time.Now().UnixNano())
		if fixedTimestampNS != nil && *fixedTimestampNS > 0 {
			created = uint64(*fixedTimestampNS)
		}
		built, err := store.CalibrationFromMeasurement(
			outcome, options, store.CurrentHostIdentity(), created)
		if err != nil {
			return err
		}
		path := *out
		if path == "" {
			path = "decode-calibration.json"
		}
		if err := built.WriteFile(path); err != nil {
			return err
		}
		record = built
		outputPath = &path
	}

	var installedPath *string
	if *install {
		path, err := record.Install(storeDir)
		if err != nil {
			return err
		}
		installedPath = &path
	}

	baked := store.BakedCostTable(store.CostModelMeasured)
	if jsonOut {
		rowValues := make([]any, 0, len(store.CostClassAll))
		divergence := make([]any, 0, len(store.CostClassAll))
		for _, class := range store.CostClassAll {
			row := record.Row(class)
			rowValues = append(rowValues, map[string]any{
				"class":      string(class),
				"fixed_ns":   row.FixedNS,
				"ns_per_mib": row.NSperMiB,
				"samples":    row.Samples,
				"origin":     string(row.Origin),
			})
			entry := divergenceEntry(record, baked, class)
			divergence = append(divergence, entry)
		}
		document := map[string]any{
			"schema":          store.CalibrationSchema,
			"calibration_id":  record.ID,
			"created_unix_ns": record.CreatedUnixNS,
			"out":             nil,
			"installed":       nil,
			"rows":            rowValues,
			"divergence":      divergence,
		}
		if outputPath != nil {
			document["out"] = *outputPath
		}
		if installedPath != nil {
			document["installed"] = *installedPath
		}
		data, err := json.MarshalIndent(document, "", "  ")
		if err != nil {
			return werr.Wrap(werr.Io, err, "calibrate: cannot serialise output")
		}
		fmt.Printf("%s\n", data)
		return nil
	}
	fmt.Printf("calibration_id=%s\n", record.ID)
	if outputPath != nil {
		fmt.Printf("out=%s\n", *outputPath)
	}
	if installedPath != nil {
		fmt.Printf("installed=%s\n", *installedPath)
	}
	fmt.Printf("divergence_vs_baked_measured:\n")
	for _, class := range store.CostClassAll {
		fmt.Printf("  %s host_fixed_ns=%d host_ns_per_mib=%d baked_fixed_ns=%d baked_ns_per_mib=%d host_1mib_ns=%d baked_1mib_ns=%d delta=%+.3f%%\n",
			class,
			record.Row(class).FixedNS, record.Row(class).NSperMiB,
			baked.Row(class).FixedNS, baked.Row(class).NSperMiB,
			record.EstimateNS(class, calibrationMib), baked.EstimateNS(class, calibrationMib),
			deltaPercent(record.EstimateNS(class, calibrationMib), baked.EstimateNS(class, calibrationMib)))
	}
	return nil
}

func divergenceEntry(record *store.Calibration, baked *store.CostTable, class store.CostClass) map[string]any {
	hostRow := record.Row(class)
	bakedRow := baked.Row(class)
	hostEstimate := record.EstimateNS(class, calibrationMib)
	bakedEstimate := baked.EstimateNS(class, calibrationMib)
	return map[string]any{
		"class":                   string(class),
		"host_fixed_ns":           hostRow.FixedNS,
		"host_ns_per_mib":         hostRow.NSperMiB,
		"baked_fixed_ns":          bakedRow.FixedNS,
		"baked_ns_per_mib":        bakedRow.NSperMiB,
		"host_1mib_ns":            hostEstimate,
		"baked_1mib_ns":           bakedEstimate,
		"estimate_1mib_delta_ppm": deltaPPM(hostEstimate, bakedEstimate),
	}
}

func deltaPercent(value, reference uint64) float64 {
	if reference == 0 {
		if value == 0 {
			return 0
		}
		return 100
	}
	return float64(int64(value)-int64(reference)) / float64(reference) * 100
}

func deltaPPM(value, reference uint64) int64 {
	if reference == 0 {
		if value == 0 {
			return 0
		}
		return int64(^uint64(0) >> 1)
	}
	numerator := int64(value) - int64(reference)
	return numerator * 1_000_000 / int64(reference)
}
