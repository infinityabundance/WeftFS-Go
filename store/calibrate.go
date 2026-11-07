// Host-local decode-cost measurement (`weftfs calibrate`).
//
// This is the producer half of `weft.calibration.v1`; calibration.go is the
// strict consumer. Rust's `src/calibration.rs` measures through the store.
// Go measures at the **codec frame layer** with the shipped `WeftCodec-Go`
// encoders and decoders:
//
//   - a frame is constructed once per class and size with the shipped
//     encoder (`EncodeRaw`, `EncodeZstd`, `EncodeFloatTensor`,
//     `EncodeShardedTensor`, `EncodeTiledTensor`, `EncodeWeightDelta`,
//     `EncodeSemanticDelta`);
//   - every timed repetition parses and decodes that frame with the shipped
//     decoder, exactly as `modes.DecodeBytes` / the store read path does;
//   - delta classes are charged their *incremental* cost: the median cost of
//     decoding the same base frame is measured with the same repetition count
//     and subtracted, so the planner can price a dependency chain by
//     recursion (identical rule to Rust).
//
// A uniform codec-level method is used because the Go store has no mode-15 or
// mode-14 writer; measuring some classes through the store and others at the
// codec would make the rows incomparable. The consequence is explicit: these
// numbers are host-local codec decode costs and are NOT byte-comparable with
// the Rust store-level table in `examples/calibrate_decode.rs`.
//
// Classes the measurement cannot honestly produce are recorded with the
// historical declared rows and origin `declared` (kv-cache, activation);
// sparse-delta reuses the measured weight-delta row with origin `reused`,
// matching the Rust record. No row is ever guessed.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"runtime"
	"sort"
	"strconv"
	"time"

	"github.com/infinityabundance/WeftCodec-Go/dependency"
	"github.com/infinityabundance/WeftCodec-Go/frame"
	"github.com/infinityabundance/WeftCodec-Go/limits"
	"github.com/infinityabundance/WeftCodec-Go/modes"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// MeasurementOptions are the measurement parameters. The defaults equal the
// Rust CLI defaults (7 repetitions, 128 KiB and 16 MiB).
type MeasurementOptions struct {
	Reps     int
	LargeMiB uint64
	SmallKiB uint64
}

// DefaultMeasurementOptions returns the Rust defaults.
func DefaultMeasurementOptions() MeasurementOptions {
	return MeasurementOptions{Reps: 7, LargeMiB: 16, SmallKiB: 128}
}

// Validate enforces the same bounds as Rust's MeasurementOptions::validate.
func (o MeasurementOptions) Validate() error {
	if o.Reps < int(MinCalibrationSamples) {
		return werr.Newf(werr.InvalidArgument,
			"calibration: the calibration requires at least %d repetitions", MinCalibrationSamples)
	}
	if o.LargeMiB < 8 || o.SmallKiB < 64 || o.SmallKiB*1024 >= o.LargeMiB*mib {
		return werr.Newf(werr.InvalidArgument,
			"calibration: sizes must satisfy 8 <= large MiB and 64 KiB <= small < large")
	}
	return nil
}

// MeasuredClass is the raw evidence behind one measured row.
type MeasuredClass struct {
	Class                   CostClass
	SmallBytes              uint64
	LargeBytes              uint64
	SmallMedianNS           uint64
	LargeMedianNS           uint64
	SmallDependencyMedianNS *uint64
	LargeDependencyMedianNS *uint64
}

// MeasurementOutcome is the complete measurement result.
type MeasurementOutcome struct {
	Rows    []CalibrationRow
	Errors  []string
	Details []MeasuredClass
}

// measurementFixture is one constructed frame plus its timed decoder.
type measurementFixture struct {
	logicalBytes uint64
	frameBytes   []byte
	baseFrame    []byte
	baseDecode   func([]byte) ([]byte, error)
	decode       func([]byte, []byte) ([]byte, error)
}

type measurementCase struct {
	class CostClass
	build func(targetBytes uint64) (measurementFixture, error)
}

type measurementResult struct {
	logicalBytes       uint64
	medianNS           uint64
	dependencyMedianNS *uint64
}

func measurementLimits() limits.Limits { return limits.Default() }

func measurementContext() context.Context { return context.Background() }

// MeasureDecodeCosts measures the seven classes the planner can encode with
// the shipped codec. It never writes a store and never mutates anything.
func MeasureDecodeCosts(options MeasurementOptions) (MeasurementOutcome, error) {
	if err := options.Validate(); err != nil {
		return MeasurementOutcome{}, err
	}
	if options.SmallKiB*1024%2048 != 0 || options.LargeMiB*mib%2048 != 0 {
		return MeasurementOutcome{}, werr.Newf(werr.InvalidArgument,
			"calibration: payload sizes must be multiples of 2048 bytes so each class has a valid shape")
	}
	classes := []measurementCase{
		{CostClassRaw, buildRawFixture},
		{CostClassZstd, buildZstdFixture},
		{CostClassFloatTensor, buildFloatTensorFixture},
		{CostClassTensorSharded, buildShardedFixture},
		{CostClassTensorTiled, buildTiledFixture},
		{CostClassWeightDelta, buildWeightDeltaFixture},
		{CostClassSemanticDelta, buildSemanticDeltaFixture},
	}
	outcome := MeasurementOutcome{}
	sizes := [2]uint64{options.SmallKiB * 1024, options.LargeMiB * mib}
	for _, c := range classes {
		measured := make([]measurementResult, 0, 2)
		failed := false
		for _, target := range sizes {
			result, err := measureOne(c, target, options.Reps)
			if err != nil {
				outcome.Errors = append(outcome.Errors,
					fmt.Sprintf("%s @ %d bytes: %s", c.class, target, err))
				failed = true
				break
			}
			measured = append(measured, result)
		}
		if failed || len(measured) != 2 {
			continue
		}
		small, large := measured[0], measured[1]
		smallNS := small.medianNS
		largeNS := large.medianNS
		if small.dependencyMedianNS != nil {
			smallNS -= minUint64(smallNS, *small.dependencyMedianNS)
		}
		if large.dependencyMedianNS != nil {
			largeNS -= minUint64(largeNS, *large.dependencyMedianNS)
		}
		fixed, perMiB := fitAffine(smallNS, small.logicalBytes, largeNS, large.logicalBytes)
		outcome.Rows = append(outcome.Rows, CalibrationRow{
			Class: c.class, FixedNS: fixed, NSperMiB: perMiB,
			Samples: uint64(options.Reps * 2), Origin: OriginMeasured,
		})
		outcome.Details = append(outcome.Details, MeasuredClass{
			Class:      c.class,
			SmallBytes: small.logicalBytes, LargeBytes: large.logicalBytes,
			SmallMedianNS: small.medianNS, LargeMedianNS: large.medianNS,
			SmallDependencyMedianNS: small.dependencyMedianNS,
			LargeDependencyMedianNS: large.dependencyMedianNS,
		})
	}
	return outcome, nil
}

func minUint64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

// fitAffine fits fixed_ns + ns_per_mib * bytes / 2^20 through two measured
// points, using Rust's exact arithmetic and rounding.
func fitAffine(smallNS, smallBytes, largeNS, largeBytes uint64) (uint64, uint64) {
	smallF := float64(smallNS)
	largeF := float64(largeNS)
	deltaBytes := float64(largeBytes) - float64(smallBytes)
	perByte := 0.0
	if largeF > smallF && deltaBytes > 0 {
		perByte = (largeF - smallF) / deltaBytes
	}
	fixed := smallF - perByte*float64(smallBytes)
	if fixed < 0 {
		fixed = 0
	}
	nsPerMiB := uint64(math.Round(perByte * float64(mib)))
	if nsPerMiB == 0 {
		nsPerMiB = 1
	}
	return uint64(math.Round(fixed)), nsPerMiB
}

func measureOne(c measurementCase, targetBytes uint64, reps int) (measurementResult, error) {
	fixture, err := c.build(targetBytes)
	if err != nil {
		return measurementResult{}, err
	}
	// Warm-up decode: also proves the frame decodes and has the right length.
	decoded, err := fixture.decode(fixture.frameBytes, fixture.baseFrame)
	if err != nil {
		return measurementResult{}, werr.Wrap(werr.Corrupt, err, "%s warm-up decode", c.class)
	}
	if uint64(len(decoded)) != fixture.logicalBytes {
		return measurementResult{}, werr.Newf(werr.Corrupt,
			"%s decoded %d bytes, expected %d", c.class, len(decoded), fixture.logicalBytes)
	}
	var dependencyMedian *uint64
	if fixture.baseFrame != nil {
		if fixture.baseDecode == nil {
			return measurementResult{}, werr.Newf(werr.InvalidArgument,
				"%s fixture has a base frame but no base decoder", c.class)
		}
		if _, err := fixture.baseDecode(fixture.baseFrame); err != nil {
			return measurementResult{}, werr.Wrap(werr.Corrupt, err, "%s base warm-up decode", c.class)
		}
		baseTimes := make([]uint64, 0, reps)
		for index := 0; index < reps; index++ {
			started := time.Now()
			if _, err := fixture.baseDecode(fixture.baseFrame); err != nil {
				return measurementResult{}, werr.Wrap(werr.Corrupt, err, "%s base decode", c.class)
			}
			baseTimes = append(baseTimes, uint64(time.Since(started).Nanoseconds()))
		}
		median := medianOf(baseTimes)
		dependencyMedian = &median
	}
	times := make([]uint64, 0, reps)
	for index := 0; index < reps; index++ {
		started := time.Now()
		data, err := fixture.decode(fixture.frameBytes, fixture.baseFrame)
		elapsed := uint64(time.Since(started).Nanoseconds())
		if err != nil {
			return measurementResult{}, werr.Wrap(werr.Corrupt, err, "%s decode", c.class)
		}
		if uint64(len(data)) != fixture.logicalBytes {
			return measurementResult{}, werr.Newf(werr.Corrupt,
				"%s decoded %d bytes, expected %d", c.class, len(data), fixture.logicalBytes)
		}
		times = append(times, elapsed)
	}
	return measurementResult{
		logicalBytes:       fixture.logicalBytes,
		medianNS:           medianOf(times),
		dependencyMedianNS: dependencyMedian,
	}, nil
}

func medianOf(values []uint64) uint64 {
	sorted := append([]uint64(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[len(sorted)/2]
}

// ---- payloads (verbatim ports of src/calibration.rs) ----------------------

func bf16MeasurementPayload(elements uint64) []byte {
	out := make([]byte, 0, elements*2)
	state := uint64(0x9e37_79b9_7f4a_7c15)
	for index := uint64(0); index < elements; index++ {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		unit := float32(state>>40) / float32(uint64(1)<<24)
		value := (unit*2 - 1) * 0.5
		bits := math.Float32bits(value)
		word := uint16(bits >> 16)
		out = append(out, byte(word), byte(word>>8))
	}
	return out
}

func q8MeasurementPayload(elements uint64) []byte {
	out := make([]byte, 0, elements)
	state := uint64(0x1234_5678_9abc_def0)
	for index := uint64(0); index < elements; index++ {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		out = append(out, byte(state>>32))
	}
	return out
}

func nudgeBytes(bytesValue []byte) []byte {
	out := append([]byte(nil), bytesValue...)
	words := len(out) / 2
	for index := 0; index < words; index += 4096 {
		out[index*2] ^= 1
	}
	return out
}

func clearLowMantissaBits(bytesValue []byte, bits uint32) []byte {
	mask := ^uint16((uint32(1) << bits) - 1)
	out := make([]byte, 0, len(bytesValue))
	for index := 0; index+1 < len(bytesValue); index += 2 {
		word := uint16(bytesValue[index]) | uint16(bytesValue[index+1])<<8
		word &= mask
		out = append(out, byte(word), byte(word>>8))
	}
	return out
}

// bf16MeasurementShape mirrors the Rust shape: [elements/1024, 1024].
func bf16MeasurementShape(targetBytes uint64) ([]uint64, []byte, error) {
	if targetBytes%2 != 0 {
		return nil, nil, werr.Newf(werr.InvalidArgument,
			"calibration: %d is not an even byte count", targetBytes)
	}
	elements := targetBytes / 2
	if elements%1024 != 0 {
		return nil, nil, werr.Newf(werr.InvalidArgument,
			"calibration: %d bytes do not form a [n/1024, 1024] bf16 shape", targetBytes)
	}
	return []uint64{elements / 1024, 1024}, bf16MeasurementPayload(elements), nil
}

// ---- frame builders -------------------------------------------------------

func frameDecoder(decoder func(*frame.Frame) ([]byte, error)) func([]byte, []byte) ([]byte, error) {
	lim := measurementLimits()
	return func(frameBytes, _ []byte) ([]byte, error) {
		parsed, err := frame.Parse(frameBytes, lim)
		if err != nil {
			return nil, err
		}
		return decoder(parsed)
	}
}

func buildRawFixture(targetBytes uint64) (measurementFixture, error) {
	_, payload, err := bf16MeasurementShape(targetBytes)
	if err != nil {
		return measurementFixture{}, err
	}
	frameBytes, err := modes.EncodeRaw(payload, 64*1024, measurementLimits())
	if err != nil {
		return measurementFixture{}, werr.FromCodec(err)
	}
	lim := measurementLimits()
	return measurementFixture{
		logicalBytes: targetBytes,
		frameBytes:   frameBytes,
		decode: func(frameBytes, _ []byte) ([]byte, error) {
			return modes.DecodeBytes(measurementContext(), frameBytes, dependency.NewMapResolver(), lim)
		},
	}, nil
}

func buildZstdFixture(targetBytes uint64) (measurementFixture, error) {
	_, payload, err := bf16MeasurementShape(targetBytes)
	if err != nil {
		return measurementFixture{}, err
	}
	frameBytes, err := modes.EncodeZstd(payload, CodecZstdLevel, 64*1024, measurementLimits())
	if err != nil {
		return measurementFixture{}, werr.FromCodec(err)
	}
	lim := measurementLimits()
	return measurementFixture{
		logicalBytes: targetBytes,
		frameBytes:   frameBytes,
		decode: func(frameBytes, _ []byte) ([]byte, error) {
			return modes.DecodeBytes(measurementContext(), frameBytes, dependency.NewMapResolver(), lim)
		},
	}, nil
}

func buildFloatTensorFixture(targetBytes uint64) (measurementFixture, error) {
	shape, payload, err := bf16MeasurementShape(targetBytes)
	if err != nil {
		return measurementFixture{}, err
	}
	dtype, err := modes.ParseFloatDtype("bf16")
	if err != nil {
		return measurementFixture{}, werr.FromCodec(err)
	}
	lim := measurementLimits()
	frameBytes, err := modes.EncodeFloatTensor(payload, dtype, shape, lim)
	if err != nil {
		return measurementFixture{}, werr.FromCodec(err)
	}
	return measurementFixture{
		logicalBytes: targetBytes,
		frameBytes:   frameBytes,
		decode: frameDecoder(func(parsed *frame.Frame) ([]byte, error) {
			return modes.DecodeFloatTensorFrame(parsed, lim)
		}),
	}, nil
}

func buildShardedFixture(targetBytes uint64) (measurementFixture, error) {
	elementCount := targetBytes
	blockSize := q8BlockSize(elementCount)
	if blockSize == 0 {
		return measurementFixture{}, werr.Newf(werr.InvalidArgument,
			"calibration: %d q8_0 elements are not divisible by a mode-10 block size", elementCount)
	}
	payload := q8MeasurementPayload(elementCount)
	words := make([]int8, len(payload))
	for index, value := range payload {
		words[index] = int8(value)
	}
	scales, zeroPoints := q8Scales(words, blockSize)
	lim := measurementLimits()
	frames, err := modes.EncodeShardedTensor(modes.ShardedTensorInput{
		Dtype: modes.ShardedQ8_0, Shape: []uint64{elementCount}, ShardAxis: 0,
		ShardCount: 1, BlockSize: blockSize, Scales: scales, ZeroPoints: zeroPoints, Words: words,
	}, lim)
	if err != nil {
		return measurementFixture{}, werr.FromCodec(err)
	}
	if len(frames) != 1 {
		return measurementFixture{}, werr.Newf(werr.Corrupt,
			"calibration: mode-10 encoder produced %d frames", len(frames))
	}
	return measurementFixture{
		logicalBytes: targetBytes,
		frameBytes:   frames[0],
		decode: frameDecoder(func(parsed *frame.Frame) ([]byte, error) {
			shard, err := modes.DecodeShardFrame(parsed, lim)
			if err != nil {
				return nil, err
			}
			out := make([]byte, len(shard.Words))
			for index, word := range shard.Words {
				out[index] = byte(word)
			}
			return out, nil
		}),
	}, nil
}

func buildTiledFixture(targetBytes uint64) (measurementFixture, error) {
	shape, payload, err := bf16MeasurementShape(targetBytes)
	if err != nil {
		return measurementFixture{}, err
	}
	tileShape := []uint64{32, 256}
	for axis := range shape {
		if shape[axis]%tileShape[axis] != 0 {
			return measurementFixture{}, werr.Newf(werr.InvalidArgument,
				"calibration: tile shape %v does not divide shape %v", tileShape, shape)
		}
	}
	lim := measurementLimits()
	frameBytes, err := modes.EncodeTiledTensor(payload, "bf16", shape, tileShape, lim)
	if err != nil {
		return measurementFixture{}, werr.FromCodec(err)
	}
	return measurementFixture{
		logicalBytes: targetBytes,
		frameBytes:   frameBytes,
		decode: frameDecoder(func(parsed *frame.Frame) ([]byte, error) {
			return modes.DecodeTiledTensor(parsed, lim)
		}),
	}, nil
}

func buildWeightDeltaFixture(targetBytes uint64) (measurementFixture, error) {
	return buildDeltaFixture(targetBytes, false)
}

func buildSemanticDeltaFixture(targetBytes uint64) (measurementFixture, error) {
	return buildDeltaFixture(targetBytes, true)
}

func buildDeltaFixture(targetBytes uint64, semantic bool) (measurementFixture, error) {
	shape, base, err := bf16MeasurementShape(targetBytes)
	if err != nil {
		return measurementFixture{}, err
	}
	dtype, err := modes.ParseWeightDtype("bf16")
	if err != nil {
		return measurementFixture{}, werr.FromCodec(err)
	}
	lim := measurementLimits()
	baseFrame, err := modes.EncodeTensor(base, "bf16", shape, lim)
	if err != nil {
		return measurementFixture{}, werr.FromCodec(err)
	}
	baseDecode := func(frameBytes []byte) ([]byte, error) {
		return modes.DecodeBytes(measurementContext(), frameBytes, dependency.NewMapResolver(), lim)
	}
	ctx := measurementContext()
	var frameBytes []byte
	if semantic {
		target := clearLowMantissaBits(base, 3)
		frameBytes, err = modes.EncodeSemanticDelta(
			ctx, target, dtype, shape, baseFrame, modes.MantissaTruncatePolicy(3), lim)
	} else {
		target := nudgeBytes(base)
		frameBytes, err = modes.EncodeWeightDelta(ctx, target, dtype, shape, baseFrame, lim)
	}
	if err != nil {
		return measurementFixture{}, werr.FromCodec(err)
	}
	return measurementFixture{
		logicalBytes: targetBytes,
		frameBytes:   frameBytes,
		baseFrame:    baseFrame,
		baseDecode:   baseDecode,
		decode: frameDecoder(func(parsed *frame.Frame) ([]byte, error) {
			if semantic {
				return modes.DecodeSemanticDeltaFrameWithBase(
					ctx, parsed, baseFrame, dependency.NewMapResolver(), lim)
			}
			return modes.DecodeWeightDeltaFrameWithBase(
				ctx, parsed, baseFrame, dependency.NewMapResolver(), lim)
		}),
	}, nil
}

// ---- record assembly ------------------------------------------------------

// CalibrationFromMeasurement assembles a validated record from a measurement.
// The seven measured classes must be present; a missing row is an error, never
// a guess. Sparse-delta reuses weight-delta and the two unproduced classes
// keep the historical declared rows, matching `record_from_measurement` in
// src/calibration.rs.
func CalibrationFromMeasurement(
	outcome MeasurementOutcome,
	options MeasurementOptions,
	host HostIdentity,
	createdUnixNS uint64,
) (*Calibration, error) {
	if err := options.Validate(); err != nil {
		return nil, err
	}
	if len(outcome.Errors) > 0 {
		joined := ""
		for index, message := range outcome.Errors {
			if index > 0 {
				joined += "; "
			}
			joined += message
		}
		return nil, werr.Newf(werr.InvalidArgument,
			"calibration: calibration measurement failed: %s", joined)
	}
	method := CalibrationMethod{
		Reps: uint64(options.Reps), WarmupReads: 1,
		SmallBytes: options.SmallKiB * 1024, LargeBytes: options.LargeMiB * mib,
	}
	measured := func(class CostClass) (CalibrationRow, error) {
		for _, row := range outcome.Rows {
			if row.Class == class {
				return row, nil
			}
		}
		return CalibrationRow{}, werr.Newf(werr.InvalidArgument,
			"calibration: calibration measurement did not produce a `%s` row", class)
	}
	weightDelta, err := measured(CostClassWeightDelta)
	if err != nil {
		return nil, err
	}
	var rows [10]CalibrationRow
	for _, class := range []CostClass{
		CostClassRaw, CostClassZstd, CostClassFloatTensor, CostClassTensorSharded,
		CostClassTensorTiled, CostClassWeightDelta, CostClassSemanticDelta,
	} {
		row, err := measured(class)
		if err != nil {
			return nil, err
		}
		rows[class.Index()] = row
	}
	rows[CostClassSparseDelta.Index()] = CalibrationRow{
		Class: CostClassSparseDelta, FixedNS: weightDelta.FixedNS,
		NSperMiB: weightDelta.NSperMiB, Samples: 0, Origin: OriginReused,
	}
	for _, class := range []CostClass{CostClassKvCache, CostClassActivation} {
		declared := DeclaredCoefficients[class]
		rows[class.Index()] = CalibrationRow{
			Class: class, FixedNS: declared.FixedNS, NSperMiB: declared.NSperMiB,
			Samples: 0, Origin: OriginDeclared,
		}
	}
	document := buildCalibrationDocument(rows, host, method, createdUnixNS)
	digest, err := calibrationDigest(documentWithoutDigest(document))
	if err != nil {
		return nil, err
	}
	document["digest"] = digest.Hex()
	return CalibrationFromDocument(document)
}

func documentWithoutDigest(document map[string]any) map[string]any {
	out := make(map[string]any, len(document))
	for key, value := range document {
		if key == "digest" {
			continue
		}
		out[key] = value
	}
	return out
}

func buildCalibrationDocument(
	rows [10]CalibrationRow,
	host HostIdentity,
	method CalibrationMethod,
	createdUnixNS uint64,
) map[string]any {
	rowValues := make([]any, 0, len(CostClassAll))
	for _, class := range CostClassAll {
		row := rows[class.Index()]
		rowValues = append(rowValues, map[string]any{
			"class":      string(class),
			"fixed_ns":   jsonU64(row.FixedNS),
			"ns_per_mib": jsonU64(row.NSperMiB),
			"samples":    jsonU64(row.Samples),
			"origin":     string(row.Origin),
		})
	}
	return map[string]any{
		"schema":          CalibrationSchema,
		"created_unix_ns": jsonU64(createdUnixNS),
		"host": map[string]any{
			"hostname":           host.Hostname,
			"kernel":             host.Kernel,
			"arch":               host.Arch,
			"cpus":               jsonU64(host.CPUs),
			"image":              host.Image,
			"image_id":           host.ImageID,
			"memory_limit":       host.MemoryLimit,
			"pids_limit":         host.PidsLimit,
			"weftfs_revision":    host.WeftFSRevision,
			"weftcodec_revision": host.WeftCodecRevision,
		},
		"method": map[string]any{
			"reps":         jsonU64(method.Reps),
			"warmup_reads": jsonU64(method.WarmupReads),
			"small_bytes":  jsonU64(method.SmallBytes),
			"large_bytes":  jsonU64(method.LargeBytes),
			"fit":          calibrationFitText,
		},
		"rows": rowValues,
	}
}

func jsonU64(value uint64) interface{} {
	return json.Number(strconv.FormatUint(value, 10))
}

// CurrentHostIdentity captures the best-effort environment identity. The
// `WEFT_COURT_*` and `WEFT_REPO_*` variables are set by
// `scripts/docker-court.sh`; outside a court they are `unknown`. Nothing here
// is trusted for pricing.
func CurrentHostIdentity() HostIdentity {
	readFileTrimmed := func(path string) string {
		data, err := os.ReadFile(path)
		if err != nil {
			return ""
		}
		text := string(data)
		for len(text) > 0 && (text[len(text)-1] == '\n' || text[len(text)-1] == '\r' || text[len(text)-1] == ' ') {
			text = text[:len(text)-1]
		}
		return text
	}
	env := func(name string) string {
		if value, ok := os.LookupEnv(name); ok && value != "" {
			return value
		}
		return "unknown"
	}
	hostname := readFileTrimmed("/proc/sys/kernel/hostname")
	if hostname == "" {
		hostname = env("HOSTNAME")
	}
	kernel := os.Getenv("WEFT_COURT_KERNEL")
	if kernel == "" {
		kernel = readFileTrimmed("/proc/sys/kernel/osrelease")
	}
	if kernel == "" {
		kernel = "unknown"
	}
	cpus := uint64(runtime.NumCPU())
	return HostIdentity{
		Hostname: hostname, Kernel: kernel, Arch: runtime.GOARCH, CPUs: cpus,
		Image: env("WEFT_COURT_IMAGE"), ImageID: env("WEFT_COURT_IMAGE_ID"),
		MemoryLimit: env("WEFT_COURT_MEMORY"), PidsLimit: env("WEFT_COURT_PIDS"),
		WeftFSRevision: env("WEFT_REPO_WEFTFS"), WeftCodecRevision: env("WEFT_REPO_WEFTCODEC"),
	}
}
