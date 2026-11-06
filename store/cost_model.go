// Decode cost model shared with the Rust planner (src/cost_model.rs).
//
//	cost = fixed_ns + decoded_bytes * ns_per_mib / 1048576
//
// Two tables exist: the historical hand-written `Declared` linear model and the
// host-calibrated `Measured` table produced by
// `examples/calibrate_decode.rs` in the bench court. The constants below MUST
// equal the Rust constants byte for byte; the cross-language test
// `TestCostModelMatchesRust` asserts the shared expected values.
package store

import (
	"math/bits"

	"github.com/infinityabundance/WeftFS-Go/werr"
)

// CostModelKind selects a coefficient table.
type CostModelKind string

const (
	// CostModelDeclared is the historical hand-written estimate.
	CostModelDeclared CostModelKind = "declared"
	// CostModelMeasured is the host-calibrated table (default).
	CostModelMeasured CostModelKind = "measured"
)

// DefaultCostModel is the planner default.
const DefaultCostModel = CostModelMeasured

// ParseCostModelKind parses `declared|measured`.
func ParseCostModelKind(text string) (CostModelKind, error) {
	switch CostModelKind(text) {
	case CostModelDeclared, CostModelMeasured:
		return CostModelKind(text), nil
	default:
		return "", werr.Newf(werr.InvalidArgument,
			"planner cost model `%s` is not `declared|measured`", text)
	}
}

// CostClass is one row of the decode cost table.
type CostClass string

const (
	CostClassRaw           CostClass = "raw"
	CostClassZstd          CostClass = "zstd"
	CostClassFloatTensor   CostClass = "float-tensor"
	CostClassTensorSharded CostClass = "tensor-sharded"
	CostClassTensorTiled   CostClass = "tensor-tiled"
	CostClassWeightDelta   CostClass = "weight-delta"
	CostClassSemanticDelta CostClass = "semantic-delta"
	CostClassKvCache       CostClass = "kv-cache"
	CostClassActivation    CostClass = "activation"
)

// ParseCostClass maps a canonical strategy spelling to a table row.
func ParseCostClass(text string) (CostClass, bool) {
	switch CostClass(text) {
	case CostClassRaw, CostClassZstd, CostClassFloatTensor,
		CostClassTensorSharded, CostClassTensorTiled, CostClassWeightDelta,
		CostClassSemanticDelta, CostClassKvCache, CostClassActivation:
		return CostClass(text), true
	default:
		return "", false
	}
}

// Coefficients is one affine row.
type Coefficients struct {
	FixedNS  uint64
	NSperMiB uint64
}

// DeclaredCoefficients is the historical linear model expressed as a table.
// `1048576/200` is rounded to `5243` so both languages run identical integer
// arithmetic.
var DeclaredCoefficients = map[CostClass]Coefficients{
	CostClassRaw:           {FixedNS: 20_000, NSperMiB: 5_243},
	CostClassZstd:          {FixedNS: 50_000, NSperMiB: 1_048_576},
	CostClassFloatTensor:   {FixedNS: 150_000, NSperMiB: 4_194_304},
	CostClassTensorSharded: {FixedNS: 100_000, NSperMiB: 4_194_304},
	CostClassTensorTiled:   {FixedNS: 100_000, NSperMiB: 4_194_304},
	CostClassWeightDelta:   {FixedNS: 100_000, NSperMiB: 3_145_728},
	CostClassSemanticDelta: {FixedNS: 150_000, NSperMiB: 3_145_728},
	CostClassKvCache:       {FixedNS: 100_000, NSperMiB: 1_048_576},
	CostClassActivation:    {FixedNS: 100_000, NSperMiB: 1_048_576},
}

// MeasuredCalibration names the exact court measurement.
const MeasuredCalibration = "weftfs-r1/decode-calibration/v1"

// MeasuredCoefficients is the median of three independent 7-repetition runs of
// `examples/calibrate_decode.rs` (128 KiB and 16 MiB, warm cache). Delta rows
// are incremental: the measured base read is subtracted. Modes 12/13 are never
// produced by the store and retain the declared values.
var MeasuredCoefficients = map[CostClass]Coefficients{
	CostClassRaw:           {FixedNS: 10_000, NSperMiB: 318_321},
	CostClassZstd:          {FixedNS: 17_000, NSperMiB: 814_267},
	CostClassFloatTensor:   {FixedNS: 0, NSperMiB: 15_403_165},
	CostClassTensorSharded: {FixedNS: 32_000, NSperMiB: 13_788_933},
	CostClassTensorTiled:   {FixedNS: 14_000, NSperMiB: 10_056_794},
	CostClassWeightDelta:   {FixedNS: 31_000, NSperMiB: 5_297_277},
	CostClassSemanticDelta: {FixedNS: 18_000, NSperMiB: 7_228_350},
	CostClassKvCache:       {FixedNS: 100_000, NSperMiB: 1_048_576},
	CostClassActivation:    {FixedNS: 100_000, NSperMiB: 1_048_576},
}

// CoefficientsFor returns the row for one class under one model.
func CoefficientsFor(class CostClass, model CostModelKind) Coefficients {
	if model == CostModelDeclared {
		return DeclaredCoefficients[class]
	}
	return MeasuredCoefficients[class]
}

// EstimateDecodeNS returns the affine decode estimate. The division by 2^20 is
// an exact u128 shift, matching Rust's `(u128 product) / 1_048_576`.
func EstimateDecodeNS(class CostClass, decodedBytes uint64, model CostModelKind) uint64 {
	row := CoefficientsFor(class, model)
	hi, lo := bits.Mul64(decodedBytes, row.NSperMiB)
	scaled := (hi << 44) | (lo >> 20)
	return saturatingAdd(scaled, row.FixedNS)
}
