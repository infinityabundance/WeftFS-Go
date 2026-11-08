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

// Mode18MeasuredCalibration names the measured mode-18 row. Mode 18 has its
// own measured affine coefficients; the persisted calibration schema has no
// mode-18 class, so a host calibration prices mode 18 with the tensor-tiled row.
const Mode18MeasuredCalibration = "weftfs-mode18/decode-calibration/v1"

// mode18FixedNS and mode18NSPerMiB are the measured mode-18 coefficients
// (median of three 7-repetition runs, 128 KiB and 16 MiB, four interleaved
// streams). They are not a copy of the tensor-tiled row.
//
// The two-point fit produced a negative intercept, which used to be clamped to
// zero; a zero fixed term made a one-tile region read look free. The fixed term
// is now the measured small-region lower bound, derived from the mode-18
// court's 1-row and 100-row medians at tile [64,896]:
//
//	(415,555 - 256,078) ns per extra 114,688-byte tile => 1,457,700 ns/MiB
//	256,078 - 159,477                                  => 96,601 ns
//
// The per-MiB term remains the whole-frame measured rate (the persisted
// calibration schema has one rate per class).
const (
	mode18FixedNS  uint64 = 96601
	mode18NSPerMiB uint64 = 3674824
)

// EstimateMode18NS returns the measured mode-18 decode estimate for
// decodedBytes logical bytes.
func EstimateMode18NS(decodedBytes uint64) uint64 {
	hi, lo := bits.Mul64(decodedBytes, mode18NSPerMiB)
	scaled := (hi << 44) | (lo >> 20)
	return saturatingAdd(scaled, mode18FixedNS)
}

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
	CostClassSparseDelta   CostClass = "sparse-delta"
	CostClassSemanticDelta CostClass = "semantic-delta"
	CostClassKvCache       CostClass = "kv-cache"
	CostClassActivation    CostClass = "activation"
)

// ParseCostClass maps a canonical strategy spelling to a table row.
func ParseCostClass(text string) (CostClass, bool) {
	switch CostClass(text) {
	case CostClassRaw, CostClassZstd, CostClassFloatTensor,
		CostClassTensorSharded, CostClassTensorTiled, CostClassWeightDelta,
		CostClassSparseDelta, CostClassSemanticDelta, CostClassKvCache, CostClassActivation:
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
	// SPARSE_DELTA reuses the WEIGHT_DELTA row (not separately calibrated);
	// keeps parity with src/cost_model.rs.
	CostClassSparseDelta:   {FixedNS: 100_000, NSperMiB: 3_145_728},
	CostClassSemanticDelta: {FixedNS: 150_000, NSperMiB: 3_145_728},
	CostClassKvCache:       {FixedNS: 100_000, NSperMiB: 1_048_576},
	CostClassActivation:    {FixedNS: 100_000, NSperMiB: 1_048_576},
}

// MeasuredCalibration names the exact court measurement.
const MeasuredCalibration = "weftfs-r2/decode-calibration/v1"

// MeasuredCoefficients is the median of three independent 7-repetition runs of
// `examples/calibrate_decode.rs` (128 KiB and 16 MiB, warm cache), re-measured
// after the R2 Huffman and plane-join work. Delta rows are incremental: the
// measured base read is subtracted. Modes 12/13 are never produced by the
// store and retain the declared values. Must equal src/cost_model.rs.
var MeasuredCoefficients = map[CostClass]Coefficients{
	CostClassRaw:           {FixedNS: 11_757, NSperMiB: 307_019},
	CostClassZstd:          {FixedNS: 21_285, NSperMiB: 779_888},
	CostClassFloatTensor:   {FixedNS: 18_264, NSperMiB: 4_683_726},
	CostClassTensorSharded: {FixedNS: 16_172, NSperMiB: 9_123_307},
	CostClassTensorTiled:   {FixedNS: 14_131, NSperMiB: 3_366_772},
	CostClassWeightDelta:   {FixedNS: 30_725, NSperMiB: 5_293_987},
	// SPARSE_DELTA reuses the measured WEIGHT_DELTA row (not separately
	// calibrated); keeps parity with src/cost_model.rs.
	CostClassSparseDelta:   {FixedNS: 30_725, NSperMiB: 5_293_987},
	CostClassSemanticDelta: {FixedNS: 31_891, NSperMiB: 6_458_523},
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

// CostClassAll is the canonical row order. A calibration document must carry
// exactly one row for each entry.
var CostClassAll = [10]CostClass{
	CostClassRaw,
	CostClassZstd,
	CostClassFloatTensor,
	CostClassTensorSharded,
	CostClassTensorTiled,
	CostClassWeightDelta,
	CostClassSparseDelta,
	CostClassSemanticDelta,
	CostClassKvCache,
	CostClassActivation,
}

// Index is the position of a class in CostClassAll.
func (c CostClass) Index() int {
	for index, candidate := range CostClassAll {
		if candidate == c {
			return index
		}
	}
	return 0
}

// CostTable is a complete ten-row affine decode-cost table.
type CostTable struct {
	rows [10]Coefficients
}

// NewCostTable builds a table from rows in CostClassAll order.
func NewCostTable(rows [10]Coefficients) *CostTable {
	return &CostTable{rows: rows}
}

// BakedCostTable returns the historical declared or measured table.
func BakedCostTable(model CostModelKind) *CostTable {
	rows := [10]Coefficients{}
	source := MeasuredCoefficients
	if model == CostModelDeclared {
		source = DeclaredCoefficients
	}
	for index, class := range CostClassAll {
		rows[index] = source[class]
	}
	return NewCostTable(rows)
}

// Row returns one row of the table.
func (t *CostTable) Row(class CostClass) Coefficients {
	if t == nil {
		return Coefficients{}
	}
	return t.rows[class.Index()]
}

// EstimateNS prices `decodedBytes` with this table.
func (t *CostTable) EstimateNS(class CostClass, decodedBytes uint64) uint64 {
	row := t.Row(class)
	hi, lo := bits.Mul64(decodedBytes, row.NSperMiB)
	scaled := (hi << 44) | (lo >> 20)
	return saturatingAdd(scaled, row.FixedNS)
}

// EstimateDecodeNSWith prices with an explicit table when one is supplied.
func EstimateDecodeNSWith(class CostClass, decodedBytes uint64, model CostModelKind, table *CostTable) uint64 {
	if table != nil {
		return table.EstimateNS(class, decodedBytes)
	}
	return EstimateDecodeNS(class, decodedBytes, model)
}

// ---------------------------------------------------------------------------
// Encoder (write) cost
// ---------------------------------------------------------------------------

// EncodeCalibration names the encode-cost table. Constants here MUST equal the
// Rust table in src/cost_model.rs; TestEncodeCostModelMatchesRust asserts it.
const EncodeCalibration = "weftfs-write-cost/v1"

// EncodeClass is an encode-cost row. It tracks planner strategies rather than
// the frozen decode CostClass set because modes 17 and 18 have their own
// measured encode cost but no decode class of their own.
type EncodeClass string

const (
	EncodeClassRaw               EncodeClass = "raw"
	EncodeClassZstd              EncodeClass = "zstd"
	EncodeClassZstd19            EncodeClass = "zstd-19"
	EncodeClassFloatTensor       EncodeClass = "float-tensor"
	EncodeClassTensorSharded     EncodeClass = "tensor-sharded"
	EncodeClassTensorTiled       EncodeClass = "tensor-tiled"
	EncodeClassFloatTiled        EncodeClass = "float-tiled"
	EncodeClassFloatTiledStreams EncodeClass = "float-tiled-streams"
	EncodeClassWeightDelta       EncodeClass = "weight-delta"
	EncodeClassSparseDelta       EncodeClass = "sparse-delta"
	EncodeClassSemanticDelta     EncodeClass = "semantic-delta"
)

// EncodeClassAll is every encode row in canonical order.
var EncodeClassAll = []EncodeClass{
	EncodeClassRaw,
	EncodeClassZstd,
	EncodeClassZstd19,
	EncodeClassFloatTensor,
	EncodeClassTensorSharded,
	EncodeClassTensorTiled,
	EncodeClassFloatTiled,
	EncodeClassFloatTiledStreams,
	EncodeClassWeightDelta,
	EncodeClassSparseDelta,
	EncodeClassSemanticDelta,
}

// EncodeCoefficients is one encode row: fixed cost plus nanoseconds per MiB of
// encoded logical bytes.
type EncodeCoefficients struct {
	FixedNS    uint64
	NSperMiB   uint64
	Provenance string
}

// EncodeCoefficientsTable mirrors the Rust ENCODE table. Measured rows come
// from the T1 write-policy court (raw, zstd) and the float-tiled court
// (float-tensor, float-tiled); float-tiled-streams is derived from the measured
// mode-18 codec ratio; the rest are declared.
var EncodeCoefficientsTable = map[EncodeClass]EncodeCoefficients{
	EncodeClassRaw:               {FixedNS: 0, NSperMiB: 2620000, Provenance: "measured"},
	EncodeClassZstd:              {FixedNS: 0, NSperMiB: 3090000, Provenance: "measured"},
	EncodeClassZstd19:            {FixedNS: 0, NSperMiB: 35087719, Provenance: "measured"},
	EncodeClassFloatTensor:       {FixedNS: 0, NSperMiB: 8806000, Provenance: "measured"},
	EncodeClassTensorSharded:     {FixedNS: 0, NSperMiB: 8806000, Provenance: "declared"},
	EncodeClassTensorTiled:       {FixedNS: 0, NSperMiB: 28633000, Provenance: "declared"},
	EncodeClassFloatTiled:        {FixedNS: 0, NSperMiB: 28633000, Provenance: "measured"},
	EncodeClassFloatTiledStreams: {FixedNS: 0, NSperMiB: 37360000, Provenance: "derived"},
	EncodeClassWeightDelta:       {FixedNS: 0, NSperMiB: 17612000, Provenance: "declared"},
	EncodeClassSparseDelta:       {FixedNS: 0, NSperMiB: 17612000, Provenance: "declared"},
	EncodeClassSemanticDelta:     {FixedNS: 0, NSperMiB: 17612000, Provenance: "declared"},
}

// EncodeClassOf maps a planner strategy to its encode row.
func EncodeClassOf(strategy TensorStrategy) EncodeClass {
	switch strategy {
	case TensorStrategyRaw:
		return EncodeClassRaw
	case TensorStrategyZstd:
		return EncodeClassZstd
	case TensorStrategyFloatTensor:
		return EncodeClassFloatTensor
	case TensorStrategySharded:
		return EncodeClassTensorSharded
	case TensorStrategyFloatTiled:
		return EncodeClassFloatTiled
	case TensorStrategyFloatTiledStreams:
		return EncodeClassFloatTiledStreams
	case TensorStrategyWeightDelta:
		return EncodeClassWeightDelta
	case TensorStrategySparseDelta:
		return EncodeClassSparseDelta
	case TensorStrategySemanticDelta:
		return EncodeClassSemanticDelta
	default:
		return EncodeClassTensorSharded
	}
}

// EstimateEncodeNS prices one whole-tensor encode of `bytes`.
func EstimateEncodeNS(strategy TensorStrategy, bytes uint64) uint64 {
	return EstimateEncodeNSClass(EncodeClassOf(strategy), bytes)
}

// EstimateEncodeNSClass prices one whole-tensor encode with an explicit row.
func EstimateEncodeNSClass(class EncodeClass, bytes uint64) uint64 {
	row := EncodeCoefficientsTable[class]
	hi, lo := bits.Mul64(bytes, row.NSperMiB)
	scaled := (hi << 44) | (lo >> 20)
	return saturatingAdd(scaled, row.FixedNS)
}
