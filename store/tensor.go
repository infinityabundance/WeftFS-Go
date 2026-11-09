// First-class WeftTensor physical representations in the Go store.
//
// A tensor object is stored through a v2 representation manifest of kind
// `"tensor"` (frame modes 10-14) or, when the planner chooses a byte
// representation, through the unchanged `"raw"`/`"codec"` kinds. Tensor
// identity (dtype, shape, LogicalTensorRoot, physical layout) is carried both
// in the tensor representation and in reserved object attributes, so a tensor
// object written as raw/zstd bytes still has an exact, checkable logical
// identity.
//
// The planner is deliberately small and deterministic, mirroring
// `src/tensor_store.rs`: it encodes every applicable candidate, prices it as
//
//	cost = physical_bytes + lambda_ns * estimated_decode_ns
//
// and picks the minimum (ties keep the fixed candidate order). `lambda_ns`
// defaults to 0, i.e. bytes-only. Estimated decode time is an explicit integer
// model, not a measurement. B2 implements the raw, zstd, mode-10 (q8_0), and
// mode-11 (weight-delta) candidates; mode 14 is readable here and remains a
// Rust-written candidate.
package store

import (
	"context"
	"fmt"
	"math"
	"math/bits"
	"sort"
	"strconv"
	"strings"

	"github.com/infinityabundance/WeftCodec-Go/frame"
	"github.com/infinityabundance/WeftCodec-Go/limits"
	"github.com/infinityabundance/WeftCodec-Go/modes"
	"github.com/infinityabundance/WeftCodec-Go/tensor"
	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// DefaultTensorMaxCandidates is the default bound on the semantic-delta
// candidate search. B2's writer does not produce mode 14, but the field keeps
// the option surface identical to Rust.
const DefaultTensorMaxCandidates = 16

// TensorStrategy is a physical representation strategy the planner considers.
type TensorStrategy string

// AccessPattern kinds accepted by the planner.
const (
	AccessPatternWhole  = "whole"
	AccessPatternRegion = "region"
	AccessPatternMixed  = "mixed"
)

// AccessPattern is the access pattern a plan is priced for.
type AccessPattern struct {
	Kind          string
	RegionBytes   uint64
	ReadsPerWrite uint64
	WholeReads    uint64
	RegionReads   uint64
}

// ParseAccessPattern parses whole | region:BYTES:READS | mixed:WHOLE:BYTES:READS.
func ParseAccessPattern(text string) (AccessPattern, error) {
	parts := strings.Split(text, ":")
	switch {
	case len(parts) == 1 && parts[0] == "whole":
		return AccessPattern{Kind: AccessPatternWhole}, nil
	case len(parts) == 3 && parts[0] == "region":
		bytesValue, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			return AccessPattern{}, werr.Newf(werr.InvalidArgument, "bad region bytes %q", parts[1])
		}
		reads, err := strconv.ParseUint(parts[2], 10, 64)
		if err != nil {
			return AccessPattern{}, werr.Newf(werr.InvalidArgument, "bad region reads %q", parts[2])
		}
		return AccessPattern{Kind: AccessPatternRegion, RegionBytes: bytesValue, ReadsPerWrite: reads}, nil
	case len(parts) == 4 && parts[0] == "mixed":
		whole, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			return AccessPattern{}, werr.Newf(werr.InvalidArgument, "bad whole reads %q", parts[1])
		}
		bytesValue, err := strconv.ParseUint(parts[2], 10, 64)
		if err != nil {
			return AccessPattern{}, werr.Newf(werr.InvalidArgument, "bad region bytes %q", parts[2])
		}
		reads, err := strconv.ParseUint(parts[3], 10, 64)
		if err != nil {
			return AccessPattern{}, werr.Newf(werr.InvalidArgument, "bad region reads %q", parts[3])
		}
		return AccessPattern{Kind: AccessPatternMixed, WholeReads: whole, RegionBytes: bytesValue, RegionReads: reads}, nil
	default:
		return AccessPattern{}, werr.Newf(werr.InvalidArgument,
			"access pattern must be whole, region:BYTES:READS, or mixed:WHOLE:BYTES:READS (got %q)", text)
	}
}

const (
	// TensorStrategyRaw is concatenated raw chunk blobs (v2 kind:"raw").
	TensorStrategyRaw TensorStrategy = "raw"
	// TensorStrategyZstd is one WeftCodec ZSTD frame (v2 kind:"codec").
	TensorStrategyZstd TensorStrategy = "zstd"
	// TensorStrategyFloatTensor is one mode-9 FLOAT_TENSOR frame.
	TensorStrategyFloatTensor TensorStrategy = "float-tensor"
	// TensorStrategySharded is one mode-10 TENSOR_SHARDED frame.
	TensorStrategySharded TensorStrategy = "tensor-sharded"
	// TensorStrategyWeightDelta is one mode-11 frame against the causal parent.
	TensorStrategyWeightDelta TensorStrategy = "weight-delta"
	// TensorStrategySparseDelta is one mode-16 zero-run delta frame against the
	// causal parent.
	TensorStrategySparseDelta TensorStrategy = "sparse-delta"
	// TensorStrategySemanticDelta is one mode-14 frame (readable, not produced
	// by the B2 writer).
	TensorStrategySemanticDelta TensorStrategy = "semantic-delta"
	// TensorStrategyKvCache is one mode-12 frame (readable only).
	TensorStrategyKvCache TensorStrategy = "kv-cache"
	// TensorStrategyActivation is one mode-13 frame (readable only).
	TensorStrategyActivation TensorStrategy = "activation"
	// TensorStrategyFloatTiled is one mode-17 FLOAT_TILED frame: a per-tile
	// mode-9 plane split with independent tiles.
	TensorStrategyFloatTiled TensorStrategy = "float-tiled"
	// TensorStrategyFloatTiledStreams is one mode-18 FLOAT_TILED_STREAMS
	// frame: per-tile interleaved Huffman streams.
	TensorStrategyFloatTiledStreams TensorStrategy = "float-tiled-streams"
)

// ParseTensorStrategy parses a canonical planner strategy spelling.
func ParseTensorStrategy(text string) (TensorStrategy, error) {
	switch TensorStrategy(text) {
	case TensorStrategyRaw, TensorStrategyZstd, TensorStrategyFloatTensor,
		TensorStrategySharded, TensorStrategyWeightDelta, TensorStrategySparseDelta,
		TensorStrategySemanticDelta, TensorStrategyKvCache, TensorStrategyActivation,
		TensorStrategyFloatTiled, TensorStrategyFloatTiledStreams:
		return TensorStrategy(text), nil
	default:
		return "", werr.Newf(werr.Malformed, "unknown tensor strategy `%s`", text)
	}
}

// ParseTensorStrategyHint parses the CLI spelling, where "auto" means no hint.
func ParseTensorStrategyHint(text string) (*TensorStrategy, error) {
	if text == "auto" {
		return nil, nil
	}
	strategy, err := ParseTensorStrategy(text)
	if err != nil {
		return nil, err
	}
	return &strategy, nil
}

// String returns the canonical spelling.
func (s TensorStrategy) String() string { return string(s) }

// frameMode returns the frame mode this strategy requires, when frame-backed.
func (s TensorStrategy) frameMode() (uint32, bool) {
	switch s {
	case TensorStrategyFloatTensor:
		return 9, true
	case TensorStrategySharded:
		return 10, true
	case TensorStrategyWeightDelta:
		return 11, true
	case TensorStrategySparseDelta:
		return 16, true
	case TensorStrategyKvCache:
		return 12, true
	case TensorStrategyActivation:
		return 13, true
	case TensorStrategySemanticDelta:
		return 14, true
	case TensorStrategyFloatTiled:
		return 17, true
	case TensorStrategyFloatTiledStreams:
		return 18, true
	default:
		return 0, false
	}
}

// usesDependency reports whether the representation carries a base root.
func (s TensorStrategy) usesDependency() bool {
	return s == TensorStrategyWeightDelta || s == TensorStrategySparseDelta ||
		s == TensorStrategySemanticDelta
}

// IsIndependent reports whether the representation decodes without another
// object. Rebase requires one of these; a delta is what rebase removes.
func (s TensorStrategy) IsIndependent() bool {
	switch s {
	case TensorStrategyRaw, TensorStrategyZstd, TensorStrategyFloatTensor,
		TensorStrategySharded, TensorStrategyFloatTiled, TensorStrategyFloatTiledStreams:
		return true
	default:
		return false
	}
}

func tensorStrategyRank(s TensorStrategy) int {
	switch s {
	case TensorStrategyRaw:
		return 0
	case TensorStrategyZstd:
		return 1
	case TensorStrategyFloatTensor:
		return 2
	case TensorStrategySharded:
		return 3
	case TensorStrategyWeightDelta:
		return 4
	case TensorStrategySparseDelta:
		return 5
	case TensorStrategySemanticDelta:
		return 6
	case TensorStrategyKvCache:
		return 7
	case TensorStrategyActivation:
		return 8
	case TensorStrategyFloatTiled:
		return 9
	case TensorStrategyFloatTiledStreams:
		return 10
	default:
		return 99
	}
}

// tensorCost is an unsigned 128-bit price, matching Rust's `u128`.
type tensorCost struct {
	Hi uint64
	Lo uint64
}

func priceTensor(physicalBytes, estimatedNS, lambdaNS uint64) tensorCost {
	hi, lo := bits.Mul64(lambdaNS, estimatedNS)
	lo, carry := bits.Add64(lo, physicalBytes, 0)
	return tensorCost{Hi: hi + carry, Lo: lo}
}

// effectiveWriteLambda is the explicit write lambda, or the decode lambda when
// the caller did not set one (so --lambda-ns prices both).
func (o TensorPlanOptions) effectiveWriteLambda() uint64 {
	if o.LambdaWriteNSSet {
		return o.LambdaWriteNS
	}
	return o.LambdaNS
}

// priceTensorWithWrite is the access-pattern objective:
//
//	physical + lambda_read*decode + lambda_write*encode
//
// Decode already accounts for reads_per_write; the encode is charged once for
// the plan's single write.
func priceTensorWithWrite(strategy TensorStrategy, physicalBytes, estimatedDecodeNS, size uint64, options TensorPlanOptions) tensorCost {
	cost := priceTensor(physicalBytes, estimatedDecodeNS, options.LambdaNS)
	encode := EstimateEncodeNS(strategy, size)
	hi, lo := bits.Mul64(options.effectiveWriteLambda(), encode)
	var carry uint64
	lo, carry = bits.Add64(cost.Lo, lo, 0)
	return tensorCost{Hi: cost.Hi + hi + carry, Lo: lo}
}

func (c tensorCost) less(other tensorCost) bool {
	if c.Hi != other.Hi {
		return c.Hi < other.Hi
	}
	return c.Lo < other.Lo
}

// saturatingMul mirrors Rust's `saturating_mul`.
func saturatingMul(a, b uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	if hi != 0 {
		return math.MaxUint64
	}
	return lo
}

// costClass maps a strategy to the shared decode-cost table.
func (s TensorStrategy) costClass() CostClass {
	switch s {
	case TensorStrategyRaw:
		return CostClassRaw
	case TensorStrategyZstd:
		return CostClassZstd
	case TensorStrategyFloatTensor:
		return CostClassFloatTensor
	case TensorStrategyFloatTiled:
		// Same per-tile geometry and Huffman exponent decode as mode 15; the
		// frozen calibration class set has no float-tiled row.
		return CostClassTensorTiled
	case TensorStrategyFloatTiledStreams:
		// Mode 18 has its own measured row (see EstimateMode18NS); the frozen
		// calibration class set has no mode-18 row.
		return CostClassTensorTiled
	case TensorStrategySharded:
		return CostClassTensorSharded
	case TensorStrategyWeightDelta:
		return CostClassWeightDelta
	case TensorStrategySparseDelta:
		return CostClassSparseDelta
	case TensorStrategySemanticDelta:
		return CostClassSemanticDelta
	case TensorStrategyKvCache:
		return CostClassKvCache
	case TensorStrategyActivation:
		return CostClassActivation
	default:
		return CostClassRaw
	}
}

// estimatedDecodeNS prices a candidate with the shared table, at the
// configured access pattern.
func estimatedDecodeNS(strategy TensorStrategy, size uint64, options TensorPlanOptions) uint64 {
	model := options.CostModel
	if model == "" {
		model = DefaultCostModel
	}
	var full uint64
	if strategy == TensorStrategyFloatTiledStreams && options.Cost == nil {
		full = EstimateMode18NS(size)
	} else {
		full = EstimateDecodeNSWith(strategy.costClass(), size, model, options.Cost)
	}
	tileIndependent := strategy == TensorStrategyFloatTiled ||
		strategy == TensorStrategyFloatTiledStreams
	estimate := func(bytes uint64) uint64 {
		if strategy == TensorStrategyFloatTiledStreams && options.Cost == nil {
			return EstimateMode18NS(bytes)
		}
		return EstimateDecodeNSWith(strategy.costClass(), bytes, model, options.Cost)
	}
	regionCost := func(regionBytes uint64) uint64 {
		if regionBytes > size {
			regionBytes = size
		}
		if tileIndependent {
			return estimate(regionBytes)
		}
		return full
	}
	switch options.AccessPattern.Kind {
	case AccessPatternRegion:
		reads := options.AccessPattern.ReadsPerWrite
		if reads == 0 {
			reads = 1
		}
		return saturatingMul(regionCost(options.AccessPattern.RegionBytes), reads)
	case AccessPatternMixed:
		whole := saturatingMul(full, options.AccessPattern.WholeReads)
		region := saturatingMul(regionCost(options.AccessPattern.RegionBytes), options.AccessPattern.RegionReads)
		if math.MaxUint64-whole < region {
			return math.MaxUint64
		}
		return whole + region
	default:
		return full
	}
}

// IsExperimental reports whether a strategy is experimental and therefore
// never auto-selected without an explicit opt-in.
func (s TensorStrategy) IsExperimental() bool {
	return s == TensorStrategyFloatTiledStreams
}

// tensorElementBytes is the logical element width used by tile accounting.
func tensorElementBytes(dtype string) uint64 {
	switch dtype {
	case "f16", "bf16", "i16":
		return 2
	case "f32", "i32":
		return 4
	case "f64", "i64":
		return 8
	default:
		return 1
	}
}

func ceilDiv(value, divisor uint64) uint64 {
	if divisor == 0 {
		return 0
	}
	return value/divisor + btoi(value%divisor != 0)
}

func btoi(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}

// tilesIntersected counts the whole tiles a leading row-major prefix read
// touches. It mirrors Rust's TileGeometry::tiles_intersected.
func tilesIntersected(shape, tileShape []uint64, elementBytes, regionBytes uint64) uint64 {
	if len(shape) == 0 || len(shape) != len(tileShape) {
		return 1
	}
	for _, extent := range shape {
		if extent == 0 {
			return 1
		}
	}
	for _, tile := range tileShape {
		if tile == 0 {
			return 1
		}
	}
	total := uint64(1)
	for axis := range shape {
		total = saturatingMul(total, ceilDiv(shape[axis], tileShape[axis]))
	}
	rowElements := uint64(1)
	for axis := 1; axis < len(shape); axis++ {
		rowElements = saturatingMul(rowElements, shape[axis])
	}
	if rowElements == 0 {
		return total
	}
	if elementBytes == 0 {
		elementBytes = 1
	}
	if regionBytes == 0 {
		regionBytes = 1
	}
	elements := ceilDiv(regionBytes, elementBytes)
	fullRows := elements / rowElements
	remainder := elements % rowElements
	if len(shape) == 1 {
		rows := elements
		if rows > shape[0] {
			rows = shape[0]
		}
		tiles := ceilDiv(rows, tileShape[0])
		if tiles > total {
			tiles = total
		}
		if tiles == 0 {
			tiles = 1
		}
		return tiles
	}
	var tiles uint64
	if remainder == 0 {
		rows := fullRows
		if rows < 1 {
			rows = 1
		}
		if rows > shape[0] {
			rows = shape[0]
		}
		tiles = ceilDiv(rows, tileShape[0])
		for axis := 1; axis < len(shape); axis++ {
			tiles = saturatingMul(tiles, ceilDiv(shape[axis], tileShape[axis]))
		}
	} else {
		rows := fullRows + 1
		if rows > shape[0] {
			rows = shape[0]
		}
		columns := remainder
		if columns > shape[1] {
			columns = shape[1]
		}
		tiles = saturatingMul(ceilDiv(rows, tileShape[0]), ceilDiv(columns, tileShape[1]))
		for axis := 2; axis < len(shape); axis++ {
			tiles = saturatingMul(tiles, ceilDiv(shape[axis], tileShape[axis]))
		}
	}
	if tiles > total {
		tiles = total
	}
	if tiles == 0 {
		tiles = 1
	}
	return tiles
}

// estimatedDecodeNSFor prices a candidate at the configured pattern, counting
// the whole tiles a region read intersects for tile-independent strategies.
func estimatedDecodeNSFor(strategy TensorStrategy, size uint64, options TensorPlanOptions, shape, tileShape []uint64, dtype string) uint64 {
	if strategy != TensorStrategyFloatTiled && strategy != TensorStrategyFloatTiledStreams {
		return estimatedDecodeNS(strategy, size, options)
	}
	if len(tileShape) == 0 {
		return estimatedDecodeNS(strategy, size, options)
	}
	model := options.CostModel
	if model == "" {
		model = DefaultCostModel
	}
	elementBytes := tensorElementBytes(dtype)
	tileElements := uint64(1)
	totalTiles := uint64(1)
	for _, tile := range tileShape {
		tileElements = saturatingMul(tileElements, tile)
	}
	tileBytes := saturatingMul(tileElements, elementBytes)
	for axis := range shape {
		if axis >= len(tileShape) {
			break
		}
		totalTiles = saturatingMul(totalTiles, ceilDiv(shape[axis], tileShape[axis]))
	}
	full := estimatedDecodeNS(strategy, size, options)
	perTile := func(bytes uint64) uint64 {
		if strategy == TensorStrategyFloatTiledStreams && options.Cost == nil {
			return EstimateMode18NS(bytes)
		}
		return EstimateDecodeNSWith(strategy.costClass(), bytes, model, options.Cost)
	}
	regionCost := func(regionBytes uint64) uint64 {
		tiles := tilesIntersected(shape, tileShape, elementBytes, regionBytes)
		if tiles == 0 {
			tiles = 1
		}
		_ = totalTiles
		return saturatingMul(perTile(tileBytes), tiles)
	}
	switch options.AccessPattern.Kind {
	case AccessPatternRegion:
		reads := options.AccessPattern.ReadsPerWrite
		if reads == 0 {
			reads = 1
		}
		return saturatingMul(regionCost(options.AccessPattern.RegionBytes), reads)
	case AccessPatternMixed:
		whole := saturatingMul(full, options.AccessPattern.WholeReads)
		region := saturatingMul(regionCost(options.AccessPattern.RegionBytes), options.AccessPattern.RegionReads)
		if math.MaxUint64-whole < region {
			return math.MaxUint64
		}
		return whole + region
	default:
		return full
	}
}

// isIndependent reports whether a representation stands alone.
func (s TensorStrategy) isIndependent() bool { return !s.usesDependency() }

// TensorLayoutSpec is a validated physical layout declaration for one tensor
// write. Bytes supplied with it are arranged in this physical order and are
// canonicalised to row-major before encoding, so the LogicalTensorRoot is
// layout-independent.
type TensorLayoutSpec struct {
	Layout tensor.Layout
}

// RowMajorTensorLayout declares canonical row-major input.
func RowMajorTensorLayout() TensorLayoutSpec {
	return TensorLayoutSpec{Layout: tensor.Layout{Kind: tensor.RowMajor}}
}

// ColumnMajorTensorLayout declares column-major input.
func ColumnMajorTensorLayout() TensorLayoutSpec {
	return TensorLayoutSpec{Layout: tensor.Layout{Kind: tensor.ColumnMajor}}
}

// BlockedTensorLayout declares blocked input in canonical grid order.
func BlockedTensorLayout(blockShape []uint64) TensorLayoutSpec {
	return TensorLayoutSpec{Layout: tensor.Layout{
		Kind:       tensor.Blocked,
		BlockShape: append([]uint64(nil), blockShape...),
	}}
}

// ShardedTensorLayout declares a single-shard input.
func ShardedTensorLayout(axis, shards, index uint32) TensorLayoutSpec {
	return TensorLayoutSpec{Layout: tensor.Layout{
		Kind: tensor.Sharded, Axis: axis, Shards: shards, Index: index,
	}}
}

// Name returns the canonical layout name.
func (s TensorLayoutSpec) Name() string { return s.Layout.Name() }

// Descriptor returns the canonical layout record for a dtype and shape.
func (s TensorLayoutSpec) Descriptor(dtype string, shape []uint64) tensor.Descriptor {
	return tensor.Descriptor{
		Dtype:  dtype,
		Shape:  append([]uint64(nil), shape...),
		Layout: s.Layout,
	}
}

// WCBValue returns the canonical `weft.tensor.layout.v1` map. The dtype is the
// manifest spelling (q8_0/q4_0 included), not the physical core dtype.
func (s TensorLayoutSpec) WCBValue(dtype string, shape []uint64) wcb.Value {
	return s.Descriptor(dtype, shape).WCBValue()
}

// Validate performs structural validation against a dtype and shape.
func (s TensorLayoutSpec) Validate(dtype string, shape []uint64) error {
	lim := limits.Default()
	if _, err := tensor.ValidateShape(shape, lim); err != nil {
		return werr.FromCodec(err)
	}
	physical, ok := model.TensorPhysicalDtype(dtype)
	if !ok {
		return werr.Newf(werr.Unsupported,
			"tensor dtype `%s` has no physical layout dtype", dtype)
	}
	if err := s.Descriptor(physical, shape).Validate(lim); err != nil {
		return werr.FromCodec(err)
	}
	if s.Layout.Kind == tensor.Sharded {
		if s.Layout.Shards > 1 {
			return werr.Newf(werr.InvalidArgument,
				"a kind:\"tensor\" manifest names exactly one frame; a sharded write with "+
					"%d shards is not a single object (axis %d, index %d)",
				s.Layout.Shards, s.Layout.Axis, s.Layout.Index)
		}
		if s.Layout.Index != 0 {
			return werr.Newf(werr.InvalidArgument,
				"a single-object sharded layout must use index 0")
		}
	}
	return nil
}

// Canonicalize reassembles supplied physical bytes into row-major order.
func (s TensorLayoutSpec) Canonicalize(dtype string, shape []uint64, bytesValue []byte) ([]byte, error) {
	lim := limits.Default()
	physical, ok := model.TensorPhysicalDtype(dtype)
	if !ok {
		return nil, werr.Newf(werr.Unsupported,
			"tensor dtype `%s` has no physical layout dtype", dtype)
	}
	elementCount, err := tensor.ValidateShape(shape, lim)
	if err != nil {
		return nil, werr.FromCodec(err)
	}
	logicalLen, err := tensor.PayloadLen(elementCount, physical)
	if err != nil {
		return nil, werr.FromCodec(err)
	}
	if logicalLen != uint64(len(bytesValue)) {
		return nil, werr.Newf(werr.Malformed,
			"tensor payload is %d bytes but %s x %d requires %d",
			len(bytesValue), dtype, len(shape), logicalLen)
	}
	switch s.Layout.Kind {
	case tensor.RowMajor:
		if _, err := tensor.CheckPayload(physical, shape, bytesValue, lim); err != nil {
			return nil, werr.FromCodec(err)
		}
		return append([]byte(nil), bytesValue...), nil
	case tensor.ColumnMajor:
		physicalTensor, err := tensor.NewColumnMajor(physical, shape, bytesValue, lim)
		if err != nil {
			return nil, werr.FromCodec(err)
		}
		out, err := physicalTensor.AssembleWithLimits(lim)
		if err != nil {
			return nil, werr.FromCodec(err)
		}
		return out, nil
	case tensor.Blocked:
		extents, err := tensor.BlockExtents(shape, s.Layout.BlockShape)
		if err != nil {
			return nil, werr.FromCodec(err)
		}
		elementBytes, _ := model.TensorElementBytes(dtype)
		blocks := make([][]byte, 0, len(extents))
		cursor := 0
		for _, extent := range extents {
			count := uint64(1)
			for _, dim := range extent {
				if dim != 0 && count > math.MaxUint64/dim {
					return nil, werr.Newf(werr.LimitExceeded, "block payload length overflows")
				}
				count *= dim
			}
			length := count * elementBytes
			if length > uint64(len(bytesValue)-cursor) {
				return nil, werr.Newf(werr.Malformed, "blocked payload is truncated")
			}
			blocks = append(blocks, append([]byte(nil), bytesValue[cursor:cursor+int(length)]...))
			cursor += int(length)
		}
		if cursor != len(bytesValue) {
			return nil, werr.Newf(werr.Malformed, "blocked payload has trailing bytes")
		}
		physicalTensor, err := tensor.NewBlocked(physical, shape, s.Layout.BlockShape, blocks, lim)
		if err != nil {
			return nil, werr.FromCodec(err)
		}
		out, err := physicalTensor.AssembleWithLimits(lim)
		if err != nil {
			return nil, werr.FromCodec(err)
		}
		return out, nil
	case tensor.Sharded:
		if s.Layout.Shards != 1 {
			return nil, werr.Newf(werr.InvalidArgument,
				"a single-object tensor write requires shards == 1")
		}
		physicalTensor, err := tensor.NewSharded(physical, shape, s.Layout.Axis,
			[][]byte{append([]byte(nil), bytesValue...)}, lim)
		if err != nil {
			return nil, werr.FromCodec(err)
		}
		out, err := physicalTensor.AssembleWithLimits(lim)
		if err != nil {
			return nil, werr.FromCodec(err)
		}
		return out, nil
	default:
		return nil, werr.Newf(werr.Unsupported, "unknown tensor layout kind %d", s.Layout.Kind)
	}
}

// TensorLayoutFromWCB parses and validates a canonical `weft.tensor.layout.v1`
// map, returning the manifest dtype, shape, and layout.
func TensorLayoutFromWCB(value wcb.Value) (string, []uint64, TensorLayoutSpec, error) {
	var spec TensorLayoutSpec
	m, err := model.AsMap(value)
	if err != nil {
		return "", nil, spec, werr.Newf(werr.Malformed, "tensor layout must be a canonical WCB map")
	}
	schema, err := model.GetText(m, "schema")
	if err != nil {
		return "", nil, spec, err
	}
	if schema != tensor.LayoutSchema {
		return "", nil, spec, werr.Newf(werr.UnknownSchema,
			"tensor layout schema `%s` is not `%s`", schema, tensor.LayoutSchema)
	}
	dtypeText, err := model.GetText(m, "dtype")
	if err != nil {
		return "", nil, spec, err
	}
	dtype, err := model.ParseTensorDtype(dtypeText)
	if err != nil {
		return "", nil, spec, err
	}
	shape, err := tensorShapeField(m, "shape")
	if err != nil {
		return "", nil, spec, err
	}
	layoutName, err := model.GetText(m, "layout")
	if err != nil {
		return "", nil, spec, err
	}
	switch layoutName {
	case "row-major", "column-major":
		if err := model.CheckKeys(m, "schema", "dtype", "shape", "layout"); err != nil {
			return "", nil, spec, err
		}
		kind := tensor.RowMajor
		if layoutName == "column-major" {
			kind = tensor.ColumnMajor
		}
		spec.Layout = tensor.Layout{Kind: kind}
	case "blocked":
		if err := model.CheckKeys(m, "schema", "dtype", "shape", "layout", "block_shape"); err != nil {
			return "", nil, spec, err
		}
		blockShape, err := tensorShapeField(m, "block_shape")
		if err != nil {
			return "", nil, spec, err
		}
		spec.Layout = tensor.Layout{Kind: tensor.Blocked, BlockShape: blockShape}
	case "sharded":
		if err := model.CheckKeys(m, "schema", "dtype", "shape", "layout", "axis", "shards", "index"); err != nil {
			return "", nil, spec, err
		}
		axis, err := tensorU32Field(m, "axis")
		if err != nil {
			return "", nil, spec, err
		}
		shards, err := tensorU32Field(m, "shards")
		if err != nil {
			return "", nil, spec, err
		}
		index, err := tensorU32Field(m, "index")
		if err != nil {
			return "", nil, spec, err
		}
		spec.Layout = tensor.Layout{Kind: tensor.Sharded, Axis: axis, Shards: shards, Index: index}
	default:
		return "", nil, spec, werr.Newf(werr.Malformed, "unknown tensor layout `%s`", layoutName)
	}
	// Structural validation uses the physical dtype, exactly as Rust does.
	physical, ok := model.TensorPhysicalDtype(dtype)
	if !ok {
		return "", nil, spec, werr.Newf(werr.Unsupported,
			"tensor dtype `%s` is not physical", dtype)
	}
	if err := spec.Descriptor(physical, shape).Validate(limits.Default()); err != nil {
		return "", nil, spec, werr.FromCodec(err)
	}
	// Exact canonical re-encoding: any alternate spelling or key order is
	// rejected rather than silently normalised.
	canonical, err := wcb.Encode(spec.WCBValue(dtype, shape), limits.Default())
	if err != nil {
		return "", nil, spec, werr.FromCodec(err)
	}
	actual, err := wcb.Encode(value, limits.Default())
	if err != nil {
		return "", nil, spec, werr.FromCodec(err)
	}
	if string(canonical) != string(actual) {
		return "", nil, spec, werr.Newf(werr.NonCanonical,
			"tensor layout descriptor is not the canonical encoding of its fields")
	}
	return dtype, shape, spec, nil
}

func tensorShapeField(m map[string]wcb.Value, key string) ([]uint64, error) {
	items, err := model.GetArray(m, key)
	if err != nil {
		return nil, err
	}
	out := make([]uint64, 0, len(items))
	for _, item := range items {
		if item.Kind != wcb.U64 {
			return nil, werr.Newf(werr.Malformed, "%s must be an array of u64", key)
		}
		out = append(out, item.U)
	}
	return out, nil
}

func tensorU32Field(m map[string]wcb.Value, key string) (uint32, error) {
	value, err := model.GetU64(m, key)
	if err != nil {
		return 0, err
	}
	if value > math.MaxUint32 {
		return 0, werr.Newf(werr.Malformed, "%s does not fit u32", key)
	}
	return uint32(value), nil
}

// TensorPlanOptions are the planner options. The zero value is bytes-only.
type TensorPlanOptions struct {
	// LambdaNS is the number of bytes charged per estimated nanosecond of
	// decode time. 0 is bytes-only.
	LambdaNS uint64
	// LambdaWriteNS is the number of bytes charged per estimated nanosecond of
	// encode time. When LambdaWriteNSSet is false it tracks LambdaNS, so a
	// bytes-only plan is unchanged and a latency-priced plan pays for its
	// one-time encode.
	LambdaWriteNS uint64
	// LambdaWriteNSSet records whether LambdaWriteNS was set explicitly.
	LambdaWriteNSSet bool
	// AllowExperimentalModes permits experimental representations (mode 18) to
	// be auto-selected. Default false: mode 18 stays selectable only by an
	// explicit strategy hint.
	AllowExperimentalModes bool
	// NoZstd19 disables the level-19 ZSTD candidate (the zero value offers it).
	NoZstd19 bool
	// Zstd19CPUBudgetNS bounds the estimated level-19 encode time (0 = the
	// 20 s default).
	Zstd19CPUBudgetNS uint64
	// CostModel selects the decode-cost table. The empty value means
	// DefaultCostModel (measured).
	CostModel CostModelKind
	// Cost is an explicit host calibration table. When non-nil it wins over
	// CostModel; it is only set by `--calibration` after strict validation.
	Cost *CostTable
	// MaxCandidates bounds the semantic search (unused by the B2 writer).
	MaxCandidates int
	// Candidates are explicit tensor ObjectIds for the semantic search (unused
	// by the B2 writer).
	Candidates []model.Hash32
	// TileShape enables the mode-17 FLOAT_TILED candidate. Empty skips it,
	// matching the Rust planner's explicit opt-in.
	TileShape []uint64
	// AccessPattern is the pattern the decode estimate is priced for. The zero
	// value is Whole and reproduces the historical plan exactly.
	AccessPattern AccessPattern
	// NStreams is the mode-18 interleaved stream count. 0 uses
	// modes.FloatTiledStreamsDefault (4).
	NStreams uint64
}

// zstd19MinBytes and zstd19CPUBudgetNS mirror the Rust defaults.
const (
	zstd19MinBytes    uint64 = 1024 * 1024
	zstd19CPUBudgetNS uint64 = 20_000_000_000
)

// TensorWriteSpec is the option set for one tensor write.
type TensorWriteSpec struct {
	// StrategyHint is nil to run the planner, or a required strategy.
	StrategyHint *TensorStrategy
	// Causal are causal parent version ids (weight-delta bases).
	Causal []model.Hash32
	// Plan holds planner options.
	Plan TensorPlanOptions
}

// TensorPlanCandidate is one priced planner candidate.
type TensorPlanCandidate struct {
	Strategy          TensorStrategy
	Applicable        bool
	Detail            string
	PhysicalBytes     *uint64
	EstimatedDecodeNS *uint64
	// EstimatedEncodeNS is the one-time whole-tensor encode cost from the
	// shared write-cost table (see EncodeCalibration).
	EstimatedEncodeNS *uint64
	Cost              *tensorCost
	// Dependency is the base content root for weight-delta candidates.
	Dependency *model.Hash32
}

// TensorPlan is the complete planner decision, including the runner-up.
type TensorPlan struct {
	Chosen                    TensorStrategy
	ChosenPhysicalBytes       uint64
	ChosenEstimatedDecodeNS   uint64
	ChosenEstimatedEncodeNS   uint64
	ChosenCost                tensorCost
	RunnerUp                  *TensorStrategy
	RunnerUpPhysicalBytes     *uint64
	RunnerUpEstimatedDecodeNS *uint64
	RunnerUpEstimatedEncodeNS *uint64
	RunnerUpCost              *tensorCost
	Candidates                []TensorPlanCandidate
}

// StoredTensorMetadata is tensor identity recovered from an object record.
type StoredTensorMetadata struct {
	Dtype       string
	Shape       []uint64
	LogicalRoot model.Hash32
	Layout      TensorLayoutSpec
	Strategy    string
}

type tensorArtifact struct {
	Kind         model.RepresentationKind
	StrategyName string
	Frame        []byte
	Dependencies []model.Hash32
	Tensor       *model.TensorRepresentation
}

type preparedTensorCandidate struct {
	candidate TensorPlanCandidate
	artifact  *tensorArtifact
}

func skippedTensor(strategy TensorStrategy, detail string) preparedTensorCandidate {
	return preparedTensorCandidate{
		candidate: TensorPlanCandidate{
			Strategy: strategy, Applicable: false, Detail: detail,
		},
	}
}

// WriteTensorFile writes one logical tensor as a new file object. `bytes` are
// arranged per `layout`; the store canonicalises them to row-major before
// encoding. A nil strategy hint runs the planner.
func (s *Store) WriteTensorFile(
	parent model.Hash32,
	name []byte,
	dtype string,
	shape []uint64,
	bytesValue []byte,
	layout TensorLayoutSpec,
	strategyHint *TensorStrategy,
) (model.Hash32, error) {
	spec := TensorWriteSpec{StrategyHint: strategyHint}
	return s.WriteTensorFileWithSpec(parent, name, dtype, shape, bytesValue, layout, spec)
}

// WriteTensorFileWithSpec writes one logical tensor with explicit causal and
// planner options.
func (s *Store) WriteTensorFileWithSpec(
	parent model.Hash32,
	name []byte,
	dtypeText string,
	shape []uint64,
	bytesValue []byte,
	layout TensorLayoutSpec,
	spec TensorWriteSpec,
) (model.Hash32, error) {
	if err := s.requireWritable(); err != nil {
		return model.Hash32{}, err
	}
	if err := s.requireDir(parent); err != nil {
		return model.Hash32{}, err
	}
	if err := model.ValidateNameBytes(name); err != nil {
		return model.Hash32{}, err
	}
	if err := s.requireFreeName(parent, name); err != nil {
		return model.Hash32{}, err
	}
	dtype, err := model.ParseTensorDtype(dtypeText)
	if err != nil {
		return model.Hash32{}, err
	}
	if err := layout.Validate(dtype, shape); err != nil {
		return model.Hash32{}, err
	}
	logical, err := layout.Canonicalize(dtype, shape, bytesValue)
	if err != nil {
		return model.Hash32{}, err
	}
	allowExperimental := spec.Plan.AllowExperimentalModes ||
		(spec.StrategyHint != nil && spec.StrategyHint.IsExperimental())
	prepared, err := s.prepareTensorCandidates(dtype, shape, logical, layout, spec.Causal, spec.Plan, false, allowExperimental)
	if err != nil {
		return model.Hash32{}, err
	}
	chosen, err := chooseTensorCandidate(prepared, spec.StrategyHint)
	if err != nil {
		return model.Hash32{}, err
	}
	if chosen.artifact == nil {
		return model.Hash32{}, werr.Newf(werr.InvalidArgument,
			"chosen tensor strategy has no artifact")
	}
	artifact := *chosen.artifact
	root := model.Hash32{}
	if artifact.Tensor != nil {
		root = artifact.Tensor.LogicalRoot
	} else {
		root, err = logicalRootForBytes(dtype, shape, logical)
		if err != nil {
			return model.Hash32{}, err
		}
	}
	manifestID, contentHash, size, err := s.storeTensorArtifact(dtype, shape, logical, layout, &artifact)
	if err != nil {
		return model.Hash32{}, err
	}
	attrs := map[string]wcb.Value{}
	if err := applyTensorAttrs(attrs, dtype, shape, root, layout, artifact.StrategyName); err != nil {
		return model.Hash32{}, err
	}
	seed, err := randomSeed()
	if err != nil {
		return model.Hash32{}, err
	}
	return s.commitTensorFile(parent, name, manifestID, contentHash, size, attrs, spec.Causal, seed)
}

// TensorIndependentPlan is the priced decision among standalone
// representations (the rebase planner's input).
type TensorIndependentPlan struct {
	Chosen          TensorStrategy
	PhysicalBytes   uint64
	EstimatedDecode uint64
	Cost            tensorCost
	Candidates      []TensorPlanCandidate
}

// TensorRebase is the result of re-publishing one tensor with a standalone
// representation. Logical bytes are unchanged; the content root (manifest id)
// changes because the representation changed.
type TensorRebase struct {
	OldVersion  model.Hash32
	NewVersion  model.Hash32
	OldContent  model.Hash32
	NewContent  model.Hash32
	OldStrategy string
	Plan        TensorIndependentPlan
}

// PlanTensorIndependent prices only standalone representations of an existing
// tensor object (deltas excluded).
func (s *Store) PlanTensorIndependent(
	id model.Hash32,
	options TensorPlanOptions,
	hint *TensorStrategy,
) (TensorIndependentPlan, error) {
	meta, err := s.TensorMetadata(id)
	if err != nil {
		return TensorIndependentPlan{}, err
	}
	logical, err := s.readObjectUncounted(id)
	if err != nil {
		return TensorIndependentPlan{}, err
	}
	prepared, err := s.prepareTensorCandidates(
		meta.Dtype, meta.Shape, logical, meta.Layout, nil, options, true,
		options.AllowExperimentalModes || (hint != nil && hint.IsExperimental()))
	if err != nil {
		return TensorIndependentPlan{}, err
	}
	chosen, err := chooseTensorCandidate(prepared, hint)
	if err != nil {
		return TensorIndependentPlan{}, err
	}
	plan := TensorIndependentPlan{
		Chosen:     chosen.candidate.Strategy,
		Candidates: make([]TensorPlanCandidate, 0, len(prepared)),
	}
	if chosen.candidate.PhysicalBytes != nil {
		plan.PhysicalBytes = *chosen.candidate.PhysicalBytes
	}
	if chosen.candidate.EstimatedDecodeNS != nil {
		plan.EstimatedDecode = *chosen.candidate.EstimatedDecodeNS
	}
	if chosen.candidate.Cost != nil {
		plan.Cost = *chosen.candidate.Cost
	}
	for _, item := range prepared {
		plan.Candidates = append(plan.Candidates, item.candidate)
	}
	return plan, nil
}

// RebaseTensorObject publishes a new version with a standalone representation.
// The previous version and every snapshot are untouched.
func (s *Store) RebaseTensorObject(
	id model.Hash32,
	options TensorPlanOptions,
	hint *TensorStrategy,
) (TensorRebase, error) {
	if err := s.requireWritable(); err != nil {
		return TensorRebase{}, err
	}
	meta, err := s.TensorMetadata(id)
	if err != nil {
		return TensorRebase{}, err
	}
	old, err := s.ObjectMeta(id)
	if err != nil {
		return TensorRebase{}, err
	}
	logical, err := s.readObjectUncounted(id)
	if err != nil {
		return TensorRebase{}, err
	}
	prepared, err := s.prepareTensorCandidates(
		meta.Dtype, meta.Shape, logical, meta.Layout, nil, options, true,
		options.AllowExperimentalModes || (hint != nil && hint.IsExperimental()))
	if err != nil {
		return TensorRebase{}, err
	}
	chosen, err := chooseTensorCandidate(prepared, hint)
	if err != nil {
		return TensorRebase{}, err
	}
	if chosen.artifact == nil {
		return TensorRebase{}, werr.Newf(werr.InvalidArgument,
			"chosen tensor strategy has no artifact")
	}
	root, err := chosenRoot(chosen, s, meta, logical)
	if err != nil {
		return TensorRebase{}, err
	}
	manifestID, _, size, err := s.storeTensorArtifact(
		meta.Dtype, meta.Shape, logical, meta.Layout, chosen.artifact)
	if err != nil {
		return TensorRebase{}, err
	}
	attrs := model.CloneAttrs(old.Attrs)
	if err := applyTensorAttrs(attrs, meta.Dtype, meta.Shape, root, meta.Layout,
		chosen.artifact.StrategyName); err != nil {
		return TensorRebase{}, err
	}
	newVersion, err := s.publishTensorVersion(
		id, old, manifestID, size, []model.Hash32{old.Version}, attrs)
	if err != nil {
		return TensorRebase{}, err
	}
	newRecord, err := s.ObjectMeta(id)
	if err != nil {
		return TensorRebase{}, err
	}
	plan := TensorIndependentPlan{
		Chosen:     chosen.candidate.Strategy,
		Candidates: make([]TensorPlanCandidate, 0, len(prepared)),
	}
	if chosen.candidate.PhysicalBytes != nil {
		plan.PhysicalBytes = *chosen.candidate.PhysicalBytes
	}
	if chosen.candidate.EstimatedDecodeNS != nil {
		plan.EstimatedDecode = *chosen.candidate.EstimatedDecodeNS
	}
	if chosen.candidate.Cost != nil {
		plan.Cost = *chosen.candidate.Cost
	}
	for _, item := range prepared {
		plan.Candidates = append(plan.Candidates, item.candidate)
	}
	return TensorRebase{
		OldVersion:  old.Version,
		NewVersion:  newVersion,
		OldContent:  old.Content,
		NewContent:  newRecord.Content,
		OldStrategy: meta.Strategy,
		Plan:        plan,
	}, nil
}

func chosenRoot(
	chosen preparedTensorCandidate,
	s *Store,
	meta StoredTensorMetadata,
	logical []byte,
) (model.Hash32, error) {
	if chosen.artifact != nil && chosen.artifact.Tensor != nil {
		return chosen.artifact.Tensor.LogicalRoot, nil
	}
	return logicalRootForBytes(meta.Dtype, meta.Shape, logical)
}

func (s *Store) publishTensorVersion(
	id model.Hash32,
	old model.ObjectRecord,
	manifestID model.Hash32,
	newSize uint64,
	causal []model.Hash32,
	attrs map[string]wcb.Value,
) (model.Hash32, error) {
	attrs, identityMode, causalHash, closure, err := s.prepareCausal(attrs, causal)
	if err != nil {
		return model.Hash32{}, err
	}
	if closure != nil {
		if err := s.storeCausalClosure(closure); err != nil {
			return model.Hash32{}, err
		}
	}
	mtime := s.nowNS()
	version, err := model.DeriveVersionIDWithIdentity(
		id, manifestID, newSize, mtime, hashPtr(old.Version), identityMode, causalHash)
	if err != nil {
		return model.Hash32{}, err
	}
	record := old.Clone()
	record.Version = version
	record.MtimeNS = mtime
	record.Content = manifestID
	record.Size = newSize
	record.Attrs = attrs
	ops := []model.Op{
		model.PutObjectOp{Record: record},
		model.SetTipOp{Object: id, Version: version},
	}
	if _, err := s.commitOps(ops, false); err != nil {
		return model.Hash32{}, err
	}
	return version, nil
}

// PlanTensor prices every applicable strategy without writing anything.
func (s *Store) PlanTensor(
	dtypeText string,
	shape []uint64,
	bytesValue []byte,
	layout TensorLayoutSpec,
	causal []model.Hash32,
	options TensorPlanOptions,
) (TensorPlan, error) {
	dtype, err := model.ParseTensorDtype(dtypeText)
	if err != nil {
		return TensorPlan{}, err
	}
	if err := layout.Validate(dtype, shape); err != nil {
		return TensorPlan{}, err
	}
	logical, err := layout.Canonicalize(dtype, shape, bytesValue)
	if err != nil {
		return TensorPlan{}, err
	}
	prepared, err := s.prepareTensorCandidates(dtype, shape, logical, layout, causal, options, false, options.AllowExperimentalModes)
	if err != nil {
		return TensorPlan{}, err
	}
	chosen, err := chooseTensorCandidate(prepared, nil)
	if err != nil {
		return TensorPlan{}, err
	}
	applicable := make([]preparedTensorCandidate, 0, len(prepared))
	for _, item := range prepared {
		if item.candidate.Applicable {
			applicable = append(applicable, item)
		}
	}
	sortTensorCandidates(applicable)
	var runnerUp *preparedTensorCandidate
	for index := range applicable {
		if applicable[index].candidate.Strategy != chosen.candidate.Strategy {
			runnerUp = &applicable[index]
			break
		}
	}
	plan := TensorPlan{
		Chosen:     chosen.candidate.Strategy,
		Candidates: make([]TensorPlanCandidate, 0, len(prepared)),
	}
	if chosen.candidate.PhysicalBytes != nil {
		plan.ChosenPhysicalBytes = *chosen.candidate.PhysicalBytes
	}
	if chosen.candidate.EstimatedDecodeNS != nil {
		plan.ChosenEstimatedDecodeNS = *chosen.candidate.EstimatedDecodeNS
	}
	if chosen.candidate.EstimatedEncodeNS != nil {
		plan.ChosenEstimatedEncodeNS = *chosen.candidate.EstimatedEncodeNS
	}
	if chosen.candidate.Cost != nil {
		plan.ChosenCost = *chosen.candidate.Cost
	}
	if runnerUp != nil {
		strategy := runnerUp.candidate.Strategy
		plan.RunnerUp = &strategy
		plan.RunnerUpPhysicalBytes = runnerUp.candidate.PhysicalBytes
		plan.RunnerUpEstimatedDecodeNS = runnerUp.candidate.EstimatedDecodeNS
		plan.RunnerUpEstimatedEncodeNS = runnerUp.candidate.EstimatedEncodeNS
		plan.RunnerUpCost = runnerUp.candidate.Cost
	}
	for _, item := range prepared {
		plan.Candidates = append(plan.Candidates, item.candidate)
	}
	return plan, nil
}

func sortTensorCandidates(items []preparedTensorCandidate) {
	sort.SliceStable(items, func(i, j int) bool {
		left, right := items[i].candidate, items[j].candidate
		if left.Cost != nil && right.Cost != nil {
			if left.Cost.less(*right.Cost) {
				return true
			}
			if right.Cost.less(*left.Cost) {
				return false
			}
		}
		return tensorStrategyRank(left.Strategy) < tensorStrategyRank(right.Strategy)
	})
}

// ---- planner internals ----------------------------------------------------

func (s *Store) prepareTensorCandidates(
	dtype string,
	shape []uint64,
	logical []byte,
	layout TensorLayoutSpec,
	causal []model.Hash32,
	options TensorPlanOptions,
	independentOnly bool,
	allowExperimental bool,
) ([]preparedTensorCandidate, error) {
	lim := limits.Default()
	size := uint64(len(logical))
	var out []preparedTensorCandidate

	// q8_0's additive LogicalTensorRoot binds the mode-10 scale plane, so it is
	// only stored through mode 10. q4_0 store support is not implemented in B2.
	if dtype == "q4_0" {
		return nil, werr.Newf(werr.InvalidArgument,
			"q4_0 tensor storage is not implemented; use q8_0 or a full-precision dtype")
	}
	quantized := dtype == "q8_0"

	// Raw chunks (v2 kind:"raw").
	if quantized {
		out = append(out, skippedTensor(TensorStrategyRaw,
			"q8_0 identity requires the mode-10 scale plane"))
	} else {
		out = append(out, preparedTensorCandidate{
			candidate: TensorPlanCandidate{
				Strategy: TensorStrategyRaw, Applicable: true,
				Detail:            "canonical row-major chunks",
				PhysicalBytes:     uint64Ptr(size),
				EstimatedDecodeNS: uint64Ptr(estimatedDecodeNS(TensorStrategyRaw, size, options)),
				EstimatedEncodeNS: uint64Ptr(EstimateEncodeNS(TensorStrategyRaw, size)),
				Cost:              costPtr(priceTensorWithWrite(TensorStrategyRaw, size, estimatedDecodeNS(TensorStrategyRaw, size, options), size, options)),
			},
			artifact: &tensorArtifact{
				Kind: model.RepresentationRaw, StrategyName: model.StrategyRaw,
			},
		})
	}

	// Zstandard frame.
	codecChunk := codecChunkSize(s.options.ChunkSize)
	if quantized {
		out = append(out, skippedTensor(TensorStrategyZstd,
			"q8_0 identity requires the mode-10 scale plane"))
	} else if codecChunk > uint64(math.MaxInt) {
		out = append(out, skippedTensor(TensorStrategyZstd, "codec chunk size overflows int"))
	} else if zstdFrame, err := modes.EncodeZstd(logical, CodecZstdLevel, int(codecChunk), lim); err != nil {
		out = append(out, skippedTensor(TensorStrategyZstd, err.Error()))
	} else {
		physical := uint64(len(zstdFrame))
		estimate := estimatedDecodeNS(TensorStrategyZstd, size, options)
		out = append(out, preparedTensorCandidate{
			candidate: TensorPlanCandidate{
				Strategy: TensorStrategyZstd, Applicable: true,
				Detail:            "one ZSTD frame",
				PhysicalBytes:     uint64Ptr(physical),
				EstimatedDecodeNS: uint64Ptr(estimate),
				EstimatedEncodeNS: uint64Ptr(EstimateEncodeNS(TensorStrategyZstd, size)),
				Cost:              costPtr(priceTensorWithWrite(TensorStrategyZstd, physical, estimate, size, options)),
			},
			artifact: &tensorArtifact{
				Kind: model.RepresentationCodec, StrategyName: model.StrategyZstd,
				Frame: zstdFrame,
			},
		})
	}

	// ZSTD level 19: the same frozen ZSTD mode encoded again at a much slower
	// setting. Only offered by the planned policy, above the size threshold,
	// and inside the CPU budget. Mirrors the Rust candidate.
	// Go has no separate fast write policy; the candidate is offered whenever
	// the caller did not disable it and the bounds hold.
	if !quantized && !options.NoZstd19 && size >= zstd19MinBytes {
		budget := options.Zstd19CPUBudgetNS
		if budget == 0 {
			budget = zstd19CPUBudgetNS
		}
		encodeNS := EstimateEncodeNSClass(EncodeClassZstd19, size)
		if encodeNS <= budget {
			if frameBytes, err := modes.EncodeZstd(logical, 19, int(codecChunk), lim); err == nil {
				physical := uint64(len(frameBytes))
				estimate := estimatedDecodeNS(TensorStrategyZstd, size, options)
				encoded := encodeNS
				out = append(out, preparedTensorCandidate{
					candidate: TensorPlanCandidate{
						Strategy: TensorStrategyZstd, Applicable: true,
						Detail:            "one ZSTD level-19 frame",
						PhysicalBytes:     uint64Ptr(physical),
						EstimatedDecodeNS: uint64Ptr(estimate),
						EstimatedEncodeNS: &encoded,
						Cost:              costPtr(priceTensorWithWrite(TensorStrategyZstd, physical, estimate, size, options)),
					},
					artifact: &tensorArtifact{
						Kind: model.RepresentationCodec, StrategyName: model.StrategyZstd,
						Frame: frameBytes,
					},
				})
			}
		}
	}

	// Mode 9 FLOAT_TENSOR. Offered for byte-aligned float dtypes; priced only
	// when it saves at least 1/64 of the zstd frame (mode 9 decodes ~19x
	// slower). This mirrors the Rust planner exactly.
	var zstdPhysical *uint64
	for index := range out {
		if out[index].candidate.Strategy == TensorStrategyZstd && out[index].candidate.Applicable {
			zstdPhysical = out[index].candidate.PhysicalBytes
			break
		}
	}
	if floatDtype, ok := floatTensorDtype(dtype); !ok {
		out = append(out, skippedTensor(TensorStrategyFloatTensor,
			"dtype "+dtype+" has no mode-9 float layout"))
	} else if frameBytes, err := modes.EncodeFloatTensor(logical, floatDtype, shape, lim); err != nil {
		out = append(out, skippedTensor(TensorStrategyFloatTensor, err.Error()))
	} else {
		physical := uint64(len(frameBytes))
		worthwhile := true
		if zstdPhysical != nil {
			worthwhile = saturatingMul(physical, 64) <= saturatingMul(*zstdPhysical, 63)
		}
		if !worthwhile {
			out = append(out, skippedTensor(TensorStrategyFloatTensor,
				"mode 9 saves less than 1/64 of the zstd frame; not worth the decode cost"))
		} else {
			root, err := logicalRootForBytes(dtype, shape, logical)
			if err != nil {
				return nil, err
			}
			estimate := estimatedDecodeNS(TensorStrategyFloatTensor, size, options)
			out = append(out, preparedTensorCandidate{
				candidate: TensorPlanCandidate{
					Strategy: TensorStrategyFloatTensor, Applicable: true,
					Detail:            "one mode-9 FLOAT_TENSOR frame (" + floatDtype.Name + ")",
					PhysicalBytes:     uint64Ptr(physical),
					EstimatedDecodeNS: uint64Ptr(estimate),
					EstimatedEncodeNS: uint64Ptr(EstimateEncodeNS(TensorStrategyFloatTensor, size)),
					Cost:              costPtr(priceTensorWithWrite(TensorStrategyFloatTensor, physical, estimate, size, options)),
				},
				artifact: &tensorArtifact{
					Kind: model.RepresentationTensor, StrategyName: TensorStrategyFloatTensor.String(),
					Frame: frameBytes,
					Tensor: &model.TensorRepresentation{
						Mode: 9, Dtype: dtype, Shape: append([]uint64(nil), shape...),
						LogicalRoot: root, Layout: layout.WCBValue(dtype, shape),
					},
				},
			})
		}
	}

	// Mode 17 FLOAT_TILED: the per-tile mode-9 plane split. Offered only when
	// the caller names a tile shape and the dtype has both a mode-9 layout and
	// a logical-tensor identity (bf16/fp16/fp32).
	if len(options.TileShape) == 0 {
		out = append(out, skippedTensor(TensorStrategyFloatTiled, "no tile shape supplied"))
	} else if floatDtype, ok := floatTensorDtype(dtype); !ok {
		out = append(out, skippedTensor(TensorStrategyFloatTiled,
			"dtype "+dtype+" has no mode-9 float layout"))
	} else if floatDtype.Name != "bf16" && floatDtype.Name != "fp16" && floatDtype.Name != "fp32" {
		out = append(out, skippedTensor(TensorStrategyFloatTiled,
			floatDtype.Name+" has no logical-tensor identity layout for mode 17"))
	} else if frameBytes, err := modes.EncodeFloatTiled(logical, floatDtype, shape, options.TileShape, lim); err != nil {
		out = append(out, skippedTensor(TensorStrategyFloatTiled, err.Error()))
	} else if parsed, err := frame.Parse(frameBytes, lim); err != nil {
		out = append(out, skippedTensor(TensorStrategyFloatTiled, err.Error()))
	} else if descriptor, err := modes.ParseFloatTiled(parsed, lim); err != nil {
		out = append(out, skippedTensor(TensorStrategyFloatTiled, err.Error()))
	} else {
		physical := uint64(len(frameBytes))
		estimate := estimatedDecodeNSFor(TensorStrategyFloatTiled, size, options, shape, options.TileShape, dtype)
		out = append(out, preparedTensorCandidate{
			candidate: TensorPlanCandidate{
				Strategy: TensorStrategyFloatTiled, Applicable: true,
				Detail:            "one mode-17 float-tiled frame",
				PhysicalBytes:     uint64Ptr(physical),
				EstimatedDecodeNS: uint64Ptr(estimate),
				EstimatedEncodeNS: uint64Ptr(EstimateEncodeNS(TensorStrategyFloatTiled, size)),
				Cost:              costPtr(priceTensorWithWrite(TensorStrategyFloatTiled, physical, estimate, size, options)),
			},
			artifact: &tensorArtifact{
				Kind: model.RepresentationTensor, StrategyName: TensorStrategyFloatTiled.String(),
				Frame: frameBytes,
				Tensor: &model.TensorRepresentation{
					Mode: 17, Dtype: dtype, Shape: append([]uint64(nil), shape...),
					LogicalRoot: descriptor.Meta.LogicalRoot, Layout: layout.WCBValue(dtype, shape),
				},
			},
		})
	}

	// Mode 18 FLOAT_TILED_STREAMS: multi-stream interleaved per-tile split.
	// Same tile opt-in as mode 17; the bytes-only default keeps choosing the
	// strictly smaller representation because mode 18 pays one 256-byte table
	// per exponent stream.
	//
	// EXPERIMENTAL GATE: mode 18 lost every measured axis, so it is never
	// auto-selected. It is prepared (and therefore selectable) only when the
	// caller opted in with --allow-experimental-modes or named the strategy.
	if !allowExperimental {
		out = append(out, skippedTensor(TensorStrategyFloatTiledStreams,
			"experimental: mode 18 is not auto-selected; pass --allow-experimental-modes or name the strategy"))
	} else if len(options.TileShape) == 0 {
		out = append(out, skippedTensor(TensorStrategyFloatTiledStreams, "no tile shape supplied"))
	} else if floatDtype, ok := floatTensorDtype(dtype); !ok {
		out = append(out, skippedTensor(TensorStrategyFloatTiledStreams,
			"dtype "+dtype+" has no mode-9 float layout"))
	} else if floatDtype.Name != "bf16" && floatDtype.Name != "fp16" && floatDtype.Name != "fp32" {
		out = append(out, skippedTensor(TensorStrategyFloatTiledStreams,
			floatDtype.Name+" has no logical-tensor identity layout for mode 18"))
	} else {
		nStreams := options.NStreams
		if nStreams == 0 {
			nStreams = modes.FloatTiledStreamsDefault
		}
		frameBytes, err := modes.EncodeFloatTiledStreams(
			logical, floatDtype, shape, options.TileShape, nStreams, lim)
		if err != nil {
			out = append(out, skippedTensor(TensorStrategyFloatTiledStreams, err.Error()))
		} else if parsed, err := frame.Parse(frameBytes, lim); err != nil {
			out = append(out, skippedTensor(TensorStrategyFloatTiledStreams, err.Error()))
		} else if descriptor, err := modes.ParseFloatTiledStreams(parsed, lim); err != nil {
			out = append(out, skippedTensor(TensorStrategyFloatTiledStreams, err.Error()))
		} else {
			physical := uint64(len(frameBytes))
			estimate := estimatedDecodeNSFor(TensorStrategyFloatTiledStreams, size, options, shape, options.TileShape, dtype)
			out = append(out, preparedTensorCandidate{
				candidate: TensorPlanCandidate{
					Strategy: TensorStrategyFloatTiledStreams, Applicable: true,
					Detail:            fmt.Sprintf("one mode-18 float-tiled frame with %d streams", nStreams),
					PhysicalBytes:     uint64Ptr(physical),
					EstimatedDecodeNS: uint64Ptr(estimate),
					EstimatedEncodeNS: uint64Ptr(EstimateEncodeNS(TensorStrategyFloatTiledStreams, size)),
					Cost:              costPtr(priceTensorWithWrite(TensorStrategyFloatTiledStreams, physical, estimate, size, options)),
				},
				artifact: &tensorArtifact{
					Kind: model.RepresentationTensor, StrategyName: TensorStrategyFloatTiledStreams.String(),
					Frame: frameBytes,
					Tensor: &model.TensorRepresentation{
						Mode: 18, Dtype: dtype, Shape: append([]uint64(nil), shape...),
						LogicalRoot: descriptor.Meta.LogicalRoot, Layout: layout.WCBValue(dtype, shape),
					},
				},
			})
		}
	}

	// Mode 10 tensor-sharded, restricted to q8_0 (one whole-tensor shard).
	if quantized {
		frameBytes, root, err := s.prepareMode10(dtype, shape, logical, lim)
		if err != nil {
			out = append(out, skippedTensor(TensorStrategySharded, err.Error()))
		} else {
			physical := uint64(len(frameBytes))
			estimate := estimatedDecodeNS(TensorStrategySharded, size, options)
			out = append(out, preparedTensorCandidate{
				candidate: TensorPlanCandidate{
					Strategy: TensorStrategySharded, Applicable: true,
					Detail:            "one mode-10 shard (shard_count = 1)",
					PhysicalBytes:     uint64Ptr(physical),
					EstimatedDecodeNS: uint64Ptr(estimate),
					EstimatedEncodeNS: uint64Ptr(EstimateEncodeNS(TensorStrategySharded, size)),
					Cost:              costPtr(priceTensorWithWrite(TensorStrategySharded, physical, estimate, size, options)),
				},
				artifact: &tensorArtifact{
					Kind: model.RepresentationTensor, StrategyName: TensorStrategySharded.String(),
					Frame: frameBytes,
					Tensor: &model.TensorRepresentation{
						Mode: 10, Dtype: dtype, Shape: append([]uint64(nil), shape...),
						LogicalRoot: root, Layout: layout.WCBValue(dtype, shape),
					},
				},
			})
		}
	} else {
		out = append(out, skippedTensor(TensorStrategySharded,
			"mode 10 carries quantized tensors; "+dtype+" is not q8_0"))
	}

	// Mode 11 weight-delta against the causal parent.
	if independentOnly {
		out = append(out, skippedTensor(TensorStrategyWeightDelta,
			"rebase requires an independent representation"))
	} else {
		switch frameBytes, dependency, err := s.prepareDelta(dtype, shape, logical, causal, lim,
			TensorStrategyWeightDelta); {
		case err != nil:
			out = append(out, skippedTensor(TensorStrategyWeightDelta, err.Error()))
		case frameBytes == nil:
			out = append(out, skippedTensor(TensorStrategyWeightDelta,
				"no usable causal parent with the same dtype/shape"))
		default:
			physical := uint64(len(frameBytes))
			estimate := estimatedDecodeNS(TensorStrategyWeightDelta, size, options)
			root, err := logicalRootForBytes(dtype, shape, logical)
			if err != nil {
				return nil, err
			}
			out = append(out, preparedTensorCandidate{
				candidate: TensorPlanCandidate{
					Strategy: TensorStrategyWeightDelta, Applicable: true,
					Detail:            "mode 11 against the causal parent",
					PhysicalBytes:     uint64Ptr(physical),
					EstimatedDecodeNS: uint64Ptr(estimate),
					EstimatedEncodeNS: uint64Ptr(EstimateEncodeNS(TensorStrategyWeightDelta, size)),
					Cost:              costPtr(priceTensorWithWrite(TensorStrategyWeightDelta, physical, estimate, size, options)),
					Dependency:        dependency,
				},
				artifact: &tensorArtifact{
					Kind: model.RepresentationTensor, StrategyName: TensorStrategyWeightDelta.String(),
					Frame:        frameBytes,
					Dependencies: []model.Hash32{*dependency},
					Tensor: &model.TensorRepresentation{
						Mode: 11, Dtype: dtype, Shape: append([]uint64(nil), shape...),
						LogicalRoot: root, Layout: layout.WCBValue(dtype, shape),
					},
				},
			})
		}
	}

	// Mode 16 sparse-delta against the causal parent: the same exact delta as
	// mode 11, stored as a zero-run stream. The planner keeps mode 11 when its
	// Huffman planes are smaller (dense deltas) and mode 16 when the run stream
	// is smaller (sparse deltas).
	if independentOnly {
		out = append(out, skippedTensor(TensorStrategySparseDelta,
			"rebase requires an independent representation"))
	} else {
		switch frameBytes, dependency, err := s.prepareDelta(dtype, shape, logical, causal, lim,
			TensorStrategySparseDelta); {
		case err != nil:
			out = append(out, skippedTensor(TensorStrategySparseDelta, err.Error()))
		case frameBytes == nil:
			out = append(out, skippedTensor(TensorStrategySparseDelta,
				"no usable causal parent with the same dtype/shape"))
		default:
			physical := uint64(len(frameBytes))
			estimate := estimatedDecodeNS(TensorStrategySparseDelta, size, options)
			root, err := logicalRootForBytes(dtype, shape, logical)
			if err != nil {
				return nil, err
			}
			out = append(out, preparedTensorCandidate{
				candidate: TensorPlanCandidate{
					Strategy: TensorStrategySparseDelta, Applicable: true,
					Detail:            "mode 16 against the causal parent",
					PhysicalBytes:     uint64Ptr(physical),
					EstimatedDecodeNS: uint64Ptr(estimate),
					EstimatedEncodeNS: uint64Ptr(EstimateEncodeNS(TensorStrategySparseDelta, size)),
					Cost:              costPtr(priceTensorWithWrite(TensorStrategySparseDelta, physical, estimate, size, options)),
					Dependency:        dependency,
				},
				artifact: &tensorArtifact{
					Kind: model.RepresentationTensor, StrategyName: TensorStrategySparseDelta.String(),
					Frame:        frameBytes,
					Dependencies: []model.Hash32{*dependency},
					Tensor: &model.TensorRepresentation{
						Mode: 16, Dtype: dtype, Shape: append([]uint64(nil), shape...),
						LogicalRoot: root, Layout: layout.WCBValue(dtype, shape),
					},
				},
			})
		}
	}

	return out, nil
}

func (s *Store) prepareMode10(dtype string, shape []uint64, logical []byte, lim limits.Limits) ([]byte, model.Hash32, error) {
	if dtype != "q8_0" {
		return nil, model.Hash32{}, werr.Newf(werr.InvalidArgument,
			"dtype does not support mode 10")
	}
	elementCount, err := tensor.ValidateShape(shape, lim)
	if err != nil {
		return nil, model.Hash32{}, werr.FromCodec(err)
	}
	blockSize := q8BlockSize(elementCount)
	if blockSize == 0 {
		return nil, model.Hash32{}, werr.Newf(werr.InvalidArgument,
			"element count %d is not divisible by any mode-10 block size", elementCount)
	}
	words := make([]int8, len(logical))
	for index, value := range logical {
		words[index] = int8(value)
	}
	scales, zeroPoints := q8Scales(words, blockSize)
	frames, err := modes.EncodeShardedTensor(modes.ShardedTensorInput{
		Dtype:      modes.ShardedQ8_0,
		Shape:      shape,
		ShardAxis:  0,
		ShardCount: 1,
		BlockSize:  blockSize,
		Scales:     scales,
		ZeroPoints: zeroPoints,
		Words:      words,
	}, lim)
	if err != nil {
		return nil, model.Hash32{}, werr.FromCodec(err)
	}
	if len(frames) != 1 {
		return nil, model.Hash32{}, werr.Newf(werr.Corrupt,
			"mode-10 encoder produced %d frames", len(frames))
	}
	parsed, err := frame.Parse(frames[0], lim)
	if err != nil {
		return nil, model.Hash32{}, werr.FromCodec(err)
	}
	shard, err := modes.DecodeShardFrame(parsed, lim)
	if err != nil {
		return nil, model.Hash32{}, werr.FromCodec(err)
	}
	root, err := modes.LogicalRootSharded(shard.Meta.Dtype, shard.Meta.Shape,
		shard.Words, shard.Meta.Scales, shard.Meta.ZeroPoints, lim)
	if err != nil {
		return nil, model.Hash32{}, werr.FromCodec(err)
	}
	return frames[0], root, nil
}

// q8Scales derives a deterministic q8_0 block scale from each block's maximum
// magnitude. The scale is descriptive metadata only; reconstruction is exact on
// the stored words.
func q8Scales(words []int8, blockSize uint64) ([]uint32, []int64) {
	block := int(blockSize)
	if block <= 0 {
		block = 1
	}
	scales := make([]uint32, 0, len(words)/block+1)
	zeroPoints := make([]int64, 0, len(words)/block+1)
	for start := 0; start < len(words); start += block {
		end := start + block
		if end > len(words) {
			end = len(words)
		}
		amax := 0
		for _, word := range words[start:end] {
			value := int(word)
			if value < 0 {
				value = -value
			}
			if value > amax {
				amax = value
			}
		}
		scale := float32(1.0)
		if amax != 0 {
			scale = float32(amax) / 127.0
		}
		scales = append(scales, math.Float32bits(scale))
		zeroPoints = append(zeroPoints, 0)
	}
	return scales, zeroPoints
}

// floatTensorDtype maps a manifest dtype to the mode-9 float layout.
func floatTensorDtype(dtype string) (modes.FloatDtype, bool) {
	name := ""
	switch dtype {
	case "f16":
		name = "fp16"
	case "bf16":
		name = "bf16"
	case "f32":
		name = "fp32"
	default:
		return modes.FloatDtype{}, false
	}
	parsed, err := modes.ParseFloatDtype(name)
	if err != nil {
		return modes.FloatDtype{}, false
	}
	return parsed, true
}

// q8BlockSize selects the mode-10 block size. It prefers the largest block
// that divides the payload, matching Rust's `q8_0_block_size`: the scale plane
// costs one 4-byte record per block, so 16-element blocks add 25 % metadata
// while 256-element blocks add about 1.6 %. The previous ascending order picked
// 16 for every even element count and made large q8_0 tensors exceed the WCB
// item bound (mode-10 descriptors of 8 MiB and above failed).
func q8BlockSize(elementCount uint64) uint64 {
	for _, block := range []uint64{256, 128, 64, 32, 16} {
		if elementCount%block == 0 {
			return block
		}
	}
	return 0
}

func (s *Store) prepareDelta(
	dtype string,
	shape []uint64,
	logical []byte,
	causal []model.Hash32,
	lim limits.Limits,
	strategy TensorStrategy,
) ([]byte, *model.Hash32, error) {
	if strategy != TensorStrategyWeightDelta && strategy != TensorStrategySparseDelta {
		return nil, nil, nil
	}
	weightName, ok := model.TensorWeightDtype(dtype)
	if !ok || (dtype != "bf16" && dtype != "f16" && dtype != "f32") {
		return nil, nil, nil
	}
	baseRoot, baseBytes, err := s.tensorCausalBase(dtype, shape, causal)
	if err != nil {
		return nil, nil, err
	}
	if baseRoot == nil {
		return nil, nil, nil
	}
	// Respect the frozen dependency depth bound: a delta on a chain at the
	// bound would be unreadable. Fall back to an independent representation.
	baseDepth, err := s.representationDepDepth(*baseRoot, nil)
	if err != nil {
		return nil, nil, err
	}
	if baseDepth+1 > MaxCodecDependencyDepth {
		return nil, nil, nil
	}
	physical, ok := model.TensorPhysicalDtype(dtype)
	if !ok {
		return nil, nil, nil
	}
	baseFrame, err := modes.EncodeTensor(baseBytes, physical, shape, lim)
	if err != nil {
		return nil, nil, werr.FromCodec(err)
	}
	weight, err := modes.ParseWeightDtype(weightName)
	if err != nil {
		return nil, nil, werr.FromCodec(err)
	}
	var frameBytes []byte
	if strategy == TensorStrategySparseDelta {
		frameBytes, err = modes.EncodeSparseDelta(
			context.Background(), logical, weight, shape, baseFrame, lim)
	} else {
		frameBytes, err = modes.EncodeWeightDelta(
			context.Background(), logical, weight, shape, baseFrame, lim)
	}
	if err != nil {
		return nil, nil, werr.FromCodec(err)
	}
	return frameBytes, baseRoot, nil
}

// tensorCausalBase resolves the first causal parent naming a live file version
// with the same tensor identity to its content root and logical bytes.
func (s *Store) tensorCausalBase(dtype string, shape []uint64, causal []model.Hash32) (*model.Hash32, []byte, error) {
	if len(causal) == 0 {
		return nil, nil, nil
	}
	ids := model.SortHashKeys(s.state.Objects)
	for _, parent := range causal {
		for _, id := range ids {
			record := s.state.Objects[id]
			if record.Kind != model.KindFile || record.Version != parent {
				continue
			}
			meta, err := s.TensorMetadata(id)
			if err != nil || meta.Dtype != dtype || !equalShapes(meta.Shape, shape) {
				continue
			}
			bytesValue, err := s.ReadContent(record.Content, 0, record.Size)
			if err != nil || uint64(len(bytesValue)) != record.Size {
				continue
			}
			root := record.Content
			return &root, bytesValue, nil
		}
	}
	return nil, nil, nil
}

// representationDepDepth is the maximum representation-dependency depth below
// manifestID.
func (s *Store) representationDepDepth(manifestID model.Hash32, seen []model.Hash32) (int, error) {
	if containsHash(seen, manifestID) {
		return 0, werr.Newf(werr.Corrupt, "tensor representation dependency cycle")
	}
	manifest, err := readManifest(s.blobs, manifestID)
	if err != nil {
		return 0, err
	}
	if manifest.Representation == nil || len(manifest.Representation.Dependencies) == 0 {
		return 0, nil
	}
	seen = append(seen, manifestID)
	deepest := 0
	for _, dependency := range manifest.Representation.Dependencies {
		depth, err := s.representationDepDepth(dependency, seen)
		if err != nil {
			return 0, err
		}
		if depth > deepest {
			deepest = depth
		}
	}
	return deepest + 1, nil
}

func chooseTensorCandidate(prepared []preparedTensorCandidate, hint *TensorStrategy) (preparedTensorCandidate, error) {
	if hint != nil {
		for _, item := range prepared {
			if item.candidate.Applicable && item.candidate.Strategy == *hint {
				return item, nil
			}
		}
		detail := "strategy is not a planner candidate"
		for _, item := range prepared {
			if item.candidate.Strategy == *hint {
				detail = item.candidate.Detail
				break
			}
		}
		return preparedTensorCandidate{}, werr.Newf(werr.InvalidArgument,
			"tensor strategy `%s` is not applicable: %s", hint.String(), detail)
	}
	var best *preparedTensorCandidate
	for index := range prepared {
		item := &prepared[index]
		if !item.candidate.Applicable || item.candidate.Cost == nil {
			continue
		}
		if best == nil || item.candidate.Cost.less(*best.candidate.Cost) {
			best = item
		}
	}
	if best == nil {
		return preparedTensorCandidate{}, werr.Newf(werr.InvalidArgument,
			"no applicable tensor strategy")
	}
	return *best, nil
}

func (s *Store) storeTensorArtifact(
	dtype string,
	shape []uint64,
	logical []byte,
	layout TensorLayoutSpec,
	artifact *tensorArtifact,
) (model.Hash32, model.Hash32, uint64, error) {
	contentHash := model.ContentHash(logical)
	size := uint64(len(logical))
	switch artifact.Kind {
	case model.RepresentationRaw:
		manifest, err := s.buildRawManifest(logical, s.options.ChunkSize, contentHash)
		if err != nil {
			return model.Hash32{}, model.Hash32{}, 0, err
		}
		manifest.Representation = &model.Representation{
			Kind: model.RepresentationRaw, Strategy: model.StrategyRaw, DecodedSize: size,
		}
		return s.storeManifest(manifest)
	case model.RepresentationCodec:
		if artifact.Frame == nil {
			return model.Hash32{}, model.Hash32{}, 0, werr.Newf(werr.Corrupt,
				"codec artifact has no frame")
		}
		frameID, err := s.storeBlob(BlobManifest, model.DomainManifest, artifact.Frame)
		if err != nil {
			return model.Hash32{}, model.Hash32{}, 0, err
		}
		manifest := model.Manifest{
			Size: size, ChunkSize: s.options.ChunkSize, ContentHash: contentHash,
			Representation: &model.Representation{
				Kind: model.RepresentationCodec, Frame: &frameID,
				Strategy: model.StrategyZstd, DecodedSize: size,
			},
		}
		return s.storeManifest(manifest)
	case model.RepresentationTensor:
		if artifact.Frame == nil {
			return model.Hash32{}, model.Hash32{}, 0, werr.Newf(werr.Corrupt,
				"tensor artifact has no frame")
		}
		if artifact.Tensor == nil {
			return model.Hash32{}, model.Hash32{}, 0, werr.Newf(werr.Corrupt,
				"tensor artifact has no tensor fields")
		}
		frameID, err := s.storeBlob(BlobManifest, model.DomainManifest, artifact.Frame)
		if err != nil {
			return model.Hash32{}, model.Hash32{}, 0, err
		}
		tensorValue := artifact.Tensor.Clone()
		tensorValue.Layout = layout.WCBValue(dtype, shape)
		manifest := model.Manifest{
			Size: size, ChunkSize: s.options.ChunkSize, ContentHash: contentHash,
			Representation: &model.Representation{
				Kind: model.RepresentationTensor, Frame: &frameID,
				Dependencies: append([]model.Hash32(nil), artifact.Dependencies...),
				Strategy:     artifact.StrategyName, DecodedSize: size,
				Tensor: &tensorValue,
			},
		}
		return s.storeManifest(manifest)
	default:
		return model.Hash32{}, model.Hash32{}, 0, werr.Newf(werr.Corrupt,
			"unknown tensor artifact kind `%s`", artifact.Kind)
	}
}

func (s *Store) commitTensorFile(
	parent model.Hash32,
	name []byte,
	manifestID model.Hash32,
	contentHash model.Hash32,
	size uint64,
	attrs map[string]wcb.Value,
	causal []model.Hash32,
	seed []byte,
) (model.Hash32, error) {
	_ = contentHash
	objectID := model.ObjectIDFromSeed(seed)
	if _, exists := s.state.Objects[objectID]; exists {
		return model.Hash32{}, werr.Newf(werr.Exists, "object id already exists")
	}
	preparedAttrs, identityMode, causalHash, closure, err := s.prepareCausal(attrs, causal)
	if err != nil {
		return model.Hash32{}, err
	}
	if closure != nil {
		if err := s.storeCausalClosure(closure); err != nil {
			return model.Hash32{}, err
		}
	}
	mtime := s.nowNS()
	version, err := model.DeriveVersionIDWithIdentity(
		objectID, manifestID, size, mtime, nil, identityMode, causalHash)
	if err != nil {
		return model.Hash32{}, err
	}
	record := model.ObjectRecord{
		ID: objectID, Kind: model.KindFile, Mode: 0o644,
		UID: s.options.OwnerUID, GID: s.options.OwnerGID,
		MtimeNS: mtime, Version: version, Content: manifestID, Size: size,
		Attrs: preparedAttrs,
	}
	entryID, err := model.DeriveEntryID(parent, name)
	if err != nil {
		return model.Hash32{}, err
	}
	entry := model.EntryRecord{
		ID: entryID, Parent: parent, Name: append([]byte(nil), name...), Target: objectID,
	}
	ops := []model.Op{
		model.PutObjectOp{Record: record},
		model.PutEntryOp{Record: entry},
		model.SetTipOp{Object: objectID, Version: version},
	}
	if _, err := s.commitOps(ops, false); err != nil {
		return model.Hash32{}, err
	}
	return objectID, nil
}

// TensorMetadata returns the tensor identity recorded for an object. A byte
// rewrite that drops the reserved attributes makes this NotFound, exactly as
// Rust's `tensor_metadata` does.
func (s *Store) TensorMetadata(id model.Hash32) (StoredTensorMetadata, error) {
	var meta StoredTensorMetadata
	record, err := s.ObjectMeta(id)
	if err != nil {
		return meta, err
	}
	if record.Kind != model.KindFile {
		return meta, werr.Newf(werr.InvalidArgument,
			"tensor metadata requires a file object")
	}
	manifest, err := readManifest(s.blobs, record.Content)
	if err != nil {
		return meta, err
	}
	if rep := manifest.Representation; rep != nil && rep.Kind == model.RepresentationTensor {
		if rep.Tensor == nil {
			return meta, werr.Newf(werr.Corrupt, "tensor manifest has no tensor fields")
		}
		layoutDtype, layoutShape, layout, err := TensorLayoutFromWCB(rep.Tensor.Layout)
		if err != nil {
			return meta, err
		}
		if layoutDtype != rep.Tensor.Dtype || !equalShapes(layoutShape, rep.Tensor.Shape) {
			return meta, werr.Newf(werr.Corrupt,
				"tensor layout descriptor disagrees with the manifest dtype/shape")
		}
		return StoredTensorMetadata{
			Dtype: rep.Tensor.Dtype, Shape: append([]uint64(nil), rep.Tensor.Shape...),
			LogicalRoot: rep.Tensor.LogicalRoot, Layout: layout, Strategy: rep.Strategy,
		}, nil
	}
	dtypeValue, ok := record.Attrs[model.AttrTensorDtype]
	if !ok || dtypeValue.Kind != wcb.Text {
		return meta, werr.Newf(werr.NotFound, "object is not a tensor")
	}
	dtype, err := model.ParseTensorDtype(dtypeValue.Str)
	if err != nil {
		return meta, err
	}
	shapeValue, ok := record.Attrs[model.AttrTensorShape]
	if !ok || shapeValue.Kind != wcb.Array {
		return meta, werr.Newf(werr.Corrupt, "tensor shape attribute is missing")
	}
	shape := make([]uint64, 0, len(shapeValue.Array))
	for _, item := range shapeValue.Array {
		if item.Kind != wcb.U64 {
			return meta, werr.Newf(werr.Corrupt, "tensor shape attribute is not u64")
		}
		shape = append(shape, item.U)
	}
	rootValue, ok := record.Attrs[model.AttrTensorLogicalRoot]
	if !ok || rootValue.Kind != wcb.Bytes || len(rootValue.Bytes) != 32 {
		return meta, werr.Newf(werr.Corrupt, "tensor root attribute is missing")
	}
	var logicalRoot model.Hash32
	copy(logicalRoot[:], rootValue.Bytes)
	layoutValue, ok := record.Attrs[model.AttrTensorLayout]
	if !ok || layoutValue.Kind != wcb.Bytes {
		return meta, werr.Newf(werr.Corrupt, "tensor layout attribute is missing")
	}
	decoded, err := model.DecodeWCB(layoutValue.Bytes)
	if err != nil {
		return meta, err
	}
	layoutDtype, layoutShape, layout, err := TensorLayoutFromWCB(decoded)
	if err != nil {
		return meta, err
	}
	if layoutDtype != dtype || !equalShapes(layoutShape, shape) {
		return meta, werr.Newf(werr.Corrupt,
			"tensor layout attribute disagrees with the tensor dtype/shape")
	}
	strategy := "unknown"
	if value, ok := record.Attrs[model.AttrTensorStrategy]; ok && value.Kind == wcb.Text {
		strategy = value.Str
	}
	return StoredTensorMetadata{
		Dtype: dtype, Shape: shape, LogicalRoot: logicalRoot, Layout: layout, Strategy: strategy,
	}, nil
}

// ReadTensor reads one tensor object's canonical logical bytes.
func (s *Store) ReadTensor(id model.Hash32) ([]byte, error) {
	if _, err := s.TensorMetadata(id); err != nil {
		return nil, err
	}
	return s.ReadObject(id)
}

// ReadTensorRegion reads a logical hyper-rectangle in row-major order. Frames
// are not independently seekable, so the whole object is decoded and sliced;
// the returned region is exact.
func (s *Store) ReadTensorRegion(id model.Hash32, region tensor.Region) (tensor.RegionRead, error) {
	meta, err := s.TensorMetadata(id)
	if err != nil {
		return tensor.RegionRead{}, err
	}
	// Mode 20 is independently region-addressable: decode only the groups
	// whose row intervals intersect the region.
	record, err := s.ObjectMeta(id)
	if err != nil {
		return tensor.RegionRead{}, err
	}
	manifest, err := readManifest(s.blobs, record.Content)
	if err != nil {
		return tensor.RegionRead{}, err
	}
	if manifest.Representation != nil && manifest.Representation.Tensor != nil &&
		manifest.Representation.Tensor.Mode == 20 {
		return s.readEngramRegion(manifest, region)
	}
	bytesValue, err := s.ReadObject(id)
	if err != nil {
		return tensor.RegionRead{}, err
	}
	physical, ok := model.TensorPhysicalDtype(meta.Dtype)
	if !ok {
		return tensor.RegionRead{}, werr.Newf(werr.Unsupported,
			"tensor dtype has no physical layout")
	}
	physicalTensor, err := tensor.NewRowMajor(physical, meta.Shape, bytesValue, limits.Default())
	if err != nil {
		return tensor.RegionRead{}, werr.FromCodec(err)
	}
	read, err := physicalTensor.ReadRegionWithLimits(region, limits.Default())
	if err != nil {
		return tensor.RegionRead{}, werr.FromCodec(err)
	}
	return read, nil
}

// readEngramRegion decodes only the mode-20 groups intersecting the region.
// It reads the frame blob and its dependency frames, then calls the codec's
// group-region reader; untouched groups are never decoded. The exact region
// (including a column subset) is returned.
func (s *Store) readEngramRegion(manifest model.Manifest, region tensor.Region) (tensor.RegionRead, error) {
	rep := manifest.Representation
	if rep == nil || rep.Frame == nil {
		return tensor.RegionRead{}, werr.Newf(werr.Corrupt, "engram representation has no frame")
	}
	lim := limits.Default()
	frameBytes, err := readBlobVerified(s.blobs, BlobManifest, *rep.Frame, model.DomainManifest)
	if err != nil {
		return tensor.RegionRead{}, err
	}
	parsed, err := frame.Parse(frameBytes, lim)
	if err != nil {
		return tensor.RegionRead{}, werr.FromCodec(err)
	}
	descriptor, err := modes.ParseEngram(parsed, lim)
	if err != nil {
		return tensor.RegionRead{}, werr.FromCodec(err)
	}
	if len(region.Start) != 2 || len(region.End) != 2 {
		return tensor.RegionRead{}, werr.Newf(werr.InvalidArgument,
			"engram regions must have rank 2")
	}
	source, err := engramFrameSource(s.blobs, rep)
	if err != nil {
		return tensor.RegionRead{}, err
	}
	rows, touched, err := modes.ReadEngramRegion(
		context.Background(), parsed, descriptor, region.Start[0], region.End[0], source, lim)
	if err != nil {
		return tensor.RegionRead{}, werr.FromCodec(err)
	}
	dim := descriptor.Meta.TableShape[1]
	word, err := modes.TensorElementSize(descriptor.Meta.Dtype)
	if err != nil {
		return tensor.RegionRead{}, werr.FromCodec(err)
	}
	out := rows
	if region.Start[1] != 0 || region.End[1] != dim {
		rowBytes := dim * word
		colStart := region.Start[1] * word
		colEnd := region.End[1] * word
		rowCount := region.End[0] - region.Start[0]
		out = make([]byte, 0, int(rowCount*(colEnd-colStart)))
		for row := uint64(0); row < rowCount; row++ {
			base := row * rowBytes
			out = append(out, rows[base+colStart:base+colEnd]...)
		}
	}
	return tensor.RegionRead{
		Shape:        region.Extent(),
		Bytes:        out,
		UnitsTouched: uint64(len(touched)),
	}, nil
}

// TensorLogicalRoot recomputes and verifies an object's LogicalTensorRoot.
func (s *Store) TensorLogicalRoot(id model.Hash32) (model.Hash32, error) {
	meta, err := s.TensorMetadata(id)
	if err != nil {
		return model.Hash32{}, err
	}
	bytesValue, err := s.ReadObject(id)
	if err != nil {
		return model.Hash32{}, err
	}
	var root model.Hash32
	if meta.Dtype == "q8_0" {
		shard, err := s.q8ShardMeta(id)
		if err != nil {
			return model.Hash32{}, err
		}
		words := make([]int8, len(bytesValue))
		for index, value := range bytesValue {
			words[index] = int8(value)
		}
		root, err = modes.LogicalRootSharded(shard.Dtype, shard.Shape, words,
			shard.Scales, shard.ZeroPoints, limits.Default())
		if err != nil {
			return model.Hash32{}, werr.FromCodec(err)
		}
	} else {
		root, err = logicalRootForBytes(meta.Dtype, meta.Shape, bytesValue)
		if err != nil {
			return model.Hash32{}, err
		}
	}
	if root != meta.LogicalRoot {
		return model.Hash32{}, werr.Newf(werr.Corrupt,
			"object %s tensor logical root does not match its recorded identity", id.Hex())
	}
	return root, nil
}

// q8ShardMeta decodes the mode-10 descriptor of a q8_0 tensor object.
func (s *Store) q8ShardMeta(id model.Hash32) (modes.ShardedTensorMeta, error) {
	record, err := s.ObjectMeta(id)
	if err != nil {
		return modes.ShardedTensorMeta{}, err
	}
	manifest, err := readManifest(s.blobs, record.Content)
	if err != nil {
		return modes.ShardedTensorMeta{}, err
	}
	if manifest.Representation == nil || manifest.Representation.Kind != model.RepresentationTensor ||
		manifest.Representation.Tensor == nil || manifest.Representation.Tensor.Mode != 10 ||
		manifest.Representation.Frame == nil {
		return modes.ShardedTensorMeta{}, werr.Newf(werr.Corrupt,
			"q8_0 tensor is not stored through mode 10")
	}
	frameBytes, err := readBlobVerified(s.blobs, BlobManifest,
		*manifest.Representation.Frame, model.DomainManifest)
	if err != nil {
		return modes.ShardedTensorMeta{}, err
	}
	parsed, err := frame.Parse(frameBytes, limits.Default())
	if err != nil {
		return modes.ShardedTensorMeta{}, werr.FromCodec(err)
	}
	shard, err := modes.DecodeShardFrame(parsed, limits.Default())
	if err != nil {
		return modes.ShardedTensorMeta{}, werr.FromCodec(err)
	}
	return shard.Meta, nil
}

func logicalRootForBytes(dtype string, shape []uint64, bytesValue []byte) (model.Hash32, error) {
	if dtype == "q8_0" || dtype == "q4_0" {
		return model.Hash32{}, werr.Newf(werr.InvalidArgument,
			"a quantized logical root requires the mode-10 scale plane")
	}
	physical, ok := model.TensorPhysicalDtype(dtype)
	if !ok {
		return model.Hash32{}, werr.Newf(werr.Unsupported,
			"tensor dtype has no logical root")
	}
	root, err := tensor.LogicalRoot(physical, shape, bytesValue, limits.Default())
	if err != nil {
		return model.Hash32{}, werr.FromCodec(err)
	}
	return root, nil
}

// applyTensorAttrs records the reserved tensor identity attributes.
func applyTensorAttrs(
	attrs map[string]wcb.Value,
	dtype string,
	shape []uint64,
	root model.Hash32,
	layout TensorLayoutSpec,
	strategy string,
) error {
	shapeItems := make([]wcb.Value, 0, len(shape))
	for _, dim := range shape {
		shapeItems = append(shapeItems, wcb.U64Value(dim))
	}
	layoutBytes, err := model.EncodeWCB(layout.WCBValue(dtype, shape))
	if err != nil {
		return err
	}
	attrs[model.AttrTensorDtype] = wcb.TextValue(dtype)
	attrs[model.AttrTensorShape] = wcb.ArrayValue(shapeItems)
	attrs[model.AttrTensorLogicalRoot] = wcb.BytesValue(root.Bytes())
	attrs[model.AttrTensorLayout] = wcb.BytesValue(layoutBytes)
	attrs[model.AttrTensorStrategy] = wcb.TextValue(strategy)
	return nil
}

// stripTensorAttrs removes tensor identity attributes from an attribute map.
// A byte rewrite of a tensor object is no longer the tensor those attributes
// describe, so the identity is dropped rather than left stale.
func stripTensorAttrs(attrs map[string]wcb.Value) map[string]wcb.Value {
	if len(attrs) == 0 {
		return attrs
	}
	out := make(map[string]wcb.Value, len(attrs))
	for key, value := range attrs {
		switch key {
		case model.AttrTensorDtype, model.AttrTensorShape, model.AttrTensorLogicalRoot,
			model.AttrTensorLayout, model.AttrTensorStrategy:
			continue
		default:
			out[key] = value
		}
	}
	return out
}

func uint64Ptr(value uint64) *uint64 { return &value }

func costPtr(value tensorCost) *tensorCost { return &value }

func equalShapes(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}
