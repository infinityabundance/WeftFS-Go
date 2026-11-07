// Additive `kind:"tensor"` representation support (WEFT-MODEL.md §2.3.1).
//
// A v2 manifest may name a WeftTensor frame (modes 10-14) as the physical
// representation of a file's logical bytes. This file holds the manifest-side
// tensor fields, the canonical dtype tables, and the tensor strategy/mode
// binding. The store's planner, reader, GC, and verifier all use these rules.
//
// The constants mirror the Rust reference (`src/format.rs`,
// `src/representation.rs`, `src/tensor_store.rs`). They are duplicated because
// the Go implementation is independent; a change here must be matched in Rust.
package model

import (
	"sort"

	"github.com/infinityabundance/WeftCodec-Go/limits"
	"github.com/infinityabundance/WeftCodec-Go/tensor"
	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// Reserved object attributes recording tensor identity for objects written
// through `kind:"raw"` or `kind:"codec"`.
const (
	// AttrTensorDtype is the canonical tensor dtype name.
	AttrTensorDtype = "weft.tensor.dtype"
	// AttrTensorShape is the logical shape as an array of u64.
	AttrTensorShape = "weft.tensor.shape"
	// AttrTensorLogicalRoot is the LogicalTensorRoot as bytes32.
	AttrTensorLogicalRoot = "weft.tensor.logical_root"
	// AttrTensorLayout is the canonical `weft.tensor.layout.v1` WCB bytes.
	AttrTensorLayout = "weft.tensor.layout"
	// AttrTensorStrategy is the chosen representation strategy name.
	AttrTensorStrategy = "weft.tensor.strategy"
)

// TensorRepresentation is the additive tensor payload of a v2 representation
// map. It exists exactly when Kind is RepresentationTensor.
type TensorRepresentation struct {
	// Mode is the tensor frame mode: 9 FLOAT_TENSOR, 10 TENSOR_SHARDED,
	// 11 WEIGHT_DELTA, 12 KV_CACHE, 13 ACTIVATION_STREAM, 14 SEMANTIC_DELTA.
	Mode uint32
	// Dtype is the canonical WEFT-TENSOR dtype name (or q8_0/q4_0).
	Dtype string
	// Shape is the logical extent array.
	Shape []uint64
	// LogicalRoot is the WEFT-TENSOR LogicalTensorRoot.
	LogicalRoot Hash32
	// Layout is the canonical `weft.tensor.layout.v1` WCB map.
	Layout wcb.Value
}

// Clone deep-copies the tensor payload.
func (t TensorRepresentation) Clone() TensorRepresentation {
	out := t
	out.Shape = append([]uint64(nil), t.Shape...)
	out.Layout = CloneValue(t.Layout)
	return out
}

var tensorRepresentationKeys = []string{
	"kind", "frame", "tensor_mode", "dtype", "shape", "logical_root",
	"layout", "dependencies", "decoded_size", "strategy",
}

// TensorStrategyForMode returns the canonical strategy spelling fixed by a
// tensor mode.
func TensorStrategyForMode(mode uint32) (string, bool) {
	switch mode {
	case 9:
		return "float-tensor", true
	case 10:
		return "tensor-sharded", true
	case 11:
		return "weight-delta", true
	case 12:
		return "kv-cache", true
	case 13:
		return "activation", true
	case 14:
		return "semantic-delta", true
	case 15:
		return "tensor-tiled", true
	case 16:
		return "sparse-delta", true
	case 17:
		return "float-tiled", true
	default:
		return "", false
	}
}

// TensorModeForStrategy returns the frame mode a canonical tensor strategy
// requires.
func TensorModeForStrategy(strategy string) (uint32, bool) {
	switch strategy {
	case "float-tensor":
		return 9, true
	case "tensor-sharded":
		return 10, true
	case "weight-delta":
		return 11, true
	case "kv-cache":
		return 12, true
	case "activation":
		return 13, true
	case "semantic-delta":
		return 14, true
	case "tensor-tiled":
		return 15, true
	case "sparse-delta":
		return 16, true
	case "float-tiled":
		return 17, true
	default:
		return 0, false
	}
}

// TensorModeHasDependency reports whether a tensor mode carries a base content
// root (modes 11, 14, and 16).
func TensorModeHasDependency(mode uint32) bool { return mode == 11 || mode == 14 || mode == 16 }

// TensorDtypeNames lists the canonical manifest dtype names in Rust order.
var TensorDtypeNames = []string{
	"f16", "bf16", "f32", "f64", "i8", "u8", "i16", "i32", "i64", "q8_0", "q4_0",
}

// ParseTensorDtype validates a canonical manifest tensor dtype name.
func ParseTensorDtype(name string) (string, error) {
	for _, candidate := range TensorDtypeNames {
		if name == candidate {
			return name, nil
		}
	}
	return "", werr.Newf(werr.Malformed,
		"unknown tensor dtype `%s` (v1 allows f16, bf16, f32, f64, i8, u8, "+
			"i16, i32, i64, q8_0, q4_0)", name)
}

// TensorElementBytes returns the logical element width of a manifest dtype.
func TensorElementBytes(name string) (uint64, bool) {
	switch name {
	case "f16", "bf16", "i16":
		return 2, true
	case "f32", "i32":
		return 4, true
	case "f64", "i64":
		return 8, true
	case "i8", "u8", "q8_0", "q4_0":
		return 1, true
	default:
		return 0, false
	}
}

// TensorPhysicalDtype maps a manifest dtype to the core WeftTensor physical
// dtype used for layout arithmetic. q8_0 behaves like i8 and q4_0 like u8.
func TensorPhysicalDtype(name string) (string, bool) {
	switch name {
	case "f16", "bf16", "f32", "f64", "i8", "u8", "i16", "i32", "i64":
		return name, true
	case "q8_0":
		return "i8", true
	case "q4_0":
		return "u8", true
	default:
		return "", false
	}
}

// TensorWeightDtype maps a manifest dtype to the mode 11/14 descriptor dtype
// name, when the dtype supports exact weight deltas.
func TensorWeightDtype(name string) (string, bool) {
	switch name {
	case "bf16":
		return "bf16", true
	case "f16":
		return "fp16", true
	case "f32":
		return "fp32", true
	case "q8_0":
		return "q8_0", true
	case "q4_0":
		return "q4_0", true
	default:
		return "", false
	}
}

// TensorDtypeFromWeightName maps a mode 11/14 descriptor dtype name to the
// canonical manifest dtype name.
func TensorDtypeFromWeightName(name string) (string, bool) {
	switch name {
	case "bf16":
		return "bf16", true
	case "fp16":
		return "f16", true
	case "fp32":
		return "f32", true
	case "q8_0":
		return "q8_0", true
	case "q4_0":
		return "q4_0", true
	default:
		return "", false
	}
}

// tensorDependencies parses the `dependencies` array of a representation map.
func tensorDependencies(m map[string]wcb.Value) ([]Hash32, error) {
	items, err := GetArray(m, "dependencies")
	if err != nil {
		return nil, err
	}
	dependencies := make([]Hash32, 0, len(items))
	for _, item := range items {
		if item.Kind != wcb.Bytes {
			return nil, werr.Newf(werr.Malformed, "representation dependency must be bytes32")
		}
		dependency, err := hashFromSlice(item.Bytes)
		if err != nil {
			return nil, err
		}
		dependencies = append(dependencies, dependency)
	}
	return dependencies, nil
}

// tensorRepresentationToWCB renders the canonical tensor representation map.
func tensorRepresentationToWCB(rep Representation) wcb.Value {
	tensorValue := TensorRepresentation{}
	if rep.Tensor != nil {
		tensorValue = *rep.Tensor
	}
	dependencies := make([]wcb.Value, 0, len(rep.Dependencies))
	for _, dependency := range rep.Dependencies {
		dependencies = append(dependencies, HashValue(dependency))
	}
	shape := make([]wcb.Value, 0, len(tensorValue.Shape))
	for _, dim := range tensorValue.Shape {
		shape = append(shape, wcb.U64Value(dim))
	}
	return Map(map[string]wcb.Value{
		"kind":         wcb.TextValue(string(rep.Kind)),
		"frame":        OptHashValue(rep.Frame),
		"tensor_mode":  wcb.U64Value(uint64(tensorValue.Mode)),
		"dtype":        wcb.TextValue(tensorValue.Dtype),
		"shape":        wcb.ArrayValue(shape),
		"logical_root": HashValue(tensorValue.LogicalRoot),
		"layout":       tensorValue.Layout,
		"dependencies": wcb.ArrayValue(dependencies),
		"decoded_size": wcb.U64Value(rep.DecodedSize),
		"strategy":     wcb.TextValue(rep.Strategy),
	})
}

// tensorRepresentationFromWCB parses and validates a tensor representation map.
//
// Class parity with Rust: an unknown kind, strategy, dtype, shape, layout
// shape, missing/extra key, non-zero frame requirement, and strategy/mode
// mismatch are Malformed; shape limits use the codec's LimitExceeded. The
// canonical layout content is validated on every read, where Rust validates it.
func tensorRepresentationFromWCB(m map[string]wcb.Value) (Representation, error) {
	var representation Representation
	if err := CheckKeys(m, tensorRepresentationKeys...); err != nil {
		return representation, err
	}
	frame, err := GetOptHash(m, "frame")
	if err != nil {
		return representation, err
	}
	if frame == nil || *frame == ZeroHash {
		return representation, werr.Newf(werr.Malformed,
			"tensor representation requires a non-zero frame id")
	}
	modeValue, err := GetU64(m, "tensor_mode")
	if err != nil {
		return representation, err
	}
	if modeValue > 0xFFFF_FFFF {
		return representation, werr.Newf(werr.Malformed, "tensor_mode does not fit u32")
	}
	mode := uint32(modeValue)
	strategy, err := GetText(m, "strategy")
	if err != nil {
		return representation, err
	}
	expected, ok := TensorModeForStrategy(strategy)
	if !ok {
		return representation, werr.Newf(werr.Malformed, "unknown tensor strategy `%s`", strategy)
	}
	if expected != mode {
		return representation, werr.Newf(werr.Malformed,
			"tensor strategy `%s` requires tensor_mode %d, got %d", strategy, expected, mode)
	}
	dtypeText, err := GetText(m, "dtype")
	if err != nil {
		return representation, err
	}
	dtype, err := ParseTensorDtype(dtypeText)
	if err != nil {
		return representation, err
	}
	items, err := GetArray(m, "shape")
	if err != nil {
		return representation, err
	}
	shape := make([]uint64, 0, len(items))
	for _, item := range items {
		if item.Kind != wcb.U64 {
			return representation, werr.Newf(werr.Malformed, "tensor shape must be an array of u64")
		}
		shape = append(shape, item.U)
	}
	if _, err := tensor.ValidateShape(shape, limits.Default()); err != nil {
		return representation, werr.FromCodec(err)
	}
	logicalRoot, err := GetHash(m, "logical_root")
	if err != nil {
		return representation, err
	}
	layout, err := Field(m, "layout")
	if err != nil {
		return representation, err
	}
	if layout.Kind != wcb.Map {
		return representation, werr.Newf(werr.Malformed,
			"tensor layout must be a canonical WCB map")
	}
	dependencies, err := tensorDependencies(m)
	if err != nil {
		return representation, err
	}
	decodedSize, err := GetU64(m, "decoded_size")
	if err != nil {
		return representation, err
	}
	if TensorModeHasDependency(mode) {
		if len(dependencies) != 1 {
			return representation, werr.Newf(werr.Malformed,
				"weight-delta/semantic-delta representation requires exactly one dependency")
		}
	} else if len(dependencies) != 0 {
		return representation, werr.Newf(werr.Malformed,
			"this tensor representation must not have dependencies")
	}
	return Representation{
		Kind:         RepresentationTensor,
		Frame:        frame,
		Dependencies: dependencies,
		Strategy:     strategy,
		DecodedSize:  decodedSize,
		Tensor: &TensorRepresentation{
			Mode:        mode,
			Dtype:       dtype,
			Shape:       shape,
			LogicalRoot: logicalRoot,
			Layout:      CloneValue(layout),
		},
	}, nil
}

// SortTensorStrategies orders strategy names by the Rust enum order, which is
// the deterministic planner tie-break.
func SortTensorStrategies(strategies []string) {
	rank := func(name string) int {
		mode, ok := TensorModeForStrategy(name)
		switch {
		case name == StrategyRaw:
			return 0
		case name == StrategyZstd:
			return 1
		case name == StrategyFloatTensor:
			return 2
		case ok:
			return 3 + int(mode) - 10
		default:
			return 99
		}
	}
	sort.SliceStable(strategies, func(i, j int) bool { return rank(strategies[i]) < rank(strategies[j]) })
}
