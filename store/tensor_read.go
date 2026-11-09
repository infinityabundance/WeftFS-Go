package store

import (
	"context"

	"github.com/infinityabundance/WeftCodec-Go/dependency"
	"github.com/infinityabundance/WeftCodec-Go/frame"
	"github.com/infinityabundance/WeftCodec-Go/limits"
	"github.com/infinityabundance/WeftCodec-Go/modes"
	"github.com/infinityabundance/WeftCodec-Go/tensor"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// readTensorRange decodes a v2 `kind:"tensor"` representation.
//
// The frame blob is fetched and verified, parsed with the codec's default
// limits, and its actual mode must equal the manifest's `tensor_mode`. dtype,
// shape, layout, dependency closure, recomputed LogicalTensorRoot, and (on a
// full read) the frozen content hash are all verified. A missing, unreadable,
// cyclic, or mismatched dependency is Corrupt; no partial bytes are returned.
func readTensorRange(
	src blobSource,
	manifest model.Manifest,
	rep *model.Representation,
	offset, length uint64,
	verifyWhole bool,
	depth int,
	seen []model.Hash32,
) ([]byte, error) {
	if depth > MaxCodecDependencyDepth {
		return nil, werr.Newf(werr.Corrupt,
			"tensor representation dependency depth exceeds %d", MaxCodecDependencyDepth)
	}
	if rep.Tensor == nil {
		return nil, werr.Newf(werr.Corrupt, "tensor representation has no tensor fields")
	}
	layoutDtype, layoutShape, _, err := TensorLayoutFromWCB(rep.Tensor.Layout)
	if err != nil {
		return nil, err
	}
	if layoutDtype != rep.Tensor.Dtype || !equalShapes(layoutShape, rep.Tensor.Shape) {
		return nil, werr.Newf(werr.Corrupt,
			"tensor layout descriptor disagrees with the manifest dtype/shape")
	}
	if rep.Frame == nil {
		return nil, werr.Newf(werr.Corrupt, "tensor representation has no frame id")
	}
	frameBytes, err := readBlobVerified(src, BlobManifest, *rep.Frame, model.DomainManifest)
	if err != nil {
		return nil, err
	}
	lim := limits.Default()
	parsed, err := frame.Parse(frameBytes, lim)
	if err != nil {
		return nil, werr.FromCodec(err)
	}
	expectedMode, ok := tensorFrameMode(rep.Tensor.Mode)
	if !ok {
		return nil, werr.Newf(werr.Corrupt,
			"tensor_mode %d is not a defined tensor frame mode", rep.Tensor.Mode)
	}
	if parsed.Header.Mode != expectedMode {
		return nil, werr.Newf(werr.Corrupt,
			"tensor strategy `%s` disagrees with frame mode `%s`",
			rep.Strategy, parsed.Header.Mode)
	}

	var logical []byte
	switch rep.Tensor.Mode {
	case 9:
		logical, err = decodeTensorMode9(parsed, rep, manifest, lim)
	case 10:
		logical, err = decodeTensorMode10(parsed, rep, manifest, lim)
	case 11:
		logical, err = decodeTensorDelta(src, parsed, rep, depth, seen, deltaWeight, lim)
	case 14:
		logical, err = decodeTensorDelta(src, parsed, rep, depth, seen, deltaSemantic, lim)
	case 16:
		logical, err = decodeTensorDelta(src, parsed, rep, depth, seen, deltaSparse, lim)
	case 12:
		logical, err = decodeTensorKvPage(parsed, rep, lim)
	case 13:
		logical, err = decodeTensorActivation(parsed, rep, lim)
	case 15:
		logical, err = modes.DecodeTiledTensor(parsed, lim)
	case 18:
		logical, err = modes.DecodeFloatTiledStreams(parsed, lim, 1)
		if err == nil {
			var root model.Hash32
			root, err = tensor.LogicalRoot(rep.Tensor.Dtype, rep.Tensor.Shape, logical, lim)
			if err == nil && root != rep.Tensor.LogicalRoot {
				err = werr.Newf(werr.Corrupt, "mode-18 logical root disagrees with the manifest")
			}
		}
	case 17:
		logical, err = modes.DecodeFloatTiled(parsed, lim)
		if err == nil {
			var root model.Hash32
			root, err = tensor.LogicalRoot(rep.Tensor.Dtype, rep.Tensor.Shape, logical, lim)
			if err == nil && root != rep.Tensor.LogicalRoot {
				err = werr.Newf(werr.Corrupt, "mode-17 logical root disagrees with the manifest")
			}
		}
	case 20:
		var source *dependency.MapFrameSource
		source, err = engramFrameSource(src, rep)
		if err == nil {
			logical, err = modes.DecodeEngram(context.Background(), parsed, source, lim)
		}
		if err == nil {
			var root model.Hash32
			root, err = tensor.LogicalRoot(rep.Tensor.Dtype, rep.Tensor.Shape, logical, lim)
			if err == nil && root != rep.Tensor.LogicalRoot {
				err = werr.Newf(werr.Corrupt, "mode-20 logical root disagrees with the manifest")
			}
		}
	default:
		return nil, werr.Newf(werr.Corrupt,
			"tensor_mode %d is not a defined tensor frame mode", rep.Tensor.Mode)
	}
	if err != nil {
		return nil, err
	}
	if uint64(len(logical)) != manifest.Size || uint64(len(logical)) != rep.DecodedSize {
		return nil, werr.Newf(werr.Corrupt,
			"tensor representation decoded length disagrees with the manifest")
	}
	if offset >= manifest.Size {
		return []byte{}, nil
	}
	end := offset + length
	if end < offset || end > manifest.Size {
		end = manifest.Size
	}
	out := append([]byte(nil), logical[offset:end]...)
	if verifyWhole && offset == 0 && end == manifest.Size {
		if model.ContentHash(out) != manifest.ContentHash {
			return nil, werr.Newf(werr.Corrupt, "whole-content hash mismatch")
		}
	}
	return out, nil
}

// deltaKind selects which exact word-wise delta decoder a kind:"tensor"
// manifest names.
type deltaKind int

const (
	deltaWeight deltaKind = iota
	deltaSemantic
	deltaSparse
)

func tensorFrameMode(mode uint32) (frame.Mode, bool) {
	switch mode {
	case 9:
		return frame.ModeFloatTensor, true
	case 10:
		return frame.ModeTensorSharded, true
	case 11:
		return frame.ModeWeightDelta, true
	case 12:
		return frame.ModeKvCache, true
	case 13:
		return frame.ModeActivationStream, true
	case 14:
		return frame.ModeSemanticDelta, true
	case 15:
		return frame.ModeTensorTiled, true
	case 16:
		return frame.ModeSparseDelta, true
	case 17:
		return frame.ModeFloatTiled, true
	case 18:
		return frame.ModeFloatTiledStreams, true
	case 20:
		return frame.ModeEngramShard, true
	default:
		return 0, false
	}
}

// engramFrameSource builds a frame source for a mode-20 representation's
// dependency manifests. Each dependency is an earlier tensor object's manifest
// id; its frame is keyed by the frame's own content hash (the hash named by
// the engram frame's dependency table).
func engramFrameSource(src blobSource, rep *model.Representation) (*dependency.MapFrameSource, error) {
	source := dependency.NewMapFrameSource()
	lim := limits.Default()
	for _, dep := range rep.Dependencies {
		depManifest, err := readManifest(src, dep)
		if err != nil {
			return nil, err
		}
		if depManifest.Representation == nil || depManifest.Representation.Frame == nil {
			return nil, werr.Newf(werr.Corrupt,
				"engram dependency has no frame")
		}
		frameBytes, err := readBlobVerified(src, BlobManifest,
			*depManifest.Representation.Frame, model.DomainManifest)
		if err != nil {
			return nil, err
		}
		if _, err := source.InsertFrame(context.Background(), frameBytes, lim); err != nil {
			return nil, werr.FromCodec(err)
		}
	}
	return source, nil
}

func decodeTensorMode9(
	parsed *frame.Frame,
	rep *model.Representation,
	manifest model.Manifest,
	lim limits.Limits,
) ([]byte, error) {
	meta, err := modes.FloatTensorMetadata(parsed, lim)
	if err != nil {
		return nil, werr.FromCodec(err)
	}
	floatDtype, ok := floatTensorDtype(rep.Tensor.Dtype)
	if !ok {
		return nil, werr.Newf(werr.Corrupt,
			"mode-9 dtype `%s` has no float layout", rep.Tensor.Dtype)
	}
	if meta.Dtype.Name != floatDtype.Name {
		return nil, werr.Newf(werr.Corrupt,
			"mode-9 dtype `%s` disagrees with manifest dtype `%s`",
			meta.Dtype.Name, rep.Tensor.Dtype)
	}
	if !equalShapes(meta.Shape, rep.Tensor.Shape) {
		return nil, werr.Newf(werr.Corrupt,
			"mode-9 shape disagrees with the representation manifest")
	}
	if meta.ElementCount*floatDtype.ElementSize() != manifest.Size {
		return nil, werr.Newf(werr.Corrupt,
			"mode-9 element count disagrees with the manifest size")
	}
	logical, err := modes.DecodeFloatTensorFrame(parsed, lim)
	if err != nil {
		return nil, werr.FromCodec(err)
	}
	if uint64(len(logical)) != manifest.Size {
		return nil, werr.Newf(werr.Corrupt,
			"mode-9 decoded length disagrees with the manifest")
	}
	physical, ok := model.TensorPhysicalDtype(rep.Tensor.Dtype)
	if !ok {
		return nil, werr.Newf(werr.Unsupported, "mode-9 dtype has no logical root")
	}
	recomputed, err := tensor.LogicalRoot(physical, rep.Tensor.Shape, logical, lim)
	if err != nil {
		return nil, werr.FromCodec(err)
	}
	if recomputed != rep.Tensor.LogicalRoot {
		return nil, werr.Newf(werr.Corrupt,
			"mode-9 logical root recomputation mismatch")
	}
	return logical, nil
}

func decodeTensorMode10(
	parsed *frame.Frame,
	rep *model.Representation,
	manifest model.Manifest,
	lim limits.Limits,
) ([]byte, error) {
	shard, err := modes.DecodeShardFrame(parsed, lim)
	if err != nil {
		return nil, werr.FromCodec(err)
	}
	shardDtype := shard.Meta.Dtype.Name()
	if shardDtype != rep.Tensor.Dtype {
		return nil, werr.Newf(werr.Corrupt,
			"mode-10 shard dtype `%s` disagrees with manifest dtype `%s`",
			shardDtype, rep.Tensor.Dtype)
	}
	if !equalShapes(shard.Meta.Shape, rep.Tensor.Shape) {
		return nil, werr.Newf(werr.Corrupt,
			"mode-10 shard shape disagrees with the manifest")
	}
	if shard.Meta.ShardCount != 1 {
		return nil, werr.Newf(werr.Corrupt,
			"a kind:\"tensor\" manifest names one frame; mode-10 shard_count is %d",
			shard.Meta.ShardCount)
	}
	if shard.Meta.ElementCount != manifest.Size {
		return nil, werr.Newf(werr.Corrupt,
			"mode-10 element count disagrees with the manifest size")
	}
	if shard.Meta.LayoutRoot != rep.Tensor.LogicalRoot {
		return nil, werr.Newf(werr.Corrupt,
			"mode-10 declared layout_root disagrees with the manifest logical_root")
	}
	root, err := modes.LogicalRootSharded(shard.Meta.Dtype, shard.Meta.Shape,
		shard.Words, shard.Meta.Scales, shard.Meta.ZeroPoints, lim)
	if err != nil {
		return nil, werr.FromCodec(err)
	}
	if root != rep.Tensor.LogicalRoot {
		return nil, werr.Newf(werr.Corrupt,
			"mode-10 logical root recomputation mismatch")
	}
	out := make([]byte, len(shard.Words))
	for index, word := range shard.Words {
		out[index] = byte(word)
	}
	return out, nil
}

func decodeTensorDelta(
	src blobSource,
	parsed *frame.Frame,
	rep *model.Representation,
	depth int,
	seen []model.Hash32,
	kind deltaKind,
	lim limits.Limits,
) ([]byte, error) {
	var descriptorDtype string
	var descriptorShape []uint64
	var baseHash model.Hash32
	switch kind {
	case deltaSemantic:
		meta, err := modes.SemanticDeltaMetadata(parsed, lim)
		if err != nil {
			return nil, werr.FromCodec(err)
		}
		dtype, ok := model.TensorDtypeFromWeightName(meta.Dtype.Name)
		if !ok {
			return nil, werr.Newf(werr.Malformed,
				"unknown weight-dtype `%s`", meta.Dtype.Name)
		}
		descriptorDtype, descriptorShape, baseHash = dtype, meta.Shape, meta.Base
	case deltaSparse:
		meta, err := modes.SparseDeltaMetadata(parsed, lim)
		if err != nil {
			return nil, werr.FromCodec(err)
		}
		dtype, ok := model.TensorDtypeFromWeightName(meta.Dtype.Name)
		if !ok {
			return nil, werr.Newf(werr.Malformed,
				"unknown weight-dtype `%s`", meta.Dtype.Name)
		}
		descriptorDtype, descriptorShape, baseHash = dtype, meta.Shape, meta.Base
	default:
		meta, err := modes.WeightDeltaMetadata(parsed, lim)
		if err != nil {
			return nil, werr.FromCodec(err)
		}
		dtype, ok := model.TensorDtypeFromWeightName(meta.Dtype.Name)
		if !ok {
			return nil, werr.Newf(werr.Malformed,
				"unknown weight-dtype `%s`", meta.Dtype.Name)
		}
		descriptorDtype, descriptorShape, baseHash = dtype, meta.Shape, meta.Base
	}
	if descriptorDtype != rep.Tensor.Dtype {
		return nil, werr.Newf(werr.Corrupt,
			"delta dtype `%s` disagrees with manifest dtype `%s`",
			descriptorDtype, rep.Tensor.Dtype)
	}
	if !equalShapes(descriptorShape, rep.Tensor.Shape) {
		return nil, werr.Newf(werr.Corrupt,
			"delta shape disagrees with the manifest shape")
	}
	if len(rep.Dependencies) == 0 {
		return nil, werr.Newf(werr.Corrupt, "delta representation has no dependency")
	}
	depRoot := rep.Dependencies[0]
	if containsHash(seen, depRoot) {
		return nil, werr.Newf(werr.Corrupt, "tensor representation dependency cycle")
	}
	depManifest, err := readManifest(src, depRoot)
	if err != nil {
		return nil, err
	}
	seen = append(seen, depRoot)
	baseBytes, err := readManifestRangeInner(src, depManifest, 0, depManifest.Size, true, depth+1, seen)
	seen = seen[:len(seen)-1]
	if err != nil {
		return nil, err
	}
	elementCount, err := tensor.ValidateShape(rep.Tensor.Shape, lim)
	if err != nil {
		return nil, werr.FromCodec(err)
	}
	elementBytes, ok := model.TensorElementBytes(rep.Tensor.Dtype)
	if !ok {
		return nil, werr.Newf(werr.Unsupported,
			"tensor dtype `%s` has no element width", rep.Tensor.Dtype)
	}
	expected := elementCount * elementBytes
	if uint64(len(baseBytes)) != expected {
		return nil, werr.Newf(werr.Corrupt,
			"delta base length disagrees with the tensor dtype/shape")
	}
	if model.ContentHash(baseBytes) != baseHash {
		return nil, werr.Newf(werr.Corrupt,
			"delta base content hash disagrees with the frame descriptor")
	}
	physical, ok := model.TensorPhysicalDtype(rep.Tensor.Dtype)
	if !ok {
		return nil, werr.Newf(werr.Unsupported,
			"delta dtype has no logical root")
	}
	baseFrame, err := modes.EncodeTensor(baseBytes, physical, rep.Tensor.Shape, lim)
	if err != nil {
		return nil, werr.FromCodec(err)
	}
	var logical []byte
	switch kind {
	case deltaSemantic:
		logical, err = modes.DecodeSemanticDeltaFrameWithBase(
			context.Background(), parsed, baseFrame, dependency.NewMapResolver(), lim)
	case deltaSparse:
		logical, err = modes.DecodeSparseDeltaFrameWithBase(
			context.Background(), parsed, baseFrame, dependency.NewMapResolver(), lim)
	default:
		logical, err = modes.DecodeWeightDeltaFrameWithBase(
			context.Background(), parsed, baseFrame, dependency.NewMapResolver(), lim)
	}
	if err != nil {
		return nil, werr.FromCodec(err)
	}
	if uint64(len(logical)) != rep.DecodedSize {
		return nil, werr.Newf(werr.Corrupt,
			"delta frame decoded length disagrees with the manifest")
	}
	recomputed, err := tensor.LogicalRoot(physical, rep.Tensor.Shape, logical, lim)
	if err != nil {
		return nil, werr.FromCodec(err)
	}
	if recomputed != rep.Tensor.LogicalRoot {
		return nil, werr.Newf(werr.Corrupt,
			"delta logical root recomputation mismatch")
	}
	return logical, nil
}

func decodeTensorKvPage(
	parsed *frame.Frame,
	rep *model.Representation,
	lim limits.Limits,
) ([]byte, error) {
	page, err := modes.DecodeKvPage(parsed, lim)
	if err != nil {
		return nil, werr.FromCodec(err)
	}
	dtype, ok := model.TensorDtypeFromWeightName(page.Meta.Dtype.Name)
	if !ok {
		return nil, werr.Newf(werr.Malformed,
			"unknown weight-dtype `%s`", page.Meta.Dtype.Name)
	}
	if dtype != rep.Tensor.Dtype || !equalShapes(page.Meta.Shape, rep.Tensor.Shape) {
		return nil, werr.Newf(werr.Corrupt,
			"kv-cache descriptor dtype/shape disagree with the manifest")
	}
	physical, ok := model.TensorPhysicalDtype(dtype)
	if !ok {
		return nil, werr.Newf(werr.Unsupported, "kv-cache dtype has no logical root")
	}
	recomputed, err := tensor.LogicalRoot(physical, rep.Tensor.Shape, page.Bytes, lim)
	if err != nil {
		return nil, werr.FromCodec(err)
	}
	if recomputed != rep.Tensor.LogicalRoot {
		return nil, werr.Newf(werr.Corrupt,
			"kv-cache logical root recomputation mismatch")
	}
	return page.Bytes, nil
}

func decodeTensorActivation(
	parsed *frame.Frame,
	rep *model.Representation,
	lim limits.Limits,
) ([]byte, error) {
	chunk, err := modes.DecodeActivationChunk(parsed, lim)
	if err != nil {
		return nil, werr.FromCodec(err)
	}
	dtype, ok := model.TensorDtypeFromWeightName(chunk.Meta.Dtype.Name)
	if !ok {
		return nil, werr.Newf(werr.Malformed,
			"unknown weight-dtype `%s`", chunk.Meta.Dtype.Name)
	}
	if dtype != rep.Tensor.Dtype || !equalShapes(chunk.Meta.Shape, rep.Tensor.Shape) {
		return nil, werr.Newf(werr.Corrupt,
			"activation descriptor dtype/shape disagree with the manifest")
	}
	physical, ok := model.TensorPhysicalDtype(dtype)
	if !ok {
		return nil, werr.Newf(werr.Unsupported, "activation dtype has no logical root")
	}
	recomputed, err := tensor.LogicalRoot(physical, rep.Tensor.Shape, chunk.Bytes, lim)
	if err != nil {
		return nil, werr.FromCodec(err)
	}
	if recomputed != rep.Tensor.LogicalRoot {
		return nil, werr.Newf(werr.Corrupt,
			"activation logical root recomputation mismatch")
	}
	return chunk.Bytes, nil
}
