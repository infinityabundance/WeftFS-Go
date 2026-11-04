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
	root string,
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
	frameBytes, err := ReadBlobVerified(root, BlobManifest, *rep.Frame, model.DomainManifest)
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
	case 10:
		logical, err = decodeTensorMode10(parsed, rep, manifest, lim)
	case 11:
		logical, err = decodeTensorDelta(root, parsed, rep, depth, seen, false, lim)
	case 14:
		logical, err = decodeTensorDelta(root, parsed, rep, depth, seen, true, lim)
	case 12:
		logical, err = decodeTensorKvPage(parsed, rep, lim)
	case 13:
		logical, err = decodeTensorActivation(parsed, rep, lim)
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

func tensorFrameMode(mode uint32) (frame.Mode, bool) {
	switch mode {
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
	default:
		return 0, false
	}
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
	root string,
	parsed *frame.Frame,
	rep *model.Representation,
	depth int,
	seen []model.Hash32,
	semantic bool,
	lim limits.Limits,
) ([]byte, error) {
	var descriptorDtype string
	var descriptorShape []uint64
	var baseHash model.Hash32
	if semantic {
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
	} else {
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
	depManifest, err := ReadManifest(root, depRoot)
	if err != nil {
		return nil, err
	}
	seen = append(seen, depRoot)
	baseBytes, err := readManifestRangeInner(root, depManifest, 0, depManifest.Size, true, depth+1, seen)
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
	if semantic {
		logical, err = modes.DecodeSemanticDeltaFrameWithBase(
			context.Background(), parsed, baseFrame, dependency.NewMapResolver(), lim)
	} else {
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
