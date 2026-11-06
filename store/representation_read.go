package store

import (
	"context"

	"github.com/infinityabundance/WeftCodec-Go/dependency"
	"github.com/infinityabundance/WeftCodec-Go/frame"
	"github.com/infinityabundance/WeftCodec-Go/limits"
	"github.com/infinityabundance/WeftCodec-Go/modes"
	"github.com/infinityabundance/WeftCodec-Go/stream"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// readManifestRange is the internal range reader. rootID is the manifest id of
// manifest when known; it seeds the cycle check exactly as the Rust reader
// seeds `seen` with the content root.
func readManifestRange(root string, rootID *model.Hash32, manifest model.Manifest, offset, length uint64, verifyWhole bool) ([]byte, error) {
	if manifest.Size > MaxFileBytes {
		return nil, werr.Newf(werr.LimitExceeded, "manifest size %d exceeds the %d-byte v1 bound", manifest.Size, MaxFileBytes)
	}
	var seen []model.Hash32
	if rootID != nil {
		seen = append(seen, *rootID)
	}
	return readManifestRangeInner(root, manifest, offset, length, verifyWhole, 0, seen)
}

func readManifestRangeInner(root string, manifest model.Manifest, offset, length uint64, verifyWhole bool, depth int, seen []model.Hash32) ([]byte, error) {
	if manifest.Representation != nil && manifest.Representation.Kind == model.RepresentationOverlay {
		return readOverlayRange(root, manifest, manifest.Representation, offset, length, verifyWhole)
	}
	if manifest.Representation != nil && manifest.Representation.Kind == model.RepresentationCodec {
		return readCodecRange(root, manifest, manifest.Representation, offset, length, verifyWhole, depth, seen)
	}
	if manifest.Representation != nil && manifest.Representation.Kind == model.RepresentationTensor {
		return readTensorRange(root, manifest, manifest.Representation, offset, length, verifyWhole, depth, seen)
	}
	return readRawRange(root, manifest, offset, length, verifyWhole)
}

// readOverlayRange resolves a `weft.manifest.v4` base chain to a canonical
// chunk table without fetching any content chunk, then reads only the chunks
// intersecting the requested range.
func readOverlayRange(root string, manifest model.Manifest, rep *model.Representation, offset, length uint64, verifyWhole bool) ([]byte, error) {
	if rep == nil || rep.Overlay == nil {
		return nil, werr.Newf(werr.Corrupt, "overlay representation is missing its overlay map")
	}
	if rep.DecodedSize != manifest.Size {
		return nil, werr.Newf(werr.Corrupt, "overlay representation decoded_size disagrees with manifest size")
	}
	manifestID, err := manifest.ID()
	if err != nil {
		return nil, err
	}
	seenSet := make(map[model.Hash32]struct{})
	table, err := overlayChunkTable(root, manifestID, manifest, rep.Overlay, 0, seenSet)
	if err != nil {
		return nil, err
	}
	return readChunkTableRange(root, table, manifest.Size, manifest.ContentHash,
		model.ContentIdentityMerkleV1, offset, length, verifyWhole)
}

// overlayChunkTable resolves and validates the canonical chunk table of one
// immutable overlay layer over its base chain. Only manifest blobs are read.
func overlayChunkTable(root string, manifestID model.Hash32, manifest model.Manifest,
	overlay *model.OverlayRepresentation, depth int, seen map[model.Hash32]struct{}) ([]model.ChunkRef, error) {
	if depth > int(model.MaxOverlayChainDepth) {
		return nil, werr.Newf(werr.LimitExceeded,
			"overlay chain exceeds the hard bound %d", model.MaxOverlayChainDepth)
	}
	if _, ok := seen[manifestID]; ok {
		return nil, werr.Newf(werr.Corrupt, "overlay base chain participates in a cycle")
	}
	seen[manifestID] = struct{}{}
	if overlay == nil {
		return nil, werr.Newf(werr.Corrupt, "overlay representation is missing its overlay map")
	}
	if err := overlay.ValidateShape(manifest.ChunkSize, manifest.Size); err != nil {
		return nil, err
	}
	baseManifest, err := ReadManifest(root, overlay.Base)
	if err != nil {
		return nil, err
	}
	if baseManifest.ContentHash != overlay.BaseContentRoot {
		return nil, werr.Newf(werr.Corrupt,
			"overlay base %s content root %s disagrees with the declared %s",
			overlay.Base.Hex(), baseManifest.ContentHash.Hex(), overlay.BaseContentRoot.Hex())
	}
	if baseManifest.Size != overlay.BaseSize {
		return nil, werr.Newf(werr.Corrupt,
			"overlay base %s size %d disagrees with the declared %d",
			overlay.Base.Hex(), baseManifest.Size, overlay.BaseSize)
	}
	if baseManifest.ChunkSize != manifest.ChunkSize {
		return nil, werr.Newf(werr.Corrupt, "overlay base chunk_size differs from the new manifest")
	}
	if baseManifest.Identity != model.ContentIdentityMerkleV1 {
		return nil, werr.Newf(werr.Corrupt, "overlay base must use the Merkle content identity")
	}
	if manifest.Size < baseManifest.Size {
		return nil, werr.Newf(werr.Corrupt, "an overlay extent cannot make the file smaller than its base")
	}

	baseOverlayBytes := uint64(0)
	var baseTable []model.ChunkRef
	baseIsOverlay := baseManifest.Representation != nil &&
		baseManifest.Representation.Kind == model.RepresentationOverlay
	if baseIsOverlay {
		baseOverlay := baseManifest.Representation.Overlay
		if baseOverlay == nil {
			return nil, werr.Newf(werr.Corrupt, "overlay base is missing its overlay map")
		}
		if baseOverlay.Depth+1 != overlay.Depth {
			return nil, werr.Newf(werr.Corrupt,
				"overlay depth %d does not follow the base depth %d", overlay.Depth, baseOverlay.Depth)
		}
		baseOverlayBytes = baseOverlay.OverlayBytes
		baseTable, err = overlayChunkTable(root, overlay.Base, baseManifest, baseOverlay, depth+1, seen)
		if err != nil {
			return nil, err
		}
	} else {
		if baseManifest.Representation != nil && baseManifest.Representation.Kind != model.RepresentationRaw {
			return nil, werr.Newf(werr.Corrupt,
				"overlay base must be a chunk table, not a frame-backed representation")
		}
		if overlay.Depth != 1 {
			return nil, werr.Newf(werr.Corrupt,
				"overlay depth %d does not follow a non-overlay base", overlay.Depth)
		}
		baseTable = baseManifest.Chunks
	}
	var baseTotal uint64
	for _, chunk := range baseTable {
		var ok bool
		baseTotal, ok = addNoOverflow(baseTotal, chunk.Len)
		if !ok {
			return nil, werr.Newf(werr.Corrupt, "overlay base table length overflows")
		}
	}
	if baseTotal != baseManifest.Size {
		return nil, werr.Newf(werr.Corrupt, "overlay base chunk table length disagrees with its size")
	}

	table := append([]model.ChunkRef(nil), baseTable...)
	var extentTotal uint64
	var previousEnd *uint64
	for _, extent := range overlay.Extents {
		if previousEnd != nil && extent.Offset < *previousEnd {
			return nil, werr.Newf(werr.Corrupt, "overlay extents are not canonically ordered or overlap")
		}
		end, ok := addNoOverflow(extent.Offset, extent.Length)
		if !ok {
			return nil, werr.Newf(werr.Corrupt, "overlay extent end overflows")
		}
		previousEnd = &end
		extentTotal, ok = addNoOverflow(extentTotal, extent.Length)
		if !ok {
			return nil, werr.Newf(werr.Corrupt, "overlay byte total overflows")
		}
		if extent.Offset%manifest.ChunkSize != 0 {
			return nil, werr.Newf(werr.Malformed, "overlay extent offset is not chunk-aligned")
		}
		start := extent.Offset / manifest.ChunkSize
		if start > uint64(len(table)) {
			return nil, werr.Newf(werr.Corrupt,
				"overlay extent at %d leaves a gap after the base table", extent.Offset)
		}
		startIndex := int(start)
		endIndex := startIndex + len(extent.Chunks)
		if endIndex > len(table) {
			endIndex = len(table)
		}
		next := make([]model.ChunkRef, 0, startIndex+len(extent.Chunks)+len(table)-endIndex)
		next = append(next, table[:startIndex]...)
		next = append(next, extent.Chunks...)
		next = append(next, table[endIndex:]...)
		table = next
	}
	expectedOverlayBytes, ok := addNoOverflow(baseOverlayBytes, extentTotal)
	if !ok {
		return nil, werr.Newf(werr.Corrupt, "overlay byte accounting overflows")
	}
	if overlay.OverlayBytes != expectedOverlayBytes {
		return nil, werr.Newf(werr.Corrupt,
			"overlay_bytes is %d, expected %d", overlay.OverlayBytes, expectedOverlayBytes)
	}
	if uint64(len(table)) > model.MaxChunksPerFile {
		return nil, werr.Newf(werr.LimitExceeded,
			"resolved overlay table exceeds the %d-chunk bound", model.MaxChunksPerFile)
	}
	var total uint64
	for _, chunk := range table {
		total, ok = addNoOverflow(total, chunk.Len)
		if !ok {
			return nil, werr.Newf(werr.Corrupt, "resolved overlay table length overflows")
		}
	}
	if total != manifest.Size {
		return nil, werr.Newf(werr.Corrupt,
			"resolved overlay table sums to %d, manifest size is %d", total, manifest.Size)
	}
	if model.MerkleRootChunks(table) != manifest.ContentHash {
		return nil, werr.Newf(werr.Corrupt,
			"resolved overlay table does not reproduce the manifest content root")
	}
	for index, chunk := range table {
		if index+1 < len(table) && chunk.Len != manifest.ChunkSize {
			return nil, werr.Newf(werr.Corrupt, "resolved overlay table has a short interior chunk")
		}
	}
	return table, nil
}

// readRawRange assembles a byte range from the manifest's chunk references,
// verifying every chunk it touches. v1 manifests and v2 `kind:"raw"`
// manifests share this path byte for byte.
func readRawRange(root string, manifest model.Manifest, offset, length uint64, verifyWhole bool) ([]byte, error) {
	return readChunkTableRange(root, manifest.Chunks, manifest.Size, manifest.ContentHash,
		manifest.Identity, offset, length, verifyWhole)
}

// readChunkTableRange assembles a range from an explicit canonical chunk table.
// It is shared by the raw path and the resolved overlay path.
func readChunkTableRange(root string, chunks []model.ChunkRef, size uint64, contentHash model.Hash32,
	identity model.ContentIdentity, offset, length uint64, verifyWhole bool) ([]byte, error) {
	if offset >= size {
		return []byte{}, nil
	}
	end := offset + length
	if end < offset || end > size {
		end = size
	}
	capacity, err := checkedSize(end - offset)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, capacity)
	var cursor uint64
	for index, chunk := range chunks {
		chunkStart := cursor
		chunkEnd := cursor + chunk.Len
		if chunkEnd < cursor {
			return nil, werr.Newf(werr.Corrupt, "chunk offset overflow")
		}
		cursor = chunkEnd
		if chunkEnd <= offset || chunkStart >= end {
			continue
		}
		bytesValue, err := ReadBlobVerified(root, BlobObject, chunk.Hash, model.DomainChunk)
		if err != nil {
			return nil, werr.Newf(werr.Corrupt, "chunk %d (%s): %s", index, chunk.Hash.Hex(), err.Error())
		}
		if uint64(len(bytesValue)) != chunk.Len {
			return nil, werr.Newf(werr.Corrupt, "chunk %d length disagrees with manifest", index)
		}
		localStart := uint64(0)
		if offset > chunkStart {
			localStart = offset - chunkStart
		}
		localEnd := end - chunkStart
		if localEnd > chunk.Len {
			localEnd = chunk.Len
		}
		out = append(out, bytesValue[localStart:localEnd]...)
	}
	if uint64(len(out)) != end-offset {
		return nil, werr.Newf(werr.Corrupt, "assembled range length mismatch")
	}
	if verifyWhole && offset == 0 && end == size {
		if identity == model.ContentIdentityMerkleV1 {
			if model.MerkleRootChunks(chunks) != contentHash {
				return nil, werr.Newf(werr.Corrupt, "merkle content root mismatch for a fully read file")
			}
		} else if model.ContentHash(out) != contentHash {
			return nil, werr.Newf(werr.Corrupt, "whole-content hash mismatch")
		}
	}
	return out, nil
}

// readCodecRange decodes a v2 `kind:"codec"` representation.
//
// The frame blob is fetched and parsed with the codec's default limits. Its
// payload mode must match the manifest's strategy, its decoded length must
// match the manifest size, and every dependency is materialised from its
// content root (recursively, depth-bounded, cycle-checked) and verified against
// the frame's dependency table. A missing, unreadable, or mismatched dependency
// is Corrupt; no partial or approximate bytes are ever returned.
func readCodecRange(root string, manifest model.Manifest, rep *model.Representation, offset, length uint64, verifyWhole bool, depth int, seen []model.Hash32) ([]byte, error) {
	if depth > MaxCodecDependencyDepth {
		return nil, werr.Newf(werr.Corrupt,
			"codec representation dependency depth exceeds %d", MaxCodecDependencyDepth)
	}
	if rep.Frame == nil {
		return nil, werr.Newf(werr.Corrupt, "codec representation has no frame id")
	}
	if rep.DecodedSize != manifest.Size {
		return nil, werr.Newf(werr.Corrupt,
			"codec representation decoded_size disagrees with manifest size")
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
	expectedMode, ok := codecStrategyMode(rep.Strategy)
	if !ok {
		return nil, werr.Newf(werr.Corrupt, "codec representation has unknown strategy `%s`", rep.Strategy)
	}
	if parsed.Header.Mode != expectedMode {
		return nil, werr.Newf(werr.Corrupt,
			"representation strategy `%s` disagrees with frame mode `%s`",
			rep.Strategy, parsed.Header.Mode)
	}
	if parsed.Header.DecodedLen != manifest.Size {
		return nil, werr.Newf(werr.Corrupt,
			"frame decoded_len %d disagrees with manifest size %d",
			parsed.Header.DecodedLen, manifest.Size)
	}
	if len(parsed.Dependencies) != len(rep.Dependencies) {
		return nil, werr.Newf(werr.Corrupt,
			"representation dependency count disagrees with the frame")
	}

	resolver := dependency.NewMapResolver()
	for index, frameDependency := range parsed.Dependencies {
		depRoot := rep.Dependencies[index]
		if containsHash(seen, depRoot) {
			return nil, werr.Newf(werr.Corrupt, "codec representation dependency cycle")
		}
		depManifest, err := ReadManifest(root, depRoot)
		if err != nil {
			return nil, err
		}
		seen = append(seen, depRoot)
		bytesValue, err := readManifestRangeInner(root, depManifest, 0, depManifest.Size, true, depth+1, seen)
		seen = seen[:len(seen)-1]
		if err != nil {
			return nil, err
		}
		if uint64(len(bytesValue)) != frameDependency.DecodedLen {
			return nil, werr.Newf(werr.Corrupt,
				"dependency %s has length %d but the frame declares %d",
				depRoot.Hex(), len(bytesValue), frameDependency.DecodedLen)
		}
		if model.ContentHash(bytesValue) != frameDependency.Hash {
			return nil, werr.Newf(werr.Corrupt,
				"dependency %s content hash disagrees with the frame", depRoot.Hex())
		}
		resolver.Insert(frameDependency.Hash, bytesValue)
	}

	if offset >= manifest.Size {
		return []byte{}, nil
	}
	wanted := manifest.Size - offset
	if length < wanted {
		wanted = length
	}
	end := offset + wanted
	if end < offset {
		return nil, werr.Newf(werr.Corrupt, "range end overflow")
	}

	var out []byte
	if parsed.Header.IsChunked() && (parsed.Header.Mode == frame.ModeRaw || parsed.Header.Mode == frame.ModeZstd) {
		// The codec's ranged read decodes only the chunks that intersect the
		// requested range and verifies each chunk's hash.
		out, err = stream.ReadRange(context.Background(), frameBytes, resolver, lim, offset, wanted)
		if err != nil {
			return nil, werr.FromCodec(err)
		}
	} else {
		// DELTA/REFERENCE and unchunked frames need the whole plaintext; the
		// codec verifies its own whole-content hash while decoding.
		plaintext, err := modes.DecodeBytes(context.Background(), frameBytes, resolver, lim)
		if err != nil {
			return nil, werr.FromCodec(err)
		}
		start, err := checkedSize(offset)
		if err != nil {
			return nil, err
		}
		stop, err := checkedSize(end)
		if err != nil {
			return nil, err
		}
		if stop > len(plaintext) || start > stop {
			return nil, werr.Newf(werr.Corrupt, "decoded frame is shorter than its header claims")
		}
		out = plaintext[start:stop]
	}
	if uint64(len(out)) != wanted {
		return nil, werr.Newf(werr.Corrupt, "codec range read produced an unexpected length")
	}
	if verifyWhole && offset == 0 && end == manifest.Size {
		if model.ContentHash(out) != manifest.ContentHash {
			return nil, werr.Newf(werr.Corrupt, "whole-content hash mismatch")
		}
	}
	return out, nil
}

func containsHash(haystack []model.Hash32, needle model.Hash32) bool {
	for _, candidate := range haystack {
		if candidate == needle {
			return true
		}
	}
	return false
}

// addNoOverflow returns the sum and whether it is representable. It differs
// from quota's addU64, whose second result reports carry-out.
func addNoOverflow(a, b uint64) (uint64, bool) {
	sum := a + b
	return sum, sum >= a
}
