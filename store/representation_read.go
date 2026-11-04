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
	if manifest.Representation != nil && manifest.Representation.Kind == model.RepresentationCodec {
		return readCodecRange(root, manifest, manifest.Representation, offset, length, verifyWhole, depth, seen)
	}
	return readRawRange(root, manifest, offset, length, verifyWhole)
}

// readRawRange assembles a byte range from the manifest's chunk references,
// verifying every chunk it touches. v1 manifests and v2 `kind:"raw"`
// manifests share this path byte for byte.
func readRawRange(root string, manifest model.Manifest, offset, length uint64, verifyWhole bool) ([]byte, error) {
	if offset >= manifest.Size {
		return []byte{}, nil
	}
	end := offset + length
	if end < offset || end > manifest.Size {
		end = manifest.Size
	}
	capacity, err := checkedSize(end - offset)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, capacity)
	var cursor uint64
	for _, chunk := range manifest.Chunks {
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
			return nil, err
		}
		if uint64(len(bytesValue)) != chunk.Len {
			return nil, werr.Newf(werr.Corrupt, "chunk length disagrees with manifest")
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
	if verifyWhole && offset == 0 && end == manifest.Size {
		if model.ContentHash(out) != manifest.ContentHash {
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
