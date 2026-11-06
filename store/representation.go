// Experimental `weft.manifest.v2` representation support.
//
// A v2 manifest can name a WFT1 frame blob as the physical representation of a
// file's logical bytes. This file holds the policy constants shared by the
// writer, reader, GC, and verify paths, and the writer-side encoding rules.
//
// The constants mirror the Rust reference:
//   - `weft/WeftFS/../src/representation.rs` (chunk size, zstd level)
//   - `weft/src/store.rs` (DEFAULT_CODEC_MIN_BYTES,
//     DEFAULT_CODEC_DELTA_MARGIN_PERCENT)
//
// They are duplicated because the Go implementation is independent; a change
// here must be matched in Rust.
package store

import (
	"github.com/infinityabundance/WeftCodec-Go/frame"
	"github.com/infinityabundance/WeftCodec-Go/limits"
	"github.com/infinityabundance/WeftCodec-Go/modes"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// MaxCodecDependencyDepth is the maximum transitive dependency depth for a
// codec representation. Depth 0 is the manifest itself; a dependency at depth 9
// is rejected.
const MaxCodecDependencyDepth = 8

// CodecChunkSizeMax is the largest codec frame chunk size the writer chooses.
const CodecChunkSizeMax uint64 = 64 * 1024

// CodecChunkSizeMin is the smallest codec frame chunk size the writer chooses.
const CodecChunkSizeMin uint64 = 4 * 1024

// CodecZstdLevel is the zstd level used by the experimental auto representation.
const CodecZstdLevel = 3

// DefaultCodecMinBytes is the threshold below which `codec-auto` leaves a file
// on the raw path.
const DefaultCodecMinBytes uint64 = 4 * 1024

// DefaultCodecDeltaMarginPercent is the margin by which a DELTA frame must beat
// a ZSTD frame, in percent.
const DefaultCodecDeltaMarginPercent uint8 = 10

// RepresentationMode is the physical representation policy for new content.
type RepresentationMode string

const (
	// RepresentationModeRaw writes the frozen v1 chunk manifest.
	RepresentationModeRaw RepresentationMode = "raw"
	// RepresentationModeCodecAuto writes experimental v2 manifests, selecting
	// ZSTD or DELTA when the frame is smaller.
	RepresentationModeCodecAuto RepresentationMode = "codec-auto"
	// RepresentationModeOverlay writes a v3 Merkle base and publishes every
	// later range write as a `weft.manifest.v4` immutable-overlay layer.
	RepresentationModeOverlay RepresentationMode = "overlay"
)

// ParseRepresentationMode parses the canonical CLI spelling.
func ParseRepresentationMode(text string) (RepresentationMode, error) {
	switch text {
	case string(RepresentationModeRaw):
		return RepresentationModeRaw, nil
	case string(RepresentationModeCodecAuto):
		return RepresentationModeCodecAuto, nil
	case string(RepresentationModeOverlay):
		return RepresentationModeOverlay, nil
	default:
		return "", werr.Newf(werr.InvalidArgument,
			"--representation must be `raw`, `codec-auto`, or `overlay` (got `%s`)", text)
	}
}

// AsString returns the canonical CLI spelling.
func (m RepresentationMode) AsString() string { return string(m) }

// ParseContentIdentity parses `whole-file` or `merkle`.
func ParseContentIdentity(text string) (model.ContentIdentity, error) {
	switch text {
	case "whole-file":
		return model.ContentIdentityWholeFile, nil
	case "merkle":
		return model.ContentIdentityMerkleV1, nil
	default:
		return "", werr.Newf(werr.InvalidArgument,
			"--content-identity must be `whole-file` or `merkle` (got `%s`)", text)
	}
}

// ContentIdentityString returns the canonical CLI spelling.
func ContentIdentityString(identity model.ContentIdentity) string {
	if identity == model.ContentIdentityMerkleV1 {
		return "merkle"
	}
	return "whole-file"
}

// codecChunkSize returns the codec frame chunk size for a store chunk size,
// clamped to the Rust bounds.
func codecChunkSize(storeChunkSize uint64) uint64 {
	if storeChunkSize < CodecChunkSizeMin {
		return CodecChunkSizeMin
	}
	if storeChunkSize > CodecChunkSizeMax {
		return CodecChunkSizeMax
	}
	return storeChunkSize
}

// deltaBase is a causal base resolved to a content root and plaintext.
type deltaBase struct {
	root  model.Hash32
	bytes []byte
}

// deltaBaseFor resolves the first causal parent that names a live file version
// to its content root and bytes. An unavailable base is skipped, never assumed.
func (s *Store) deltaBaseFor(causal []model.Hash32) (*deltaBase, error) {
	if s.options.Representation != RepresentationModeCodecAuto || len(causal) == 0 {
		return nil, nil
	}
	ids := model.SortHashKeys(s.state.Objects)
	for _, parent := range causal {
		for _, id := range ids {
			record := s.state.Objects[id]
			if record.Kind != model.KindFile || record.Version != parent {
				continue
			}
			bytes, err := s.ReadContent(record.Content, 0, record.Size)
			if err != nil {
				continue
			}
			return &deltaBase{root: record.Content, bytes: bytes}, nil
		}
	}
	return nil, nil
}

// tryCodecRepresentation builds a codec representation.
//
// It mirrors the Rust selection rule exactly: encode chunked ZSTD at level 3;
// when a base is available also encode DELTA; DELTA wins only when
// `delta_len * 100 <= zstd_len * (100 - margin)` (or, with no ZSTD frame, when
// it beats the raw bytes). The chosen frame must be strictly smaller than the
// plaintext, otherwise the caller writes a v2 `kind:"raw"` manifest.
func (s *Store) tryCodecRepresentation(data []byte, chunkSize uint64, base *deltaBase) (*model.Representation, []byte, error) {
	lim := limits.Default()
	codecChunk := codecChunkSize(chunkSize)
	codecChunkInt, err := checkedSize(codecChunk)
	if err != nil {
		return nil, nil, err
	}

	var chosenFrame []byte
	var strategy string
	var dependencies []model.Hash32

	if zstdFrame, err := modes.EncodeZstd(data, CodecZstdLevel, codecChunkInt, lim); err == nil {
		chosenFrame = zstdFrame
		strategy = model.StrategyZstd
	}

	if base != nil {
		if deltaFrame, err := modes.EncodeDelta(data, base.bytes, lim); err == nil {
			margin := s.options.CodecDeltaMarginPercent
			if margin > 90 {
				margin = 90
			}
			wins := false
			if chosenFrame != nil {
				wins = uint64(len(deltaFrame))*100 <=
					uint64(len(chosenFrame))*uint64(100-margin)
			} else {
				wins = len(deltaFrame) < len(data)
			}
			if wins {
				chosenFrame = deltaFrame
				strategy = model.StrategyDelta
				dependencies = []model.Hash32{base.root}
			}
		}
	}

	if chosenFrame == nil || len(chosenFrame) >= len(data) {
		return nil, nil, nil
	}
	return &model.Representation{
		Kind:         model.RepresentationCodec,
		Frame:        nil, // filled by the caller after storing the frame blob
		Dependencies: dependencies,
		Strategy:     strategy,
		DecodedSize:  uint64(len(data)),
	}, chosenFrame, nil
}

// codecStrategyMode maps a manifest strategy to its required frame mode.
func codecStrategyMode(strategy string) (frame.Mode, bool) {
	switch strategy {
	case model.StrategyZstd:
		return frame.ModeZstd, true
	case model.StrategyDelta:
		return frame.ModeDelta, true
	case model.StrategyReference:
		return frame.ModeReference, true
	default:
		return 0, false
	}
}
