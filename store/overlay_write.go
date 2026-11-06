// Immutable-overlay writer and compaction (`weft.manifest.v4`).
//
// This is the Go port of the Rust writer in `src/store.rs`. The on-disk
// contract is identical: a range write publishes the previous version as an
// immutable base plus one merged extent, a misaligned edit is widened to the
// enclosing chunk grid, adjacent or overlapping extents fold into the current
// layer while it stays at or below `model.MaxOverlayExtentsPerManifest`, and a
// new layer is published only when folding would exceed that bound or the
// writer's configured chain bounds.
//
// The writer derives the canonical chunk table twice — once by applying the
// edit to the previous table, once by resolving the manifest it is about to
// publish as the reader will — and refuses with `Corrupt` unless the two
// tables are identical. A writer therefore cannot publish an overlay that its
// own reader (or the Rust reader) would resolve differently.
package store

import (
	"sort"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// DefaultMaxOverlayDepth is the writer bound on chained overlay manifests.
// A write that would exceed it is refused with LimitExceeded and names
// compaction, exactly as in Rust.
const DefaultMaxOverlayDepth uint64 = 64

// DefaultMaxOverlayBytes is the writer bound on the total logical bytes carried
// by an overlay chain.
const DefaultMaxOverlayBytes uint64 = 1 << 30

// CompactReport is the outcome of Compact.
type CompactReport struct {
	Object          model.Hash32
	PreviousContent model.Hash32
	Content         model.Hash32
	Version         model.Hash32
	Size            uint64
	ContentRoot     model.Hash32
	Chunks          uint64
	OverlayDepth    uint64
	OverlayBytes    uint64
	VerifiedBytes   uint64
}

// overlayEdit is one byte edit applied to an overlay extent. Data == nil means
// Length zero bytes, so a large zero fill never materialises a buffer.
type overlayEdit struct {
	offset uint64
	length uint64
	data   []byte
}

func overlayBytesEdit(offset uint64, data []byte) overlayEdit {
	return overlayEdit{offset: offset, length: uint64(len(data)), data: data}
}

func overlayZeroEdit(offset, length uint64) overlayEdit {
	return overlayEdit{offset: offset, length: length}
}

func (e overlayEdit) end() (uint64, error) {
	end := e.offset + e.length
	if end < e.offset {
		return 0, werr.Newf(werr.LimitExceeded, "write offset overflows")
	}
	return end, nil
}

// apply applies the part of the edit inside [chunkStart, chunkEnd) to dst,
// which is the chunk's buffer starting at chunkStart.
func (e overlayEdit) apply(chunkStart, chunkEnd uint64, dst []byte) error {
	end, err := e.end()
	if err != nil {
		return err
	}
	start := e.offset
	if chunkStart > start {
		start = chunkStart
	}
	if chunkEnd < end {
		end = chunkEnd
	}
	if start >= end {
		return nil
	}
	dstStart := start - chunkStart
	dstEnd := end - chunkStart
	if e.data != nil {
		srcStart := start - e.offset
		srcEnd := end - e.offset
		copy(dst[dstStart:dstEnd], e.data[srcStart:srcEnd])
		return nil
	}
	clear(dst[dstStart:dstEnd])
	return nil
}

// canonicalChunkTable returns the canonical chunk table of a manifest the
// writer may build on: a v3 chunk table or a resolved v4 overlay chain. A
// frame-backed representation is refused; there is no table to extend.
func canonicalChunkTable(src blobSource, manifestID model.Hash32, manifest model.Manifest) ([]model.ChunkRef, error) {
	rep := manifest.Representation
	if rep == nil || rep.Kind == model.RepresentationRaw {
		if manifest.Identity != model.ContentIdentityMerkleV1 {
			return nil, werr.Newf(werr.InvalidArgument,
				"overlay writes require a Merkle (`weft.manifest.v3`) base; "+
					"re-create the file with `--content-identity merkle`")
		}
		table := make([]model.ChunkRef, len(manifest.Chunks))
		copy(table, manifest.Chunks)
		if err := validateCanonicalTable(table, manifest.ChunkSize, manifest.Size, manifest.ContentHash); err != nil {
			return nil, err
		}
		return table, nil
	}
	if rep.Kind == model.RepresentationOverlay {
		if rep.Overlay == nil {
			return nil, werr.Newf(werr.Corrupt, "overlay representation is missing its overlay map")
		}
		seen := make(map[model.Hash32]struct{})
		return overlayChunkTable(src, manifestID, manifest, rep.Overlay, 0, seen)
	}
	return nil, werr.Newf(werr.InvalidArgument,
		"overlay writes require a chunk-table base, not a frame-backed representation")
}

// validateCanonicalTable enforces the chunk-grid shape, the total length, and
// the Merkle root of a base table before a writer extends it.
func validateCanonicalTable(table []model.ChunkRef, chunkSize, size uint64, contentRoot model.Hash32) error {
	if chunkSize == 0 || chunkSize > model.MaxChunkSize {
		return werr.Newf(werr.InvalidArgument, "chunk size is out of range")
	}
	if uint64(len(table)) > model.MaxChunksPerFile {
		return werr.Newf(werr.LimitExceeded, "manifest exceeds the %d-chunk bound", model.MaxChunksPerFile)
	}
	var total uint64
	for index, chunk := range table {
		if chunk.Len == 0 {
			return werr.Newf(werr.Corrupt, "base chunk has zero length")
		}
		if index+1 < len(table) && chunk.Len != chunkSize {
			return werr.Newf(werr.Corrupt, "base chunk table has a short interior chunk")
		}
		if total > ^uint64(0)-chunk.Len {
			return werr.Newf(werr.Corrupt, "base chunk table length overflows")
		}
		total += chunk.Len
	}
	if total != size {
		return werr.Newf(werr.Corrupt,
			"base chunk table sums to %d, manifest size is %d", total, size)
	}
	if model.MerkleRootChunks(table) != contentRoot {
		return werr.Newf(werr.Corrupt, "base chunk table does not reproduce the manifest content root")
	}
	return nil
}

// applyOverlayExtents applies extents to a base table exactly as the reader
// does: each extent replaces the chunk references at its grid positions and may
// append past the base end.
func applyOverlayExtents(base []model.ChunkRef, chunkSize uint64, extents []model.OverlayExtent, size uint64) ([]model.ChunkRef, error) {
	if chunkSize == 0 {
		return nil, werr.Newf(werr.Malformed, "overlay chunk_size is out of range")
	}
	table := make([]model.ChunkRef, len(base))
	copy(table, base)
	for _, extent := range extents {
		start := extent.Offset / chunkSize
		if start > uint64(len(table)) {
			return nil, werr.Newf(werr.Corrupt, "overlay extent leaves a gap after the base table")
		}
		end := start + uint64(len(extent.Chunks))
		if end < start {
			return nil, werr.Newf(werr.Corrupt, "overlay extent chunk count overflows")
		}
		if end > uint64(len(table)) {
			end = uint64(len(table))
		}
		next := make([]model.ChunkRef, 0, int(start)+len(extent.Chunks)+len(table)-int(end))
		next = append(next, table[:start]...)
		next = append(next, extent.Chunks...)
		next = append(next, table[end:]...)
		table = next
	}
	var total uint64
	for _, chunk := range table {
		if total > ^uint64(0)-chunk.Len {
			return nil, werr.Newf(werr.Corrupt, "overlay table size overflows")
		}
		total += chunk.Len
	}
	if total != size {
		return nil, werr.Newf(werr.Corrupt,
			"overlay table sums to %d, declared size is %d", total, size)
	}
	return table, nil
}

// writeFileOverlay applies byte edits as one immutable overlay layer over the
// previous version. The caller supplies the already-read previous manifest.
func (s *Store) writeFileOverlay(
	id model.Hash32,
	old model.ObjectRecord,
	oldManifest model.Manifest,
	edits []overlayEdit,
	newSize uint64,
	causal []model.Hash32,
) (WriteOutcome, error) {
	if oldManifest.Identity != model.ContentIdentityMerkleV1 {
		return WriteOutcome{}, werr.Newf(werr.InvalidArgument,
			"overlay writes require a Merkle (`weft.manifest.v3`) base; "+
				"re-create the file with `--content-identity merkle`")
	}
	chunkSize := oldManifest.ChunkSize
	if chunkSize == 0 || chunkSize > model.MaxChunkSize {
		return WriteOutcome{}, werr.Newf(werr.InvalidArgument, "chunk size is out of range")
	}
	if newSize < oldManifest.Size {
		return WriteOutcome{}, werr.Newf(werr.InvalidArgument,
			"range write exceeds the target file size")
	}
	if newSize > MaxFileBytes {
		return WriteOutcome{}, werr.Newf(werr.LimitExceeded,
			"file exceeds the %d-byte v1 bound", MaxFileBytes)
	}
	oldTable, err := canonicalChunkTable(s.blobs, old.Content, oldManifest)
	if err != nil {
		return WriteOutcome{}, err
	}
	var oldTotal uint64
	for _, chunk := range oldTable {
		if oldTotal > ^uint64(0)-chunk.Len {
			return WriteOutcome{}, werr.Newf(werr.Corrupt, "base chunk table size overflows")
		}
		oldTotal += chunk.Len
	}
	if oldTotal != old.Size {
		return WriteOutcome{}, werr.Newf(werr.Corrupt,
			"base chunk table length disagrees with the object size")
	}

	// Which chunks the edits touch. Only those are read or rewritten.
	touched := make(map[uint64][]int)
	var first uint64 = ^uint64(0)
	var last uint64
	for index, edit := range edits {
		if edit.length == 0 {
			continue
		}
		end, err := edit.end()
		if err != nil {
			return WriteOutcome{}, err
		}
		if end > newSize {
			return WriteOutcome{}, werr.Newf(werr.InvalidArgument,
				"range write exceeds the target file size")
		}
		startChunk := edit.offset / chunkSize
		endChunk := (end - 1) / chunkSize
		if startChunk < first {
			first = startChunk
		}
		if endChunk > last {
			last = endChunk
		}
		for chunk := startChunk; chunk <= endChunk; chunk++ {
			touched[chunk] = append(touched[chunk], index)
		}
	}
	if first == ^uint64(0) {
		return WriteOutcome{Version: old.Version, Content: old.Content, Size: old.Size}, nil
	}
	totalChunks := newSize / chunkSize
	if newSize%chunkSize != 0 {
		totalChunks++
	}
	if totalChunks > model.MaxChunksPerFile {
		return WriteOutcome{}, werr.Newf(werr.LimitExceeded,
			"manifest exceeds the %d-chunk bound", model.MaxChunksPerFile)
	}
	oldChunks := old.Size / chunkSize
	if old.Size%chunkSize != 0 {
		oldChunks++
	}
	spanFirst := first
	spanLast := last
	if newSize > old.Size {
		// Growing the file must re-encode the old final chunk (it may be short)
		// and any chunk skipped by a write that starts past EOF.
		if oldChunks > 0 && oldChunks-1 < spanFirst {
			spanFirst = oldChunks - 1
		}
	}

	// Publication shape: fold into the current overlay layer when its extent
	// list survives the merge, otherwise publish a new layer.
	var oldOverlay *model.OverlayRepresentation
	if oldManifest.Representation != nil && oldManifest.Representation.Kind == model.RepresentationOverlay {
		oldOverlay = oldManifest.Representation.Overlay
	}
	var keptExtents []model.OverlayExtent
	var baseID model.Hash32
	var baseRoot model.Hash32
	var baseSize, baseDepth, baseChainBytes uint64
	if oldOverlay != nil {
		var oldExtentTotal uint64
		for _, extent := range oldOverlay.Extents {
			if oldExtentTotal > ^uint64(0)-extent.Length {
				return WriteOutcome{}, werr.Newf(werr.Corrupt, "overlay byte total overflows")
			}
			oldExtentTotal += extent.Length
		}
		if oldExtentTotal > oldOverlay.OverlayBytes {
			return WriteOutcome{}, werr.Newf(werr.Corrupt,
				"overlay_bytes is smaller than the base layer's extents")
		}
		chainBytes := oldOverlay.OverlayBytes - oldExtentTotal
		for _, extent := range oldOverlay.Extents {
			extentFirst := extent.Offset / chunkSize
			extentLastExclusive := extentFirst + uint64(len(extent.Chunks))
			touches := extentFirst <= spanLast+1 && spanFirst <= extentLastExclusive
			if touches {
				if extentFirst < spanFirst {
					spanFirst = extentFirst
				}
				if extentLastExclusive > 0 && extentLastExclusive-1 > spanLast {
					spanLast = extentLastExclusive - 1
				}
			} else {
				keptExtents = append(keptExtents, extent)
			}
		}
		if uint64(len(keptExtents))+1 <= model.MaxOverlayExtentsPerManifest {
			baseID = oldOverlay.Base
			baseRoot = oldOverlay.BaseContentRoot
			baseSize = oldOverlay.BaseSize
			baseDepth = oldOverlay.Depth - 1
			baseChainBytes = chainBytes
		} else {
			keptExtents = nil
			baseID = old.Content
			baseRoot = oldManifest.ContentHash
			baseSize = oldManifest.Size
			baseDepth = oldOverlay.Depth
			baseChainBytes = oldOverlay.OverlayBytes
		}
	} else {
		baseID = old.Content
		baseRoot = oldManifest.ContentHash
		baseSize = oldManifest.Size
		baseDepth = 0
		baseChainBytes = 0
	}
	newDepth := baseDepth + 1
	if newDepth < baseDepth {
		return WriteOutcome{}, werr.Newf(werr.LimitExceeded, "overlay depth overflows")
	}
	maxDepth := s.options.MaxOverlayDepth
	if maxDepth == 0 {
		maxDepth = DefaultMaxOverlayDepth
	}
	if newDepth > maxDepth {
		return WriteOutcome{}, werr.Newf(werr.LimitExceeded,
			"overlay depth %d exceeds the configured writer bound %d; "+
				"run `weftfs compact <path>` to canonicalise the file", newDepth, maxDepth)
	}

	// Re-encode exactly the chunks the merged extent covers.
	spanCount := spanLast - spanFirst + 1
	if spanCount > model.MaxChunksPerFile {
		return WriteOutcome{}, werr.Newf(werr.LimitExceeded,
			"overlay extent exceeds the %d-chunk bound", model.MaxChunksPerFile)
	}
	extentChunks := make([]model.ChunkRef, 0, spanCount)
	changed := false
	for index := spanFirst; index <= spanLast; index++ {
		chunkStart := index * chunkSize
		chunkEnd := chunkStart + chunkSize
		if chunkEnd > newSize {
			chunkEnd = newSize
		}
		if chunkEnd <= chunkStart {
			return WriteOutcome{}, werr.Newf(werr.Corrupt, "overlay span lies past the new file size")
		}
		chunkLen := chunkEnd - chunkStart
		var oldRef *model.ChunkRef
		if index < uint64(len(oldTable)) {
			oldRef = &oldTable[index]
		}
		overlapping := touched[index]
		if oldRef != nil && oldRef.Len == chunkLen && len(overlapping) == 0 {
			// An untouched chunk inside the extent keeps its old reference
			// verbatim; its blob is not read.
			extentChunks = append(extentChunks, *oldRef)
			continue
		}
		assembled := make([]byte, chunkLen)
		var oldBytes []byte
		if oldRef != nil {
			keep := chunkLen
			if oldRef.Len < keep {
				keep = oldRef.Len
			}
			if keep > 0 {
				stored, err := readBlobVerified(s.blobs, BlobObject, oldRef.Hash, model.DomainChunk)
				if err != nil {
					return WriteOutcome{}, err
				}
				s.writeChunkReads.Add(1)
				if uint64(len(stored)) != oldRef.Len {
					return WriteOutcome{}, werr.Newf(werr.Corrupt, "chunk length disagrees with manifest")
				}
				copy(assembled[:keep], stored[:keep])
				oldBytes = stored
			}
		}
		for _, editIndex := range overlapping {
			if err := edits[editIndex].apply(chunkStart, chunkEnd, assembled); err != nil {
				return WriteOutcome{}, err
			}
		}
		if oldRef != nil && oldBytes != nil && oldRef.Len == chunkLen && overlayBytesSame(assembled, oldBytes) {
			extentChunks = append(extentChunks, *oldRef)
			continue
		}
		changed = true
		hash, err := s.storeBlob(BlobObject, model.DomainChunk, assembled)
		if err != nil {
			return WriteOutcome{}, err
		}
		extentChunks = append(extentChunks, model.ChunkRef{Hash: hash, Len: chunkLen})
	}
	if !changed && newSize == old.Size {
		return WriteOutcome{Version: old.Version, Content: old.Content, Size: old.Size}, nil
	}

	// The expected canonical table: the previous table with the extent span
	// replaced.
	if spanFirst > uint64(len(oldTable)) {
		return WriteOutcome{}, werr.Newf(werr.Corrupt, "overlay extent leaves a gap after the base table")
	}
	expected := make([]model.ChunkRef, 0, uint64(len(oldTable))+uint64(len(extentChunks)))
	expected = append(expected, oldTable[:spanFirst]...)
	expected = append(expected, extentChunks...)
	resume := spanLast + 1
	if resume < uint64(len(oldTable)) {
		expected = append(expected, oldTable[resume:]...)
	}
	var expectedTotal uint64
	for _, chunk := range expected {
		if expectedTotal > ^uint64(0)-chunk.Len {
			return WriteOutcome{}, werr.Newf(werr.Corrupt, "derived chunk table size overflows")
		}
		expectedTotal += chunk.Len
	}
	if expectedTotal != newSize {
		return WriteOutcome{}, werr.Newf(werr.Corrupt,
			"derived overlay table sums to %d, new size is %d", expectedTotal, newSize)
	}
	for index, chunk := range expected {
		if index+1 < len(expected) && chunk.Len != chunkSize {
			return WriteOutcome{}, werr.Newf(werr.Corrupt,
				"derived overlay table has a short interior chunk")
		}
	}

	extents := append([]model.OverlayExtent(nil), keptExtents...)
	extents = append(extents, model.OverlayExtent{
		Offset: spanFirst * chunkSize,
		Length: chunkEndOf(spanLast, chunkSize, newSize) - spanFirst*chunkSize,
		Chunks: extentChunks,
	})
	sort.SliceStable(extents, func(i, j int) bool { return extents[i].Offset < extents[j].Offset })
	var extentTotal uint64
	for _, extent := range extents {
		if extentTotal > ^uint64(0)-extent.Length {
			return WriteOutcome{}, werr.Newf(werr.Corrupt, "overlay byte total overflows")
		}
		extentTotal += extent.Length
	}
	overlayBytes := baseChainBytes + extentTotal
	if overlayBytes < baseChainBytes {
		return WriteOutcome{}, werr.Newf(werr.LimitExceeded, "overlay byte accounting overflows")
	}
	maxOverlayBytes := s.options.MaxOverlayBytes
	if maxOverlayBytes == 0 {
		maxOverlayBytes = DefaultMaxOverlayBytes
	}
	if overlayBytes > maxOverlayBytes {
		return WriteOutcome{}, werr.Newf(werr.LimitExceeded,
			"overlay chain would carry %d bytes, above the configured writer bound %d; "+
				"run `weftfs compact <path>` to canonicalise the file", overlayBytes, maxOverlayBytes)
	}

	// Fail closed unless the manifest the reader will resolve is exactly the
	// table this writer derived.
	var baseManifest model.Manifest
	baseTable := oldTable
	if baseID == old.Content {
		baseManifest = oldManifest
	} else {
		baseManifest, err = readManifest(s.blobs, baseID)
		if err != nil {
			return WriteOutcome{}, err
		}
	}
	if baseManifest.ContentHash != baseRoot || baseManifest.Size != baseSize {
		return WriteOutcome{}, werr.Newf(werr.Corrupt,
			"overlay base disagrees with the previous version's declared base")
	}
	if baseID != old.Content {
		baseTable, err = canonicalChunkTable(s.blobs, baseID, baseManifest)
		if err != nil {
			return WriteOutcome{}, err
		}
	}
	derived, err := applyOverlayExtents(baseTable, chunkSize, extents, newSize)
	if err != nil {
		return WriteOutcome{}, err
	}
	if len(derived) != len(expected) {
		return WriteOutcome{}, werr.Newf(werr.Corrupt,
			"overlay writer derived a different table than the reader will build")
	}
	for index := range derived {
		if derived[index] != expected[index] {
			return WriteOutcome{}, werr.Newf(werr.Corrupt,
				"overlay writer derived a different table than the reader will build")
		}
	}
	contentRoot := model.MerkleRootChunks(expected)

	manifest := model.Manifest{
		Size:        newSize,
		ChunkSize:   chunkSize,
		ContentHash: contentRoot,
		Identity:    model.ContentIdentityMerkleV1,
		Representation: &model.Representation{
			Kind:        model.RepresentationOverlay,
			Strategy:    "overlay",
			DecodedSize: newSize,
			Overlay: &model.OverlayRepresentation{
				Base:            baseID,
				BaseContentRoot: baseRoot,
				BaseSize:        baseSize,
				Depth:           newDepth,
				OverlayBytes:    overlayBytes,
				Extents:         extents,
			},
		},
	}
	manifestID, _, _, err := s.storeManifest(manifest)
	if err != nil {
		return WriteOutcome{}, err
	}
	version, err := s.publishFileWrite(id, old, manifestID, newSize, causal)
	if err != nil {
		return WriteOutcome{}, err
	}
	return WriteOutcome{Version: version, Content: manifestID, Size: newSize}, nil
}

// chunkEndOf returns the exclusive end offset of chunk `index` for a file of
// `size` bytes and the given chunk size.
func chunkEndOf(index, chunkSize, size uint64) uint64 {
	end := index*chunkSize + chunkSize
	if end > size {
		end = size
	}
	return end
}

func overlayBytesSame(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Compact canonicalises an overlay-represented file into one
// `weft.manifest.v3` chunk table.
//
// Every logical chunk is re-read and re-hashed in order (bounded to one chunk
// of memory), the Merkle root is recomputed, and it MUST equal the
// pre-compaction content root. Any mismatch fails closed with Corrupt before a
// manifest or commit is published.
func (s *Store) Compact(id model.Hash32) (CompactReport, error) {
	if err := s.requireWritable(); err != nil {
		return CompactReport{}, err
	}
	old, ok := s.state.Objects[id]
	if !ok {
		return CompactReport{}, werr.Newf(werr.NotFound, "no such object")
	}
	if old.Kind != model.KindFile {
		return CompactReport{}, werr.Newf(werr.InvalidArgument, "compact requires a file object")
	}
	oldManifest, err := readManifest(s.blobs, old.Content)
	if err != nil {
		return CompactReport{}, err
	}
	if oldManifest.Size != old.Size {
		return CompactReport{}, werr.Newf(werr.Corrupt, "object size disagrees with manifest")
	}
	if oldManifest.Representation == nil || oldManifest.Representation.Kind != model.RepresentationOverlay ||
		oldManifest.Representation.Overlay == nil {
		return CompactReport{}, werr.Newf(werr.InvalidArgument,
			"compact requires an overlay-represented object")
	}
	overlay := oldManifest.Representation.Overlay
	table, err := canonicalChunkTable(s.blobs, old.Content, oldManifest)
	if err != nil {
		return CompactReport{}, err
	}
	if uint64(len(table)) > model.MaxChunksPerFile {
		return CompactReport{}, werr.Newf(werr.LimitExceeded,
			"manifest exceeds the %d-chunk bound", model.MaxChunksPerFile)
	}
	var verifiedBytes uint64
	for index, chunk := range table {
		bytesValue, err := readBlobVerified(s.blobs, BlobObject, chunk.Hash, model.DomainChunk)
		if err != nil {
			return CompactReport{}, err
		}
		if uint64(len(bytesValue)) != chunk.Len {
			return CompactReport{}, werr.Newf(werr.Corrupt,
				"chunk %d length disagrees with the overlay table", index)
		}
		if verifiedBytes > ^uint64(0)-chunk.Len {
			return CompactReport{}, werr.Newf(werr.Corrupt, "verified byte total overflows")
		}
		verifiedBytes += chunk.Len
	}
	if verifiedBytes != oldManifest.Size {
		return CompactReport{}, werr.Newf(werr.Corrupt,
			"verified %d bytes, manifest size is %d", verifiedBytes, oldManifest.Size)
	}
	contentRoot := model.MerkleRootChunks(table)
	if contentRoot != oldManifest.ContentHash {
		return CompactReport{}, werr.Newf(werr.Corrupt,
			"compaction would change the content root; refusing to publish")
	}
	compacted := model.Manifest{
		Size:        oldManifest.Size,
		ChunkSize:   oldManifest.ChunkSize,
		Chunks:      table,
		ContentHash: contentRoot,
		Identity:    model.ContentIdentityMerkleV1,
	}
	encoded, err := compacted.Encode()
	if err != nil {
		return CompactReport{}, err
	}
	roundTripValue, err := model.DecodeWCB(encoded)
	if err != nil {
		return CompactReport{}, err
	}
	roundTrip, err := model.ManifestFromWCB(roundTripValue)
	if err != nil {
		return CompactReport{}, err
	}
	if roundTrip.ContentHash != oldManifest.ContentHash || roundTrip.Size != oldManifest.Size ||
		len(roundTrip.Chunks) != len(table) {
		return CompactReport{}, werr.Newf(werr.Corrupt,
			"compacted manifest does not reproduce the pre-compaction table")
	}
	for index := range table {
		if roundTrip.Chunks[index] != table[index] {
			return CompactReport{}, werr.Newf(werr.Corrupt,
				"compacted manifest does not reproduce the pre-compaction table")
		}
	}
	manifestID, _, _, err := s.storeManifest(compacted)
	if err != nil {
		return CompactReport{}, err
	}
	previousContent := old.Content
	version, err := s.publishFileWrite(id, old, manifestID, oldManifest.Size, nil)
	if err != nil {
		return CompactReport{}, err
	}
	return CompactReport{
		Object:          id,
		PreviousContent: previousContent,
		Content:         manifestID,
		Version:         version,
		Size:            oldManifest.Size,
		ContentRoot:     contentRoot,
		Chunks:          uint64(len(table)),
		OverlayDepth:    overlay.Depth,
		OverlayBytes:    overlay.OverlayBytes,
		VerifiedBytes:   verifiedBytes,
	}, nil
}
