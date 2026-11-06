package store

import (
	"bytes"
	"encoding/hex"
	"sort"

	weftcontext "github.com/infinityabundance/WeftCodec-Go/context"
	"github.com/infinityabundance/WeftCodec-Go/limits"
	"github.com/infinityabundance/WeftCodec-Go/selector"
	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/resolver"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// CreateFile creates a regular file and commits atomically.
func (s *Store) CreateFile(parent model.Hash32, name []byte, data []byte, mode, uid, gid uint64, attrs map[string]wcb.Value) (model.Hash32, error) {
	seed, err := randomSeed()
	if err != nil {
		return model.Hash32{}, err
	}
	return s.CreateFileSeeded(parent, name, data, mode, uid, gid, attrs, seed)
}

// CreateFileSeeded creates a regular file with an explicit ObjectId seed.
func (s *Store) CreateFileSeeded(parent model.Hash32, name []byte, data []byte, mode, uid, gid uint64, attrs map[string]wcb.Value, seed []byte) (model.Hash32, error) {
	return s.CreateFileSeededCausal(parent, name, data, mode, uid, gid, attrs, seed, nil)
}

// CreateFileSeededCausal creates a regular file with optional causal_exact
// ancestry. A non-empty causal slice selects causal_exact; nil/empty keeps the
// frozen bytes_only v1 identity.
func (s *Store) CreateFileSeededCausal(parent model.Hash32, name []byte, data []byte, mode, uid, gid uint64, attrs map[string]wcb.Value, seed []byte, causal []model.Hash32) (model.Hash32, error) {
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
	if err := checkMode(mode); err != nil {
		return model.Hash32{}, err
	}
	if uint64(len(data)) > MaxFileBytes {
		return model.Hash32{}, werr.Newf(werr.LimitExceeded, "file exceeds the %d-byte v1 bound", MaxFileBytes)
	}
	base, err := s.deltaBaseFor(causal)
	if err != nil {
		return model.Hash32{}, err
	}
	manifestID, _, size, err := s.storeFileContentWithBase(data, base)
	if err != nil {
		return model.Hash32{}, err
	}
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
	version, err := model.DeriveVersionIDWithIdentity(objectID, manifestID, size, mtime, nil, identityMode, causalHash)
	if err != nil {
		return model.Hash32{}, err
	}
	record := model.ObjectRecord{
		ID: objectID, Kind: model.KindFile, Mode: mode, UID: uid, GID: gid,
		MtimeNS: mtime, Version: version, Content: manifestID, Size: size,
		Attrs: preparedAttrs,
	}
	entryID, err := model.DeriveEntryID(parent, name)
	if err != nil {
		return model.Hash32{}, err
	}
	entry := model.EntryRecord{ID: entryID, Parent: parent, Name: append([]byte(nil), name...), Target: objectID}
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

// WriteFile replaces a byte range in a file, zero-filling a gap past EOF.
func (s *Store) WriteFile(id model.Hash32, offset uint64, data []byte) (model.Hash32, error) {
	return s.WriteFileCausal(id, offset, data, nil)
}

// RangeWrite is one byte range to apply in a single range-write commit.
type RangeWrite struct {
	Offset uint64
	Data   []byte
}

// WriteOutcome reports the new version, manifest id, and logical size of a
// range write. Callers keeping a ManifestCache refresh it from these fields.
type WriteOutcome struct {
	Version model.Hash32
	Content model.Hash32
	Size    uint64
}

// ManifestCache is a manifest a caller already holds for one object version.
// WriteFileCached uses it only when it still names the object's current
// content id and size; a stale cache is ignored, never trusted.
type ManifestCache struct {
	Content  model.Hash32
	Manifest model.Manifest
}

// WriteFileCausal replaces a byte range with optional causal_exact ancestry.
// An empty causal slice preserves an existing causal_exact closure (the mode is
// sticky) and keeps bytes_only objects byte-identical to v1.
func (s *Store) WriteFileCausal(id model.Hash32, offset uint64, data []byte, causal []model.Hash32) (model.Hash32, error) {
	outcome, err := s.writeFileRangesCausal(id, []RangeWrite{{Offset: offset, Data: data}}, causal, nil)
	if err != nil {
		return model.Hash32{}, err
	}
	return outcome.Version, nil
}

// WriteFileCached replaces a byte range, reusing a manifest the caller already
// holds. The cache is advisory: it is used only when it still matches the
// object's current content id and size, so it can never change a result.
func (s *Store) WriteFileCached(id model.Hash32, offset uint64, data []byte, cached *ManifestCache) (WriteOutcome, error) {
	return s.writeFileRangesCausal(id, []RangeWrite{{Offset: offset, Data: data}}, nil, cached)
}

// WriteFileRanges applies several byte ranges with one manifest read, one
// manifest write, and one commit. Ranges are applied in the order given, so
// overlapping writes have the same last-writer-wins result as separate calls.
// Empty ranges are ignored; an all-empty input publishes nothing.
func (s *Store) WriteFileRanges(id model.Hash32, ranges []RangeWrite) (WriteOutcome, error) {
	return s.writeFileRangesCausal(id, ranges, nil, nil)
}

func (s *Store) writeFileRangesCausal(id model.Hash32, ranges []RangeWrite, causal []model.Hash32, cached *ManifestCache) (WriteOutcome, error) {
	if err := s.requireWritable(); err != nil {
		return WriteOutcome{}, err
	}
	old, ok := s.state.Objects[id]
	if !ok {
		return WriteOutcome{}, werr.Newf(werr.NotFound, "no such object")
	}
	if old.Kind != model.KindFile {
		return WriteOutcome{}, werr.Newf(werr.InvalidArgument, "write_file requires a file object")
	}
	applied := make([]RangeWrite, 0, len(ranges))
	for _, r := range ranges {
		if len(r.Data) > 0 {
			applied = append(applied, r)
		}
	}
	if len(applied) == 0 {
		return WriteOutcome{Version: old.Version, Content: old.Content, Size: old.Size}, nil
	}
	end := old.Size
	for _, r := range applied {
		rEnd := r.Offset + uint64(len(r.Data))
		if rEnd < r.Offset || rEnd > MaxFileBytes {
			return WriteOutcome{}, werr.Newf(werr.LimitExceeded, "file exceeds the %d-byte v1 bound", MaxFileBytes)
		}
		if rEnd > end {
			end = rEnd
		}
	}
	var oldManifest model.Manifest
	var err error
	if cached != nil && cached.Content == old.Content && cached.Manifest.Size == old.Size {
		oldManifest = cached.Manifest
	} else {
		oldManifest, err = ReadManifest(s.root, old.Content)
		if err != nil {
			return WriteOutcome{}, err
		}
	}
	if oldManifest.Size != old.Size {
		return WriteOutcome{}, werr.Newf(werr.Corrupt, "object size disagrees with manifest")
	}
	identity := s.options.ContentIdentity
	if oldManifest.Identity == model.ContentIdentityMerkleV1 {
		identity = model.ContentIdentityMerkleV1
	}
	frameBacked := oldManifest.Representation != nil &&
		(oldManifest.Representation.Kind == model.RepresentationCodec || oldManifest.Representation.Kind == model.RepresentationTensor)
	if oldManifest.Representation != nil && oldManifest.Representation.Kind == model.RepresentationOverlay {
		return WriteOutcome{}, werr.Newf(werr.InvalidArgument,
			"range write to a weft.manifest.v4 overlay is not implemented")
	}
	// A Merkle file is rewritten chunk-granularly: only changed chunks are
	// re-hashed and re-stored, and the root is folded from the manifest's
	// stored chunk hashes. A v3 file is never implicitly downgraded.
	if identity == model.ContentIdentityMerkleV1 && !frameBacked {
		return s.writeFileMerkleRanges(id, old, oldManifest, applied, causal)
	}
	current, err := s.ReadObject(id)
	if err != nil {
		return WriteOutcome{}, err
	}
	if uint64(len(current)) != old.Size {
		return WriteOutcome{}, werr.Newf(werr.Corrupt, "file size changed while writing")
	}
	newSize := end
	if old.Size > newSize {
		newSize = old.Size
	}
	sizeInt, err := checkedSize(newSize)
	if err != nil {
		return WriteOutcome{}, err
	}
	buffer := make([]byte, sizeInt)
	copy(buffer, current)
	for _, r := range applied {
		offsetInt, err := checkedSize(r.Offset)
		if err != nil {
			return WriteOutcome{}, err
		}
		endInt, err := checkedSize(r.Offset + uint64(len(r.Data)))
		if err != nil {
			return WriteOutcome{}, err
		}
		copy(buffer[offsetInt:endInt], r.Data)
	}
	parentVersions := causal
	if len(parentVersions) == 0 {
		closure, err := model.ObjectCausalClosure(old)
		if err != nil {
			return WriteOutcome{}, err
		}
		if closure != nil {
			parentVersions = closure.Parents
		}
	}
	base, err := s.deltaBaseFor(parentVersions)
	if err != nil {
		return WriteOutcome{}, err
	}
	manifestID, _, _, err := s.storeFileContentWithBase(buffer, base)
	if err != nil {
		return WriteOutcome{}, err
	}
	version, err := s.publishFileWrite(id, old, manifestID, newSize, causal)
	if err != nil {
		return WriteOutcome{}, err
	}
	return WriteOutcome{Version: version, Content: manifestID, Size: newSize}, nil
}

// publishFileWrite derives the new version and publishes one commit. Shared by
// the whole-file write path and the Merkle chunk-granular path.
func (s *Store) publishFileWrite(id model.Hash32, old model.ObjectRecord, manifestID model.Hash32, newSize uint64, causal []model.Hash32) (model.Hash32, error) {
	var attrs map[string]wcb.Value
	var identityMode weftcontext.IdentityMode
	var causalHash *model.Hash32
	var err error
	if len(causal) == 0 {
		identityMode, causalHash, err = model.IdentityFromAttrs(old)
		if err != nil {
			return model.Hash32{}, err
		}
		attrs = stripTensorAttrs(model.CloneAttrs(old.Attrs))
	} else {
		var closure *weftcontext.CausalClosure
		attrs, identityMode, causalHash, closure, err = s.prepareCausal(stripTensorAttrs(old.Attrs), causal)
		if err != nil {
			return model.Hash32{}, err
		}
		if closure != nil {
			if err := s.storeCausalClosure(closure); err != nil {
				return model.Hash32{}, err
			}
		}
	}
	mtime := s.nowNS()
	version, err := model.DeriveVersionIDWithIdentity(id, manifestID, newSize, mtime, hashPtr(old.Version), identityMode, causalHash)
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

// writeFileMerkleRanges applies range writes to a `weft.manifest.v3` file.
//
// Only chunks intersecting a range are read and re-hashed; untouched chunk
// references are reused verbatim and their blobs are never read. The root is
// recomputed from the resulting chunk table with no whole-file read.
func (s *Store) writeFileMerkleRanges(id model.Hash32, old model.ObjectRecord, oldManifest model.Manifest, ranges []RangeWrite, causal []model.Hash32) (WriteOutcome, error) {
	chunkSize := oldManifest.ChunkSize
	if chunkSize == 0 || chunkSize > model.MaxChunkSize {
		return WriteOutcome{}, werr.Newf(werr.InvalidArgument, "chunk size is out of range")
	}
	newSize := old.Size
	for _, r := range ranges {
		end := r.Offset + uint64(len(r.Data))
		if end < r.Offset || end > MaxFileBytes {
			return WriteOutcome{}, werr.Newf(werr.LimitExceeded, "file exceeds the %d-byte v1 bound", MaxFileBytes)
		}
		if end > newSize {
			newSize = end
		}
	}
	var declared uint64
	for _, chunk := range oldManifest.Chunks {
		if declared > ^uint64(0)-chunk.Len {
			return WriteOutcome{}, werr.Newf(werr.Corrupt, "manifest size overflows")
		}
		declared += chunk.Len
	}
	if declared != oldManifest.Size || oldManifest.Size != old.Size {
		return WriteOutcome{}, werr.Newf(werr.Corrupt, "manifest chunk lengths disagree with its size")
	}
	chunkCount := newSize / chunkSize
	if newSize%chunkSize != 0 {
		chunkCount++
	}
	if chunkCount > model.MaxChunksPerFile {
		return WriteOutcome{}, werr.Newf(werr.LimitExceeded, "manifest exceeds the %d-chunk bound", model.MaxChunksPerFile)
	}
	// Which ranges touch each chunk, so the walk stays linear in the chunk
	// count rather than quadratic in the range list.
	touched := make(map[uint64][]int)
	for index, r := range ranges {
		end := r.Offset + uint64(len(r.Data))
		if end > newSize {
			return WriteOutcome{}, werr.Newf(werr.InvalidArgument, "range write exceeds the target file size")
		}
		first := r.Offset / chunkSize
		last := (end - 1) / chunkSize
		for chunk := first; chunk <= last; chunk++ {
			touched[chunk] = append(touched[chunk], index)
		}
	}
	chunks := make([]model.ChunkRef, 0, chunkCount)
	for index := uint64(0); index < chunkCount; index++ {
		chunkStart := index * chunkSize
		chunkEnd := chunkStart + chunkSize
		if chunkEnd > newSize {
			chunkEnd = newSize
		}
		var oldRef *model.ChunkRef
		if index < uint64(len(oldManifest.Chunks)) {
			oldRef = &oldManifest.Chunks[index]
		}
		overlapping := touched[index]
		if oldRef != nil && chunkEnd <= oldManifest.Size && len(overlapping) == 0 {
			chunks = append(chunks, *oldRef)
			continue
		}
		assembled := make([]byte, chunkEnd-chunkStart)
		var oldBytes []byte
		if oldRef != nil {
			keep := chunkEnd - chunkStart
			if oldRef.Len < keep {
				keep = oldRef.Len
			}
			if keep > 0 {
				stored, err := ReadBlobVerified(s.root, BlobObject, oldRef.Hash, model.DomainChunk)
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
		for _, rangeIndex := range overlapping {
			r := ranges[rangeIndex]
			writeStart := r.Offset
			if chunkStart > writeStart {
				writeStart = chunkStart
			}
			writeEnd := r.Offset + uint64(len(r.Data))
			if chunkEnd < writeEnd {
				writeEnd = chunkEnd
			}
			if writeStart >= writeEnd {
				continue
			}
			copy(assembled[writeStart-chunkStart:writeEnd-chunkStart], r.Data[writeStart-r.Offset:writeEnd-r.Offset])
		}
		if oldRef != nil && oldBytes != nil && oldRef.Len == chunkEnd-chunkStart && bytes.Equal(assembled, oldBytes) {
			chunks = append(chunks, *oldRef)
			continue
		}
		hash, err := s.storeBlob(BlobObject, model.DomainChunk, assembled)
		if err != nil {
			return WriteOutcome{}, err
		}
		chunks = append(chunks, model.ChunkRef{Hash: hash, Len: uint64(len(assembled))})
	}
	manifest := model.Manifest{
		Size: newSize, ChunkSize: chunkSize, Chunks: chunks,
		ContentHash: model.MerkleRootChunks(chunks),
		Identity:    model.ContentIdentityMerkleV1,
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

// contentIdentityFor returns the identity a rewrite of record must keep: an
// existing v3 file stays v3; a v1/v2 file adopts the store-wide option.
func (s *Store) contentIdentityFor(record model.ObjectRecord) model.ContentIdentity {
	if record.Kind == model.KindFile {
		if manifest, err := ReadManifest(s.root, record.Content); err == nil && manifest.Identity == model.ContentIdentityMerkleV1 {
			return model.ContentIdentityMerkleV1
		}
	}
	return s.options.ContentIdentity
}

// storeFileContentAs stores a whole buffer under an explicit identity.
func (s *Store) storeFileContentAs(data []byte, identity model.ContentIdentity) (model.Hash32, model.Hash32, uint64, error) {
	if identity == model.ContentIdentityMerkleV1 {
		chunkSize := s.options.ChunkSize
		if chunkSize == 0 || chunkSize > model.MaxChunkSize {
			return model.Hash32{}, model.Hash32{}, 0, werr.Newf(werr.InvalidArgument, "chunk size is out of range")
		}
		manifest, err := s.buildMerkleManifest(data, chunkSize)
		if err != nil {
			return model.Hash32{}, model.Hash32{}, 0, err
		}
		return s.storeManifest(manifest)
	}
	return s.storeFileContent(data)
}

// Truncate resizes a file, zero-filling when growing.
func (s *Store) Truncate(id model.Hash32, size uint64) (model.Hash32, error) {
	if err := s.requireWritable(); err != nil {
		return model.Hash32{}, err
	}
	if size > MaxFileBytes {
		return model.Hash32{}, werr.Newf(werr.LimitExceeded, "file exceeds the %d-byte v1 bound", MaxFileBytes)
	}
	old, ok := s.state.Objects[id]
	if !ok {
		return model.Hash32{}, werr.Newf(werr.NotFound, "no such object")
	}
	if old.Kind != model.KindFile {
		return model.Hash32{}, werr.Newf(werr.InvalidArgument, "truncate requires a file object")
	}
	current, err := s.ReadObject(id)
	if err != nil {
		return model.Hash32{}, err
	}
	sizeInt, err := checkedSize(size)
	if err != nil {
		return model.Hash32{}, err
	}
	buffer := make([]byte, sizeInt)
	copied := len(current)
	if copied > len(buffer) {
		copied = len(buffer)
	}
	copy(buffer, current[:copied])
	manifestID, _, _, err := s.storeFileContentAs(buffer, s.contentIdentityFor(old))
	if err != nil {
		return model.Hash32{}, err
	}
	identityMode, causalHash, err := model.IdentityFromAttrs(old)
	if err != nil {
		return model.Hash32{}, err
	}
	mtime := s.nowNS()
	version, err := model.DeriveVersionIDWithIdentity(id, manifestID, size, mtime, hashPtr(old.Version), identityMode, causalHash)
	if err != nil {
		return model.Hash32{}, err
	}
	record := old.Clone()
	record.Version = version
	record.MtimeNS = mtime
	record.Content = manifestID
	record.Size = size
	// A byte rewrite is not the tensor the reserved attributes describe.
	record.Attrs = stripTensorAttrs(record.Attrs)
	ops := []model.Op{
		model.PutObjectOp{Record: record},
		model.SetTipOp{Object: id, Version: version},
	}
	if _, err := s.commitOps(ops, false); err != nil {
		return model.Hash32{}, err
	}
	return version, nil
}

// commitFileBuffer replaces a file object's whole content in one commit. It
// preserves the object's identity mode and version parent. The caller holds
// the single-writer serialization.
func (s *Store) commitFileBuffer(id model.Hash32, old model.ObjectRecord, buffer []byte) (model.Hash32, error) {
	if uint64(len(buffer)) > MaxFileBytes {
		return model.Hash32{}, werr.Newf(werr.LimitExceeded, "file exceeds the %d-byte v1 bound", MaxFileBytes)
	}
	manifestID, _, size, err := s.storeFileContentAs(buffer, s.contentIdentityFor(old))
	if err != nil {
		return model.Hash32{}, err
	}
	identityMode, causalHash, err := model.IdentityFromAttrs(old)
	if err != nil {
		return model.Hash32{}, err
	}
	mtime := s.nowNS()
	version, err := model.DeriveVersionIDWithIdentity(id, manifestID, size, mtime, hashPtr(old.Version), identityMode, causalHash)
	if err != nil {
		return model.Hash32{}, err
	}
	record := old.Clone()
	record.Version = version
	record.MtimeNS = mtime
	record.Content = manifestID
	record.Size = size
	// A byte rewrite is not the tensor the reserved attributes describe.
	record.Attrs = stripTensorAttrs(record.Attrs)
	ops := []model.Op{
		model.PutObjectOp{Record: record},
		model.SetTipOp{Object: id, Version: version},
	}
	if _, err := s.commitOps(ops, false); err != nil {
		return model.Hash32{}, err
	}
	return version, nil
}

// ZeroRange writes zeros into [offset, offset+length). When extend is true the
// file grows to cover the range; otherwise bytes past EOF are ignored. Files
// are dense in v1, so this defines content but does not reclaim physical
// chunks (see the FUSE fallocate documentation).
func (s *Store) ZeroRange(id model.Hash32, offset, length uint64, extend bool) (model.Hash32, error) {
	if err := s.requireWritable(); err != nil {
		return model.Hash32{}, err
	}
	if length == 0 {
		return model.Hash32{}, werr.Newf(werr.InvalidArgument, "zero range length must be nonzero")
	}
	end := offset + length
	if end < offset {
		return model.Hash32{}, werr.Newf(werr.LimitExceeded, "zero range overflows")
	}
	old, ok := s.state.Objects[id]
	if !ok {
		return model.Hash32{}, werr.Newf(werr.NotFound, "no such object")
	}
	if old.Kind != model.KindFile {
		return model.Hash32{}, werr.Newf(werr.InvalidArgument, "zero range requires a file object")
	}
	if extend && end > MaxFileBytes {
		return model.Hash32{}, werr.Newf(werr.LimitExceeded, "file exceeds the %d-byte v1 bound", MaxFileBytes)
	}
	high := offset
	if end > high {
		high = end
	}
	newSize := old.Size
	if extend && high > newSize {
		newSize = high
	}
	zeroEnd := high
	if zeroEnd > newSize {
		zeroEnd = newSize
	}
	if zeroEnd <= offset {
		return old.Version, nil
	}
	current, err := s.ReadObject(id)
	if err != nil {
		return model.Hash32{}, err
	}
	if uint64(len(current)) != old.Size {
		return model.Hash32{}, werr.Newf(werr.Corrupt, "file size changed while zeroing")
	}
	sizeInt, err := checkedSize(newSize)
	if err != nil {
		return model.Hash32{}, err
	}
	offsetInt, err := checkedSize(offset)
	if err != nil {
		return model.Hash32{}, err
	}
	zeroEndInt, err := checkedSize(zeroEnd)
	if err != nil {
		return model.Hash32{}, err
	}
	buffer := make([]byte, sizeInt)
	copy(buffer, current)
	clear(buffer[offsetInt:zeroEndInt])
	return s.commitFileBuffer(id, old, buffer)
}

// CollapseRange removes [offset, offset+length) and shifts later bytes left.
func (s *Store) CollapseRange(id model.Hash32, offset, length uint64) (model.Hash32, error) {
	if err := s.requireWritable(); err != nil {
		return model.Hash32{}, err
	}
	if length == 0 {
		return model.Hash32{}, werr.Newf(werr.InvalidArgument, "collapse length must be nonzero")
	}
	old, ok := s.state.Objects[id]
	if !ok {
		return model.Hash32{}, werr.Newf(werr.NotFound, "no such object")
	}
	if old.Kind != model.KindFile {
		return model.Hash32{}, werr.Newf(werr.InvalidArgument, "collapse requires a file object")
	}
	if offset > old.Size || length > old.Size-offset {
		return model.Hash32{}, werr.Newf(werr.InvalidArgument, "collapse range lies past EOF")
	}
	current, err := s.ReadObject(id)
	if err != nil {
		return model.Hash32{}, err
	}
	if uint64(len(current)) != old.Size {
		return model.Hash32{}, werr.Newf(werr.Corrupt, "file size changed while collapsing")
	}
	newLength, err := checkedSize(old.Size - length)
	if err != nil {
		return model.Hash32{}, err
	}
	offsetInt, err := checkedSize(offset)
	if err != nil {
		return model.Hash32{}, err
	}
	shiftEnd, err := checkedSize(offset + length)
	if err != nil {
		return model.Hash32{}, err
	}
	buffer := make([]byte, newLength)
	copy(buffer, current[:offsetInt])
	copy(buffer[offsetInt:], current[shiftEnd:])
	return s.commitFileBuffer(id, old, buffer)
}

// InsertRange inserts length zero bytes at offset and shifts later bytes right.
func (s *Store) InsertRange(id model.Hash32, offset, length uint64) (model.Hash32, error) {
	if err := s.requireWritable(); err != nil {
		return model.Hash32{}, err
	}
	if length == 0 {
		return model.Hash32{}, werr.Newf(werr.InvalidArgument, "insert length must be nonzero")
	}
	old, ok := s.state.Objects[id]
	if !ok {
		return model.Hash32{}, werr.Newf(werr.NotFound, "no such object")
	}
	if old.Kind != model.KindFile {
		return model.Hash32{}, werr.Newf(werr.InvalidArgument, "insert requires a file object")
	}
	if offset > old.Size {
		return model.Hash32{}, werr.Newf(werr.InvalidArgument, "insert offset lies past EOF")
	}
	newSize := old.Size + length
	if newSize < old.Size || newSize > MaxFileBytes {
		return model.Hash32{}, werr.Newf(werr.LimitExceeded, "file exceeds the %d-byte v1 bound", MaxFileBytes)
	}
	current, err := s.ReadObject(id)
	if err != nil {
		return model.Hash32{}, err
	}
	if uint64(len(current)) != old.Size {
		return model.Hash32{}, werr.Newf(werr.Corrupt, "file size changed while inserting")
	}
	sizeInt, err := checkedSize(newSize)
	if err != nil {
		return model.Hash32{}, err
	}
	offsetInt, err := checkedSize(offset)
	if err != nil {
		return model.Hash32{}, err
	}
	shiftStart, err := checkedSize(offset + length)
	if err != nil {
		return model.Hash32{}, err
	}
	buffer := make([]byte, sizeInt)
	copy(buffer, current[:offsetInt])
	copy(buffer[shiftStart:], current[offsetInt:])
	return s.commitFileBuffer(id, old, buffer)
}

// CreateUnlinkedFile creates a regular file object with no directory entry
// (O_TMPFILE). The caller must pin it before concurrent GC can observe it; the
// FUSE frontend does so in the same critical section. If it is never linked,
// the pin's release removes the record in one commit.
func (s *Store) CreateUnlinkedFile(data []byte, mode, uid, gid uint64, attrs map[string]wcb.Value) (model.Hash32, error) {
	seed, err := randomSeed()
	if err != nil {
		return model.Hash32{}, err
	}
	return s.CreateUnlinkedFileSeeded(data, mode, uid, gid, attrs, seed)
}

// CreateUnlinkedFileSeeded is CreateUnlinkedFile with an explicit ObjectId seed.
func (s *Store) CreateUnlinkedFileSeeded(data []byte, mode, uid, gid uint64, attrs map[string]wcb.Value, seed []byte) (model.Hash32, error) {
	if err := s.requireWritable(); err != nil {
		return model.Hash32{}, err
	}
	if err := checkMode(mode); err != nil {
		return model.Hash32{}, err
	}
	if uint64(len(data)) > MaxFileBytes {
		return model.Hash32{}, werr.Newf(werr.LimitExceeded, "file exceeds the %d-byte v1 bound", MaxFileBytes)
	}
	manifestID, _, size, err := s.storeFileContent(data)
	if err != nil {
		return model.Hash32{}, err
	}
	objectID := model.ObjectIDFromSeed(seed)
	if _, exists := s.state.Objects[objectID]; exists {
		return model.Hash32{}, werr.Newf(werr.Exists, "object id already exists")
	}
	preparedAttrs, _, _, _, err := s.prepareCausal(attrs, nil)
	if err != nil {
		return model.Hash32{}, err
	}
	mtime := s.nowNS()
	version, err := model.DeriveVersionID(objectID, manifestID, size, mtime, nil)
	if err != nil {
		return model.Hash32{}, err
	}
	record := model.ObjectRecord{
		ID: objectID, Kind: model.KindFile, Mode: mode, UID: uid, GID: gid,
		MtimeNS: mtime, Version: version, Content: manifestID, Size: size,
		Attrs: preparedAttrs,
	}
	ops := []model.Op{
		model.PutObjectOp{Record: record},
		model.SetTipOp{Object: objectID, Version: version},
	}
	if _, err := s.commitOps(ops, false); err != nil {
		return model.Hash32{}, err
	}
	return objectID, nil
}

// Unlink removes a directory entry. When the last entry for an object
// disappears the object record is deleted in the same commit, unless an open
// handle pins it.
func (s *Store) Unlink(parent model.Hash32, name []byte) error {
	if err := s.requireWritable(); err != nil {
		return err
	}
	if err := s.requireDir(parent); err != nil {
		return err
	}
	target, err := s.state.Lookup(parent, name)
	if err != nil {
		return err
	}
	object, ok := s.state.Objects[target]
	if !ok {
		return werr.Newf(werr.Corrupt, "entry target does not exist")
	}
	if object.Kind == model.KindDir {
		return werr.Newf(werr.IsDir, "unlink does not remove directories")
	}
	entryID, err := model.DeriveEntryID(parent, name)
	if err != nil {
		return err
	}
	remaining := 0
	for _, entry := range s.state.Entries {
		if entry.Target == target && entry.ID != entryID {
			remaining++
		}
	}
	ops := []model.Op{model.DelEntryOp{ID: entryID}}
	if remaining == 0 && !s.isObjectPinned(target) {
		ops = append(ops, model.DeleteObjectOp{ID: target})
	}
	_, err = s.commitOps(ops, false)
	return err
}

// Rmdir removes an empty directory.
func (s *Store) Rmdir(parent model.Hash32, name []byte) error {
	if err := s.requireWritable(); err != nil {
		return err
	}
	if err := s.requireDir(parent); err != nil {
		return err
	}
	if err := model.ValidateNameBytes(name); err != nil {
		return err
	}
	target, err := s.state.Lookup(parent, name)
	if err != nil {
		return err
	}
	if target == model.RootID {
		return werr.Newf(werr.InvalidArgument, "cannot remove the namespace root")
	}
	object, ok := s.state.Objects[target]
	if !ok {
		return werr.Newf(werr.Corrupt, "entry target does not exist")
	}
	if object.Kind != model.KindDir {
		return werr.Newf(werr.NotDir, "rmdir requires a directory entry")
	}
	for _, entry := range s.state.Entries {
		if entry.Parent == target {
			return werr.Newf(werr.NotEmpty, "directory is not empty")
		}
	}
	entryID, err := model.DeriveEntryID(parent, name)
	if err != nil {
		return err
	}
	remaining := 0
	for _, entry := range s.state.Entries {
		if entry.Target == target && entry.ID != entryID {
			remaining++
		}
	}
	ops := []model.Op{model.DelEntryOp{ID: entryID}}
	if remaining == 0 && !s.isObjectPinned(target) {
		ops = append(ops, model.DeleteObjectOp{ID: target})
	}
	_, err = s.commitOps(ops, false)
	return err
}

// Rename atomically moves (and optionally replaces) a directory entry.
func (s *Store) Rename(oldParent model.Hash32, oldName []byte, newParent model.Hash32, newName []byte) error {
	return s.renameWith(oldParent, oldName, newParent, newName, false)
}

// RenameNoReplace is Rename with RENAME_NOREPLACE semantics.
func (s *Store) RenameNoReplace(oldParent model.Hash32, oldName []byte, newParent model.Hash32, newName []byte) error {
	return s.renameWith(oldParent, oldName, newParent, newName, true)
}

func (s *Store) renameWith(oldParent model.Hash32, oldName []byte, newParent model.Hash32, newName []byte, noReplace bool) error {
	if err := s.requireWritable(); err != nil {
		return err
	}
	if err := s.requireDir(oldParent); err != nil {
		return err
	}
	if err := s.requireDir(newParent); err != nil {
		return err
	}
	if err := model.ValidateNameBytes(oldName); err != nil {
		return err
	}
	if err := model.ValidateNameBytes(newName); err != nil {
		return err
	}
	target, err := s.state.Lookup(oldParent, oldName)
	if err != nil {
		return err
	}
	if oldParent == newParent && bytes.Equal(oldName, newName) {
		return nil
	}
	targetObject, ok := s.state.Objects[target]
	if !ok {
		return werr.Newf(werr.Corrupt, "entry target does not exist")
	}
	targetKind := targetObject.Kind
	oldEntryID, err := model.DeriveEntryID(oldParent, oldName)
	if err != nil {
		return err
	}
	newEntryID, err := model.DeriveEntryID(newParent, newName)
	if err != nil {
		return err
	}
	existing, hasExisting := s.state.Entries[newEntryID]
	ops := make([]model.Op, 0, 4)
	if hasExisting {
		if existing.Target == target {
			return nil
		}
		if noReplace {
			return werr.Newf(werr.Exists, "rename destination already exists")
		}
		destObject, ok := s.state.Objects[existing.Target]
		if !ok {
			return werr.Newf(werr.Corrupt, "rename destination target does not exist")
		}
		switch {
		case targetKind == model.KindDir && destObject.Kind == model.KindDir:
			for _, entry := range s.state.Entries {
				if entry.Parent == destObject.ID {
					return werr.Newf(werr.NotEmpty, "rename would replace a non-empty directory")
				}
			}
		case targetKind == model.KindDir:
			return werr.Newf(werr.NotDir, "rename would replace a non-directory with a directory")
		case destObject.Kind == model.KindDir:
			return werr.Newf(werr.IsDir, "rename would replace a directory with a non-directory")
		}
		ops = append(ops, model.DelEntryOp{ID: existing.ID})
		remaining := 0
		for _, entry := range s.state.Entries {
			if entry.Target == existing.Target && entry.ID != existing.ID {
				remaining++
			}
		}
		if remaining == 0 && !s.isObjectPinned(existing.Target) {
			ops = append(ops, model.DeleteObjectOp{ID: existing.Target})
		}
	}
	if targetKind == model.KindDir && s.state.IsWithin(target, newParent) {
		return werr.Newf(werr.InvalidArgument, "cannot move a directory into itself or a descendant")
	}
	ops = append(ops, model.DelEntryOp{ID: oldEntryID})
	ops = append(ops, model.PutEntryOp{Record: model.EntryRecord{
		ID: newEntryID, Parent: newParent, Name: append([]byte(nil), newName...), Target: target,
	}})
	_, err = s.commitOps(ops, false)
	return err
}

// RenameExchange atomically exchanges two existing entries (RENAME_EXCHANGE).
// Directories are rejected in v1 because exchange can create a parent cycle.
func (s *Store) RenameExchange(aParent model.Hash32, aName []byte, bParent model.Hash32, bName []byte) error {
	if err := s.requireWritable(); err != nil {
		return err
	}
	if err := s.requireDir(aParent); err != nil {
		return err
	}
	if err := s.requireDir(bParent); err != nil {
		return err
	}
	if err := model.ValidateNameBytes(aName); err != nil {
		return err
	}
	if err := model.ValidateNameBytes(bName); err != nil {
		return err
	}
	aID, err := model.DeriveEntryID(aParent, aName)
	if err != nil {
		return err
	}
	bID, err := model.DeriveEntryID(bParent, bName)
	if err != nil {
		return err
	}
	aEntry, ok := s.state.Entries[aID]
	if !ok {
		return werr.Newf(werr.NotFound, "rename exchange source does not exist")
	}
	bEntry, ok := s.state.Entries[bID]
	if !ok {
		return werr.Newf(werr.NotFound, "rename exchange target does not exist")
	}
	if aEntry.ID == bEntry.ID {
		return nil
	}
	aObject, ok := s.state.Objects[aEntry.Target]
	if !ok {
		return werr.Newf(werr.Corrupt, "rename exchange source target is missing")
	}
	bObject, ok := s.state.Objects[bEntry.Target]
	if !ok {
		return werr.Newf(werr.Corrupt, "rename exchange destination target is missing")
	}
	if aObject.Kind == model.KindDir || bObject.Kind == model.KindDir {
		return werr.Newf(werr.InvalidArgument, "RENAME_EXCHANGE of directories is not supported in v1")
	}
	ops := []model.Op{
		model.DelEntryOp{ID: aEntry.ID},
		model.DelEntryOp{ID: bEntry.ID},
		model.PutEntryOp{Record: model.EntryRecord{ID: aEntry.ID, Parent: aParent, Name: append([]byte(nil), aName...), Target: bEntry.Target}},
		model.PutEntryOp{Record: model.EntryRecord{ID: bEntry.ID, Parent: bParent, Name: append([]byte(nil), bName...), Target: aEntry.Target}},
	}
	_, err = s.commitOps(ops, false)
	return err
}

// Link creates a hard link to an existing non-directory object.
func (s *Store) Link(target model.Hash32, parent model.Hash32, name []byte) error {
	if err := s.requireWritable(); err != nil {
		return err
	}
	if err := s.requireDir(parent); err != nil {
		return err
	}
	if err := model.ValidateNameBytes(name); err != nil {
		return err
	}
	object, ok := s.state.Objects[target]
	if !ok {
		return werr.Newf(werr.NotFound, "no such object")
	}
	if object.Kind == model.KindDir {
		return werr.Newf(werr.InvalidArgument, "hard links to directories are not allowed")
	}
	entryID, err := model.DeriveEntryID(parent, name)
	if err != nil {
		return err
	}
	if _, exists := s.state.Entries[entryID]; exists {
		return werr.Newf(werr.Exists, "directory entry already exists")
	}
	entry := model.EntryRecord{ID: entryID, Parent: parent, Name: append([]byte(nil), name...), Target: target}
	_, err = s.commitOps([]model.Op{model.PutEntryOp{Record: entry}}, false)
	return err
}

// Mkdir creates a directory.
func (s *Store) Mkdir(parent model.Hash32, name []byte, mode, uid, gid uint64) (model.Hash32, error) {
	seed, err := randomSeed()
	if err != nil {
		return model.Hash32{}, err
	}
	return s.MkdirSeeded(parent, name, mode, uid, gid, seed)
}

// MkdirSeeded creates a directory with an explicit ObjectId seed.
func (s *Store) MkdirSeeded(parent model.Hash32, name []byte, mode, uid, gid uint64, seed []byte) (model.Hash32, error) {
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
	if err := checkMode(mode); err != nil {
		return model.Hash32{}, err
	}
	objectID := model.ObjectIDFromSeed(seed)
	if _, exists := s.state.Objects[objectID]; exists {
		return model.Hash32{}, werr.Newf(werr.Exists, "object id already exists")
	}
	mtime := s.nowNS()
	content := model.ContentHash(nil)
	version, err := model.DeriveVersionID(objectID, content, 0, mtime, nil)
	if err != nil {
		return model.Hash32{}, err
	}
	record := model.ObjectRecord{
		ID: objectID, Kind: model.KindDir, Mode: mode, UID: uid, GID: gid,
		MtimeNS: mtime, Version: version, Content: content, Size: 0,
		Attrs: map[string]wcb.Value{},
	}
	entryID, err := model.DeriveEntryID(parent, name)
	if err != nil {
		return model.Hash32{}, err
	}
	entry := model.EntryRecord{ID: entryID, Parent: parent, Name: append([]byte(nil), name...), Target: objectID}
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

// Symlink creates a symlink whose target is stored as bytes.
func (s *Store) Symlink(parent model.Hash32, name, target []byte, uid, gid uint64) (model.Hash32, error) {
	seed, err := randomSeed()
	if err != nil {
		return model.Hash32{}, err
	}
	return s.SymlinkSeeded(parent, name, target, uid, gid, seed)
}

// SymlinkSeeded creates a symlink with an explicit ObjectId seed.
func (s *Store) SymlinkSeeded(parent model.Hash32, name, target []byte, uid, gid uint64, seed []byte) (model.Hash32, error) {
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
	objectID := model.ObjectIDFromSeed(seed)
	if _, exists := s.state.Objects[objectID]; exists {
		return model.Hash32{}, werr.Newf(werr.Exists, "object id already exists")
	}
	mtime := s.nowNS()
	content := model.ContentHash(target)
	size := uint64(len(target))
	version, err := model.DeriveVersionID(objectID, content, size, mtime, nil)
	if err != nil {
		return model.Hash32{}, err
	}
	attrs := map[string]wcb.Value{
		model.AttrSymlinkTarget: wcb.BytesValue(append([]byte(nil), target...)),
	}
	record := model.ObjectRecord{
		ID: objectID, Kind: model.KindSymlink, Mode: 0o777, UID: uid, GID: gid,
		MtimeNS: mtime, Version: version, Content: content, Size: size, Attrs: attrs,
	}
	entryID, err := model.DeriveEntryID(parent, name)
	if err != nil {
		return model.Hash32{}, err
	}
	entry := model.EntryRecord{ID: entryID, Parent: parent, Name: append([]byte(nil), name...), Target: objectID}
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

// Setattr updates mode, ownership, mtime, and/or attributes in one commit.
func (s *Store) Setattr(id model.Hash32, changes SetAttr) (model.Hash32, error) {
	if err := s.requireWritable(); err != nil {
		return model.Hash32{}, err
	}
	old, ok := s.state.Objects[id]
	if !ok {
		return model.Hash32{}, werr.Newf(werr.NotFound, "no such object")
	}
	record := old.Clone()
	if changes.Mode != nil {
		if err := checkMode(*changes.Mode); err != nil {
			return model.Hash32{}, err
		}
		record.Mode = *changes.Mode
	}
	if changes.UID != nil {
		record.UID = *changes.UID
	}
	if changes.GID != nil {
		record.GID = *changes.GID
	}
	if changes.MtimeNS != nil {
		record.MtimeNS = *changes.MtimeNS
	}
	if changes.Attrs != nil {
		record.Attrs = model.CloneAttrs(changes.Attrs)
	}
	identityMode, causalHash, err := model.IdentityFromAttrs(record)
	if err != nil {
		return model.Hash32{}, err
	}
	version, err := model.DeriveVersionIDWithIdentity(record.ID, record.Content, record.Size, record.MtimeNS, hashPtr(old.Version), identityMode, causalHash)
	if err != nil {
		return model.Hash32{}, err
	}
	record.Version = version
	ops := []model.Op{
		model.PutObjectOp{Record: record},
		model.SetTipOp{Object: id, Version: version},
	}
	if _, err := s.commitOps(ops, false); err != nil {
		return model.Hash32{}, err
	}
	return version, nil
}

func validateXattrName(name string) error {
	if name == "" {
		return werr.Newf(werr.InvalidName, "extended attribute name must not be empty")
	}
	if len(name) > MaxXattrNameBytes {
		return werr.Newf(werr.InvalidName, "extended attribute name exceeds 255 bytes")
	}
	if bytes.IndexByte([]byte(name), 0) >= 0 || bytes.IndexByte([]byte(name), '/') >= 0 {
		return werr.Newf(werr.InvalidName, "extended attribute name must not contain NUL or '/'")
	}
	if len(name) >= 5 && name[:5] == "weft." {
		return werr.Newf(werr.InvalidName, "the weft.* attribute namespace is reserved")
	}
	return nil
}

// SetXattr sets (or replaces) an extended attribute.
func (s *Store) SetXattr(id model.Hash32, name string, value []byte) error {
	if err := validateXattrName(name); err != nil {
		return err
	}
	if uint64(len(value)) > MaxXattrValueBytes {
		return werr.Newf(werr.LimitExceeded, "extended attribute value exceeds the 64 KiB bound")
	}
	record, ok := s.state.Objects[id]
	if !ok {
		return werr.Newf(werr.NotFound, "no such object")
	}
	key := model.XattrPrefix + name
	attrs := model.CloneAttrs(record.Attrs)
	if _, exists := attrs[key]; !exists {
		count := 0
		for attrKey := range attrs {
			if len(attrKey) >= len(model.XattrPrefix) && attrKey[:len(model.XattrPrefix)] == model.XattrPrefix {
				count++
			}
		}
		if count >= MaxXattrCount {
			return werr.Newf(werr.LimitExceeded, "object has reached the extended attribute count bound")
		}
	}
	attrs[key] = wcb.BytesValue(append([]byte(nil), value...))
	_, err := s.Setattr(id, SetAttr{Attrs: attrs})
	return err
}

// GetXattr reads an extended attribute. A nil slice with ok=false means absent.
func (s *Store) GetXattr(id model.Hash32, name string) ([]byte, bool, error) {
	if err := validateXattrName(name); err != nil {
		return nil, false, err
	}
	record, ok := s.state.Objects[id]
	if !ok {
		return nil, false, werr.Newf(werr.NotFound, "no such object")
	}
	value, ok := record.Attrs[model.XattrPrefix+name]
	if !ok {
		return nil, false, nil
	}
	if value.Kind != wcb.Bytes {
		return nil, false, werr.Newf(werr.Corrupt, "extended attribute is not stored as bytes")
	}
	return append([]byte(nil), value.Bytes...), true, nil
}

// ListXattr lists extended attribute names (the suffixes), sorted. Reserved
// weft.* keys are never exposed.
func (s *Store) ListXattr(id model.Hash32) ([]string, error) {
	record, ok := s.state.Objects[id]
	if !ok {
		return nil, werr.Newf(werr.NotFound, "no such object")
	}
	names := make([]string, 0)
	for key, value := range record.Attrs {
		if len(key) < len(model.XattrPrefix) || key[:len(model.XattrPrefix)] != model.XattrPrefix {
			continue
		}
		name := key[len(model.XattrPrefix):]
		if len(name) >= 5 && name[:5] == "weft." {
			continue
		}
		if value.Kind != wcb.Bytes {
			return nil, werr.Newf(werr.Corrupt, "extended attribute is not stored as bytes")
		}
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return bytes.Compare([]byte(names[i]), []byte(names[j])) < 0 })
	return names, nil
}

// RemoveXattr removes an extended attribute; it reports whether it existed.
func (s *Store) RemoveXattr(id model.Hash32, name string) (bool, error) {
	if err := validateXattrName(name); err != nil {
		return false, err
	}
	record, ok := s.state.Objects[id]
	if !ok {
		return false, werr.Newf(werr.NotFound, "no such object")
	}
	key := model.XattrPrefix + name
	if _, exists := record.Attrs[key]; !exists {
		return false, nil
	}
	attrs := model.CloneAttrs(record.Attrs)
	delete(attrs, key)
	if _, err := s.Setattr(id, SetAttr{Attrs: attrs}); err != nil {
		return false, err
	}
	return true, nil
}

// RelationAdd adds a relation assertion. It is idempotent by RelationId.
func (s *Store) RelationAdd(subject model.Hash32, predicate string, target model.RelationTarget, provenance, attrs map[string]wcb.Value) (model.Hash32, error) {
	if err := s.requireWritable(); err != nil {
		return model.Hash32{}, err
	}
	if _, ok := s.state.Objects[subject]; !ok {
		return model.Hash32{}, werr.Newf(werr.NotFound, "relation subject object does not exist")
	}
	if predicate == "" {
		return model.Hash32{}, werr.Newf(werr.InvalidArgument, "relation predicate must not be empty")
	}
	record, err := model.NewRelationRecord(subject, predicate, target, provenance, attrs)
	if err != nil {
		return model.Hash32{}, err
	}
	if _, exists := s.state.Relations[record.ID]; exists {
		return record.ID, nil
	}
	if _, err := s.commitOps([]model.Op{model.PutRelationOp{Record: record}}, false); err != nil {
		return model.Hash32{}, err
	}
	return record.ID, nil
}

// RelationDelete deletes a relation by id.
func (s *Store) RelationDelete(relationID model.Hash32) error {
	if err := s.requireWritable(); err != nil {
		return err
	}
	if _, ok := s.state.Relations[relationID]; !ok {
		return werr.Newf(werr.NotFound, "no such relation")
	}
	_, err := s.commitOps([]model.Op{model.DelRelationOp{ID: relationID}}, false)
	return err
}

// SnapshotCreate snapshots the current commit under name. It returns the
// pinned commit hash (the v1 SnapshotId).
func (s *Store) SnapshotCreate(name string) (model.Hash32, error) {
	if err := s.requireWritable(); err != nil {
		return model.Hash32{}, err
	}
	if err := model.ValidateSnapshotName(name); err != nil {
		return model.Hash32{}, err
	}
	if _, exists := s.state.Snapshots[name]; exists {
		return model.Hash32{}, werr.Newf(werr.Exists, "snapshot name already exists")
	}
	pinned := s.head
	if _, err := s.commitOps([]model.Op{model.SetSnapshotOp{SnapshotName: name, Commit: pinned}}, false); err != nil {
		return model.Hash32{}, err
	}
	if err := s.writeSnapshotPointer(name, pinned); err != nil {
		return model.Hash32{}, err
	}
	return pinned, nil
}

// SnapshotList returns snapshot names and pinned commit hashes.
func (s *Store) SnapshotList() []struct {
	Name   string
	Commit model.Hash32
} {
	names := make([]string, 0, len(s.state.Snapshots))
	for name := range s.state.Snapshots {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]struct {
		Name   string
		Commit model.Hash32
	}, 0, len(names))
	for _, name := range names {
		out = append(out, struct {
			Name   string
			Commit model.Hash32
		}{Name: name, Commit: s.state.Snapshots[name]})
	}
	return out
}

// Checkpoint forces a checkpoint commit.
func (s *Store) Checkpoint() (model.Hash32, error) {
	if err := s.requireWritable(); err != nil {
		return model.Hash32{}, err
	}
	return s.commitOps(nil, true)
}

// Pin returns a pinned reference for an object at the current or a named
// commit.
func (s *Store) Pin(object model.Hash32, snapshot *model.Hash32) (resolver.ResolvedRef, error) {
	pin := s.head
	state := s.state
	if snapshot != nil {
		pin = *snapshot
		pinned, err := s.StateAt(pin)
		if err != nil {
			return resolver.ResolvedRef{}, err
		}
		state = pinned
	}
	record, ok := state.Objects[object]
	if !ok {
		return resolver.ResolvedRef{}, werr.Newf(werr.NotFound, "no such object at this snapshot")
	}
	return resolver.ResolvedRef{
		Namespace: model.DefaultNamespace, Snapshot: pin, ObjectID: record.ID,
		VersionID: record.Version, ContentID: record.Content,
	}, nil
}

// ---- saved contexts ------------------------------------------------------

func isSavedContext(relation model.RelationRecord) bool {
	return relation.Subject == model.RootID &&
		relation.Predicate == model.SavedContextPred &&
		relation.Kind == model.RelationValue &&
		relation.Provenance == nil
}

func contextRelationsAt(state *model.State, name string) ([]model.RelationRecord, error) {
	out := make([]model.RelationRecord, 0, 1)
	for _, relation := range state.Relations {
		if !isSavedContext(relation) {
			continue
		}
		if relation.Target.Object == nil && relation.Target.Value.Kind == wcb.Text && relation.Target.Value.Str == name {
			out = append(out, relation)
		}
	}
	if len(out) > 1 {
		return nil, werr.Newf(werr.Corrupt, "more than one saved context relation has the same name")
	}
	return out, nil
}

func contextFromRelation(name string, relation model.RelationRecord) (SavedContext, error) {
	value, ok := relation.Attrs[model.SavedContextAttr]
	if !ok || value.Kind != wcb.Text {
		return SavedContext{}, werr.Newf(werr.Corrupt, "saved context relation has no selector_hex attribute")
	}
	bytesValue, err := hex.DecodeString(value.Str)
	if err != nil {
		return SavedContext{}, werr.Newf(werr.Corrupt, "saved context selector is not hex")
	}
	sel, err := selector.FromCanonicalBytes(bytesValue, limits.Default())
	if err != nil {
		return SavedContext{}, werr.FromCodec(err)
	}
	selectorID, err := sel.SelectorID(limits.Default())
	if err != nil {
		return SavedContext{}, werr.FromCodec(err)
	}
	return SavedContext{
		Name: name, SelectorHex: value.Str, SelectorID: selectorID, RelationID: relation.ID,
	}, nil
}

// ListContexts returns all saved contexts sorted by name.
func (s *Store) ListContexts() ([]SavedContext, error) {
	return s.ListContextsAt(s.state)
}

// ListContextsAt returns saved contexts in an explicit state.
func (s *Store) ListContextsAt(state *model.State) ([]SavedContext, error) {
	out := make([]SavedContext, 0)
	for _, relation := range state.Relations {
		if !isSavedContext(relation) {
			continue
		}
		if relation.Target.Object != nil || relation.Target.Value.Kind != wcb.Text {
			return nil, werr.Newf(werr.Corrupt, "saved_context target is not text")
		}
		context, err := contextFromRelation(relation.Target.Value.Str, relation)
		if err != nil {
			return nil, err
		}
		out = append(out, context)
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare([]byte(out[i].Name), []byte(out[j].Name)) < 0 })
	return out, nil
}

// LoadContext loads a saved context selector by name.
func (s *Store) LoadContext(name string) (*selector.Selector, error) {
	return s.LoadContextAt(s.state, name)
}

// LoadContextAt loads a saved context selector from an explicit state.
func (s *Store) LoadContextAt(state *model.State, name string) (*selector.Selector, error) {
	relations, err := contextRelationsAt(state, name)
	if err != nil {
		return nil, err
	}
	if len(relations) == 0 {
		return nil, werr.Newf(werr.NotFound, "no such saved context")
	}
	saved, err := contextFromRelation(name, relations[0])
	if err != nil {
		return nil, err
	}
	bytesValue, err := hex.DecodeString(saved.SelectorHex)
	if err != nil {
		return nil, werr.Newf(werr.Corrupt, "saved context selector is not hex")
	}
	sel, err := selector.FromCanonicalBytes(bytesValue, limits.Default())
	if err != nil {
		return nil, werr.FromCodec(err)
	}
	reencoded, err := sel.CanonicalBytes(limits.Default())
	if err != nil {
		return nil, werr.FromCodec(err)
	}
	if !bytes.Equal(reencoded, bytesValue) {
		return nil, werr.Newf(werr.NonCanonical, "saved context selector bytes are not canonical")
	}
	return sel, nil
}

// SaveContext saves (or replaces) a named selector context.
func (s *Store) SaveContext(name string, sel *selector.Selector) (model.Hash32, error) {
	if err := s.requireWritable(); err != nil {
		return model.Hash32{}, err
	}
	if err := model.ValidateSnapshotName(name); err != nil {
		return model.Hash32{}, err
	}
	canonical, err := sel.CanonicalBytes(limits.Default())
	if err != nil {
		return model.Hash32{}, werr.FromCodec(err)
	}
	attrs := map[string]wcb.Value{
		model.SavedContextAttr: wcb.TextValue(hex.EncodeToString(canonical)),
	}
	record, err := model.NewRelationRecord(
		model.RootID, model.SavedContextPred, model.ValueTarget(wcb.TextValue(name)), nil, attrs,
	)
	if err != nil {
		return model.Hash32{}, err
	}
	existing, err := contextRelationsAt(s.state, name)
	if err != nil {
		return model.Hash32{}, err
	}
	switch len(existing) {
	case 0:
		if _, err := s.commitOps([]model.Op{model.PutRelationOp{Record: record}}, false); err != nil {
			return model.Hash32{}, err
		}
		return record.ID, nil
	case 1:
		if existing[0].ID == record.ID {
			return record.ID, nil
		}
		ops := []model.Op{
			model.DelRelationOp{ID: existing[0].ID},
			model.PutRelationOp{Record: record},
		}
		if _, err := s.commitOps(ops, false); err != nil {
			return model.Hash32{}, err
		}
		return record.ID, nil
	default:
		return model.Hash32{}, werr.Newf(werr.Corrupt, "more than one saved context relation has the same name")
	}
}

// DeleteContext deletes a saved context by name.
func (s *Store) DeleteContext(name string) error {
	if err := s.requireWritable(); err != nil {
		return err
	}
	existing, err := contextRelationsAt(s.state, name)
	if err != nil {
		return err
	}
	if len(existing) == 0 {
		return werr.Newf(werr.NotFound, "no such saved context")
	}
	_, err = s.commitOps([]model.Op{model.DelRelationOp{ID: existing[0].ID}}, false)
	return err
}
