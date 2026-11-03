// Package store reads and writes the portable WeftFS v1 on-disk format
// (WEFT-MODEL.md §2). It is single-writer (flock) and verifies content
// identities before use. No Rust binary, cgo, or FFI participates in any
// production path.
package store

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// Superblock magic.
var superblockMagic = [4]byte{'W', 'F', 'S', 'B'}

// Commit file magic.
var commitMagic = [4]byte{'W', 'F', 'C', '1'}

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// CRC32C returns the Castagnoli CRC used throughout the format.
func CRC32C(b []byte) uint32 { return crc32.Checksum(b, castagnoli) }

// SuperblockSlot is one 4096-byte slot.
type SuperblockSlot struct {
	Generation  uint64
	Commit      model.Hash32
	CommitLen   uint64
	TimestampNS int64
}

// Encode returns one 4096-byte slot.
func (s SuperblockSlot) Encode() []byte {
	out := make([]byte, model.SlotBytes)
	copy(out[0:4], superblockMagic[:])
	binary.LittleEndian.PutUint16(out[4:6], model.FormatMajor)
	binary.LittleEndian.PutUint16(out[6:8], model.FormatMinor)
	binary.LittleEndian.PutUint64(out[8:16], s.Generation)
	copy(out[16:48], s.Commit[:])
	binary.LittleEndian.PutUint64(out[48:56], s.CommitLen)
	binary.LittleEndian.PutUint64(out[56:64], uint64(s.TimestampNS))
	binary.LittleEndian.PutUint32(out[64:68], CRC32C(out[0:64]))
	return out
}

// DecodeSuperblockSlot decodes and validates one 4096-byte slot.
func DecodeSuperblockSlot(b []byte) (SuperblockSlot, error) {
	var slot SuperblockSlot
	if len(b) != model.SlotBytes {
		return slot, werr.Newf(werr.Malformed, "superblock slot must be 4096 bytes")
	}
	if !bytes.Equal(b[0:4], superblockMagic[:]) {
		return slot, werr.Newf(werr.Malformed, "bad superblock magic")
	}
	major := binary.LittleEndian.Uint16(b[4:6])
	minor := binary.LittleEndian.Uint16(b[6:8])
	if major != model.FormatMajor || minor != model.FormatMinor {
		return slot, werr.Newf(werr.Unsupported, "superblock version %d.%d", major, minor)
	}
	stored := binary.LittleEndian.Uint32(b[64:68])
	actual := CRC32C(b[0:64])
	if stored != actual {
		return slot, werr.Newf(werr.Corrupt, "superblock slot CRC mismatch")
	}
	for _, byteValue := range b[68:] {
		if byteValue != 0 {
			return slot, werr.Newf(werr.Malformed, "superblock slot padding is not zero")
		}
	}
	slot.Generation = binary.LittleEndian.Uint64(b[8:16])
	copy(slot.Commit[:], b[16:48])
	slot.CommitLen = binary.LittleEndian.Uint64(b[48:56])
	slot.TimestampNS = int64(binary.LittleEndian.Uint64(b[56:64]))
	if slot.Generation == 0 {
		return slot, werr.Newf(werr.Malformed, "superblock generation must be positive")
	}
	if slot.Commit == model.ZeroHash {
		return slot, werr.Newf(werr.Malformed, "superblock commit hash is zero")
	}
	if slot.CommitLen == 0 {
		return slot, werr.Newf(werr.Malformed, "superblock commit length is zero")
	}
	return slot, nil
}

// SuperblockView is the decoded superblock plus per-slot outcomes.
type SuperblockView struct {
	Bytes []byte
	Slots [2]SuperblockSlot
	Valid [2]bool
	Notes []string
}

// ReadSuperblock reads both slots. An all-zero slot is empty; a non-zero
// invalid slot is recorded as a recovery note.
func ReadSuperblock(root string) (SuperblockView, error) {
	var view SuperblockView
	path := filepath.Join(root, "superblock")
	b, err := os.ReadFile(path)
	if err != nil {
		return view, werr.Wrap(werr.Corrupt, err, "cannot read superblock %s", path)
	}
	if len(b) != model.SuperblockBytes {
		return view, werr.Newf(werr.Corrupt, "superblock is %d bytes, expected %d", len(b), model.SuperblockBytes)
	}
	view.Bytes = b
	for index := 0; index < 2; index++ {
		offset := index * model.SlotBytes
		raw := b[offset : offset+model.SlotBytes]
		slot, err := DecodeSuperblockSlot(raw)
		if err != nil {
			nonZero := false
			for _, byteValue := range raw {
				if byteValue != 0 {
					nonZero = true
					break
				}
			}
			if nonZero {
				view.Notes = append(view.Notes, "superblock slot "+strconv.Itoa(index)+" is invalid: "+err.Error())
			}
			continue
		}
		view.Slots[index] = slot
		view.Valid[index] = true
	}
	return view, nil
}

// LoadedCommit is a parsed commit file.
type LoadedCommit struct {
	Generation uint64
	Hash       model.Hash32
	WCBLength  uint64
	Commit     model.Commit
}

// EncodeCommitFile returns `WFC1 || u64le len || WCB || u32le CRC32C(WCB)`.
func EncodeCommitFile(wcbBytes []byte) []byte {
	out := make([]byte, 0, 4+8+len(wcbBytes)+4)
	out = append(out, commitMagic[:]...)
	var length [8]byte
	binary.LittleEndian.PutUint64(length[:], uint64(len(wcbBytes)))
	out = append(out, length[:]...)
	out = append(out, wcbBytes...)
	var crc [4]byte
	binary.LittleEndian.PutUint32(crc[:], CRC32C(wcbBytes))
	out = append(out, crc[:]...)
	return out
}

// DecodeCommitFile validates magic, exact length, CRC, WCB canonical form, and
// the commit hash. It returns the raw WCB bytes and the parsed commit.
func DecodeCommitFile(b []byte) ([]byte, model.Commit, error) {
	if len(b) < 16 {
		return nil, model.Commit{}, werr.Newf(werr.Corrupt, "commit file is truncated")
	}
	if !bytes.Equal(b[0:4], commitMagic[:]) {
		return nil, model.Commit{}, werr.Newf(werr.Malformed, "bad commit file magic")
	}
	length := binary.LittleEndian.Uint64(b[4:12])
	if length > uint64(^uint(0)>>1) {
		return nil, model.Commit{}, werr.Newf(werr.LimitExceeded, "commit length exceeds addressable size")
	}
	expected := uint64(12) + length + 4
	if expected != uint64(len(b)) {
		return nil, model.Commit{}, werr.Newf(werr.Corrupt, "commit file length %d does not match declared %d", len(b), expected)
	}
	wcbBytes := b[12 : 12+length]
	stored := binary.LittleEndian.Uint32(b[12+length:])
	if stored != CRC32C(wcbBytes) {
		return nil, model.Commit{}, werr.Newf(werr.Corrupt, "commit record CRC mismatch")
	}
	value, err := model.DecodeWCB(wcbBytes)
	if err != nil {
		return nil, model.Commit{}, err
	}
	commit, err := model.CommitFromWCB(value)
	if err != nil {
		return nil, model.Commit{}, err
	}
	reencoded, err := commit.Encode()
	if err != nil {
		return nil, model.Commit{}, err
	}
	if !bytes.Equal(reencoded, wcbBytes) {
		return nil, model.Commit{}, werr.Newf(werr.Corrupt, "commit record re-encoding is not canonical")
	}
	return append([]byte(nil), wcbBytes...), commit, nil
}

// ObjectPath returns objects/<ab>/<hash>.
func ObjectPath(root string, hash model.Hash32) string {
	hex := hash.Hex()
	return filepath.Join(root, "objects", hex[0:2], hex)
}

// ManifestPath returns manifests/<ab>/<hash>.
func ManifestPath(root string, hash model.Hash32) string {
	hex := hash.Hex()
	return filepath.Join(root, "manifests", hex[0:2], hex)
}

// CommitPath returns commits/<generation>.commit.
func CommitPath(root string, generation uint64) string {
	return filepath.Join(root, "commits", strconv.FormatUint(generation, 10)+".commit")
}

// ParseCommitFilename returns the generation of a canonical commit filename.
func ParseCommitFilename(name string) (uint64, bool) {
	stem, ok := strings.CutSuffix(name, ".commit")
	if !ok || stem == "" {
		return 0, false
	}
	for i := 0; i < len(stem); i++ {
		if stem[i] < '0' || stem[i] > '9' {
			return 0, false
		}
	}
	value, err := strconv.ParseUint(stem, 10, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

// ScanCommitFiles returns every commit file keyed by generation.
func ScanCommitFiles(root string) (map[uint64]string, error) {
	dir := filepath.Join(root, "commits")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, werr.Wrap(werr.Corrupt, err, "cannot read %s", dir)
	}
	out := make(map[uint64]string, len(entries))
	for _, entry := range entries {
		generation, ok := ParseCommitFilename(entry.Name())
		if !ok {
			continue
		}
		out[generation] = filepath.Join(dir, entry.Name())
	}
	return out, nil
}

// LoadCommitFile reads and validates one commit file. When expected is
// non-nil, the commit's declared generation must match it.
func LoadCommitFile(path string, expected *uint64) (LoadedCommit, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return LoadedCommit{}, werr.Wrap(werr.Corrupt, err, "cannot read %s", path)
	}
	wcbBytes, commit, err := DecodeCommitFile(b)
	if err != nil {
		return LoadedCommit{}, err
	}
	if expected != nil && commit.Generation != *expected {
		return LoadedCommit{}, werr.Newf(werr.Corrupt, "commit file %s declares generation %d but the filename says %d", path, commit.Generation, *expected)
	}
	hash := model.CommitIDBytes(wcbBytes)
	recomputed, err := commit.ID()
	if err != nil {
		return LoadedCommit{}, err
	}
	if recomputed != hash {
		return LoadedCommit{}, werr.Newf(werr.Corrupt, "commit record re-encoding is not canonical")
	}
	return LoadedCommit{
		Generation: commit.Generation, Hash: hash, WCBLength: uint64(len(wcbBytes)), Commit: commit,
	}, nil
}
