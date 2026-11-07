// Blob and commit planes: the two physical contracts a Go store needs.
//
// Rust splits the historical `StorageBackend` into an immutable `BlobPlane`
// (chunks, manifests, indexes, packs) and a versioned `CommitPlane` (FORMAT,
// LOCK, superblock, commits, refs, quota, access counters). This file is the
// Go port of that split for the local and object filesystem backends.
//
// Capabilities are proved on a writable open, never merely declared:
//
//   - the blob probe publishes a private object, HEADs its length, reads a
//     mid-range slice, and deletes it;
//   - the commit probe performs a create-once CAS, a matching CAS, and a stale
//     CAS that must be refused with Busy.
//
// A declared-absent capability is never upgraded by a probe. The `posix`
// backend declares no atomic publication and no conditional update and is
// therefore refused for a writable store; it exists so that refusal is
// testable, exactly like Rust's `BackendKind::Posix`.
//
// Read-only opens never probe and never write.
package store

import (
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/infinityabundance/WeftCodec-Go/hash"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// ControlTokenDomain is the domain for the compare-and-swap token of a control
// record. It is the same domain and construction as Rust's `control_token`, so
// a token computed by one implementation matches the other.
const ControlTokenDomain = "weft/control/token/v1"

// ControlToken returns the canonical CAS token of a control record: the hex
// content hash of its bytes.
func ControlToken(bytes []byte) string {
	return hash.Domain(ControlTokenDomain, bytes).Hex()
}

// PlaneKind selects one physical filesystem plane.
type PlaneKind string

const (
	// PlaneLocal is the normative POSIX layout published with rename(2).
	PlaneLocal PlaneKind = "local"
	// PlaneObject uses the same layout and publishes with link(2).
	PlaneObject PlaneKind = "object"
	// PlanePosix declares absent atomic publication and conditional update. It
	// is never usable for a writable store; it exists to prove the refusal.
	PlanePosix PlaneKind = "posix"
	// PlaneS3 is an S3-compatible object endpoint. Every blob and control
	// record maps to one logical key and is published with a conditional write.
	PlaneS3 PlaneKind = "s3"
)

// ParsePlaneKind parses `local|object|posix|s3`.
func ParsePlaneKind(text string) (PlaneKind, error) {
	switch PlaneKind(text) {
	case PlaneLocal, PlaneObject, PlanePosix, PlaneS3:
		return PlaneKind(text), nil
	default:
		return "", werr.Newf(werr.InvalidArgument,
			"backend must be `local`, `object`, `posix`, or `s3` (got `%s`)", text)
	}
}

// BlobCapabilities are the declared guarantees of a blob plane.
type BlobCapabilities struct {
	Backend        string `json:"backend"`
	AtomicPublish  bool   `json:"atomic_publish"`
	DurableFSync   bool   `json:"durable_fsync"`
	TrueRangeReads bool   `json:"true_range_reads"`
	MaxObjectBytes uint64 `json:"max_object_bytes"`
	Consistency    string `json:"consistency"`
	Publication    string `json:"publication"`
}

// CommitCapabilities are the declared guarantees of a commit plane.
type CommitCapabilities struct {
	Backend           string `json:"backend"`
	ConditionalUpdate bool   `json:"conditional_update"`
	AtomicPublish     bool   `json:"atomic_publish"`
	DurableFSync      bool   `json:"durable_fsync"`
	MaxControlBytes   uint64 `json:"max_control_bytes"`
	Consistency       string `json:"consistency"`
	Publication       string `json:"publication"`
}

// BlobProbe is the evidence produced by a blob-plane probe.
type BlobProbe struct {
	Backend           string `json:"backend"`
	Attempted         bool   `json:"attempted"`
	CreateOnceVisible bool   `json:"create_once_visible"`
	LengthMatch       bool   `json:"length_match"`
	RangeReadMatch    bool   `json:"range_read_match"`
	DeleteObserved    bool   `json:"delete_observed"`
	BytesProbed       uint64 `json:"bytes_probed"`
	Detail            string `json:"detail"`
}

// CommitProbe is the evidence produced by a commit-plane probe.
type CommitProbe struct {
	Backend                      string `json:"backend"`
	Attempted                    bool   `json:"attempted"`
	CreateOK                     bool   `json:"create_ok"`
	MatchingCompareExchangeOK    bool   `json:"matching_compare_exchange_ok"`
	StaleCompareExchangeRejected bool   `json:"stale_compare_exchange_rejected"`
	TokenKind                    string `json:"token_kind"`
	Detail                       string `json:"detail"`
}

// PlaneReport records both probes and the routed plane capabilities.
type PlaneReport struct {
	Blobs       BlobCapabilities   `json:"blobs"`
	Commits     CommitCapabilities `json:"commits"`
	BlobProbe   *BlobProbe         `json:"blob_probe,omitempty"`
	CommitProbe *CommitProbe       `json:"commit_probe,omitempty"`
	BlobRoot    string             `json:"blob_root"`
	CommitRoot  string             `json:"commit_root"`
	Packing     bool               `json:"packing"`
}

const maxObjectBytes = uint64(1) << 30

var probeCounter atomic.Uint64

func probeRelPath(tag string) string {
	return filepath.ToSlash(filepath.Join("tmp", "put-plane-probe-"+tag+"-"+
		itoa(uint64(os.Getpid()))+"-"+itoa(probeCounter.Add(1))))
}

// probeBytes is the deterministic 192-byte probe payload.
func probeBytes() []byte {
	out := make([]byte, 192)
	for i := range out {
		out[i] = byte(i % 251)
	}
	return out
}

// BlobEntry is one logical blob discovered by List.
type BlobEntry struct {
	Kind    BlobKind
	ID      model.Hash32
	Rel     string
	Size    uint64
	ModTime time.Time
}

// probe is the capability proof a blob plane must provide on a writable open.
type blobProber interface {
	probe() (BlobProbe, error)
}

// BlobAccess is the logical immutable blob namespace. Every reader, writer,
// verifier, and collector uses it, so packing and routing cannot be bypassed.
type BlobAccess interface {
	Label() string
	Capabilities() BlobCapabilities
	Get(kind BlobKind, id model.Hash32) ([]byte, error)
	GetRange(kind BlobKind, id model.Hash32, offset, length uint64) ([]byte, error)
	Put(kind BlobKind, id model.Hash32, data []byte) error
	Delete(kind BlobKind, id model.Hash32) error
	DeleteEntry(entry BlobEntry) error
	Length(kind BlobKind, id model.Hash32) (uint64, error)
	Exists(kind BlobKind, id model.Hash32) (bool, error)
	List(kindDir string) ([]BlobEntry, []string, error)
	Modified(kind BlobKind, id model.Hash32) (time.Time, bool)
	Flush() error
	ReclaimUnreferencedPacks() (PackReclaim, error)
	VerifyPacks() ([]string, error)
	Root() string
}

// CloseBlob releases a plane that owns handles (none currently). It exists so
// a future remote plane can be shut down deterministically.
func CloseBlob(plane BlobAccess) error {
	if closer, ok := plane.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

func blobRelPath(kind BlobKind, id model.Hash32) string {
	switch kind {
	case BlobObject:
		return relFromAbs("objects", id)
	case BlobManifest:
		return relFromAbs("manifests", id)
	case BlobIndex:
		hexID := id.Hex()
		return filepath.ToSlash(filepath.Join("indexes", hexID[:2], hexID+".idx"))
	case BlobPack:
		return relFromAbs("packs", id)
	case BlobPackCatalog:
		return relFromAbs("pack-catalog", id)
	default:
		return ""
	}
}

func relFromAbs(dir string, id model.Hash32) string {
	hexID := id.Hex()
	return filepath.ToSlash(filepath.Join(dir, hexID[:2], hexID))
}

func parseBlobRel(rel string) (BlobKind, model.Hash32, bool) {
	cleaned := filepath.ToSlash(rel)
	switch {
	case hasPrefix(cleaned, "objects/"):
		id, ok := hashFromRel(cleaned, "objects/", "")
		return BlobObject, id, ok
	case hasPrefix(cleaned, "manifests/"):
		id, ok := hashFromRel(cleaned, "manifests/", "")
		return BlobManifest, id, ok
	case hasPrefix(cleaned, "indexes/"):
		id, ok := hashFromRel(cleaned, "indexes/", ".idx")
		return BlobIndex, id, ok
	case hasPrefix(cleaned, "packs/"):
		id, ok := hashFromRel(cleaned, "packs/", "")
		return BlobPack, id, ok
	case hasPrefix(cleaned, "pack-catalog/"):
		id, ok := hashFromRel(cleaned, "pack-catalog/", "")
		return BlobPackCatalog, id, ok
	default:
		return 0, model.Hash32{}, false
	}
}

func hashFromRel(rel, prefix, suffix string) (model.Hash32, bool) {
	rest := rel[len(prefix):]
	parts := splitSlash(rest)
	if len(parts) != 2 {
		return model.Hash32{}, false
	}
	name := parts[1]
	if suffix != "" {
		if len(name) <= len(suffix) || name[len(name)-len(suffix):] != suffix {
			return model.Hash32{}, false
		}
		name = name[:len(name)-len(suffix)]
	}
	id, ok := parseLowerHash(name)
	if !ok {
		return model.Hash32{}, false
	}
	// The shard directory is not part of the name: the Go collector has
	// always swept a hash-named regular file wherever it sits inside its kind
	// namespace, and DeleteEntry removes the exact relative path observed.
	return id, true
}

func splitSlash(text string) []string {
	out := make([]string, 0, 2)
	start := 0
	for i := 0; i < len(text); i++ {
		if text[i] == '/' {
			out = append(out, text[start:i])
			start = i + 1
		}
	}
	out = append(out, text[start:])
	return out
}

// flatBlobPlane is the local or object filesystem plane.
type flatBlobPlane struct {
	root string
	kind PlaneKind
	caps BlobCapabilities
}

func newFlatBlobPlane(root string, kind PlaneKind) (*flatBlobPlane, error) {
	switch kind {
	case PlaneLocal:
		return &flatBlobPlane{root: root, kind: kind, caps: BlobCapabilities{
			Backend: string(PlaneLocal), AtomicPublish: true, DurableFSync: true,
			TrueRangeReads: true, MaxObjectBytes: maxObjectBytes,
			Consistency: "single POSIX filesystem; one writer under LOCK",
			Publication: "fsynced temporary file published with rename(2), then directory fsync",
		}}, nil
	case PlaneObject:
		return &flatBlobPlane{root: root, kind: kind, caps: BlobCapabilities{
			Backend: string(PlaneObject), AtomicPublish: true, DurableFSync: true,
			TrueRangeReads: true, MaxObjectBytes: maxObjectBytes,
			Consistency: "immutable object namespace on one POSIX filesystem",
			Publication: "fsynced temporary file published with link(2), then directory fsync",
		}}, nil
	case PlanePosix:
		return &flatBlobPlane{root: root, kind: kind, caps: BlobCapabilities{
			Backend: string(PlanePosix), AtomicPublish: false, DurableFSync: false,
			TrueRangeReads: true, MaxObjectBytes: maxObjectBytes,
			Consistency: "declared unmeasured POSIX mount; no guarantee is claimed",
			Publication: "declared: no atomic publication path",
		}}, nil
	default:
		return nil, werr.Newf(werr.InvalidArgument, "unknown blob plane `%s`", kind)
	}
}

func (p *flatBlobPlane) Label() string                  { return string(p.kind) }
func (p *flatBlobPlane) Capabilities() BlobCapabilities { return p.caps }
func (p *flatBlobPlane) Root() string                   { return p.root }
func (p *flatBlobPlane) Flush() error                   { return nil }
func (p *flatBlobPlane) ReclaimUnreferencedPacks() (PackReclaim, error) {
	return PackReclaim{}, nil
}
func (p *flatBlobPlane) VerifyPacks() ([]string, error) { return nil, nil }

func (p *flatBlobPlane) path(kind BlobKind, id model.Hash32) string {
	rel := blobRelPath(kind, id)
	return filepath.Join(p.root, filepath.FromSlash(rel))
}

func (p *flatBlobPlane) Get(kind BlobKind, id model.Hash32) ([]byte, error) {
	path := p.path(kind, id)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, werr.Wrap(werr.NotFound, err, "blob %s does not exist", path)
		}
		return nil, werr.Wrap(werr.Io, err, "cannot read %s", path)
	}
	return data, nil
}

func (p *flatBlobPlane) GetRange(kind BlobKind, id model.Hash32, offset, length uint64) ([]byte, error) {
	path := p.path(kind, id)
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, werr.Wrap(werr.NotFound, err, "blob %s does not exist", path)
		}
		return nil, werr.Wrap(werr.Io, err, "cannot open %s", path)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, werr.Wrap(werr.Io, err, "cannot stat %s", path)
	}
	size := uint64(info.Size())
	if offset > size {
		return nil, werr.Newf(werr.InvalidArgument,
			"read offset %d is beyond %s (%d bytes)", offset, path, size)
	}
	want := size - offset
	if length < want {
		want = length
	}
	if want == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, want)
	n, err := file.ReadAt(buf, int64(offset))
	if err != nil && uint64(n) < want {
		return nil, werr.Wrap(werr.Io, err, "short ranged read of %s", path)
	}
	return buf[:n], nil
}

func (p *flatBlobPlane) Put(kind BlobKind, id model.Hash32, data []byte) error {
	path := p.path(kind, id)
	if existing, err := os.ReadFile(path); err == nil {
		if !overlayBytesSame(existing, data) {
			return werr.Newf(werr.Exists, "blob %s already exists with different bytes", path)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return werr.Wrap(werr.Io, err, "cannot stat %s", path)
	}
	parent := filepath.Dir(path)
	if _, err := os.Stat(parent); err == nil {
		// Shard directory already exists.
	} else if errors.Is(err, os.ErrNotExist) {
		if err := makeDir(parent); err != nil {
			return err
		}
		if err := fsyncDir(filepath.Dir(parent)); err != nil {
			return err
		}
	} else {
		return werr.Wrap(werr.Io, err, "cannot stat %s", parent)
	}
	tmpDir := filepath.Join(p.root, "tmp")
	if err := makeDir(tmpDir); err != nil {
		return err
	}
	tmp := filepath.Join(tmpDir, "blob-"+itoa(uint64(os.Getpid()))+"-"+id.Hex()+"-"+itoa(probeCounter.Add(1)))
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return werr.Wrap(werr.Io, err, "cannot create %s", tmp)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		_ = os.Remove(tmp)
		return werr.Wrap(werr.Io, err, "cannot write %s", tmp)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		_ = os.Remove(tmp)
		return werr.Wrap(werr.Io, err, "cannot fsync %s", tmp)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmp)
		return werr.Wrap(werr.Io, err, "cannot close %s", tmp)
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		_ = os.Remove(tmp)
		return werr.Wrap(werr.Io, err, "cannot chmod %s", tmp)
	}
	if p.kind == PlaneObject {
		if err := os.Link(tmp, path); err != nil {
			_ = os.Remove(tmp)
			if errors.Is(err, os.ErrExist) {
				existing, readErr := os.ReadFile(path)
				if readErr == nil && overlayBytesSame(existing, data) {
					return nil
				}
				return werr.Newf(werr.Exists, "blob %s already exists with different bytes", path)
			}
			return werr.Wrap(werr.Io, err, "cannot link %s into place", path)
		}
		_ = os.Remove(tmp)
	} else {
		if err := os.Rename(tmp, path); err != nil {
			_ = os.Remove(tmp)
			return werr.Wrap(werr.Io, err, "cannot rename %s into place", path)
		}
	}
	return fsyncDir(parent)
}

func (p *flatBlobPlane) DeleteEntry(entry BlobEntry) error {
	path := filepath.Join(p.root, filepath.FromSlash(entry.Rel))
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return werr.Wrap(werr.NotFound, err, "blob %s does not exist", path)
		}
		return werr.Wrap(werr.Io, err, "cannot delete %s", path)
	}
	return fsyncDir(filepath.Dir(path))
}

func (p *flatBlobPlane) Delete(kind BlobKind, id model.Hash32) error {
	path := p.path(kind, id)
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return werr.Wrap(werr.NotFound, err, "blob %s does not exist", path)
		}
		return werr.Wrap(werr.Io, err, "cannot delete %s", path)
	}
	return fsyncDir(filepath.Dir(path))
}

func (p *flatBlobPlane) Length(kind BlobKind, id model.Hash32) (uint64, error) {
	path := p.path(kind, id)
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, werr.Wrap(werr.NotFound, err, "blob %s does not exist", path)
		}
		return 0, werr.Wrap(werr.Io, err, "cannot stat %s", path)
	}
	return uint64(info.Size()), nil
}

func (p *flatBlobPlane) Exists(kind BlobKind, id model.Hash32) (bool, error) {
	_, err := os.Stat(p.path(kind, id))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, werr.Wrap(werr.Io, err, "cannot stat blob")
}

func (p *flatBlobPlane) List(kindDir string) ([]BlobEntry, []string, error) {
	dir := filepath.Join(p.root, kindDir)
	shards, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, nil, werr.Wrap(werr.Io, err, "cannot read %s", dir)
	}
	entries := make([]BlobEntry, 0)
	problems := make([]string, 0)
	for _, shard := range shards {
		shardPath := filepath.Join(dir, shard.Name())
		shardInfo, err := os.Lstat(shardPath)
		if err != nil {
			return nil, nil, werr.Wrap(werr.Io, err, "cannot stat %s", shardPath)
		}
		if !shardInfo.IsDir() || shardInfo.Mode()&os.ModeSymlink != 0 {
			continue
		}
		files, err := os.ReadDir(shardPath)
		if err != nil {
			return nil, nil, werr.Wrap(werr.Io, err, "cannot read %s", shardPath)
		}
		for _, file := range files {
			name := file.Name()
			path := filepath.Join(shardPath, name)
			info, err := os.Lstat(path)
			if err != nil {
				return nil, nil, werr.Wrap(werr.Io, err, "cannot stat %s", path)
			}
			if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				continue
			}
			rel := filepath.ToSlash(filepath.Join(kindDir, shard.Name(), name))
			kind, id, ok := parseBlobRel(rel)
			if !ok {
				problems = append(problems, "unrecognized blob filename "+path)
				continue
			}
			entries = append(entries, BlobEntry{Kind: kind, ID: id, Rel: rel, Size: uint64(info.Size()), ModTime: info.ModTime()})
		}
	}
	return entries, problems, nil
}

func (p *flatBlobPlane) Modified(kind BlobKind, id model.Hash32) (time.Time, bool) {
	info, err := os.Stat(p.path(kind, id))
	if err != nil {
		return time.Time{}, false
	}
	return info.ModTime(), true
}

// putRaw publishes an arbitrary relative path create-once. It exists for the
// plane probe, which is not a store key.
func (p *flatBlobPlane) putRaw(rel string, data []byte) error {
	path := filepath.Join(p.root, filepath.FromSlash(rel))
	if existing, err := os.ReadFile(path); err == nil {
		if !overlayBytesSame(existing, data) {
			return werr.Newf(werr.Exists, "%s already exists with different bytes", path)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return werr.Wrap(werr.Io, err, "cannot stat %s", path)
	}
	if err := makeDir(filepath.Dir(path)); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return werr.Wrap(werr.Io, err, "cannot create %s", path)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		_ = os.Remove(path)
		return werr.Wrap(werr.Io, err, "cannot write %s", path)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		_ = os.Remove(path)
		return werr.Wrap(werr.Io, err, "cannot fsync %s", path)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return werr.Wrap(werr.Io, err, "cannot close %s", path)
	}
	return fsyncDir(filepath.Dir(path))
}

func (p *flatBlobPlane) probe() (BlobProbe, error) {
	probe := BlobProbe{Backend: string(p.kind)}
	if !p.caps.AtomicPublish {
		probe.Detail = "skipped: atomic_publish is declared absent, so a writable store is refused"
		return probe, nil
	}
	data := probeBytes()
	rel := probeRelPath("blob")
	probe.Attempted = true
	probe.BytesProbed = uint64(len(data))
	if err := p.putRaw(rel, data); err != nil {
		return probe, err
	}
	path := filepath.Join(p.root, filepath.FromSlash(rel))
	stored, err := os.ReadFile(path)
	if err != nil {
		return probe, werr.Wrap(werr.Io, err, "probe read")
	}
	probe.CreateOnceVisible = overlayBytesSame(stored, data)
	info, err := os.Stat(path)
	if err == nil {
		probe.LengthMatch = uint64(info.Size()) == uint64(len(data))
	}
	start := len(data) / 3
	want := len(data) - start
	if want > 17 {
		want = 17
	}
	file, err := os.Open(path)
	if err != nil {
		return probe, werr.Wrap(werr.Io, err, "probe open")
	}
	buf := make([]byte, want)
	n, readErr := file.ReadAt(buf, int64(start))
	file.Close()
	if readErr != nil && n < want {
		return probe, werr.Wrap(werr.Io, readErr, "probe ranged read")
	}
	probe.RangeReadMatch = overlayBytesSame(buf[:n], data[start:start+n])
	if err := os.Remove(path); err != nil {
		return probe, werr.Wrap(werr.Io, err, "probe delete")
	}
	_, statErr := os.Stat(path)
	probe.DeleteObserved = errors.Is(statErr, os.ErrNotExist)
	if !probe.CreateOnceVisible || !probe.LengthMatch || !probe.RangeReadMatch || !probe.DeleteObserved {
		return probe, werr.Newf(werr.Io,
			"blob plane `%s` failed its capability probe (create_once_visible=%t, length_match=%t, range_read_match=%t, delete_observed=%t)",
			probe.Backend, probe.CreateOnceVisible, probe.LengthMatch, probe.RangeReadMatch, probe.DeleteObserved)
	}
	probe.Detail = "published 192 bytes under a private key, HEAD reported that length, a 17-byte ranged read matched, and delete was observed; durability is attested by the publication primitive and is not proved here"
	return probe, nil
}

// ControlPlane is the compare-and-swap control-record contract a pack catalog
// needs. commitPlane implements it; tests and future metadata engines can
// provide another implementation without simulating POSIX files.
type ControlPlane interface {
	ReadControl(name string) ([]byte, string, bool, error)
	CompareExchange(name string, expected *string, data []byte) (string, error)
	Root() string
}

// OpenControlPlane opens a local control plane at root.
func OpenControlPlane(root string, kind PlaneKind) (ControlPlane, error) {
	return newCommitPlane(root, kind)
}

// OpenFlatBlobPlane opens a flat local/object blob plane. It is exported for
// tests and embedders that compose planes directly; the store builds its own
// through the open options.
func OpenFlatBlobPlane(root string, kind PlaneKind) (BlobAccess, error) {
	return newFlatBlobPlane(root, kind)
}

// OpenPackedBlobPlane opens a packed plane over a flat blob root and a control
// plane at commitRoot.
func OpenPackedBlobPlane(blobRoot, commitRoot string, options PackOptions) (*PackedBlobPlane, error) {
	inner, err := newFlatBlobPlane(blobRoot, PlaneLocal)
	if err != nil {
		return nil, err
	}
	catalog, err := newCommitPlane(commitRoot, PlaneLocal)
	if err != nil {
		return nil, err
	}
	return NewPackedBlobPlane(inner, catalog, options)
}

// commitPlane stores the versioned control records under the store root.
type commitPlane struct {
	root string
	kind PlaneKind
	caps CommitCapabilities
}

func newCommitPlane(root string, kind PlaneKind) (*commitPlane, error) {
	caps := CommitCapabilities{
		Backend: string(kind), MaxControlBytes: maxObjectBytes,
		Consistency: "single POSIX filesystem; one writer under LOCK",
		Publication: "fsynced temporary file published with rename(2), then directory fsync",
	}
	switch kind {
	case PlaneLocal:
		caps.ConditionalUpdate = true
		caps.AtomicPublish = true
		caps.DurableFSync = true
	case PlaneObject:
		caps.ConditionalUpdate = true
		caps.AtomicPublish = true
		caps.DurableFSync = true
		caps.Publication = "fsynced temporary file published with link(2), then directory fsync"
	case PlanePosix:
		caps.ConditionalUpdate = false
		caps.AtomicPublish = false
		caps.DurableFSync = false
		caps.Publication = "declared: no atomic publication path"
	default:
		return nil, werr.Newf(werr.InvalidArgument, "unknown commit plane `%s`", kind)
	}
	return &commitPlane{root: root, kind: kind, caps: caps}, nil
}

func (c *commitPlane) Label() string                    { return string(c.kind) }
func (c *commitPlane) Capabilities() CommitCapabilities { return c.caps }
func (c *commitPlane) Root() string                     { return c.root }

func (c *commitPlane) path(name string) string {
	return filepath.Join(c.root, filepath.FromSlash(name))
}

// readControl returns (bytes, token, present, error).
func (c *commitPlane) ReadControl(name string) ([]byte, string, bool, error) {
	return c.readControl(name)
}

func (c *commitPlane) CompareExchange(name string, expected *string, data []byte) (string, error) {
	return c.compareExchange(name, expected, data)
}

func (c *commitPlane) readControl(name string) ([]byte, string, bool, error) {
	data, err := os.ReadFile(c.path(name))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, "", false, nil
		}
		return nil, "", false, werr.Wrap(werr.Io, err, "cannot read control record %s", name)
	}
	return data, ControlToken(data), true, nil
}

func (c *commitPlane) compareExchange(name string, expected *string, data []byte) (string, error) {
	_, token, present, err := c.readControl(name)
	if err != nil {
		return "", err
	}
	if expected == nil {
		if present {
			return "", werr.Newf(werr.Busy,
				"control record %s appeared before the compare-and-swap", name)
		}
	} else if !present || token != *expected {
		return "", werr.Newf(werr.Busy,
			"control record %s changed since it was read; compare-and-swap refused", name)
	}
	if err := writeReplace(c.path(name), data); err != nil {
		return "", err
	}
	return ControlToken(data), nil
}

func (c *commitPlane) writeControl(name string, data []byte) error {
	return writeReplace(c.path(name), data)
}

func (c *commitPlane) putControlIfAbsent(name string, data []byte) error {
	return writeNewFile(c.path(name), data, 0o644)
}

func (c *commitPlane) deleteControl(name string) error {
	if err := os.Remove(c.path(name)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return werr.Wrap(werr.NotFound, err, "control record %s does not exist", name)
		}
		return werr.Wrap(werr.Io, err, "cannot delete control record %s", name)
	}
	return fsyncDir(filepath.Dir(c.path(name)))
}

func (c *commitPlane) probe() (CommitProbe, error) {
	probe := CommitProbe{Backend: string(c.kind), TokenKind: "content-token"}
	if !c.caps.ConditionalUpdate {
		probe.Detail = "skipped: conditional_update is declared absent, so a writable store is refused"
		return probe, nil
	}
	probe.Attempted = true
	name := probeRelPath("commit")
	if err := makeDir(filepath.Dir(c.path(name))); err != nil {
		return probe, err
	}
	first, err := c.compareExchange(name, nil, []byte("plane-probe-a"))
	if err != nil {
		return probe, err
	}
	data, _, _, err := c.readControl(name)
	if err != nil {
		return probe, err
	}
	probe.CreateOK = overlayBytesSame(data, []byte("plane-probe-a"))
	second, err := c.compareExchange(name, &first, []byte("plane-probe-b"))
	if err != nil {
		return probe, err
	}
	data, _, _, err = c.readControl(name)
	if err != nil {
		return probe, err
	}
	probe.MatchingCompareExchangeOK = overlayBytesSame(data, []byte("plane-probe-b"))
	if _, err := c.compareExchange(name, &first, []byte("plane-probe-c")); err != nil {
		if typed, ok := err.(*werr.Error); ok && typed.Kind == werr.Busy {
			probe.StaleCompareExchangeRejected = true
		}
	}
	_ = second
	_ = c.deleteControl(name)
	if !probe.CreateOK || !probe.MatchingCompareExchangeOK {
		return probe, werr.Newf(werr.Io,
			"commit plane `%s` failed its capability probe (create_ok=%t, matching_compare_exchange_ok=%t)",
			probe.Backend, probe.CreateOK, probe.MatchingCompareExchangeOK)
	}
	if !probe.StaleCompareExchangeRejected {
		return probe, werr.Newf(werr.Unsupported,
			"commit plane `%s` accepted a stale compare-and-swap token; refusing a writable store",
			probe.Backend)
	}
	probe.Detail = "create-once CAS, matching CAS, and stale-token rejection all observed on a private control record; durability is attested by the publication primitive and is not proved here"
	return probe, nil
}

// requireWritablePlanes refuses a configuration the store cannot publish on.
func requireWritablePlanes(blobs BlobCapabilities, commits CommitCapabilities) error {
	if !blobs.AtomicPublish {
		return werr.Newf(werr.Unsupported,
			"blob plane `%s` declares no atomic publication; refusing a writable store", blobs.Backend)
	}
	if !commits.ConditionalUpdate {
		return werr.Newf(werr.Unsupported,
			"commit plane `%s` declares no conditional update; refusing a writable store", commits.Backend)
	}
	if !commits.AtomicPublish {
		return werr.Newf(werr.Unsupported,
			"commit plane `%s` declares no atomic publication; refusing a writable store", commits.Backend)
	}
	return nil
}

// ensureBlobLayout creates the immutable namespaces on the blob plane.
func ensureBlobLayout(root string) error {
	for _, relative := range []string{"objects", "manifests", "indexes", "tmp", "packs", "pack-catalog"} {
		if err := makeDir(filepath.Join(root, relative)); err != nil {
			return err
		}
	}
	return nil
}

// ensureCommitLayout creates the control namespaces on the commit plane.
func ensureCommitLayout(root string) error {
	for _, relative := range []string{
		"commits", "refs", "refs/snapshots", "refs/tags", "tmp", "access", "calibrations",
	} {
		if err := makeDir(filepath.Join(root, relative)); err != nil {
			return err
		}
	}
	return nil
}

// flockExclusive takes the single-writer lock. It lives here so both the store
// and a test can use exactly the same primitive.
func flockExclusive(path string) (*os.File, error) {
	lock, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, werr.Wrap(werr.Io, err, "cannot open LOCK")
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, werr.Wrap(werr.Busy, err, "store is locked by another writer")
	}
	return lock, nil
}
