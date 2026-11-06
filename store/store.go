package store

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/infinityabundance/WeftCodec-Go/hash"
	"github.com/infinityabundance/WeftCodec-Go/limits"
	"github.com/infinityabundance/WeftCodec-Go/selector"
	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/auth"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/resolver"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// Bounds (v1).
const (
	// MaxFileBytes is the maximum logical file size accepted by every
	// create/write/append/truncate path and by manifest validation.
	//
	// 1 TiB is a deliberate format/resource bound, not a product preference. A
	// v1 manifest carries one ChunkRef per chunk_size bytes; at the default
	// 64 KiB chunk size a full 1 TiB file still encodes to a manifest below the
	// MaxChunkSize*64 defensive cap enforced by storeFileContent. The bound is
	// enforced with LimitExceeded on create, buffered write, range write,
	// truncate, zero/collapse/insert, and on every manifest read. It matches
	// the Rust store's MAX_FILE_BYTES so both implementations accept the same
	// on-disk objects.
	MaxFileBytes              uint64 = 1024 * 1024 * 1024 * 1024
	DefaultCheckpointInterval uint64 = 256
	DefaultGCGraceSecs        uint64 = 3600
	DefaultGCIntervalSecs     uint64 = 60
	DefaultGCWatchMaxDeletes  uint64 = 256
	MaxXattrNameBytes                = 255
	MaxXattrValueBytes        uint64 = 65536
	MaxXattrCount                    = 1024
)

// maxInt is the largest value an int can hold on this platform.
const maxInt = int(^uint(0) >> 1)

// checkedSize converts a byte count to int for an allocation. A size the
// platform cannot address is a LimitExceeded, never a truncated index or a
// wrapped length.
func checkedSize(value uint64) (int, error) {
	if value > uint64(maxInt) {
		return 0, werr.Newf(werr.LimitExceeded, "size (%d) does not fit int", value)
	}
	return int(value), nil
}

// OpenMode selects writer locking.
type OpenMode int

const (
	// ReadWrite takes the exclusive writer lock.
	ReadWrite OpenMode = iota
	// ReadOnly takes no lock and pins a generation.
	ReadOnly
)

// Options configures a store.
type Options struct {
	OwnerUID           uint64
	OwnerGID           uint64
	ChunkSize          uint64
	CheckpointInterval uint64
	GCGraceSecs        uint64
	// GCBackground enables the FUSE frontend's periodic collector. It is
	// disabled by default; the store still requires the exclusive writer lock.
	GCBackground bool
	// GCIntervalSecs and GCWatchMaxDeletes bound a background pass: one
	// deletion budget per interval. Zero selects the v1 defaults.
	GCIntervalSecs    uint64
	GCWatchMaxDeletes uint64
	// FixedTimestampNS overrides every generated mtime and commit timestamp
	// (tests and the deterministic fixture). Nil uses the wall clock.
	FixedTimestampNS *int64
	// Representation selects the physical manifest policy for new content:
	// `raw` (the frozen v1 writer, the default) or `codec-auto` (experimental
	// v2 manifests).
	Representation RepresentationMode
	// ContentIdentity selects the content root for newly written chunk
	// manifests. The zero value writes the frozen v1 whole-file ContentId;
	// `merkle-v1` writes `weft.manifest.v3`. Existing v3 files stay v3.
	ContentIdentity model.ContentIdentity
	// CodecMinBytes leaves files smaller than this on the raw path under
	// `codec-auto`.
	CodecMinBytes uint64
	// CodecDeltaMarginPercent is the margin by which a DELTA frame must beat
	// the ZSTD frame to be selected. 0 disables the margin.
	CodecDeltaMarginPercent uint8
	// Quotas installs (or replaces) write budgets on open. An empty slice
	// leaves the persisted policy untouched.
	Quotas []QuotaBudget
	// MaxOverlayDepth bounds the chained `weft.manifest.v4` layers a range
	// write may create. Zero selects DefaultMaxOverlayDepth. It can never
	// exceed the normative reader bound model.MaxOverlayChainDepth.
	MaxOverlayDepth uint64
	// MaxOverlayBytes bounds the total logical bytes carried by an overlay
	// chain. Zero selects DefaultMaxOverlayBytes.
	MaxOverlayBytes uint64
	// BlobBackend selects the immutable blob plane (`local`, `object`, or
	// `posix`). The empty value is `local` (and `object` when the commit plane
	// is `object`, so a single `--backend object` store stays unchanged).
	BlobBackend PlaneKind
	// CommitBackend selects the versioned control plane. The empty value is
	// `local`.
	CommitBackend PlaneKind
	// BlobRoot relocates the blob plane (chunks, manifests, indexes, packs)
	// to another directory. Empty keeps it on the store root. Commit/control
	// state always lives on the store root.
	BlobRoot string
	// Packing groups small immutable blobs into physical pack objects.
	Packing bool
	// PackOptions is the physical packing policy; zero fields take the
	// DefaultPackOptions values before validation.
	PackOptions PackOptions
}

// DefaultOptions returns the normative v1 defaults.
func DefaultOptions() Options {
	return Options{
		OwnerUID:                0,
		OwnerGID:                0,
		ChunkSize:               model.DefaultChunkSize,
		CheckpointInterval:      DefaultCheckpointInterval,
		GCGraceSecs:             DefaultGCGraceSecs,
		GCIntervalSecs:          DefaultGCIntervalSecs,
		GCWatchMaxDeletes:       DefaultGCWatchMaxDeletes,
		Representation:          RepresentationModeRaw,
		ContentIdentity:         model.ContentIdentityWholeFile,
		CodecMinBytes:           DefaultCodecMinBytes,
		CodecDeltaMarginPercent: DefaultCodecDeltaMarginPercent,
		MaxOverlayDepth:         DefaultMaxOverlayDepth,
		MaxOverlayBytes:         DefaultMaxOverlayBytes,
		BlobBackend:             PlaneLocal,
		CommitBackend:           PlaneLocal,
		PackOptions:             DefaultPackOptions(),
	}
}

// DirEntry is a directory entry returned by ListDir.
type DirEntry struct {
	Name    []byte
	EntryID model.Hash32
	Target  model.Hash32
}

// SetAttr is a mutable attribute set for Setattr.
type SetAttr struct {
	Mode    *uint64
	UID     *uint64
	GID     *uint64
	MtimeNS *int64
	// Attrs replaces the whole attribute map when non-nil.
	Attrs map[string]wcb.Value
}

// SavedContext is a named selector saved as a relation.
type SavedContext struct {
	Name        string
	SelectorHex string
	SelectorID  model.Hash32
	RelationID  model.Hash32
}

// StatFS counters derived from replayed state.
type StatFS struct {
	BlockSize       uint64
	Blocks          uint64
	BlocksFree      uint64
	BlocksAvailable uint64
	Files           uint64
	FilesFree       uint64
	MaxNameLen      uint64
}

// Store is an open WeftFS store.
type Store struct {
	root           string
	mode           OpenMode
	options        Options
	lock           *os.File
	state          *model.State
	head           model.Hash32
	generation     uint64
	nextGeneration uint64
	rejected       []uint64
	notes          []string
	pins           map[model.Hash32]uint64
	contentPins    map[model.Hash32]uint64
	// Physical planes. `blobRoot` is the immutable namespace root (chunks,
	// manifests, indexes, packs); `root` is the store/commit root. On the
	// default configuration they are the same directory and the bytes are the
	// historical single-backend layout.
	blobRoot    string
	blobs       BlobAccess
	commits     *commitPlane
	probeFlat   *flatBlobPlane
	packed      *PackedBlobPlane
	planeReport PlaneReport
	// Write budgets and the committed blob set used to charge only genuinely
	// new bytes. Both are derived from committed state.
	quota     QuotaState
	blobIndex map[model.Hash32]uint64
	// access holds advisory per-object read counters (access/counts.v1).
	access         *accessCounts
	blobIndexReady bool
	// Chunk blobs read by the most recent Merkle range write. Diagnostic only:
	// it proves an overwrite does not stream the whole file.
	writeChunkReads atomic.Uint64
	// Group commit: while groupDepth > 0 mutations are applied to the live
	// state and their ops buffered instead of published. Nothing is durable
	// until CommitGroup publishes one commit; AbortGroup restores the
	// pre-group state from the journal.
	groupDepth           int
	pendingOps           []model.Op
	groupForceCheckpoint bool
	groupUndo            groupJournal
}

// ResetWriteChunkReads resets the Merkle range-write chunk-read counter.
func (s *Store) ResetWriteChunkReads() { s.writeChunkReads.Store(0) }

// WriteChunkReads returns the chunk blobs read by the most recent Merkle range
// write. It is a test/receipt hook, not a format feature.
func (s *Store) WriteChunkReads() uint64 { return s.writeChunkReads.Load() }

var tmpCounter atomic.Uint64

func crashPoint(phase string) {
	if configured := os.Getenv("WEFT_CRASH_PHASE"); configured == phase {
		// Process-fault proxy only; never a claim about power loss.
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGKILL)
		select {}
	}
}

func fsyncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return werr.Wrap(werr.Io, err, "cannot open directory %s", path)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return werr.Wrap(werr.Io, err, "cannot fsync directory %s", path)
	}
	return nil
}

func makeDir(path string) error {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return werr.Wrap(werr.Io, err, "cannot create %s", path)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		return werr.Wrap(werr.Io, err, "cannot chmod %s", path)
	}
	return nil
}

func validateOptions(opts Options) error {
	if opts.ChunkSize == 0 || opts.ChunkSize > model.MaxChunkSize {
		return werr.Newf(werr.InvalidArgument, "chunk_size must be 1..=16 MiB")
	}
	if _, err := NormalizeQuotaPolicy(opts.Quotas); err != nil {
		return err
	}
	switch opts.Representation {
	case RepresentationModeRaw, RepresentationModeCodecAuto, RepresentationModeOverlay:
	default:
		return werr.Newf(werr.InvalidArgument, "representation must be `raw`, `codec-auto`, or `overlay` (got `%s`)", opts.Representation)
	}
	if opts.BlobBackend == "" {
		opts.BlobBackend = PlaneLocal
	}
	if opts.CommitBackend == "" {
		opts.CommitBackend = PlaneLocal
	}
	if _, err := ParsePlaneKind(string(opts.BlobBackend)); err != nil {
		return err
	}
	if _, err := ParsePlaneKind(string(opts.CommitBackend)); err != nil {
		return err
	}
	if opts.BlobRoot != "" && opts.BlobBackend == PlanePosix {
		return werr.Newf(werr.InvalidArgument, "a `posix` blob plane cannot be given an explicit root")
	}
	if opts.BlobRoot != "" {
		cleaned := filepath.Clean(opts.BlobRoot)
		if cleaned == "." || cleaned == string(filepath.Separator) {
			return werr.Newf(werr.InvalidArgument, "--blob-root must name a directory")
		}
	}
	if opts.Packing && opts.PackOptions != (PackOptions{}) {
		if err := opts.PackOptions.Validate(); err != nil {
			return err
		}
	}
	if opts.MaxOverlayDepth == 0 {
		opts.MaxOverlayDepth = DefaultMaxOverlayDepth
	}
	if opts.MaxOverlayBytes == 0 {
		opts.MaxOverlayBytes = DefaultMaxOverlayBytes
	}
	if opts.MaxOverlayDepth > model.MaxOverlayChainDepth {
		return werr.Newf(werr.InvalidArgument,
			"max_overlay_depth must be 1..=%d (the normative reader bound)", model.MaxOverlayChainDepth)
	}
	if opts.Representation == RepresentationModeOverlay && opts.ContentIdentity != model.ContentIdentityMerkleV1 {
		return werr.Newf(werr.InvalidArgument,
			"`--representation overlay` requires the Merkle content identity; pass `--content-identity merkle`")
	}
	switch opts.ContentIdentity {
	case model.ContentIdentityWholeFile:
	case model.ContentIdentityMerkleV1:
		if opts.Representation == RepresentationModeCodecAuto {
			return werr.Newf(werr.InvalidArgument, "content_identity `merkle` cannot be combined with representation `codec-auto`")
		}
	default:
		return werr.Newf(werr.InvalidArgument, "content_identity must be `whole-file` or `merkle` (got `%s`)", opts.ContentIdentity)
	}
	if opts.CheckpointInterval > 1_000_000 {
		return werr.Newf(werr.InvalidArgument, "checkpoint_interval must be at most 1,000,000")
	}
	if opts.CodecDeltaMarginPercent > 90 {
		return werr.Newf(werr.InvalidArgument, "codec_delta_margin_percent must be at most 90")
	}
	if opts.GCBackground {
		if opts.GCIntervalSecs == 0 || opts.GCIntervalSecs > 86400 {
			return werr.Newf(werr.InvalidArgument, "gc_interval_secs must be 1..=86400")
		}
		if opts.GCWatchMaxDeletes == 0 || opts.GCWatchMaxDeletes > 1_000_000 {
			return werr.Newf(werr.InvalidArgument, "gc_watch_max_deletes must be 1..=1,000,000")
		}
	}
	return nil
}

func ensureLayout(root string) error {
	for _, relative := range []string{
		"commits", "objects", "manifests", "refs", "refs/snapshots", "refs/tags", "tmp",
	} {
		if err := makeDir(filepath.Join(root, relative)); err != nil {
			return err
		}
	}
	return nil
}

func cleanStaleTmp(root string, graceSecs uint64) error {
	dir := filepath.Join(root, "tmp")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return werr.Wrap(werr.Io, err, "cannot read %s", dir)
	}
	now := time.Now()
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !hasPrefix(name, "blob-") && !hasPrefix(name, "snap-") {
			continue
		}
		if graceSecs > 0 {
			info, err := entry.Info()
			if err != nil {
				continue
			}
			age := uint64(now.Sub(info.ModTime()).Seconds())
			if now.Before(info.ModTime()) || age < graceSecs {
				continue
			}
		}
		_ = os.Remove(filepath.Join(dir, name))
	}
	return nil
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func writeNewFile(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return werr.Wrap(werr.Io, err, "cannot create %s", path)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return werr.Wrap(werr.Io, err, "cannot write %s", path)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return werr.Wrap(werr.Io, err, "cannot fsync %s", path)
	}
	return file.Close()
}

// Init creates a new store at path. The directory must be absent or empty.
func Init(path string, opts Options) (*Store, error) {
	if err := validateOptions(opts); err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err == nil {
		if !info.IsDir() {
			return nil, werr.Newf(werr.Exists, "store path exists and is not a directory")
		}
		if _, err := os.Stat(filepath.Join(path, "FORMAT")); err == nil {
			return nil, werr.Newf(werr.Exists, "a WeftFS store already exists at this path")
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, werr.Wrap(werr.Io, err, "cannot read %s", path)
		}
		if len(entries) != 0 {
			return nil, werr.Newf(werr.Exists, "store path is not empty")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := makeDir(path); err != nil {
			return nil, err
		}
	} else {
		return nil, werr.Wrap(werr.Io, err, "cannot stat %s", path)
	}

	if err := ensureCommitLayout(path); err != nil {
		return nil, err
	}
	store := &Store{root: path, mode: ReadWrite, options: opts}
	if err := store.buildPlanes(); err != nil {
		return nil, err
	}
	if err := requireWritablePlanes(store.blobs.Capabilities(), store.commits.Capabilities()); err != nil {
		return nil, err
	}
	if err := ensureBlobLayout(store.blobRoot); err != nil {
		return nil, err
	}
	if err := writeNewFile(filepath.Join(path, "FORMAT"), []byte(model.FormatContents), 0o644); err != nil {
		return nil, err
	}

	lockPath := filepath.Join(path, "LOCK")
	lock, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, werr.Wrap(werr.Io, err, "cannot open LOCK")
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, werr.Wrap(werr.Busy, err, "store is locked by another writer")
	}

	superblockPath := filepath.Join(path, "superblock")
	file, err := os.OpenFile(superblockPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		lock.Close()
		return nil, werr.Wrap(werr.Io, err, "cannot create superblock")
	}
	if err := file.Truncate(model.SuperblockBytes); err != nil {
		file.Close()
		lock.Close()
		return nil, werr.Wrap(werr.Io, err, "cannot size superblock")
	}
	if err := file.Sync(); err != nil {
		file.Close()
		lock.Close()
		return nil, werr.Wrap(werr.Io, err, "cannot fsync superblock")
	}
	file.Close()

	store.lock = lock
	store.state = model.NewState()
	store.head = model.ZeroHash
	store.generation = 0
	store.rejected = nil
	store.notes = nil
	store.pins = make(map[model.Hash32]uint64)
	store.contentPins = make(map[model.Hash32]uint64)
	store.quota = newQuotaState()
	store.blobIndex = map[model.Hash32]uint64{}
	store.access = loadAccessCounts(path)
	if err := store.writeGenesis(); err != nil {
		lock.Close()
		return nil, err
	}
	if len(opts.Quotas) > 0 {
		if err := store.InstallQuotaPolicy(opts.Quotas); err != nil {
			lock.Close()
			return nil, err
		}
	}
	if err := fsyncDir(path); err != nil {
		lock.Close()
		return nil, err
	}
	return store, nil
}

// Open opens an existing store. Read-only opens use the generation-addressed
// bounded replay and never enumerate the commit directory; a writable open
// enumerates it once so next_generation cannot reuse a rejected generation.
func Open(path string, mode OpenMode) (*Store, error) {
	return openWithStrategy(path, mode, false, DefaultOptions())
}

// OpenFullScanForBench opens through the original full commit-directory scan so
// the bounded fast path's cost can be measured against it. It is not used by
// any production path.
func OpenFullScanForBench(path string, mode OpenMode) (*Store, error) {
	return openWithStrategy(path, mode, true, DefaultOptions())
}

func openWithStrategy(path string, mode OpenMode, fullScan bool, opts Options) (*Store, error) {
	if err := validateOptions(opts); err != nil {
		return nil, err
	}
	format, err := os.ReadFile(filepath.Join(path, "FORMAT"))
	if err != nil {
		return nil, werr.Wrap(werr.Corrupt, err, "cannot read FORMAT")
	}
	if string(format) != model.FormatContents {
		return nil, werr.Newf(werr.Unsupported, "FORMAT is %q, expected %q", string(format), model.FormatContents)
	}
	store := &Store{root: path, mode: mode, options: opts}
	if err := store.buildPlanes(); err != nil {
		return nil, err
	}
	if mode == ReadWrite {
		if err := requireWritablePlanes(store.blobs.Capabilities(), store.commits.Capabilities()); err != nil {
			return nil, err
		}
	}
	var lock *os.File
	if mode == ReadWrite {
		lockPath := filepath.Join(path, "LOCK")
		lock, err = os.OpenFile(lockPath, os.O_RDWR, 0o644)
		if err != nil {
			return nil, werr.Wrap(werr.Io, err, "cannot open LOCK")
		}
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			lock.Close()
			return nil, werr.Wrap(werr.Busy, err, "store is locked by another writer")
		}
		if err := ensureCommitLayout(path); err != nil {
			lock.Close()
			return nil, err
		}
		if err := ensureBlobLayout(store.blobRoot); err != nil {
			lock.Close()
			return nil, err
		}
		if err := cleanStaleTmp(path, DefaultGCGraceSecs); err != nil {
			lock.Close()
			return nil, err
		}
		if err := cleanStaleTmp(store.blobRoot, DefaultGCGraceSecs); err != nil {
			lock.Close()
			return nil, err
		}
		if err := store.probePlanes(); err != nil {
			lock.Close()
			return nil, err
		}
	}

	var recovery *Recovery
	switch {
	case fullScan:
		recovery, err = recoverFullScan(path, store.blobs)
	case mode == ReadWrite:
		recovery, err = recoverForWrite(path, store.blobs)
	default:
		recovery, err = recoverWithStrategy(path, store.blobs, replayBounded, true)
	}
	if err != nil {
		if lock != nil {
			lock.Close()
		}
		return nil, err
	}
	base := recovery.Generation
	if recovery.HighestFileGeneration > base {
		base = recovery.HighestFileGeneration
	}
	if base == ^uint64(0) {
		if lock != nil {
			lock.Close()
		}
		return nil, werr.Newf(werr.LimitExceeded, "generation counter overflow")
	}
	store.lock = lock
	store.state = recovery.State
	store.head = recovery.Head
	store.generation = recovery.Generation
	store.nextGeneration = base + 1
	store.rejected = recovery.Rejected
	store.notes = recovery.Notes
	store.pins = make(map[model.Hash32]uint64)
	store.contentPins = make(map[model.Hash32]uint64)
	store.quota = newQuotaState()
	store.blobIndex = map[model.Hash32]uint64{}
	store.access = loadAccessCounts(path)
	store.loadQuotaRecord()
	return store, nil
}

// OpenWithOptions opens with explicit runtime options.
func OpenWithOptions(path string, mode OpenMode, opts Options) (*Store, error) {
	if err := validateOptions(opts); err != nil {
		return nil, err
	}
	store, err := openWithStrategy(path, mode, false, opts)
	if err != nil {
		return nil, err
	}
	if len(opts.Quotas) > 0 {
		if err := store.InstallQuotaPolicy(opts.Quotas); err != nil {
			store.Close()
			return nil, err
		}
	}
	store.options = opts
	return store, nil
}

// SetOptions replaces runtime options.
func (s *Store) SetOptions(opts Options) error {
	if err := validateOptions(opts); err != nil {
		return err
	}
	s.options = opts
	return nil
}

// Options returns the runtime options.
func (s *Store) Options() Options { return s.options }

// Mode returns the open mode.
func (s *Store) Mode() OpenMode { return s.mode }

// Root returns the store directory.
func (s *Store) Root() string { return s.root }

// BlobRoot returns the immutable blob namespace root.
func (s *Store) BlobRoot() string { return s.blobRoot }

// Planes reports the routed planes and their probe evidence.
func (s *Store) Planes() PlaneReport { return s.planeReport }

// PackStats reports this handle's pack-plane counters when packing is enabled.
func (s *Store) PackStats() (PackStats, bool) {
	if s.packed == nil {
		return PackStats{}, false
	}
	return s.packed.PackStats(), true
}

// PackCatalogStats reports what the on-disk pack catalog names. Unlike
// PackStats it is meaningful on a freshly opened read-only handle.
func (s *Store) PackCatalogStats() (PackStats, bool, error) {
	if s.packed == nil {
		return PackStats{}, false, nil
	}
	stats, err := s.packed.PackCatalogStats()
	return stats, true, err
}

// buildPlanes constructs the two planes from the open options.
func (s *Store) buildPlanes() error {
	blobKind := s.options.BlobBackend
	if blobKind == "" {
		if s.options.CommitBackend == PlaneObject {
			blobKind = PlaneObject
		} else {
			blobKind = PlaneLocal
		}
	}
	commitKind := s.options.CommitBackend
	if commitKind == "" {
		commitKind = PlaneLocal
	}
	blobRoot := s.options.BlobRoot
	if blobRoot == "" {
		blobRoot = s.root
	}
	blobs, err := newFlatBlobPlane(blobRoot, blobKind)
	if err != nil {
		return err
	}
	commits, err := newCommitPlane(s.root, commitKind)
	if err != nil {
		return err
	}
	var access BlobAccess = blobs
	var packed *PackedBlobPlane
	if s.options.Packing {
		packOptions := s.options.PackOptions
		if packOptions == (PackOptions{}) {
			packOptions = DefaultPackOptions()
		}
		packed, err = NewPackedBlobPlane(blobs, commits, packOptions)
		if err != nil {
			return err
		}
		access = packed
	}
	s.blobs = access
	s.commits = commits
	s.probeFlat = blobs
	s.packed = packed
	s.blobRoot = blobRoot
	s.planeReport = PlaneReport{
		Blobs:      access.Capabilities(),
		Commits:    commits.Capabilities(),
		BlobRoot:   blobRoot,
		CommitRoot: s.root,
		Packing:    s.options.Packing,
	}
	return nil
}

// probePlanes proves both capabilities on a writable open. A probe may only
// refute a declared capability, never upgrade one; a failure refuses the open.
func (s *Store) probePlanes() error {
	flat := s.probeFlat
	if flat == nil {
		return werr.Newf(werr.Unsupported, "blob plane has no capability probe")
	}
	blobProbe, err := flat.probe()
	if err != nil {
		return err
	}
	commitProbe, err := s.commits.probe()
	if err != nil {
		return err
	}
	s.planeReport.BlobProbe = &blobProbe
	s.planeReport.CommitProbe = &commitProbe
	return requireWritablePlanes(s.blobs.Capabilities(), s.commits.Capabilities())
}

// Generation returns the published generation.
func (s *Store) Generation() uint64 { return s.generation }

// SnapshotRoot returns the current commit root hash.
func (s *Store) SnapshotRoot() model.Hash32 { return s.head }

// Head is an alias for SnapshotRoot.
func (s *Store) Head() model.Hash32 { return s.head }

// RejectedGenerations returns generations rejected at open.
func (s *Store) RejectedGenerations() []uint64 { return append([]uint64(nil), s.rejected...) }

// RecoveryNotes returns non-fatal recovery notes.
func (s *Store) RecoveryNotes() []string { return append([]string(nil), s.notes...) }

// CurrentState returns the replayed state. Callers must not mutate it; use
// Clone when a private snapshot is needed.
func (s *Store) CurrentState() *model.State { return s.state }

// Close releases the writer lock. It does not fsync anything: every mutation
// was durably published before its call returned.
func (s *Store) Close() error {
	if s.mode == ReadWrite && s.access != nil {
		_ = s.access.flush(s.root)
	}
	if s.lock != nil {
		err := syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
		closeErr := s.lock.Close()
		s.lock = nil
		if err != nil {
			return werr.Wrap(werr.Io, err, "cannot unlock LOCK")
		}
		return closeErr
	}
	return nil
}

func (s *Store) maxVisibleGeneration() (uint64, error) {
	view, err := ReadSuperblock(s.root)
	if err != nil {
		return 0, err
	}
	var max uint64
	for index := 0; index < 2; index++ {
		if view.Valid[index] && view.Slots[index].Generation > max {
			max = view.Slots[index].Generation
		}
	}
	return max, nil
}

// LineageEntry is one commit on the published parent chain (newest first).
type LineageEntry struct {
	Commit      model.Hash32
	Generation  uint64
	TimestampNS int64
}

// StateAt rebuilds the state at a commit on the published parent chain.
func (s *Store) StateAt(commit model.Hash32) (*model.State, error) {
	if commit == s.head {
		return s.state.Clone(), nil
	}
	published, err := s.isPublishedAncestor(commit)
	if err != nil {
		return nil, err
	}
	if !published {
		return nil, werr.Newf(werr.NotFound, "commit is not on the published parent chain")
	}
	maxVisible, err := s.maxVisibleGeneration()
	if err != nil {
		return nil, err
	}
	state, _, err := loadStateAt(s.blobs, s.root, commit, maxVisible, false)
	if err != nil {
		return nil, err
	}
	return state, nil
}

func (s *Store) isPublishedAncestor(target model.Hash32) (bool, error) {
	maxVisible, err := s.maxVisibleGeneration()
	if err != nil {
		return false, err
	}
	index, err := CommitIndex(s.root, maxVisible)
	if err != nil {
		return false, err
	}
	cursor := s.head
	seen := make(map[model.Hash32]bool)
	for {
		if cursor == target {
			return true, nil
		}
		if seen[cursor] {
			return false, nil
		}
		seen[cursor] = true
		loaded, ok := index[cursor]
		if !ok || loaded.Commit.Parent == nil {
			return false, nil
		}
		cursor = *loaded.Commit.Parent
	}
}

// CommitLineage returns the published ancestry of base, newest first, down to
// the genesis commit. Every entry was reachable from the recovered head.
func (s *Store) CommitLineage(base model.Hash32) ([]LineageEntry, error) {
	maxVisible, err := s.maxVisibleGeneration()
	if err != nil {
		return nil, err
	}
	index, err := CommitIndex(s.root, maxVisible)
	if err != nil {
		return nil, err
	}
	out := make([]LineageEntry, 0)
	cursor := base
	seen := make(map[model.Hash32]bool)
	for {
		if seen[cursor] {
			return nil, werr.Newf(werr.Corrupt, "commit parent chain contains a cycle")
		}
		seen[cursor] = true
		loaded, ok := index[cursor]
		if !ok {
			return nil, werr.Newf(werr.NotFound, "commit is not present on the store's parent chain")
		}
		out = append(out, LineageEntry{
			Commit: cursor, Generation: loaded.Generation, TimestampNS: loaded.Commit.TimestampNS,
		})
		if loaded.Commit.Parent == nil {
			break
		}
		cursor = *loaded.Commit.Parent
	}
	return out, nil
}

// CommitAtOrBefore returns the newest commit in base's lineage whose timestamp
// is <= atNS. Ties on timestamp break toward the higher generation. A nil
// result means the requested time predates the lineage; callers must fail
// closed rather than substitute a different state.
func (s *Store) CommitAtOrBefore(base model.Hash32, atNS int64) (*LineageEntry, error) {
	lineage, err := s.CommitLineage(base)
	if err != nil {
		return nil, err
	}
	var best *LineageEntry
	for i := range lineage {
		entry := lineage[i]
		if entry.TimestampNS > atNS {
			continue
		}
		if best == nil || entry.TimestampNS > best.TimestampNS ||
			(entry.TimestampNS == best.TimestampNS && entry.Generation > best.Generation) {
			copy := entry
			best = &copy
		}
	}
	return best, nil
}

// ---- reads ---------------------------------------------------------------

// Lookup returns the target of (parent,name).
func (s *Store) Lookup(parent model.Hash32, name []byte) (model.Hash32, error) {
	return s.state.Lookup(parent, name)
}

// ListDir lists a directory sorted by unsigned byte name.
func (s *Store) ListDir(parent model.Hash32) ([]DirEntry, error) {
	entries, err := s.state.ListDir(parent)
	if err != nil {
		return nil, err
	}
	out := make([]DirEntry, 0, len(entries))
	for _, entry := range entries {
		out = append(out, DirEntry{Name: entry.Name, EntryID: entry.ID, Target: entry.Target})
	}
	return out, nil
}

// ObjectMeta returns an object record.
func (s *Store) ObjectMeta(id model.Hash32) (model.ObjectRecord, error) {
	record, ok := s.state.Objects[id]
	if !ok {
		return model.ObjectRecord{}, werr.Newf(werr.NotFound, "no such object")
	}
	return record.Clone(), nil
}

// ResolvePath resolves a `/`-separated path against the current state.
func (s *Store) ResolvePath(path string) (model.Hash32, error) {
	return resolveIn(s.state, path)
}

// ResolvePathAt resolves a path against a pinned commit.
func (s *Store) ResolvePathAt(snapshot *model.Hash32, path string) (model.Hash32, error) {
	if snapshot == nil {
		return s.ResolvePath(path)
	}
	state, err := s.StateAt(*snapshot)
	if err != nil {
		return model.Hash32{}, err
	}
	return resolveIn(state, path)
}

// ResolveComponents resolves pre-split byte components.
func (s *Store) ResolveComponents(components [][]byte) (model.Hash32, error) {
	return resolveComponentsIn(s.state, components)
}

func resolveIn(state *model.State, path string) (model.Hash32, error) {
	components := make([][]byte, 0)
	for _, part := range bytes.Split([]byte(path), []byte{'/'}) {
		if len(part) == 0 {
			continue
		}
		if string(part) == "." {
			continue
		}
		if string(part) == ".." {
			return model.Hash32{}, werr.Newf(werr.InvalidName, "`..` is not accepted at the store layer")
		}
		components = append(components, part)
	}
	return resolveComponentsIn(state, components)
}

func resolveComponentsIn(state *model.State, components [][]byte) (model.Hash32, error) {
	current := model.RootID
	for _, component := range components {
		if err := model.ValidateNameBytes(component); err != nil {
			return model.Hash32{}, err
		}
		object, ok := state.Objects[current]
		if !ok {
			return model.Hash32{}, werr.Newf(werr.NotFound, "no such parent object")
		}
		if object.Kind != model.KindDir {
			return model.Hash32{}, werr.Newf(werr.NotDir, "path component is not a directory")
		}
		target, err := state.Lookup(current, component)
		if err != nil {
			return model.Hash32{}, err
		}
		current = target
	}
	return current, nil
}

// ReadObject reads a complete object, verifying every chunk and the
// whole-content hash for files.
func (s *Store) ReadObject(id model.Hash32) ([]byte, error) {
	data, err := s.readObjectState(s.state, id)
	if err == nil {
		s.noteObjectRead(id)
	}
	return data, err
}

// readObjectUncounted reads without touching access counters (internal work).
func (s *Store) readObjectUncounted(id model.Hash32) ([]byte, error) {
	return s.readObjectState(s.state, id)
}

// ReadObjectAt reads an object in a pinned snapshot state.
func (s *Store) ReadObjectAt(snapshot *model.Hash32, id model.Hash32) ([]byte, error) {
	if snapshot == nil {
		return s.ReadObject(id)
	}
	state, err := s.StateAt(*snapshot)
	if err != nil {
		return nil, err
	}
	data, err := s.readObjectState(state, id)
	if err == nil {
		s.noteObjectRead(id)
	}
	return data, err
}

func (s *Store) readObjectState(state *model.State, id model.Hash32) ([]byte, error) {
	record, ok := state.Objects[id]
	if !ok {
		return nil, werr.Newf(werr.NotFound, "no such object")
	}
	switch record.Kind {
	case model.KindDir:
		return nil, werr.Newf(werr.IsDir, "object is a directory")
	case model.KindSymlink:
		target, ok := record.SymlinkTarget()
		if !ok {
			return nil, werr.Newf(werr.Corrupt, "symlink object has no target attribute")
		}
		return append([]byte(nil), target...), nil
	default:
		manifest, err := readManifest(s.blobs, record.Content)
		if err != nil {
			return nil, err
		}
		if manifest.Size != record.Size {
			return nil, werr.Newf(werr.Corrupt, "object size disagrees with manifest")
		}
		contentRoot := record.Content
		return readManifestRange(s.blobs, &contentRoot, manifest, 0, manifest.Size, true)
	}
}

// ReadRange reads a byte range from a file object.
func (s *Store) ReadRange(id model.Hash32, offset, length uint64) ([]byte, error) {
	record, ok := s.state.Objects[id]
	if !ok {
		return nil, werr.Newf(werr.NotFound, "no such object")
	}
	if record.Kind != model.KindFile {
		return nil, werr.Newf(werr.InvalidArgument, "read_range requires a file object")
	}
	manifest, err := readManifest(s.blobs, record.Content)
	if err != nil {
		return nil, err
	}
	if manifest.Size != record.Size {
		return nil, werr.Newf(werr.Corrupt, "object size disagrees with manifest")
	}
	contentRoot := record.Content
	data, err := readManifestRange(s.blobs, &contentRoot, manifest, offset, length, false)
	if err == nil {
		s.noteObjectRead(id)
	}
	return data, err
}

// ReadContent reads a byte range directly from a content root (manifest id).
// It does not consult live object state, so it is safe for snapshot
// materialization.
func (s *Store) ReadContent(contentRoot model.Hash32, offset, length uint64) ([]byte, error) {
	manifest, err := readManifest(s.blobs, contentRoot)
	if err != nil {
		return nil, err
	}
	whole := offset == 0 && length >= manifest.Size
	return readManifestRange(s.blobs, &contentRoot, manifest, offset, length, whole)
}

// NLink returns the POSIX link count for an object.
func (s *Store) NLink(id model.Hash32) (uint64, error) {
	if _, ok := s.state.Objects[id]; !ok {
		return 0, werr.Newf(werr.NotFound, "no such object")
	}
	return s.state.NLink(id), nil
}

// StatFS returns counters derived from replayed state.
func (s *Store) StatFS() StatFS { return StatFSAt(s.state) }

// StatFSAt returns counters for an explicit state.
func StatFSAt(state *model.State) StatFS {
	const block = 4096
	var contentBytes uint64
	for _, record := range state.Objects {
		contentBytes = saturatingAdd(contentBytes, record.Size)
	}
	blocks := (contentBytes+block-1)/block + uint64(len(state.Objects))
	return StatFS{
		BlockSize: block, Blocks: blocks, BlocksFree: 0, BlocksAvailable: 0,
		Files: uint64(len(state.Objects)), FilesFree: 0, MaxNameLen: model.MaxNameBytes,
	}
}

func saturatingAdd(a, b uint64) uint64 {
	if a > ^uint64(0)-b {
		return ^uint64(0)
	}
	return a + b
}

// ---- selector resolution -------------------------------------------------

// LookupSnapshot resolves a snapshot name or hex commit hash.
func (s *Store) LookupSnapshot(nameOrHash string) (model.Hash32, error) {
	if h, err := parseHashHex(nameOrHash); err == nil {
		return h, nil
	}
	if h, ok := s.state.Snapshots[nameOrHash]; ok {
		return h, nil
	}
	return model.Hash32{}, werr.Newf(werr.NotFound, "no snapshot named `%s`", nameOrHash)
}

func parseHashHex(s string) (model.Hash32, error) {
	var h model.Hash32
	if len(s) != 64 {
		return h, werr.Newf(werr.InvalidArgument, "hash hex must be 64 characters")
	}
	for i := 0; i < 32; i++ {
		hi, ok1 := nibble(s[i*2])
		lo, ok2 := nibble(s[i*2+1])
		if !ok1 || !ok2 {
			return h, werr.Newf(werr.InvalidArgument, "invalid hex digit")
		}
		h[i] = hi<<4 | lo
	}
	return h, nil
}

func nibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

// Resolve evaluates a selector against the authorized universe of a snapshot.
func (s *Store) Resolve(sel *selector.Selector, snapshot *model.Hash32, principal auth.Principal, lim limits.Limits) (*resolver.Resolution, error) {
	snapshotID := s.head
	state := s.state
	if snapshot != nil && *snapshot != s.head {
		pinned, err := s.StateAt(*snapshot)
		if err != nil {
			return nil, err
		}
		snapshotID = *snapshot
		state = pinned
	}
	return resolver.ResolveState(sel, snapshotID, state, principal, lim)
}

// ResolveState evaluates a selector against an explicit state.
func ResolveState(sel *selector.Selector, snapshotID model.Hash32, state *model.State, principal auth.Principal, lim limits.Limits) (*resolver.Resolution, error) {
	return resolver.ResolveState(sel, snapshotID, state, principal, lim)
}

// RequireOne resolves exactly one object.
func (s *Store) RequireOne(sel *selector.Selector, snapshot *model.Hash32, principal auth.Principal, lim limits.Limits) (resolver.ResolvedRef, error) {
	snapshotID := s.head
	state := s.state
	if snapshot != nil && *snapshot != s.head {
		pinned, err := s.StateAt(*snapshot)
		if err != nil {
			return resolver.ResolvedRef{}, err
		}
		snapshotID = *snapshot
		state = pinned
	}
	return resolver.RequireOne(sel, snapshotID, state, principal, lim)
}

// ---- lifecycle internals -------------------------------------------------

func (s *Store) nowNS() int64 {
	if s.options.FixedTimestampNS != nil {
		return *s.options.FixedTimestampNS
	}
	return time.Now().UnixNano()
}

// ClockNowNS returns the store clock in UTC nanoseconds. Capability expiry is
// enforced against this clock.
func (s *Store) ClockNowNS() int64 { return s.nowNS() }

func (s *Store) requireWritable() error {
	if s.mode != ReadWrite {
		return werr.Newf(werr.ReadOnly, "store is opened read-only; mutation refused")
	}
	return nil
}

func (s *Store) requireDir(id model.Hash32) error {
	object, ok := s.state.Objects[id]
	if !ok {
		return werr.Newf(werr.NotFound, "no such parent object")
	}
	if object.Kind != model.KindDir {
		return werr.Newf(werr.NotDir, "parent object is not a directory")
	}
	return nil
}

func (s *Store) requireFreeName(parent model.Hash32, name []byte) error {
	id, err := model.DeriveEntryID(parent, name)
	if err != nil {
		return err
	}
	if _, ok := s.state.Entries[id]; ok {
		return werr.Newf(werr.Exists, "directory entry already exists")
	}
	return nil
}

func checkMode(mode uint64) error {
	if mode > 0o7777 {
		return werr.Newf(werr.InvalidArgument, "mode must fit POSIX permission bits (0..=0o7777)")
	}
	return nil
}

func randomSeed() ([]byte, error) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, werr.Wrap(werr.Io, err, "cannot read CSPRNG")
	}
	return seed, nil
}

func (s *Store) writeGenesis() error {
	mtime := s.nowNS()
	content := model.ContentHash(nil)
	version, err := model.DeriveVersionID(model.RootID, content, 0, mtime, nil)
	if err != nil {
		return err
	}
	root := model.ObjectRecord{
		ID: model.RootID, Kind: model.KindDir, Mode: 0o755,
		UID: s.options.OwnerUID, GID: s.options.OwnerGID, MtimeNS: mtime,
		Version: version, Content: content, Size: 0, Attrs: map[string]wcb.Value{},
	}
	ops := []model.Op{
		model.PutObjectOp{Record: root},
		model.SetTipOp{Object: model.RootID, Version: version},
	}
	state := model.NewState()
	if err := state.ApplyOps(ops); err != nil {
		return err
	}
	state.Generation = 1
	commit := model.Commit{
		Generation: 1, Parent: nil, TimestampNS: mtime, Ops: ops, Checkpoint: nil,
	}
	if _, err := s.publishCommit(commit); err != nil {
		return err
	}
	s.state = state
	hash, err := commit.ID()
	if err != nil {
		return err
	}
	s.head = hash
	s.generation = 1
	s.nextGeneration = 2
	return nil
}

func (s *Store) commitOps(ops []model.Op, forceCheckpoint bool) (model.Hash32, error) {
	if err := s.requireWritable(); err != nil {
		return model.Hash32{}, err
	}
	if s.groupDepth > 0 {
		// Buffer instead of publish. ApplyOps is atomic for this batch, and the
		// journal keeps the pre-group value of every key so AbortGroup can
		// restore it exactly.
		s.journalOps(ops)
		if forceCheckpoint {
			s.groupForceCheckpoint = true
		}
		if err := s.state.ApplyOps(ops); err != nil {
			return model.Hash32{}, err
		}
		s.pendingOps = append(s.pendingOps, ops...)
		// Inside a group no commit exists yet; the pre-group head is returned.
		return s.head, nil
	}
	newGeneration := s.nextGeneration
	timestamp := s.nowNS()
	nextState := s.state.Clone()
	if err := nextState.ApplyOps(ops); err != nil {
		return model.Hash32{}, err
	}
	nextState.Generation = newGeneration

	// Write-budget admission happens before any commit bytes exist. A denial
	// returns BudgetExceeded and leaves generation, head, and state untouched.
	quotaPlan, err := s.quotaPreflight(ops, quotaPreMap(s.state, ops))
	if err != nil {
		return model.Hash32{}, err
	}
	if quotaPlan != nil {
		// The usage snapshot travels in the same commit; no second durable write.
		ops = append(ops, quotaUsageOpFromMap(quotaPlan.usageAfter))
	}

	interval := s.options.CheckpointInterval
	wantsCheckpoint := forceCheckpoint || (interval > 0 && newGeneration%interval == 0)
	var checkpoint *model.Hash32
	if wantsCheckpoint {
		encoded, err := model.EncodeState(nextState, newGeneration)
		if err != nil {
			return model.Hash32{}, err
		}
		id, err := s.storeBlob(BlobManifest, model.DomainManifest, encoded)
		if err != nil {
			return model.Hash32{}, err
		}
		checkpoint = &id
	}

	// Every content blob and checkpoint manifest is durable here.
	crashPoint("after_objects")

	commit := model.Commit{
		Generation: newGeneration, Parent: hashPtr(s.head), TimestampNS: timestamp,
		Ops: ops, Checkpoint: checkpoint,
	}
	hash, err := s.publishCommit(commit)
	if err != nil {
		return model.Hash32{}, err
	}
	s.state = nextState
	s.head = hash
	s.generation = newGeneration
	if newGeneration == ^uint64(0) {
		return model.Hash32{}, werr.Newf(werr.LimitExceeded, "generation counter overflow")
	}
	s.nextGeneration = newGeneration + 1
	if quotaPlan != nil {
		s.recordQuotaAfterCommit(quotaPlan)
	}
	return hash, nil
}

func hashPtr(h model.Hash32) *model.Hash32 {
	copy := h
	return &copy
}

// publishCommit writes the commit file, fsyncs it and its directory, publishes
// the superblock slot, then fsyncs the store root.
func (s *Store) publishCommit(commit model.Commit) (model.Hash32, error) {
	// Every blob the commit names must be durable and visible before the
	// commit record is published. A packed plane buffers the open pack.
	if err := s.blobs.Flush(); err != nil {
		return model.Hash32{}, err
	}
	wcbBytes, err := commit.Encode()
	if err != nil {
		return model.Hash32{}, err
	}
	hash := model.CommitIDBytes(wcbBytes)
	fileBytes := EncodeCommitFile(wcbBytes)
	path := CommitPath(s.root, commit.Generation)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return model.Hash32{}, werr.Wrap(werr.Corrupt, err, "cannot create commit file %s", path)
	}
	if _, err := file.Write(fileBytes); err != nil {
		file.Close()
		return model.Hash32{}, werr.Wrap(werr.Io, err, "cannot write commit file %s", path)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return model.Hash32{}, werr.Wrap(werr.Io, err, "cannot fsync commit file %s", path)
	}
	if err := file.Close(); err != nil {
		return model.Hash32{}, werr.Wrap(werr.Io, err, "cannot close commit file %s", path)
	}
	if err := fsyncDir(filepath.Join(s.root, "commits")); err != nil {
		return model.Hash32{}, err
	}

	crashPoint("after_commit_file")

	slot := SuperblockSlot{
		Generation: commit.Generation, Commit: hash,
		CommitLen: uint64(len(wcbBytes)), TimestampNS: commit.TimestampNS,
	}
	superblockPath := filepath.Join(s.root, "superblock")
	superblock, err := os.OpenFile(superblockPath, os.O_RDWR, 0o644)
	if err != nil {
		return model.Hash32{}, werr.Wrap(werr.Io, err, "cannot open superblock")
	}
	offset := int64(commit.Generation%2) * int64(model.SlotBytes)
	if _, err := superblock.WriteAt(slot.Encode(), offset); err != nil {
		superblock.Close()
		return model.Hash32{}, werr.Wrap(werr.Io, err, "cannot write superblock slot")
	}
	if err := superblock.Sync(); err != nil {
		superblock.Close()
		return model.Hash32{}, werr.Wrap(werr.Io, err, "cannot fsync superblock")
	}
	if err := superblock.Close(); err != nil {
		return model.Hash32{}, werr.Wrap(werr.Io, err, "cannot close superblock")
	}

	crashPoint("after_superblock_write")

	if err := fsyncDir(s.root); err != nil {
		return model.Hash32{}, err
	}
	return hash, nil
}

func (s *Store) storeFileContent(data []byte) (manifestID model.Hash32, contentHash model.Hash32, size uint64, err error) {
	return s.storeFileContentWithBase(data, nil)
}

// storeFileContentWithBase stores a complete buffer. With `codec-auto` and a
// buffer at or above CodecMinBytes it may write a v2 codec representation; a
// frame that is not smaller than the plaintext (or cannot be produced) falls
// back to a v2 `kind:"raw"` manifest. The raw policy writes the frozen v1
// manifest byte for byte.
func (s *Store) storeFileContentWithBase(data []byte, base *deltaBase) (manifestID model.Hash32, contentHash model.Hash32, size uint64, err error) {
	size = uint64(len(data))
	if size > MaxFileBytes {
		return model.Hash32{}, model.Hash32{}, 0, werr.Newf(werr.LimitExceeded, "file exceeds the %d-byte v1 bound", MaxFileBytes)
	}
	chunkSize := s.options.ChunkSize
	if chunkSize == 0 || chunkSize > model.MaxChunkSize {
		return model.Hash32{}, model.Hash32{}, 0, werr.Newf(werr.InvalidArgument, "chunk size is out of range")
	}
	if s.options.ContentIdentity == model.ContentIdentityMerkleV1 {
		if s.options.Representation == RepresentationModeCodecAuto {
			return model.Hash32{}, model.Hash32{}, 0, werr.Newf(werr.InvalidArgument, "content_identity `merkle` cannot be combined with codec-auto")
		}
		manifest, err := s.buildMerkleManifest(data, chunkSize)
		if err != nil {
			return model.Hash32{}, model.Hash32{}, 0, err
		}
		return s.storeManifest(manifest)
	}
	contentHash = model.ContentHash(data)
	codecAuto := s.options.Representation == RepresentationModeCodecAuto

	if codecAuto && size >= s.options.CodecMinBytes {
		representation, frameBytes, err := s.tryCodecRepresentation(data, chunkSize, base)
		if err != nil {
			return model.Hash32{}, model.Hash32{}, 0, err
		}
		if representation != nil {
			frameID, err := s.storeBlob(BlobManifest, model.DomainManifest, frameBytes)
			if err != nil {
				return model.Hash32{}, model.Hash32{}, 0, err
			}
			representation.Frame = &frameID
			manifest := model.Manifest{
				Size: size, ChunkSize: chunkSize, ContentHash: contentHash,
				Representation: representation,
			}
			return s.storeManifest(manifest)
		}
	}

	manifest, err := s.buildRawManifest(data, chunkSize, contentHash)
	if err != nil {
		return model.Hash32{}, model.Hash32{}, 0, err
	}
	if codecAuto {
		// CodecAuto always writes v2, even when it falls back to the raw chunk
		// layout.
		manifest.Representation = &model.Representation{
			Kind: model.RepresentationRaw, Frame: nil, Dependencies: nil,
			Strategy: model.StrategyRaw, DecodedSize: size,
		}
	}
	return s.storeManifest(manifest)
}

// buildMerkleManifest writes the chunk blobs for a raw layout and returns a
// `weft.manifest.v3` value whose ContentHash is the Merkle root. No whole-file
// digest is computed.
func (s *Store) buildMerkleManifest(data []byte, chunkSize uint64) (model.Manifest, error) {
	chunks, err := s.writeChunks(data, chunkSize)
	if err != nil {
		return model.Manifest{}, err
	}
	return model.Manifest{
		Size: uint64(len(data)), ChunkSize: chunkSize, Chunks: chunks,
		ContentHash: model.MerkleRootChunks(chunks),
		Identity:    model.ContentIdentityMerkleV1,
	}, nil
}

// buildRawManifest writes the chunk blobs for a raw layout and returns a
// v1-shaped manifest value (no representation).
func (s *Store) buildRawManifest(data []byte, chunkSize uint64, contentHash model.Hash32) (model.Manifest, error) {
	chunks, err := s.writeChunks(data, chunkSize)
	if err != nil {
		return model.Manifest{}, err
	}
	return model.Manifest{Size: uint64(len(data)), ChunkSize: chunkSize, Chunks: chunks, ContentHash: contentHash}, nil
}

func (s *Store) writeChunks(data []byte, chunkSize uint64) ([]model.ChunkRef, error) {
	chunks := make([]model.ChunkRef, 0)
	step := int(chunkSize)
	for start := 0; start < len(data); start += step {
		end := start + step
		if end > len(data) {
			end = len(data)
		}
		chunk := data[start:end]
		if uint64(len(chunks)) >= model.MaxChunksPerFile {
			return nil, werr.Newf(werr.LimitExceeded, "manifest exceeds the %d-chunk bound", model.MaxChunksPerFile)
		}
		hash, err := s.storeBlob(BlobObject, model.DomainChunk, chunk)
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, model.ChunkRef{Hash: hash, Len: uint64(len(chunk))})
	}
	return chunks, nil
}

func (s *Store) storeManifest(manifest model.Manifest) (model.Hash32, model.Hash32, uint64, error) {
	size := manifest.Size
	contentHash := manifest.ContentHash
	wcbBytes, err := manifest.Encode()
	if err != nil {
		return model.Hash32{}, model.Hash32{}, 0, err
	}
	if uint64(len(wcbBytes)) > model.MaxChunkSize*64 {
		return model.Hash32{}, model.Hash32{}, 0, werr.Newf(werr.LimitExceeded, "manifest encoding is implausibly large")
	}
	manifestID, err := s.storeBlob(BlobManifest, model.DomainManifest, wcbBytes)
	if err != nil {
		return model.Hash32{}, model.Hash32{}, 0, err
	}
	return manifestID, contentHash, size, nil
}

// storeBlob writes a content-addressed blob through the routed blob plane.
// An existing blob is verified, never overwritten. Publication (fsync + rename
// or link + directory fsync) belongs to the plane.
func (s *Store) storeBlob(kind BlobKind, domain string, data []byte) (model.Hash32, error) {
	hash := hashOf(domain, data)
	if existing, err := s.blobs.Get(kind, hash); err == nil {
		if hashOf(domain, existing) != hash {
			return model.Hash32{}, werr.Newf(werr.Corrupt, "existing blob %s does not match its name", blobRelPath(kind, hash))
		}
		return hash, nil
	} else if typed, ok := err.(*werr.Error); !ok || typed.Kind != werr.NotFound {
		return model.Hash32{}, err
	}
	if err := s.blobs.Put(kind, hash, data); err != nil {
		return model.Hash32{}, err
	}
	return hash, nil
}

func hashOf(domain string, data []byte) model.Hash32 {
	return hash.Domain(domain, data)
}

func (s *Store) writeSnapshotPointer(name string, commit model.Hash32) error {
	dir := filepath.Join(s.root, "refs", "snapshots")
	if err := makeDir(dir); err != nil {
		return err
	}
	path := filepath.Join(dir, name)
	tmp := filepath.Join(s.root, "tmp", "snap-"+itoa(uint64(os.Getpid()))+"-"+name+"-"+itoa(tmpCounter.Add(1)))
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return werr.Wrap(werr.Io, err, "cannot create snapshot pointer")
	}
	if _, err := file.Write([]byte(commit.Hex() + "\n")); err != nil {
		file.Close()
		_ = os.Remove(tmp)
		return werr.Wrap(werr.Io, err, "cannot write snapshot pointer")
	}
	if err := file.Sync(); err != nil {
		file.Close()
		_ = os.Remove(tmp)
		return werr.Wrap(werr.Io, err, "cannot fsync snapshot pointer")
	}
	file.Close()
	if _, err := os.Stat(path); err == nil {
		_ = os.Remove(tmp)
		return werr.Newf(werr.Exists, "snapshot pointer already exists")
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return werr.Wrap(werr.Io, err, "cannot publish snapshot pointer")
	}
	return fsyncDir(dir)
}

// ---- open-handle pins ----------------------------------------------------

// PinObject pins an object (open handle). A pinned record survives unlink and
// rmdir until the last pin is released.
func (s *Store) PinObject(id model.Hash32) (uint64, error) {
	if _, ok := s.state.Objects[id]; !ok {
		return 0, werr.Newf(werr.NotFound, "no such object")
	}
	count := s.pins[id]
	if count == ^uint64(0) {
		return 0, werr.Newf(werr.LimitExceeded, "pin count overflow")
	}
	s.pins[id] = count + 1
	return count + 1, nil
}

// UnpinObject releases an object pin. When the count reaches zero and the
// object has no remaining directory entry, its record is deleted in one
// commit (durable cleanup, not a GC sweep).
func (s *Store) UnpinObject(id model.Hash32) (uint64, error) {
	count := uint64(0)
	if current, ok := s.pins[id]; ok {
		if current > 0 {
			count = current - 1
		}
		if count == 0 {
			delete(s.pins, id)
		} else {
			s.pins[id] = count
		}
	}
	if count == 0 && s.mode == ReadWrite {
		hasEntry := false
		hasChildren := false
		for _, entry := range s.state.Entries {
			if entry.Target == id {
				hasEntry = true
			}
			if entry.Parent == id {
				hasChildren = true
			}
		}
		_, exists := s.state.Objects[id]
		if exists && !hasEntry && !hasChildren && id != model.RootID {
			if _, err := s.commitOps([]model.Op{model.DeleteObjectOp{ID: id}}, false); err != nil {
				return count, err
			}
		}
	}
	return count, nil
}

// ObjectPinCount returns the current pin count.
func (s *Store) ObjectPinCount(id model.Hash32) uint64 { return s.pins[id] }

// PinContent pins a content root (manifest id).
func (s *Store) PinContent(content model.Hash32) uint64 {
	s.contentPins[content]++
	return s.contentPins[content]
}

// UnpinContent releases a content pin.
func (s *Store) UnpinContent(content model.Hash32) uint64 {
	if count, ok := s.contentPins[content]; ok {
		if count <= 1 {
			delete(s.contentPins, content)
			return 0
		}
		s.contentPins[content] = count - 1
		return count - 1
	}
	return 0
}

func (s *Store) isObjectPinned(id model.Hash32) bool { return s.pins[id] > 0 }

// SortedPinIDs returns pinned object ids in byte order.
func (s *Store) SortedPinIDs() []model.Hash32 {
	return model.SortHashKeys(s.pins)
}

// SortHashKeys is a convenience re-export for callers building stable output.
func SortHashKeys[V any](m map[model.Hash32]V) []model.Hash32 {
	keys := make([]model.Hash32, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Less(keys[j]) })
	return keys
}
