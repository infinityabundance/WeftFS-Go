// ControlVolume is the versioned control-record namespace a store needs:
// FORMAT, the writer lock, the two-slot superblock, commit records, snapshot
// pointers, quota and access counters.
//
// The interface is deliberately small and record-shaped. The local filesystem
// implementation delegates to the existing path helpers, so the frozen v1
// layout and commit protocol are unchanged; the S3 implementation maps each
// record to one logical key and uses the conditional-write protocol. No store
// code may bypass it with a local path when the plane is remote.
package store

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// ControlVolume is the control-record plane.
type ControlVolume interface {
	Label() string
	Capabilities() CommitCapabilities
	Root() string

	EnsureLayout() error
	CleanTmp(graceSecs uint64) error
	Sync() error
	Diagnostics() []string
	Close() error

	ReadFormat() ([]byte, error)
	CreateFormat() error

	ReadSuperblock() (SuperblockView, error)
	CreateSuperblock() error
	// PublishSuperblockSlot patches one 4096-byte slot and publishes it. On a
	// remote plane this is a conditional whole-object write, and the volume
	// fences the writer immediately before it.
	PublishSuperblockSlot(slot SuperblockSlot, index int) error

	CreateCommit(generation uint64, data []byte) error
	ReadCommit(generation uint64) (LoadedCommit, error)
	HasCommit(generation uint64) (bool, error)
	ListCommitGenerations() ([]uint64, error)

	ReadRecord(name string) ([]byte, bool, error)
	WriteRecordNew(name string, data []byte) error
	WriteRecordReplace(name string, data []byte) error
	DeleteRecord(name string) error
	ListRecords(prefix string) ([]string, error)

	AcquireWriterLock() error
	VerifyWriteLease() error
	// CheckLeaseDeadline is a local own-deadline check with no network write.
	CheckLeaseDeadline() error
	// PublishFencedHead publishes a head through the writer lock record in one
	// conditional write (fence + head). Returns true when the plane did it; a
	// POSIX plane returns false and the store writes the superblock slot.
	PublishFencedHead(generation uint64, commit model.Hash32, commitLen uint64) (bool, error)
	// AttestedHead returns the head the writer lock record names, when the plane
	// uses its lock record as the publication point.
	AttestedHead() (uint64, model.Hash32, uint64, bool, error)
	// RefreshHeadCache keeps the superblock cache current after a fenced head
	// publication. It never moves the cache backwards.
	RefreshHeadCache(generation uint64, commit model.Hash32, commitLen uint64, timestampNS int64) error
	ReleaseWriterLock() error

	probe() (CommitProbe, error)
}

// ---- local filesystem volume --------------------------------------------

// localControl is the POSIX implementation. Every method delegates to the
// helper the store used before the plane split, so existing stores and fixtures
// are byte-identical.
type localControl struct {
	*commitPlane
	lock *os.File
}

func newLocalControl(root string, kind PlaneKind) (*localControl, error) {
	plane, err := newCommitPlane(root, kind)
	if err != nil {
		return nil, err
	}
	return &localControl{commitPlane: plane}, nil
}

func (c *localControl) EnsureLayout() error { return ensureCommitLayout(c.root) }

func (c *localControl) CleanTmp(graceSecs uint64) error { return cleanStaleTmp(c.root, graceSecs) }

func (c *localControl) Sync() error { return fsyncDir(c.root) }

func (c *localControl) Diagnostics() []string { return nil }

func (c *localControl) Close() error { return c.ReleaseWriterLock() }

func (c *localControl) ReadFormat() ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(c.root, "FORMAT"))
	if err != nil {
		return nil, werr.Wrap(werr.Corrupt, err, "cannot read FORMAT")
	}
	return data, nil
}

func (c *localControl) CreateFormat() error {
	return writeNewFile(filepath.Join(c.root, "FORMAT"), []byte(model.FormatContents), 0o644)
}

func (c *localControl) ReadSuperblock() (SuperblockView, error) {
	return ReadSuperblock(c.root)
}

func (c *localControl) CreateSuperblock() error {
	path := filepath.Join(c.root, "superblock")
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return werr.Wrap(werr.Io, err, "cannot create superblock")
	}
	if err := file.Truncate(model.SuperblockBytes); err != nil {
		file.Close()
		return werr.Wrap(werr.Io, err, "cannot size superblock")
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return werr.Wrap(werr.Io, err, "cannot fsync superblock")
	}
	return file.Close()
}

func (c *localControl) PublishSuperblockSlot(slot SuperblockSlot, index int) error {
	path := filepath.Join(c.root, "superblock")
	file, err := os.OpenFile(path, os.O_RDWR, 0o644)
	if err != nil {
		return werr.Wrap(werr.Io, err, "cannot open superblock")
	}
	if _, err := file.WriteAt(slot.Encode(), int64(index)*int64(model.SlotBytes)); err != nil {
		file.Close()
		return werr.Wrap(werr.Io, err, "cannot write superblock slot")
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return werr.Wrap(werr.Io, err, "cannot fsync superblock")
	}
	return file.Close()
}

func (c *localControl) CreateCommit(generation uint64, data []byte) error {
	path := CommitPath(c.root, generation)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			existing, readErr := os.ReadFile(path)
			if readErr == nil && overlayBytesSame(existing, data) {
				return nil
			}
			return werr.Wrap(werr.Exists, err, "commit file %s already exists with different bytes", path)
		}
		return werr.Wrap(werr.Corrupt, err, "cannot create commit file %s", path)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return werr.Wrap(werr.Io, err, "cannot write commit file %s", path)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return werr.Wrap(werr.Io, err, "cannot fsync commit file %s", path)
	}
	if err := file.Close(); err != nil {
		return werr.Wrap(werr.Io, err, "cannot close commit file %s", path)
	}
	return fsyncDir(filepath.Join(c.root, "commits"))
}

func (c *localControl) ReadCommit(generation uint64) (LoadedCommit, error) {
	expected := generation
	return LoadCommitFile(CommitPath(c.root, generation), &expected)
}

func (c *localControl) HasCommit(generation uint64) (bool, error) {
	info, err := os.Stat(CommitPath(c.root, generation))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, werr.Wrap(werr.Io, err, "cannot stat commit %d", generation)
	}
	if !info.Mode().IsRegular() {
		return false, werr.Newf(werr.Corrupt, "commit path for generation %d is not a regular file", generation)
	}
	return true, nil
}

func (c *localControl) ListCommitGenerations() ([]uint64, error) {
	files, err := ScanCommitFiles(c.root)
	if err != nil {
		return nil, err
	}
	out := make([]uint64, 0, len(files))
	for generation := range files {
		out = append(out, generation)
	}
	return out, nil
}

func (c *localControl) ReadRecord(name string) ([]byte, bool, error) {
	data, _, present, err := c.readControl(name)
	return data, present, err
}

func (c *localControl) WriteRecordNew(name string, data []byte) error {
	return c.putControlIfAbsent(name, data)
}

func (c *localControl) WriteRecordReplace(name string, data []byte) error {
	return writeRecordReplace(c.root, c.path(name), data)
}

// writeRecordReplace atomically replaces a control record, staging in the
// store's single `tmp/` directory. It must not stage under the record's own
// directory: `access/counts.v1` and `tmp/probe-*` would otherwise create
// nested `access/tmp` or `tmp/tmp` directories.
func writeRecordReplace(root, path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := makeDir(dir); err != nil {
		return err
	}
	tmpDir := filepath.Join(root, "tmp")
	if err := makeDir(tmpDir); err != nil {
		return err
	}
	tmp := filepath.Join(tmpDir, "record-"+itoa(uint64(os.Getpid()))+"-"+itoa(tmpCounter.Add(1)))
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
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
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return werr.Wrap(werr.Io, err, "cannot publish %s", path)
	}
	return fsyncDir(dir)
}

func (c *localControl) DeleteRecord(name string) error {
	return c.deleteControl(name)
}

func (c *localControl) ListRecords(prefix string) ([]string, error) {
	dir := filepath.Join(c.root, filepath.FromSlash(prefix))
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, werr.Wrap(werr.Io, err, "cannot read %s", dir)
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		out = append(out, prefix+"/"+entry.Name())
	}
	return out, nil
}

func (c *localControl) AcquireWriterLock() error {
	lock, err := flockExclusive(filepath.Join(c.root, "LOCK"))
	if err != nil {
		return err
	}
	c.lock = lock
	return nil
}

func (c *localControl) VerifyWriteLease() error { return nil }

// A POSIX plane has no lease record: the exclusive flock is the ownership proof,
// a suspended process keeps it, and nothing can reclaim it. The store writes the
// superblock slot as the publication point.
func (c *localControl) CheckLeaseDeadline() error { return nil }

func (c *localControl) PublishFencedHead(uint64, model.Hash32, uint64) (bool, error) {
	return false, nil
}

func (c *localControl) AttestedHead() (uint64, model.Hash32, uint64, bool, error) {
	return 0, model.ZeroHash, 0, false, nil
}

func (c *localControl) RefreshHeadCache(uint64, model.Hash32, uint64, int64) error { return nil }

func (c *localControl) ReleaseWriterLock() error {
	if c.lock == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(c.lock.Fd()), syscall.LOCK_UN)
	closeErr := c.lock.Close()
	c.lock = nil
	if unlockErr != nil {
		return werr.Wrap(werr.Io, unlockErr, "cannot unlock LOCK")
	}
	return closeErr
}
