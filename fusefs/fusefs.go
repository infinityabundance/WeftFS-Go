// Package fusefs implements the WeftFS Linux FUSE frontend with
// github.com/hanwen/go-fuse/v2. It is pure Go: no cgo, no Rust binary, and no
// subprocess participates in serving requests.
package fusefs

import (
	"sync"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/infinityabundance/WeftFS-Go/auth"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
)

// Virtual inode numbers, matching the Rust frontend's reserved values.
const (
	rootIno     uint64 = 1
	weftIno     uint64 = 2
	weftIDsIno  uint64 = 3
	weftCtxIno  uint64 = 4
	virtualBase uint64 = 1 << 62
)

// Options configures a mount.
type Options struct {
	Mountpoint string
	// Snapshot pins the mount to a commit. It implies read-only.
	Snapshot   *model.Hash32
	ReadOnly   bool
	AllowOther bool
	Debug      bool
	// Capability optionally narrows exact-id and saved-context views.
	Capability *auth.Capability
	// Context makes the mount root a resolved Context Root's result set.
	Context *ContextMount
}

// ContextMount is a resolved Context Root used as the mount root.
type ContextMount struct {
	Name          string
	ContextRootID model.Hash32
	Snapshot      model.Hash32
	SelectorID    model.Hash32
	// Results are the ordered, capability-authorized result ids.
	Results []model.Hash32
}

// Server owns the mount state and serializes access to the store. All node
// operations take mu; the store is single-writer and its state is not
// intrinsically concurrent.
type Server struct {
	store  *store.Store
	opts   Options
	mu     sync.Mutex
	state  *model.State
	pinned bool
	// readOnly is true for --read-only, snapshot mounts, and stores opened
	// read-only.
	readOnly bool
	inodes   *inodeTable
	root     *node
}

// inodeTable assigns stable, collision-free inode numbers per mount.
type inodeTable struct {
	mu          sync.Mutex
	used        map[uint64]bool
	objects     map[model.Hash32]uint64
	idView      map[model.Hash32]uint64
	contextDirs map[string]uint64
	contextView map[contextKey]uint64
	nextVirtual uint64
}

type contextKey struct {
	context string
	object  model.Hash32
}

func newInodeTable() *inodeTable {
	return &inodeTable{
		used:        map[uint64]bool{rootIno: true, weftIno: true, weftIDsIno: true, weftCtxIno: true},
		objects:     make(map[model.Hash32]uint64),
		idView:      make(map[model.Hash32]uint64),
		contextDirs: make(map[string]uint64),
		contextView: make(map[contextKey]uint64),
		nextVirtual: virtualBase,
	}
}

func bytesToU64(b []byte) uint64 {
	return uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
}

// objectIno maps an ObjectId to a stable per-mount inode. The root object is
// always ino 1 and distinct objects never share an inode.
func (t *inodeTable) objectIno(id model.Hash32) uint64 {
	if id == model.RootID {
		return rootIno
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if ino, ok := t.objects[id]; ok {
		return ino
	}
	candidate := bytesToU64(id[:8])
	if candidate <= weftCtxIno || candidate >= virtualBase || t.used[candidate] {
		candidate = t.allocLocked()
	}
	t.used[candidate] = true
	t.objects[id] = candidate
	return candidate
}

func (t *inodeTable) allocLocked() uint64 {
	for {
		candidate := t.nextVirtual
		t.nextVirtual++
		if candidate == 0 || candidate == ^uint64(0) {
			continue
		}
		if !t.used[candidate] {
			return candidate
		}
	}
}

func (t *inodeTable) idViewIno(id model.Hash32) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	if ino, ok := t.idView[id]; ok {
		return ino
	}
	ino := t.allocLocked()
	t.used[ino] = true
	t.idView[id] = ino
	return ino
}

func (t *inodeTable) contextDirIno(name string) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	if ino, ok := t.contextDirs[name]; ok {
		return ino
	}
	ino := t.allocLocked()
	t.used[ino] = true
	t.contextDirs[name] = ino
	return ino
}

func (t *inodeTable) contextNodeIno(contextName string, id model.Hash32) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := contextKey{context: contextName, object: id}
	if ino, ok := t.contextView[key]; ok {
		return ino
	}
	ino := t.allocLocked()
	t.used[ino] = true
	t.contextView[key] = ino
	return ino
}

// nodeKind identifies the semantic role of a node.
type nodeKind int

const (
	kindObject nodeKind = iota
	kindContextRoot
	kindWeftRoot
	kindWeftIDs
	kindWeftContexts
	kindWeftID
	kindWeftContextDir
	kindWeftContextResult
)

// node is the single node type used for every namespace, virtual, id-view, and
// context-view inode. Semantic role lives in kind, so no distinct object can
// alias another.
type node struct {
	fs.Inode
	srv     *Server
	kind    nodeKind
	id      model.Hash32
	context string
}

func (s *Server) newNode(kind nodeKind, id model.Hash32, contextName string) *node {
	return &node{srv: s, kind: kind, id: id, context: contextName}
}

func (n *node) stable() fs.StableAttr {
	switch n.kind {
	case kindContextRoot:
		return fs.StableAttr{Mode: syscall.S_IFDIR, Ino: rootIno}
	case kindWeftRoot, kindWeftIDs, kindWeftContexts, kindWeftContextDir:
		return fs.StableAttr{Mode: syscall.S_IFDIR, Ino: n.srv.virtualIno(n)}
	case kindObject, kindWeftID, kindWeftContextResult:
		return fs.StableAttr{Mode: n.objectMode(), Ino: n.srv.objectInoFor(n)}
	}
	return fs.StableAttr{Mode: syscall.S_IFREG}
}

func (s *Server) virtualIno(n *node) uint64 {
	switch n.kind {
	case kindContextRoot:
		return rootIno
	case kindWeftRoot:
		return weftIno
	case kindWeftIDs:
		return weftIDsIno
	case kindWeftContexts:
		return weftCtxIno
	case kindWeftContextDir:
		return s.inodes.contextDirIno(n.context)
	}
	return 0
}

func (s *Server) objectInoFor(n *node) uint64 {
	switch n.kind {
	case kindObject:
		return s.inodes.objectIno(n.id)
	case kindWeftID:
		return s.inodes.idViewIno(n.id)
	case kindWeftContextResult:
		return s.inodes.contextNodeIno(n.context, n.id)
	}
	return 0
}

func (n *node) objectMode() uint32 {
	state := n.srv.viewState()
	if record, ok := state.Objects[n.id]; ok {
		switch record.Kind {
		case model.KindDir:
			return syscall.S_IFDIR
		case model.KindSymlink:
			return syscall.S_IFLNK
		default:
			return syscall.S_IFREG
		}
	}
	return syscall.S_IFREG
}

// viewState returns the state this mount serves. For a snapshot mount it is
// the pinned replay; for a live mount it is the store's current state.
func (s *Server) viewState() *model.State {
	if s.state != nil {
		return s.state
	}
	return s.store.CurrentState()
}

func (s *Server) viewSnapshot() model.Hash32 {
	if s.opts.Snapshot != nil {
		return *s.opts.Snapshot
	}
	return s.store.Head()
}

// Mount mounts the store. The caller owns the store and must keep it open.
func Mount(st *store.Store, opts Options) (*fuse.Server, *Server, error) {
	s := &Server{store: st, opts: opts, inodes: newInodeTable()}
	if opts.Context != nil {
		if opts.Snapshot == nil {
			snapshot := opts.Context.Snapshot
			s.opts.Snapshot = &snapshot
		}
	}
	if s.opts.Snapshot != nil {
		pinned, err := st.StateAt(*s.opts.Snapshot)
		if err != nil {
			return nil, nil, err
		}
		s.state = pinned
		s.pinned = true
	}
	s.readOnly = opts.ReadOnly || s.opts.Snapshot != nil || opts.Context != nil || st.Mode() == store.ReadOnly
	s.root = &node{srv: s, kind: kindObject, id: model.RootID}
	if opts.Context != nil {
		s.root = &node{srv: s, kind: kindContextRoot, context: opts.Context.Name}
	}

	mountOptions := fuse.MountOptions{
		AllowOther: opts.AllowOther,
		FsName:     "weftfs",
		Name:       "weftfs",
		Debug:      opts.Debug,
		Options:    []string{"default_permissions"},
	}
	if s.readOnly {
		mountOptions.Options = append(mountOptions.Options, "ro")
	}
	rootStable := &fs.StableAttr{Ino: rootIno}
	fsOptions := &fs.Options{
		MountOptions:   mountOptions,
		RootStableAttr: rootStable,
	}
	server, err := fs.Mount(opts.Mountpoint, s.root, fsOptions)
	if err != nil {
		return nil, nil, err
	}
	return server, s, nil
}

// errno maps store errors to POSIX errno.
func errno(err error) syscall.Errno { return store.Errno(err) }

// Verify runs store verification while holding the server lock, so it never
// races a live request. It is used by the CLI-side tests and is safe to call
// while the mount is active.
func (s *Server) Verify(full bool) (*store.VerifyReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.store.Verify(full)
}

// SnapshotState returns a deep copy of the state this mount serves. Callers
// outside the server can inspect it without racing FUSE requests.
func (s *Server) SnapshotState() *model.State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.viewState().Clone()
}
