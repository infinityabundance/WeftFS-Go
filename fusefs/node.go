package fusefs

import (
	"context"
	"sort"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/infinityabundance/WeftCodec-Go/limits"
	"github.com/infinityabundance/WeftFS-Go/auth"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

const (
	fattrNorReplace = 0x1 // RENAME_NOREPLACE
	xattrCreate     = 0x1
	xattrReplace    = 0x2
)

// principalOf extracts the kernel caller. FUSE does not forward supplementary
// groups, so authorization uses uid, primary gid, and weft.acl.read.
func principalOf(ctx context.Context) auth.Principal {
	if caller, ok := fuse.FromContext(ctx); ok {
		return auth.New(uint64(caller.Uid), uint64(caller.Gid), nil)
	}
	return auth.Root()
}

func clampU32(value uint64) uint32 {
	if value > ^uint64(0)>>32 {
		return ^uint32(0)
	}
	return uint32(value)
}

func splitTime(ns int64) (uint64, uint32) {
	if ns >= 0 {
		return uint64(ns / 1_000_000_000), uint32(ns % 1_000_000_000)
	}
	seconds := ns / 1_000_000_000
	remainder := ns % 1_000_000_000
	if remainder < 0 {
		seconds--
		remainder += 1_000_000_000
	}
	return uint64(seconds), uint32(remainder)
}

func fillAttr(attr *fuse.Attr, record model.ObjectRecord, nlink uint64, ino uint64) {
	attr.Ino = ino
	attr.Size = record.Size
	attr.Blocks = (record.Size + 511) / 512
	seconds, nanos := splitTime(record.MtimeNS)
	attr.Mtime = seconds
	attr.Mtimensec = nanos
	attr.Atime = seconds
	attr.Atimensec = nanos
	attr.Ctime = seconds
	attr.Ctimensec = nanos
	attr.Mode = uint32(record.Mode)
	attr.Nlink = clampU32(nlink)
	attr.Uid = clampU32(record.UID)
	attr.Gid = clampU32(record.GID)
	attr.Blksize = 4096
}

func (n *node) virtualOwner() (uint32, uint32, uint64) {
	state := n.srv.viewState()
	if root, ok := state.Objects[model.RootID]; ok {
		seconds, _ := splitTime(root.MtimeNS)
		return clampU32(root.UID), clampU32(root.GID), seconds
	}
	return 0, 0, 0
}

func (n *node) virtualDirAttr(attr *fuse.Attr, ino uint64) {
	uid, gid, seconds := n.virtualOwner()
	attr.Ino = ino
	attr.Mode = 0o555
	attr.Nlink = 2
	attr.Uid = uid
	attr.Gid = gid
	attr.Mtime = seconds
	attr.Atime = seconds
	attr.Ctime = seconds
	attr.Blksize = 4096
}

func modeFor(record model.ObjectRecord) uint32 {
	switch record.Kind {
	case model.KindDir:
		return syscall.S_IFDIR
	case model.KindSymlink:
		return syscall.S_IFLNK
	default:
		return syscall.S_IFREG
	}
}

// recordLocked returns the record for an object-backed node. The caller holds
// srv.mu.
func (n *node) recordLocked() (model.ObjectRecord, error) {
	state := n.srv.viewState()
	record, ok := state.Objects[n.id]
	if !ok {
		return model.ObjectRecord{}, werr.Newf(werr.NotFound, "no such object")
	}
	return record, nil
}

func (n *node) isVirtual() bool {
	switch n.kind {
	case kindContextRoot, kindWeftRoot, kindWeftIDs, kindWeftContexts, kindWeftContextDir:
		return true
	default:
		return false
	}
}

// contextEntries names the context mount's authorized results. The same
// helper feeds readdir and lookup, so they cannot disagree.
func (s *Server) contextEntries(state *model.State, principal auth.Principal) []struct {
	Name []byte
	ID   model.Hash32
} {
	if s.opts.Context == nil {
		return nil
	}
	ids := make([]model.Hash32, 0, len(s.opts.Context.Results))
	for _, id := range s.opts.Context.Results {
		record, ok := state.Objects[id]
		if ok && auth.CanRead(record, principal) {
			ids = append(ids, id)
		}
	}
	return contextEntryNames(ids, state)
}

func (n *node) isDirectory() bool {
	if n.isVirtual() {
		return true
	}
	state := n.srv.viewState()
	record, ok := state.Objects[n.id]
	return ok && record.Kind == model.KindDir
}

// ---- getattr -------------------------------------------------------------

var _ = (fs.NodeGetattrer)((*node)(nil))

func (n *node) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	n.srv.mu.Lock()
	defer n.srv.mu.Unlock()
	ino := n.Inode.StableAttr().Ino
	if n.isVirtual() {
		n.virtualDirAttr(&out.Attr, ino)
		return 0
	}
	record, err := n.recordLocked()
	if err != nil {
		return errno(err)
	}
	fillAttr(&out.Attr, record, n.srv.viewState().NLink(n.id), ino)
	return 0
}

// ---- lookup and readdir --------------------------------------------------

type dirItem struct {
	name []byte
	ino  uint64
	mode uint32
}

func (n *node) listLocked(principal auth.Principal) ([]dirItem, error) {
	state := n.srv.viewState()
	items := make([]dirItem, 0)
	switch n.kind {
	case kindObject:
		object, ok := state.Objects[n.id]
		if !ok {
			return nil, werr.Newf(werr.NotFound, "no such directory")
		}
		if object.Kind != model.KindDir {
			return nil, werr.Newf(werr.NotDir, "not a directory")
		}
		entries, err := state.ListDir(n.id)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if n.id == model.RootID && string(entry.Name) == ".weft" {
				continue
			}
			record, ok := state.Objects[entry.Target]
			if !ok {
				return nil, werr.Newf(werr.Corrupt, "directory entry has no target object")
			}
			if !auth.ACLAllows(record, principal) {
				continue
			}
			items = append(items, dirItem{
				name: entry.Name, ino: n.srv.inodes.objectIno(entry.Target), mode: modeFor(record),
			})
		}
		if n.id == model.RootID {
			items = append(items, dirItem{name: []byte(".weft"), ino: weftIno, mode: syscall.S_IFDIR})
		}
	case kindContextRoot:
		if n.srv.opts.Context == nil {
			return nil, werr.Newf(werr.Corrupt, "context mount has no context root")
		}
		for _, named := range n.srv.contextEntries(state, principal) {
			record, ok := state.Objects[named.ID]
			if !ok {
				return nil, werr.Newf(werr.Corrupt, "selector result has no object record")
			}
			items = append(items, dirItem{
				name: named.Name,
				ino:  n.srv.inodes.contextNodeIno(n.srv.opts.Context.Name, named.ID),
				mode: modeFor(record),
			})
		}
		// Constant name: the exact-id surface stays reachable and never changes
		// the result listing.
		items = append(items, dirItem{name: []byte(".weft"), ino: weftIno, mode: syscall.S_IFDIR})
	case kindWeftRoot:
		items = append(items,
			dirItem{name: []byte("contexts"), ino: weftCtxIno, mode: syscall.S_IFDIR},
			dirItem{name: []byte("id"), ino: weftIDsIno, mode: syscall.S_IFDIR},
		)
	case kindWeftIDs:
		now := n.srv.store.ClockNowNS()
		for _, id := range model.SortHashKeys(state.Objects) {
			record := state.Objects[id]
			if !auth.CanRead(record, principal) {
				continue
			}
			if n.srv.opts.Capability != nil {
				if _, err := n.srv.store.ExactIDObjectAt(state, id, n.srv.opts.Capability, principal, now); err != nil {
					continue
				}
			}
			items = append(items, dirItem{
				name: []byte(id.Hex()), ino: n.srv.inodes.idViewIno(id), mode: modeFor(record),
			})
		}
	case kindWeftContexts:
		root, ok := state.Objects[model.RootID]
		if !ok {
			return nil, werr.Newf(werr.Corrupt, "namespace root is missing")
		}
		if !auth.CanRead(root, principal) {
			return items, nil
		}
		contexts, err := n.srv.store.VisibleSavedContexts(state, n.srv.opts.Capability, principal, n.srv.store.ClockNowNS())
		if err != nil {
			return nil, err
		}
		for _, saved := range contexts {
			items = append(items, dirItem{
				name: []byte(saved.Name), ino: n.srv.inodes.contextDirIno(saved.Name), mode: syscall.S_IFDIR,
			})
		}
	case kindWeftContextDir:
		root, ok := state.Objects[model.RootID]
		if !ok {
			return nil, werr.Newf(werr.Corrupt, "namespace root is missing")
		}
		if !auth.CanRead(root, principal) {
			return nil, werr.Newf(werr.Unauthorized, "principal cannot read the namespace root")
		}
		saved, err := n.srv.store.LoadContextAt(state, n.context)
		if err != nil {
			return nil, err
		}
		resolution, err := n.srv.store.ResolveSavedContextWithCapability(
			saved, n.srv.viewSnapshot(), state, principal, limits.Default(),
			n.srv.opts.Capability, n.srv.store.ClockNowNS(),
		)
		if err != nil {
			return nil, err
		}
		ids := make([]model.Hash32, 0, len(resolution.Results))
		for _, result := range resolution.Results {
			ids = append(ids, result.ObjectID)
		}
		for _, named := range contextEntryNames(ids, state) {
			record, ok := state.Objects[named.ID]
			if !ok {
				return nil, werr.Newf(werr.Corrupt, "selector result has no object record")
			}
			items = append(items, dirItem{
				name: named.Name, ino: n.srv.inodes.contextNodeIno(n.context, named.ID), mode: modeFor(record),
			})
		}
	case kindWeftID, kindWeftContextResult:
		object, ok := state.Objects[n.id]
		if !ok {
			return nil, werr.Newf(werr.NotFound, "no such object")
		}
		if object.Kind != model.KindDir {
			return nil, werr.Newf(werr.NotDir, "not a directory")
		}
		entries, err := state.ListDir(n.id)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			record, ok := state.Objects[entry.Target]
			if !ok {
				return nil, werr.Newf(werr.Corrupt, "directory entry has no target object")
			}
			if !auth.CanRead(record, principal) {
				continue
			}
			var ino uint64
			if n.kind == kindWeftContextResult {
				ino = n.srv.inodes.contextNodeIno(n.context, entry.Target)
			} else {
				ino = n.srv.inodes.idViewIno(entry.Target)
			}
			items = append(items, dirItem{name: entry.Name, ino: ino, mode: modeFor(record)})
		}
	}
	sort.Slice(items, func(i, j int) bool { return string(items[i].name) < string(items[j].name) })
	return items, nil
}

var _ = (fs.NodeLookuper)((*node)(nil))

func (n *node) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	principal := principalOf(ctx)
	n.srv.mu.Lock()
	defer n.srv.mu.Unlock()
	child, err := n.lookupLocked(name, principal, out)
	if err != nil {
		return nil, errno(err)
	}
	return n.NewInode(ctx, child, child.stable()), 0
}

func (n *node) lookupLocked(name string, principal auth.Principal, out *fuse.EntryOut) (*node, error) {
	state := n.srv.viewState()
	nameBytes := []byte(name)
	switch n.kind {
	case kindObject:
		if n.id == model.RootID && name == ".weft" {
			child := n.srv.newNode(kindWeftRoot, model.Hash32{}, "")
			child.virtualDirAttr(&out.Attr, weftIno)
			return child, nil
		}
		target, err := state.Lookup(n.id, nameBytes)
		if err != nil {
			return nil, err
		}
		record, ok := state.Objects[target]
		if !ok {
			return nil, werr.Newf(werr.Corrupt, "directory entry has no target object")
		}
		if !auth.ACLAllows(record, principal) {
			return nil, werr.Newf(werr.NotFound, "no such directory entry")
		}
		child := n.srv.newNode(kindObject, target, "")
		fillAttr(&out.Attr, record, state.NLink(target), n.srv.inodes.objectIno(target))
		return child, nil
	case kindContextRoot:
		if name == ".weft" {
			child := n.srv.newNode(kindWeftRoot, model.Hash32{}, "")
			child.virtualDirAttr(&out.Attr, weftIno)
			return child, nil
		}
		for _, named := range n.srv.contextEntries(state, principal) {
			if string(named.Name) != name {
				continue
			}
			record, ok := state.Objects[named.ID]
			if !ok || !auth.CanRead(record, principal) {
				return nil, werr.Newf(werr.NotFound, "no such context entry")
			}
			child := n.srv.newNode(kindWeftContextResult, named.ID, n.srv.opts.Context.Name)
			fillAttr(&out.Attr, record, state.NLink(named.ID),
				n.srv.inodes.contextNodeIno(n.srv.opts.Context.Name, named.ID))
			return child, nil
		}
		return nil, werr.Newf(werr.NotFound, "no such context entry")
	case kindWeftRoot:
		switch name {
		case "id":
			child := n.srv.newNode(kindWeftIDs, model.Hash32{}, "")
			child.virtualDirAttr(&out.Attr, weftIDsIno)
			return child, nil
		case "contexts":
			child := n.srv.newNode(kindWeftContexts, model.Hash32{}, "")
			child.virtualDirAttr(&out.Attr, weftCtxIno)
			return child, nil
		default:
			return nil, werr.Newf(werr.NotFound, "no such directory entry")
		}
	case kindWeftIDs:
		if len(name) != 64 {
			return nil, werr.Newf(werr.NotFound, "no such object id")
		}
		for index := 0; index < len(name); index++ {
			c := name[index]
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return nil, werr.Newf(werr.NotFound, "no such object id")
			}
		}
		id, err := parseHexHash(name)
		if err != nil {
			return nil, werr.Newf(werr.NotFound, "no such object id")
		}
		record, err := n.srv.store.ExactIDObjectAt(state, id, n.srv.opts.Capability, principal, n.srv.store.ClockNowNS())
		if err != nil {
			return nil, werr.Newf(werr.NotFound, "no such object id")
		}
		child := n.srv.newNode(kindWeftID, id, "")
		fillAttr(&out.Attr, record, state.NLink(id), n.srv.inodes.idViewIno(id))
		return child, nil
	case kindWeftContexts:
		contexts, err := n.srv.store.VisibleSavedContexts(state, n.srv.opts.Capability, principal, n.srv.store.ClockNowNS())
		if err != nil {
			return nil, err
		}
		found := false
		for _, saved := range contexts {
			if saved.Name == name {
				found = true
				break
			}
		}
		if !found {
			return nil, werr.Newf(werr.NotFound, "no such context")
		}
		root, ok := state.Objects[model.RootID]
		if !ok {
			return nil, werr.Newf(werr.Corrupt, "namespace root is missing")
		}
		if !auth.CanRead(root, principal) {
			return nil, werr.Newf(werr.NotFound, "no such context")
		}
		child := n.srv.newNode(kindWeftContextDir, model.Hash32{}, name)
		child.virtualDirAttr(&out.Attr, n.srv.inodes.contextDirIno(name))
		return child, nil
	case kindWeftContextDir, kindWeftID, kindWeftContextResult:
		if n.kind == kindWeftContextDir {
			ids, err := n.contextResultIDs(principal)
			if err != nil {
				return nil, err
			}
			for _, named := range contextEntryNames(ids, state) {
				if string(named.Name) != name {
					continue
				}
				record, ok := state.Objects[named.ID]
				if !ok || !auth.CanRead(record, principal) {
					return nil, werr.Newf(werr.NotFound, "no such context entry")
				}
				child := n.srv.newNode(kindWeftContextResult, named.ID, n.context)
				fillAttr(&out.Attr, record, state.NLink(named.ID), n.srv.inodes.contextNodeIno(n.context, named.ID))
				return child, nil
			}
			return nil, werr.Newf(werr.NotFound, "no such context entry")
		}
		entries, err := state.ListDir(n.id)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if string(entry.Name) != name {
				continue
			}
			record, ok := state.Objects[entry.Target]
			if !ok || !auth.CanRead(record, principal) {
				return nil, werr.Newf(werr.NotFound, "no such directory entry")
			}
			child := n.srv.newNode(n.kind, entry.Target, n.context)
			var ino uint64
			if n.kind == kindWeftContextResult {
				ino = n.srv.inodes.contextNodeIno(n.context, entry.Target)
			} else {
				ino = n.srv.inodes.idViewIno(entry.Target)
			}
			fillAttr(&out.Attr, record, state.NLink(entry.Target), ino)
			return child, nil
		}
		return nil, werr.Newf(werr.NotFound, "no such directory entry")
	}
	return nil, werr.Newf(werr.NotFound, "no such directory entry")
}

// contextResultIDs runs the context selector and returns the matched ids.
func (n *node) contextResultIDs(principal auth.Principal) ([]model.Hash32, error) {
	state := n.srv.viewState()
	saved, err := n.srv.store.LoadContextAt(state, n.context)
	if err != nil {
		return nil, err
	}
	resolution, err := n.srv.store.ResolveSavedContextWithCapability(
		saved, n.srv.viewSnapshot(), state, principal, limits.Default(),
		n.srv.opts.Capability, n.srv.store.ClockNowNS(),
	)
	if err != nil {
		return nil, err
	}
	ids := make([]model.Hash32, 0, len(resolution.Results))
	for _, result := range resolution.Results {
		ids = append(ids, result.ObjectID)
	}
	return ids, nil
}

var _ = (fs.NodeReaddirer)((*node)(nil))

func (n *node) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	principal := principalOf(ctx)
	n.srv.mu.Lock()
	items, err := n.listLocked(principal)
	n.srv.mu.Unlock()
	if err != nil {
		return nil, errno(err)
	}
	selfIno := n.Inode.StableAttr().Ino
	parentIno := selfIno
	if _, parent := n.Parent(); parent != nil {
		parentIno = parent.StableAttr().Ino
	}
	entries := make([]fuse.DirEntry, 0, len(items)+2)
	entries = append(entries,
		fuse.DirEntry{Name: ".", Ino: selfIno, Mode: syscall.S_IFDIR},
		fuse.DirEntry{Name: "..", Ino: parentIno, Mode: syscall.S_IFDIR},
	)
	for _, item := range items {
		entries = append(entries, fuse.DirEntry{Name: string(item.name), Ino: item.ino, Mode: item.mode})
	}
	return fs.NewListDirStream(entries), 0
}

// ---- open / read / write -------------------------------------------------

// fileHandle pins the object or content while the descriptor is open.
type fileHandle struct {
	srv           *Server
	id            model.Hash32
	content       model.Hash32
	size          uint64
	append        bool
	readOnlyView  bool
	pinnedObject  bool
	pinnedContent bool
	tmpfile       bool
	// lockOwners are the FUSE lock owners observed on this handle. They are
	// released when the handle is released (see locks.go for the limitation).
	lockOwners map[uint64]struct{}
}

var _ = (fs.FileReader)((*fileHandle)(nil))
var _ = (fs.FileWriter)((*fileHandle)(nil))
var _ = (fs.FileFlusher)((*fileHandle)(nil))
var _ = (fs.FileFsyncer)((*fileHandle)(nil))
var _ = (fs.FileReleaser)((*fileHandle)(nil))

var _ = (fs.NodeOpener)((*node)(nil))

func (n *node) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	writeIntent := flags&uint32(syscall.O_ACCMODE) != uint32(syscall.O_RDONLY) ||
		flags&uint32(syscall.O_TRUNC) != 0
	n.srv.mu.Lock()
	defer n.srv.mu.Unlock()
	if n.isVirtual() {
		return nil, 0, syscall.EISDIR
	}
	if n.srv.readOnly && writeIntent && n.kind == kindObject {
		return nil, 0, syscall.EROFS
	}
	record, err := n.recordLocked()
	if err != nil {
		return nil, 0, errno(err)
	}
	principal := principalOf(ctx)
	if !auth.ACLAllows(record, principal) {
		return nil, 0, syscall.EACCES
	}
	if record.Kind == model.KindDir {
		return nil, 0, syscall.EISDIR
	}
	if record.Kind == model.KindSymlink {
		return nil, 0, syscall.EINVAL
	}
	readOnlyView := n.kind != kindObject || n.srv.readOnly
	if writeIntent && readOnlyView {
		return nil, 0, syscall.EROFS
	}
	if flags&uint32(syscall.O_TRUNC) != 0 {
		if _, err := n.srv.store.Truncate(n.id, 0); err != nil {
			return nil, 0, errno(err)
		}
		record, _ = n.recordLocked()
	}
	handle := &fileHandle{
		srv: n.srv, id: n.id, content: record.Content, size: record.Size,
		append: flags&uint32(syscall.O_APPEND) != 0, readOnlyView: readOnlyView,
	}
	if readOnlyView {
		n.srv.store.PinContent(record.Content)
		handle.pinnedContent = true
	} else {
		if _, err := n.srv.store.PinObject(n.id); err != nil {
			return nil, 0, errno(err)
		}
		handle.pinnedObject = true
	}
	fuseFlags := uint32(0)
	if !writeIntent {
		fuseFlags = fuse.FOPEN_DIRECT_IO
	}
	return handle, fuseFlags, 0
}

func (h *fileHandle) currentLocked() (model.Hash32, uint64) {
	state := h.srv.viewState()
	if record, ok := state.Objects[h.id]; ok {
		return record.Content, record.Size
	}
	return h.content, h.size
}

func (h *fileHandle) Read(ctx context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	if off < 0 {
		return nil, syscall.EINVAL
	}
	h.srv.mu.Lock()
	content, size := h.currentLocked()
	h.srv.mu.Unlock()
	if uint64(off) >= size {
		return fuse.ReadResultData(nil), 0
	}
	length := uint64(len(dest))
	if uint64(off)+length > size {
		length = size - uint64(off)
	}
	data, err := h.srv.store.ReadContent(content, uint64(off), length)
	if err != nil {
		return nil, errno(err)
	}
	return fuse.ReadResultData(data), 0
}

func (h *fileHandle) Write(ctx context.Context, data []byte, off int64) (uint32, syscall.Errno) {
	if off < 0 {
		return 0, syscall.EINVAL
	}
	if len(data) == 0 {
		return 0, 0
	}
	if h.srv.readOnly || h.readOnlyView {
		return 0, syscall.EROFS
	}
	h.srv.mu.Lock()
	defer h.srv.mu.Unlock()
	writeOffset := uint64(off)
	state := h.srv.viewState()
	if record, ok := state.Objects[h.id]; ok {
		if h.append {
			writeOffset = record.Size
		}
	} else if h.append {
		writeOffset = h.size
	}
	if writeOffset > store.MaxFileBytes || uint64(len(data)) > store.MaxFileBytes ||
		writeOffset+uint64(len(data)) < writeOffset ||
		writeOffset+uint64(len(data)) > store.MaxFileBytes {
		return 0, syscall.EFBIG
	}
	if _, err := h.srv.store.WriteFile(h.id, writeOffset, data); err != nil {
		return 0, errno(err)
	}
	if record, ok := h.srv.viewState().Objects[h.id]; ok {
		h.content = record.Content
		h.size = record.Size
	}
	return uint32(len(data)), 0
}

func (h *fileHandle) Flush(ctx context.Context) syscall.Errno { return 0 }
func (h *fileHandle) Fsync(ctx context.Context, flags uint32) syscall.Errno {
	// Every mutation is a durably published commit before its reply.
	return 0
}

func (h *fileHandle) Release(ctx context.Context) syscall.Errno {
	h.srv.mu.Lock()
	defer h.srv.mu.Unlock()
	for owner := range h.lockOwners {
		h.srv.locks.releaseOwner(owner)
	}
	h.lockOwners = nil
	if h.pinnedContent {
		h.srv.store.UnpinContent(h.content)
		h.pinnedContent = false
	}
	if h.pinnedObject {
		// A failed cleanup commit is not reportable through close; the
		// unreferenced record is retained (and reclaimed by GC in Rust).
		_, _ = h.srv.store.UnpinObject(h.id)
		h.pinnedObject = false
	}
	return 0
}

// ---- create / namespace mutations ---------------------------------------

var _ = (fs.NodeCreater)((*node)(nil))

func (n *node) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	if n.kind != kindObject {
		return nil, nil, 0, syscall.EROFS
	}
	n.srv.mu.Lock()
	defer n.srv.mu.Unlock()
	if n.srv.readOnly {
		return nil, nil, 0, syscall.EROFS
	}
	principal := principalOf(ctx)
	if err := model.ValidateNameBytes([]byte(name)); err != nil {
		return nil, nil, 0, errno(err)
	}
	state := n.srv.viewState()
	var id model.Hash32
	created := false
	if existing, err := state.Lookup(n.id, []byte(name)); err == nil {
		if flags&uint32(syscall.O_EXCL) != 0 {
			return nil, nil, 0, syscall.EEXIST
		}
		record, ok := state.Objects[existing]
		if !ok {
			return nil, nil, 0, syscall.ENOENT
		}
		if record.Kind == model.KindDir {
			return nil, nil, 0, syscall.EISDIR
		}
		if record.Kind == model.KindSymlink {
			return nil, nil, 0, syscall.ELOOP
		}
		id = existing
		if flags&uint32(syscall.O_TRUNC) != 0 {
			if _, err := n.srv.store.Truncate(id, 0); err != nil {
				return nil, nil, 0, errno(err)
			}
		}
	} else {
		perm := uint64(mode & 0o7777)
		createdID, err := n.srv.store.CreateFile(n.id, []byte(name), nil, perm, uint64(principal.UID), uint64(principal.GID), nil)
		if err != nil {
			return nil, nil, 0, errno(err)
		}
		id = createdID
		created = true
	}
	_ = created
	record, ok := n.srv.viewState().Objects[id]
	if !ok {
		return nil, nil, 0, syscall.ENOENT
	}
	if _, err := n.srv.store.PinObject(id); err != nil {
		return nil, nil, 0, errno(err)
	}
	child := n.srv.newNode(kindObject, id, "")
	fillAttr(&out.Attr, record, n.srv.viewState().NLink(id), n.srv.inodes.objectIno(id))
	handle := &fileHandle{
		srv: n.srv, id: id, content: record.Content, size: record.Size,
		append: flags&uint32(syscall.O_APPEND) != 0, pinnedObject: true,
	}
	return n.NewInode(ctx, child, child.stable()), handle, 0, 0
}

var _ = (fs.NodeMkdirer)((*node)(nil))

func (n *node) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if n.kind != kindObject {
		return nil, syscall.EROFS
	}
	n.srv.mu.Lock()
	defer n.srv.mu.Unlock()
	if n.srv.readOnly {
		return nil, syscall.EROFS
	}
	if err := model.ValidateNameBytes([]byte(name)); err != nil {
		return nil, errno(err)
	}
	principal := principalOf(ctx)
	id, err := n.srv.store.Mkdir(n.id, []byte(name), uint64(mode&0o7777), uint64(principal.UID), uint64(principal.GID))
	if err != nil {
		return nil, errno(err)
	}
	record, ok := n.srv.viewState().Objects[id]
	if !ok {
		return nil, syscall.ENOENT
	}
	child := n.srv.newNode(kindObject, id, "")
	fillAttr(&out.Attr, record, n.srv.viewState().NLink(id), n.srv.inodes.objectIno(id))
	return n.NewInode(ctx, child, child.stable()), 0
}

var _ = (fs.NodeUnlinker)((*node)(nil))

func (n *node) Unlink(ctx context.Context, name string) syscall.Errno {
	if n.kind != kindObject {
		return syscall.EROFS
	}
	n.srv.mu.Lock()
	defer n.srv.mu.Unlock()
	if n.srv.readOnly {
		return syscall.EROFS
	}
	if err := n.srv.store.Unlink(n.id, []byte(name)); err != nil {
		return errno(err)
	}
	return 0
}

var _ = (fs.NodeRmdirer)((*node)(nil))

func (n *node) Rmdir(ctx context.Context, name string) syscall.Errno {
	if n.kind != kindObject {
		return syscall.EROFS
	}
	n.srv.mu.Lock()
	defer n.srv.mu.Unlock()
	if n.srv.readOnly {
		return syscall.EROFS
	}
	if err := n.srv.store.Rmdir(n.id, []byte(name)); err != nil {
		return errno(err)
	}
	return 0
}

var _ = (fs.NodeRenamer)((*node)(nil))

func (n *node) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	if n.kind != kindObject {
		return syscall.EROFS
	}
	target, ok := newParent.(*node)
	if !ok || target.kind != kindObject {
		return syscall.EROFS
	}
	n.srv.mu.Lock()
	defer n.srv.mu.Unlock()
	if n.srv.readOnly {
		return syscall.EROFS
	}
	var err error
	switch {
	case flags&fs.RENAME_EXCHANGE != 0:
		if flags&fattrNorReplace != 0 {
			return syscall.EINVAL
		}
		err = n.srv.store.RenameExchange(n.id, []byte(name), target.id, []byte(newName))
	case flags&fattrNorReplace != 0:
		err = n.srv.store.RenameNoReplace(n.id, []byte(name), target.id, []byte(newName))
	default:
		if flags != 0 {
			return syscall.EINVAL
		}
		err = n.srv.store.Rename(n.id, []byte(name), target.id, []byte(newName))
	}
	if err != nil {
		return errno(err)
	}
	return 0
}

var _ = (fs.NodeLinker)((*node)(nil))

func (n *node) Link(ctx context.Context, target fs.InodeEmbedder, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if n.kind != kindObject {
		return nil, syscall.EROFS
	}
	targetNode, ok := target.(*node)
	if !ok || targetNode.kind != kindObject {
		return nil, syscall.EPERM
	}
	n.srv.mu.Lock()
	defer n.srv.mu.Unlock()
	if n.srv.readOnly {
		return nil, syscall.EROFS
	}
	if err := n.srv.store.Link(targetNode.id, n.id, []byte(name)); err != nil {
		return nil, errno(err)
	}
	record, ok := n.srv.viewState().Objects[targetNode.id]
	if !ok {
		return nil, syscall.ENOENT
	}
	child := n.srv.newNode(kindObject, targetNode.id, "")
	fillAttr(&out.Attr, record, n.srv.viewState().NLink(targetNode.id), n.srv.inodes.objectIno(targetNode.id))
	return n.NewInode(ctx, child, child.stable()), 0
}

var _ = (fs.NodeSymlinker)((*node)(nil))

func (n *node) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if n.kind != kindObject {
		return nil, syscall.EROFS
	}
	n.srv.mu.Lock()
	defer n.srv.mu.Unlock()
	if n.srv.readOnly {
		return nil, syscall.EROFS
	}
	principal := principalOf(ctx)
	id, err := n.srv.store.Symlink(n.id, []byte(name), []byte(target), uint64(principal.UID), uint64(principal.GID))
	if err != nil {
		return nil, errno(err)
	}
	record, ok := n.srv.viewState().Objects[id]
	if !ok {
		return nil, syscall.ENOENT
	}
	child := n.srv.newNode(kindObject, id, "")
	fillAttr(&out.Attr, record, n.srv.viewState().NLink(id), n.srv.inodes.objectIno(id))
	return n.NewInode(ctx, child, child.stable()), 0
}

var _ = (fs.NodeReadlinker)((*node)(nil))

func (n *node) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	n.srv.mu.Lock()
	defer n.srv.mu.Unlock()
	record, err := n.recordLocked()
	if err != nil {
		return nil, errno(err)
	}
	if record.Kind != model.KindSymlink {
		return nil, syscall.EINVAL
	}
	target, ok := record.SymlinkTarget()
	if !ok {
		return nil, syscall.EIO
	}
	return append([]byte(nil), target...), 0
}

// ---- setattr -------------------------------------------------------------

var _ = (fs.NodeSetattrer)((*node)(nil))

func (n *node) Setattr(ctx context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if n.kind != kindObject {
		return syscall.EROFS
	}
	n.srv.mu.Lock()
	defer n.srv.mu.Unlock()
	if n.srv.readOnly {
		return syscall.EROFS
	}
	changes := store.SetAttr{}
	anyChange := false
	if mode, ok := in.GetMode(); ok {
		value := uint64(mode & 0o7777)
		changes.Mode = &value
		anyChange = true
	}
	if uid, ok := in.GetUID(); ok {
		value := uint64(uid)
		changes.UID = &value
		anyChange = true
	}
	if gid, ok := in.GetGID(); ok {
		value := uint64(gid)
		changes.GID = &value
		anyChange = true
	}
	if mtime, ok := in.GetMTime(); ok {
		ns := mtime.UnixNano()
		changes.MtimeNS = &ns
		anyChange = true
	}
	record, err := n.recordLocked()
	if err != nil {
		return errno(err)
	}
	if size, ok := in.GetSize(); ok {
		if record.Kind != model.KindFile {
			if record.Kind == model.KindDir {
				return syscall.EISDIR
			}
			return syscall.EINVAL
		}
		if _, err := n.srv.store.Truncate(n.id, size); err != nil {
			return errno(err)
		}
	}
	if anyChange {
		if _, err := n.srv.store.Setattr(n.id, changes); err != nil {
			return errno(err)
		}
	}
	record, err = n.recordLocked()
	if err != nil {
		return errno(err)
	}
	fillAttr(&out.Attr, record, n.srv.viewState().NLink(n.id), n.Inode.StableAttr().Ino)
	return 0
}

// ---- statfs and access ---------------------------------------------------

var _ = (fs.NodeStatfser)((*node)(nil))

func (n *node) Statfs(ctx context.Context, out *fuse.StatfsOut) syscall.Errno {
	n.srv.mu.Lock()
	stats := store.StatFSAt(n.srv.viewState())
	n.srv.mu.Unlock()
	out.Blocks = stats.Blocks
	out.Bfree = stats.BlocksFree
	out.Bavail = stats.BlocksAvailable
	out.Files = stats.Files
	out.Ffree = stats.FilesFree
	out.Bsize = uint32(stats.BlockSize)
	out.NameLen = uint32(stats.MaxNameLen)
	out.Frsize = uint32(stats.BlockSize)
	return 0
}

var _ = (fs.NodeAccesser)((*node)(nil))

func (n *node) Access(ctx context.Context, mask uint32) syscall.Errno {
	n.srv.mu.Lock()
	defer n.srv.mu.Unlock()
	principal := principalOf(ctx)
	if n.isVirtual() {
		if mask&2 != 0 {
			return syscall.EROFS
		}
		return 0
	}
	record, err := n.recordLocked()
	if err != nil {
		return errno(err)
	}
	if !auth.ACLAllows(record, principal) {
		return syscall.EACCES
	}
	effective := auth.EffectiveMode(record, principal)
	if mask&4 != 0 && effective&4 == 0 {
		return syscall.EACCES
	}
	if mask&1 != 0 && effective&1 == 0 {
		return syscall.EACCES
	}
	if mask&2 != 0 {
		if n.srv.readOnly || n.kind != kindObject {
			return syscall.EROFS
		}
		if effective&2 == 0 {
			return syscall.EACCES
		}
	}
	return 0
}

// ---- extended attributes -------------------------------------------------

var _ = (fs.NodeGetxattrer)((*node)(nil))
var _ = (fs.NodeSetxattrer)((*node)(nil))
var _ = (fs.NodeRemovexattrer)((*node)(nil))
var _ = (fs.NodeListxattrer)((*node)(nil))

func (n *node) Getxattr(ctx context.Context, attr string, dest []byte) (uint32, syscall.Errno) {
	n.srv.mu.Lock()
	defer n.srv.mu.Unlock()
	if n.isVirtual() {
		return 0, syscall.ENODATA
	}
	record, err := n.recordLocked()
	if err != nil {
		return 0, errno(err)
	}
	if !auth.ACLAllows(record, principalOf(ctx)) {
		return 0, syscall.EACCES
	}
	value, ok, err := n.srv.store.GetXattr(n.id, attr)
	if err != nil {
		return 0, errno(err)
	}
	if !ok {
		return 0, syscall.ENODATA
	}
	if len(dest) == 0 {
		return uint32(len(value)), 0
	}
	if len(dest) < len(value) {
		return uint32(len(value)), syscall.ERANGE
	}
	copy(dest, value)
	return uint32(len(value)), 0
}

func (n *node) Setxattr(ctx context.Context, attr string, data []byte, flags uint32) syscall.Errno {
	if n.kind != kindObject {
		return syscall.EROFS
	}
	n.srv.mu.Lock()
	defer n.srv.mu.Unlock()
	if n.srv.readOnly {
		return syscall.EROFS
	}
	_, exists, err := n.srv.store.GetXattr(n.id, attr)
	if err != nil {
		return errno(err)
	}
	if flags&xattrCreate != 0 && exists {
		return syscall.EEXIST
	}
	if flags&xattrReplace != 0 && !exists {
		return syscall.ENODATA
	}
	if flags&^(xattrCreate|xattrReplace) != 0 {
		return syscall.EINVAL
	}
	if err := n.srv.store.SetXattr(n.id, attr, data); err != nil {
		return errno(err)
	}
	return 0
}

func (n *node) Removexattr(ctx context.Context, attr string) syscall.Errno {
	if n.kind != kindObject {
		return syscall.EROFS
	}
	n.srv.mu.Lock()
	defer n.srv.mu.Unlock()
	if n.srv.readOnly {
		return syscall.EROFS
	}
	removed, err := n.srv.store.RemoveXattr(n.id, attr)
	if err != nil {
		return errno(err)
	}
	if !removed {
		return syscall.ENODATA
	}
	return 0
}

func (n *node) Listxattr(ctx context.Context, dest []byte) (uint32, syscall.Errno) {
	n.srv.mu.Lock()
	defer n.srv.mu.Unlock()
	if n.isVirtual() {
		return 0, 0
	}
	record, err := n.recordLocked()
	if err != nil {
		return 0, errno(err)
	}
	if !auth.ACLAllows(record, principalOf(ctx)) {
		return 0, syscall.EACCES
	}
	names, err := n.srv.store.ListXattr(n.id)
	if err != nil {
		return 0, errno(err)
	}
	total := 0
	for _, name := range names {
		total += len(name) + 1
	}
	if len(dest) == 0 {
		return uint32(total), 0
	}
	if len(dest) < total {
		return uint32(total), syscall.ERANGE
	}
	offset := 0
	for _, name := range names {
		copy(dest[offset:], []byte(name))
		offset += len(name)
		dest[offset] = 0
		offset++
	}
	return uint32(total), 0
}

// ---- locking -------------------------------------------------------------

var _ = (fs.NodeGetlker)((*node)(nil))
var _ = (fs.NodeSetlker)((*node)(nil))
var _ = (fs.NodeSetlkwer)((*node)(nil))

// Getlk reports a conflicting lock from another owner, or F_UNLCK. Virtual
// views never hold locks. The manager covers both POSIX byte ranges and flock
// because the kernel forwards both when EnableLocks is set.
func (n *node) Getlk(ctx context.Context, f fs.FileHandle, owner uint64, lk *fuse.FileLock, flags uint32, out *fuse.FileLock) syscall.Errno {
	if n.isVirtual() {
		out.Typ = syscall.F_UNLCK
		return 0
	}
	n.srv.mu.Lock()
	record, err := n.recordLocked()
	if err != nil {
		n.srv.mu.Unlock()
		return errno(err)
	}
	if record.Kind != model.KindFile {
		n.srv.mu.Unlock()
		return syscall.EINVAL
	}
	if !auth.ACLAllows(record, principalOf(ctx)) {
		n.srv.mu.Unlock()
		return syscall.EACCES
	}
	id := n.id
	n.srv.mu.Unlock()
	return n.srv.locks.get(id, owner, lk, flags, out)
}

func (n *node) Setlk(ctx context.Context, f fs.FileHandle, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	return n.setLock(ctx, f, owner, lk, flags, false)
}

func (n *node) Setlkw(ctx context.Context, f fs.FileHandle, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	return n.setLock(ctx, f, owner, lk, flags, true)
}

func (n *node) setLock(ctx context.Context, f fs.FileHandle, owner uint64, lk *fuse.FileLock, flags uint32, wait bool) syscall.Errno {
	if lk.Typ == syscall.F_UNLCK {
		// Unlocking is always permitted, including after a link disappears.
		return n.srv.locks.set(ctx, n.id, owner, lk, flags, false)
	}
	n.srv.mu.Lock()
	if n.isVirtual() {
		n.srv.mu.Unlock()
		return syscall.EROFS
	}
	record, err := n.recordLocked()
	if err != nil {
		n.srv.mu.Unlock()
		return errno(err)
	}
	if record.Kind != model.KindFile {
		n.srv.mu.Unlock()
		return syscall.EINVAL
	}
	principal := principalOf(ctx)
	if !auth.ACLAllows(record, principal) {
		n.srv.mu.Unlock()
		return syscall.EACCES
	}
	if lk.Typ == syscall.F_WRLCK {
		if n.srv.readOnly {
			n.srv.mu.Unlock()
			return syscall.EROFS
		}
		if auth.EffectiveMode(record, principal)&0o2 == 0 {
			n.srv.mu.Unlock()
			return syscall.EACCES
		}
	}
	if handle, ok := f.(*fileHandle); ok && handle != nil {
		if handle.lockOwners == nil {
			handle.lockOwners = make(map[uint64]struct{})
		}
		handle.lockOwners[owner] = struct{}{}
	}
	id := n.id
	n.srv.mu.Unlock()
	return n.srv.locks.set(ctx, id, owner, lk, flags, wait)
}

// OnForget runs when the root inode is dropped at unmount. It stops the
// collector and drops every in-memory lock; nothing is persisted.
var _ = (fs.NodeOnForgetter)((*node)(nil))

func (n *node) OnForget() {
	if n.kind == kindContextRoot || (n.kind == kindObject && n.id == model.RootID) {
		n.srv.StopBackgroundGC()
		n.srv.locks.clear()
	}
}

// ---- mknod, tmpfile, fallocate, copy_file_range, lseek -------------------

const (
	fallocKeepSize  = 0x01
	fallocPunchHole = 0x02
	fallocCollapse  = 0x08
	fallocZeroRange = 0x10
	fallocInsert    = 0x20

	seekSet = 0
	seekCur = 1
	seekEnd = 2
)

var _ = (fs.NodeMknoder)((*node)(nil))

// Mknod creates a regular file. v1 has no FIFO, socket, or device object kind,
// so those types are refused with EPERM rather than silently degraded to a
// regular file. The rejection is deliberate and tested.
func (n *node) Mknod(ctx context.Context, name string, mode uint32, dev uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if n.kind != kindObject {
		return nil, syscall.EROFS
	}
	n.srv.mu.Lock()
	defer n.srv.mu.Unlock()
	if n.srv.readOnly {
		return nil, syscall.EROFS
	}
	if mode&uint32(syscall.S_IFMT) != uint32(syscall.S_IFREG) {
		return nil, syscall.EPERM
	}
	if err := model.ValidateNameBytes([]byte(name)); err != nil {
		return nil, errno(err)
	}
	principal := principalOf(ctx)
	id, err := n.srv.store.CreateFile(n.id, []byte(name), nil, uint64(mode&0o7777), uint64(principal.UID), uint64(principal.GID), nil)
	if err != nil {
		return nil, errno(err)
	}
	record, ok := n.srv.viewState().Objects[id]
	if !ok {
		return nil, syscall.ENOENT
	}
	child := n.srv.newNode(kindObject, id, "")
	fillAttr(&out.Attr, record, n.srv.viewState().NLink(id), n.srv.inodes.objectIno(id))
	return n.NewInode(ctx, child, child.stable()), 0
}

var _ = (fs.NodeTmpfiler)((*node)(nil))

// Tmpfile creates an unnamed regular file (O_TMPFILE) with no directory entry.
// The object is pinned for the handle; linking it through /proc/self/fd adds
// the entry, and closing it unlinked removes the record in one commit.
func (n *node) Tmpfile(ctx context.Context, flags uint32, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	if n.kind != kindObject {
		return nil, nil, 0, syscall.EROFS
	}
	if flags&uint32(syscall.O_ACCMODE) == uint32(syscall.O_RDONLY) {
		return nil, nil, 0, syscall.EINVAL
	}
	n.srv.mu.Lock()
	defer n.srv.mu.Unlock()
	if n.srv.readOnly {
		return nil, nil, 0, syscall.EROFS
	}
	principal := principalOf(ctx)
	id, err := n.srv.store.CreateUnlinkedFile(nil, uint64(mode&0o7777), uint64(principal.UID), uint64(principal.GID), nil)
	if err != nil {
		return nil, nil, 0, errno(err)
	}
	record, ok := n.srv.viewState().Objects[id]
	if !ok {
		return nil, nil, 0, syscall.ENOENT
	}
	if _, err := n.srv.store.PinObject(id); err != nil {
		return nil, nil, 0, errno(err)
	}
	child := n.srv.newNode(kindObject, id, "")
	fillAttr(&out.Attr, record, n.srv.viewState().NLink(id), n.srv.inodes.objectIno(id))
	handle := &fileHandle{
		srv: n.srv, id: id, content: record.Content, size: record.Size,
		append: flags&uint32(syscall.O_APPEND) != 0, pinnedObject: true, tmpfile: true,
	}
	return n.NewInode(ctx, child, child.stable()), handle, 0, 0
}

var _ = (fs.NodeAllocater)((*node)(nil))

// Allocate implements fallocate. v1 files are dense, so PUNCH_HOLE and
// ZERO_RANGE zero the range instead of reclaiming physical extents. That is a
// real data-semantics implementation, not a space-reclamation claim. Mode 0
// extends with zeros without touching existing bytes. COLLAPSE_RANGE and
// INSERT_RANGE rewrite content exactly. Unknown combinations are EOPNOTSUPP.
func (n *node) Allocate(ctx context.Context, f fs.FileHandle, off uint64, size uint64, mode uint32) syscall.Errno {
	if n.kind != kindObject {
		return syscall.EROFS
	}
	n.srv.mu.Lock()
	defer n.srv.mu.Unlock()
	if n.srv.readOnly {
		return syscall.EROFS
	}
	record, err := n.recordLocked()
	if err != nil {
		return errno(err)
	}
	if record.Kind != model.KindFile {
		return syscall.EINVAL
	}
	if !auth.CanWrite(record, principalOf(ctx)) {
		return syscall.EACCES
	}
	if size == 0 {
		return syscall.EINVAL
	}
	end := off + size
	if end < off || off > store.MaxFileBytes || end > store.MaxFileBytes {
		return syscall.EFBIG
	}
	known := uint32(fallocKeepSize | fallocPunchHole | fallocCollapse | fallocZeroRange | fallocInsert)
	if mode&^known != 0 {
		return syscall.EOPNOTSUPP
	}
	var operation error
	switch {
	case mode&fallocCollapse != 0:
		if mode != fallocCollapse {
			return syscall.EINVAL
		}
		_, operation = n.srv.store.CollapseRange(n.id, off, size)
	case mode&fallocInsert != 0:
		if mode != fallocInsert {
			return syscall.EINVAL
		}
		_, operation = n.srv.store.InsertRange(n.id, off, size)
	case mode&fallocPunchHole != 0:
		if mode&fallocKeepSize == 0 {
			return syscall.EINVAL
		}
		if mode&^(fallocPunchHole|fallocKeepSize) != 0 {
			return syscall.EOPNOTSUPP
		}
		_, operation = n.srv.store.ZeroRange(n.id, off, size, false)
	case mode&fallocZeroRange != 0:
		if mode&^(fallocZeroRange|fallocKeepSize) != 0 {
			return syscall.EOPNOTSUPP
		}
		_, operation = n.srv.store.ZeroRange(n.id, off, size, mode&fallocKeepSize == 0)
	default:
		if mode&^uint32(fallocKeepSize) != 0 {
			return syscall.EOPNOTSUPP
		}
		if mode&fallocKeepSize == 0 && end > record.Size {
			_, operation = n.srv.store.Truncate(n.id, end)
		}
	}
	if operation != nil {
		return errno(operation)
	}
	return 0
}

var _ = (fs.NodeCopyFileRanger)((*node)(nil))

// CopyFileRange copies within the daemon. Both ends must be regular file
// objects; the destination must be writable. A short copy at EOF or at the
// 256 MiB v1 bound is returned as the copied length, matching read(2)-style
// short-copy semantics rather than inventing a failure.
func (n *node) CopyFileRange(ctx context.Context, fhIn fs.FileHandle, offIn uint64, out *fs.Inode, fhOut fs.FileHandle, offOut uint64, length uint64, flags uint64) (uint32, syscall.Errno) {
	if flags != 0 {
		return 0, syscall.EINVAL
	}
	if length == 0 {
		return 0, 0
	}
	outNode, ok := out.Operations().(*node)
	if !ok || outNode.kind != kindObject {
		return 0, syscall.EROFS
	}
	n.srv.mu.Lock()
	defer n.srv.mu.Unlock()
	state := n.srv.viewState()
	sourceID := n.id
	var sourceContent model.Hash32
	var sourceSize uint64
	if handle, ok := fhIn.(*fileHandle); ok && handle != nil {
		sourceID = handle.id
		sourceContent, sourceSize = handle.currentLocked()
	} else {
		record, err := n.recordLocked()
		if err != nil {
			return 0, errno(err)
		}
		if record.Kind != model.KindFile {
			return 0, syscall.EINVAL
		}
		sourceContent, sourceSize = record.Content, record.Size
	}
	if record, ok := state.Objects[sourceID]; ok {
		if !auth.ACLAllows(record, principalOf(ctx)) {
			return 0, syscall.EACCES
		}
	}
	destination, err := outNode.recordLocked()
	if err != nil {
		return 0, errno(err)
	}
	if destination.Kind != model.KindFile {
		return 0, syscall.EINVAL
	}
	if n.srv.readOnly {
		return 0, syscall.EROFS
	}
	if !auth.CanWrite(destination, principalOf(ctx)) {
		return 0, syscall.EACCES
	}
	if offOut > store.MaxFileBytes {
		return 0, syscall.EFBIG
	}
	if length > store.MaxFileBytes-offOut {
		length = store.MaxFileBytes - offOut
	}
	if offIn >= sourceSize {
		return 0, 0
	}
	if length > sourceSize-offIn {
		length = sourceSize - offIn
	}
	if length > uint64(^uint32(0)) {
		length = uint64(^uint32(0))
	}
	data, err := n.srv.store.ReadContent(sourceContent, offIn, length)
	if err != nil {
		return 0, errno(err)
	}
	if _, err := n.srv.store.WriteFile(outNode.id, offOut, data); err != nil {
		return 0, errno(err)
	}
	return uint32(len(data)), 0
}

var _ = (fs.NodeLseeker)((*node)(nil))

// Lseek reports dense-file holes: data exists from 0 to size, and the only
// hole is the virtual EOF hole at size. SEEK_SET is answered directly;
// SEEK_CUR/SEEK_END are normally handled by the kernel and answer ENOSYS if
// forwarded because the daemon holds no file position.
func (n *node) Lseek(ctx context.Context, f fs.FileHandle, off uint64, whence uint32) (uint64, syscall.Errno) {
	n.srv.mu.Lock()
	defer n.srv.mu.Unlock()
	if n.isVirtual() {
		return 0, syscall.EINVAL
	}
	record, err := n.recordLocked()
	if err != nil {
		return 0, errno(err)
	}
	if record.Kind != model.KindFile {
		return 0, syscall.EINVAL
	}
	switch whence {
	case seekSet:
		return off, 0
	case 3: // SEEK_DATA
		if off >= record.Size {
			return 0, syscall.ENXIO
		}
		return off, 0
	case 4: // SEEK_HOLE
		if off > record.Size {
			return 0, syscall.ENXIO
		}
		return record.Size, 0
	case seekCur, seekEnd:
		return 0, syscall.ENOSYS
	default:
		return 0, syscall.EINVAL
	}
}

// ---- directory open ------------------------------------------------------

var _ = (fs.NodeOpendirer)((*node)(nil))

func (n *node) Opendir(ctx context.Context) syscall.Errno {
	n.srv.mu.Lock()
	defer n.srv.mu.Unlock()
	if !n.isDirectory() {
		return syscall.ENOTDIR
	}
	if n.isVirtual() {
		return 0
	}
	record, err := n.recordLocked()
	if err != nil {
		return errno(err)
	}
	if !auth.ACLAllows(record, principalOf(ctx)) {
		return syscall.EACCES
	}
	return 0
}

// helper aliases avoiding a dependency cycle in import lists.

func isHexLower(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func parseHexHash(s string) (model.Hash32, error) {
	var h model.Hash32
	if !isHexLower(s) {
		return h, werr.Newf(werr.InvalidArgument, "invalid lowercase hash hex")
	}
	for i := 0; i < 32; i++ {
		var hi, lo byte
		switch c := s[i*2]; {
		case c >= '0' && c <= '9':
			hi = c - '0'
		default:
			hi = c - 'a' + 10
		}
		switch c := s[i*2+1]; {
		case c >= '0' && c <= '9':
			lo = c - '0'
		default:
			lo = c - 'a' + 10
		}
		h[i] = hi<<4 | lo
	}
	return h, nil
}
