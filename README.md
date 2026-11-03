# WeftFS-Go

Independent Go implementation of the WeftFS v1 portable store and Linux FUSE
frontend. It reads and writes the **identical on-disk format** produced by the
Rust reference implementation and uses
[`WeftCodec-Go`](../WeftCodec-Go) for WCB, hashing, selectors, limits, and
error classes.

No Rust, cgo, FFI, subprocess, or shared library participates in any production
path. The Rust binary appears only in test oracles that check cross-language
compatibility, and those tests skip with a precise reason if the oracle has not
been built.

## Status (2026-11-03, branch `staging`)

Implemented and exercised in the Docker FUSE court:

- **Portable reader** (`store`, `model`, `auth`, `resolver`): `FORMAT`/`LOCK`/
  superblock validation, highest-valid-generation selection with fallback,
  commit CRC/hash/parent-chain verification, replay of all eight op kinds,
  checkpoints with the generation rule, pointer files as caches, manifest
  chunk reads with per-chunk and whole-content hash verification, exact
  selector evaluation (authorized universe first, one-hop relations, tags,
  ordering with `object_id` tie-break, offset/limit, evidence), POSIX mode +
  `weft.acl.read` authorization without count/evidence disclosure, and
  `verify --full`.
- **Writable store** with identical bytes and publication order: `init`
  (generation 1, root object 32 zero bytes), create/write/truncate/mkdir/
  rmdir/unlink/rename (including `RENAME_NOREPLACE`/`RENAME_EXCHANGE`)/link/
  symlink/setattr/xattr, relations, snapshots, checkpoints, exclusive `flock`
  writer locking, read-only opens without a lock, open-handle pins, and
  `fsync` on file/directory/root plus superblock slot `gen % 2`.
- **Mark-and-sweep GC** (`store.GC`, `store.GCBounded`, `store.GCWatch`,
  CLI `gc`): Rust-compatible roots (current state, snapshot states, all
  checkpoint manifests including valid unpublished tails, content pins),
  orphan-record cleanup on apply, `gc_grace_secs` age gate, dry run by default,
  checked non-symlink regular-file sweep under `objects/` and `manifests/`, and
  file/byte counts for reachable, unreachable, deleted, and remaining sets.
  `gc --apply --watch` runs bounded, cancellable passes under the exclusive
  writer lock; `mount --gc-watch` enables the same collector inside a writable
  live mount, serialized with every FUSE request. Both are opt-in. Cross-
  language handoff gates cover Rust→Go, Go→Rust, alternating generations, and
  SIGKILL-during-commit recovery.
- **Go FUSE frontend** (`fusefs`, `github.com/hanwen/go-fuse/v2`): mount,
  lookup/getattr/readdir(+)/open/create/read/write/flush/fsync/release/mkdir/
  rmdir/unlink/rename/link/symlink/readlink/setattr/statfs/xattrs/access,
  `mknod` (regular files; FIFO/socket/device rejected with `EPERM`), `tmpfile`
  (O_TMPFILE, linkable through `/proc/self/fd`), `fallocate` modes 0,
  `KEEP_SIZE`, `PUNCH_HOLE`, and `ZERO_RANGE` (dense zero-fill; no physical
  space-reclamation claim), `copy_file_range` (daemon-side, short copy at EOF),
  `lseek` `SEEK_DATA`/`SEEK_HOLE` (dense file; only the EOF hole), and in-memory
  `getlk`/`setlk`/`setlkw` for POSIX byte ranges and flock (kernel forwarding
  enabled with `EnableLocks`). Read-only and snapshot mounts refuse mutations;
  read locks remain available. Read-only and snapshot mounts, `/.weft/id/<64hex>`
  exact-object view, and saved-context views with deterministic escaped display
  names are unchanged.
- **CLI** (`weftfs`): `init`, `info`, `create`, `write`, `cat`, `ls`, `stat`,
  `mkdir`, `unlink`, `rmdir`, `rename`, `link`, `symlink`, `readlink`,
  `setattr`, `xattr`, `relation`, `query`, `snapshot`, `verify`, `gc`
  (including `--watch`), `checkpoint`, `pin`, `mount` (including `--gc-watch`).

Not implemented or explicitly bounded (see [NOTES.md](NOTES.md)): `ioctl`
(go-fuse answers `ENOTTY`), `mmap` writeback, `atime`/`ctime` persistence, and
`COLLAPSE_RANGE`/`INSERT_RANGE` through the 7.3.1 FUSE kernel boundary (it
rejects them before `FUSE_FALLOCATE`; the store implementations and tests
exist). Locks are advisory and per-mount-process; they do not coordinate
independent daemons or hosts. `PUNCH_HOLE`/`ZERO_RANGE` define content but do
not reclaim physical chunks because v1 files are dense. No performance claims
are made.

## Layout

| Path | Purpose |
|---|---|
| `model` | Hash32 identities, object/entry/relation/commit/manifest/state records, ops, replay state |
| `store` | Format framing, recovery, replay, reads, writes, verification |
| `auth` | POSIX mode + `weft.acl.read` predicate |
| `resolver` | WeftQL evaluation over a pinned state |
| `fusefs` | Native Go FUSE nodes, handles, virtual views |
| `cmd/weftfs` | CLI |
| `werr` | Store error taxonomy (class strings + errno mapping) |
| `conformance/store/v1` | Frozen Rust fixture (see `PROVENANCE.md`) |

## Module wiring

`go.mod` requires `github.com/infinityabundance/WeftCodec-Go v0.0.0` and uses a
path replacement in this monorepo:

```
replace github.com/infinityabundance/WeftCodec-Go => ../WeftCodec-Go
```

The standalone `WeftFS-Go` repository replaces that directive with a normal
versioned requirement. The replacement affects only build resolution; it never
affects bytes written to a store. `go.sum` is committed.

## Build and test

All commands run inside the OOM-protected Docker courts; do not run them on the
host.

```sh
# Build and unit/integration tests (includes FUSE, needs /dev/fuse).
cd /mnt/1tb_kingston/WeftFS
scripts/docker-court.sh fuse "cd WeftFS-Go && CGO_ENABLED=0 go build ./... && go vet ./... && go test -race ./... -count=1"

# Rust oracle used by the bidirectional handoff tests (built once).
scripts/docker-court.sh rust "cargo build --release --features fuse --locked --bin weftfs"
```

The handoff tests locate the oracle at
`../.docker-cache/target-rust/release/weftfs` (or `$WEFTFS_RUST_BIN`) and
`t.Skip` with the build command if it is absent.

## CLI examples

```sh
weftfs --store /tmp/store init
weftfs --store /tmp/store create /hello.txt --text "hello weft"
weftfs --store /tmp/store mkdir /docs
weftfs --store /tmp/store relation add --subject /hello.txt --predicate tagged_as --value greeting
weftfs --store /tmp/store snapshot create v1
weftfs --store /tmp/store query --json 'select tag("greeting")'
weftfs --store /tmp/store verify --full
weftfs --store /tmp/store gc                     # dry run (default)
weftfs --store /tmp/store gc --apply             # sweep, respecting 1h grace
weftfs --store /tmp/store --json gc --grace-secs 0
weftfs --store /tmp/store mount --mountpoint /mnt/weft --read-only
```

## Conformance

The frozen fixture in `conformance/store/v1` is the Rust-generated handoff
contract. `TestRustFixtureOpensExactly` asserts every object id, version id,
content hash, entry path, entry id, relation id, snapshot, and the three
selectors in `EXPECTED.json`. `TestFixtureSequenceReproducesRustIdentities`
builds the same fixture from scratch with the Go writer and compares
`FORMAT`, `superblock`, every commit file, every manifest, every chunk, and the
snapshot pointer bytes against the Rust fixture: with the fixture's fixed clock
and explicit seeds the stores are byte-identical.

Bidirectional gates (Rust → Go and Go → Rust) are recorded in
[NOTES.md](NOTES.md), including four GC-specific gates: Rust garbage swept by
Go, Go garbage swept by Rust, three alternating generations with GC between
them, and SIGKILL-during-commit followed by Go GC and a Rust verify. No result
in this repository is a performance claim.
