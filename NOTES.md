# WeftFS-Go — implementation notes, evidence, and handoff matrix

This file records what is implemented, what is missing, the exact court
commands that were run, and the raw observed outcomes. It contains no
performance claims. Status labels: **implemented** (exercised by a test in this
repository), **experimental** (present but not claimed complete), and
**missing**.

Revisions recorded for this work:

| Item | Revision / value |
|---|---|
| WeftFS-Go branch `staging`, base before P6 | `447a7e401d0bf3aaaef547698817a4fbe1608278` |
| WeftCodec-Go (path-replaced module) | `b2beeab4b0da0401006984214dcfd6602be795a5` |
| Rust oracle binary | `weftfs 0.1.0`, built from the program-home working tree (parent `HEAD` `66fbf3ec101335b76b3ee7dfbcf2d0680cc8711e`) |
| Fixture generator revision (recorded inside the fixture) | `61b11a802f3475ecb1723b5c54cb83f49e465f8a` |
| Frozen fixture copy digest (all files except `PROVENANCE.md`) | `ac73419fb4070c442fec14a960997c10821cd0cea0d92d9180cbf52040a0013e` |

---

## 1. Implemented surface

### Reader (`model`, `store`, `auth`, `resolver`) — implemented

- `FORMAT` exact match (`weftfs-store 1\n`); `LOCK` is required for a writer.
- Both 4096-byte superblock slots: magic `WFSB`, major/minor, CRC32C over
  `[0,64)`, zero padding, non-zero generation/commit/length.
- Highest valid generation selection with one-generation-at-a-time fallback;
  rejected generations are recorded and never deleted or overwritten.
- Commit file framing `WFC1 || u64le len || WCB || u32le CRC32C`; exact length,
  CRC, WCB canonical decode, canonical re-encode, and
  `H("weft/store/commit/v1", WCB)` checks.
- Parent-chain walk: cycle rejection, strictly increasing generations, parent
  hash equality, generation 1 has no parent.
- Replay of `put_object`, `delete_object`, `put_entry`, `del_entry`,
  `put_relation`, `del_relation`, `set_snapshot`, `set_tip` with the same
  all-or-nothing validation as the Rust reference.
- Checkpoints: a checkpoint is the state **after** its commit; a matching
  `generation` loads it and skips that commit's ops; a mismatched/unreadable
  checkpoint is ignored with a recovery note and ops are replayed.
- Snapshot/tag pointer files are treated as caches; state is authoritative.
- File manifests: 64 KiB chunks in v1 output, non-final chunks full, chunk
  lengths sum to `size`, `content_hash` is `H("weft/chunk/v1", plaintext)`,
  every chunk is hash-verified before use, and the whole-content hash is
  verified on full-range reads. A 256 MiB decoder bound fails closed before a
  larger allocation.
- `verify --full` recomputes commit, checkpoint, manifest, chunk, and
  whole-content identities and reports generation, counts, rejected
  generations, and problems.
- Selector evaluation: authorized universe first, one-hop relation lookup,
  `tag` sugar, absent/mistyped comparisons false, `attr_ne` only when both
  sides exist, `not` inside the authorized universe, ordering with an
  unconditional `object_id` ascending tie-break, offset then limit, and
  evidence filtered by the same authorization predicate. `SelectorId` is the
  query hash.
- Authorization: POSIX owner/group/other bits plus `weft.acl.read` as an array
  of `u64` uids; malformed ACL values deny. Denied objects are excluded from
  results, counts, and evidence.

### Writer (`store`) — implemented

- `init`: empty/absent directory, layout, `FORMAT`, `LOCK`, 8192-byte
  superblock, generation 1 with root object `ObjectId = 32 zero bytes`.
- create/write/truncate/mkdir/rmdir/unlink/rename/rename-no-replace/
  rename-exchange/link/symlink/setattr/get-set-list-remove-xattr.
- Relations add (idempotent by `RelationId`) / delete.
- Snapshot creation (commit the `set_snapshot` op, then publish the cache
  pointer) and forced checkpoints.
- Identity derivations match `WEFT-MODEL.md` §2.3.1:
  `H("weft/object/v1", seed)`, version, entry, relation, manifest, commit.
- Canonical WCB records and checkpoint state manifests; checkpoint arrays are
  emitted in a deterministic order (objects by id, entries by parent+name,
  relations by id).
- Publication order: blob `tmp/` → fsync file → rename → fsync directory;
  commit file → fsync file → fsync `commits/`; superblock slot `gen % 2` →
  fsync superblock; fsync store root. Crash hooks sit after object writes,
  after the commit file, and after the superblock write.
- Exclusive non-blocking `flock` on `LOCK`; a second writer gets `Busy`.
  Read-only opens take no lock and pin the state they loaded.
- In-memory open-handle pins: unlink keeps a pinned record readable/writable;
  the final unpin deletes an entry-less record in one commit.

### FUSE frontend (`fusefs`, `go-fuse/v2`) — implemented, with documented gaps

- Node operations: lookup, getattr, readdir/readdirplus (go-fuse derives plus
  from `Lookup`), open, create, read, write, flush, fsync, release, mkdir,
  rmdir, unlink, rename (including `RENAME_NOREPLACE`/`RENAME_EXCHANGE`),
  link, symlink, readlink, setattr, statfs, get/set/list/remove xattr, access,
  opendir.
- Stable inode numbers per mount: root `ObjectId` is ino 1; namespace objects
  derive an ino from the first 8 ObjectId bytes with a collision-safe allocator;
  exact-id and context views allocate distinct ino ranges so distinct
  viewpoints never alias. Two hard links to one object share one ino.
- Read-only and snapshot mounts reject writes with `EROFS`.
- `/.weft/id/<64 lowercase hex>` exact-object access (read-only).
- `/.weft/contexts/<name>/` saved-context views. Display names are the escaped
  basename of the object's first path plus `--<8+ hex>`; prefixes extend in
  8-character steps on collision; names are sorted; readdir and lookup use the
  same rules and return all authorized results (no silent singleton).
- Open-unlinked handles pin their object; reads and writes continue until the
  last release.
- Locking answers `ENOSYS` so the kernel uses local locks. `mknod`, `tmpfile`,
  `fallocate`, `copy_file_range`, and `lseek` hole queries are unsupported and
  fall through to the kernel-visible `ENOTSUP`/`ENOSYS` behavior.

### Missing

- **Garbage collection.** Rust's mark-and-sweep GC is not ported. Unreferenced
  blobs from failed commits and unreferenced records from crash tails remain
  until an external sweep. `UnpinObject` performs its own durable cleanup
  commit; it is not a GC.
- Multi-writer concurrency (v1 is single-writer by design; the lock refuses a
  second writer).
- `atime`/`ctime` persistence. `Getattr` mirrors the stored mtime for both;
  `setattr` ignores `FATTR_ATIME`/`FATTR_CTIME`.
- `mmap` writeback. Writable handles are write-through; read handles request
  direct I/O so one read is served from one immutable content root.
- Performance measurements. None are made.

---

## 2. Exact court commands and observed results

All runs used the OOM-protected courts (`--memory=3g --memory-swap=3g
--pids-limit=1024 --cpus=4`, bounded `/tmp`, `no-new-privileges`). Nothing was
run on the host.

### 2.1 Rust oracle build

```sh
cd /mnt/1tb_kingston/WeftFS
scripts/docker-court.sh rust \
  "cargo build --release --features fuse --locked --bin weftfs"
```

Observed (tail):

```
   Compiling weftfs v0.1.0 (/work)
    Finished `release` profile [optimized] target(s) in 12.34s
```

Oracle version observed: `weftfs 0.1.0`.

### 2.2 Build, vet, race tests

```sh
cd /mnt/1tb_kingston/WeftFS
scripts/docker-court.sh fuse \
  "cd WeftFS-Go && CGO_ENABLED=0 go build ./... && go vet ./... && go test -race ./... -count=1"
```

Observed:

```
ok  	github.com/infinityabundance/WeftFS-Go/fusefs	1.176s
ok  	github.com/infinityabundance/WeftFS-Go/store	1.339s
```

`CGO_ENABLED=0 go build ./...` and `go vet ./...` exited 0. With `-v`, the run
reported **29 top-level tests passed** (23 in `store`, 6 in `fusefs`) plus
**5 subtests passed**, and **1 intentional helper skip**
(`TestCrashChildProcess`, re-executed as a child by `TestCrashProxy`).

The command from the operator directive also works verbatim:

```sh
cd /mnt/1tb_kingston/WeftFS && scripts/docker-court.sh fuse "cd WeftFS-Go && go test ./..."
```

### 2.3 Fixture and byte-identity checks

- `TestRustFixtureOpensExactly`: opens the frozen Rust fixture read-only and
  asserts every object id, version id, content id, manifest content hash, path,
  entry id, relation id, snapshot commit, the three `EXPECTED.json` selectors
  (selector id, snapshot id, matched count, ordered object ids), exact
  `hello.txt`/symlink bytes, and `verify --full` (`ok=true`,
  `checked_objects>=3`, `checked_chunks>=3`).
- `TestFixtureSequenceReproducesRustIdentities`: builds the same store with the
  Go writer (fixed timestamp `1700000000000000000`, the fixture's explicit
  seeds, the same operation order) and asserts generation `11`, head
  `8959c65b7b5d821063e8785ed950a67214b555210bec45f65fd576053b0e1d81`, every
  object/version/content identity, every entry id, both relation ids, and all
  three selector results. The same test then compares **bytes** for `FORMAT`,
  `superblock`, every `commits/*.commit`, every manifest, every object chunk,
  and `refs/snapshots/v1` against the frozen Rust fixture: all are identical.
  With the fixture's fixed clock and explicit seeds, the two implementations
  therefore produce the same store byte for byte (barring a hash collision).

Corruption tests (all fail closed or fall back exactly as documented):

| Test | Mutation | Observed |
|---|---|---|
| `TestTruncatedCommitFallsBack` | truncate `commits/11.commit` | generation < 11, `rejected` names 11, `/hello.txt` still resolves |
| `TestCommitCRCFlipFallsBack` | flip last byte of `11.commit` | fallback below 11, 11 rejected |
| `TestCorruptSuperblockSlotFallsBack` | zero slot 1 | generation 10 (the other slot) |
| `TestBadSlotCRCAndWrongSlotHashFallBack/crc` | corrupt slot 1 CRC | generation 10 |
| `TestBadSlotCRCAndWrongSlotHashFallBack/hash` | valid slot 1 CRC, wrong commit hash | generation 10, 11 rejected |
| `TestWrongChunkHashFailsClosedAtRead` | flip a chunk byte (same length) | open succeeds (catalog checks length), `ReadObject` fails `Corrupt`, `verify --full` reports a problem |
| `TestCorruptManifestFallsBack` | flip a manifest byte | fallback before the object's commit; `/hello.txt` absent; `verify` not ok |
| `TestBothSuperblockSlotsZeroFailsClosed` | zero both slots | open fails `Corrupt` |
| `TestUnpublishedCommitTailIsNotVisible` | copy `11.commit` to `12.commit` | generation 11 selected; `verify` flags the tail |
| `TestAuthorizationDoesNotDiscloseCounts` | `weft.acl.read = [0]` on hello | uid 0 sees 3 files; uid 1000 sees 2; no hello in results or evidence |

### 2.4 Crash proxy (SIGKILL during commit)

`TestCrashProxy` re-executes the test binary as a child, which opens a fresh
store and creates `crash.txt`; `WEFT_CRASH_PHASE` makes the store send
`SIGKILL` to itself at the named point. The parent then reopens and verifies.

| Phase | Observed on reopen |
|---|---|
| `after_objects` | file **absent** (no commit file); store replays generation 1; no data corruption |
| `after_commit_file` | file **absent** (superblock not published); store selects generation 1; `verify` reports only the unpublished commit tail above the published generation (the same diagnostic the Rust reference documents) |
| `after_superblock_write` | file **present** with the complete payload; `verify --full` `ok=true` |

`TestRejectedTailIsNotOverwritten` additionally confirms that a valid-but-
unpublished `2.commit` is never deleted or rewritten: the recovered writer
commits generation 3, the tail file keeps its bytes, and the final store
verifies `ok=true` with generation 3.

These are process-fault proxies, not power-loss evidence. No hardware or
kernel-crash claim is made.

### 2.5 Bidirectional handoff gates (Rust oracle)

Every gate below was actually run in the FUSE court; the Rust binary is a test
oracle only.

| Gate | Test | Commands (abridged) | Observed |
|---|---|---|---|
| 1. Rust fixture → Go mutations → Rust | `TestHandoffRustFixtureThenGoMutations` | Go: create `/go-added.txt`, add object relation `go_provenance`, snapshot `go-snap`. Rust: `verify --full`, `cat /go-added.txt`, `cat /docs/readme.md`, `query 'select relation(go_provenance, obj:<readme>)'`, `snapshot list`, `info`, mount and read | `ok=true`; exact bytes; query `matched_count=1`; `go-snap` present with Go's commit; `info` generation/head equal Go's; mount read `added by Go\n` |
| 2. Go `init` + mutations → Rust | `TestHandoffGoInitThenRust` | Rust: `verify --full`, `cat /gate2.txt`, `cat /dir/nested.txt`, mount and read | `ok=true`; exact bytes in the CLI and through the Rust mount |
| 3. Alternating 5 generations | `TestHandoffAlternatingGenerations` | 5 × (Go create → Rust `verify --full` + `cat`; Rust `create` + `checkpoint` → Go `Verify(true)` + re-read both files) | every Go verify `ok=true`; every Rust verify `ok=true`; final store generation > 11; all 10 files exact |
| 4. Snapshots both ways | `TestHandoffSnapshotsBidirectional` | Rust `pin /snap.txt --snapshot go-snap --json`; Rust snapshot mount read; Rust `snapshot create rust-snap`; Go reopen `LookupSnapshot`/`StateAt`/read | Rust pin snapshot/object/version/content equal Go's snapshot record; Rust mount read `v1`; Go reads `rust-snap` content `v2` |
| 5. Checkpoints both ways | `TestHandoffCheckpointsBothWays` | Go init with `checkpoint_interval=1` → Rust `verify --full` + `cat` + `create`; Rust `checkpoint` → Go `Verify(true)` + reads | Rust replays the Go checkpoint and commits on top; Go replays the Rust checkpoint; both files exact; `ok=true` |

Handoff matrix per operation:

| Operation | Rust → Go | Go → Rust | Evidence |
|---|---|---|---|
| Open/replay fixture | yes | n/a | `TestRustFixtureOpensExactly` |
| Open/replay live store | yes (Go writer output) | yes (Rust output) | gates 2, 3 |
| Exact file bytes | yes | yes | gates 1, 2, 3; fixture test |
| Object/version/content identities | yes | yes | fixture test; `TestFixtureSequenceReproducesRustIdentities`; gate 4 pin |
| Relation graph | yes | yes | gate 1 query; gate 2 value relation read by Rust verify |
| Snapshot create/read | yes | yes | gate 4 |
| Checkpoint create/read | yes | yes | gate 5; alternating gate |
| `verify --full` | n/a | yes (Rust verifies Go stores) | gates 1–5 |
| FUSE mount/read | Go mounts the Rust fixture | Rust mounts Go stores and Go snapshots | `TestFixtureMountReadOnly`; gates 1, 2, 4 |

### 2.6 Go FUSE tests

All six ran against a real `/dev/fuse` mount in the court:

- `TestFixtureMountReadOnly` — exact bytes, readdir/lookup agreement, hard-link
  ino equality and nlink 2, root ino 1, symlink target, exact-id file and
  directory views, missing id `ENOENT`, and `EROFS` for writes/mkdir.
- `TestMountWritesAndPosixSurface` — create/write/pwrite/read, mkdir, rename,
  link, symlink, truncate, chmod, set/get/list/remove xattr, unlink/rmdir, and
  `verify --full` while mounted.
- `TestSnapshotMountIsReadOnlyAtOldVersion` — snapshot mount reads `v1`, write
  returns `EROFS`, live mount reads `v2!`.
- `TestContextViewNamesAndLookupAgree` — three authorized results → three
  deterministic `basename--<8hex>` names, unique, sorted, each opens with exact
  content; saved-context listing/lookup agree; missing context `ENOENT`;
  exact-id access works.
- `TestOpenUnlinkedHandle` — read and write through an already-unlinked
  descriptor; the record is reclaimed after the last release.
- `TestSeparateFileConcurrency` — six workers write/read distinct files for 12
  rounds; `verify --full` is clean.

---

## 3. Known limitations and honest gaps

1. **No GC.** See above. A long-lived store accumulates unreferenced blobs
   after failed commits and after crash tails until swept by other means.
2. **Same-inode concurrent direct read/write is not claimed.** The parent
   project records a kernel EIO issue for that pattern in
   `docs/fuse-status.md`. This implementation tests concurrent traffic on
   separate files and store-level atomicity, not the same-inode pattern.
3. **Live context display names are not frozen per directory handle.** They
   are recomputed from the current paths, so a concurrent commit/rename can
   change a name between readdir and lookup on a live mount. Snapshot mounts
   are immutable and always agree. The Rust frontend freezes the listing at
   `opendir`; this is a fidelity difference for live mounts only.
4. **Locking, mknod, tmpfile, fallocate, copy_file_range, lseek holes** are not
   implemented. Locking answers `ENOSYS` (kernel local locks); the others use
   the kernel-visible unsupported response.
5. **atime/ctime** are not stored; getattr mirrors mtime. `setattr` applies
   mode/uid/gid/mtime/size only.
6. **`write` is whole-file rematerialisation** in v1 (`WEFT-MODEL.md` §3), so a
   write is O(file size) and bounded at 256 MiB. This is the normative v1
   behaviour, not an optimization.
7. **No hardware power-loss court.** Crash evidence is a process-fault proxy.
8. **Module replacement.** The committed `go.mod` uses
   `replace ... => ../WeftCodec-Go` for the monorepo. The standalone repository
   must switch to a versioned requirement; no on-disk behavior depends on it.
9. **Court write permissions.** The court runs as uid 0 with `cap-drop=ALL`, so
   `go mod tidy` needs `go.mod`/`go.sum` to be writable by the container. The
   committed `go.sum` is complete; `go build`/`go test` run without modifying
   it.
