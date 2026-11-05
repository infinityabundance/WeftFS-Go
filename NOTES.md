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
| WeftFS-Go branch `staging`, base before Go GC | `74c8c90202030ad0dcb0bca680501c6b8fef24a9` |
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
- **Bounded open replay** (parity with Rust `load_state_bounded`): a read-only
  open starts at the highest published superblock generation, reads
  `commits/<gen>.commit` by generation, requires the declared generation to
  equal the path, records the hash and parent linkage, and descends to
  `gen-1`. It stops at the newest commit whose checkpoint manifest verifies
  (hash valid and declared generation equal to the commit generation). It never
  enumerates the commit directory. A writable open does one enumeration for
  `next_generation`; its commit decode window is still checkpoint-bounded. When
  the bounded walk resumes from a checkpoint it returns exactly:
  `bounded replay resumed from the checkpoint at generation <g>; commit files
  below it were not enumerated`.
- **Every bounded-replay inconsistency falls back to the authoritative full
  scan**: missing file, generation/name disagreement, hash or parent mismatch,
  non-contiguous generation, truncated record, unreadable or mislabelled
  checkpoint, published slot without a commit file, or a step bound exceeded.
  The fallback is recorded as `open fast path fell back to full commit-directory
  recovery: <reason>`; the full scan owns the rejected set and notes. A bounded
  walk never yields a shorter state.
- `store.CommitFileReads()`/`store.ResetCommitFileReads()` expose a process-wide
  counter incremented per `LoadCommitFile`; it is diagnostic only, used by the
  fast-open tests and the bench.
- `store.OpenFullScanForBench` forces the pre-optimisation full scan. It is not
  used by any production path.
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
  verified on full-range reads. A 1 TiB decoder bound (`MaxFileBytes`, matching
  Rust `MAX_FILE_BYTES`) and a 16,777,216-chunk manifest bound (`MaxChunksPerFile`,
  matching Rust `MAX_CHUNKS_PER_FILE`) fail closed before a larger allocation.
- `weft.manifest.v2` representation parity with Rust is implemented and
  cross-language tested: the Go store reads and verifies Rust `codec-auto`
  stores (ZSTD, DELTA with a causal base, v2 raw fallback) and Rust reads and
  verifies Go `codec-auto` stores; frames are not claimed byte-identical.
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
- **Mark-and-sweep GC** (`store.GC`, CLI `gc`) with Rust-compatible semantics:
  roots are the current state, every snapshot state, every checkpoint manifest
  named by any parseable commit (including valid but unpublished/rejected
  tails), and in-process content pins; object pins are roots because their
  records remain in state. Dry run is the default; `--apply` takes the
  exclusive writer lock, first removes crash-orphaned object records in one
  commit, then deletes only unmarked regular files under `objects/<ab>/` and
  `manifests/<ab>/` that are older than `gc_grace_secs` (default 3600, zero
  disables the age gate). Sweep paths are `Lstat`-checked: no symlink is
  followed and no non-regular file is removed.

### F2 Context Roots, capabilities, causal identity (`store`, `auth`, `cmd`) — implemented

- Phase `store/context.go`, model causal helpers, and `auth.Capability`.
- Context Root persistence as a root-subject `context_root` relation carrying
  canonical record hex plus `uri`; duplicate names are `Exists`, `--replace` is
  one delete+add commit; capability records are persisted in the same commit.
- Resolution recomputes `ContextRootId`, verifies the URI and pinned snapshot,
  requires `weft-resolver-v1`, authorizes before counting, and returns ordered
  results with root/selector/snapshot ids and closure. 0/1/n is explicit.
- Capability enforcement for namespace/root grants, selector predicates,
  exact-id access (including `/.weft/id`), saved-context views, and
  materialization. Denials are `Unauthorized`/`NotFound` without counts or ids.
  v1 makes no cryptographic or timing claim.
- Budgets: component-wise minimum of root and capability budgets. No truncation
  policy in v1; overrun is `LimitExceeded`. `max_bytes` bounds materialization,
  `max_depth` is one-hop, `max_work` is deterministic.
- Causal: `--causal` stores the four reserved attrs, computes the available
  transitive closure with a visited set (cycles terminate), publishes the
  closure record content-addressed, and changes `VersionId` only in
  `causal_exact`. `bytes_only` is unchanged from v1.
- Materialization verifies every content hash before publishing, writes to a
  sibling temporary directory, and renames into place; mismatch leaves no
  output. The manifest carries root/snapshot/selector ids, closure, capability
  hash, budget, counts, and per-file hashes/sizes/ids/causal closure.
- `verify --full` validates context records/URIs, re-resolves roots and checks
  recorded ids, validates causal attrs and closure blobs, and re-hashes stored
  capability records. GC retains causal closure blobs with their objects;
  context/capability relations are ordinary metadata.
- CLI: `context create|list|show|resolve|materialize|uri|delete`,
  `causal show`, `uri canonicalize|show`, `--causal` on create/write, and
  `mount --capability FILE` (capability mounts are forced read-only).
- Cross-language: Rust→Go and Go→Rust tests cover context identity/resolution,
  causal `VersionId` and closure, stored capabilities, and materialization.
  Golden vectors: `conformance/context/v1/causal_versions.json`.
- Evidence: `go test -race ./...` passes in the FUSE court (store + fusefs),
  including the new context/causal/capability/handoff tests; `go vet ./...`
  and `CGO_ENABLED=0 go build ./...` pass in the Go court.

### F3 Context mounts, time roots, and ambiguity (`store`, `fusefs`, `cmd`) — implemented

- `mount --context NAME|weft://...` resolves the Context Root with the mount
  capability and root principal, then serves its ordered result set as the
  read-only mount root. Entry names are the existing escaped
  `basename--<8+ hex ObjectId>` scheme; one helper feeds readdir and lookup.
  The constant `.weft` exact-id surface remains; all mutations are `EROFS`.
- `mount --at RFC3339|unix-ns` selects the newest commit at or before the time
  in the base lineage (`Store.CommitAtOrBefore`). No match is `NotFound`; it
  never substitutes a state. `--context` + `--at` is rejected.
- Read-only opens take no writer lock. The test suite mounts three different
  roots concurrently and then opens a writer successfully; the pinned mount
  does not observe the later commit.
- `RequireOne` re-evaluates unpaged and includes every competing ObjectId in
  the `Ambiguous` message. `context materialize --require-one` fails before
  creating any output path.
- Replay: Go extracts a Rust-produced bundle with `tar`/`zstd`, opens the
  store, runs `verify --full`, resolves/materializes every Context Root, and
  runs `scripts/replay/verify_manifest.go` (stdlib only) to compare every store
  entry and output hash with `manifest.json`. No Rust runs at Go replay time.
- Evidence: `go test -race ./...` passes in the FUSE court, including
  `TestContextMountListsAllResultsAndReadsExactBytes`,
  `TestCapabilityScopedMountIsReadOnlyAndDeniesUnlistedRoots`,
  `TestAtSelectsLatestCommitAndBeforeFirstFails`,
  `TestThreeSimultaneousMountsServeDifferentRoots`, and
  `TestRequireOneAmbiguityListsEveryCompetingObjectID`.

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

- **Online/background GC.** GC is an explicit CLI/API pass, never a daemon.
  No persisted mark record is kept; each run recomputes reachability from
  roots, which makes an interrupted sweep recoverable by re-running. A
  concurrent reader is not consulted; safety comes from the writer lock plus
  immutable content addressing.
- Multi-writer concurrency (v1 is single-writer by design; the lock refuses a
  second writer).
- `atime`/`ctime` persistence. `Getattr` mirrors the stored mtime for both;
  `setattr` ignores `FATTR_ATIME`/`FATTR_CTIME`.
- `mmap` writeback. Writable handles are write-through; read handles request
  direct I/O so one read is served from one immutable content root.
- Performance measurements: the frontend makes no throughput or latency claim.
  The only measurement recorded here is the bounded-open comparison in §2.8,
  which is an open-path microbenchmark, not a filesystem performance claim.

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
reported **31 top-level tests passed** (23 in `store`, 8 in `fusefs`) plus
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

Checkpoint acceptance is asserted, not assumed: the tests fail if either side
emits a recovery note containing `checkpoint` (the note Rust/Go produce when a
checkpoint is unreadable or declares the wrong generation). Gate 3 additionally
forces a Rust checkpoint each round and asserts that Go's next open carries no
checkpoint-ignore note.

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
- `TestEscapeComponentMatchesRustRules` and
  `TestContextNamesExtendPrefixOnCollision` — unit tests that pin the escaping
  table (including `%`, `/`, control bytes, non-UTF-8, empty, `.`/`..`) and the
  8→16 hex prefix extension when two results share a basename and an 8-hex
  prefix.

### 2.7 Go garbage collection: commands, results, and handoff

All runs used the FUSE court (it carries both toolchains and `/dev/fuse`).

```sh
cd /mnt/1tb_kingston/WeftFS
scripts/docker-court.sh fuse \
  "cd WeftFS-Go && go test -race ./store -run 'TestGC' -count=1 -v"
```

Observed (the full suite in §2.2 was also re-run after this work: `store`
`ok 1.520s`, `fusefs` `ok 1.145s`; `gofmt -l .`, `go vet ./...`, and
`CGO_ENABLED=0 go build ./...` were clean):

- **13 GC tests passed**, **1 intentional helper skip**
  (`TestGCRejectedTailChild`, re-executed by `TestGCRejectedTailKeepsCheckpoint`),
  and **2 subtests passed** (`TestGCHandoffKilledGoCommit/after_commit_file`,
  `.../after_superblock_write`).
- `TestGCReclaimsUnreferencedBlobAndKeepsSnapshot`: dry run listed 2 candidates
  and deleted 0; apply then removed the unreferenced manifest and chunk;
  snapshot content stayed byte-exact and live content remained readable;
  `verify --full` was clean.
- `TestGCGraceWindow`: with `gc_grace_secs=3600` a fresh unreachable blob was
  retained (`grace_retained > 0`, `deleted_files=0`); after `0`, apply removed
  it.
- `TestGCRetainsAndSweepsPinnedContent`: a pinned manifest/chunk was not a
  candidate and remained readable; after unpin it was swept and the content
  read failed.
- `TestGCRemovesOrphanRecordsLeftByACrash`: an unlinked record kept alive only
  by a process-local pin survived close/reopen, then `GC(true)` removed the
  record in a new commit (`removed_orphans` named it), swept its blobs, and
  `verify --full` was clean.
- `TestGCRejectedTailKeepsCheckpoint`: a valid but unpublished tail commit
  (SIGKILL at `after_commit_file`) carried a checkpoint. Apply swept
  checkpoint-free garbage but retained the tail checkpoint manifest, the tail
  file manifest, and every tail chunk. The tail stayed invisible, the head did
  not move, a later commit published generation 5, and `verify --full` was
  clean with the tail checkpoint still parseable.
- `TestGCNeverSweepsFixtureReachability`: every manifest/chunk named by
  `EXPECTED.json` and by the fixture snapshot states survived dry run and
  apply; `verify --full` stayed clean.
- `TestGCInterruptedSweepIsRecoverable`: after one candidate was deleted by
  hand (simulating a killed sweep), the next pass recomputed roots, removed
  the remainder, and verified clean. No persisted mark record is trusted.
- `TestGCSweepSkipsSymlinksAndNonRegularEntries`: symlink and directory
  entries with valid 64-lowercase-hex blob names were never candidates; a
  symlink target outside the store was untouched; exactly the one regular
  unmarked file was deleted. Paths are `Lstat`-checked.

CLI smoke run (exact commands in the court, store at `/tmp/gcstore`; output
abridged):

```sh
weftfs --store /tmp/gcstore gc --grace-secs 0            # dry run
weftfs --store /tmp/gcstore gc --apply --grace-secs 0
weftfs --store /tmp/gcstore --json gc --grace-secs 0
weftfs --store /tmp/gcstore verify --full
```

Observed: dry run `applied=false unreachable_files=2 unreachable_bytes=171
deleted_files=0`; apply `deleted_files=2 deleted_bytes=171`;
the next run `unreachable_files=0`; `verify --full` `ok=true generation=6`;
`cat /keep.txt` returned `LIVE-CONTENT-123`. With the default grace in the
same smoke store, the first run reported `unreachable_files=0
grace_retained=2 retained=6`, proving the age gate. JSON output used
lowercase keys and empty arrays for empty candidate/deleted/problem sets.

Cross-language GC handoff (Rust binary is a test oracle only):

| Gate | Observed |
|---|---|
| A. Rust store + snapshot + unreferenced blob → Go `gc --apply` | Go dry run listed the blob, apply deleted it; Rust `verify --full` `ok=true`, Rust `cat /keep.txt` and a Rust snapshot mount read returned the exact pre-snapshot bytes; Go snapshot read also exact |
| B. Go store + snapshot + garbage → Rust `gc --apply --grace-secs 0` | Rust reported `applied=true`; Go-created garbage manifest/chunk were gone; the snapshot-only chunk survived; Rust and Go `verify --full` clean; snapshot and live reads exact |
| C. Three alternating generations with GC between | Go wrote/GC’d, Rust wrote/GC’d, Go wrote/GC’d; after every round the stable ObjectId, VersionId, ContentId, and snapshot commit were unchanged, snapshot/live bytes were exact, and both `verify --full` runs were clean |
| D. SIGKILL during Go commit → Go GC → Rust verify | `after_commit_file`: the tail’s chunk was swept, the tail stayed invisible, Rust `verify --full` reported only `commit file for generation 2 exists above the highest published superblock generation 1`. `after_superblock_write`: the chunk survived, Rust `verify --full` was `ok=true`, and Rust read the killed commit’s exact bytes |

### 2.8 Bounded open replay and the fast-open bench (2026-11-04)

Code revision WeftFS-Go `1461c04` (measured); parent `8c112de`. Court
`weft/fuse-court:1` (tests) and `weft/go-court:1` (bench), kernel
`7.3.1-1-cachyos`, hard limits `--memory=3g --memory-swap=3g
--pids-limit=1024 --cpus=4`, bounded `/tmp` (1 GiB).

```sh
# new courts
scripts/docker-court.sh go "cd /work/WeftFS-Go && go test -race -count=1 ./store -run 'TestFastOpen|TestCorruptedChains|TestOpenStopsAt' -v"
scripts/docker-court.sh fuse "cd /work/WeftFS-Go && go test -race -count=1 ./..."
# bench (100,000 generations, checkpoint interval 256)
scripts/docker-court.sh go "cd /work/WeftFS-Go && go build -o /work/.docker-cache/go-tmp/openbench ./cmd/openbench && /work/.docker-cache/go-tmp/openbench --generations 100000 --samples 5 --work-dir /tmp/weft-go-open-bench --out /work/bench/receipts/go-fast-open-20261104T190732Z.json"
```

Observed:

- `store` fast-open courts: 4/4 pass. The 2,000-generation store opens in the
  head-to-checkpoint window (≤ 130 commit decodes), returns exactly one note
  naming generation 1920, and matches the full-scan oracle in generation, head,
  objects, entries, relations, snapshots, and tips. The forced full path decodes
  ≥ 2,000 commits. Deleting, corrupting, truncating, and mislabelling commits,
  and removing the checkpoint manifest, each fall back with a note and match the
  full oracle; no case produced a shorter state.
- Full suite: `go test -race -count=1 ./...` → 101 PASS / 2 SKIP / 0 FAIL
  (the 2 skips are the existing child-process helper guards). `TestHandoff`
  checkpoint gates pass unchanged, including `TestHandoffCheckpointsBothWays`.
- Bench receipt `bench/receipts/go-fast-open-20261104T190732Z.json` in the
  program-home repo: 100,000 generations, 9 objects, 8 entries, 1 relation,
  1 snapshot; store apparent bytes 47,585,212, allocated bytes 411,287,552
  (fits the 1 GiB `/tmp`); build 2.962 s; peak RSS 243,484 KiB.

| Path | Commit files read | Open wall ms (5 runs) | Median | p95 |
|---|---|---|---|---|
| `store.Open(ReadOnly)` (bounded) | 162, 162, 162, 162, 162 | 2.80, 2.69, 2.72, 4.14, 3.48 | **2.80 ms** | 4.14 ms |
| `OpenFullScanForBench` (full scan) | 100,001 × 5 | 2093.34, 2155.65, 2174.52, 2181.77, 2148.18 | **2155.65 ms** | 2181.77 ms |

Both paths recovered identical state (`state_match=true`). The fast path read
161 window commits plus one head load. The payload is identical for every
generation, so content blobs deduplicate and the store is one commit file per
generation; the commit chain and replay work are real. This is a synthetic,
single-host, tmpfs, page-cache measurement — not a device, fleet, power-loss, or
production claim. No court limit was raised for this run.

---

## 3. Known limitations and honest gaps

1. **Normal GC is explicit; the online collector is opt-in.** Collection is
   `store.GC`/`GCBounded`/`GCWatch` or `weftfs gc` under the exclusive writer
   lock. `mount --gc-watch` runs the same bounded pass under the FUSE server
   mutex; it is disabled by default. There is no persisted mark record: every
   run recomputes roots, so an interrupted sweep is recovered by re-running.
   A separate long-lived reader pinned to a pre-snapshot commit is not a GC
   root; use snapshots (which are roots) or the grace window.
2. **Same-inode concurrent direct read/write is not claimed.** The parent
   project records a kernel EIO issue for that pattern in
   `docs/fuse-status.md`. This implementation tests concurrent traffic on
   separate files and store-level atomicity, not the same-inode pattern.
3. **Live context display names are not frozen per directory handle.** They
   are recomputed from the current paths, so a concurrent commit/rename can
   change a name between readdir and lookup on a live mount. Snapshot mounts
   are immutable and always agree. The Rust frontend freezes the listing at
   `opendir`; this is a fidelity difference for live mounts only.
4. **Verb limits are documented, not hidden.** `ioctl` is not implemented
   (go-fuse answers `ENOTTY`). `mknod` accepts regular files only; FIFO,
   socket, and device nodes are `EPERM` because v1 has no such object kind.
   `COLLAPSE_RANGE`/`INSERT_RANGE` are implemented in the store and directly
   tested, but the 7.3.1 FUSE kernel boundary rejects them before sending
   `FUSE_FALLOCATE`; the mount test records that precise refusal. `PUNCH_HOLE`
   and `ZERO_RANGE` define content but do not reclaim physical chunks (dense
   v1 files). Locks are advisory, in-memory, and per-mount-process; they do
   not coordinate independent daemons or hosts.
5. **atime/ctime** are not stored; getattr mirrors mtime. `setattr` applies
   mode/uid/gid/mtime/size only.
6. **`write` is whole-file rematerialisation** in v1 (`WEFT-MODEL.md` §3), so a
   write is O(file size) and bounded at 1 TiB (matching Rust `MAX_FILE_BYTES`).
   This is the normative v1 behaviour, not an optimization; a random write to a
   multi-GiB file allocates the whole file in the Go process. Reads can open and
   read Rust-written files above 256 MiB (the format is unchanged).
7. **No hardware power-loss court.** Crash evidence is a process-fault proxy.
8. **Module replacement.** The committed `go.mod` uses
   `replace ... => ../WeftCodec-Go` for the monorepo. The standalone repository
   must switch to a versioned requirement; no on-disk behavior depends on it.
9. **Court write permissions.** The court runs as uid 0 with `cap-drop=ALL`, so
   `go mod tidy` needs `go.mod`/`go.sum` to be writable by the container. The
   committed `go.sum` is complete; `go build`/`go test` run without modifying
   it.
10. **No acceleration in F3.** Context mounts and time travel are correctness
    paths only. There is no io_uring, EKBLOOM, or equivalent; none is claimed.
11. **Replay bundles are whole-store and unsigned.** No partitioned subset,
    remote fetch, or signature exists. `tar`/`zstd` are required tools.

## F5 — participation in the proof courts (2026-11-03)

No WeftFS-Go code changed for F5. The independent Go store/FUSE implementation
is exercised as a writer and reader in both F5 FUSE courts:

- `bench/scripts/posix_torture.sh`: three seeds in both directions; the Go
  frontend writes and the Rust frontend verifies/remounts, and vice versa.
  Exact state (names, types, modes, uid/gid, nlink, mtime, content sha256,
  symlinks, xattrs) matched in all six runs; 13,694 operations total.
- `bench/scripts/crash_torture.sh`: 1,000 alternating Rust/Go writer/reader
  iterations through `WEFT_CRASH_PHASE`; every observed state was the old or
  new whole file, never partial.

Receipts: `bench/receipts/posix-torture-20261103T213317Z.json` and
`bench/receipts/crash-torture-20261103T213446Z.json`. The crash court is a
process-fault proxy, not physical power loss.

---

## F8 — FUSE verb closure and online GC (2026-11-03)

Base revision WeftFS-Go `73a671930b504fd2913887f703d5efa02d591bd8` (parent
`49a3bad899a376fb6da89e6f1cd6e2eaf201c19e`); WeftCodec-Go is the path-replaced
module at `ce2cff9283c2ccb841ee27ea5415ef3cb4691c6a`. The final revision is the
`staging` commit carrying this file; no result below depends on a later tree.

### 1. FUSE verbs implemented in this pass

- `getlk`/`setlk`/`setlkw`: an in-memory advisory manager for POSIX byte ranges
  (including partial unlock/split and cross-owner conflict) and flock
  (whole-file, separate namespace) with `EnableLocks` so the kernel forwards
  both. `Setlkw` waits on a per-object broadcast channel and returns `EINTR`
  when the FUSE request is cancelled. Owners observed on a handle are released
  when that handle is released. Read-only/snapshot mounts permit read locks and
  refuse write locks with `EROFS`; virtual views never hold locks.
- `mknod`: regular files (`S_IFREG`) only. FIFO, socket, character, and block
  devices are `EPERM` because v1 has no such object kind (no silent degradation
  to a regular file). Read-only mounts return `EROFS`.
- `tmpfile`: `O_TMPFILE` creates an unnamed file object, pins it for the handle,
  supports write/read, links through `/proc/self/fd` with `AT_SYMLINK_FOLLOW`,
  and removes the record in one commit when the last handle closes unlinked.
- `fallocate`: mode 0, `KEEP_SIZE`, `PUNCH_HOLE` (requires `KEEP_SIZE`),
  `ZERO_RANGE` (with/without `KEEP_SIZE`), `COLLAPSE_RANGE`, and `INSERT_RANGE`
  are implemented. Mode 0 extends with zeros without touching existing bytes.
  Dense v1 files mean `PUNCH_HOLE`/`ZERO_RANGE` zero content but do not reclaim
  physical chunks; this is stated rather than claimed as space reclamation.
  Unknown modes are `EOPNOTSUPP`; zero length is `EINVAL`; ranges past the
  1 TiB v1 bound are `EFBIG`.
- `copy_file_range`: daemon-side copy for regular objects, `flags != 0` is
  `EINVAL`, source ACL and destination write authorization are checked,
  read-only/snapshot destinations are `EROFS`, and a short copy at EOF or at
  the 1 TiB bound returns the copied length.
- `lseek`: `SEEK_DATA` returns the offset for a dense file and `ENXIO` at/after
  EOF; `SEEK_HOLE` returns the file size (the only hole) and `ENXIO` past EOF;
  `SEEK_SET` is answered directly; `SEEK_CUR`/`SEEK_END` answer `ENOSYS` if the
  kernel ever forwards them.
- `ioctl` was not needed and remains unimplemented; go-fuse answers `ENOTTY`.

### 2. Online/background GC

`store.GCBounded(apply, maxDeletes)` performs one mark-and-sweep pass and
deletes at most `maxDeletes` candidates. Marking is still O(reachable); the
sweep is the bounded unit. Cancellation is checked during marking, snapshot and
checkpoint expansion, directory scans, and between deletions; a cancelled pass
leaves only already-deleted unreachable blobs, never a partial reachable set.

`store.GCWatch(ctx, interval, maxDeletes, onPass)` is the standalone/CLI
collector. It requires the exclusive writer lock, applies each pass, honors
`GCGraceSecs`, and returns `nil` on cancellation. `weftfs gc --apply --watch`
requires the explicit `--apply` (the collector is disabled by default).

`fusefs.Server.StartBackgroundGC` is the in-mount collector. `mount --gc-watch`
sets `GCBackground`, `GCIntervalSecs`, and `GCWatchMaxDeletes` on the store; a
writable live mount starts it after `fs.Mount`, and every pass takes the same
`srv.mu` as all FUSE requests. It is not started for read-only, snapshot,
context, `--at`, or capability mounts. `StopBackgroundGC` is idempotent and is
also called from the root inode's `OnForget` during unmount, so no pass can
touch the store after close.

Safe use: the writer lock serializes writers; snapshots, checkpoints, current
state, and in-process object/content pins are roots. A separate reader pinned
to a historical commit that is not a snapshot is not a root, so use snapshots
or the grace window for long-lived historical readers.

### 3. Exact court commands and observed results

```text
scripts/docker-court.sh go "cd /work/WeftFS-Go && gofmt -l . && go vet ./... && CGO_ENABLED=0 go build ./..."
  -> clean: gofmt listed no files; go vet and CGO-disabled build completed 0.

scripts/docker-court.sh fuse "cd /work/WeftFS-Go && go test -race -count=1 -v ./..."
  -> 74 passed, 2 skipped, 0 failed.
     fusefs 6.503 s, store 1.893 s.
     Skips are the pre-existing child-process guards TestCrashChildProcess and
     TestGCRejectedTailChild (they require an explicit helper environment).
     New passes: TestMknodRegularFilesOnly, TestTmpfileWriteLinkAndRelease,
     TestFallocateModesOnDenseFiles, TestCopyFileRangeServerSide,
     TestLseekDataAndHole, TestByteRangeAndFlockLocks,
     TestBackgroundGCDuringReadsAndWrites,
     TestBackgroundGCPreservesSnapshotAndOpenHandle,
     TestGCBoundedRespectsDeletionBudgetAndConverges,
     TestGCWatchCancellationAndPassBudget, TestGCWatchRequiresWriterLock,
     TestGCWatchPreservesPinnedContentAndSnapshot,
     TestGCBoundedInterruptedPassConverges,
     TestCollapseInsertAndZeroRangeStoreLevel,
     TestGCHandoffGoBackgroundWatchRustVerifies.

CLI watch smoke (Go court, no host execution):
  weftfs --store DIR init
  weftfs --store DIR create /gone.txt --text garbage-background-watch
  weftfs --store DIR unlink /gone.txt
  timeout --preserve-status -s TERM 1 weftfs --store DIR gc --apply --watch \
    --interval 100ms --max-deletes 1 --grace-secs 0
  -> pass deleted_files=1 remaining_files=1; pass deleted_files=1
     remaining_files=0; later passes deleted_files=0; SIGTERM exit 0.
  weftfs --store DIR gc --dry-run --grace-secs 0 -> unreachable_files=0
  weftfs --store DIR verify --full -> ok=true, full=true, generation=3

Cross-language after GC: TestGCHandoffGoBackgroundWatchRustVerifies creates a
Rust store with a snapshot and unreachable blob, runs the Go watch loop to
deletion, then requires Rust verify --full, Rust cat of the live file, and a
Rust --snapshot mount read of the pinned snapshot bytes. Existing gates A-D
(Rust→Go, Go→Rust, alternating generations, SIGKILL tail) still pass in the
same suite. The Rust binary is a test oracle only; no Go production path
invokes Rust.
```

### 4. Precise blocked or limited verbs

- **COLLAPSE_RANGE / INSERT_RANGE at the mount boundary.** The daemon and store
  implement both and `TestCollapseInsertAndZeroRangeStoreLevel` proves the
  semantics. On the court kernel 7.3.1, `unix.Fallocate(fd, 0x08, 1, 2)`
  returns `EOPNOTSUPP` and go-fuse debug showed **no `FUSE_FALLOCATE` frame**
  after the preceding successful modes. The mount test therefore accepts
  `EOPNOTSUPP` only for this boundary and fails on any other error. If a future
  kernel forwards the mode, the existing handler path is exercised.
- **PUNCH_HOLE without KEEP_SIZE.** The daemon returns `EINVAL` if reached; this
  kernel returns `EOPNOTSUPP` before forwarding. The test accepts either and
  documents both.
- **ioctl.** No command needed it; go-fuse's default is `ENOTTY`.
- **Lock release on close.** FUSE reveals a POSIX lock owner only on lock
  requests, not at open. A descriptor that never acquired a lock cannot release
  the process's locks on that file (POSIX close-any-fd semantics). Owners seen
  on a handle are released at handle release, and explicit `F_UNLCK` always
  works. Locks are per-daemon; independent mounts/hosts are not coordinated.
- **Physical space.** `PUNCH_HOLE`/`ZERO_RANGE` are content semantics only on
  dense v1 files. No `st_blocks` reclamation or sparse-extent format exists.
- **atime/ctime** are still not stored; `mmap` writeback is not implemented.

### 5. Remaining gaps

1. Kernel-forwarded COLLAPSE/INSERT and a sparse/chunk-freeing `PUNCH_HOLE`
   require a newer/changed FUSE boundary and an on-disk sparse-extent design;
   neither is claimed.
2. Locks do not coordinate separate daemons or hosts, and the close-any-fd
   release limitation above remains.
3. The online collector is opt-in; default GC is still an explicit pass.
   Long-lived readers pinned to non-snapshot historical commits are outside the
   root set.
4. `ioctl`, `mmap` writeback, atime/ctime persistence, and a physical
   power-loss court remain out of scope for this pass.

## P5a — write budgets and branching time travel

Parity with the Rust store; normative layout in `spec/WEFT-QUOTA.md`.

- **Budgets.** `--quota uid:GID:BYTES:OBJECTS` / `--quota-file FILE` install a
  persisted admission policy. Before `publishCommit`, `quotaPreflight` charges
  new/changed object records plus manifest/frame/chunk blobs not already
  reachable from committed state and refuses the commit with
  `BudgetExceeded: write budget exceeded` when any budget would be exceeded.
  Nothing is published; generation, head, and state are unchanged. Denial text
  is fixed and never discloses usage, limits, or another principal.
- **Usage storage.** The store-root `quota` file (`WFQ1 || u64le len || WCB ||
  BLAKE3("weft/quota/v1", WCB)`) is byte-identical to the Rust record. It names
  the committed generation/head; a mismatch or a decode failure makes writes
  fail closed (`Corrupt`) and is reported by `verify`. `quota rebuild`
  recomputes usage from the published commit chain, `quota reset` zeroes
  counters, and `quota show` returns only the caller's own counters. If the
  record is unusable and no policy is known, rebuild is refused (re-supply
  `--quota`) instead of silently disabling enforcement.
- **Branching.** `snapshot branch` adds a ref to an immutable commit;
  `context branch` persists a Context Root pinned to the source root's fork
  commit with `derived_from` lineage; `merge` is a union merge that fails with
  `Conflict` naming the path when the same path has different content (or the
  live head already has different content). It never overwrites the head.
- **Tests.** `store/quota_test.go` (7) and `store/branch_test.go` (7, including
  both cross-language directions with the Rust oracle). Full `go test -race
  ./...` passes in the fuse court; `go vet` and `CGO_ENABLED=0 go build` pass in
  the Go court.
- **Limits.** Admission budgets do not return budget on deletion. Tenant
  attribution requires the `weft.tenant` attribute (`create --tenant`); the
  FUSE write path does not set it yet. Merge is not a three-way content merge.
