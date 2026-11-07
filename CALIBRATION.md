# Go decode-cost calibration (`weftfs calibrate`)

Host-local measurement only: these numbers describe one container on one host.
They are **not** portable constants and are not a cross-machine or cross-language
performance claim.

## Method

`weftfs calibrate` builds one frame per representation and payload size with the
shipped `WeftCodec-Go` encoders, then times the shipped decoder for every
repetition:

| class | encoder | decoder |
| --- | --- | --- |
| raw | `modes.EncodeRaw` | `modes.DecodeBytes` |
| zstd | `modes.EncodeZstd` (level 3, 64 KiB chunks) | `modes.DecodeBytes` |
| float-tensor (mode 9) | `modes.EncodeFloatTensor` (bf16) | `modes.DecodeFloatTensorFrame` |
| tensor-sharded (mode 10) | `modes.EncodeShardedTensor` (one q8_0 shard) | `modes.DecodeShardFrame` |
| tensor-tiled (mode 15) | `modes.EncodeTiledTensor` (bf16, tile 32x256) | `modes.DecodeTiledTensor` |
| weight-delta (mode 11) | `modes.EncodeWeightDelta` over a mode-6 base | `modes.DecodeWeightDeltaFrameWithBase` |
| semantic-delta (mode 14) | `modes.EncodeSemanticDelta`, `mantissa_truncate:3` | `modes.DecodeSemanticDeltaFrameWithBase` |

- Two sizes, `reps` samples each, median per size, one warm-up decode.
- Delta rows are **incremental**: the median decode cost of the same mode-6
  base frame is measured with the same repetition count and subtracted.
- Fit: `fixed_ns + ns_per_mib * decoded_bytes / 1048576` through the two
  medians, with Rust's arithmetic and rounding.
- `sparse-delta` copies the measured `weight-delta` row (origin `reused`).
  `kv-cache` and `activation` keep the historical declared rows (origin
  `declared`); the Go store produces neither.
- Payloads are the Rust calibration payloads (weight-like BF16, q8_0 bytes,
  low-bit nudge, 3-bit mantissa clear).

The Rust reference measures through the store; Go measures at the codec frame
layer because the Go store has no mode-15 or mode-14 writer and a mixed method
would make rows incomparable. Consequently the divergence against the baked
Rust table below is a statement about method and machine, not about relative
implementation speed.

## Environment

- `weft/go-court:1`, image id `sha256:ace88700bc27c45294a8d9d808ee163bbe888f35354ef9dea237b362c026f166`
- kernel `7.3.1-1-cachyos`, 4 CPUs, 3 GiB, pids 1024, bounded `/tmp`
- WeftFS-Go staging at the revision that carries this file (see the commit)

## Default run (7 reps, 128 KiB and 16 MiB)

```
$ scripts/docker-court.sh go "time /work/.docker-cache/go-tmp/weftfs-go \
    calibrate --json --out /work/.docker-cache/go-tmp/go-calibration-default.json"
real 0m4.422s
calibration_id 7eafbb1a29016ef221c014a5cb16f194243a788f93a49579e763e72dc1b596f6
```

| class | origin | fixed_ns | ns_per_mib | samples | 1 MiB estimate vs baked measured |
| --- | --- | --- | --- | --- | --- |
| raw | measured | 0 | 819494 | 14 | +157.075% |
| zstd | measured | 0 | 1115176 | 14 | +39.193% |
| float-tensor | measured | 0 | 2837430 | 14 | -39.655% |
| tensor-sharded | measured | 72267 | 3475654 | 14 | -61.180% |
| tensor-tiled | measured | 23215 | 4828817 | 14 | +43.513% |
| weight-delta | measured | 0 | 6003877 | 14 | +12.755% |
| sparse-delta | reused | 0 | 6003877 | 0 | +12.755% |
| semantic-delta | measured | 17442 | 7206540 | 14 | +11.302% |
| kv-cache | declared | 100000 | 1048576 | 0 | 0.000% |
| activation | declared | 100000 | 1048576 | 0 | 0.000% |

A `fixed_ns` of 0 means the affine fit through the two medians produced a
non-positive intercept; it is clamped to zero exactly as Rust does.

## Reproducibility check (minimum sizes, two runs)

At 5 reps, 64 KiB / 8 MiB, two back-to-back runs produced the same schema,
classes, origins and sample counts; the worst `ns_per_mib` drift was 11.1%
(raw) and the worst `fixed_ns` drift was 57,648 ns. The test tolerance is
therefore stated as 25% on `ns_per_mib` and max(100%, 150 µs) on `fixed_ns`.
Declared rows are identical by construction; reused rows move with
`weight-delta`.

## Installing a document

`weftfs calibrate --install --store DIR` (or `--from FILE --install`) validates
the document through the same strict loader and atomically writes it to
`DIR/calibrations/<calibration_id>.json` (temporary file, `fsync`, `rename`,
directory `fsync`). Re-installing the same document is idempotent because the
file name is the content digest. The directory is advisory and is ignored by
replay, verify, and GC, exactly as in Rust. An installed document is consumed
explicitly:

```
weftfs --calibration DIR/calibrations/<id>.json --planner-cost-model measured \
    write --tensor ... --lambda-ns N
```

A malformed document fails the loader before anything is written, so
`calibrations/` is not even created. `--install` requires a local `--store`; a
remote plane is refused.

## Non-claims

- Not a cross-machine constant. Re-run `weftfs calibrate` on the target host.
- Not comparable row-for-row with `examples/calibrate_decode.rs`: that harness
  measures store reads, this one measures codec frame decodes.
- The measurement is single-threaded and warm-cache.
- No claim about mode 12/13 (never produced) or about any representation the
  Go store cannot write.
