# WeftFS overlay fixture v1

Append-only. Regenerate (into an empty directory) with:

```
cargo run --release --example gen_overlay_fixture -- <empty-output-dir>
```

The store contains three files at a fixed 8-byte chunk size:

| path | representation |
|---|---|
| `/base` | `weft.manifest.v3` raw chunk table |
| `/overlay` | `weft.manifest.v4`, depth 1, one extent replacing chunk 1 |
| `/nested` | `weft.manifest.v4`, depth 2, one extent replacing chunk 3 |

`EXPECTED.json` records each object's content root, exact logical bytes
(hex), and the base/overlay/nested chunk lists.

There is no v4 write path in this subphase: the generator builds the chunk
blobs and canonical manifests by hand and republishes them through the store's
test hook. The Rust test `tests/overlay_fixture.rs` and the Go test
`store/overlay_handoff_test.go` read and verify this same directory. A
correction must add a new fixture version directory; existing files are never
edited.
