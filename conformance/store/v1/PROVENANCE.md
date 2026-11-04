# Fixture provenance

These files are a byte-for-byte copy of the Rust-generated conformance store
fixture in the program home repository:

- Source: `infinityabundance/WeftFS`, path `conformance/store/v1/`
- Generator: Rust `weftfs (Rust) 0.1.0` P4
- Generator revision (recorded by the fixture itself):
  `61b11a802f3475ecb1723b5c54cb83f49e465f8a`
- Copy note: copied without editing, regenerating, or "fixing" any byte.
  New directories in this repository cannot represent empty directories, so
  `refs/tags/.gitkeep` and `tmp/.gitkeep` are zero-byte placeholders that were
  already present in the source fixture. `LOCK` is a zero-byte file.

Integrity of the copy: over all files except this note, in sorted path order,
`sha256sum` of the `sha256sum` listing is

```
ac73419fb4070c442fec14a960997c10821cd0cea0d92d9180cbf52040a0013e
```

`EXPECTED.json` is the handoff contract: format version, generation, snapshot
root, object/version/content identities, paths, relation ids, exact file
content hashes, and selector results. Tests must copy this directory to a
temporary location before mutating it; the frozen fixture is never written in
place.
