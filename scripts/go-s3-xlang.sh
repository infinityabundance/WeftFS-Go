#!/usr/bin/env bash
# Bidirectional cross-language check on one MinIO bucket set.
#
# Runs inside the Go court (the Rust CLI is a mounted release binary). Both
# directions use the *same* logical key layout, so this proves the two
# implementations publish and read one format rather than two:
#
#   A. Go writes init/files/snapshot -> Rust verifies --full, reads bytes, and
#      reports the same head.
#   B. Rust writes init/files -> Go verifies --full, reads bytes, and reports
#      the same head. Go then unlinks a file, runs GC, and Rust verifies again.
#
# Every check prints `XLANG: ...` and exits non-zero on the first failure.
set -Eeuo pipefail

: "${WEFT_S3_TEST_ENDPOINT:?WEFT_S3_TEST_ENDPOINT is required}"
: "${WEFT_XLANG_GO_BIN:?WEFT_XLANG_GO_BIN is required}"
: "${WEFT_XLANG_RUST_BIN:?WEFT_XLANG_RUST_BIN is required}"

region="${WEFT_S3_REGION:-us-east-1}"
access="${WEFT_S3_ACCESS_KEY:-weftcourt}"
secret="${WEFT_S3_SECRET_KEY:-weftcourt-secret}"
prefix="${WEFT_XLANG_PREFIX:-weft-go-xlang}"
go_bucket="${prefix}-xlgo"
rust_bucket="${prefix}-xlrust"

go_common=(--backend s3 --s3-endpoint "$WEFT_S3_TEST_ENDPOINT" --s3-region "$region"
  --s3-access-key "$access" --s3-secret-key "$secret")
rust_common=(--backend s3 --s3-endpoint "$WEFT_S3_TEST_ENDPOINT" --s3-region "$region"
  --s3-access-key "$access" --s3-secret-key "$secret")

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

head_of() {
  grep -o '"snapshot_root": "[0-9a-f]*"' | sed 's/.*: "//;s/"$//'
}

go_run() { "$WEFT_XLANG_GO_BIN" "${go_common[@]}" "$@"; }
# No --store is passed: an all-S3 store is addressed by bucket, and the Go CLI
# accepts an empty store directory exactly when a plane is remote.
rust_run() { "$WEFT_XLANG_RUST_BIN" "${rust_common[@]}" "$@"; }

printf 'hello from the Go implementation\n' > "$work/from-go.txt"
head -c 70000 /dev/urandom > "$work/binary-go.bin"
printf 'hello from the Rust implementation\n' > "$work/from-rust.txt"
head -c 70000 /dev/urandom > "$work/binary-rust.bin"

echo "XLANG: direction go->rust bucket=$go_bucket"
go_run --s3-bucket "$go_bucket" init >/dev/null
go_run --s3-bucket "$go_bucket" create /from-go.txt --file "$work/from-go.txt" >/dev/null
go_run --s3-bucket "$go_bucket" create /binary-go.bin --file "$work/binary-go.bin" >/dev/null
go_run --s3-bucket "$go_bucket" snapshot create s1 >/dev/null
go_verify="$(go_run --s3-bucket "$go_bucket" --json verify --full)"
grep -q '"OK": true' <<<"$go_verify"
echo "XLANG: go verify --full ok"
go_head="$(go_run --s3-bucket "$go_bucket" --json info | head_of)"
echo "XLANG: go head $go_head"

rust_run --s3-bucket "$go_bucket" verify --full >/dev/null
echo "XLANG: rust verify --full on the Go-written store ok"
rust_head="$(rust_run --s3-bucket "$go_bucket" --json info | head_of)"
[[ "$rust_head" == "$go_head" ]]
echo "XLANG: rust reports the same head $rust_head"
rust_run --s3-bucket "$go_bucket" cat /from-go.txt > "$work/rust-read-go.txt"
cmp "$work/from-go.txt" "$work/rust-read-go.txt"
echo "XLANG: rust cat byte-exact on the Go-written file"
rust_run --s3-bucket "$go_bucket" cat /binary-go.bin > "$work/rust-read-go.bin"
cmp "$work/binary-go.bin" "$work/rust-read-go.bin"
echo "XLANG: rust cat byte-exact on the Go-written 70,000-byte file"

echo "XLANG: direction rust->go bucket=$rust_bucket"
rust_run --s3-bucket "$rust_bucket" init >/dev/null
rust_run --s3-bucket "$rust_bucket" create /from-rust.txt --file "$work/from-rust.txt" >/dev/null
rust_run --s3-bucket "$rust_bucket" create /binary-rust.bin --file "$work/binary-rust.bin" >/dev/null
rust_run --s3-bucket "$rust_bucket" verify --full >/dev/null
echo "XLANG: rust verify --full ok"
rust_head="$(rust_run --s3-bucket "$rust_bucket" --json info | head_of)"
go_head="$(go_run --s3-bucket "$rust_bucket" --json info | head_of)"
[[ "$go_head" == "$rust_head" ]]
echo "XLANG: go reports the same head $go_head"
go_verify="$(go_run --s3-bucket "$rust_bucket" --json verify --full)"
grep -q '"OK": true' <<<"$go_verify"
echo "XLANG: go verify --full on the Rust-written store ok"
go_run --s3-bucket "$rust_bucket" cat /from-rust.txt > "$work/go-read-rust.txt"
cmp "$work/from-rust.txt" "$work/go-read-rust.txt"
echo "XLANG: go cat byte-exact on the Rust-written file"
go_run --s3-bucket "$rust_bucket" cat /binary-rust.bin > "$work/go-read-rust.bin"
cmp "$work/binary-rust.bin" "$work/go-read-rust.bin"
echo "XLANG: go cat byte-exact on the Rust-written 70,000-byte file"

# Cross-language maintenance: Go unlinks and collects on the Rust-written store,
# then Rust verifies the result.
go_run --s3-bucket "$rust_bucket" unlink /from-rust.txt >/dev/null
go_run --s3-bucket "$rust_bucket" gc --apply --grace-secs 0 >/dev/null
go_verify="$(go_run --s3-bucket "$rust_bucket" --json verify --full)"
grep -q '"OK": true' <<<"$go_verify"
echo "XLANG: go gc --apply + verify --full on the Rust-written store ok"
rust_run --s3-bucket "$rust_bucket" verify --full >/dev/null
echo "XLANG: rust verify --full after Go unlink+GC ok"
if rust_run --s3-bucket "$rust_bucket" cat /from-rust.txt >/dev/null 2>&1; then
  echo "XLANG: unlinked file is still readable" >&2
  exit 1
fi
echo "XLANG: rust agrees the unlinked file is gone"

echo "XLANG: all cross-language checks passed"
