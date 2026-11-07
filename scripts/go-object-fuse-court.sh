#!/usr/bin/env bash
# Read-only FUSE over an object-store backend, run inside the fuse court.
#
# Usage: scripts/go-object-fuse-court.sh <s3|gcs>
#
# The court script that starts the emulator sets WEFT_DOCKER_NETWORK and the
# endpoint variables. This script:
#
#   1. builds the Go CLI;
#   2. creates a fresh bucket-backed store with `--backend <kind>`;
#   3. writes three files (two binary, one text) plus a directory;
#   4. takes a snapshot and runs `verify --full`;
#   5. mounts the store read-only with the Go daemon;
#   6. compares every mounted file byte-for-byte and by SHA-256, does a ranged
#      read, and hashes the listing;
#   7. unmounts, proves the daemon exited, and runs `verify --full` again.
#
# A writable mount over object storage is NOT exercised here. The store path is
# the same one the CLI writable commands use, but a writable FUSE mount over a
# remote plane has no court evidence, so no claim is made about it.
set -Eeuo pipefail

backend="${1:-}"
case "$backend" in
  s3|gcs) ;;
  *) echo "usage: $0 <s3|gcs>" >&2; exit 64 ;;
esac

repo="/work/WeftFS-Go"
work="$(mktemp -d /tmp/go-object-fuse.XXXXXX)"
binary_dir="/work/.docker-cache"
mkdir -p "$binary_dir"
binary="$binary_dir/weftfs-go-object-fuse-$$"
source_root="$work/source"
mnt="/mnt/weft-fuse/object-$backend-$$"
mkdir -p "$source_root/dir" "$mnt"
trap 'umount "$mnt" >/dev/null 2>&1 || true; rm -rf "$work"' EXIT

suffix="$(printf '%s' "$$" | tr -cd '0-9')"
flags=()
case "$backend" in
  s3)
    endpoint="${WEFT_S3_TEST_ENDPOINT:?WEFT_S3_TEST_ENDPOINT is required in the fuse court}"
    prefix="${WEFT_S3_TEST_PREFIX:-weft-go}"
    bucket="$(printf '%s' "${prefix}-fuse-${suffix}" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9-' '-')"
    bucket="${bucket%-}"
    flags+=(--backend s3 --s3-endpoint "$endpoint" --s3-bucket "$bucket"
      --s3-region "${WEFT_S3_REGION:-us-east-1}"
      --s3-access-key "${WEFT_S3_ACCESS_KEY:-weftcourt}"
      --s3-secret-key "${WEFT_S3_SECRET_KEY:-weftcourt-secret}")
    ;;
  gcs)
    endpoint="${WEFT_GCS_TEST_ENDPOINT:?WEFT_GCS_TEST_ENDPOINT is required in the fuse court}"
    prefix="${WEFT_GCS_TEST_BUCKET:-weft-go}"
    bucket="$(printf '%s' "${prefix}-fuse-${suffix}" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9-' '-')"
    bucket="${bucket%-}"
    flags+=(--backend gcs --gcs-endpoint "$endpoint" --gcs-bucket "$bucket"
      --gcs-project "${WEFT_GCS_PROJECT:-weft-court}" --gcs-anonymous)
    ;;
esac

echo "object-fuse: backend=$backend endpoint=$endpoint bucket=$bucket"

cd "$repo"
CGO_ENABLED=0 go build -o "$binary" ./cmd/weftfs
chmod +x "$binary"
cli=("$binary" "${flags[@]}")

# Deterministic payload sizes; the bytes come from the kernel CSPRNG, which is
# fine because only mounted/source equality is compared.
head -c 4096 /dev/urandom > "$source_root/alpha.bin"
head -c 262144 /dev/urandom > "$source_root/beta.bin"
printf 'gamma-object-fuse-%s\n' "$backend" > "$source_root/dir/gamma.txt"

"${cli[@]}" init
"${cli[@]}" mkdir /dir --seed fuse-dir-seed
"${cli[@]}" create /alpha.bin --file "$source_root/alpha.bin" --seed fuse-alpha
"${cli[@]}" create /beta.bin --file "$source_root/beta.bin" --seed fuse-beta
"${cli[@]}" create /dir/gamma.txt --file "$source_root/dir/gamma.txt" --seed fuse-gamma
"${cli[@]}" snapshot create s1
"${cli[@]}" verify --full

"${cli[@]}" mount --mountpoint "$mnt" --read-only &
daemon=$!
mounted=0
for _ in $(seq 1 300); do
  if mountpoint -q "$mnt"; then mounted=1; break; fi
  if ! kill -0 "$daemon" 2>/dev/null; then
    echo "object-fuse: the daemon exited before the mount appeared" >&2
    exit 1
  fi
  sleep 0.1
done
if [[ "$mounted" != 1 ]]; then
  echo "object-fuse: mount did not appear within 30 s" >&2
  exit 1
fi

files=0
sha_matches=0
byte_matches=0
while IFS= read -r -d '' relative; do
  files=$((files + 1))
  src="$source_root/$relative"
  dst="$mnt/$relative"
  if ! cmp -s "$src" "$dst"; then
    echo "object-fuse: $relative differs byte-for-byte" >&2
    exit 1
  fi
  byte_matches=$((byte_matches + 1))
  src_sha="$(sha256sum "$src" | awk '{print $1}')"
  dst_sha="$(sha256sum "$dst" | awk '{print $1}')"
  if [[ "$src_sha" != "$dst_sha" ]]; then
    echo "object-fuse: $relative SHA-256 mismatch ($src_sha vs $dst_sha)" >&2
    exit 1
  fi
  sha_matches=$((sha_matches + 1))
done < <(cd "$source_root" && find . -type f -print0 | LC_ALL=C sort -z)

listing_digest="$(cd "$mnt" && find . -path './.weft' -prune -o -type f -printf '%P %s\n' | LC_ALL=C sort | sha256sum | awk '{print $1}')"
expected_digest="$(cd "$source_root" && find . -type f -printf '%P %s\n' | LC_ALL=C sort | sha256sum | awk '{print $1}')"
if [[ "$listing_digest" != "$expected_digest" ]]; then
  echo "object-fuse: listing digest mismatch ($listing_digest vs $expected_digest)" >&2
  echo "object-fuse: source listing:" >&2
  (cd "$source_root" && find . -type f -printf '%P %s\n' | LC_ALL=C sort) >&2 || true
  echo "object-fuse: mount listing:" >&2
  (cd "$mnt" && find . -path './.weft' -prune -o -type f -printf '%P %s\n' | LC_ALL=C sort) >&2 || true
  exit 1
fi

# Ranged read: 4096 bytes starting at offset 12345 from the largest file.
dd if="$mnt/beta.bin" bs=1 skip=12345 count=4096 status=none > "$work/ranged.bin"
dd if="$source_root/beta.bin" bs=1 skip=12345 count=4096 status=none > "$work/ranged.expected"
if ! cmp -s "$work/ranged.bin" "$work/ranged.expected"; then
  echo "object-fuse: ranged read differs" >&2
  exit 1
fi
ranged_sha="$(sha256sum "$work/ranged.bin" | awk '{print $1}')"
ranged_expected_sha="$(sha256sum "$work/ranged.expected" | awk '{print $1}')"
if [[ "$ranged_sha" != "$ranged_expected_sha" ]]; then
  echo "object-fuse: ranged SHA-256 mismatch" >&2
  exit 1
fi

# A read-only mount must refuse a write. This is evidence that the flag was
# honoured, not a durability claim.
if { printf 'must-not-write' > "$mnt/forbidden.txt"; } 2>/dev/null; then
  echo "object-fuse: a read-only mount accepted a write" >&2
  exit 1
fi
if [[ -e "$mnt/forbidden.txt" ]]; then
  echo "object-fuse: a refused write left a file behind" >&2
  exit 1
fi

if ! fusermount3 -u "$mnt" 2>/dev/null; then
  umount "$mnt"
fi
for _ in $(seq 1 100); do
  if ! kill -0 "$daemon" 2>/dev/null; then break; fi
  sleep 0.05
done
if kill -0 "$daemon" 2>/dev/null; then
  echo "object-fuse: the daemon survived unmount" >&2
  kill -9 "$daemon" >/dev/null 2>&1 || true
  exit 1
fi
wait "$daemon" 2>/dev/null || true

"${cli[@]}" verify --full

echo "object-fuse: files=$files byte_matches=$byte_matches sha_matches=$sha_matches"
echo "object-fuse: listing_digest=$listing_digest ranged_sha256=$ranged_sha"
echo "object-fuse: read_only_write_refused=1 daemon_exited=1 verify_after_unmount=1"
echo "object-fuse: PASS backend=$backend bucket=$bucket"
