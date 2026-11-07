#!/usr/bin/env bash
# Go S3 court: the official MinIO release binary in a minimal container under
# the same hard limits as every other court, plus the Go S3 integration tests,
# the full `-race` suite in the FUSE court, and a bidirectional cross-language
# store check against the Rust CLI.
#
# The MinIO container is a sibling on a private Docker network and the Go court
# joins that network (WEFT_DOCKER_NETWORK), exactly like the parent
# scripts/s3_court.sh wires the Rust court. Endpoint form used: container-name
# DNS over the private bridge, `http://<minio-container>:9000` (path-style).
#
# The binary is the same pinned release the parent court uses. Its data
# directory is a tmpfs, so this court proves protocol and conditional-write
# behaviour, not media or power-loss durability.
#
# Usage: scripts/go-s3-court.sh [--focused-only]
#   --focused-only   run the S3 package tests only (no full -race suite, no
#                    cross-language leg)
set -Eeuo pipefail

skip() {
  echo "go-s3-court: skip $1" >&2
  exit 78
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
weft_root="$(cd "$repo_root/.." && pwd)"
cd "$repo_root"

focused_only=0
for arg in "$@"; do
  case "$arg" in
    --focused-only) focused_only=1 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown argument '$arg'" >&2; exit 64 ;;
  esac
done

WEFT_MEMORY="${WEFT_MEMORY:-3g}"
WEFT_CPUS="${WEFT_CPUS:-4}"
WEFT_PIDS="${WEFT_PIDS:-1024}"
WEFT_NPROC="${WEFT_NPROC:-2048}"

if [[ "$(uname -m)" != "x86_64" ]]; then
  skip "only the verified linux-amd64 MinIO release is supported (host is $(uname -m))"
fi
command -v docker >/dev/null 2>&1 || skip "no docker CLI on PATH"
docker info >/dev/null 2>&1 || skip "no reachable docker daemon"
command -v curl >/dev/null 2>&1 || skip "curl is required to fetch the pinned MinIO release"

minio_release="${WEFT_S3_SERVER_RELEASE:-RELEASE.2025-04-22T22-12-26Z}"
minio_sha256="${WEFT_S3_SERVER_SHA256:-53e2a2cb16c5366ea6fbbc479c19ddb4c6a0948273e752f740fb1fbf27bb817c}"
minio_dir="$weft_root/.docker-cache/minio"
minio_bin="$minio_dir/minio"
minio_url="https://github.com/minio/minio/releases/download/${minio_release}/minio.linux-amd64.${minio_release}"
mkdir -p "$minio_dir"
if [[ ! -f "$minio_bin" ]]; then
  echo "go-s3-court: downloading official MinIO binary $minio_release" >&2
  if ! curl -fL --retry 3 -o "$minio_bin.part" "$minio_url"; then
    rm -f "$minio_bin.part"
    skip "cannot obtain the pinned MinIO release $minio_release"
  fi
  mv "$minio_bin.part" "$minio_bin"
fi
chmod +x "$minio_bin"
actual_sha256="$(sha256sum "$minio_bin" | awk '{print $1}')"
if [[ "$actual_sha256" != "$minio_sha256" ]]; then
  echo "go-s3-court: MinIO binary sha256 mismatch (expected $minio_sha256, got $actual_sha256)" >&2
  exit 1
fi
minio_version="$("$minio_bin" --version | head -1)"

container_image="debian:bookworm-slim"
if ! docker image inspect "$container_image" >/dev/null 2>&1; then
  if ! docker pull "$container_image" >/dev/null; then
    skip "cannot obtain the pinned $container_image court image"
  fi
fi
container_image_digest="$(docker image inspect "$container_image" --format '{{index .RepoDigests 0}}')"
container_image_id="$(docker image inspect "$container_image" --format '{{.Id}}')"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
suffix="$(printf '%s' "$stamp" | tr '[:upper:]' '[:lower:]')"
access_key="${WEFT_S3_ACCESS_KEY:-weftcourt}"
secret_key="${WEFT_S3_SECRET_KEY:-weftcourt-secret}"
minio_name="weft-go-s3-minio-$$"
network="weft-go-s3-net-$$"
prefix="weft-go-s3-$suffix"
mkdir -p bench/receipts
chmod -R a+rwX bench/receipts 2>/dev/null || true

cleanup() {
  docker rm -f "$minio_name" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

if ! docker network create "$network" >/dev/null 2>&1; then
  skip "cannot create the court Docker network $network"
fi
docker run -d --name "$minio_name" \
  --memory="$WEFT_MEMORY" --memory-swap="$WEFT_MEMORY" \
  --pids-limit="$WEFT_PIDS" --cpus="$WEFT_CPUS" \
  --ulimit nofile=65536:65536 \
  --security-opt no-new-privileges \
  --cap-drop=ALL \
  --network "$network" \
  --tmpfs /data:rw,size=1g,nosuid,nodev \
  -p 127.0.0.1::9000 \
  -e MINIO_ROOT_USER="$access_key" \
  -e MINIO_ROOT_PASSWORD="$secret_key" \
  -v "$minio_bin":/minio:ro \
  "$container_image" \
  /minio server /data --address :9000 --console-address :9001 >/dev/null

host_port_line="$(docker port "$minio_name" 9000/tcp | head -1)"
host_port="${host_port_line##*:}"
ready=0
for _ in $(seq 1 60); do
  if curl -sf "http://127.0.0.1:${host_port}/minio/health/ready" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.5
done
if [[ "$ready" != 1 ]]; then
  echo "go-s3-court: MinIO did not become ready; logs follow" >&2
  docker logs "$minio_name" >&2 || true
  exit 1
fi

endpoint="http://${minio_name}:9000"
export WEFT_DOCKER_NETWORK="$network"
export WEFT_S3_ENDPOINT="$endpoint"
export WEFT_S3_TEST_ENDPOINT="$endpoint"
export WEFT_S3_TEST_PREFIX="$prefix"
export WEFT_S3_REGION="${WEFT_S3_REGION:-us-east-1}"
export WEFT_S3_ACCESS_KEY="$access_key"
export WEFT_S3_SECRET_KEY="$secret_key"
# General suites do many operations between publications; the writer lease must
# outlast them. The fencing test sets its own 1 s lease inside the test.
export WEFT_S3_LOCK_LEASE_SECS="${WEFT_S3_LOCK_LEASE_SECS:-60}"
export WEFT_S3_SERVER_LABEL="$minio_version"
export WEFT_S3_SERVER_VERSION="$minio_release"
export WEFT_S3_SERVER_SHA256="$actual_sha256"
export WEFT_S3_CONTAINER_IMAGE="$container_image_digest"

go_rev="$(git -C "$repo_root" rev-parse HEAD)"
image_id="$(docker image inspect --format '{{.Id}}' weft/go-court:1 2>/dev/null || echo unknown)"
fuse_image_id="$(docker image inspect --format '{{.Id}}' weft/fuse-court:1 2>/dev/null || echo unknown)"
docker_server="$(docker version --format '{{.Server.Version}}')"

focused_log="bench/receipts/go-s3-focused-${stamp}.log"
full_log="bench/receipts/go-s3-full-${stamp}.log"
xlang_log="bench/receipts/go-s3-xlang-${stamp}.log"

echo "go-s3-court: MinIO $minio_release sha256=$actual_sha256 endpoint=$endpoint prefix=$prefix" >&2

echo "go-s3-court: focused S3 tests in the go court" >&2
set +e
"$weft_root/scripts/docker-court.sh" go \
  "cd /work/WeftFS-Go && gofmt -l . && go vet ./... && CGO_ENABLED=0 go build ./... && go test -race -count=1 -v -run 'TestS3|TestSigV4|TestPayloadHash|TestCanonicalQuery|TestPathAndComponent|TestIfMatchForms|TestLockRecord|TestSchemasDoNot|TestS3Config' ./store/" \
  >"$focused_log" 2>&1
focused_status=$?
set -e
tail -40 "$focused_log" >&2
if [[ $focused_status -ne 0 ]]; then
  echo "go-s3-court: focused S3 tests failed (log $focused_log)" >&2
  exit 1
fi

if [[ "$focused_only" == 0 ]]; then
  echo "go-s3-court: full -race suite in the fuse court" >&2
  set +e
  "$weft_root/scripts/docker-court.sh" fuse \
    "cd /work/WeftFS-Go && go test -race -count=1 ./..." \
    >"$full_log" 2>&1
  full_status=$?
  set -e
  tail -30 "$full_log" >&2
  if [[ $full_status -ne 0 ]]; then
    echo "go-s3-court: full suite failed (log $full_log)" >&2
    exit 1
  fi

	echo "go-s3-court: building the Rust CLI at $weft_root (fuse court)" >&2
	"$weft_root/scripts/docker-court.sh" fuse \
	  "cd /work && cargo build --release --features fuse --bin weftfs" >&2
	rust_bin="$weft_root/.docker-cache/target-rust/release/weftfs"
	if [[ ! -x "$rust_bin" ]]; then
	  echo "go-s3-court: Rust CLI was not produced at $rust_bin" >&2
	  exit 1
	fi

	echo "go-s3-court: bidirectional cross-language leg (fuse court: Rust links libfuse3)" >&2
	export WEFT_XLANG_PREFIX="$prefix"
	export WEFT_XLANG_GIT_REV="$go_rev"
	set +e
	"$weft_root/scripts/docker-court.sh" fuse \
	  "cd /work/WeftFS-Go && CGO_ENABLED=0 go build -o /work/.docker-cache/weftfs-go-xlang ./cmd/weftfs && WEFT_XLANG_GO_BIN=/work/.docker-cache/weftfs-go-xlang WEFT_XLANG_RUST_BIN=/work/.docker-cache/target-rust/release/weftfs bash scripts/go-s3-xlang.sh" \
	  >"$xlang_log" 2>&1
  xlang_status=$?
  set -e
  cat "$xlang_log" >&2
  if [[ $xlang_status -ne 0 ]]; then
    echo "go-s3-court: cross-language leg failed (log $xlang_log)" >&2
    exit 1
  fi
fi

# Count evidence from the raw logs rather than restating it.
focused_passed="$(grep -c -- '--- PASS' "$focused_log" || true)"
focused_failed="$(grep -c -- '--- FAIL' "$focused_log" || true)"
focused_skipped="$(grep -c -- '--- SKIP' "$focused_log" || true)"
measured_form="$(grep -o 'measured If-Match form: [a-z-]*' "$focused_log" | sed 's/measured If-Match form: //' | head -1 || true)"

full_passed=0
full_failed=0
xlang_checks=0
logs_json="\"$focused_log\""
if [[ "$focused_only" == 0 ]]; then
  # `go test ./...` without -v prints one `ok`/`FAIL` line per package.
  full_passed="$(grep -c '^ok[[:space:]]' "$full_log" || true)"
  full_failed="$(grep -c '^FAIL' "$full_log" || true)"
  xlang_checks="$(grep -c -- '^XLANG:' "$xlang_log" || true)"
  logs_json="$logs_json, \"$full_log\", \"$xlang_log\""
fi

receipt="bench/receipts/go-s3-${stamp}.json"
cat > "$receipt" <<JSON
{
  "schema": "weft-go-s3-court-v1",
  "generated_utc": "$stamp",
  "revision": {
    "weftfs_go": "$go_rev",
    "note": "WeftFS-Go only; the parent Rust revision and submodule pin were not changed"
  },
  "server": {
    "product": "MinIO",
    "release": "$minio_release",
    "version_line": "$minio_version",
    "binary_sha256": "$actual_sha256",
    "binary_url": "$minio_url",
    "container_image": "$container_image_digest",
    "container_image_id": "$container_image_id",
    "started_by": "scripts/go-s3-court.sh",
    "endpoint_form": "http://<container-name>:9000 path-style on a private bridge network"
  },
  "court": {
    "docker_server": "$docker_server",
    "go_image_id": "$image_id",
    "fuse_image_id": "$fuse_image_id",
    "memory": "$WEFT_MEMORY",
    "memory_swap": "$WEFT_MEMORY",
    "pids": "$WEFT_PIDS",
    "cpus": "$WEFT_CPUS",
    "nproc": "$WEFT_NPROC",
    "cap_drop": "ALL",
    "no_new_privileges": true,
    "tmpfs": "/tmp 1g; MinIO data tmpfs 1g"
  },
  "tests": {
    "focused_command": "go test -race -count=1 -v -run 'TestS3|...' ./store/ in the go court",
    "focused_passed": $focused_passed,
    "focused_failed": $focused_failed,
    "focused_skipped": $focused_skipped,
    "full_command": "$(if [[ "$focused_only" == 0 ]]; then echo "go test -race -count=1 ./... in the fuse court"; else echo "not run (--focused-only)"; fi)",
    "full_passed": $full_passed,
    "full_failed": $full_failed,
    "full_count_kind": "packages reporting ok",
    "cross_language_checks": $xlang_checks,
    "measured_if_match_form": "${measured_form:-not recorded}",
    "logs": [$logs_json]
  },
  "label": "Single-node MinIO on loopback in the OOM-protected Docker court with a tmpfs data directory. Not a cloud, multi-node, fleet, device-cache, media, power-loss, or production claim."
}
JSON

echo "go-s3-court: focused pass=$focused_passed fail=$focused_failed skip=$focused_skipped" >&2
echo "go-s3-court: If-Match form ${measured_form:-not recorded}" >&2
echo "go-s3-court: receipt $receipt" >&2
