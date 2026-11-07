#!/usr/bin/env bash
# Go GCS court: a pinned `fake-gcs-server` in a sibling container under the
# same hard limits as every other court, the Go GCS integration tests, and a
# read-only FUSE mount over the same emulator.
#
# The emulator is a single static Linux binary published on GitHub
# (fsouza/fake-gcs-server). This script downloads the pinned release, verifies
# the tarball's sha256, and runs it in `debian:bookworm-slim` on a private
# Docker network. The Go court joins that network and talks to
# `http://<container>:4443` (path-style JSON API). Its data backend is memory
# and its data directory is a bounded tmpfs, so this proves protocol and
# generation-precondition behaviour, not media, power-loss, or cloud
# durability.
#
# Usage: scripts/go-gcs-court.sh [--focused-only]
set -Eeuo pipefail

skip() {
  echo "go-gcs-court: skip $1" >&2
  exit 78
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
weft_root="$(cd "$repo_root/.." && pwd)"
cd "$repo_root"

focused_only=0
run_full=1
for arg in "$@"; do
  case "$arg" in
    --focused-only) focused_only=1; run_full=0 ;;
    --no-full) run_full=0 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown argument '$arg'" >&2; exit 64 ;;
  esac
done

WEFT_MEMORY="${WEFT_MEMORY:-3g}"
WEFT_CPUS="${WEFT_CPUS:-4}"
WEFT_PIDS="${WEFT_PIDS:-1024}"
WEFT_NPROC="${WEFT_NPROC:-2048}"

if [[ "$(uname -m)" != "x86_64" ]]; then
  skip "only the verified linux-amd64 fake-gcs-server release is supported (host is $(uname -m))"
fi
command -v docker >/dev/null 2>&1 || skip "no docker CLI on PATH"
docker info >/dev/null 2>&1 || skip "no reachable docker daemon"
command -v curl >/dev/null 2>&1 || skip "curl is required to fetch the pinned emulator release"

gcs_release_tag="v1.56.1"
gcs_release_version="1.56.1"
gcs_tarball_name="fake-gcs-server_${gcs_release_version}_Linux_amd64.tar.gz"
gcs_tarball_sha256="0f2f9f6884417acd5cc27126a9aa237ccc627372a4aa5008b399641de6db9469"
gcs_url="https://github.com/fsouza/fake-gcs-server/releases/download/${gcs_release_tag}/${gcs_tarball_name}"
gcs_dir="$weft_root/.docker-cache/gcs"
gcs_bin="$gcs_dir/fake-gcs-server"
mkdir -p "$gcs_dir"

obtain() {
  if [[ -x "$gcs_bin" ]]; then
    return 0
  fi
  if [[ ! -s "$gcs_dir/$gcs_tarball_name" ]]; then
    echo "go-gcs-court: downloading pinned fake-gcs-server $gcs_release_tag" >&2
    if ! curl -fL --retry 3 -o "$gcs_dir/${gcs_tarball_name}.part" "$gcs_url"; then
      rm -f "$gcs_dir/${gcs_tarball_name}.part"
      return 1
    fi
    mv "$gcs_dir/${gcs_tarball_name}.part" "$gcs_dir/$gcs_tarball_name"
  fi
  actual="$(sha256sum "$gcs_dir/$gcs_tarball_name" | awk '{print $1}')"
  if [[ "$actual" != "$gcs_tarball_sha256" ]]; then
    echo "go-gcs-court: emulator tarball sha256 mismatch (expected $gcs_tarball_sha256, got $actual)" >&2
    return 1
  fi
  tar -xzf "$gcs_dir/$gcs_tarball_name" -C "$gcs_dir" fake-gcs-server
  [[ -x "$gcs_bin" ]]
}
if ! obtain; then
  skip "cannot obtain the pinned fake-gcs-server release $gcs_release_tag"
fi
gcs_version="fake-gcs-server ${gcs_release_version} (the binary exposes no -version flag; the tarball sha256 above is the identity)"

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
gcs_name="weft-go-gcs-emulator-$$"
network="weft-go-gcs-net-$$"
prefix="weft-go-gcs-$suffix"
mkdir -p bench/receipts
chmod -R a+rwX bench/receipts 2>/dev/null || true

cleanup() {
  docker rm -f "$gcs_name" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

if ! docker network create "$network" >/dev/null 2>&1; then
  skip "cannot create the court Docker network $network"
fi
docker run -d --name "$gcs_name" \
  --memory="$WEFT_MEMORY" --memory-swap="$WEFT_MEMORY" \
  --pids-limit="$WEFT_PIDS" --cpus="$WEFT_CPUS" \
  --ulimit nofile=65536:65536 \
  --security-opt no-new-privileges \
  --cap-drop=ALL \
  --network "$network" \
  --tmpfs /data:rw,size=1g,nosuid,nodev \
  -p 127.0.0.1::4443 \
  -v "$gcs_bin":/fake-gcs-server:ro \
  "$container_image" \
  /fake-gcs-server -backend memory -scheme http -host 0.0.0.0 -port 4443 \
  -external-url "http://${gcs_name}:4443" -data /data -log-level warn >/dev/null

host_port_line="$(docker port "$gcs_name" 4443/tcp | head -1)"
host_port="${host_port_line##*:}"
ready=0
for _ in $(seq 1 100); do
  if (exec 3<>"/dev/tcp/127.0.0.1/${host_port}") 2>/dev/null; then
    ready=1
    break
  fi
  if ! docker inspect -f '{{.State.Running}}' "$gcs_name" 2>/dev/null | grep -q true; then
    echo "go-gcs-court: the emulator exited before becoming ready; logs follow" >&2
    docker logs "$gcs_name" >&2 || true
    exit 1
  fi
  sleep 0.2
done
if [[ "$ready" != 1 ]]; then
  echo "go-gcs-court: the emulator never accepted a connection" >&2
  docker logs "$gcs_name" >&2 || true
  exit 1
fi

endpoint="http://${gcs_name}:4443"
export WEFT_DOCKER_NETWORK="$network"
export WEFT_GCS_TEST_ENDPOINT="$endpoint"
export WEFT_GCS_TEST_BUCKET="$prefix"
export WEFT_GCS_PROJECT="${WEFT_GCS_PROJECT:-weft-court}"
export WEFT_GCS_ANONYMOUS=1
export WEFT_GCS_LOCK_LEASE_SECS="${WEFT_GCS_LOCK_LEASE_SECS:-60}"
export WEFT_GCS_FENCE_LEASE_SECS="${WEFT_GCS_FENCE_LEASE_SECS:-3}"
export WEFT_GCS_SERVER_LABEL="fake-gcs-server"
export WEFT_GCS_SERVER_VERSION="$gcs_release_tag"
export WEFT_GCS_SERVER_SHA256="$gcs_tarball_sha256"

go_rev="$(git -C "$repo_root" rev-parse HEAD)"
image_id="$(docker image inspect --format '{{.Id}}' weft/go-court:1 2>/dev/null || echo unknown)"
fuse_image_id="$(docker image inspect --format '{{.Id}}' weft/fuse-court:1 2>/dev/null || echo unknown)"
docker_server="$(docker version --format '{{.Server.Version}}')"

tests_log="bench/receipts/go-gcs-${stamp}.log"
full_log="bench/receipts/go-gcs-full-${stamp}.log"
fuse_log="bench/receipts/go-gcs-fuse-${stamp}.log"

echo "go-gcs-court: fake-gcs-server $gcs_release_tag sha256=$gcs_tarball_sha256 endpoint=$endpoint prefix=$prefix" >&2

echo "go-gcs-court: GCS integration tests in the go court" >&2
set +e
"$weft_root/scripts/docker-court.sh" go \
  "cd /work/WeftFS-Go && gofmt -l . && go vet ./... && CGO_ENABLED=0 go build ./... && go test -race -count=1 -v -run 'TestGCS' ./store/" \
  >"$tests_log" 2>&1
tests_status=$?
set -e
tail -60 "$tests_log" >&2
if [[ $tests_status -ne 0 ]]; then
  echo "go-gcs-court: GCS tests failed (log $tests_log)" >&2
  exit 1
fi

full_passed=0
full_failed=0
if [[ "$run_full" == 1 ]]; then
  echo "go-gcs-court: full -race suite in the fuse court" >&2
  set +e
  "$weft_root/scripts/docker-court.sh" fuse \
    "cd /work/WeftFS-Go && go test -race -count=1 ./..." \
    >"$full_log" 2>&1
  full_status=$?
  set -e
  tail -30 "$full_log" >&2
  if [[ $full_status -ne 0 ]]; then
    echo "go-gcs-court: full suite failed (log $full_log)" >&2
    exit 1
  fi
  full_passed="$(grep -c '^ok[[:space:]]' "$full_log" || true)"
  full_failed="$(grep -c '^FAIL' "$full_log" || true)"
fi
if [[ "$focused_only" == 0 ]]; then
  echo "go-gcs-court: read-only FUSE mount over GCS (fuse court)" >&2
  set +e
  "$weft_root/scripts/docker-court.sh" fuse \
    "cd /work/WeftFS-Go && bash scripts/go-object-fuse-court.sh gcs" \
    >"$fuse_log" 2>&1
  fuse_status=$?
  set -e
  cat "$fuse_log" >&2
  if [[ $fuse_status -ne 0 ]]; then
    echo "go-gcs-court: FUSE-over-GCS leg failed (log $fuse_log)" >&2
    exit 1
  fi
fi

passed="$(grep -c -- '--- PASS' "$tests_log" || true)"
failed="$(grep -c -- '--- FAIL' "$tests_log" || true)"
skipped="$(grep -c -- '--- SKIP' "$tests_log" || true)"
fuse_files="$(grep -o 'files=[0-9]*' "$fuse_log" 2>/dev/null | head -1 | cut -d= -f2 || true)"
fuse_shas="$(grep -o 'sha_matches=[0-9]*' "$fuse_log" 2>/dev/null | head -1 | cut -d= -f2 || true)"
listing_digest="$(grep -o 'listing_digest=[a-f0-9]*' "$fuse_log" 2>/dev/null | head -1 | cut -d= -f2 || true)"
ranged_sha="$(grep -o 'ranged_sha256=[a-f0-9]*' "$fuse_log" 2>/dev/null | head -1 | cut -d= -f2 || true)"
logs_json="\"$tests_log\""
fuse_command="not run (--focused-only)"
if [[ "$focused_only" == 0 ]]; then
  logs_json="$logs_json, \"$fuse_log\""
  fuse_command="bash scripts/go-object-fuse-court.sh gcs in the fuse court"
  if [[ "$run_full" == 1 ]]; then
    logs_json="\"$tests_log\", \"$full_log\", \"$fuse_log\""
  fi
fi

receipt="bench/receipts/go-gcs-${stamp}.json"
cat > "$receipt" <<JSON
{
  "schema": "weft-go-gcs-court-v1",
  "generated_utc": "$stamp",
  "revision": {
    "weftfs_go": "$go_rev",
    "note": "WeftFS-Go only; the parent Rust revision and submodule pin were not changed"
  },
  "emulator": {
    "product": "fake-gcs-server (fsouza/fake-gcs-server)",
    "release": "$gcs_release_tag",
    "version_line": "$gcs_version",
    "tarball": "$gcs_tarball_name",
    "tarball_sha256": "$gcs_tarball_sha256",
    "container_image": "$container_image_digest",
    "container_image_id": "$container_image_id",
    "backend": "memory",
    "started_by": "scripts/go-gcs-court.sh",
    "endpoint_form": "http://<container-name>:4443 on a private bridge network"
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
    "tmpfs": "/tmp 1g; emulator data tmpfs 1g"
  },
  "tests": {
    "command": "go test -race -count=1 -v -run 'TestGCS' ./store/ in the go court",
    "passed": $passed,
    "failed": $failed,
    "skipped": $skipped,
    "full_command": "$(if [[ "$run_full" == 1 ]]; then echo "go test -race -count=1 ./... in the fuse court"; else echo "not run (--no-full)"; fi)",
    "full_packages_ok": $full_passed,
    "full_packages_failed": $full_failed,
    "fuse_command": "$fuse_command",
    "fuse_files": ${fuse_files:-0},
    "fuse_sha256_matches": ${fuse_shas:-0},
    "fuse_listing_digest": "${listing_digest:-not recorded}",
    "fuse_ranged_sha256": "${ranged_sha:-not recorded}",
    "logs": [$logs_json]
  },
  "label": "Single-host GCS-compatible emulator on a private bridge network in the OOM-protected Docker court with a memory backend. Not a cloud, multi-node, fleet, device-cache, media, power-loss, or production claim. The FUSE leg is a read-only mount; no writable FUSE-over-object claim is made."
}
JSON

echo "go-gcs-court: pass=$passed fail=$failed skip=$skipped" >&2
echo "go-gcs-court: FUSE files=${fuse_files:-0} sha256_matches=${fuse_shas:-0}" >&2
echo "go-gcs-court: receipt $receipt" >&2
