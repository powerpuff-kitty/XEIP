#!/usr/bin/env bash
# Scan a built local image. Downloads only public scanner/advisory data.
# Usage: bash conformance/organization-image-scan.sh IMAGE NEW_REPORT_DIRECTORY
# Optional XEIP_GRYPE_DB_VOLUME reuses an existing public cache without deleting it.
set -euo pipefail
umask 077

if [[ $# != 2 || ! $1 =~ ^[a-z0-9][a-z0-9._/:@-]*$ || $2 == *,* ]]; then
  echo 'Usage: organization-image-scan.sh IMAGE NEW_REPORT_DIRECTORY (no commas)' >&2
  exit 1
fi
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
mkdir -- "$2"
report_dir=$(cd -- "$2" && pwd)
scanner='anchore/grype@sha256:e4a44ef45d285b829ce6efe2642980329661bd2d18eab5fc539138d4adaebbbe'
helper='node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402'
suffix=$(node -p 'require("node:crypto").randomUUID()')
cache_volume=${XEIP_GRYPE_DB_VOLUME:-xeip-grype-$suffix}
own_cache=false
archive_dir=''
cleanup() {
  status=$?
  trap - EXIT
  printf '%s\n' "$status" > "$report_dir/exit.txt"
  # Only these unguessable per-invocation names and owned temporary resources.
  docker rm -f "xeip-grype-helper-$suffix" "xeip-grype-prepare-$suffix" "xeip-grype-scan-$suffix" > "$report_dir/cleanup.log" 2>&1 || true
  if [[ $own_cache == true ]]; then
    docker volume rm "$cache_volume" >> "$report_dir/cleanup.log" 2>&1 || true
  fi
  if [[ -n $archive_dir ]]; then rm -f -- "$archive_dir/image.tar" "$archive_dir/raw-scan.json"; rmdir -- "$archive_dir"; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if [[ ! $cache_volume =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]+$ ]]; then
  echo 'Invalid public cache volume name' >&2
  exit 1
fi

# Record only artifact identity, never image environment/configuration secrets.
docker image inspect "$1" 2> "$report_dir/inspect-docker.log" | node --input-type=module -e '
  import {readFileSync} from "node:fs";
  const image=JSON.parse(readFileSync(0,"utf8"))[0];
  if (image.Os!=="linux" || image.Architecture!=="amd64" || !/^sha256:[a-f0-9]{64}$/.test(image.Id)) throw Error("Expected local Linux/amd64 image");
  console.log(JSON.stringify({id:image.Id,os:image.Os,architecture:image.Architecture},null,2));
' > "$report_dir/image.json" 2> "$report_dir/inspect.log"
image_id=$(node -p 'JSON.parse(require("node:fs").readFileSync(process.argv[1],"utf8")).id' "$report_dir/image.json")
printf '%s\n' "$scanner" > "$report_dir/scanner-image.txt"
docker pull "$scanner" > "$report_dir/scanner-pull.log" 2>&1
isolated=(--rm --pull=never --read-only --cap-drop=ALL --security-opt no-new-privileges --pids-limit 128)
if [[ -z ${XEIP_GRYPE_DB_VOLUME:-} ]]; then
  # BuildKit's base-layer cache does not imply a runnable local helper image.
  docker pull "$helper" > "$report_dir/helper-pull.log" 2>&1
  docker volume create "$cache_volume" > "$report_dir/cache-create.log"
  own_cache=true
  # Trusted pinned base, not code from the image being assessed. No network.
  docker run "${isolated[@]}" --name "xeip-grype-helper-$suffix" --network none --user 0:0 \
    --mount "type=volume,src=$cache_volume,dst=/db" --entrypoint node "$helper" \
    -e 'require("node:fs").chmodSync("/db",0o777)' > "$report_dir/cache-init.log" 2>&1
else
  docker volume inspect "$cache_volume" > /dev/null
fi

# The networked preparation container has no image, source or credential mount.
docker run "${isolated[@]}" --name "xeip-grype-prepare-$suffix" --user 1000:1000 \
  --tmpfs /tmp:rw,nosuid,nodev,mode=1777 \
  --mount "type=volume,src=$cache_volume,dst=/db" \
  -e GRYPE_DB_CACHE_DIR=/db -e GRYPE_CHECK_FOR_APP_UPDATE=false \
  "$scanner" db update -v > "$report_dir/db-update.log" 2>&1

archive_dir=$(mktemp -d)
docker save --output "$archive_dir/image.tar" "$image_id" 2> "$report_dir/export.log"
chmod 444 "$archive_dir/image.tar"
node --input-type=module - "$archive_dir/image.tar" > "$report_dir/archive-sha256.txt" <<'JS'
import {createReadStream} from 'node:fs';
import {createHash} from 'node:crypto';
const hash = createHash('sha256');
for await (const chunk of createReadStream(process.argv[2])) hash.update(chunk);
console.log(hash.digest('hex'));
JS

set +e
docker run "${isolated[@]}" --name "xeip-grype-scan-$suffix" --network none --user 1000:1000 \
  --tmpfs /tmp:rw,nosuid,nodev,mode=1777 \
  --mount "type=volume,src=$cache_volume,dst=/db,readonly" \
  --mount "type=bind,src=$archive_dir/image.tar,dst=/image.tar,readonly" \
  -e GRYPE_DB_CACHE_DIR=/db -e GRYPE_DB_AUTO_UPDATE=false \
  -e GRYPE_DB_VALIDATE_BY_HASH_ON_START=true -e GRYPE_DB_VALIDATE_AGE=true \
  -e GRYPE_CHECK_FOR_APP_UPDATE=false \
  "$scanner" docker-archive:/image.tar --scope squashed --output json --fail-on high -vv \
  > "$archive_dir/raw-scan.json" 2> "$report_dir/scan.log"
scanner_exit=$?
set -e
printf '%s\n' "$scanner_exit" > "$report_dir/scanner-exit.txt"
node "$script_dir/../tools/image-scan-report.mjs" "$archive_dir/raw-scan.json" "$scanner_exit" "$report_dir/scan.json" \
  > "$report_dir/summary.json" 2> "$report_dir/policy.log"
cat "$report_dir/summary.json"
