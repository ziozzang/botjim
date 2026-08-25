#!/usr/bin/env bash
set -euo pipefail

# Builds static release binaries + SHA256SUMS into dist/.
# usage: VERSION=0.1.0 scripts/build-release.sh

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"
VERSION="${VERSION:-0.1.0}"

if [[ ! "${VERSION}" =~ ^[0-9A-Za-z._-]+$ ]]; then
  echo "invalid VERSION: ${VERSION}" >&2
  exit 1
fi

mkdir -p "${DIST_DIR}"

targets=(
  "darwin arm64 macos arm64"
  "darwin amd64 macos x86_64"
  "linux arm64 linux arm64"
  "linux amd64 linux x86_64"
)

artifacts=()
for target in "${targets[@]}"; do
  read -r goos goarch platform arch <<<"${target}"
  extension=""
  if [[ "${goos}" == "windows" ]]; then
    extension=".exe"
  fi
  filename="botjim_${VERSION}_${platform}_${arch}${extension}"
  output="${DIST_DIR}/${filename}"
  echo "building ${filename}"
  (
    cd "${ROOT_DIR}"
    CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" \
      go build -buildvcs=false -trimpath -tags="netgo,osusergo" -ldflags="-s -w" -o "${output}" ./cmd/botjim
  )
  if ! go version -m "${output}" 2>&1 | grep -q 'CGO_ENABLED=0'; then
    echo "static-build verification failed for ${filename}: CGO_ENABLED is not 0" >&2
    exit 1
  fi
  if [[ "${goos}" == "linux" ]] && ! file "${output}" | grep -q 'statically linked'; then
    echo "static-link verification failed for ${filename}" >&2
    file "${output}" >&2
    exit 1
  fi
  if [[ "${goos}" != "windows" ]]; then
    chmod 0755 "${output}"
  else
    chmod 0644 "${output}"
  fi
  artifacts+=("${filename}")
done

(
  cd "${DIST_DIR}"
  sha256sum "${artifacts[@]}" > SHA256SUMS
  chmod 0644 SHA256SUMS
)

echo "release binaries written to ${DIST_DIR}"
