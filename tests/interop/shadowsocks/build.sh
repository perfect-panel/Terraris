#!/usr/bin/env bash
set -euo pipefail
source_dir=${1:?usage: build.sh POLARIS_CHECKOUT OUTPUT_BINARY}
output=${2:?usage: build.sh POLARIS_CHECKOUT OUTPUT_BINARY}
revision=56d52fb44958ef3cc2a7fb841cd240f8206234b2
fixture_dir=$(cd -- "$(dirname -- "$0")" && pwd)
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/terraris-ss-peer.XXXXXX")
trap 'rm -rf -- "$work_dir"' EXIT
git -C "$source_dir" archive "$revision" | tar -x -C "$work_dir"
mkdir -p "$work_dir/test/terraris-ss-peer"
cp "$fixture_dir/"*.go "$work_dir/test/terraris-ss-peer/"
(cd "$work_dir" && go build -mod=readonly -o "$output" ./test/terraris-ss-peer)
