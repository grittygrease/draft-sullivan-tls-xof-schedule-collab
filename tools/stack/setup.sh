#!/usr/bin/env bash
# Bootstrap the optional implementations and their offline dependency caches.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
stack="$root/.stack"
: "${GOROOT_BOOTSTRAP:?Set GOROOT_BOOTSTRAP to an installed bootstrap Go tree}"
stock_go=${STOCK_GO:-$(command -v go)}
if [[ ! -x "$GOROOT_BOOTSTRAP/bin/go" || ! -x "$stock_go" ]]; then
    echo "setup: GOROOT_BOOTSTRAP and STOCK_GO must name installed stock Go tools" >&2
    exit 1
fi
if [[ -e "$stack" ]]; then
    echo "setup: $stack already exists; move it aside before rebuilding" >&2
    exit 1
fi
for tool in curl tar shasum patch git python3 cargo; do
    command -v "$tool" >/dev/null
done

mkdir -p "$stack/gocache" "$stack/tmp" "$stack/modcache" "$stack/cargo-home"
export GOCACHE="$stack/gocache" GOTMPDIR="$stack/tmp" TMPDIR="$stack/tmp"
export GOMODCACHE="$stack/modcache" GOFLAGS=-modcacherw
export GOENV=off GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org,direct
export CARGO_HOME="$stack/cargo-home" CARGO_TARGET_DIR="$stack/cargo-target"

archive="$stack/go1.26.4.src.tar.gz"
curl --fail --location --retry 3 https://go.dev/dl/go1.26.4.src.tar.gz -o "$archive"
printf '%s  %s\n' \
    4f668a32fbfc1132e6a881fb968c2f1dada631492a339211735fbb255a42602d \
    "$archive" | shasum -a 256 -c -
tar -xzf "$archive" -C "$stack"
(
    cd "$stack/go"
    patch --batch -p1 < "$root/tools/stack/go1.26.4-xof.patch"
    cd src
    env -u GOROOT bash make.bash
)

# Read the BoGo revision from this exact toolchain's test, then fetch the
# runner's dependencies using a stock Go (the patched stack runs them later).
bogo_version=$(python3 -c 'import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text()
versions = re.findall(r"const boringsslModVer = \"([^\"]+)\"", text)
assert len(versions) == 1, "expected one pinned BoGo revision"
print(versions[0])' "$stack/go/src/crypto/tls/bogo_shim_test.go")
(
    cd "$stack"
    env -u GOROOT "$stock_go" mod download -json \
        "boringssl.googlesource.com/boringssl.git@$bogo_version" > bogo-module.json
)
bogo_dir=$(python3 -c 'import json, sys
print(json.load(open(sys.argv[1]))["Dir"])' "$stack/bogo-module.json")
# Download the module list from go.mod without touching the cached
# module itself: "mod download all" would rewrite its read-only go.sum.
(
    cd "$bogo_dir"
    env -u GOROOT "$stock_go" mod download
)

revision=$(tr -d '\n\r' < "$root/tools/stack/altkdf-rs.rev")
if [[ ! "$revision" =~ ^[0-9a-f]{40}$ ]]; then
    echo "setup: invalid altkdf-rs revision" >&2
    exit 1
fi
git clone https://github.com/mjosaarinen/altkdf-rs.git "$stack/altkdf-rs"
git -C "$stack/altkdf-rs" checkout --detach "$revision"
(
    cd "$stack/altkdf-rs"
    cargo fetch --locked
    cargo build --offline --locked --release -p deck-schedule --example gen_vectors
    cargo build --offline --locked --release -p tls-demo
)

# The HKDF-only peer for the fallback test, built with stock Go.
(
    cd "$root/tools/stack/stockserver"
    env -u GOROOT "$stock_go" build -o "$stack/bin/stock-server" main.go
)
echo "setup: ready; run make vectors-check and make check-stack"
