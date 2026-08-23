#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
ROOT_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd -P)"
BIN_DIR="$ROOT_DIR/bin"
ZAKURA_DIR="$ROOT_DIR/zakura"
ZAINO_DIR="$ROOT_DIR/zaino"
DEVTOOL_DIR="$ROOT_DIR/zcash-devtool"

STAGE_DIR=""

on_error() {
    local status=$?
    printf '[FAIL] build.sh:%s (exit %d)\n' "$BASH_LINENO" "$status" >&2
    exit "$status"
}

cleanup() {
    if [[ -n "$STAGE_DIR" && -d "$STAGE_DIR" ]]; then
        rm -rf -- "$STAGE_DIR"
    fi
}

trap on_error ERR
trap cleanup EXIT

status() {
    printf '\n==> %s\n' "$*"
}

die() {
    printf '[FAIL] %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

require_repo() {
    local repo=$1
    [[ -d "$repo" ]] || die "repository directory not found: $repo"
    [[ -f "$repo/Cargo.toml" ]] || die "Cargo.toml not found in: $repo"
}

stage_binary() {
    local repo=$1
    local binary=$2
    local source="$repo/target/release/$binary"

    [[ -x "$source" ]] || die "expected executable was not built: $source"
    install -m 0755 "$source" "$STAGE_DIR/$binary"
    printf '[OK] staged %s\n' "$binary"
}

build_binary() {
    local label=$1
    local repo=$2
    local package=$3
    local binary=$4
    shift 4

    status "Build $label"
    printf '[INFO] repo=%s package=%s binary=%s\n' "$repo" "$package" "$binary"
    (
        cd "$repo"
        cargo build \
            --locked \
            --release \
            --target-dir "$repo/target" \
            --package "$package" \
            --bin "$binary" \
            "$@"
    )
    stage_binary "$repo" "$binary"
}

verify_binary() {
    local binary=$1
    local path=$2
    local version_hint=$3
    local version
    local version_status=0

    if version="$("$path" --version 2>&1)"; then
        :
    else
        version_status=$?
    fi
    "$path" --help >/dev/null 2>&1

    if (( version_status == 0 )); then
        printf '[OK] %s: %s\n' "$binary" "$version"
    elif [[ "$version" == *"unexpected argument '--version' found"* ]]; then
        printf '[OK] %s: %s (no CLI --version flag; --help succeeded)\n' \
            "$binary" "$version_hint"
    else
        printf '[FAIL] %s --version failed unexpectedly:\n%s\n' "$binary" "$version" >&2
        return 1
    fi
}

status "Check build prerequisites and cloned repositories"
require_command cargo
require_command rustc
require_command install
require_repo "$ZAKURA_DIR"
require_repo "$ZAINO_DIR"
require_repo "$DEVTOOL_DIR"

STAGE_DIR="$(mktemp -d /tmp/coppice-build.XXXXXX)"
printf '[INFO] staging binaries in %s\n' "$STAGE_DIR"

# Zakura's package is named zakura, while its node binary is zakurad.
# Its default features include the repository's release-binary feature set.
build_binary "Zakura (zakurad)" "$ZAKURA_DIR" zakura zakurad

# Zaino's zainod package has an empty default feature set. The local fork's
# Ironwood subtree plumbing is part of that default build.
build_binary "patched Zaino (zainod)" "$ZAINO_DIR" zainod zainod

# Coppice/Regtest support is explicitly feature-gated in zcash-devtool.
build_binary \
    "Coppice-enabled zcash-devtool" \
    "$DEVTOOL_DIR" \
    zcash-devtool \
    zcash-devtool \
    --features regtest_support

status "Verify staged binaries"
verify_binary zakurad "$STAGE_DIR/zakurad" "version flag"
verify_binary zainod "$STAGE_DIR/zainod" "version flag"
DEVTOOL_VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$DEVTOOL_DIR/Cargo.toml" | head -n 1)"
[[ -n "$DEVTOOL_VERSION" ]] || die "could not read zcash-devtool package version"
verify_binary zcash-devtool "$STAGE_DIR/zcash-devtool" \
    "zcash-devtool package $DEVTOOL_VERSION"

status "Install qualification binaries in $BIN_DIR"
mkdir -p "$BIN_DIR"
install -m 0755 "$STAGE_DIR/zakurad" "$BIN_DIR/zakurad"
install -m 0755 "$STAGE_DIR/zainod" "$BIN_DIR/zainod"
install -m 0755 "$STAGE_DIR/zcash-devtool" "$BIN_DIR/zcash-devtool"

status "Verify installed binaries"
verify_binary zakurad "$BIN_DIR/zakurad" "version flag"
verify_binary zainod "$BIN_DIR/zainod" "version flag"
verify_binary zcash-devtool "$BIN_DIR/zcash-devtool" \
    "zcash-devtool package $DEVTOOL_VERSION"

printf '\n[DONE] qualification binaries are available in %s\n' "$BIN_DIR"
