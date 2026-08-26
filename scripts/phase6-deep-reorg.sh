#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

usage() {
    cat <<'EOF'
Usage: phase6-deep-reorg.sh [--keep-state]

Run the deterministic Coppice deep-reorg/rebuild qualification without
launching Zakura or Zaino. The focused Rust regressions construct the
canonical state and exercise the configured retention horizon directly.
EOF
}

KEEP_STATE=0
while (($# > 0)); do
    case "$1" in
        --keep-state)
            KEEP_STATE=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf '[FAIL] unknown option: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
ROOT_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd -P)"
COPPICE_DIR="$ROOT_DIR/coppice"
NAMES_DIR="$ROOT_DIR/coppice-names"
WORK_DIR="$(mktemp -d /tmp/coppice-phase6-deep-reorg.XXXXXX)"
LOG_DIR="$WORK_DIR/logs"
CURRENT_STAGE="bootstrap"

cleanup() {
    local status=$?

    trap - EXIT
    if (( status == 0 && KEEP_STATE == 0 )); then
        rm -rf -- "$WORK_DIR"
        printf '\n[CLEAN] removed %s\n' "$WORK_DIR"
    elif (( status == 0 )); then
        printf '\n[KEEP] preserved %s\n' "$WORK_DIR"
    else
        printf '\n[FAIL] stage=%s exit=%d\n' "$CURRENT_STAGE" "$status" >&2
        printf '[FAIL] logs preserved at %s\n' "$WORK_DIR" >&2
        for log in "$LOG_DIR"/*.log; do
            [[ -f "$log" ]] || continue
            printf '\n--- %s tail ---\n' "$log" >&2
            tail -80 "$log" >&2 || true
        done
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

status() {
    CURRENT_STAGE="$*"
    printf '\n==> %s\n' "$*"
}

die() {
    printf '[FAIL] %s\n' "$*" >&2
    exit 1
}

run_logged() {
    local label=$1
    shift
    local output="$LOG_DIR/$label.log"

    printf '[RUN]'
    printf ' %q' "$@"
    printf '\n'
    if "$@" >"$output" 2>&1; then
        printf '[OK] %s\n' "$label"
    else
        local status_code=$?
        printf '[FAIL] %s (exit %d); see %s\n' \
            "$label" "$status_code" "$output" >&2
        tail -100 "$output" >&2 || true
        return "$status_code"
    fi
}

command -v cargo >/dev/null 2>&1 || die "required command not found: cargo"
[[ -d "$COPPICE_DIR" ]] || die "Coppice checkout not found: $COPPICE_DIR"
[[ -d "$NAMES_DIR" ]] || die "Coppice Names checkout not found: $NAMES_DIR"
mkdir -p "$LOG_DIR"

status "Phase 6: deterministic retained reorg, deep rebuild, and lock recovery"
run_logged coppice-names-reorg-tests cargo test --locked \
    --manifest-path "$NAMES_DIR/Cargo.toml" -p coppice-names \
    --test fuzz_properties persisted_delta_reorgs_equal_fresh_replay -- --nocapture
run_logged coppice-names-lifecycle-tests cargo test --locked \
    --manifest-path "$NAMES_DIR/Cargo.toml" -p coppice-names \
    --test names_runtime_lifecycle \
    routed_names_lifecycle_rewind_bond_spend_pruning_and_fresh_replay -- --nocapture
run_logged librustzcash-phase6-tests cargo test --locked \
    --manifest-path "$NAMES_DIR/Cargo.toml" -p coppice-names-librustzcash --lib phase6_ -- --nocapture

printf '\n[PASS] Phase 6 deterministic qualification complete\n'
printf '[PASS] configured retention exercised: 121 blocks; deep fork: 135 blocks from common height 105\n'
printf '[PASS] retained reorg: 15 replacement blocks from common height 225 to tip 240 (within horizon)\n'
printf '[PASS] rebuild signal: ReconcileError::NoRetainedCommonAncestor / NamesRuntimeRewindError\n'
printf '[PASS] replay evidence: activation-checkpoint replacement replay matched an independent clean replay byte-for-byte\n'
printf '[PASS] lock evidence: rebuilt Active bond restored; Released and BondSpent bonds were not protected\n'
printf '[PASS] logs: %s\n' "$WORK_DIR"
