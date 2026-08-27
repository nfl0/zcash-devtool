#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

# Phase 1 qualifies the local Zakura -> Zaino -> zcash-devtool plumbing; Phase 2
# extends that same stack with the live Coppice lifecycle and shallow reorg;
# Phase 3 checks fresh same-seed recovery; Phase 4 checks account isolation;
# Phase 5 attacks every wallet-backed Ironwood spend boundary and protection mode.
# Phase 6 dispatches to the deterministic Coppice/coppice-librustzcash deep
# reorg qualification and deliberately does not launch the live stack. Phase 7
# runs phases 1-5 and then forces a beyond-retention reorg through the real
# Zakura -> Zaino -> zcash-devtool stack. Phase 8 runs one disposable v2
# COMMIT -> REVEAL flow, including canonical replay acceptance.
# Every node, database, wallet, and log is disposable and lives below one
# run-specific directory under /tmp.

usage() {
    cat <<'EOF'
Usage: live-qualification.sh [--phase N] [--keep-state]
       live-qualification.sh --resume RUN_DIR --phase 5 [--keep-state]

Options:
  --phase N       Run a fresh stack through phase N (1-5), run deterministic
                  Phase 6, run all live phases including deep-reorg Phase 7,
                  or run the one live v2 COMMIT -> REVEAL flow (Phase 8).
                  The default is 5.
  --resume DIR   Reuse a Phase 4 checkpoint and run only Phase 5. The directory
                  must have been produced with --phase 4 --keep-state.
  --keep-state   Preserve the disposable run directory after success. This is
                  required when creating a checkpoint for --resume.
  -h, --help     Show this help.

Examples:
  ./scripts/live-qualification.sh --phase 1
  ./scripts/live-qualification.sh --phase 4 --keep-state
  ./scripts/live-qualification.sh --resume /tmp/coppice-live-qualification.X --phase 5
  ./scripts/live-qualification.sh --phase 6
  ./scripts/live-qualification.sh --phase 7
  ./scripts/live-qualification.sh --phase 8 --keep-state
EOF
}

TARGET_PHASE=5
RESUME_DIR=""
KEEP_STATE=0
PHASE_ARGUMENT_GIVEN=0
while (($# > 0)); do
    case "$1" in
        --phase|--through)
            (($# >= 2)) || { usage >&2; exit 2; }
            TARGET_PHASE=$2
            PHASE_ARGUMENT_GIVEN=1
            shift 2
            ;;
        --resume)
            (($# >= 2)) || { usage >&2; exit 2; }
            RESUME_DIR=$2
            shift 2
            ;;
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

[[ "$TARGET_PHASE" =~ ^[1-8]$ ]] || {
    printf '[FAIL] --phase must be an integer from 1 through 8\n' >&2
    exit 2
}
if [[ -n "$RESUME_DIR" ]]; then
    (( PHASE_ARGUMENT_GIVEN == 1 )) || {
        printf '[FAIL] --resume requires an explicit --phase 5\n' >&2
        exit 2
    }
    [[ "$TARGET_PHASE" == 5 ]] || {
        printf '[FAIL] --resume currently supports only --phase 5\n' >&2
        exit 2
    }
    RESUME_DIR="$(CDPATH= cd -- "$RESUME_DIR" && pwd -P)"
    [[ "$RESUME_DIR" == /tmp/coppice-live-qualification.* ]] || {
        printf '[FAIL] --resume must point to a generated /tmp/coppice-live-qualification.* run\n' >&2
        exit 2
    }
    START_PHASE=5
else
    START_PHASE=1
fi

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
ROOT_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd -P)"

if [[ "$TARGET_PHASE" == 6 ]]; then
    [[ -z "$RESUME_DIR" ]] || {
        printf '[FAIL] Phase 6 is deterministic and does not accept --resume\n' >&2
        exit 2
    }
    PHASE6_ARGS=()
    if (( KEEP_STATE == 1 )); then
        PHASE6_ARGS+=(--keep-state)
    fi
    exec "$SCRIPT_DIR/phase6-deep-reorg.sh" "${PHASE6_ARGS[@]}"
fi

BIN_DIR="$ROOT_DIR/bin"
ZAKURA_BIN="$BIN_DIR/zakurad"
ZAINO_BIN="$BIN_DIR/zainod"
DEVTOOL_BIN="$BIN_DIR/zcash-devtool"
NAMES_V2_LIVE_BIN="$ROOT_DIR/zcash-devtool/target/debug/names-v2-live"

ZAKURA_RPC_ADDR="127.0.0.1:18232"
ZAKURA_RPC_URL="http://$ZAKURA_RPC_ADDR"
ZAKURA_P2P_ADDR="127.0.0.1:18233"
ZAINO_GRPC_ADDR="127.0.0.1:8137"
ZAINO_GRPC_URL="http://$ZAINO_GRPC_ADDR"

COPPICE_NAME_ONE="phase2-alpha"
COPPICE_NAME_TWO="phase2-beta"
PHASE4_NAME_ONE="phase4-account-a"
PHASE4_NAME_TWO="phase4-account-b"
PHASE5_NAME_PENDING="phase5-pending"
COPPICE_BOND_VALUE=100000000
PHASE4_ACCOUNT_FUNDING_VALUE=400000000
# The production registration path deliberately selects an exact-minimum
# bond unless a caller explicitly opts into larger-note bonding.
PHASE5_PENDING_FUNDING_VALUE=$COPPICE_BOND_VALUE
# Coppice Regtest qualification activation height in the pinned parameters.
COPPICE_ACTIVATION_HEIGHT=10

# Disposable BIP-39 zero-entropy test mnemonic (23 x "abandon" + "art").
# Never use it for funds outside this local Regtest.
WALLET_MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
# Separate disposable mnemonic used only to derive an external transparent
# destination for the pre-NU6.3 bootstrap Sapling coinbase note.
SAPLING_DISCARD_MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

if [[ -n "$RESUME_DIR" ]]; then
    WORK_DIR="$RESUME_DIR"
else
    WORK_DIR="$(mktemp -d /tmp/coppice-live-qualification.XXXXXX)"
fi
CONFIG_DIR="$WORK_DIR/config"
STATE_DIR="$WORK_DIR/state"
ZAKURA_STATE_DIR="$STATE_DIR/zakura"
ZAINO_STATE_DIR="$STATE_DIR/zaino"
WALLET_DIR="$STATE_DIR/wallet"
RECOVERY_WALLET_DIR="$STATE_DIR/recovery-wallet"
PHASE4_RECOVERY_WALLET_DIR="$STATE_DIR/phase4-recovery-wallet"
PHASE5_OFF_WALLET_DIR="$STATE_DIR/phase5-off-wallet"
PHASE5_PCZT_DIR="$STATE_DIR/phase5-pczt"
PHASE7_RECOVERY_WALLET_DIR="$STATE_DIR/phase7-recovery-wallet"
ZAKURA_CONFIG="$CONFIG_DIR/zakura.toml"
ZAINO_CONFIG="$CONFIG_DIR/zaino.toml"
ACTIVATION_FILE="$CONFIG_DIR/activation-heights.toml"
IDENTITY_FILE="$WALLET_DIR/identity.txt"
RECOVERY_IDENTITY_FILE="$RECOVERY_WALLET_DIR/identity.txt"
PHASE4_RECOVERY_IDENTITY_FILE="$PHASE4_RECOVERY_WALLET_DIR/identity.txt"
PHASE5_OFF_IDENTITY_FILE="$PHASE5_OFF_WALLET_DIR/identity.txt"
PHASE7_RECOVERY_IDENTITY_FILE="$PHASE7_RECOVERY_WALLET_DIR/identity.txt"
PHASE4_CHECKPOINT="$WORK_DIR/phase4.env"

if [[ -n "$RESUME_DIR" ]]; then
    [[ -d "$WORK_DIR" ]] || {
        printf '[FAIL] resume run directory does not exist: %s\n' "$WORK_DIR" >&2
        exit 1
    }
    [[ -f "$PHASE4_CHECKPOINT" ]] || {
        printf '[FAIL] missing Phase 4 checkpoint: %s\n' "$PHASE4_CHECKPOINT" >&2
        exit 1
    }
    # This file is written by this script and contains only shell-quoted
    # deterministic wallet/account values needed by the Phase 5 continuation.
    # shellcheck disable=SC1090
    source "$PHASE4_CHECKPOINT"
    for checkpoint_var in \
        MINER_UA ACCOUNT_A_UUID ACCOUNT_B_UUID ACCOUNT_A_WALLET_ID \
        ACCOUNT_B_WALLET_ID PHASE4_UA_ONE PHASE4_UA_TWO \
        PHASE4_COMMITMENT_A PHASE4_COMMITMENT_B \
        PHASE4_A_REVEAL_HEIGHT_EXPECTED PHASE4_B_REVEAL_HEIGHT_EXPECTED \
        PHASE4_A_ACTIVE_LOCKED PHASE4_B_ACTIVE_LOCKED; do
        [[ -n "${!checkpoint_var:-}" ]] || {
            printf '[FAIL] checkpoint is missing %s\n' "$checkpoint_var" >&2
            exit 1
        }
    done
    for required_path in "$CONFIG_DIR" "$ZAKURA_STATE_DIR" "$ZAINO_STATE_DIR" \
        "$WALLET_DIR" "$IDENTITY_FILE"; do
        [[ -e "$required_path" ]] || {
            printf '[FAIL] checkpoint path is missing: %s\n' "$required_path" >&2
            exit 1
        }
    done
fi

if [[ -n "$RESUME_DIR" ]]; then
    LOG_DIR="$WORK_DIR/logs/phase${TARGET_PHASE}-resume"
else
    LOG_DIR="$WORK_DIR/logs"
fi
GRPC_DIR="$LOG_DIR/grpc"

mkdir -p "$CONFIG_DIR" "$ZAKURA_STATE_DIR" "$ZAINO_STATE_DIR" "$WALLET_DIR" \
    "$PHASE5_PCZT_DIR" "$LOG_DIR" "$GRPC_DIR"
umask 077

ZAKURA_PID=""
ZAINO_PID=""
CURRENT_STAGE="bootstrap"

cleanup() {
    local status=$?

    trap - EXIT
    set +e

    if [[ -n "$ZAINO_PID" ]]; then
        kill -TERM "$ZAINO_PID" 2>/dev/null || true
    fi
    if [[ -n "$ZAKURA_PID" ]]; then
        kill -TERM "$ZAKURA_PID" 2>/dev/null || true
    fi
    if [[ -n "$ZAINO_PID" ]]; then
        wait "$ZAINO_PID" 2>/dev/null || true
    fi
    if [[ -n "$ZAKURA_PID" ]]; then
        wait "$ZAKURA_PID" 2>/dev/null || true
    fi

    if (( status == 0 && KEEP_STATE == 0 )); then
        rm -rf -- "$WORK_DIR"
        printf '\n[CLEAN] removed %s\n' "$WORK_DIR"
    elif (( status == 0 )); then
        printf '\n[KEEP] preserved %s\n' "$WORK_DIR"
        if [[ -f "$PHASE4_CHECKPOINT" ]]; then
            printf '[KEEP] resume Phase 5 with: %q --resume %q --phase 5\n' \
                "$0" "$WORK_DIR"
        fi
    else
        printf '\n[FAIL] stage=%s exit=%d\n' "$CURRENT_STAGE" "$status" >&2
        printf '[FAIL] logs and disposable state preserved at %s\n' "$WORK_DIR" >&2
        if [[ -f "$LOG_DIR/zakura.log" ]]; then
            printf '\n--- zakurad tail ---\n' >&2
            tail -40 "$LOG_DIR/zakura.log" >&2 || true
        fi
        if [[ -f "$LOG_DIR/zainod.log" ]]; then
            printf '\n--- zainod tail ---\n' >&2
            tail -60 "$LOG_DIR/zainod.log" >&2 || true
        fi
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

write_phase4_checkpoint() {
    local checkpoint_tmp="$PHASE4_CHECKPOINT.tmp"

    {
        printf '# Generated by live-qualification.sh; do not edit.\n'
        printf 'MINER_UA=%q\n' "$MINER_UA"
        printf 'ACCOUNT_A_UUID=%q\n' "$ACCOUNT_A_UUID"
        printf 'ACCOUNT_B_UUID=%q\n' "$ACCOUNT_B_UUID"
        printf 'ACCOUNT_A_WALLET_ID=%q\n' "$ACCOUNT_A_WALLET_ID"
        printf 'ACCOUNT_B_WALLET_ID=%q\n' "$ACCOUNT_B_WALLET_ID"
        printf 'PHASE4_UA_ONE=%q\n' "$PHASE4_UA_ONE"
        printf 'PHASE4_UA_TWO=%q\n' "$PHASE4_UA_TWO"
        printf 'PHASE4_COMMITMENT_A=%q\n' "$PHASE4_COMMITMENT_A"
        printf 'PHASE4_COMMITMENT_B=%q\n' "$PHASE4_COMMITMENT_B"
        printf 'PHASE4_A_REVEAL_HEIGHT_EXPECTED=%q\n' \
            "$PHASE4_A_REVEAL_HEIGHT_EXPECTED"
        printf 'PHASE4_B_REVEAL_HEIGHT_EXPECTED=%q\n' \
            "$PHASE4_B_REVEAL_HEIGHT_EXPECTED"
        printf 'PHASE4_A_ACTIVE_LOCKED=%q\n' "$PHASE4_A_ACTIVE_LOCKED"
        printf 'PHASE4_B_ACTIVE_LOCKED=%q\n' "$PHASE4_B_ACTIVE_LOCKED"
    } >"$checkpoint_tmp"
    mv -- "$checkpoint_tmp" "$PHASE4_CHECKPOINT"
    printf '[OK] wrote Phase 4 continuation checkpoint %s\n' "$PHASE4_CHECKPOINT"
}

finish_phase_if_requested() {
    local completed_phase=$1

    if (( TARGET_PHASE == completed_phase )); then
        printf '\n[PASS] requested qualification through Phase %s complete\n' \
            "$completed_phase"
        exit 0
    fi
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

require_executable() {
    [[ -x "$1" ]] || die "required executable not found: $1"
}

print_command() {
    local arg
    printf '[RUN]'
    for arg in "$@"; do
        printf ' %q' "$arg"
    done
    printf '\n'
}

run_logged() {
    local label=$1
    shift
    local output="$LOG_DIR/$label.log"

    print_command "$@"
    if "$@" >"$output" 2>&1; then
        printf '[OK] %s\n' "$label"
    else
        local status=$?
        printf '[FAIL] %s (exit %d); see %s\n' "$label" "$status" "$output" >&2
        tail -80 "$output" >&2 || true
        return "$status"
    fi
}

run_devtool_logged() {
    local label=$1
    shift
    run_logged "$label" timeout 240 "$DEVTOOL_BIN" "$@"
}

run_devtool_stdin_logged() {
    local label=$1
    local input=$2
    shift 2
    local output="$LOG_DIR/$label.log"

    printf '[RUN]'
    for arg in timeout 240 "$DEVTOOL_BIN" "$@"; do
        printf ' %q' "$arg"
    done
    printf ' < %q\n' "$input"
    if timeout 240 "$DEVTOOL_BIN" "$@" <"$input" >"$output" 2>&1; then
        printf '[OK] %s\n' "$label"
    else
        local status=$?
        printf '[FAIL] %s (exit %d); see %s\n' "$label" "$status" "$output" >&2
        tail -80 "$output" >&2 || true
        return "$status"
    fi
}

run_devtool_stdin_expect_failure() {
    local label=$1
    local input=$2
    shift 2
    local output="$LOG_DIR/$label.log"

    printf '[RUN]'
    for arg in timeout 240 "$DEVTOOL_BIN" "$@"; do
        printf ' %q' "$arg"
    done
    printf ' < %q\n' "$input"
    if timeout 240 "$DEVTOOL_BIN" "$@" <"$input" >"$output" 2>&1; then
        printf '[FAIL] %s unexpectedly succeeded; see %s\n' "$label" "$output" >&2
        tail -80 "$output" >&2 || true
        return 1
    fi
    printf '[PASS] %s failed as expected\n' "$label"
}

run_devtool_expect_failure() {
    local label=$1
    shift
    local output="$LOG_DIR/$label.log"

    print_command timeout 240 "$DEVTOOL_BIN" "$@"
    if timeout 240 "$DEVTOOL_BIN" "$@" >"$output" 2>&1; then
        printf '[FAIL] %s unexpectedly succeeded; see %s\n' "$label" "$output" >&2
        tail -80 "$output" >&2 || true
        return 1
    fi
    printf '[PASS] %s failed as expected\n' "$label"
}

wallet_sync_logged_for() {
    local label=$1
    local wallet_dir=$2

    run_devtool_logged "$label" wallet \
        --wallet-dir "$wallet_dir" sync \
        --server "$ZAINO_GRPC_ADDR" --connection direct
}

wallet_sync_logged() {
    wallet_sync_logged_for "$1" "$WALLET_DIR"
}

wallet_status_logged_for() {
    local label=$1
    local wallet_dir=$2

    run_devtool_logged "$label" wallet \
        --wallet-dir "$wallet_dir" coppice status
}

wallet_status_logged() {
    wallet_status_logged_for "$1" "$WALLET_DIR"
}

wallet_balance_logged_for() {
    local label=$1
    local wallet_dir=$2
    local account_id=$3

    run_devtool_logged "$label" wallet \
        --wallet-dir "$wallet_dir" balance --json --min-confirmations 1 "$account_id"
}

balance_json() {
    local label=$1
    local output

    output="$(rg -a '^[{]' "$LOG_DIR/$label.log" | tail -1)"
    [[ -n "$output" ]] || die "balance command $label did not emit JSON"
    printf '%s\n' "$output"
}

balance_locked_value() {
    local label=$1

    # Balance.total includes values that are not currently spendable, while
    # each pool-specific *_spendable field includes all ordinary spendable
    # pools. Subtract every spendable pool so Sapling/other-pool value does
    # not masquerade as an Ironwood Coppice lock.
    jq -r '.total - (.sapling_spendable + .orchard_spendable + .ironwood_spendable + .transparent_spendable)' \
        <<<"$(balance_json "$label")"
}

balance_spendable_value() {
    local label=$1

    jq -r '.ironwood_spendable' <<<"$(balance_json "$label")"
}

balance_total_value() {
    local label=$1

    jq -r '.total' <<<"$(balance_json "$label")"
}

account_record_for_name() {
    local output=$1
    local name=$2

    python3 - "$output" "$name" <<'PY'
import json
import pathlib
import sys

path, target = sys.argv[1:]
current = None
for line in pathlib.Path(path).read_text().splitlines():
    if line.startswith("Account "):
        current = {"uuid": line.split()[1]}
    elif line.startswith("     Name: ") and current is not None:
        current["name"] = line.removeprefix("     Name: ")
    elif line.startswith("     UIVK: ") and current is not None:
        current["uivk"] = line.removeprefix("     UIVK: ")
    elif line.startswith("     UFVK: ") and current is not None:
        current["ufvk"] = line.removeprefix("     UFVK: ")
    elif line.startswith("       Account index: ") and current is not None:
        current["index"] = line.removeprefix("       Account index: ")
        if current.get("name") == target:
            print(json.dumps(current, sort_keys=True))
            raise SystemExit(0)

raise SystemExit(f"account {target!r} not found in {path}")
PY
}

wallet_account_id_from_status() {
    local label=$1
    local account_uuid=$2

    jq -er --arg uuid "$account_uuid" \
        '.wallet_accounts[] | select(.account_uuid == $uuid) | .wallet_account_id' \
        "$LOG_DIR/$label.log"
}

assert_pending_owner() {
    local status_label=$1
    local commitment=$2
    local name=$3
    local expected_account_id=$4

    jq -e \
        --arg commitment "$commitment" \
        --arg name "$name" \
        --arg account_id "$expected_account_id" \
        '.local_registrations
         | any(.[]; .commitment == $commitment
                    and .name == $name
                    and .account_id == $account_id)' \
        "$LOG_DIR/$status_label.log" >/dev/null \
        || die "$status_label does not bind $name/$commitment to WalletAccountId $expected_account_id"
    printf '[PASS] pending %s is bound to FVK-derived WalletAccountId %s\n' \
        "$name" "$expected_account_id"
}

assert_no_pending_commitment() {
    local status_label=$1
    local commitment=$2

    jq -e --arg commitment "$commitment" \
        'all(.local_registrations[]; .commitment != $commitment)' \
        "$LOG_DIR/$status_label.log" >/dev/null \
        || die "$status_label still contains completed commitment $commitment"
}

assert_account_records_match() {
    local original_json=$1
    local fresh_json=$2
    local label=$3

    jq -n -e --argjson original "$original_json" --argjson fresh "$fresh_json" \
        '$original.index == $fresh.index
         and $original.uivk == $fresh.uivk
         and $original.ufvk == $fresh.ufvk' \
        >/dev/null \
        || die "$label did not recreate the same deterministic account keys"
    printf '[PASS] %s recreated the same deterministic account index/UIVK/UFVK\n' "$label"
}

assert_coppice_status() {
    local label=$1
    local expected_height=$2
    local expected_protection=$3
    local expected_names=$4
    local expected_pending=$5
    local output="$LOG_DIR/$label.log"

    jq -e \
        --arg protection "$expected_protection" \
        --argjson height "$expected_height" \
        --argjson names "$expected_names" \
        --argjson pending "$expected_pending" \
        '.protection == $protection
         and .tip_height == $height
         and .names == $names
         and .pending_protocol_commits == $pending' \
        "$output" >/dev/null \
        || die "unexpected Coppice status in $output"
    printf '[PASS] Coppice status tip=%s protection=%s names=%s pending=%s\n' \
        "$expected_height" "$expected_protection" "$expected_names" "$expected_pending"
}

reverse_hex() {
    python3 - "$1" <<'PY'
import sys

print(bytes.fromhex(sys.argv[1])[::-1].hex())
PY
}

assert_coppice_tip_hash() {
    local label=$1
    local expected_rpc_hash=$2
    local output="$LOG_DIR/$label.log"
    local actual reversed

    actual="$(jq -r '.tip_hash' "$output")"
    reversed="$(reverse_hex "$expected_rpc_hash")"
    if [[ "$actual" != "$expected_rpc_hash" && "$actual" != "$reversed" ]]; then
        die "Coppice tip hash $actual does not match Zakura RPC hash $expected_rpc_hash"
    fi
    printf '[PASS] Coppice canonical tip hash matches Zakura replacement tip\n'
}

assert_snapshot_status_for() {
    local wallet_dir=$1
    local name=$2
    local expected_status=$3
    local expected_height=$4

    jq -e \
        --arg name "$name" \
        --arg expected "$expected_status" \
        --argjson height "$expected_height" \
        '
        (.application_snapshot | implode | fromjson) as $application
        | def record:
          [$application.state.names[] | select(.[0] == $name)]
          | if length == 1 then .[0][1] else null end;
        (record) as $record
        | .format_version == 1
          and .tip.height == $height
          and $application.format_version == 1
          and $record != null
          and (if $expected == "Active" then
                 $record.status == "Active"
               elif $expected == "Released" then
                 (($record.status | type) == "object"
                   and ($record.status | has("Released")))
               elif $expected == "BondSpent" then
                 (($record.status | type) == "object"
                   and ($record.status | has("BondSpent")))
               else false
               end)' \
        "$wallet_dir/coppice-runtime-v1.json" >/dev/null \
        || die "Coppice snapshot does not show $name=$expected_status at height $expected_height"
    printf '[PASS] canonical Coppice snapshot: %s=%s at height %s\n' \
        "$name" "$expected_status" "$expected_height"
}

assert_snapshot_status() {
    assert_snapshot_status_for "$WALLET_DIR" "$@"
}

assert_resolved_address_for() {
    local label=$1
    local wallet_dir=$2
    local name=$3
    local expected=$4
    local output="$LOG_DIR/$label.log"
    local actual

    run_devtool_logged "$label" wallet \
        --wallet-dir "$wallet_dir" coppice resolve "$name"
    actual="$(tail -1 "$output" | tr -d '\r')"
    [[ "$actual" == "$expected" ]] \
        || die "resolve($name) returned $actual, expected $expected"
    printf '[PASS] resolve(%s)=%s\n' "$name" "$actual"
}

assert_resolved_address() {
    assert_resolved_address_for "$1" "$WALLET_DIR" "$2" "$3"
}

assert_resolve_inactive_for() {
    local label=$1
    local wallet_dir=$2
    local name=$3
    local output="$LOG_DIR/$label.log"

    run_devtool_expect_failure "$label" wallet \
        --wallet-dir "$wallet_dir" coppice resolve "$name"
    [[ -s "$output" ]] || die "inactive resolve($name) produced no diagnostic"
    printf '[PASS] resolve(%s) is unavailable/inactive\n' "$name"
}

assert_resolve_inactive() {
    assert_resolve_inactive_for "$1" "$WALLET_DIR" "$2"
}

rpc_call() {
    local method=$1
    local params=$2
    local request

    request="$(jq -cn \
        --arg method "$method" \
        --argjson params "$params" \
        '{jsonrpc:"2.0",id:1,method:$method,params:$params}')"

    curl --silent --show-error \
        --connect-timeout 2 --max-time 15 \
        -H 'content-type: application/json' \
        --data-binary "$request" "$ZAKURA_RPC_URL"
}

rpc_generate() {
    local count=$1
    local response

    printf '[RPC] generate %s\n' "$count"
    if ! response="$(rpc_call generate "[$count]")"; then
        die "Zakura generate RPC transport failed"
    fi
    printf '%s\n' "$response" >>"$LOG_DIR/zakura-rpc.log"
    if ! jq -e --argjson expected "$count" \
        '.error == null and (.result | type == "array") and (.result | length == $expected)' \
        >/dev/null <<<"$response"; then
        printf '%s\n' "$response" >&2
        die "Zakura generate RPC returned an error or the wrong block count"
    fi
}

rpc_generate_batched() {
    local remaining=$1
    local batch_size=${2:-20}
    local batch

    (( remaining >= 0 )) || die "batched generation count must be non-negative"
    (( batch_size > 0 )) || die "batched generation size must be positive"
    while (( remaining > 0 )); do
        batch=$batch_size
        if (( batch > remaining )); then
            batch=$remaining
        fi
        rpc_generate "$batch"
        remaining=$((remaining - batch))
    done
}

zakura_tip_height() {
    local response

    if ! response="$(rpc_call getblockchaininfo '[]')"; then
        die "Zakura getblockchaininfo RPC transport failed"
    fi
    jq -e '.error == null and (.result.blocks | type == "number")' >/dev/null <<<"$response" \
        || die "Zakura getblockchaininfo RPC returned an error"
    jq -r '.result.blocks' <<<"$response"
}

zakura_block_hash() {
    local height=$1
    local response

    if ! response="$(rpc_call getblockhash "[$height]")"; then
        die "Zakura getblockhash RPC transport failed at height $height"
    fi
    jq -e '.error == null and (.result | type == "string")' >/dev/null <<<"$response" \
        || die "Zakura getblockhash RPC returned an error at height $height"
    jq -r '.result' <<<"$response"
}

wait_for_zakura_tip() {
    local target=$1
    local attempt height

    for ((attempt = 1; attempt <= 120; attempt++)); do
        if kill -0 "$ZAKURA_PID" 2>/dev/null \
            && height="$(zakura_tip_height 2>/dev/null)" \
            && (( height == target )); then
            printf '[PASS] Zakura canonical tip height %s\n' "$height"
            return 0
        fi
        sleep 1
    done

    die "timed out waiting for Zakura canonical tip height $target"
}

rpc_invalidate_block() {
    local block_hash=$1
    local response
    local params

    params="$(jq -cn --arg hash "$block_hash" '[$hash]')"
    printf '[RPC] invalidateblock %s\n' "$block_hash"
    if ! response="$(rpc_call invalidateblock "$params")"; then
        die "Zakura invalidateblock RPC transport failed"
    fi
    printf '%s\n' "$response" >>"$LOG_DIR/zakura-rpc.log"
    jq -e '.error == null' >/dev/null <<<"$response" \
        || die "Zakura invalidateblock RPC returned an error: $response"
}

wait_for_zakura_rpc() {
    local attempt response

    for ((attempt = 1; attempt <= 90; attempt++)); do
        if ! kill -0 "$ZAKURA_PID" 2>/dev/null; then
            die "zakurad exited before JSON-RPC became ready"
        fi
        if response="$(rpc_call getblockchaininfo '[]' 2>/dev/null)" \
            && jq -e '.error == null and .result.chain == "test"' >/dev/null <<<"$response"; then
            printf '[PASS] Zakura JSON-RPC ready: chain=%s height=%s\n' \
                "$(jq -r '.result.chain' <<<"$response")" \
                "$(jq -r '.result.blocks' <<<"$response")"
            return 0
        fi
        sleep 1
    done

    die "timed out waiting for Zakura JSON-RPC at $ZAKURA_RPC_URL"
}

write_grpc_frame() {
    local payload_hex=$1
    local output=$2

    python3 - "$payload_hex" "$output" <<'PY'
import pathlib
import struct
import sys

payload = bytes.fromhex(sys.argv[1])
pathlib.Path(sys.argv[2]).write_bytes(b"\x00" + struct.pack(">I", len(payload)) + payload)
PY
}

grpc_call() {
    local method=$1
    local payload_hex=$2
    local label=$3
    local request="$GRPC_DIR/$label.request"
    local headers="$GRPC_DIR/$label.headers"
    local body="$GRPC_DIR/$label.body"
    local trace="$GRPC_DIR/$label.trace"

    write_grpc_frame "$payload_hex" "$request"
    : >"$headers"
    : >"$body"
    : >"$trace"

    curl --silent --show-error --http2-prior-knowledge \
        --connect-timeout 2 --max-time 20 \
        --dump-header "$headers" \
        --trace-ascii "$trace" \
        -H 'content-type: application/grpc' \
        -H 'te: trailers' \
        -H 'grpc-encoding: identity' \
        -H 'grpc-accept-encoding: identity' \
        --data-binary "@$request" \
        --output "$body" \
        "$ZAINO_GRPC_URL/cash.z.wallet.sdk.rpc.CompactTxStreamer/$method" \
        >/dev/null 2>>"$trace" || return 1

    if rg -a -qi 'grpc-status:[[:space:]]*0' "$headers" "$trace"; then
        return 0
    fi
    return 1
}

grpc_error_contains() {
    local label=$1

    rg -a -qi \
        'Invalid shielded protocol value|Invalid%20shielded%20protocol%20value' \
        "$GRPC_DIR/$label.headers" "$GRPC_DIR/$label.trace" "$GRPC_DIR/$label.body"
}

parse_latest_block_height() {
    local body=$1

    python3 - "$body" <<'PY'
import pathlib
import struct
import sys

data = pathlib.Path(sys.argv[1]).read_bytes()

def read_varint(buf, pos):
    value = 0
    shift = 0
    while pos < len(buf):
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7f) << shift
        if byte < 0x80:
            return value, pos
        shift += 7
        if shift >= 64:
            raise ValueError("protobuf varint too long")
    raise ValueError("truncated protobuf varint")

def parse_block_id(payload):
    pos = 0
    while pos < len(payload):
        tag, pos = read_varint(payload, pos)
        field = tag >> 3
        wire = tag & 7
        if wire == 0:
            value, pos = read_varint(payload, pos)
            if field == 1:
                return value
        elif wire == 1:
            pos += 8
        elif wire == 2:
            size, pos = read_varint(payload, pos)
            pos += size
        elif wire == 5:
            pos += 4
        else:
            return None
    return None

offset = 0
while offset + 5 <= len(data):
    compressed = data[offset]
    length = struct.unpack(">I", data[offset + 1:offset + 5])[0]
    offset += 5
    payload = data[offset:offset + length]
    offset += length
    if compressed == 0 and len(payload) == length:
        height = parse_block_id(payload)
        if height is not None:
            print(height)
            raise SystemExit(0)

raise SystemExit(1)
PY
}

parse_latest_block_hash() {
    local body=$1

    python3 - "$body" <<'PY'
import pathlib
import struct
import sys

data = pathlib.Path(sys.argv[1]).read_bytes()

def read_varint(buf, pos):
    value = 0
    shift = 0
    while pos < len(buf):
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7f) << shift
        if byte < 0x80:
            return value, pos
        shift += 7
        if shift >= 64:
            raise ValueError("protobuf varint too long")
    raise ValueError("truncated protobuf varint")

offset = 0
while offset + 5 <= len(data):
    compressed = data[offset]
    length = struct.unpack(">I", data[offset + 1:offset + 5])[0]
    offset += 5
    payload = data[offset:offset + length]
    offset += length
    if compressed != 0 or len(payload) != length:
        continue

    pos = 0
    while pos < len(payload):
        tag, pos = read_varint(payload, pos)
        field = tag >> 3
        wire = tag & 7
        if wire == 0:
            _, pos = read_varint(payload, pos)
        elif wire == 1:
            pos += 8
        elif wire == 2:
            size, pos = read_varint(payload, pos)
            value = payload[pos:pos + size]
            pos += size
            if field == 2 and len(value) == 32:
                print(value.hex())
                raise SystemExit(0)
        elif wire == 5:
            pos += 4
        else:
            raise ValueError("unsupported protobuf wire type")

raise SystemExit(1)
PY
}

wait_for_grpc_ready() {
    local attempt

    for ((attempt = 1; attempt <= 120; attempt++)); do
        if ! kill -0 "$ZAINO_PID" 2>/dev/null; then
            die "zainod exited before gRPC became ready"
        fi
        if grpc_call GetLightdInfo '' readiness; then
            printf '[PASS] Zaino gRPC ready at %s\n' "$ZAINO_GRPC_ADDR"
            return 0
        fi
        sleep 1
    done

    printf '[INFO] readiness trace:\n' >&2
    tail -80 "$GRPC_DIR/readiness.trace" >&2 || true
    die "timed out waiting for Zaino gRPC at $ZAINO_GRPC_ADDR"
}

wait_for_zaino_tip() {
    local target=$1
    local attempt height

    for ((attempt = 1; attempt <= 120; attempt++)); do
        if grpc_call GetLatestBlock '' latest-block; then
            if height="$(parse_latest_block_height "$GRPC_DIR/latest-block.body" 2>/dev/null)" \
                && (( height >= target )); then
                printf '[PASS] Zaino indexed through height %s (target %s)\n' "$height" "$target"
                return 0
            fi
        fi
        sleep 1
    done

    printf '[INFO] latest-block trace:\n' >&2
    tail -80 "$GRPC_DIR/latest-block.trace" >&2 || true
    die "timed out waiting for Zaino to index height $target"
}

wait_for_zaino_tip_hash() {
    local target_hash=$1
    local target_height=$2
    local reversed attempt height actual

    reversed="$(reverse_hex "$target_hash")"
    for ((attempt = 1; attempt <= 120; attempt++)); do
        if grpc_call GetLatestBlock '' latest-block; then
            if height="$(parse_latest_block_height "$GRPC_DIR/latest-block.body" 2>/dev/null)" \
                && actual="$(parse_latest_block_hash "$GRPC_DIR/latest-block.body" 2>/dev/null)" \
                && (( height == target_height )) \
                && [[ "$actual" == "$target_hash" || "$actual" == "$reversed" ]]; then
                printf '[PASS] Zaino canonical tip hash matches replacement at height %s\n' "$height"
                return 0
            fi
        fi
        sleep 1
    done

    printf '[INFO] latest-block trace:\n' >&2
    tail -80 "$GRPC_DIR/latest-block.trace" >&2 || true
    die "timed out waiting for Zaino replacement tip $target_hash at height $target_height"
}

write_configs() {
    cat >"$ACTIVATION_FILE" <<EOF
overwinter = 1
sapling = 1
blossom = 1
heartwood = 1
canopy = 1
nu5 = 2
nu6 = 2
nu6_1 = 2
nu6_2 = 2
nu6_3 = 2
EOF

    cat >"$ZAKURA_CONFIG" <<EOF
[network]
network = "Regtest"
listen_addr = "$ZAKURA_P2P_ADDR"
p2p_stack = "legacy"
cache_dir = false
identity_dir = "$ZAKURA_STATE_DIR/identity"
initial_testnet_peers = []
max_connections_per_ip = 10
peerset_initial_target_size = 1

[network.testnet_parameters]
lockbox_disbursements = [
    { address = "t26YoyZ1iPgiMEWL4zGUm74eVWfhyDMXzY2", amount = 0 },
]

[network.testnet_parameters.activation_heights]
Overwinter = 1
Sapling = 1
Blossom = 1
Heartwood = 1
Canopy = 1
"NU5" = 2
"NU6" = 2
"NU6.1" = 2
"NU6.2" = 2
"NU6.3" = 2

[state]
cache_dir = "$ZAKURA_STATE_DIR/chain"
ephemeral = false
should_backup_non_finalized_state = true
delete_old_database = true
storage_mode = "archive"

[rpc]
listen_addr = "$ZAKURA_RPC_ADDR"
cookie_dir = "$ZAKURA_STATE_DIR/rpc"
enable_cookie_auth = false

[mining]
internal_miner = false
miner_address = "$MINER_UA"

[tracing]
filter = "info"
use_color = false
force_use_color = false
use_journald = false
EOF

    cat >"$ZAINO_CONFIG" <<EOF
backend = "rpc"
zebra_db_path = "$ZAINO_STATE_DIR/zebra-db"
ephemeral_finalised_state = false
network = "Regtest"

[grpc_settings]
listen_address = "$ZAINO_GRPC_ADDR"

[validator_settings]
validator_grpc_listen_address = "127.0.0.1:18230"
validator_jsonrpc_listen_address = "$ZAKURA_RPC_ADDR"
validator_user = "xxxxxx"
validator_password = "xxxxxx"

[storage.database]
path = "$ZAINO_STATE_DIR/database"
EOF
}

status "Check prerequisites for requested Phase $TARGET_PHASE"
for command in curl jq python3 rg sha256sum timeout cargo; do
    require_command "$command"
done
require_executable "$ZAKURA_BIN"
require_executable "$ZAINO_BIN"
require_executable "$DEVTOOL_BIN"
if (( TARGET_PHASE == 8 )); then
    status "Build the narrow live Names v2 COMMIT -> REVEAL entry point"
    if ! (cd "$ROOT_DIR/zcash-devtool" && cargo build --offline --bin names-v2-live) \
        >"$LOG_DIR/names-v2-live-build.log" 2>&1; then
        tail -100 "$LOG_DIR/names-v2-live-build.log" >&2 || true
        die "could not build names-v2-live"
    fi
    require_executable "$NAMES_V2_LIVE_BIN"
fi
printf '[INFO] binaries: %s, %s, %s\n' "$ZAKURA_BIN" "$ZAINO_BIN" "$DEVTOOL_BIN"
if (( TARGET_PHASE == 8 )); then
    printf '[INFO] live Names v2 binary: %s\n' "$NAMES_V2_LIVE_BIN"
fi
printf '[INFO] disposable run directory: %s\n' "$WORK_DIR"

if [[ -z "$RESUME_DIR" ]]; then
    status "Derive the deterministic Regtest miner/wallet address"
    if "$DEVTOOL_BIN" wallet derive-address \
        --mnemonic "$WALLET_MNEMONIC" --network regtest \
        >"$LOG_DIR/derive-address.log" 2>&1; then
        MINER_UA="$(sed -n 's/^Unified Address: //p' "$LOG_DIR/derive-address.log")"
    else
        tail -80 "$LOG_DIR/derive-address.log" >&2 || true
        die "could not derive the deterministic Regtest unified address"
    fi
    [[ -n "$MINER_UA" ]] || die "derive-address did not print a unified address"
    printf '[OK] derived unified miner address (%s characters)\n' \
        "$(printf '%s' "$MINER_UA" | wc -c)"

    status "Derive a disposable external address for the bootstrap Sapling note"
    if "$DEVTOOL_BIN" wallet derive-address \
        --mnemonic "$SAPLING_DISCARD_MNEMONIC" --network regtest \
        >"$LOG_DIR/derive-sapling-discard-address.log" 2>&1; then
        SAPLING_DISCARD_ADDRESS="$(sed -n 's/^Transparent Address: //p' \
            "$LOG_DIR/derive-sapling-discard-address.log" | tail -1)"
    else
        tail -80 "$LOG_DIR/derive-sapling-discard-address.log" >&2 || true
        die "could not derive the external Sapling-discard destination"
    fi
    [[ -n "$SAPLING_DISCARD_ADDRESS" ]] \
        || die "derive-address did not print a transparent Sapling-discard destination"
    printf '[OK] derived external transparent discard address (%s characters)\n' \
        "$(printf '%s' "$SAPLING_DISCARD_ADDRESS" | wc -c)"
else
    printf '[SKIP] Phase 1 address derivation and Sapling bootstrap; using Phase 4 checkpoint\n'
fi
write_configs
printf '[INFO] Zakura config: %s\n' "$ZAKURA_CONFIG"
printf '[INFO] Zaino config: %s\n' "$ZAINO_CONFIG"
printf '[INFO] activation heights: %s\n' "$ACTIVATION_FILE"

status "Launch Zakura in isolated Regtest state"
RUST_LOG=info "$ZAKURA_BIN" --config "$ZAKURA_CONFIG" start \
    >"$LOG_DIR/zakura.log" 2>&1 &
ZAKURA_PID=$!
printf '[INFO] zakurad pid=%s rpc=%s\n' "$ZAKURA_PID" "$ZAKURA_RPC_URL"
wait_for_zakura_rpc

status "Launch patched Zaino against Zakura"
ZAINOLOG_COLOR=0 RUST_LOG=info "$ZAINO_BIN" start --config "$ZAINO_CONFIG" \
    >"$LOG_DIR/zainod.log" 2>&1 &
ZAINO_PID=$!
printf '[INFO] zainod pid=%s grpc=%s\n' "$ZAINO_PID" "$ZAINO_GRPC_URL"
wait_for_grpc_ready

if (( START_PHASE <= 1 )); then
    status "Explicitly qualify GetSubtreeRoots(Ironwood) through Zaino"
    if grpc_call GetSubtreeRoots 1002 ironwood-subtree-roots; then
        printf '[PASS] GetSubtreeRoots(Ironwood) returned grpc-status 0\n'
    else
        if grpc_error_contains ironwood-subtree-roots; then
            die "GetSubtreeRoots(Ironwood) returned Invalid shielded protocol value"
        fi
        printf '[INFO] Ironwood subtree trace:\n' >&2
        tail -100 "$GRPC_DIR/ironwood-subtree-roots.trace" >&2 || true
        die "GetSubtreeRoots(Ironwood) did not return grpc-status 0"
    fi

    status "Bootstrap the first block needed by devtool wallet birthday initialization"
    # zcash-devtool clamps a Regtest birthday to Sapling activation at height 1 and
    # asks the server for block 1 when the birthday is exactly that activation. One
    # non-funding qualification block makes that CLI path valid; all funding below
    # happens after NU6.3 activation at height 2.
    rpc_generate 1
    wait_for_zaino_tip 1

status "Initialize a fresh Regtest zcash-devtool wallet against Zaino"
if {
    printf '%s\n' "$WALLET_MNEMONIC" | timeout 240 "$DEVTOOL_BIN" wallet \
        --wallet-dir "$WALLET_DIR" init \
        --name phase1 \
        --identity "$IDENTITY_FILE" \
        --network regtest \
        --birthday 1 \
        --activation-heights "$ACTIVATION_FILE" \
        --server "$ZAINO_GRPC_ADDR" \
        --connection direct
} >"$LOG_DIR/wallet-init.log" 2>&1; then
    printf '[OK] wallet initialized at %s\n' "$WALLET_DIR"
else
    status_code=$?
    printf '[FAIL] wallet-init (exit %d); see %s\n' "$status_code" "$LOG_DIR/wallet-init.log" >&2
    tail -100 "$LOG_DIR/wallet-init.log" >&2 || true
    exit "$status_code"
fi

status "Run normal wallet sync (including Sapling, Orchard, and Ironwood roots)"
run_devtool_logged wallet-sync wallet \
    --wallet-dir "$WALLET_DIR" sync \
    --server "$ZAINO_GRPC_ADDR" --connection direct

status "Discard the pre-NU6.3 bootstrap Sapling coinbase note"
run_devtool_logged discard-bootstrap-sapling wallet \
    --wallet-dir "$WALLET_DIR" send \
    --identity "$IDENTITY_FILE" \
    --address "$SAPLING_DISCARD_ADDRESS" \
    --value 624985000 \
    --min-confirmations 1 \
    --server "$ZAINO_GRPC_ADDR" --connection direct
SAPLING_DISCARD_TXID="$(rg -a -o '[0-9a-fA-F]{64}' \
    "$LOG_DIR/discard-bootstrap-sapling.log" | tail -1 || true)"
[[ -n "$SAPLING_DISCARD_TXID" ]] \
    || die "bootstrap Sapling discard did not emit a transaction id"
printf '[OK] broadcast bootstrap Sapling discard transaction %s\n' \
    "$SAPLING_DISCARD_TXID"

status "Mine and index the discarded bootstrap note plus post-NU6.3 Ironwood funding blocks"
rpc_generate 12
wait_for_zaino_tip 13

status "Resync and prove the wallet received spendable Ironwood value"
run_devtool_logged wallet-resync-funded wallet \
    --wallet-dir "$WALLET_DIR" sync \
    --server "$ZAINO_GRPC_ADDR" --connection direct
run_devtool_logged balance-funded wallet \
    --wallet-dir "$WALLET_DIR" balance --json
FUNDED_BALANCE="$(rg -a '^[{]' "$LOG_DIR/balance-funded.log" | tail -1)"
[[ -n "$FUNDED_BALANCE" ]] || die "funded balance command did not emit JSON"
jq -e '.ironwood_spendable > 0' >/dev/null <<<"$FUNDED_BALANCE" \
    || die "wallet did not report spendable Ironwood funding: $FUNDED_BALANCE"
jq -e '.sapling_spendable == 0' >/dev/null <<<"$FUNDED_BALANCE" \
    || die "bootstrap Sapling note was not fully discarded: $FUNDED_BALANCE"
run_devtool_logged discard-bootstrap-sapling-history wallet \
    --wallet-dir "$WALLET_DIR" list-tx --json
rg -a -q -F "$SAPLING_DISCARD_TXID" \
    "$LOG_DIR/discard-bootstrap-sapling-history.log" \
    || die "wallet transaction history does not contain confirmed bootstrap Sapling discard $SAPLING_DISCARD_TXID"
SAPLING_DISCARD_MINED_HEIGHT="$(jq -r --arg txid "$SAPLING_DISCARD_TXID" \
    '.[] | select(.txid == $txid) | .mined_height' \
    "$LOG_DIR/discard-bootstrap-sapling-history.log" | tail -1)"
[[ "$SAPLING_DISCARD_MINED_HEIGHT" =~ ^[0-9]+$ ]] \
    || die "bootstrap Sapling discard $SAPLING_DISCARD_TXID has no mined height"
printf '[PASS] wallet reports ironwood_spendable=%s zatoshi\n' \
    "$(jq -r '.ironwood_spendable' <<<"$FUNDED_BALANCE")"
printf '[PASS] bootstrap Sapling note discarded: tx %s at height %s; sapling_spendable=0\n' \
    "$SAPLING_DISCARD_TXID" "$SAPLING_DISCARD_MINED_HEIGHT"

status "Create an ordinary Ironwood receive target"
run_devtool_logged generate-receive-address wallet \
    --wallet-dir "$WALLET_DIR" generate-address
RECEIVER_ADDRESS="$(sed -n 's/^     Address: //p' "$LOG_DIR/generate-receive-address.log" | tail -1)"
[[ -n "$RECEIVER_ADDRESS" ]] || die "generate-address did not emit a receive address"
printf '[OK] generated receive address (%s characters)\n' "$(printf '%s' "$RECEIVER_ADDRESS" | wc -c)"

status "Spend Ironwood value to the generated receive address"
run_devtool_logged ironwood-send wallet \
    --wallet-dir "$WALLET_DIR" send \
    --identity "$IDENTITY_FILE" \
    --address "$RECEIVER_ADDRESS" \
    --value 1000000 \
    --server "$ZAINO_GRPC_ADDR" --connection direct
TXID="$(rg -a -o '[0-9a-fA-F]{64}' "$LOG_DIR/ironwood-send.log" | tail -1 || true)"
[[ -n "$TXID" ]] || die "wallet send did not emit a transaction id"
printf '[OK] broadcast Ironwood transaction %s\n' "$TXID"

status "Mine and index one confirmation for the Ironwood spend"
rpc_generate 1
wait_for_zaino_tip 14

status "Resync and verify the mined Ironwood receive/spend transaction"
run_devtool_logged wallet-resync-spend wallet \
    --wallet-dir "$WALLET_DIR" sync \
    --server "$ZAINO_GRPC_ADDR" --connection direct
run_devtool_logged list-transactions wallet \
    --wallet-dir "$WALLET_DIR" list-tx
rg -a -q -F "$TXID" "$LOG_DIR/list-transactions.log" \
    || die "wallet transaction history does not contain $TXID"
rg -a -q 'Output .*\(Ironwood\)' "$LOG_DIR/list-transactions.log" \
    || die "wallet transaction history does not show an Ironwood output for $TXID"
run_devtool_logged balance-final wallet \
    --wallet-dir "$WALLET_DIR" balance --json
FINAL_BALANCE="$(rg -a '^[{]' "$LOG_DIR/balance-final.log" | tail -1)"
[[ -n "$FINAL_BALANCE" ]] || die "final balance command did not emit JSON"
jq -e '.ironwood_spendable > 0' >/dev/null <<<"$FINAL_BALANCE" \
    || die "final wallet balance has no spendable Ironwood value: $FINAL_BALANCE"

printf '\n[PASS] Phase 1 infrastructure qualification complete\n'
printf '[PASS] Ironwood subtree-root serving: yes (explicit gRPC GetSubtreeRoots, enum value 2)\n'
printf '[PASS] ordinary Ironwood wallet receive/spend: yes (mined tx %s)\n' "$TXID"
    printf '[PASS] Phase 1 completed before Phase 2 Coppice lifecycle qualification\n'

if (( TARGET_PHASE == 8 )); then
    status "Phase 8: submit the real v2 COMMIT carrier transaction"
    # The live helper reads the mnemonic only from its environment. Keeping it
    # out of the command line also keeps it out of the run log.
    export NAMES_V2_LIVE_MNEMONIC="$WALLET_MNEMONIC"
    run_logged names-v2-commit timeout 900 "$NAMES_V2_LIVE_BIN" commit \
        --wallet-dir "$WALLET_DIR" --rpc-url "$ZAKURA_RPC_URL"
    COMMIT_LINE="$(rg -a -o '^COMMIT_TXID=[0-9a-f]{64}$' \
        "$LOG_DIR/names-v2-commit.log" | tail -1 || true)"
    [[ -n "$COMMIT_LINE" ]] || die "live v2 COMMIT did not emit a transaction id"
    COMMIT_TXID="${COMMIT_LINE#COMMIT_TXID=}"
    COMMIT_HEIGHT_START="$(zakura_tip_height)"
    COMMIT_HEIGHT_EXPECTED=$((COMMIT_HEIGHT_START + 1))

    status "Phase 8: mine the v2 COMMIT canonically"
    rpc_generate 1
    wait_for_zaino_tip "$COMMIT_HEIGHT_EXPECTED"
    wallet_sync_logged names-v2-commit-sync

    status "Phase 8: derive the next legal v2 REVEAL anchor"
    run_logged names-v2-target timeout 120 "$NAMES_V2_LIVE_BIN" target \
        --from-height "$COMMIT_HEIGHT_EXPECTED"
    TARGET_REVEAL_HEIGHT="$(sed -n 's/^TARGET_REVEAL_HEIGHT=//p' \
        "$LOG_DIR/names-v2-target.log" | tail -1)"
    [[ "$TARGET_REVEAL_HEIGHT" =~ ^[0-9]+$ ]] \
        || die "live v2 target command did not emit a target height"
    MATURITY_DISTANCE=$((TARGET_REVEAL_HEIGHT - COMMIT_HEIGHT_EXPECTED))
    (( MATURITY_DISTANCE >= 1 && MATURITY_DISTANCE <= 15 )) \
        || die "live v2 target is outside the current COMMIT maturity/lifetime window"

    CURRENT_TIP="$(zakura_tip_height)"
    PRE_REVEAL_TIP=$((TARGET_REVEAL_HEIGHT - 1))
    (( PRE_REVEAL_TIP >= CURRENT_TIP )) \
        || die "live v2 target height is already behind the current chain tip"
    BLOCKS_TO_TARGET=$((PRE_REVEAL_TIP - CURRENT_TIP))
    if (( BLOCKS_TO_TARGET > 0 )); then
        status "Phase 8: mine to the exact legal v2 REVEAL height"
        rpc_generate "$BLOCKS_TO_TARGET"
        wait_for_zaino_tip "$PRE_REVEAL_TIP"
    fi
    wallet_sync_logged names-v2-reveal-sync

    status "Phase 8: prove, authorize, and submit the real v2 REVEAL"
    run_logged names-v2-reveal timeout 1800 "$NAMES_V2_LIVE_BIN" reveal \
        --wallet-dir "$WALLET_DIR" --rpc-url "$ZAKURA_RPC_URL" \
        --commit-txid "$COMMIT_TXID"
    REVEAL_LINE="$(rg -a -o '^REVEAL_TXID=[0-9a-f]{64}$' \
        "$LOG_DIR/names-v2-reveal.log" | tail -1 || true)"
    [[ -n "$REVEAL_LINE" ]] || die "live v2 REVEAL did not emit a transaction id"
    REVEAL_TXID="${REVEAL_LINE#REVEAL_TXID=}"
    REVEAL_HEIGHT_EXPECTED=$((PRE_REVEAL_TIP + 1))

    status "Phase 8: mine the real v2 REVEAL"
    rpc_generate 1
    wait_for_zaino_tip "$REVEAL_HEIGHT_EXPECTED"
    wallet_sync_logged names-v2-final-sync

    status "Phase 8: replay canonical COMMIT -> REVEAL and verify registration"
    run_logged names-v2-verify timeout 1200 "$NAMES_V2_LIVE_BIN" verify \
        --rpc-url "$ZAKURA_RPC_URL" --commit-txid "$COMMIT_TXID" \
        --reveal-txid "$REVEAL_TXID"
    rg -a -q '^NAMES_REPLAY_STATUS=Active$' \
        "$LOG_DIR/names-v2-verify.log" \
        || die "canonical Names v2 replay did not accept the live registration"
    printf '[PASS] live v2 COMMIT %s mined at h=%s; REVEAL %s mined at h=%s; Names replay accepted Active registration\n' \
        "$COMMIT_TXID" "$COMMIT_HEIGHT_EXPECTED" \
        "$REVEAL_TXID" "$REVEAL_HEIGHT_EXPECTED"
    printf '[PASS] v2 COMMIT maturity distance=%s blocks; target/reveal height=%s; logs=%s\n' \
        "$MATURITY_DISTANCE" "$TARGET_REVEAL_HEIGHT" "$LOG_DIR"
    exit 0
fi

finish_phase_if_requested 1

status "Phase 2: enable Coppice protection and create a confirmed bond note"

run_devtool_logged coppice-protection-enabled wallet \
    --wallet-dir "$WALLET_DIR" coppice protection enabled
rg -a -q '^Enabled$' "$LOG_DIR/coppice-protection-enabled.log" \
    || die "Coppice protection did not become Enabled"
wallet_sync_logged coppice-initial-sync
PHASE2_INITIAL_HEIGHT="$(zakura_tip_height)"
wallet_status_logged coppice-initial-status
assert_coppice_status coppice-initial-status \
    "$PHASE2_INITIAL_HEIGHT" Enabled 0 0
run_devtool_logged coppice-account-list wallet \
    --wallet-dir "$WALLET_DIR" list-accounts
WALLET_ACCOUNT_ID="$(sed -n 's/^Account \([0-9a-fA-F-]\{36\}\) .*/\1/p' \
    "$LOG_DIR/coppice-account-list.log" | head -1)"
[[ -n "$WALLET_ACCOUNT_ID" ]] || die "could not determine the wallet account UUID"
printf '[OK] selected wallet account %s for positional Coppice commands\n' "$WALLET_ACCOUNT_ID"

run_devtool_logged coppice-bond-address wallet \
    --wallet-dir "$WALLET_DIR" generate-address
BOND_ADDRESS="$(sed -n 's/^     Address: //p' "$LOG_DIR/coppice-bond-address.log" | tail -1)"
[[ -n "$BOND_ADDRESS" ]] || die "could not create the dedicated bond-note address"

run_devtool_logged coppice-bond-funding wallet \
    --wallet-dir "$WALLET_DIR" send \
    --identity "$IDENTITY_FILE" \
    --address "$BOND_ADDRESS" \
    --value "$COPPICE_BOND_VALUE" \
    --server "$ZAINO_GRPC_ADDR" --connection direct
BOND_FUND_TXID="$(rg -a -o '[0-9a-fA-F]{64}' "$LOG_DIR/coppice-bond-funding.log" | tail -1 || true)"
[[ -n "$BOND_FUND_TXID" ]] || die "bond funding did not emit a transaction id"
BOND_FUND_HEIGHT_START="$(zakura_tip_height)"
BOND_FUND_HEIGHT=$((BOND_FUND_HEIGHT_START + 3))
rpc_generate 3
wait_for_zaino_tip "$BOND_FUND_HEIGHT"
wallet_sync_logged coppice-bond-funding-sync
run_devtool_logged coppice-bond-funding-tx wallet \
    --wallet-dir "$WALLET_DIR" list-tx --json
BOND_FUND_MINED_HEIGHT="$(jq -r --arg txid "$BOND_FUND_TXID" \
    '.[] | select(.txid == $txid) | .mined_height' \
    "$LOG_DIR/coppice-bond-funding-tx.log" | tail -1)"
[[ "$BOND_FUND_MINED_HEIGHT" =~ ^[0-9]+$ ]] \
    || die "bond funding transaction $BOND_FUND_TXID is not mined in wallet history"
printf '[PASS] confirmed dedicated bond funding tx %s at height %s\n' \
    "$BOND_FUND_TXID" "$BOND_FUND_MINED_HEIGHT"

status "Phase 2: COMMIT, canonical observation, REVEAL, and registration"
run_devtool_logged coppice-address-one wallet \
    --wallet-dir "$WALLET_DIR" generate-address
UA_ONE="$(sed -n 's/^     Address: //p' "$LOG_DIR/coppice-address-one.log" | tail -1)"
[[ -n "$UA_ONE" ]] || die "could not create the first Coppice UA"

COMMIT_HEIGHT_EXPECTED=$(($(zakura_tip_height) + 1))
run_devtool_logged coppice-register-one wallet \
    --wallet-dir "$WALLET_DIR" coppice register \
    --identity "$IDENTITY_FILE" \
    --name "$COPPICE_NAME_ONE" \
    --address "$UA_ONE" \
    --server "$ZAINO_GRPC_ADDR" --connection direct
COMMITMENT_ONE="$(rg -a -o 'commitment=[0-9a-fA-F]{64}' "$LOG_DIR/coppice-register-one.log" \
    | tail -1 | cut -d= -f2)"
COMMIT_TXID_ONE="$(rg -a -o 'txid=[0-9a-fA-F]{64}' "$LOG_DIR/coppice-register-one.log" \
    | tail -1 | cut -d= -f2)"
[[ -n "$COMMITMENT_ONE" && -n "$COMMIT_TXID_ONE" ]] \
    || die "COMMIT did not emit commitment and transaction id"
rpc_generate 1
wait_for_zaino_tip "$COMMIT_HEIGHT_EXPECTED"
wallet_sync_logged coppice-commit-sync
run_devtool_logged coppice-observe-commit-one wallet \
    --wallet-dir "$WALLET_DIR" coppice observe-commit "$COMMITMENT_ONE"
COMMIT_HEIGHT_ONE="$(tail -1 "$LOG_DIR/coppice-observe-commit-one.log" | tr -d '\r')"
[[ "$COMMIT_HEIGHT_ONE" == "$COMMIT_HEIGHT_EXPECTED" ]] \
    || die "COMMIT canonical height $COMMIT_HEIGHT_ONE != $COMMIT_HEIGHT_EXPECTED"
wallet_status_logged coppice-commit-status
assert_coppice_status coppice-commit-status "$COMMIT_HEIGHT_ONE" Enabled 0 1
rg -a -q 'CommitCanonical' "$LOG_DIR/coppice-commit-status.log" \
    || die "wallet status did not retain the canonical COMMIT registration stage"
printf '[PASS] COMMIT tx %s observed canonically at height %s\n' \
    "$COMMIT_TXID_ONE" "$COMMIT_HEIGHT_ONE"

REVEAL_HEIGHT_EXPECTED=$(($(zakura_tip_height) + 1))
run_devtool_logged coppice-reveal-one wallet \
    --wallet-dir "$WALLET_DIR" coppice reveal \
    --identity "$IDENTITY_FILE" "$WALLET_ACCOUNT_ID" "$COMMITMENT_ONE" \
    --server "$ZAINO_GRPC_ADDR" --connection direct
REVEAL_TXID_ONE="$(rg -a -o 'txid=[0-9a-fA-F]{64}' "$LOG_DIR/coppice-reveal-one.log" \
    | tail -1 | cut -d= -f2)"
[[ -n "$REVEAL_TXID_ONE" ]] || die "REVEAL did not emit a transaction id"
rpc_generate 1
wait_for_zaino_tip "$REVEAL_HEIGHT_EXPECTED"
wallet_sync_logged coppice-reveal-sync
wallet_status_logged coppice-reveal-status
assert_coppice_status coppice-reveal-status "$REVEAL_HEIGHT_EXPECTED" Enabled 1 0
assert_snapshot_status "$COPPICE_NAME_ONE" Active "$REVEAL_HEIGHT_EXPECTED"
assert_resolved_address coppice-resolve-one "$COPPICE_NAME_ONE" "$UA_ONE"
printf '[PASS] REVEAL tx %s activated %s at height %s\n' \
    "$REVEAL_TXID_ONE" "$COPPICE_NAME_ONE" "$REVEAL_HEIGHT_EXPECTED"

run_devtool_logged coppice-complete-one wallet \
    --wallet-dir "$WALLET_DIR" coppice complete "$WALLET_ACCOUNT_ID" "$COMMITMENT_ONE"
wallet_status_logged coppice-complete-one-status
assert_coppice_status coppice-complete-one-status \
    "$REVEAL_HEIGHT_EXPECTED" Enabled 1 0
assert_snapshot_status "$COPPICE_NAME_ONE" Active "$REVEAL_HEIGHT_EXPECTED"
assert_resolved_address coppice-complete-resolve-one "$COPPICE_NAME_ONE" "$UA_ONE"
jq -e '.protection == "Enabled" and .local_registrations == []' \
    "$LOG_DIR/coppice-complete-one-status.log" >/dev/null \
    || die "completed first registration did not clear pending state while retaining protection"
printf '[PASS] coppice complete finalized %s; canonical name remains Active and its bond remains protected\n' \
    "$COPPICE_NAME_ONE"

status "Phase 2: UPDATE to a second UA and RELEASE"
run_devtool_logged coppice-address-two wallet \
    --wallet-dir "$WALLET_DIR" generate-address
UA_TWO="$(sed -n 's/^     Address: //p' "$LOG_DIR/coppice-address-two.log" | tail -1)"
[[ -n "$UA_TWO" ]] || die "could not create the second Coppice UA"

UPDATE_HEIGHT_EXPECTED=$(($(zakura_tip_height) + 1))
run_devtool_logged coppice-update-one wallet \
    --wallet-dir "$WALLET_DIR" coppice update \
    --identity "$IDENTITY_FILE" \
    --name "$COPPICE_NAME_ONE" \
    --address "$UA_TWO" \
    --server "$ZAINO_GRPC_ADDR" --connection direct
UPDATE_TXID_ONE="$(rg -a -o '[0-9a-fA-F]{64}' "$LOG_DIR/coppice-update-one.log" | tail -1 || true)"
[[ -n "$UPDATE_TXID_ONE" ]] || die "UPDATE did not emit a transaction id"
rpc_generate 1
wait_for_zaino_tip "$UPDATE_HEIGHT_EXPECTED"
wallet_sync_logged coppice-update-sync
wallet_status_logged coppice-update-status
assert_coppice_status coppice-update-status "$UPDATE_HEIGHT_EXPECTED" Enabled 1 0
assert_snapshot_status "$COPPICE_NAME_ONE" Active "$UPDATE_HEIGHT_EXPECTED"
assert_resolved_address coppice-resolve-updated "$COPPICE_NAME_ONE" "$UA_TWO"
printf '[PASS] UPDATE tx %s changed %s at height %s\n' \
    "$UPDATE_TXID_ONE" "$COPPICE_NAME_ONE" "$UPDATE_HEIGHT_EXPECTED"

RELEASE_HEIGHT_EXPECTED=$(($(zakura_tip_height) + 1))
run_devtool_logged coppice-release-one wallet \
    --wallet-dir "$WALLET_DIR" coppice release \
    --identity "$IDENTITY_FILE" \
    --name "$COPPICE_NAME_ONE" \
    --server "$ZAINO_GRPC_ADDR" --connection direct
RELEASE_TXID_ONE="$(rg -a -o '[0-9a-fA-F]{64}' "$LOG_DIR/coppice-release-one.log" | tail -1 || true)"
[[ -n "$RELEASE_TXID_ONE" ]] || die "RELEASE did not emit a transaction id"
rpc_generate 1
wait_for_zaino_tip "$RELEASE_HEIGHT_EXPECTED"
wallet_sync_logged coppice-release-sync
wallet_status_logged coppice-release-status
assert_coppice_status coppice-release-status "$RELEASE_HEIGHT_EXPECTED" Enabled 1 0
assert_snapshot_status "$COPPICE_NAME_ONE" Released "$RELEASE_HEIGHT_EXPECTED"
assert_resolve_inactive coppice-resolve-released "$COPPICE_NAME_ONE"
printf '[PASS] RELEASE tx %s made %s inactive at height %s\n' \
    "$RELEASE_TXID_ONE" "$COPPICE_NAME_ONE" "$RELEASE_HEIGHT_EXPECTED"

status "Phase 2: restart Zaino and reopen the persisted wallet state"
if [[ -n "$ZAINO_PID" ]]; then
    kill -TERM "$ZAINO_PID" 2>/dev/null || true
    wait "$ZAINO_PID" 2>/dev/null || true
    ZAINO_PID=""
fi
ZAINOLOG_COLOR=0 RUST_LOG=info "$ZAINO_BIN" start --config "$ZAINO_CONFIG" \
    >"$LOG_DIR/zainod-restart.log" 2>&1 &
ZAINO_PID=$!
printf '[INFO] restarted zainod pid=%s with the same config/database\n' "$ZAINO_PID"
wait_for_grpc_ready
wallet_status_logged wallet-reopen-status
assert_coppice_status wallet-reopen-status "$RELEASE_HEIGHT_EXPECTED" Enabled 1 0
assert_snapshot_status "$COPPICE_NAME_ONE" Released "$RELEASE_HEIGHT_EXPECTED"
assert_resolve_inactive wallet-reopen-resolve-released "$COPPICE_NAME_ONE"
wallet_sync_logged wallet-reopen-sync
wallet_status_logged wallet-reopen-post-sync-status
assert_coppice_status wallet-reopen-post-sync-status "$RELEASE_HEIGHT_EXPECTED" Enabled 1 0
assert_snapshot_status "$COPPICE_NAME_ONE" Released "$RELEASE_HEIGHT_EXPECTED"
printf '[PASS] Zaino restart and fresh zcash-devtool processes recovered Coppice protection/resolution state\n'

status "Phase 2: second registration and ordinary explicit bond spend"
run_devtool_logged coppice-address-three wallet \
    --wallet-dir "$WALLET_DIR" generate-address
UA_THREE="$(sed -n 's/^     Address: //p' "$LOG_DIR/coppice-address-three.log" | tail -1)"
[[ -n "$UA_THREE" ]] || die "could not create the second registration UA"

# Use the already-created unified address as the explicit Break Bond destination.
# This keeps the reclaim transaction in the Orchard-family/Ironwood wallet path,
# while the selected input remains constrained by the Break Bond plan to the
# exact active bond note.
BREAK_BOND_ADDRESS="$UA_THREE"

SECOND_COMMIT_HEIGHT_EXPECTED=$(($(zakura_tip_height) + 1))
run_devtool_logged coppice-register-two wallet \
    --wallet-dir "$WALLET_DIR" coppice register \
    --identity "$IDENTITY_FILE" \
    --name "$COPPICE_NAME_TWO" \
    --address "$UA_THREE" \
    --server "$ZAINO_GRPC_ADDR" --connection direct
COMMITMENT_TWO="$(rg -a -o 'commitment=[0-9a-fA-F]{64}' "$LOG_DIR/coppice-register-two.log" \
    | tail -1 | cut -d= -f2)"
COMMIT_TXID_TWO="$(rg -a -o 'txid=[0-9a-fA-F]{64}' "$LOG_DIR/coppice-register-two.log" \
    | tail -1 | cut -d= -f2)"
[[ -n "$COMMITMENT_TWO" && -n "$COMMIT_TXID_TWO" ]] \
    || die "second COMMIT did not emit commitment and transaction id"
rpc_generate 1
wait_for_zaino_tip "$SECOND_COMMIT_HEIGHT_EXPECTED"
wallet_sync_logged coppice-second-commit-sync
run_devtool_logged coppice-observe-commit-two wallet \
    --wallet-dir "$WALLET_DIR" coppice observe-commit "$COMMITMENT_TWO"
SECOND_COMMIT_HEIGHT="$(tail -1 "$LOG_DIR/coppice-observe-commit-two.log" | tr -d '\r')"
[[ "$SECOND_COMMIT_HEIGHT" == "$SECOND_COMMIT_HEIGHT_EXPECTED" ]] \
    || die "second COMMIT canonical height $SECOND_COMMIT_HEIGHT != $SECOND_COMMIT_HEIGHT_EXPECTED"
printf '[PASS] second COMMIT tx %s observed canonically at height %s\n' \
    "$COMMIT_TXID_TWO" "$SECOND_COMMIT_HEIGHT"

SECOND_REVEAL_HEIGHT_EXPECTED=$(($(zakura_tip_height) + 1))
run_devtool_logged coppice-reveal-two wallet \
    --wallet-dir "$WALLET_DIR" coppice reveal \
    --identity "$IDENTITY_FILE" "$WALLET_ACCOUNT_ID" "$COMMITMENT_TWO" \
    --server "$ZAINO_GRPC_ADDR" --connection direct
SECOND_REVEAL_TXID="$(rg -a -o 'txid=[0-9a-fA-F]{64}' "$LOG_DIR/coppice-reveal-two.log" \
    | tail -1 | cut -d= -f2)"
[[ -n "$SECOND_REVEAL_TXID" ]] || die "second REVEAL did not emit a transaction id"
rpc_generate 1
wait_for_zaino_tip "$SECOND_REVEAL_HEIGHT_EXPECTED"
wallet_sync_logged coppice-second-reveal-sync
wallet_status_logged coppice-second-reveal-status
assert_coppice_status coppice-second-reveal-status "$SECOND_REVEAL_HEIGHT_EXPECTED" Enabled 2 0
assert_snapshot_status "$COPPICE_NAME_ONE" Released "$SECOND_REVEAL_HEIGHT_EXPECTED"
assert_snapshot_status "$COPPICE_NAME_TWO" Active "$SECOND_REVEAL_HEIGHT_EXPECTED"
assert_resolved_address coppice-resolve-second "$COPPICE_NAME_TWO" "$UA_THREE"
printf '[PASS] second REVEAL tx %s activated %s at height %s\n' \
    "$SECOND_REVEAL_TXID" "$COPPICE_NAME_TWO" "$SECOND_REVEAL_HEIGHT_EXPECTED"

run_devtool_logged coppice-complete-two wallet \
    --wallet-dir "$WALLET_DIR" coppice complete "$WALLET_ACCOUNT_ID" "$COMMITMENT_TWO"
wallet_status_logged coppice-complete-two-status
assert_coppice_status coppice-complete-two-status \
    "$SECOND_REVEAL_HEIGHT_EXPECTED" Enabled 2 0
assert_snapshot_status "$COPPICE_NAME_ONE" Released "$SECOND_REVEAL_HEIGHT_EXPECTED"
assert_snapshot_status "$COPPICE_NAME_TWO" Active "$SECOND_REVEAL_HEIGHT_EXPECTED"
assert_resolved_address coppice-complete-resolve-two "$COPPICE_NAME_TWO" "$UA_THREE"
jq -e '.protection == "Enabled" and .local_registrations == []' \
    "$LOG_DIR/coppice-complete-two-status.log" >/dev/null \
    || die "completed second registration did not clear pending state while retaining protection"
printf '[PASS] coppice complete finalized %s; canonical name remains Active and its bond remains protected\n' \
    "$COPPICE_NAME_TWO"

status "Phase 2: mature the active bond for the default wallet spend policy"
BOND_MATURITY_HEIGHT_EXPECTED=$(($(zakura_tip_height) + 1))
rpc_generate 1
wait_for_zaino_tip "$BOND_MATURITY_HEIGHT_EXPECTED"
wallet_sync_logged coppice-bond-maturity-sync
wallet_status_logged coppice-bond-maturity-status
assert_coppice_status coppice-bond-maturity-status \
    "$BOND_MATURITY_HEIGHT_EXPECTED" Enabled 2 0
assert_snapshot_status "$COPPICE_NAME_ONE" Released "$BOND_MATURITY_HEIGHT_EXPECTED"
assert_snapshot_status "$COPPICE_NAME_TWO" Active "$BOND_MATURITY_HEIGHT_EXPECTED"
assert_resolved_address coppice-resolve-matured-bond "$COPPICE_NAME_TWO" "$UA_THREE"
printf '[PASS] active bond matured at wallet tip height %s for Break Bond confirmation policy\n' \
    "$BOND_MATURITY_HEIGHT_EXPECTED"

BREAK_BOND_HEIGHT_EXPECTED=$(($(zakura_tip_height) + 1))
run_devtool_logged coppice-break-bond wallet \
    --wallet-dir "$WALLET_DIR" coppice break-bond \
    --identity "$IDENTITY_FILE" \
    --name "$COPPICE_NAME_TWO" \
    --address "$BREAK_BOND_ADDRESS" \
    --value 1000000 \
    --server "$ZAINO_GRPC_ADDR" --connection direct
BREAK_BOND_TXID="$(rg -a -o '[0-9a-fA-F]{64}' "$LOG_DIR/coppice-break-bond.log" | tail -1 || true)"
[[ -n "$BREAK_BOND_TXID" ]] || die "Break Bond did not emit a transaction id"
rpc_generate 1
wait_for_zaino_tip "$BREAK_BOND_HEIGHT_EXPECTED"
wallet_sync_logged coppice-break-bond-sync
wallet_status_logged coppice-break-bond-status
assert_coppice_status coppice-break-bond-status "$BREAK_BOND_HEIGHT_EXPECTED" Enabled 2 0
assert_snapshot_status "$COPPICE_NAME_TWO" BondSpent "$BREAK_BOND_HEIGHT_EXPECTED"
assert_resolve_inactive coppice-resolve-bond-spent "$COPPICE_NAME_TWO"
printf '[PASS] Break Bond tx %s marked %s BondSpent/inactive at height %s\n' \
    "$BREAK_BOND_TXID" "$COPPICE_NAME_TWO" "$BREAK_BOND_HEIGHT_EXPECTED"

status "Phase 2: shallow canonical reorg removes the Break Bond transition"
REORG_OLD_HEIGHT="$(zakura_tip_height)"
[[ "$REORG_OLD_HEIGHT" == "$BREAK_BOND_HEIGHT_EXPECTED" ]] \
    || die "reorg target tip $REORG_OLD_HEIGHT is not the Break Bond height $BREAK_BOND_HEIGHT_EXPECTED"
REORG_OLD_HASH="$(zakura_block_hash "$REORG_OLD_HEIGHT")"
REORG_PARENT_HASH="$(zakura_block_hash "$((REORG_OLD_HEIGHT - 1))")"
printf '[INFO] reorg shape: invalidate h=%s hash=%s, retain parent h=%s hash=%s, mine one replacement at h=%s\n' \
    "$REORG_OLD_HEIGHT" "$REORG_OLD_HASH" "$((REORG_OLD_HEIGHT - 1))" "$REORG_PARENT_HASH" "$REORG_OLD_HEIGHT"
rpc_invalidate_block "$REORG_OLD_HASH"
wait_for_zakura_tip "$((REORG_OLD_HEIGHT - 1))"
rpc_generate 1
wait_for_zakura_tip "$REORG_OLD_HEIGHT"
REORG_NEW_HASH="$(zakura_block_hash "$REORG_OLD_HEIGHT")"
[[ "$REORG_NEW_HASH" != "$REORG_OLD_HASH" ]] \
    || die "Zakura replacement block hash did not differ from invalidated block"
printf '[PASS] Zakura replacement canonical block h=%s hash=%s differs from invalidated %s\n' \
    "$REORG_OLD_HEIGHT" "$REORG_NEW_HASH" "$REORG_OLD_HASH"
wait_for_zaino_tip_hash "$REORG_NEW_HASH" "$REORG_OLD_HEIGHT"
wallet_sync_logged coppice-reorg-sync
wallet_status_logged coppice-reorg-status
assert_coppice_status coppice-reorg-status "$REORG_OLD_HEIGHT" Enabled 2 0
assert_coppice_tip_hash coppice-reorg-status "$REORG_NEW_HASH"
assert_snapshot_status "$COPPICE_NAME_ONE" Released "$REORG_OLD_HEIGHT"
assert_snapshot_status "$COPPICE_NAME_TWO" Active "$REORG_OLD_HEIGHT"
assert_resolved_address coppice-reorg-resolve-second "$COPPICE_NAME_TWO" "$UA_THREE"
assert_resolve_inactive coppice-reorg-resolve-first "$COPPICE_NAME_ONE"
printf '[PASS] Coppice replay rewound the removed BondSpent transition and followed replacement h=%s\n' \
    "$REORG_OLD_HEIGHT"

printf '\n[PASS] Phase 2 lifecycle, restart recovery, and shallow reorg qualification complete\n'
finish_phase_if_requested 2

status "Phase 3: fresh same-seed wallet recovery from Coppice activation"
[[ ! -e "$RECOVERY_WALLET_DIR" ]] \
    || die "fresh recovery wallet directory already exists"
mkdir "$RECOVERY_WALLET_DIR"
for forbidden_state in \
    "$RECOVERY_WALLET_DIR/coppice-runtime-v1.json" \
    "$RECOVERY_WALLET_DIR/coppice-pending-v1.json" \
    "$RECOVERY_WALLET_DIR/coppice-protection.json" \
    "$RECOVERY_WALLET_DIR/data.sqlite"; do
    [[ ! -e "$forbidden_state" ]] \
        || die "fresh recovery wallet unexpectedly contains preexisting state: $forbidden_state"
done
printf '[PASS] fresh recovery directory started empty; no original wallet or Coppice state was copied\n'

printf '[INFO] initializing fresh wallet with birthday/Coppice replay start height %s\n' \
    "$COPPICE_ACTIVATION_HEIGHT"
if {
    printf '%s\n' "$WALLET_MNEMONIC" | timeout 240 "$DEVTOOL_BIN" wallet \
        --wallet-dir "$RECOVERY_WALLET_DIR" init \
        --name phase3-recovery \
        --identity "$RECOVERY_IDENTITY_FILE" \
        --network regtest \
        --birthday "$COPPICE_ACTIVATION_HEIGHT" \
        --activation-heights "$ACTIVATION_FILE" \
        --server "$ZAINO_GRPC_ADDR" \
        --connection direct
} >"$LOG_DIR/phase3-wallet-init.log" 2>&1; then
    printf '[PASS] fresh same-seed wallet initialized normally at %s\n' \
        "$RECOVERY_WALLET_DIR"
else
    status_code=$?
    printf '[FAIL] phase3-wallet-init (exit %d); see %s\n' \
        "$status_code" "$LOG_DIR/phase3-wallet-init.log" >&2
    tail -100 "$LOG_DIR/phase3-wallet-init.log" >&2 || true
    exit "$status_code"
fi

for forbidden_state in \
    "$RECOVERY_WALLET_DIR/coppice-runtime-v1.json" \
    "$RECOVERY_WALLET_DIR/coppice-pending-v1.json"; do
    [[ ! -e "$forbidden_state" ]] \
        || die "fresh wallet init unexpectedly created copied Coppice state: $forbidden_state"
done

wallet_sync_logged_for phase3-wallet-sync "$RECOVERY_WALLET_DIR"
wallet_status_logged_for phase3-recovery-status "$RECOVERY_WALLET_DIR"
assert_coppice_status phase3-recovery-status "$REORG_OLD_HEIGHT" Enabled 2 0
assert_snapshot_status_for "$RECOVERY_WALLET_DIR" \
    "$COPPICE_NAME_ONE" Released "$REORG_OLD_HEIGHT"
assert_snapshot_status_for "$RECOVERY_WALLET_DIR" \
    "$COPPICE_NAME_TWO" Active "$REORG_OLD_HEIGHT"
assert_resolved_address_for phase3-recovery-resolve-active \
    "$RECOVERY_WALLET_DIR" "$COPPICE_NAME_TWO" "$UA_THREE"
assert_resolve_inactive_for phase3-recovery-resolve-released \
    "$RECOVERY_WALLET_DIR" "$COPPICE_NAME_ONE"
jq -e '.local_registrations == []' "$LOG_DIR/phase3-recovery-status.log" >/dev/null \
    || die "fresh recovery recreated stale local pending-registration metadata"
printf '[PASS] fresh standard sync replayed the canonical registry: %s=Released, %s=Active, no local pending registrations\n' \
    "$COPPICE_NAME_ONE" "$COPPICE_NAME_TWO"

run_devtool_logged phase3-recovery-balance wallet \
    --wallet-dir "$RECOVERY_WALLET_DIR" balance --json --min-confirmations 1
RECOVERY_BALANCE="$(rg -a '^[{]' "$LOG_DIR/phase3-recovery-balance.log" | tail -1)"
[[ -n "$RECOVERY_BALANCE" ]] || die "fresh recovery balance command did not emit JSON"
RECOVERY_TOTAL="$(jq -r '.total' <<<"$RECOVERY_BALANCE")"
RECOVERY_SPENDABLE="$(jq -r '.ironwood_spendable' <<<"$RECOVERY_BALANCE")"
[[ "$RECOVERY_TOTAL" =~ ^[0-9]+$ && "$RECOVERY_SPENDABLE" =~ ^[0-9]+$ ]] \
    || die "fresh recovery balance values were not numeric: $RECOVERY_BALANCE"
RECOVERY_LOCKED_VALUE=$((RECOVERY_TOTAL - RECOVERY_SPENDABLE))
(( RECOVERY_LOCKED_VALUE == COPPICE_BOND_VALUE )) \
    || die "fresh recovery locked-value evidence $RECOVERY_LOCKED_VALUE does not equal active bond $COPPICE_BOND_VALUE: $RECOVERY_BALANCE"
printf '[PASS] fresh FVK/nullifier-derived inventory reconstructed the %s-zatoshi active bond lock (total=%s spendable=%s)\n' \
    "$RECOVERY_LOCKED_VALUE" "$RECOVERY_TOTAL" "$RECOVERY_SPENDABLE"

run_devtool_logged phase3-probe-address wallet \
    --wallet-dir "$RECOVERY_WALLET_DIR" generate-address
RECOVERY_PROBE_ADDRESS="$(sed -n 's/^     Address: //p' \
    "$LOG_DIR/phase3-probe-address.log" | tail -1)"
[[ -n "$RECOVERY_PROBE_ADDRESS" ]] || die "fresh recovery probe address was not generated"
RECOVERY_PROBE_VALUE=$((RECOVERY_SPENDABLE + 1))
run_devtool_expect_failure phase3-ordinary-send wallet \
    --wallet-dir "$RECOVERY_WALLET_DIR" send \
    --identity "$RECOVERY_IDENTITY_FILE" \
    --address "$RECOVERY_PROBE_ADDRESS" \
    --value "$RECOVERY_PROBE_VALUE" \
    --server "$ZAINO_GRPC_ADDR" --connection direct
rg -a -qi 'insufficient|not enough|Coppice spend protection|locked' \
    "$LOG_DIR/phase3-ordinary-send.log" \
    || die "ordinary send did not fail for the locked active bond as expected"
printf '[PASS] ordinary send could not consume the reconstructed active bond while protection was Enabled\n'

run_devtool_logged phase3-break-bond-address wallet \
    --wallet-dir "$RECOVERY_WALLET_DIR" generate-address
RECOVERY_BREAK_BOND_ADDRESS="$(sed -n 's/^     Address: //p' \
    "$LOG_DIR/phase3-break-bond-address.log" | tail -1)"
[[ -n "$RECOVERY_BREAK_BOND_ADDRESS" ]] \
    || die "fresh recovery Break Bond destination was not generated"
PHASE3_BREAK_BOND_HEIGHT_EXPECTED=$(($(zakura_tip_height) + 1))
run_devtool_logged phase3-break-bond wallet \
    --wallet-dir "$RECOVERY_WALLET_DIR" coppice break-bond \
    --identity "$RECOVERY_IDENTITY_FILE" \
    --name "$COPPICE_NAME_TWO" \
    --address "$RECOVERY_BREAK_BOND_ADDRESS" \
    --value 1000000 \
    --server "$ZAINO_GRPC_ADDR" --connection direct
RECOVERY_BREAK_BOND_TXID="$(rg -a -o '[0-9a-fA-F]{64}' \
    "$LOG_DIR/phase3-break-bond.log" | tail -1 || true)"
[[ -n "$RECOVERY_BREAK_BOND_TXID" ]] \
    || die "fresh recovery Break Bond did not emit a transaction id"
rpc_generate 1
wait_for_zaino_tip "$PHASE3_BREAK_BOND_HEIGHT_EXPECTED"
wallet_sync_logged_for phase3-break-bond-sync "$RECOVERY_WALLET_DIR"
wallet_status_logged_for phase3-break-bond-status "$RECOVERY_WALLET_DIR"
assert_coppice_status phase3-break-bond-status \
    "$PHASE3_BREAK_BOND_HEIGHT_EXPECTED" Enabled 2 0
assert_snapshot_status_for "$RECOVERY_WALLET_DIR" \
    "$COPPICE_NAME_ONE" Released "$PHASE3_BREAK_BOND_HEIGHT_EXPECTED"
assert_snapshot_status_for "$RECOVERY_WALLET_DIR" \
    "$COPPICE_NAME_TWO" BondSpent "$PHASE3_BREAK_BOND_HEIGHT_EXPECTED"
assert_resolve_inactive_for phase3-break-bond-resolve-spent \
    "$RECOVERY_WALLET_DIR" "$COPPICE_NAME_TWO"
jq -e '.local_registrations == []' "$LOG_DIR/phase3-break-bond-status.log" >/dev/null \
    || die "fresh recovery retained local pending registrations after Break Bond"
printf '[PASS] fresh-wallet Break Bond tx %s spent the reconstructed active bond at height %s; Released and BondSpent names remained inactive\n' \
    "$RECOVERY_BREAK_BOND_TXID" "$PHASE3_BREAK_BOND_HEIGHT_EXPECTED"

printf '\n[PASS] Phase 1 + Phase 2 + Phase 3 prerequisite complete\n'
printf '[PASS] lifecycle evidence: %s COMMIT/REVEAL/UPDATE/RELEASE, %s second COMMIT/REVEAL/Break Bond\n' \
    "$COPPICE_NAME_ONE" "$COPPICE_NAME_TWO"
printf '[PASS] restart recovery: Zaino and fresh wallet processes reused persisted state\n'
printf '[PASS] shallow reorg: invalidated h=%s (%s), replacement h=%s (%s); post-reorg %s=Active and %s=Released\n' \
    "$REORG_OLD_HEIGHT" "$REORG_OLD_HASH" "$REORG_OLD_HEIGHT" "$REORG_NEW_HASH" \
    "$COPPICE_NAME_TWO" "$COPPICE_NAME_ONE"
printf '[PASS] Phase 3 fresh same-seed recovery: birthday=%s, sync tip=%s, Break Bond tx=%s at h=%s\n' \
    "$COPPICE_ACTIVATION_HEIGHT" "$REORG_OLD_HEIGHT" "$RECOVERY_BREAK_BOND_TXID" \
    "$PHASE3_BREAK_BOND_HEIGHT_EXPECTED"
printf '[PASS] deep reorg tests were not run\n'
finish_phase_if_requested 3

status "Phase 4: create a second same-seed account and map FVK-derived identities"
wallet_sync_logged phase4-original-preparation-sync
PHASE4_BASELINE_HEIGHT="$(zakura_tip_height)"
wallet_status_logged phase4-original-baseline-status
assert_coppice_status phase4-original-baseline-status \
    "$PHASE4_BASELINE_HEIGHT" Enabled 2 0

run_devtool_logged phase4-account-list-before wallet \
    --wallet-dir "$WALLET_DIR" list-accounts
ACCOUNT_A_RECORD="$(account_record_for_name \
    "$LOG_DIR/phase4-account-list-before.log" phase1)"
[[ -n "$ACCOUNT_A_RECORD" ]] || die "could not identify the original phase4 Account A"
ACCOUNT_A_UUID="$(jq -r '.uuid' <<<"$ACCOUNT_A_RECORD")"
ORIGINAL_ACCOUNT_A_RECORD="$ACCOUNT_A_RECORD"

run_devtool_logged phase4-generate-account-b wallet \
    --wallet-dir "$WALLET_DIR" generate-account \
    --identity "$IDENTITY_FILE" \
    --name phase4-account-b \
    --server "$ZAINO_GRPC_ADDR" --connection direct
wallet_sync_logged phase4-account-add-sync
run_devtool_logged phase4-account-list wallet \
    --wallet-dir "$WALLET_DIR" list-accounts
ACCOUNT_A_RECORD="$(account_record_for_name \
    "$LOG_DIR/phase4-account-list.log" phase1)"
ACCOUNT_B_RECORD="$(account_record_for_name \
    "$LOG_DIR/phase4-account-list.log" phase4-account-b)"
ACCOUNT_A_UUID="$(jq -r '.uuid' <<<"$ACCOUNT_A_RECORD")"
ACCOUNT_B_UUID="$(jq -r '.uuid' <<<"$ACCOUNT_B_RECORD")"
[[ "$ACCOUNT_A_UUID" != "$ACCOUNT_B_UUID" ]] \
    || die "the two wallet accounts unexpectedly share an AccountUuid"
ORIGINAL_ACCOUNT_A_RECORD="$ACCOUNT_A_RECORD"
ORIGINAL_ACCOUNT_B_RECORD="$ACCOUNT_B_RECORD"
[[ "$(jq -r '.index' <<<"$ACCOUNT_A_RECORD")" == 0 ]] \
    || die "phase4 Account A is not deterministic account index 0"
[[ "$(jq -r '.index' <<<"$ACCOUNT_B_RECORD")" == 1 ]] \
    || die "phase4 Account B is not deterministic account index 1"
printf '[PASS] same-seed accounts: A uuid=%s index=%s; B uuid=%s index=%s\n' \
    "$ACCOUNT_A_UUID" "$(jq -r '.index' <<<"$ACCOUNT_A_RECORD")" \
    "$ACCOUNT_B_UUID" "$(jq -r '.index' <<<"$ACCOUNT_B_RECORD")"

wallet_status_logged phase4-account-map
assert_coppice_status phase4-account-map "$PHASE4_BASELINE_HEIGHT" Enabled 2 0
jq -e '.wallet_accounts | length == 2' \
    "$LOG_DIR/phase4-account-map.log" >/dev/null \
    || die "Coppice status did not expose both wallet accounts"
ACCOUNT_A_WALLET_ID="$(wallet_account_id_from_status phase4-account-map "$ACCOUNT_A_UUID")"
ACCOUNT_B_WALLET_ID="$(wallet_account_id_from_status phase4-account-map "$ACCOUNT_B_UUID")"
[[ "$ACCOUNT_A_WALLET_ID" != "$ACCOUNT_B_WALLET_ID" ]] \
    || die "the two accounts unexpectedly share a FVK-derived WalletAccountId"
printf '[PASS] account A WalletAccountId=%s; account B WalletAccountId=%s\n' \
    "$ACCOUNT_A_WALLET_ID" "$ACCOUNT_B_WALLET_ID"

status "Phase 4: independently fund both accounts and create separate bond notes"
wallet_balance_logged_for phase4-baseline-balance-a "$WALLET_DIR" "$ACCOUNT_A_UUID"
wallet_balance_logged_for phase4-baseline-balance-b "$WALLET_DIR" "$ACCOUNT_B_UUID"
PHASE4_A_BASE_LOCKED="$(balance_locked_value phase4-baseline-balance-a)"
PHASE4_B_BASE_LOCKED="$(balance_locked_value phase4-baseline-balance-b)"
printf '[INFO] pre-Phase-4 locked values: account A=%s, account B=%s zatoshi\n' \
    "$PHASE4_A_BASE_LOCKED" "$PHASE4_B_BASE_LOCKED"

run_devtool_logged phase4-account-b-funding-address wallet \
    --wallet-dir "$WALLET_DIR" generate-address "$ACCOUNT_B_UUID"
PHASE4_B_FUNDING_ADDRESS="$(sed -n 's/^     Address: //p' \
    "$LOG_DIR/phase4-account-b-funding-address.log" | tail -1)"
[[ -n "$PHASE4_B_FUNDING_ADDRESS" ]] \
    || die "could not create Account B's independent funding address"
run_devtool_logged phase4-account-a-bond-address wallet \
    --wallet-dir "$WALLET_DIR" generate-address "$ACCOUNT_A_UUID"
PHASE4_A_BOND_ADDRESS="$(sed -n 's/^     Address: //p' \
    "$LOG_DIR/phase4-account-a-bond-address.log" | tail -1)"
[[ -n "$PHASE4_A_BOND_ADDRESS" ]] \
    || die "could not create Account A's dedicated bond address"

run_devtool_logged phase4-fund-account-b wallet \
    --wallet-dir "$WALLET_DIR" send \
    --identity "$IDENTITY_FILE" \
    --address "$PHASE4_B_FUNDING_ADDRESS" \
    --value "$PHASE4_ACCOUNT_FUNDING_VALUE" \
    --server "$ZAINO_GRPC_ADDR" --connection direct "$ACCOUNT_A_UUID"
PHASE4_B_FUND_TXID="$(rg -a -o '[0-9a-fA-F]{64}' \
    "$LOG_DIR/phase4-fund-account-b.log" | tail -1 || true)"
[[ -n "$PHASE4_B_FUND_TXID" ]] || die "Account B funding did not emit a transaction id"
PHASE4_B_FUND_HEIGHT_EXPECTED=$(($(zakura_tip_height) + 4))
rpc_generate 4
wait_for_zaino_tip "$PHASE4_B_FUND_HEIGHT_EXPECTED"
wallet_sync_logged phase4-account-b-funding-sync
wallet_balance_logged_for phase4-account-b-funded-balance "$WALLET_DIR" "$ACCOUNT_B_UUID"
jq -e --argjson required "$PHASE4_ACCOUNT_FUNDING_VALUE" \
    '.ironwood_spendable >= $required' \
    <<<"$(balance_json phase4-account-b-funded-balance)" >/dev/null \
    || die "Account B did not receive independent spendable Ironwood funding"
printf '[PASS] Account B independently received tx %s with spendable Ironwood value\n' \
    "$PHASE4_B_FUND_TXID"

run_devtool_logged phase4-fund-account-a-bond wallet \
    --wallet-dir "$WALLET_DIR" send \
    --identity "$IDENTITY_FILE" \
    --address "$PHASE4_A_BOND_ADDRESS" \
    --value "$COPPICE_BOND_VALUE" \
    --server "$ZAINO_GRPC_ADDR" --connection direct "$ACCOUNT_A_UUID"
PHASE4_A_BOND_FUND_TXID="$(rg -a -o '[0-9a-fA-F]{64}' \
    "$LOG_DIR/phase4-fund-account-a-bond.log" | tail -1 || true)"
[[ -n "$PHASE4_A_BOND_FUND_TXID" ]] \
    || die "Account A bond funding did not emit a transaction id"
PHASE4_A_BOND_FUND_HEIGHT_EXPECTED=$(($(zakura_tip_height) + 3))
rpc_generate 3
wait_for_zaino_tip "$PHASE4_A_BOND_FUND_HEIGHT_EXPECTED"
wallet_sync_logged phase4-account-a-bond-funding-sync

run_devtool_logged phase4-account-b-bond-address wallet \
    --wallet-dir "$WALLET_DIR" generate-address "$ACCOUNT_B_UUID"
PHASE4_B_BOND_ADDRESS="$(sed -n 's/^     Address: //p' \
    "$LOG_DIR/phase4-account-b-bond-address.log" | tail -1)"
[[ -n "$PHASE4_B_BOND_ADDRESS" ]] \
    || die "could not create Account B's dedicated bond address"
run_devtool_logged phase4-fund-account-b-bond wallet \
    --wallet-dir "$WALLET_DIR" send \
    --identity "$IDENTITY_FILE" \
    --address "$PHASE4_B_BOND_ADDRESS" \
    --value "$COPPICE_BOND_VALUE" \
    --min-confirmations 1 \
    --server "$ZAINO_GRPC_ADDR" --connection direct "$ACCOUNT_B_UUID"
PHASE4_B_BOND_FUND_TXID="$(rg -a -o '[0-9a-fA-F]{64}' \
    "$LOG_DIR/phase4-fund-account-b-bond.log" | tail -1 || true)"
[[ -n "$PHASE4_B_BOND_FUND_TXID" ]] \
    || die "Account B bond funding did not emit a transaction id"
PHASE4_B_BOND_FUND_HEIGHT_EXPECTED=$(($(zakura_tip_height) + 3))
rpc_generate 3
wait_for_zaino_tip "$PHASE4_B_BOND_FUND_HEIGHT_EXPECTED"
wallet_sync_logged phase4-independent-funding-sync
wallet_balance_logged_for phase4-independent-funding-balance-a "$WALLET_DIR" "$ACCOUNT_A_UUID"
wallet_balance_logged_for phase4-independent-funding-balance-b "$WALLET_DIR" "$ACCOUNT_B_UUID"
[[ "$(balance_locked_value phase4-independent-funding-balance-a)" == "$PHASE4_A_BASE_LOCKED" ]] \
    || die "Account A lock value changed before its Phase 4 registration"
[[ "$(balance_locked_value phase4-independent-funding-balance-b)" == "$PHASE4_B_BASE_LOCKED" ]] \
    || die "Account B lock value changed before its Phase 4 registration"
printf '[PASS] both accounts have independent spendable funding and no premature Coppice lock mutation\n'

status "Phase 4: create and canonicalize two account-owned registrations"
run_devtool_logged phase4-name-a-address wallet \
    --wallet-dir "$WALLET_DIR" generate-address "$ACCOUNT_A_UUID"
PHASE4_UA_ONE="$(sed -n 's/^     Address: //p' \
    "$LOG_DIR/phase4-name-a-address.log" | tail -1)"
[[ -n "$PHASE4_UA_ONE" ]] || die "could not create Account A's Phase 4 UA"
run_devtool_logged phase4-name-b-address wallet \
    --wallet-dir "$WALLET_DIR" generate-address "$ACCOUNT_B_UUID"
PHASE4_UA_TWO="$(sed -n 's/^     Address: //p' \
    "$LOG_DIR/phase4-name-b-address.log" | tail -1)"
[[ -n "$PHASE4_UA_TWO" ]] || die "could not create Account B's Phase 4 UA"

PHASE4_A_COMMIT_HEIGHT_EXPECTED=$(($(zakura_tip_height) + 1))
run_devtool_logged phase4-register-a wallet \
    --wallet-dir "$WALLET_DIR" coppice register "$ACCOUNT_A_UUID" \
    --identity "$IDENTITY_FILE" \
    --name "$PHASE4_NAME_ONE" \
    --address "$PHASE4_UA_ONE" \
    --server "$ZAINO_GRPC_ADDR" --connection direct
PHASE4_COMMITMENT_A="$(rg -a -o 'commitment=[0-9a-fA-F]{64}' \
    "$LOG_DIR/phase4-register-a.log" | tail -1 | cut -d= -f2)"
PHASE4_A_COMMIT_TXID="$(rg -a -o 'txid=[0-9a-fA-F]{64}' \
    "$LOG_DIR/phase4-register-a.log" | tail -1 | cut -d= -f2)"
[[ -n "$PHASE4_COMMITMENT_A" && -n "$PHASE4_A_COMMIT_TXID" ]] \
    || die "Account A COMMIT did not emit commitment and transaction id"
rpc_generate 1
wait_for_zaino_tip "$PHASE4_A_COMMIT_HEIGHT_EXPECTED"
wallet_sync_logged phase4-a-commit-sync
run_devtool_logged phase4-observe-commit-a wallet \
    --wallet-dir "$WALLET_DIR" coppice observe-commit "$PHASE4_COMMITMENT_A"
[[ "$(tail -1 "$LOG_DIR/phase4-observe-commit-a.log" | tr -d '\r')" == \
    "$PHASE4_A_COMMIT_HEIGHT_EXPECTED" ]] \
    || die "Account A COMMIT was not observed at its canonical height"
wallet_status_logged phase4-a-commit-status
assert_coppice_status phase4-a-commit-status \
    "$PHASE4_A_COMMIT_HEIGHT_EXPECTED" Enabled 2 1
assert_pending_owner phase4-a-commit-status "$PHASE4_COMMITMENT_A" \
    "$PHASE4_NAME_ONE" "$ACCOUNT_A_WALLET_ID"
wallet_balance_logged_for phase4-a-pending-balance-a "$WALLET_DIR" "$ACCOUNT_A_UUID"
wallet_balance_logged_for phase4-a-pending-balance-b "$WALLET_DIR" "$ACCOUNT_B_UUID"
PHASE4_A_PENDING_LOCKED="$(balance_locked_value phase4-a-pending-balance-a)"
PHASE4_B_PENDING_AFTER_A="$(balance_locked_value phase4-a-pending-balance-b)"
(( PHASE4_A_PENDING_LOCKED == PHASE4_A_BASE_LOCKED + COPPICE_BOND_VALUE )) \
    || die "Account A pending registration did not lock exactly its own bond"
(( PHASE4_B_PENDING_AFTER_A == PHASE4_B_BASE_LOCKED )) \
    || die "Account A pending registration changed Account B's lock value"
printf '[PASS] Account A pending bond lock is account-scoped at %s zatoshi\n' \
    "$PHASE4_A_PENDING_LOCKED"

PHASE4_B_COMMIT_HEIGHT_EXPECTED=$(($(zakura_tip_height) + 1))
run_devtool_logged phase4-register-b wallet \
    --wallet-dir "$WALLET_DIR" coppice register "$ACCOUNT_B_UUID" \
    --identity "$IDENTITY_FILE" \
    --name "$PHASE4_NAME_TWO" \
    --address "$PHASE4_UA_TWO" \
    --server "$ZAINO_GRPC_ADDR" --connection direct
PHASE4_COMMITMENT_B="$(rg -a -o 'commitment=[0-9a-fA-F]{64}' \
    "$LOG_DIR/phase4-register-b.log" | tail -1 | cut -d= -f2)"
PHASE4_B_COMMIT_TXID="$(rg -a -o 'txid=[0-9a-fA-F]{64}' \
    "$LOG_DIR/phase4-register-b.log" | tail -1 | cut -d= -f2)"
[[ -n "$PHASE4_COMMITMENT_B" && -n "$PHASE4_B_COMMIT_TXID" ]] \
    || die "Account B COMMIT did not emit commitment and transaction id"
rpc_generate 1
wait_for_zaino_tip "$PHASE4_B_COMMIT_HEIGHT_EXPECTED"
wallet_sync_logged phase4-b-commit-sync
run_devtool_logged phase4-observe-commit-b wallet \
    --wallet-dir "$WALLET_DIR" coppice observe-commit "$PHASE4_COMMITMENT_B"
[[ "$(tail -1 "$LOG_DIR/phase4-observe-commit-b.log" | tr -d '\r')" == \
    "$PHASE4_B_COMMIT_HEIGHT_EXPECTED" ]] \
    || die "Account B COMMIT was not observed at its canonical height"
wallet_status_logged phase4-both-commit-status
assert_coppice_status phase4-both-commit-status \
    "$PHASE4_B_COMMIT_HEIGHT_EXPECTED" Enabled 2 2
assert_pending_owner phase4-both-commit-status "$PHASE4_COMMITMENT_A" \
    "$PHASE4_NAME_ONE" "$ACCOUNT_A_WALLET_ID"
assert_pending_owner phase4-both-commit-status "$PHASE4_COMMITMENT_B" \
    "$PHASE4_NAME_TWO" "$ACCOUNT_B_WALLET_ID"
wallet_balance_logged_for phase4-both-pending-balance-a "$WALLET_DIR" "$ACCOUNT_A_UUID"
wallet_balance_logged_for phase4-both-pending-balance-b "$WALLET_DIR" "$ACCOUNT_B_UUID"
[[ "$(balance_locked_value phase4-both-pending-balance-a)" == "$PHASE4_A_PENDING_LOCKED" ]] \
    || die "Account B COMMIT mutated Account A's pending lock"
PHASE4_B_PENDING_LOCKED="$(balance_locked_value phase4-both-pending-balance-b)"
(( PHASE4_B_PENDING_LOCKED == PHASE4_B_BASE_LOCKED + COPPICE_BOND_VALUE )) \
    || die "Account B pending registration did not lock exactly its own bond"
printf '[PASS] Account B pending bond lock is account-scoped at %s zatoshi\n' \
    "$PHASE4_B_PENDING_LOCKED"

PHASE4_A_REVEAL_HEIGHT_EXPECTED=$(($(zakura_tip_height) + 1))
run_devtool_logged phase4-reveal-a wallet \
    --wallet-dir "$WALLET_DIR" coppice reveal \
    --identity "$IDENTITY_FILE" "$ACCOUNT_A_UUID" "$PHASE4_COMMITMENT_A" \
    --server "$ZAINO_GRPC_ADDR" --connection direct
PHASE4_A_REVEAL_TXID="$(rg -a -o 'txid=[0-9a-fA-F]{64}' \
    "$LOG_DIR/phase4-reveal-a.log" | tail -1 | cut -d= -f2)"
[[ -n "$PHASE4_A_REVEAL_TXID" ]] || die "Account A REVEAL did not emit a transaction id"
rpc_generate 1
wait_for_zaino_tip "$PHASE4_A_REVEAL_HEIGHT_EXPECTED"
wallet_sync_logged phase4-a-reveal-sync
wallet_status_logged phase4-a-reveal-status
assert_coppice_status phase4-a-reveal-status \
    "$PHASE4_A_REVEAL_HEIGHT_EXPECTED" Enabled 3 1
assert_snapshot_status "$PHASE4_NAME_ONE" Active "$PHASE4_A_REVEAL_HEIGHT_EXPECTED"
assert_resolved_address phase4-resolve-a "$PHASE4_NAME_ONE" "$PHASE4_UA_ONE"
assert_pending_owner phase4-a-reveal-status "$PHASE4_COMMITMENT_A" \
    "$PHASE4_NAME_ONE" "$ACCOUNT_A_WALLET_ID"
assert_pending_owner phase4-a-reveal-status "$PHASE4_COMMITMENT_B" \
    "$PHASE4_NAME_TWO" "$ACCOUNT_B_WALLET_ID"
wallet_balance_logged_for phase4-a-reveal-balance-a "$WALLET_DIR" "$ACCOUNT_A_UUID"
wallet_balance_logged_for phase4-a-reveal-balance-b "$WALLET_DIR" "$ACCOUNT_B_UUID"
[[ "$(balance_locked_value phase4-a-reveal-balance-a)" == "$PHASE4_A_PENDING_LOCKED" ]] \
    || die "Account A REVEAL changed its own protected bond value"
[[ "$(balance_locked_value phase4-a-reveal-balance-b)" == "$PHASE4_B_PENDING_LOCKED" ]] \
    || die "Account A REVEAL changed Account B's pending lock value"
printf '[PASS] Account A REVEAL activated %s while Account B remains pending and locked\n' \
    "$PHASE4_NAME_ONE"

status "Phase 4: reject cross-account completion and complete Account A only"
run_devtool_expect_failure phase4-wrong-complete-a wallet \
    --wallet-dir "$WALLET_DIR" coppice complete \
    "$ACCOUNT_B_UUID" "$PHASE4_COMMITMENT_A"
rg -a -qi 'does not own|own the Coppice registration' \
    "$LOG_DIR/phase4-wrong-complete-a.log" \
    || die "wrong-account completion failed without the ownership guard diagnostic"
wallet_status_logged phase4-after-wrong-complete-status
assert_coppice_status phase4-after-wrong-complete-status \
    "$PHASE4_A_REVEAL_HEIGHT_EXPECTED" Enabled 3 1
assert_pending_owner phase4-after-wrong-complete-status "$PHASE4_COMMITMENT_A" \
    "$PHASE4_NAME_ONE" "$ACCOUNT_A_WALLET_ID"
assert_pending_owner phase4-after-wrong-complete-status "$PHASE4_COMMITMENT_B" \
    "$PHASE4_NAME_TWO" "$ACCOUNT_B_WALLET_ID"
wallet_balance_logged_for phase4-after-wrong-complete-balance-a "$WALLET_DIR" "$ACCOUNT_A_UUID"
wallet_balance_logged_for phase4-after-wrong-complete-balance-b "$WALLET_DIR" "$ACCOUNT_B_UUID"
[[ "$(balance_locked_value phase4-after-wrong-complete-balance-a)" == "$PHASE4_A_PENDING_LOCKED" ]] \
    || die "wrong-account completion mutated Account A's lock"
[[ "$(balance_locked_value phase4-after-wrong-complete-balance-b)" == "$PHASE4_B_PENDING_LOCKED" ]] \
    || die "wrong-account completion mutated Account B's lock"

run_devtool_logged phase4-complete-a wallet \
    --wallet-dir "$WALLET_DIR" coppice complete \
    "$ACCOUNT_A_UUID" "$PHASE4_COMMITMENT_A"
wallet_status_logged phase4-complete-a-status
assert_coppice_status phase4-complete-a-status \
    "$PHASE4_A_REVEAL_HEIGHT_EXPECTED" Enabled 3 1
assert_no_pending_commitment phase4-complete-a-status "$PHASE4_COMMITMENT_A"
assert_pending_owner phase4-complete-a-status "$PHASE4_COMMITMENT_B" \
    "$PHASE4_NAME_TWO" "$ACCOUNT_B_WALLET_ID"
assert_snapshot_status "$PHASE4_NAME_ONE" Active "$PHASE4_A_REVEAL_HEIGHT_EXPECTED"
assert_resolved_address phase4-complete-a-resolve "$PHASE4_NAME_ONE" "$PHASE4_UA_ONE"
wallet_balance_logged_for phase4-complete-a-balance-a "$WALLET_DIR" "$ACCOUNT_A_UUID"
wallet_balance_logged_for phase4-complete-a-balance-b "$WALLET_DIR" "$ACCOUNT_B_UUID"
[[ "$(balance_locked_value phase4-complete-a-balance-a)" == "$PHASE4_A_PENDING_LOCKED" ]] \
    || die "completing Account A changed its active bond lock"
[[ "$(balance_locked_value phase4-complete-a-balance-b)" == "$PHASE4_B_PENDING_LOCKED" ]] \
    || die "completing Account A changed Account B's pending bond lock"
printf '[PASS] completing Account A removed only Account A pending metadata and preserved both locks\n'

PHASE4_B_REVEAL_HEIGHT_EXPECTED=$(($(zakura_tip_height) + 1))
run_devtool_logged phase4-reveal-b wallet \
    --wallet-dir "$WALLET_DIR" coppice reveal \
    --identity "$IDENTITY_FILE" "$ACCOUNT_B_UUID" "$PHASE4_COMMITMENT_B" \
    --server "$ZAINO_GRPC_ADDR" --connection direct
PHASE4_B_REVEAL_TXID="$(rg -a -o 'txid=[0-9a-fA-F]{64}' \
    "$LOG_DIR/phase4-reveal-b.log" | tail -1 | cut -d= -f2)"
[[ -n "$PHASE4_B_REVEAL_TXID" ]] || die "Account B REVEAL did not emit a transaction id"
rpc_generate 1
wait_for_zaino_tip "$PHASE4_B_REVEAL_HEIGHT_EXPECTED"
wallet_sync_logged phase4-b-reveal-sync
wallet_status_logged phase4-b-reveal-status
assert_coppice_status phase4-b-reveal-status \
    "$PHASE4_B_REVEAL_HEIGHT_EXPECTED" Enabled 4 0
assert_snapshot_status "$PHASE4_NAME_ONE" Active "$PHASE4_B_REVEAL_HEIGHT_EXPECTED"
assert_snapshot_status "$PHASE4_NAME_TWO" Active "$PHASE4_B_REVEAL_HEIGHT_EXPECTED"
assert_resolved_address phase4-resolve-a-after-b "$PHASE4_NAME_ONE" "$PHASE4_UA_ONE"
assert_resolved_address phase4-resolve-b "$PHASE4_NAME_TWO" "$PHASE4_UA_TWO"
assert_pending_owner phase4-b-reveal-status "$PHASE4_COMMITMENT_B" \
    "$PHASE4_NAME_TWO" "$ACCOUNT_B_WALLET_ID"
wallet_balance_logged_for phase4-b-reveal-balance-a "$WALLET_DIR" "$ACCOUNT_A_UUID"
wallet_balance_logged_for phase4-b-reveal-balance-b "$WALLET_DIR" "$ACCOUNT_B_UUID"
[[ "$(balance_locked_value phase4-b-reveal-balance-a)" == "$PHASE4_A_PENDING_LOCKED" ]] \
    || die "Account B REVEAL changed Account A's active bond lock"
[[ "$(balance_locked_value phase4-b-reveal-balance-b)" == "$PHASE4_B_PENDING_LOCKED" ]] \
    || die "Account B REVEAL changed its own protected bond value"

run_devtool_logged phase4-complete-b wallet \
    --wallet-dir "$WALLET_DIR" coppice complete \
    "$ACCOUNT_B_UUID" "$PHASE4_COMMITMENT_B"
wallet_status_logged phase4-complete-b-status
assert_coppice_status phase4-complete-b-status \
    "$PHASE4_B_REVEAL_HEIGHT_EXPECTED" Enabled 4 0
[[ "$(jq -r '.local_registrations | length' "$LOG_DIR/phase4-complete-b-status.log")" == 0 ]] \
    || die "completing Account B did not clear only the remaining local registration"
assert_snapshot_status "$PHASE4_NAME_ONE" Active "$PHASE4_B_REVEAL_HEIGHT_EXPECTED"
assert_snapshot_status "$PHASE4_NAME_TWO" Active "$PHASE4_B_REVEAL_HEIGHT_EXPECTED"
assert_resolved_address phase4-complete-b-resolve-a "$PHASE4_NAME_ONE" "$PHASE4_UA_ONE"
assert_resolved_address phase4-complete-b-resolve-b "$PHASE4_NAME_TWO" "$PHASE4_UA_TWO"
wallet_balance_logged_for phase4-active-balance-a "$WALLET_DIR" "$ACCOUNT_A_UUID"
wallet_balance_logged_for phase4-active-balance-b "$WALLET_DIR" "$ACCOUNT_B_UUID"
PHASE4_A_ACTIVE_LOCKED="$(balance_locked_value phase4-active-balance-a)"
PHASE4_B_ACTIVE_LOCKED="$(balance_locked_value phase4-active-balance-b)"
(( PHASE4_A_ACTIVE_LOCKED == PHASE4_A_BASE_LOCKED + COPPICE_BOND_VALUE )) \
    || die "Account A active bond lock value is incorrect"
(( PHASE4_B_ACTIVE_LOCKED == PHASE4_B_BASE_LOCKED + COPPICE_BOND_VALUE )) \
    || die "Account B active bond lock value is incorrect"
printf '[PASS] both active names resolve and both account-scoped bonds remain protected\n'

status "Phase 4: reject lifecycle and ordinary spends that cross account ownership"
run_devtool_expect_failure phase4-wrong-break-bond wallet \
    --wallet-dir "$WALLET_DIR" coppice break-bond \
    "$ACCOUNT_B_UUID" \
    --identity "$IDENTITY_FILE" \
    --name "$PHASE4_NAME_ONE" \
    --address "$PHASE4_UA_TWO" \
    --value 1000000 \
    --server "$ZAINO_GRPC_ADDR" --connection direct
rg -a -qi 'bond|owned|missing|account' "$LOG_DIR/phase4-wrong-break-bond.log" \
    || die "wrong-account Break Bond failed without an ownership/bond diagnostic"

run_devtool_logged phase4-ordinary-probe-address-a wallet \
    --wallet-dir "$WALLET_DIR" generate-address "$ACCOUNT_A_UUID"
PHASE4_PROBE_ADDRESS_A="$(sed -n 's/^     Address: //p' \
    "$LOG_DIR/phase4-ordinary-probe-address-a.log" | tail -1)"
run_devtool_logged phase4-ordinary-probe-address-b wallet \
    --wallet-dir "$WALLET_DIR" generate-address "$ACCOUNT_B_UUID"
PHASE4_PROBE_ADDRESS_B="$(sed -n 's/^     Address: //p' \
    "$LOG_DIR/phase4-ordinary-probe-address-b.log" | tail -1)"
PHASE4_A_TOTAL="$(balance_total_value phase4-active-balance-a)"
PHASE4_B_TOTAL="$(balance_total_value phase4-active-balance-b)"
run_devtool_expect_failure phase4-ordinary-send-a wallet \
    --wallet-dir "$WALLET_DIR" send \
    --identity "$IDENTITY_FILE" \
    --address "$PHASE4_PROBE_ADDRESS_A" \
    --value "$((PHASE4_A_TOTAL - 1))" \
    --min-confirmations 1 \
    --server "$ZAINO_GRPC_ADDR" --connection direct "$ACCOUNT_A_UUID"
run_devtool_expect_failure phase4-ordinary-send-b wallet \
    --wallet-dir "$WALLET_DIR" send \
    --identity "$IDENTITY_FILE" \
    --address "$PHASE4_PROBE_ADDRESS_B" \
    --value "$((PHASE4_B_TOTAL - 1))" \
    --min-confirmations 1 \
    --server "$ZAINO_GRPC_ADDR" --connection direct "$ACCOUNT_B_UUID"
for ordinary_failure in phase4-ordinary-send-a phase4-ordinary-send-b; do
    rg -a -qi 'insufficient|not enough|Coppice spend protection|locked|unavailable' \
        "$LOG_DIR/$ordinary_failure.log" \
        || die "$ordinary_failure did not report protected-value rejection"
done
wallet_balance_logged_for phase4-after-ordinary-balance-a "$WALLET_DIR" "$ACCOUNT_A_UUID"
wallet_balance_logged_for phase4-after-ordinary-balance-b "$WALLET_DIR" "$ACCOUNT_B_UUID"
[[ "$(balance_locked_value phase4-after-ordinary-balance-a)" == "$PHASE4_A_ACTIVE_LOCKED" ]] \
    || die "Account A ordinary-send rejection changed its bond lock"
[[ "$(balance_locked_value phase4-after-ordinary-balance-b)" == "$PHASE4_B_ACTIVE_LOCKED" ]] \
    || die "Account B ordinary-send rejection changed its bond lock"
printf '[PASS] wrong-account lifecycle and ordinary sends could not consume either protected bond\n'

status "Phase 4: restart Zaino and reopen the persisted two-account wallet"
if [[ -n "$ZAINO_PID" ]]; then
    kill -TERM "$ZAINO_PID" 2>/dev/null || true
    wait "$ZAINO_PID" 2>/dev/null || true
    ZAINO_PID=""
fi
ZAINOLOG_COLOR=0 RUST_LOG=info "$ZAINO_BIN" start --config "$ZAINO_CONFIG" \
    >"$LOG_DIR/zainod-phase4-restart.log" 2>&1 &
ZAINO_PID=$!
printf '[INFO] Phase 4 restarted zainod pid=%s with the same indexer database\n' "$ZAINO_PID"
wait_for_grpc_ready
wallet_sync_logged phase4-persisted-wallet-sync
PHASE4_PERSISTED_HEIGHT="$(zakura_tip_height)"
wallet_status_logged phase4-persisted-wallet-status
assert_coppice_status phase4-persisted-wallet-status \
    "$PHASE4_PERSISTED_HEIGHT" Enabled 4 0
assert_snapshot_status "$PHASE4_NAME_ONE" Active "$PHASE4_PERSISTED_HEIGHT"
assert_snapshot_status "$PHASE4_NAME_TWO" Active "$PHASE4_PERSISTED_HEIGHT"
assert_resolved_address phase4-persisted-resolve-a "$PHASE4_NAME_ONE" "$PHASE4_UA_ONE"
assert_resolved_address phase4-persisted-resolve-b "$PHASE4_NAME_TWO" "$PHASE4_UA_TWO"
[[ "$(wallet_account_id_from_status phase4-persisted-wallet-status "$ACCOUNT_A_UUID")" == \
    "$ACCOUNT_A_WALLET_ID" ]] \
    || die "persisted restart changed Account A's FVK-derived WalletAccountId"
[[ "$(wallet_account_id_from_status phase4-persisted-wallet-status "$ACCOUNT_B_UUID")" == \
    "$ACCOUNT_B_WALLET_ID" ]] \
    || die "persisted restart changed Account B's FVK-derived WalletAccountId"
run_devtool_logged phase4-persisted-account-list wallet \
    --wallet-dir "$WALLET_DIR" list-accounts
assert_account_records_match "$ORIGINAL_ACCOUNT_A_RECORD" \
    "$(account_record_for_name "$LOG_DIR/phase4-persisted-account-list.log" phase1)" \
    "persisted Account A"
assert_account_records_match "$ORIGINAL_ACCOUNT_B_RECORD" \
    "$(account_record_for_name "$LOG_DIR/phase4-persisted-account-list.log" phase4-account-b)" \
    "persisted Account B"
wallet_balance_logged_for phase4-persisted-balance-a "$WALLET_DIR" "$ACCOUNT_A_UUID"
wallet_balance_logged_for phase4-persisted-balance-b "$WALLET_DIR" "$ACCOUNT_B_UUID"
[[ "$(balance_locked_value phase4-persisted-balance-a)" == "$PHASE4_A_ACTIVE_LOCKED" ]] \
    || die "persisted restart did not recover Account A's active bond lock"
[[ "$(balance_locked_value phase4-persisted-balance-b)" == "$PHASE4_B_ACTIVE_LOCKED" ]] \
    || die "persisted restart did not recover Account B's active bond lock"
printf '[PASS] persisted two-account restart recovered both canonical names, IDs, and locks\n'

status "Phase 4: fresh same-seed two-account recovery with no copied local state"
[[ ! -e "$PHASE4_RECOVERY_WALLET_DIR" ]] \
    || die "Phase 4 fresh recovery wallet directory already exists"
mkdir "$PHASE4_RECOVERY_WALLET_DIR"
if [[ -n "$(find "$PHASE4_RECOVERY_WALLET_DIR" -mindepth 1 -print -quit)" ]]; then
    die "Phase 4 fresh recovery directory was not empty"
fi
printf '[PASS] Phase 4 fresh recovery directory began empty\n'

if {
    printf '%s\n' "$WALLET_MNEMONIC" | timeout 240 "$DEVTOOL_BIN" wallet \
        --wallet-dir "$PHASE4_RECOVERY_WALLET_DIR" init \
        --name phase4-fresh-a \
        --identity "$PHASE4_RECOVERY_IDENTITY_FILE" \
        --network regtest \
        --birthday "$COPPICE_ACTIVATION_HEIGHT" \
        --activation-heights "$ACTIVATION_FILE" \
        --server "$ZAINO_GRPC_ADDR" \
        --connection direct
} >"$LOG_DIR/phase4-fresh-wallet-init.log" 2>&1; then
    printf '[PASS] fresh two-account wallet initialized from the deterministic mnemonic at birthday %s\n' \
        "$COPPICE_ACTIVATION_HEIGHT"
else
    status_code=$?
    printf '[FAIL] phase4-fresh-wallet-init (exit %d); see %s\n' \
        "$status_code" "$LOG_DIR/phase4-fresh-wallet-init.log" >&2
    tail -100 "$LOG_DIR/phase4-fresh-wallet-init.log" >&2 || true
    exit "$status_code"
fi
for forbidden_state in \
    "$PHASE4_RECOVERY_WALLET_DIR/coppice-runtime-v1.json" \
    "$PHASE4_RECOVERY_WALLET_DIR/coppice-pending-v1.json" \
    "$PHASE4_RECOVERY_WALLET_DIR/coppice-protection.json"; do
    [[ ! -e "$forbidden_state" ]] \
        || die "fresh Phase 4 init unexpectedly copied Coppice state: $forbidden_state"
done

run_devtool_logged phase4-fresh-generate-account-b wallet \
    --wallet-dir "$PHASE4_RECOVERY_WALLET_DIR" generate-account \
    --identity "$PHASE4_RECOVERY_IDENTITY_FILE" \
    --name phase4-fresh-b \
    --server "$ZAINO_GRPC_ADDR" --connection direct
run_devtool_logged phase4-fresh-account-list wallet \
    --wallet-dir "$PHASE4_RECOVERY_WALLET_DIR" list-accounts
FRESH_ACCOUNT_A_RECORD="$(account_record_for_name \
    "$LOG_DIR/phase4-fresh-account-list.log" phase4-fresh-a)"
FRESH_ACCOUNT_B_RECORD="$(account_record_for_name \
    "$LOG_DIR/phase4-fresh-account-list.log" phase4-fresh-b)"
FRESH_ACCOUNT_A_UUID="$(jq -r '.uuid' <<<"$FRESH_ACCOUNT_A_RECORD")"
FRESH_ACCOUNT_B_UUID="$(jq -r '.uuid' <<<"$FRESH_ACCOUNT_B_RECORD")"
assert_account_records_match "$ORIGINAL_ACCOUNT_A_RECORD" \
    "$FRESH_ACCOUNT_A_RECORD" "fresh Account A"
assert_account_records_match "$ORIGINAL_ACCOUNT_B_RECORD" \
    "$FRESH_ACCOUNT_B_RECORD" "fresh Account B"
[[ "$FRESH_ACCOUNT_A_UUID" != "$FRESH_ACCOUNT_B_UUID" ]] \
    || die "fresh recovery accounts unexpectedly share an AccountUuid"

wallet_sync_logged_for phase4-fresh-wallet-sync "$PHASE4_RECOVERY_WALLET_DIR"
wallet_status_logged_for phase4-fresh-wallet-status "$PHASE4_RECOVERY_WALLET_DIR"
assert_coppice_status phase4-fresh-wallet-status \
    "$PHASE4_PERSISTED_HEIGHT" Enabled 4 0
assert_snapshot_status_for "$PHASE4_RECOVERY_WALLET_DIR" \
    "$PHASE4_NAME_ONE" Active "$PHASE4_PERSISTED_HEIGHT"
assert_snapshot_status_for "$PHASE4_RECOVERY_WALLET_DIR" \
    "$PHASE4_NAME_TWO" Active "$PHASE4_PERSISTED_HEIGHT"
assert_resolved_address_for phase4-fresh-resolve-a \
    "$PHASE4_RECOVERY_WALLET_DIR" "$PHASE4_NAME_ONE" "$PHASE4_UA_ONE"
assert_resolved_address_for phase4-fresh-resolve-b \
    "$PHASE4_RECOVERY_WALLET_DIR" "$PHASE4_NAME_TWO" "$PHASE4_UA_TWO"
[[ "$(jq -r '.local_registrations | length' "$LOG_DIR/phase4-fresh-wallet-status.log")" == 0 ]] \
    || die "fresh two-account recovery recreated stale local pending metadata"
[[ -f "$PHASE4_RECOVERY_WALLET_DIR/coppice-pending-v1.json" ]] \
    || die "fresh two-account recovery did not create the normal empty pending store"
jq -e '.registrations == []' \
    "$PHASE4_RECOVERY_WALLET_DIR/coppice-pending-v1.json" >/dev/null \
    || die "fresh two-account recovery pending store is not empty"
FRESH_ACCOUNT_A_WALLET_ID="$(wallet_account_id_from_status \
    phase4-fresh-wallet-status "$FRESH_ACCOUNT_A_UUID")"
FRESH_ACCOUNT_B_WALLET_ID="$(wallet_account_id_from_status \
    phase4-fresh-wallet-status "$FRESH_ACCOUNT_B_UUID")"
[[ "$FRESH_ACCOUNT_A_WALLET_ID" == "$ACCOUNT_A_WALLET_ID" ]] \
    || die "fresh Account A did not reconstruct its FVK-derived WalletAccountId"
[[ "$FRESH_ACCOUNT_B_WALLET_ID" == "$ACCOUNT_B_WALLET_ID" ]] \
    || die "fresh Account B did not reconstruct its FVK-derived WalletAccountId"
wallet_balance_logged_for phase4-fresh-balance-a \
    "$PHASE4_RECOVERY_WALLET_DIR" "$FRESH_ACCOUNT_A_UUID"
wallet_balance_logged_for phase4-fresh-balance-b \
    "$PHASE4_RECOVERY_WALLET_DIR" "$FRESH_ACCOUNT_B_UUID"
PHASE4_FRESH_A_LOCKED="$(balance_locked_value phase4-fresh-balance-a)"
PHASE4_FRESH_B_LOCKED="$(balance_locked_value phase4-fresh-balance-b)"
(( PHASE4_FRESH_A_LOCKED == COPPICE_BOND_VALUE )) \
    || die "fresh recovery did not reconstruct Account A's Phase 4 active bond lock"
(( PHASE4_FRESH_B_LOCKED == COPPICE_BOND_VALUE )) \
    || die "fresh recovery did not reconstruct Account B's Phase 4 active bond lock"
printf '[PASS] fresh sync reconstructed both active registrations, both FVK-derived IDs, and both independent locks\n'

run_devtool_logged phase4-fresh-probe-address-a wallet \
    --wallet-dir "$PHASE4_RECOVERY_WALLET_DIR" generate-address "$FRESH_ACCOUNT_A_UUID"
PHASE4_FRESH_PROBE_ADDRESS_A="$(sed -n 's/^     Address: //p' \
    "$LOG_DIR/phase4-fresh-probe-address-a.log" | tail -1)"
run_devtool_logged phase4-fresh-probe-address-b wallet \
    --wallet-dir "$PHASE4_RECOVERY_WALLET_DIR" generate-address "$FRESH_ACCOUNT_B_UUID"
PHASE4_FRESH_PROBE_ADDRESS_B="$(sed -n 's/^     Address: //p' \
    "$LOG_DIR/phase4-fresh-probe-address-b.log" | tail -1)"
FRESH_ACCOUNT_A_TOTAL="$(balance_total_value phase4-fresh-balance-a)"
FRESH_ACCOUNT_B_TOTAL="$(balance_total_value phase4-fresh-balance-b)"
run_devtool_expect_failure phase4-fresh-ordinary-send-a wallet \
    --wallet-dir "$PHASE4_RECOVERY_WALLET_DIR" send \
    --identity "$PHASE4_RECOVERY_IDENTITY_FILE" \
    --address "$PHASE4_FRESH_PROBE_ADDRESS_A" \
    --value "$((FRESH_ACCOUNT_A_TOTAL - 1))" \
    --min-confirmations 1 \
    --server "$ZAINO_GRPC_ADDR" --connection direct "$FRESH_ACCOUNT_A_UUID"
run_devtool_expect_failure phase4-fresh-ordinary-send-b wallet \
    --wallet-dir "$PHASE4_RECOVERY_WALLET_DIR" send \
    --identity "$PHASE4_RECOVERY_IDENTITY_FILE" \
    --address "$PHASE4_FRESH_PROBE_ADDRESS_B" \
    --value "$((FRESH_ACCOUNT_B_TOTAL - 1))" \
    --min-confirmations 1 \
    --server "$ZAINO_GRPC_ADDR" --connection direct "$FRESH_ACCOUNT_B_UUID"
for fresh_ordinary_failure in phase4-fresh-ordinary-send-a phase4-fresh-ordinary-send-b; do
    rg -a -qi 'insufficient|not enough|Coppice spend protection|locked|unavailable' \
        "$LOG_DIR/$fresh_ordinary_failure.log" \
        || die "$fresh_ordinary_failure did not report protected-value rejection"
done
printf '[PASS] fresh reconstructed locks protected both accounts from ordinary spending\n'

write_phase4_checkpoint
printf '\n[PASS] Phase 4 multi-account isolation, restart recovery, and fresh recovery qualification complete\n'
finish_phase_if_requested 4
fi

status "Phase 5: create one active-and-one-pending adversarial protection fixture"
# Phase 4 leaves the two original lifecycle names plus both account-isolation
# names in the canonical registry. Phase 5 adds only one pending COMMIT.
PHASE5_EXPECTED_NAME_COUNT=4
PHASE5_PREP_HEIGHT=$(($(zakura_tip_height) + 4))
rpc_generate 4
wait_for_zaino_tip "$PHASE5_PREP_HEIGHT"
wallet_sync_logged phase5-preparation-sync

run_devtool_logged phase5-pending-funding-address wallet \
    --wallet-dir "$WALLET_DIR" generate-address "$ACCOUNT_A_UUID"
PHASE5_PENDING_FUNDING_ADDRESS="$(sed -n 's/^     Address: //p' \
    "$LOG_DIR/phase5-pending-funding-address.log" | tail -1)"
[[ -n "$PHASE5_PENDING_FUNDING_ADDRESS" ]] \
    || die "could not create the Phase 5 pending-bond funding address"
run_devtool_logged phase5-pending-funding wallet \
    --wallet-dir "$WALLET_DIR" send \
    --identity "$IDENTITY_FILE" \
    --address "$PHASE5_PENDING_FUNDING_ADDRESS" \
    --value "$PHASE5_PENDING_FUNDING_VALUE" \
    --min-confirmations 1 \
    --server "$ZAINO_GRPC_ADDR" --connection direct "$ACCOUNT_A_UUID"
PHASE5_PENDING_FUNDING_TXID="$(rg -a -o '[0-9a-fA-F]{64}' \
    "$LOG_DIR/phase5-pending-funding.log" | tail -1 || true)"
[[ -n "$PHASE5_PENDING_FUNDING_TXID" ]] \
    || die "Phase 5 pending-bond funding did not emit a transaction id"
PHASE5_PENDING_FUNDING_HEIGHT=$(($(zakura_tip_height) + 3))
rpc_generate 3
wait_for_zaino_tip "$PHASE5_PENDING_FUNDING_HEIGHT"
wallet_sync_logged phase5-pending-funding-sync
run_devtool_logged phase5-pending-funding-history wallet \
    --wallet-dir "$WALLET_DIR" list-tx --json
PHASE5_PENDING_FUNDING_MINED_HEIGHT="$(jq -r --arg txid "$PHASE5_PENDING_FUNDING_TXID" \
    '.[] | select(.txid == $txid) | .mined_height' \
    "$LOG_DIR/phase5-pending-funding-history.log" | tail -1)"
[[ "$PHASE5_PENDING_FUNDING_MINED_HEIGHT" =~ ^[0-9]+$ ]] \
    || die "Phase 5 pending-bond funding tx $PHASE5_PENDING_FUNDING_TXID has no mined height"

run_devtool_logged phase5-pending-name-address wallet \
    --wallet-dir "$WALLET_DIR" generate-address "$ACCOUNT_A_UUID"
PHASE5_PENDING_UA="$(sed -n 's/^     Address: //p' \
    "$LOG_DIR/phase5-pending-name-address.log" | tail -1)"
[[ -n "$PHASE5_PENDING_UA" ]] || die "could not create the Phase 5 pending registration UA"

PHASE5_COMMIT_HEIGHT_EXPECTED=$(($(zakura_tip_height) + 1))
run_devtool_logged phase5-register-pending wallet \
    --wallet-dir "$WALLET_DIR" coppice register "$ACCOUNT_A_UUID" \
    --identity "$IDENTITY_FILE" \
    --name "$PHASE5_NAME_PENDING" \
    --address "$PHASE5_PENDING_UA" \
    --server "$ZAINO_GRPC_ADDR" --connection direct
PHASE5_COMMITMENT="$(rg -a -o 'commitment=[0-9a-fA-F]{64}' \
    "$LOG_DIR/phase5-register-pending.log" | tail -1 | cut -d= -f2)"
PHASE5_COMMIT_TXID="$(rg -a -o 'txid=[0-9a-fA-F]{64}' \
    "$LOG_DIR/phase5-register-pending.log" | tail -1 | cut -d= -f2)"
[[ -n "$PHASE5_COMMITMENT" && -n "$PHASE5_COMMIT_TXID" ]] \
    || die "Phase 5 pending COMMIT did not emit commitment and transaction id"
rpc_generate 1
wait_for_zaino_tip "$PHASE5_COMMIT_HEIGHT_EXPECTED"
wallet_sync_logged phase5-pending-commit-sync
run_devtool_logged phase5-observe-pending-commit wallet \
    --wallet-dir "$WALLET_DIR" coppice observe-commit "$PHASE5_COMMITMENT"
[[ "$(tail -1 "$LOG_DIR/phase5-observe-pending-commit.log" | tr -d '\r')" == \
    "$PHASE5_COMMIT_HEIGHT_EXPECTED" ]] \
    || die "Phase 5 pending COMMIT was not observed at its canonical height"
wallet_status_logged phase5-pending-status
PHASE5_TIP="$(zakura_tip_height)"
assert_coppice_status phase5-pending-status "$PHASE5_TIP" Enabled \
    "$PHASE5_EXPECTED_NAME_COUNT" 1
assert_snapshot_status "$PHASE4_NAME_ONE" Active "$PHASE5_TIP"
assert_snapshot_status "$PHASE4_NAME_TWO" Active "$PHASE5_TIP"
assert_pending_owner phase5-pending-status "$PHASE5_COMMITMENT" \
    "$PHASE5_NAME_PENDING" "$ACCOUNT_A_WALLET_ID"
wallet_balance_logged_for phase5-pending-balance-a "$WALLET_DIR" "$ACCOUNT_A_UUID"
wallet_balance_logged_for phase5-pending-balance-b "$WALLET_DIR" "$ACCOUNT_B_UUID"
PHASE5_A_LOCKED="$(balance_locked_value phase5-pending-balance-a)"
PHASE5_B_LOCKED="$(balance_locked_value phase5-pending-balance-b)"
(( PHASE5_A_LOCKED == PHASE4_A_ACTIVE_LOCKED + PHASE5_PENDING_FUNDING_VALUE )) \
    || die "Phase 5 pending registration did not lock the dedicated Account A bond note"
(( PHASE5_B_LOCKED == PHASE4_B_ACTIVE_LOCKED )) \
    || die "Phase 5 pending registration changed Account B's active-bond lock"
printf '[PASS] active bonds plus pending registration: A locked=%s, B locked=%s, pending=%s\n' \
    "$PHASE5_A_LOCKED" "$PHASE5_B_LOCKED" "$PHASE5_COMMITMENT"

phase5_assert_fixture_unchanged() {
    local label=$1
    local expected_mode=$2
    local digest

    wallet_status_logged "$label-status"
    assert_coppice_status "$label-status" "$PHASE5_TIP" "$expected_mode" \
        "$PHASE5_EXPECTED_NAME_COUNT" 1
    assert_snapshot_status "$PHASE4_NAME_ONE" Active "$PHASE5_TIP"
    assert_snapshot_status "$PHASE4_NAME_TWO" Active "$PHASE5_TIP"
    assert_pending_owner "$label-status" "$PHASE5_COMMITMENT" \
        "$PHASE5_NAME_PENDING" "$ACCOUNT_A_WALLET_ID"
    digest="$(sha256sum "$WALLET_DIR/coppice-runtime-v1.json" \
        "$WALLET_DIR/coppice-pending-v1.json")"
    [[ "$digest" == "$PHASE5_STATE_DIGEST" ]] \
        || die "$label changed Coppice snapshot or pending metadata"
    wallet_balance_logged_for "$label-balance-a" "$WALLET_DIR" "$ACCOUNT_A_UUID"
    wallet_balance_logged_for "$label-balance-b" "$WALLET_DIR" "$ACCOUNT_B_UUID"
    [[ "$(balance_locked_value "$label-balance-a")" == "$PHASE5_A_LOCKED" ]] \
        || die "$label changed Account A's protected lock value"
    [[ "$(balance_locked_value "$label-balance-b")" == "$PHASE5_B_LOCKED" ]] \
        || die "$label changed Account B's protected lock value"
    printf '[PASS] %s left canonical state, pending metadata, and both locks unchanged\n' "$label"
}

phase5_assert_rejected_diagnostic() {
    local label=$1

    rg -a -qi 'Coppice|protected|bond|locked|insufficient|not enough|ineligible|unavailable|spend protection' \
        "$LOG_DIR/$label.log" \
        || die "$label failed without a protected-spend diagnostic"
}

status "Phase 5: reject wrong-account REVEAL, ABANDON, COMPLETE, and Break Bond"
PHASE5_STATE_DIGEST="$(sha256sum "$WALLET_DIR/coppice-runtime-v1.json" \
    "$WALLET_DIR/coppice-pending-v1.json")"
run_devtool_expect_failure phase5-wrong-account-reveal wallet \
    --wallet-dir "$WALLET_DIR" coppice reveal "$ACCOUNT_B_UUID" \
    --identity "$IDENTITY_FILE" "$PHASE5_COMMITMENT" \
    --server "$ZAINO_GRPC_ADDR" --connection direct
phase5_assert_rejected_diagnostic phase5-wrong-account-reveal
phase5_assert_fixture_unchanged phase5-wrong-account-reveal Enabled

run_devtool_expect_failure phase5-wrong-account-abandon wallet \
    --wallet-dir "$WALLET_DIR" coppice abandon "$ACCOUNT_B_UUID" "$PHASE5_COMMITMENT"
phase5_assert_rejected_diagnostic phase5-wrong-account-abandon
phase5_assert_fixture_unchanged phase5-wrong-account-abandon Enabled

run_devtool_expect_failure phase5-wrong-account-complete wallet \
    --wallet-dir "$WALLET_DIR" coppice complete "$ACCOUNT_B_UUID" "$PHASE5_COMMITMENT"
phase5_assert_rejected_diagnostic phase5-wrong-account-complete
phase5_assert_fixture_unchanged phase5-wrong-account-complete Enabled

run_devtool_logged phase5-wrong-break-bond-address wallet \
    --wallet-dir "$WALLET_DIR" generate-address "$ACCOUNT_B_UUID"
PHASE5_WRONG_BREAK_ADDRESS="$(sed -n 's/^     Address: //p' \
    "$LOG_DIR/phase5-wrong-break-bond-address.log" | tail -1)"
[[ -n "$PHASE5_WRONG_BREAK_ADDRESS" ]] \
    || die "could not create the wrong-account Break Bond destination"
run_devtool_expect_failure phase5-wrong-account-break-bond wallet \
    --wallet-dir "$WALLET_DIR" coppice break-bond "$ACCOUNT_B_UUID" \
    --identity "$IDENTITY_FILE" \
    --name "$PHASE4_NAME_ONE" \
    --address "$PHASE5_WRONG_BREAK_ADDRESS" \
    --value 1000000 \
    --server "$ZAINO_GRPC_ADDR" --connection direct
phase5_assert_rejected_diagnostic phase5-wrong-account-break-bond
phase5_assert_fixture_unchanged phase5-wrong-account-break-bond Enabled
printf '[PASS] wrong-account lifecycle and Break Bond attempts were rejected without mutation\n'

status "Phase 5: build a fully signed adversarial Ironwood PCZT while protection is Off"
run_devtool_logged phase5-adversarial-address wallet \
    --wallet-dir "$WALLET_DIR" generate-address "$ACCOUNT_B_UUID"
PHASE5_ADVERSARIAL_ADDRESS="$(sed -n 's/^     Address: //p' \
    "$LOG_DIR/phase5-adversarial-address.log" | tail -1)"
[[ -n "$PHASE5_ADVERSARIAL_ADDRESS" ]] \
    || die "could not create the adversarial PCZT destination"
run_devtool_logged phase5-protection-off wallet \
    --wallet-dir "$WALLET_DIR" coppice protection off
rg -a -q '^Off$' "$LOG_DIR/phase5-protection-off.log" \
    || die "Phase 5 wallet protection did not become Off"
wallet_balance_logged_for phase5-off-balance-a "$WALLET_DIR" "$ACCOUNT_A_UUID"
wallet_balance_logged_for phase5-off-balance-b "$WALLET_DIR" "$ACCOUNT_B_UUID"
PHASE5_A_OFF_RESIDUAL=$((PHASE4_A_ACTIVE_LOCKED - COPPICE_BOND_VALUE))
PHASE5_B_OFF_RESIDUAL=$((PHASE4_B_ACTIVE_LOCKED - COPPICE_BOND_VALUE))
[[ "$(balance_locked_value phase5-off-balance-a)" == "$PHASE5_A_OFF_RESIDUAL" ]] \
    || die "switching protection Off did not remove Account A's Coppice-owned locks"
[[ "$(balance_locked_value phase5-off-balance-b)" == "$PHASE5_B_OFF_RESIDUAL" ]] \
    || die "switching protection Off did not remove Account B's Coppice-owned locks"
[[ "$(sha256sum "$WALLET_DIR/coppice-runtime-v1.json" \
    "$WALLET_DIR/coppice-pending-v1.json")" == "$PHASE5_STATE_DIGEST" ]] \
    || die "switching protection Off changed canonical or pending Coppice state"
printf '[PASS] Off removed both Coppice-owned advisory lock sets; residual non-Coppice values A=%s, B=%s\n' \
    "$PHASE5_A_OFF_RESIDUAL" "$PHASE5_B_OFF_RESIDUAL"

PHASE5_RAW_PCZT="$PHASE5_PCZT_DIR/protected-spend.raw.pczt"
PHASE5_PROVED_PCZT="$PHASE5_PCZT_DIR/protected-spend.proved.pczt"
PHASE5_SIGNED_PCZT="$PHASE5_PCZT_DIR/protected-spend.signed.pczt"
run_devtool_logged phase5-pczt-create-max-off pczt \
    --wallet-dir "$WALLET_DIR" create-max "$ACCOUNT_A_UUID" \
    --address "$PHASE5_ADVERSARIAL_ADDRESS" \
    --only-spendable \
    --output "$PHASE5_RAW_PCZT"
[[ -s "$PHASE5_RAW_PCZT" ]] || die "Off-mode create-max did not write an adversarial PCZT"
run_devtool_logged phase5-pczt-inspect-off pczt \
    --wallet-dir "$WALLET_DIR" inspect "$PHASE5_RAW_PCZT"
rg -a -qi 'Ironwood' "$LOG_DIR/phase5-pczt-inspect-off.log" \
    || die "adversarial PCZT does not contain an Ironwood bundle"
run_devtool_logged phase5-pczt-prove-off pczt \
    --wallet-dir "$WALLET_DIR" prove \
    --identity "$IDENTITY_FILE" \
    --output "$PHASE5_PROVED_PCZT" "$PHASE5_RAW_PCZT"
run_devtool_logged phase5-pczt-sign-off pczt \
    --wallet-dir "$WALLET_DIR" sign \
    --identity "$IDENTITY_FILE" \
    --output "$PHASE5_SIGNED_PCZT" "$PHASE5_PROVED_PCZT"
[[ -s "$PHASE5_SIGNED_PCZT" ]] || die "Off-mode PCZT signing did not write a signed PCZT"
run_devtool_stdin_logged phase5-pczt-extract-off "$PHASE5_SIGNED_PCZT" \
    pczt --wallet-dir "$WALLET_DIR" extract
PHASE5_ADVERSARIAL_TXID="$(rg -a -o '[0-9a-fA-F]{64}' \
    "$LOG_DIR/phase5-pczt-extract-off.log" | tail -1 || true)"
[[ -n "$PHASE5_ADVERSARIAL_TXID" ]] \
    || die "Off-mode PCZT extraction did not produce a transaction id"
printf '[PASS] built fully signed adversarial Ironwood PCZT %s without broadcasting it\n' \
    "$PHASE5_ADVERSARIAL_TXID"

status "Phase 5: restore Enabled and reconstitute the protected fixture"
run_devtool_logged phase5-protection-reenabled wallet \
    --wallet-dir "$WALLET_DIR" coppice protection enabled
rg -a -q '^Enabled$' "$LOG_DIR/phase5-protection-reenabled.log" \
    || die "Phase 5 wallet protection did not become Enabled"
wallet_sync_logged phase5-reenabled-sync
PHASE5_TIP="$(zakura_tip_height)"
wallet_status_logged phase5-reenabled-status
assert_coppice_status phase5-reenabled-status "$PHASE5_TIP" Enabled \
    "$PHASE5_EXPECTED_NAME_COUNT" 1
assert_snapshot_status "$PHASE4_NAME_ONE" Active "$PHASE5_TIP"
assert_snapshot_status "$PHASE4_NAME_TWO" Active "$PHASE5_TIP"
assert_pending_owner phase5-reenabled-status "$PHASE5_COMMITMENT" \
    "$PHASE5_NAME_PENDING" "$ACCOUNT_A_WALLET_ID"
wallet_balance_logged_for phase5-reenabled-balance-a "$WALLET_DIR" "$ACCOUNT_A_UUID"
wallet_balance_logged_for phase5-reenabled-balance-b "$WALLET_DIR" "$ACCOUNT_B_UUID"
PHASE5_A_LOCKED="$(balance_locked_value phase5-reenabled-balance-a)"
PHASE5_B_LOCKED="$(balance_locked_value phase5-reenabled-balance-b)"
PHASE5_STATE_DIGEST="$(sha256sum "$WALLET_DIR/coppice-runtime-v1.json" \
    "$WALLET_DIR/coppice-pending-v1.json")"
printf '[PASS] Enabled replay reconstructed active/pending state and locks: A=%s, B=%s\n' \
    "$PHASE5_A_LOCKED" "$PHASE5_B_LOCKED"

status "Phase 5: reject Enabled ordinary send, proposal, create, sign, extract, and submission paths"
PHASE5_A_TOTAL="$(balance_total_value phase5-reenabled-balance-a)"
PHASE5_PROTECTED_SEND_VALUE=$((PHASE5_A_TOTAL - 1))
(( PHASE5_PROTECTED_SEND_VALUE > 0 )) || die "Phase 5 Account A total balance is unusable"
PHASE5_PROTECTED_SEND_ZEC_WHOLE=$((PHASE5_PROTECTED_SEND_VALUE / 100000000))
PHASE5_PROTECTED_SEND_ZEC_FRACTION=$(printf '%08d' "$((PHASE5_PROTECTED_SEND_VALUE % 100000000))")
PHASE5_PROTECTED_SEND_AMOUNT_ZEC="${PHASE5_PROTECTED_SEND_ZEC_WHOLE}.${PHASE5_PROTECTED_SEND_ZEC_FRACTION}"

run_devtool_expect_failure phase5-enabled-wallet-send wallet \
    --wallet-dir "$WALLET_DIR" send \
    --identity "$IDENTITY_FILE" \
    --address "$PHASE5_ADVERSARIAL_ADDRESS" \
    --value "$PHASE5_PROTECTED_SEND_VALUE" \
    --min-confirmations 1 \
    --server "$ZAINO_GRPC_ADDR" --connection direct "$ACCOUNT_A_UUID"
phase5_assert_rejected_diagnostic phase5-enabled-wallet-send
phase5_assert_fixture_unchanged phase5-enabled-wallet-send Enabled

run_devtool_expect_failure phase5-enabled-wallet-propose wallet \
    --wallet-dir "$WALLET_DIR" propose "$ACCOUNT_A_UUID" \
    --address "$PHASE5_ADVERSARIAL_ADDRESS" \
    --value "$PHASE5_PROTECTED_SEND_VALUE"
phase5_assert_rejected_diagnostic phase5-enabled-wallet-propose
phase5_assert_fixture_unchanged phase5-enabled-wallet-propose Enabled

run_devtool_expect_failure phase5-enabled-wallet-pay wallet \
    --wallet-dir "$WALLET_DIR" pay "$ACCOUNT_A_UUID" \
    --identity "$IDENTITY_FILE" \
    --payment-uri "zcash:${PHASE5_ADVERSARIAL_ADDRESS}?amount=${PHASE5_PROTECTED_SEND_AMOUNT_ZEC}" \
    --server "$ZAINO_GRPC_ADDR" --connection direct
phase5_assert_rejected_diagnostic phase5-enabled-wallet-pay
phase5_assert_fixture_unchanged phase5-enabled-wallet-pay Enabled

PHASE5_ENABLED_CREATE_PCZT="$PHASE5_PCZT_DIR/enabled-create.pczt"
run_devtool_expect_failure phase5-enabled-pczt-create pczt \
    --wallet-dir "$WALLET_DIR" create "$ACCOUNT_A_UUID" \
    --address "$PHASE5_ADVERSARIAL_ADDRESS" \
    --value "$PHASE5_PROTECTED_SEND_VALUE" \
    --output "$PHASE5_ENABLED_CREATE_PCZT"
phase5_assert_rejected_diagnostic phase5-enabled-pczt-create
phase5_assert_fixture_unchanged phase5-enabled-pczt-create Enabled

PHASE5_ENABLED_MAX_PCZT="$PHASE5_PCZT_DIR/enabled-max.pczt"
run_devtool_expect_failure phase5-enabled-pczt-create-max pczt \
    --wallet-dir "$WALLET_DIR" create-max "$ACCOUNT_A_UUID" \
    --address "$PHASE5_ADVERSARIAL_ADDRESS" \
    --output "$PHASE5_ENABLED_MAX_PCZT"
phase5_assert_rejected_diagnostic phase5-enabled-pczt-create-max
phase5_assert_fixture_unchanged phase5-enabled-pczt-create-max Enabled

run_devtool_expect_failure phase5-enabled-pczt-prove pczt \
    --wallet-dir "$WALLET_DIR" prove \
    --identity "$IDENTITY_FILE" \
    --output "$PHASE5_PCZT_DIR/rejected-prove.pczt" "$PHASE5_RAW_PCZT"
phase5_assert_rejected_diagnostic phase5-enabled-pczt-prove
phase5_assert_fixture_unchanged phase5-enabled-pczt-prove Enabled

run_devtool_expect_failure phase5-enabled-pczt-sign pczt \
    --wallet-dir "$WALLET_DIR" sign \
    --identity "$IDENTITY_FILE" \
    --output "$PHASE5_PCZT_DIR/rejected-sign.pczt" "$PHASE5_RAW_PCZT"
phase5_assert_rejected_diagnostic phase5-enabled-pczt-sign
phase5_assert_fixture_unchanged phase5-enabled-pczt-sign Enabled

run_devtool_stdin_expect_failure phase5-enabled-pczt-extract "$PHASE5_SIGNED_PCZT" \
    pczt --wallet-dir "$WALLET_DIR" extract
phase5_assert_rejected_diagnostic phase5-enabled-pczt-extract
phase5_assert_fixture_unchanged phase5-enabled-pczt-extract Enabled

run_devtool_expect_failure phase5-enabled-pczt-send pczt \
    --wallet-dir "$WALLET_DIR" send \
    --server "$ZAINO_GRPC_ADDR" --connection direct "$PHASE5_SIGNED_PCZT"
phase5_assert_rejected_diagnostic phase5-enabled-pczt-send
phase5_assert_fixture_unchanged phase5-enabled-pczt-send Enabled

run_devtool_expect_failure phase5-enabled-pczt-send-without-storing pczt \
    --wallet-dir "$WALLET_DIR" send-without-storing \
    --server "$ZAINO_GRPC_ADDR" --connection direct "$PHASE5_SIGNED_PCZT"
phase5_assert_rejected_diagnostic phase5-enabled-pczt-send-without-storing
phase5_assert_fixture_unchanged phase5-enabled-pczt-send-without-storing Enabled
printf '[PASS] Enabled rejected ordinary, proposal/create, PCZT prove/sign/extract, stored-submit, and direct-submit attempts\n'

status "Phase 5: GuardOnly retains replay, resolver, and every spend guard"
run_devtool_logged phase5-protection-guard-only wallet \
    --wallet-dir "$WALLET_DIR" coppice protection guard-only
rg -a -q '^GuardOnly$' "$LOG_DIR/phase5-protection-guard-only.log" \
    || die "Phase 5 wallet protection did not become GuardOnly"
phase5_assert_fixture_unchanged phase5-guard-only GuardOnly
assert_resolved_address phase5-guard-only-resolve "$PHASE4_NAME_ONE" "$PHASE4_UA_ONE"

run_devtool_expect_failure phase5-guard-only-wallet-send wallet \
    --wallet-dir "$WALLET_DIR" send \
    --identity "$IDENTITY_FILE" \
    --address "$PHASE5_ADVERSARIAL_ADDRESS" \
    --value "$PHASE5_PROTECTED_SEND_VALUE" \
    --min-confirmations 1 \
    --server "$ZAINO_GRPC_ADDR" --connection direct "$ACCOUNT_A_UUID"
phase5_assert_rejected_diagnostic phase5-guard-only-wallet-send
phase5_assert_fixture_unchanged phase5-guard-only-wallet-send GuardOnly

run_devtool_expect_failure phase5-guard-only-pczt-send pczt \
    --wallet-dir "$WALLET_DIR" send \
    --server "$ZAINO_GRPC_ADDR" --connection direct "$PHASE5_SIGNED_PCZT"
phase5_assert_rejected_diagnostic phase5-guard-only-pczt-send
phase5_assert_fixture_unchanged phase5-guard-only-pczt-send GuardOnly
printf '[PASS] GuardOnly preserved canonical replay/resolution and protected active plus pending bonds; management UI was not used in guard-only mode\n'

status "Phase 5: Off cleanup, foreign-lock regression, and unsynchronized ordinary send"
run_logged phase5-foreign-lock-regression cargo \
    test --manifest-path "$ROOT_DIR/coppice-names/Cargo.toml" --locked \
    -p coppice-names-librustzcash --lib off_transition_cleanup_removes_only_coppice_owned_locks
rg -a -q 'test .*off_transition_cleanup_removes_only_coppice_owned_locks .*ok' \
    "$LOG_DIR/phase5-foreign-lock-regression.log" \
    || die "foreign-lock cleanup regression did not pass"
printf '[PASS] exact-owner Off cleanup regression preserved a foreign lock\n'

run_devtool_logged phase5-protection-off-main wallet \
    --wallet-dir "$WALLET_DIR" coppice protection off
rg -a -q '^Off$' "$LOG_DIR/phase5-protection-off-main.log" \
    || die "main wallet protection did not become Off"
wallet_balance_logged_for phase5-off-main-balance-a "$WALLET_DIR" "$ACCOUNT_A_UUID"
wallet_balance_logged_for phase5-off-main-balance-b "$WALLET_DIR" "$ACCOUNT_B_UUID"
[[ "$(balance_locked_value phase5-off-main-balance-a)" == "$PHASE5_A_OFF_RESIDUAL" ]] \
    || die "main Off transition left Account A's Coppice lock"
[[ "$(balance_locked_value phase5-off-main-balance-b)" == "$PHASE5_B_OFF_RESIDUAL" ]] \
    || die "main Off transition left Account B's Coppice lock"
[[ "$(sha256sum "$WALLET_DIR/coppice-runtime-v1.json" \
    "$WALLET_DIR/coppice-pending-v1.json")" == "$PHASE5_STATE_DIGEST" ]] \
    || die "main Off transition changed canonical or pending state"
printf '[PASS] main Off transition removed only Coppice-owned lock values (residual A/B=%s/%s)\n' \
    "$PHASE5_A_OFF_RESIDUAL" "$PHASE5_B_OFF_RESIDUAL"

PHASE5_OFF_BIRTHDAY="$(zakura_tip_height)"
[[ ! -e "$PHASE5_OFF_WALLET_DIR" ]] \
    || die "Phase 5 Off wallet directory already exists"
mkdir "$PHASE5_OFF_WALLET_DIR"
[[ -z "$(find "$PHASE5_OFF_WALLET_DIR" -mindepth 1 -print -quit)" ]] \
    || die "Phase 5 Off wallet directory was not empty"
if {
    printf '%s\n' "$WALLET_MNEMONIC" | timeout 240 "$DEVTOOL_BIN" wallet \
        --wallet-dir "$PHASE5_OFF_WALLET_DIR" init \
        --name phase5-off \
        --identity "$PHASE5_OFF_IDENTITY_FILE" \
        --network regtest \
        --birthday "$PHASE5_OFF_BIRTHDAY" \
        --activation-heights "$ACTIVATION_FILE" \
        --server "$ZAINO_GRPC_ADDR" \
        --connection direct
} >"$LOG_DIR/phase5-off-wallet-init.log" 2>&1; then
    printf '[PASS] fresh Off wallet initialized at birthday %s\n' "$PHASE5_OFF_BIRTHDAY"
else
    status_code=$?
    printf '[FAIL] phase5-off-wallet-init (exit %d); see %s\n' \
        "$status_code" "$LOG_DIR/phase5-off-wallet-init.log" >&2
    tail -100 "$LOG_DIR/phase5-off-wallet-init.log" >&2 || true
    exit "$status_code"
fi
for forbidden_state in \
    "$PHASE5_OFF_WALLET_DIR/coppice-runtime-v1.json" \
    "$PHASE5_OFF_WALLET_DIR/coppice-pending-v1.json"; do
    [[ ! -e "$forbidden_state" ]] \
        || die "fresh Off wallet init unexpectedly created Coppice state: $forbidden_state"
done
run_devtool_logged phase5-off-wallet-protection wallet \
    --wallet-dir "$PHASE5_OFF_WALLET_DIR" coppice protection off
rg -a -q '^Off$' "$LOG_DIR/phase5-off-wallet-protection.log" \
    || die "fresh Off wallet did not enter Off mode"
PHASE5_OFF_MINED_HEIGHT=$(($(zakura_tip_height) + 4))
rpc_generate 4
wait_for_zaino_tip "$PHASE5_OFF_MINED_HEIGHT"
wallet_sync_logged_for phase5-off-wallet-sync "$PHASE5_OFF_WALLET_DIR"
run_devtool_logged phase5-off-wallet-balance wallet \
    --wallet-dir "$PHASE5_OFF_WALLET_DIR" balance --json --min-confirmations 1
PHASE5_OFF_BALANCE="$(balance_json phase5-off-wallet-balance)"
jq -e '.ironwood_spendable > 0' >/dev/null <<<"$PHASE5_OFF_BALANCE" \
    || die "fresh Off wallet did not receive spendable Ironwood value"
for forbidden_state in \
    "$PHASE5_OFF_WALLET_DIR/coppice-runtime-v1.json" \
    "$PHASE5_OFF_WALLET_DIR/coppice-pending-v1.json"; do
    [[ ! -e "$forbidden_state" ]] \
        || die "Off-mode sync unexpectedly created Coppice state: $forbidden_state"
done
run_devtool_logged phase5-off-wallet-receive-address wallet \
    --wallet-dir "$PHASE5_OFF_WALLET_DIR" generate-address
PHASE5_OFF_RECEIVE_ADDRESS="$(sed -n 's/^     Address: //p' \
    "$LOG_DIR/phase5-off-wallet-receive-address.log" | tail -1)"
[[ -n "$PHASE5_OFF_RECEIVE_ADDRESS" ]] \
    || die "fresh Off wallet did not generate an ordinary receive address"
run_devtool_logged phase5-off-wallet-send wallet \
    --wallet-dir "$PHASE5_OFF_WALLET_DIR" send \
    --identity "$PHASE5_OFF_IDENTITY_FILE" \
    --address "$PHASE5_OFF_RECEIVE_ADDRESS" \
    --value 1000000 \
    --min-confirmations 1 \
    --server "$ZAINO_GRPC_ADDR" --connection direct
PHASE5_OFF_SEND_TXID="$(rg -a -o '[0-9a-fA-F]{64}' \
    "$LOG_DIR/phase5-off-wallet-send.log" | tail -1 || true)"
[[ -n "$PHASE5_OFF_SEND_TXID" ]] \
    || die "fresh Off wallet ordinary send did not emit a transaction id"
PHASE5_OFF_SEND_HEIGHT=$(($(zakura_tip_height) + 1))
rpc_generate 1
wait_for_zaino_tip "$PHASE5_OFF_SEND_HEIGHT"
wallet_sync_logged_for phase5-off-wallet-resync "$PHASE5_OFF_WALLET_DIR"
run_devtool_logged phase5-off-wallet-history wallet \
    --wallet-dir "$PHASE5_OFF_WALLET_DIR" list-tx --json
PHASE5_OFF_SEND_MINED_HEIGHT="$(jq -r --arg txid "$PHASE5_OFF_SEND_TXID" \
    '.[] | select(.txid == $txid) | .mined_height' \
    "$LOG_DIR/phase5-off-wallet-history.log" | tail -1)"
[[ "$PHASE5_OFF_SEND_MINED_HEIGHT" =~ ^[0-9]+$ ]] \
    || die "fresh Off ordinary send $PHASE5_OFF_SEND_TXID has no mined height"
printf '[PASS] Off wallet sent ordinary Ironwood tx %s at height %s without Coppice state or sync\n' \
    "$PHASE5_OFF_SEND_TXID" "$PHASE5_OFF_SEND_MINED_HEIGHT"

status "Phase 5: restore main protection and execute the owner-scoped Break Bond exception"
run_devtool_logged phase5-final-protection-enabled wallet \
    --wallet-dir "$WALLET_DIR" coppice protection enabled
rg -a -q '^Enabled$' "$LOG_DIR/phase5-final-protection-enabled.log" \
    || die "main wallet protection did not return to Enabled"
wallet_sync_logged phase5-final-main-sync
PHASE5_TIP="$(zakura_tip_height)"
wallet_status_logged phase5-final-pending-status
assert_coppice_status phase5-final-pending-status "$PHASE5_TIP" Enabled \
    "$PHASE5_EXPECTED_NAME_COUNT" 1
assert_snapshot_status "$PHASE4_NAME_ONE" Active "$PHASE5_TIP"
assert_snapshot_status "$PHASE4_NAME_TWO" Active "$PHASE5_TIP"
assert_pending_owner phase5-final-pending-status "$PHASE5_COMMITMENT" \
    "$PHASE5_NAME_PENDING" "$ACCOUNT_A_WALLET_ID"
wallet_balance_logged_for phase5-final-pending-balance-a "$WALLET_DIR" "$ACCOUNT_A_UUID"
wallet_balance_logged_for phase5-final-pending-balance-b "$WALLET_DIR" "$ACCOUNT_B_UUID"
[[ "$(balance_locked_value phase5-final-pending-balance-a)" == "$PHASE5_A_LOCKED" ]] \
    || die "Enabled recovery did not reconstruct Account A's active plus pending locks"
[[ "$(balance_locked_value phase5-final-pending-balance-b)" == "$PHASE5_B_LOCKED" ]] \
    || die "Enabled recovery did not reconstruct Account B's active lock"

run_devtool_logged phase5-abandon-pending wallet \
    --wallet-dir "$WALLET_DIR" coppice abandon "$ACCOUNT_A_UUID" "$PHASE5_COMMITMENT"
wallet_status_logged phase5-abandon-pending-status
assert_coppice_status phase5-abandon-pending-status "$PHASE5_TIP" Enabled \
    "$PHASE5_EXPECTED_NAME_COUNT" 1
assert_snapshot_status "$PHASE4_NAME_ONE" Active "$PHASE5_TIP"
assert_snapshot_status "$PHASE4_NAME_TWO" Active "$PHASE5_TIP"
jq -e '.local_registrations == []' "$LOG_DIR/phase5-abandon-pending-status.log" >/dev/null \
    || die "correct Phase 5 abandonment did not clear the pending local registration"
wallet_balance_logged_for phase5-after-abandon-balance-a "$WALLET_DIR" "$ACCOUNT_A_UUID"
wallet_balance_logged_for phase5-after-abandon-balance-b "$WALLET_DIR" "$ACCOUNT_B_UUID"
[[ "$(balance_locked_value phase5-after-abandon-balance-a)" == "$PHASE4_A_ACTIVE_LOCKED" ]] \
    || die "correct Phase 5 abandonment did not release only the pending bond lock"
[[ "$(balance_locked_value phase5-after-abandon-balance-b)" == "$PHASE4_B_ACTIVE_LOCKED" ]] \
    || die "correct Phase 5 abandonment changed Account B's active lock"
printf '[PASS] correct owner abandonment removed pending metadata/lock while preserving both active bonds\n'

run_devtool_logged phase5-break-bond-address wallet \
    --wallet-dir "$WALLET_DIR" generate-address "$ACCOUNT_B_UUID"
PHASE5_BREAK_BOND_ADDRESS="$(sed -n 's/^     Address: //p' \
    "$LOG_DIR/phase5-break-bond-address.log" | tail -1)"
[[ -n "$PHASE5_BREAK_BOND_ADDRESS" ]] \
    || die "could not create the intentional Phase 5 Break Bond destination"
PHASE5_BREAK_BOND_HEIGHT_EXPECTED=$(($(zakura_tip_height) + 1))
run_devtool_logged phase5-break-bond wallet \
    --wallet-dir "$WALLET_DIR" coppice break-bond "$ACCOUNT_B_UUID" \
    --identity "$IDENTITY_FILE" \
    --name "$PHASE4_NAME_TWO" \
    --address "$PHASE5_BREAK_BOND_ADDRESS" \
    --value 1000000 \
    --server "$ZAINO_GRPC_ADDR" --connection direct
PHASE5_BREAK_BOND_TXID="$(rg -a -o '[0-9a-fA-F]{64}' \
    "$LOG_DIR/phase5-break-bond.log" | tail -1 || true)"
[[ -n "$PHASE5_BREAK_BOND_TXID" ]] \
    || die "intentional owner-scoped Phase 5 Break Bond did not emit a transaction id"
rpc_generate 1
wait_for_zaino_tip "$PHASE5_BREAK_BOND_HEIGHT_EXPECTED"
wallet_sync_logged phase5-break-bond-sync
PHASE5_TIP="$(zakura_tip_height)"
wallet_status_logged phase5-final-status
assert_coppice_status phase5-final-status "$PHASE5_TIP" Enabled \
    "$PHASE5_EXPECTED_NAME_COUNT" 1
assert_snapshot_status "$PHASE4_NAME_ONE" Active "$PHASE5_TIP"
assert_snapshot_status "$PHASE4_NAME_TWO" BondSpent "$PHASE5_TIP"
assert_resolved_address phase5-final-resolve-a "$PHASE4_NAME_ONE" "$PHASE4_UA_ONE"
assert_resolve_inactive phase5-final-resolve-b "$PHASE4_NAME_TWO"
jq -e '.local_registrations == []' "$LOG_DIR/phase5-final-status.log" >/dev/null \
    || die "Phase 5 final status recreated stale pending metadata"
wallet_balance_logged_for phase5-final-balance-a "$WALLET_DIR" "$ACCOUNT_A_UUID"
wallet_balance_logged_for phase5-final-balance-b "$WALLET_DIR" "$ACCOUNT_B_UUID"
[[ "$(balance_locked_value phase5-final-balance-a)" == "$PHASE4_A_ACTIVE_LOCKED" ]] \
    || die "Phase 5 Break Bond changed Account A's active lock"
[[ "$(balance_locked_value phase5-final-balance-b)" == 0 ]] \
    || die "Phase 5 Break Bond did not release Account B's spent bond lock"
printf '[PASS] owner-scoped Break Bond tx %s spent only Account B bond at height %s; Account A stayed Active/protected\n' \
    "$PHASE5_BREAK_BOND_TXID" "$PHASE5_BREAK_BOND_HEIGHT_EXPECTED"

printf '\n[PASS] Phase 1 + Phase 2 + Phase 3 + Phase 4 + Phase 5 qualification complete\n'
printf '[PASS] Phase 4 account A: uuid=%s WalletAccountId=%s name=%s commitment=%s active_height=%s\n' \
    "$ACCOUNT_A_UUID" "$ACCOUNT_A_WALLET_ID" "$PHASE4_NAME_ONE" \
    "$PHASE4_COMMITMENT_A" "$PHASE4_A_REVEAL_HEIGHT_EXPECTED"
printf '[PASS] Phase 4 account B: uuid=%s WalletAccountId=%s name=%s commitment=%s active_height=%s\n' \
    "$ACCOUNT_B_UUID" "$ACCOUNT_B_WALLET_ID" "$PHASE4_NAME_TWO" \
    "$PHASE4_COMMITMENT_B" "$PHASE4_B_REVEAL_HEIGHT_EXPECTED"
printf '[PASS] Phase 5 fixture: active=%s, pending=%s, A/B locks before adversarial tests=%s/%s zatoshi\n' \
    "$PHASE4_NAME_ONE" "$PHASE5_COMMITMENT" "$PHASE5_A_LOCKED" "$PHASE5_B_LOCKED"
printf '[PASS] Phase 5 rejection paths: wallet send/pay/propose, PCZT create/create-max/prove/sign/extract/send/send-without-storing\n'
printf '[PASS] Phase 5 modes: Enabled and GuardOnly rejected protected spends; Off removed Coppice locks and unsynchronized Off send=%s mined at h=%s\n' \
    "$PHASE5_OFF_SEND_TXID" "$PHASE5_OFF_SEND_MINED_HEIGHT"
printf '[PASS] Phase 5 owner exception: Break Bond tx=%s at h=%s; final %s=Active, %s=BondSpent/inactive\n' \
    "$PHASE5_BREAK_BOND_TXID" "$PHASE5_BREAK_BOND_HEIGHT_EXPECTED" \
    "$PHASE4_NAME_ONE" "$PHASE4_NAME_TWO"
printf '[PASS] Phase 5 wrong-account attempts and rejected-operation state invariants held; foreign-lock unit regression passed\n'
if (( TARGET_PHASE == 5 )); then
    printf '[PASS] live deep reorg was not requested; use --phase 7\n'
fi
finish_phase_if_requested 5

status "Phase 7: place an application transition on the branch that will be abandoned"
PHASE7_COMMON_HEIGHT="$(zakura_tip_height)"
PHASE7_RELEASE_HEIGHT=$((PHASE7_COMMON_HEIGHT + 1))
run_devtool_logged phase7-release-a wallet \
    --wallet-dir "$WALLET_DIR" coppice release "$ACCOUNT_A_UUID" \
    --identity "$IDENTITY_FILE" \
    --name "$PHASE4_NAME_ONE" \
    --server "$ZAINO_GRPC_ADDR" --connection direct
PHASE7_RELEASE_TXID="$(rg -a -o '[0-9a-fA-F]{64}' \
    "$LOG_DIR/phase7-release-a.log" | tail -1 || true)"
[[ -n "$PHASE7_RELEASE_TXID" ]] \
    || die "Phase 7 RELEASE did not emit a transaction id"
rpc_generate 1
wait_for_zaino_tip "$PHASE7_RELEASE_HEIGHT"
PHASE7_RELEASE_HASH="$(zakura_block_hash "$PHASE7_RELEASE_HEIGHT")"
wallet_sync_logged phase7-release-sync
wallet_status_logged phase7-release-status
assert_coppice_status phase7-release-status "$PHASE7_RELEASE_HEIGHT" Enabled \
    "$PHASE5_EXPECTED_NAME_COUNT" 1
assert_snapshot_status "$PHASE4_NAME_ONE" Released "$PHASE7_RELEASE_HEIGHT"
assert_snapshot_status "$PHASE4_NAME_TWO" BondSpent "$PHASE7_RELEASE_HEIGHT"
assert_resolve_inactive phase7-release-resolve-a "$PHASE4_NAME_ONE"
printf '[PASS] branch-only RELEASE tx %s made %s inactive at h=%s hash=%s\n' \
    "$PHASE7_RELEASE_TXID" "$PHASE4_NAME_ONE" \
    "$PHASE7_RELEASE_HEIGHT" "$PHASE7_RELEASE_HASH"

status "Phase 7: advance the old branch beyond the retained rewind horizon"
# Names v1 currently requests 121 retained blocks from generic Core. The
# abandoned suffix includes the RELEASE block plus 130 descendants.
PHASE7_PADDING_BLOCKS=130
PHASE7_REORG_DEPTH=$((PHASE7_PADDING_BLOCKS + 1))
(( PHASE7_REORG_DEPTH > 121 )) \
    || die "Phase 7 reorg depth does not exceed the configured retention"
PHASE7_OLD_TIP_HEIGHT=$((PHASE7_RELEASE_HEIGHT + PHASE7_PADDING_BLOCKS))
rpc_generate_batched "$PHASE7_PADDING_BLOCKS"
wait_for_zaino_tip "$PHASE7_OLD_TIP_HEIGHT"
wallet_sync_logged phase7-old-branch-sync
PHASE7_OLD_TIP_HASH="$(zakura_block_hash "$PHASE7_OLD_TIP_HEIGHT")"
wallet_status_logged phase7-old-branch-status
assert_coppice_status phase7-old-branch-status "$PHASE7_OLD_TIP_HEIGHT" Enabled \
    "$PHASE5_EXPECTED_NAME_COUNT" 0
assert_coppice_tip_hash phase7-old-branch-status "$PHASE7_OLD_TIP_HASH"
assert_snapshot_status "$PHASE4_NAME_ONE" Released "$PHASE7_OLD_TIP_HEIGHT"
assert_snapshot_status "$PHASE4_NAME_TWO" BondSpent "$PHASE7_OLD_TIP_HEIGHT"
PHASE7_OLD_SNAPSHOT_DIGEST="$(sha256sum \
    "$WALLET_DIR/coppice-runtime-v1.json" | cut -d' ' -f1)"
printf '[PASS] old branch retained %s blocks beyond common h=%s; %s remained Released at h=%s\n' \
    "$PHASE7_REORG_DEPTH" "$PHASE7_COMMON_HEIGHT" \
    "$PHASE4_NAME_ONE" "$PHASE7_OLD_TIP_HEIGHT"

status "Phase 7: invalidate the deep suffix and mine an equal-length replacement"
rpc_invalidate_block "$PHASE7_RELEASE_HASH"
wait_for_zakura_tip "$PHASE7_COMMON_HEIGHT"
rpc_generate_batched "$PHASE7_REORG_DEPTH"
wait_for_zakura_tip "$PHASE7_OLD_TIP_HEIGHT"
PHASE7_NEW_TIP_HASH="$(zakura_block_hash "$PHASE7_OLD_TIP_HEIGHT")"
[[ "$PHASE7_NEW_TIP_HASH" != "$PHASE7_OLD_TIP_HASH" ]] \
    || die "Phase 7 replacement tip hash did not change"
wait_for_zaino_tip_hash "$PHASE7_NEW_TIP_HASH" "$PHASE7_OLD_TIP_HEIGHT"

status "Phase 7: force beyond-retention runtime rebuild from canonical activation"
wallet_sync_logged phase7-deep-reorg-sync
wallet_status_logged phase7-deep-reorg-status
assert_coppice_status phase7-deep-reorg-status "$PHASE7_OLD_TIP_HEIGHT" Enabled \
    "$PHASE5_EXPECTED_NAME_COUNT" 0
assert_coppice_tip_hash phase7-deep-reorg-status "$PHASE7_NEW_TIP_HASH"
assert_snapshot_status "$PHASE4_NAME_ONE" Active "$PHASE7_OLD_TIP_HEIGHT"
assert_snapshot_status "$PHASE4_NAME_TWO" BondSpent "$PHASE7_OLD_TIP_HEIGHT"
assert_resolved_address phase7-deep-reorg-resolve-a \
    "$PHASE4_NAME_ONE" "$PHASE4_UA_ONE"
assert_resolve_inactive phase7-deep-reorg-resolve-b "$PHASE4_NAME_TWO"
wallet_balance_logged_for phase7-deep-reorg-balance-a "$WALLET_DIR" "$ACCOUNT_A_UUID"
wallet_balance_logged_for phase7-deep-reorg-balance-b "$WALLET_DIR" "$ACCOUNT_B_UUID"
PHASE7_A_PROTECTED_LOCKED="$(balance_locked_value phase7-deep-reorg-balance-a)"
PHASE7_B_PROTECTED_LOCKED="$(balance_locked_value phase7-deep-reorg-balance-b)"

# Mining 131 replacement blocks leaves immature coinbase value in the miner's
# account, so total-minus-spendable is no longer an exact Coppice lock metric.
# Toggle only Coppice protection and require its exact-owner cleanup/rebuild to
# remove and restore precisely one active Names bond without changing Account B.
run_devtool_logged phase7-protection-off wallet \
    --wallet-dir "$WALLET_DIR" coppice protection off
wallet_balance_logged_for phase7-off-balance-a "$WALLET_DIR" "$ACCOUNT_A_UUID"
wallet_balance_logged_for phase7-off-balance-b "$WALLET_DIR" "$ACCOUNT_B_UUID"
PHASE7_A_OFF_LOCKED="$(balance_locked_value phase7-off-balance-a)"
PHASE7_B_OFF_LOCKED="$(balance_locked_value phase7-off-balance-b)"
[[ "$((PHASE7_A_PROTECTED_LOCKED - PHASE7_A_OFF_LOCKED))" == "$COPPICE_BOND_VALUE" ]] \
    || die "deep rebuild did not restore exactly Account A's active Names bond lock"
[[ "$PHASE7_B_PROTECTED_LOCKED" == "$PHASE7_B_OFF_LOCKED" ]] \
    || die "deep rebuild recreated a Coppice lock for Account B's terminal bond"
run_devtool_logged phase7-protection-enabled wallet \
    --wallet-dir "$WALLET_DIR" coppice protection enabled
wallet_sync_logged phase7-reenabled-sync
wallet_balance_logged_for phase7-reenabled-balance-a "$WALLET_DIR" "$ACCOUNT_A_UUID"
wallet_balance_logged_for phase7-reenabled-balance-b "$WALLET_DIR" "$ACCOUNT_B_UUID"
[[ "$(balance_locked_value phase7-reenabled-balance-a)" == "$PHASE7_A_PROTECTED_LOCKED" ]] \
    || die "re-enabling protection did not restore Account A's rebuilt bond lock"
[[ "$(balance_locked_value phase7-reenabled-balance-b)" == "$PHASE7_B_PROTECTED_LOCKED" ]] \
    || die "re-enabling protection changed Account B's terminal lock state"
PHASE7_REBUILT_SNAPSHOT_DIGEST="$(sha256sum \
    "$WALLET_DIR/coppice-runtime-v1.json" | cut -d' ' -f1)"
[[ "$PHASE7_REBUILT_SNAPSHOT_DIGEST" != "$PHASE7_OLD_SNAPSHOT_DIGEST" ]] \
    || die "deep replacement left the old-branch runtime snapshot unchanged"
printf '[PASS] main wallet rebuilt across a %s-block reorg: %s returned Active and its lock was restored\n' \
    "$PHASE7_REORG_DEPTH" "$PHASE4_NAME_ONE"

status "Phase 7: independently reconstruct the replacement state from the same seed"
[[ ! -e "$PHASE7_RECOVERY_WALLET_DIR" ]] \
    || die "Phase 7 recovery wallet directory already exists"
mkdir "$PHASE7_RECOVERY_WALLET_DIR"
if {
    printf '%s\n' "$WALLET_MNEMONIC" | timeout 240 "$DEVTOOL_BIN" wallet \
        --wallet-dir "$PHASE7_RECOVERY_WALLET_DIR" init \
        --name phase7-fresh \
        --identity "$PHASE7_RECOVERY_IDENTITY_FILE" \
        --network regtest \
        --birthday "$COPPICE_ACTIVATION_HEIGHT" \
        --activation-heights "$ACTIVATION_FILE" \
        --server "$ZAINO_GRPC_ADDR" \
        --connection direct
} >"$LOG_DIR/phase7-fresh-wallet-init.log" 2>&1; then
    printf '[PASS] Phase 7 fresh same-seed wallet initialized at birthday %s\n' \
        "$COPPICE_ACTIVATION_HEIGHT"
else
    status_code=$?
    printf '[FAIL] phase7-fresh-wallet-init (exit %d); see %s\n' \
        "$status_code" "$LOG_DIR/phase7-fresh-wallet-init.log" >&2
    tail -100 "$LOG_DIR/phase7-fresh-wallet-init.log" >&2 || true
    exit "$status_code"
fi
wallet_sync_logged_for phase7-fresh-wallet-sync "$PHASE7_RECOVERY_WALLET_DIR"
wallet_status_logged_for phase7-fresh-wallet-status "$PHASE7_RECOVERY_WALLET_DIR"
assert_coppice_status phase7-fresh-wallet-status "$PHASE7_OLD_TIP_HEIGHT" Enabled \
    "$PHASE5_EXPECTED_NAME_COUNT" 0
assert_coppice_tip_hash phase7-fresh-wallet-status "$PHASE7_NEW_TIP_HASH"
assert_snapshot_status_for "$PHASE7_RECOVERY_WALLET_DIR" \
    "$PHASE4_NAME_ONE" Active "$PHASE7_OLD_TIP_HEIGHT"
assert_snapshot_status_for "$PHASE7_RECOVERY_WALLET_DIR" \
    "$PHASE4_NAME_TWO" BondSpent "$PHASE7_OLD_TIP_HEIGHT"
assert_resolved_address_for phase7-fresh-resolve-a \
    "$PHASE7_RECOVERY_WALLET_DIR" "$PHASE4_NAME_ONE" "$PHASE4_UA_ONE"
assert_resolve_inactive_for phase7-fresh-resolve-b \
    "$PHASE7_RECOVERY_WALLET_DIR" "$PHASE4_NAME_TWO"
PHASE7_FRESH_SNAPSHOT_DIGEST="$(sha256sum \
    "$PHASE7_RECOVERY_WALLET_DIR/coppice-runtime-v1.json" | cut -d' ' -f1)"
[[ "$PHASE7_FRESH_SNAPSHOT_DIGEST" == "$PHASE7_REBUILT_SNAPSHOT_DIGEST" ]] \
    || die "fresh replay and deep-reorg rebuild produced different runtime snapshots"
printf '\n[PASS] Phase 7 live deep-reorg qualification complete\n'
printf '[PASS] real stack: common h=%s, abandoned RELEASE h=%s, old/new tip h=%s hashes=%s/%s\n' \
    "$PHASE7_COMMON_HEIGHT" "$PHASE7_RELEASE_HEIGHT" \
    "$PHASE7_OLD_TIP_HEIGHT" "$PHASE7_OLD_TIP_HASH" "$PHASE7_NEW_TIP_HASH"
printf '[PASS] beyond-retention depth=%s forced canonical rebuild; rebuilt and fresh snapshots sha256=%s\n' \
    "$PHASE7_REORG_DEPTH" "$PHASE7_REBUILT_SNAPSHOT_DIGEST"
printf '[PASS] application reconstruction: %s=Active/locked, %s=BondSpent/inactive\n' \
    "$PHASE4_NAME_ONE" "$PHASE4_NAME_TWO"
