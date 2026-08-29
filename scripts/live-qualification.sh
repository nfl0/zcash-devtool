#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

# Disposable Names v1 live qualification. Phase 1 checks the local
# Zcash/Zakura/Zaino/devtool plumbing and Ironwood funding. Phase 2 runs the
# canonical COMMIT -> REVEAL -> UPDATE -> RENEW -> RELEASE lifecycle and checks
# the exact Released -> Expired boundary. Names v1 replay and FreshResolver
# checks are performed by names-v1-live itself.

usage() {
    cat <<'EOF'
Usage: live-qualification.sh [--phase N] [--keep-state]

  --phase N       1 for infrastructure, 2 for the full Names v1 lifecycle
                  (default: 2).
  --keep-state    Preserve the disposable run directory after success.
  -h|--help       Show this help.
EOF
}

TARGET_PHASE=2
KEEP_STATE=0
while (($# > 0)); do
    case "$1" in
        --phase|--through)
            (($# >= 2)) || { usage >&2; exit 2; }
            TARGET_PHASE=$2
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
[[ "$TARGET_PHASE" =~ ^[12]$ ]] || {
    printf '[FAIL] --phase must be 1 or 2\n' >&2
    exit 2
}

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
ROOT_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd -P)"
BIN_DIR="$ROOT_DIR/bin"
ZAKURA_BIN="$BIN_DIR/zakurad"
ZAINO_BIN="$BIN_DIR/zainod"
DEVTOOL_BIN="$BIN_DIR/zcash-devtool"
NAMES_V1_LIVE_BIN="$ROOT_DIR/zcash-devtool/target/debug/names-v1-live"

ZAKURA_RPC_ADDR="127.0.0.1:18232"
ZAKURA_RPC_URL="http://$ZAKURA_RPC_ADDR"
ZAKURA_P2P_ADDR="127.0.0.1:18233"
ZAINO_GRPC_ADDR="127.0.0.1:8137"
ZAINO_GRPC_URL="http://$ZAINO_GRPC_ADDR"

WALLET_MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
SAPLING_DISCARD_MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

WORK_DIR="$(mktemp -d /tmp/coppice-names-v1-live.XXXXXX)"
CONFIG_DIR="$WORK_DIR/config"
STATE_DIR="$WORK_DIR/state"
ZAKURA_STATE_DIR="$STATE_DIR/zakura"
ZAINO_STATE_DIR="$STATE_DIR/zaino"
WALLET_DIR="$STATE_DIR/wallet"
ZAKURA_CONFIG="$CONFIG_DIR/zakura.toml"
ZAINO_CONFIG="$CONFIG_DIR/zaino.toml"
ACTIVATION_FILE="$CONFIG_DIR/activation-heights.toml"
IDENTITY_FILE="$WALLET_DIR/identity.txt"
LOG_DIR="$WORK_DIR/logs"
GRPC_DIR="$LOG_DIR/grpc"
mkdir -p "$CONFIG_DIR" "$ZAKURA_STATE_DIR" "$ZAINO_STATE_DIR" "$WALLET_DIR" \
    "$LOG_DIR" "$GRPC_DIR"
umask 077

ZAKURA_PID=""
ZAINO_PID=""
CURRENT_STAGE="bootstrap"

cleanup() {
    local status=$?
    trap - EXIT
    set +e
    [[ -z "$ZAINO_PID" ]] || kill -TERM "$ZAINO_PID" 2>/dev/null || true
    [[ -z "$ZAKURA_PID" ]] || kill -TERM "$ZAKURA_PID" 2>/dev/null || true
    [[ -z "$ZAINO_PID" ]] || wait "$ZAINO_PID" 2>/dev/null || true
    [[ -z "$ZAKURA_PID" ]] || wait "$ZAKURA_PID" 2>/dev/null || true
    if (( status == 0 && KEEP_STATE == 0 )); then
        rm -rf -- "$WORK_DIR"
        printf '\n[CLEAN] removed %s\n' "$WORK_DIR"
    elif (( status == 0 )); then
        printf '\n[KEEP] preserved %s\n' "$WORK_DIR"
    else
        printf '\n[FAIL] stage=%s exit=%d; state/logs: %s\n' \
            "$CURRENT_STAGE" "$status" "$WORK_DIR" >&2
        [[ -f "$LOG_DIR/zakura.log" ]] && tail -40 "$LOG_DIR/zakura.log" >&2 || true
        [[ -f "$LOG_DIR/zainod.log" ]] && tail -60 "$LOG_DIR/zainod.log" >&2 || true
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
require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}
require_executable() {
    [[ -x "$1" ]] || die "required executable not found: $1"
}
run_logged() {
    local label=$1
    shift
    local output="$LOG_DIR/$label.log"
    printf '[RUN]'
    printf ' %q' "$@"
    printf '\n'
    "$@" >"$output" 2>&1 || {
        local code=$?
        printf '[FAIL] %s (exit %d); see %s\n' "$label" "$code" "$output" >&2
        tail -80 "$output" >&2 || true
        return "$code"
    }
    printf '[OK] %s\n' "$label"
}
run_devtool_logged() {
    local label=$1
    shift
    run_logged "$label" timeout 240 "$DEVTOOL_BIN" "$@"
}
wallet_sync_logged() {
    run_devtool_logged "$1" wallet --wallet-dir "$WALLET_DIR" sync \
        --server "$ZAINO_GRPC_ADDR" --connection direct
}
rpc_call() {
    local method=$1
    local params=$2
    local request
    request="$(jq -cn --arg method "$method" --argjson params "$params" \
        '{jsonrpc:"2.0",id:1,method:$method,params:$params}')"
    curl --silent --show-error --connect-timeout 2 --max-time 15 \
        -H 'content-type: application/json' --data-binary "$request" "$ZAKURA_RPC_URL"
}
rpc_generate() {
    local count=$1
    local response
    response="$(rpc_call generate "[$count]")" || die "Zakura generate RPC failed"
    printf '%s\n' "$response" >>"$LOG_DIR/zakura-rpc.log"
    jq -e --argjson expected "$count" \
        '.error == null and (.result | type == "array") and (.result | length == $expected)' \
        >/dev/null <<<"$response" || die "Zakura generate RPC returned an error"
}
zakura_tip_height() {
    local response
    response="$(rpc_call getblockchaininfo '[]')" || die "Zakura RPC failed"
    jq -e '.error == null and (.result.blocks | type == "number")' \
        >/dev/null <<<"$response" || die "invalid Zakura chain-info response"
    jq -r '.result.blocks' <<<"$response"
}
wait_for_zakura_rpc() {
    local attempt response
    for ((attempt = 1; attempt <= 90; attempt++)); do
        kill -0 "$ZAKURA_PID" 2>/dev/null || die "zakurad exited before RPC readiness"
        if response="$(rpc_call getblockchaininfo '[]' 2>/dev/null)" \
            && jq -e '.error == null and .result.chain == "test"' >/dev/null <<<"$response"; then
            printf '[PASS] Zakura JSON-RPC ready\n'
            return 0
        fi
        sleep 1
    done
    die "timed out waiting for Zakura RPC"
}
wait_for_zakura_tip() {
    local target=$1 attempt height
    for ((attempt = 1; attempt <= 120; attempt++)); do
        if height="$(zakura_tip_height 2>/dev/null)" && (( height == target )); then
            printf '[PASS] Zakura tip=%s\n' "$height"
            return 0
        fi
        sleep 1
    done
    die "timed out waiting for Zakura tip $target"
}
write_grpc_frame() {
    local payload_hex=$1 output=$2
    python3 - "$payload_hex" "$output" <<'PY'
import pathlib, struct, sys
payload = bytes.fromhex(sys.argv[1])
pathlib.Path(sys.argv[2]).write_bytes(b"\x00" + struct.pack(">I", len(payload)) + payload)
PY
}
grpc_call() {
    local method=$1 payload_hex=$2 label=$3
    local request="$GRPC_DIR/$label.request" headers="$GRPC_DIR/$label.headers"
    local body="$GRPC_DIR/$label.body" trace="$GRPC_DIR/$label.trace"
    write_grpc_frame "$payload_hex" "$request"
    : >"$headers"; : >"$body"; : >"$trace"
    curl --silent --show-error --http2-prior-knowledge --connect-timeout 2 --max-time 20 \
        --dump-header "$headers" --trace-ascii "$trace" \
        -H 'content-type: application/grpc' -H 'te: trailers' \
        -H 'grpc-encoding: identity' -H 'grpc-accept-encoding: identity' \
        --data-binary "@$request" --output "$body" \
        "$ZAINO_GRPC_URL/cash.z.wallet.sdk.rpc.CompactTxStreamer/$method" \
        >/dev/null 2>>"$trace" || return 1
    rg -a -qi 'grpc-status:[[:space:]]*0' "$headers" "$trace"
}
parse_latest_block_height() {
    local body=$1
    python3 - "$body" <<'PY'
import pathlib, struct, sys
data = pathlib.Path(sys.argv[1]).read_bytes()
def varint(buf, pos):
    value = 0
    shift = 0
    while pos < len(buf):
        byte = buf[pos]; pos += 1
        value |= (byte & 0x7f) << shift
        if byte < 0x80: return value, pos
        shift += 7
    raise ValueError("truncated varint")
offset = 0
while offset + 5 <= len(data):
    compressed = data[offset]; length = struct.unpack(">I", data[offset+1:offset+5])[0]
    offset += 5; payload = data[offset:offset+length]; offset += length
    if compressed != 0 or len(payload) != length: continue
    pos = 0
    while pos < len(payload):
        tag, pos = varint(payload, pos); field = tag >> 3; wire = tag & 7
        if wire == 0:
            value, pos = varint(payload, pos)
            if field == 1: print(value); raise SystemExit(0)
        elif wire == 1: pos += 8
        elif wire == 2:
            size, pos = varint(payload, pos); pos += size
        elif wire == 5: pos += 4
        else: raise ValueError("unsupported wire")
raise SystemExit(1)
PY
}
wait_for_grpc_ready() {
    local attempt
    for ((attempt = 1; attempt <= 120; attempt++)); do
        kill -0 "$ZAINO_PID" 2>/dev/null || die "zainod exited before gRPC readiness"
        if grpc_call GetLightdInfo '' readiness; then
            printf '[PASS] Zaino gRPC ready\n'
            return 0
        fi
        sleep 1
    done
    die "timed out waiting for Zaino gRPC"
}
wait_for_zaino_tip() {
    local target=$1 attempt height
    for ((attempt = 1; attempt <= 120; attempt++)); do
        if grpc_call GetLatestBlock '' latest-block \
            && height="$(parse_latest_block_height "$GRPC_DIR/latest-block.body" 2>/dev/null)" \
            && (( height >= target )); then
            printf '[PASS] Zaino indexed through %s\n' "$height"
            return 0
        fi
        sleep 1
    done
    die "timed out waiting for Zaino height $target"
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

status "Check prerequisites for Names v1 phase $TARGET_PHASE"
for command in curl jq python3 rg timeout cargo; do
    require_command "$command"
done
require_executable "$ZAKURA_BIN"
require_executable "$ZAINO_BIN"
require_executable "$DEVTOOL_BIN"

status "Build the Names v1 live entry point"
if ! (cd "$ROOT_DIR/zcash-devtool" && cargo build --offline --bin names-v1-live) \
    >"$LOG_DIR/names-v1-live-build.log" 2>&1; then
    tail -100 "$LOG_DIR/names-v1-live-build.log" >&2 || true
    die "could not build names-v1-live"
fi
require_executable "$NAMES_V1_LIVE_BIN"

status "Derive disposable Regtest addresses"
run_logged derive-address "$DEVTOOL_BIN" wallet derive-address \
    --mnemonic "$WALLET_MNEMONIC" --network regtest
MINER_UA="$(sed -n 's/^Unified Address: //p' "$LOG_DIR/derive-address.log")"
[[ -n "$MINER_UA" ]] || die "derive-address did not emit a miner address"
run_logged derive-sapling-discard-address "$DEVTOOL_BIN" wallet derive-address \
    --mnemonic "$SAPLING_DISCARD_MNEMONIC" --network regtest
SAPLING_DISCARD_ADDRESS="$(sed -n 's/^Transparent Address: //p' \
    "$LOG_DIR/derive-sapling-discard-address.log" | tail -1)"
[[ -n "$SAPLING_DISCARD_ADDRESS" ]] || die "derive-address did not emit discard address"

write_configs
status "Launch Zakura and Zaino"
RUST_LOG=info "$ZAKURA_BIN" --config "$ZAKURA_CONFIG" start \
    >"$LOG_DIR/zakura.log" 2>&1 &
ZAKURA_PID=$!
wait_for_zakura_rpc
ZAINOLOG_COLOR=0 RUST_LOG=info "$ZAINO_BIN" start --config "$ZAINO_CONFIG" \
    >"$LOG_DIR/zainod.log" 2>&1 &
ZAINO_PID=$!
wait_for_grpc_ready

status "Check Ironwood subtree-root serving"
grpc_call GetSubtreeRoots 1002 ironwood-subtree-roots \
    || die "GetSubtreeRoots(Ironwood) did not return grpc-status 0"

status "Initialize and fund the disposable wallet"
rpc_generate 1
wait_for_zaino_tip 1
if printf '%s\n' "$WALLET_MNEMONIC" | timeout 240 "$DEVTOOL_BIN" wallet \
    --wallet-dir "$WALLET_DIR" init --name names-v1-live \
    --identity "$IDENTITY_FILE" --network regtest --birthday 1 \
    --activation-heights "$ACTIVATION_FILE" --server "$ZAINO_GRPC_ADDR" \
    --connection direct >"$LOG_DIR/wallet-init.log" 2>&1; then
    printf '[OK] wallet initialized\n'
else
    status_code=$?
    tail -100 "$LOG_DIR/wallet-init.log" >&2 || true
    exit "$status_code"
fi
wallet_sync_logged wallet-bootstrap-sync
run_devtool_logged discard-bootstrap-sapling wallet \
    --wallet-dir "$WALLET_DIR" send --identity "$IDENTITY_FILE" \
    --address "$SAPLING_DISCARD_ADDRESS" --value 624985000 \
    --min-confirmations 1 --server "$ZAINO_GRPC_ADDR" --connection direct
rpc_generate 12
wait_for_zaino_tip 13
wallet_sync_logged wallet-funded-sync
run_devtool_logged wallet-funded-balance wallet \
    --wallet-dir "$WALLET_DIR" balance --json
FUNDED_BALANCE="$(rg -a '^[{]' "$LOG_DIR/wallet-funded-balance.log" | tail -1)"
jq -e '.ironwood_spendable > 0 and .sapling_spendable == 0' \
    >/dev/null <<<"$FUNDED_BALANCE" \
    || die "wallet did not expose spendable Ironwood funding: $FUNDED_BALANCE"
printf '[PASS] Ironwood funding=%s zatoshi\n' \
    "$(jq -r '.ironwood_spendable' <<<"$FUNDED_BALANCE")"

if (( TARGET_PHASE == 1 )); then
    printf '\n[PASS] Names v1 infrastructure qualification complete\n'
    exit 0
fi

export NAMES_V1_LIVE_MNEMONIC="$WALLET_MNEMONIC"
status "Names v1 COMMIT"
run_logged names-v1-commit timeout 900 "$NAMES_V1_LIVE_BIN" commit \
    --wallet-dir "$WALLET_DIR" --rpc-url "$ZAKURA_RPC_URL"
COMMIT_TXID="$(rg -a -o '^COMMIT_TXID=[0-9a-f]{64}$' \
    "$LOG_DIR/names-v1-commit.log" | tail -1 | cut -d= -f2)"
[[ -n "$COMMIT_TXID" ]] || die "v1 COMMIT did not emit a transaction id"
COMMIT_HEIGHT_EXPECTED=$(( $(zakura_tip_height) + 1 ))
rpc_generate 1
wait_for_zaino_tip "$COMMIT_HEIGHT_EXPECTED"
wallet_sync_logged names-v1-commit-sync

status "Names v1 REVEAL"
run_logged names-v1-target timeout 120 "$NAMES_V1_LIVE_BIN" target \
    --from-height "$COMMIT_HEIGHT_EXPECTED"
TARGET_REVEAL_HEIGHT="$(sed -n 's/^TARGET_REVEAL_HEIGHT=//p' \
    "$LOG_DIR/names-v1-target.log" | tail -1)"
[[ "$TARGET_REVEAL_HEIGHT" =~ ^[0-9]+$ ]] || die "v1 target height missing"
CURRENT_TIP="$(zakura_tip_height)"
PRE_REVEAL_TIP=$((TARGET_REVEAL_HEIGHT - 1))
(( PRE_REVEAL_TIP >= CURRENT_TIP )) || die "v1 target is behind current tip"
if (( PRE_REVEAL_TIP > CURRENT_TIP )); then
    rpc_generate "$((PRE_REVEAL_TIP - CURRENT_TIP))"
    wait_for_zaino_tip "$PRE_REVEAL_TIP"
fi
wallet_sync_logged names-v1-reveal-sync
run_logged names-v1-reveal timeout 1800 "$NAMES_V1_LIVE_BIN" reveal \
    --wallet-dir "$WALLET_DIR" --rpc-url "$ZAKURA_RPC_URL" \
    --commit-txid "$COMMIT_TXID"
REVEAL_TXID="$(rg -a -o '^REVEAL_TXID=[0-9a-f]{64}$' \
    "$LOG_DIR/names-v1-reveal.log" | tail -1 | cut -d= -f2)"
[[ -n "$REVEAL_TXID" ]] || die "v1 REVEAL did not emit a transaction id"
REVEAL_HEIGHT_EXPECTED=$((PRE_REVEAL_TIP + 1))
rpc_generate 1
wait_for_zaino_tip "$REVEAL_HEIGHT_EXPECTED"
wallet_sync_logged names-v1-reveal-mined-sync
run_logged names-v1-verify timeout 1200 "$NAMES_V1_LIVE_BIN" verify \
    --rpc-url "$ZAKURA_RPC_URL" --commit-txid "$COMMIT_TXID" \
    --reveal-txid "$REVEAL_TXID"
rg -a -q '^NAMES_FULL_REPLAY_STATUS=Active$' "$LOG_DIR/names-v1-verify.log" \
    || die "full replay did not accept the v1 REVEAL"
rg -a -q '^NAMES_FRESH_RESOLVER_STATUS=Active$' "$LOG_DIR/names-v1-verify.log" \
    || die "FreshResolver did not accept the v1 REVEAL"
rg -a -q '^NAMES_FULL_FRESH_MATCH=yes$' "$LOG_DIR/names-v1-verify.log" \
    || die "full replay and FreshResolver disagree after REVEAL"
status "Names v1 UPDATE"
UPDATE_HEIGHT_EXPECTED=$(( $(zakura_tip_height) + 1 ))
run_logged names-v1-update timeout 1800 "$NAMES_V1_LIVE_BIN" update \
    --wallet-dir "$WALLET_DIR" --rpc-url "$ZAKURA_RPC_URL" \
    --reveal-txid "$REVEAL_TXID"
UPDATE_TXID="$(rg -a -o '^UPDATE_TXID=[0-9a-f]{64}$' \
    "$LOG_DIR/names-v1-update.log" | tail -1 | cut -d= -f2)"
[[ -n "$UPDATE_TXID" ]] || die "v1 UPDATE did not emit a transaction id"
rpc_generate 1
wait_for_zaino_tip "$UPDATE_HEIGHT_EXPECTED"
wallet_sync_logged names-v1-update-sync
run_logged names-v1-verify-update timeout 1200 "$NAMES_V1_LIVE_BIN" verify-update \
    --rpc-url "$ZAKURA_RPC_URL" --reveal-txid "$REVEAL_TXID" \
    --update-txid "$UPDATE_TXID"
rg -a -q '^NAMES_FULL_FRESH_MATCH=yes$' "$LOG_DIR/names-v1-verify-update.log" \
    || die "full replay and FreshResolver disagree after UPDATE"

status "Reach the next v1 RENEW anchor"
wallet_sync_logged names-v1-renew-pre-sync
RENEW_TARGET_HEIGHT="$(timeout 120 "$NAMES_V1_LIVE_BIN" target \
    --from-height "$(($(zakura_tip_height) + 1))" \
    | sed -n 's/^TARGET_REVEAL_HEIGHT=//p' | tail -1)"
[[ "$RENEW_TARGET_HEIGHT" =~ ^[0-9]+$ ]] || die "v1 RENEW target height missing"
RENEW_BLOCKS=$((RENEW_TARGET_HEIGHT - 1 - $(zakura_tip_height)))
(( RENEW_BLOCKS >= 0 )) || die "v1 RENEW target is behind current tip"
if (( RENEW_BLOCKS > 0 )); then
    rpc_generate "$RENEW_BLOCKS"
    wait_for_zaino_tip "$((RENEW_TARGET_HEIGHT - 1))"
    wallet_sync_logged names-v1-renew-sync
fi

status "Names v1 RENEW"
run_logged names-v1-renew timeout 1800 "$NAMES_V1_LIVE_BIN" renew \
    --wallet-dir "$WALLET_DIR" --rpc-url "$ZAKURA_RPC_URL" \
    --reveal-txid "$REVEAL_TXID" --update-txid "$UPDATE_TXID"
RENEW_TXID="$(rg -a -o '^RENEW_TXID=[0-9a-f]{64}$' \
    "$LOG_DIR/names-v1-renew.log" | tail -1 | cut -d= -f2)"
[[ -n "$RENEW_TXID" ]] || die "v1 RENEW did not emit a transaction id"
rpc_generate 1
wait_for_zaino_tip "$RENEW_TARGET_HEIGHT"
wallet_sync_logged names-v1-renew-mined-sync
run_logged names-v1-verify-renew timeout 1200 "$NAMES_V1_LIVE_BIN" verify-renew \
    --rpc-url "$ZAKURA_RPC_URL" --reveal-txid "$REVEAL_TXID" \
    --update-txid "$UPDATE_TXID" --renew-txid "$RENEW_TXID"
rg -a -q '^NAMES_FULL_FRESH_MATCH=yes$' "$LOG_DIR/names-v1-verify-renew.log" \
    || die "full replay and FreshResolver disagree after RENEW"

status "Names v1 RELEASE"
RELEASE_HEIGHT_EXPECTED=$((RENEW_TARGET_HEIGHT + 1))
run_logged names-v1-release timeout 1800 "$NAMES_V1_LIVE_BIN" release \
    --wallet-dir "$WALLET_DIR" --rpc-url "$ZAKURA_RPC_URL" \
    --reveal-txid "$REVEAL_TXID" --update-txid "$UPDATE_TXID" \
    --renew-txid "$RENEW_TXID"
RELEASE_TXID="$(rg -a -o '^RELEASE_TXID=[0-9a-f]{64}$' \
    "$LOG_DIR/names-v1-release.log" | tail -1 | cut -d= -f2)"
[[ -n "$RELEASE_TXID" ]] || die "v1 RELEASE did not emit a transaction id"
rpc_generate 1
wait_for_zaino_tip "$RELEASE_HEIGHT_EXPECTED"
wallet_sync_logged names-v1-release-mined-sync
run_logged names-v1-verify-release timeout 1200 "$NAMES_V1_LIVE_BIN" verify-release \
    --rpc-url "$ZAKURA_RPC_URL" --reveal-txid "$REVEAL_TXID" \
    --update-txid "$UPDATE_TXID" --renew-txid "$RENEW_TXID" \
    --release-txid "$RELEASE_TXID"
rg -a -q '^NAMES_FULL_FRESH_MATCH=yes$' "$LOG_DIR/names-v1-verify-release.log" \
    || die "full replay and FreshResolver disagree after RELEASE"

status "Check the exact Released -> Expired boundary"
CLAIMABLE_HEIGHT="$(rg -a -o '^CLAIMABLE_HEIGHT=[0-9]+$' \
    "$LOG_DIR/names-v1-verify-release.log" | tail -1 | cut -d= -f2)"
[[ "$CLAIMABLE_HEIGHT" =~ ^[0-9]+$ ]] || die "claimability height missing"
LAST_BLOCKED_HEIGHT=$((CLAIMABLE_HEIGHT - 1))
BOUNDARY_BLOCKS=$((LAST_BLOCKED_HEIGHT - $(zakura_tip_height)))
(( BOUNDARY_BLOCKS >= 0 )) || die "claimability boundary is behind current tip"
if (( BOUNDARY_BLOCKS > 0 )); then
    rpc_generate "$BOUNDARY_BLOCKS"
    wait_for_zaino_tip "$LAST_BLOCKED_HEIGHT"
    wallet_sync_logged names-v1-boundary-released-sync
fi
run_logged names-v1-boundary-released timeout 1200 "$NAMES_V1_LIVE_BIN" \
    verify-release-boundary --rpc-url "$ZAKURA_RPC_URL" \
    --reveal-txid "$REVEAL_TXID" --update-txid "$UPDATE_TXID" \
    --renew-txid "$RENEW_TXID" --release-txid "$RELEASE_TXID" \
    --expected-status released
rg -a -q '^NAMES_FULL_REPLAY_STATUS=Released$' \
    "$LOG_DIR/names-v1-boundary-released.log" \
    || die "last blocked height was not Released"
rpc_generate 1
wait_for_zaino_tip "$CLAIMABLE_HEIGHT"
wallet_sync_logged names-v1-boundary-expired-sync
run_logged names-v1-boundary-expired timeout 1200 "$NAMES_V1_LIVE_BIN" \
    verify-release-boundary --rpc-url "$ZAKURA_RPC_URL" \
    --reveal-txid "$REVEAL_TXID" --update-txid "$UPDATE_TXID" \
    --renew-txid "$RENEW_TXID" --release-txid "$RELEASE_TXID" \
    --expected-status expired
rg -a -q '^NAMES_FULL_REPLAY_STATUS=Expired$' \
    "$LOG_DIR/names-v1-boundary-expired.log" \
    || die "claimability height was not Expired"

printf '\n[PASS] full Names v1 live qualification complete\n'
printf '[PASS] COMMIT=%s REVEAL=%s UPDATE=%s RENEW=%s RELEASE=%s\n' \
    "$COMMIT_TXID" "$REVEAL_TXID" "$UPDATE_TXID" "$RENEW_TXID" "$RELEASE_TXID"
