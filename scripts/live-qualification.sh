#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

# Phase 1 qualifies the local Zakura -> Zaino -> zcash-devtool plumbing; Phase 2
# extends that same stack with the live Coppice lifecycle and shallow reorg.
# Every node, database, wallet, and log is disposable and lives below one
# run-specific directory under /tmp.

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
ROOT_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd -P)"
BIN_DIR="$ROOT_DIR/bin"
ZAKURA_BIN="$BIN_DIR/zakurad"
ZAINO_BIN="$BIN_DIR/zainod"
DEVTOOL_BIN="$BIN_DIR/zcash-devtool"

ZAKURA_RPC_ADDR="127.0.0.1:18232"
ZAKURA_RPC_URL="http://$ZAKURA_RPC_ADDR"
ZAKURA_P2P_ADDR="127.0.0.1:18233"
ZAINO_GRPC_ADDR="127.0.0.1:8137"
ZAINO_GRPC_URL="http://$ZAINO_GRPC_ADDR"

COPPICE_NAME_ONE="phase2-alpha"
COPPICE_NAME_TWO="phase2-beta"
COPPICE_BOND_VALUE=100000000

# Disposable BIP-39 zero-entropy test mnemonic (23 x "abandon" + "art").
# Never use it for funds outside this local Regtest.
WALLET_MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

WORK_DIR="$(mktemp -d /tmp/coppice-live-qualification.XXXXXX)"
CONFIG_DIR="$WORK_DIR/config"
STATE_DIR="$WORK_DIR/state"
ZAKURA_STATE_DIR="$STATE_DIR/zakura"
ZAINO_STATE_DIR="$STATE_DIR/zaino"
WALLET_DIR="$STATE_DIR/wallet"
LOG_DIR="$WORK_DIR/logs"
GRPC_DIR="$LOG_DIR/grpc"
ZAKURA_CONFIG="$CONFIG_DIR/zakura.toml"
ZAINO_CONFIG="$CONFIG_DIR/zaino.toml"
ACTIVATION_FILE="$CONFIG_DIR/activation-heights.toml"
IDENTITY_FILE="$WALLET_DIR/identity.txt"

mkdir -p "$CONFIG_DIR" "$ZAKURA_STATE_DIR" "$ZAINO_STATE_DIR" "$WALLET_DIR" "$LOG_DIR" "$GRPC_DIR"
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

    if (( status == 0 )); then
        rm -rf -- "$WORK_DIR"
        printf '\n[CLEAN] removed %s\n' "$WORK_DIR"
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

wallet_sync_logged() {
    local label=$1

    run_devtool_logged "$label" wallet \
        --wallet-dir "$WALLET_DIR" sync \
        --server "$ZAINO_GRPC_ADDR" --connection direct
}

wallet_status_logged() {
    local label=$1

    run_devtool_logged "$label" wallet \
        --wallet-dir "$WALLET_DIR" coppice status
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

assert_snapshot_status() {
    local name=$1
    local expected_status=$2
    local expected_height=$3

    jq -e \
        --arg name "$name" \
        --arg expected "$expected_status" \
        --argjson height "$expected_height" \
        '
        def record:
          [.current.state.names[] | select(.[0] == $name)]
          | if length == 1 then .[0][1] else null end;
        (record) as $record
        | .format_version == 1
          and .current.height == $height
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
        "$WALLET_DIR/coppice-v1.json" >/dev/null \
        || die "Coppice snapshot does not show $name=$expected_status at height $expected_height"
    printf '[PASS] canonical Coppice snapshot: %s=%s at height %s\n' \
        "$name" "$expected_status" "$expected_height"
}

assert_resolved_address() {
    local label=$1
    local name=$2
    local expected=$3
    local output="$LOG_DIR/$label.log"
    local actual

    run_devtool_logged "$label" wallet \
        --wallet-dir "$WALLET_DIR" coppice resolve "$name"
    actual="$(tail -1 "$output" | tr -d '\r')"
    [[ "$actual" == "$expected" ]] \
        || die "resolve($name) returned $actual, expected $expected"
    printf '[PASS] resolve(%s)=%s\n' "$name" "$actual"
}

assert_resolve_inactive() {
    local label=$1
    local name=$2
    local output="$LOG_DIR/$label.log"

    run_devtool_expect_failure "$label" wallet \
        --wallet-dir "$WALLET_DIR" coppice resolve "$name"
    [[ -s "$output" ]] || die "inactive resolve($name) produced no diagnostic"
    printf '[PASS] resolve(%s) is unavailable/inactive\n' "$name"
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
should_backup_non_finalized_state = false
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
ephemeral_finalised_state = true
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

status "Check Phase 1 prerequisites"
for command in curl jq python3 rg timeout; do
    require_command "$command"
done
require_executable "$ZAKURA_BIN"
require_executable "$ZAINO_BIN"
require_executable "$DEVTOOL_BIN"
printf '[INFO] binaries: %s, %s, %s\n' "$ZAKURA_BIN" "$ZAINO_BIN" "$DEVTOOL_BIN"
printf '[INFO] disposable run directory: %s\n' "$WORK_DIR"

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
printf '[OK] derived unified miner address (%s characters)\n' "$(printf '%s' "$MINER_UA" | wc -c)"
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

status "Mine and index post-NU6.3 Ironwood funding blocks"
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
printf '[PASS] wallet reports ironwood_spendable=%s zatoshi\n' \
    "$(jq -r '.ironwood_spendable' <<<"$FUNDED_BALANCE")"

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

printf '\n[PASS] Phase 2 Coppice qualification complete\n'
printf '[PASS] lifecycle evidence: %s COMMIT/REVEAL/UPDATE/RELEASE, %s second COMMIT/REVEAL/Break Bond\n' \
    "$COPPICE_NAME_ONE" "$COPPICE_NAME_TWO"
printf '[PASS] restart recovery: Zaino and fresh wallet processes reused persisted state\n'
printf '[PASS] shallow reorg: invalidated h=%s (%s), replacement h=%s (%s); post-reorg %s=Active and %s=Released\n' \
    "$REORG_OLD_HEIGHT" "$REORG_OLD_HASH" "$REORG_OLD_HEIGHT" "$REORG_NEW_HASH" \
    "$COPPICE_NAME_TWO" "$COPPICE_NAME_ONE"
printf '[PASS] deep reorg tests were not run\n'
