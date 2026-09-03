#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEVTOOL_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"

# Defaults to a 10,000-block recent sample from zec.rocks. Pass any estimator
# arguments after the script name; for example:
#   ./scripts/names-speed-mainnet.sh --sample-blocks 50000 > sample.json
exec cargo run --release --quiet \
  --manifest-path "$DEVTOOL_DIR/Cargo.toml" \
  --bin names-speed-sample -- "$@"
