#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEVTOOL_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"

exec cargo run --release --quiet \
  --manifest-path "$DEVTOOL_DIR/Cargo.toml" \
  --bin names-speed-simulate -- "$@"
