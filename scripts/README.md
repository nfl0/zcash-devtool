# Names v2 live qualification

`live-qualification.sh` is a disposable local-regtest harness for the current
Names protocol. It launches the pinned Zakura/Zaino stack, funds a wallet with
Ironwood value, and then drives the canonical lifecycle through the
`names-v2-live` binary.

```sh
./scripts/live-qualification.sh --phase 1
./scripts/live-qualification.sh --phase 2 --keep-state
```

Phase 1 checks JSON-RPC/gRPC readiness, Ironwood subtree-root serving, wallet
initialization, and spendable Ironwood funding. Phase 2 additionally mines and
verifies `COMMIT -> REVEAL -> UPDATE -> RENEW -> RELEASE`, including replay /
FreshResolver parity and the exact `Released -> Expired` claimability edge.

All node state, wallet data, and logs are disposable and live below
`/tmp/coppice-names-v2-live.*`. The script does not perform release artifact
generation or performance qualification.
