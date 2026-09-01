# Names v1 live qualification

`live-qualification.sh` is a disposable local-regtest harness for the current
Names protocol. It launches the pinned Zakura/Zaino stack, funds a wallet with
Ironwood value, and then drives the canonical lifecycle through the
`names-v1-live` binary. The Zakura-backed run on 2026-08-30 completed
`COMMIT -> REVEAL -> UPDATE -> RENEW -> RELEASE` and both exact
`Released -> Expired` boundary checks; its preserved logs are recorded in
`coppice-names/docs/QUALIFICATION.md`.

```sh
./scripts/live-qualification.sh --phase 1
./scripts/live-qualification.sh --phase 2 --keep-state
```

Phase 1 checks JSON-RPC/gRPC readiness, Ironwood subtree-root serving, wallet
initialization, and spendable Ironwood funding. Phase 2 additionally mines and
verifies `COMMIT -> REVEAL -> UPDATE -> RENEW -> RELEASE`, including replay /
FreshResolver parity and the exact `Released -> Expired` claimability edge.
The current protocol accepts a REVEAL declaration strictly after COMMIT and
through the inclusive COMMIT TTL even when canonical inclusion is later, and a
RENEW declaration inside the predecessor renewal window when inclusion is
before predecessor lease expiry. Operation expiry must cover these windows;
exact name-derived scheduling is not a validity rule. FreshResolver discovery
uses bounded block-window probing.

All node state, wallet data, and logs are disposable and live below
`/tmp/coppice-names-v1-live.*`. The script does not perform release artifact
generation or performance qualification; those deterministic values are
checked and frozen by `coppice-names`.
