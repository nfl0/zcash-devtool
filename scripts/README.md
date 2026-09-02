# Replacement Names live qualification

`live-qualification.sh` launches a disposable local Zakura/Zaino stack and
uses the reusable replacement Names wallet APIs.

```sh
./scripts/live-qualification.sh --phase 1
./scripts/live-qualification.sh --phase 2 --keep-state
```

Phase 1 checks JSON-RPC/gRPC readiness, Ironwood subtree-root serving, wallet
initialization, and spendable Ironwood funding. Phase 2 selects the next
feasible name-specific daily window, mines a zero-value generic-route COMMIT,
creates an exact one-ZEC wallet bond, builds and mines a real hidden-authority
REVEAL, resolves it, advances to the first later-epoch window, reconstructs
and spends the hidden managed bond in a real REFRESH, and resolves the renewed
head through Core-authenticated exact replay. Name-route full-transaction
acquisition is enabled only in scheduled windows; compact Ironwood effects
remain visible across the complete authenticated range.

All node state, wallet data, and logs are disposable and live below
`/tmp/coppice-names-live.*`. Successful state is removed unless `--keep-state`
is supplied; failed runs retain their logs and databases for diagnosis.
