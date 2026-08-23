# Local Coppice qualification

These scripts build and exercise the local Zakura → patched Zaino →
`zcash-devtool` stack.

## Repository layout

Run the commands from the Coppice workspace root. The scripts expect:

```text
Coppice/
├── zakura/
├── zaino/              # patched fork, not upstream Zaino
├── zcash-devtool/
├── coppice/
└── bin/                # created by build.sh
```

The required Zaino fork is:

```text
https://github.com/nfl0/zaino.git
```

Use the fork's `dev` branch (or another branch containing the Ironwood
`GetSubtreeRoots` plumbing). Upstream `https://github.com/zingolabs/zaino.git`
is currently missing the Coppice-required feature and must not be substituted.

If cloning from scratch:

```sh
git clone https://github.com/nfl0/zaino.git zaino
git -C zaino checkout dev
```

Verify the checkout before building:

```sh
git -C zaino remote -v
git -C zaino log -1 --oneline
```

## Build the binaries

From the workspace root:

```sh
./zcash-devtool/scripts/build.sh
```

This creates or refreshes:

```text
bin/zakurad
bin/zainod
bin/zcash-devtool
```

The build uses locked release builds and enables `regtest_support` for
`zcash-devtool`. It also checks that each binary starts and responds to its
version/help command.

## Run the live qualification

After a successful build:

```sh
./zcash-devtool/scripts/live-qualification.sh
```

For a shorter targeted run, stop after a requested phase:

```sh
./zcash-devtool/scripts/live-qualification.sh --phase 1
./zcash-devtool/scripts/live-qualification.sh --phase 2
```

When iterating on Phase 5, preserve the Phase 4 checkpoint once, then resume
only Phase 5 on later runs:

```sh
./zcash-devtool/scripts/live-qualification.sh --phase 4 --keep-state
./zcash-devtool/scripts/live-qualification.sh \
  --resume /tmp/coppice-live-qualification.XXXXXX --phase 5
```

The first command prints the actual run directory and the exact resume command.
The default invocation still runs all five phases. Phase 5 cannot be resumed
from a Phase 1–3 checkpoint because its adversarial fixture depends on the
canonical two-account state produced by Phase 4.

The harness creates an isolated disposable Regtest stack and runs:

- Phase 1: Ironwood `GetSubtreeRoots`, wallet sync, and an ordinary Ironwood
  receive/spend.
- Phase 2: Coppice COMMIT, REVEAL, `coppice complete`, UPDATE, RELEASE, second
  registration, Break Bond, restart recovery, and a same-height shallow reorg.
- Phase 3: fresh same-seed wallet initialization from Coppice activation,
  canonical replay, bond-lock reconstruction, protected ordinary-send rejection,
  and fresh-wallet Break Bond.
- Phase 4: same-seed multi-account registration and lock isolation, persisted
  restart recovery, and fresh two-account recovery.
- Phase 5: adversarial wallet/PCZT spend-path rejection under Enabled and
  GuardOnly, exact-owner Break Bond, Off-mode lock cleanup, foreign-lock
  preservation, and an unsynchronized ordinary Off-mode send.

On success, temporary state and logs are removed. On failure, the run directory
under `/tmp/coppice-live-qualification.*` is preserved and printed so the
Zakura, Zaino, wallet, and gRPC logs can be inspected.

The harness uses loopback ports `18232`/`18233` for Zakura and `8137` for Zaino.
Stop any conflicting local services before running it.
