# Testing and anti-drift

    corepack pnpm install --frozen-lockfile
    corepack pnpm supply-chain:generate                                   # SBOM and licence report under artifacts/, not committed
    git clone https://github.com/LegalQuants/LQGovernance-OpenBoard vendor/openboard
    git -C vendor/openboard checkout 1b38dbf2c1ea413fea0661c34c63cd0fd10dc4bb   # pinned prior-art reference, git-ignored
    corepack pnpm verify:phase0                                           # registry, format, lint, typecheck, phase-0
    corepack pnpm exec vitest run tests/unit --no-file-parallelism --maxWorkers=1
    tests/run_all.py            # the full regression net (all tiers in tests/NET.json)

Run the supply-chain step once after every install and before the unit suite: the
generated SBOM and licence report are git-ignored inputs that several unit tests read.
The `vendor/openboard` clone is the read-only prior-art reference that a phase-0 test
pins by commit and licence hash; it is never built, imported or shipped.

Run it before and after every change. Green before and green after means no drift.
Green before and red after means the change did something: fix it, or bring the diff to
the project owner. `tests/bless.py --yes`, run from the project owner's own terminal, is
the only way to accept a changed baseline.

## Tiers

`tests/NET.json` declares eleven deterministic tiers, T0 to T10. Each tier runs
`scripts/src/verify-release.ts` for one profile (`phase1`, `private-beta` or `release`)
with `--tier Tn`. T0 is the integrity tier (registry check, supply-chain check and the
phase-0 tests) and T1 is the static tier (formatting, lint and typecheck);
`corepack pnpm verify:phase0` runs the same checks in one command. Later tiers need a
PostgreSQL 18.6 test database (`compose.test.yaml`), the pinned browser and the released
MCP clients described below. T10 is the independent external review tier and cannot be
self-issued.

## Deterministic browser prerequisite

Install the Chromium revision pinned by the locked Playwright package before T6:

```sh
corepack pnpm exec playwright install chromium
```

CI or an isolated workstation may set `PLAYWRIGHT_BROWSERS_PATH` to an absolute cache
directory for both installation and verification. Release T6 requires that variable: the
test hashes the captured headless-shell executable and launches it to verify the browser
version in `artifacts/provenance/toolchain.json`. The tests never use the operator's
interactive system-browser profile.

## Released MCP client prerequisite

`corepack pnpm install --frozen-lockfile` installs exact test-only mcporter `0.13.7`
and OpenClaw `2026.7.1` packages. The lifecycle scripts of OpenClaw and of the test-only
transitive packages listed in `pnpm-workspace.yaml` are denied there.
`tests/protocol/released-client-matrix.spec.ts` invokes the published runtimes as
separate Node processes through a locally trusted HTTPS endpoint; neither package enters
the production image.

## How the net re-arms

The net re-arms by fingerprint, not just by code edits. `tests/NET.json` lists the source
globs that make up the fingerprint (TypeScript, SQL, JSON, Markdown, YAML and the
Dockerfile), so a documentation change re-arms it too.

| Piece                     | What it is                                                                                              |
| ------------------------- | ------------------------------------------------------------------------------------------------------- |
| `tests/NET.json`          | the net policy: tiers, thresholds, baselines (blessed only by the project owner) and fingerprint inputs |
| `tests/net_engine.py`     | the runner                                                                                              |
| `tests/run_all.py`        | the one command                                                                                         |
| `tests/bless.py`          | owner-only baseline acceptance (two-phase: diff, then `--yes`)                                          |
| `tests/.net-stamp.json`   | written only by a green run; compared to the live fingerprint (git-ignored)                             |
| `tests/.net-lastrun.json` | every run's results, which is what bless reads (git-ignored)                                            |
