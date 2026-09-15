# ADR 0004: Phase 0 toolchain and supply-chain receipt

- Status: accepted for the local Gate-2 build
- Date: 2026-08-31
- Authority: D2-052 and `BUILD_PLAN.md` sections 2.4 and 6 Phase 0

## Decision

The build uses Node 24.20.0 and pnpm 11.24.0 exactly. Direct product and development
dependencies are exact versions in `package.json`; workspace edges use only
`workspace:*`; `pnpm-lock.yaml` freezes the transitive graph. No permissive version
range is accepted. The host executable, lockfile and container-image digests are
recorded under `artifacts/provenance/`.

The Phase 0 dependency receipt consists of:

- `pnpm-lock.yaml` SHA-256, recorded as `lockfileSha256` in
  `artifacts/provenance/toolchain.json` and checked against the lockfile by
  `tests/phase0/documentation-closure.test.ts`;
- `artifacts/provenance/toolchain.json` for the exact local Node and pnpm build tools;
- `artifacts/provenance/container-images.json` for the three immutable image indexes;
- `artifacts/sbom/boardagent.cdx.json` for the normalized production CycloneDX graph;
- `artifacts/license-report/dependencies.json` and `docs/THIRD_PARTY_NOTICES.md` for
  dependency and hostile-harvest licensing.

The PostgreSQL runtime additionally installs Alpine `libuuid` `2.42.3-r1` from its exact
signed APK because the rolling v3.24 package index can temporarily expose an older
revision even while the fixed package remains available. `Dockerfile` maps BuildKit's
`TARGETARCH` to the exact `x86_64` or `aarch64` artifact, rejects every other
architecture, verifies the recorded SHA-256 and the Alpine package signature, and then
checks the installed version. The two artifact hashes and repository are part of
`artifacts/provenance/container-images.json`.

On 2026-08-31 the exact locked production graph returned no known vulnerabilities from
`pnpm audit --prod --audit-level high`. This is a dated build receipt, not a permanent
claim; every release run must scan again and the T9 threshold remains unresolved.

## Consequences

Changing Node, pnpm, a direct dependency, the lockfile, an image digest, or a
supplemental package URL/version/hash creates T0 drift and requires regenerated receipts
plus the affected protocol, database, browser, container and security nets. A green
Phase 0 check does not claim the image has cold started or that later release lanes have
passed.
