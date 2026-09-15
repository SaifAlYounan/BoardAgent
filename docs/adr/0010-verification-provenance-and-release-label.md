# ADR 0010: Verification, provenance, and release label

- Status: accepted at Gate 2
- Date: 2026-08-28
- Authority: D2-001, D2-002, D2-055 through D2-057, D2-061

## Context

BoardAgent handles high-consequence governance records. A release label based on builder
confidence, a stale test run, skipped infrastructure, or unreviewed upstream code would
overstate what the system proves.

## Decision

- The maximum pre-independent-review label is jurisdiction-neutral **private hardened
  beta**. BoardAgent makes no QES, notary, comprehension, legal-effect, or certification
  claim (D2-001).
- The product is a standalone strict-ESM pnpm monorepo with exact Node 24.20.0, TypeScript
  7.0.2, pnpm/lock and direct dependency pins (D2-002).
- All deterministic security behavior is code-graded: complete registered requirements,
  attacks, acceptance, exhaustive authorization, tally properties, critical coverage/
  mutation thresholds, zero skips/quarantine, and no LLM judge tier (D2-055).
- CI/release verification includes integrity/format/lint/types, unit/property, real
  PostgreSQL, migrations, browser/OAuth, modern+legacy clients, jobs/crash, load, attacks,
  acceptance, registry closure, SBOM/license, vulnerability, and container checks (D2-056).
  Browser evidence binds the exact Playwright runner, revision, browser version and
  executable SHA-256; client evidence binds exact package versions and registry
  integrities. Both are recorded in `artifacts/provenance/toolchain.json`.
- A full candidate run snapshots the source digest, Git status and exact commit before and
  after every tier. Its Gate 3 pack includes the build log and rejects a mismatched commit,
  dirty or moving worktree, stale image scan, altered frozen surface count, unsupported
  receipt label/schema, unbound registry, toolchain or lockfile, empty test summaries, or
  incomplete mutation evidence. A blocked pack makes the verifier exit unsuccessfully even
  when the underlying tier commands passed.
- OpenBoard is a read-only exact-commit hostile-review source with MIT attribution; vendor
  is excluded from build/image and no file is taken as-is (D2-057).
- Independent security review is mandatory before public production, while deployment-
  specific legal review owns charter/retention/privacy/evidence wording. Gate 2 does not
  authorize contacting a reviewer, deploying, sharing data, or making public claims
  (D2-061).

## Consequences and rejected alternatives

Verification is slow and release evidence invalidates on any source change. Private beta
cannot be marketed as a certification, and the builder cannot self-issue T10. The design
rejects floating toolchains, unit-only CI, tuned-after-the-fact thresholds, skipped lanes,
LLM-score gates, moving upstream imports, and treating tests as legal/security assurance.

Any threshold, tier, provider, toolchain, upstream pin, independent-review requirement, or
release-label change requires the project owner's approval and a corresponding regression
net update. A failing net is fixed or presented honestly; it is never blessed by the
builder.
