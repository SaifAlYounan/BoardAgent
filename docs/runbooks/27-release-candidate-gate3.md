# 27 — Release candidate and Gate 3

**Owners:** the maintainer prepares; the independent reviewer challenges; the project owner decides.
**Purpose:** produce a truthful immutable handoff and prevent stale or partial evidence from
becoming a release claim.

1. Freeze the candidate source. Record `git diff`, status, source-tree hash, lockfile,
   registry, migration, ADR, docs/runbook, and toolchain fingerprints. No file changes are
   permitted after the verification start.
2. Preserve all 94 original SR rows, 63 original threats and AC-01..AC-22, and include
   the exact approved administrative amendment. The current combined register has 102 SR
   rows; each requires exact implementation and executing-test pointers. Required threat
   and acceptance mappings must resolve to actual runnable proof. SR102 additionally
   requires actual human first-account activation and recovery proof; synthetic
   authenticators cannot close it. External professional security review is T10,
   a separate requirement; neither proof substitutes for the other.
3. Run the release orchestrator once on the unchanged tree. Private beta requires T0–T9;
   public production requires T0–T10. Zero skipped, quarantined, unresolved, stale, or
   silently substituted lanes.
4. Build application/PostgreSQL/Caddy images bound to that source hash; run SBOM/license and
   high/critical vulnerability/secret/misconfiguration scans with fresh scanner data.
5. Verify cold start from empty volumes, browser/MCP role journeys, confirmation attacks,
   load envelope, worker/crash paths, logical/physical backup, PITR preparation, isolated
   restore, and signed restore receipt.
6. Assemble the Gate-3 manifest: frozen Gate 1/2 records, source/image/toolchain digests,
   tier receipts, evidence ledger, outcome-vs-plan comparison, limitations, unresolved
   findings, operator docs, rollback/recovery plan, and release label. A full orchestrator
   run writes `gate3-manifest.json`, `evidence-ledger.json`, `outcome-comparison.md`, and
   `HANDOFF.md` beside `result.json`; verify every recorded hash before presentation.
7. Independent T10 reviewer records scope, method, findings, retests, independence, and
   signed receipt. The maintainer cannot self-issue this evidence.
8. Present the exact pack to the project owner. Only their explicit Gate-3 approval authorizes the
   release decision; it does not implicitly authorize deployment, push, data sharing, or a
   broader label.

Any source/doc change after step 1 invalidates downstream receipts and requires a fresh run.
Without T10, the maximum truthful label is beta. Without signed Gate 3, the build is not
go-live approved.

T10 artifact validation uses `boardagent.independent-security-review.v2` in
`artifacts/review/independent-security-review.json`. The old digest-only v1 format is
rejected. Preserve the actual security report and deployment-specific legal review under
`artifacts/review/`; preserve the project owner's decision authorizing independent review under
`artifacts/verification/`. Both directories are created at release time and are not
committed. Paths are project-relative, without symlinks or traversal.
Reports are nonempty regular files of at most 16 MiB; metadata and the owner decision are
at most 256 KiB. The evidence directories remain under trusted operator custody.

The v2 metadata contains: reviewedGitCommit, sourceTreeSha256, reviewerOrganization,
reviewerName, completedAt, reportPath/reportSha256, unresolvedCritical (zero),
unresolvedHigh (zero), mediumDisposition, deploymentLegalReviewPath and its Sha256,
and gate3DecisionPath/gate3DecisionSha256. The last two hash field names are exactly
`deploymentLegalReviewSha256` and `gate3DecisionSha256`. All SHA-256 values hash original
file bytes. Do not edit a reviewed report to make it pass. If the candidate changes,
obtain a new exact-candidate decision and review.

The checker reads the files, validates strict JSON without duplicate keys, checks the
report/legal/decision digests, binds commit and source to both the review and the owner decision,
and checks that approval preceded the review. It requires a clean committed candidate
and unchanged Git/source state during the check. The handover builder repeats artifact
validation and includes all four files in its digest ledger. A declared passed T10 tier
alone is insufficient. Unit fixtures live only in disposable synthetic directories.

These checks establish integrity and candidate binding. They do not authenticate a human
reviewer, establish independence, interpret a legal opinion, or turn a report into the
project owner's approval. The independent reviewer and the project owner must verify those
substantive matters; the maintainer must never manufacture their positive evidence.
