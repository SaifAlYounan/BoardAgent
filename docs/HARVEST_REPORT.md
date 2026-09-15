# OpenBoard hostile-harvest report

Status: Phase 0 provenance decision record, reviewed 2026-08-30. The "Phase 1" and later
work named in the table rows has since been implemented; the current proof for each area
is in the [verification register](VERIFICATION.md).

BoardAgent is not an OpenBoard fork. OpenBoard is an untrusted, read-only design and
test reference. No upstream package is a runtime, build, migration, image, or release
dependency of BoardAgent.

## Frozen source and license

- Repository: <https://github.com/LegalQuants/LQGovernance-OpenBoard>
- Frozen upstream commit: `1b38dbf2c1ea413fea0661c34c63cd0fd10dc4bb`
- Reference checkout: `vendor/openboard/`
- Upstream license: MIT, canonical bytes at `vendor/openboard/LICENSE`
- License size: 1,088 bytes
- License SHA-256:
  `8f8175ef116b82fbd057625d0751517802643de57254e4fb737b4f1e91e06521`
- Original copyright notice:
  `Copyright (c) 2026 Alexios Kirillov`

The pin and license digest are executed by
`tests/phase0/frozen-authority.test.ts`. The vendor directory is ignored by Git at the
BoardAgent boundary, excluded from the Docker context, absent from the workspace list,
and not imported by product source. `docs/THIRD_PARTY_NOTICES.md` preserves the notice
and exact license text.

## Verdict vocabulary and merge rule

- **Adapted** means BoardAgent retained a bounded concept, failure case, or test idea,
  but re-derived the implementation for the frozen BoardAgent model.
- **Rewritten** means the upstream area informed hostile review, while BoardAgent uses a
  new contract and implementation. It is not a representation that upstream code is
  safe.
- **Rejected** means no implementation, dependency, schema, protocol, or data path from
  that area may enter BoardAgent v1.
- **Taken as-is** means byte/substantial-expression reuse without a security rewrite.
  The count for this verdict is **zero**.

Every adapted file must carry a source header naming the repository, frozen commit,
upstream path or area, original copyright, MIT license notice, and the material hostile
changes. A test derived from an upstream edge case follows the same rule. A rewritten
file that retains no copyrightable upstream expression may use a short provenance note,
but must still be traceable to this report. Any later reuse or a different upstream pin
requires a new hostile review, an updated notice and a recorded decision; it cannot inherit
one of the verdicts below.

## Candidate-by-candidate hostile verdicts

| Candidate                                                 | Frozen upstream reference                                                                                                                      | Verdict                                                                  | Hostile finding and BoardAgent disposition                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Current product/evidence pointer                                                                                                                                                                                                                                                                                                        |
| --------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Boot migration mechanism                                  | `lib/db/src/migrate.ts`, `lib/db/migrations/**`, `artifacts/api-server/src/lib/migrations.integration.test.ts`                                 | **Adapted**                                                              | The same-session PostgreSQL advisory-lock pattern is useful. The upstream ledger does not prove immutable checksums, contiguous history, downgrade/unknown-version refusal, bounded lock acquisition, separated migration authority, or partial-failure behavior. BoardAgent therefore uses a checksummed, monotonic, transactional migrator and must prove edited/reordered/concurrent/up-down-up cases against PostgreSQL.                                                                                       | `lib/db/src/migrate.ts` has the required origin header; initial filename/checksum tests are in `tests/phase0/migrations.test.ts`. Real PostgreSQL concurrency/up-down-up proof remains a Phase-1 exit, so this row does not claim it has passed.                                                                                        |
| Drizzle governance schema                                 | `lib/db/src/schema/**`, `lib/db/migrations/0000_baseline.sql` through `0009_governance_semantics.sql`                                          | **Rewritten**                                                            | OpenBoard's tables are browser-era aggregates and do not encode BoardAgent's immutable decision packages, live exclusions, one-use consent, permanent Q&A, feed/tombstone lineage, onboarding, MRTR state, or no-purge boundary. Importing them wholesale would preserve unsafe authority and mutation semantics. BoardAgent re-derives tables, constraints, composite references, RLS, and immutable triggers from the Gate-2 data/transaction appendix.                                                          | `lib/db/src/schema.ts` and `lib/db/migrations/0001_baseline.sql` are early product schema work. Full RLS, immutability, grouped migrations, and real-database proof remain Phase 1.                                                                                                                                                     |
| Weighted tally and quorum                                 | `artifacts/api-server/src/lib/voteTally.ts`, `voteClose.ts`, `voteTally.test.ts`, vote integration tests                                       | **Adapted**                                                              | Preserve weighted arithmetic and the edge case that observers, management, ineligible seats, and recused seats do not enter eligible totals. Upstream can accept ballots outside the supplied eligible set and mixes ballot-snapshot and live-membership weights. BoardAgent freezes an electorate, uses exact `bigint` rational arithmetic, defines abstention/denominator/tie behavior once, rejects duplicate or ineligible principals, and makes this one oracle serve cast checks, display, and close.        | `lib/domain/src/voting.ts`, `lib/domain/src/value-objects.ts`, and `tests/unit/voting.test.ts`. The current property test is initial coverage; the frozen >=100,000-run, exhaustive-small-case, and mutation thresholds remain mandatory. Provenance headers must be present before this implementation is considered harvest-complete. |
| Proxy voting                                              | `lib/db/src/schema/voteProxies.ts`, proxy branches in `artifacts/api-server/src/routes/votes.ts`, related vote tests                           | **Adapted**                                                              | Retain per-vote grants, ballot attribution to the principal, caster stamping, and an explicit principal-supersession rule. Reject upstream admin-driven grant/revoke and any path without the principal or holder's fresh server-attested confirmation. Proxy authority, electorate eligibility, revocation, expiry, replacement, and races must be checked inside the same locked transaction as the act.                                                                                                         | `lib/domain/src/voting.ts` currently contains the pure supersession rule. Persistent proxy grants, confirmed grant/revoke/cast transactions, certificate coverage, race proof, and attributed acceptance scenarios are not yet complete. Provenance headers are required on the eventual adapted files/tests.                           |
| Vote certificates                                         | `artifacts/api-server/src/lib/voteClose.ts`, `artifacts/api-server/src/routes/votesCertificateV3.integration.test.ts`, server signing helpers  | **Rewritten**                                                            | Upstream certificate v3 is already an Ed25519-signed artifact; it is not merely a hash of persisted data. Its shape and verification trust model do not bind BoardAgent consent, canonical decision package, statement, principal/caster, ruleset/electorate, or a trusted historical evidence-key record. BoardAgent separates payload recomputation from signature verification and never accepts a self-asserted public key.                                                                                    | `lib/audit/src/certificate.ts`, `lib/audit/src/checkpoint.ts`, and `tests/unit/audit.test.ts` establish the new payload/trusted-key primitive. Persisted-truth recomputation, privacy-safe public verification, historical-key lookup, and offline acceptance proof remain Phase 3/5 work.                                              |
| Tamper-evident audit trail                                | `artifacts/api-server/src/lib/auditLog.ts`, `auditVerify.test.ts`, audit fail-closed/keyed/route integration tests, `scripts/verify-audit.mjs` | **Rewritten**                                                            | The upstream trail is an HMAC-keyed chain derived from a server secret, not the BoardAgent independent SHA-256 event-chain contract. A row-local chain alone cannot detect tail truncation and does not prove serialized append, key separation/rotation, exported head, or external checkpoint trust. BoardAgent binds a domain tag, sequence, previous hash, canonical event body, and own hash; signed Ed25519 checkpoints commit expected count/head.                                                          | `lib/audit/src/event.ts`, `lib/audit/src/checkpoint.ts`, and `tests/unit/audit.test.ts` cover mutation, reorder, truncation against an expected head, and wrong trusted key. Transactional serialization, checkpoint scheduling, export, first-break CLI, crash and database-tamper acceptance tests remain mandatory.                  |
| Per-document ACL and conflict recusal                     | `artifacts/api-server/src/lib/access.ts`, `lib/db/src/schema/accessControl.ts`, document/vote/graph authorization tests                        | **Rewritten**                                                            | Upstream evaluates some privileged allows before an explicit deny, so an admin-style allow can bypass recusal. BoardAgent is deny-first and must apply one SQL-first visibility predicate before direct read, list, search rank/snippet, count, facet, pagination, cursor, resource resolution, feed, export, and fetch audit. A hidden object is indistinguishable from absence.                                                                                                                                  | `lib/authz/src/authorize.ts` and `tests/unit/authz.test.ts` contain the initial deny-wins policy primitive. Generated SQL/RLS parity, pool-context isolation, and recusal-invisibility across every read surface are not yet complete.                                                                                                  |
| Soft delete, retention snapshots, legal hold, and export  | `artifacts/api-server/src/lib/retention.ts`, deleted-record/legal-hold schemas and routes, system export route                                 | **Rejected** for deletion/purge; **rewritten** for visibility and export | Upstream can hard-delete after a partial snapshot and therefore cannot be the BoardAgent evidence-retention model. BoardAgent v1 retains governance records indefinitely, exposes no physical purge callable, and represents removal only as permanent visibility state plus complete lineage/tombstone. Export is a repeatable, authorization-checked snapshot with an audited asynchronous artifact lifecycle, not an admin shortcut around policy.                                                              | The no-purge/no-browser-era dependency boundary is asserted by `tests/phase0/non-goals.test.ts`. Full visibility/tombstone/export implementation and authorization proof remain Phase 1/4. No upstream retention code is copied.                                                                                                        |
| Vote, meeting, task, and minutes state transitions        | vote/deadline/close routes and tests; `lib/db/src/schema/{votes,meetings,tasks,minutes}.ts`                                                    | **Rewritten**                                                            | Useful terminal/deadline cases exist upstream, but route-local checks can occur before transaction entry and the model does not cover BoardAgent package replacement, revote, transcript annex, redline disposition, action activation/evidence closure, re-sign, or linked correction cycles. BoardAgent uses explicit pure transition tables and re-locks/revalidates inside every mutation transaction. Cancel, supersede, correct, and hide are distinct; terminal data is never silently mutated or reopened. | `lib/domain/src/state-machines.ts` and `tests/unit/state-machines.test.ts` cover the initial vote/meeting/task/minutes tables. Decision-package, minutes/action, correction, race, and database-trigger proof remain Phase 1/4.                                                                                                         |
| Object authorization and Zod-at-every-boundary discipline | `artifacts/api-server/src/lib/governanceSchemas.ts`, generated `lib/api-zod/**`, route authorization tests                                     | **Rewritten**                                                            | Upstream uses stripping schemas in places, which can silently discard attacker-controlled unknown fields, and its route checks are not a single closed surface/authority registry. BoardAgent requires strict input and output schemas, explicit bounded free text, structured errors, a logged/audited trust-boundary rejection where required, exact scope plus object policy, and generated registry closure.                                                                                                   | `lib/contracts/src/schemas.ts`, `lib/contracts/src/content.ts`, `lib/authz/src/authorize.ts`, and their unit tests are initial primitives. Full registry closure (148 tools, 16 resources and 7 prompts at the time of review) and exhaustive actor/context matrix are separate Phase-0/2 evidence.                                     |
| Proposal approval queue                                   | approval-workflow schemas/routes and manual-governance/approval-loop tests                                                                     | **Adapted**                                                              | Retain only the human-in-the-loop proposition that member/management input remains a proposal until an authorized secretariat disposition. Reject server-generated AI proposals, hidden execution, mutable queue payloads, or approval that bypasses the ordinary confirmed service. BoardAgent stores immutable canonical proposal versions and executes no proposal merely because it was submitted.                                                                                                             | The complete proposal queue and confirmed approval transactions are Phase-4 work; no OpenBoard queue code has entered the product at this review point. Eventual adapted files/tests require provenance headers.                                                                                                                        |
| VPS Compose/Caddy deployment topology                     | `Dockerfile`, `docker-compose.yml`, `Caddyfile`, `docker-entrypoint.sh`, `DEPLOY.md`                                                           | **Adapted** as a topology; implementation **rewritten**                  | Reuse the operational idea of one image, PostgreSQL, and optional Caddy HTTPS. Reject browser assets, OpenBoard environment/auth assumptions, unsafe default credentials, entrypoint mutation ambiguity, and any vendor source in the build context. BoardAgent pins its own Node/PostgreSQL images, runs nonroot, separates server/worker/migrator roles, validates secrets, and documents backup/restore.                                                                                                        | `Dockerfile`, `compose.yaml`, `Caddyfile`, `.dockerignore`, and `tests/phase0/container-skeleton.test.ts` are the Phase-0 skeleton. Cold start, health, least privilege, digest/provenance, backup/restore, and VPS acceptance remain Phase 4/5.                                                                                        |

## Explicitly rejected shell and feature areas

The following are not harvest candidates. They remain reference-only even if an
upstream implementation appears convenient:

| Upstream area                                                                                                                               | Verdict      | Reason                                                                                                                                                                                                      |
| ------------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `artifacts/easyboard/**`, React/Vite pages, dashboard/graph/browser client                                                                  | **Rejected** | BoardAgent has no governance portal, SPA, dashboard, or server-selected presentation. Only minimal security-critical OAuth/enrollment/onboarding browser surfaces are allowed.                              |
| Express/browser API shell, Socket.IO/realtime modules, generated React API client                                                           | **Rejected** | BoardAgent exposes one native Node Streamable HTTP MCP resource with an exact modern profile and bounded legacy read lane; no realtime/browser dual shell.                                                  |
| Cookie/session/JWT-in-cookie authentication, CSRF assumptions, password reset, email login, browser account management as designed upstream | **Rejected** | BoardAgent authenticates precreated people through passkey-first OAuth or exact prelinked OIDC, uses resource-bound tokens, and has no email recovery or browser governance account manager.                |
| `ai.ts`, `aiProvider.ts`, `aiSchemas.ts`, `aiUsage` and proposal-generation logic                                                           | **Rejected** | The deterministic server makes zero model calls and accepts no model/provider key. Intelligence, classification, drafting, extraction, chunks, embeddings, and summaries remain with each person's agent.   |
| `extractText.ts`, extracted-PDF/Office processing and persisted extraction paths                                                            | **Rejected** | BoardAgent accepts only canonical machine-readable Markdown, UTF-8 text, and versioned strict JSON. PPTX, PDF, DOCX, images, scans, archives, and conversion/extraction are refused even as evidence in v1. |
| `mailer.ts`, password/email flows and SMTP notification routes                                                                              | **Rejected** | All governance communication is recorded through MCP. Optional webhooks are contentless wake signals only; SMTP is absent.                                                                                  |
| Upstream per-user Ed25519/passphrase minutes signing and signing-key management                                                             | **Rejected** | BoardAgent uses the one server-attested confirmation coordinator over an immutable minutes package. It does not require client-held signing keys and does not claim QES.                                    |
| OpenBoard demo seeds, system reset, public portal routes, render.com deployment and social assets                                           | **Rejected** | They add browser/demo/destructive/hosting surfaces outside the frozen registry and evidence boundary.                                                                                                       |

## Attribution and isolation controls

The required header for a source file containing adapted upstream expression is:

```text
Portions adapted from LQGovernance-OpenBoard
https://github.com/LegalQuants/LQGovernance-OpenBoard
commit 1b38dbf2c1ea413fea0661c34c63cd0fd10dc4bb; upstream path: <path>
Copyright (c) 2026 Alexios Kirillov
MIT License; see docs/THIRD_PARTY_NOTICES.md
BoardAgent hostile changes: <material changes>
```

For comment-capable files this text belongs in the leading block comment. SQL and shell
files use their native comment prefix. A derived test names the upstream test/failure
case and states which expectation BoardAgent changed. These notices are additive to the
BoardAgent repository license and are never removed by formatting or code generation.

The following controls keep OpenBoard reference-only:

1. `vendor/openboard/` is the only approved upstream reference location and its commit
   and license digest are pinned by an executing test.
2. `.gitignore` excludes the reference clone from BoardAgent source history; the frozen
   provenance and license notice live in this repository instead.
3. `.dockerignore` excludes it from every image context. `pnpm-workspace.yaml` has no
   vendor workspace, and product manifests declare no OpenBoard package.
4. TypeScript/package/release inputs must not include or import the vendor path. A later
   build-closure check must fail if that boundary drifts.
5. The reference checkout is never executed, migrated, installed, tested as product,
   bundled, published, or contacted at runtime. Upstream movement is irrelevant until a
   separately approved repin.

## Review conclusion

Across the candidate table, **5 rows retain an adapted pattern**, **7 require rewritten
or mixed treatment**, and deletion/purge is rejected; the separate shell table rejects
**8 feature areas**. Categories overlap where a topology or visibility concept is kept
but its implementation is rewritten. The count of **taken as-is is 0**. OpenBoard
contributes bounded concepts and hostile test cases only. The existing migration adapter
is attributed; other current or future
files that implement an adapted candidate must receive the required provenance header
before the corresponding harvest row can be reported as fully merged. Passing this
document does not substitute for the Phase-1 through Phase-5 implementation and attack
evidence named in each row.
