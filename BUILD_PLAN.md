# BUILD_PLAN — BoardAgent (frozen at Gate 2, 2026-08-28)

> Completeness test: a competent builder not present for discovery must be able to build
> Phase 1 safely from this file plus the four normative Gate-2 appendices named below.
> Gate 2 was approved exactly on 2026-08-28. This file is the executable frozen plan.

Approval record: `planning/gate2/GATE2-APPROVAL-RECORD.md`  
Gate-2 manifest SHA-256: `a548ac62f8f135e5dcaf7e1d36ece2922c36cad425c733f5d52cbb6c05e6242b`

Normative appendices at freeze (under `planning/gate2/gate2/`):

- `GATE2-DECISIONS.md`
- `SURFACE-AUTHORITY-EVENT-MATRIX.md`
- `DATA-STATE-TRANSACTIONS.md`
- `VERIFICATION-AND-RELEASE-NET.md`

Gate-1 authority: `G1-01` through `G1-47`, approved without corrections; frozen digest
`d87baff752cbd95b5cdcda9c8bc5aa8cbb03ab49e8622b17a64dcfdb1e77d998`.

## 1. Context and requirements

### 1.1 Business goal

Build a standalone, self-hosted, MCP-native board governance system named BoardAgent.
People do not operate a governance portal: their chosen agent authenticates them, reads
their entitled canonical records, maintains optional local intelligence, presents the
information as they prefer, and invokes deterministic BoardAgent tools. BoardAgent is
the system of record/evidence, while intelligence and judgment remain at the edge.

### 1.2 Feasibility verdict

**Feasible as a hardened private beta with constraints.** The design can provide strong
server-attested canonical consent, object authorization, immutable governance lineage,
tamper-evident evidence, independently verifiable certificates and a feasible daily
agent experience. It cannot prove human comprehension, safe client rendering, legal
effect, qualified electronic signature, notarization or external time-of-existence.
Public production additionally requires independent security and deployment-specific
legal review.

### 1.3 Must do

- Current remote MCP read/action/prompt/resource server plus bounded legacy read-only
  compatibility for practical agent portability.
- Secure person identity, silent ordinary reconnection, passkey-first builtin OAuth and
  exact prelinked OIDC/UAE Pass federation.
- Role/scope/object/board/ACL/live-recusal authorization with observer denial, exact
  own-security self-service and only six enumerated governance/workflow exceptions.
- Strict agent-native canonical content, cited governance profiles/rulesets, one weighted
  tally/quorum/proxy kernel and immutable vote decision packages.
- Fresh server-attested confirmation for each binding action, hash-chained audit,
  independently recomputable vote certificates and permanent evidence retention.
- MCP-native management submissions, questions/answers, secretariat workflows, meetings,
  transcripts as text annexes, minutes redlines/signatures, evidence-closed action items,
  tasks, proposals, notices, exports, backup and operator CLIs.
- One-call member briefing and snapshot/delta resources suitable for client-side chunks,
  embeddings, summaries and memory under the member/agent's responsibility.
- One Linux VPS deployment profile: server, worker, PostgreSQL and optional Caddy HTTPS
  through Compose; one immutable image; no mandatory paid service.

### 1.4 Must not do

- No web governance portal/SPA/dashboard; browser only for OAuth, enrollment, passkey,
  TOTP/OIDC and onboarding attestation.
- No server AI/model/embedding/vector/OCR/conversion/extraction or content-check API in
  v1; no dormant provider implementation/config/secret/egress.
- No PPTX/PDF/DOCX/image/scan/archive even as evidence. No DOCX tracked-change input.
- No email/SMTP governance communications. BoardAgent sends no invite; secretary hands a
  one-use QR/link through a separately trusted method or uses prelinked identity.
- No raw database query tool, multi-tenancy, SCIM, A2A, blockchain anchoring, offline
  queued voting, standing act token, client-side signing requirement or physical purge
  of system-of-record material.
- No claim of reading/comprehension, QES, legal validity, notarization or guaranteed
  delivery to a human.

### 1.5 Translation table

| Sponsor statement/outcome | Implied constraint | Frozen design decision |
|---|---|---|
| “Agents only infra” | information/presentation must be protocol data, not UI | D2-003–005, D2-028–029, D2-045 |
| Any agent should connect | no brand authority; current protocol plus bounded compatibility | D2-003–004, D2-008 |
| Secure but not an obstacle course | one-time strong enrollment, then silent rotation | D2-011–017 |
| How does it know the right guy? | invitation possession is insufficient identity proof | D2-013–017 |
| Configure charter/majority/quorum | constitutional settings are cited/versioned data | D2-030–032 |
| No server AI | no provider/runtime inference; client drafts and classifies | D2-001, D2-025, D2-027 |
| Refuse bad documents | canonical MD/TXT/strict JSON only, zero durable rejected bytes | D2-023–025 |
| Management talks to secretary inside system | immutable MCP submission/revision thread, no SMTP | D2-026 |
| Future API checking gate | inert interface/schema namespace only; new lifecycle to activate | D2-027 |
| Role onboarding/contact/responsibility | role terms, support version and attestation gate | D2-028–029 |
| Edge agent may chunk/query | metadata/delta sync, content separately fetched/audited | D2-045 |
| Unlimited retention | permanent system record; visibility-only delete | D2-049 |
| Members/observers ask management | exact ask/follow-up exceptions, permanent Q&A | D2-062 |
| Vote is based on Q&A | exact turn cutoffs/hashes in decision package | D2-063 |
| Management may amend | immutable version; linked vote blocked pending disposition | D2-064 |
| Changed open package requires revote | old vote superseded; new empty vote; no carried act | D2-034, D2-064 |
| Prior voter must be told | persistent per-person `revote_required` delta | D2-066 |
| Transcript may annex minutes | edge transcription only, loud verification state | D2-065 |
| Minutes action items need evidence closure | secretary logs structured manifest; owner evidence; confirmed closure | D2-067 |
| Members/observers redline and sign | strict JSON anchored redlines; server-attested final signatures | D2-068–069 |
| Redline is not DOCX | local rendering free; submitted payload strict/no binary/fuzzy match | D2-068 |
| Minutes/task corrections must preserve history | nonfinal package versioning; finalized/completed correction starts linked terminal-safe cycle | D2-040, D2-059, D2-067–069 |

## 2. Design

### 2.1 Delegation and accountability map

| Owner | Owns | Why / reversibility / stakes |
|---|---|---|
| BoardAgent server | canonical schemas, policy, state machines, hashes, evidence, deterministic evaluation, exact delivery/confirmation records | high-stakes and centrally testable; append-only correction, not silent reversal |
| Person's agent | explanation, local rendering, drafting, local chunks/embeddings/summaries/memory, optional local DOCX/deck | subjective/vendor-specific and reversible at the edge; never authoritative until strict canonical submission |
| Board member/observer | judgment, review duty, preferred presentation, agent/local-copy security, exact confirmations | cannot be delegated to server; accepted in versioned onboarding terms |
| Secretary/team | seat/invite creation, identity proof confirmation, support contact, charter/profile encoding, notice/minutes/action completeness, dispositions and binding administration | accountable procedural actor; high-stakes actions require fresh confirmation/audit |
| Management | canonical submissions/revisions, assigned Q&A and task evidence | content owner; immutable versions and due-state make accountability visible |
| Deployment admin/operator | VPS/TLS/Postgres, keys/secrets, backups/restores/upgrades, incident response | infrastructure authority; separate from ordinary governance scopes/CLIs |
| External IdP/UAE Pass | authenticate an exact external subject | replaceable identity input only; never BoardAgent authorization/token authority |
| OpenBoard prior art | hostile-reviewed concepts/test cases only | pinned untrusted reference; no runtime/build dependency |

### 2.2 Architecture pattern and deciding factors

Pattern: **hexagonal deterministic governance kernel around PostgreSQL, exposed through a
generated MCP/HTTP registry, with asynchronous typed outbox workers and intelligence at
the client edge.**

| Factor | Decision impact |
|---|---|
| Evidentiary stakes | Deciding factor: exact versioned packages, consent and audit must commit transactionally from one authoritative database. |
| Reversibility | Client presentation/intelligence stays reversible; governance records use linked versions/supersessions instead of edit/delete. |
| Security boundary | Central generated policy plus FORCE RLS and composite FKs; no handler/client metadata may invent authority. |
| Interoperability | Current sessionless MCP/MRTR is primary; one registry generates a strict legacy read lane rather than duplicating logic. |
| Operational feasibility | One VPS/Compose/Postgres/image, no proprietary queue/search/AI service; explicit backup/restore and performance envelope. |

Credible alternative rejected: a portal/API monolith with server AI and converted Office
documents. It would make ingestion/UI convenient but reintroduce untrusted parsers,
provider egress, server interpretation, dual read/action shells and proof ambiguity. A
serverless/Vercel profile is also rejected because long-running worker, PostgreSQL
transaction/locks, stable secret/key custody and backup boundaries are central.

### 2.3 Repository and package layout

After Gate 2, create a new Git repository for BoardAgent (this repository's root)
with no remote unless separately requested. It is a standalone repository.

```text
BoardAgent/
  artifacts/server/        native Node HTTP + MCP server + OAuth interactions + worker entry
  lib/contracts/           strict Zod schemas; generated tool/resource/prompt/event registry
  lib/domain/              pure tally, quorum, proxy, state machines, package/action rules
  lib/db/                  Drizzle schema, SQL migrations, RLS, transaction repositories/jobs
  lib/audit/               canonical event chain, checkpoints, certificates, offline formats
  lib/authz/               scopes, roles, object policies, SQL visibility predicates
  lib/ruleset/             typed profile/ruleset validation and pure evaluation
  lib/config/              strict startup configuration and secret/key adapters
  scripts/                 bootstrap, migrate/check, export, verify, backup/restore-check
  tests/                   unit/property/integration/protocol/browser/attacks/acceptance/ops
  docs/                    required product/security/deploy/verification/ADR/runbooks
  vendor/openboard/        pinned read-only reference; ignored from build/image/package
  Dockerfile
  compose.yaml
  Caddyfile
  pnpm-workspace.yaml
  package.json
  pnpm-lock.yaml
  tsconfig.base.json
  .env.example
  LICENSE
  BUILD_LOG.md
  BUILD_PLAN.md             frozen copy of this plan plus approved appendices/digests
```

One direction of dependency only:

`contracts ← domain/ruleset/audit primitives ← authz/db adapters ← server/scripts`.

`domain`, ruleset evaluation and canonical/hash primitives import no DB, HTTP, MCP,
OAuth, filesystem, clock, random, network or model package. Effects enter through typed
ports. `artifacts/server` is composition, never a second business-logic implementation.

### 2.4 Toolchain and direct pins

- Node `24.20.0`, pnpm `11.24.0`, TypeScript `7.0.2`, strict ESM.
- MCP modular packages `@modelcontextprotocol/{server,client,core,node}` `2.0.0`.
- Zod `4.4.3`, Vitest `4.1.11`, fast-check `4.9.0`, canonicalize `4.0.0`.
- PostgreSQL `18.6`, `pg` `8.23.0`, `@types/pg` `8.20.0`, Drizzle ORM `0.45.2`,
  Drizzle Kit `0.31.10`.
- `oidc-provider` `9.11.4`, `jose` `6.2.10`, `openid-client` `6.8.7`,
  `@simplewebauthn/server` `13.3.3`.
- Native `node:http`, Web Crypto/crypto, Fetch and HTML templates; no general SPA or
  application framework required. Other build/lint/scan tools are exact-lockfile pins
  selected in Phase 0 and recorded in ADR/dependency receipts before source imports.
- PostgreSQL and base container images are digest-pinned in the release lock; Node release
  binary/image provenance and SHA-256 are recorded.

Lockfile integrity, licenses, known vulnerabilities, engine constraints and transitive
packages are checked before Phase 1. No permissive range (`^`, `~`, `latest`) appears in
published manifests.

### 2.5 Deterministic rule ownership (“iron rules”)

| Rule | Sole planned owner | Mandatory proof |
|---|---|---|
| canonical text/JSON/hash | `lib/contracts/src/canonical.ts` | official vectors, duplicate/Unicode/number adversarial tests |
| UUIDv7/time/rational/weight types | `lib/domain/src/value-objects.ts` | RFC bits/order/cap/overflow properties |
| vote tally/quorum/proxy | `lib/domain/src/voting.ts` | exhaustive small cases, ≥100k properties, mutants |
| vote/meeting/minutes/task states | `lib/domain/src/state-machines.ts` | transition table and terminal mutation tests |
| decision-package replacement | `lib/domain/src/decision-package.ts` | old/new/no-carry/revote property + race integration |
| minutes review/action/sign package | `lib/domain/src/minutes.ts` | strict lineage/action/evidence/re-sign properties |
| ruleset evaluation | `lib/ruleset/src/evaluate.ts` | match/priority/specificity/missing/ambiguous properties |
| authorization decision | `lib/authz/src/authorize.ts` and generated SQL predicates | exhaustive surface × actor matrix, RLS parity/differential tests |
| strict surface schemas | `lib/contracts/src/registry.ts` generated artifacts | registry closure/drift/unknown-field tests |
| consent verification | `lib/domain/src/consent.ts` + `lib/db/src/transactions/confirm.ts` | MRTR and crash/race/replay suite |
| audit event bytes/hash | `lib/audit/src/event.ts` | independent canonical verifier vectors |
| certificate payload/recompute | `lib/audit/src/certificate.ts` | offline + persisted-truth + tamper suite |
| feed/cursor/tombstones | `lib/domain/src/feed.ts` + DB query | one-call/delta/revocation/cursor properties |

No route, worker or CLI may reimplement one of these rules. CI performs forbidden-import,
duplicate-symbol and mutation-consumer checks.

### 2.6 Protocol and request path

1. Caddy terminates HTTPS and forwards through exactly configured trusted proxy hops.
2. Native Node HTTP validates Host, origin, method, headers and size before routing.
3. One sessionless `POST /mcp` endpoint explicitly pins `2026-07-28`: exact protocol/
   method/name headers must match protocol/capability metadata and every result declares
   `resultType`. The `2025-11-25` profile on that same resource lists reads/resources/
   prompts only; H tools are omitted/refused before stage and the SDK shim is disabled.
4. Path-aware protected-resource metadata lives at
   `/.well-known/oauth-protected-resource/mcp`. OAuth middleware verifies BoardAgent
   issuer/signature/JTI/lifetime, byte-identical normalized `/mcp` resource/audience,
   typed protocol client ID and scopes; it establishes transaction-local policy context.
5. Registry validates strict input, rate/idempotency class and policy, then invokes one
   application service. Output is strict-validated before return.
6. Reads use SQL-first RLS visibility and append required fetch evidence. Mutations use
   the exact transactions in `DATA-STATE-TRANSACTIONS.md`.
7. Binding MCP calls require form-elicitation capability before persistence, bind the
   exact original method/arguments and protected response state, and return embedded
   MRTR `input_required`. Only a new request ID with the exact call/state/form responses,
   `accept`, `approve=true` and code enters confirmation. Frozen mismatch/capability/
   version errors are `-32020/-32021/-32022`; incapable/legacy clients stage nothing.

### 2.7 Security posture

- External client/document/OIDC/CIMD/webhook input is untrusted. It is parsed only through
  strict bounded schemas; text is inert and never becomes prompt/rule/code/HTML.
- Browser interactions have no remote scripts/assets, render escaped server text, rotate
  sessions and enforce CSP/frame/referrer/HSTS/secure-cookie protections.
- Server, worker, migrator and backup roles are distinct. Production secrets are
  purpose-separated files/KMS refs and never exported/logged.
- Audit and protected reads fail closed. Ed25519 evidence checkpoints are separate from
  OAuth ES256 tokens. Historical public keys and compromise timestamps persist.
- Operational output uses allowlisted fields and pseudonyms. Webhooks contain only wake
  class/random ID/time and never content.
- Unlimited system-record retention is explicit; deployment privacy/legal review must
  address that consequence. No hidden erasure promise is made.

### 2.8 Decision log

`GATE2-DECISIONS.md` D2-001 through D2-069 is the complete dated decision log, including
credible alternatives and reversal costs. Builders do not re-decide these. A genuine
blocker becomes a new sponsor card and amended Gate 2, never a silent code choice.

## 3. Eval set and thresholds

### 3.1 Stage-B design evidence

Disposable evaluation workspace: `/private/tmp/boardagent-stage-b`.

- strict Node 24/TypeScript typecheck passes;
- Vitest `171/171` passes across 20 files;
- includes 25,000 seeded tally properties, real modular-SDK current HTTP/MRTR exchanges,
  strict OAuth/resource/client/document/onboarding/feed/submission/Q&A/package/transcript/
  minutes-action/redline models;
- current MCP/OAuth/toolchain/VPS/UAE Pass/OpenClaw primary-source research recorded;
- OpenBoard upstream `main` verified/pinned at
  `1b38dbf2c1ea413fea0661c34c63cd0fd10dc4bb` and GitHub identifies MIT.

Still unverified: real PostgreSQL RLS/migrations/races/load, browser authenticator/TOTP,
live IdP, released independent clients over HTTPS, job/crash, Compose/VPS, backup/restore
and attacks against product code. These are mandatory phase exits, not deferred polish.

### 3.2 Product regression net

The immutable thresholds, 94 preassigned SRs, 63 attack lanes and 22 acceptance
scenarios are in `VERIFICATION-AND-RELEASE-NET.md`. Gate-2 approval freezes them. Product
`tests/NET.json` mirrors the registry and may gain tests/requirements but may not weaken,
delete, skip or reduce a threshold without sponsor amendment.

Golden fixtures are hand-authored and include canonical bytes/hashes, OAuth metadata,
MCP wire exchanges, tally/proxy electorates, rule profiles, document rejections,
recusal-invisibility corpora, consent packages, replacement votes/notices, minutes
redlines/action evidence/signatures, audit chains/certificates and backup manifests.
Generated production output never blesses its own golden.

## 4. SLA and operating objectives

| Promise | Frozen number | Trace |
|---|---:|---|
| supported organization/boards/seats | 1 / 25 / 1,000 | D2-018, D2-054 |
| concurrent MCP requests | 100 | D2-054 |
| document versions/audit/feed rows | 100k / 1m / 1m | D2-054 |
| canonical document maximum | 10 MiB/version | D2-023, D2-054 |
| warm list/get p95 | ≤500 ms | D2-054 |
| entitled search/briefing p95 | ≤1.5 s | D2-054 |
| consent server p95, excluding person/client wait | ≤750 ms | D2-054 |
| audit append p95 | ≤250 ms | D2-054 |
| access token | 15 min | D2-011 |
| refresh idle/absolute | 30/90 days | D2-011 |
| invite / activation code / stage | 24 h / 10 min / 10 min | D2-013, D2-038 |
| checkpoint | ≤1,000 events or ≤15 min | D2-041 |
| export artifact | 24 h | D2-048 |
| system-of-record retention | indefinite | D2-049 |
| RPO / RTO | ≤15 min / ≤4 h | D2-050 |
| restore drill | quarterly full clean-room | D2-050 |

These are hardened-beta objectives, not an HA/SLA contract. Exceeding the capacity
envelope triggers a measured scale ADR. It does not authorize silent replicas/sharding.

## 5. Governance table

| Signal | Trigger | Required action | Owner/evidence |
|---|---|---|---|
| any required tier red/unavailable/skipped | current run | stop release; fix or present exact diff/blocker | builder; verification receipt |
| security requirement lacks code+test pointer | any registry check | claim remains false; implement/prove | builder; `docs/VERIFICATION.md` |
| surface/event/schema drift | generated registry differs | refuse build until decision/registry/tests align | architect/sponsor if new authority |
| migration/schema decision drift | table depends on changed decision | stop before migration; Gate-2 amendment | architect/sponsor |
| protocol/SDK/Node/IdP dependency change | fingerprint/version advisory | run full protocol/auth/client net; ADR | maintainer/security owner |
| charter/profile/ruleset change | every activation | cited validation, fresh confirmation, audit, replay eval | board admin/secretary |
| key near expiry/compromise/checkpoint overdue | configured alert | rotation/incident runbook; no evidence fabrication | operator |
| audit/certificate/feed/backup inconsistency | any verify/reconcile | fail readiness, preserve evidence, investigate; never auto-repair | operator/security owner |
| no full green release run in 30 days | periodic | run deterministic net and sample one flow | maintainer |
| no clean restore in 90 days | periodic | execute full isolated restore drill | operator |
| public production requested | before real public deployment | independent security + deployment legal review | sponsor/operator |

## 6. Build phases

Builder rules for every phase:

- Preserve frozen files/digests and append `BUILD_LOG.md` after each verified work unit.
- Test fails first for every behavioral/security requirement; then implementation; then
  focused and full required net.
- Never weaken thresholds/baselines or mark unavailable as pass.
- Do not add a callable/event/config/dependency/egress route outside the frozen registry.
- No external write, remote, deployment or real-person communication without separate
  authority. Local nested-repository commits are allowed; push is not implied.

### Phase 0 — provenance, threat model and reproducible skeleton

**Entry:** approved Gate-2 manifest/digest and exact approval record.

Work:

1. Create standalone `BoardAgent` nested Git repository, MIT license, root contracts,
   pinned toolchain manifests/lockfile and exact directory layout.
2. Clone OpenBoard commit `1b38dbf2c1ea413fea0661c34c63cd0fd10dc4bb`
   read-only into `vendor/openboard`; record exact license bytes/digest; exclude vendor from
   TypeScript, package, Docker context/SBOM except attribution report.
3. Produce `docs/HARVEST_REPORT.md`, with every candidate `adapted`, `rewritten` or
   `rejected`; no `taken as-is` without an amended hostile review.
4. Produce `docs/THREAT_MODEL.md` mapping TH-01..TH-63 to actor/assets/control/test/
   residual risk. Include auth pages, content, onboarding, Q&A, redlines/action closure,
   protocol downgrade and permanent-retention consequences.
5. Generate machine-readable callable/event/schema/state/SR registry and `tests/NET.json`
   from approved matrices; add closure/drift CI.
6. Scaffold packages with public interfaces and forbidden dependency checks. Add native
   structured logger/config loader and local dev keyring only after tests.
7. Add reproducible nonroot multi-stage image skeleton, PostgreSQL 18.6 Compose service
   and optional Caddy profile, but no claim of cold-start completion.

**Exit:** T0/T1 green; lock/SBOM/license report; frozen registry exact; threat/harvest docs
complete; product contains no runtime AI/converter/SMTP/SPA dependency; vendor license
captured; `BUILD_LOG.md` evidence entry.

### Phase 1 — deterministic kernel, schema and database safety

**Entry:** Phase-0 exit green and a real local PostgreSQL 18.6 service available.

Implementation order:

1. `lib/contracts`: canonical text/JSON/hash, UUIDv7, strict error envelope, all value and
   surface schemas (including machine-readable redline/action manifests).
2. `lib/domain`: approval rules, one BigInt tally/quorum/proxy oracle, decision-package
   composition/supersession, all state machines, feed delta rules and minutes/action/
   signature package composition.
3. `lib/ruleset`: profile/ruleset schemas, priority/specificity/fail-closed evaluation and
   persisted replay format.
4. `lib/db` migrations in dependency groups: platform/keys → identity/onboarding/auth →
   documents/ACL/search → governance/rules → meetings/minutes/tasks → submissions/Q&A →
   votes/consent/certificates → audit/feed/jobs/exports → RLS/immutability/indexes.
5. Same-session advisory-lock migrator with checksum/order/unknown/downgrade refusal;
   separate migrator/server/worker roles.
6. RLS policy functions generated from authz predicates, connection-pool transaction
   context, composite FKs, immutable triggers and no-purge privileges.
7. `lib/audit`: canonical event registry/hash chain, serialized append, checkpoint bundle,
   certificate payload/recomputation and offline formats.
8. Transaction repositories in the exact lock/order/boundaries of
   `DATA-STATE-TRANSACTIONS.md`; begin with audit append, document contribution/fetch,
   Q&A, matter evaluation, stage/reject/confirm, vote replacement/recusal/close, minutes
   publish/review/withdraw/disposition/correction/action/sign/finalized-correction and
   completed-task correction cycles.

Required failing-first proof:

- official/independent canonical vectors and malformed Unicode/number/duplicate cases;
- exhaustive small + ≥100k seeded tally/proxy/rule properties and critical mutants;
- every state transition/terminal/correction path;
- migration up/down/up, concurrent boot, edited/reordered/downgrade refusal;
- RLS full role/board/ACL/recusal matrix and pool-context bleed;
- transaction races/crash points for cast/recusal/replacement/close, Q&A answer,
  redline/signature and action-evidence closure;
- audit first-break/reorder/truncate/checkpoint and certificate persisted-recompute cases.

**Exit:** T0–T5 kernel/database subset green; all Phase-1 SR code/test pointers resolved;
zero skipped DB lane; performance microbenchmarks meet target at seeded envelope;
`BUILD_LOG.md` entry.

### Phase 2 — identity, OAuth, MCP read surface and onboarding

**Entry:** Phase-1 green.

Work:

1. Native HTTP security shell and one exact sessionless `POST /mcp` current/legacy-profile
   adapter over the generated registry, with frozen header/body/result/errors and no shim.
2. `oidc-provider` PostgreSQL adapter/config, ES256 token/JTI/refresh rotation, exact
   path-aware RFC 9728/RFC 8707 `/mcp` binding, typed CIMD/preregistered/DCR protocol IDs,
   rate-limited DCR, revocation and client controls.
3. Builtin invite/QR/passkey/pending-activation/secretary-code flow, multiple credentials,
   explicit TOTP fallback and minimal hardened browser pages.
4. Generic OIDC and UAE Pass exact-subject linking; unknown subject rejection.
5. Role-specific onboarding/support/attestation and scope gating.
6. Resources, document list/read/search/hash, board/vote/meeting/minutes/action/Q&A reads,
   snapshot/delta/pending actions, two-phase fetch evidence and contentless webhook wake.
7. One full generated authorization matrix across every read and all actors/context.

**Exit:** T0–T6 through real browser/virtual authenticator and real MCP clients; recusal
invisibility on every surface; seamless reconnect/reuse handling; AC-02/05/08/10/11/12/
18 read/identity portions green; `BUILD_LOG.md` entry.

### Phase 3 — consent, votes, proxies, rules and certificates

**Entry:** Phase-2 green and every act-capable test client supports MRTR.

Work:

1. One-use exact MRTR stage/input-required/retry/confirmation coordinator for all `H`
   MCP acts, including capability-before-stage and byte-identical retry-state proof.
2. Governance-profile/ruleset administration and guided `set-vote` flow with citations,
   override reason and final confirmation.
3. Decision packages, vote open/notices, ballots/statements, proxies/precedence, live
   recusal, source-update pending/exclusion, full replacement/new vote and persistent
   revote notifications.
4. Closing/certificate signing recovery state; authenticated/public/offline verification.
5. Apply same confirmation coordinator to minutes signatures/profile changes and other
   implemented binding acts; no alternate confirmation code path.

**Exit:** T0–T8 consent/vote subset green; every rejection/race/crash path; no legacy act;
AC-01/03/04/06/09/15/20 green; exact SR pointers; `BUILD_LOG.md` entry.

### Phase 4 — complete operations, minutes and deployment

**Entry:** Phase-3 green.

Work:

1. Full management submission/revision queue, proposals and secretariat requests.
2. Permanent management questions/answers/follow-up/due states and decision links.
3. Meetings/agendas/attendance/transcript annex/challenges/Q&A links.
4. Minutes unpublished drafting → published review → withdrawal/disposition → signature
   freeze, strict comments/redlines, nonfinal and linked-finalized correction cycles,
   stale-draft-action supersession, exact activation manifests, owner evidence, linked
   completed-task correction, member/observer signatures and re-sign lifecycle.
5. Generic tasks/proposals, all remaining guided flows/prompts/drafts and notices.
6. Typed worker/jobs, webhook SSRF controls, feed reconciliation, checkpointing, clock
   health, async export lifecycle and temporary artifact cleanup.
7. Bootstrap/migrate/export/verify/backup/restore-check CLIs through correct authority.
8. Production Dockerfile/Compose/Caddy, strict `.env.example`, key rotation, graceful
   shutdown/readiness, backups/WAL/off-host instructions and complete runbooks.

**Exit:** all T0–T9 except final attack/load rerun green; fresh VPS Compose from empty
volumes to first vote/minutes/action closure; AC-07/13/14/16/17/19/21/22 green;
`BUILD_LOG.md` entry.

### Phase 5 — adversarial review, release evidence and handoff

**Entry:** Phase-4 complete and no unresolved SR.

Work:

1. Execute TH-01..TH-63 against the running release image; preserve receipts and fix all
   findings with regression tests.
2. Execute AC-01..AC-22, full authz matrix, load envelope, crash/fault, backup/restore,
   upgrade/rollback compatibility, SBOM/license/vulnerability/container scans.
3. Run `pnpm verify:release`; private beta may omit only independent external review and
   must carry the exact limitation banner.
4. Complete README/DEPLOY/SECURITY/VERIFICATION/AGENT_GUIDE/THREAT_MODEL/HARVEST_REPORT,
   ADRs and every operator runbook; document candid known limitations and residual client
   auto-approval/agent-security risk.
5. Produce Gate-3 manifest/digests, evidence ledger, outcome comparison and handoff.

**Exit:** all required deterministic tiers green, zero skipped/quarantined/unresolved SR,
full restore receipt and signed Gate-3 sponsor approval. No “done”/public-production claim
before this exit; lack of external review limits label to private hardened beta.

## 7. Verification checklist for Gate 3

- Correctness: one registry, one tally/rules/consent/certificate implementation; all 22
  acceptance scenarios and objectives pass against release image.
- Security: all 94 SRs have exact code/function + exact test pointers; all 63 attacks run;
  no content/authz/observer/protocol/purge escape; vulnerability disposition complete.
- Maintainability: lock/registry/migration/ADR/runbook/SBOM current; future protocol,
  rule, content type, client action, retention or checker-provider change names its
  Architect cycle and regression lanes.
- Operations: cold start, upgrade, graceful stop, key rotation, incident paths, backup/
  PITR/full restore and evidence verification are reproducible by an operator not present.
- Human understanding: plain-language product boundary says “your agent presents;
  BoardAgent records exact information and confirmations; you remain responsible for
  review and agent/local security; there is no governance UI or server AI.”

## 8. Handoff package

Required artifacts:

- frozen Gate-1/Gate-2/Gate-3 manifests and approval records;
- source/image/lock/migration/registry/SBOM digests;
- `docs/VERIFICATION.md` control register and machine-readable net results;
- threat/attack/acceptance/load/restore receipts and known-limitations ledger;
- `README.md`, `DEPLOY.md`, `SECURITY.md`, `docs/AGENT_GUIDE.md`, complete ADRs;
- runbooks for bootstrap/member/AI observer/onboarding/recovery/OIDC/UAE Pass/client
  registration, rules/profile/votes/recusal/proxies/Q&A/submissions/minutes/redlines/
  action items/signatures, content rejects, audit/certificates/exports/webhooks/jobs,
  migration/upgrade, key compromise, incident response, backup/PITR/restore and release;
- escalation map: secretary for governance records/access, deployment admin for service/
  identity/backup, security contact for suspected compromise, sponsor/architect for a
  frozen-decision change.

No deployment, remote push, external review contact or sharing of real board data is
authorized by Gate 2 alone.

