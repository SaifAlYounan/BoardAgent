# BoardAgent verification and release net

Status: **PROPOSED FOR GATE 2 — thresholds are immutable after approval**  
Prepared: 2026-08-28 (Asia/Dubai)

## 1. Evidence doctrine

No prose claim is complete without all three pointers in `docs/VERIFICATION.md`:

1. a numbered requirement (`SR-nnn`);
2. the exact product file and exported function/constraint implementing it; and
3. the exact test or scripted attack proving it.

`PASS` means the required lane executed against the required target. `BLOCKED`,
`UNVERIFIED`, `SKIPPED`, `QUARANTINED` and “not available” are never green. CI parses the
registry, checks every callable/event/schema/state transition has a row, checks paths and
test names exist, and refuses a release when an SR is unresolved.

Stage-B disposable tests prove design feasibility only. They are not copied into the
product as evidence unless independently rewritten against production boundaries.

## 2. Frozen scoring tiers

| Tier | Required target | Threshold | Per-category rollback/release rule |
|---|---|---:|---|
| T0 integrity | lockfile, source, generated registries, migrations, container context | 100% deterministic; no drift | any drift or undeclared generated diff blocks |
| T1 static | format, ESLint, strict TS, dependency architecture, forbidden imports/config/egress | 100% pass; zero warning waivers | any failure blocks |
| T2 unit/state | every branch of domain, canonicalization, policy and state machines | critical packages 100% branches; overall ≥90% branches and ≥95% lines | any critical uncovered branch blocks |
| T3 property | tally/quorum/proxy/ruleset/canonical/event invariants | ≥100,000 seeded cases plus exhaustive bounded small state spaces | one counterexample blocks; seed/case retained forever |
| T4 mutation | critical domain/authz/consent/audit/certificate packages | 100% non-equivalent mutants killed | any surviving non-equivalent mutant blocks |
| T5 PostgreSQL | real supported PostgreSQL 18.6, RLS, migrations, races, crash injection | 100% required cases; zero skipped | unavailable DB blocks release |
| T6 protocol/auth | real modular MCP clients, legacy read client, OAuth AS, browser WebAuthn/TOTP/OIDC | 100% positive/negative matrix | any silent fallback/downgrade blocks |
| T7 adversarial | every TH row below against a running instance | 100%; safe failure plus required event | any unexecuted or unsafe scenario blocks |
| T8 acceptance | every AC row below, real MCP SDK client and real services | 100% | any scenario failure blocks |
| T9 operations | image, Compose/VPS, backup/restore, upgrade, load, SBOM/license/vulnerability | 100%; zero untriaged critical/high vulnerability | unavailable restore or scan blocks |
| T10 independent review | external security review for public production label | zero unresolved critical/high; medium disposition recorded | absence permits private beta only, never public-production claim |

There is no LLM judge tier. Human review may add findings but cannot convert a failing
code-graded tier into a pass or bless generated goldens.

## 3. Security-requirement index

The implementation will expand each row into exact code/test pointers without renumbering.

### Determinism, content and trust boundaries

| ID | Requirement |
|---|---|
| SR-001 | Server runtime makes zero model/embedding/OCR/conversion/content-analysis calls and has no provider SDK, key, endpoint or egress path. |
| SR-002 | Every inbound MCP/HTTP/job/CLI trust-boundary payload is strict-versioned Zod; unknown fields reject and are safely audited. |
| SR-003 | Canonical JSON uses versioned RFC 8785/JCS; text uses strict UTF-8 NFC/LF; hashes bind exact canonical bytes/schema. |
| SR-004 | Only canonical MD, TXT and declared strict JSON document versions are accepted; PDF, Office, image, scan, archive, polyglot and malformed bytes are rejected before durable content storage. |
| SR-005 | Unsupported material failure is loud, identifies the rejected class and instructs management/secretariat to resubmit machine-readable source. |
| SR-006 | Free text remains inert data, is never interpreted as instructions/rules/code, is escaped on browser surfaces and excluded from operational logs/wake-up notifications. |
| SR-007 | Future `SubmissionCheckProvider` is schema-only and unreachable in v1: no implementation, tool, config, job, secret, dependency or network permission. |

### Identity, OAuth and client boundaries

| ID | Requirement |
|---|---|
| SR-008 | Path-aware `/.well-known/oauth-protected-resource/mcp` identifies exactly normalized `https://host/mcp`; every 401 points there, authorization/token requests carry that exact RFC 8707 resource and JWT `aud` equals it. |
| SR-009 | OAuth authorization code uses S256 PKCE, exact registered redirect, 60-second one-use code; implicit/password/device/client-credentials/plain PKCE are absent. |
| SR-010 | Access token lifetime is at most 15 minutes; persisted JTI revocation is checked on protected use. |
| SR-011 | Opaque refresh tokens rotate on every use, enforce 30-day idle/90-day absolute limits, and family reuse atomically compromises/revokes the family. |
| SR-012 | Client name, brand, software ID and self-asserted metadata never grant data/action authority; internal client UUID and exact protocol client-ID kind/value remain distinct throughout policy/audit. |
| SR-013 | CIMD/DCR redirect and metadata resolution resists SSRF/DNS rebinding, has size/count/rate limits and audits registration. Allowlisting accepts only a typed verified CIMD URL, DCR opaque ID or preregistered ID—never asserted metadata. |
| SR-014 | An arbitrary conforming client without an invited, activated person and current board authority obtains no protected existence, count, content or action. |
| SR-015 | Builtin enrollment requires precreated seat, 24-hour one-use hashed invite, UV passkey, pending activation and secretary-confirmed 10-minute human code before grants. |
| SR-016 | Passkeys enforce exact RP ID/origin/challenge, `userVerification: required`, one-use challenge and sign-counter/backup-state policy; no silent UV downgrade. |
| SR-017 | TOTP is an explicit fallback only, with encrypted secret, replay-step protection, bounded attempts and lockout; passwords are absent. |
| SR-018 | OIDC/UAE Pass maps only an invited prelinked exact `(issuer, subject)` or confirmed pending link; no email matching or auto-provisioning. |
| SR-019 | External IdP tokens remain server-side; BoardAgent alone mints resource-bound MCP tokens. |
| SR-020 | Daily use silently rotates refresh credentials; secretary is not involved again except recovery, identity or authority change. |
| SR-021 | Recovery revokes or explicitly preserves each credential/session according to the confirmed package and records the identity-proof method. |
| SR-022 | Auth/browser pages rotate sessions, bind state/nonce/CSRF, escape all external text, set secure cookies/CSP/frame protections and reject Host/origin/proxy confusion. |

### Roles, authorization and confidentiality

| ID | Requirement |
|---|---|
| SR-023 | Scopes are ceilings; active identity, current onboarding, organization capability, board seat, object state, ACL and live exclusion are rechecked per request. |
| SR-024 | Observer identities hold no governance/admin/management/secretary/task authority. Every identity retains exact own-object onboarding attestation, session revocation and contentless-webhook self-service. Observer governance/workflow writes are exactly the six registered question/follow-up/minutes comment/withdraw/redline/signature operations. Observer minutes signature is record attestation, never a vote. |
| SR-025 | Every document/list/search/snippet/count/cursor/feed/notification uses the same deny-wins visibility policy; recused users learn no excluded existence. |
| SR-026 | PostgreSQL `FORCE ROW LEVEL SECURITY`, distinct migrator/server/worker roles, composite FKs and transaction-local principal context defend visibility-sensitive data. |
| SR-027 | Connection-pool reuse cannot carry principal/board/RLS context across transactions. |
| SR-028 | Worker, bootstrap, public verifier, operator CLI and anonymous actors have explicit least-authority policy; forged typed jobs cannot target another object/board. |
| SR-029 | AI observer uses separate seat credentials and recorded accountable principal; audit actor remains the AI seat and never impersonates the principal. |
| SR-030 | Rate limits apply by trusted token/member/client/IP class without leaking protected identifiers or differing hidden-object responses. |

### Onboarding, agent mediation and synchronized edge state

| ID | Requirement |
|---|---|
| SR-031 | Role-specific onboarding states no governance portal exists and directs the agent to ask how the person wants information presented. |
| SR-032 | Secretary publishes current support contact details before participants can attest onboarding. |
| SR-033 | Exact versioned terms require secure attestation of review duty, presentation/local-memory responsibility, agent/local-copy security, refetch-before-act and tombstone handling. |
| SR-034 | Ordinary scopes are denied until current terms are attested; material terms change forces reattestation. |
| SR-035 | BoardAgent records canonical terms delivery and attestation, never claims comprehension, consumption or safe client rendering. |
| SR-036 | Snapshot/delta responses contain currently entitled metadata/resource references only; content fetch remains separately authorized and audited. |
| SR-037 | Signed cursors bind member, board, entitlement generation and position; revocation/recusal emits tombstones and stale cursors cannot resurrect access. |
| SR-038 | `list_pending_actions` returns all entitled deltas in one bounded call and keeps `revote_required` pending until resolved/terminal. |

### Governance profiles, rules and voting

| ID | Requirement |
|---|---|
| SR-039 | Admin-activated governance profile is immutable/versioned and cites machine-readable charter clauses for weights, thresholds, quorum, ties, abstentions, proxies, notice and close modes. |
| SR-040 | Secretary can select only profile-permitted vote rules; an allowed override requires exact reason/citation/fresh confirmation and `rule_overridden`. |
| SR-041 | `evaluate_matter` is pure/deterministic over strict typed facts; missing/no-match/ambiguous equal result fails closed and every result is reproducibly persisted. |
| SR-042 | One BigInt/rational kernel drives casting display, quorum, tally and certificate; observers/nonvoters/recusals are excluded from eligible weight. |
| SR-043 | Opening freezes baseline electorate/weights, resolution, decision package, profile/rule/ruleset and explicit close mode. |
| SR-044 | Post-open recusal is a live versioned exclusion that atomically invalidates that principal's stage, ballot and proxy authority and recomputes eligible weight. |
| SR-045 | Proxy is per-vote, no chain/cycle, eligible same-board holder, attributed to principal/stamped caster; frozen precedence/revocation rule is applied once. |
| SR-046 | Modern MCP is sessionless `POST /mcp`; every request has matching protocol/method/name headers and protocol-version/capability metadata, every result has `resultType`, and a missing form-elicitation capability returns `-32021` before any binding stage. Header/body mismatch returns `-32020`; unsupported version returns `-32022`. |
| SR-047 | Every H act persists a one-use 10-minute stage and exact canonical embedded MRTR form/protected state before `input_required`; retry must use a new request ID, exact original method/arguments, byte-identical state, exact input responses, `action=accept`, `approve=true` and exact code. Cross-context or legacy invocation rejects before act; the legacy list omits H tools. |
| SR-048 | Wrong confirmation code atomically rejects/consumes stage and audits; timeout/cancel/replay/stale package/authz creates no act. |
| SR-049 | Successful confirm transaction rechecks token/policy/version/expiry/code, records consent then act, feed and audit atomically. |
| SR-050 | An open decision package is immutable. Any included resolution/submission/document/Q&A/rule/deadline change supersedes old vote and opens a new linked vote with zero carried ballot/stage/proxy. |
| SR-051 | Superseded acts remain permanent/non-counting. Replacement atomically creates new package/electorate/open event; notice/feed/`notice_delivered` for every newly eligible member; informational `vote_replaced` for every entitled recipient; and persistent actionable `revote_required` only for still-eligible prior ballot principals, with old/new IDs/hashes, changed classes, deadline and safe refs. It resolves only by accepted direct/proxy ballot, terminal/replacement vote or eligibility loss. |
| SR-052 | Live recusal is the only narrow eligibility-state exception to replacement; no content/rule/deadline edit is mislabeled recusal. |
| SR-053 | Automatic close is explicit per vote and suppressed on unhealthy clock; a vote cannot become `closed` without persisted, recomputed and signed certificate evidence. |

### Management submissions, Q&A, meetings and minutes

| ID | Requirement |
|---|---|
| SR-054 | All management-secretariat submissions, revisions, replies, disposition and materials occur through MCP immutable records; product has no SMTP/email workflow. |
| SR-055 | Submission approval creates a separately confirmable draft only and never executes the proposed governance act. |
| SR-056 | Voting members and observers can ask entitled board-bound questions with assigned management owner and due time; turns/citations/delivery are immutable and permanent. |
| SR-057 | Assigned management must add a nonblank recorded answer; an unanswered question cannot become answered/closed by status mutation and becomes overdue predictably. |
| SR-058 | Follow-up appends a permanent turn and reopens management pending action. |
| SR-059 | Vote decision package binds exact management submission, documents, explicitly secretary-linked Q&A thread inclusive turn cutoffs/hashes, resolution, electorate and governance versions; consent/certificate bind the package hash. Unlinked questions never block. |
| SR-060 | Every explicitly included Q&A thread must contain a recorded management answer through its frozen cutoff before close; a later turn on that linked thread atomically enters source-update pending. |
| SR-061 | Management amendment or post-cutoff turn on a linked Q&A thread blocks linked open-vote close until confirmed byte-preserving exclusion or full replacement. Server never infers materiality. |
| SR-062 | Meetings/agendas/schedules/minutes are immutable versions after notice. Minutes distinguish unpublished draft, published review, signature-ready and terminal states; nonfinal correction returns a new version to review, while finalized correction creates a separately identified linked aggregate and leaves the original terminal. |
| SR-063 | BoardAgent accepts no recording and transcribes nothing; secretary may contribute only a canonical transcript annex with loud provenance/coverage/verification state. |
| SR-064 | Transcript turns are immutable; correction is a new version; minutes bind annex hash/version and transcript change invalidates stale signature stages/signatures. |
| SR-065 | Transcript-derived unanswered Q&A creates management actions and links exact turns to permanent management threads. |

### Audit, certificates, exports and operations

| ID | Requirement |
|---|---|
| SR-066 | Every registered governance/security/delivery event appends strict canonical details to one immutable SHA-256 sequence/previous-hash chain in transaction order. |
| SR-067 | DB roles/triggers prevent request-path update/delete of audit, consent, ballot, version, certificate and snapshot rows. |
| SR-068 | Separate Ed25519 evidence key signs checkpoint at ≤1,000 events or ≤15 minutes and on export; key history and compromise time remain verifiable. |
| SR-069 | Audit verifier recomputes canonical events/order/links/checkpoints and reports the first break, truncation or manifest inconsistency without repair. |
| SR-070 | Mandatory audit append failure blocks governance writes and protected resource serving; checkpoint outage obeys explicit lag readiness policy and never fabricates signature. |
| SR-071 | `resource_fetch` prepared event binds exact URI/representation/hash/length/member/JTI/client/origin before bytes; completion/interruption is separately recorded when observable. |
| SR-072 | `notice_delivered` means committed recipient feed/channel handoff only, never human receipt/reading. |
| SR-073 | Certificate payload is recomputable entirely from persisted vote/package/rule/electorate/consent/ballot/proxy/outcome rows using the one kernel. |
| SR-074 | Public verification uses unguessable POST input, reloads persisted truth, recomputes, rate-limits and returns generic verdict without enumeration/disclosure bypass. |
| SR-075 | Every mutation has scoped canonical idempotency; one-time secrets are never stored/replayed as ordinary idempotent response. |
| SR-076 | System/audit exports require fresh confirmation/recent auth, frozen scope, repeatable-read complete manifest, encryption and 24-hour artifact deletion receipt; secrets are excluded. |
| SR-077 | Governance records, content, Q&A, audit, evidence, terms and history have indefinite retention; v1 has no physical purge path. Soft deletion is visibility-only plus permanent snapshot/tombstone. |
| SR-078 | Only ephemeral secrets/codes/tokens/temp exports/rate buckets/allowlisted operational logs and rotating backup generations expire under explicit policy. |
| SR-079 | Webhook is optional/off, contentless, per-member HMAC, HTTPS public target, fresh DNS/no redirects/private addresses and bounded retries. |
| SR-080 | Jobs use typed payloads, transactional outbox, leases/heartbeat, idempotency, bounded retry/dead letter and no external call inside governance transaction. |
| SR-081 | Migrations verify immutable ledger/checksum/order under fixed advisory lock; unknown/downgrade/edited history refuses readiness; production never auto-downs. |
| SR-082 | Backup boundary includes consistent DB/WAL, full content hashes, migration ledger, audit head/checkpoint and key registry; clean restore verifies all records before readiness. |
| SR-083 | Production configuration refuses placeholder/default/unknown `BOARDAGENT_` values, insecure public URL, weak key topology or unavailable authoritative storage. |
| SR-084 | Operational logs/metrics/traces exclude canonical/free text, protected raw IDs, statements, secrets and small-group governance signals. |
| SR-085 | Single image runs nonroot/read-only-root/minimal capabilities; server and worker have distinct DB/egress roles; vendor reference is excluded from build/image/publish. |

### Minutes review, signatures and action-item execution

| ID | Requirement |
|---|---|
| SR-086 | Minutes comments use only strict `boardagent.minutes-comment.v1`; redlines use only strict `boardagent.minutes-redline.v1` with base ID/version/hash, exact section/line anchor and anchored-text hash, operation, canonical proposed text, rationale and citations. |
| SR-087 | BoardAgent accepts no DOCX tracked changes, attachment, binary patch, fuzzy anchor or unknown redline/comment field; stale/cross-minutes bases and changed anchor text reject without mutation. |
| SR-088 | Entitled voting members and observers may submit comments/redlines only against the exact current `published_review` package; signature-ready/finalized input rejects. Content is inert, bounded, ACL/recusal-filtered, idempotent, permanent and excluded from logs/webhooks. |
| SR-089 | Only a pending current-package comment's author may append immutable withdrawal. Every nonwithdrawn item must receive secretary accept/reject plus reason; accepted redline creates a new immutable version/diff, all content remains permanent, and any pending item blocks signature readiness. |
| SR-090 | Before signature-ready state, secretary must freshly confirm a structured complete action-item manifest or exact `no_action_items` declaration for the current minutes version. BoardAgent never extracts action items. Logged items remain non-actionable drafts with no owner notice until that exact package finalizes. |
| SR-091 | A minutes package change atomically dispositions its draft action items as superseded. Finalization binds an activation-manifest hash and activates/notifies only that exact signed manifest. Each item binds source minutes hash/locator, owner, due, evidence and visibility; rejection preserves evidence and assignee cannot self-close. |
| SR-092 | Action-item closure freshly confirms the exact task and accepted evidence hashes. Closure stays terminal/permanent; correction creates a separately identified linked open task/evidence cycle and never reopens or mutates the original. |
| SR-093 | Minutes signature binds signer/seat, exact package hash, transcript/action/review manifests, optional reservation, consent/token/client/origin/time. `signature_record_hash` identifies bytes; consent plus Ed25519-checkpointed chain provides attribution. V1 issues no standalone minutes certificate. |
| SR-094 | A package change supersedes stages/signatures, resolves older re-sign rows as package-superseded and emits exactly one current `minutes_resign_required` per affected signer. It resolves only by fresh current signature, later package supersession or package terminality; no signature/re-sign action carries silently. |

## 4. Mandatory adversarial scenarios

| ID | Attack/scripted scenario | Expected control | Planned exact proof |
|---|---|---|---|
| TH-01 | Prompt-injected/malicious client with valid read token attempts an act | read scope never stages/acts; safe denial | `tests/attacks/compromised-client.spec.ts` |
| TH-02 | Stolen read bearer | resource-bound limited reads only; no mutation | `tests/attacks/stolen-token.spec.ts` |
| TH-03 | Stolen action bearer on capable client | cannot bypass MRTR; residual attributable completion is documented | `tests/attacks/stolen-token.spec.ts` |
| TH-04 | Cross-board target substitution/confused deputy | composite policy/FKs deny without existence signal | `tests/attacks/cross-board-deputy.spec.ts` |
| TH-05 | Scope inflation/observer attempts every mutation | exact own-security self-service plus six governance exceptions pass; every other row denies | generated `tests/authz/full-surface-matrix.spec.ts` |
| TH-06 | CIMD/DCR SSRF, flood, squatting or self-asserted software ID used as allowlist key | SSRF/rates/caps/audit; only typed protocol ID grants client admission | `tests/attacks/client-registration-abuse.spec.ts` |
| TH-07 | Redirect/PKCE/code replay/OAuth mix-up | exact redirect/S256/one-use/issuer-resource binding | `tests/attacks/oauth-flow-confusion.spec.ts` |
| TH-08 | Token for another audience/resource/base URL | reject and challenge exact resource | `tests/attacks/token-audience-confusion.spec.ts` |
| TH-09 | Recused member probes read/list/search/snippet/count/cursor/feed | indistinguishable empty/not-found; no leak | `tests/attacks/recusal-invisibility.spec.ts` |
| TH-10 | MRTR retry changes request ID incorrectly, method/name/arguments/form responses/state/client/member/vote | exact staged wire contract rejects; consumed stage cannot replay | `tests/attacks/consent-context-replay.spec.ts` |
| TH-11 | Wrong/expired code or stale package | atomic reject/audit, zero act | `tests/attacks/consent-rejections.spec.ts` |
| TH-12 | Client auto-echoes confirmation | event remains client-attributable; no comprehension claim | `tests/attacks/auto-approval-residual.spec.ts` |
| TH-13 | Audit row edit/delete/reorder/truncate | verifier reports first break/manifest gap | `tests/attacks/audit-tamper.spec.ts` |
| TH-14 | Audit append/checkpoint signer outage | fetch/write fail closed or bounded explicit checkpoint lag | `tests/attacks/audit-outage.spec.ts` |
| TH-15 | Forged/stale/enumerated public certificate | persisted recomputation/generic rate-limited verdict | `tests/attacks/public-certificate-abuse.spec.ts` |
| TH-16 | Passkey wrong RP/origin/challenge/UV/replay | ceremony refuses and rate-limits | `tests/browser/webauthn-negative.spec.ts` |
| TH-17 | Intercepted invite/QR or wrong person redeems | pending zero-access; human code + secretary proof required | `tests/attacks/enrollment-interception.spec.ts` |
| TH-18 | Refresh-token reuse race | one successor; whole family atomically compromised | `tests/attacks/refresh-rotation-race.spec.ts` |
| TH-19 | Unknown OIDC/UAE Pass subject/email collision | no auto-provision; pending link/deny | `tests/attacks/oidc-linking.spec.ts` |
| TH-20 | CSRF/session fixation/clickjack/XSS/Host spoof on auth pages | bound session/state/headers/escaping/origin | `tests/browser/auth-page-hardening.spec.ts` |
| TH-21 | Prompt instructions/HTML/Unicode/formulas in accepted text | inert bytes, safe MCP framing/escaping, no log/notification copy | `tests/attacks/untrusted-content.spec.ts` |
| TH-22 | Spoofed Office/PDF/image/archive/polyglot/bomb | reject before durable content and loudly remediate | `tests/attacks/document-format-boundary.spec.ts` |
| TH-23 | Operator sets future checker endpoint/key/provider | unknown/forbidden config refuses v1 | `tests/attacks/future-provider-activation.spec.ts` |
| TH-24 | Cross-board/recused Q&A query and count probing | shared visibility predicate; no trace | `tests/attacks/question-confidentiality.spec.ts` |
| TH-25 | Management/status job silently closes unanswered question | DB/state transition refuses; remains pending/overdue | `tests/attacks/question-answer-integrity.spec.ts` |
| TH-26 | Amend submission concurrent with cast/close | vote lock enters pending/superseded; no close on stale package | `tests/races/submission-vote-race.spec.ts` |
| TH-27 | Prior voter misses replacement or ineligible member receives impossible action | atomic open/notices/delivery/replaced/revote events; actionable only when eligible, with exact resolution lifecycle | `tests/races/replacement-notice-atomicity.spec.ts` |
| TH-28 | Cast/proxy concurrent with live recusal | vote root serializes; excluded act cannot survive | `tests/races/recusal-cast-race.spec.ts` |
| TH-29 | Proxy cycle/chain/double cast/principal precedence race | strict graph/policy/unique active principal ballot | `tests/races/proxy-ballot-race.spec.ts` |
| TH-30 | Weight/quorum/abstain/tie overflow/order manipulation | exact one BigInt kernel/property invariants | `tests/property/tally-quorum-proxy.property.ts` |
| TH-31 | Poisoned/stale/ambiguous ruleset recommends weaker rule | version/citation/fail-closed/confirmed override | `tests/attacks/ruleset-steering.spec.ts` |
| TH-32 | Wizard retry crosses draft/member/client | signed bound state and row version reject | `tests/attacks/cross-draft-confusion.spec.ts` |
| TH-33 | Idempotency key replays invitation/webhook/export secret | safe reference only; secret not replayed | `tests/attacks/idempotency-secret-replay.spec.ts` |
| TH-34 | Webhook localhost/metadata/DNS rebound/redirect | resolve every attempt; block private classes/no redirects | `tests/attacks/webhook-ssrf.spec.ts` |
| TH-35 | Over-scoped member exfiltrates system export | admin+recent auth+confirmation+frozen scope | `tests/attacks/export-exfiltration.spec.ts` |
| TH-36 | Forged job payload/lease theft/cross-board target | typed schema, service policy, binding/idempotent lease | `tests/attacks/job-forgery.spec.ts` |
| TH-37 | Cursor tamper or entitlement revoked mid-page | signature/generation/re-auth and tombstone | `tests/attacks/cursor-entitlement.spec.ts` |
| TH-38 | Migration checksum edit/reorder/downgrade/dual boot | advisory lock and immutable ledger refuse | `tests/attacks/migration-integrity.spec.ts` |
| TH-39 | Restore with missing/changed blob/row/key/checkpoint | full verification refuses readiness; never repairs | `tests/operations/restore-corruption.spec.ts` |
| TH-40 | Evidence key expires/compromised/KMS fails | history/public keys retained; signing state blocks close/checkpoint policy | `tests/attacks/key-lifecycle.spec.ts` |
| TH-41 | Logs/metrics distinguish recused from nonexistent or contain text/IDs | allowlist/pseudonym/differential outputs | `tests/attacks/telemetry-leak.spec.ts` |
| TH-42 | Unverified transcript presented as authoritative/audio-derived | loud status/provenance; no recording claim | `tests/attacks/transcript-claim.spec.ts` |
| TH-43 | Transcript/minutes correction preserves old signatures | version change atomically invalidates stages/signatures | `tests/races/transcript-minutes-signature.spec.ts` |
| TH-44 | One-call briefing omits delta or leaks other principal | indexed member sequence and entitlement filter | `tests/acceptance/daily-briefing.spec.ts` |
| TH-45 | Client/handler omits/mismatches modern headers/capability/result contract or silently negotiates legacy act | exact `-32020/-32021/-32022`; legacy H omitted/refused pre-stage; SDK shim off | `tests/protocol/protocol-downgrade.spec.ts` |
| TH-46 | Same member changes client brand | identity/history/entitlements unchanged | `tests/acceptance/client-portability.spec.ts` |
| TH-47 | User skips/stales onboarding terms | ordinary scope issuance/use denied | `tests/attacks/onboarding-bypass.spec.ts` |
| TH-48 | AI observer uses principal credential or mutates outside exact self-service/six governance exceptions | separate actor credential/full-matrix denial/accountable metadata | `tests/acceptance/ai-observer.spec.ts` |
| TH-49 | Feed delivery is described as human reading | typed wording/events prohibit consumption claim | `tests/contracts/delivery-semantics.spec.ts` |
| TH-50 | Clock drift causes legally mistimed automatic close | health threshold suppresses close and alerts | `tests/operations/clock-drift.spec.ts` |
| TH-51 | Stream interrupts after prepared fetch event | completion/interruption event is honest; no receipt claim | `tests/faults/resource-stream-interruption.spec.ts` |
| TH-52 | Secretary attempts in-place open vote edit/extension | server creates replacement or refuses; no old hash mutation | `tests/attacks/open-vote-mutation.spec.ts` |
| TH-53 | Admin/job/operator attempts physical governance purge | no product path/privilege; permanence invariant holds | `tests/attacks/permanent-record-purge.spec.ts` |
| TH-54 | Pooled DB context leaks across users | transaction-local context reset; FORCE RLS denies | `tests/races/rls-context-bleed.spec.ts` |
| TH-55 | Concurrent rate-limit increments bypass cap | atomic bucket/update and trusted keys | `tests/races/rate-limit-concurrency.spec.ts` |
| TH-56 | Client submits DOCX tracked changes/base64 attachment/unknown redline field | strict schema and document boundary reject before review row | `tests/attacks/minutes-redline-format.spec.ts` |
| TH-57 | Client fuzzy-applies a stale/cross-minutes/changed-anchor patch | exact base and anchored-text hash reject with zero version change | `tests/attacks/minutes-redline-context.spec.ts` |
| TH-58 | Observer uses minutes-review scope to vote/admin/task/alter minutes | generated exact-tool exception; all other mutations deny | `tests/authz/observer-exception-matrix.spec.ts` |
| TH-59 | Review input/other-author withdrawal occurs after signature freeze, or secretary issues package with pending item/omitted action declaration | current published-review and author/state/DB constraints refuse | `tests/attacks/minutes-review-bypass.spec.ts` |
| TH-60 | Assignee self-closes action, closure lacks accepted evidence, or correction reopens/mutates completed task | role/state/confirmation refuses; linked correction cycle leaves original terminal | `tests/attacks/action-item-false-closure.spec.ts` |
| TH-61 | Minutes version/finalized correction races signature; second correction strands/carries re-sign state | minutes root serializes; linked finalized correction, signature supersession and exact re-sign lifecycle commit atomically | `tests/races/minutes-signature-version-race.spec.ts` |
| TH-62 | Draft action is notified/acted before finalization, survives package replacement, or stale manifest activates | draft rejects evidence; replacement dispositions stale drafts; exact activation manifest alone opens/notifies | `tests/races/minutes-action-activation.spec.ts` |
| TH-63 | Unlinked arbitrary question blocks close, or linked Q&A turn races cast/close without update-pending | only explicit link/cutoff controls; linked turn locks vote and serializes pending state | `tests/races/question-turn-vote-race.spec.ts` |

## 5. Acceptance scenarios

All applicable scenarios start a real PostgreSQL 18.6 instance, BoardAgent server and
worker, and drive a real modular MCP SDK client over HTTPS. Protocol-portability cases
also use the frozen legacy client and at least one independently packaged modern client.

| ID | End-to-end outcome |
|---|---|
| AC-01 | Fresh Compose/VPS bootstrap → first secretary enrollment/passkey/activation → client registration → cited-rule `/set-vote` → second client briefing → MRTR ballot → close → offline certificate verification. |
| AC-02 | Recused member sees no excluded document trace through read, list, search, snippet, count, cursor, feed, notice or differential telemetry. |
| AC-03 | Proxy grant, attributed cast/stamped caster, direct-principal precedence and certificate lineage are exact. |
| AC-04 | Wrong code, expired stage, stale package, cross-client retry and post-replacement retry reject/audit with zero ballot. |
| AC-05 | One `list_pending_actions` call returns every entitled delta after cursor and nothing else. |
| AC-06 | Ruleset recommendation cites exact clause/version; departure requires reason and emits `rule_overridden`. |
| AC-07 | AI observer attests its own onboarding, revokes its own session and manages its own contentless webhook; reads entitled records, asks/follows up management questions, submits exact minutes comments/redlines and signs a configured minutes package; every other governance/workflow mutation is denied and every fetch/action identifies the AI seat plus accountable-principal metadata. |
| AC-08 | Same member connects through two differently branded conforming clients; identity/history/entitlements are unchanged; legacy client remains read-only. |
| AC-09 | Manual audit row mutation makes verifier report the exact first break; no repair occurs. |
| AC-10 | Prelinked OIDC/UAE Pass identity succeeds; unknown subject cannot auto-provision. |
| AC-11 | Role-specific agent onboarding asks presentation/local-memory preference, supplies secretary contact, and gates ordinary scopes until exact responsibility/agent-security terms are attested. |
| AC-12 | MD/TXT/typed JSON succeeds byte-exactly; PPTX/PDF/DOCX/image/scan/archive/spoof fails loudly with zero durable content/evidence attachment. |
| AC-13 | Management submits canonical materials, secretary requests revision, management resubmits, and approval creates only a separately confirmable draft—all inside MCP, with no email module. |
| AC-14 | Member and observer questions reach assigned management, become overdue, require recorded answers, preserve follow-up/citations and can be included by exact cutoff in a decision package. |
| AC-15 | After a member votes, an included submission/Q&A/resolution/deadline changes: old vote/acts become permanent non-counting history, empty linked vote opens with per-eligible notices/delivery events, old stages/proxies fail, still-eligible prior principals receive persistent `revote_required` with old/new hashes, changed classes, deadline and refs, and ineligible principals receive information but no impossible action. |
| AC-16 | Secretary contributes an unverified canonical transcript annex, verifies/corrects versions, links meeting Q&A, and minutes correction invalidates old signature state without storing recordings/transcribing. |
| AC-17 | Soft-delete hides a record from ordinary surfaces but export/chain retains snapshot/tombstone forever; no physical purge tool/job/DB privilege exists. |
| AC-18 | After one secure enrollment, ordinary client reconnect silently rotates refresh; passkey appears only at absolute/risk boundary and secretary is not involved. |
| AC-19 | Encrypted off-host backup plus WAL restores to clean VPS; every content hash, migration, chain/checkpoint, certificate and role invariant verifies before readiness. |
| AC-20 | Public certificate endpoint resists enumeration/disclosure, recomputes persisted truth, detects DB tamper, while offline verification remains stateless. |
| AC-21 | Secretary's agent logs structured action items (or exact none) from the current minutes. A changed package supersedes stale drafts. Exact finalization binds/activates/notifies one manifest; owner submits canonical evidence; rejection persists; secretary freshly closes; a correction creates a linked task cycle while completed original remains terminal. |
| AC-22 | Member and observer agents submit strict anchored JSON comments/redlines only during published review; an author withdraws a pending comment without deletion; every other item is dispositioned; signature freeze rejects late review. Both roles sign exact package; nonfinal correction returns to review and drives exact re-sign lifecycle; finalized correction creates a linked aggregate without rewriting the original. |

## 6. Performance and reliability gates

At the D2-054 envelope, with database statistics representative of 25 boards/1,000
seats/100k document versions/1m audit/1m feed events:

- p95 warm list/get ≤500 ms;
- p95 entitled search and one-call briefing ≤1.5 s;
- p95 server processing for consent (excluding human/client wait) ≤750 ms;
- p95 audit append ≤250 ms;
- 100 concurrent MCP requests with zero incorrect authorization/result/event;
- a briefing returns up to 1,000 deltas or an explicit signed resync instruction;
- global audit-head lock remains below 20% of request critical-path time at objective
  load; exceeding it blocks release and triggers a scale ADR, not silent sharding;
- crash injection at every listed transaction/job boundary produces either complete
  committed state or safe retry/rollback, never a half-governance act;
- full restore meets RPO ≤15 minutes and documented drill RTO ≤4 hours.

## 7. Release command contract

The product repository must expose one noninteractive `pnpm verify:release` command that
runs or orchestrates T0–T9 and writes immutable machine-readable results under
`artifacts/verification/<build-id>/`. It fails if Docker/PostgreSQL/browser/client/scan
prerequisites are absent. A separate `pnpm verify:private-beta` may omit only T10 and
must label the output `PRIVATE HARDENED BETA — INDEPENDENT REVIEW NOT COMPLETE`.

The Gate-3 pack includes the exact build/image digest, dependency lock digest,
migration-ledger digest, verification-registry digest, test totals, coverage/mutation
reports, attack receipts, acceptance receipts, SBOM/license/vulnerability results,
backup/restore receipt, known limitations and every remaining non-green status.
