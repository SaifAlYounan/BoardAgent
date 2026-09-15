# BoardAgent data, state and transaction design

Status: **PROPOSED FOR GATE 2 — not yet frozen**  
Prepared: 2026-08-28 (Asia/Dubai)

## 1. Relational doctrine

PostgreSQL 18.6 is authoritative. Drizzle provides typed queries/schema declarations;
versioned hand-reviewed SQL migrations express constraints, RLS, triggers and indexes.

1. One `system_instance` points to exactly one organization. Security-sensitive rows
   retain `organization_id` and composite foreign keys even in the singleton deployment.
2. Internal IDs are UUIDv7. Public certificate/export references are independent
   256-bit random values. No sequential public identifier is an authorization secret.
3. Database `transaction_timestamp()` in UTC at microsecond precision is authoritative.
   Voting weights are capped positive `bigint`; percentages are integer numerator/
   denominator; monetary facts are signed `numeric(38,0)` minor units plus ISO currency.
   No float enters governance arithmetic.
4. SHA-256 values are `bytea` with `octet_length = 32`. Every canonical record carries a
   schema/canonicalization version. JSON is RFC 8785/JCS-compatible; text is exact strict
   UTF-8 NFC/LF.
5. Mutable aggregate roots have `row_version` and legal state transitions. Immutable
   evidence/version/turn/act rows have no `updated_at`; the request-path DB role cannot
   update/delete them and triggers provide defense in depth.
6. Governance/history/content has indefinite retention. There is no physical purge SQL,
   job, tool or request-path role privilege in v1. A soft deletion is a state change plus
   permanent snapshot/tombstone. Cascades are allowed only for expired ephemeral OAuth,
   rate-limit and temporary-export rows whose parent record is not evidence.
7. Cross-board links use composite FKs such as `(board_id, member_id)`, `(vote_id,
   resolution_version_id)` and `(minutes_id, minutes_version_id)`. Active uniqueness uses
   partial indexes. All enum/check constraints mirror strict Zod schemas.
8. RLS is `ENABLE` + `FORCE` on protected tables. Request transactions set signed/
   validated `SET LOCAL boardagent.member_id`, `organization_id`, `client_id`, `token_jti`
   and allowed board set. The pooled server role cannot disable/bypass RLS or read base
   tables through a separate superuser connection.
9. Search is a derived PostgreSQL `tsvector` over accepted canonical text only. The
   entitlement predicate is applied before count, rank, snippet and cursor. A failed or
   unsupported input never creates search content.
10. All external/network calls occur outside governance transactions. Feed/outbox rows
    commit with the source state; workers deliver later with idempotent leases.

## 2. Table inventory and invariants

Column lists below identify the security-relevant core; routine timestamps and
`organization_id` are implied where stated. The migration must add explicit checks,
unique indexes and composite FKs described here.

### 2.1 Platform, configuration and keys

| Table | Security-relevant content/invariant |
|---|---|
| `schema_migrations` | `version`, name, SQL checksum, applied build/time; strict ordered ledger; edited/unknown/reordered history refuses boot. |
| `system_instance` | singleton key, instance UUID, organization ID, exactly normalized HTTPS canonical resource URI ending `/mcp`, bootstrapped time; bootstrap insert once and refuse base-URL normalization drift. |
| `organizations` | legal/display name, slug, timezone, state; only one referenced row. |
| `boards` | name/slug/state/current settings/profile/ruleset IDs and row version; unique organization slug. |
| `board_versions` | immutable canonical board settings and hash; archive/correction never rewrites prior version. |
| `crypto_key_registry` | `kid`, purpose, algorithm, public JWK, nonsecret KMS/file locator, activation/retirement/compromise times; no private key bytes. |
| `config_receipts` | validated nonsecret effective config hash, build/schema/protocol versions and startup time; secrets excluded. |

### 2.2 People, roles, support and onboarding

| Table | Security-relevant content/invariant |
|---|---|
| `accountable_principals` | named human/legal entity responsible for AI observer; not a credential. |
| `members` | human/AI-seat kind, legal/display name, status and current identity/onboarding generation. AI observer requires accountable principal. |
| `organization_role_assignments` | versioned admin/secretariat/management capability; observer member ID forbidden by deferred constraint. |
| `board_memberships` | board/member, exactly one active seat (`voting_member`, `management`, `observer`), secretary flag, weight, effective period, state; observer weight zero and secretary false. |
| `membership_versions` | immutable seat/weight/authority snapshots and change reason/actor/consent/event. |
| `external_identity_links` | exact issuer/subject/member/status/invite lineage; unique `(issuer,subject)`; login never inserts automatically. |
| `secretary_support_versions` | organization/board support name, approved machine-readable contact methods, effective version/hash; required before onboarding attestation. |
| `onboarding_terms_versions` | role-specific exact canonical terms, security/responsibility clauses, version/hash/effective time. |
| `onboarding_attestations` | member, terms/support versions, presentation/local-memory choices, consent record and time; immutable. |
| `member_contact_points` | optional verified operational contact metadata used only for explicit enrollment handoff records; no product email sender. |

### 2.3 OAuth, passkeys and enrollment

| Table | Security-relevant content/invariant |
|---|---|
| `oauth_clients` | internal UUID plus exact protocol-client-ID kind/value (`verified_cimd_url`, `dcr_opaque`, `preregistered`), safe metadata/hash/status/registration actor; typed protocol ID is unique and asserted names/software IDs never authority. |
| `oauth_client_redirect_uris` | exact normalized URI/hash; unique per client; strict loopback/native/HTTPS policy. |
| `oauth_client_grants` | allowed grant types and scopes as normalized rows. |
| `oauth_authorization_requests` | client/resource/redirect/scope/member/session binding, state/status/expiry. |
| `oauth_authorization_codes` | only code hash, S256 challenge, exact redirect/resource/client/member/scopes, 60-second expiry, consumed/revoked times. |
| `oauth_consents` | member/client/resource/scope exact grant; never governance-act consent. |
| `access_token_records` | JTI, member/client/resource/scopes/session/family, issue/expiry/revoke and signing key; bearer value absent. |
| `refresh_families` | member/client/resource, generation and active/revoked/compromised/expired state, idle/absolute expiry. |
| `refresh_tokens` | token hash, family/generation, issue/use/replace/revoke; one active generation and atomic reuse response. |
| `auth_sessions` | opaque browser-session hash, member/client/status/origin/create/expiry/last auth; secure cookie stores only opaque ID. |
| `webauthn_credentials` | credential ID, member, public key, counter, transports/backup flags/status; unique credential ID. |
| `webauthn_challenges` | challenge hash, session/enrollment/purpose, exact RP/origin binding, expiry/consume; one-use. |
| `totp_credentials` | encrypted secret and key version, member/status, failed count/lock, last accepted step; never plaintext/logged. |
| `enrollment_invitations` | random token hash, precreated member, issuer, handoff method, 24-hour expiry, consume/revoke and pending-activation link. |
| `enrollment_activation_challenges` | pending member, 10-minute human-code protected value, secretary proofing method/attempts/status. |
| `oidc_login_transactions` | exact issuer/state/nonce/session/client/resource, expiry/consume; upstream token never persisted as BoardAgent authority. |
| `rate_limit_buckets` | trusted subject hash/class/window/count/block; atomic conditional upsert. |

### 2.4 Canonical documents, ACL and search

| Table | Security-relevant content/invariant |
|---|---|
| `documents` | board/title/state/current version/creator/row version; state active/archived/soft-deleted. |
| `document_versions` | immutable version number, media/schema, exact canonical `bytea`, length/hash, creator/time; max 10 MiB and unique version/hash relation. |
| `document_validation_attempts` | actor, offered media/name/length/hash-if-safe, accepted/rejected code/remediation; rejected content bytes are not retained. |
| `document_search` | current accepted version, board, text hash and `tsvector`; derivative cannot outlive source visibility. |
| `document_access_grants` | document plus member/board-role grantee, permission and active period; exact XOR grantee constraint. |
| `document_exclusions` | document/member, reason/version/effective period; partial unique active exclusion; deny wins. |
| `document_circulations` | exact document version/hash, recipient policy/package/consent/time/state; immutable after circulation. |
| `circulation_recipients` | circulation/member, entitlement snapshot hash, notice/feed IDs; unique recipient/version. |
| `retention_snapshots` | soft-deleted object canonical payload/hash and content refs; permanent. |
| `deletion_tombstones` | object/snapshot, actor/reason/time; no purge eligibility/physical-delete column in v1. |

### 2.5 Management submissions and permanent questions

| Table | Security-relevant content/invariant |
|---|---|
| `management_submission_threads` | board, management owner(s), secretary queue, state and current version. |
| `management_submission_versions` | immutable strict structured payload/document refs/hash, author, reason/supersedes/time. |
| `management_revision_requests` | thread/version/secretary, immutable request/reason/time. |
| `management_revision_replies` | request/version/management author, immutable reply/time. |
| `management_submission_dispositions` | exact version, approve-to-draft/reject, secretary/reason/resulting draft; approval never executes. |
| `management_questions` | board, asker, assigned owner(s), due time, ACL policy, pending/overdue/answered state projection and current turn. |
| `management_question_turns` | immutable ordered question/answer/follow-up turn, author/role, canonical text/hash, citations/time/idempotency. |
| `management_question_answers` | answer turn and question, assigned management author; required existence for answered projection. |
| `question_visibility` | inherited document/object ACL refs plus explicit grants/exclusions; same deny-wins RLS function. |
| `question_decision_links` | explicitly secretary-selected question, inclusive turn cutoff/hash and exact decision-package version; immutable. New turns on this linked thread after vote open trigger source-update pending; unlinked threads never block the vote. |

### 2.6 Meetings, agendas, transcripts and attendance

| Table | Security-relevant content/invariant |
|---|---|
| `meetings` | board/title/state/schedule/current agenda/minutes, row version; draft/called/completed/cancelled. |
| `meeting_versions` | immutable canonical title/schedule/notice package/hash; amendments create version/re-notice. |
| `agenda_versions` | immutable canonical JSON/hash and meeting version. |
| `agenda_items` | version/ordinal/title/source document version/hash; unique ordinal. |
| `meeting_rsvps` | meeting/member, immutable response versions with current projection; observers denied. |
| `meeting_attendance` | immutable record/correction chain, member/status/source/recorder; never inferred. |
| `meeting_transcripts` | meeting/current version/state; annex only. |
| `meeting_transcript_versions` | immutable canonical MD/typed-turn JSON, hash, source/coverage, loud verification state, creator/time/supersedes. |
| `transcript_turns` | immutable version/ordinal/speaker/time-range-if-provided/text/hash; no audio reference/blob. |
| `transcript_verifications` | exact version/hash, secretary consent/status/time; does not claim comparison to stored recording. |
| `transcript_challenges` | exact turn/base version, member comment/hash/state/time. |
| `transcript_challenge_dispositions` | challenge, secretary decision/reason/corrected version/consent. |
| `transcript_question_links` | turn(s), permanent management question and exact hashes. |

### 2.7 Minutes review, signatures and action items

| Table | Security-relevant content/invariant |
|---|---|
| `minutes` | meeting, state, current version/current signature package, correction lineage and row version; unpublished-draft/published-review/signature-ready/finalized/cancelled. |
| `minutes_versions` | immutable canonical text/package base, hash, transcript version/hash, creator/supersedes/time. |
| `minutes_review_items` | immutable strict comment/redline envelope, author/seat, exact base version/hash/anchor and payload hash; no attachment column. |
| `minutes_review_withdrawals` | immutable comment/author/current-package link and time; only the pending comment author may insert; comment bytes remain. |
| `minutes_review_dispositions` | exact item, secretary accept/reject, reason, resulting minutes version/diff hash and consent; one disposition. |
| `minutes_diffs` | immutable base/new versions and strict operations/canonical hash; derived only from confirmed accepted redlines. |
| `minutes_correction_cycles` | finalized original minutes, separately identified replacement aggregate, reason/consent/time; unique replacement and original remains terminal. |
| `minutes_action_declarations` | exact minutes version/hash, `items_logged` or `no_action_items`, complete manifest hash, secretary consent; unique current version. |
| `tasks` | board, optional source meeting/minutes/version/hash/locator, owner, due time, canonical description/required evidence, state and row version. Minutes-linked action item requires all source fields and begins `draft`, with no owner pending action until source minutes finalization. |
| `minutes_action_item_dispositions` | draft task, stale minutes package/new version, `superseded` reason/event/time; a stale draft can never activate. |
| `task_evidence` | immutable canonical text/document/resource refs and hash, task/owner/time/status projection. |
| `task_evidence_reviews` | evidence, secretary accept/reject, reason/consent/time; one active disposition per submitted evidence. |
| `task_closures` | task, exact accepted evidence IDs/hashes, source minutes hash, secretary consent and closure hash/time; requires accepted evidence FK. |
| `task_correction_cycles` | completed prior task/closure, authorized secretary, reason/consent and separately identified new open task; never mutates or reopens the original. |
| `minutes_signature_packages` | exact minutes/transcript/action/review/signer manifests and hashes, version/state/time; one current package. |
| `minutes_signature_requirements` | package/member/seat, required or permitted status; no waiver v1. |
| `minutes_signatures` | immutable package/version/hash, signer/seat, optional reservation hash, consent, token/client/origin/times and `signature_record_hash`; no standalone minutes certificate. |
| `minutes_signature_supersessions` | old signature/package, new minutes/package, reason/event/time; old signature remains verifiable/noncurrent. |
| `minutes_resign_requirements` | signer, from/to packages, pending/resolved state and exact resolution (`signed_current_package`, `package_superseded`, `package_terminal`); one current pending row per signer/lineage. |

### 2.8 Votes, packages, proxies and certificates

| Table | Security-relevant content/invariant |
|---|---|
| `votes` | board/title/state/current resolution/package, frozen rule/profile/ruleset/electorate, explicit close mode/deadline, row version; draft/open/source-update-pending/closing/closed/superseded/cancelled. |
| `vote_supersessions` | old vote/new vote, changed component classes, old/new package hashes, secretary consent/reason/time; unique old vote. |
| `resolution_versions` | immutable canonical text/hash/version/supersedes/author/time. |
| `approval_rules` | immutable schema and exact rational threshold/quorum/denominator/abstention/tie/proxy/close settings plus hash. |
| `decision_packages` | immutable vote/version; exact resolution, submission, document, Q&A cutoff, rule/profile/ruleset/electorate refs/hashes and whole package hash. |
| `decision_package_components` | typed ordered component refs/version/hash; no mutable “latest” link. |
| `vote_electorate` | frozen baseline member/seat/positive weight/eligibility snapshot/hash. |
| `vote_exclusions` | versioned live recusal/exclusion, actor/reason/consent/effective time; lifting appends a new state and restores no act. |
| `proxy_grants` | immutable confirmed grant, vote/principal/holder/policy/consent/time. No staged/effective row exists before consent. |
| `proxy_revocations` | grant/revoker/reason/consent/time and frozen effect. |
| `ballots` | immutable vote/package/principal/caster/choice/statement hash/weight/source/consent/time. |
| `ballot_dispositions` | prior ballot plus superseding ballot/vote or recusal reason/event; payload never updates. |
| `vote_outcomes` | vote/package/electorate/rule, canonical tally/hash/outcome/finalized time; only one for successfully closed vote. |
| `vote_certificates` | unguessable public ID, schema/payload/hash/signature/key/time/status/supersedes; payload recomputable from persisted refs. |

### 2.9 Consent, idempotency and guided drafts

| Table | Security-relevant content/invariant |
|---|---|
| `action_stages` | actor/acting-for, action/target/board, exact canonical version/payload/hash, nonce, protected code, client/token/context, 10-minute expiry and active/rejected/confirmed/replaced/expired state; one active action key. |
| `input_required_attempts` | stage/draft, exact protocol/header/meta version, original method/name/arguments hash, capabilities hash, embedded form/result payload hash, protected `requestState` bytes/hash, prepared/retry request IDs, exact input-response hash, accept/decline/cancel/status/times. A byte-different retry can never confirm. |
| `consent_records` | immutable stage/actor/action/target/payload/package/code-record/token/client/origin/stage+confirm times/schema. |
| `idempotency_records` | actor/client/operation/key/request hash/state/safe response reference/expiry; no ordinary one-time secret response. |
| `wizard_drafts` | type/board/creator, current step, signed context, state/expiry/ruleset/package hash/row version. |
| `wizard_steps` | immutable ordinal/question/schema/value/hash/recommendation/citation/override/reason/attempt/time. |
| `rule_overrides` | evaluation/draft/final object, recommended/selected rules, reason/citation/consent/event. |

### 2.10 Governance profile and rules engine

| Table | Security-relevant content/invariant |
|---|---|
| `governance_profiles` | board/version/state/hash/source agreement refs/activation consent; one active. |
| `governance_seat_rules` | profile seat class/weights/eligibility constraints. |
| `governance_rule_templates` | profile code and exact approval/quorum/tie/abstain/proxy/notice/close JSON/hash. |
| `governance_citations` | profile/rule, exact source document version/hash/clause/locator. |
| `rulesets` | board/version/state/hash/profile/activation consent/supersedes; immutable active version. |
| `matter_types` | ruleset/code/name/strict fact schema/hash. |
| `ruleset_rules` | ruleset/matter type/priority/specificity/condition tree/required rule/hash. Equal winning match is error. |
| `rule_citations` | rule/source version/hash/clause/locator. |
| `matter_evaluations` | every call's canonical facts/hash, engine/profile/ruleset versions, matched/ambiguous/missing/no-match result, citations/result hash/requester/time. |

### 2.11 Audit, feed, jobs, exports and backup receipts

| Table | Security-relevant content/invariant |
|---|---|
| `audit_chain_head` | singleton sequence/last hash/row version; locked on append. |
| `audit_events` | immutable sequence/event ID/previous+event hashes/type/actor/client/JTI/entity/board/strict details hash/origin/time/schema/correlation. |
| `audit_checkpoints` | immutable sequence/head hash/Ed25519 signature/key/time; unique sequence. |
| `notices` | typed board/object/version/recipient/content hash/feed sequence/state; unique required notice key. |
| `pending_action_feed` | per-member sequence, delta/object/version/entitlement generation/state/minimal payload/hash/time; signed cursor never stored as authority. |
| `feed_tombstones` | member/object/prior sequence/reason/new entitlement generation/time. |
| `member_webhooks` | member URL/hash, encrypted per-member HMAC/key version, event allowlist/state/verification; no global secret. |
| `notification_jobs` | notice/member/endpoint, contentless payload hash, queued/leased/retry/delivered/dead state, run time/attempt/lease; unique notice/endpoint. |
| `notification_attempts` | immutable job/attempt/resolved IP/request hash/response class/times/next run. |
| `jobs` | typed job schema/version/subject/payload hash/state/lease/retry/idempotency; worker service RLS. |
| `export_requests` | requester/type/frozen scope hash/consent/state/snapshot/artifact refs/expiry. |
| `export_artifacts` | random ID, encrypted bytes or operator path, manifest/hash/size/key ref/create/expiry/deleted receipt; content is temporary. |
| `export_chunks` | artifact/chunk ordinal/hash/size; complete manifest prevents omitted middle chunks. |
| `backup_receipts` | manifest/hash/snapshot LSN/time/content-set hash/key ref/status/verified-restore time; evidence only, no key. |

## 3. State machines

No transition outside this list exists. Terminal corrections use a new linked object.

- Instance: absent → active once.
- Member: invited → enrollment-pending → pending-activation → active → suspended →
  removed. Reactivation/recovery is a newly confirmed transition and revokes stale
  sessions as specified.
- Board: active → archived. Board creation is confirmed; archive is terminal for normal
  work and requires no open governance aggregate.
- OAuth code: issued → consumed | expired | revoked. Refresh family: active → revoked |
  compromised | expired. Invitation/challenge: issued → consumed | expired | revoked.
- Document: active → archived | soft-deleted. Versions are immutable accepted records;
  validation attempts are accepted/rejected without a binary-ingestion state.
- Submission: submitted → revision-requested ↔ resubmitted → approved-to-draft |
  rejected. Every version/reply remains.
- Management question projection: pending → overdue → answered; follow-up appends a turn
  and returns to pending. “Answered” requires an answer row.
- Meeting: draft → called → completed | cancelled. A called amendment appends a version
  and remains called; terminal state never reopens.
- Transcript: unverified → secretary-verified; correction creates a new unverified
  version. Challenge: pending → accepted | rejected through a disposition.
- Minutes: unpublished-draft → published-review → signature-ready → finalized, or
  nonfinalized → cancelled. A confirmed nonfinal correction appends a version and returns
  to published-review; a finalized correction creates a new linked minutes aggregate in
  published-review while the original remains finalized.
- Review item: pending → accepted | rejected; a pending comment alone may become withdrawn
  through an immutable author withdrawal. Review mutation is accepted only against the
  current published-review package. Every nonwithdrawn item must be accepted/rejected and
  no pending item survives into signature-ready.
- Minutes action item: draft → open only when the exact signed source minutes finalize;
  a package change instead dispositions the draft as superseded. Then open → in-progress
  → evidence-submitted → completed. Evidence reject returns task to open while preserving
  evidence. A completed-task correction creates a separately identified linked open task;
  it never reopens the original.
- Minutes re-sign requirement: pending → resolved by fresh current-package signature,
  package supersession or package terminality only. A second correction resolves the old
  pending row and creates exactly one new current row per signer.
- Vote: draft → open; `open | source-update-pending` → superseded only atomically with a
  new linked vote entering open; draft/open → cancelled; open → closing → closed. Open may
  enter source-update-pending on a linked source/Q&A turn. Pending source may return to
  open only by confirmed exclusion that leaves package bytes unchanged.
- Proxy grant: absent → active by consent; active → revoked/expired/superseded through
  immutable disposition. Stage never creates a proxy row.
- Ballot: immutable cast; a separate disposition marks superseded/invalidated. No active
  ballot is copied across vote replacement.
- Consent stage: active → replaced | confirmed | rejected | expired | cancelled.
- Wizard: active(step N) → ready-to-confirm → posted; active/ready → expired | cancelled.
- Ruleset/profile: draft → active → superseded; versions immutable.
- Export: staged/confirmed → queued → running → succeeded | failed → expired/deleted.
- Notification/job: queued → leased → delivered/succeeded | retry → leased | dead |
  cancelled.

## 4. Global lock order

All product writers follow one order, enforced by helpers and deadlock tests:

1. aggregate roots sorted by `(aggregate_type, UUID)`;
2. dependent current-state/projection rows sorted by primary key;
3. stage and idempotency row;
4. feed/outbox uniqueness rows; and
5. the singleton audit-chain head last.

Multi-event append takes the audit head once and allocates contiguous sequences. No path
may acquire an aggregate after the head. Serialization/deadlock retries are bounded and
reuse the same idempotency key. At the D2-054 load target, audit-head contention is a
measured release gate; v1 does not silently shard the evidentiary chain.

## 5. Mandatory transaction boundaries

### Boot, bootstrap and identity

1. **Migration boot:** acquire fixed advisory lock; validate entire ledger/checksums and
   supported app/schema range; apply forward SQL transactionally where PostgreSQL allows;
   record migration event; release only after schema readiness. No down at production
   boot.
2. **Bootstrap:** serializable transaction plus singleton advisory lock creates instance,
   organization, first board-capable admin/secretary, invitation and audit exactly once.
3. **Enrollment activation:** lock invitation/member/challenge; validate passkey-enrolled
   pending person, human code and secretary recent confirmation; consume challenge,
   activate member, append event/feed atomically. Link possession alone never activates.
4. **Token issue:** atomically consume code, create access JTI/refresh family/token and
   `token_issued`. Refresh locks family/current generation; reuse marks family compromised,
   revokes successors/sessions and audits in one transaction.

### Content, fetch and communications

5. **Document contribution:** validate media/signature/UTF-8/NFC/LF/schema/size and hash in
   bounded memory before transaction; transaction rechecks authority/idempotency and
   inserts exact accepted bytes/version/search row/event. Rejected bytes are not stored.
6. **Resource fetch:** one transaction executes the entitlement SQL, obtains exact bytes
   and appends `resource_fetch(prepared)`; only then stream. A short transaction appends
   completion/interruption if observable. Failure to append prepared means zero bytes.
7. **Question/answer/follow-up:** lock thread and idempotency; recheck actor/ACL/owner;
   append immutable turn, update projection/feed/notice/audit atomically. Answered state
   requires the answer turn FK. If the thread is explicitly linked into an open decision
   package and the new turn is beyond its frozen cutoff, lock that vote in global order,
   enter source-update-pending and block close in the same transaction. Unlinked threads
   never affect a vote. Scheduler changes pending to overdue only.
8. **Management resubmission:** append version/thread/audit/feed under lock. If linked open
   vote includes prior version, same transaction locks vote, sets
   `source_update_pending`, blocks close and notifies secretary; it never changes package.

### Consent and governance

9. **Stage/restage and MRTR prepare:** before any stage, validate the exact modern
   header/body/method/name/version contract and `clientCapabilities.elicitation.form`;
   otherwise return the frozen protocol error with no stage. Lock aggregate then active
   stage key; revalidate token/onboarding/policy/version/recusal; replace old stage; bind
   exact original method/arguments, client capabilities, protected state, canonical form
   and response hashes; insert protected code plus `stage_created` and
   `elicitation_sent` (meaning MRTR response prepared); commit before returning the
   embedded `input_required`. No client or human receipt is claimed.
10. **Rejected confirmation:** in one transaction lock stage/aggregate; verify exact safe
    identity/context; mark rejected/consumed and append `consent_rejected`; no act rows.
    A crash cannot leave a reusable wrong-code stage with contradictory audit.
11. **Successful confirmation/act:** accept only a new request ID retrying the exact
    original method/arguments with byte-identical protected state, exact form responses,
    elicitation action `accept`, `approve=true` and exact code. Lock root/dependents/stage/
    idempotency; recheck every policy/version/expiry/nonce/context; insert consent then
    act, feed/outbox and contiguous audit events; consume stage; commit. Any failure leaves
    no partial act. Decline/cancel/wrong-code is the one-transaction rejection path above.
11a. **Matter evaluation:** validate strict facts and idempotency; within one transaction
    lock the selected profile/ruleset versions, run the one deterministic engine and insert
    the canonical facts/hash, engine/profile/ruleset versions, result/citations plus
    `matter_evaluated`. Missing/no-match/ambiguous is a persisted fail-closed result, never
    a read-only side effect or silent fallback.
12. **Vote open:** lock draft; freeze decision package/rule/profile/ruleset/electorate;
    open; create one notice/feed row and `notice_delivered` event per entitled member plus
    `vote_opened`; commit together.
13. **Vote replacement:** lock old vote plus source package; accept old state open or
    source-update-pending; validate confirmed new package; insert new vote/electorate/
    package in open, append supersession and disposition for every old stage/proxy/ballot,
    mark old superseded, append `vote_opened`, create one new-vote notice/feed and
    `notice_delivered` for every newly eligible member, create informational
    `vote_replaced` for every entitled recipient, and create actionable
    `revote_required` only for prior ballot principals still eligible on the new vote.
    Each action carries changed classes/deadline/safe refs. Commit once. Resolve a revote
    delta on accepted direct/proxy ballot, terminal/superseding new vote, or eligibility
    loss; a second replacement resolves prior lineage and creates the next. No old
    stage/proxy/ballot reference is copied.
14. **Live recusal:** lock vote/member/exclusion/current stages/proxy/ballot projections;
    append exclusion and act dispositions, recompute one-kernel eligibility, create
    notices/feed/audit. A concurrent cast serializes before or after and cannot survive
    wrongly.
15. **Vote close:** lock vote and inputs; require open/current package, no linked-source
    update pending, a recorded management answer in every explicitly included Q&A thread
    through its frozen cutoff, and healthy clock; compute one-kernel outcome; persist outcome and complete
    certificate payload, set closing, sign/recompute, insert certificate and set closed
    under the chosen recoverable signing protocol. A key failure leaves closing, never
    closed-without-certificate.

### Minutes, action items and signatures

16. **Review submission:** require the exact current package in `published_review`; validate
    strict comment/redline schema and visible base version/hash/anchor before transaction;
    lock minutes/idempotency, recheck context, append immutable item/feed/audit. It never
    edits minutes. Unpublished, signature-ready and terminal packages reject.
17. **Comment withdrawal:** lock minutes/comment/idempotency; require current
    `published_review`, pending comment and exact author; insert immutable withdrawal plus
    `minutes_review_withdrawn`. Comment bytes remain. Redlines cannot be withdrawn.
18. **Review disposition:** lock minutes/item; require current published review, pending
    nonwithdrawn item and reason. Reject appends disposition. Accepting a comment appends
    disposition only. Accepting a redline validates supplied canonical replacement,
    appends version/diff/disposition, returns the new package to published-review,
    invalidates the declaration/signature package, dispositions every stale draft action,
    supersedes stages/signatures, resolves older re-sign deltas and creates current
    `minutes_resign_required` rows/notices; one commit.
19. **Explicit nonfinal package correction:** same root lock and fresh confirmation as an
    accepted redline, but with a secretary correction reason. Append new immutable version
    and `minutes_package_corrected`; return to review; supersede stale draft actions,
    stages/signatures and re-sign deltas atomically. Direct unpublished-draft revision is
    the only nonconfirmed version write.
20. **Action declaration:** lock current review-resolved minutes; confirm either nonempty
    strict action list or exact none. Supersede any prior draft declaration tasks for this
    package, then insert new **draft** tasks/manifest/consent/audit together. Create no owner
    pending action/notice. No server extraction or hidden task creation.
21. **Signature-package issue:** lock current published-review minutes, all nonwithdrawn
    review items, withdrawals/dispositions, action/transcript/signer requirements; require
    zero pending review and the current declaration; persist exact package hash, move to
    signature-ready, notify signers and audit atomically. Review writes now reject.
22. **Minutes signature:** standard successful confirmation binds exact current package/
    signer/seat/reservation and inserts signature record/consent/feed/audit; resolve only
    that signer's current re-sign requirement. No minutes certificate exists. Observer
    signature runs the exact narrow policy and grants no other capability.
23. **Minutes finalization:** lock current package, all required signatures and manifest
    tasks; require every current required signature; hash the exact activation manifest;
    finalize and atomically move only those tasks `draft` → `open`, append
    `minutes_action_items_activated`, owner pending actions/notices and `minutes_finalized`.
    Resolve any remaining re-sign rows by package terminality. A stale package activates
    nothing.
24. **Finalized-minutes correction cycle:** lock finalized original and idempotency;
    require fresh confirmed reason/new package; create a separately identified linked
    minutes aggregate in published-review and `minutes_correction_cycle_created`. The
    original state, signatures and activated tasks remain unchanged.
25. **Evidence review/closure:** evidence submission appends owner-bound canonical record.
    Review locks task/evidence and appends accept/reject disposition. Closure locks task
    and all accepted evidence, requires secretary confirmation, inserts immutable closure
    hash/feed/audit and completes projection. Owner cannot self-close.
26. **Completed-task correction cycle:** lock completed task/closure and idempotency;
    require secretary confirmation and reason; create a separately identified linked open
    task/evidence cycle and `task_correction_cycle_created`. The prior task/closure stays
    completed and immutable.

### Audit, jobs, exports and recovery

27. **Idempotency:** insert/lock key before mutation. Same canonical request returns safe
    reference; different hash rejects/audits. Secret-bearing first responses return
    `already_issued` on repeat and require explicit rotate/reissue.
28. **Job claim/result:** `FOR UPDATE SKIP LOCKED`, short lease/heartbeat and typed
    payload. External call happens outside transaction; result/outbox transaction is
    idempotent. Dead-letter never changes governance state.
29. **Export:** confirmed request stores frozen scope hash. Worker reads a repeatable-read
    snapshot and builds every component/chunk hash; completion inserts encrypted artifact
    and complete manifest/event. Partial artifacts reconcile/quarantine, never succeed.
30. **Checkpoint:** snapshot exact `(instance, sequence, head hash, schema)` for signing;
    insert only a verified signature bound to unchanged sequence/head, otherwise retry and
    alert. Chain stays valid; readiness follows approved lag policy.
31. **Backup/restore:** database base/WAL boundary, migration ledger, public key registry
    and all content share one manifest/LSN. Restore in isolation verifies every content
    hash/reference, full chain/checkpoint and every certificate before readiness; never
    repairs evidence.

## 6. Scheduler and worker jobs

Required typed jobs: notice fan-out; contentless webhook delivery; action/question/task
due-state and reminder projection; vote deadline scan; internal `automatic_vote_close`
only for a vote whose confirmed package selected automatic mode and only with healthy clock;
action-stage expiry; wizard expiry; OAuth/ephemera expiry; refresh/session revocation;
export build and temporary-artifact reconciliation/expiry; certificate closing recovery;
feed entitlement reconciliation/consistency check; audit checkpoint/signature and full
verify; notification retry/lease reaper/dead-letter alert; clock-health monitor; backup
trigger/receipt/restore-due alerts; key/protocol/dependency compatibility alerts; job/log/
rate-bucket retention.

There is no document extraction/conversion/AI job and no governance/content purge job.
The scheduler never marks a question answered, a task completed, minutes finalized, a
submission approved or an action understood.

## 7. Migration dependency rule

No table migration begins until Gate 2 approves every decision that shapes that table.
The build plan creates migrations by aggregate in dependency order, with an up/down/up
test database for development validation. “Down” proves migration author quality only;
production rollback is compatible application rollback or verified isolated restore,
never an automatic downgrade.
