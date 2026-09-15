# BoardAgent callable, authority and event matrix

Status: **PROPOSED FOR GATE 2 — not production code**  
Prepared: 2026-08-28 (Asia/Dubai)

This is the closed v1 registry. Every callable identifier appears exactly once. Product
code must be generated or checked against a machine-readable form of this registry; an
unregistered handler, event, resource or prompt fails CI.

## 1. Legend and universal rules

- `R` — repeat-safe read. A read may append a mandatory fetch/security event, but does
  not alter governance state.
- `D` — direct, idempotent, audited, nonbinding contribution, communication, draft or
  reversible-progress mutation.
- `H` — fresh human confirmation over exact canonical content. MCP governance actions
  use modern MRTR `input_required`; pre-MCP enrollment, onboarding and recovery use the
  minimal browser/passkey ceremony. No standing token completes an `H` action.
- `S` means the named OAuth scope is necessary but never sufficient. Every row also
  applies active-person, current-onboarding, organization/board role, membership,
  object-state, ACL and live-recusal policy. Deny wins.
- Every mutation requires a caller-supplied idempotency key. Same key plus the same
  canonical request returns a safe result reference; a different request conflicts.
- Modern MCP has one sessionless `POST /mcp` surface. Every request must carry matching
  `MCP-Protocol-Version`, `Mcp-Method`, applicable `Mcp-Name`, and
  `_meta.io.modelcontextprotocol/protocolVersion` plus `clientCapabilities`; every result
  has `resultType`. H tools require `clientCapabilities.elicitation.form` before a stage
  exists, persist the stage, then return embedded `elicitation/create` plus protected
  `requestState`. Only the exact original method/arguments retried under a new request ID
  with byte-identical state and exact `inputResponses` may confirm it. Errors are frozen:
  `-32020` header/body/name mismatch, `-32021 MISSING_REQUIRED_CLIENT_CAPABILITY`, and
  `-32022` unsupported version.
- The `2025-11-25` compatibility profile is read/resource/prompt only. Its listing omits
  every H tool and direct H invocation returns `legacy_read_only` before any stage. The
  SDK input-required legacy shim is disabled.
- Every served resource is authorized before lookup/count/snippet construction and
  appends the two-phase `resource_fetch` evidence required by D2-042.
- Platform self-service is evaluated separately from governance/workflow authority. Every
  identity, including an observer, may use only its own-object
  `prepare_onboarding_attestation`, `revoke_my_session`, `configure_webhook`,
  `rotate_webhook_secret`, `disable_webhook`, and `test_webhook` rows. Observer identities
  are denied every other `D`/`H` governance/workflow row except exactly
  `ask_management`, `follow_up_management_question`, `comment_minutes`,
  `withdraw_minutes_comment`, `propose_minutes_redline`, and `stage_minutes_signature`
  on an entitled exact object. A minutes signature attests the record only and grants no
  governance voting authority.
- “Secretary” means an active compatible `is_secretary` board flag or delegated
  organization secretariat authority. “Admin” never inherits hidden board access.

Scope abbreviations: `G:R governance:read`, `D:R documents:read`, `V:A vote:act`,
`P:M proxy:manage`, `M:A minutes:act`, `MP member:propose`, `S:A secretariat:admin`,
`A:R audit:read`, `MT:A meeting:act`, `T:A task:act`, `D:C documents:contribute`,
`S:M secretariat:message`, `MQ management:question`, `N:M notifications:manage`,
`O:R onboarding:read`.

## 2. MCP tool registry

### 2.1 Context, onboarding and synchronized edge memory

| Tool | Class | Required authority | Object rule | Required evidence/result |
|---|---:|---|---|---|
| `whoami` | R | authenticated or enrollment-limited token | own identity only | safe identity/role/session view; `context_read` |
| `list_my_boards` | R | `G:R` | active memberships only | entitlement-filtered list; no hidden counts |
| `get_board` | R | `G:R` | active membership on board | `resource_fetch` for canonical board metadata |
| `get_my_board_snapshot` | R | `G:R` | one active board membership | bounded metadata/resource references, cursor and entitlement generation |
| `list_my_updates` | R | `G:R` | caller-bound signed cursor | deltas/tombstones only; cursor tamper is a safe denial |
| `list_pending_actions` | R | `G:R` | own entitled objects only | one-call briefing; `revote_required` resolves only by accepted new-vote ballot, terminal/replacement vote, or eligibility loss; includes `minutes_resign_required` until current signature/terminal package |
| `get_onboarding` | R | `O:R` | own role and current terms version | canonical terms, secretary support details and presentation/local-memory questions |
| `get_onboarding_status` | R | `O:R` | own attestation only | current/stale/required state; no other member status |
| `prepare_onboarding_attestation` | H | `O:R`; browser recent-auth completion | own current exact terms | `onboarding_stage_created`, `onboarding_attested`; no comprehension claim |

### 2.2 Boards, charter profile and rulesets

| Tool | Class | Required authority | Object rule | Required evidence/result |
|---|---:|---|---|---|
| `create_board` | H | admin + `S:A` | organization singleton | `board_created`; creates no implicit seats |
| `update_board` | H | admin + `S:A` | nonterminal board | immutable settings version; `board_amended` |
| `archive_board` | H | admin + `S:A` | no open governance action | visibility-only terminal transition; `board_archived` |
| `get_board_governance_profile` | R | `G:R` | board membership | active version/hash and cited source clauses |
| `list_approval_rule_templates` | R | `G:R` | board membership | only active-profile permitted templates |
| `configure_board_governance` | H | admin + `S:A` | cited machine-readable charter sources | immutable activated profile; `governance_profile_activated` |
| `list_matter_types` | R | `G:R` | board membership | active ruleset types/citations |
| `evaluate_matter` | D | secretary/admin + `S:A` | entitled board and strict typed facts | persisted reproducible evaluation; `matter_evaluated` |
| `get_ruleset` | R | `G:R` | board membership | exact version/canonical hash/citations |
| `list_ruleset_versions` | R | `G:R` | board membership | immutable visible version history |
| `validate_ruleset_draft` | R | admin/secretary + `S:A` | owned draft | deterministic validation only; no activation |
| `manage_ruleset` | H | admin + `S:A` | exact version/citations and no ambiguity | `ruleset_amended`; activation/override package is confirmed |

### 2.3 Canonical documents and circulation

| Tool | Class | Required authority | Object rule | Required evidence/result |
|---|---:|---|---|---|
| `list_documents` | R | `D:R` | SQL entitlement predicate before count/page | no excluded existence, count or cursor leak |
| `read_document` | R | `D:R` | exact document/version ACL and no exclusion | exact canonical bytes plus two-phase `resource_fetch` |
| `search_documents` | R | `D:R` | visibility predicate before rank/snippet/count | deterministic PostgreSQL FTS; no server embeddings |
| `get_document_hash` | R | `D:R` | exact version access | SHA-256/media/schema/length only |
| `list_document_versions` | R | `D:R` | document access | immutable entitled versions only |
| `get_document_validation_status` | R | contributor or `D:R` | own contribution or entitled document | loud accepted/rejected reason and remediation |
| `create_document_version` | D | management/secretary + `D:C` | board contribution rights; strict MD/TXT/JSON only | reject unsupported bytes before durable content; `document_version_created` |
| `circulate_document` | H | secretary + `S:A` | accepted immutable version and recipient ACL | `document_circulated` plus one `notice_delivered` per recipient |
| `manage_document_access` | H | secretary/admin + `S:A` | board-bound grants; deny-wins exclusions | `document_access_changed` and removal tombstones |
| `manage_recusal` | H | secretary/admin + `S:A` | named board/person/object or live vote exclusion | `recusal_changed`; invalidations/recalculation under aggregate lock |
| `archive_document` | H | secretary/admin + `S:A` | no rewrite/delete | `document_archived`; normal listings hide it |
| `soft_delete_document` | H | admin + `S:A` | snapshot first; no physical purge | `document_soft_deleted`, permanent tombstone and feed removals |

### 2.4 Management-to-secretariat submissions

| Tool | Class | Required authority | Object rule | Required evidence/result |
|---|---:|---|---|---|
| `submit_document_to_secretariat` | D | management + `D:C` | own board; accepted document versions only | immutable submission version/thread; `management_submission_created` |
| `list_management_submissions` | R | management/secretary + `G:R` | own submissions or secretary board queue | entitlement-filtered queue |
| `get_management_submission` | R | management/secretary + `G:R` | exact thread access | versions, replies and disposition lineage |
| `request_management_revision` | D | secretary + `S:A` | submitted thread | immutable request; `management_revision_requested` |
| `reply_to_management_revision` | D | submitting management + `D:C` | own thread | immutable reply; `management_revision_replied` |
| `resubmit_management_materials` | D | submitting management + `D:C` | new immutable accepted document/submission version | `management_submission_version_created`; linked vote enters pending-source state |
| `approve_management_submission` | D | secretary + `S:A` | submitted version | creates confirmable draft only; `management_submission_approved_to_draft` |
| `reject_management_submission` | D | secretary + `S:A` | submitted version; reason required | `management_submission_rejected`; no deletion |

### 2.5 Permanent questions to management

| Tool | Class | Required authority | Object rule | Required evidence/result |
|---|---:|---|---|---|
| `ask_management` | D | voting member **or observer** + `MQ` | entitled board, ACL-safe citations, responsible owner and due time | immutable question; `management_question_asked`; management pending action |
| `list_management_questions` | R | `G:R` | visible threads only; role/ACL/recusal filter before count | pending/overdue/answered state without hidden totals |
| `get_management_question` | R | `G:R` | visible exact thread | immutable turns/citations/delivery lineage |
| `answer_management_question` | D | assigned management + `MQ` | pending/overdue visible thread; nonblank answer | immutable answer; `management_question_answered`; cannot answer by status flip; a new turn beyond an open linked package cutoff enters source-update pending |
| `follow_up_management_question` | D | entitled voting member **or observer** + `MQ` | visible thread | immutable follow-up; `management_question_followed_up`; reopens management action and, only when thread is linked to an open package, source-update pending |

### 2.6 Meetings, agendas and attendance

| Tool | Class | Required authority | Object rule | Required evidence/result |
|---|---:|---|---|---|
| `list_meetings` | R | `G:R` | board membership and ACL | entitled meetings only |
| `get_agenda` | R | `G:R` | meeting/agenda/document access | exact immutable agenda version/resources |
| `rsvp` | D | nonobserver board seat + `MT:A` | called, nonterminal meeting and own response | append/update with history; `meeting_rsvp_recorded` |
| `get_attendance` | R | `G:R` | board membership | recorded evidence; never inferred from RSVP |
| `create_meeting` | H | secretary + `S:A` | final canonical package from guided draft | `meeting_called` plus one recipient notice |
| `amend_meeting` | H | secretary + `S:A` | called/nonterminal; immutable replacement version | `meeting_amended`; stale stages invalidated and recipients re-noticed |
| `record_attendance` | D | secretary + `S:A` | called/completed meeting and listed participant | `meeting_attendance_recorded`; correction uses a new record |
| `correct_attendance` | H | secretary + `S:A` | exact prior record and reason | linked correction; `meeting_attendance_corrected` |
| `cancel_meeting` | H | secretary + `S:A` | nonterminal meeting | `meeting_cancelled`; terminal and re-noticed |
| `complete_meeting` | H | secretary + `S:A` | called meeting | `meeting_completed`; terminal evidence snapshot |

### 2.7 Machine-readable transcript annexes

| Tool | Class | Required authority | Object rule | Required evidence/result |
|---|---:|---|---|---|
| `list_meeting_transcripts` | R | `G:R` | meeting access | versions and loud verification state |
| `get_meeting_transcript` | R | `G:R` | meeting/transcript ACL | canonical MD/strict-JSON turns; `resource_fetch` |
| `create_meeting_transcript_version` | D | secretary + `S:A` | meeting; machine-readable text only | immutable `agent_prepared_unverified` annex; `transcript_version_created` |
| `verify_meeting_transcript` | H | secretary + `S:A` | exact annex hash/version | `transcript_secretary_verified`; no claim about original audio |
| `link_meeting_qna` | H | secretary + `S:A` | exact transcript turns and D2-062 threads | immutable link; `transcript_qna_linked`; unanswered turns create management actions |
| `challenge_transcript_turn` | D | entitled nonobserver participant + `S:M` | exact visible turn | immutable challenge; `transcript_turn_challenged` |
| `resolve_transcript_challenge` | H | secretary + `S:A` | challenge plus corrected new version | `transcript_challenge_resolved`; never rewrites old turn |

### 2.8 Votes, proxies and certificates

| Tool | Class | Required authority | Object rule | Required evidence/result |
|---|---:|---|---|---|
| `list_votes` | R | `G:R` | board membership and tally-visibility policy | no hidden vote/statement/interim-count leak |
| `get_vote` | R | `G:R` | exact vote access | canonical package/hash/rule and authorized tally state |
| `get_vote_lineage` | R | `G:R` | access to linked votes | draft/open/superseded/replacement IDs and hashes |
| `stage_ballot` | H | eligible voting seat + `V:A` | open, unrecused, current package; own or valid proxy principal | MRTR confirmation; `stage_created`, `elicitation_sent`, `consent_recorded`, `ballot_cast` |
| `grant_proxy` | H | eligible principal + `P:M` | open vote, permitted holder, no chain/cycle | `proxy_granted`; no pre-consent grant row |
| `revoke_proxy` | H | principal + `P:M` | own active grant and frozen policy | `proxy_revoked`; effects explicit/audited |
| `get_proxy_status` | R | principal/holder/secretary + `G:R` | exact vote and relationship | safe attribution/status only |
| `get_vote_certificate` | R | `G:R` or `A:R` | board-authorized vote | persisted recomputed bundle and signature |
| `verify_certificate` | R | authenticated | supplied/visible certificate | persisted-data recomputation; generic reason class |
| `create_vote` | H | secretary + `S:A` | completed guided package/profile-permitted rule | `vote_opened`, package/electorate freeze, per-member notices |
| `amend_resolution_text` | H | secretary + `S:A` | draft creates version; open vote invokes replacement invariant | `resolution_amended`; when open also `vote_superseded`/new `vote_opened` |
| `replace_open_vote` | H | secretary + `S:A` | open or source-update-pending vote and exact replacement package | atomically disposes every old act, creates new open vote/electorate/package, `vote_opened`, per-newly-eligible notice/`notice_delivered`, informational `vote_replaced`, and actionable `revote_required` only for still-eligible prior principals |
| `exclude_pending_vote_source` | H | secretary + `S:A` | exact pending source with nonblank reason | `vote_source_excluded`; original package remains byte-identical |
| `extend_vote_deadline` | H | secretary + `S:A` | draft version or open-vote replacement only | no in-place open extension; replacement events/notices |
| `close_vote` | H | secretary + `S:A`; only for `secretariat_confirmed` close mode | exact open vote, healthy clock, one tally kernel | `vote_closing`, signed certificate, then `vote_closed` atomically recoverable; automatic close is an internal typed worker operation, never this MCP tool |
| `cancel_vote` | H | secretary + `S:A` | open/draft, exact reason | `vote_cancelled`; terminal, acts retained non-outcome-bearing |

### 2.9 Minutes and signatures

| Tool | Class | Required authority | Object rule | Required evidence/result |
|---|---:|---|---|---|
| `get_minutes` | R | `G:R` | meeting/minutes access | exact version/hash/transcript annex refs |
| `list_minutes_versions` | R | `G:R` | minutes access | immutable visible versions |
| `get_minutes_lineage` | R | `G:R` | access to original/correction aggregates | immutable package/correction IDs, versions, hashes and terminal states |
| `create_minutes_version` | D | secretary + `S:A` | unpublished draft only; accepted canonical text/transcript refs | `minutes_version_created`; no publication; published/finalized input rejects |
| `publish_minutes` | H | secretary + `S:A` | exact unpublished draft version and proposed signer set | enters `published_review`; `minutes_published`, per-recipient review notices |
| `list_minutes_review_items` | R | entitled participant + `G:R` | exact visible minutes package | immutable comments/redlines/withdrawals/dispositions only |
| `comment_minutes` | D | entitled voting member **or observer** + `M:A` | current `published_review` package; strict `boardagent.minutes-comment.v1`, exact base hash and anchor | immutable comment; `minutes_commented` |
| `withdraw_minutes_comment` | D | entitled comment author, including observer + `M:A` | own pending comment on current `published_review` package | immutable `minutes_review_withdrawn`; text remains permanent |
| `propose_minutes_redline` | D | entitled voting member **or observer** + `M:A` | current `published_review` package; strict `boardagent.minutes-redline.v1`; exact base/version/line anchor/old-text hash; no attachment | `minutes_redline_proposed`; never applies content itself |
| `resolve_minutes_review_item` | H | secretary + `S:A` | exact pending nonwithdrawn item and reason; redline acceptance supplies canonical replacement | `minutes_review_dispositioned`; accepted redline creates version/diff and returns the new package to review |
| `correct_minutes_package` | H | secretary + `S:A` | published/signature-ready but nonfinalized current package | new immutable version; `minutes_package_corrected`; supersedes stale draft actions/stages/signatures, returns to review and emits current re-sign notices |
| `prepare_minutes_for_signature` | H | secretary + `S:A` | all review items dispositioned; exact action-items-or-none declaration and signer set | freezes package; `minutes_signature_package_issued` |
| `stage_minutes_signature` | H | configured entitled voting member **or observer** + `M:A` | exact current minutes/package hash | standard MRTR; `minutes_signed`; observer attestation is non-voting |
| `finalize_minutes` | H | secretary + `S:A` | required current-package signatures complete | `minutes_action_items_activated` plus `minutes_finalized`; activation manifest is bound; terminal |
| `create_minutes_correction_cycle` | H | secretary + `S:A` | exact finalized minutes, correction reason and new canonical package | original stays terminal; new linked aggregate enters `published_review`; `minutes_correction_cycle_created` |
| `cancel_minutes` | H | secretary + `S:A` | nonfinalized package and reason | `minutes_cancelled`; immutable terminal history |

### 2.10 Tasks, proposals and secretariat messages

| Tool | Class | Required authority | Object rule | Required evidence/result |
|---|---:|---|---|---|
| `list_my_tasks` | R | `G:R` | own assigned tasks | own evidence/status only |
| `list_action_items` | R | `G:R` | board/minutes ACL; observers read entitled items | status/owner/due/source/evidence refs without hidden counts |
| `get_task` | R | `G:R` | assignee, entitled board participant or secretary/creator | exact task/evidence lineage subject to source ACL |
| `get_action_item` | R | `G:R` | exact entitled minutes-linked task | source minutes/version/hash, owner, due, evidence/review/closure lineage |
| `log_minutes_action_items` | H | secretary + `S:A` | exact review-resolved minutes version; structured nonempty list | immutable **draft** tasks/manifests; `minutes_action_items_declared`; no extraction/owner notice before finalization |
| `declare_no_minutes_action_items` | H | secretary + `S:A` | exact review-resolved minutes version | explicit hashed declaration; `minutes_action_items_declared` |
| `create_task` | H | secretary + `S:A` | active board/member and canonical assignment | `task_created`; assignee pending action |
| `start_task` | D | assignee + `T:A` | own open task | `task_started` |
| `submit_task_evidence` | D | assignee + `T:A` | own nonterminal task; canonical evidence refs only | immutable evidence; `task_evidence_submitted` |
| `review_task_evidence` | H | secretary + `S:A` | pending exact evidence; reason required | `task_evidence_reviewed`; rejection preserves evidence and returns item to open |
| `complete_task` | H | secretary + `S:A` | exact minutes/task basis and at least one accepted evidence hash | `task_completed`; closure hash binds all accepted evidence; terminal |
| `create_task_correction_cycle` | H | secretary + `S:A` | exact completed task, reason and new canonical task/evidence requirements | completed original remains terminal; linked open cycle; `task_correction_cycle_created` |
| `cancel_task` | H | secretary + `S:A` | nonterminal and reason | `task_cancelled`; terminal |
| `propose_action` | D | voting member/management + `MP` | active board and strict proposal schema | `proposal_submitted`; never executes |
| `withdraw_proposal` | D | proposer + `MP` | own pending proposal | `proposal_withdrawn`; payload retained |
| `list_proposals` | R | secretary + `S:A` | board queue | entitled proposals only |
| `approve_proposal` | D | secretary + `S:A` | pending proposal | `proposal_approved_to_draft`; creates draft only |
| `reject_proposal` | D | secretary + `S:A` | pending proposal and reason | `proposal_rejected` |
| `ask_secretariat` | D | nonobserver member/management + `S:M` | active board | immutable request; `secretariat_request_created` |
| `list_secretariat_requests` | R | requester or secretary + `G:R` | own request or board queue | no cross-board visibility |
| `reply_secretariat_request` | D | secretary + `S:A` | board request | immutable response; `secretariat_request_replied` |
| `close_secretariat_request` | D | requester or secretary + `S:M` | answered request only | `secretariat_request_closed`; no deletion |

### 2.11 Members, enrollment, sessions and clients

| Tool | Class | Required authority | Object rule | Required evidence/result |
|---|---:|---|---|---|
| `list_members` | R | secretary/admin + `S:A` | organization/board administrative view | minimal identities/roles; no credential material |
| `get_member` | R | own identity or secretary/admin + `S:A` | exact authorized member | accountable principal shown for AI observer |
| `manage_member` | H | admin + `S:A` | invite/role/weight/suspend/remove/reactivate exact change | `member_changed`; existing sessions revoked when required |
| `issue_enrollment` | H | secretary/admin + `S:A` | precreated seat; no active invitation | one-time reference/QR payload only once; `enrollment_issued` |
| `list_enrollments` | R | secretary/admin + `S:A` | organization | status/expiry only, no bearer material |
| `revoke_enrollment` | H | secretary/admin + `S:A` | exact live invitation | `enrollment_revoked` |
| `confirm_enrollment_activation` | H | secretary/admin + `S:A` | pending seat, exact 10-minute human code and identity-proof method | `member_activated`; never approves link possession alone |
| `initiate_identity_recovery` | H | secretary/admin + `S:A` | verified person/seat and reason | old sessions/credentials handled explicitly; `identity_recovery_started` |
| `list_my_sessions` | R | authenticated | own sessions only | client/time/status; token values absent |
| `revoke_my_session` | H | authenticated recent auth | own named refresh family/session | `session_revoked` |
| `list_oauth_clients` | R | admin + `S:A` | deployment | safe client metadata/status only |
| `block_oauth_client` | H | admin + `S:A` | exact server-issued client ID | grants/families revoked; `oauth_client_blocked` |
| `unblock_oauth_client` | H | admin + `S:A` | exact blocked client | `oauth_client_unblocked`; no implicit grants |
| `link_external_identity` | H | admin + `S:A` and browser subject proof | existing invited member and exact issuer/subject | `external_identity_linked` |
| `unlink_external_identity` | H | admin + `S:A` | preserve at least one recovery path | `external_identity_unlinked` and sessions revoked |

### 2.12 Audit, export, webhooks and permanent-record policy

| Tool | Class | Required authority | Object rule | Required evidence/result |
|---|---:|---|---|---|
| `export_audit_chain` | H | `A:R` + recent auth | authorized organization/board scope | async frozen request; `export_requested` |
| `verify_audit_chain` | R | `A:R` | authorized chain/chunk or supplied export | recompute and report first break |
| `export_system_data` | H | admin + `S:A` + recent auth | explicit frozen scope | excludes all secret material; `export_requested` |
| `get_export_status` | R | requesting principal + original scope | unguessable request ID | state/manifest hash only |
| `read_export_chunk` | R | requesting principal + original scope + recent auth | ready artifact and bounded chunk | exact chunk hash plus `resource_fetch` |
| `cancel_export` | H | requesting principal + original authority | queued/running request | `export_cancelled`; partial artifacts quarantined |
| `delete_export_artifact` | H | requesting principal + original authority | ready artifact | artifact destroyed, permanent receipt/hash; `export_artifact_deleted` |
| `get_retention_policy` | R | `A:R` or admin + `S:A` | deployment | reports indefinite record retention and expiring ephemera classes |
| `list_my_webhooks` | R | `N:M` | own member endpoints | URL redacted; secret absent |
| `configure_webhook` | H | `N:M` + recent auth | own HTTPS public endpoint; SSRF checks | one-time secret display; `webhook_configured` |
| `rotate_webhook_secret` | H | `N:M` + recent auth | own endpoint | old secret invalidated; new secret never idempotently replayed |
| `disable_webhook` | H | `N:M` | own endpoint | `webhook_disabled` |
| `test_webhook` | D | `N:M` | own verified endpoint | contentless test wake-up; `webhook_tested` |

### 2.13 Wizard draft lifecycle

| Tool | Class | Required authority | Object rule | Required evidence/result |
|---|---:|---|---|---|
| `list_my_drafts` | R | secretary/management/member according to draft type | own nonexpired drafts | safe summaries only |
| `resume_draft` | R | original creator plus current authority | signed draft/client binding; client portability policy | exact current step/package; no mutation |
| `cancel_draft` | D | original creator | own active draft | `draft_cancelled`; immutable answers retained |

## 3. MCP resource templates

All resources are private and `Cache-Control: private, no-store`; an HTTP cache or
resource list never becomes an authorization oracle.

| URI template | Representations | Entitlement root |
|---|---|---|
| `board://{boardId}` | canonical JSON metadata | board membership |
| `board://{boardId}/governance-profile/{version}` | canonical JSON + cited clauses | board membership |
| `board://{boardId}/rulesets/{version}` | canonical JSON | board membership |
| `board://{boardId}/documents/{documentId}/versions/{version}` | exact UTF-8 MD/TXT or canonical typed JSON | document ACL minus exclusion |
| `board://{boardId}/submissions/{submissionId}/versions/{version}` | canonical JSON/resource refs | management thread policy |
| `board://{boardId}/questions/{questionId}` | canonical immutable-turn JSON | question ACL minus exclusion |
| `board://{boardId}/meetings/{meetingId}/agendas/{version}` | canonical JSON/resource refs | meeting/document policy |
| `board://{boardId}/meetings/{meetingId}/transcripts/{version}` | canonical MD or typed turn JSON | meeting/transcript policy |
| `board://{boardId}/minutes/{minutesId}/versions/{version}` | exact canonical text/package JSON | minutes policy |
| `board://{boardId}/minutes/{minutesId}/review/{itemId}` | strict comment/redline/disposition JSON | minutes participant policy |
| `board://{boardId}/action-items/{taskId}` | canonical task/source/evidence/closure JSON | source minutes/task ACL |
| `board://{boardId}/votes/{voteId}` | canonical vote metadata | vote policy |
| `board://{boardId}/votes/{voteId}/packages/{version}` | exact decision-package JSON + hashes | vote/document/Q&A intersection |
| `board://{boardId}/votes/{voteId}/certificates/{certificateId}` | signed bundle | authenticated certificate policy |
| `board://{boardId}/tasks/{taskId}` | canonical task/evidence refs | assignee/secretariat policy |
| `export://{exportId}/chunks/{chunkNo}` | encrypted/bounded exact bytes | original requester/scope/recent auth |

## 4. MCP prompt registry

Prompts are thin, nonauthoritative instructions; they contain no frozen governance
answer. The corresponding tool drives all questions and final confirmation.

| Prompt | Intended flow |
|---|---|
| `onboard-boardagent` | Explain agent-only responsibilities, ask desired presentation/local-memory form, surface secretary support, then prepare exact attestation. |
| `set-vote` | Start/resume the cited-rule vote wizard ending in `create_vote`. |
| `call-meeting` | Start/resume the meeting wizard ending in `create_meeting`. |
| `circulate-document` | Validate/select canonical material and recipients ending in `circulate_document`. |
| `record-minutes` | Build minutes and optional machine-readable transcript annex, require structured action-items-or-none, run machine-readable review/redline disposition, then issue the signature package. |
| `configure-ruleset` | Build/validate cited typed rules ending in `manage_ruleset`. |
| `ask-management` | Collect a scoped question, citations, responsible management owner and due time ending in `ask_management`. |

## 5. Browser/HTTP surface

These are the only browser pages. There is no board portal, dashboard, document reader
or governance UI.

| Surface | Authority and behavior |
|---|---|
| `POST /mcp` | exact sessionless MCP `2026-07-28`; bounded `2025-11-25` read/resource/prompt profile on the same canonical resource |
| `/.well-known/oauth-protected-resource/mcp` | public path-aware RFC 9728 metadata whose `resource` is exactly normalized `https://host/mcp`; every 401 challenge points here |
| authorization-server metadata and JWKS | public protocol metadata/current+retired verification keys |
| CIMD client-ID resolution and `/oauth/register` | outbound CIMD resolution is SSRF-hardened; DCR fallback is open, rate-limited and audited; protocol client ID and internal UUID remain distinct |
| `/oauth/authorize`, `/oauth/token`, `/oauth/revoke` | code+S256 PKCE, exact resource, rotated refresh; no query bearer token |
| `/auth/passkey/*`, `/auth/totp/*`, `/auth/oidc/*` | minimal hardened interactions, exact RP/origin/state/nonce/session binding |
| `/enroll/{opaque}` | one-use invite redemption to pending activation; link alone grants nothing |
| `/onboarding/{opaque}` | exact current terms and secure attestation after identity activation |
| `POST /verify/certificate` | rate-limited unguessable bundle/ID, persisted-data recomputation, generic verdict |
| `/health/live`, `/health/ready` | no secret/config/data disclosure; readiness includes schema/key/storage invariants |
| `/metrics` | disabled or separately operator-authenticated; no protected identifiers |

## 6. CLI registry

| CLI | Authority path |
|---|---|
| `bootstrap` | sole preidentity exception; local operator, one-use singleton transaction, creates organization/first admin-secretary/invite and audit event |
| `migrate` / `migration-check` | separate DB migrator role; checksum/advisory-lock/forward-only production policy |
| `export` | online authenticated principal invoking the same export service and `H` policy; never direct DB dump |
| `verify-chain` | offline read-only verifier over exported bytes |
| `verify-certificate` | offline read-only stateless verifier over bundle/public keys |
| `backup` | separate operator role, consistent DB/WAL manifest and encrypted destination; no governance mutation |
| `restore-check` | isolated read-only full integrity validation; never repairs evidence |
| `worker` | service principal limited to typed jobs; cannot mint tokens or bypass board/object IDs |

## 7. Closed event registry

Each event has a versioned strict payload schema. The generated test maps every event to
its trigger, transaction boundary and at least one positive and negative vector.

### Protocol, identity and policy

`context_read`, `client_registered`, `client_registration_rejected`, `oauth_client_blocked`,
`oauth_client_unblocked`, `token_issued`, `token_refreshed`, `token_reuse_detected`,
`session_revoked`, `enrollment_issued`, `enrollment_redeemed`,
`enrollment_revoked`, `member_activated`, `identity_recovery_started`,
`external_identity_linked`, `external_identity_unlinked`, `member_changed`,
`onboarding_stage_created`, `onboarding_attested`, `onboarding_stale`,
`authorization_denied`, `rate_limited`.

### Record delivery, documents and communications

`resource_fetch`, `notice_delivered`, `document_version_created`,
`document_circulated`, `document_access_changed`, `document_archived`,
`document_soft_deleted`, `recusal_changed`, `management_submission_created`,
`management_revision_requested`, `management_revision_replied`,
`management_submission_version_created`, `management_submission_approved_to_draft`,
`management_submission_rejected`, `management_question_asked`,
`management_question_answered`, `management_question_followed_up`,
`secretariat_request_created`, `secretariat_request_replied`,
`secretariat_request_closed`.

### Governance, consent and evidence

`board_created`, `board_amended`, `board_archived`,
`governance_profile_activated`, `matter_evaluated`, `ruleset_amended`,
`rule_overridden`, `stage_created`, `stage_replaced`, `elicitation_sent`,
`consent_recorded`, `consent_rejected`, `ballot_cast`, `ballot_superseded`,
`proxy_granted`, `proxy_revoked`, `resolution_amended`, `vote_opened`,
`vote_source_update_pending`, `vote_source_excluded`, `vote_closing`,
`vote_closed`, `vote_cancelled`, `vote_superseded`, `vote_replaced`,
`revote_required`, `certificate_issued`, `certificate_corrected`,
`meeting_called`, `meeting_amended`, `meeting_rsvp_recorded`,
`meeting_attendance_recorded`, `meeting_attendance_corrected`,
`meeting_completed`, `meeting_cancelled`, `transcript_version_created`,
`transcript_secretary_verified`, `transcript_qna_linked`, `transcript_turn_challenged`,
`transcript_challenge_resolved`, `minutes_version_created`, `minutes_published`,
`minutes_commented`, `minutes_review_withdrawn`, `minutes_redline_proposed`,
`minutes_review_dispositioned`, `minutes_package_corrected`,
`minutes_correction_cycle_created`, `minutes_action_items_declared`,
`minutes_action_item_draft_superseded`, `minutes_action_items_activated`,
`minutes_signature_package_issued`, `minutes_signed`, `minutes_signature_superseded`,
`minutes_resign_required`, `minutes_finalized`, `minutes_cancelled`.

### Workflow, export and operations

`task_created`, `task_started`, `task_evidence_submitted`,
`task_evidence_reviewed`, `task_completed`, `task_correction_cycle_created`, `task_cancelled`,
`proposal_submitted`, `proposal_withdrawn`, `proposal_approved_to_draft`,
`proposal_rejected`, `draft_cancelled`, `draft_expired`, `export_requested`,
`export_started`, `export_performed`, `export_failed`, `export_cancelled`,
`export_artifact_deleted`, `webhook_configured`, `webhook_secret_rotated`, `webhook_disabled`,
`webhook_tested`, `webhook_delivery_attempted`, `audit_checkpoint_signed`,
`audit_verification_failed`, `migration_applied`, `backup_completed`,
`restore_verified`.

An event absent from this registry cannot be emitted. A state mutation lacking its
required registered event in the same transaction cannot commit.
