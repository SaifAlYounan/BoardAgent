# BoardAgent known limitations

This ledger is part of every release handoff. It distinguishes an intentional v1
boundary from an unresolved release prerequisite. A deployment may accept the documented
design boundaries and residual risks; it may not relabel an open item as passed.

| Item                                                   | Class                                  | Current disposition                                                                                                                                                                | Owner / release consequence                                                                                                      |
| ------------------------------------------------------ | -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Independent security and deployment-legal review (T10) | Public-release blocker                 | An earlier version failed its independent review. The findings were repaired; no independent review of the current tree has been completed.                                        | Independent reviewer and the project owner. The current tree has no release label.                                               |
| Production acceptance (Gate 3)                         | Go-live blocker                        | Final acceptance is pending for the exact final manifest, source and image digests.                                                                                                | The project owner. Synthetic trials do not fabricate final acceptance.                                                           |
| Deployment                                             | External action, not build evidence    | Passing tests do not deploy anything. Every deployment must be qualified on its own host with its own providers and checked before each update.                                    | Authorized operator. Synthetic tests do not establish real-provider or real-data readiness.                                      |
| Client/agent integrity                                 | Residual trust risk                    | A compromised or auto-approving client can mispresent material or misuse valid authority. Exact multi-round-trip confirmation and refetch reduce but cannot eliminate this risk.   | Each principal and client operator; disclose during onboarding and incident response.                                            |
| Agent-owned derived memory                             | Intentional boundary and residual risk | BoardAgent has no shared semantic memory. Local agent memory can be stale, poisoned, or retained after access changes, so it is never authoritative.                               | Each principal/client; preserve provenance, refetch before action, process tombstones. See ADR 0005.                             |
| Human understanding and legal effect                   | Intentional non-claim                  | Delivery, attestation, consent, signature and certificate evidence do not prove reading, comprehension, independent judgment, QES/notarization, enforceability, or legal validity. | Human participants and deployment-specific legal/governance review.                                                              |
| Server AI and semantic validation                      | Intentional v1 exclusion               | There is no server model, vector store, OCR, semantic search, deception detection, conflict detection, or automated governance judgment.                                           | Agents present exact canonical records; humans assess substance. Adding server AI requires an explicitly reviewed design change. |
| Content formats                                        | Intentional v1 constraint              | Canonical machine-readable content is accepted; DOCX/PDF/binary attachments, tracked changes, fuzzy patches, formulas and active content are rejected.                             | Secretariat converts material outside BoardAgent and verifies exact canonical text/hash.                                         |
| Availability and scale                                 | Accepted beta topology risk            | One hardened server remains one failure domain. The frozen synthetic envelope is 25 boards, 1,000 seats, 100k document versions, 1m audit events and 1m feed events.               | Operator monitors thresholds; exceeding them triggers a scale ADR, not silent sharding.                                          |
| Backup/export key custody                              | Residual operational risk              | Symmetric KEK loss makes ciphertext unrecoverable; disclosure exposes protected artifacts. Rotation does not recover a lost historical key.                                        | Recovery custodian under dual control, off-host copies and quarterly restore drills.                                             |
| External providers                                     | Residual deployment risk               | OIDC, UAE Pass, DNS, TLS, KMS/HSM and optional webhook assurances inherit provider, network and account compromise risks.                                                          | Deployment operator and independent reviewer validate exact providers and failover before relying on them.                       |
| Audit external time/witness                            | Intentional v1 constraint              | Hash chaining and signatures expose later inconsistency but do not prevent database-owner destruction or provide public timestamping/notarization.                                 | Protect checkpoints/exports off-host. A transparency or notarization service is a future capability.                             |
| Retention and deletion                                 | Intentional v1 boundary                | Governance/content/audit history is retained indefinitely. Deletion is visibility-only; there is no physical purge callable in v1.                                                 | Deployment-specific records/privacy review must accept this before real data.                                                    |
| Operational objectives                                 | Must be exercised per deployment       | RPO ≤15 minutes and drill RTO ≤4 hours are measured objectives, not guarantees. Synthetic clean-room recovery proves the mechanism only.                                           | Operator records live backup continuity and quarterly restore results.                                                           |

## Open engineering limitations

- **Real human enrollment (SR-102).** Every enrollment, activation and recovery path is
  proven with scripted authenticators, which are not proof of a real person. The
  requirement stays unresolved until real people enrol.
- **Nesting limit.** Canonical JSON and complete tool inputs are limited to 512 nested
  object or array containers. A root container counts as one and scalar values count
  as zero. The limit is checked before recursive processing, and cyclic values are
  rejected. Existing byte, field and ruleset expression limits apply independently.
- **Response memory policy.** Document, export, transcript, list, search, governance
  JSON and projection reads reserve from a process-local allocation budget after
  authorized metadata selection and before content loading, and the server admits at
  most 128 concurrent native `/mcp` dispatches before loading a body. Allocation units
  cap admitted work; they do not bound resident memory. PostgreSQL headline, rank,
  full-text-search and detoast workspace lies outside this policy. A single serialized
  JSONB resource larger than the large-work budget is refused even when the process is
  otherwise idle, and waiting does not remove that refusal. Production memory capacity
  has not been qualified; see `artifacts/server/src/response-allocation.ts`.
- **Authority freshness within a request.** Authority is re-resolved at every request
  boundary. A request that was already admitted completes under its admitted context,
  so a membership change or token revocation committed during a running read may not
  affect that read. No statement-fresh guarantee is claimed. The disposition is
  recorded in `docs/decisions/revocation-timing-disposition-2026-09.md`.
- **Management-question exclusions** use the request transaction timestamp: an
  exclusion whose effective time is later than the request is applied from the next
  request.
- **Activation restart** for an expired or exhausted activation challenge is supported
  through `reissue_activation`, `bootstrap reissue-first-activation` and the one-use
  `/enroll/restart` page (runbook 32). The restart itself activates nothing, and
  active-person replacement-passkey recovery is unchanged.

The release handoff hashes this file. Any changed limitation, accepted residual, new
provider, new content type, new memory or AI capability, broader scale target or weaker
verification threshold invalidates the prior handoff and requires documented change
review. Only the project owner may accept the resulting release posture.
