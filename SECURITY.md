# BoardAgent security policy and boundaries

## Status

BoardAgent is an open-source beta. Use synthetic information only. It is not
production-ready, and nothing in this repository is a security certification or an
approval to use real board data. The [verification register](docs/VERIFICATION.md) maps
each security requirement to its implementation and executing test, and the
[limitations ledger](docs/KNOWN_LIMITATIONS.md) records what is deliberately out of
scope and what remains open.

## Open items

These are separate from the intentional v1 limitations and from the tests that pass:

- **Real human enrollment (SR-102).** Every enrollment, activation and recovery path is
  proven with scripted authenticators. Scripted cryptographic authenticators are not
  proof of a real person, so the requirement stays unresolved until real people enrol.
- **Memory capacity.** Document, export, transcript, search and list reads reserve from
  a process-local allocation budget before loading content, and the server admits at
  most 128 concurrent native `/mcp` dispatches. Allocation units and dispatch counts do
  not guarantee a resident-memory bound. Production memory capacity has not been
  qualified.
- **Independent external review (T10).** An earlier version failed an independent
  review; the findings were repaired and the repairs are covered by executing tests. No
  independent review of the current tree has been completed. An AI-assisted review or a
  synthetic test result does not replace it.

## Supported versions and deployment responsibility

No generally available, maintained release or security-support timetable is declared
here. Select an exact qualified source/image from its release evidence rather than
assuming the latest branch is safe. The deployment owner must name the operator,
security contact and private incident route, and arrange updates, monitoring, tested
recovery and acceptance. The repository does not supply a hosted security service.

## Reporting a suspected vulnerability

Report suspected vulnerabilities in the BoardAgent software through GitHub private
vulnerability reporting on this repository:
<https://github.com/SaifAlYounan/BoardAgent/security/advisories/new>. Do not open a
public issue. Include the affected version or commit, the observable behaviour and
reproduction steps that do not disclose board content. Do not include secrets, access
tokens, enrollment links, authenticators, private keys, board material or a working
exploit against someone else's deployment.

Report suspected compromise of a specific deployment privately to that deployment's
named security contact through its agreed out-of-band channel. If no security contact
has been commissioned, stop using the affected deployment and escalate to its
deployment owner. The project makes no response-time promise.

## Security model

BoardAgent treats the following as separate trust boundaries:

- the human and their chosen MCP client/agent;
- the browser used for enrollment, authentication and onboarding attestation;
- the HTTPS edge and DNS;
- the BoardAgent server process;
- the least-privilege worker process;
- PostgreSQL roles, RLS, migrations, and persistent state;
- blob/export storage;
- operator secrets and recovery storage;
- external OIDC providers and webhook destinations.

Authorization is enforced against server-side identity, board membership, role,
confidentiality, recusal, record state, exact resource, and transaction context. The
agent's prose, a client display name, a requested role, or possession of a record ID is
never sufficient authority.

## Human confirmation

Binding human acts use a one-use server-attested confirmation protocol over exact
canonical content. Staging is not approval. Displaying a summary is not approval. A retry
cannot reuse a consumed or expired confirmation to authorize a second mutation. An exact
completed-request retry may return its original safe result where the supported workflow
allows it and current authority still passes. Changed content or an uncompleted expired
stage needs fresh preparation and confirmation.

This mechanism proves that the authenticated confirmation path accepted exact bytes under
the then-current authority. It does **not** prove that the person read, understood, or
legally consented to the content; that their local agent represented it faithfully; or
that the act has any particular legal status.

Binding action confirmations are presented by the MCP client, not a BoardAgent governance
web page. The server validates bound confirmation inputs; it cannot prove which lines
the client displayed or whether a human, automation or compromised client answered.
Client mispresentation and automatic approval remain residual risks even when the server
records a valid confirmation.

## Authentication and identity

- Production OAuth tokens are ES256-signed, short-lived, audience/resource bound, and
  checked against persisted client, session, identity, and key state.
- Built-in authentication binds enrollment to a real browser ceremony, WebAuthn, and the
  exact origin. TOTP is an explicit fallback with throttling and replay protection.
- Enrollment and recovery artifacts are short-lived, single-use credentials. Ordinary
  enrollment activation requires an authorized administrator/secretariat action and
  the member’s own browser ceremony. The supported first-account bootstrap uses its
  separate operator-plus-person activation procedure; it is not general account recovery.
- An authorized company administrator links an exact OIDC issuer/subject to an existing
  member. A secretary title alone cannot grant that link. Unknown subjects never auto-provision.
- Sessions, clients, members, external identities, and keys can be blocked or revoked;
  stale tokens must not outlive the persisted state change.

A compromised browser, authenticator, agent host, or authorized member can still exercise
that principal's legitimate powers until contained. BoardAgent cannot secure local copies
made by a client.

BoardAgent intentionally has no central semantic memory. A shared mutable brain could let
an operator or management layer bias every agent's recollection, leak excluded matters, or
preserve stale interpretation as fact. Optional derived memory belongs to each principal's
client, never grants authority, and must be source-tagged/refetched. Local memory can also
be compromised, so binding acts always return to canonical server records. The complete
decision and future-change bar are in
[ADR 0005](docs/adr/0005-agent-owned-derived-memory.md).

## Content and data handling

Only strict, bounded, canonical Markdown, plain text, and declared versioned JSON cross
the content boundary. Binary office formats, PDFs, images, scans, archives, executable
content, external URLs masquerading as uploads, and invalid Unicode are rejected. There
is no OCR, conversion, extraction, content preview service, or server-side AI.

Canonical acceptance is a technical format decision, not a claim that content is true,
safe, complete, accessible, lawful, or suitable for a board decision. Clients must not
silently reinterpret or summarize authoritative bytes.

## Records, audit, and evidence

Governance mutations append canonical audit events chained by SHA-256. Signed checkpoints
anchor chain state. Vote certificates bind the exact decision package, eligible set,
ballots/tally, governing rule, override, source set, close outcome, and evidence key.

Authenticated verification uses BoardAgent records. The public certificate endpoint
accepts only an opaque public ID or a bounded exported bundle, is rate-limited before deep
work, and returns a generic validity result. Offline verification requires an independently
trusted evidence-public-key set; a key included only inside an untrusted bundle is not a
trust anchor.

Audit export verification checks canonical parsing, event hashes, chain links, sequence
range, checkpoint signatures, snapshot anchors, and first-break location. Export packages
are encrypted and bind their frozen scope. Historical evidence still depends on safe
custody of exported bundles and authentic public keys; BoardAgent has no external
timestamp authority or public transparency log in v1.

Evidence words are intentionally narrow. A `resource_fetch` preparation record proves that
the server committed the exact URI/hash/length for a response attempt; the completion or
interruption record that follows proves only what the server could observe about the
transport, not that the bytes reached a person. `notice_delivered`
means a notice was committed to the recipient's BoardAgent feed/channel handoff. Neither
term proves that an agent rendered it or a person received, read, or understood it.

## Confidentiality and recusal

Database RLS and transaction-scoped actor context provide a mandatory backstop to
application authorization. Recusal and confidentiality exclusions apply across lists,
ordinary reads, search, feeds, pending actions, notifications, and direct-ID access.
Existence-oblivious denials are used where revealing existence would leak protected state.

Privileged system and audit archives follow their explicitly authorized frozen export
scope and retain historical records; they are not a copy of the requester's ordinary
document view. A confirmed export may continue building after requester authority changes.
Status and chunk retrieval recheck the requesting person's current authority and the
artifact's ownership. See [system export](docs/runbooks/20-system-export.md) and
[audit export](docs/runbooks/19-audit-certificate-export-verification.md) for scope and custody.

An operator with host/database-owner access remains a high-trust principal and can access
stored plaintext. Disk encryption, host hardening, administrator separation, and custody
controls are deployment responsibilities.

## Webhooks and external services

Webhooks are disabled by default and carry contentless wake-up notifications. Endpoint
validation rejects insecure schemes, credentials, local/private/link-local destinations,
unsafe redirects, and DNS/IP changes that cross the policy boundary. Delivery secrets are
shown only at creation/rotation and must be stored by the member's client.

DNS rebinding, destination compromise, and metadata-service exposure remain reasons to
keep webhooks disabled unless operationally necessary. An external OIDC provider becomes
a critical identity dependency; provider claims and regional schemes such as UAE Pass
require a separate deployment-specific assessment.

BoardAgent has no email/SMTP module. The reserved post-v1 `SubmissionCheckProvider` is inert:
v1 has no provider code, dependency, key, endpoint, configuration, tool, job, or outbound
call. If activated later, external retention, confidentiality, prompt injection, provider
error, variable cost, and outage become new unmitigated risks requiring a complete
review of the changed design and security boundaries, with explicit approval of any
change to the frozen contract.

## Secrets and cryptography

Production separates database credentials, OAuth signing, evidence signing, browser
sessions, data encryption, and backup encryption. Private key material enters through
owner-controlled files and is not stored in PostgreSQL. Public key identity and lifecycle
are registered in the database.

Production Compose gives server and worker separate read-only secret volumes under
nonroot UID 10001. Neither receives owner, migrator, backup, or the other runtime's
database password. Only the server receives OAuth and browser-session keys; both need
evidence signing and data encryption. One-shot provisioning/bootstrap custody is separate
from runtime custody, and backup encryption remains in the recovery-only volume. This
boundary depends on the trusted host/Docker administrator; container root or Docker access
is not an application permission. Exact-Compose tests check actual file readability and
negative database authentication under each runtime UID.

Rotation must preserve verification of historical evidence while preventing new use of a
retired or compromised key. Symmetric-key rotation requires a custody and re-encryption
plan for existing ciphertext. Deleting a key is not rotation and can destroy availability.
See the key and incident runbooks before changing any key.

The cryptographic design does not substitute for hardware-backed key custody. The frozen
single-server profile does not integrate an HSM/KMS, external timestamp service, certificate
transparency system, or independent notarization service.

## Availability, backup, and retention

The worker uses typed leases, bounded retries, idempotency, and dead-letter handling.
Readiness incorporates critical database/runtime/worker state. These controls reduce but
do not eliminate denial of service, resource exhaustion, operator error, or correlated
single-host failure.

Logical backups, encrypted physical base backups, encrypted WAL archival, PITR preparation,
and verified restore receipts are distinct controls. A copied file without a verified
manifest and restore exercise is not a proven backup. Recovery keys and at least one
tested copy must be outside the server's failure domain.

BoardAgent v1 never physically purges governance, content, audit, consent, or evidence
records. Soft deletion changes application visibility and lifecycle; it is not erasure.
Temporary operational artifacts have bounded cleanup, but legal/records retention and
ultimate media destruction remain operator responsibilities.

## Supply-chain and release controls

The exact Node/pnpm/PostgreSQL toolchain and direct dependencies are pinned. The release
process checks the lockfile, generated MCP registry, migrations, license inventory, SBOM,
image/source binding, container hardening, and high/critical vulnerability thresholds.
Generated output or an image from a different source digest is not acceptable evidence.

No automated scanner, test suite, mutation score, or AI-assisted review proves absence of
vulnerabilities. The independent external review tier (T10) exists specifically to add an
independent challenge to the developers' assumptions.

High or critical vulnerability, secret, or container-misconfiguration findings block the
release until fixed and rerun; they are not accepted by editing a scanner threshold.
Lower-severity findings need an explicit evidence-backed disposition and owner. A suspected
exploitable issue in a running deployment follows the incident runbook immediately rather
than waiting for a release schedule. No response-time promise exists until the deployment
commissions and publishes its private security process.

## Candid residual risks and limitations

The limitations ledger is maintained in
[docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md). In summary:

- A malicious or auto-approving MCP client can misrepresent staged content or solicit
  confirmations irresponsibly; the human must inspect exact server-presented material.
- An authorized insider can misuse powers that governance rules legitimately grant.
- Host/Docker/database-owner compromise can bypass application-level confidentiality.
- One server is a shared failure domain despite off-host recovery controls.
- Symmetric export and backup KEK custody is manual and operationally sensitive.
- OIDC and webhook security inherit external-provider, DNS, network, and account risks.
- Machine-readable-only content excludes common board-document formats and offers no OCR
  or semantic validation.
- No server AI means BoardAgent does not detect deception, mistakes, omissions, conflicts,
  or poor governance judgment in submitted content.
- Audit chaining detects later inconsistency when checked; it does not prevent all
  destruction or provide an external time witness.
- Public certificate verification proves bundle consistency and signature trust, not the
  identity or comprehension of every participant or legal enforceability.
- Independent external review (T10) has not been completed for the current tree. An
  AI-assisted review or a synthetic test result does not replace it or human acceptance.

## Change discipline

A change to protocol, canonical content, authorization, confirmation, authentication,
cryptography, retention, operator authority, client compatibility, or verification
provider requires review of the affected design and corresponding regression-test updates.
Changes to frozen decisions require the project owner's explicit approval, recorded under
`docs/decisions/`. Never weaken a failing check to obtain a green release. Historical
evidence must be preserved, and every exception must be visible in the release handoff.

## Control references and proof limits

These are implemented control descriptions, not fresh executing proofs for the working
tree. The listed SR rows in [docs/VERIFICATION.md](docs/VERIFICATION.md) carry the exact
implementation and executing-test pointers and any recorded limitations. Run the
verification tiers yourself before relying on an implementation claim.

| Boundary described here                                                       | Verification register                                      |
| ----------------------------------------------------------------------------- | ---------------------------------------------------------- |
| OAuth, passkeys, explicit TOTP, prelinked identity and recovery               | SR-005–SR-022; supported first-account/human proof: SR-102 |
| Live authorization, RLS, recusal and distinct worker authority                | SR-023–SR-029                                              |
| Exact single-use confirmation and commit-time authorization                   | SR-046–SR-050                                              |
| Typed jobs, immutable migrations, recovery, configuration and runtime custody | SR-080–SR-085                                              |
| Anchored minutes redlines and immutable review history                        | SR-086–SR-094                                              |
| Company administrator, exact board delegation and private authority discovery | SR-095–SR-100                                              |

For a suspected incident, use [runbook 26](docs/runbooks/26-incident-response.md).
For token/client containment use [runbook 7](docs/runbooks/07-token-client-incident.md);
key replacement and compromise use [runbook 8](docs/runbooks/08-key-rotation-compromise.md).
Preserve the original evidence and affected source/image identifiers. Do not reset the
database, delete audit history or rotate a key without its supported custody/recovery plan.
