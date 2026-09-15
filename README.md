# BoardAgent

BoardAgent is a self-hosted, MCP-native system of record for a board of directors. Each
person on the board works through their own MCP-capable agent. BoardAgent has no
governance portal and runs no server-side AI. It stores the canonical machine-readable
records and enforces procedure and authority on every operation. Every binding act is a
human confirmation, and every event is hash-chained and signed.

## Status

BoardAgent is an open-source beta. Use it with synthetic data only. It is not
production-ready, and it carries no security certification. I call this code line the
private hardened beta: it passes its own regression net, except SR-102, which is still
unresolved, and it has not passed an independent external review.

I built BoardAgent so that a board can keep its official records in one service that
its members reach through the agents they already use, without handing those records to
a shared assistant. Your agent presents information. BoardAgent records exact
information and the confirmations you give. You remain responsible for reading what
you confirm and for securing your agent and your local copies.

BoardAgent is not a qualified electronic-signature service or a notary, and it is not
legal advice. It cannot prove that a person understood a record.

### Binding confirmations need a client that renders forms

A binding act, such as a vote or an invitation, is confirmed through an MCP elicitation
form. Your client must render that form; a client that only reads the board
can browse it but cannot act on it. Today Claude Code renders these forms. Confirming
in the browser with a passkey is the first item on [the roadmap](docs/ROADMAP-NEXT.md).

## What it does

- Keeps one organization and its boards, members, governance profiles, rules,
  documents, meetings, transcripts, minutes, votes, proxies, questions, submissions,
  proposals and tasks in PostgreSQL.
- Applies role, board, recusal, confidentiality, lifecycle and exact-resource checks on
  every MCP operation.
- Requires a one-use, server-attested confirmation for every binding human act.
- Preserves append-only audit events, signed checkpoints, vote certificates, encrypted
  exports, backup receipts and restore receipts.
- Supports built-in WebAuthn and TOTP authentication, and pre-linked OIDC identities.
- Runs a separate least-privilege worker for notifications, exports, deadlines,
  checkpoints, cleanup of operational leftovers and recovery jobs.

## What it deliberately does not do

- No server-side language models, embeddings, OCR, format conversion or content-check
  API.
- Only canonical Markdown, plain text and declared versioned JSON are accepted. PDF,
  PowerPoint, Word, images, scans, archives and binary redlines are rejected.
- No governance web UI and no email workflow. The browser is used for enrollment,
  authentication and onboarding attestation; board work happens in your MCP client.
- No physical purge of governance, content, audit, consent or evidence records in v1.
- Webhooks are contentless wake-ups. They are disabled by default and restricted against
  server-side request forgery.
- A software client name is not an identity. A deployment can restrict clients to exact
  server-issued client IDs or to exact client metadata URLs checked over HTTPS.

The frozen implementation contract is [BUILD_PLAN.md](BUILD_PLAN.md). Security and
trust boundaries are in [SECURITY.md](SECURITY.md); deployment is in
[DEPLOY.md](DEPLOY.md).

## Architecture

```text
MCP client / human browser
          |
       HTTPS
          |
        Caddy
          |
  BoardAgent server ---- public certificate verifier
          |
   private backend network
          |
      PostgreSQL <---- least-privilege worker
          |                      |
   audit/evidence          exports/notices/jobs

Operator CLI ---- migrations, bootstrap, keys, verification, backup/PITR/restore
```

The supported v1 deployment is one organization on one Linux server, with one
BoardAgent server, one worker, PostgreSQL 18.6 and Caddy. Runtime containers run
read-only as non-root users, with dropped capabilities and separate database principals.
Horizontal scale, multi-tenant hosting, public cloud control planes and automatic
failover are outside the frozen profile.

## Toolchain

- Node.js `24.20.0`
- pnpm `11.24.0`
- PostgreSQL `18.6`
- Docker with Compose v2 for runtime and integration verification

Direct dependencies are pinned exactly. Do not substitute toolchain versions. The
recorded provenance is under `artifacts/provenance/`.

## Start here

| Reader                   | Guide                                                                                                |
| ------------------------ | ---------------------------------------------------------------------------------------------------- |
| New user                 | [User manual](docs/MANUAL.md): connect, understand a receipt and get help                            |
| Company administrator    | [Administrator manual](docs/manuals/administrator.md): accounts, authority, charter and succession   |
| Secretary                | [Secretary manual](docs/manuals/secretary.md): enrollment, meetings, votes, minutes and actions      |
| Board member             | [Board-member manual](docs/manuals/board-member.md): read, ask, vote, use proxies and sign minutes   |
| Agent/client implementer | [Agent guide](docs/AGENT_GUIDE.md) and [generated surface reference](docs/SURFACE_REFERENCE.md)      |
| Technical operator       | [Deployment](DEPLOY.md), [security](SECURITY.md) and [33 operator runbooks](docs/runbooks/README.md) |

### Evaluate with the Mining Exploration Co pack

The [Mining Exploration Co pack](demo/mining-exploration-co) is a fictional charter and
exercise pack for one non-voting secretary and three equal-weight board members, with a
separate setup administrator. Follow its instructions and inspect your own run records
before assuming that an instance or an account exists. Creating a fixture, installing a
service, issuing an invitation, registering a passkey and completing onboarding are
separate steps.

A secretary account does not automatically have a vote, company-administrator powers
or a server login. The manuals explain the setup administrator and the supported
handoff to the intended board seats. A scripted authenticator or an automated ballot
belongs to a test fixture; it cannot establish a real person's acceptance.

### Build and check a local checkout

With the exact toolchain versions above, run from the repository root:

```sh
corepack pnpm install --frozen-lockfile
corepack pnpm supply-chain:generate
git clone https://github.com/LegalQuants/LQGovernance-OpenBoard vendor/openboard
git -C vendor/openboard checkout 1b38dbf2c1ea413fea0661c34c63cd0fd10dc4bb
corepack pnpm verify:phase0
corepack pnpm exec vitest run tests/unit --no-file-parallelism --maxWorkers=1
```

`supply-chain:generate` writes the SBOM and licence report under `artifacts/`, which are
not committed and which the unit suite reads. The `vendor/openboard` clone is the
read-only prior-art reference at its pinned commit; it is git-ignored, never built or
imported, and a phase-0 test checks its commit and licence. `verify:phase0` checks
static integrity and provenance. None of these is a running-system or database
qualification. Some browser and released-client prerequisites are separate
from dependency installation; [tests/TESTING.md](tests/TESTING.md) explains them. Do not
skip a check to make setup pass.

For a disposable local installation, follow [DEPLOY.md](DEPLOY.md) with reviewed
`.env.example` values and synthetic data. Build the server and PostgreSQL images before
starting services. The default server listens on loopback port 8787; it is not a
browser governance interface. Use the [bootstrap procedure](docs/runbooks/02-bootstrap.md)
for its one-use operator command.

Keep enrollment links, activation codes, OAuth credentials, secrets and private operator
inputs outside source control.

## First agent session

After your account is registered and activated, connect your agent to the HTTPS
resource ending in `/mcp` that your operator gives you. A cautious first session is:

1. Connect and log in. Until your onboarding is current the server issues an
   `onboarding:read` token and says so in the token response. Call `whoami`, then
   `list_my_boards`.
2. Run `onboard-boardagent` and inspect `get_onboarding`, then complete your own
   attestation. The next token refresh (within fifteen minutes) or a reconnect carries
   your ordinary scopes.
3. Read `get_my_board_snapshot` and `list_my_updates`, then `list_pending_actions`.
4. Use read tools before any write. For a binding act, inspect the staged exact content
   and complete the server-driven confirmation yourself.
5. Rehearse an entitled read, then follow the role manual for a synthetic workflow.

The role-by-role guide, the safe prompting rules, the content formats and the
confirmation workflow are in [docs/AGENT_GUIDE.md](docs/AGENT_GUIDE.md). BoardAgent has
no shared semantic memory: [ADR 0005](docs/adr/0005-agent-owned-derived-memory.md)
explains why canonical shared records stay on the server while any derived memory stays
under each person's own agent.

## Verification and release labels

The regression net has eleven tiers, T0 to T10. The beta command runs the deterministic
tiers T0 to T9; a public release also requires the independent external review at T10.

```sh
corepack pnpm verify:private-beta
```

The command must run against one unchanged source tree, and a passing historical run is
not evidence for later edits. [docs/VERIFICATION.md](docs/VERIFICATION.md) maps the 94
original security requirements and the eight approved administrative additions to their
implementation and their executing tests; [tests/TESTING.md](tests/TESTING.md) explains
how to run the net. A full run writes a release manifest, an evidence ledger, an outcome
comparison and a handoff document beside its result receipt. These files collect
evidence; they do not approve a release.

## Glossary

The documents use a few internal terms. Here is what they mean.

- **Gate 1, Gate 2 and Gate 3.** The sign-off points of the project. Gate 1 approved
  the requirements. Gate 2 froze the design: the authority matrix, the data and
  transaction design, the verification net and the build plan. Gate 3 is production
  acceptance for one exact build, and it has not been given.
- **Frozen.** A document or a registry that was fixed at Gate 2 and is pinned by hash.
  It is not edited; a change is recorded as a separate, additive amendment.
- **BUILD_PLAN.md.** The build plan as frozen on 28 August 2026. It predates the change
  to the Apache licence and names a build log and two Gate 2 appendices that are not
  published in this repository; it is kept unchanged because its hash is pinned.
- **Decision records.** The files under `docs/decisions/` are immutable formal records
  approved by me, the project owner. Four of them are pinned by hash in the registry
  amendments and cannot change without regenerating the registry.
- **T0 to T10.** The verification tiers, in order: integrity, static analysis, unit and
  state coverage, property tests, mutation testing, PostgreSQL integration, protocol and
  authentication, adversarial tests, acceptance scenarios, operations, and finally the
  independent external review at T10, which I cannot issue myself.
- **SR-nnn.** A numbered security requirement from the verification net. The register
  in `docs/VERIFICATION.md` maps each one to code and to a test.
- **TH-nn and AC-nn.** A numbered threat in `docs/THREAT_MODEL.md` and a numbered
  acceptance scenario.
- **D2-nnn.** A numbered decision from the Gate 2 design record, cited in
  `BUILD_PLAN.md` and in the ADRs.
- **R, D and H tools.** The registry marks every MCP tool as a read (R), a direct
  non-binding mutation (D) or a binding human act (H). An H tool always runs the
  prepare, present, confirm and act ceremony.
- **S:A and the other scope codes.** Short forms of OAuth scopes: `S:A` is
  `secretariat:admin`, `G:R` is `governance:read`, `V:A` is `vote:act` and `M:A` is
  `minutes:act`. The full list is in the surface matrix under `planning/`.
- **Candidate.** One exact source tree, identified by hash, that is being verified for
  release.
- **Receipt.** A machine-readable record that a command or a test produced, bound to the
  exact source it ran against.
- **Harvest.** The review of an earlier open-source project of mine, LQGovernance-OpenBoard,
  from which four files were adapted under their original MIT notice. The record is
  [docs/HARVEST_REPORT.md](docs/HARVEST_REPORT.md).
- **Project owner.** Me. Earlier documents used the word sponsor for the same role.

## Contributing and reporting problems

Use synthetic reproductions and keep changes scoped to the stated defect. Preserve the
immutable migration history, the generated registry contracts and failing evidence. Run
the focused checks, then the full net on a clean final tree. The
[contributor contract](AGENTS.md), the [build plan](BUILD_PLAN.md) and the
[testing guide](tests/TESTING.md) explain the repository rules.

A useful bug report identifies the exact commit or image, the environment, a non-secret
request reference, the expected result, the observed result and minimal synthetic
steps. Report vulnerabilities privately through GitHub private vulnerability reporting
as described in [SECURITY.md](SECURITY.md). Do not post real board records, invitation
URLs, private keys or access tokens in issues.

## Documents

- [DEPLOY.md](DEPLOY.md): supported topology, secrets, initialization, upgrades and
  recovery.
- [SECURITY.md](SECURITY.md): threat boundaries, reporting, residual risks and open
  items.
- [docs/AGENT_GUIDE.md](docs/AGENT_GUIDE.md): agent onboarding and safe operation.
- [docs/SURFACE_REFERENCE.md](docs/SURFACE_REFERENCE.md): generated inventory of the
  MCP, HTTP, CLI, resource, prompt and event surfaces.
- [docs/runbooks/README.md](docs/runbooks/README.md): operator procedures and evidence
  expectations.
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): the threat matrix with controls and
  proofs.
- [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md): intentional boundaries,
  residual risks and open items.
- [docs/adr/](docs/adr/): accepted architecture decisions.
- [CITATION.cff](CITATION.cff): how to cite this repository.

## Licence

BoardAgent is licensed under the [Apache License 2.0](LICENSE); see also
[NOTICE](NOTICE) and [docs/THIRD_PARTY_NOTICES.md](docs/THIRD_PARTY_NOTICES.md).
