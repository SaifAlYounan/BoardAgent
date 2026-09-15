# BoardAgent manual

BoardAgent stores the board's official records. You work through your own connected agent.
The agent helps explain and prepare work; BoardAgent checks permissions and records the
actions you confirm. Each person uses their own account and connection.

**Status:** BoardAgent is an open-source beta for use with synthetic data. This manual
describes supported source behaviour; it does not establish that your installation is
running that version. Ask the operator for its exact release and service status.

The [Mining Exploration Co pack](../demo/mining-exploration-co) provides a fictional
charter and exercises for one secretary and three board members. Creating an account in
a synthetic run does not establish that a real person registered a passkey, completed
onboarding or accepted a board act. Recovery custody, alert delivery, security review
and personal acceptance need their own evidence before any handover to a real board.

## Who handles what?

| Person                           | Everyday responsibility                                                                               | Start here                                                                   |
| -------------------------------- | ----------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Company administrator            | Set up people and their permitted responsibilities; arrange administrator succession.                 | [Administrator manual](manuals/administrator.md)                             |
| Secretary                        | Organize board business, arrange member enrollment, circulate material, prepare meetings and minutes. | [Secretary manual](manuals/secretary.md)                                     |
| Director                         | Read entitled material and personally confirm votes, signatures and other binding actions.            | [Board-member manual](manuals/board-member.md)                               |
| Technical administrator/operator | Install and maintain the service, monitor failures, protect keys, and run backup/recovery procedures. | [Deployment guide](../DEPLOY.md) and [operator runbooks](runbooks/README.md) |

The secretary needs an explicit, limited delegation to register ordinary directors.
Otherwise the company administrator creates the seats and the secretary arranges their
enrollment. A person can hold both company and technical administration responsibilities,
but the accounts and permissions are separate. A company-admin login is not a server login.

## Keeping terms and support details current

The board secretary can publish updated support contacts. The company administrator can
publish role-specific onboarding terms for the organization. Both require exact confirmation,
preserve previous versions and require affected people to accept the current version themselves.
Follow [the terms and support procedure](runbooks/30-onboarding-terms-and-support.md);
it also explains stale confirmations, expired acceptance links and the retained audit evidence.

## Getting started

### Configuring your own entity and charter

Mining Exploration Co is a fictional example; the software is not specific to it or to
any industry. Each installation serves one organization, with its own named boards, people,
documents and supported governance rules. A separate organization's installation needs
its own setup; this is not a shared service for unrelated companies.

The technical operator first installs the service and creates the initial organization,
board and administrator invitation. After that administrator activates the account and
connects an agent, the setup proceeds through the agent:

1. Supply the charter and the appointment records. The agent prepares the canonical text
   or JSON that BoardAgent accepts; review any conversion from the original document.
2. Create and enroll the separate secretary/director accounts from the appointment records.
   Check their identities, roles and voting weights before building a profile that refers to them.
3. Ask the agent to list the proposed voting seats and weights, quorum, approval thresholds,
   treatment of abstentions and ties, proxies, notice and closing rules, with source clauses.
4. Resolve omissions before activation. For example, if the charter says nothing about
   proxies, the agent should ask for the applicable decision and its authority rather than
   inventing a rule. Record supplementary instructions or resolutions as cited sources.
   If the rules cannot be represented by the supported model, stop setup and report the gap.
5. Review and personally confirm the exact profile and ruleset the administrator's agent
   submits. BoardAgent validates their structure, cited source versions and hashes, and
   the administrator's authority, then records the configuration and its history.
6. Verify the current voting seats match the approved configuration, and rehearse one
   resolution before relying on it.

Your agent does the reading and asks clarification questions. BoardAgent contains no AI
that interprets a charter, and it does not establish that the agent interpreted the text
correctly. The people approving the configuration must compare it with the source.
Account permissions are a separate decision: uploading a charter never makes someone an
administrator or gives an agent additional powers. The secretary manages ordinary business;
changing constitutional rules requires the existing administrator authority and confirmation.

An example instruction to the administrator's agent is: "Configure this board from the
attached charter and appointments. Show each proposed setting with its source clause.
List anything missing or ambiguous and ask me before proposing a choice. Do not activate
the rules until I have reviewed and confirmed the exact configuration."

### Connecting the people

Follow the [administrator account handoff](manuals/administrator.md) in order. The operator first
commissions the reviewed service; the company administrator enrolls; the secretary and
directors then enroll as separate people. Each person connects their own agent and completes
their own login and confirmation steps. Creating an account alone does not complete them.

To begin ordinary work, ask your connected agent to show your BoardAgent briefing. It
should show only material your account can access. For a vote, signature or other binding
action, read the exact confirmation presented before accepting it. If the details are
wrong, decline and correct the preparation. The agent's conversational summary does not
replace that confirmation.

## Your first ordinary session

Ask your agent:

> Connect to the BoardAgent service my administrator supplied. Show which person I am
> signed in as, my boards and any onboarding I must complete. Then show my pending work.
> Read before acting, and ask me to review every binding confirmation.

Verify your own name and board before opening material. If onboarding is required, read
the complete terms/support details and follow the private browser/passkey attestation.
Afterward, authorize only the scopes needed for your role. The agent should use
`whoami`, `list_my_boards`, `get_my_board_snapshot`, `list_my_updates` and
`list_pending_actions` to build its briefing. A remembered summary is not current state.

| What you want          | Example request to your agent                                                                     | What to inspect afterward                                                                         |
| ---------------------- | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| Read board material    | “Show the current papers for this meeting, with versions and source links.”                       | Entitled documents, exact version/hash and meeting context.                                       |
| Ask about a paper      | “Prepare a question for the assigned management owner, citing this paragraph.”                    | Exact question, recipient/owner, due time and saved question reference.                           |
| Cast a vote            | “Show this resolution, its governing rule, sources and my proxy status. I will choose my ballot.” | The exact confirmation, then the recorded ballot status.                                          |
| Comment on minutes     | “Compare these published minutes with the meeting record and prepare these specific edits.”       | Current base version, precise redline anchors and submitted review item.                          |
| Sign minutes           | “Show the final package, unresolved review items and required signatures before I decide.”        | Exact package/hash, your own signature receipt and finalization state.                            |
| Complete assigned work | “Prepare my evidence for this action and show its acceptance criteria.”                           | Evidence submission and later secretariat acceptance/closure; submission alone is not completion. |

These examples request preparation. Your role, board membership, current onboarding,
recusal and the record’s state determine whether an action is available. Do not switch to
someone else’s credentials to get around a refusal. An observer has narrower rights than
a director; a secretary title does not give a vote.

## Documents and confirmations

BoardAgent accepts canonical Markdown, plain text and the declared strict JSON formats.
It rejects PDF, DOCX, PPTX, images, scans and archives, including an original attached
“for evidence.” If a source begins in one of those formats, an accountable person must
prepare and verify a text/JSON version outside BoardAgent. The agent can help, but the
server neither extracts the text nor verifies that the translation is complete or true.

For a binding action, the first tool response is a proposed confirmation. Read the whole
server message, including the person, board, object, version/hash, action and consequences.
Choose approve or cancel and enter the displayed code yourself. An agent’s summary,
a prepared draft or a request that timed out is not a completed act. If content changes,
review a fresh package and confirmation. Keep the successful canonical receipt (the server's record of the completed act); a
result reported as `queued`, `pending`, `closing` or partial remains exactly that state,
not a completed act.

If you lose the response after confirming, ask the agent to inspect the saved record
before trying again. Repeating the conversation is not a safe retry strategy. A closed
vote has a certificate to verify; published minutes can still await review or signatures;
an action with submitted evidence can still await acceptance.

## Something went wrong — who should help?

| What you see                                                       | What to do                                                                                                   | Who fixes it                                                                      |
| ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------- |
| Login or enrollment fails                                          | Record the time and displayed error. Use the supported recovery procedure.                                   | Company administrator/secretary for identity checks; operator for service faults. |
| An expected board or document is unavailable                       | Check that the agent is connected as the intended person. Request a permission review.                       | Secretary or company administrator.                                               |
| A read says response capacity is busy                              | Wait briefly and retry the read once. If it persists, give support the error, time and nonsecret reference.  | Technical operator.                                                               |
| An action reports a temporary audit-capacity error                 | Let the agent check whether the action was saved before retrying. If it persists, report the error and time. | Technical operator checks the signing worker.                                     |
| An action says it exceeds the supported size                       | Stop repeating the same request. Give support its nonsecret reference, time and error.                       | Technical operator investigates the action size and supported capacity.           |
| The service cannot be reached or says it is not ready              | Report the time and error; use the outage procedure.                                                         | Technical operator.                                                               |
| A vote or signature seems to have succeeded but the reply was lost | Ask the agent to check the saved result before repeating the action.                                         | Secretary can help locate the record; operator investigates service errors.       |
| A server credential or security key may have been exposed          | Contact the technical operator promptly through your established support channel.                            | Technical operator and the designated security contact.                           |

Support needs the displayed error, approximate time, affected task and any nonsecret
request reference. Do not send passwords, invitation URLs, login codes, private keys or
access tokens in a support report.

The audit-backlog and action-size messages mean different things. A temporary backlog means the
background signing worker must catch up before more work can be saved. An action-size
error means that particular action needs more records or data than the tested limit;
waiting or restarting does not enlarge it. The limit counts internal records, not just
people. A normal notice to 1,000 people also creates evidence that those notices were
recorded. Do not remove recipients, drop evidence or break up a confirmed action merely
to bypass the limit. The operator records the failure and arranges a supported fix.

A busy read can clear when other requests finish. Repeatedly retrying is not a
solution if the same response cannot fit within the service’s supported capacity.
Ask support to investigate a persistent refusal; do not change the underlying board
record just to make the read succeed.

## What the technical operator does

Use the exact installation record: host, release directory, Compose project, image digest,
configuration-file paths, backup location and responsible contacts. The installer must
fill these in before handover. Guessing a project name can target another installation.

1. **Identify the symptom.** Check service readiness, worker health and the first recorded
   failure using [runtime checks](runbooks/01-runtime-tls-readiness-drain.md).
2. **Preserve the evidence.** Record the installed version and original failure before
   changing anything. Keep existing records, keys and backup generations.
3. **Follow the matching procedure.** Use [worker jobs](runbooks/17-worker-jobs.md),
   [outage and capacity](runbooks/24-outage-capacity.md),
   [audit-signing recovery](runbooks/29-audit-signing-recovery.md),
   [backup and restore](runbooks/22-backup-pitr-restore.md), or
   [key replacement](runbooks/08-key-rotation-compromise.md).
4. **Check the actual result.** A running container alone is insufficient. Check readiness,
   signing progress and the result required by that procedure. A restore must be tested in
   an isolated target before it can be relied upon.
5. **Close the maintenance record.** Record who acted, what was changed, the result and
   verification evidence, any remaining limitation, and who owns the next action.

The worker automatically retries eligible temporary failures. A stopped process and an
unhealthy running process are different: container restart policy does not itself repair
a failed job, a missing key or damaged data. Repeated restarts are not a recovery procedure.

An audit-signing interruption means the service missed producing some timely evidence.
Restarting cannot change that historical fact. Any supported recovery must preserve the
records and disclose the missed interval; a green current-health check must not erase it.

## What a complete maintenance procedure must contain

Every published procedure must state who may run it, what access/files it needs, the exact
commands for the installed version, expected output, and what to do if interrupted or
refused. It must explain where its audit or maintenance receipt is saved and how to verify
success. Commands must not require an operator to invent SQL, change recorded timestamps,
delete evidence or mark failed work successful.

A command labelled unavailable is not an instruction to improvise an alternative. It is
an unfinished capability that must be completed and verified before the installation is
handed over for that use. The release handover must include a tested installation record
and a manual walkthrough of startup, a worker failure, account recovery, key replacement
and restoring a backup. Actual human acceptance is recorded separately from automated tests.
