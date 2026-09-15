# BoardAgent architecture decision records

The Gate-2 decision pack is the frozen normative authority. These ADRs explain how its
nontrivial decisions are embodied, what was rejected, and what must trigger a new
architecture cycle. Closely coupled decisions share an ADR; implementation-only deviations
receive their own record.

| ADR                                                             | Gate-2 decisions                                                    | Subject                                                  |
| --------------------------------------------------------------- | ------------------------------------------------------------------- | -------------------------------------------------------- |
| [0001](0001-frozen-protocol-bundle.md)                          | D2-003 through D2-008; D2-036 through D2-038                        | MCP/OAuth resource, versions, clients, and MRTR          |
| [0002](0002-typescript-seven-third-party-declarations.md)       | implementation constraint under D2-002/D2-052                       | TypeScript 7 third-party declaration isolation           |
| [0003](0003-no-purge-machine-readable-only.md)                  | D2-023 through D2-027; D2-049                                       | machine-readable content, no provider, permanent records |
| [0004](0004-phase0-toolchain-and-supply-chain.md)               | implementation receipt under D2-002/D2-052/D2-055 through D2-057    | exact toolchain and supply chain                         |
| [0005](0005-agent-owned-derived-memory.md)                      | D2-018; D2-019; D2-025; D2-028; D2-029; D2-045                      | no shared semantic brain; agent-owned derived memory     |
| [0006](0006-identity-oauth-and-client-boundary.md)              | D2-008 through D2-018                                               | identity, OAuth, enrollment, OIDC, clients               |
| [0007](0007-authority-canonical-data-and-evidence.md)           | D2-019 through D2-022; D2-041 through D2-045; D2-058 through D2-060 | authority, canonical state, audit, certificates          |
| [0008](0008-governance-state-and-human-confirmation.md)         | D2-030 through D2-040; D2-062 through D2-069                        | rules, voting, MRTR, questions, minutes, tasks           |
| [0009](0009-worker-exports-recovery-and-deployment.md)          | D2-046 through D2-054                                               | worker, egress, retention, recovery, deployment          |
| [0010](0010-verification-provenance-and-release-label.md)       | D2-001; D2-002; D2-055 through D2-057; D2-061                       | regression evidence, provenance, release label           |
| [0011](0011-onboarding-narrowed-tokens-and-form-elicitation.md) | D2-013; D2-023; ADR 0006 trigger                                    | onboarding-narrowed tokens, form elicitation capability  |

Together these records cover D2-001 through D2-069. The coverage assertion is mechanical in
`tests/phase0/documentation-closure.test.ts`. An ADR may clarify implementation consequences
but cannot weaken or silently amend the frozen Gate-2 decision.
