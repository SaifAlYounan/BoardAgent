import { canonicalSha256 } from "../../lib/contracts/src/index.js";
import { testId } from "./authorized-actor.js";

/** Pure synthetic charter inputs; no database writes or inferred interpretation. */
export function governanceEnvelopeFixture(
  boardId: string,
  memberIds: string[],
  sourceId: string,
  sha256: string
) {
  const citation = {
    sourceDocumentVersionId: sourceId,
    sourceDocumentSha256: sha256,
    clause: "C2",
    locator: "Ordinary resolution rules"
  };
  const rulesetCitations = [
    { document_version_id: sourceId, sha256, clause: citation.clause, locator: citation.locator }
  ];
  const sourceAgreement = { ...citation, clause: "C1", locator: "Voting seats" };
  const citations = [
    { ...rulesetCitations[0]!, clause: sourceAgreement.clause, locator: sourceAgreement.locator },
    ...rulesetCitations
  ];
  const profile = {
    schemaVersion: "boardagent.governance-profile.v1" as const,
    id: testId(891_001),
    boardId,
    version: 1,
    supersedesId: null,
    sourceAgreements: [sourceAgreement],
    seats: memberIds.map((memberId) => ({
      memberId,
      role: "voting_member" as const,
      weight: "1",
      chair: false
    })),
    templates: [
      {
        id: testId(891_002),
        code: "ordinary",
        label: "Ordinary resolution",
        approval: { numerator: "1", denominator: "2" },
        quorum: { numerator: "1", denominator: "2" },
        approvalDenominator: "yes_no" as const,
        abstentionsCountForQuorum: true,
        tieBehavior: "reject" as const,
        proxyPolicy: "forbidden" as const,
        noticePeriodSeconds: 0,
        closeMode: "secretariat_confirmed" as const,
        overridePolicy: "forbidden" as const,
        citations: [citation]
      }
    ]
  };
  const ruleset = (approvalRuleId: string) => {
    const base = {
      schemaVersion: "boardagent.ruleset.v1" as const,
      id: testId(891_003),
      boardId,
      version: 1,
      matterTypes: [
        {
          code: "ordinary_resolution",
          fields: [{ name: "budget_usd", type: "integer" as const, required: true, minimum: 0 }]
        }
      ],
      rules: [
        {
          id: testId(891_004),
          matterType: "ordinary_resolution",
          priority: 10,
          specificity: 10,
          condition: { kind: "number_gte" as const, field: "budget_usd", value: 0 },
          approvalRuleId,
          citations: [citation]
        }
      ]
    };
    return { ...base, canonicalHash: canonicalSha256(base) };
  };
  return { profile, ruleset, citations, rulesetCitations };
}
