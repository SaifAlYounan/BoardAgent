import type { Client } from "@modelcontextprotocol/client";
import { decodeJwt } from "jose";
import { describe, expect, it } from "vitest";
import { sha256Hex } from "../../lib/contracts/src/index.js";
import { withRequestTransaction } from "../../lib/db/src/index.js";
import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";
import { administrativeOAuthFixture } from "../helpers/administrative-oauth.js";
import { testId } from "../helpers/authorized-actor.js";
import { governanceEnvelopeFixture } from "../helpers/governance-envelope.js";

const SCHEMA = "boardagent.tool-input.v1";
async function call(client: Client, name: string, input: Record<string, unknown>) {
  return client.callTool({ name, arguments: { schema_version: SCHEMA, ...input } });
}

describe("charter configuration through actual TLS OAuth and MCP", () => {
  it("activates a cited profile and rules, evaluates a first resolution, and refuses non-admin changes", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await administrativeOAuthFixture(pool);
      try {
        const adminToken = await f.login(f.issuer.memberId, true);
        const admin = await f.connect(adminToken);
        const secretary = await f.connect(await f.login(f.target.memberId));
        const boardId = f.issuer.boardId;
        const body =
          "# Synthetic association charter\n\nC1: Two equal voting seats.\n\nC2: Ordinary resolutions require more yes than no votes, at least half the eligible weight present, ties rejected, no proxies, no notice period and confirmed secretary closure. No rule overrides. Nonnegative budgets use this ordinary rule.\n";
        const created = await call(admin, "create_document_version", {
          board_id: boardId,
          document_id: testId(891_020),
          title: "Synthetic association charter",
          media_type: "text/markdown; charset=utf-8",
          schema_name: null,
          canonical_body: body,
          expected_current_version_id: null,
          idempotency_key: "charter-transport-source-0001"
        });
        expect(created.isError).not.toBe(true);
        const sourceId = (created.structuredContent as { reference: string }).reference;
        expect(sourceId).toEqual(expect.any(String));
        const g = governanceEnvelopeFixture(
          boardId,
          [f.issuer.memberId, f.target.memberId],
          sourceId,
          sha256Hex(Buffer.from(body))
        );
        const input = {
          board_id: boardId,
          expected_profile_id: null,
          profile: { schema_version: "boardagent.governance-profile.v1", values: g.profile },
          citations: g.citations,
          reason: "Activate the explicit synthetic association rules",
          idempotency_key: "charter-transport-profile-0001"
        };

        const configured = await call(admin, "configure_board_governance", input);
        expect(configured.isError, JSON.stringify(configured)).not.toBe(true);
        expect(configured.structuredContent).toMatchObject({
          data: { profileId: g.profile.id, state: "active" }
        });
        const denied = await call(secretary, "configure_board_governance", {
          ...input,
          idempotency_key: "charter-transport-secretary-refused"
        });
        expect(denied.isError).toBe(true);
        expect(JSON.stringify(denied)).toMatch(
          /denied|not authorized|requires.*admin|not permitted/iu
        );
        expect(
          (await pool.query("select count(*)::int as n from governance_profiles")).rows[0]?.n
        ).toBe(1);

        const templates = await call(admin, "list_approval_rule_templates", { board_id: boardId });
        expect(templates.isError).not.toBe(true);
        expect(
          templates.structuredContent,
          JSON.stringify({
            response: templates,
            savedTemplates: (
              await pool.query("select id,profile_id,code from governance_rule_templates")
            ).rows,
            savedBoard: (
              await pool.query("select current_governance_profile_id from boards where id=$1", [
                boardId
              ])
            ).rows
          })
        ).toMatchObject({
          data: { items: [expect.objectContaining({ template_id: g.profile.templates[0]!.id })] }
        });
        const approvalId = (
          templates.structuredContent as { data: { items: { approval_rule_id: string }[] } }
        ).data.items[0]!.approval_rule_id;
        const ruleset = g.ruleset(approvalId);
        const draft = { schema_version: "boardagent.ruleset.v1", values: ruleset };
        const invalid = await call(admin, "validate_ruleset_draft", {
          board_id: boardId,
          citations: g.rulesetCitations,
          draft: { ...draft, values: { ...ruleset, additionalAuthority: "admin" } }
        });
        expect(invalid.isError).not.toBe(true);
        expect(invalid.structuredContent).toMatchObject({ data: { valid: false } });
        const valid = await call(admin, "validate_ruleset_draft", {
          board_id: boardId,
          citations: g.rulesetCitations,
          draft
        });
        expect(valid.isError).not.toBe(true);
        expect(valid.structuredContent).toMatchObject({ data: { valid: true, issues: [] } });
        const managed = await call(admin, "manage_ruleset", {
          board_id: boardId,
          expected_ruleset_id: null,
          ruleset: draft,
          citations: g.rulesetCitations,
          reason: "Activate explicit ordinary-resolution classification",
          idempotency_key: "charter-transport-rules-0001"
        });
        expect(managed.isError, JSON.stringify(managed.structuredContent)).not.toBe(true);
        expect(managed.structuredContent).toMatchObject({
          data: { rulesetId: ruleset.id, state: "active" }
        });
        const matters = await call(admin, "list_matter_types", { board_id: boardId });
        expect(matters.isError).not.toBe(true);
        const matterId = (
          matters.structuredContent as { data: { items: { matter_type_id: string }[] } }
        ).data.items[0]!.matter_type_id;
        const evaluated = await call(admin, "evaluate_matter", {
          board_id: boardId,
          matter_type_id: matterId,
          facts: { schema_version: "boardagent.facts.v1", values: { budget_usd: 1000 } },
          expected_profile_id: g.profile.id,
          expected_ruleset_id: ruleset.id,
          idempotency_key: "charter-transport-evaluate-0001"
        });
        expect(evaluated.isError, JSON.stringify(evaluated.structuredContent)).not.toBe(true);
        expect(evaluated.structuredContent).toMatchObject({
          data: {
            status: "matched",
            selected_approval_rule_id: approvalId,
            missing_fields: []
          }
        });
        const firstVote = await call(admin, "create_vote", {
          board_id: boardId,
          vote_id: testId(891_050),
          title: "Approve the first association resolution",
          resolution_text: "Approve the charter-backed ordinary resolution.",
          decision_package: {
            schema_version: "boardagent.vote-package-components.v1",
            values: {
              components: [
                {
                  type: "document",
                  ordinal: 1,
                  id: sourceId,
                  version: 1,
                  sha256: sha256Hex(Buffer.from(body))
                }
              ]
            }
          },
          approval_rule_id: approvalId,
          matter_evaluation_id: (evaluated.structuredContent as { reference: string }).reference,
          selected_ruleset_rule_id: ruleset.rules[0]!.id,
          override_reason: null,
          close_mode: "secretariat_confirmed",
          deadline_at: new Date(Date.now() + 86_400_000).toISOString(),
          idempotency_key: "charter-transport-first-vote-0001"
        });
        expect(firstVote.isError, JSON.stringify(firstVote)).not.toBe(true);
        expect(
          (await pool.query("select state from votes where id=$1", [testId(891_050)])).rows
        ).toEqual([{ state: "open" }]);
        expect(
          (
            await pool.query(
              "select current_governance_profile_id,current_ruleset_id from boards where id=$1",
              [boardId]
            )
          ).rows
        ).toEqual([
          { current_governance_profile_id: g.profile.id, current_ruleset_id: ruleset.id }
        ]);
        expect(
          (
            await pool.query(
              "select count(*)::int as n from action_stages where action_code in ('configure_board_governance','manage_ruleset') and state='confirmed'"
            )
          ).rows[0]?.n
        ).toBe(2);

        // Exercise the actual database role: catalog reads need a current token,
        // the exact organization/member/client/board and governance:read. They
        // must not acquire any corresponding insert/update authority.
        const context = { ...f.issuer.context, tokenJti: decodeJwt(adminToken.access_token).jti! };
        const catalog = (candidate = context) =>
          withRequestTransaction(
            pool,
            candidate,
            async (client) =>
              (
                await client.query(
                  "select (select count(*)::int from governance_rule_templates) as templates,(select count(*)::int from matter_types) as matters"
                )
              ).rows[0],
            { assumeRole: "boardagent_server" }
          );
        expect(await catalog()).toEqual({ templates: 1, matters: 1 });
        for (const candidate of [
          { ...context, boardIds: [] },
          { ...context, organizationId: testId(891_090) },
          { ...context, memberId: f.target.memberId },
          { ...context, clientId: f.target.clientId }
        ])
          expect(await catalog(candidate)).toEqual({ templates: 0, matters: 0 });
        await expect(
          withRequestTransaction(
            pool,
            context,
            (client) =>
              client.query(
                "insert into governance_rule_templates(id,profile_id,code,approval_rule_id,exact_rule_payload,canonical_sha256) values($1,$2,'unconfirmed',$3,'{}',$4)",
                [testId(891_091), g.profile.id, approvalId, Buffer.alloc(32, 91)]
              ),
            { assumeRole: "boardagent_server" }
          )
        ).rejects.toMatchObject({ code: "42501" });
        const savedScopes = (
          await pool.query("select scope_set from access_token_records where jti=$1", [
            context.tokenJti
          ])
        ).rows[0]?.scope_set;
        await pool.query(
          "update access_token_records set scope_set=array['secretariat:admin'] where jti=$1",
          [context.tokenJti]
        );
        expect(await catalog()).toEqual({ templates: 0, matters: 0 });
        await pool.query("update access_token_records set scope_set=$2 where jti=$1", [
          context.tokenJti,
          savedScopes
        ]);
        await pool.query(
          "update access_token_records set revoked_at=transaction_timestamp() where jti=$1",
          [context.tokenJti]
        );
        expect(await catalog()).toEqual({ templates: 0, matters: 0 });
        expect(f.errors).toEqual([]);
      } finally {
        await f.close();
      }
    });
  }, 180_000);
});
