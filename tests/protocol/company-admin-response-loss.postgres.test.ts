import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { describe, expect, it } from "vitest";
import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";
import { administrativeOAuthFixture } from "../helpers/administrative-oauth.js";
import { testId } from "../helpers/authorized-actor.js";

describe("SR095/SR100 AC20 confirmed administrator response loss", () => {
  it("reconnects after losing the committed MCP acceptance reply without creating a second appointment", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await administrativeOAuthFixture(pool);
      let target: Client | undefined;
      try {
        const proposalId = testId(198_000);
        const issuer = await f.connect(await f.login(f.issuer.memberId));
        expect(
          (
            await issuer.callTool({
              name: "manage_company_admin",
              arguments: {
                schema_version: "boardagent.tool-input.v1",
                idempotency_key: "response-loss-admin-offer-0001",
                change: {
                  operation: "grant",
                  proposal_id: proposalId,
                  member_id: f.target.memberId,
                  expected_member_version: 1,
                  reason: "Offer administrator responsibility"
                }
              }
            })
          ).isError
        ).not.toBe(true);
        const token = await f.login(f.target.memberId);
        let droppedReplies = 0;
        target = new Client(
          { name: "response-loss-test-agent", version: "1.0.0" },
          {
            capabilities: { elicitation: { form: {} } },
            versionNegotiation: { mode: { pin: "2026-07-28" } },
            inputRequired: { autoFulfill: true, maxRounds: 2 }
          }
        );
        await target.connect(
          new StreamableHTTPClientTransport(new URL(f.resource), {
            requestInit: { headers: { authorization: `Bearer ${token.access_token}` } },
            fetch: async (input, init) => {
              const request = new Request(input, init);
              const body = request.body ? await request.clone().text() : "{}";
              const call = JSON.parse(body) as { method?: string; params?: { name?: string } };
              const response = await f.trustedFetch(request);
              if (
                !droppedReplies &&
                response.ok &&
                call.method === "tools/call" &&
                call.params?.name === "manage_company_admin"
              ) {
                const committed =
                  (
                    await pool.query("select state from company_admin_proposals where id=$1", [
                      proposalId
                    ])
                  ).rows[0]?.state === "accepted";
                if (committed) {
                  // Real TLS request and server commit; discard the reply before the SDK
                  // can observe it. This is a client transport fault, not a server crash.
                  await response.arrayBuffer();
                  droppedReplies += 1;
                  throw new TypeError("synthetic lost acceptance response");
                }
              }
              return response;
            }
          })
        );
        target.setRequestHandler("elicitation/create", async (request) => {
          const code = /Confirmation code: ([A-Z2-9]{8})/u.exec(
            String(request.params.message)
          )?.[1];
          if (!code) throw new Error("actual acceptance form omitted its code");
          return { action: "accept", content: { approve: true, confirmation_code: code } };
        });
        const acceptance = {
          name: "manage_company_admin",
          arguments: {
            schema_version: "boardagent.tool-input.v1",
            idempotency_key: "response-loss-admin-accept-0001",
            change: {
              operation: "accept",
              proposal_id: proposalId,
              expected_proposal_version: 1,
              reason: "Accept this exact administrator responsibility"
            }
          }
        };
        await expect(target.callTool(acceptance)).rejects.toThrow(
          "synthetic lost acceptance response"
        );
        expect(droppedReplies).toBe(1);
        const committed = async () =>
          (
            await pool.query(
              `select
          (select count(*)::int from organization_role_assignments where member_id=$1 and role='admin' and active_until is null) as assignments,
          (select count(*)::int from audit_events where event_type='company_admin_granted') as grants,
          (select count(*)::int from administrative_authority_changes where action_code='manage_company_admin') as authority_changes,
          (select state from company_admin_proposals where id=$2) as state`,
              [f.target.memberId, proposalId]
            )
          ).rows[0];
        const original = await committed();
        expect(original).toEqual({
          assignments: 1,
          grants: 1,
          authority_changes: 2,
          state: "accepted"
        });
        await expect(target.callTool(acceptance)).rejects.toMatchObject({ status: 401 });
        const reconnected = await f.connect(await f.login(f.target.memberId));
        expect(
          (
            await reconnected.callTool({
              name: "list_administrative_access",
              arguments: {
                schema_version: "boardagent.tool-input.v1",
                mode: "organization"
              }
            })
          ).isError
        ).not.toBe(true);
        expect((await reconnected.callTool(acceptance)).isError).toBe(true);
        expect(await committed()).toEqual(original);
        expect(f.errors).toEqual([]);
      } finally {
        await target?.close();
        await f.close();
      }
    });
  }, 120_000);
});
