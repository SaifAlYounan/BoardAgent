import { createHash } from "node:crypto";
import type { PoolClient } from "pg";
import { expect, it } from "vitest";
import { loadAdmittedGovernanceJson } from "../../artifacts/server/src/governance-json-resource.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import { canonicalJson } from "../../lib/contracts/src/canonical.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";

it("loads exact admitted governance JSON under actual server-role scopes and scalar bindings", async () => {
  await withMigratedDatabase("governance_json", async (pool) => {
    const actor = await seedAuthorizedActor(pool, {
      seatRole: "voting_member",
      isSecretary: true,
      scopes: ["governance:read", "secretariat:admin"]
    });
    const profileId = testId(1000),
      rulesetId = testId(1001);
    // Controlled storage fixtures: normal constraints/RLS, not public schema or
    // profile activation proof. Exercise native JSONB whitespace, nested values,
    // numeric spelling, NFC multibyte and escaping against the old driver result.
    const payload = { z: [0.00001, 1e30, true, null, 'Δ\n"'], a: { text: "synthetic Mining" } };
    const canonical = Buffer.from(canonicalJson(payload));
    const digest = createHash("sha256").update(canonical).digest();
    await pool.query(
      `insert into governance_profiles(id,organization_id,board_id,version,state,schema_version,canonical_payload,canonical_sha256,source_agreement_references,created_by)
      values ($1,$2,$3,1,'draft','boardagent.governance-profile.v1',$4::jsonb,$5,'[]',$6)`,
      [
        profileId,
        actor.organizationId,
        actor.boardId,
        JSON.stringify(payload),
        digest,
        actor.memberId
      ]
    );
    await pool.query(
      `insert into rulesets(id,organization_id,board_id,profile_id,version,state,schema_version,canonical_payload,canonical_sha256,created_by)
      values ($1,$2,$3,$4,1,'draft','boardagent.ruleset.v1',$5::jsonb,$6,$7)`,
      [
        rulesetId,
        actor.organizationId,
        actor.boardId,
        profileId,
        JSON.stringify(payload),
        digest,
        actor.memberId
      ]
    );
    const manager = new ResponseAllocationManager();
    const lanes = [
      { kind: "governance_profile", table: "governance_profiles", id: profileId },
      { kind: "ruleset", table: "rulesets", id: rulesetId }
    ] as const;
    const rawByKind = new Map<string, Buffer>();
    await withRequestTransaction(
      pool,
      actor.context,
      async (client) => {
        for (const lane of lanes) {
          const ordinary = await client.query(
            `select canonical_payload,canonical_payload::text as raw from ${lane.table} where board_id=$1 and version=1`,
            [actor.boardId]
          );
          expect(ordinary.rows).toHaveLength(1);
          expect(Buffer.from(canonicalJson(ordinary.rows[0].canonical_payload))).toEqual(canonical);
          rawByKind.set(lane.kind, Buffer.from(ordinary.rows[0].raw));
        }
      },
      { assumeRole: "boardagent_server" }
    );
    async function read(
      lane: (typeof lanes)[number],
      options: { wrongBoard?: boolean; wrongDigest?: boolean; saturated?: boolean } = {}
    ) {
      const owner = manager.openRequest(new AbortController().signal);
      let content = 0,
        metadata = 0;
      try {
        const value = await owner.produce(() =>
          withRequestTransaction(
            pool,
            actor.context,
            async (client) => {
              expect((await client.query("select current_user")).rows[0].current_user).toBe(
                "boardagent_server"
              );
              const raw = rawByKind.get(lane.kind);
              if (!raw) throw new Error("missing precomputed oracle");
              const observed = {
                query: async (sql: string, values?: unknown[]) => {
                  const isMetadata = sql.includes("as byte_length");
                  if (!isMetadata) {
                    content += 1;
                    expect(manager.accounting.usedUnits).toBeGreaterThan(0);
                  }
                  // Deliberately perturb only the bound metadata digest sent to the real
                  // content query. This verifies SQL binding, not a concurrent DB write.
                  const sent =
                    !isMetadata && options.wrongDigest
                      ? [...(values ?? []).slice(0, 4), Buffer.alloc(32, 255)]
                      : values;
                  const result = await client.query(sql, sent);
                  if (isMetadata) {
                    metadata += 1;
                    for (const row of result.rows) {
                      expect(Object.keys(row).sort()).toEqual([
                        "byte_length",
                        "id",
                        "sha256",
                        "version"
                      ]);
                      expect(row).toEqual({
                        id: lane.id,
                        version: 1,
                        byte_length: raw.length,
                        sha256: createHash("sha256").update(raw).digest("hex")
                      });
                    }
                  }
                  return result;
                }
              } as unknown as PoolClient;
              return loadAdmittedGovernanceJson(observed, {
                kind: lane.kind,
                boardId: options.wrongBoard ? testId(9999) : actor.boardId,
                version: 1
              });
            },
            { assumeRole: "boardagent_server" }
          )
        );
        if (value) {
          expect(value.id).toBe(lane.id);
          expect(value.version).toBe(1);
          expect(Buffer.from(canonicalJson(value.payload as typeof payload))).toEqual(canonical);
          expect(metadata).toBe(1);
          expect(content).toBe(1);
          expect(manager.accounting.usedUnits).toBe(1);
          owner.nativeTerminal();
          expect(manager.accounting.usedUnits).toBe(1);
        }
        return value;
      } finally {
        if (options.saturated) {
          expect(metadata).toBe(1);
          expect(content).toBe(0);
        }
        owner.nativeTerminal();
        owner.collectorSettled();
      }
    }
    for (const lane of lanes) {
      expect(await read(lane)).not.toBeNull();
      expect(await read(lane, { wrongBoard: true })).toBeNull();
      expect(await read(lane, { wrongDigest: true })).toBeNull();
    }
    const smallPlan = responseAllocationPlan({
      kind: "document",
      representation: "resource",
      sourceId: "occupied",
      sourceVersion: "1",
      sha256: "a".repeat(64),
      canonicalBytes: 2
    });
    const leases = Array.from({ length: 2048 }, () => manager.tryReserve(smallPlan));
    try {
      for (const lane of lanes)
        await expect(read(lane, { saturated: true })).rejects.toBeInstanceOf(
          ResponseAllocationUnavailable
        );
      expect(manager.accounting.usedUnits).toBe(2048);
    } finally {
      leases.forEach((lease) => lease.release());
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
}, 30_000);
