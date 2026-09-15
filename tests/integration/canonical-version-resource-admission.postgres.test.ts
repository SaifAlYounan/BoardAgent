import { createHash } from "node:crypto";
import type { PoolClient } from "pg";
import { expect, it } from "vitest";
import { loadAdmittedCanonicalVersion } from "../../artifacts/server/src/canonical-version-resource.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import { canonicalJson } from "../../lib/contracts/src/canonical.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import {
  seedAuthorizedActor,
  seedAdditionalAuthorizedActor,
  testId,
  type AuthorizedActorFixture
} from "../helpers/authorized-actor.js";

it("loads exact admitted agenda and submission versions under actual server-role visibility", async () => {
  await withMigratedDatabase("canonical_resources", async (pool) => {
    const owner = await seedAuthorizedActor(pool, {
      seatRole: "management",
      scopes: ["documents:read", "documents:contribute"]
    });
    const secretary = await seedAdditionalAuthorizedActor(pool, owner, {
      idBase: 100,
      seatRole: "voting_member",
      scopes: ["governance:read", "secretariat:admin"],
      isSecretary: true
    });
    const stranger = await seedAdditionalAuthorizedActor(pool, owner, {
      idBase: 200,
      seatRole: "management",
      scopes: ["documents:read", "documents:contribute"]
    });
    const submissionId = testId(1000),
      submissionVersionId = testId(1001);
    const meetingId = testId(1100),
      meetingVersionId = testId(1101),
      agendaId = testId(1102);
    const smallSubmission = Buffer.from(
      canonicalJson({
        schema_version: "boardagent.management-submission.v1",
        values: { purpose: "Synthetic Mining materials Δ", document_references: [] }
      })
    );
    const smallAgenda = Buffer.from(
      canonicalJson({
        schema_version: "boardagent.agenda.v1",
        values: {
          items: [
            {
              title: "Mining programme Δ",
              source_document_version_id: null,
              source_document_sha256: null
            }
          ]
        }
      })
    );
    const hash = (bytes: Buffer) => createHash("sha256").update(bytes).digest();
    // Isolated storage fixtures with valid canonical bytes, hashes and normal
    // constraints/triggers. This case does not certify public creation workflows.
    await pool.query(
      `insert into management_submission_threads(id,organization_id,board_id,management_owner_ids,assigned_secretary_id,created_by)
      values ($1,$2,$3,array[$4::uuid],$5,$4)`,
      [submissionId, owner.organizationId, owner.boardId, owner.memberId, secretary.memberId]
    );
    await pool.query(
      `insert into management_submission_versions(id,organization_id,board_id,thread_id,version,schema_version,canonical_payload,document_references,payload_sha256,author_member_id,change_reason)
      values ($1,$2,$3,$4,1,'boardagent.management-submission.v1',$5,'[]',$6,$7,'Synthetic fixture')`,
      [
        submissionVersionId,
        owner.organizationId,
        owner.boardId,
        submissionId,
        smallSubmission,
        hash(smallSubmission),
        owner.memberId
      ]
    );
    await pool.query(
      "update management_submission_threads set current_version_id=$2,row_version=row_version+1 where id=$1",
      [submissionId, submissionVersionId]
    );
    await pool.query(
      `insert into meetings(id,organization_id,board_id,title,state,scheduled_start,scheduled_end,created_by)
      values ($1,$2,$3,'Mining programme','called','2026-10-01T09:00:00Z','2026-10-01T10:00:00Z',$4)`,
      [meetingId, owner.organizationId, owner.boardId, secretary.memberId]
    );
    await pool.query(
      `insert into meeting_versions(id,organization_id,board_id,meeting_id,version,canonical_schema,canonical_title,scheduled_start,scheduled_end,notice_package,notice_package_sha256,canonical_sha256,change_reason,created_by)
      values ($1,$2,$3,$4,1,'boardagent.meeting.v1','Mining programme','2026-10-01T09:00:00Z','2026-10-01T10:00:00Z',$5,$6,$6,'Synthetic fixture',$7)`,
      [
        meetingVersionId,
        owner.organizationId,
        owner.boardId,
        meetingId,
        smallAgenda,
        hash(smallAgenda),
        secretary.memberId
      ]
    );
    await pool.query(
      `insert into agenda_versions(id,organization_id,board_id,meeting_id,meeting_version_id,version,schema_version,canonical_payload,canonical_sha256,created_by)
      values ($1,$2,$3,$4,$5,1,'boardagent.agenda.v1',$6,$7,$8)`,
      [
        agendaId,
        owner.organizationId,
        owner.boardId,
        meetingId,
        meetingVersionId,
        smallAgenda,
        hash(smallAgenda),
        secretary.memberId
      ]
    );
    await pool.query(
      "update meetings set current_version_id=$2,current_agenda_version_id=$3,row_version=row_version+1 where id=$1",
      [meetingId, meetingVersionId, agendaId]
    );
    const manager = new ResponseAllocationManager();
    async function read(
      actor: AuthorizedActorFixture,
      kind: "submission" | "agenda",
      options: {
        boardId?: string;
        afterMetadata?: () => Promise<void>;
        requireSaturation?: boolean;
      } = {}
    ) {
      const request = manager.openRequest(new AbortController().signal);
      let preflight = 0,
        content = 0;
      try {
        const value = await request.produce(() =>
          withRequestTransaction(
            pool,
            actor.context,
            async (client) => {
              const role = await client.query<{ current_user: string }>("select current_user");
              expect(role.rows[0]?.current_user).toBe("boardagent_server");
              const observed = {
                query: async (sql: string, values?: unknown[]) => {
                  const isMetadata = sql.includes("as byte_length");
                  if (!isMetadata) {
                    content += 1;
                    expect(manager.accounting.usedUnits).toBeGreaterThan(0);
                  }
                  const result = await client.query(sql, values);
                  if (isMetadata) {
                    preflight += 1;
                    for (const row of result.rows) {
                      expect(Object.keys(row).sort()).toEqual([
                        "byte_length",
                        "id",
                        "sha256",
                        "version"
                      ]);
                      expect(row).toMatchObject({
                        version: 1,
                        byte_length: (kind === "submission" ? smallSubmission : smallAgenda).length,
                        sha256: hash(
                          kind === "submission" ? smallSubmission : smallAgenda
                        ).toString("hex")
                      });
                    }
                    await options.afterMetadata?.();
                  }
                  return result;
                }
              } as unknown as PoolClient;
              return loadAdmittedCanonicalVersion(observed, {
                kind,
                boardId: options.boardId ?? owner.boardId,
                parentId: kind === "submission" ? submissionId : meetingId,
                version: 1,
                memberId: actor.memberId
              });
            },
            { assumeRole: "boardagent_server" }
          )
        );
        if (value) {
          expect(preflight).toBe(1);
          expect(content).toBe(1);
          expect(value).toEqual({
            id: kind === "submission" ? submissionVersionId : agendaId,
            version: 1,
            bytes: kind === "submission" ? smallSubmission : smallAgenda
          });
          expect(manager.accounting.usedUnits).toBe(1);
          request.nativeTerminal();
          expect(manager.accounting.usedUnits).toBe(1);
        }
        return value;
      } finally {
        if (options.requireSaturation) {
          expect(preflight).toBe(1);
          expect(content).toBe(0);
        }
        request.nativeTerminal();
        request.collectorSettled();
      }
    }
    expect(await read(owner, "submission")).not.toBeNull();
    expect(await read(secretary, "submission")).not.toBeNull();
    expect(await read(stranger, "submission")).toBeNull();
    expect(await read(secretary, "agenda")).not.toBeNull();
    expect(await read(secretary, "agenda", { boardId: testId(9999) })).toBeNull();
    const leases = Array.from({ length: 2048 }, (_, index) =>
      manager.tryReserve(
        responseAllocationPlan({
          kind: "document",
          representation: "resource",
          sourceId: `small-${index}`,
          sourceVersion: "1",
          sha256: "b".repeat(64),
          canonicalBytes: 2
        })
      )
    );
    try {
      await expect(read(owner, "submission", { requireSaturation: true })).rejects.toBeInstanceOf(
        ResponseAllocationUnavailable
      );
      await expect(read(secretary, "agenda", { requireSaturation: true })).rejects.toBeInstanceOf(
        ResponseAllocationUnavailable
      );
      expect(manager.accounting.usedUnits).toBe(2048);
    } finally {
      for (const lease of leases) lease.release();
    }
    // Lose the explicit parent-owner grant after the first statement. This is an
    // authorized fixture mutation, not a claim about every token-revocation policy.
    expect(
      await read(owner, "submission", {
        afterMetadata: async () => {
          await pool.query(
            "update management_submission_threads set management_owner_ids=array[$2::uuid],row_version=row_version+1 where id=$1",
            [submissionId, secretary.memberId]
          );
        }
      })
    ).toBeNull();
    expect(manager.accounting.usedUnits).toBe(0);
  });
}, 30_000);
