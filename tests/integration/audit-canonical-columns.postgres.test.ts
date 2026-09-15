import { expect, it } from "vitest";
import { withUnseededWorker } from "../helpers/unseeded-worker.js";
import { seedValidAuditEnvelope } from "../helpers/valid-audit-envelope.js";
import { verifyPersistedAuditEvidence, withWorkerTransaction } from "../../lib/db/src/index.js";

it("checks stored columns and canonical bytes even after an earlier chain failure", async () => {
  await withUnseededWorker("canonical-columns", async ({ pool, config }) => {
    await seedValidAuditEnvelope(pool, config, 1000);
    const verify = () =>
      withWorkerTransaction(pool, verifyPersistedAuditEvidence, {
        assumeRole: "boardagent_worker"
      });
    expect(await verify()).toMatchObject({ valid: true, ready: true, eventCount: "1000" });
    const originals = (
      await pool.query<{
        sequence: string;
        canonical_payload: Buffer;
        event_sha256: Buffer;
        object_type: string;
      }>(
        "select sequence::text,canonical_payload,event_sha256,object_type from public.audit_events where sequence in (2,3) order by sequence"
      )
    ).rows;
    const cases = [
      { hash: true, column: 0, canonical: false, reason: "event_hash_mismatch", sequence: "2" },
      {
        hash: false,
        column: 2,
        canonical: false,
        reason: "event_column_manifest_mismatch",
        sequence: "2"
      },
      {
        hash: true,
        column: 2,
        canonical: false,
        reason: "event_column_manifest_mismatch",
        sequence: "2"
      },
      {
        hash: true,
        column: 3,
        canonical: false,
        reason: "event_column_manifest_mismatch",
        sequence: "3"
      },
      {
        hash: true,
        column: 0,
        canonical: true,
        reason: "event_manifest_not_canonical",
        sequence: "3"
      }
    ];
    // Fixture-owner corruption only. Actual verification uses the restricted worker
    // transaction; each case restores the exact synthetic bytes before the next case.
    const mutate = async (scenario?: (typeof cases)[number]) => {
      const owner = await pool.connect();
      try {
        await owner.query("begin");
        await owner.query("set local session_replication_role=replica");
        if (scenario) {
          if (scenario.hash)
            await owner.query("update public.audit_events set event_sha256=$1 where sequence=2", [
              Buffer.alloc(32, 0xff)
            ]);
          if (scenario.column)
            await owner.query(
              "update public.audit_events set object_type='mismatched_object' where sequence=$1",
              [scenario.column]
            );
          if (scenario.canonical)
            await owner.query(
              "update public.audit_events set canonical_payload=$1 where sequence=3",
              [Buffer.concat([Buffer.from(" "), originals[1]!.canonical_payload])]
            );
        } else {
          for (const original of originals)
            await owner.query(
              "update public.audit_events set canonical_payload=$1,event_sha256=$2,object_type=$3 where sequence=$4",
              [
                original.canonical_payload,
                original.event_sha256,
                original.object_type,
                original.sequence
              ]
            );
        }
        await owner.query("commit");
      } catch (error) {
        await owner.query("rollback");
        throw error;
      } finally {
        owner.release();
      }
    };
    for (const scenario of cases) {
      try {
        await mutate(scenario);
        expect(await verify()).toMatchObject({
          valid: false,
          ready: false,
          reason: scenario.reason,
          firstBreakSequence: scenario.sequence
        });
      } finally {
        await mutate();
      }
    }
    expect(await verify()).toMatchObject({ valid: true, ready: true, eventCount: "1000" });
  });
}, 30000);
