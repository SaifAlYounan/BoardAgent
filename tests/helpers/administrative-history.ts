import type { Pool } from "pg";
import { generateKeyPairSync } from "node:crypto";
import { delegationFixture } from "./administrative-delegation.js";
import { stageAdministrativeAction } from "./administrative-service.js";
import { seedAdditionalAuthorizedActor, testId } from "./authorized-actor.js";
import { expect } from "vitest";

/** Arrange real confirmed administrative history in a disposable database. */
export async function administrativeHistory(pool: Pool) {
  const f = await delegationFixture(pool);
  expect(
    (
      await (
        await stageAdministrativeAction(pool, f.issuer, "manage_member_admin_delegation", f.input)
      ).confirm()
    ).confirmed
  ).toBe(true);
  expect(
    (
      await (
        await stageAdministrativeAction(pool, f.issuer, "manage_member_admin_delegation", {
          schema_version: "boardagent.tool-input.v1",
          idempotency_key: "export-delegation-revocation",
          change: {
            operation: "revoke",
            delegation_id: f.input.change.delegation_id,
            board_id: f.issuer.boardId,
            expected_delegation_version: 1,
            reason: "Retain revoked authority in the export"
          }
        })
      ).confirm()
    ).confirmed
  ).toBe(true);
  const other = await seedAdditionalAuthorizedActor(pool, f.issuer, {
    idBase: 94_000,
    seatRole: "voting_member",
    scopes: ["governance:read"]
  });
  for (const [index, target] of [f.target, other].entries()) {
    const version = Number(
      (await pool.query("select row_version from members where id=$1", [target.memberId])).rows[0]
        ?.row_version
    );
    expect(
      (
        await (
          await stageAdministrativeAction(pool, f.issuer, "manage_company_admin", {
            schema_version: "boardagent.tool-input.v1",
            idempotency_key: `export-admin-proposal-${index}`,
            change: {
              operation: "grant",
              proposal_id: testId(94_100 + index),
              member_id: target.memberId,
              expected_member_version: version,
              reason: "Retain a pending admin offer"
            }
          })
        ).confirm()
      ).confirmed
    ).toBe(true);
  }
  // The basic actor helper uses placeholder JWKs because H transaction tests do
  // not sign bearer tokens. A backup fixture must contain valid public key data.
  const oauthKeys = await pool.query<{ id: string }>(
    "select id from crypto_key_registry where purpose='oauth_signing'"
  );
  for (const key of oauthKeys.rows)
    await pool.query("update crypto_key_registry set public_jwk=$1 where id=$2", [
      generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey.export({ format: "jwk" }),
      key.id
    ]);
  return { ...f, other };
}
