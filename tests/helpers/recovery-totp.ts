import { randomBytes } from "node:crypto";
import type { Pool } from "pg";
import {
  generateTotpCodeFromBase32,
  PgRateLimiter,
  PgTotpService
} from "../../artifacts/server/src/index.js";
import { testId } from "./authorized-actor.js";

// Synthetic enrollment uses the same encrypted-seed and first-code lifecycle as
// the application. No trigger bypass or impossible active credential fixture.
export async function recoveryTotp(
  pool: Pool,
  organizationId: string,
  authorizedByMemberId: string,
  idBase = 114_000
) {
  const keyId = testId(idBase);
  await pool.query(
    `insert into crypto_key_registry(id,organization_id,kid,purpose,algorithm,
      nonsecret_locator,activated_at)
     values($1,$2,$3,'data_kek','A256GCM','test://recovery-totp',transaction_timestamp())`,
    [keyId, organizationId, `recovery-totp-${String(idBase)}`]
  );
  let nextId = idBase + 1;
  const policy = { windowSeconds: 60, maxRequests: 100, blockSeconds: 60 };
  const service = new PgTotpService(pool, {
    issuer: "BoardAgent synthetic recovery",
    activeKeyId: keyId,
    keys: new Map([[keyId, randomBytes(32)]]),
    rateLimiter: new PgRateLimiter(pool, {
      hmacKey: randomBytes(32),
      assumeRole: "boardagent_server"
    }),
    rateLimits: { ip: policy, client: policy, member: policy, token: policy },
    maxFailedAttempts: 3,
    lockoutSeconds: 300,
    assumeRole: "boardagent_server",
    newId: () => testId(nextId++)
  });
  const begin = (memberId: string) =>
    service.beginEnrollment({
      organizationId,
      memberId,
      authorizedByMemberId
    });
  const activate = async (enrollment: Awaited<ReturnType<typeof begin>>) => {
    const now = (
      await pool.query("select floor(extract(epoch from clock_timestamp()))::bigint as now")
    ).rows[0].now;
    await service.completeEnrollment({
      organizationId,
      credentialId: enrollment.credentialId,
      authorizedByMemberId,
      code: generateTotpCodeFromBase32(enrollment.secretBase32, Number(now))
    });
  };
  return { service, begin, activate };
}
