import { createHash } from "node:crypto";
import path from "node:path";

import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import {
  generateTotpCodeFromBase32,
  PgRateLimiter,
  PgTotpService,
  type RateLimitPolicy
} from "../../artifacts/server/src/index.js";
import { migrate } from "../../lib/db/src/index.js";
import { testId } from "../helpers/authorized-actor.js";

const MIGRATIONS = path.resolve(import.meta.dirname, "../../lib/db/migrations");
const BASE_URL =
  process.env["BOARDAGENT_TEST_DATABASE_URL"] ??
  "postgresql://boardagent:boardagent-local-only@127.0.0.1:55432/boardagent";
const ORGANIZATION_ID = testId(69_001);
const SECRETARY_ID = testId(69_002);
const MEMBER_ID = testId(69_003);
const OUTSIDER_ID = testId(69_004);
const KEY_ID = testId(69_005);
const CLIENT_ID = testId(69_006);
const SESSION_ID = testId(69_007);
const OPEN_POLICY: RateLimitPolicy = {
  windowSeconds: 60,
  maxRequests: 100,
  blockSeconds: 60
};
let databaseCounter = 0;

async function withDatabase<T>(run: (pool: Pool) => Promise<T>): Promise<T> {
  databaseCounter += 1;
  const database = `boardagent_totp_${String(process.pid)}_${String(databaseCounter)}`;
  const adminUrl = new URL(BASE_URL);
  adminUrl.pathname = "/postgres";
  const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
  await admin.query(`create database "${database}"`);
  const testUrl = new URL(BASE_URL);
  testUrl.pathname = `/${database}`;
  const pool = new Pool({ connectionString: testUrl.toString(), max: 8 });
  try {
    await migrate(pool, MIGRATIONS, "totp-test");
    return await run(pool);
  } finally {
    await pool.end();
    await admin.query(`drop database "${database}" with (force)`);
    await admin.end();
  }
}

async function seedIdentity(pool: Pool): Promise<void> {
  await pool.query(
    "insert into organizations(id,legal_name,display_name,slug,timezone) values ($1,'Org','Org','org','UTC')",
    [ORGANIZATION_ID]
  );
  await pool.query(
    `insert into members(id,organization_id,member_kind,legal_name,display_name,state)
     values ($1,$4,'human','Secretary','Secretary','active'),
            ($2,$4,'human','Member','Member','active'),
            ($3,$4,'human','Outsider','Outsider','active')`,
    [SECRETARY_ID, MEMBER_ID, OUTSIDER_ID, ORGANIZATION_ID]
  );
  await pool.query(
    `insert into organization_role_assignments(
       id,organization_id,member_id,role,change_reason
     ) values ($1,$2,$3,'secretariat','TOTP test authority')`,
    [testId(69_008), ORGANIZATION_ID, SECRETARY_ID]
  );
  await pool.query(
    `insert into crypto_key_registry(
       id,organization_id,kid,purpose,algorithm,public_jwk,nonsecret_locator,activated_at
     ) values ($1,$2,'totp-kek-1','data_kek','A256GCM',null,'test://totp-kek-1',
               transaction_timestamp())`,
    [KEY_ID, ORGANIZATION_ID]
  );
}

function service(
  pool: Pool,
  options: {
    readonly maxFailedAttempts?: number;
    readonly ratePolicy?: RateLimitPolicy;
  } = {}
): PgTotpService {
  let nextId = 69_100;
  let entropyByte = 0x31;
  const selectedPolicy = options.ratePolicy ?? OPEN_POLICY;
  return new PgTotpService(pool, {
    issuer: "BoardAgent",
    activeKeyId: KEY_ID,
    keys: new Map([[KEY_ID, Buffer.alloc(32, 0xa5)]]),
    rateLimiter: new PgRateLimiter(pool, {
      hmacKey: Buffer.alloc(32, 0xb6),
      assumeRole: "boardagent_server"
    }),
    rateLimits: {
      ip: selectedPolicy,
      client: selectedPolicy,
      member: selectedPolicy,
      token: selectedPolicy
    },
    maxFailedAttempts: options.maxFailedAttempts ?? 5,
    lockoutSeconds: 300,
    assumeRole: "boardagent_server",
    newId: () => testId(nextId++),
    randomBytes: (size) => Buffer.alloc(size, entropyByte++)
  });
}

function loginInput(fallbackHandle: string, code: string) {
  return {
    organizationId: ORGANIZATION_ID,
    sessionId: SESSION_ID,
    clientId: CLIENT_ID,
    clientIpClass: "ipv4:127.0.0.0/24",
    fallbackHandle,
    code
  } as const;
}

describe("PostgreSQL TOTP authority", () => {
  it("requires live secretariat enablement, encrypts the seed, and rejects concurrent step replay", async () => {
    await withDatabase(async (pool) => {
      await seedIdentity(pool);
      const totp = service(pool);
      await expect(
        totp.beginEnrollment({
          organizationId: ORGANIZATION_ID,
          memberId: MEMBER_ID,
          authorizedByMemberId: OUTSIDER_ID
        })
      ).rejects.toMatchObject({ code: "enrollment_not_authorized" });

      const enrollment = await totp.beginEnrollment({
        organizationId: ORGANIZATION_ID,
        memberId: MEMBER_ID,
        authorizedByMemberId: SECRETARY_ID
      });
      expect(enrollment).toMatchObject({
        credentialId: expect.stringMatching(/^[0-9a-f-]{36}$/u),
        fallbackHandle: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/u),
        secretBase32: expect.stringMatching(/^[A-Z2-7]{32}$/u),
        provisioningUri: expect.stringMatching(/^otpauth:\/\/totp\//u)
      });
      const stored = await pool.query<{
        authorized_by: string;
        encrypted_secret: Buffer;
        fallback_handle_sha256: Buffer;
        state: string;
      }>(
        `select authorized_by,encrypted_secret,fallback_handle_sha256,state
           from totp_credentials where id=$1`,
        [enrollment.credentialId]
      );
      expect(stored.rows).toHaveLength(1);
      expect(stored.rows[0]).toMatchObject({
        authorized_by: SECRETARY_ID,
        state: "pending_verification"
      });
      expect(stored.rows[0]!.encrypted_secret.toString("utf8")).not.toContain(
        enrollment.secretBase32
      );
      expect(stored.rows[0]!.encrypted_secret.includes(Buffer.from(enrollment.secretBase32))).toBe(
        false
      );
      expect(stored.rows[0]!.fallback_handle_sha256).toEqual(
        createHash("sha256").update(enrollment.fallbackHandle).digest()
      );
      expect(JSON.stringify(stored.rows)).not.toContain(enrollment.fallbackHandle);

      const nowSeconds = Math.floor(Date.now() / 1000);
      await totp.completeEnrollment({
        organizationId: ORGANIZATION_ID,
        credentialId: enrollment.credentialId,
        authorizedByMemberId: SECRETARY_ID,
        code: generateTotpCodeFromBase32(enrollment.secretBase32, nowSeconds)
      });
      await expect(
        totp.authenticate(
          loginInput(
            enrollment.fallbackHandle,
            generateTotpCodeFromBase32(enrollment.secretBase32, nowSeconds + 60)
          )
        )
      ).rejects.toMatchObject({ code: "invalid_totp" });
      const nextCode = generateTotpCodeFromBase32(enrollment.secretBase32, nowSeconds + 30);
      const raced = await Promise.allSettled([
        totp.authenticate(loginInput(enrollment.fallbackHandle, nextCode)),
        totp.authenticate(loginInput(enrollment.fallbackHandle, nextCode))
      ]);
      expect(raced.filter(({ status }) => status === "fulfilled")).toHaveLength(1);
      expect(raced.filter(({ status }) => status === "rejected")).toHaveLength(1);
      expect(raced.find(({ status }) => status === "fulfilled")).toMatchObject({
        status: "fulfilled",
        value: { memberId: MEMBER_ID, credentialId: enrollment.credentialId }
      });
      expect(raced.find(({ status }) => status === "rejected")).toMatchObject({
        status: "rejected",
        reason: { code: "invalid_totp" }
      });
      await expect(
        totp.authenticate(loginInput(enrollment.fallbackHandle, nextCode))
      ).rejects.toMatchObject({ code: "invalid_totp" });
      const active = await pool.query<{
        failed_attempts: number;
        last_accepted_step: string;
        state: string;
      }>(
        `select failed_attempts,last_accepted_step::text,state
           from totp_credentials where id=$1`,
        [enrollment.credentialId]
      );
      expect(active.rows[0]).toMatchObject({
        failed_attempts: 2,
        state: "active"
      });
      expect(Number(active.rows[0]!.last_accepted_step)).toBeGreaterThan(
        Math.floor(nowSeconds / 30)
      );
    });
  });

  it("locks after bounded failures and applies persistent IP/client/member/session rates", async () => {
    await withDatabase(async (pool) => {
      await seedIdentity(pool);
      const totp = service(pool, { maxFailedAttempts: 3 });
      const enrollment = await totp.beginEnrollment({
        organizationId: ORGANIZATION_ID,
        memberId: MEMBER_ID,
        authorizedByMemberId: SECRETARY_ID
      });
      const nowSeconds = Math.floor(Date.now() / 1000);
      const validCodes = new Set(
        [-30, 0, 30].map((offset) =>
          generateTotpCodeFromBase32(enrollment.secretBase32, nowSeconds + offset)
        )
      );
      let wrongCode = "000000";
      while (validCodes.has(wrongCode)) {
        wrongCode = String(Number(wrongCode) + 1).padStart(6, "0");
      }
      await totp.completeEnrollment({
        organizationId: ORGANIZATION_ID,
        credentialId: enrollment.credentialId,
        authorizedByMemberId: SECRETARY_ID,
        code: generateTotpCodeFromBase32(enrollment.secretBase32, nowSeconds)
      });
      for (let attempt = 0; attempt < 3; attempt += 1) {
        await expect(
          totp.authenticate(loginInput(enrollment.fallbackHandle, wrongCode))
        ).rejects.toMatchObject({ code: "invalid_totp" });
      }
      await expect(
        totp.authenticate(
          loginInput(
            enrollment.fallbackHandle,
            generateTotpCodeFromBase32(enrollment.secretBase32, nowSeconds + 30)
          )
        )
      ).rejects.toMatchObject({ code: "invalid_totp" });
      expect(
        await pool.query(
          `select failed_attempts,locked_until>transaction_timestamp() as locked
             from totp_credentials where id=$1`,
          [enrollment.credentialId]
        )
      ).toMatchObject({ rows: [{ failed_attempts: 3, locked: true }] });

      const tightPolicy = { windowSeconds: 60, maxRequests: 2, blockSeconds: 60 } as const;
      const rateLimited = service(pool, { ratePolicy: tightPolicy });
      const unknown = Buffer.alloc(32, 0xf1).toString("base64url");
      const boundedAttempt = {
        ...loginInput(unknown, wrongCode),
        sessionId: testId(69_900),
        clientId: testId(69_901),
        clientIpClass: "ipv4:198.51.100.0/24"
      };
      await expect(rateLimited.authenticate(boundedAttempt)).rejects.toMatchObject({
        code: "invalid_totp"
      });
      await expect(rateLimited.authenticate(boundedAttempt)).rejects.toMatchObject({
        code: "invalid_totp"
      });
      await expect(rateLimited.authenticate(boundedAttempt)).rejects.toMatchObject({
        code: "rate_limited",
        retryAfterSeconds: expect.any(Number)
      });
    });
  });
});
