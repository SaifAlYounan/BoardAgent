import { createHash, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { withIdentityTransaction, withRequestTransaction } from "../../lib/db/src/index.js";
import { administrativeOAuthFixture, testAuthenticator } from "../helpers/administrative-oauth.js";
import { withAdministrativeDatabase } from "../helpers/administrative-authority.js";

const SCHEMA = "boardagent.tool-input.v1";
type Fixture = Awaited<ReturnType<typeof administrativeOAuthFixture>>;
type Agent = Awaited<ReturnType<Fixture["connect"]>>;
type Pending = {
  memberId: string;
  invitationId: string;
  activationChallengeId: string;
  activationCode: string;
  proofingMethod: string;
  status: string;
};
const activate = (pending: Pending, key: string) => ({
  name: "confirm_enrollment_activation",
  arguments: {
    schema_version: SCHEMA,
    member_id: pending.memberId,
    invitation_id: pending.invitationId,
    challenge_id: pending.activationChallengeId,
    confirmation_code: pending.activationCode,
    proofing_method: pending.proofingMethod,
    idempotency_key: key
  }
});
async function handoff(f: Fixture, admin: Agent, key: string) {
  const result = await admin.callTool({
    name: "initiate_identity_recovery",
    arguments: {
      schema_version: SCHEMA,
      member_id: f.target.memberId,
      reason: "Synthetic verified-person recovery regression",
      proofing_method: "verified_number_call",
      credential_disposition: "revoke_all",
      preserved_credential_ids: [],
      idempotency_key: key
    }
  });
  expect(result.isError).not.toBe(true);
  const data = (
    result.structuredContent as {
      data: { replacement_enrollment: { url: string }; recoveryRequestId: string };
    }
  ).data;
  const token = new URL(data.replacement_enrollment.url).hash.slice(1);
  const browser = f.browserSession();
  const page = await browser.get("/recover");
  const csrf = /name="csrf_token" value="([A-Za-z0-9_-]+)"/u.exec(await page.text())?.[1];
  if (!csrf) throw new Error("missing recovery CSRF");
  const common = { csrf_token: csrf, recovery_token: token };
  const begin = async () => {
    const result = await browser.post("/recover/passkey/begin", common);
    expect(result.status).toBe(200);
    return (await result.json()) as { publicKey: { challenge: string } };
  };
  const register = async () => {
    const options = await begin();
    const auth = testAuthenticator();
    const form = {
      ...common,
      credential: JSON.stringify(auth.registration(options.publicKey.challenge, f.origin))
    };
    const result = await browser.post("/recover/passkey/complete", form);
    expect(result.status, f.errors.map((e) => e.message).join("; ")).toBe(200);
    const pending = (await result.json()) as Pending;
    expect(pending.status).toBe("pending_activation");
    return { auth, form, pending };
  };
  return { browser, common, token, begin, register, requestId: data.recoveryRequestId };
}

async function withRecovery(
  run: (
    f: Fixture,
    admin: Agent,
    pool: Parameters<Parameters<typeof withAdministrativeDatabase>[0]>[0]
  ) => Promise<void>
) {
  await withAdministrativeDatabase(async (pool) => {
    const f = await administrativeOAuthFixture(pool);
    try {
      await run(f, await f.connect(await f.login(f.issuer.memberId)), pool);
    } finally {
      await f.close();
    }
  });
}

describe("AC24 replacement recovery refusals", () => {
  it("keeps an intercepted candidate unusable after a wrong code or cancelled H form, then permits exact human confirmation", async () => {
    await withRecovery(async (f, admin, pool) => {
      const h = await handoff(f, admin, "recovery-wrong-code-start");
      const { pending, auth } = await h.register();
      await f.registerAgent(f.target.memberId, auth);
      await expect(f.login(f.target.memberId)).rejects.toThrow();
      const wrongCode = pending.activationCode.startsWith("2") ? "333-3333" : "222-2222";
      const wrong = await admin.callTool(
        activate({ ...pending, activationCode: wrongCode }, "recovery-wrong-code-attempt")
      );
      expect(wrong.structuredContent).toMatchObject({
        data: { activated: false, reason: "code_mismatch", attempt_count: 1 }
      });
      admin.setRequestHandler("elicitation/create", async () => ({ action: "cancel" }));
      expect(
        (await admin.callTool(activate(pending, "recovery-cancelled-human-form"))).isError
      ).toBe(true);
      expect(
        (
          await pool.query(
            "select count(*)::int as n from webauthn_credentials where member_id=$1 and state='active'",
            [f.target.memberId]
          )
        ).rows[0].n
      ).toBe(0);
      const freshAdmin = await f.connect(await f.login(f.issuer.memberId));
      expect(
        (await freshAdmin.callTool(activate(pending, "recovery-correct-human-form")))
          .structuredContent
      ).toMatchObject({ data: { activated: true, next_action: "fresh_sign_in" } });
      expect(
        (await freshAdmin.callTool(activate(pending, "recovery-replayed-human-form"))).isError
      ).toBe(true);
      const connection = await f.connect(await f.login(f.target.memberId));
      expect(
        (await connection.callTool({ name: "whoami", arguments: { schema_version: SCHEMA } }))
          .isError
      ).not.toBe(true);
      const audit = (
        await pool.query("select convert_from(canonical_payload,'UTF8') as bytes from audit_events")
      ).rows;
      expect(JSON.stringify(audit)).not.toContain(h.token);
      expect(JSON.stringify(audit)).not.toContain(pending.activationCode);
    });
  });

  it("supersedes a lost handoff and rejects a challenge belonging to the earlier recovery", async () => {
    await withRecovery(async (f, admin, pool) => {
      const old = await handoff(f, admin, "recovery-superseded-first");
      const options = await old.begin();
      const current = await handoff(f, admin, "recovery-superseded-second");
      expect((await old.browser.post("/recover/passkey/begin", old.common)).status).toBe(400);
      const stale = testAuthenticator().registration(options.publicKey.challenge, f.origin);
      expect(
        (
          await current.browser.post("/recover/passkey/complete", {
            ...current.common,
            credential: JSON.stringify(stale)
          })
        ).status
      ).toBe(400);
      expect(
        (
          await pool.query(
            "select count(*)::int as n from recovery_registration_grants where consumed_at is not null"
          )
        ).rows[0].n
      ).toBe(0);
      const { pending } = await current.register();
      expect(
        (await admin.callTool(activate(pending, "recovery-current-confirmation"))).structuredContent
      ).toMatchObject({ data: { activated: true } });
    });
  });

  it("refuses a pending candidate after the issuer's identity is recovered, even after that issuer signs in again", async () => {
    await withRecovery(async (f, admin, pool) => {
      const h = await handoff(f, admin, "recovery-issuer-loss-start");
      const { pending } = await h.register();
      const own = await admin.callTool({
        name: "get_member",
        arguments: { schema_version: SCHEMA, member_id: f.issuer.memberId }
      });
      const metadata = (
        own.structuredContent as {
          data: {
            member: {
              recovery_credentials: { items: { kind: string; credential_record_id: string }[] };
            };
          };
        }
      ).data.member.recovery_credentials;
      const passkey = metadata.items.find((item) => item.kind === "passkey");
      if (!passkey) throw new Error("fixture issuer has no recovery metadata");
      const self = await admin.callTool({
        name: "initiate_identity_recovery",
        arguments: {
          schema_version: SCHEMA,
          member_id: f.issuer.memberId,
          reason: "Synthetic issuer generation change",
          proofing_method: "in_person",
          credential_disposition: "preserve_named",
          preserved_credential_ids: [passkey.credential_record_id],
          idempotency_key: "recovery-issuer-generation-change"
        }
      });
      expect(self.isError).not.toBe(true);
      expect(
        (self.structuredContent as { data: Record<string, unknown> }).data.replacement_enrollment
      ).toBeUndefined();
      const freshAdmin = await f.connect(await f.login(f.issuer.memberId));
      expect(
        (await freshAdmin.callTool(activate(pending, "recovery-stale-issuer-confirmation"))).isError
      ).toBe(true);
      expect(
        (
          await pool.query(
            "select count(*)::int as n from webauthn_credentials where member_id=$1 and state='active'",
            [f.target.memberId]
          )
        ).rows[0].n
      ).toBe(0);
    });
  });

  it("accepts only one of two concurrent registrations for the same handoff", async () => {
    await withRecovery(async (f, admin, pool) => {
      const h = await handoff(f, admin, "recovery-racing-registrations");
      const a = await h.begin();
      const b = await h.begin();
      const forms = [a, b].map((options) => ({
        ...h.common,
        credential: JSON.stringify(
          testAuthenticator().registration(options.publicKey.challenge, f.origin)
        )
      }));
      const responses = await Promise.all(
        forms.map((form) => h.browser.post("/recover/passkey/complete", form))
      );
      expect(responses.map((r) => r.status).sort()).toEqual([200, 400]);
      expect(
        (
          await pool.query(
            "select count(*)::int as n from webauthn_credentials where member_id=$1 and state='active'",
            [f.target.memberId]
          )
        ).rows[0].n
      ).toBe(0);
      const winner = responses.find((r) => r.status === 200)!;
      expect(
        (
          await admin.callTool(
            activate((await winner.json()) as Pending, "recovery-race-winner-confirm")
          )
        ).structuredContent
      ).toMatchObject({ data: { activated: true } });
      expect(
        (
          await pool.query(
            "select count(*)::int as n from recovery_registration_grants where activated_at is not null"
          )
        ).rows[0].n
      ).toBe(1);
    });
  });

  it("rolls registration and activation back when their audit append fails, then permits a clean retry", async () => {
    await withRecovery(async (f, admin, pool) => {
      const h = await handoff(f, admin, "recovery-audit-rollback-start");
      const options = await h.begin();
      const form = {
        ...h.common,
        credential: JSON.stringify(
          testAuthenticator().registration(options.publicKey.challenge, f.origin)
        )
      };
      await pool.query(`create function test_refuse_recovery_audit() returns trigger language plpgsql as $$begin
        if new.object_type='identity_recovery' and new.event_type='enrollment_redeemed' then raise exception 'synthetic recovery audit failure'; end if; return new; end$$;
        create trigger test_refuse_recovery_audit before insert on audit_events for each row execute function test_refuse_recovery_audit()`);
      try {
        expect((await h.browser.post("/recover/passkey/complete", form)).status).toBe(500);
        expect(
          (
            await pool.query(
              "select consumed_at from recovery_registration_grants where recovery_request_id=$1",
              [h.requestId]
            )
          ).rows[0].consumed_at
        ).toBeNull();
      } finally {
        await pool.query("drop trigger test_refuse_recovery_audit on audit_events");
      }
      const response = await h.browser.post("/recover/passkey/complete", form);
      expect(response.status).toBe(200);
      const pending = (await response.json()) as Pending;
      await pool.query(
        "create trigger test_refuse_recovery_audit before insert on audit_events for each row execute function test_refuse_recovery_audit()"
      );
      try {
        expect(
          (await admin.callTool(activate(pending, "recovery-audit-failed-confirm"))).isError
        ).toBe(true);
        expect(
          (
            await pool.query(
              "select activated_at from recovery_registration_grants where recovery_request_id=$1",
              [h.requestId]
            )
          ).rows[0].activated_at
        ).toBeNull();
        expect(
          (
            await pool.query(
              "select count(*)::int as n from webauthn_credentials where member_id=$1 and state='active'",
              [f.target.memberId]
            )
          ).rows[0].n
        ).toBe(0);
      } finally {
        await pool.query("drop trigger test_refuse_recovery_audit on audit_events");
      }
      expect(
        (await admin.callTool(activate(pending, "recovery-audit-failed-confirm"))).structuredContent
      ).toMatchObject({ data: { activated: true } });
      expect(f.errors.map((e) => e.message)).toEqual(["synthetic recovery audit failure"]);
    });
  });

  it("rejects a wrong RP/origin response without consuming the handoff", async () => {
    await withRecovery(async (f, admin, pool) => {
      const h = await handoff(f, admin, "recovery-origin-binding-start");
      const options = await h.begin();
      const credential = testAuthenticator().registration(
        options.publicKey.challenge,
        "https://wrong-origin.test"
      );
      expect(
        (
          await h.browser.post("/recover/passkey/complete", {
            ...h.common,
            credential: JSON.stringify(credential)
          })
        ).status
      ).toBe(400);
      expect(
        (
          await pool.query(
            "select consumed_at from recovery_registration_grants where recovery_request_id=$1",
            [h.requestId]
          )
        ).rows[0].consumed_at
      ).toBeNull();
      expect((await h.register()).pending.status).toBe("pending_activation");
    });
  });

  it("uses database time at the exact handoff expiry and hides a foreign organization", async () => {
    await withRecovery(async (f, admin, pool) => {
      const h = await handoff(f, admin, "recovery-exact-expiry-start");
      const hash = createHash("sha256").update(h.token).digest();
      const other = await withIdentityTransaction(
        pool,
        { organizationId: "00000000-0000-7000-8000-000000000099" },
        async (client) =>
          (
            await client.query("select boardagent_lookup_recovery_registration($1) as candidate", [
              hash
            ])
          ).rows[0].candidate,
        { assumeRole: "boardagent_server" }
      );
      expect(other).toBeNull();
      for (const offset of [1, 0, -1]) {
        const candidate = await withIdentityTransaction(
          pool,
          { organizationId: f.issuer.organizationId },
          async (client) => {
            // Test-only clock fixture: align persisted dates to this transaction's exact
            // database time. Restore the trigger before exercising the runtime role.
            await client.query("reset role");
            await client.query(
              "alter table recovery_registration_grants disable trigger boardagent_recovery_registration_grant_transition"
            );
            await client.query(
              "update recovery_registration_grants set created_at=transaction_timestamp()-interval '10 minutes'+$2*interval '1 microsecond', expires_at=transaction_timestamp()+$2*interval '1 microsecond' where recovery_request_id=$1",
              [h.requestId, offset]
            );
            await client.query(
              "alter table recovery_registration_grants enable trigger boardagent_recovery_registration_grant_transition"
            );
            await client.query("set local role boardagent_server");
            return (
              await client.query(
                "select boardagent_lookup_recovery_registration($1) as candidate",
                [hash]
              )
            ).rows[0].candidate;
          },
          { assumeRole: "boardagent_server" }
        );
        if (offset > 0) expect(candidate?.memberId).toBe(f.target.memberId);
        else expect(candidate).toBeNull();
      }
    });
  });

  it("bounds invalid handoff probes before credential lookup and creates no challenges", async () => {
    await withAdministrativeDatabase(async (pool) => {
      const f = await administrativeOAuthFixture(pool);
      try {
        const browser = f.browserSession();
        const page = await browser.get("/recover");
        const csrf = /name="csrf_token" value="([A-Za-z0-9_-]+)"/u.exec(await page.text())?.[1];
        if (!csrf) throw new Error("missing CSRF");
        const before = (await pool.query("select count(*)::int as n from webauthn_challenges"))
          .rows[0].n;
        for (let i = 0; i < 31; i++) {
          const result = await browser.post("/recover/passkey/begin", {
            csrf_token: csrf,
            recovery_token: randomBytes(32).toString("base64url")
          });
          expect(result.status).toBe(i < 30 ? 400 : 429);
          if (i === 30) expect(Number(result.headers.get("retry-after"))).toBeGreaterThan(0);
        }
        expect(
          (await pool.query("select count(*)::int as n from webauthn_challenges")).rows[0].n
        ).toBe(before);
        expect(f.errors).toEqual([]);
      } finally {
        await f.close();
      }
    });
  });
  it("exhausts the twenty-code budget and refuses the correct code after lockout", async () => {
    await withRecovery(async (f, admin, pool) => {
      const h = await handoff(f, admin, "recovery-human-code-lockout");
      const { pending } = await h.register();
      const wrongCode = pending.activationCode.startsWith("2") ? "333-3333" : "222-2222";
      for (let attempt = 1; attempt <= 20; attempt++) {
        const result = await admin.callTool(
          activate(
            { ...pending, activationCode: wrongCode },
            `recovery-lockout-attempt-${String(attempt).padStart(2, "0")}`
          )
        );
        expect(result.structuredContent).toMatchObject({
          data: {
            activated: false,
            attempt_count: attempt,
            challenge_state: attempt === 20 ? "revoked" : "issued"
          }
        });
      }
      expect(
        (await admin.callTool(activate(pending, "recovery-lockout-correct-code"))).isError
      ).toBe(true);
      expect(
        (
          await pool.query(
            "select attempt_count,activated_at from recovery_registration_grants where recovery_request_id=$1",
            [h.requestId]
          )
        ).rows[0]
      ).toMatchObject({ attempt_count: 20, activated_at: null });
      expect(
        (
          await pool.query(
            "select count(*)::int as n from webauthn_credentials where member_id=$1 and state='active'",
            [f.target.memberId]
          )
        ).rows[0].n
      ).toBe(0);
    });
  });

  it("rejects activation at the exact database deadline while preserving the candidate and all authority", async () => {
    await withRecovery(async (f, admin, pool) => {
      const h = await handoff(f, admin, "recovery-activation-deadline");
      const { pending } = await h.register();
      const token = (
        await pool.query(
          "select client_id,jti from access_token_records where member_id=$1 and revoked_at is null order by issued_at desc limit 1",
          [f.issuer.memberId]
        )
      ).rows[0];
      const request = {
        schema_version: SCHEMA,
        member_id: pending.memberId,
        invitation_id: pending.invitationId,
        challenge_id: pending.activationChallengeId,
        confirmation_code_sha256: createHash("sha256").update(pending.activationCode).digest("hex"),
        proofing_method: pending.proofingMethod,
        idempotency_key: "recovery-exact-deadline-confirm"
      };
      for (const offset of [1, 0, -1]) {
        const payload = await withRequestTransaction(
          pool,
          { ...f.issuer.context, clientId: token.client_id, tokenJti: token.jti },
          async (client) => {
            // Test-only date fixture. No live candidate or production clock is modified.
            await client.query("reset role");
            await client.query(
              "alter table recovery_registration_grants disable trigger boardagent_recovery_registration_grant_transition"
            );
            await client.query(
              `update recovery_registration_grants set
            created_at=transaction_timestamp()-interval '11 minutes'+$2*interval '1 microsecond',
            expires_at=transaction_timestamp()-interval '1 minute'+$2*interval '1 microsecond',
            consumed_at=transaction_timestamp()-interval '10 minutes'+$2*interval '1 microsecond',
            activation_expires_at=transaction_timestamp()+$2*interval '1 microsecond' where recovery_request_id=$1`,
              [h.requestId, offset]
            );
            await client.query(
              "alter table recovery_registration_grants enable trigger boardagent_recovery_registration_grant_transition"
            );
            await client.query("set local role boardagent_server");
            return (
              await client.query(
                "select boardagent_prepare_recovery_activation($1::jsonb) as payload",
                [request]
              )
            ).rows[0].payload;
          },
          { assumeRole: "boardagent_server", isolation: "serializable" }
        );
        if (offset > 0) expect(payload?.member?.memberId).toBe(f.target.memberId);
        else expect(payload).toBeNull();
      }
      expect(
        (await admin.callTool(activate(pending, "recovery-expired-human-confirm"))).isError
      ).toBe(true);
      expect(
        (
          await pool.query(
            "select count(*)::int as n from webauthn_credentials where member_id=$1 and state='active'",
            [f.target.memberId]
          )
        ).rows[0].n
      ).toBe(0);
    });
  });
});
