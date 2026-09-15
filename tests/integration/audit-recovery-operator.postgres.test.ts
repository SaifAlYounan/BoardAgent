import { generateKeyPairSync, randomBytes } from "node:crypto";
import type { Pool } from "pg";
import { chmod, lstat, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { runOperatorWithDiagnostics } from "../../scripts/src/operator.js";
import { canonicalSha256 } from "../../lib/contracts/src/index.js";
import { seedAgedAudit } from "../helpers/aged-audit.js";
import { testId } from "../helpers/authorized-actor.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";

async function withOperatorFixture(
  run: (fixture: {
    invoke: (
      args: string[],
      overrides?: NodeJS.ProcessEnv
    ) => Promise<{ code: number; output: Record<string, unknown> }>;
    pool: Pool;
    databaseUrl: string;
    directory: string;
    incident: string;
    request: string;
    receipt: string;
    evidenceCount: () => Promise<number>;
    authorityCount: () => Promise<number>;
  }) => Promise<void>
) {
  await withMigratedDatabase("audit-recovery-operator", async (pool) => {
    const fixture = await seedAgedAudit(pool);
    const directory = await mkdtemp(path.join(tmpdir(), "boardagent-audit-recovery-operator-"));
    try {
      const keyFile = path.join(directory, "evidence.pem");
      await writeFile(
        keyFile,
        fixture.evidence.privateKey.export({ type: "pkcs8", format: "pem" }),
        { mode: 0o600 }
      );
      const databaseUrl = pool.options.connectionString;
      if (!databaseUrl) throw new Error("synthetic database URL missing");
      const env = {
        BOARDAGENT_ENV: "test",
        BOARDAGENT_DATABASE_URL: databaseUrl,
        BOARDAGENT_INSTANCE_ID: testId(15),
        BOARDAGENT_ORGANIZATION_ID: fixture.actor.organizationId,
        BOARDAGENT_EVIDENCE_SIGNING_KEY_FILE: keyFile
      };
      const incident = path.join(directory, "incident.json"),
        request = path.join(directory, "request.json"),
        receipt = path.join(directory, "receipt.json");
      await writeFile(
        incident,
        JSON.stringify({
          operatorReference: "synthetic-maintenance-incident",
          reason: "Restarted the worker after the isolated signing outage."
        }),
        { mode: 0o600 }
      );
      await run({
        pool,
        databaseUrl,
        directory,
        incident,
        request,
        receipt,
        invoke: async (args, overrides = {}) => {
          const output: string[] = [];
          const code = await runOperatorWithDiagnostics(
            ["audit-recovery", ...args],
            { ...env, ...overrides },
            {
              stdout: (line) => output.push(line),
              stderr: (line) => output.push(line)
            }
          );
          const line = output.at(-1);
          // Unknown-command usage is intentionally not parsed as a successful result.
          return {
            code,
            output: line?.trimStart().startsWith("{") ? JSON.parse(line) : { message: line }
          };
        },
        evidenceCount: async () =>
          Number((await pool.query("select count(*)::int as n from audit_events")).rows[0]!.n),
        authorityCount: async () =>
          Number((await pool.query("select count(*)::int as n from audit_recoveries")).rows[0]!.n)
      });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
}

describe("operator signing-outage recovery commands", () => {
  it("refuses changed digests, unknown fields, unsafe files and the wrong installation before authority is created", async () => {
    await withOperatorFixture(async (f) => {
      expect((await f.invoke(["prepare", f.incident, f.request])).code).toBe(0);
      const proposal = JSON.parse(await readFile(f.request, "utf8"));
      const original = await readFile(f.request, "utf8");
      await chmod(f.request, 0o644);
      expect(await f.invoke(["apply", f.request, proposal.requestSha256, f.receipt])).toMatchObject(
        { code: 1, output: { reasonCode: "private_file_invalid" } }
      );
      await chmod(f.request, 0o600);
      const link = path.join(f.directory, "request-link.json");
      await symlink(f.request, link);
      expect((await f.invoke(["apply", link, proposal.requestSha256, f.receipt])).code).toBe(1);
      await writeFile(f.request, JSON.stringify({ ...proposal, unknown: "not accepted" }));
      expect((await f.invoke(["apply", f.request, proposal.requestSha256, f.receipt])).code).toBe(
        1
      );
      await writeFile(f.request, original);
      expect(
        await f.invoke(["apply", f.request, proposal.requestSha256, f.receipt], {
          BOARDAGENT_INSTANCE_ID: testId(116_000)
        })
      ).toMatchObject({ code: 1, output: { reasonCode: "installation_target_mismatch" } });
      expect((await f.invoke(["prepare", f.incident, f.request])).code).toBe(1);
      expect(await readFile(f.request, "utf8")).toBe(original);
      expect(await f.evidenceCount()).toBe(1);
      expect(await f.authorityCount()).toBe(0);
    });
  });

  it("rolls back a mismatched signing key and does not require private signing material for an exact committed retry", async () => {
    await withOperatorFixture(async (f) => {
      const missing = path.join(f.directory, "no-private-key.pem");
      expect(
        (
          await f.invoke(["prepare", f.incident, f.request], {
            BOARDAGENT_EVIDENCE_SIGNING_KEY_FILE: missing
          })
        ).code
      ).toBe(0);
      const proposal = JSON.parse(await readFile(f.request, "utf8"));
      const wrong = path.join(f.directory, "wrong-evidence.pem");
      await writeFile(
        wrong,
        generateKeyPairSync("ed25519").privateKey.export({ format: "pem", type: "pkcs8" }),
        { mode: 0o600 }
      );
      expect(
        await f.invoke(["apply", f.request, proposal.requestSha256, f.receipt], {
          BOARDAGENT_EVIDENCE_SIGNING_KEY_FILE: wrong
        })
      ).toMatchObject({ code: 1, output: { reasonCode: "evidence_key_mismatch" } });
      expect(await f.evidenceCount()).toBe(1);
      expect(await f.authorityCount()).toBe(0);
      expect((await f.invoke(["apply", f.request, proposal.requestSha256, f.receipt])).code).toBe(
        0
      );
      expect(
        await f.invoke(["apply", f.request, proposal.requestSha256, f.receipt], {
          BOARDAGENT_EVIDENCE_SIGNING_KEY_FILE: missing
        })
      ).toMatchObject({ code: 0, output: { replayed: true } });
    });
  });

  it("refuses a real worker login that cannot assume operator authority", async () => {
    await withOperatorFixture(async (f) => {
      const role = `boardagent_recovery_runtime_${String(process.pid)}_${randomBytes(4).toString("hex")}`;
      const password = randomBytes(32).toString("hex");
      // Disposable login, solely for this synthetic database permission test.
      const ddl = (
        await f.pool.query(
          "select format('create role %I login password %L in role boardagent_worker',$1::text,$2::text) as sql",
          [role, password]
        )
      ).rows[0]!.sql;
      await f.pool.query(ddl);
      try {
        const url = new URL(f.databaseUrl);
        url.username = role;
        url.password = password;
        expect(
          await f.invoke(["prepare", f.incident, f.request], {
            BOARDAGENT_DATABASE_URL: url.toString()
          })
        ).toMatchObject({ code: 1, output: { reasonCode: "operator_authority_required" } });
        expect(await f.authorityCount()).toBe(0);
      } finally {
        await f.pool.query(`drop role "${role}"`);
      }
    });
  });

  it("inspects and prepares a private exact proposal without changing retained evidence", async () => {
    await withOperatorFixture(async (f) => {
      const inspected = await f.invoke(["inspect"]);
      expect(inspected).toMatchObject({
        code: 1,
        output: {
          action: "inspect",
          status: "inspected",
          verification: { valid: true, ready: false }
        }
      });
      const prepared = await f.invoke(["prepare", f.incident, f.request]);
      expect(prepared).toMatchObject({
        code: 0,
        output: { action: "prepare", status: "prepared" }
      });
      const proposal = JSON.parse(await readFile(f.request, "utf8"));
      expect(proposal.requestSha256).toBe(canonicalSha256(proposal.request));
      expect(prepared.output["requestSha256"]).toBe(proposal.requestSha256);
      expect((await lstat(f.request)).mode & 0o777).toBe(0o600);
      expect(await f.evidenceCount()).toBe(1);
      expect(await f.authorityCount()).toBe(0);
    });
  });

  it("applies only the explicit proposal digest, preserves its receipt and safely repeats after a lost reply", async () => {
    await withOperatorFixture(async (f) => {
      expect((await f.invoke(["prepare", f.incident, f.request])).code).toBe(0);
      const proposal = JSON.parse(await readFile(f.request, "utf8"));
      expect((await f.invoke(["apply", f.request, "a".repeat(64), f.receipt])).code).toBe(1);
      expect(await f.authorityCount()).toBe(0);
      const applied = await f.invoke(["apply", f.request, proposal.requestSha256, f.receipt]);
      expect(applied).toMatchObject({ code: 0, output: { status: "committed", replayed: false } });
      const receipt = await readFile(f.receipt, "utf8");
      expect(JSON.parse(receipt)).toMatchObject({
        schemaVersion: "boardagent.audit-recovery-receipt.v1",
        recoveryId: proposal.request.recoveryId,
        requestSha256: proposal.requestSha256
      });
      const count = await f.evidenceCount();
      expect(await f.invoke(["apply", f.request, proposal.requestSha256, f.receipt])).toMatchObject(
        { code: 0, output: { status: "committed", replayed: true } }
      );
      expect(await readFile(f.receipt, "utf8")).toBe(receipt);
      expect(await f.evidenceCount()).toBe(count);
      const copy = path.join(f.directory, "inspected-receipt.json");
      expect(await f.invoke(["inspect", proposal.request.recoveryId, copy])).toMatchObject({
        code: 0,
        output: { status: "inspected", verification: { valid: true, ready: true } }
      });
      expect(await readFile(copy, "utf8")).toBe(receipt);
    });
  });

  it("reports a committed recovery when receipt publication fails and recreates the receipt without resigning", async () => {
    await withOperatorFixture(async (f) => {
      expect((await f.invoke(["prepare", f.incident, f.request])).code).toBe(0);
      const proposal = JSON.parse(await readFile(f.request, "utf8"));
      const failed = await f.invoke([
        "apply",
        f.request,
        proposal.requestSha256,
        path.join(f.directory, "missing", "receipt.json")
      ]);
      expect(failed).toMatchObject({
        code: 1,
        output: {
          status: "committed_receipt_publication_unconfirmed",
          recoveryId: proposal.request.recoveryId
        }
      });
      expect(await f.authorityCount()).toBe(1);
      const count = await f.evidenceCount();
      expect((await f.invoke(["inspect", proposal.request.recoveryId, f.receipt])).code).toBe(0);
      expect(await f.evidenceCount()).toBe(count);
      expect(JSON.parse(await readFile(f.receipt, "utf8"))).toMatchObject({
        recoveryId: proposal.request.recoveryId
      });
    });
  });
});
