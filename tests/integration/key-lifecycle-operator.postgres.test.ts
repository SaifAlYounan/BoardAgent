import { createHash, createPrivateKey, randomBytes } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, realpath, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type { Pool } from "pg";
import { describe, expect, it } from "vitest";
import { BoardAgentBootstrapOperator } from "../../scripts/src/bootstrap.js";
import { runOperatorWithDiagnostics } from "../../scripts/src/operator.js";
import { parseConfig } from "../../lib/config/src/index.js";
import { canonicalSha256 } from "../../lib/contracts/src/index.js";
import { signCheckpoint } from "../../lib/audit/src/index.js";
import { loadBoardAgentKeyMaterial } from "../../artifacts/server/src/key-material.js";
import { runtimeKeyRegistrations } from "../../artifacts/server/src/runtime-binding.js";
import { createBoardAgentServerApplication } from "../../artifacts/server/src/server-application.js";
import {
  applyKeyLifecycleInTransaction,
  prepareAuditCheckpointInTransaction,
  commitAuditCheckpointInTransaction,
  appendAuditEventsInTransaction,
  withWorkerTransaction,
  registerBackupKeyInTransaction,
  registerRuntimeKeysInTransaction,
  withBootstrapTransaction
} from "../../lib/db/src/index.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { newWorkerTestId } from "../helpers/unseeded-worker.js";

type Purpose = "oauth_signing" | "evidence_signing" | "browser_session" | "data_kek" | "backup_kek";
interface Fixture {
  startServer(): Promise<{ close(): Promise<void> }>;
  pool: Pool;
  directory: string;
  requestFile: string;
  receiptFile: string;
  planFile: string;
  recoveryRoot: string;
  plan: {
    schemaVersion: string;
    keyId: string;
    operation: string;
    declaredCompromisedAt: string | null;
    operatorReference: string;
    reason: string;
    keyFiles: { keyId: string; file: string }[];
    recoveryRoots: string[];
    replacement: { keyFile: string; runtimeFile: string } | null;
    custodyReference: string;
  };
  savePlan(): Promise<void>;
  invoke(
    args: string[],
    overrides?: NodeJS.ProcessEnv
  ): Promise<{ code: number; output: Record<string, unknown> }>;
}
async function fixture(purpose: Purpose, run: (f: Fixture) => Promise<void>) {
  await withMigratedDatabase("key-lifecycle-operator", async (pool) => {
    const directory = await mkdtemp(
      path.join(await realpath(tmpdir()), "boardagent-key-operator-")
    );
    try {
      const created = await new BoardAgentBootstrapOperator(pool, {
        assumeRole: "boardagent_migrator"
      }).initialize({
        organizationLegalName: "Synthetic Maintenance Board",
        organizationDisplayName: "Synthetic Maintenance",
        organizationSlug: "synthetic-maintenance",
        timezone: "UTC",
        canonicalResourceUri: "https://maintenance.boardagent.test/mcp",
        boardSlug: "main",
        boardName: "Synthetic Board",
        boardCanonicalPayload: { synthetic: true },
        firstSecretaryLegalName: "Synthetic Unenrolled Person",
        firstSecretaryDisplayName: "Unenrolled",
        votingWeight: 1,
        supportName: "Synthetic operator",
        supportContactMethods: [{ kind: "operator_reference", value: "test" }],
        onboardingTermsText: "No human ceremony performed",
        invitationHandoffMethod: "not delivered"
      });
      if (created.status !== "created") throw new Error("fresh bootstrap required");
      const config = parseConfig({
        BOARDAGENT_ENV: "test",
        BOARDAGENT_DATABASE_URL: pool.options.connectionString,
        BOARDAGENT_ORGANIZATION_ID: created.organizationId,
        BOARDAGENT_PUBLIC_BASE_URL: "https://maintenance.boardagent.test",
        BOARDAGENT_AUTHORIZATION_MODE: "builtin",
        BOARDAGENT_BLOB_ROOT: directory,
        BOARDAGENT_DEV_MASTER_SECRET: "synthetic-key-maintenance-master-material-long-enough",
        BOARDAGENT_TRUSTED_PROXY_HOPS: "1",
        BOARDAGENT_WEBHOOKS_ENABLED: "false"
      });
      const material = await loadBoardAgentKeyMaterial(config),
        backup = randomBytes(32);
      await withBootstrapTransaction(
        pool,
        async (client) => {
          await registerRuntimeKeysInTransaction(
            client,
            created.organizationId,
            runtimeKeyRegistrations(config, material, newWorkerTestId)
          );
          await registerBackupKeyInTransaction(
            client,
            created.organizationId,
            newWorkerTestId(),
            createHash("sha256").update(backup).digest("hex")
          );
        },
        { assumeRole: "boardagent_migrator" }
      );
      const values: Record<Purpose, Buffer | string> = {
        oauth_signing: JSON.stringify(material.oauthPrivateJwk),
        evidence_signing: material.evidencePrivateKey
          .export({ format: "pem", type: "pkcs8" })
          .toString(),
        browser_session: Buffer.from(material.browserSessionKey),
        data_kek: Buffer.from(material.dataEncryptionKey),
        backup_kek: backup
      };
      const keys = (
        await pool.query<{ id: string; purpose: Purpose }>(
          "select id,purpose from crypto_key_registry order by id"
        )
      ).rows;
      const keyFiles = [];
      for (const key of keys) {
        const file = path.join(directory, `${key.purpose}.key`);
        await writeFile(file, values[key.purpose], { mode: 0o600 });
        keyFiles.push({ keyId: key.id, file });
      }
      const recoveryRoot = path.join(directory, "recovery");
      await mkdir(recoveryRoot, { mode: 0o700 });
      const instanceId = (await pool.query("select instance_id from system_instance")).rows[0]
        .instance_id;
      const env = {
        BOARDAGENT_ENV: "test",
        BOARDAGENT_DATABASE_URL: pool.options.connectionString,
        BOARDAGENT_INSTANCE_ID: instanceId,
        BOARDAGENT_ORGANIZATION_ID: created.organizationId
      };
      const planFile = path.join(directory, "plan.json"),
        requestFile = path.join(directory, "request.json"),
        receiptFile = path.join(directory, "receipt.json");
      const plan = {
        schemaVersion: "boardagent.operator-key-plan.v1",
        keyId: keys.find((k) => k.purpose === purpose)!.id,
        operation: "replace",
        declaredCompromisedAt: null as string | null,
        operatorReference: "synthetic-maintenance",
        reason: "Synthetic operator workflow; no human acceptance",
        keyFiles,
        recoveryRoots: [recoveryRoot],
        replacement: {
          keyFile: path.join(directory, "replacement.key"),
          runtimeFile: "/run/boardagent-secrets/maintenance/replacement.key"
        } as Fixture["plan"]["replacement"],
        custodyReference: "Local synthetic files only; off-host custody is not verified"
      };
      const savePlan = () => writeFile(planFile, JSON.stringify(plan), { mode: 0o600 });
      await savePlan();
      await run({
        startServer: () =>
          createBoardAgentServerApplication(pool, config, { assumeRole: "boardagent_server" }),
        pool,
        directory,
        recoveryRoot,
        plan,
        planFile,
        requestFile,
        receiptFile,
        savePlan,
        invoke: async (args, overrides = {}) => {
          const lines: string[] = [];
          const code = await runOperatorWithDiagnostics(
            ["key-lifecycle", ...args],
            { ...env, ...overrides },
            { stdout: (line) => lines.push(line), stderr: (line) => lines.push(line) }
          );
          const line = lines.at(-1);
          return {
            code,
            output: line?.trim().startsWith("{") ? JSON.parse(line) : { message: line }
          };
        }
      });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
}
async function prepared(f: Fixture) {
  const result = await f.invoke(["prepare", f.planFile, f.requestFile]);
  expect(result, JSON.stringify(result.output)).toMatchObject({
    code: 0,
    output: { status: "prepared" }
  });
  const proposal = JSON.parse(await readFile(f.requestFile, "utf8"));
  expect(proposal.requestSha256).toBe(canonicalSha256(proposal.request));
  return proposal;
}

describe("operator key lifecycle commands", () => {
  it("inspects, prepares and applies real private material; recovers the original receipt without files", async () => {
    await fixture("browser_session", async (f) => {
      expect(await f.invoke(["inspect"])).toMatchObject({
        code: 0,
        output: { status: "inspected", keys: expect.any(Array) }
      });
      const old = await readFile(f.plan.keyFiles.find((k) => k.keyId === f.plan.keyId)!.file);
      const proposal = await prepared(f);
      expect(
        await f.invoke(["apply", f.requestFile, proposal.requestSha256, f.receiptFile])
      ).toMatchObject({
        code: 0,
        output: { status: "database_applied", runtimeInstallation: "pending" }
      });
      expect(await readFile(f.plan.keyFiles.find((k) => k.keyId === f.plan.keyId)!.file)).toEqual(
        old
      );
      const receipt = await readFile(f.receiptFile, "utf8");
      for (const key of f.plan.keyFiles) await rename(key.file, `${key.file}.preserved`);
      await rename(f.plan.replacement!.keyFile, `${f.plan.replacement!.keyFile}.preserved`);
      expect(
        await f.invoke(["apply", f.requestFile, proposal.requestSha256, f.receiptFile])
      ).toMatchObject({ code: 0, output: { replayed: true } });
      expect(await readFile(f.receiptFile, "utf8")).toBe(receipt);
      await rm(f.receiptFile);
      expect(
        await f.invoke(["inspect", proposal.request.operationId, f.receiptFile])
      ).toMatchObject({ code: 0, output: { status: "inspected" } });
      expect(await readFile(f.receiptFile, "utf8")).toBe(receipt);
      expect(
        (await f.pool.query("select count(*)::int as n from key_lifecycle_operations")).rows[0].n
      ).toBe(1);
    });
  });
  it("refuses a changed digest, unsafe plan and changed retained files before changing keys", async () => {
    await fixture("data_kek", async (f) => {
      await chmod(f.planFile, 0o666);
      expect((await f.invoke(["prepare", f.planFile, f.requestFile])).code).toBe(1);
      await chmod(f.planFile, 0o600);
      const proposal = await prepared(f);
      expect(await f.invoke(["apply", f.requestFile, "0".repeat(64), f.receiptFile])).toMatchObject(
        { code: 1, output: { reasonCode: "request_digest_mismatch" } }
      );
      await writeFile(path.join(f.recoveryRoot, "new-retained-file"), "preserved", { mode: 0o600 });
      expect(
        await f.invoke(["apply", f.requestFile, proposal.requestSha256, f.receiptFile])
      ).toMatchObject({ code: 1, output: { reasonCode: "retained_material_changed" } });
      expect(
        (await f.pool.query("select count(*)::int as n from key_lifecycle_operations")).rows[0].n
      ).toBe(0);
    });
  });
});

describe("operator key lifecycle purpose and refusal matrix", () => {
  it.each([
    "oauth_signing",
    "evidence_signing",
    "browser_session",
    "data_kek",
    "backup_kek"
  ] as const)(
    "replaces %s through actual protected files and preserves its historical identity",
    async (purpose) => {
      await fixture(purpose, async (f) => {
        const before = (
          await f.pool.query(
            "select public_jwk,nonsecret_locator,kid,activated_at from crypto_key_registry where id=$1",
            [f.plan.keyId]
          )
        ).rows[0];
        const p = await prepared(f);
        const result = await f.invoke(["apply", f.requestFile, p.requestSha256, f.receiptFile]);
        expect(result, JSON.stringify(result.output)).toMatchObject({
          code: 0,
          output: { status: "database_applied" }
        });
        const old = (
          await f.pool.query(
            "select public_jwk,nonsecret_locator,kid,activated_at from crypto_key_registry where id=$1",
            [f.plan.keyId]
          )
        ).rows[0];
        expect(old).toEqual(before);
        const active = (
          await f.pool.query(
            "select id,nonsecret_locator from crypto_key_registry where purpose=$1 and retired_at is null and compromised_at is null",
            [purpose]
          )
        ).rows;
        expect(active).toEqual([
          {
            id: p.request.replacement.keyId,
            nonsecret_locator: p.request.replacement.nonsecretLocator
          }
        ]);
        expect(p.retainedMaterialInventory.keys).toHaveLength(5);
        expect(p.retainedMaterialInventory.offHostCustody).toBe("not_verified");
      });
    }
  );
  it.each(["retire", "mark_compromised"])(
    "records %s without creating or replacing a private file",
    async (operation) => {
      await fixture("evidence_signing", async (f) => {
        f.plan.operation = operation;
        f.plan.replacement = null;
        if (operation === "mark_compromised")
          f.plan.declaredCompromisedAt = (
            await f.pool.query(
              "select to_char(activated_at at time zone 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') as at from crypto_key_registry where id=$1",
              [f.plan.keyId]
            )
          ).rows[0].at;
        await f.savePlan();
        const p = await prepared(f);
        expect(
          await f.invoke(["apply", f.requestFile, p.requestSha256, f.receiptFile])
        ).toMatchObject({ code: 0 });
        expect(p.request.replacement).toBeNull();
        expect(
          (await f.pool.query("select count(*)::int as n from crypto_key_registry")).rows[0].n
        ).toBe(5);
      });
    }
  );
  it("refuses while an actual server is open and succeeds after orderly shutdown", async () => {
    await fixture("evidence_signing", async (f) => {
      const p = await prepared(f),
        server = await f.startServer();
      try {
        expect(
          await f.invoke(["apply", f.requestFile, p.requestSha256, f.receiptFile])
        ).toMatchObject({ code: 1, output: { reasonCode: "stop_server_and_worker" } });
        expect(
          (await f.pool.query("select count(*)::int as n from key_lifecycle_operations")).rows[0].n
        ).toBe(0);
      } finally {
        await server.close();
      }
      expect(
        await f.invoke(["apply", f.requestFile, p.requestSha256, f.receiptFile])
      ).toMatchObject({ code: 0 });
    });
  });
  it("refuses incomplete key custody, altered replacement and receipt collisions before any database effect", async () => {
    await fixture("browser_session", async (f) => {
      const omitted = f.plan.keyFiles.pop()!;
      await f.savePlan();
      expect(await f.invoke(["prepare", f.planFile, f.requestFile])).toMatchObject({
        code: 1,
        output: { reasonCode: "complete_registered_key_files_required" }
      });
      f.plan.keyFiles.push(omitted);
      await f.savePlan();
      const p = await prepared(f),
        raw = await readFile(f.plan.replacement!.keyFile);
      await writeFile(f.plan.replacement!.keyFile, randomBytes(32));
      expect((await f.invoke(["apply", f.requestFile, p.requestSha256, f.receiptFile])).code).toBe(
        1
      );
      await writeFile(f.plan.replacement!.keyFile, raw);
      await writeFile(f.receiptFile, "preserve me", { mode: 0o600 });
      expect(
        await f.invoke(["apply", f.requestFile, p.requestSha256, f.receiptFile])
      ).toMatchObject({ code: 1, output: { reasonCode: "output_file_already_exists" } });
      expect(await readFile(f.receiptFile, "utf8")).toBe("preserve me");
      expect(
        (await f.pool.query("select count(*)::int as n from key_lifecycle_operations")).rows[0].n
      ).toBe(0);
    });
  });
  it("refuses actual runtime database principals and the wrong installation without granting authority", async () => {
    await fixture("evidence_signing", async (f) => {
      const role = `boardagent_key_operator_test_${process.pid}_${randomBytes(4).toString("hex")}`,
        password = randomBytes(32).toString("hex");
      const ddl = (
        await f.pool.query(
          "select format('create role %I login password %L in role boardagent_worker',$1::text,$2::text) as sql",
          [role, password]
        )
      ).rows[0].sql;
      await f.pool.query(ddl);
      try {
        const url = new URL(f.pool.options.connectionString!);
        url.username = role;
        url.password = password;
        expect(
          await f.invoke(["inspect"], { BOARDAGENT_DATABASE_URL: url.toString() })
        ).toMatchObject({ code: 1, output: { reasonCode: "operator_authority_required" } });
      } finally {
        await f.pool.query(
          (await f.pool.query("select format('drop role %I',$1::text) as sql", [role])).rows[0].sql
        );
      }
      expect(
        await f.invoke(["prepare", f.planFile, f.requestFile], {
          BOARDAGENT_INSTANCE_ID: newWorkerTestId()
        })
      ).toMatchObject({ code: 1, output: { reasonCode: "installation_target_mismatch" } });
      expect(
        (await f.pool.query("select count(*)::int as n from key_lifecycle_operations")).rows[0].n
      ).toBe(0);
    });
  });
  it("serializes concurrent identical applies and exact retries to one immutable operation", async () => {
    await fixture("evidence_signing", async (f) => {
      const p = await prepared(f),
        args = ["apply", f.requestFile, p.requestSha256, f.receiptFile];
      const results = await Promise.all([f.invoke(args), f.invoke(args)]);
      expect(results.some((r) => r.code === 0)).toBe(true);
      expect(await f.invoke(args)).toMatchObject({ code: 0, output: { replayed: true } });
      expect(
        (await f.pool.query("select count(*)::int as n from key_lifecycle_operations")).rows[0].n
      ).toBe(1);
      expect(
        (
          await f.pool.query(
            "select count(*)::int as n from audit_events where event_type='key_lifecycle_changed'"
          )
        ).rows[0].n
      ).toBe(1);
    });
  });
});

describe("operator incident containment without missing private material", () => {
  it("contains a compromised key even when its private file is unavailable, then replaces it with fresh material", async () => {
    await fixture("browser_session", async (f) => {
      const file = f.plan.keyFiles.find((key) => key.keyId === f.plan.keyId)!.file;
      await rename(file, `${file}.preserved-unavailable`);
      const changed = {
        ...f.plan,
        operation: "mark_compromised",
        replacement: null,
        declaredCompromisedAt: (
          await f.pool.query(
            "select to_char(activated_at at time zone 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') as at from crypto_key_registry where id=$1",
            [f.plan.keyId]
          )
        ).rows[0].at,
        keyFiles: f.plan.keyFiles.map((key) =>
          key.keyId === f.plan.keyId ? { ...key, file: null } : key
        )
      };
      await writeFile(f.planFile, JSON.stringify(changed));
      const p = await prepared(f);
      expect(
        p.retainedMaterialInventory.keys.find(
          (key: { keyId: string }) => key.keyId === f.plan.keyId
        )
      ).toMatchObject({ file: null, privateMaterial: "unavailable" });
      expect(
        await f.invoke(["apply", f.requestFile, p.requestSha256, f.receiptFile])
      ).toMatchObject({ code: 0 });
      const replacementPlan = {
        ...changed,
        operation: "replace",
        replacement: f.plan.replacement,
        declaredCompromisedAt: null
      };
      await writeFile(f.planFile, JSON.stringify(replacementPlan));
      const nextFile = path.join(f.directory, "after-compromise.json"),
        nextReceipt = path.join(f.directory, "after-compromise-receipt.json");
      expect(await f.invoke(["prepare", f.planFile, nextFile])).toMatchObject({ code: 0 });
      const next = JSON.parse(await readFile(nextFile, "utf8"));
      expect(await f.invoke(["apply", nextFile, next.requestSha256, nextReceipt])).toMatchObject({
        code: 0
      });
      expect(
        (
          await f.pool.query("select compromised_at from crypto_key_registry where id=$1", [
            f.plan.keyId
          ])
        ).rows[0].compromised_at
      ).not.toBeNull();
    });
  });
  it("refuses ordinary data-key replacement when required retained decryption material is unavailable", async () => {
    await fixture("data_kek", async (f) => {
      await writeFile(
        f.planFile,
        JSON.stringify({
          ...f.plan,
          keyFiles: f.plan.keyFiles.map((key) =>
            key.keyId === f.plan.keyId ? { ...key, file: null } : key
          )
        })
      );
      expect(await f.invoke(["prepare", f.planFile, f.requestFile])).toMatchObject({
        code: 1,
        output: { reasonCode: "required_private_material_unavailable" }
      });
      expect(
        (await f.pool.query("select count(*)::int as n from key_lifecycle_operations")).rows[0].n
      ).toBe(0);
    });
  });
});

describe("operator data-key rewrapping with actual stored material", () => {
  it("keeps the notification destination and shared secret while changing their encryption through the CLI", async () => {
    await fixture("data_kek", async (f) => {
      const { Aes256GcmWebhookSecurity } =
        await import("../../artifacts/server/src/webhook-security.js");
      const organizationId = (await f.pool.query("select organization_id from system_instance"))
        .rows[0].organization_id;
      const memberId = newWorkerTestId(),
        webhookId = newWorkerTestId(),
        keyId = f.plan.keyId;
      await f.pool.query(
        "insert into members(id,organization_id,member_kind,legal_name,display_name,state) values($1,$2,'human','Synthetic webhook fixture','Synthetic','active')",
        [memberId, organizationId]
      );
      const oldKey = await readFile(f.plan.keyFiles.find((key) => key.keyId === keyId)!.file);
      const security = new Aes256GcmWebhookSecurity({
        activeKeyId: keyId,
        keys: new Map([[keyId, oldKey]]),
        resolve: async () => [{ address: "8.8.8.8", family: 4 }]
      });
      const context = { organizationId, memberId, webhookId };
      const endpoint = await security.protectEndpoint({
          ...context,
          endpoint: `https://synthetic-notifications.example/board/${webhookId}`
        }),
        secret = security.createSecret(context);
      await f.pool.query(
        `insert into member_webhooks(id,organization_id,member_id,endpoint_ciphertext,endpoint_sha256,secret_ciphertext,secret_sha256,key_id,ssrf_validation_receipt_sha256,state,generation,event_classes,verified_at) values($1,$2,$3,$4,$5,$6,$7,$8,$9,'active',1,array['security'],transaction_timestamp())`,
        [
          webhookId,
          organizationId,
          memberId,
          endpoint.endpointCiphertext,
          Buffer.from(endpoint.endpointSha256, "hex"),
          secret.secretCiphertext,
          Buffer.from(secret.secretSha256, "hex"),
          keyId,
          Buffer.from(endpoint.validationReceiptSha256, "hex")
        ]
      );
      const p = await prepared(f),
        result = await f.invoke(["apply", f.requestFile, p.requestSha256, f.receiptFile]);
      expect(result, JSON.stringify(result.output)).toMatchObject({
        code: 0,
        output: { details: { effects: { rewrappedWebhooks: "1" } } }
      });
      const after = (await f.pool.query("select * from member_webhooks where id=$1", [webhookId]))
        .rows[0];
      expect(after.key_id).toBe(p.request.replacement.keyId);
      expect(after.generation).toBe("2");
      expect(after.endpoint_sha256).toEqual(Buffer.from(endpoint.endpointSha256, "hex"));
      expect(after.secret_sha256).toEqual(Buffer.from(secret.secretSha256, "hex"));
      expect(after.endpoint_ciphertext).not.toEqual(endpoint.endpointCiphertext);
      const nextKey = await readFile(f.plan.replacement!.keyFile);
      const next = new Aes256GcmWebhookSecurity({
        activeKeyId: after.key_id,
        keys: new Map([[after.key_id, nextKey]]),
        resolve: async () => [{ address: "8.8.8.8", family: 4 }]
      });
      expect(
        next.openEndpoint({
          ...context,
          keyId: after.key_id,
          endpointCiphertext: after.endpoint_ciphertext
        })
      ).toBe(endpoint.endpoint);
      expect(
        next.openSecret({
          ...context,
          keyId: after.key_id,
          secretCiphertext: after.secret_ciphertext
        })
      ).toEqual(
        security.openSecret({ ...context, keyId, secretCiphertext: secret.secretCiphertext })
      );
      oldKey.fill(0);
      nextKey.fill(0);
    });
  });
});

describe("reviewed key-maintenance failure boundaries", () => {
  it("records a lost evidence key at full signing debt without admitting ordinary work, then replaces it", async () => {
    await fixture("evidence_signing", async (f) => {
      const organizationId = (await f.pool.query("select organization_id from system_instance"))
        .rows[0].organization_id;
      const ordinaryEvent = () => ({
        organizationId,
        event: {
          eventId: newWorkerTestId(),
          eventType: "context_read" as const,
          actorMemberId: null,
          actorClientId: null,
          tokenJti: null,
          entityType: "context",
          entityId: newWorkerTestId(),
          boardId: null,
          origin: "worker" as const,
          details: { synthetic: true },
          schemaVersion: 1 as const
        }
      });
      const initial = Number(
        (await f.pool.query("select last_sequence from audit_chain_head")).rows[0].last_sequence
      );
      await withWorkerTransaction(
        f.pool,
        (client) =>
          appendAuditEventsInTransaction(
            client,
            Array.from({ length: 1000 - initial }, ordinaryEvent)
          ),
        { assumeRole: "boardagent_worker" }
      );
      const ordinary = () =>
        withWorkerTransaction(
          f.pool,
          (client) => appendAuditEventsInTransaction(client, [ordinaryEvent()]),
          { assumeRole: "boardagent_worker" }
        );
      await expect(ordinary()).rejects.toMatchObject({
        code: "55000",
        constraint: "boardagent_audit_checkpoint_capacity"
      });
      const history = (
        await f.pool.query(
          "select canonical_payload,event_sha256,occurred_at from audit_events order by sequence"
        )
      ).rows;
      const unavailable = f.plan.keyFiles.find((k) => k.keyId === f.plan.keyId)!;
      await rename(unavailable.file, `${unavailable.file}.unavailable`);
      const changed = {
        ...f.plan,
        operation: "mark_compromised",
        replacement: null,
        declaredCompromisedAt: (
          await f.pool.query(
            "select to_char(activated_at at time zone 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') as at from crypto_key_registry where id=$1",
            [f.plan.keyId]
          )
        ).rows[0].at,
        keyFiles: f.plan.keyFiles.map((k) => (k.keyId === f.plan.keyId ? { ...k, file: null } : k))
      };
      await writeFile(f.planFile, JSON.stringify(changed));
      const proposal = await prepared(f);
      // The exact incident receipt cannot grant admission to another append even
      // inside the same trusted transaction. Its failure rolls back containment too.
      await expect(
        withBootstrapTransaction(
          f.pool,
          async (client) => {
            await applyKeyLifecycleInTransaction(client, {
              request: proposal.request,
              requestSha256: proposal.requestSha256
            });
            await appendAuditEventsInTransaction(client, [ordinaryEvent()]);
          },
          { assumeRole: "boardagent_migrator" }
        )
      ).rejects.toMatchObject({
        code: "55000",
        constraint: "boardagent_audit_checkpoint_capacity"
      });
      expect(
        (await f.pool.query("select count(*)::int as n from key_lifecycle_operations")).rows[0].n
      ).toBe(0);
      const contained = await f.invoke([
        "apply",
        f.requestFile,
        proposal.requestSha256,
        f.receiptFile
      ]);
      expect(contained, JSON.stringify(contained.output)).toMatchObject({
        code: 0,
        output: { status: "database_applied" }
      });
      await expect(ordinary()).rejects.toMatchObject({
        code: "55000",
        constraint: "boardagent_audit_checkpoint_capacity"
      });
      await writeFile(
        f.planFile,
        JSON.stringify({
          ...changed,
          operation: "replace",
          replacement: f.plan.replacement,
          declaredCompromisedAt: null
        })
      );
      const nextFile = path.join(f.directory, "next.json"),
        nextReceipt = path.join(f.directory, "next-receipt.json");
      expect(await f.invoke(["prepare", f.planFile, nextFile])).toMatchObject({ code: 0 });
      const next = JSON.parse(await readFile(nextFile, "utf8"));
      expect(await f.invoke(["apply", nextFile, next.requestSha256, nextReceipt])).toMatchObject({
        code: 0,
        output: { status: "database_applied" }
      });
      await expect(ordinary()).rejects.toMatchObject({
        code: "55000",
        constraint: "boardagent_audit_checkpoint_capacity"
      });
      expect(
        (
          await f.pool.query(
            "select canonical_payload,event_sha256,occurred_at from audit_events where sequence<=1000 order by sequence"
          )
        ).rows
      ).toEqual(history);
      expect(
        (await f.pool.query("select count(*)::int as n from key_lifecycle_operations")).rows[0].n
      ).toBe(2);
      expect(
        (
          await f.pool.query(
            "select count(*)::int as n from audit_events where event_type='key_lifecycle_changed'"
          )
        ).rows[0].n
      ).toBe(2);
      expect(
        (await f.pool.query("select count(*)::int as n from audit_checkpoints")).rows[0].n
      ).toBe(0);
      const freshPrivateKey = createPrivateKey(await readFile(f.plan.replacement!.keyFile));
      await withWorkerTransaction(
        f.pool,
        async (client) => {
          const checkpoint = await prepareAuditCheckpointInTransaction(client, {
            checkpointId: newWorkerTestId(),
            signingKeyId: next.request.replacement.keyId
          });
          await commitAuditCheckpointInTransaction(client, {
            checkpoint: signCheckpoint(checkpoint.payload, freshPrivateKey),
            auditEventId: newWorkerTestId()
          });
        },
        { assumeRole: "boardagent_worker" }
      );
      await expect(ordinary()).resolves.toHaveLength(1);
      expect((await f.pool.query("select signing_key_id from audit_checkpoints")).rows).toEqual([
        { signing_key_id: next.request.replacement.keyId }
      ]);
    });
  });
  it.each([
    "oauth_signing",
    "evidence_signing",
    "browser_session",
    "data_kek",
    "backup_kek"
  ] as const)(
    "refuses initial registration as a successor shortcut after %s retirement",
    async (purpose) => {
      await fixture(purpose, async (f) => {
        f.plan.operation = "retire";
        f.plan.replacement = null;
        await f.savePlan();
        const proposal = await prepared(f);
        expect(
          await f.invoke(["apply", f.requestFile, proposal.requestSha256, f.receiptFile])
        ).toMatchObject({ code: 0 });
        const before = (await f.pool.query("select * from crypto_key_registry order by id")).rows;
        const old = before.find((k) => k.id === f.plan.keyId)!;
        const attempted = withBootstrapTransaction(
          f.pool,
          async (client) => {
            if (purpose === "backup_kek")
              return registerBackupKeyInTransaction(
                client,
                old.organization_id,
                newWorkerTestId(),
                createHash("sha256").update(randomBytes(32)).digest("hex")
              );
            return registerRuntimeKeysInTransaction(
              client,
              old.organization_id,
              before
                .filter((k) => k.purpose !== "backup_kek")
                .map((k) => ({
                  keyId: k.id === old.id ? newWorkerTestId() : k.id,
                  kid: k.id === old.id ? `replacement-${newWorkerTestId()}` : k.kid,
                  purpose: k.purpose,
                  algorithm: k.algorithm,
                  publicJwk: k.public_jwk,
                  nonsecretLocator:
                    k.id === old.id ? "file:/run/secrets/unreviewed-successor" : k.nonsecret_locator
                }))
            );
          },
          { assumeRole: "boardagent_migrator" }
        );
        await expect(attempted).rejects.toMatchObject({ code: "23505" });
        expect((await f.pool.query("select * from crypto_key_registry order by id")).rows).toEqual(
          before
        );
        expect(
          (await f.pool.query("select count(*)::int as n from key_lifecycle_operations")).rows[0].n
        ).toBe(1);
      });
    }
  );
});
