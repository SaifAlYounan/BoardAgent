import { createHash, randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import type { Pool } from "pg";
import { describe, expect, it } from "vitest";
import * as db from "../../lib/db/src/index.js";
import { canonicalJson, canonicalSha256 } from "../../lib/contracts/src/index.js";
import {
  encryptBackupArtifact,
  decryptBackupArtifact
} from "../../scripts/src/recovery-artifact.js";
import { writeBackupKeyReceipt } from "../../scripts/src/backup-key-binding.js";
import { newWorkerTestId, withUnseededWorker } from "../helpers/unseeded-worker.js";

async function prepare(
  pool: Pool,
  organizationId: string,
  keyId: string,
  operation: "replace" | "retire" | "mark_compromised",
  bytes = randomBytes(32)
) {
  const target = (
    await pool.query(
      `select instance_id,(select to_char(activated_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') from crypto_key_registry where id=$1) as activated from system_instance`,
      [keyId]
    )
  ).rows[0];
  const id = newWorkerTestId(),
    hash = createHash("sha256").update(bytes).digest("hex");
  return db.withBootstrapTransaction(
    pool,
    (c) =>
      db.prepareKeyLifecycleInTransaction(c, {
        instanceId: target.instance_id,
        organizationId,
        keyId,
        operationId: newWorkerTestId(),
        operation,
        replacement:
          operation === "replace"
            ? {
                keyId: id,
                kid: `backup-${id}`,
                algorithm: "A256GCM",
                publicJwk: null,
                nonsecretLocator: `sha256:${hash}`,
                materialSha256: hash
              }
            : null,
        declaredCompromisedAt: operation === "mark_compromised" ? target.activated : null,
        retainedMaterialSha256: "a".repeat(64),
        operatorReference: "Synthetic backup operator",
        reason: "Backup key lifecycle regression"
      }),
    { assumeRole: "boardagent_migrator", readOnly: true }
  );
}
const apply = (pool: Pool, input: Awaited<ReturnType<typeof prepare>>) =>
  db.withBootstrapTransaction(pool, (c) => db.applyKeyLifecycleInTransaction(c, input), {
    assumeRole: "boardagent_migrator"
  });
const active = (pool: Pool, id: string) =>
  db.withBootstrapTransaction(pool, (c) => db.readActiveBackupKeyInTransaction(c, id), {
    assumeRole: "boardagent_migrator",
    readOnly: true
  });
async function decrypt(filename: string, key: Uint8Array) {
  const chunks: Buffer[] = [];
  for await (const chunk of decryptBackupArtifact(filename, key)) chunks.push(chunk);
  return Buffer.concat(chunks);
}

describe("backup key lifecycle", () => {
  it("replaces the backup key, preserves old encrypted bytes and receipts, and selects the new writer", async () => {
    await withUnseededWorker(
      "backup-key-replace",
      async ({ pool, organizationId, backupKeyId }) => {
        const oldKey = randomBytes(32),
          newKey = randomBytes(32);
        // Explicit synthetic material binding before the tested lifecycle starts.
        await pool.query("update crypto_key_registry set nonsecret_locator=$1 where id=$2", [
          `sha256:${createHash("sha256").update(oldKey).digest("hex")}`,
          backupKeyId
        ]);
        const directory = await mkdtemp(path.join(tmpdir(), "boardagent-key-backup-"));
        try {
          const oldFile = path.join(directory, "old.enc"),
            newFile = path.join(directory, "new.enc");
          const oldReceipt = await writeBackupKeyReceipt(
            directory,
            await active(pool, backupKeyId)
          );
          const receiptBytes = await readFile(oldReceipt.receiptFile);
          const content = Buffer.from(
            "Synthetic backup artifact; not a database restore qualification"
          );
          await encryptBackupArtifact(Readable.from([content]), oldFile, oldKey);
          const oldBytes = await readFile(oldFile);
          const input = await prepare(pool, organizationId, backupKeyId, "replace", newKey);
          const first = await apply(pool, input);
          await expect(active(pool, backupKeyId)).rejects.toThrow(
            "no active registered fingerprint"
          );
          const replacement = await active(pool, input.request.replacement!.keyId);
          expect(replacement.fingerprintSha256).toBe(
            createHash("sha256").update(newKey).digest("hex")
          );
          await writeBackupKeyReceipt(directory, replacement);
          await encryptBackupArtifact(Readable.from([content]), newFile, newKey);
          expect(await decrypt(oldFile, oldKey)).toEqual(content);
          expect(await decrypt(newFile, newKey)).toEqual(content);
          await expect(decrypt(oldFile, newKey)).rejects.toThrow();
          expect(await readFile(oldFile)).toEqual(oldBytes);
          expect(await readFile(oldReceipt.receiptFile)).toEqual(receiptBytes);
          expect(await apply(pool, input)).toEqual({ ...first, replayed: true });
          const reuse = await prepare(pool, organizationId, replacement.keyId, "replace", oldKey);
          await expect(apply(pool, reuse)).rejects.toMatchObject({ code: "55000" });
          expect((await active(pool, replacement.keyId)).keyId).toBe(replacement.keyId);
        } finally {
          oldKey.fill(0);
          newKey.fill(0);
          await rm(directory, { recursive: true, force: true });
        }
      }
    );
  });

  it.each(["retire", "mark_compromised"] as const)(
    "%s preserves backup history and allows a distinct replacement",
    async (operation) => {
      await withUnseededWorker(
        `backup-key-${operation}`,
        async ({ pool, organizationId, backupKeyId }) => {
          const before = (
            await pool.query("select * from crypto_key_registry where id=$1", [backupKeyId])
          ).rows[0];
          const input = await prepare(pool, organizationId, backupKeyId, operation);
          const receipt = await apply(pool, input);
          await expect(active(pool, backupKeyId)).rejects.toThrow(
            "no active registered fingerprint"
          );
          const changed = (
            await pool.query("select * from crypto_key_registry where id=$1", [backupKeyId])
          ).rows[0];
          expect({
            ...changed,
            retired_at: before.retired_at,
            compromised_at: before.compromised_at
          }).toEqual(before);
          await apply(pool, await prepare(pool, organizationId, backupKeyId, "replace"));
          const after = (
            await pool.query("select * from crypto_key_registry where id=$1", [backupKeyId])
          ).rows[0];
          expect(after.compromised_at).toEqual(changed.compromised_at);
          if (operation === "retire") expect(after.retired_at).toEqual(changed.retired_at);
          expect(await apply(pool, input)).toEqual({ ...receipt, replayed: true });
        }
      );
    }
  );

  it("refuses reused fingerprints and malformed backup replacements at the SQL boundary", async () => {
    await withUnseededWorker(
      "backup-key-invalid",
      async ({ pool, organizationId, backupKeyId }) => {
        const input = await prepare(pool, organizationId, backupKeyId, "replace");
        for (const mutation of [
          { materialSha256: "a".repeat(64), nonsecretLocator: `sha256:${"a".repeat(64)}` },
          { nonsecretLocator: `sha256:${"b".repeat(64)}` },
          { nonsecretLocator: "file:/tmp/backup.key" },
          { kid: "backup-wrong-key" },
          { publicJwk: {} }
        ]) {
          const request = {
            ...input.request,
            replacement: { ...input.request.replacement!, ...mutation }
          };
          const { observedAt: _time, ...dependencies } = request.expectedInventory.keyDependencies;
          await expect(
            db.withBootstrapTransaction(
              pool,
              (c) =>
                c.query("select * from boardagent_begin_key_lifecycle($1,$2,$3)", [
                  Buffer.from(canonicalJson(request)),
                  Buffer.from(canonicalSha256(request), "hex"),
                  Buffer.from(
                    canonicalJson({ ...request.expectedInventory, keyDependencies: dependencies })
                  )
                ]),
              { assumeRole: "boardagent_migrator" }
            )
          ).rejects.toMatchObject({ code: "55000" });
        }
        expect((await active(pool, backupKeyId)).keyId).toBe(backupKeyId);
      }
    );
  });

  it("rolls back both key rows when replacement lacks its audit and completion", async () => {
    await withUnseededWorker(
      "backup-key-incomplete",
      async ({ pool, organizationId, backupKeyId }) => {
        const input = await prepare(pool, organizationId, backupKeyId, "replace");
        const { observedAt: _time, ...dependencies } =
          input.request.expectedInventory.keyDependencies;
        let reachedReplacement = false;
        await expect(
          db.withBootstrapTransaction(
            pool,
            async (c) => {
              await c.query("select * from boardagent_begin_key_lifecycle($1,$2,$3)", [
                Buffer.from(canonicalJson(input.request)),
                Buffer.from(input.requestSha256, "hex"),
                Buffer.from(
                  canonicalJson({
                    ...input.request.expectedInventory,
                    keyDependencies: dependencies
                  })
                )
              ]);
              expect(
                (await db.readActiveBackupKeyInTransaction(c, input.request.replacement!.keyId))
                  .keyId
              ).toBe(input.request.replacement!.keyId);
              reachedReplacement = true;
            },
            { assumeRole: "boardagent_migrator" }
          )
        ).rejects.toMatchObject({ code: "23514" });
        expect(reachedReplacement).toBe(true);
        expect((await active(pool, backupKeyId)).keyId).toBe(backupKeyId);
        expect(
          (
            await pool.query("select id from crypto_key_registry where id=$1", [
              input.request.replacement!.keyId
            ])
          ).rows
        ).toHaveLength(0);
      }
    );
  });
});
