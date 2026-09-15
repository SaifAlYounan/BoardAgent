import { createHash, createPublicKey, randomBytes, type JsonWebKey } from "node:crypto";
import { lstat } from "node:fs/promises";
import path from "node:path";
import { Pool, type PoolClient } from "pg";
import { z } from "zod";
import { resolveDatabaseUrl } from "@boardagent/config";
import {
  canonicalJson,
  canonicalJsonFromText,
  canonicalSha256,
  Sha256HexSchema,
  UuidV7Schema,
  type JsonValue
} from "@boardagent/contracts";
import { KeyLifecyclePurposeSchema, keyLifecyclePublicMaterialSha256 } from "@boardagent/audit";
import {
  applyKeyLifecycleInTransaction,
  prepareKeyLifecycleInTransaction,
  readKeyLifecycleReceiptInTransaction,
  withBootstrapTransaction,
  KeyLifecyclePreparationSchema,
  KeyLifecycleRequestSchema,
  type KeyLifecycleReceipt
} from "@boardagent/db";
import { uuidV7 } from "@boardagent/domain";
import { Aes256GcmWebhookSecurity } from "@boardagent/server";
import {
  assertDistinctOperatorKeyMaterial,
  assertOperatorFileParents,
  generateOperatorKeyFile,
  loadOperatorKeyMaterial,
  OperatorFilePathSchema,
  readOperatorProtectedFile,
  type OperatorKeyMaterial
} from "./operator-key-files.js";
import { inspectRetainedRecoveryFiles } from "./key-maintenance-inventory.js";
import {
  installKeyGeneration,
  inspectKeyGenerationRequirements,
  KeyGenerationRefusal
} from "./key-generation-install.js";
import { publishRecoveryJson } from "./recovery-publication.js";

const Fields = KeyLifecyclePreparationSchema.shape;
export const OperatorKeyPlanSchema = z
  .object({
    schemaVersion: z.literal("boardagent.operator-key-plan.v1"),
    keyId: UuidV7Schema,
    operation: Fields.operation,
    declaredCompromisedAt: Fields.declaredCompromisedAt,
    operatorReference: Fields.operatorReference,
    reason: Fields.reason,
    keyFiles: z
      .array(z.object({ keyId: UuidV7Schema, file: OperatorFilePathSchema.nullable() }).strict())
      .min(1)
      .max(4096),
    recoveryRoots: z.array(OperatorFilePathSchema).max(64),
    replacement: z
      .object({ keyFile: OperatorFilePathSchema, runtimeFile: OperatorFilePathSchema })
      .strict()
      .nullable(),
    custodyReference: Fields.operatorReference
  })
  .strict()
  .superRefine((plan, context) => {
    if (
      (plan.operation === "replace") !== (plan.replacement !== null) ||
      (plan.operation === "mark_compromised") !== (plan.declaredCompromisedAt !== null) ||
      new Set(plan.keyFiles.map((k) => k.keyId)).size !== plan.keyFiles.length ||
      new Set(plan.keyFiles.flatMap((k) => (k.file === null ? [] : [k.file]))).size !==
        plan.keyFiles.filter((k) => k.file !== null).length ||
      (plan.replacement !== null && plan.keyFiles.some((k) => k.file === plan.replacement!.keyFile))
    )
      context.addIssue({ code: "custom", message: "inconsistent key maintenance plan" });
  });
type Plan = z.infer<typeof OperatorKeyPlanSchema>;
const Proposal = z
  .object({
    schemaVersion: z.literal("boardagent.operator-key-proposal.v1"),
    request: KeyLifecycleRequestSchema,
    requestSha256: Sha256HexSchema,
    plan: OperatorKeyPlanSchema,
    retainedMaterialInventory: z.json()
  })
  .strict()
  .superRefine((p, context) => {
    if (
      canonicalSha256(p.request) !== p.requestSha256 ||
      canonicalSha256(p.retainedMaterialInventory) !== p.request.retainedMaterialSha256 ||
      p.plan.keyId !== p.request.keyId ||
      p.plan.operation !== p.request.operation ||
      p.plan.declaredCompromisedAt !== p.request.declaredCompromisedAt ||
      p.plan.operatorReference !== p.request.operatorReference ||
      p.plan.reason !== p.request.reason
    )
      context.addIssue({ code: "custom", message: "proposal bindings differ" });
  });
const KeyRecord = z
  .object({
    id: UuidV7Schema,
    purpose: KeyLifecyclePurposeSchema,
    kid: z.string(),
    algorithm: z.string(),
    public_jwk: z.json().nullable(),
    nonsecret_locator: z.string(),
    activated_at: z.string(),
    retired_at: z.string().nullable(),
    compromised_at: z.string().nullable()
  })
  .strict();
type RecordKey = z.infer<typeof KeyRecord>;
type Target = { instanceId: string; organizationId: string };
interface Io {
  stdout(line: string): void;
  stderr(line: string): void;
}
const dbOptions = { assumeRole: "boardagent_migrator", statementTimeoutMs: 60_000 } as const;
class Refusal extends Error {
  constructor(readonly reasonCode: string) {
    super(reasonCode);
  }
}
function required(env: NodeJS.ProcessEnv, name: string) {
  const value = env[name];
  if (!value) throw new Refusal("installation_configuration_missing");
  return value;
}
async function jsonFile(file: string): Promise<unknown> {
  const bytes = await readOperatorProtectedFile(file, 16_777_216);
  try {
    return JSON.parse(canonicalJsonFromText(bytes));
  } finally {
    bytes.fill(0);
  }
}
async function publish(file: string, value: JsonValue, exact = false): Promise<void> {
  await assertOperatorFileParents(file);
  if (Buffer.byteLength(canonicalJson(value)) > 16_777_215)
    throw new Refusal("record_file_limit_exceeded");
  try {
    await publishRecoveryJson(file, value);
  } catch (error) {
    if (!exact || !(error instanceof Error) || !("code" in error) || error.code !== "EEXIST")
      throw error;
    if (canonicalJson((await jsonFile(file)) as JsonValue) !== canonicalJson(value))
      throw new Refusal("receipt_file_conflict");
  }
}
async function assertTarget(client: PoolClient, target: Target): Promise<void> {
  const result = await client.query(
    "select instance_id,organization_id from system_instance where singleton_key"
  );
  if (
    result.rows.length !== 1 ||
    result.rows[0].instance_id !== target.instanceId ||
    result.rows[0].organization_id !== target.organizationId
  )
    throw new Refusal("installation_target_mismatch");
}
async function keyRecords(pool: Pool, target: Target): Promise<RecordKey[]> {
  return withBootstrapTransaction(
    pool,
    async (client) => {
      await assertTarget(client, target);
      const rows = await client.query(
        `select id,purpose,kid,algorithm,public_jwk,nonsecret_locator,
      to_char(activated_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as activated_at,
      to_char(retired_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as retired_at,
      to_char(compromised_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as compromised_at
      from crypto_key_registry where organization_id=$1 order by id limit 4097`,
        [target.organizationId]
      );
      if (rows.rows.length > 4096) throw new Refusal("retained_key_limit_exceeded");
      return rows.rows.map((row) => KeyRecord.parse(row));
    },
    { ...dbOptions, readOnly: true }
  );
}
function assertBinding(record: RecordKey, material: OperatorKeyMaterial): void {
  if (
    record.purpose !== material.purpose ||
    record.algorithm !== material.algorithm ||
    (record.purpose === "backup_kek"
      ? record.kid !== `backup-${record.id}` ||
        record.nonsecret_locator !== `sha256:${material.materialSha256}`
      : record.kid !== material.kid) ||
    canonicalJson(record.public_jwk) !== canonicalJson(material.publicJwk)
  )
    throw new Refusal("private_material_registry_mismatch");
}
async function materialSnapshot(
  plan: Plan,
  records: RecordKey[],
  target: Target,
  held: OperatorKeyMaterial[]
) {
  if (
    plan.keyFiles.length !== records.length ||
    records.some((key) => !plan.keyFiles.some((f) => f.keyId === key.id))
  )
    throw new Refusal("complete_registered_key_files_required");
  const keys = [];
  const materials = new Map<string, OperatorKeyMaterial>();
  for (const record of records) {
    const file = plan.keyFiles.find((f) => f.keyId === record.id)!.file;
    let material: OperatorKeyMaterial | undefined;
    let knownFingerprint: string | null = null;
    if (file !== null) {
      material = await loadOperatorKeyMaterial(record.purpose, file);
      held.push(material);
      materials.set(record.id, material);
      assertBinding(record, material);
      knownFingerprint = material.materialSha256;
    } else {
      const historicalVerificationOnly =
        record.retired_at !== null &&
        ["oauth_signing", "evidence_signing", "browser_session"].includes(record.purpose);
      if (
        plan.operation !== "mark_compromised" &&
        record.compromised_at === null &&
        !historicalVerificationOnly
      )
        throw new Refusal("required_private_material_unavailable");
      if (record.purpose === "oauth_signing" || record.purpose === "evidence_signing") {
        const key = createPublicKey({ key: record.public_jwk as JsonWebKey, format: "jwk" });
        const jwk = key.export({ format: "jwk" });
        if (record.purpose === "oauth_signing") {
          if (
            key.asymmetricKeyType !== "ec" ||
            key.asymmetricKeyDetails?.namedCurve !== "prime256v1"
          )
            throw new Refusal("registered_public_material_invalid");
          knownFingerprint = keyLifecyclePublicMaterialSha256({
            kty: "EC",
            crv: "P-256",
            x: jwk.x!,
            y: jwk.y!
          });
        } else {
          if (key.asymmetricKeyType !== "ed25519")
            throw new Refusal("registered_public_material_invalid");
          knownFingerprint = keyLifecyclePublicMaterialSha256({
            kty: "OKP",
            crv: "Ed25519",
            x: jwk.x!
          });
        }
      } else if (record.purpose === "backup_kek") {
        if (!/^sha256:[0-9a-f]{64}$/u.test(record.nonsecret_locator))
          throw new Refusal("registered_backup_fingerprint_invalid");
        knownFingerprint = record.nonsecret_locator.slice(7);
      }
    }
    keys.push({
      keyId: record.id,
      purpose: record.purpose,
      kid: record.kid,
      algorithm: record.algorithm,
      file,
      privateMaterial: material ? "verified_local_file" : "unavailable",
      fileSha256: material?.fileSha256 ?? null,
      materialSha256: knownFingerprint
    });
  }
  const purpose = records.find((record) => record.id === plan.keyId)?.purpose;
  if (!purpose) throw new Refusal("registered_key_not_found");
  const replacement =
    plan.replacement === null
      ? null
      : await loadOperatorKeyMaterial(purpose, plan.replacement.keyFile);
  if (replacement) held.push(replacement);
  await assertDistinctOperatorKeyMaterial([
    ...materials.values(),
    ...(replacement ? [replacement] : [])
  ]);
  if (replacement) {
    if (keys.some((key) => key.materialSha256 === replacement.materialSha256))
      throw new Refusal("replacement_material_reused");
    if (replacement.publicJwk === null) {
      const raw = replacement.symmetricBytes();
      try {
        for (const prefix of ["browser", "data"] as const) {
          const kid = `${prefix}-${createHash("sha256").update(`boardagent/${prefix}/key-id/v1\0`).update(raw).digest("hex").slice(0, 24)}`;
          if (records.some((key) => key.kid === kid))
            throw new Refusal("replacement_material_reused");
        }
      } finally {
        raw.fill(0);
      }
    }
  }
  const recovery = await inspectRetainedRecoveryFiles(plan.recoveryRoots, keys, target);
  const inventory = {
    schemaVersion: "boardagent.retained-key-material.v1",
    ...target,
    planSha256: canonicalSha256(plan),
    keys,
    recovery,
    replacement:
      replacement === null
        ? null
        : {
            keyFile: plan.replacement!.keyFile,
            runtimeFile: plan.replacement!.runtimeFile,
            purpose,
            kid: replacement.kid,
            algorithm: replacement.algorithm,
            publicJwk: replacement.publicJwk,
            materialSha256: replacement.materialSha256,
            fileSha256: replacement.fileSha256
          },
    custodyReference: plan.custodyReference,
    offHostCustody: "not_verified"
  };
  return { inventory, materials, replacement, purpose };
}
function stableReceipt(receipt: KeyLifecycleReceipt, target: Target) {
  return { schemaVersion: "boardagent.key-lifecycle-receipt.v1", ...target, ...receipt };
}
async function existingReceipt(
  pool: Pool,
  target: Target,
  operationId: string
): Promise<KeyLifecycleReceipt | null> {
  return withBootstrapTransaction(
    pool,
    async (client) => {
      await assertTarget(client, target);
      const exists = await client.query("select id from key_lifecycle_operations where id=$1", [
        operationId
      ]);
      return exists.rows.length === 0
        ? null
        : readKeyLifecycleReceiptInTransaction(client, { ...target, operationId });
    },
    { ...dbOptions, readOnly: true }
  );
}
function diagnostic(error: unknown): string {
  if (error instanceof Refusal || error instanceof KeyGenerationRefusal) return error.reasonCode;
  if (error instanceof z.ZodError) return "input_invalid";
  const code = error instanceof Error && "code" in error ? error.code : undefined;
  if (code === "42501") return "operator_authority_required";
  if (
    error instanceof Error &&
    "constraint" in error &&
    error.constraint === "boardagent_audit_checkpoint_capacity"
  )
    return "audit_signing_backlog";
  if (code === "55000")
    return error instanceof Error &&
      error.message === "stop server and worker before key maintenance"
      ? "stop_server_and_worker"
      : "request_no_longer_applicable";
  if (code === "40001" || code === "40P01") return "state_changed_prepare_again";
  if (code === "EEXIST") return "output_file_already_exists";
  if (code === "ENOSPC" || code === "EDQUOT") return "storage_full";
  if (["ENOENT", "EACCES", "EPERM", "ELOOP", "ENOTDIR"].includes(String(code)))
    return "protected_file_unavailable";
  if (
    typeof code === "string" &&
    (/^08[A-Z0-9]{3}$/u.test(code) ||
      ["ECONNRESET", "ECONNREFUSED", "ETIMEDOUT", "57P01"].includes(code))
  )
    return "connection_unavailable";
  return "protected_material_or_operation_invalid";
}
function output(io: Io, action: string, data: Record<string, unknown>) {
  io.stdout(
    `${JSON.stringify({ schemaVersion: "boardagent.operator-key-lifecycle.v1", command: "key-lifecycle", action, ...data })}\n`
  );
}

/** Technical operator only. Database completion, mounted-file installation and readiness are distinct facts. */
export async function runKeyLifecycleOperator(
  args: readonly string[],
  env: NodeJS.ProcessEnv,
  io: Io
): Promise<number> {
  const action = ["inspect", "prepare", "apply", "install"].includes(args[0] ?? "")
    ? args[0]!
    : "unknown";
  let pool: Pool | undefined;
  let applying: { operationId: string; requestSha256: string } | undefined;
  const held: OperatorKeyMaterial[] = [];
  try {
    if (!(
      (action === "inspect" && (args.length === 1 || args.length === 3)) ||
      (action === "prepare" && args.length === 3) ||
      (action === "apply" && args.length === 4) ||
      (action === "install" && args.length === 2)
    ))
      throw new Refusal("usage_inspect_prepare_apply_or_install");
    if (action === "install" && (process.platform !== "linux" || process.getuid?.() !== 0))
      throw new Refusal("installation_requires_linux_root_operator");
    const target = {
      instanceId: UuidV7Schema.parse(required(env, "BOARDAGENT_INSTANCE_ID")),
      organizationId: UuidV7Schema.parse(required(env, "BOARDAGENT_ORGANIZATION_ID"))
    };
    pool = new Pool({ connectionString: resolveDatabaseUrl(env), max: 1 });
    if (action === "install") {
      if (env["BOARDAGENT_ENV"] !== "production")
        throw new Refusal("installation_requires_production_environment");
      const installed = await installKeyGeneration(pool, target, path.resolve(args[1]!));
      output(io, action, { status: "generation_prepared", ...target, ...installed });
      return 0;
    }
    if (action === "inspect") {
      if (args.length === 1) {
        const keys = await keyRecords(pool, target);
        output(io, action, {
          status: "inspected",
          ...target,
          keys,
          installationRequirements: await inspectKeyGenerationRequirements(pool, target),
          runtimeInstallation: "not_verified",
          offHostCustody: "not_verified"
        });
      } else {
        const receipt = await existingReceipt(pool, target, UuidV7Schema.parse(args[1]));
        if (!receipt) throw new Refusal("operation_not_committed");
        const receiptFile = path.resolve(args[2]!);
        await publish(receiptFile, stableReceipt(receipt, target), true);
        output(io, action, {
          status: "inspected",
          ...target,
          ...receipt,
          receiptFile,
          runtimeInstallation: "not_verified"
        });
      }
      return 0;
    }
    if (action === "prepare") {
      const plan = OperatorKeyPlanSchema.parse(await jsonFile(path.resolve(args[1]!)));
      const requestFile = path.resolve(args[2]!);
      await assertOperatorFileParents(requestFile);
      if (
        await lstat(requestFile).then(
          () => true,
          (e: unknown) => {
            if ((e as NodeJS.ErrnoException).code === "ENOENT") return false;
            throw e;
          }
        )
      )
        throw new Refusal("output_file_already_exists");
      if (
        [...plan.keyFiles.map((k) => k.file), plan.replacement?.keyFile].includes(requestFile) ||
        plan.recoveryRoots.some(
          (root) =>
            requestFile.startsWith(`${root}/`) || plan.replacement?.keyFile.startsWith(`${root}/`)
        )
      )
        throw new Refusal("maintenance_outputs_must_be_outside_recovery_roots");
      const records = await keyRecords(pool, target);
      const purpose = records.find((key) => key.id === plan.keyId)?.purpose;
      if (!purpose) throw new Refusal("registered_key_not_found");
      if (
        plan.replacement &&
        !(await lstat(plan.replacement.keyFile).then(
          () => true,
          (e: unknown) => {
            if ((e as NodeJS.ErrnoException).code === "ENOENT") return false;
            throw e;
          }
        ))
      )
        await generateOperatorKeyFile(purpose, plan.replacement.keyFile);
      const snapshot = await materialSnapshot(plan, records, target, held);
      const newId = uuidV7(Date.now(), randomBytes(10));
      const replacement = !snapshot.replacement
        ? null
        : {
            keyId: newId,
            kid: purpose === "backup_kek" ? `backup-${newId}` : snapshot.replacement.kid!,
            algorithm: snapshot.replacement.algorithm,
            publicJwk: snapshot.replacement.publicJwk,
            materialSha256: snapshot.replacement.materialSha256,
            nonsecretLocator:
              purpose === "backup_kek"
                ? `sha256:${snapshot.replacement.materialSha256}`
                : `file:${plan.replacement!.runtimeFile}`
          };
      const prepared = await withBootstrapTransaction(
        pool,
        (client) =>
          prepareKeyLifecycleInTransaction(client, {
            ...target,
            keyId: plan.keyId,
            operationId: uuidV7(Date.now(), randomBytes(10)),
            operation: plan.operation,
            replacement,
            declaredCompromisedAt: plan.declaredCompromisedAt,
            retainedMaterialSha256: canonicalSha256(snapshot.inventory),
            operatorReference: plan.operatorReference,
            reason: plan.reason
          }),
        { ...dbOptions, readOnly: true }
      );
      const proposal = Proposal.parse({
        schemaVersion: "boardagent.operator-key-proposal.v1",
        ...prepared,
        plan,
        retainedMaterialInventory: snapshot.inventory
      });
      await publish(requestFile, proposal);
      output(io, action, {
        status: "prepared",
        ...target,
        operationId: prepared.request.operationId,
        purpose,
        operation: plan.operation,
        requestSha256: prepared.requestSha256,
        requestFile,
        expiresAt: prepared.request.expiresAt,
        replacementKeyId: replacement?.keyId ?? null,
        replacementKeyFile: plan.replacement?.keyFile ?? null,
        offHostCustody: "not_verified",
        nextStep: "stop_services_then_apply_exact_request"
      });
      return 0;
    }
    const proposal = Proposal.parse(await jsonFile(path.resolve(args[1]!)));
    if (Sha256HexSchema.parse(args[2]) !== proposal.requestSha256)
      throw new Refusal("request_digest_mismatch");
    if (
      proposal.request.instanceId !== target.instanceId ||
      proposal.request.organizationId !== target.organizationId
    )
      throw new Refusal("installation_target_mismatch");
    const receiptFile = path.resolve(args[3]!);
    await assertOperatorFileParents(receiptFile);
    let result = await existingReceipt(pool, target, proposal.request.operationId),
      replayed = result !== null;
    if (result && result.requestSha256 !== proposal.requestSha256)
      throw new Refusal("operation_id_conflict");
    if (!result) {
      if (
        await lstat(receiptFile).then(
          () => true,
          (error: unknown) => {
            if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
            throw error;
          }
        )
      )
        throw new Refusal("output_file_already_exists");
      const snapshot = await materialSnapshot(
        proposal.plan,
        await keyRecords(pool, target),
        target,
        held
      );
      if (canonicalSha256(snapshot.inventory) !== proposal.request.retainedMaterialSha256)
        throw new Refusal("retained_material_changed");
      const replacement = proposal.request.replacement;
      if (
        (replacement === null) !== (snapshot.replacement === null) ||
        (replacement &&
          (!snapshot.replacement ||
            replacement.materialSha256 !== snapshot.replacement.materialSha256 ||
            replacement.algorithm !== snapshot.replacement.algorithm ||
            canonicalJson(replacement.publicJwk) !==
              canonicalJson(snapshot.replacement.publicJwk) ||
            replacement.kid !==
              (proposal.request.purpose === "backup_kek"
                ? `backup-${replacement.keyId}`
                : snapshot.replacement.kid) ||
            replacement.nonsecretLocator !==
              (proposal.request.purpose === "backup_kek"
                ? `sha256:${snapshot.replacement.materialSha256}`
                : `file:${proposal.plan.replacement!.runtimeFile}`)))
      )
        throw new Refusal("replacement_material_mismatch");
      let rewrap: Aes256GcmWebhookSecurity | undefined;
      const rawCopies: Buffer[] = [];
      if (
        proposal.request.purpose === "data_kek" &&
        replacement &&
        snapshot.replacement &&
        snapshot.materials.has(proposal.request.keyId)
      ) {
        const old = snapshot.materials.get(proposal.request.keyId)!.symmetricBytes(),
          next = snapshot.replacement.symmetricBytes();
        rawCopies.push(old, next);
        rewrap = new Aes256GcmWebhookSecurity({
          activeKeyId: replacement.keyId,
          keys: new Map([
            [proposal.request.keyId, old],
            [replacement.keyId, next]
          ])
        });
      }
      applying = {
        operationId: proposal.request.operationId,
        requestSha256: proposal.requestSha256
      };
      const abort = new AbortController(),
        stop = () => abort.abort();
      process.once("SIGINT", stop);
      process.once("SIGTERM", stop);
      try {
        const applied = await withBootstrapTransaction(
          pool,
          async (client) => {
            if (abort.signal.aborted) throw new Refusal("operation_canceled");
            const changed = await applyKeyLifecycleInTransaction(
              client,
              { request: proposal.request, requestSha256: proposal.requestSha256 },
              rewrap
            );
            if (abort.signal.aborted) throw new Refusal("operation_canceled");
            return changed;
          },
          dbOptions
        );
        const { replayed: actualReplay, ...receipt } = applied;
        result = receipt;
        replayed = actualReplay;
      } finally {
        process.off("SIGINT", stop);
        process.off("SIGTERM", stop);
        for (const copy of rawCopies) copy.fill(0);
      }
    }
    await publish(receiptFile, stableReceipt(result, target), true);
    output(io, action, {
      status: "database_applied",
      ...target,
      ...result,
      replayed,
      receiptFile,
      runtimeInstallation: "pending",
      nextStep: "install_versioned_files_then_restart_and_verify"
    });
    return 0;
  } catch (error) {
    output(io, action, {
      status: applying ? "inspect_required" : "refused",
      reasonCode: diagnostic(error),
      ...applying,
      ...(applying ? { nextStep: "inspect_original_operation_before_retry_or_new_request" } : {})
    });
    return 1;
  } finally {
    for (const material of held) material.destroy();
    await pool?.end();
  }
}
