import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { chown, chmod, lstat, mkdir, open, unlink } from "node:fs/promises";
import path from "node:path";
import { Pool, type PoolClient } from "pg";
import { z } from "zod";
import {
  canonicalJson,
  canonicalJsonFromText,
  canonicalSha256,
  Sha256HexSchema,
  UuidV7Schema
} from "@boardagent/contracts";
import { KeyLifecyclePurposeSchema } from "@boardagent/audit";
import {
  readKeyLifecycleReceiptInTransaction,
  readActiveBackupKeyInTransaction,
  withBootstrapTransaction
} from "@boardagent/db";
import {
  assertDistinctOperatorKeyMaterial,
  assertOperatorFileParents,
  loadOperatorKeyMaterial,
  OperatorFilePathSchema,
  readOperatorProtectedFile,
  type OperatorKeyMaterial
} from "./operator-key-files.js";
import { BackupKeyReceiptSchema } from "./backup-key-binding.js";

const Mount = "/run/boardagent-secrets";
const Roles = ["server", "worker", "operator", "recovery"] as const;
type Role = (typeof Roles)[number];
const Plan = z
  .object({
    schemaVersion: z.literal("boardagent.key-generation-plan.v1"),
    operationId: UuidV7Schema,
    requestSha256: Sha256HexSchema,
    generationRoot: OperatorFilePathSchema,
    keyFiles: z
      .array(z.object({ keyId: UuidV7Schema, file: OperatorFilePathSchema }).strict())
      .min(5)
      .max(4096),
    retainedDataKeyIds: z.array(UuidV7Schema).max(4091),
    passwordFiles: z
      .object({
        migrator: OperatorFilePathSchema,
        server: OperatorFilePathSchema,
        worker: OperatorFilePathSchema,
        backup: OperatorFilePathSchema
      })
      .strict()
  })
  .strict();
const Key = z
  .object({
    id: UuidV7Schema,
    purpose: KeyLifecyclePurposeSchema,
    kid: z.string(),
    algorithm: z.string(),
    public_jwk: z.json().nullable(),
    nonsecret_locator: z.string(),
    active: z.boolean(),
    retired: z.boolean(),
    compromised: z.boolean()
  })
  .strict();
type KeyRow = z.infer<typeof Key>;
type Target = { instanceId: string; organizationId: string };
export class KeyGenerationRefusal extends Error {
  constructor(readonly reasonCode: string) {
    super(reasonCode);
  }
}
function refuse(reason: string): never {
  throw new KeyGenerationRefusal(reason);
}
const sha = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const unique = (values: readonly string[]) => new Set(values).size === values.length;
const sameSet = (a: readonly string[], b: readonly string[]) =>
  a.length === b.length && unique(a) && a.every((v) => b.includes(v));

function runtimeRelative(locator: string): string {
  if (!locator.startsWith(`file:${Mount}/`)) return refuse("unsupported_runtime_key_location");
  const file = locator.slice(5),
    relative = file.slice(Mount.length + 1);
  if (
    path.normalize(file) !== file ||
    relative
      .split("/")
      .some(
        (p) =>
          !p || p.startsWith(".") || ![...p].every((c) => /[A-Za-z0-9_-]/u.test(c) || c === ".")
      )
  )
    return refuse("unsupported_runtime_key_location");
  return relative;
}
async function syncDirectory(directory: string) {
  const h = await open(
    directory,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW
  );
  try {
    await h.sync();
  } finally {
    await h.close();
  }
}
async function publishFile(file: string, bytes: Uint8Array, serviceOwned: boolean) {
  const h = await open(
    file,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    0o400
  );
  try {
    await h.writeFile(bytes);
    if (serviceOwned) await h.chown(10001, 10001);
    await h.sync();
  } finally {
    await h.close();
  }
  await syncDirectory(path.dirname(file));
}
async function readRegistry(client: PoolClient, target: Target) {
  const result = await client.query(
    `select id,purpose,kid,algorithm,public_jwk,nonsecret_locator,
    (activated_at<=transaction_timestamp() and retired_at is null and compromised_at is null) as active,
    (retired_at<=transaction_timestamp()) is true as retired,compromised_at is not null as compromised
    from crypto_key_registry where organization_id=$1 order by id limit 4097`,
    [target.organizationId]
  );
  if (result.rows.length > 4096) refuse("registered_key_limit_exceeded");
  return result.rows.map((row) => Key.parse(row));
}
async function runtimeDependencies(client: PoolClient, target: Target, activeData: string | null) {
  const dependencies = await client.query<{ key_id: string; consumer: string }>(
    `select distinct key_id,'server' as consumer from totp_credentials where organization_id=$1 and ($2::uuid is null or key_id<>$2) and state='active'
     union select distinct key_id,'both' as consumer from member_webhooks where organization_id=$1 and ($2::uuid is null or key_id<>$2) and state='active'`,
    [target.organizationId, activeData]
  );
  return {
    retainedDataKeyIds: [...new Set(dependencies.rows.map((r) => r.key_id))].sort(),
    workerRetainedDataKeyIds: [
      ...new Set(dependencies.rows.filter((r) => r.consumer === "both").map((r) => r.key_id))
    ].sort()
  };
}

/** Read-only information needed to prepare the installation plan; no private material is read. */
export async function inspectKeyGenerationRequirements(pool: Pool, target: Target) {
  return withBootstrapTransaction(
    pool,
    async (client) => {
      const installed = await client.query(
        "select instance_id,organization_id from system_instance where singleton_key"
      );
      if (
        installed.rows.length !== 1 ||
        installed.rows[0].instance_id !== target.instanceId ||
        installed.rows[0].organization_id !== target.organizationId
      )
        refuse("installation_target_mismatch");
      const records = await readRegistry(client, target),
        activeKeys = records.filter((k) => k.active);
      const activeData = activeKeys.filter((k) => k.purpose === "data_kek");
      const requirements = await runtimeDependencies(
        client,
        target,
        activeData.length === 1 ? activeData[0]!.id : null
      );
      return {
        ...requirements,
        activeKeyIds: activeKeys.map((k) => k.id),
        unavailablePurposes: KeyLifecyclePurposeSchema.options.filter(
          (p) => activeKeys.filter((k) => k.purpose === p).length !== 1
        ),
        unusableRetainedKeyIds: requirements.retainedDataKeyIds.filter(
          (id) =>
            !records.some(
              (k) => k.id === id && k.purpose === "data_kek" && k.retired && !k.compromised
            )
        ),
        privateFiles: "not_inspected",
        runtimeInstallation: "not_verified"
      };
    },
    { assumeRole: "boardagent_migrator", readOnly: true }
  );
}

function assertKeyBinding(key: KeyRow, material: OperatorKeyMaterial) {
  if (
    key.algorithm !== material.algorithm ||
    canonicalJson(key.public_jwk) !== canonicalJson(material.publicJwk) ||
    (key.purpose === "backup_kek"
      ? key.kid !== `backup-${key.id}` ||
        key.nonsecret_locator !== `sha256:${material.materialSha256}`
      : key.kid !== material.kid)
  )
    refuse("private_material_registry_mismatch");
}
async function verifyPasswords(connectionString: string, passwords: Record<string, Buffer>) {
  const decoded = Object.entries(passwords).map(([role, bytes]) => {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes).replace(/\n$/u, "");
    if (!/^[A-Za-z0-9_-]{43,128}$/u.test(text)) refuse("database_password_file_invalid");
    return [role, text] as const;
  });
  if (!unique(decoded.map(([, text]) => text))) refuse("database_passwords_must_be_distinct");
  for (const [role, text] of decoded) {
    const url = new URL(connectionString);
    url.username = `boardagent_${role}_login`;
    url.password = text;
    const probe = new Pool({
      connectionString: url.toString(),
      max: 1,
      connectionTimeoutMillis: 5000
    });
    try {
      const r = await probe.query("select current_user as principal");
      if (r.rows[0]?.principal !== `boardagent_${role}_login`)
        refuse("database_password_check_failed");
    } catch {
      refuse("database_password_check_failed");
    } finally {
      await probe.end();
    }
  }
}

function composeOverride(root: string, environment: Record<Role, Record<string, string>>): string {
  const yamlJson = (value: unknown) => JSON.stringify(value).replaceAll("$", "$$");
  const complete = { condition: "service_completed_successfully" };
  const runtimeDependencies = {
    postgres: { condition: "service_healthy" },
    "maintenance-lock-init": complete
  };
  const mounted = (role: Role, target = Mount) => ({
    type: "bind",
    source: `${root}/${role}`,
    target,
    read_only: true,
    bind: { create_host_path: false }
  });
  const roleFor: Record<string, Role> = {
    server: "server",
    worker: "worker",
    operator: "operator",
    "wal-archiver": "recovery",
    "backup-key-check": "recovery"
  };
  const parts = [
    "# Add last to the same production + recovery Compose project. Preserve all earlier generations.",
    "services:"
  ];
  for (const [service, role] of Object.entries(roleFor)) {
    const dependencies = service === "backup-key-check" ? {} : runtimeDependencies;
    const mounts = [mounted(role)];
    if (role === "recovery") mounts.push(mounted(role, "/run/boardagent-key-receipts"));
    parts.push(
      `  ${service}:`,
      `    depends_on: !override ${yamlJson(dependencies)}`,
      `    environment: ${yamlJson(environment[role])}`,
      `    volumes: ${yamlJson(mounts)}`
    );
  }
  parts.push(
    "  postgres:",
    `    depends_on: !override ${yamlJson({ "wal-staging-init": complete, "backup-key-check": complete })}`
  );
  for (const name of [
    "application-secret-init",
    "recovery-secret-init",
    "backup-registration-secret-init",
    "backup-key-registrar"
  ])
    parts.push(`  ${name}:`, '    profiles: !override ["initialize-original-secrets-only"]');
  return parts.join("\n") + "\n";
}

/** Root-only local installation. Database authority is unchanged; this command never starts services. */
export async function installKeyGeneration(pool: Pool, target: Target, planFile: string) {
  if (process.platform !== "linux" || process.getuid?.() !== 0)
    refuse("installation_requires_linux_root_operator");
  const raw = await readOperatorProtectedFile(planFile, 1_048_576);
  let plan: z.infer<typeof Plan>;
  try {
    plan = Plan.parse(JSON.parse(canonicalJsonFromText(raw)));
  } finally {
    raw.fill(0);
  }
  const allInputs = [
    planFile,
    ...plan.keyFiles.map((k) => k.file),
    ...Object.values(plan.passwordFiles)
  ];
  if (
    !unique(plan.keyFiles.map((k) => k.keyId)) ||
    !unique(plan.keyFiles.map((k) => k.file)) ||
    !unique(Object.values(plan.passwordFiles)) ||
    !unique(plan.retainedDataKeyIds) ||
    allInputs.some((f) => f === plan.generationRoot || f.startsWith(`${plan.generationRoot}/`))
  )
    refuse("generation_input_paths_or_ids_invalid");
  await assertOperatorFileParents(plan.generationRoot);
  if (
    await lstat(plan.generationRoot).then(
      () => true,
      (e: unknown) => {
        if ((e as NodeJS.ErrnoException).code === "ENOENT") return false;
        throw e;
      }
    )
  )
    refuse("generation_directory_already_exists");
  const held: OperatorKeyMaterial[] = [],
    buffers: Buffer[] = [];
  try {
    return await withBootstrapTransaction(
      pool,
      async (client) => {
        const lock = await client.query("select pg_try_advisory_xact_lock(424248,1) as held");
        if (lock.rows[0]?.held !== true) refuse("stop_server_and_worker");
        const operation = await readKeyLifecycleReceiptInTransaction(client, {
          ...target,
          operationId: plan.operationId
        });
        if (operation.requestSha256 !== plan.requestSha256)
          refuse("committed_operation_digest_mismatch");
        const records = await readRegistry(client, target);
        if (plan.keyFiles.some((k) => !records.some((r) => r.id === k.keyId)))
          refuse("unregistered_private_key_input");
        const active = new Map<string, KeyRow>();
        for (const purpose of KeyLifecyclePurposeSchema.options) {
          const candidates = records.filter((r) => r.purpose === purpose && r.active);
          if (candidates.length !== 1) refuse("one_active_key_per_purpose_required");
          active.set(purpose, candidates[0]!);
        }
        if (
          operation.details.replacement === null ||
          active.get(operation.details.purpose)?.id !== operation.details.replacement.keyId
        )
          refuse("operation_replacement_is_not_current");
        const activeData = active.get("data_kek")!.id;
        const { retainedDataKeyIds: serverRetained, workerRetainedDataKeyIds: workerRetained } =
          await runtimeDependencies(client, target, activeData);
        if (!sameSet(plan.retainedDataKeyIds, serverRetained))
          refuse("retained_runtime_dependency_list_mismatch");
        const needed = [
          ...active.values(),
          ...serverRetained.map((id) => {
            const r = records.find((k) => k.id === id);
            if (!r || r.purpose !== "data_kek" || !r.retired || r.compromised)
              refuse("required_retained_key_is_not_usable");
            return r;
          })
        ];
        const materials = new Map<string, OperatorKeyMaterial>(),
          keyBytes = new Map<string, Buffer>();
        for (const key of needed) {
          const file = plan.keyFiles.find((k) => k.keyId === key.id)?.file;
          if (!file) refuse("required_private_key_file_missing");
          const material = await loadOperatorKeyMaterial(key.purpose, file);
          held.push(material);
          assertKeyBinding(key, material);
          const bytes = await readOperatorProtectedFile(file, 65_536);
          buffers.push(bytes);
          if (sha(bytes) !== material.fileSha256) refuse("private_file_changed");
          materials.set(key.id, material);
          keyBytes.set(key.id, bytes);
        }
        await assertDistinctOperatorKeyMaterial(held);
        const passwords: Record<string, Buffer> = {};
        for (const [role, file] of Object.entries(plan.passwordFiles)) {
          const bytes = await readOperatorProtectedFile(file, 129);
          buffers.push(bytes);
          passwords[role] = bytes;
        }
        await verifyPasswords(pool.options.connectionString!, passwords);
        const files: Record<Role, Map<string, Buffer>> = {
          server: new Map(),
          worker: new Map(),
          operator: new Map(),
          recovery: new Map()
        };
        const environments: Record<Role, Record<string, string>> = {
          server: {},
          worker: {},
          operator: {},
          recovery: {}
        };
        const put = (role: Role, relative: string, bytes: Buffer) => {
          if (files[role].has(relative) || relative.split("/").some((p) => p.startsWith(".")))
            refuse("runtime_file_collision");
          files[role].set(relative, bytes);
        };
        const json = (value: Parameters<typeof canonicalJson>[0]) => {
          const bytes = Buffer.from(canonicalJson(value) + "\n");
          buffers.push(bytes);
          return bytes;
        };
        const vars = {
          oauth_signing: "BOARDAGENT_OAUTH_SIGNING_KEY_FILE",
          evidence_signing: "BOARDAGENT_EVIDENCE_SIGNING_KEY_FILE",
          browser_session: "BOARDAGENT_BROWSER_SESSION_KEY_FILE",
          data_kek: "BOARDAGENT_DATA_KEK_FILE"
        };
        for (const [purpose, variable] of Object.entries(vars)) {
          const key = active.get(purpose)!,
            relative = runtimeRelative(key.nonsecret_locator);
          for (const role of [
            "server",
            "operator",
            ...(purpose === "evidence_signing" || purpose === "data_kek" ? ["worker"] : [])
          ] as Role[]) {
            put(role, relative, keyBytes.get(key.id)!);
            environments[role][variable] = `${Mount}/${relative}`;
          }
        }
        for (const role of ["server", "worker", "operator"] as const) {
          const ids = role === "worker" ? workerRetained : serverRetained;
          const keys = ids.map((id) => {
            const m = materials.get(id)!,
              relative = `retained/${id}.key`;
            put(role, relative, keyBytes.get(id)!);
            return {
              keyId: id,
              kid: m.kid!,
              fingerprintSha256: m.materialSha256,
              keyFile: `${Mount}/${relative}`
            };
          });
          const retainedManifest = json({
            schemaVersion: "boardagent.retained-data-keys.v1",
            ...target,
            keys
          });
          if (retainedManifest.byteLength > 1_048_576) refuse("retained_manifest_limit_exceeded");
          put(role, "retained-data-keys.json", retainedManifest);
          environments[role]["BOARDAGENT_RETAINED_DATA_KEYS_FILE"] =
            `${Mount}/retained-data-keys.json`;
        }
        const backup = active.get("backup_kek")!,
          identity = await readActiveBackupKeyInTransaction(client, backup.id);
        const body = {
          schemaVersion: "boardagent.backup-key-registration.v1" as const,
          ...identity
        };
        const receipt = BackupKeyReceiptSchema.parse({
          ...body,
          receiptSha256: canonicalSha256(body)
        });
        for (const role of ["operator", "recovery"] as const) {
          put(role, "backup_kek", keyBytes.get(backup.id)!);
          put(role, `${backup.id}.json`, json(receipt));
          Object.assign(environments[role], {
            BOARDAGENT_BACKUP_KEY_ID: backup.id,
            BOARDAGENT_BACKUP_KEK_FILE: `${Mount}/backup_kek`,
            BOARDAGENT_BACKUP_KEY_REGISTRATION_FILE: `${Mount}/${backup.id}.json`,
            BOARDAGENT_BACKUP_DATABASE_PASSWORD_FILE: `${Mount}/database_backup_password`,
            BOARDAGENT_BACKUP_DATABASE_URL:
              "postgresql://boardagent_backup_login@postgres:5432/boardagent"
          });
          put(role, "database_backup_password", passwords["backup"]!);
        }
        put("server", "database_server_password", passwords["server"]!);
        put("worker", "database_worker_password", passwords["worker"]!);
        put("operator", "database_migrator_password", passwords["migrator"]!);
        put("operator", "database_worker_password", passwords["worker"]!);
        Object.assign(environments.operator, {
          BOARDAGENT_RECEIPT_DATABASE_URL:
            "postgresql://boardagent_worker_login@postgres:5432/boardagent",
          BOARDAGENT_RECEIPT_DATABASE_PASSWORD_FILE: `${Mount}/database_worker_password`
        });
        // Reject file/directory prefix collisions before creating any output.
        for (const role of Roles)
          for (const name of files[role].keys()) {
            let parent = path.dirname(name);
            while (parent !== ".") {
              if (files[role].has(parent)) refuse("runtime_file_collision");
              parent = path.dirname(parent);
            }
          }
        await mkdir(plan.generationRoot, { mode: 0o700 });
        await syncDirectory(path.dirname(plan.generationRoot));
        const marked = new Set<string>();
        const initializeDirectory = async (directory: string) => {
          await mkdir(directory, { mode: 0o750 });
          await chown(directory, 0, 10001);
          await chmod(directory, 0o750);
          await publishFile(
            path.join(directory, ".initialization-incomplete"),
            Buffer.from("incomplete\n"),
            false
          );
          marked.add(directory);
        };
        const entries = [];
        for (const role of Roles) {
          const roleRoot = path.join(plan.generationRoot, role);
          await initializeDirectory(roleRoot);
          for (const [relative, bytes] of files[role]) {
            let parent = roleRoot;
            for (const component of relative.split("/").slice(0, -1)) {
              parent = path.join(parent, component);
              if (!marked.has(parent)) await initializeDirectory(parent);
            }
            const file = path.join(roleRoot, relative);
            await publishFile(file, bytes, true);
            entries.push({
              role,
              relativePath: relative,
              fileSha256: sha(bytes),
              bytes: bytes.length
            });
          }
        }
        const manifest = {
          schemaVersion: "boardagent.key-generation.v1",
          ...target,
          operationId: operation.operationId,
          requestSha256: operation.requestSha256,
          planSha256: canonicalSha256(plan),
          registrySha256: canonicalSha256(records),
          generationRoot: plan.generationRoot,
          keys: needed.map((k) => ({
            keyId: k.id,
            purpose: k.purpose,
            kid: k.kid,
            materialSha256: materials.get(k.id)!.materialSha256
          })),
          files: entries,
          runtimeInstallation: "restart_and_verify_required",
          offHostCustody: "not_verified"
        };
        const compose = Buffer.from(composeOverride(plan.generationRoot, environments));
        buffers.push(compose);
        for (const directory of marked) {
          await unlink(path.join(directory, ".initialization-incomplete"));
          await syncDirectory(directory);
        }
        await publishFile(path.join(plan.generationRoot, "compose.yaml"), compose, false);
        await publishFile(path.join(plan.generationRoot, "generation.json"), json(manifest), false);
        return {
          operationId: operation.operationId,
          requestSha256: operation.requestSha256,
          generationRoot: plan.generationRoot,
          manifestFile: path.join(plan.generationRoot, "generation.json"),
          composeFile: path.join(plan.generationRoot, "compose.yaml"),
          runtimeInstallation: "restart_and_verify_required"
        };
      },
      { assumeRole: "boardagent_migrator", readOnly: true, statementTimeoutMs: 60_000 }
    );
  } finally {
    for (const bytes of buffers) bytes.fill(0);
    for (const material of held) material.destroy();
  }
}
