import { createPrivateKey, randomBytes, type KeyObject } from "node:crypto";
import { constants } from "node:fs";
import { open } from "node:fs/promises";
import path from "node:path";
import { Pool, type PoolClient } from "pg";
import { z } from "zod";
import { assertSecretDirectoryReady, resolveDatabaseUrl } from "@boardagent/config";
import {
  canonicalJson,
  canonicalJsonFromText,
  canonicalSha256,
  Sha256HexSchema,
  UuidV7Schema,
  type JsonValue
} from "@boardagent/contracts";
import {
  AuditRecoveryRequestSchema,
  signCheckpoint,
  signRecoveryCheckpoint
} from "@boardagent/audit";
import {
  applyAuditRecoveryInTransaction,
  prepareAuditRecoveryInTransaction,
  readAuditRecoveryReceiptInTransaction,
  verifyPersistedAuditEvidence,
  withBootstrapTransaction,
  type AppliedAuditRecovery
} from "@boardagent/db";
import { uuidV7 } from "@boardagent/domain";
import { publishRecoveryJson } from "./recovery-publication.js";

const ProposalSchema = z
  .object({
    schemaVersion: z.literal("boardagent.operator-audit-recovery-proposal.v1"),
    request: AuditRecoveryRequestSchema,
    requestSha256: Sha256HexSchema
  })
  .strict()
  .refine((p) => p.requestSha256 === canonicalSha256(p.request), "proposal digest mismatch");
const IncidentSchema = z
  .object({
    operatorReference: AuditRecoveryRequestSchema.in.shape.operatorReference,
    reason: AuditRecoveryRequestSchema.in.shape.reason
  })
  .strict();
interface Io {
  readonly stdout: (line: string) => void;
  readonly stderr: (line: string) => void;
}
interface Target {
  readonly instanceId: string;
  readonly organizationId: string;
}
const operatorOptions = { assumeRole: "boardagent_migrator", statementTimeoutMs: 60_000 } as const;

class OperatorRefusal extends Error {
  constructor(readonly reasonCode: string) {
    super(reasonCode);
  }
}
function required(env: NodeJS.ProcessEnv, key: string): string {
  const value = env[key];
  if (!value) throw new OperatorRefusal("installation_configuration_missing");
  return value;
}
function output(io: Io, action: string, data: Record<string, unknown>): void {
  io.stdout(
    `${JSON.stringify({ schemaVersion: "boardagent.operator-audit-recovery.v1", command: "audit-recovery", action, ...data })}\n`
  );
}
async function privateFile(
  filename: string,
  maximumBytes: number,
  secret = false
): Promise<Buffer> {
  const absolute = path.resolve(filename);
  if (secret) assertSecretDirectoryReady(absolute);
  const handle = await open(
    absolute,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK
  );
  const buffer = Buffer.alloc(maximumBytes + 1);
  try {
    const stat = await handle.stat();
    // Requests/receipts are owner-only. Mounted signing keys may also be group-readable,
    // but neither group-writable nor accessible by unrelated users.
    if (
      !stat.isFile() ||
      (stat.mode & (secret ? 0o027 : 0o077)) !== 0 ||
      stat.size < 1 ||
      stat.size > maximumBytes
    )
      throw new OperatorRefusal("private_file_invalid");
    let length = 0;
    while (length <= maximumBytes) {
      const read = await handle.read(buffer, length, buffer.length - length, null);
      if (read.bytesRead === 0) return Buffer.from(buffer.subarray(0, length));
      length += read.bytesRead;
    }
    throw new OperatorRefusal("private_file_invalid");
  } finally {
    buffer.fill(0);
    await handle.close();
  }
}
async function privateJson(filename: string): Promise<unknown> {
  const bytes = await privateFile(filename, 32_768);
  try {
    return JSON.parse(canonicalJsonFromText(bytes)) as unknown;
  } finally {
    bytes.fill(0);
  }
}
async function signingKey(env: NodeJS.ProcessEnv): Promise<KeyObject> {
  const bytes = await privateFile(
    required(env, "BOARDAGENT_EVIDENCE_SIGNING_KEY_FILE"),
    65_536,
    true
  );
  try {
    const key = createPrivateKey(bytes);
    if (key.type !== "private" || key.asymmetricKeyType !== "ed25519")
      throw new OperatorRefusal("evidence_key_invalid");
    return key;
  } finally {
    bytes.fill(0);
  }
}
async function assertTarget(client: PoolClient, target: Target): Promise<void> {
  const found = await client.query<{ instance_id: string; organization_id: string }>(
    "select instance_id,organization_id from public.system_instance where singleton_key"
  );
  if (
    found.rows.length !== 1 ||
    found.rows[0]?.instance_id !== target.instanceId ||
    found.rows[0]?.organization_id !== target.organizationId
  )
    throw new OperatorRefusal("installation_target_mismatch");
}
function stableReceipt(receipt: AppliedAuditRecovery, target: Target) {
  const { replayed: _replayed, ...record } = receipt;
  return { schemaVersion: "boardagent.audit-recovery-receipt.v1" as const, ...target, ...record };
}
async function publishExactReceipt(
  filename: string,
  receipt: ReturnType<typeof stableReceipt>
): Promise<void> {
  try {
    await publishRecoveryJson(filename, receipt);
  } catch (error) {
    if (!(error instanceof Error) || !("code" in error) || error.code !== "EEXIST") throw error;
    if (canonicalJson((await privateJson(filename)) as JsonValue) !== canonicalJson(receipt))
      throw new OperatorRefusal("receipt_file_conflict");
  }
}
function reasonCode(error: unknown): string {
  if (error instanceof OperatorRefusal) return error.reasonCode;
  if (error instanceof z.ZodError) return "input_invalid";
  const code = error instanceof Error && "code" in error ? error.code : undefined;
  if (code === "42501") return "operator_authority_required";
  if (code === "55000") return "request_no_longer_applicable";
  if (code === "recovery_target_mismatch") return "installation_target_mismatch";
  if (code === "recovery_integrity_invalid") return "retained_evidence_invalid";
  if (code === "recovery_signature_invalid") return "evidence_key_mismatch";
  if (code === "recovery_invalid") return "recovery_record_or_request_invalid";
  if (["ENOENT", "EACCES", "EPERM", "ELOOP", "ENOTDIR"].includes(String(code)))
    return "required_private_file_unavailable";
  if (code === "EEXIST") return "output_file_already_exists";
  if (
    typeof code === "string" &&
    (/^08[A-Z0-9]{3}$/u.test(code) ||
      ["ECONNRESET", "ECONNREFUSED", "ETIMEDOUT", "57P01"].includes(code))
  )
    return "connection_unavailable";
  return "validation_or_operation_failed";
}

/** Operator-only maintenance. No agent, governance role or human enrollment is simulated. */
export async function runAuditRecoveryOperator(
  args: readonly string[],
  env: NodeJS.ProcessEnv,
  io: Io
): Promise<number> {
  const action = ["inspect", "prepare", "apply"].includes(args[0] ?? "") ? args[0]! : "unknown";
  let pool: Pool | undefined;
  let applying: { recoveryId: string; requestSha256: string } | undefined;
  try {
    if (!(
      (action === "inspect" && (args.length === 1 || args.length === 3)) ||
      (action === "prepare" && args.length === 3) ||
      (action === "apply" && args.length === 4)
    ))
      throw new OperatorRefusal(
        "usage_inspect_or_prepare_incident_request_or_apply_request_digest_receipt"
      );
    const target = {
      instanceId: UuidV7Schema.parse(required(env, "BOARDAGENT_INSTANCE_ID")),
      organizationId: UuidV7Schema.parse(required(env, "BOARDAGENT_ORGANIZATION_ID"))
    };
    pool = new Pool({ connectionString: resolveDatabaseUrl(env), max: 1 });
    if (action === "inspect") {
      const recoveryId = args[1] === undefined ? undefined : UuidV7Schema.parse(args[1]);
      const inspected = await withBootstrapTransaction(
        pool,
        async (client) => {
          await assertTarget(client, target);
          const verification = await verifyPersistedAuditEvidence(client);
          const receipt =
            recoveryId === undefined
              ? undefined
              : stableReceipt(
                  await readAuditRecoveryReceiptInTransaction(client, { ...target, recoveryId }),
                  target
                );
          if (verification.valid) {
            const { recoveryEvidence: _recoveryEvidence, ...summary } = verification;
            return { verification: summary, receipt };
          }
          return { verification, receipt };
        },
        { ...operatorOptions, readOnly: true }
      );
      if (inspected.receipt !== undefined)
        await publishExactReceipt(path.resolve(args[2]!), inspected.receipt);
      output(io, action, {
        status: "inspected",
        ...target,
        ...inspected,
        ...(args[2] ? { receiptFile: path.resolve(args[2]) } : {})
      });
      return inspected.verification.valid && inspected.verification.ready ? 0 : 1;
    }
    if (action === "prepare") {
      const incident = IncidentSchema.parse(await privateJson(args[1]!));
      const prepared = await withBootstrapTransaction(
        pool,
        async (client) => {
          await assertTarget(client, target);
          const keys = await client.query<{ id: string }>(
            `select id from public.crypto_key_registry
          where organization_id=$1 and purpose='evidence_signing' and activated_at<=transaction_timestamp()
            and retired_at is null and compromised_at is null order by id limit 2`,
            [target.organizationId]
          );
          if (keys.rows.length !== 1) throw new OperatorRefusal("one_active_evidence_key_required");
          return prepareAuditRecoveryInTransaction(client, {
            ...target,
            ...incident,
            recoveryId: uuidV7(Date.now(), randomBytes(10)),
            signingKeyId: keys.rows[0]!.id
          });
        },
        { ...operatorOptions, readOnly: true }
      );
      const proposal = ProposalSchema.parse({
        schemaVersion: "boardagent.operator-audit-recovery-proposal.v1",
        request: prepared.request,
        requestSha256: prepared.requestSha256
      });
      const requestFile = path.resolve(args[2]!);
      await publishRecoveryJson(requestFile, proposal);
      output(io, action, {
        status: "prepared",
        ...target,
        recoveryId: proposal.request.recoveryId,
        requestSha256: proposal.requestSha256,
        requestFile,
        expiresAt: proposal.request.expiresAt,
        firstSequence: proposal.request.firstSequence,
        lastSequence: proposal.request.lastSequence
      });
      return 0;
    }
    const proposal = ProposalSchema.parse(await privateJson(args[1]!));
    if (Sha256HexSchema.parse(args[2]) !== proposal.requestSha256)
      throw new OperatorRefusal("request_digest_mismatch");
    if (
      proposal.request.instanceId !== target.instanceId ||
      proposal.request.organizationId !== target.organizationId
    )
      throw new OperatorRefusal("installation_target_mismatch");
    applying = { recoveryId: proposal.request.recoveryId, requestSha256: proposal.requestSha256 };
    const abort = new AbortController();
    const stop = () => abort.abort(new OperatorRefusal("operation_canceled"));
    process.once("SIGTERM", stop);
    process.once("SIGINT", stop);
    let result: AppliedAuditRecovery;
    let key: Promise<KeyObject> | undefined;
    try {
      result = await withBootstrapTransaction(
        pool,
        (client) =>
          applyAuditRecoveryInTransaction(
            client,
            {
              ...target,
              request: proposal.request,
              requestSha256: proposal.requestSha256
            },
            {
              signal: abort.signal,
              createId: () => uuidV7(Date.now(), randomBytes(10)),
              sign: async (payload) => {
                key ??= signingKey(env);
                return payload.schema === "boardagent.audit.recovery-checkpoint.v1"
                  ? signRecoveryCheckpoint(payload, await key)
                  : signCheckpoint(payload, await key);
              }
            }
          ),
        operatorOptions
      );
    } finally {
      process.removeListener("SIGTERM", stop);
      process.removeListener("SIGINT", stop);
    }
    const receipt = stableReceipt(result, target),
      receiptFile = path.resolve(args[3]!);
    try {
      await publishExactReceipt(receiptFile, receipt);
    } catch (error) {
      output(io, action, {
        status: "committed_receipt_publication_unconfirmed",
        ...target,
        ...applying,
        receiptFile,
        reasonCode: reasonCode(error),
        nextStep:
          "Inspect this recovery ID into a writable private receipt file; do not repeat a different recovery."
      });
      return 1;
    }
    output(io, action, {
      status: "committed",
      receipt,
      receiptFile,
      replayed: result.replayed,
      warnings: [`recovery:${result.recoveryId}:historical_checkpoint_deadline_missed`]
    });
    return 0;
  } catch (error) {
    const reason = reasonCode(error);
    output(io, action, {
      status:
        applying && reason === "connection_unavailable" ? "completion_unconfirmed" : "refused",
      reasonCode: reason,
      ...applying
    });
    return 1;
  } finally {
    await pool?.end();
  }
}
