import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { signAuditExportAttestation } from "../../lib/audit/src/index.js";
import type { FrozenExportSnapshot } from "../../lib/db/src/index.js";
import { testId } from "./authorized-actor.js";

/** Signature fixture for artifact I/O tests and controlled crash points. This does
 * not claim the opaque component fixtures form a valid governance audit export. */
export function fixtureExportAttestation(
  frozen: FrozenExportSnapshot,
  privateKey: KeyObject = generateKeyPairSync("ed25519").privateKey,
  signingKeyId = testId(50_990),
  keyId = "artifact-test-evidence"
) {
  if (frozen.scope.exportType !== "audit_chain") throw new Error("audit fixture required");
  return signAuditExportAttestation(
    {
      ...(frozen.snapshot.schemaVersion === "boardagent.export-snapshot.v2"
        ? {
            schemaVersion: "boardagent.audit-export-attestation.v2" as const,
            auditRecoveryEvidence: frozen.snapshot.auditRecoveryEvidence
          }
        : { schemaVersion: "boardagent.audit-export-attestation.v1" as const }),
      instanceId: testId(15),
      exportRequestId: frozen.exportRequestId,
      organizationId: frozen.snapshot.organizationId,
      boardId: frozen.snapshot.boardId,
      scopeSha256: frozen.snapshot.scopeSha256,
      snapshotSha256: frozen.snapshotSha256,
      firstSequence: frozen.scope.firstSequence,
      lastSequence: frozen.scope.lastSequence,
      auditHeadSequence: frozen.snapshot.auditHeadSequence,
      auditHeadSha256: frozen.snapshot.auditHeadSha256,
      latestCheckpointSha256: frozen.snapshot.latestCheckpointSha256,
      eventComponentSha256:
        frozen.components.find((c) => c.name === "audit:events")?.sha256 ?? "0".repeat(64),
      checkpointComponentSha256:
        frozen.components.find((c) => c.name === "audit:checkpoints")?.sha256 ?? "0".repeat(64),
      issuedAt: frozen.snapshot.capturedAt,
      signingKeyId,
      keyId
    },
    privateKey
  );
}
