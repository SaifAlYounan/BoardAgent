import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  LocalExportArtifactStore,
  decryptExportEnvelope
} from "../../artifacts/server/src/export-artifact-store.js";
import { canonicalSha256, sha256Hex } from "../../lib/contracts/src/index.js";
import { ExportSnapshotManifestSchema, type FrozenExportSnapshot } from "../../lib/db/src/index.js";
import { fixtureExportAttestation } from "../helpers/export-attestation-fixture.js";
import { testId } from "../helpers/authorized-actor.js";
import { inspectRetainedRecoveryFiles } from "../../scripts/src/key-maintenance-inventory.js";

describe("local encrypted export artifact store", () => {
  it("publishes atomic bounded chunks, decrypts exact components, and deletes only manifest bytes", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "boardagent-export-store-"));
    try {
      const componentBytes = Buffer.from("private-governance-value\n".repeat(5_000), "utf8");
      const component = {
        name: "audit:events",
        rowCount: "5000",
        byteLength: componentBytes.length.toString(10),
        sha256: sha256Hex(componentBytes)
      };
      const plaintextContentSetSha256 = canonicalSha256({
        schemaVersion: "boardagent.export-content-set.v1",
        components: [component]
      });
      const snapshot = ExportSnapshotManifestSchema.parse({
        schemaVersion: "boardagent.export-snapshot.v1",
        exportRequestId: testId(50_000),
        organizationId: testId(1),
        boardId: testId(2),
        exportType: "audit_chain",
        scopeSha256: canonicalSha256({
          schemaVersion: "boardagent.export-scope.v1",
          exportType: "audit_chain",
          organizationId: testId(1),
          boardId: testId(2),
          firstSequence: "1",
          lastSequence: "1",
          includeCheckpoints: true,
          includePublicKeys: true
        }),
        transactionSnapshot: "1:1:",
        auditHeadSequence: "1",
        auditHeadSha256: "22".repeat(32),
        latestCheckpointSha256: "33".repeat(32),
        migrationLedgerSha256: "44".repeat(32),
        capturedAt: "2026-09-04T12:00:00.000000Z",
        plaintextContentSetSha256,
        components: [component]
      });
      const frozen: FrozenExportSnapshot = {
        exportRequestId: snapshot.exportRequestId,
        scope: {
          schemaVersion: "boardagent.export-scope.v1",
          exportType: "audit_chain",
          organizationId: snapshot.organizationId,
          boardId: snapshot.boardId,
          firstSequence: "1",
          lastSequence: "1",
          includeCheckpoints: true,
          includePublicKeys: true
        },
        snapshot,
        snapshotSha256: canonicalSha256(snapshot),
        components: [
          {
            name: component.name,
            rowCount: component.rowCount,
            sha256: component.sha256,
            bytes: componentBytes
          }
        ]
      };
      const store = new LocalExportArtifactStore(root, {
        maximumArtifactBytes: 1_048_576,
        chunkBytes: 65_536
      });
      let nextId = 50_100;
      const encryptionKey = Buffer.alloc(32, 0x61);
      await expect(
        store.publish({
          frozen,
          artifactId: testId(50_999),
          encryptionKeyId: testId(50_002),
          encryptionKey,
          newChunkId: () => testId(nextId++)
        })
      ).rejects.toThrow("audit export attestation is required");
      const manifest = await store.publish({
        frozen,
        auditAttestation: fixtureExportAttestation(frozen),
        artifactId: testId(50_001),
        encryptionKeyId: testId(50_002),
        encryptionKey,
        newChunkId: () => testId(nextId++),
        randomBytes: (length) => Buffer.alloc(length, 0x71)
      });
      expect(manifest.complete).toBe(true);
      expect(manifest.chunks.length).toBeGreaterThan(1);
      expect(await store.scanArtifacts()).toEqual([
        expect.objectContaining({
          state: "committed",
          exportRequestId: manifest.exportRequestId,
          artifactId: manifest.artifactId,
          manifest
        })
      ]);
      const encrypted = Buffer.concat(
        await Promise.all(
          manifest.chunks.map(async (chunk) =>
            Buffer.from(
              await store.readExactChunk({
                exportRequestId: manifest.exportRequestId,
                artifactId: manifest.artifactId,
                ordinal: chunk.ordinal,
                storageLocator: chunk.storageLocator,
                byteLength: chunk.byteLength,
                expectedSha256: chunk.chunkSha256
              })
            )
          )
        )
      );
      expect(encrypted.includes(Buffer.from("private-governance-value"))).toBe(false);
      const decrypted = decryptExportEnvelope(encrypted, encryptionKey);
      expect(decrypted.header).toMatchObject({
        artifactId: manifest.artifactId,
        exportRequestId: manifest.exportRequestId,
        encryptionKeyId: manifest.encryptionKeyId
      });
      expect(decrypted.scope).toEqual(frozen.scope);
      expect(decrypted.components).toHaveLength(1);
      expect(decrypted.components[0]?.bytes.equals(componentBytes)).toBe(true);

      const retained = await inspectRetainedRecoveryFiles(
        [await realpath(root)],
        [
          {
            keyId: manifest.encryptionKeyId,
            purpose: "data_kek",
            materialSha256: sha256Hex(encryptionKey)
          }
        ],
        { instanceId: testId(50_003), organizationId: snapshot.organizationId }
      );
      expect(retained.manifests).toEqual([
        expect.objectContaining({
          kind: "export",
          keyId: manifest.encryptionKeyId,
          payload: "present_hash_verified"
        })
      ]);
      expect(retained.files).toHaveLength(manifest.chunks.length + 1);

      const tampered = Buffer.from(encrypted);
      tampered.writeUInt8(tampered.readUInt8(tampered.length - 1) ^ 0x01, tampered.length - 1);
      expect(() => decryptExportEnvelope(tampered, encryptionKey)).toThrow();
      await expect(
        store.readExactChunk({
          exportRequestId: manifest.exportRequestId,
          artifactId: manifest.artifactId,
          ordinal: 0,
          storageLocator: "boardagent-export:v1/wrong",
          byteLength: manifest.chunks[0]!.byteLength,
          expectedSha256: manifest.chunks[0]!.chunkSha256
        })
      ).rejects.toThrow("locator");

      await store.deleteArtifact(manifest);
      expect(await store.scanArtifacts()).toEqual([]);
      await expect(
        store.readExactChunk({
          exportRequestId: manifest.exportRequestId,
          artifactId: manifest.artifactId,
          ordinal: manifest.chunks[0]!.ordinal,
          storageLocator: manifest.chunks[0]!.storageLocator,
          byteLength: manifest.chunks[0]!.byteLength,
          expectedSha256: manifest.chunks[0]!.chunkSha256
        })
      ).rejects.toThrow();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("classifies interrupted publication as an exact partial and deletes only that fingerprint", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "boardagent-export-partial-"));
    try {
      const componentBytes = Buffer.alloc(180_000, 0x61);
      const component = {
        name: "audit:events",
        rowCount: "1",
        byteLength: componentBytes.length.toString(10),
        sha256: sha256Hex(componentBytes)
      };
      const snapshot = ExportSnapshotManifestSchema.parse({
        schemaVersion: "boardagent.export-snapshot.v1",
        exportRequestId: testId(50_500),
        organizationId: testId(1),
        boardId: testId(2),
        exportType: "audit_chain",
        scopeSha256: canonicalSha256({
          schemaVersion: "boardagent.export-scope.v1",
          exportType: "audit_chain",
          organizationId: testId(1),
          boardId: testId(2),
          firstSequence: "1",
          lastSequence: "1",
          includeCheckpoints: true,
          includePublicKeys: true
        }),
        transactionSnapshot: "1:1:",
        auditHeadSequence: "1",
        auditHeadSha256: "22".repeat(32),
        latestCheckpointSha256: "33".repeat(32),
        migrationLedgerSha256: "44".repeat(32),
        capturedAt: "2026-09-04T12:00:00.000000Z",
        plaintextContentSetSha256: canonicalSha256({
          schemaVersion: "boardagent.export-content-set.v1",
          components: [component]
        }),
        components: [component]
      });
      const frozen: FrozenExportSnapshot = {
        exportRequestId: snapshot.exportRequestId,
        scope: {
          schemaVersion: "boardagent.export-scope.v1",
          exportType: "audit_chain",
          organizationId: snapshot.organizationId,
          boardId: snapshot.boardId,
          firstSequence: "1",
          lastSequence: "1",
          includeCheckpoints: true,
          includePublicKeys: true
        },
        snapshot,
        snapshotSha256: canonicalSha256(snapshot),
        components: [
          {
            name: component.name,
            rowCount: component.rowCount,
            sha256: component.sha256,
            bytes: componentBytes
          }
        ]
      };
      const store = new LocalExportArtifactStore(root, {
        maximumArtifactBytes: 1_048_576,
        chunkBytes: 65_536
      });
      const interrupted = new AbortController();
      let nextId = 50_510;
      await expect(
        store.publish({
          frozen,
          auditAttestation: fixtureExportAttestation(frozen),
          artifactId: testId(50_501),
          encryptionKeyId: testId(50_502),
          encryptionKey: Buffer.alloc(32, 0x62),
          newChunkId: () => {
            const id = testId(nextId++);
            interrupted.abort();
            return id;
          },
          randomBytes: (length) => Buffer.alloc(length, 0x72),
          signal: interrupted.signal
        })
      ).rejects.toThrow("interrupted");

      const inventory = await store.scanArtifacts();
      expect(inventory).toHaveLength(1);
      expect(inventory[0]).toMatchObject({
        state: "partial",
        exportRequestId: frozen.exportRequestId,
        artifactId: testId(50_501)
      });
      if (inventory[0]?.state !== "partial") throw new Error("partial artifact not found");
      await store.deletePartialArtifact(inventory[0]);
      expect(await store.scanArtifacts()).toEqual([]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
