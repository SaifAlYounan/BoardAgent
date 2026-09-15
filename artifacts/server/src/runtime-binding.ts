import type { Pool, PoolClient } from "pg";

import type { BoardAgentConfig } from "@boardagent/config";
import { UuidV7Schema, canonicalJson } from "@boardagent/contracts";
import {
  assertBundledSchemaInTransaction,
  withIdentityTransaction,
  withWorkerTransaction,
  type RuntimeKeyRegistration
} from "@boardagent/db";

import type { BoardAgentKeyMaterial, BoardAgentWorkerKeyMaterial } from "./key-material.js";
import { assertRetainedDataKeyBinding } from "./retained-data-keys.js";

const PURPOSES = ["oauth_signing", "evidence_signing", "browser_session", "data_kek"] as const;

type RuntimeKeyPurpose = (typeof PURPOSES)[number];

interface InstanceRow {
  readonly instance_id: string;
  readonly organization_id: string;
  readonly canonical_resource_uri: string;
}

interface RuntimeKeyRow {
  readonly id: string;
  readonly kid: string;
  readonly purpose: RuntimeKeyPurpose;
  readonly algorithm: RuntimeKeyRegistration["algorithm"];
  readonly public_jwk: Readonly<Record<string, unknown>> | null;
  readonly nonsecret_locator: string;
}

export interface BoardAgentRuntimeBinding {
  readonly instanceId: string;
  readonly organizationId: string;
  readonly canonicalResourceUri: string;
  readonly keyIds: Readonly<Record<RuntimeKeyPurpose, string>>;
  readonly keyLocators: Readonly<Record<RuntimeKeyPurpose, string>>;
}

function locator(config: BoardAgentConfig, purpose: RuntimeKeyPurpose): string {
  const source = {
    oauth_signing: config.keySources.oauth,
    evidence_signing: config.keySources.evidence,
    browser_session: config.keySources.browserSession,
    data_kek: config.keySources.dataEncryption
  }[purpose];
  return typeof source === "string" ? `file:${source}` : `derived:boardagent.dev.v1/${purpose}`;
}

export function runtimeKeyRegistrations(
  config: BoardAgentConfig,
  keys: BoardAgentKeyMaterial,
  newId: () => string
): readonly RuntimeKeyRegistration[] {
  const registrations: readonly RuntimeKeyRegistration[] = [
    {
      keyId: UuidV7Schema.parse(newId()),
      kid: keys.oauthKid,
      purpose: "oauth_signing",
      algorithm: "ES256",
      publicJwk: keys.oauthPublicJwk,
      nonsecretLocator: locator(config, "oauth_signing")
    },
    {
      keyId: UuidV7Schema.parse(newId()),
      kid: keys.evidenceKid,
      purpose: "evidence_signing",
      algorithm: "EdDSA",
      publicJwk: keys.evidencePublicJwk,
      nonsecretLocator: locator(config, "evidence_signing")
    },
    {
      keyId: UuidV7Schema.parse(newId()),
      kid: keys.browserSessionKid,
      purpose: "browser_session",
      algorithm: "HMAC-SHA256",
      publicJwk: null,
      nonsecretLocator: locator(config, "browser_session")
    },
    {
      keyId: UuidV7Schema.parse(newId()),
      kid: keys.dataEncryptionKid,
      purpose: "data_kek",
      algorithm: "A256GCM",
      publicJwk: null,
      nonsecretLocator: locator(config, "data_kek")
    }
  ];
  return registrations;
}

function samePublicJwk(
  left: Readonly<Record<string, unknown>> | null,
  right: Readonly<Record<string, unknown>> | null
): boolean {
  return left === null || right === null
    ? left === right
    : canonicalJson(left as never) === canonicalJson(right as never);
}

/**
 * Resolves the sole configured instance and proves that every loaded secret is bound to
 * the exact active public/key identity recorded by the migrator. Startup must not infer
 * an organization or silently accept a rotated/compromised key.
 */
async function resolveRuntimeBinding(
  client: PoolClient,
  config: BoardAgentConfig,
  keys: BoardAgentKeyMaterial | BoardAgentWorkerKeyMaterial
): Promise<BoardAgentRuntimeBinding> {
  await assertBundledSchemaInTransaction(client);
  const organizationId = UuidV7Schema.parse(config.organizationId);
  const expected: readonly RuntimeKeyRegistration[] =
    "oauthKid" in keys
      ? runtimeKeyRegistrations(
          config,
          keys,
          () =>
            // The registration helper validates identifiers. These values are discarded here;
            // only its deterministic key metadata is used for comparison.
            "018f0000-0000-7000-8000-000000000000"
        )
      : [
          {
            keyId: "018f0000-0000-7000-8000-000000000000",
            kid: keys.evidenceKid,
            purpose: "evidence_signing",
            algorithm: "EdDSA",
            publicJwk: keys.evidencePublicJwk,
            nonsecretLocator: locator(config, "evidence_signing")
          },
          {
            keyId: "018f0000-0000-7000-8000-000000000000",
            kid: keys.dataEncryptionKid,
            purpose: "data_kek",
            algorithm: "A256GCM",
            publicJwk: null,
            nonsecretLocator: locator(config, "data_kek")
          }
        ];
  const instanceResult = await client.query<InstanceRow>(
    `select instance_id,organization_id,canonical_resource_uri
           from system_instance
          where singleton_key and organization_id=$1`,
    [organizationId]
  );
  const instance = instanceResult.rows[0];
  if (!instance || instanceResult.rows.length !== 1) {
    throw new Error("configured BoardAgent organization is not the bootstrapped instance");
  }
  if (instance.canonical_resource_uri !== config.canonicalResourceUri) {
    throw new Error("configured canonical resource does not match the bootstrapped instance");
  }
  const keyResult = await client.query<RuntimeKeyRow>(
    `select id,kid,purpose,algorithm,public_jwk,nonsecret_locator
           from crypto_key_registry
          where organization_id=$1 and retired_at is null and compromised_at is null
            and activated_at<=transaction_timestamp()
            and purpose in ('oauth_signing','evidence_signing','browser_session','data_kek')
          order by purpose,id`,
    [organizationId]
  );
  if (keyResult.rows.length !== PURPOSES.length) {
    throw new Error("runtime requires exactly four active purpose-separated keys");
  }
  const byPurpose = new Map(keyResult.rows.map((row) => [row.purpose, row]));
  const keyIds = {} as Record<RuntimeKeyPurpose, string>;
  const keyLocators = {} as Record<RuntimeKeyPurpose, string>;
  for (const purpose of PURPOSES) {
    const row = byPurpose.get(purpose);
    if (!row) throw new Error("runtime requires exactly four active purpose-separated keys");
    keyIds[purpose] = UuidV7Schema.parse(row.id);
    keyLocators[purpose] = row.nonsecret_locator;
  }
  for (const registration of expected) {
    const row = byPurpose.get(registration.purpose);
    if (
      !row ||
      row.kid !== registration.kid ||
      row.algorithm !== registration.algorithm ||
      row.nonsecret_locator !== registration.nonsecretLocator ||
      !samePublicJwk(row.public_jwk, registration.publicJwk)
    ) {
      throw new Error(`active ${registration.purpose} key does not match loaded key material`);
    }
    keyIds[registration.purpose] = UuidV7Schema.parse(row.id);
    keyLocators[registration.purpose] = row.nonsecret_locator;
  }
  await assertRetainedDataKeyBinding(
    client,
    {
      instanceId: instance.instance_id,
      organizationId,
      activeKeyId: keyIds.data_kek
    },
    keys.retainedDataKeys
  );
  return {
    instanceId: UuidV7Schema.parse(instance.instance_id),
    organizationId,
    canonicalResourceUri: instance.canonical_resource_uri,
    keyIds,
    keyLocators
  };
}

export async function loadBoardAgentRuntimeBinding(
  pool: Pool,
  config: BoardAgentConfig,
  keys: BoardAgentKeyMaterial,
  options: { readonly assumeRole?: "boardagent_server" } = {}
): Promise<BoardAgentRuntimeBinding> {
  const organizationId = UuidV7Schema.parse(config.organizationId);
  return withIdentityTransaction(
    pool,
    { organizationId },
    (client) => resolveRuntimeBinding(client, config, keys),
    options
  );
}

/** Worker startup proves the same binding through worker scope and worker-only authority. */
export async function loadBoardAgentWorkerRuntimeBinding(
  pool: Pool,
  config: BoardAgentConfig,
  keys: BoardAgentWorkerKeyMaterial,
  options: { readonly assumeRole?: "boardagent_worker" } = {}
): Promise<BoardAgentRuntimeBinding> {
  return withWorkerTransaction(
    pool,
    (client) =>
      resolveRuntimeBinding(client, config, {
        evidencePrivateKey: keys.evidencePrivateKey,
        evidencePublicJwk: keys.evidencePublicJwk,
        evidenceKid: keys.evidenceKid,
        dataEncryptionKid: keys.dataEncryptionKid,
        dataEncryptionKey: keys.dataEncryptionKey,
        ...(keys.retainedDataKeys === undefined ? {} : { retainedDataKeys: keys.retainedDataKeys })
      }),
    options
  );
}
