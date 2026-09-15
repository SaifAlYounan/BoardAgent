import type { Pool, PoolClient } from "pg";
import { expect, it } from "vitest";
import { canonicalJson, type JsonValue } from "../../lib/contracts/src/canonical.js";
import { TOOL_INPUT_SCHEMA_VERSION } from "../../lib/contracts/src/surface-inputs.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import {
  IDENTITY_ONBOARDING_PREFLIGHT_SQL,
  IDENTITY_ONBOARDING_CONTENT_SQL,
  loadAdmittedWhoami,
  loadAdmittedOnboarding,
  type WhoamiProjectionInput
} from "../../artifacts/server/src/identity-onboarding-projection.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";
import { identityOnboardingProjectionPrincipal } from "../helpers/identity-onboarding-projection-principal.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { ORIGINAL_WHOAMI_SQL } from "../helpers/identity-onboarding-original-sql.js";
import {
  originalIdentityOnboarding,
  originalIdentityBound,
  identityObject,
  identityGraph,
  identitySqlUnchanged,
  type IdentityOracleKind,
  type IdentitySqlTransform
} from "../helpers/identity-onboarding-postgres-oracle.js";

type Context = Parameters<typeof withRequestTransaction>[1];
type Fixture = {
  actor: Awaited<ReturnType<typeof seedAuthorizedActor>>;
  principal: Awaited<ReturnType<typeof identityOnboardingProjectionPrincipal>>;
};
type Metadata = Awaited<ReturnType<typeof originalIdentityOnboarding>>["metadata"];
const fields = [
  "row_count",
  "recent_auth_count",
  "scalar_utf8",
  "normalized_json_utf8",
  "json_property_count",
  "json_container_count",
  "observation_sha256"
] as const;
const tx = <T>(pool: Pool, context: Context, work: (client: PoolClient) => Promise<T>) =>
  withRequestTransaction(pool, context, work, { assumeRole: "boardagent_server" });
function whoamiInput(f: Fixture, memberId = f.actor.memberId): WhoamiProjectionInput {
  return {
    memberId,
    roles: f.principal.roles,
    scopes: f.principal.scopes,
    boardIds: f.principal.boardIds,
    protocolClientId: f.principal.protocolClientId,
    accessTokenRecordId: f.principal.accessTokenRecordId
  };
}
function parameters(f: Fixture, kind: IdentityOracleKind, memberId = f.actor.memberId): unknown[] {
  const input = whoamiInput(f, memberId);
  return kind === "onboarding"
    ? [f.actor.boardId, memberId]
    : [
        input.memberId,
        input.roles,
        input.scopes,
        input.boardIds,
        input.protocolClientId,
        input.accessTokenRecordId
      ];
}
const bounds = (m: Metadata) => fields.map((key) => m[key]);
function gate() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, release };
}
const capture = <T>(promise: Promise<T>) =>
  promise.then(
    (value) => ({ ok: true as const, value }),
    (error) => ({ ok: false as const, error })
  );
async function bounded<T>(promise: Promise<T>, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(label)), 5000);
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
async function oracle(
  pool: Pool,
  f: Fixture,
  kind: IdentityOracleKind,
  transform = identitySqlUnchanged,
  context: Context = f.actor.context,
  memberId = f.actor.memberId
) {
  return tx(pool, context, (client) =>
    originalIdentityOnboarding(client, kind, parameters(f, kind, memberId), transform)
  );
}
async function read(
  pool: Pool,
  f: Fixture,
  kind: IdentityOracleKind,
  options: {
    manager?: ResponseAllocationManager;
    signal?: AbortSignal;
    context?: Context;
    memberId?: string;
    transform?: IdentitySqlTransform;
    contentTransform?: IdentitySqlTransform;
    abortAfterMetadata?: boolean;
    afterContent?: () => Promise<void>;
  } = {}
) {
  const manager = options.manager ?? new ResponseAllocationManager(),
    start = manager.accounting.usedUnits,
    abort = new AbortController(),
    owner = manager.openRequest(options.signal ?? abort.signal);
  let metadataCalls = 0,
    contentCalls = 0,
    error: unknown,
    value: unknown,
    metadata: unknown[] = [],
    held = 0,
    afterTerminal = 0;
  const cleanupErrors: unknown[] = [];
  try {
    value = await owner.produce(() =>
      tx(pool, options.context ?? f.actor.context, async (client) => {
        const port = {
          query: async (sql: string, args: unknown[]) => {
            const isMetadata = sql === IDENTITY_ONBOARDING_PREFLIGHT_SQL[kind],
              isContent = sql === IDENTITY_ONBOARDING_CONTENT_SQL[kind];
            expect(isMetadata || isContent).toBe(true);
            if (isMetadata) metadataCalls++;
            if (isContent) contentCalls++;
            const transform = isContent
              ? (options.contentTransform ?? options.transform)
              : options.transform;
            const result = await client.query(transform ? transform(sql) : sql, args);
            if (isMetadata) {
              metadata = result.rows;
              if (options.abortAfterMetadata) abort.abort();
            }
            if (isContent) await options.afterContent?.();
            return result;
          }
        } as unknown as PoolClient;
        return kind === "whoami"
          ? loadAdmittedWhoami(port, whoamiInput(f, options.memberId))
          : loadAdmittedOnboarding(port, f.actor.boardId, options.memberId ?? f.actor.memberId);
      })
    );
  } catch (caught) {
    error = caught;
  } finally {
    held = manager.accounting.usedUnits - start;
    try {
      owner.nativeTerminal();
      afterTerminal = manager.accounting.usedUnits - start;
    } catch (caught) {
      cleanupErrors.push(caught);
    }
    try {
      owner.collectorSettled();
    } catch (caught) {
      cleanupErrors.push(caught);
    }
  }
  if (manager.accounting.usedUnits !== start)
    cleanupErrors.push(new Error("identity/onboarding allocation did not settle"));
  if (cleanupErrors.length)
    throw new AggregateError(
      error === undefined ? cleanupErrors : [error, ...cleanupErrors],
      "identity/onboarding cleanup failed"
    );
  return { value, error, metadata, metadataCalls, contentCalls, held, afterTerminal };
}
async function verify(
  pool: Pool,
  f: Fixture,
  kind: IdentityOracleKind,
  options: { transform?: IdentitySqlTransform; context?: Context; memberId?: string } = {}
) {
  const expected = await oracle(
      pool,
      f,
      kind,
      options.transform,
      options.context,
      options.memberId
    ),
    actual = await read(pool, f, kind, options);
  if (actual.error !== undefined) throw actual.error;
  expect(actual.metadata).toEqual([expected.metadata]);
  expect(Object.keys(actual.metadata[0] as object).sort()).toEqual([...fields].sort());
  for (const key of fields.slice(0, 6))
    expect(expected.metadata[key]).toMatch(/^(0|[1-9][0-9]*)$/u);
  const rows = actual.value as Array<{ fits: boolean; view: JsonValue }>;
  expect(rows.map((row) => canonicalJson(row.view)).sort()).toEqual(
    expected.views.map((view) => canonicalJson(view)).sort()
  );
  expect(rows.every((row) => row.fits === true)).toBe(true);
  const bound = originalIdentityBound(kind, expected.metadata);
  expect(actual.held).toBe(bound.units);
  expect(actual.afterTerminal).toBe(bound.units);
  expect(actual.metadataCalls).toBe(1);
  expect(actual.contentCalls).toBe(1);
  expect(BigInt(Buffer.byteLength(JSON.stringify(rows)))).toBeLessThanOrEqual(bound.jsonUpperBytes);
  const data = kind === "whoami" ? (rows[0]?.view ?? null) : { onboarding: rows[0]?.view ?? null };
  const envelope = {
    schema_version: "boardagent.tool-result.v1",
    tool: kind === "whoami" ? "whoami" : "get_onboarding",
    status: "ok",
    reference: kind === "whoami" ? (options.memberId ?? f.actor.memberId) : f.actor.boardId,
    resource_uri: null,
    data
  };
  const wire = {
      content: [{ type: "text", text: JSON.stringify(envelope) }],
      structuredContent: envelope
    },
    graph = identityGraph([rows, wire]);
  expect(BigInt(graph.properties)).toBeLessThanOrEqual(bound.propertyCount);
  expect(BigInt(graph.containers)).toBeLessThanOrEqual(bound.objectOrArrayCount);
  expect(BigInt(Buffer.byteLength(JSON.stringify(wire)))).toBeLessThanOrEqual(bound.wireUpperBytes);
  return { expected, actual };
}
function replaceExactly(sql: string, old: string, next: string, count = 1) {
  expect(sql.split(old)).toHaveLength(count + 1);
  return sql.replaceAll(old, next);
}
const authFunction = "public.boardagent_recent_auth_context()";
function authRelation(count: number, allNull = false) {
  return `(select ${allNull ? "null" : `'${testId(510010)}'`}::uuid as session_id,
  ${allNull ? "null" : "'Synthetic proof Δ'"}::text as proof_reference,
  ${allNull ? "null" : "'2026-09-13T01:02:03.123456Z'"}::timestamptz as authenticated_at,
  ${allNull ? "null" : "'2026-09-13T01:12:03.123456Z'"}::timestamptz as expires_at from generate_series(1,${count}))`;
}
const contactA = `'[{"synthetic":"1","number":9999999999999999,"nested":[null,"Δ"]}]'::jsonb`;
const contactB = contactA.replace('"synthetic":"1"', '"synthetic":"2"');
function shaped(kind: IdentityOracleKind, contact = contactA): IdentitySqlTransform {
  return (sql) =>
    kind === "whoami"
      ? sql
          .replaceAll(authFunction, authRelation(1))
          .replaceAll(
            "to_jsonb($2::text[])",
            `(to_jsonb($2::text[])||'[{"synthetic":"role"}]'::jsonb)`
          )
      : sql
          .replaceAll("'contact_methods',support.contact_methods", `'contact_methods',${contact}`)
          .replaceAll(
            "support.support_name,support.contact_methods,",
            `support.support_name,${contact} as contact_methods,`
          );
}

it("preserves original identity onboarding rows and auth cardinality while gating every complete projection", async () => {
  const observations: Record<string, unknown>[] = [];
  await withMigratedDatabase("identity_onboarding_projection", async (pool) => {
    const actor = await seedAuthorizedActor(pool, {
      seatRole: "voting_member",
      isSecretary: true,
      scopes: [
        "documents:contribute",
        "documents:read",
        "governance:read",
        "meeting:act",
        "onboarding:read",
        "secretariat:admin"
      ]
    });
    const f: Fixture = {
      actor,
      principal: await identityOnboardingProjectionPrincipal(pool, actor)
    };
    const catalog = await pool.query<{
      relname: string;
      relrowsecurity: boolean;
      relforcerowsecurity: boolean;
      single_id_primary_key: boolean;
    }>(`
      select c.relname,c.relrowsecurity,c.relforcerowsecurity,exists(select 1 from pg_index i join pg_attribute a on a.attrelid=c.oid and a.attnum=i.indkey[0]
      where i.indrelid=c.oid and i.indisprimary and i.indisvalid and i.indisready and i.indnkeyatts=1 and a.attname='id') as single_id_primary_key
      from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='public'
      and c.relname in ('members','board_memberships','onboarding_terms_versions','secretary_support_versions','onboarding_attestations') order by c.relname`);
    expect(catalog.rows).toHaveLength(5);
    for (const row of catalog.rows)
      expect(row).toMatchObject({
        relrowsecurity: true,
        relforcerowsecurity: true,
        single_id_primary_key: true
      });
    await tx(pool, actor.context, async (client) =>
      expect((await client.query("select current_user as role")).rows).toEqual([
        { role: "boardagent_server" }
      ])
    );
    const initial = await verify(pool, f, "whoami"),
      onboarding = await verify(pool, f, "onboarding");
    process.stdout.write(
      `IDENTITY_ONBOARDING_PREREQUISITE ${JSON.stringify({ whoami: initial.expected.metadata, onboarding: onboarding.expected.metadata })}\n`
    );
    expect(initial.expected.views).toHaveLength(1);
    // Mandatory fixture prerequisite, not a conditional skip or synthesized row.
    expect(onboarding.expected.views).toHaveLength(1);
    expect(
      identityObject(identityObject(onboarding.expected.views[0]).secretary_support).version_id
    ).toBe(actor.supportVersionId);
    observations.push({
      phase: "normal",
      catalog: catalog.rows,
      whoami: initial.expected,
      onboarding: onboarding.expected
    });
    const absent = testId(510999);
    for (const kind of ["whoami", "onboarding"] as const) {
      const empty = await verify(pool, f, kind, { memberId: absent });
      expect(empty.expected.views).toEqual([]);
      expect(empty.actual.held).toBe(1);
      for (const context of [
        { ...actor.context, organizationId: testId(510998) },
        { ...actor.context, boardIds: [] }
      ]) {
        const originalContext = await capture(oracle(pool, f, kind, identitySqlUnchanged, context));
        if (originalContext.ok) {
          const checked = await verify(pool, f, kind, { context });
          observations.push({
            phase: "context",
            kind,
            context,
            visibleRows: checked.expected.views.length
          });
        } else {
          const checked = await read(pool, f, kind, { context }),
            originalError = originalContext.error as { code?: unknown; message?: unknown },
            actualError = checked.error as { code?: unknown; message?: unknown } | undefined;
          expect(actualError).toBeDefined();
          expect(
            typeof originalError.code === "string" ? actualError?.code : actualError?.message
          ).toBe(
            typeof originalError.code === "string" ? originalError.code : originalError.message
          );
          observations.push({
            phase: "context",
            kind,
            context,
            originalErrorCode: originalError.code ?? null,
            originalAndAdmittedErrorMatched: true
          });
        }
      }
    }
    let falseGates = 0,
      trueFaults = 0;
    for (const kind of ["whoami", "onboarding"] as const) {
      const transform = shaped(kind),
        positive = await verify(pool, f, kind, { transform }),
        m = positive.expected.metadata;
      expect(BigInt(m.json_property_count)).toBeGreaterThan(0n);
      expect(BigInt(m.scalar_utf8)).toBeGreaterThan(0n);
      const variants =
        kind === "whoami"
          ? [
              { label: "root", needle: "'member_id',source.member_id", column: "source.member_id" },
              { label: "auth", needle: "'proof',source.auth_proof", column: "source.member_id" }
            ]
          : [
              {
                label: "root",
                needle: "'board_id',source.board_id",
                column: "source.membership_id"
              },
              {
                label: "terms",
                needle: "'canonical_text',source.canonical_text",
                column: "source.membership_id"
              },
              {
                label: "support",
                needle: "'name',source.support_name",
                column: "source.membership_id"
              }
            ];
      for (const variant of variants) {
        const text = replaceExactly(
          transform(IDENTITY_ONBOARDING_CONTENT_SQL[kind]),
          variant.needle,
          `${variant.needle}::text||(1/(length(${variant.column}::text)-36))::text`
        );
        for (const mode of ["force_custom_plan", "force_generic_plan"] as const) {
          const name = `wo_${kind}_${variant.label}_${mode}`;
          for (const field of fields) {
            const changed = { ...m };
            changed[field] =
              field === "observation_sha256"
                ? "0".repeat(64)
                : field === "row_count" || field === "recent_auth_count"
                  ? String(BigInt(m[field]) + 1n)
                  : String(BigInt(m[field]) - 1n);
            const rows = await tx(pool, actor.context, async (client) => {
              await client.query(`set local plan_cache_mode=${mode}`);
              return client.query({
                name,
                text,
                values: [...parameters(f, kind), ...bounds(changed)]
              });
            });
            expect(rows.rows).toEqual([{ fits: false, view: null }]);
            falseGates++;
          }
          await expect(
            tx(pool, actor.context, async (client) => {
              await client.query(`set local plan_cache_mode=${mode}`);
              await client.query({ name, text, values: [...parameters(f, kind), ...bounds(m)] });
            })
          ).rejects.toMatchObject({ code: "22012" });
          trueFaults++;
        }
      }
      observations.push({
        phase: "positive-query-shape",
        kind,
        metadata: m,
        normalizedRoots: positive.expected.normalizedRoots
      });
    }
    expect(falseGates).toBe(70);
    expect(trueFaults).toBe(10);
    const shapes = [
      { label: "zero", relation: authRelation(0), count: 0 },
      { label: "one", relation: authRelation(1), count: 1 },
      { label: "null", relation: authRelation(1, true), count: 1 },
      { label: "two", relation: authRelation(2), count: 2 },
      { label: "three", relation: authRelation(3), count: 3 },
      {
        label: "fault",
        count: 1,
        relation: `(select fault_member.id as session_id,(1/(length(fault_member.id::text)-length($1::uuid::text)))::text as proof_reference,
        null::timestamptz as authenticated_at,null::timestamptz as expires_at from members as fault_member where fault_member.id='${actor.memberId}'::uuid)`
      }
    ];
    for (const shape of shapes) {
      let positiveShape: Awaited<ReturnType<typeof verify>> | undefined;
      if (shape.count <= 1 && shape.label !== "fault") {
        const checked = await verify(pool, f, "whoami", {
          transform: (sql) => sql.replaceAll(authFunction, shape.relation)
        });
        positiveShape = checked;
        expect(checked.expected.metadata.recent_auth_count).toBe(String(shape.count));
        expect(identityObject(checked.expected.views[0]).recent_auth).toEqual(
          shape.count === 0
            ? null
            : shape.label === "null"
              ? { proof: null, session_id: null, authenticated_at: null, expires_at: null }
              : identityObject(checked.expected.views[0]).recent_auth
        );
      }
      for (const mode of ["force_custom_plan", "force_generic_plan"] as const) {
        for (const visible of [true, false]) {
          if (!visible && shape.label === "null") continue;
          for (const statement of ["original", "metadata", "content"] as const) {
            const source =
              statement === "original"
                ? ORIGINAL_WHOAMI_SQL
                : statement === "metadata"
                  ? IDENTITY_ONBOARDING_PREFLIGHT_SQL.whoami
                  : IDENTITY_ONBOARDING_CONTENT_SQL.whoami;
            const text = replaceExactly(source, authFunction, shape.relation),
              args = parameters(f, "whoami", visible ? actor.memberId : absent),
              name = `wo_shape_${shape.label}_${visible}_${statement}_${mode}`;
            const call = tx(pool, actor.context, async (client) => {
              await client.query(`set local plan_cache_mode=${mode}`);
              return client.query({
                name,
                text,
                values:
                  statement === "content"
                    ? [
                        ...args,
                        ...bounds(positiveShape?.expected.metadata ?? initial.expected.metadata)
                      ]
                    : args
              });
            });
            if (visible && (shape.count > 1 || shape.label === "fault"))
              await expect(call).rejects.toMatchObject({
                code: shape.label === "fault" ? "22012" : "21000"
              });
            else {
              const result = await call;
              if (!visible)
                expect(
                  statement === "metadata" ? result.rows[0].row_count : String(result.rows.length)
                ).toBe("0");
              else {
                if (!positiveShape) throw new Error("positive auth source oracle absent");
                if (statement === "metadata")
                  expect(result.rows).toEqual([positiveShape.expected.metadata]);
                else
                  expect(result.rows.map((row) => canonicalJson(row.view))).toEqual(
                    positiveShape.expected.views.map((view) => canonicalJson(view))
                  );
              }
            }
          }
          observations.push({
            phase: "auth-source",
            shape: shape.label,
            visible,
            mode,
            expected:
              visible && (shape.count > 1 || shape.label === "fault")
                ? shape.label === "fault"
                  ? "22012"
                  : "21000"
                : visible
                  ? "selected"
                  : "empty"
          });
        }
      }
    }
    for (const kind of ["whoami", "onboarding"] as const) {
      const positive = await verify(pool, f, kind),
        loss: IdentitySqlTransform = (sql) =>
          kind === "whoami"
            ? replaceExactly(sql, "member.state='active'", "member.state='active' and false")
            : replaceExactly(
                sql,
                "member_id=$2 and state='active'",
                "member_id=$2 and state='active' and false"
              );
      const missing = await read(pool, f, kind, { contentTransform: loss });
      if (missing.error !== undefined) throw missing.error;
      expect(missing.value).toEqual([]);
      expect(missing.held).toBe(positive.actual.held);
      const changed: IdentitySqlTransform = (sql) =>
        kind === "whoami"
          ? sql
              .replaceAll(
                "'display_name',member.display_name",
                "'display_name',reverse(member.display_name)"
              )
              .replaceAll(
                "member.member_kind,member.display_name,member.state",
                "member.member_kind,reverse(member.display_name) as display_name,member.state"
              )
          : sql
              .replaceAll(
                "'canonical_text',terms.canonical_text",
                "'canonical_text',reverse(terms.canonical_text)"
              )
              .replaceAll(
                "terms.canonical_text,encode(",
                "reverse(terms.canonical_text) as canonical_text,encode("
              );
      const fresh = await verify(pool, f, kind, { transform: changed });
      for (const field of fields.slice(0, 6))
        expect(fresh.expected.metadata[field]).toBe(positive.expected.metadata[field]);
      expect(fresh.expected.metadata.observation_sha256).not.toBe(
        positive.expected.metadata.observation_sha256
      );
      const refusal = await read(pool, f, kind, { contentTransform: changed });
      expect(refusal.error).toBeInstanceOf(ResponseAllocationUnavailable);
      observations.push({
        phase: "query-only-change",
        kind,
        fullLossRows: 0,
        sameCostTextRefused: true,
        held: refusal.held
      });
      const manager = new ResponseAllocationManager(),
        holder = manager.openRequest(new AbortController().signal),
        one = responseAllocationPlan({
          kind: "document",
          representation: "tool",
          canonicalBytes: 1,
          sourceId: "wo-occupancy",
          sourceVersion: "1",
          sha256: "a".repeat(64)
        });
      const holderErrors: unknown[] = [];
      try {
        await holder.produce(async () => {
          for (let n = 0; n < 2048; n++) holder.reserve(one);
        });
        const busy = await read(pool, f, kind, { manager });
        expect(busy.error).toBeInstanceOf(ResponseAllocationUnavailable);
        expect(busy.metadataCalls).toBe(1);
        expect(busy.contentCalls).toBe(0);
        expect(manager.accounting.usedUnits).toBe(2048);
      } catch (error) {
        holderErrors.push(error);
      } finally {
        try {
          holder.nativeTerminal();
        } catch (error) {
          holderErrors.push(error);
        }
        try {
          holder.collectorSettled();
        } catch (error) {
          holderErrors.push(error);
        }
      }
      if (holderErrors.length) throw new AggregateError(holderErrors, "occupancy cleanup failed");
      expect(manager.accounting.usedUnits).toBe(0);
      const aborted = await read(pool, f, kind, { abortAfterMetadata: true });
      expect(aborted.error).toBeInstanceOf(ResponseAllocationUnavailable);
      expect(aborted.metadataCalls).toBe(1);
      expect(aborted.contentCalls).toBe(0);
      const entered = gate(),
        release = gate(),
        abort = new AbortController(),
        pending = capture(
          read(pool, f, kind, {
            manager,
            signal: abort.signal,
            afterContent: async () => {
              entered.release();
              await release.promise;
            }
          })
        );
      const heldErrors: unknown[] = [];
      try {
        await bounded(
          Promise.race([
            entered.promise,
            pending.then((result) => {
              throw result.ok ? new Error("producer settled before held content") : result.error;
            })
          ]),
          "held content never entered"
        );
        abort.abort();
        expect(manager.accounting.usedUnits).toBe(positive.actual.held);
      } catch (error) {
        heldErrors.push(error);
      } finally {
        release.release();
        try {
          const settled = await bounded(pending, "held producer did not settle");
          if (!settled.ok) heldErrors.push(settled.error);
          else expect(settled.value.error).toBeInstanceOf(ResponseAllocationUnavailable);
        } catch (error) {
          heldErrors.push(error);
        }
      }
      if (heldErrors.length) throw new AggregateError(heldErrors, "held producer fixture failed");
      expect(manager.accounting.usedUnits).toBe(0);
      observations.push({
        phase: "occupancy-lifetime",
        kind,
        fullUnits: 2048,
        metadataAbortContentCalls: 0,
        heldContentAborted: true,
        finalUnits: 0
      });
    }
    const contactsBefore = await verify(pool, f, "onboarding", {
        transform: shaped("onboarding", contactA)
      }),
      contactsAfter = await verify(pool, f, "onboarding", {
        transform: shaped("onboarding", contactB)
      });
    for (const field of fields.slice(0, 6))
      expect(contactsBefore.expected.metadata[field]).toBe(contactsAfter.expected.metadata[field]);
    expect(contactsBefore.expected.metadata.observation_sha256).not.toBe(
      contactsAfter.expected.metadata.observation_sha256
    );
    expect(
      (
        await read(pool, f, "onboarding", {
          transform: shaped("onboarding", contactA),
          contentTransform: shaped("onboarding", contactB)
        })
      ).error
    ).toBeInstanceOf(ResponseAllocationUnavailable);
    expect(contactsBefore.expected.normalizedRoots[0]).toContain("9999999999999999");
    const contacts = identityObject(
      identityObject(contactsBefore.expected.views[0]).secretary_support
    ).contact_methods as JsonValue[];
    expect(identityObject(contacts[0]).number).toBe(10000000000000000);
    const authBefore: IdentitySqlTransform = (sql) => sql.replaceAll(authFunction, authRelation(1)),
      authAfter: IdentitySqlTransform = (sql) =>
        authBefore(sql).replaceAll("01:02:03.123456Z", "01:02:03.123457Z");
    const beforeTime = await verify(pool, f, "whoami", { transform: authBefore }),
      afterTime = await verify(pool, f, "whoami", { transform: authAfter });
    for (const field of fields.slice(0, 6))
      expect(beforeTime.expected.metadata[field]).toBe(afterTime.expected.metadata[field]);
    expect(beforeTime.expected.metadata.observation_sha256).not.toBe(
      afterTime.expected.metadata.observation_sha256
    );
    expect(
      (await read(pool, f, "whoami", { transform: authBefore, contentTransform: authAfter })).error
    ).toBeInstanceOf(ResponseAllocationUnavailable);
    const repository = new PgSurfaceReadRepository(pool, { cursorKey: Buffer.alloc(32, 1) });
    let publicCalls = 0;
    for (const tool of ["whoami", "get_onboarding", "get_onboarding_status"] as const) {
      const kind = tool === "whoami" ? "whoami" : "onboarding",
        expected = await oracle(pool, f, kind),
        manager = new ResponseAllocationManager(),
        owner = manager.openRequest(new AbortController().signal),
        errors: unknown[] = [];
      try {
        const actual = await owner.produce(() =>
          repository.executeRead(f.principal, tool, {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            ...(tool === "whoami" ? {} : { board_id: actor.boardId })
          })
        );
        const view = expected.views[0] ?? null;
        const data =
          tool === "whoami"
            ? view
            : tool === "get_onboarding"
              ? { onboarding: view }
              : {
                  board_id: actor.boardId,
                  status:
                    view === null
                      ? "unavailable"
                      : identityObject(view).attested === true
                        ? "current"
                        : "required",
                  terms_version_id:
                    view === null ? null : identityObject(identityObject(view).terms).version_id
                };
        const envelope = {
          schema_version: "boardagent.tool-result.v1",
          tool,
          status: "ok",
          reference:
            tool === "whoami" ? actor.memberId : tool === "get_onboarding" ? actor.boardId : null,
          resource_uri: null,
          data
        };
        expect(canonicalJson(actual)).toBe(canonicalJson(envelope));
        expect(JSON.stringify(actual)).toBe(JSON.stringify(envelope));
        expect(manager.accounting.usedUnits).toBe(
          originalIdentityBound(kind, expected.metadata).units
        );
        publicCalls++;
      } catch (error) {
        errors.push(error);
      } finally {
        try {
          owner.nativeTerminal();
        } catch (error) {
          errors.push(error);
        }
        try {
          owner.collectorSettled();
        } catch (error) {
          errors.push(error);
        }
      }
      if (errors.length) throw new AggregateError(errors, `public ${tool} failed`);
      expect(manager.accounting.usedUnits).toBe(0);
    }
    expect(publicCalls).toBe(3);
    observations.push({
      falseGates,
      trueFaults,
      publicCalls,
      contactNumericCarry: true,
      sameCostContactRefused: true,
      rawMicrosecondChangeRefused: true,
      finalUnits: 0
    });
  });
  process.stdout.write(
    `IDENTITY_ONBOARDING_PROJECTION_OBSERVATION ${JSON.stringify({ observations, limitations: ["Synthetic constrained session and query-only auth/contact relations", "No authentication function replacement, administrative writer or real recent-auth ceremony", "Modelled PostgreSQL owner lifetime; native and RSS separate"] })}\n`
  );
}, 120000);
