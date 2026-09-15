import { expect, it } from "vitest";
import type { PoolClient } from "pg";
import { canonicalJson, sha256Hex } from "../../lib/contracts/src/index.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import {
  DOCUMENT_METADATA_PREFLIGHT_SQL,
  DOCUMENT_METADATA_CONTENT_SQL,
  loadAdmittedDocumentMetadata,
  documentMetadataProjectionPlan,
  documentMetadataProjectionCost,
  type DocumentMetadataKind,
  type DocumentMetadataInput,
  type DocumentMetadataObservation
} from "../../artifacts/server/src/document-metadata-projection.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { testId } from "../helpers/authorized-actor.js";
import { seedDocumentMetadataFixture } from "../helpers/document-metadata-fixture.js";
import {
  documentOriginalSql,
  documentMetadataOracleSql,
  normalizedOriginalRows,
  independentDocumentCost,
  type DocumentOriginalRow,
  type DocumentOracleRow
} from "../helpers/document-metadata-pg-oracle.js";

const kinds = ["hash", "validation", "versions", "documents"] as const;
const copy = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;
const parameters = (input: DocumentMetadataInput) =>
  input.kind === "hash"
    ? [input.selectorId, input.versionId]
    : input.kind === "validation"
      ? [input.selectorId]
      : [input.selectorId, input.cursorAt, input.cursorId, input.limit + 1];
const strip = (rows: readonly DocumentOriginalRow[]) =>
  rows.map(({ item, cursor_at, cursor_id }) => ({ item, cursor_at, cursor_id }));
const close = (owner: ReturnType<ResponseAllocationManager["openRequest"]>) => {
  try {
    owner.nativeTerminal();
  } finally {
    owner.collectorSettled();
  }
};
const graph = (roots: readonly unknown[]) => {
  const pending = [...roots],
    seen = new Set<object>();
  let properties = 0,
    containers = 0;
  while (pending.length) {
    const value = pending.pop();
    if (value === null || typeof value !== "object" || seen.has(value)) continue;
    seen.add(value);
    containers++;
    if (!Array.isArray(value)) properties += Object.keys(value).length;
    pending.push(...Object.values(value));
  }
  return { properties, containers };
};

it("admits exact document metadata with normal contributions and fresh PostgreSQL constructor gates", async () => {
  await withMigratedDatabase("document_metadata_projection", async (pool) => {
    const fixture = await seedDocumentMetadataFixture(pool),
      actor = fixture.actor;
    expect(fixture.attempts).toHaveLength(4);
    const manager = new ResponseAllocationManager(),
      reports: unknown[] = [],
      parity: unknown[] = [];
    const transaction = <T>(body: (client: PoolClient) => Promise<T>, context = actor.context) =>
      withRequestTransaction(pool, context, body, { assumeRole: "boardagent_server" });
    const input = (kind: DocumentMetadataKind, limit = 100): DocumentMetadataInput => ({
      kind,
      selectorId:
        kind === "validation"
          ? fixture.acceptedAttemptId
          : kind === "documents"
            ? actor.boardId
            : fixture.documentAId,
      versionId: kind === "hash" ? fixture.firstVersionId : null,
      cursorAt: null,
      cursorId: null,
      limit: kind === "hash" || kind === "validation" ? 1 : limit
    });
    const original = (selection: DocumentMetadataInput, context = actor.context) =>
      transaction(
        async (client) =>
          normalizedOriginalRows(
            selection.kind,
            (await client.query(documentOriginalSql[selection.kind], parameters(selection))).rows
          ),
        context
      );
    const metadata = (selection: DocumentMetadataInput, context = actor.context) =>
      transaction(
        async (client) =>
          (
            await client.query<DocumentMetadataObservation>(
              DOCUMENT_METADATA_PREFLIGHT_SQL[selection.kind],
              parameters(selection)
            )
          ).rows,
        context
      );
    const catalog = (
      await pool.query(`select c.relname::text,c.relrowsecurity,c.relforcerowsecurity,
      exists(select 1 from pg_index i join pg_attribute a on a.attrelid=c.oid and a.attnum=i.indkey[0]
        where i.indrelid=c.oid and i.indisprimary and i.indisvalid and i.indisready and i.indnkeyatts=1
          and i.indpred is null and i.indexprs is null and a.attname='id' and a.attnotnull) as id_pk,
      (select jsonb_agg(jsonb_build_object('type',co.contype,'definition',pg_get_constraintdef(co.oid),'deferred',co.condeferrable,'initially_deferred',co.condeferred)
        order by co.conname) from pg_constraint co where co.conrelid=c.oid and co.contype in ('f','u')) as relations
      from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='public'
        and c.relname in ('documents','document_versions','document_validation_attempts') order by c.relname`)
    ).rows;
    expect(catalog).toHaveLength(3);
    for (const row of catalog)
      expect(row).toMatchObject({ relrowsecurity: true, relforcerowsecurity: true, id_pk: true });
    const documentRelations = catalog.find((row) => row.relname === "documents")
      ?.relations as Array<Record<string, unknown>>;
    expect(documentRelations).toContainEqual(
      expect.objectContaining({
        type: "f",
        definition: expect.stringContaining(
          "FOREIGN KEY (id, current_version_id) REFERENCES document_versions(document_id, id)"
        ),
        deferred: true,
        initially_deferred: true
      })
    );
    const versionRelations = catalog.find((row) => row.relname === "document_versions")
      ?.relations as Array<Record<string, unknown>>;
    for (const definition of ["UNIQUE (document_id, id)", "UNIQUE (document_id, version)"])
      expect(versionRelations).toContainEqual(expect.objectContaining({ type: "u", definition }));
    expect(versionRelations).toContainEqual(
      expect.objectContaining({
        type: "f",
        definition: expect.stringContaining(
          "FOREIGN KEY (board_id, document_id) REFERENCES documents(board_id, id)"
        )
      })
    );
    expect(
      await transaction(async (client) => (await client.query("select current_user")).rows)
    ).toEqual([{ current_user: "boardagent_server" }]);

    async function read(
      selection: DocumentMetadataInput,
      options: { afterMetadata?: () => Promise<unknown>; context?: typeof actor.context } = {}
    ) {
      const owner = manager.openRequest(new AbortController().signal),
        baseline = manager.accounting.usedUnits;
      let preflights = 0,
        contents = 0,
        held = baseline,
        afterTerminal = baseline,
        failure: unknown,
        rows: readonly DocumentOriginalRow[] | undefined;
      try {
        rows = await owner.produce(() =>
          transaction(async (client) => {
            const proxy = Object.create(client) as PoolClient;
            proxy.query = (async (sql: string, values?: unknown[]) => {
              if (sql === DOCUMENT_METADATA_PREFLIGHT_SQL[selection.kind]) {
                preflights++;
                const result = await client.query(sql, values);
                await options.afterMetadata?.();
                return result;
              }
              if (sql === DOCUMENT_METADATA_CONTENT_SQL[selection.kind]) {
                contents++;
                return client.query(sql, values);
              }
              throw new Error("unexpected document metadata statement");
            }) as PoolClient["query"];
            return loadAdmittedDocumentMetadata(proxy, selection);
          }, options.context ?? actor.context)
        );
      } catch (error) {
        failure = error;
      } finally {
        held = manager.accounting.usedUnits;
        try {
          owner.nativeTerminal();
          afterTerminal = manager.accounting.usedUnits;
        } finally {
          owner.collectorSettled();
        }
      }
      reports.push({
        kind: selection.kind,
        preflights,
        contents,
        held,
        afterTerminal,
        finalUnits: manager.accounting.usedUnits,
        failed: failure !== undefined
      });
      try {
        expect(preflights).toBe(1);
        expect(manager.accounting.usedUnits).toBe(baseline);
        expect(afterTerminal).toBe(held);
      } catch (error) {
        if (failure !== undefined)
          throw new AggregateError([failure, error], "document SQL/accounting failed");
        throw error;
      }
      if (failure !== undefined) throw failure;
      return { rows: rows!, held, contents };
    }
    async function verify(selection: DocumentMetadataInput) {
      const old = await original(selection),
        observed = await metadata(selection);
      const measured = await transaction(
        async (client) =>
          (
            await client.query<DocumentOracleRow>(
              documentMetadataOracleSql[selection.kind],
              parameters(selection)
            )
          ).rows
      );
      expect(observed).toEqual(measured);
      const bound = independentDocumentCost(selection.kind, measured);
      expect(
        documentMetadataProjectionCost(selection.kind, {
          row_count: bound.row_count,
          scalar_utf8: bound.scalar_utf8
        })
      ).toEqual({
        jsonUpperBytes: bound.jsonUpperBytes,
        propertyCount: bound.propertyCount,
        objectOrArrayCount: bound.objectOrArrayCount
      });
      expect(documentMetadataProjectionPlan(selection, observed).units).toBe(bound.units);
      const actual = await read(selection);
      expect(strip(actual.rows)).toEqual(old);
      expect(actual.held).toBe(bound.units);
      expect(actual.contents).toBe(1);
      expect(Buffer.byteLength(JSON.stringify(actual.rows))).toBeLessThanOrEqual(
        Number(bound.jsonUpperBytes)
      );
      const shape = graph([actual.rows]);
      expect(shape.properties).toBeLessThanOrEqual(Number(bound.propertyCount));
      expect(shape.containers).toBeLessThanOrEqual(Number(bound.objectOrArrayCount));
      parity.push({
        kind: selection.kind,
        rows: old.length,
        hash: sha256Hex(canonicalJson(strip(old))),
        ...bound
      });
      return { old, observed, bound };
    }
    const initialHash = await verify(input("hash"));
    expect(initialHash.old).toHaveLength(1);
    expect(initialHash.old[0]?.item).toMatchObject({
      document_id: fixture.documentAId,
      version_id: fixture.firstVersionId,
      version: 1,
      document_schema: null
    });
    const currentHash = await verify({ ...input("hash"), versionId: fixture.secondVersionId });
    expect(currentHash.old[0]?.item).toMatchObject({
      version: 2,
      document_schema: "boardagent.board-pack.v1"
    });
    expect((await verify({ ...input("hash"), versionId: fixture.absentVersionId })).old).toEqual(
      []
    );
    const initialValidation = await verify(input("validation"));
    expect(initialValidation.old[0]?.item).toMatchObject({
      result: "accepted",
      accepted_document_version_id: fixture.secondVersionId
    });
    const rejected = await verify({
      ...input("validation"),
      selectorId: fixture.rejectedAttemptId
    });
    expect(rejected.old[0]?.item).toMatchObject({
      result: "rejected",
      accepted_document_version_id: null
    });
    expect(
      (await verify({ ...input("validation"), selectorId: fixture.absentAttemptId })).old
    ).toEqual([]);
    expect((await verify(input("versions"))).old).toHaveLength(2);
    const initialDocuments = await verify(input("documents"));
    expect(initialDocuments.old).toHaveLength(2);
    expect(
      (await verify({ ...input("versions"), selectorId: fixture.absentDocumentId })).old
    ).toEqual([]);
    for (const kind of ["versions", "documents"] as const) {
      const first = await verify(input(kind, 1));
      expect(first.old).toHaveLength(2);
      const anchor = first.old[0]!;
      expect(typeof anchor.cursor_at).toBe("string");
      const next = await verify({
        ...input(kind, 1),
        cursorAt: anchor.cursor_at,
        cursorId: anchor.cursor_id
      });
      expect(next.old).toHaveLength(1);
      const last = next.old[0]!;
      expect(
        (await verify({ ...input(kind, 1), cursorAt: last.cursor_at, cursorId: last.cursor_id }))
          .old
      ).toEqual([]);
    }

    let thirdVersion = "";
    await expect(
      read(input("versions"), {
        afterMetadata: async () => {
          thirdVersion = await fixture.growDocumentA();
        }
      })
    ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    expect(fixture.attempts).toHaveLength(5);
    const grownVersions = await verify(input("versions"));
    expect(grownVersions.old).toHaveLength(3);
    expect(grownVersions.old.some((row) => row.cursor_id === thirdVersion)).toBe(true);
    // Reuse the saved pre-A3 document plan to isolate a real current-version
    // change without manufacturing another writer action or immutable update.
    const staleOwner = manager.openRequest(new AbortController().signal);
    try {
      const result = await staleOwner.produce(async () => {
        staleOwner.reserve(
          documentMetadataProjectionPlan(input("documents"), initialDocuments.observed)
        );
        return transaction((client) =>
          client.query(DOCUMENT_METADATA_CONTENT_SQL.documents, [
            ...parameters(input("documents")),
            JSON.stringify(initialDocuments.observed)
          ])
        );
      });
      expect(result.rows).toEqual([{ fits: false, item: null, cursor_at: null, cursor_id: null }]);
    } finally {
      close(staleOwner);
    }
    const afterA3 = await verify(input("documents"));
    expect(afterA3.old).toHaveLength(2);
    expect((await verify(input("hash"))).old).toEqual(initialHash.old);
    expect((await verify(input("validation"))).old).toEqual(initialValidation.old);
    let thirdDocument = "";
    await expect(
      read(input("documents"), {
        afterMetadata: async () => {
          thirdDocument = (await fixture.createThirdDocument()).documentId;
        }
      })
    ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    const allDocuments = await verify(input("documents"));
    expect(allDocuments.old).toHaveLength(3);
    expect(allDocuments.old.some((row) => row.cursor_id === thirdDocument)).toBe(true);
    expect(fixture.attempts).toHaveLength(6);

    for (const kind of kinds) {
      const occupied = manager.openRequest(new AbortController().signal);
      try {
        await occupied.produce(async () => {
          for (let i = 0; i < 2048; i++)
            occupied.reserve(
              responseAllocationPlan({
                kind: "document",
                representation: "tool",
                canonicalBytes: 1,
                sourceId: "synthetic-occupancy",
                sourceVersion: "1",
                sha256: "a".repeat(64)
              })
            );
        });
        await expect(read(input(kind))).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
        expect(reports.at(-1)).toMatchObject({ preflights: 1, contents: 0, held: 2048 });
      } finally {
        close(occupied);
      }
      expect(manager.accounting.usedUnits).toBe(0);
    }
    async function guarded(
      selection: DocumentMetadataInput,
      bound: readonly DocumentMetadataObservation[],
      fault: string,
      mode: "force_custom_plan" | "force_generic_plan"
    ) {
      const owner = manager.openRequest(new AbortController().signal);
      try {
        return await owner.produce(async () => {
          owner.reserve(documentMetadataProjectionPlan(selection, await metadata(selection)));
          return transaction(async (client) => {
            await client.query(`set local plan_cache_mode=${mode}`);
            return client.query({
              text: fault,
              values: [...parameters(selection), JSON.stringify(bound)],
              name: `document_${selection.kind}_${mode}`
            });
          });
        });
      } finally {
        close(owner);
      }
    }
    let falseControls = 0,
      trueControls = 0;
    for (const kind of kinds)
      for (const mode of ["force_custom_plan", "force_generic_plan"] as const) {
        const selection = input(kind),
          observed = await metadata(selection);
        expect(observed.length).toBeGreaterThan(0);
        const needle = "jsonb_build_object(";
        expect(DOCUMENT_METADATA_CONTENT_SQL[kind].split(needle)).toHaveLength(2);
        const fault = DOCUMENT_METADATA_CONTENT_SQL[kind].replace(
          needle,
          `jsonb_build_object('fault',1/(0*random())) || ${needle}`
        );
        const mutate = (key: keyof DocumentMetadataObservation, value: string | null) => {
          const changed = copy(observed) as Array<
            Record<keyof DocumentMetadataObservation, string | null>
          >;
          changed[0]![key] = value;
          return changed as unknown as DocumentMetadataObservation[];
        };
        const falseBounds = [
          [],
          mutate("id", testId(286_099)),
          mutate(
            "observation_sha256",
            observed[0]!.observation_sha256 === "0".repeat(64) ? "1".repeat(64) : "0".repeat(64)
          ),
          mutate("scalar_utf8", String(BigInt(observed[0]!.scalar_utf8) - 1n)),
          mutate("cursor_at", observed[0]!.cursor_at === null ? "different" : null),
          mutate("raw_created_at", "2000-01-01 00:00:00+00")
        ];
        for (const bound of falseBounds) {
          expect((await guarded(selection, bound, fault, mode)).rows).toEqual([
            { fits: false, item: null, cursor_at: null, cursor_id: null }
          ]);
          falseControls++;
        }
        await expect(guarded(selection, observed, fault, mode)).rejects.toMatchObject({
          code: "22012"
        });
        trueControls++;
      }
    expect(falseControls).toBe(48);
    expect(trueControls).toBe(8);
    const authority: unknown[] = [];
    for (const [label, context] of [
      ["wrong-organization", { ...actor.context, organizationId: testId(286_098) }],
      ["empty-board-context", { ...actor.context, boardIds: [] }]
    ] as const) {
      for (const kind of kinds) {
        const old = await original(input(kind), context);
        if (label === "wrong-organization") expect(old).toEqual([]);
        // Own validation-attempt visibility is compared to the original query;
        // empty-board context alone is not assumed to alter that contract.
        const actual = await read(input(kind), { context });
        expect(strip(actual.rows)).toEqual(old);
        authority.push({ label, kind, originalRows: old.length, admittedRows: actual.rows.length });
      }
    }
    expect(manager.accounting.usedUnits).toBe(0);
    process.stdout.write(
      JSON.stringify({
        kind: "document-metadata-postgres-observations",
        catalog,
        attempts: fixture.attempts,
        normalAttemptCount: fixture.attempts.length,
        falseControls,
        trueControls,
        parity,
        authority,
        reads: reports,
        finalUnits: manager.accounting.usedUnits,
        limitations: [
          "synthetic secretary fixture",
          "modelled terminal/collector markers",
          "direct SQL falsified private-roster controls",
          "no canonical body/resource fetch",
          "native/public signed cursors verified separately",
          "no database workspace or broad workflow qualification"
        ]
      }) + "\n"
    );
  });
}, 120000);
