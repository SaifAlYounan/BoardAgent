import { expect, it } from "vitest";
import type { PoolClient } from "pg";
import {
  canonicalJson,
  sha256Hex,
  TOOL_INPUT_SCHEMA_VERSION
} from "../../lib/contracts/src/index.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import type { SurfacePrincipal } from "../../artifacts/server/src/ports.js";
import {
  MEETING_LIST_PREFLIGHT_SQL,
  MEETING_LIST_CONTENT_SQL,
  loadAdmittedMeetingList,
  meetingListProjectionCost,
  meetingListProjectionPlan,
  type MeetingListInput,
  type MeetingListKind,
  type MeetingListMetadata
} from "../../artifacts/server/src/meeting-list-projection.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { testId } from "../helpers/authorized-actor.js";
import { seedMeetingToolProjectionFixture } from "../helpers/meeting-tool-projection-fixture.js";
import {
  ORIGINAL_MEETING_LIST_SQL,
  originalMeetingListParameters,
  originalMeetingMetadata,
  originalMeetingRows,
  readOriginalMeetingListMeasurement,
  assertOriginalMeetingFlatScalars,
  originalMeetingAllocationBound,
  type OriginalMeetingPageRow
} from "../helpers/meeting-lists-postgres-oracle.js";
import {
  meetingListCursorKey,
  meetingListTools,
  originalMeetingListEnvelope,
  signMeetingListTailCursor
} from "../helpers/meeting-lists-page-oracle.js";

const identity = (sql: string) => sql;
const copy = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;
const strip = (rows: readonly OriginalMeetingPageRow[]) =>
  rows.map(({ item, cursor_at, cursor_id }) => ({ item, cursor_at, cursor_id }));
const replaceOnce = (sql: string, from: string, to: string) => {
  expect(sql.split(from)).toHaveLength(2);
  return sql.replace(from, to);
};
const graph = (roots: readonly unknown[]) => {
  const pending = [...roots],
    seen = new Set<object>();
  let properties = 0n,
    containers = 0n;
  while (pending.length) {
    const value = pending.pop();
    if (value === null || typeof value !== "object" || seen.has(value)) continue;
    seen.add(value);
    containers++;
    if (!Array.isArray(value)) properties += BigInt(Object.keys(value).length);
    pending.push(...Object.values(value));
  }
  return { properties, containers };
};
const close = (owner: ReturnType<ResponseAllocationManager["openRequest"]>) => {
  try {
    owner.nativeTerminal();
  } finally {
    owner.collectorSettled();
  }
};

it("admits original meeting list frontiers with normal RSVP/transcript transitions and guarded PostgreSQL construction", async () => {
  await withMigratedDatabase("meeting_lists_projection", async (pool) => {
    const fixture = await seedMeetingToolProjectionFixture(pool),
      actor = fixture.secretary;
    expect(fixture.commands).toHaveLength(6);
    const manager = new ResponseAllocationManager(),
      reports: unknown[] = [],
      hashes: string[] = [],
      pageReports: unknown[] = [];
    const transaction = <T>(body: (client: PoolClient) => Promise<T>, context = actor.context) =>
      withRequestTransaction(pool, context, body, { assumeRole: "boardagent_server" });
    const input = (kind: MeetingListKind, limit = 100): MeetingListInput => ({
      kind,
      selectorId: kind === "transcripts" ? fixture.meetingId : actor.boardId,
      memberId: kind === "transcripts" ? null : actor.memberId,
      cursorAt: null,
      cursorId: null,
      limit
    });
    const original = (selection: MeetingListInput, transform = identity, context = actor.context) =>
      transaction(
        async (client) =>
          (
            await client.query<OriginalMeetingPageRow>(
              transform(ORIGINAL_MEETING_LIST_SQL[selection.kind]),
              [...originalMeetingListParameters(selection)]
            )
          ).rows,
        context
      );
    const metadata = (selection: MeetingListInput) =>
      transaction(
        async (client) =>
          (
            await client.query<MeetingListMetadata>(MEETING_LIST_PREFLIGHT_SQL[selection.kind], [
              ...originalMeetingListParameters(selection)
            ])
          ).rows
      );
    const catalog = (
      await pool.query(`select c.relname::text,c.relrowsecurity,c.relforcerowsecurity,
      exists(select 1 from pg_index i join pg_attribute a on a.attrelid=c.oid and a.attnum=i.indkey[0]
        where i.indrelid=c.oid and i.indisprimary and i.indisvalid and i.indnkeyatts=1 and a.attname='id') as id_pk,
      exists(select 1 from pg_index i join pg_attribute a on a.attrelid=c.oid and a.attnum=i.indkey[0]
        where i.indrelid=c.oid and i.indisunique and i.indisvalid and i.indisready and i.indnkeyatts=1
          and i.indpred is null and i.indexprs is null and a.attname='meeting_id' and a.attnotnull) as one_transcript,
      exists(select 1 from pg_index i
        join pg_attribute a on a.attrelid=c.oid and a.attnum=i.indkey[0]
        join pg_attribute b on b.attrelid=c.oid and b.attnum=i.indkey[1]
        where i.indrelid=c.oid and i.indisunique and i.indisvalid and i.indisready and i.indnkeyatts=2
          and i.indexprs is null and pg_get_expr(i.indpred,c.oid)='is_current'
          and a.attname='meeting_id' and a.attnotnull and b.attname='member_id' and b.attnotnull) as one_current_rsvp
      from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='public'
        and c.relname in ('meetings','meeting_rsvps','meeting_transcripts','meeting_transcript_versions') order by c.relname`)
    ).rows;
    expect(catalog).toHaveLength(4);
    for (const row of catalog)
      expect(row).toMatchObject({ relrowsecurity: true, relforcerowsecurity: true, id_pk: true });
    expect(catalog.find((row) => row.relname === "meeting_transcripts")?.one_transcript).toBe(true);
    expect(catalog.find((row) => row.relname === "meeting_rsvps")?.one_current_rsvp).toBe(true);
    expect(
      await transaction(async (client) => (await client.query("select current_user")).rows)
    ).toEqual([{ current_user: "boardagent_server" }]);

    async function read(
      selection: MeetingListInput,
      options: {
        afterMetadata?: () => Promise<unknown>;
        contentTransform?: (sql: string) => string;
        context?: typeof actor.context;
      } = {}
    ) {
      const owner = manager.openRequest(new AbortController().signal),
        baseline = manager.accounting.usedUnits;
      let preflights = 0,
        contents = 0,
        held = baseline,
        failure: unknown,
        rows: readonly OriginalMeetingPageRow[] | undefined;
      try {
        rows = await owner.produce(() =>
          transaction(async (client) => {
            const proxy = Object.create(client) as PoolClient;
            proxy.query = (async (sql: string, values?: unknown[]) => {
              if (sql === MEETING_LIST_PREFLIGHT_SQL[selection.kind]) {
                preflights++;
                const result = await client.query(sql, values);
                await options.afterMetadata?.();
                return result;
              }
              if (sql === MEETING_LIST_CONTENT_SQL[selection.kind]) {
                contents++;
                return client.query((options.contentTransform ?? identity)(sql), values);
              }
              throw new Error("unexpected flat-list statement");
            }) as PoolClient["query"];
            return loadAdmittedMeetingList(proxy, selection) as Promise<
              readonly OriginalMeetingPageRow[]
            >;
          }, options.context ?? actor.context)
        );
      } catch (error) {
        failure = error;
      } finally {
        held = manager.accounting.usedUnits;
        close(owner);
      }
      reports.push({
        kind: selection.kind,
        limit: selection.limit,
        preflights,
        contents,
        held,
        finalUnits: manager.accounting.usedUnits,
        failed: failure !== undefined
      });
      try {
        expect(preflights).toBe(1);
        expect(manager.accounting.usedUnits).toBe(baseline);
      } catch (error) {
        if (failure !== undefined)
          throw new AggregateError([failure, error], "meeting list SQL/accounting failed");
        throw error;
      }
      if (failure !== undefined) throw failure;
      return { rows: rows!, held, contents };
    }
    async function verify(selection: MeetingListInput) {
      const old = await original(selection),
        observed = await metadata(selection);
      const measured = await transaction((client) =>
        readOriginalMeetingListMeasurement(client, selection)
      );
      expect(originalMeetingRows(measured)).toEqual(old);
      assertOriginalMeetingFlatScalars(selection.kind, measured);
      expect(observed).toEqual(originalMeetingMetadata(measured));
      const bound = originalMeetingAllocationBound(selection.kind, measured),
        cost = meetingListProjectionCost(selection.kind, {
          row_count: String(measured.length),
          scalar_utf8: String(bound.scalarUtf8)
        });
      expect(cost).toEqual({
        jsonUpperBytes: String(bound.jsonUpperBytes),
        propertyCount: String(bound.propertyCount),
        objectOrArrayCount: String(bound.objectOrArrayCount)
      });
      const plan = meetingListProjectionPlan(selection, observed);
      expect(plan.units).toBe(bound.units);
      const actual = await read(selection);
      expect(strip(actual.rows)).toEqual(old);
      expect(actual.held).toBe(bound.units);
      expect(actual.contents).toBe(1);
      expect(BigInt(Buffer.byteLength(JSON.stringify(actual.rows)))).toBeLessThanOrEqual(
        bound.jsonUpperBytes
      );
      const retainedGraph = graph([actual.rows]);
      expect(retainedGraph.properties).toBeLessThanOrEqual(bound.propertyCount);
      expect(retainedGraph.containers).toBeLessThanOrEqual(bound.objectOrArrayCount);
      const hash = sha256Hex(canonicalJson(strip(actual.rows)));
      hashes.push(hash);
      return { old, observed, bound, hash };
    }
    const initialMeetings = await verify(input("meetings"));
    expect(initialMeetings.old).toHaveLength(2);
    expect(initialMeetings.old.map((row) => row.item.my_rsvp)).toEqual([null, null]);
    expect((await verify(input("transcripts"))).old).toEqual([]);
    const firstTranscript = await fixture.createTranscript();
    expect(fixture.commands).toHaveLength(7);
    const visibleTranscript = await verify(input("transcripts"));
    expect(visibleTranscript.old).toHaveLength(1);
    expect(visibleTranscript.old[0]?.item).toMatchObject({
      transcript_id: firstTranscript.transcriptId,
      current_version_id: firstTranscript.versionId,
      version: 1,
      sha256: firstTranscript.sha256
    });
    const absentTranscript = { ...input("transcripts"), selectorId: fixture.emptyMeetingId };
    expect((await verify(absentTranscript)).old).toEqual([]);
    await expect(
      read(input("meetings"), { afterMetadata: fixture.rsvpAttending })
    ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    const attending = await verify(input("meetings"));
    expect(attending.old.find((row) => row.cursor_id === fixture.meetingId)?.item.my_rsvp).toBe(
      "attending"
    );
    await expect(
      read(input("meetings"), { afterMetadata: fixture.rsvpTentative })
    ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    const tentative = await verify(input("meetings"));
    expect(tentative.old.find((row) => row.cursor_id === fixture.meetingId)?.item.my_rsvp).toBe(
      "tentative"
    );
    // This normal transition has equal-length visible RSVP strings. Assert the
    // complete scalar total rather than assuming unchanged parent row versions.
    expect(tentative.bound.scalarUtf8).toBe(attending.bound.scalarUtf8);
    await expect(
      read(input("transcripts"), { afterMetadata: fixture.replaceTranscript })
    ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    const replaced = await verify(input("transcripts"));
    expect(replaced.old).toHaveLength(1);
    expect(replaced.old[0]?.item).toMatchObject({
      transcript_id: firstTranscript.transcriptId,
      version: 2
    });
    expect(replaced.old[0]?.item.current_version_id).not.toBe(firstTranscript.versionId);
    expect(replaced.old[0]?.item.sha256).not.toBe(firstTranscript.sha256);

    // Actual public repository, constrained synthetic authenticated-session row
    // and actual resolver-derived principal. No browser/OAuth login is claimed.
    const sessionId = testId(288001);
    await pool.query(
      `insert into auth_sessions(id,organization_id,opaque_session_sha256,member_id,client_id,state,exact_origin,expires_at,last_authenticated_at)
      values($1,$2,$3,$4,$5,'authenticated',$6,transaction_timestamp()+interval '10 minutes',transaction_timestamp())`,
      [
        sessionId,
        actor.organizationId,
        Buffer.alloc(32, 0x93),
        actor.memberId,
        actor.clientId,
        "https://boardagent.test"
      ]
    );
    expect(
      (
        await pool.query(
          "update access_token_records set session_id=$2 where id=$1 and session_id is null returning id",
          [actor.accessTokenRecordId, sessionId]
        )
      ).rowCount
    ).toBe(1);
    const live = await transaction(async (client) => {
      const result = await client.query<{
        token_record_id: string;
        organization_id: string;
        member_id: string;
        internal_client_id: string;
        protocol_client_id: string;
        resource_uri: string;
        scope_set: string[];
        roles: string[];
        board_ids: string[];
      }>(
        "select token_record_id,organization_id,member_id,internal_client_id,protocol_client_id,resource_uri,scope_set,roles,board_ids from boardagent_resolve_access_token($1)",
        [actor.tokenJti]
      );
      expect(result.rows).toHaveLength(1);
      return result.rows[0]!;
    });
    expect(live).toMatchObject({
      token_record_id: actor.accessTokenRecordId,
      organization_id: actor.organizationId,
      member_id: actor.memberId,
      internal_client_id: actor.clientId
    });
    expect(live.resource_uri).toBe("https://boardagent.test/mcp");
    expect([...live.scope_set].sort()).toEqual(
      [
        "secretariat:admin",
        "governance:read",
        "meeting:act",
        "documents:read",
        "documents:contribute"
      ].sort()
    );
    expect(live.board_ids).toEqual([actor.boardId]);
    const principal: SurfacePrincipal = {
      organizationId: live.organization_id,
      memberId: live.member_id,
      clientId: live.internal_client_id,
      protocolClientId: live.protocol_client_id,
      serviceOrigin: "https://boardagent.test",
      accessTokenRecordId: live.token_record_id,
      tokenJti: actor.tokenJti,
      keyId: "test-oauth",
      scopes: live.scope_set,
      roles: live.roles,
      boardIds: live.board_ids
    };
    const repository = new PgSurfaceReadRepository(pool, {
      cursorKey: meetingListCursorKey,
      transaction: { assumeRole: "boardagent_server" }
    });
    async function publicPage(selection: MeetingListInput, cursor: string | null) {
      const old = await original(selection),
        measured = await transaction((client) =>
          readOriginalMeetingListMeasurement(client, selection)
        );
      expect(originalMeetingRows(measured)).toEqual(old);
      const bound = originalMeetingAllocationBound(selection.kind, measured);
      const owner = manager.openRequest(new AbortController().signal),
        before = Math.floor(Date.now() / 1000);
      let actual,
        held = 0;
      try {
        actual = await owner.produce(() =>
          repository.executeRead(principal, meetingListTools[selection.kind], {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            [selection.kind === "transcripts" ? "meeting_id" : "board_id"]: selection.selectorId,
            limit: selection.limit,
            cursor
          })
        );
        held = manager.accounting.usedUnits;
      } finally {
        close(owner);
      }
      const after = Math.floor(Date.now() / 1000),
        data = actual.data as Readonly<Record<string, unknown>>;
      const expected = originalMeetingListEnvelope(
        selection.kind,
        selection.selectorId,
        old,
        selection.limit,
        principal,
        data.next_cursor,
        before,
        after
      );
      expect(actual).toEqual(expected);
      expect(held).toBe(1);
      expect(manager.accounting.usedUnits).toBe(0);
      const text = JSON.stringify(actual),
        wire = { content: [{ type: "text", text }], structuredContent: actual },
        wireGraph = graph([wire]);
      expect(wireGraph.properties).toBeLessThanOrEqual(bound.propertyCount);
      expect(wireGraph.containers).toBeLessThanOrEqual(bound.objectOrArrayCount);
      expect(BigInt(Buffer.byteLength(JSON.stringify(wire)))).toBeLessThanOrEqual(bound.wireBytes);
      pageReports.push({
        kind: selection.kind,
        items: (data.items as unknown[]).length,
        emittedCursor: typeof data.next_cursor === "string",
        hash: sha256Hex(canonicalJson(actual)),
        textBytes: Buffer.byteLength(text),
        wireBytes: Buffer.byteLength(JSON.stringify(wire)),
        held
      });
      return { actual, old, data };
    }
    await publicPage(input("meetings"), null);
    const firstPage = await publicPage(input("meetings", 1), null);
    expect(typeof firstPage.data.next_cursor).toBe("string");
    const firstAnchor = firstPage.old[0]!;
    const secondSelection = {
      ...input("meetings", 1),
      cursorAt: firstAnchor.cursor_at,
      cursorId: firstAnchor.cursor_id
    };
    const secondPage = await publicPage(secondSelection, firstPage.data.next_cursor as string);
    expect(secondPage.data.next_cursor).toBeNull();
    const last = secondPage.old[0]!;
    expect(last.cursor_id).not.toBe(firstAnchor.cursor_id);
    const tail = signMeetingListTailCursor(
      "meetings",
      actor.boardId,
      last,
      principal,
      Math.floor(Date.now() / 1000) + 86400
    );
    const emptyPage = await publicPage(
      { ...input("meetings", 1), cursorAt: last.cursor_at, cursorId: last.cursor_id },
      tail
    );
    expect(emptyPage.old).toEqual([]);
    await publicPage(input("transcripts"), null);
    await publicPage(absentTranscript, null);

    // A normal third meeting is committed after a two-row limit+1 frontier.
    const beforeThird = await metadata(input("meetings", 1));
    expect(beforeThird).toHaveLength(2);
    let thirdId = "";
    await expect(
      read(input("meetings", 1), {
        afterMetadata: async () => {
          thirdId = await fixture.createThirdMeeting();
        }
      })
    ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    const afterThird = await verify(input("meetings", 1));
    expect(afterThird.old).toHaveLength(2);
    expect(afterThird.old.some((row) => row.cursor_id === thirdId)).toBe(true);
    expect(beforeThird.some((row) => row.id === thirdId)).toBe(false);
    const fullMeetings = await verify(input("meetings"));
    expect(fullMeetings.old).toHaveLength(3);
    expect(fixture.commands).toHaveLength(11);

    for (const kind of ["meetings", "transcripts"] as const) {
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
        expect(manager.accounting.usedUnits).toBe(2048);
        await expect(read(input(kind))).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
        expect(reports.at(-1)).toMatchObject({ preflights: 1, contents: 0, held: 2048 });
      } finally {
        close(occupied);
      }
      expect(manager.accounting.usedUnits).toBe(0);
    }
    async function guarded(
      selection: MeetingListInput,
      observed: readonly MeetingListMetadata[],
      sql: string,
      name: string,
      mode: "force_custom_plan" | "force_generic_plan"
    ) {
      const owner = manager.openRequest(new AbortController().signal);
      try {
        return await owner.produce(async () => {
          owner.reserve(meetingListProjectionPlan(selection, await metadata(selection)));
          return transaction(async (client) => {
            await client.query(`set local plan_cache_mode=${mode}`);
            return client.query({
              text: sql,
              values: [...originalMeetingListParameters(selection), JSON.stringify(observed)],
              name
            });
          });
        });
      } finally {
        close(owner);
      }
    }
    let falseControls = 0,
      trueControls = 0;
    for (const kind of ["meetings", "transcripts"] as const)
      for (const mode of ["force_custom_plan", "force_generic_plan"] as const) {
        const selection = input(kind),
          observed = await metadata(selection);
        expect(observed.length).toBeGreaterThan(0);
        const needle = "jsonb_build_object(",
          fault = replaceOnce(
            MEETING_LIST_CONTENT_SQL[kind],
            needle,
            `jsonb_build_object('fault',1/(0*random())) || ${needle}`
          );
        const mutate = (key: keyof MeetingListMetadata, value: string | null) => {
          const next = copy(observed) as Array<Record<keyof MeetingListMetadata, string | null>>;
          next[0]![key] = value;
          return next as unknown as MeetingListMetadata[];
        };
        const falseBounds: readonly (readonly MeetingListMetadata[])[] = [
          [],
          mutate("id", testId(288099)),
          mutate("raw_created_at", "2000-01-01 00:00:00+00"),
          mutate("cursor_at", null),
          mutate(
            "observation_sha256",
            observed[0]!.observation_sha256 === "0".repeat(64) ? "1".repeat(64) : "0".repeat(64)
          ),
          mutate("scalar_utf8", String(BigInt(observed[0]!.scalar_utf8) - 1n))
        ];
        for (const bad of falseBounds) {
          const result = await guarded(selection, bad, fault, `mf_${kind}_${mode}`, mode);
          expect(result.rows).toEqual([
            { fits: false, item: null, cursor_at: null, cursor_id: null }
          ]);
          falseControls++;
        }
        if (kind === "meetings") {
          expect(observed).toHaveLength(3);
          expect(
            (await guarded(selection, observed.slice(1), fault, `mf_${kind}_${mode}`, mode)).rows
          ).toEqual([{ fits: false, item: null, cursor_at: null, cursor_id: null }]);
          falseControls++;
        }
        await expect(
          guarded(selection, observed, fault, `mf_${kind}_${mode}`, mode)
        ).rejects.toMatchObject({ code: "22012" });
        trueControls++;
      }
    expect(falseControls).toBe(26);
    expect(trueControls).toBe(4);
    expect(manager.accounting.usedUnits).toBe(0);

    // Query-only selective visibility and raw-time variants over authorized rows.
    // They are not claims of a reachable per-row RLS or immutable storage update.
    const hideId = fullMeetings.old[0]!.cursor_id;
    const hideKnown = (sql: string) =>
      replaceOnce(
        sql,
        "where meeting.board_id=$1",
        `where meeting.board_id=$1 and meeting.id<>'${hideId}'::uuid`
      );
    const subset = await read(input("meetings"), { contentTransform: hideKnown });
    expect(strip(subset.rows)).toEqual(await original(input("meetings"), hideKnown));
    expect(subset.rows).toHaveLength(2);
    const hideAll = (sql: string) =>
      replaceOnce(sql, "where meeting.board_id=$1", "where meeting.board_id=$1 and false");
    const empty = await read(input("meetings"), { contentTransform: hideAll });
    expect(empty.rows).toEqual(await original(input("meetings"), hideAll));
    expect(empty.rows).toEqual([]);
    const rawTimeOnly = (sql: string) =>
      replaceOnce(
        sql,
        "meeting.created_at::text as raw_created_at",
        "(meeting.created_at+interval '1 microsecond')::text as raw_created_at"
      );
    await expect(read(input("meetings"), { contentTransform: rawTimeOnly })).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );

    for (const context of [
      { ...actor.context, organizationId: testId(288097) },
      { ...actor.context, boardIds: [] }
    ])
      for (const kind of ["meetings", "transcripts"] as const) {
        const old = await original(input(kind), identity, context);
        expect(old).toEqual([]);
        const result = await read(input(kind), { context });
        expect(strip(result.rows)).toEqual(old);
      }
    // A normal revocation is last: no subsequent fixture/public action may rely
    // on that principal. Fresh direct-query emptiness is not public-call authority.
    await read(input("meetings"), {
      afterMetadata: async () => {
        expect(
          (
            await pool.query(
              "update access_token_records set revoked_at=transaction_timestamp() where id=$1 and revoked_at is null returning id",
              [actor.accessTokenRecordId]
            )
          ).rowCount
        ).toBe(1);
      }
    }).then(async (result) => {
      expect(result.rows).toEqual([]);
      expect(await original(input("meetings"))).toEqual([]);
    });
    expect(await original(input("transcripts"))).toEqual([]);
    expect((await read(input("transcripts"))).rows).toEqual([]);
    expect(manager.accounting.usedUnits).toBe(0);
    process.stdout.write(
      JSON.stringify({
        kind: "meeting-lists-postgres-observations",
        catalog,
        commands: fixture.commands,
        normalCommandCount: fixture.commands.length,
        falseControls,
        trueControls,
        contentHashes: hashes,
        pages: pageReports,
        readReports: reports,
        finalUnits: manager.accounting.usedUnits,
        limitations: [
          "synthetic secretary/session",
          "one transcript per meeting",
          "query-only known-subset/raw-time variants",
          "synthetic signed tail cursor",
          "direct owner markers modeled",
          "no RSS or broad workflow qualification"
        ]
      }) + "\n"
    );
  });
}, 60000);
