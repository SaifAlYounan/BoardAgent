import { createHash } from "node:crypto";
import type { PoolClient } from "pg";
import type { JsonValue } from "@boardagent/contracts";
import {
  currentResponseAllocationOwner,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "./response-allocation.js";
import { inspectProposalPayload } from "./proposal-payload-inspection.js";

type ListKind = "secretariat" | "proposals";
export interface CommunicationsListInput {
  readonly kind: ListKind;
  readonly boardId: string | null;
  readonly memberId: string;
  readonly state: string | null;
  readonly cursorAt: string | null;
  readonly cursorId: string | null;
  readonly limit: number;
}
export interface CommunicationsPageRow {
  readonly item: JsonValue;
  readonly cursor_at: string;
  readonly cursor_id: string;
}
export interface CommunicationsListMetadata {
  id: string;
  row_version: string;
  cursor_at: string;
  canonical_bytes: string;
  sha256: string | null;
  supported: boolean;
  json_upper: string;
  property_count: string;
  object_count: string;
}
interface GatedRow {
  fits: boolean;
  cursor_id: string | null;
  cursor_at: string | null;
}
interface ContentRow extends GatedRow {
  item: JsonValue;
}
interface InspectionRow extends GatedRow {
  raw_payload: Buffer | null;
}

const utc = (expression: string) =>
  `to_char(${expression} at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;
const bytes = (expression: string) => `coalesce(octet_length(${expression}),0)::numeric`;
const sumBytes = (expressions: readonly string[]) => expressions.map(bytes).join("+");
const fixedObject = (keys: readonly string[]) =>
  2 + keys.reduce((sum, key) => sum + key.length + 10, 0);

// The allowance includes key quotes, colon/spacing, nullable scalars and delimiters.
// Actual flat strings are additionally charged at six times their UTF-8 length.
const fixed = {
  request: fixedObject([
    "request_id",
    "board_id",
    "requester_member_id",
    "topic",
    "state",
    "current_turn_id",
    "row_version",
    "turns",
    "created_at",
    "closed_at"
  ]),
  turn: fixedObject([
    "turn_id",
    "ordinal",
    "turn_kind",
    "author_member_id",
    "author_role",
    "canonical_text",
    "sha256",
    "resource_references",
    "created_at"
  ]),
  proposal: fixedObject([
    "proposal_id",
    "board_id",
    "proposer_member_id",
    "proposal_type",
    "title",
    "schema_version",
    "payload",
    "payload_sha256",
    "references",
    "state",
    "row_version",
    "disposition",
    "created_at"
  ]),
  disposition: fixedObject([
    "disposition_id",
    "disposition",
    "reason",
    "resulting_draft_id",
    "actor_member_id",
    "created_at"
  ]),
  reference: fixedObject(["uri", "sha256"])
};

// Only fixed source identifiers reach this SQL builder. CASE protects array
// cardinality/expansion, object-key enumeration and scalar string extraction in
// that order. The key subquery observes at most three names; internal JSONB
// detoasting/SRF workspace is not a process-memory guarantee.
function referenceScalars(column: string): string {
  return `(select envelope.valid and coalesce(bool_and(checked.valid),true) as supported,
      count(checked.value)::numeric as item_count,
      coalesce(sum(case when checked.valid then
        octet_length(checked.value->>'uri')::numeric
        +octet_length(checked.value->>'sha256') else 0 end),0) as utf8
    from (select case when jsonb_typeof(${column})='array' then
      jsonb_array_length(${column})<=256 else false end as valid) as envelope
    left join lateral (
      select entry.value,case when jsonb_typeof(entry.value)='object' then
        case when (select count(*) from (
          select jsonb_object_keys(entry.value) limit 3
        ) as bounded_keys)=2 then
          case when jsonb_typeof(entry.value->'uri')='string'
             and jsonb_typeof(entry.value->'sha256')='string'
            then true else false end
          else false end
        else false end as valid
      from jsonb_array_elements(case when envelope.valid then ${column}
        else '[]'::jsonb end) as entry(value)
    ) as checked on true group by envelope.valid)`;
}

function authorized(kind: ListKind): string {
  if (kind === "proposals") {
    return `input_member as (select $2::uuid as member_id), authorized as materialized (
      select proposal.id,proposal.row_version,proposal.created_at
        from proposals as proposal where proposal.board_id=$1
         and ($3::text is null or proposal.state=$3)
         and ($4::timestamptz is null or
              (proposal.created_at,proposal.id)<($4::timestamptz,$5::uuid))
       order by proposal.created_at desc,proposal.id desc limit $6
    )`;
  }
  return `authorized as materialized (
    select request.id,request.row_version,request.created_at
      from secretariat_requests as request
     where ($1::uuid is null or request.board_id=$1)
       and (request.requester_member_id=$2 or exists (
         select 1 from board_memberships as membership
          where membership.board_id=request.board_id and membership.member_id=$2
            and membership.state='active' and membership.is_secretary
       ) or exists (
         select 1 from organization_role_assignments as role_assignment
          where role_assignment.organization_id=request.organization_id
            and role_assignment.member_id=$2 and role_assignment.role in ('secretariat','admin')
            and role_assignment.active_from<=transaction_timestamp()
            and (role_assignment.active_until is null
                 or role_assignment.active_until>transaction_timestamp())
       ))
       and ($3::text is null or request.state=$3)
       and ($4::timestamptz is null or
            (request.created_at,request.id)<($4::timestamptz,$5::uuid))
     order by request.created_at desc,request.id desc limit $6
  )`;
}

function metadata(kind: ListKind): string {
  if (kind === "secretariat") {
    const rootUtf8 = sumBytes([
      "request.id::text",
      "request.board_id::text",
      "request.requester_member_id::text",
      "request.topic",
      "request.state",
      "request.current_turn_id::text",
      "request.row_version::text",
      utc("request.created_at"),
      utc("request.closed_at")
    ]);
    const turnUtf8 = sumBytes([
      "turn.id::text",
      "turn.ordinal::text",
      "turn.turn_kind",
      "turn.author_member_id::text",
      "turn.author_role",
      "turn.canonical_text",
      "encode(turn.text_sha256,'hex')",
      utc("turn.created_at")
    ]);
    return `${authorized(kind)}, metadata as materialized (
      select root.id,root.row_version,root.created_at,0::numeric as canonical_bytes,
        null::text as sha256,turns.supported,
        (${fixed.request}+6*(${rootUtf8})+2
          +turns.item_count*${fixed.turn + 2}+6*turns.utf8
          +turns.item_count*2+turns.reference_count*${fixed.reference + 2}
          +6*turns.reference_utf8) as json_upper,
        (10+9*turns.item_count+2*turns.reference_count) as property_count,
        (2+2*turns.item_count+turns.reference_count) as object_count
      from authorized as root join secretariat_requests as request on request.id=root.id
      cross join lateral (
        select count(*)::numeric as item_count,coalesce(sum(${turnUtf8}),0) as utf8,
          coalesce(bool_and(refs.supported),true) as supported,
          coalesce(sum(refs.item_count),0) as reference_count,
          coalesce(sum(refs.utf8),0) as reference_utf8
        from secretariat_request_turns as turn
        cross join lateral ${referenceScalars("turn.resource_references")} as refs
        where turn.request_id=request.id
      ) as turns
    )`;
  }
  const rootUtf8 = sumBytes([
    "proposal.id::text",
    "proposal.board_id::text",
    "proposal.proposer_member_id::text",
    "proposal.proposal_type",
    "proposal.title",
    "proposal.schema_version",
    "encode(proposal.payload_sha256,'hex')",
    "proposal.state",
    "proposal.row_version::text",
    utc("proposal.created_at")
  ]);
  const dispositionUtf8 = sumBytes([
    "selected.id::text",
    "selected.disposition",
    "selected.reason",
    "selected.resulting_draft_id::text",
    "selected.actor_member_id::text",
    utc("selected.created_at")
  ]);
  return `${authorized(kind)}, metadata as materialized (
    select root.id,root.row_version,root.created_at,
      octet_length(proposal.canonical_payload)::numeric as canonical_bytes,
      encode(proposal.payload_sha256,'hex') as sha256,refs.supported,
      (${fixed.proposal}+6*(${rootUtf8})+2
        +refs.item_count*${fixed.reference + 2}+6*refs.utf8
        +disposition.item_count*${fixed.disposition}+6*disposition.utf8) as json_upper,
      (13+2*refs.item_count+6*disposition.item_count) as property_count,
      (2+refs.item_count+disposition.item_count) as object_count
    from authorized as root join proposals as proposal on proposal.id=root.id
    cross join lateral ${referenceScalars("proposal.resource_references")} as refs
    cross join lateral (
      select count(*)::numeric as item_count,coalesce(sum(${dispositionUtf8}),0) as utf8
      from (select disposition.id,disposition.disposition,disposition.reason,
          disposition.resulting_draft_id,disposition.actor_member_id,disposition.created_at
        from proposal_dispositions as disposition where disposition.proposal_id=proposal.id
        order by disposition.created_at desc limit 1) as selected
    ) as disposition
  )`;
}

const scalarColumns = `id::text,row_version::text,${utc("created_at")} as cursor_at,
  canonical_bytes::text,sha256,supported,json_upper::text,
  property_count::text,object_count::text`;

export const COMMUNICATIONS_PREFLIGHT_SQL = {
  secretariat: `with ${metadata("secretariat")} select ${scalarColumns}
    from metadata order by created_at desc,id desc`,
  proposals: `with ${metadata("proposals")} select ${scalarColumns}
    from metadata order by created_at desc,id desc`
};

function gate(kind: ListKind): string {
  return `${metadata(kind)}, expected as materialized (
    select * from jsonb_to_recordset($7::jsonb) as bound(
      id uuid,row_version bigint,canonical_bytes numeric,sha256 text,
      json_upper numeric,property_count numeric,object_count numeric)
  ), matched as materialized (
    select current.*,(bound.id is not null and current.supported
      and current.json_upper<=bound.json_upper
      and current.property_count<=bound.property_count
      and current.object_count<=bound.object_count) as fits
    from metadata as current left join expected as bound
      on bound.id=current.id and bound.row_version=current.row_version
      and bound.canonical_bytes=current.canonical_bytes
      and bound.sha256 is not distinct from current.sha256
  ), global_gate as materialized (
    select coalesce(bool_and(fits),true) as fits from matched
  )`;
}

export const PROPOSAL_INSPECTION_SQL = `with ${gate("proposals")}
  select global_gate.fits,matched.id::text as cursor_id,
    ${utc("matched.created_at")} as cursor_at,
    case when global_gate.fits and matched.id is not null then (
      select proposal.canonical_payload from proposals as proposal
       where proposal.id=matched.id and proposal.row_version=matched.row_version
         and octet_length(proposal.canonical_payload)=matched.canonical_bytes
         and encode(proposal.payload_sha256,'hex')=matched.sha256
    ) else null end as raw_payload
  from global_gate left join matched on true
  order by matched.created_at desc,matched.id desc`;

// These expressions are the original list projections, except that the proposal
// payload is a private null placeholder. Only the inspected graph is spliced into
// that fixed field after the fresh global gate succeeds.
const projection = {
  secretariat: `jsonb_build_object(
         'request_id',request.id,'board_id',request.board_id,
         'requester_member_id',request.requester_member_id,'topic',request.topic,
         'state',request.state,'current_turn_id',request.current_turn_id,
         'row_version',request.row_version::text,
         'turns',coalesce((select jsonb_agg(jsonb_build_object(
            'turn_id',turn.id,'ordinal',turn.ordinal,'turn_kind',turn.turn_kind,
            'author_member_id',turn.author_member_id,'author_role',turn.author_role,
            'canonical_text',turn.canonical_text,'sha256',encode(turn.text_sha256,'hex'),
            'resource_references',turn.resource_references,
            'created_at',to_char(turn.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
          ) order by turn.ordinal) from secretariat_request_turns as turn
           where turn.request_id=request.id),'[]'::jsonb),
         'created_at',to_char(request.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
         'closed_at',case when request.closed_at is null then null else
           to_char(request.closed_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') end
       )`,
  proposals: `jsonb_build_object(
           'proposal_id',proposal.id,'board_id',proposal.board_id,
           'proposer_member_id',proposal.proposer_member_id,
           'proposal_type',proposal.proposal_type,'title',proposal.title,
           'schema_version',proposal.schema_version,
           'payload',null,
           'payload_sha256',encode(proposal.payload_sha256,'hex'),
           'references',proposal.resource_references,'state',proposal.state,
           'row_version',proposal.row_version::text,
           'disposition',(select jsonb_build_object(
             'disposition_id',disposition.id,'disposition',disposition.disposition,
             'reason',disposition.reason,'resulting_draft_id',disposition.resulting_draft_id,
             'actor_member_id',disposition.actor_member_id,
             'created_at',to_char(disposition.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
             from proposal_dispositions as disposition where disposition.proposal_id=proposal.id
             order by disposition.created_at desc limit 1),
           'created_at',to_char(proposal.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
         )`
};

function content(kind: ListKind): string {
  const table = kind === "proposals" ? "proposals as proposal" : "secretariat_requests as request";
  const alias = kind === "proposals" ? "proposal" : "request";
  return `with ${gate(kind)}
    select global_gate.fits,matched.id::text as cursor_id,
      ${utc("matched.created_at")} as cursor_at,
      case when global_gate.fits and matched.id is not null then (
        select ${projection[kind]} from ${table}
        where ${alias}.id=matched.id and ${alias}.row_version=matched.row_version
      ) else null end as item
    from global_gate left join matched on true
    order by matched.created_at desc,matched.id desc`;
}
export const COMMUNICATIONS_CONTENT_SQL = {
  secretariat: content("secretariat"),
  proposals: content("proposals")
};

function integer(value: string): bigint {
  if (typeof value !== "string") throw new TypeError("invalid communications projection scalar");
  if (value.length > 24) throw new ResponseAllocationUnavailable();
  if (!/^(0|[1-9][0-9]*)$/u.test(value))
    throw new TypeError("invalid communications projection scalar");
  return BigInt(value);
}

// Existing executeRead authorization remains the caller's responsibility. The
// caller passes the original cursor/limit and uses unchanged page()/result().
export async function loadAdmittedCommunicationsList(
  client: PoolClient,
  input: CommunicationsListInput
): Promise<readonly CommunicationsPageRow[]> {
  const owner = currentResponseAllocationOwner();
  if (!owner) throw new Error("native response allocation owner is required");
  owner.assertLive();
  if (!Number.isSafeInteger(input.limit) || input.limit < 1 || input.limit > 500)
    throw new TypeError("invalid communications page limit");
  if (input.kind === "proposals" && input.boardId === null)
    throw new TypeError("board_id is required");
  const parameters = [
    input.boardId,
    input.memberId,
    input.state,
    input.cursorAt,
    input.cursorId,
    input.limit + 1
  ];
  const selected = await client.query<CommunicationsListMetadata>(
    COMMUNICATIONS_PREFLIGHT_SQL[input.kind],
    parameters
  );
  owner.assertLive();
  const frontier = selected.rows;
  const byId = new Map(frontier.map((row) => [row.id, row]));
  if (frontier.length > input.limit + 1 || byId.size !== frontier.length)
    throw new TypeError("invalid communications frontier");
  let canonicalBytes = 0n;
  let jsonBytes = 0n;
  let properties = 0n;
  let containers = 0n;
  for (const row of frontier) {
    if (!row.supported) throw new ResponseAllocationUnavailable();
    canonicalBytes += integer(row.canonical_bytes);
    jsonBytes += integer(row.json_upper);
    properties += integer(row.property_count);
    containers += integer(row.object_count);
  }
  if (canonicalBytes > BigInt(Number.MAX_SAFE_INTEGER)) throw new ResponseAllocationUnavailable();
  const expectedJson = JSON.stringify(frontier);
  const digest = createHash("sha256").update(input.kind).update(expectedJson).digest("hex");
  const plan = (j: bigint, p: bigint, o: bigint) =>
    responseAllocationPlan({
      kind: "communications_list",
      representation: "tool",
      sourceId: digest,
      sourceVersion: "1",
      sha256: digest,
      canonicalBytes: Number(canonicalBytes),
      listProjection: {
        jsonUpperBytes: j.toString(),
        propertyCount: p.toString(),
        objectOrArrayCount: o.toString()
      }
    });
  // Refuse already-known oversized metadata before selecting any raw payload.
  const reservation = owner.reserve(plan(jsonBytes, properties, containers));
  const payloads = new Map<string, JsonValue>();
  if (input.kind === "proposals") {
    owner.assertLive();
    const inspected = await client.query<InspectionRow>(PROPOSAL_INSPECTION_SQL, [
      ...parameters,
      expectedJson
    ]);
    owner.assertLive();
    if (inspected.rows.some((row) => !row.fits)) throw new ResponseAllocationUnavailable();
    if (inspected.rows.length > input.limit + 1)
      throw new TypeError("invalid inspection row count");
    for (const row of inspected.rows) {
      if (row.cursor_id === null) continue;
      const expected = byId.get(row.cursor_id);
      if (!expected || row.raw_payload === null || expected.sha256 === null)
        throw new ResponseAllocationUnavailable();
      if (payloads.has(row.cursor_id)) throw new TypeError("duplicate inspected proposal");
      const measured = inspectProposalPayload(row.raw_payload, {
        canonicalBytes: Number(integer(expected.canonical_bytes)),
        sha256: expected.sha256
      });
      payloads.set(row.cursor_id, measured.value);
      jsonBytes += integer(measured.jsonBytesUpper);
      properties += integer(measured.properties);
      containers += integer(measured.containers);
    }
  }
  reservation.increase(plan(jsonBytes, properties, containers));
  owner.assertLive();
  // Visibility can disappear during inspection and return before this statement.
  // Only inspected IDs may pass the final SQL gate; keeping the original frontier
  // here would construct an uninspected row before the later Map.has check.
  const finalExpectedJson =
    input.kind === "proposals"
      ? JSON.stringify(frontier.filter((row) => payloads.has(row.id)))
      : expectedJson;
  const loaded = await client.query<ContentRow>(COMMUNICATIONS_CONTENT_SQL[input.kind], [
    ...parameters,
    finalExpectedJson
  ]);
  owner.assertLive();
  if (loaded.rows.some((row) => !row.fits)) throw new ResponseAllocationUnavailable();
  if (loaded.rows.length > input.limit + 1) throw new TypeError("invalid projection row count");
  const result: CommunicationsPageRow[] = [];
  const seen = new Set<string>();
  for (const row of loaded.rows) {
    if (row.cursor_id === null) continue;
    const expected = byId.get(row.cursor_id);
    if (!expected || seen.has(row.cursor_id)) throw new TypeError("invalid projection frontier");
    seen.add(row.cursor_id);
    if (row.cursor_at === null || row.item === null) throw new ResponseAllocationUnavailable();
    if (input.kind === "proposals") {
      if (!payloads.has(row.cursor_id) || typeof row.item !== "object" || Array.isArray(row.item))
        throw new ResponseAllocationUnavailable();
      const item = row.item as Record<string, JsonValue>;
      if (
        item["proposal_id"] !== row.cursor_id ||
        item["payload"] !== null ||
        item["payload_sha256"] !== expected.sha256 ||
        item["row_version"] !== expected.row_version
      )
        throw new TypeError("invalid proposal projection identity");
      item["payload"] = payloads.get(row.cursor_id)!;
    }
    result.push({ item: row.item, cursor_at: row.cursor_at, cursor_id: row.cursor_id });
  }
  return result;
}
