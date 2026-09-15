import { createHash } from "node:crypto";
import type { PoolClient } from "pg";
import type { JsonValue } from "@boardagent/contracts";
import {
  currentResponseAllocationOwner,
  loadWithResponseAllocation,
  ResponseAllocationUnavailable,
  responseAllocationPlan,
  type ListProjectionScalars,
  type ResponseAllocationPlan
} from "./response-allocation.js";

export interface SubmissionProjectionMetadata {
  readonly submission_id: string;
  readonly board_id: string;
  readonly row_version: string;
  readonly current_version_id: string | null;
  readonly observation_sha256: string;
  readonly version_count: string;
  readonly request_count: string;
  readonly reply_count: string;
  readonly disposition_count: string;
  readonly scalar_utf8: string;
  readonly json_utf8: string;
  readonly json_properties: string;
  readonly json_containers: string;
}
const utc = (value: string) =>
  `to_char(${value} at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;
const utf8 = (value: string) =>
  `coalesce(octet_length(convert_to((${value})::text,'UTF8')),0)::numeric`;
const hash = (value: string) => `encode(sha256(convert_to((${value})::text,'UTF8')),'hex')`;
const sum = (values: readonly string[]) => values.map(utf8).join("+");
const rowHash = (values: readonly string[]) => hash(`jsonb_build_array(${values.join(",")})`);
const orderedHash = (value: string, order: string) =>
  hash(`coalesce(string_agg(${value},'' order by ${order}),'')`);

// Verbatim original point/list read predicate. No write helper or new authority.
export const MANAGEMENT_SUBMISSION_READ_ACCESS = `(
      $2::uuid=any(thread.management_owner_ids)
      or thread.assigned_secretary_id=$2
      or exists (
        select 1 from board_memberships as secretary_membership
         where secretary_membership.board_id=thread.board_id
           and secretary_membership.member_id=$2
           and secretary_membership.state='active'
           and secretary_membership.active_from<=transaction_timestamp()
           and (secretary_membership.active_until is null
                or secretary_membership.active_until>transaction_timestamp())
           and secretary_membership.is_secretary
      )
      or exists (
        select 1 from organization_role_assignments as role_assignment
         where role_assignment.organization_id=thread.organization_id
           and role_assignment.member_id=$2
           and role_assignment.role in ('secretariat','admin')
           and role_assignment.active_from<=transaction_timestamp()
           and (role_assignment.active_until is null
                or role_assignment.active_until>transaction_timestamp())
      )
    )`;
const rootFlat = [
  "root.id",
  "root.board_id",
  "root.assigned_secretary_id",
  "root.state",
  "root.current_version_id",
  "root.row_version::text",
  utc("root.queue_entered_at"),
  "root.created_by",
  utc("root.created_at")
];
const versionFlat = [
  "version_row.id",
  "version_row.version",
  "version_row.schema_version",
  "encode(version_row.payload_sha256,'hex')",
  "version_row.author_member_id",
  "version_row.change_reason",
  "version_row.supersedes_id",
  utc("version_row.created_at")
];
const requestFlat = [
  "request.id",
  "request.submission_version_id",
  "request.secretary_member_id",
  "request.request_text",
  "encode(request.request_sha256,'hex')",
  utc("request.created_at")
];
const replyFlat = [
  "reply.id",
  "reply.submission_version_id",
  "reply.management_author_id",
  "reply.canonical_reply",
  "encode(reply.reply_sha256,'hex')",
  utc("reply.created_at")
];
const dispositionFlat = [
  "disposition.id",
  "disposition.submission_version_id",
  "disposition.disposition",
  "disposition.secretary_member_id",
  "disposition.reason",
  "disposition.resulting_draft_id",
  utc("disposition.created_at")
];
const privateVersion = versionFlat.map((value) =>
  value === "version_row.change_reason" ? hash(value) : value
);
const privateRequest = requestFlat.map((value) =>
  value === "request.request_text" ? hash(value) : value
);
const privateReply = replyFlat.map((value) =>
  value === "reply.canonical_reply" ? hash(value) : value
);
const privateDisposition = dispositionFlat.map((value) =>
  value === "disposition.reason" ? hash(value) : value
);

// Selected child relations mirror independent original subqueries. In particular
// requests/dispositions do not acquire a version join, and replies are selected
// under visible requests. No unreturned canonical_payload bytea is selected.
const measured = `with recursive selected_roots as materialized (
  select thread.id,thread.board_id,thread.management_owner_ids,thread.assigned_secretary_id,
    thread.state,thread.current_version_id,thread.row_version,thread.queue_entered_at,
    thread.created_by,thread.created_at
  from management_submission_threads as thread where thread.id=$1 and ${MANAGEMENT_SUBMISSION_READ_ACCESS}
), selected_versions as materialized (
  select version_row.id,version_row.thread_id,version_row.version,version_row.schema_version,
    version_row.document_references,version_row.payload_sha256,version_row.author_member_id,
    version_row.change_reason,version_row.supersedes_id,version_row.created_at
  from management_submission_versions as version_row
  join selected_roots as root on root.id=version_row.thread_id
), selected_requests as materialized (
  select request.id,request.thread_id,request.submission_version_id,request.secretary_member_id,
    request.request_text,request.request_sha256,request.created_at
  from management_revision_requests as request join selected_roots as root on root.id=request.thread_id
), selected_replies as materialized (
  select reply.id,reply.request_id,reply.submission_version_id,reply.management_author_id,
    reply.canonical_reply,reply.reply_sha256,reply.created_at
  from management_revision_replies as reply join selected_requests as request on request.id=reply.request_id
), selected_dispositions as materialized (
  select disposition.id,disposition.thread_id,disposition.submission_version_id,disposition.disposition,
    disposition.secretary_member_id,disposition.reason,disposition.resulting_draft_id,disposition.created_at
  from management_submission_dispositions as disposition join selected_roots as root on root.id=disposition.thread_id
), version_metrics as materialized (
  select version_row.thread_id,count(*)::numeric as version_count,
    sum(${sum(versionFlat)}) as scalar_utf8,
    ${orderedHash(rowHash([...privateVersion, hash("version_row.document_references"), "version_row.created_at::text"]), "version_row.version")} as observation_sha256
  from selected_versions as version_row group by version_row.thread_id
), reply_metrics as materialized (
  select reply.request_id,count(*)::numeric as reply_count,sum(${sum(replyFlat)}) as scalar_utf8,
    ${orderedHash(rowHash([...privateReply, "reply.created_at::text"]), "reply.created_at,reply.id")} as observation_sha256
  from selected_replies as reply group by reply.request_id
), request_metrics as materialized (
  select request.thread_id,count(*)::numeric as request_count,
    sum(coalesce(replies.reply_count,0)) as reply_count,
    sum(${sum(requestFlat)}+coalesce(replies.scalar_utf8,0)) as scalar_utf8,
    ${orderedHash(rowHash([...privateRequest, "request.created_at::text", "coalesce(replies.observation_sha256,'')"]), "request.created_at,request.id")} as observation_sha256
  from selected_requests as request left join reply_metrics as replies on replies.request_id=request.id
  group by request.thread_id
), disposition_metrics as materialized (
  select disposition.thread_id,count(*)::numeric as disposition_count,
    sum(${sum(dispositionFlat)}) as scalar_utf8,
    ${orderedHash(rowHash([...privateDisposition, "disposition.created_at::text"]), "disposition.created_at,disposition.id")} as observation_sha256
  from selected_dispositions as disposition group by disposition.thread_id
), json_roots(id,value) as (
  select id,to_jsonb(management_owner_ids) from selected_roots
  union all select thread_id,document_references from selected_versions
), json_nodes(id,value,member) as (
  select id,value,false from json_roots where value is not null
  union all
  select node.id,child.value,child.member from json_nodes as node cross join lateral (
    select entry.value,true as member from jsonb_each(
      case when jsonb_typeof(node.value)='object' then node.value else '{}'::jsonb end) as entry
    union all
    select entry.value,false as member from jsonb_array_elements(
      case when jsonb_typeof(node.value)='array' then node.value else '[]'::jsonb end) as entry
  ) as child
), json_metrics as materialized (
  select id,(count(*) filter(where member))::numeric as json_properties,
    (count(*) filter(where jsonb_typeof(value) in ('object','array')))::numeric as json_containers
  from json_nodes group by id
), json_lengths as materialized (
  select id,sum(${utf8("value")}) as json_utf8 from json_roots group by id
), measured as materialized (
  select root.id as submission_id,root.board_id,root.row_version::text as row_version,root.current_version_id,
    coalesce(versions.version_count,0)::text as version_count,
    coalesce(requests.request_count,0)::text as request_count,
    coalesce(requests.reply_count,0)::text as reply_count,
    coalesce(dispositions.disposition_count,0)::text as disposition_count,
    (${sum(rootFlat)}+coalesce(versions.scalar_utf8,0)+coalesce(requests.scalar_utf8,0)+coalesce(dispositions.scalar_utf8,0))::text as scalar_utf8,
    coalesce(lengths.json_utf8,0)::text as json_utf8,
    coalesce(graph.json_properties,0)::text as json_properties,
    coalesce(graph.json_containers,0)::text as json_containers,
    ${rowHash([
      ...rootFlat,
      hash("to_jsonb(root.management_owner_ids)"),
      "root.queue_entered_at::text",
      "root.created_at::text",
      "coalesce(versions.observation_sha256,'')",
      "coalesce(requests.observation_sha256,'')",
      "coalesce(dispositions.observation_sha256,'')"
    ])} as observation_sha256
  from selected_roots as root left join version_metrics as versions on versions.thread_id=root.id
    left join request_metrics as requests on requests.thread_id=root.id
    left join disposition_metrics as dispositions on dispositions.thread_id=root.id
    left join json_lengths as lengths on lengths.id=root.id left join json_metrics as graph on graph.id=root.id
)`;
export const SUBMISSION_PROJECTION_PREFLIGHT_SQL = `${measured} select * from measured`;
const bounds = [
  "version_count",
  "request_count",
  "reply_count",
  "disposition_count",
  "scalar_utf8",
  "json_utf8",
  "json_properties",
  "json_containers"
] as const;
// The true scalar constructor reads only the already selected/observed CTEs.
// Root SQL remains all-row, with no new ORDER or LIMIT; actual PKs are asserted
// by the scoped fixture. Each nested constructor is inside this separate gate.
export const SUBMISSION_PROJECTION_CONTENT_SQL = `${measured}, gated as materialized (
  select measured.*,submission_id=$3::uuid and board_id=$4::uuid and row_version=$5::text
    and current_version_id is not distinct from $6::uuid and observation_sha256=$7::text
    ${bounds.map((field, index) => `and ${field}::numeric${index < 4 ? "=" : "<="}$${index + 8}::numeric`).join("\n")}
    as fits from measured
), global_gate as materialized (select coalesce(bool_and(fits),true) as fits from gated)
select fits,view from (
  select gate.fits,case when gate.fits then (
    select jsonb_build_object(
           'submission_id',thread.id,'board_id',thread.board_id,
           'management_owner_ids',to_jsonb(thread.management_owner_ids),
           'assigned_secretary_id',thread.assigned_secretary_id,'state',thread.state,
           'current_version_id',thread.current_version_id,'row_version',thread.row_version::text,
           'queue_entered_at',to_char(thread.queue_entered_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
           'versions',coalesce((select jsonb_agg(jsonb_build_object(
              'version_id',version_row.id,'version',version_row.version,
              'schema_version',version_row.schema_version,
              'document_references',version_row.document_references,
              'payload_sha256',encode(version_row.payload_sha256,'hex'),
              'author_member_id',version_row.author_member_id,
              'change_reason',version_row.change_reason,'supersedes_id',version_row.supersedes_id,
              'created_at',to_char(version_row.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
            ) order by version_row.version)
              from selected_versions as version_row
             where version_row.thread_id=thread.id),'[]'::jsonb),
           'revision_requests',coalesce((select jsonb_agg(jsonb_build_object(
              'request_id',request.id,'submission_version_id',request.submission_version_id,
              'secretary_member_id',request.secretary_member_id,'request_text',request.request_text,
              'request_sha256',encode(request.request_sha256,'hex'),
              'created_at',to_char(request.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
              'replies',coalesce((select jsonb_agg(jsonb_build_object(
                 'reply_id',reply.id,'submission_version_id',reply.submission_version_id,
                 'management_author_id',reply.management_author_id,
                 'canonical_reply',reply.canonical_reply,
                 'reply_sha256',encode(reply.reply_sha256,'hex'),
                 'created_at',to_char(reply.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
               ) order by reply.created_at,reply.id)
                 from selected_replies as reply where reply.request_id=request.id),'[]'::jsonb)
            ) order by request.created_at,request.id)
              from selected_requests as request where request.thread_id=thread.id),'[]'::jsonb),
           'dispositions',coalesce((select jsonb_agg(jsonb_build_object(
              'disposition_id',disposition.id,
              'submission_version_id',disposition.submission_version_id,
              'disposition',disposition.disposition,
              'secretary_member_id',disposition.secretary_member_id,
              'reason',disposition.reason,'resulting_draft_id',disposition.resulting_draft_id,
              'created_at',to_char(disposition.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
            ) order by disposition.created_at,disposition.id)
              from selected_dispositions as disposition
             where disposition.thread_id=thread.id),'[]'::jsonb),
           'created_by',thread.created_by,
           'created_at',to_char(thread.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
         ) from selected_roots as thread where thread.id=chosen.submission_id
  ) else null end as view
  from gated as chosen cross join global_gate as gate where gate.fits
  union all select gate.fits,null::jsonb from global_gate as gate where not gate.fits
) as projected`;
function scalar(value: string): bigint {
  if (typeof value !== "string") throw new TypeError("submission projection scalar is invalid");
  if (value.length > 24) throw new ResponseAllocationUnavailable();
  if (!/^(0|[1-9][0-9]*)$/u.test(value))
    throw new TypeError("submission projection scalar is invalid");
  return BigInt(value);
}
export function submissionProjectionCost(
  metadata: SubmissionProjectionMetadata
): ListProjectionScalars {
  const [v, q, l, d, s, n, p, o] = bounds.map((field) => scalar(metadata[field])) as [
    bigint,
    bigint,
    bigint,
    bigint,
    bigint,
    bigint,
    bigint,
    bigint
  ];
  return {
    jsonUpperBytes: (303n + 212n * v + 167n * q + 150n * l + 173n * d + 6n * s + n).toString(),
    propertyCount: (36n + 9n * v + 7n * q + 6n * l + 7n * d + p).toString(),
    objectOrArrayCount: (11n + v + 2n * q + l + d + o).toString()
  };
}
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
function check(metadata: SubmissionProjectionMetadata, submissionId: string) {
  if (
    metadata.submission_id !== submissionId ||
    !uuid.test(metadata.board_id) ||
    (metadata.current_version_id !== null && !uuid.test(metadata.current_version_id)) ||
    typeof metadata.observation_sha256 !== "string" ||
    !/^[0-9a-f]{64}$/u.test(metadata.observation_sha256) ||
    scalar(metadata.row_version) < 1n
  )
    throw new TypeError("submission projection identity is invalid");
  submissionProjectionCost(metadata);
}
export function submissionProjectionPlan(
  metadata: SubmissionProjectionMetadata
): ResponseAllocationPlan {
  if (!uuid.test(metadata.submission_id)) throw new TypeError("submission ID is invalid");
  check(metadata, metadata.submission_id);
  return responseAllocationPlan({
    kind: "management_read_projection",
    representation: "tool",
    canonicalBytes: 0,
    sourceId: metadata.submission_id,
    sourceVersion: metadata.row_version,
    sha256: createHash("sha256").update(JSON.stringify(metadata)).digest("hex"),
    listProjection: submissionProjectionCost(metadata)
  });
}
export async function loadAdmittedSubmission(
  client: PoolClient,
  submissionId: string,
  memberId: string
): Promise<JsonValue | null> {
  if (!uuid.test(submissionId) || !uuid.test(memberId))
    throw new TypeError("submission selector is invalid");
  const owner = currentResponseAllocationOwner();
  if (!owner) throw new TypeError("submission projection requires a native request owner");
  owner.assertLive();
  const inspected = await client.query<SubmissionProjectionMetadata>(
    SUBMISSION_PROJECTION_PREFLIGHT_SQL,
    [submissionId, memberId]
  );
  owner.assertLive();
  if (inspected.rows.length > 1)
    throw new TypeError("submission preflight returned multiple roots");
  const row = inspected.rows[0];
  if (!row) return null;
  check(row, submissionId);
  const metadata = Object.freeze({ ...row });
  const loaded = await loadWithResponseAllocation(submissionProjectionPlan(metadata), () =>
    client.query<{ fits: boolean; view: JsonValue | null }>(SUBMISSION_PROJECTION_CONTENT_SQL, [
      submissionId,
      memberId,
      metadata.submission_id,
      metadata.board_id,
      metadata.row_version,
      metadata.current_version_id,
      metadata.observation_sha256,
      ...bounds.map((field) => metadata[field])
    ])
  );
  if (loaded.rows.length > 1) throw new TypeError("submission projection returned multiple roots");
  const content = loaded.rows[0];
  if (!content) return null;
  if (content.fits === false) throw new ResponseAllocationUnavailable();
  const view = content.view;
  if (content.fits !== true || view === null || typeof view !== "object" || Array.isArray(view))
    throw new TypeError("submission projection returned identity mismatch");
  const object = view as Readonly<Record<string, JsonValue>>;
  if (
    object["submission_id"] !== submissionId ||
    object["board_id"] !== metadata.board_id ||
    object["row_version"] !== metadata.row_version ||
    object["current_version_id"] !== metadata.current_version_id
  )
    throw new TypeError("submission projection returned identity mismatch");
  return view;
}
