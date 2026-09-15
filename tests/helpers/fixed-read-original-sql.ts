// Verbatim pre-admission SQL. Do not derive expectations from proposed loaders.
export const ORIGINAL_DRAFTS_SQL = `select jsonb_build_object(
         'draft_id',draft.id,'board_id',draft.board_id,'draft_type',draft.draft_type,
         'current_step',draft.current_step,'state',draft.state,'ruleset_id',draft.ruleset_id,
         'package_sha256',case when draft.package_sha256 is null then null
            else encode(draft.package_sha256,'hex') end,
         'row_version',draft.row_version::text,
         'expires_at',to_char(draft.expires_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
         'created_at',to_char(draft.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
       ) as item,
       to_char(draft.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as cursor_at,
       draft.id::text as cursor_id from wizard_drafts as draft
      where draft.creator_member_id=$1 and draft.state in ('active','ready_to_confirm')
        and draft.expires_at>transaction_timestamp()
        and ($2::text is null or draft.draft_type=$2)
        and ($3::timestamptz is null or (draft.created_at,draft.id)<($3::timestamptz,$4::uuid))
      order by draft.created_at desc,draft.id desc limit $5`;

export const ORIGINAL_WEBHOOKS_SQL = `select jsonb_build_object(
           'webhook_id',webhook.id,'state',webhook.state,
           'endpoint_fingerprint',encode(webhook.endpoint_sha256,'hex'),
           'ssrf_validation_receipt_sha256',encode(webhook.ssrf_validation_receipt_sha256,'hex'),
           'generation',webhook.generation::text,'key_id',webhook.key_id,
           'created_at',to_char(webhook.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
           'disabled_at',case when webhook.disabled_at is null then null else
             to_char(webhook.disabled_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') end
         ) as item,
         to_char(webhook.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as cursor_at,
         webhook.id::text as cursor_id from member_webhooks as webhook
        where webhook.member_id=$1
          and ($2::timestamptz is null or
               (webhook.created_at,webhook.id)<($2::timestamptz,$3::uuid))
        order by webhook.created_at desc,webhook.id desc limit $4`;

export const ORIGINAL_EXPORT_SQL = `select jsonb_build_object(
           'export_id',$2::text,'request_id',request.id,'board_id',request.board_id,
           'export_type',request.export_type,'scope_sha256',encode(request.scope_sha256,'hex'),
           'state',request.state,'row_version',request.row_version::text,
           'expires_at',to_char(request.expires_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
           'snapshot_sha256',case when request.snapshot_sha256 is null then null
             else encode(request.snapshot_sha256,'hex') end,
           'failure_class',request.failure_class,
           'artifact',case when artifact.id is null then null else jsonb_build_object(
              'artifact_id',artifact.id,'manifest_sha256',encode(artifact.manifest_sha256,'hex'),
              'content_set_sha256',encode(artifact.content_set_sha256,'hex'),
              'byte_length',artifact.byte_length::text,'state',artifact.state,
              'created_at',to_char(artifact.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
              'deleted_at',case when artifact.deleted_at is null then null else
                to_char(artifact.deleted_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') end
           ) end,
           'created_at',to_char(request.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
           'completed_at',case when request.completed_at is null then null else
             to_char(request.completed_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') end
         ) as view from export_requests as request
         left join export_artifacts as artifact on artifact.export_request_id=request.id
        where request.public_id=$1 and request.requester_member_id=$3 limit 1`;
export const ORIGINAL_RETENTION_SQL = "select count(*)::text as count from retention_snapshots";
