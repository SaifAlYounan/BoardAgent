// Exact original SQL literals; independent of production measurement/field maps.
export const ORIGINAL_MINUTES_VERSIONS_SQL = `select jsonb_build_object(
           'version_id',version_row.id,'minutes_id',version_row.minutes_id,
           'version',version_row.version,'canonical_schema',version_row.canonical_schema,
           'sha256',encode(version_row.canonical_sha256,'hex'),
           'package_base_sha256',encode(version_row.package_base_sha256,'hex'),
           'transcript_version_id',version_row.transcript_version_id,
           'supersedes_id',version_row.supersedes_id,
           'created_at',to_char(version_row.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
         ) as item,
         to_char(version_row.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as cursor_at,
         version_row.id::text as cursor_id
         from minutes_versions as version_row where version_row.minutes_id=$1
          and ($2::timestamptz is null or
            (version_row.created_at,version_row.id)<($2::timestamptz,$3::uuid))
         order by version_row.created_at desc,version_row.id desc limit $4`;
export const ORIGINAL_MINUTES_REVIEWS_SQL = `select jsonb_build_object(
         'review_item_id',item.id,'minutes_id',item.minutes_id,'item_kind',item.item_kind,
         'schema_version',item.schema_version,'author_member_id',item.author_member_id,
         'author_seat_role',item.author_seat_role,'base_version_id',item.base_version_id,
         'base_sha256',encode(item.base_sha256,'hex'),'anchor',item.exact_anchor,
         'payload',convert_from(item.canonical_payload,'UTF8')::jsonb,
         'payload_sha256',encode(item.payload_sha256,'hex'),
         'withdrawal',case when withdrawal.id is null then null else jsonb_build_object(
            'withdrawal_id',withdrawal.id,'author_member_id',withdrawal.author_member_id,
            'withdrawn_at',to_char(withdrawal.withdrawn_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
         ) end,
         'disposition',case when disposition.id is null then null else jsonb_build_object(
            'disposition_id',disposition.id,'decision',disposition.decision,
            'reason',disposition.reason,
            'resulting_minutes_version_id',disposition.resulting_minutes_version_id,
            'created_at',to_char(disposition.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
         ) end,
         'created_at',to_char(item.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
       ) as item,
       to_char(item.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as cursor_at,
       item.id::text as cursor_id
       from minutes_review_items as item
       left join minutes_review_withdrawals as withdrawal on withdrawal.review_item_id=item.id
       left join minutes_review_dispositions as disposition on disposition.review_item_id=item.id
      where item.minutes_id=$1
        and ($2::timestamptz is null or (item.created_at,item.id)<($2::timestamptz,$3::uuid))
      order by item.created_at desc,item.id desc limit $4`;
