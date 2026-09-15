// Test-only verbatim original SQL; independent of the production field maps.
export const ORIGINAL_AGENDA_SQL = `select jsonb_build_object(
           'meeting_id',meeting.id,'agenda_version_id',agenda.id,'version',agenda.version,
           'schema_version',agenda.schema_version,
           'canonical_payload',convert_from(agenda.canonical_payload,'UTF8')::jsonb,
           'sha256',encode(agenda.canonical_sha256,'hex'),
           'items',coalesce((select jsonb_agg(jsonb_build_object(
              'item_id',item.id,'ordinal',item.ordinal,'title',item.title,
              'source_document_version_id',item.source_document_version_id,
              'source_document_sha256',case when item.source_document_sha256 is null then null
                 else encode(item.source_document_sha256,'hex') end,
              'sha256',encode(item.item_sha256,'hex')
            ) order by item.ordinal,item.id) from agenda_items as item
             where item.agenda_version_id=agenda.id),'[]'::jsonb),
           'created_at',to_char(agenda.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
         ) as view
         from meetings as meeting
         join agenda_versions as agenda on agenda.meeting_id=meeting.id
        where meeting.id=$1 and (($2::integer is null and agenda.id=meeting.current_agenda_version_id)
          or agenda.version=$2)
        order by agenda.version desc limit 1`;
export const ORIGINAL_ATTENDANCE_SQL = `select coalesce(jsonb_agg(jsonb_build_object(
           'attendance_id',attendance.id,'member_id',attendance.member_id,
           'status',attendance.attendance_status,'source',attendance.source,
           'recorder_member_id',attendance.recorder_member_id,
           'corrects_id',attendance.corrects_id,'correction_reason',attendance.correction_reason,
           'recorded_at',to_char(attendance.recorded_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
         ) order by attendance.recorded_at,attendance.id),'[]'::jsonb) as items
         from meeting_attendance as attendance where attendance.meeting_id=$1`;
