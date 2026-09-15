// Frozen original get_task/get_action_item SQL; deliberately independent of the admitted helper.
export const ORIGINAL_TASK_TOOL_SQL = `select jsonb_build_object(
           'task_id',task.id,'board_id',task.board_id,
           'source_meeting_id',task.source_meeting_id,'source_minutes_id',task.source_minutes_id,
           'source_minutes_version_id',task.source_minutes_version_id,
           'source_minutes_sha256',case when task.source_minutes_sha256 is null then null
              else encode(task.source_minutes_sha256,'hex') end,
           'source_locator',task.source_locator,'owner_member_id',task.owner_member_id,
           'due_at',to_char(task.due_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
           'description_schema',task.description_schema,
           'canonical_description',task.canonical_description,
           'required_evidence',task.required_evidence,
           'task_sha256',encode(task.task_sha256,'hex'),'state',task.state,
           'row_version',task.row_version::text,
           'evidence',coalesce((select jsonb_agg(jsonb_build_object(
              'evidence_id',evidence.id,'canonical_text',evidence.canonical_text,
              'document_references',evidence.document_references,
              'resource_references',evidence.resource_references,
              'sha256',encode(evidence.canonical_sha256,'hex'),'state',evidence.state,
              'row_version',evidence.row_version::text,
              'submitted_at',to_char(evidence.submitted_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
              'review',(select jsonb_build_object('review_id',review.id,'decision',review.decision,
                 'reason',review.reason,'secretary_member_id',review.secretary_member_id,
                 'reviewed_at',to_char(review.reviewed_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
                from task_evidence_reviews as review where review.evidence_id=evidence.id
                order by review.reviewed_at desc limit 1)
            ) order by evidence.submitted_at,evidence.id)
              from task_evidence as evidence where evidence.task_id=task.id),'[]'::jsonb),
           'closure',(select jsonb_build_object(
              'closure_id',closure.id,'primary_evidence_id',closure.primary_evidence_id,
              'accepted_evidence_manifest',closure.accepted_evidence_manifest,
              'source_minutes_sha256',case when closure.source_minutes_sha256 is null then null
                 else encode(closure.source_minutes_sha256,'hex') end,
              'secretary_member_id',closure.secretary_member_id,
              'closure_sha256',encode(closure.closure_sha256,'hex'),
              'closed_at',to_char(closure.closed_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
             from task_closures as closure where closure.task_id=task.id limit 1),
           'correction_cycles',coalesce((select jsonb_agg(jsonb_build_object(
              'cycle_id',cycle.id,'prior_task_id',cycle.prior_task_id,
              'replacement_task_id',cycle.replacement_task_id,'reason',cycle.reason,
              'created_at',to_char(cycle.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
            ) order by cycle.created_at,cycle.id) from task_correction_cycles as cycle
             where cycle.prior_task_id=task.id or cycle.replacement_task_id=task.id),'[]'::jsonb),
           'created_at',to_char(task.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
           'completed_at',case when task.completed_at is null then null else
              to_char(task.completed_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') end,
           'cancelled_at',case when task.cancelled_at is null then null else
              to_char(task.cancelled_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') end
         ) as view from tasks as task
        where task.id=$1 and (not $2::boolean or task.source_minutes_id is not null)
          and (task.owner_member_id=$3 or task.created_by=$3 or exists (
            select 1 from board_memberships as membership where membership.board_id=task.board_id
              and membership.member_id=$3 and membership.state='active'
          ))`;
