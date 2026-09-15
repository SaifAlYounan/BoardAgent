// Frozen original task/action-item resource SQL. Test-only; never a production fallback.
export const ORIGINAL_TASK_RESOURCE_SQL = `select task.id,task.row_version::text,
              jsonb_build_object('schema_version','boardagent.task-resource.v1',
                'task_id',task.id,'board_id',task.board_id,
                'source_minutes_id',task.source_minutes_id,
                'source_minutes_version_id',task.source_minutes_version_id,
                'source_minutes_sha256',case when task.source_minutes_sha256 is null then null
                  else encode(task.source_minutes_sha256,'hex') end,
                'owner_member_id',task.owner_member_id,
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
                   'sha256',encode(evidence.canonical_sha256,'hex'),'state',evidence.state)
                  order by evidence.submitted_at,evidence.id) from task_evidence as evidence
                   where evidence.task_id=task.id),'[]'::jsonb),
                'closure',(select jsonb_build_object('closure_id',closure.id,
                   'accepted_evidence_manifest',closure.accepted_evidence_manifest,
                   'closure_sha256',encode(closure.closure_sha256,'hex'))
                  from task_closures as closure where closure.task_id=task.id limit 1)) as payload
         from tasks as task where task.board_id=$1 and task.id=$2
          and (not $3::boolean or task.source_minutes_id is not null)
          and (task.owner_member_id=$4 or task.created_by=$4 or exists (
            select 1 from board_memberships as membership where membership.board_id=task.board_id
              and membership.member_id=$4 and membership.state='active'))`;
