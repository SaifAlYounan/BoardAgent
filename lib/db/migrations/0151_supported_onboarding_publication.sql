-- Additive onboarding publication; original versions and human attestations remain immutable.
-- SQL0053 already keys attestations by both terms and support versions; retain that constraint.
alter table public.secretary_support_versions
  add column publication_consent_record_id uuid unique references public.consent_records(id) on delete restrict,
  add column publication_audit_event_id uuid unique references public.audit_events(id) on delete restrict;
alter table public.onboarding_terms_versions
  add column publication_consent_record_id uuid unique references public.consent_records(id) on delete restrict,
  add column publication_audit_event_id uuid unique references public.audit_events(id) on delete restrict;
revoke insert,update,delete on public.secretary_support_versions,public.onboarding_terms_versions from boardagent_server;
grant insert on public.secretary_support_versions,public.onboarding_terms_versions to boardagent_migrator;
create policy boardagent_support_publication_insert on public.secretary_support_versions for insert to boardagent_migrator
 with check(current_setting('boardagent.transaction_scope',true)='request'
   and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
   and created_by=public.boardagent_context_uuid('boardagent.member_id')
   and board_id is not null and publication_consent_record_id is not null and publication_audit_event_id is not null);
create policy boardagent_terms_publication_insert on public.onboarding_terms_versions for insert to boardagent_migrator
 with check(current_setting('boardagent.transaction_scope',true)='request'
   and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
   and created_by=public.boardagent_context_uuid('boardagent.member_id')
   and publication_consent_record_id is not null and publication_audit_event_id is not null);

create function public.boardagent_prepare_onboarding_publication(candidate_tool text,candidate_request jsonb)
 returns jsonb language plpgsql volatile security definer set search_path=pg_catalog,public,pg_temp
as $$
declare
 org uuid:=public.boardagent_context_uuid('boardagent.organization_id');
 actor uuid:=public.boardagent_context_uuid('boardagent.member_id');
 board uuid;
 previous_id uuid;
 previous_version integer;
 previous_hash bytea;
 kind text;
 keys text[];
 initial_admin boolean:=false;
begin
 if (current_setting('boardagent.transaction_scope',true)='request'
   and candidate_tool in ('publish_secretary_support','publish_onboarding_terms')
   and jsonb_typeof(candidate_request)='object'
   and candidate_request->>'schema_version'='boardagent.tool-input.v1'
   and public.boardagent_is_uuid_v7((candidate_request->>'version_id')::uuid)
   and (not candidate_request ? 'expected_version_id' or candidate_request->'expected_version_id'='null'::jsonb or public.boardagent_is_uuid_v7((candidate_request->>'expected_version_id')::uuid))
   and jsonb_typeof(candidate_request->'reason')='string' and length(candidate_request->>'reason') between 1 and 65536
   and candidate_request->>'idempotency_key' ~ '^[A-Za-z0-9._~-]{16,200}$'
   and exists(select 1 from public.boardagent_resolve_access_token(public.boardagent_context_uuid('boardagent.token_jti')) t
     where t.organization_id=org and t.member_id=actor and t.internal_client_id=public.boardagent_context_uuid('boardagent.client_id')
       and 'secretariat:admin'=any(t.scope_set))
   and public.boardagent_administrative_member_eligible(actor)) is distinct from true then
   raise exception 'onboarding publication is unavailable' using errcode='42501';
 end if;
 -- Same organization-first serialization order as company administration. All new versions are immediate.
 perform 1 from public.organizations where id=org for update;
 if candidate_tool='publish_secretary_support' then
   keys:=array['schema_version','board_id','version_id','expected_version_id','support_name','contact_methods','reason','idempotency_key'];
   board:=(candidate_request->>'board_id')::uuid;kind:='secretary_support_version';
   select id,version,canonical_sha256 into previous_id,previous_version,previous_hash
    from public.secretary_support_versions where organization_id=org and board_id=board order by version desc limit 1;
   initial_admin:=previous_id is null and exists(
     select 1 from public.boardagent_resolve_access_token(public.boardagent_context_uuid('boardagent.token_jti')) t
     where t.organization_id=org and t.member_id=actor and 'admin'=any(t.roles));
   if (public.boardagent_is_uuid_v7(board)
     and exists(select 1 from public.boards b where b.id=board and b.organization_id=org and b.state='active')
     and not public.boardagent_member_board_recused(board,actor)
     and (initial_admin or (public.boardagent_context_board_allowed(board)
       and public.boardagent_secretariat_for_board(board)
       and exists(select 1 from public.board_memberships m where m.organization_id=org and m.member_id=actor and m.board_id=board
        and m.state='active' and m.active_from<=transaction_timestamp() and (m.active_until is null or m.active_until>transaction_timestamp())
        and (m.is_secretary or exists(select 1 from public.organization_role_assignments r where r.organization_id=org
          and r.member_id=actor and r.role='secretariat' and r.active_from<=transaction_timestamp()
          and (r.active_until is null or r.active_until>transaction_timestamp()))))))
     and jsonb_typeof(candidate_request->'support_name')='string' and length(candidate_request->>'support_name') between 1 and 512
     and jsonb_typeof(candidate_request->'contact_methods')='array' and jsonb_array_length(candidate_request->'contact_methods') between 1 and 32) is distinct from true then
     raise exception 'onboarding publication is unavailable' using errcode='42501';
   end if;
 else
   keys:=array['schema_version','seat_role','version_id','expected_version_id','canonical_text','reason','idempotency_key'];
   kind:='onboarding_terms_version';
   if (candidate_request->>'seat_role' in ('voting_member','management','observer')
     and jsonb_typeof(candidate_request->'canonical_text')='string' and length(candidate_request->>'canonical_text') between 1 and 1048576
     and exists(select 1 from public.boardagent_resolve_access_token(public.boardagent_context_uuid('boardagent.token_jti')) t
       where t.organization_id=org and t.member_id=actor and 'admin'=any(t.roles))) is distinct from true then
     raise exception 'onboarding publication is unavailable' using errcode='42501';
   end if;
   select id,version,canonical_sha256 into previous_id,previous_version,previous_hash from public.onboarding_terms_versions
    where organization_id=org and seat_role=candidate_request->>'seat_role' order by version desc limit 1;
 end if;
 if candidate_request-keys<>'{}'::jsonb or not candidate_request ?& array_remove(keys,'expected_version_id')
   or (candidate_request ? 'expected_version_id' and previous_id is distinct from (candidate_request->>'expected_version_id')::uuid)
   or exists(select 1 from public.secretary_support_versions where id=(candidate_request->>'version_id')::uuid)
   or exists(select 1 from public.onboarding_terms_versions where id=(candidate_request->>'version_id')::uuid) then
   raise exception 'onboarding publication version changed or is unavailable' using errcode='42501';
 end if;
 return jsonb_build_object('schemaVersion','boardagent.onboarding-publication.v1','tool',candidate_tool,'request',candidate_request,
  'boardId',board,'targetType',kind,'version',coalesce(previous_version,0)+1,'previousSha256',encode(previous_hash,'hex'),'previousVersionId',previous_id,'initialAdministrativeSetup',initial_admin);
end $$;
alter function public.boardagent_prepare_onboarding_publication(text,jsonb) owner to boardagent_migrator;
revoke all on function public.boardagent_prepare_onboarding_publication(text,jsonb) from public;
grant execute on function public.boardagent_prepare_onboarding_publication(text,jsonb) to boardagent_server;

create function public.boardagent_apply_onboarding_publication(candidate_consent uuid,candidate_audit uuid)
 returns void language plpgsql volatile security definer set search_path=pg_catalog,public,pg_temp
as $$
declare
 consent public.consent_records%rowtype;
 stage public.action_stages%rowtype;
 payload jsonb;
 request jsonb;
 snapshot jsonb;
 content text;
 content_hash bytea;
 expected_content jsonb;
 event_name text;
begin
 select * into consent from public.consent_records where id=candidate_consent;
 select * into stage from public.action_stages where id=consent.stage_id;
 if (current_setting('boardagent.transaction_scope',true)='request'
   and consent.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
   and consent.actor_member_id=public.boardagent_context_uuid('boardagent.member_id')
   and consent.client_id=public.boardagent_context_uuid('boardagent.client_id')
   and consent.token_jti=public.boardagent_context_uuid('boardagent.token_jti')
   and consent.confirmed_at=transaction_timestamp()
   and consent.action_code in ('publish_secretary_support','publish_onboarding_terms')
   and consent.package_sha256 is null and consent.acting_for_member_id is null
   and stage.state='confirmed' and stage.confirmed_at=consent.confirmed_at
   and stage.action_code=consent.action_code and stage.target_type=consent.target_type and stage.target_id=consent.target_id
   and stage.board_id is not distinct from consent.board_id and stage.organization_id=consent.organization_id
   and stage.actor_member_id=consent.actor_member_id and stage.client_id=consent.client_id and stage.token_jti=consent.token_jti
   and stage.payload_sha256=consent.payload_sha256 and stage.payload_sha256=pg_catalog.sha256(stage.canonical_payload)
   and stage.canonical_schema='boardagent.onboarding-publication.v1'
   and exists(select 1 from public.input_required_attempts a where a.id=consent.input_required_attempt_id
    and a.stage_id=stage.id and a.state='confirmed' and a.response_action='accept' and a.original_name=consent.action_code)) is distinct from true then
   raise exception 'onboarding publication lacks exact confirmed authority' using errcode='42501';
 end if;
 payload:=convert_from(stage.canonical_payload,'UTF8')::jsonb;request:=payload->'request';
 snapshot:=public.boardagent_prepare_onboarding_publication(consent.action_code,request);
 content:=payload->>'canonicalContent';content_hash:=pg_catalog.sha256(convert_to(content,'UTF8'));
 event_name:=case when consent.action_code='publish_secretary_support' then 'secretary_support_published' else 'onboarding_terms_published' end;
 if (payload-array['canonicalContent','contentSha256']=snapshot
   and payload->>'contentSha256'=encode(content_hash,'hex')
   and (snapshot->>'boardId')::uuid is not distinct from consent.board_id
   and snapshot->>'targetType'=consent.target_type and (request->>'version_id')::uuid=consent.target_id
   and exists(select 1 from public.audit_events a where a.id=candidate_audit and a.organization_id=consent.organization_id
    and a.board_id is not distinct from consent.board_id and a.object_type=consent.target_type and a.object_id=consent.target_id
    and a.event_type=event_name and a.actor_member_id=consent.actor_member_id and a.client_id=consent.client_id and a.token_jti=consent.token_jti
    and a.consent_record_id=consent.id
    and convert_from(a.canonical_payload,'UTF8')::jsonb->'details'=jsonb_build_object('version',snapshot->'version',
      'previousVersionId',snapshot->'previousVersionId','contentSha256',encode(content_hash,'hex'),
      'payloadSha256',encode(consent.payload_sha256,'hex'),'reason',request->>'reason'))) is distinct from true then
   raise exception 'onboarding publication lacks exact confirmed evidence' using errcode='42501';
 end if;
 if consent.action_code='publish_secretary_support' then
   expected_content:=jsonb_build_object('schemaVersion','boardagent.secretary-support.v1','boardId',consent.board_id,
     'version',snapshot->'version','supportName',request->>'support_name','contactMethods',request->'contact_methods');
   if content::jsonb is distinct from expected_content then raise exception 'support content mismatch' using errcode='42501';end if;
   insert into public.secretary_support_versions(id,organization_id,board_id,version,support_name,contact_methods,canonical_sha256,effective_at,created_by,publication_consent_record_id,publication_audit_event_id)
    values(consent.target_id,consent.organization_id,consent.board_id,(snapshot->>'version')::integer,request->>'support_name',request->'contact_methods',content_hash,transaction_timestamp(),consent.actor_member_id,consent.id,candidate_audit);
 else
   if content is distinct from request->>'canonical_text' then raise exception 'terms content mismatch' using errcode='42501';end if;
   insert into public.onboarding_terms_versions(id,organization_id,seat_role,version,schema_version,canonical_text,canonical_sha256,material_change,effective_at,created_by,publication_consent_record_id,publication_audit_event_id)
    values(consent.target_id,consent.organization_id,request->>'seat_role',(snapshot->>'version')::integer,'boardagent.onboarding-terms.v1',content,content_hash,true,transaction_timestamp(),consent.actor_member_id,consent.id,candidate_audit);
 end if;
end $$;
alter function public.boardagent_apply_onboarding_publication(uuid,uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_apply_onboarding_publication(uuid,uuid) from public;
grant execute on function public.boardagent_apply_onboarding_publication(uuid,uuid) to boardagent_server;

-- Extend the closed event vocabulary by exactly the two pinned publication events.
alter table public.audit_events drop constraint audit_events_event_type_check;
alter table public.audit_events add constraint audit_events_event_type_check check (event_type in (
  'context_read',
  'client_registered',
  'client_registration_rejected',
  'oauth_client_blocked',
  'oauth_client_unblocked',
  'token_issued',
  'token_refreshed',
  'token_reuse_detected',
  'session_revoked',
  'enrollment_issued',
  'enrollment_redeemed',
  'enrollment_revoked',
  'member_activated',
  'identity_recovery_started',
  'external_identity_linked',
  'external_identity_unlinked',
  'member_changed',
  'onboarding_stage_created',
  'onboarding_attested',
  'onboarding_stale',
  'authorization_denied',
  'rate_limited',
  'resource_fetch',
  'notice_delivered',
  'document_version_created',
  'document_circulated',
  'document_access_changed',
  'document_archived',
  'document_soft_deleted',
  'recusal_changed',
  'management_submission_created',
  'management_revision_requested',
  'management_revision_replied',
  'management_submission_version_created',
  'management_submission_approved_to_draft',
  'management_submission_rejected',
  'management_question_asked',
  'management_question_answered',
  'management_question_followed_up',
  'secretariat_request_created',
  'secretariat_request_replied',
  'secretariat_request_closed',
  'board_created',
  'board_amended',
  'board_archived',
  'governance_profile_activated',
  'matter_evaluated',
  'ruleset_amended',
  'rule_overridden',
  'stage_created',
  'stage_replaced',
  'elicitation_sent',
  'consent_recorded',
  'consent_rejected',
  'ballot_cast',
  'ballot_superseded',
  'proxy_granted',
  'proxy_revoked',
  'resolution_amended',
  'vote_opened',
  'vote_source_update_pending',
  'vote_source_excluded',
  'vote_closing',
  'vote_closed',
  'vote_cancelled',
  'vote_superseded',
  'vote_replaced',
  'revote_required',
  'certificate_issued',
  'certificate_corrected',
  'meeting_called',
  'meeting_amended',
  'meeting_rsvp_recorded',
  'meeting_attendance_recorded',
  'meeting_attendance_corrected',
  'meeting_completed',
  'meeting_cancelled',
  'transcript_version_created',
  'transcript_secretary_verified',
  'transcript_qna_linked',
  'transcript_turn_challenged',
  'transcript_challenge_resolved',
  'minutes_version_created',
  'minutes_published',
  'minutes_commented',
  'minutes_review_withdrawn',
  'minutes_redline_proposed',
  'minutes_review_dispositioned',
  'minutes_package_corrected',
  'minutes_correction_cycle_created',
  'minutes_action_items_declared',
  'minutes_action_item_draft_superseded',
  'minutes_action_items_activated',
  'minutes_signature_package_issued',
  'minutes_signed',
  'minutes_signature_superseded',
  'minutes_resign_required',
  'minutes_finalized',
  'minutes_cancelled',
  'task_created',
  'task_started',
  'task_evidence_submitted',
  'task_evidence_reviewed',
  'task_completed',
  'task_correction_cycle_created',
  'task_cancelled',
  'proposal_submitted',
  'proposal_withdrawn',
  'proposal_approved_to_draft',
  'proposal_rejected',
  'draft_cancelled',
  'draft_expired',
  'export_requested',
  'export_started',
  'export_performed',
  'export_failed',
  'export_cancelled',
  'export_artifact_deleted',
  'webhook_configured',
  'webhook_secret_rotated',
  'webhook_disabled',
  'webhook_tested',
  'webhook_delivery_attempted',
  'audit_checkpoint_signed',
  'audit_verification_failed',
  'migration_applied',
  'backup_completed',
  'restore_verified',
  'company_admin_proposed',
  'company_admin_proposal_cancelled',
  'company_admin_proposal_declined',
  'company_admin_granted',
  'company_admin_revoked',
  'company_admin_transferred',
  'member_admin_delegation_granted',
  'member_admin_delegation_revoked',
  'key_lifecycle_changed',
  'secretary_support_published',
  'onboarding_terms_published'
));

-- Own setup evidence only; the publication finalizer still independently enforces first-version/admin authority.
create or replace function public.boardagent_owned_administrative_stage(
  candidate_org uuid,candidate_board uuid,candidate_actor uuid,candidate_client uuid,
  candidate_token uuid,candidate_action text
) returns boolean language sql stable security definer set search_path=pg_catalog,public,pg_temp
as $$
  select current_setting('boardagent.transaction_scope',true)='request'
    and candidate_org=public.boardagent_context_uuid('boardagent.organization_id')
    and candidate_actor=public.boardagent_context_uuid('boardagent.member_id')
    and candidate_client=public.boardagent_context_uuid('boardagent.client_id')
    and candidate_token=public.boardagent_context_uuid('boardagent.token_jti')
    and candidate_action in ('manage_member','manage_member_admin_delegation',
      'update_board','archive_board','configure_board_governance','manage_ruleset','publish_secretary_support')
    and exists(select 1 from public.boards b where b.id=candidate_board
      and b.organization_id=candidate_org)
    and exists(select 1 from public.boardagent_resolve_access_token(candidate_token) t
      where t.organization_id=candidate_org and t.member_id=candidate_actor
        and t.internal_client_id=candidate_client
        and 'admin'=any(t.roles) and 'secretariat:admin'=any(t.scope_set))
    and public.boardagent_administrative_member_eligible(candidate_actor)
$$;

-- Own setup evidence only; the publication finalizer still independently enforces first-version/admin authority.
create or replace function public.boardagent_owned_administrative_audit(
  candidate_org uuid,candidate_board uuid,candidate_actor uuid,candidate_client uuid,
  candidate_token uuid,candidate_event text,candidate_type text,candidate_id uuid,candidate_consent uuid
) returns boolean language sql stable security definer set search_path=pg_catalog,public,pg_temp
as $$
  select exists(select 1 from public.action_stages s
    where s.organization_id=candidate_org and s.board_id=candidate_board
      and s.actor_member_id=candidate_actor and s.client_id=candidate_client and s.token_jti=candidate_token
      and public.boardagent_owned_administrative_stage(s.organization_id,s.board_id,s.actor_member_id,s.client_id,s.token_jti,s.action_code)
      and (
        (candidate_event in ('stage_created','stage_replaced','consent_rejected')
          and candidate_type='action_stage' and candidate_id=s.id and candidate_consent is null)
        or (candidate_event='elicitation_sent' and candidate_type='input_required_attempt' and candidate_consent is null
          and exists(select 1 from public.input_required_attempts a where a.stage_id=s.id and a.id=candidate_id))
        or exists(select 1 from public.consent_records c where c.stage_id=s.id and c.id=candidate_consent
          and c.organization_id=s.organization_id and c.board_id=s.board_id
          and c.actor_member_id=s.actor_member_id and c.client_id=s.client_id and c.token_jti=s.token_jti
          and ((candidate_event='consent_recorded' and candidate_type='consent_record' and candidate_id=c.id)
            or (candidate_type=s.target_type and candidate_id=s.target_id and candidate_event=case s.action_code
              when 'manage_member' then 'member_changed'
              when 'update_board' then 'board_amended'
              when 'archive_board' then 'board_archived'
              when 'configure_board_governance' then 'governance_profile_activated'
              when 'manage_ruleset' then 'ruleset_amended'
              when 'publish_secretary_support' then 'secretary_support_published'
            end)
            or (s.action_code='manage_member_admin_delegation'
              and candidate_type=s.target_type and candidate_id=s.target_id
              and candidate_event in ('member_admin_delegation_granted','member_admin_delegation_revoked'))))
      ))
$$;

-- The inverse evidence link also holds at COMMIT: a publication claim cannot survive
-- without the exact version it claims. Application finalizer ordering alone is insufficient.
create function public.boardagent_guard_onboarding_publication_audit()
 returns trigger language plpgsql security definer set search_path=pg_catalog,public,pg_temp
as $$
begin
 if new.event_type='secretary_support_published' then
  if not exists(select 1 from public.secretary_support_versions v
    where v.publication_audit_event_id=new.id and v.publication_consent_record_id=new.consent_record_id
      and v.id=new.object_id and new.object_type='secretary_support_version'
      and v.organization_id=new.organization_id and v.board_id=new.board_id
      and v.created_by=new.actor_member_id and v.version=new.object_version
      and encode(v.canonical_sha256,'hex')=convert_from(new.canonical_payload,'UTF8')::jsonb->'details'->>'contentSha256') then
   raise exception 'publication audit lacks matching committed support version' using errcode='42501';
  end if;
 elsif new.event_type='onboarding_terms_published' then
  if not exists(select 1 from public.onboarding_terms_versions v
    where v.publication_audit_event_id=new.id and v.publication_consent_record_id=new.consent_record_id
      and v.id=new.object_id and new.object_type='onboarding_terms_version'
      and v.organization_id=new.organization_id and new.board_id is null
      and v.created_by=new.actor_member_id and v.version=new.object_version
      and encode(v.canonical_sha256,'hex')=convert_from(new.canonical_payload,'UTF8')::jsonb->'details'->>'contentSha256') then
   raise exception 'publication audit lacks matching committed terms version' using errcode='42501';
  end if;
 end if;
 return new;
end $$;
alter function public.boardagent_guard_onboarding_publication_audit() owner to boardagent_migrator;
revoke all on function public.boardagent_guard_onboarding_publication_audit() from public;
create constraint trigger boardagent_onboarding_publication_audit_required
 after insert on public.audit_events deferrable initially deferred for each row
 when (new.event_type in ('secretary_support_published','onboarding_terms_published'))
 execute function public.boardagent_guard_onboarding_publication_audit();
