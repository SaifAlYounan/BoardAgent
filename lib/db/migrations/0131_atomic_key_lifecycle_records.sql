-- Initial atomic lifecycle lane: evidence-signing retirement and compromise.
-- Other operations refuse until their purpose-specific effects are installed.
create table public.key_lifecycle_operations (
  id uuid primary key check (public.boardagent_is_uuid_v7(id)),
  instance_id uuid not null references public.system_instance(instance_id) on delete restrict,
  organization_id uuid not null references public.organizations(id) on delete restrict,
  key_id uuid not null references public.crypto_key_registry(id) on delete restrict,
  canonical_request bytea not null check (octet_length(canonical_request) between 2 and 262144),
  request_sha256 bytea not null check (octet_length(request_sha256)=32),
  canonical_inventory bytea not null check (octet_length(canonical_inventory) between 2 and 262144),
  details jsonb not null,
  recorded_at timestamptz not null,
  authorizing_principal text not null,
  authorization_transaction_id xid8 not null,
  authorization_server_start timestamptz not null
);
create table public.key_lifecycle_completions (
  operation_id uuid primary key references public.key_lifecycle_operations(id) on delete restrict,
  audit_event_id uuid not null unique references public.audit_events(id) on delete restrict,
  completed_at timestamptz not null
);
alter table public.key_lifecycle_operations owner to boardagent_migrator;
alter table public.key_lifecycle_completions owner to boardagent_migrator;
alter table public.key_lifecycle_operations enable row level security;
alter table public.key_lifecycle_operations force row level security;
alter table public.key_lifecycle_completions enable row level security;
alter table public.key_lifecycle_completions force row level security;
revoke all on public.key_lifecycle_operations,public.key_lifecycle_completions from public;
grant select on public.key_lifecycle_operations,public.key_lifecycle_completions to boardagent_backup;
create policy boardagent_migrator_key_dependency_snapshot on public.key_lifecycle_operations
  for select to boardagent_migrator using (current_setting('boardagent.transaction_scope',true)='bootstrap');
create policy boardagent_migrator_key_operation_insert on public.key_lifecycle_operations
  for insert to boardagent_migrator with check (current_setting('boardagent.transaction_scope',true)='bootstrap');
create policy boardagent_migrator_key_completion_read on public.key_lifecycle_completions
  for select to boardagent_migrator using (current_setting('boardagent.transaction_scope',true)='bootstrap');
create policy boardagent_migrator_key_completion_insert on public.key_lifecycle_completions
  for insert to boardagent_migrator with check (current_setting('boardagent.transaction_scope',true)='bootstrap');
create policy boardagent_backup_key_operation_read on public.key_lifecycle_operations for select to boardagent_backup using (true);
create policy boardagent_backup_key_completion_read on public.key_lifecycle_completions for select to boardagent_backup using (true);
create trigger boardagent_immutable before update or delete on public.key_lifecycle_operations
  for each row execute function public.boardagent_reject_evidence_mutation();
create trigger boardagent_immutable before update or delete on public.key_lifecycle_completions
  for each row execute function public.boardagent_reject_evidence_mutation();

create function public.boardagent_evidence_key_lifecycle_state(candidate_key_id uuid)
returns jsonb language plpgsql stable security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare k public.crypto_key_registry%rowtype; fingerprint text;
begin
  select key.* into k from public.crypto_key_registry key where key.id=candidate_key_id;
  if k.id is null or k.purpose<>'evidence_signing' or k.algorithm<>'EdDSA'
    or k.public_jwk is null or jsonb_typeof(k.public_jwk)<>'object'
    or not k.public_jwk ?& array['kty','crv','x']
    or k.public_jwk-array['kty','crv','x']<>'{}'::jsonb
    or k.public_jwk->>'kty'<>'OKP' or k.public_jwk->>'crv'<>'Ed25519'
    or k.public_jwk->>'x'!~'^[A-Za-z0-9_-]{43}$' then
    raise exception 'invalid evidence key identity' using errcode='55000';
  end if;
  fingerprint:=encode(sha256(convert_to(format('{"crv":"Ed25519","kty":"OKP","x":"%s"}',k.public_jwk->>'x'),'UTF8')),'hex');
  return jsonb_build_object('keyId',k.id,'kid',k.kid,'algorithm',k.algorithm,
    'publicMaterialSha256',fingerprint,
    'activatedAt',to_char(k.activated_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'retiredAt',to_char(k.retired_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'compromisedAt',to_char(k.compromised_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
end;
$$;
alter function public.boardagent_evidence_key_lifecycle_state(uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_evidence_key_lifecycle_state(uuid) from public;

-- Check the complete original row as well as the declared lifecycle fields. Rebuild
-- only its two intentionally changed timestamps before comparing the prepared hash.
create function public.boardagent_key_lifecycle_state_matches(candidate_operation_id uuid)
returns boolean language plpgsql stable security definer
set search_path=pg_catalog,public,pg_temp
set timezone='UTC'
set datestyle='ISO,YMD'
set intervalstyle='iso_8601'
set bytea_output='hex'
set extra_float_digits=3
as $$
declare op public.key_lifecycle_operations%rowtype; key_row public.crypto_key_registry%rowtype; original jsonb;
begin
  select stored.* into op from public.key_lifecycle_operations stored where stored.id=candidate_operation_id;
  if op.id is null then return false; end if;
  select k.* into key_row from public.crypto_key_registry k where k.id=op.key_id;
  if key_row.id is null or public.boardagent_evidence_key_lifecycle_state(op.key_id) is distinct from op.details->'after' then
    return false;
  end if;
  original:=to_jsonb(key_row)||jsonb_build_object(
    'retired_at',(op.details#>>'{before,retiredAt}')::timestamptz,
    'compromised_at',(op.details#>>'{before,compromisedAt}')::timestamptz);
  return encode(sha256(convert_to(original::text,'UTF8')),'hex')=
    convert_from(op.canonical_request,'UTF8')::jsonb#>>'{expectedInventory,keyDependencies,keyStateSha256}';
end;
$$;
alter function public.boardagent_key_lifecycle_state_matches(uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_key_lifecycle_state_matches(uuid) from public;

create function public.boardagent_guard_key_lifecycle_authorization()
returns trigger language plpgsql security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare
  request jsonb; inventory jsonb; previous jsonb; following jsonb;
  fields text[]:=array['instanceId','organizationId','keyId','operationId','operation','replacement',
    'declaredCompromisedAt','retainedMaterialSha256','operatorReference','reason','schemaVersion',
    'purpose','expectedKey','expectedInventory','preparedAt','expiresAt'];
  declared timestamptz;
  recorded text:=to_char(transaction_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"');
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'bootstrap'
    or current_setting('transaction_isolation') is distinct from 'serializable'
    or current_setting('transaction_read_only') is distinct from 'off' then
    raise exception 'key lifecycle requires a serializable operator transaction' using errcode='25000';
  end if;
  begin
    if new.canonical_request is null or octet_length(new.canonical_request) not between 2 and 262144
      or new.request_sha256 is distinct from sha256(new.canonical_request)
      or new.canonical_inventory is null or octet_length(new.canonical_inventory) not between 2 and 262144
      or not (convert_from(new.canonical_request,'UTF8') is json object with unique keys)
      or not (convert_from(new.canonical_inventory,'UTF8') is json object with unique keys) then
      raise exception 'invalid request';
    end if;
    request:=convert_from(new.canonical_request,'UTF8')::jsonb;
    if jsonb_typeof(request)<>'object' or not request ?& fields or request-fields<>'{}'::jsonb
      or request->>'schemaVersion'<>'boardagent.key-lifecycle-request.v1'
      or request->>'purpose'<>'evidence_signing'
      or request->>'operation' not in ('retire','mark_compromised')
      or request->'replacement'<>'null'::jsonb
      or request->>'operationId' is distinct from new.id::text
      or request->>'retainedMaterialSha256'!~'^[0-9a-f]{64}$'
      or exists(select 1 from jsonb_each(request) field where field.key not in
        ('replacement','declaredCompromisedAt','expectedKey','expectedInventory') and jsonb_typeof(field.value)<>'string')
      or length(request->>'operatorReference') not between 1 and 512
      or length(request->>'reason') not between 1 and 4096
      or request->>'operatorReference'<>btrim(request->>'operatorReference')
      or request->>'reason'<>btrim(request->>'reason')
      or request->>'operatorReference'~'[[:cntrl:]]' or request->>'reason'~'[[:cntrl:]]'
      or request->>'operatorReference'<>normalize(request->>'operatorReference',NFC)
      or request->>'reason'<>normalize(request->>'reason',NFC) then
      raise exception 'unsupported or invalid lifecycle request';
    end if;
    new.instance_id:=(request->>'instanceId')::uuid;
    new.organization_id:=(request->>'organizationId')::uuid;
    new.key_id:=(request->>'keyId')::uuid;
    if not public.boardagent_is_uuid_v7(new.id)
      or convert_from(new.canonical_inventory,'UTF8')::jsonb
        is distinct from ((request->'expectedInventory') #- '{keyDependencies,observedAt}') then
      raise exception 'invalid inventory';
    end if;
  exception when others then
    raise exception 'key lifecycle request is invalid or unsupported' using errcode='55000';
  end;
  inventory:=public.boardagent_lock_key_maintenance_snapshot(new.instance_id,new.organization_id,new.key_id,
    request->'expectedInventory',request->>'preparedAt',request->>'expiresAt');
  previous:=public.boardagent_evidence_key_lifecycle_state(new.key_id);
  if previous is distinct from request->'expectedKey' or request->>'preparedAt'>recorded
    or exists(select 1 from jsonb_array_elements(inventory->'groups') g
      where g->>'name' in ('closing_votes','live_vote_close_stages','unfinished_vote_outcomes',
        'leased_jobs','leased_notifications','running_exports') and g->>'rowCount'<>'0') then
    raise exception 'key lifecycle has changed facts or unfinished signing work' using errcode='55000';
  end if;
  following:=previous;
  if request->>'operation'='retire' then
    if previous->'retiredAt'<>'null'::jsonb or request->'declaredCompromisedAt'<>'null'::jsonb then
      raise exception 'key is already retired or retirement request is invalid' using errcode='55000';
    end if;
    following:=jsonb_set(following,'{retiredAt}',to_jsonb(recorded));
  else
    begin
      declared:=(request->>'declaredCompromisedAt')::timestamptz;
      if declared is null or request->>'declaredCompromisedAt'<>
        to_char(declared at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
        or request->>'declaredCompromisedAt'<previous->>'activatedAt'
        or request->>'declaredCompromisedAt'>request->>'preparedAt'
        or (previous->'compromisedAt'<>'null'::jsonb and request->>'declaredCompromisedAt'>=previous->>'compromisedAt') then
        raise exception 'invalid compromise time';
      end if;
    exception when others then
      raise exception 'invalid compromise time' using errcode='55000';
    end;
    following:=jsonb_set(following,'{compromisedAt}',request->'declaredCompromisedAt');
  end if;
  new.recorded_at:=transaction_timestamp();
  new.authorizing_principal:=session_user;
  new.authorization_transaction_id:=pg_current_xact_id();
  new.authorization_server_start:=pg_postmaster_start_time();
  new.details:=jsonb_build_object('schemaVersion','boardagent.key-lifecycle-changed.v1',
    'operationId',new.id,'requestSha256',encode(new.request_sha256,'hex'),
    'instanceId',new.instance_id,'organizationId',new.organization_id,'purpose','evidence_signing',
    'operation',request->>'operation','before',previous,'after',following,'replacement',null,
    'recordedAt',recorded,'declaredCompromisedAt',request->'declaredCompromisedAt',
    'dependencyStateSha256',encode(sha256(new.canonical_inventory),'hex'),
    'retainedMaterialSha256',request->>'retainedMaterialSha256',
    'operatorReference',request->>'operatorReference','reason',request->>'reason',
    'effects',jsonb_build_object('revokedSessions','0','revokedRefreshFamilies','0','cancelledStages','0',
      'affectedTotp','0','disabledWebhooks','0','rewrappedWebhooks','0'));
  return new;
end;
$$;
alter function public.boardagent_guard_key_lifecycle_authorization() owner to boardagent_migrator;
revoke all on function public.boardagent_guard_key_lifecycle_authorization() from public;
create trigger boardagent_key_lifecycle_authorize before insert on public.key_lifecycle_operations
  for each row execute function public.boardagent_guard_key_lifecycle_authorization();

create function public.boardagent_begin_key_lifecycle(candidate_request bytea,candidate_sha256 bytea,candidate_inventory bytea)
returns table(operation_id uuid,replayed boolean,details jsonb)
language plpgsql volatile security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare candidate_id uuid; stored public.key_lifecycle_operations%rowtype;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'bootstrap'
    or current_setting('transaction_isolation') is distinct from 'serializable'
    or current_setting('transaction_read_only') is distinct from 'off' then
    raise exception 'key lifecycle requires a serializable operator transaction' using errcode='25000';
  end if;
  begin
    if candidate_request is null or octet_length(candidate_request) not between 2 and 262144
      or candidate_sha256 is distinct from sha256(candidate_request) then raise exception 'invalid request'; end if;
    candidate_id:=(convert_from(candidate_request,'UTF8')::jsonb->>'operationId')::uuid;
  exception when others then
    raise exception 'invalid key lifecycle request' using errcode='55000';
  end;
  perform 1 from public.audit_chain_head where singleton_key for update;
  select op.* into stored from public.key_lifecycle_operations op where op.id=candidate_id;
  if stored.id is not null then
    if stored.canonical_request is distinct from candidate_request or stored.request_sha256 is distinct from candidate_sha256
      or stored.canonical_inventory is distinct from candidate_inventory
      or not exists(select 1 from public.key_lifecycle_completions c where c.operation_id=stored.id) then
      raise exception 'key operation identifier belongs to a different or incomplete operation' using errcode='55000';
    end if;
    return query select stored.id,true,stored.details; return;
  end if;
  insert into public.key_lifecycle_operations(id,canonical_request,request_sha256,canonical_inventory)
    values(candidate_id,candidate_request,candidate_sha256,candidate_inventory) returning * into stored;
  update public.crypto_key_registry set
    retired_at=(stored.details#>>'{after,retiredAt}')::timestamptz,
    compromised_at=(stored.details#>>'{after,compromisedAt}')::timestamptz where id=stored.key_id;
  if not found then raise exception 'key transition did not apply' using errcode='55000'; end if;
  return query select stored.id,false,stored.details;
end;
$$;
alter function public.boardagent_begin_key_lifecycle(bytea,bytea,bytea) owner to boardagent_migrator;
revoke all on function public.boardagent_begin_key_lifecycle(bytea,bytea,bytea) from public;
grant execute on function public.boardagent_begin_key_lifecycle(bytea,bytea,bytea) to boardagent_migrator;

create function public.boardagent_guard_key_lifecycle_audit()
returns trigger language plpgsql security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare op public.key_lifecycle_operations%rowtype; body jsonb;
begin
  if new.event_type<>'key_lifecycle_changed' then return new; end if;
  select stored.* into op from public.key_lifecycle_operations stored where stored.id=new.object_id;
  body:=convert_from(new.canonical_payload,'UTF8')::jsonb;
  if current_setting('boardagent.transaction_scope',true) is distinct from 'bootstrap'
    or op.id is null or op.authorization_transaction_id<>pg_current_xact_id()
    or op.authorization_server_start<>pg_postmaster_start_time()
    or new.organization_id<>op.organization_id or new.object_type<>'key_lifecycle_operation'
    or new.actor_member_id is not null or new.acting_for_member_id is not null
    or new.client_id is not null or new.token_jti is not null or new.board_id is not null
    or new.consent_record_id is not null or new.object_version is not null
    or new.occurred_at<>op.recorded_at or body->>'origin' is distinct from 'cli'
    or body->>'entityId' is distinct from op.id::text or body->'details' is distinct from op.details
    or new.sequence<>(convert_from(op.canonical_request,'UTF8')::jsonb#>>'{expectedInventory,keyDependencies,auditHead,sequence}')::bigint+1
    or public.boardagent_key_lifecycle_state_matches(op.id) is distinct from true then
    raise exception 'key lifecycle audit lacks the exact applied operator transaction' using errcode='23514';
  end if;
  return new;
end;
$$;
alter function public.boardagent_guard_key_lifecycle_audit() owner to boardagent_migrator;
revoke all on function public.boardagent_guard_key_lifecycle_audit() from public;
create trigger boardagent_key_lifecycle_audit before insert on public.audit_events
  for each row execute function public.boardagent_guard_key_lifecycle_audit();

create function public.boardagent_guard_key_lifecycle_completion()
returns trigger language plpgsql security definer
set search_path=pg_catalog,public,pg_temp
as $$
declare op public.key_lifecycle_operations%rowtype; event public.audit_events%rowtype;
begin
  select stored.* into op from public.key_lifecycle_operations stored where stored.id=new.operation_id;
  select stored.* into event from public.audit_events stored where stored.id=new.audit_event_id;
  if current_setting('boardagent.transaction_scope',true) is distinct from 'bootstrap'
    or op.id is null or op.authorization_transaction_id<>pg_current_xact_id()
    or op.authorization_server_start<>pg_postmaster_start_time()
    or event.id is null or event.event_type<>'key_lifecycle_changed' or event.object_id<>op.id
    or convert_from(event.canonical_payload,'UTF8')::jsonb->'details' is distinct from op.details
    or public.boardagent_key_lifecycle_state_matches(op.id) is distinct from true then
    raise exception 'key lifecycle completion lacks the exact audited change' using errcode='23514';
  end if;
  new.completed_at:=clock_timestamp(); return new;
end;
$$;
alter function public.boardagent_guard_key_lifecycle_completion() owner to boardagent_migrator;
revoke all on function public.boardagent_guard_key_lifecycle_completion() from public;
create trigger boardagent_key_lifecycle_complete before insert on public.key_lifecycle_completions
  for each row execute function public.boardagent_guard_key_lifecycle_completion();

create function public.boardagent_require_key_lifecycle_completion()
returns trigger language plpgsql security definer
set search_path=pg_catalog,public,pg_temp
as $$
begin
  if not exists(select 1 from public.key_lifecycle_completions c where c.operation_id=new.id)
    or public.boardagent_key_lifecycle_state_matches(new.id) is distinct from true then
    raise exception 'unfinished key lifecycle cannot commit' using errcode='23514';
  end if;
  return null;
end;
$$;
alter function public.boardagent_require_key_lifecycle_completion() owner to boardagent_migrator;
revoke all on function public.boardagent_require_key_lifecycle_completion() from public;
create constraint trigger boardagent_key_lifecycle_must_complete after insert on public.key_lifecycle_operations
  deferrable initially deferred for each row execute function public.boardagent_require_key_lifecycle_completion();

-- Extend the exact prior event catalog only with the protected lifecycle event.
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
  'key_lifecycle_changed'
));
