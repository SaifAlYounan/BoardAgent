-- BoardAgent Phase 4: bounded worker-only expiry and retention authority.
-- Governance and evidentiary records are deliberately absent from this function.

-- FORCE RLS applies to the definer owner too. These policies are deliberately scoped
-- to the managed worker transaction marker; the runtime role still has no table grant.
do $worker_maintenance_read_policies$
declare
  maintained_table text;
begin
  foreach maintained_table in array array[
    'action_stages','wizard_drafts','auth_sessions','oauth_authorization_requests',
    'oauth_authorization_codes','enrollment_activation_challenges',
    'onboarding_browser_stages','webauthn_challenges','oidc_login_transactions',
    'refresh_families','refresh_tokens','access_token_records','rate_limit_buckets'
  ]
  loop
    execute format(
      'create policy boardagent_migrator_worker_maintenance_read on public.%I for select to boardagent_migrator using (current_setting(''boardagent.transaction_scope'',true)=''worker'')',
      maintained_table
    );
  end loop;
end
$worker_maintenance_read_policies$;

create policy boardagent_migrator_worker_maintenance on public.action_stages
  for update to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='worker')
  with check (current_setting('boardagent.transaction_scope',true)='worker');
create policy boardagent_migrator_worker_maintenance on public.wizard_drafts
  for update to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='worker')
  with check (current_setting('boardagent.transaction_scope',true)='worker');
create policy boardagent_migrator_worker_maintenance on public.auth_sessions
  for update to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='worker')
  with check (current_setting('boardagent.transaction_scope',true)='worker');
create policy boardagent_migrator_worker_maintenance on public.oauth_authorization_requests
  for update to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='worker')
  with check (current_setting('boardagent.transaction_scope',true)='worker');
create policy boardagent_migrator_worker_maintenance on public.oauth_authorization_codes
  for update to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='worker')
  with check (current_setting('boardagent.transaction_scope',true)='worker');
create policy boardagent_migrator_worker_maintenance on public.enrollment_activation_challenges
  for update to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='worker')
  with check (current_setting('boardagent.transaction_scope',true)='worker');
create policy boardagent_migrator_worker_maintenance on public.onboarding_browser_stages
  for update to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='worker')
  with check (current_setting('boardagent.transaction_scope',true)='worker');
create policy boardagent_migrator_worker_maintenance on public.webauthn_challenges
  for delete to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='worker');
create policy boardagent_migrator_worker_maintenance on public.oidc_login_transactions
  for delete to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='worker');
create policy boardagent_migrator_worker_maintenance on public.refresh_families
  for update to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='worker')
  with check (current_setting('boardagent.transaction_scope',true)='worker');
create policy boardagent_migrator_worker_maintenance on public.refresh_tokens
  for update to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='worker')
  with check (current_setting('boardagent.transaction_scope',true)='worker');
create policy boardagent_migrator_worker_maintenance on public.access_token_records
  for update to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='worker')
  with check (current_setting('boardagent.transaction_scope',true)='worker');
create policy boardagent_migrator_worker_maintenance on public.rate_limit_buckets
  for delete to boardagent_migrator
  using (current_setting('boardagent.transaction_scope',true)='worker');

create function public.boardagent_run_worker_maintenance(
  candidate_job_type text,
  candidate_organization_id uuid,
  candidate_limit integer
)
returns jsonb
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  affected integer;
  expired_sessions integer;
  expired_requests integer;
  revoked_codes integer;
  expired_challenges integer;
  expired_onboarding integer;
  deleted_webauthn integer;
  deleted_oidc integer;
  expired_families integer;
  revoked_refresh_tokens integer;
  revoked_access_tokens integer;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker' then
    raise exception 'worker maintenance requires a managed worker transaction'
      using errcode='25000';
  end if;
  if candidate_limit is null or candidate_limit not between 1 and 10000 then
    raise exception 'worker maintenance batch limit is invalid' using errcode='22023';
  end if;
  if not exists (
    select 1 from public.system_instance as instance
     where instance.singleton_key
       and instance.organization_id=candidate_organization_id
  ) then
    raise exception 'worker maintenance organization is unavailable' using errcode='42501';
  end if;

  if candidate_job_type='action_stage_expiry' then
    with due as (
      select stage.id from public.action_stages as stage
       where stage.organization_id=candidate_organization_id
         and stage.state='active'
         and stage.expires_at<=transaction_timestamp()
       order by stage.expires_at,stage.id
       for update skip locked
       limit candidate_limit
    )
    update public.action_stages as stage set state='expired'
     from due where stage.id=due.id;
    get diagnostics affected=row_count;
    return jsonb_build_object(
      'jobType','action_stage_expiry',
      'expiredStages',affected
    );
  elsif candidate_job_type='wizard_expiry' then
    with due as (
      select draft.id from public.wizard_drafts as draft
       where draft.organization_id=candidate_organization_id
         and draft.state in ('active','ready_to_confirm')
         and draft.expires_at<=transaction_timestamp()
       order by draft.expires_at,draft.id
       for update skip locked
       limit candidate_limit
    )
    update public.wizard_drafts as draft
       set state='expired',row_version=row_version+1
      from due where draft.id=due.id;
    get diagnostics affected=row_count;
    return jsonb_build_object(
      'jobType','wizard_expiry',
      'expiredDrafts',affected
    );
  elsif candidate_job_type='rate_bucket_retention' then
    with stale as (
      select bucket.bucket_class,bucket.subject_sha256,bucket.window_started_at
        from public.rate_limit_buckets as bucket
       where bucket.window_started_at+make_interval(secs=>bucket.window_seconds)
               <=transaction_timestamp()-interval '1 hour'
         and (bucket.blocked_until is null
              or bucket.blocked_until<=transaction_timestamp()-interval '1 hour')
       order by bucket.window_started_at,bucket.bucket_class,bucket.subject_sha256
       limit candidate_limit
    )
    delete from public.rate_limit_buckets as bucket
     using stale
     where bucket.bucket_class=stale.bucket_class
       and bucket.subject_sha256=stale.subject_sha256
       and bucket.window_started_at=stale.window_started_at;
    get diagnostics affected=row_count;
    return jsonb_build_object(
      'jobType','rate_bucket_retention',
      'deletedBuckets',affected
    );
  elsif candidate_job_type='oauth_ephemera_expiry' then
    with due as (
      select session.id from public.auth_sessions as session
       where session.organization_id=candidate_organization_id
         and session.state in ('anonymous','authenticated')
         and session.expires_at<=transaction_timestamp()
       order by session.expires_at,session.id
       for update skip locked limit candidate_limit
    )
    update public.auth_sessions as session set state='expired'
     from due where session.id=due.id;
    get diagnostics expired_sessions=row_count;

    with due as (
      select request.id from public.oauth_authorization_requests as request
       where request.organization_id=candidate_organization_id
         and request.request_state='pending'
         and request.expires_at<=transaction_timestamp()
       order by request.expires_at,request.id
       for update skip locked limit candidate_limit
    )
    update public.oauth_authorization_requests as request set request_state='expired'
     from due where request.id=due.id;
    get diagnostics expired_requests=row_count;

    with due as (
      select code.id from public.oauth_authorization_codes as code
       where code.organization_id=candidate_organization_id
         and code.consumed_at is null and code.revoked_at is null
         and code.expires_at<=transaction_timestamp()
       order by code.expires_at,code.id
       for update skip locked limit candidate_limit
    )
    update public.oauth_authorization_codes as code set revoked_at=transaction_timestamp()
     from due where code.id=due.id;
    get diagnostics revoked_codes=row_count;

    with due as (
      select challenge.id from public.enrollment_activation_challenges as challenge
       where challenge.organization_id=candidate_organization_id
         and challenge.state='issued'
         and challenge.expires_at<=transaction_timestamp()
       order by challenge.expires_at,challenge.id
       for update skip locked limit candidate_limit
    )
    update public.enrollment_activation_challenges as challenge set state='expired'
     from due where challenge.id=due.id;
    get diagnostics expired_challenges=row_count;

    with due as (
      select stage.id from public.onboarding_browser_stages as stage
       where stage.organization_id=candidate_organization_id
         and stage.state='active'
         and stage.expires_at<=transaction_timestamp()
       order by stage.expires_at,stage.id
       for update skip locked limit candidate_limit
    )
    update public.onboarding_browser_stages as stage set state='expired'
     from due where stage.id=due.id;
    get diagnostics expired_onboarding=row_count;

    with stale as (
      select challenge.id from public.webauthn_challenges as challenge
       where challenge.organization_id=candidate_organization_id
         and challenge.expires_at<=transaction_timestamp()-interval '1 hour'
       order by challenge.expires_at,challenge.id
       limit candidate_limit
    )
    delete from public.webauthn_challenges as challenge
     using stale where challenge.id=stale.id;
    get diagnostics deleted_webauthn=row_count;

    with stale as (
      select login.id from public.oidc_login_transactions as login
       where login.organization_id=candidate_organization_id
         and login.expires_at<=transaction_timestamp()-interval '1 hour'
       order by login.expires_at,login.id
       limit candidate_limit
    )
    delete from public.oidc_login_transactions as login
     using stale where login.id=stale.id;
    get diagnostics deleted_oidc=row_count;

    return jsonb_build_object(
      'jobType','oauth_ephemera_expiry',
      'expiredSessions',expired_sessions,
      'expiredAuthorizationRequests',expired_requests,
      'revokedAuthorizationCodes',revoked_codes,
      'expiredActivationChallenges',expired_challenges,
      'expiredOnboardingStages',expired_onboarding,
      'deletedWebauthnChallenges',deleted_webauthn,
      'deletedOidcTransactions',deleted_oidc
    );
  elsif candidate_job_type='refresh_session_revocation' then
    with due as (
      select family.id from public.refresh_families as family
       where family.organization_id=candidate_organization_id
         and family.state='active'
         and least(family.idle_expires_at,family.absolute_expires_at)<=transaction_timestamp()
       order by least(family.idle_expires_at,family.absolute_expires_at),family.id
       for update skip locked limit candidate_limit
    )
    update public.refresh_families as family
       set state='expired',revoked_at=transaction_timestamp()
      from due where family.id=due.id;
    get diagnostics expired_families=row_count;

    with due as (
      select token.id from public.refresh_tokens as token
      join public.refresh_families as family on family.id=token.family_id
       where family.organization_id=candidate_organization_id
         and family.state in ('revoked','compromised','expired')
         and token.used_at is null and token.revoked_at is null
       order by token.issued_at,token.id
       for update of token skip locked limit candidate_limit
    )
    update public.refresh_tokens as token set revoked_at=transaction_timestamp()
     from due where token.id=due.id;
    get diagnostics revoked_refresh_tokens=row_count;

    with due as (
      select token.id from public.access_token_records as token
       where token.organization_id=candidate_organization_id
         and token.revoked_at is null
         and (
           token.expires_at<=transaction_timestamp()
           or exists (
             select 1 from public.refresh_families as family
              where family.id=token.refresh_family_id
                and family.state in ('revoked','compromised','expired')
           )
         )
       order by token.expires_at,token.id
       for update skip locked limit candidate_limit
    )
    update public.access_token_records as token set revoked_at=transaction_timestamp()
     from due where token.id=due.id;
    get diagnostics revoked_access_tokens=row_count;

    return jsonb_build_object(
      'jobType','refresh_session_revocation',
      'expiredFamilies',expired_families,
      'revokedRefreshTokens',revoked_refresh_tokens,
      'revokedAccessTokens',revoked_access_tokens
    );
  end if;

  raise exception 'worker maintenance job type is unsupported' using errcode='22023';
end
$$;

alter function public.boardagent_run_worker_maintenance(text,uuid,integer)
  owner to boardagent_migrator;
revoke all on function public.boardagent_run_worker_maintenance(text,uuid,integer) from public;
grant execute on function public.boardagent_run_worker_maintenance(text,uuid,integer)
  to boardagent_worker;

-- The older one-argument scheduler is retained for migration compatibility. Runtime
-- workers use this board- and watermark-bound form so one forged scan cannot cross scope
-- or move a question whose due time was not part of the queued scan.
create function public.boardagent_mark_board_questions_overdue(
  candidate_organization_id uuid,
  candidate_board_id uuid,
  candidate_through timestamptz,
  candidate_limit integer
)
returns table(question_id uuid,board_id uuid,row_version bigint)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'worker' then
    raise exception 'board question scan requires a managed worker transaction'
      using errcode='25000';
  end if;
  if candidate_limit is null or candidate_limit not between 1 and 1000
     or candidate_through is null or candidate_through>transaction_timestamp() then
    raise exception 'board question scan watermark or limit is invalid' using errcode='22023';
  end if;
  if not exists (
    select 1 from public.system_instance as instance
    join public.boards as board
      on board.organization_id=instance.organization_id
     and board.id=candidate_board_id
   where instance.singleton_key
     and instance.organization_id=candidate_organization_id
  ) then
    raise exception 'board question scan target is unavailable' using errcode='42501';
  end if;
  return query
    with locked as materialized (
      select question.id
        from public.management_questions as question
       where question.organization_id=candidate_organization_id
         and question.board_id=candidate_board_id
         and question.state='pending'
         and question.due_at<=candidate_through
       order by question.due_at,question.id
       for update skip locked
       limit candidate_limit
    ), updated as (
      update public.management_questions as question
         set state='overdue',row_version=question.row_version+1
        from locked
       where question.id=locked.id and question.state='pending'
      returning question.id,question.board_id,question.row_version
    )
    select updated.id,updated.board_id,updated.row_version
      from updated order by updated.id;
end
$$;

alter function public.boardagent_mark_board_questions_overdue(uuid,uuid,timestamptz,integer)
  owner to boardagent_migrator;
revoke all on function public.boardagent_mark_board_questions_overdue(uuid,uuid,timestamptz,integer)
  from public;
grant execute on function public.boardagent_mark_board_questions_overdue(uuid,uuid,timestamptz,integer)
  to boardagent_worker;

-- Full audit verification is an explicit worker job. These are evidence/public-key
-- reads only; no worker update/delete authority is added.
grant select on public.system_instance,public.audit_chain_head,public.audit_events,
  public.audit_checkpoints,public.crypto_key_registry to boardagent_worker;

do $worker_audit_verify_policies$
declare
  evidence_table text;
begin
  foreach evidence_table in array array[
    'system_instance','audit_chain_head','audit_events','audit_checkpoints','crypto_key_registry'
  ]
  loop
    execute format(
      'create policy boardagent_worker_audit_verify on public.%I for select to boardagent_worker using (current_setting(''boardagent.transaction_scope'',true)=''worker'')',
      evidence_table
    );
  end loop;
end
$worker_audit_verify_policies$;
