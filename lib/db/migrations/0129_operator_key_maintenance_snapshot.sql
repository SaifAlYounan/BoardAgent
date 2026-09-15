-- Share the exact inventory implementation between read-only preparation and
-- serializable operator application. This changes no key and grants no runtime access.

create function public.boardagent_snapshot_key_dependencies(
  candidate_instance_id uuid,candidate_organization_id uuid,candidate_key_id uuid
) returns jsonb
language plpgsql stable security definer
set search_path=pg_catalog,public,pg_temp
set timezone='UTC'
set datestyle='ISO,YMD'
set intervalstyle='iso_8601'
set bytea_output='hex'
set extra_float_digits=3
as $$
declare
  instance_row public.system_instance%rowtype;
  key_row public.crypto_key_registry%rowtype;
  head public.audit_chain_head%rowtype;
  dependency record;
  row_digest record;
  key_attribute smallint;
  dependency_count integer:=0;
  reference_count bigint;
  total_references bigint:=0;
  chain bytea;
  facts jsonb:='[]'::jsonb;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'bootstrap'
    or current_setting('transaction_isolation') is distinct from 'serializable' then
    raise exception 'key snapshot requires a serializable operator transaction'
      using errcode='25000';
  end if;
  select instance.* into instance_row from public.system_instance instance
    where instance.singleton_key and instance.instance_id=candidate_instance_id
      and instance.organization_id=candidate_organization_id;
  select key.* into key_row from public.crypto_key_registry key
    where key.id=candidate_key_id and key.organization_id=candidate_organization_id;
  if instance_row.instance_id is null or key_row.id is null then
    raise exception 'key inspection target does not match the installation' using errcode='23503';
  end if;
  select audit.* into head from public.audit_chain_head audit where audit.singleton_key;
  if head.last_sequence is null then
    raise exception 'key inspection audit head unavailable' using errcode='55000';
  end if;
  select attnum into key_attribute from pg_attribute
    where attrelid='public.crypto_key_registry'::regclass and attname='id' and not attisdropped;
  for dependency in
    select distinct namespace.nspname collate "C" as schema_name,relation.relname collate "C" as table_name,
      attribute.attname collate "C" as column_name,relation.oid as relation_id
    from pg_constraint constraint_row
    join pg_class relation on relation.oid=constraint_row.conrelid
    join pg_namespace namespace on namespace.oid=relation.relnamespace
    join pg_attribute attribute on attribute.attrelid=relation.oid
      and attribute.attnum=constraint_row.conkey[array_position(constraint_row.confkey,key_attribute)]
    where constraint_row.contype='f'
      and constraint_row.confrelid='public.crypto_key_registry'::regclass
      and key_attribute=any(constraint_row.confkey)
    order by schema_name,table_name,column_name,relation_id
  loop
    dependency_count:=dependency_count+1;
    if dependency_count>256 then
      raise exception 'key dependency catalog exceeds supported inventory capacity' using errcode='54000';
    end if;
    if dependency.schema_name<>'public' or not exists (
      select 1 from pg_policy policy
      where policy.polrelid=dependency.relation_id
        and policy.polname='boardagent_migrator_key_dependency_snapshot'
        and policy.polcmd='r' and 'boardagent_migrator'::regrole=any(policy.polroles)
    ) then
      raise exception 'key dependency lacks an explicit operator inventory policy' using errcode='55000';
    end if;
    execute format(
      'select count(*) from (select 1 from public.%I where %I=$1 limit $2) limited',
      dependency.table_name,dependency.column_name
    ) into reference_count using candidate_key_id,1000001-total_references;
    if total_references+reference_count>1000000 then
      raise exception 'key references exceed supported inventory capacity' using errcode='54000';
    end if;
    total_references:=total_references+reference_count;
    chain:=decode(repeat('00',32),'hex');
    for row_digest in execute format(
      'select sha256(convert_to(to_jsonb(record)::text,''UTF8'')) as digest from public.%I record where %I=$1 order by digest',
      dependency.table_name,dependency.column_name
    ) using candidate_key_id loop
      chain:=sha256(chain||row_digest.digest);
    end loop;
    facts:=facts||jsonb_build_array(jsonb_build_object(
      'table',dependency.table_name,'column',dependency.column_name,
      'rowCount',reference_count::text,'rowsSha256',encode(chain,'hex')
    ));
  end loop;
  return jsonb_build_object(
    'schemaVersion','boardagent.key-dependency-inspection.v1',
    'digestMethod','postgresql18-jsonb-row-sha256-chain-v1',
    'instanceId',instance_row.instance_id,'organizationId',instance_row.organization_id,
    'keyId',key_row.id,'keyPurpose',key_row.purpose,
    'keyStateSha256',encode(sha256(convert_to(to_jsonb(key_row)::text,'UTF8')),'hex'),
    'observedAt',to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'auditHead',jsonb_build_object('sequence',head.last_sequence::text,'sha256',encode(head.last_event_sha256,'hex')),
    'foreignKeyDependencies',facts,'totalReferences',total_references::text
  );
end;
$$;

alter function public.boardagent_snapshot_key_dependencies(uuid,uuid,uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_snapshot_key_dependencies(uuid,uuid,uuid) from public;
grant execute on function public.boardagent_snapshot_key_dependencies(uuid,uuid,uuid) to boardagent_migrator;

create or replace function public.boardagent_inspect_key_dependencies(
  candidate_instance_id uuid,candidate_organization_id uuid,candidate_key_id uuid
) returns jsonb
language plpgsql stable security definer
set search_path=pg_catalog,public,pg_temp
as $$
begin
  if current_setting('transaction_read_only') is distinct from 'on' then
    raise exception 'key inspection requires a serializable read-only operator transaction' using errcode='25000';
  end if;
  return public.boardagent_snapshot_key_dependencies(candidate_instance_id,candidate_organization_id,candidate_key_id);
end;
$$;
alter function public.boardagent_inspect_key_dependencies(uuid,uuid,uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_inspect_key_dependencies(uuid,uuid,uuid) from public;
grant execute on function public.boardagent_inspect_key_dependencies(uuid,uuid,uuid) to boardagent_migrator;

create function public.boardagent_snapshot_key_maintenance_work(
  candidate_instance_id uuid,candidate_organization_id uuid,candidate_key_id uuid
) returns jsonb
language plpgsql stable security definer
set search_path=pg_catalog,public,pg_temp
set timezone='UTC'
set datestyle='ISO,YMD'
set intervalstyle='iso_8601'
set bytea_output='hex'
set extra_float_digits=3
as $$
declare
  dependency_inventory jsonb;
  work record;
  row_digest record;
  total_references bigint:=0;
  reference_count bigint;
  chain bytea;
  groups jsonb:='[]'::jsonb;
begin
  -- Reuse exact target, purpose, operator, snapshot-mode and unknown-FK policy checks.
  dependency_inventory:=public.boardagent_snapshot_key_dependencies(
    candidate_instance_id,candidate_organization_id,candidate_key_id);
  for work in select * from (values
    ('active_contact_points',$query$select to_jsonb(c) as value from public.member_contact_points c where c.organization_id=$1 and c.key_id=$2 and c.state='active'$query$),
    ('active_totp',$query$select to_jsonb(t) as value from public.totp_credentials t where t.organization_id=$1 and t.key_id=$2 and t.state='active'$query$),
    ('active_webhooks',$query$select to_jsonb(w) as value from public.member_webhooks w where w.organization_id=$1 and w.key_id=$2 and w.state='active'$query$),
    ('affected_refresh_families',$query$select to_jsonb(f) as value from public.refresh_families f where f.organization_id=$1 and f.state='active' and ($3='browser_session' or ($3='oauth_signing' and exists(select 1 from public.access_token_records a where a.refresh_family_id=f.id and a.signing_key_id=$2)))$query$),
    ('browser_action_stages',$query$select to_jsonb(s) as value from public.action_stages s where s.organization_id=$1 and $3='browser_session' and s.state='active'$query$),
    ('browser_authorization_requests',$query$select to_jsonb(a) as value from public.oauth_authorization_requests a where a.organization_id=$1 and $3='browser_session' and a.request_state in ('pending','approved')$query$),
    ('browser_sessions',$query$select to_jsonb(s) as value from public.auth_sessions s where s.organization_id=$1 and $3='browser_session' and s.state in ('anonymous','authenticated')$query$),
    ('closing_votes',$query$select to_jsonb(v) as value from public.votes v where v.organization_id=$1 and v.state='closing' and $3='evidence_signing'$query$),
    ('leased_jobs',$query$select to_jsonb(j) as value from public.jobs j where j.organization_id=$1 and j.state='leased'$query$),
    ('leased_notifications',$query$select to_jsonb(n) as value from public.notification_jobs n where n.organization_id=$1 and n.state='leased'$query$),
    ('live_vote_close_stages',$query$select jsonb_build_object('material',to_jsonb(m),'stage',to_jsonb(s)) as value from public.vote_close_stage_material m join public.action_stages s on s.id=m.stage_id where m.organization_id=$1 and m.signing_key_id=$2 and s.state='active' and s.expires_at>transaction_timestamp()$query$),
    ('pending_exports',$query$select to_jsonb(e) as value from public.export_requests e where e.organization_id=$1 and e.state in ('confirmed','queued')$query$),
    ('pending_totp',$query$select to_jsonb(t) as value from public.totp_credentials t where t.organization_id=$1 and t.key_id=$2 and t.state='pending_verification'$query$),
    ('running_exports',$query$select to_jsonb(e) as value from public.export_requests e where e.organization_id=$1 and e.state='running'$query$),
    ('unfinished_jobs',$query$select to_jsonb(j) as value from public.jobs j where j.organization_id=$1 and j.state in ('queued','retry')$query$),
    ('unfinished_vote_outcomes',$query$select jsonb_build_object('outcome',to_jsonb(o),'vote',to_jsonb(v)) as value from public.vote_outcomes o join public.votes v on v.id=o.vote_id where o.organization_id=$1 and o.signing_key_id=$2 and (v.state='closing' or not exists(select 1 from public.vote_certificates c where c.id=o.certificate_id))$query$)
  ) as facts(name,query_text) order by name collate "C" loop
    execute 'select count(*) from ('||work.query_text||' limit $4) bounded'
      into reference_count using candidate_organization_id,candidate_key_id,
        dependency_inventory->>'keyPurpose',1000001-total_references;
    if total_references+reference_count>1000000 then
      raise exception 'key maintenance work exceeds supported inventory capacity' using errcode='54000';
    end if;
    total_references:=total_references+reference_count;
    chain:=decode(repeat('00',32),'hex');
    for row_digest in execute
      'select sha256(convert_to(value::text,''UTF8'')) as digest from ('||work.query_text||') selected order by digest'
      using candidate_organization_id,candidate_key_id,dependency_inventory->>'keyPurpose'
    loop
      chain:=sha256(chain||row_digest.digest);
    end loop;
    groups:=groups||jsonb_build_array(jsonb_build_object(
      'name',work.name,'rowCount',reference_count::text,'rowsSha256',encode(chain,'hex')));
  end loop;
  return jsonb_build_object('schemaVersion','boardagent.key-maintenance-work.v1',
    'keyDependencies',dependency_inventory,'groups',groups,
    'totalWorkReferences',total_references::text);
end;
$$;

alter function public.boardagent_snapshot_key_maintenance_work(uuid,uuid,uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_snapshot_key_maintenance_work(uuid,uuid,uuid) from public;
grant execute on function public.boardagent_snapshot_key_maintenance_work(uuid,uuid,uuid) to boardagent_migrator;

create or replace function public.boardagent_inspect_key_maintenance_work(
  candidate_instance_id uuid,candidate_organization_id uuid,candidate_key_id uuid
) returns jsonb
language plpgsql stable security definer
set search_path=pg_catalog,public,pg_temp
as $$
begin
  if current_setting('transaction_read_only') is distinct from 'on' then
    raise exception 'key inspection requires a serializable read-only operator transaction' using errcode='25000';
  end if;
  return public.boardagent_snapshot_key_maintenance_work(candidate_instance_id,candidate_organization_id,candidate_key_id);
end;
$$;
alter function public.boardagent_inspect_key_maintenance_work(uuid,uuid,uuid) owner to boardagent_migrator;
revoke all on function public.boardagent_inspect_key_maintenance_work(uuid,uuid,uuid) from public;
grant execute on function public.boardagent_inspect_key_maintenance_work(uuid,uuid,uuid) to boardagent_migrator;
