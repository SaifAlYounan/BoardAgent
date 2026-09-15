-- BoardAgent Phase 2 / group 46: bounded CIMD and compatibility-DCR registration.
-- The server retains no raw INSERT grant on the normalized client tables. This one
-- definer serializes the organization cap and validates the complete insert shape.

create policy boardagent_migrator_identity_oauth_clients
  on public.oauth_clients for all to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='identity'
    and organization_id=public.boardagent_context_uuid('boardagent.organization_id')
  );

create policy boardagent_migrator_identity_oauth_client_redirects
  on public.oauth_client_redirect_uris for all to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='identity'
    and exists (
      select 1 from public.oauth_clients as client
       where client.id=oauth_client_redirect_uris.client_id
         and client.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    )
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='identity'
    and exists (
      select 1 from public.oauth_clients as client
       where client.id=oauth_client_redirect_uris.client_id
         and client.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    )
  );

create policy boardagent_migrator_identity_oauth_client_grants
  on public.oauth_client_grants for all to boardagent_migrator
  using (
    current_setting('boardagent.transaction_scope',true)='identity'
    and exists (
      select 1 from public.oauth_clients as client
       where client.id=oauth_client_grants.client_id
         and client.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    )
  )
  with check (
    current_setting('boardagent.transaction_scope',true)='identity'
    and exists (
      select 1 from public.oauth_clients as client
       where client.id=oauth_client_grants.client_id
         and client.organization_id=public.boardagent_context_uuid('boardagent.organization_id')
    )
  );

create function public.boardagent_register_oauth_client(
  candidate_organization_id uuid,
  candidate_internal_id uuid,
  candidate_protocol_id_kind text,
  candidate_protocol_id_value text,
  candidate_safe_metadata jsonb,
  candidate_metadata_sha256 bytea,
  candidate_redirect_uris text[],
  candidate_redirect_uri_sha256 bytea[],
  candidate_scopes text[],
  candidate_max_clients integer
)
returns table(result_internal_id uuid,result_inserted boolean)
language plpgsql
volatile
security definer
set search_path=pg_catalog,public
as $$
declare
  existing public.oauth_clients%rowtype;
  redirect_count integer;
  expected_registration_method text;
begin
  if current_setting('boardagent.transaction_scope',true) is distinct from 'identity'
     or candidate_organization_id
          is distinct from public.boardagent_context_uuid('boardagent.organization_id') then
    raise exception 'OAuth client registration requires the managed identity context'
      using errcode='25000';
  end if;
  if not public.boardagent_is_uuid_v7(candidate_internal_id)
     or candidate_protocol_id_kind not in ('verified_cimd_url','dcr_opaque')
     or candidate_protocol_id_value is null
     or length(candidate_protocol_id_value) not between 1 and 2048
     or octet_length(candidate_protocol_id_value) not between 1 and 2048
     or candidate_metadata_sha256 is null
     or octet_length(candidate_metadata_sha256)<>32
     or candidate_max_clients not between 1 and 10000 then
    raise exception 'invalid OAuth client registration binding' using errcode='22023';
  end if;
  if candidate_protocol_id_kind='verified_cimd_url' then
    if candidate_protocol_id_value !~ '^https://[a-z0-9][a-z0-9.-]*/[^?#[:space:]\\]*$'
       or candidate_protocol_id_value ~ '[@#?]'
       or candidate_protocol_id_value ~ '^https://[^/]*:' then
      raise exception 'invalid verified CIMD protocol identifier' using errcode='22023';
    end if;
    expected_registration_method := 'cimd';
  else
    if candidate_protocol_id_value !~ '^ba_dcr_[A-Za-z0-9_-]{43}$' then
      raise exception 'invalid DCR protocol identifier' using errcode='22023';
    end if;
    expected_registration_method := 'dcr';
  end if;

  if candidate_safe_metadata is null
     or jsonb_typeof(candidate_safe_metadata)<>'object'
     or candidate_safe_metadata->'schemaVersion' <> '1'::jsonb
     or candidate_safe_metadata->>'registrationMethod' is distinct from expected_registration_method
     or jsonb_typeof(candidate_safe_metadata->'name')<>'string'
     or length(candidate_safe_metadata->>'name') not between 1 and 120
     or exists (
       select 1 from jsonb_object_keys(candidate_safe_metadata) as property(name)
        where property.name not in ('schemaVersion','registrationMethod','name','softwareId')
     )
     or (
       candidate_safe_metadata ? 'softwareId'
       and (
         jsonb_typeof(candidate_safe_metadata->'softwareId')<>'string'
         or length(candidate_safe_metadata->>'softwareId') not between 1 and 200
       )
     ) then
    raise exception 'unsafe OAuth client display metadata shape' using errcode='22023';
  end if;

  redirect_count := cardinality(candidate_redirect_uris);
  if redirect_count not between 1 and 10
     or cardinality(candidate_redirect_uri_sha256)<>redirect_count
     or exists (
       select 1
         from unnest(candidate_redirect_uris,candidate_redirect_uri_sha256)
              as redirect(uri,digest)
        where redirect.uri is null
           or length(redirect.uri) not between 1 and 2048
           or octet_length(redirect.uri) not between 1 and 2048
           or redirect.uri ~ '[#[:space:]\\]'
           or redirect.digest is null
           or octet_length(redirect.digest)<>32
           or not (
             redirect.uri ~ '^https://[^/@]+(?:/|$)'
             or redirect.uri ~ '^http://127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]+(?:/|$)'
             or redirect.uri ~ '^http://\[::1\]:[0-9]+(?:/|$)'
             or redirect.uri ~ '^[a-z][a-z0-9-]*(\.[a-z0-9][a-z0-9-]*)+:/[^/].*$'
           )
     )
     or (select count(distinct uri) from unnest(candidate_redirect_uris) as supplied(uri))
          <>redirect_count
     or (select count(distinct encode(digest,'hex'))
           from unnest(candidate_redirect_uri_sha256) as supplied(digest))<>redirect_count then
    raise exception 'invalid OAuth redirect registration set' using errcode='22023';
  end if;

  if cardinality(candidate_scopes) not between 1 and 128
     or exists (
       select 1 from unnest(candidate_scopes) as supplied(scope)
        where supplied.scope is null
           or supplied.scope !~ '^[a-z][a-z0-9:_-]{0,127}$'
     )
     or (select count(distinct scope) from unnest(candidate_scopes) as supplied(scope))
          <>cardinality(candidate_scopes) then
    raise exception 'invalid OAuth client scope set' using errcode='22023';
  end if;

  perform pg_advisory_xact_lock(
    hashtextextended('oauth-client-registration:'||candidate_organization_id::text,424246)
  );
  select client.* into existing
    from public.oauth_clients as client
   where client.organization_id=candidate_organization_id
     and client.protocol_id_kind=candidate_protocol_id_kind
     and client.protocol_id_value=candidate_protocol_id_value
   for update;
  if found then
    if candidate_protocol_id_kind<>'verified_cimd_url'
       or existing.state<>'active'
       or existing.safe_metadata<>candidate_safe_metadata
       or existing.metadata_sha256<>candidate_metadata_sha256
       or (
         select count(*) from public.oauth_client_redirect_uris as redirect
          where redirect.client_id=existing.id
       )<>redirect_count
       or exists (
         select 1
           from unnest(candidate_redirect_uris,candidate_redirect_uri_sha256)
                as supplied(uri,digest)
          where not exists (
            select 1 from public.oauth_client_redirect_uris as stored
             where stored.client_id=existing.id
               and stored.redirect_uri=supplied.uri
               and stored.redirect_uri_sha256=supplied.digest
          )
       )
       or (
         select count(*) from public.oauth_client_grants as grant_row
          where grant_row.client_id=existing.id
       )<>2*cardinality(candidate_scopes)
       or exists (
         select 1
           from unnest(candidate_scopes) as supplied(scope)
          cross join (values ('authorization_code'),('refresh_token')) as required(grant_type)
          where not exists (
            select 1 from public.oauth_client_grants as stored
             where stored.client_id=existing.id
               and stored.grant_type=required.grant_type
               and stored.scope=supplied.scope
          )
       ) then
      raise exception 'OAuth client protocol identifier conflicts with existing authority'
        using errcode='23505';
    end if;
    result_internal_id := existing.id;
    result_inserted := false;
    return next;
    return;
  end if;

  if (select count(*) from public.oauth_clients as client
       where client.organization_id=candidate_organization_id)>=candidate_max_clients then
    raise exception 'OAuth client capacity reached' using errcode='54000';
  end if;

  insert into public.oauth_clients(
    id,organization_id,protocol_id_kind,protocol_id_value,
    safe_metadata,metadata_sha256,state,registered_by
  ) values (
    candidate_internal_id,candidate_organization_id,candidate_protocol_id_kind,
    candidate_protocol_id_value,candidate_safe_metadata,candidate_metadata_sha256,'active',null
  );
  insert into public.oauth_client_redirect_uris(client_id,redirect_uri,redirect_uri_sha256)
  select candidate_internal_id,supplied.uri,supplied.digest
    from unnest(candidate_redirect_uris,candidate_redirect_uri_sha256)
         as supplied(uri,digest);
  insert into public.oauth_client_grants(client_id,grant_type,scope)
  select candidate_internal_id,required.grant_type,supplied.scope
    from unnest(candidate_scopes) as supplied(scope)
   cross join (values ('authorization_code'),('refresh_token')) as required(grant_type);

  result_internal_id := candidate_internal_id;
  result_inserted := true;
  return next;
end
$$;

alter function public.boardagent_register_oauth_client(
  uuid,uuid,text,text,jsonb,bytea,text[],bytea[],text[],integer
) owner to boardagent_migrator;
revoke all on function public.boardagent_register_oauth_client(
  uuid,uuid,text,text,jsonb,bytea,text[],bytea[],text[],integer
) from public;
grant execute on function public.boardagent_register_oauth_client(
  uuid,uuid,text,text,jsonb,bytea,text[],bytea[],text[],integer
) to boardagent_server;
