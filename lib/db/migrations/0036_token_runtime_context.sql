-- BoardAgent Phase 2: one fail-closed, database-bound bearer-token context resolver.

create function boardagent_resolve_access_token(candidate_jti uuid)
returns table(
  token_record_id uuid,
  organization_id uuid,
  member_id uuid,
  internal_client_id uuid,
  protocol_client_id text,
  resource_uri text,
  scope_set text[],
  expires_at_epoch bigint,
  signing_key_kid text,
  roles text[],
  board_ids text[]
)
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select token.id,
         token.organization_id,
         token.member_id,
         token.client_id,
         oauth_client.protocol_id_value,
         token.resource_uri,
         token.scope_set,
         floor(extract(epoch from token.expires_at))::bigint,
         signing_key.kid,
         coalesce(
           array(
             select distinct role_name
               from (
                 select assignment.role as role_name
                   from organization_role_assignments as assignment
                  where assignment.organization_id=token.organization_id
                    and assignment.member_id=token.member_id
                    and assignment.active_from<=transaction_timestamp()
                    and (assignment.active_until is null
                         or assignment.active_until>transaction_timestamp())
                 union all
                 select case membership.seat_role
                          when 'voting_member' then 'member'
                          when 'management' then 'management'
                          when 'observer' then 'observer'
                        end as role_name
                   from board_memberships as membership
                  where membership.organization_id=token.organization_id
                    and membership.member_id=token.member_id
                    and membership.state='active'
                    and membership.active_from<=transaction_timestamp()
                    and (membership.active_until is null
                         or membership.active_until>transaction_timestamp())
                 union all
                 select 'secretariat' as role_name
                   from board_memberships as membership
                  where membership.organization_id=token.organization_id
                    and membership.member_id=token.member_id
                    and membership.is_secretary
                    and membership.state='active'
                    and membership.active_from<=transaction_timestamp()
                    and (membership.active_until is null
                         or membership.active_until>transaction_timestamp())
               ) as live_roles
              where role_name is not null
              order by role_name
           ),
           array[]::text[]
         ) as roles,
         coalesce(
           array(
             select distinct membership.board_id::text
               from board_memberships as membership
              where membership.organization_id=token.organization_id
                and membership.member_id=token.member_id
                and membership.state='active'
                and membership.active_from<=transaction_timestamp()
                and (membership.active_until is null
                     or membership.active_until>transaction_timestamp())
              order by membership.board_id::text
           ),
           array[]::text[]
         ) as board_ids
    from access_token_records as token
    join members as member
      on member.id=token.member_id
     and member.organization_id=token.organization_id
     and member.state='active'
    join oauth_clients as oauth_client
      on oauth_client.id=token.client_id
     and oauth_client.organization_id=token.organization_id
     and oauth_client.state='active'
    join auth_sessions as session
      on session.id=token.session_id
     and session.organization_id=token.organization_id
     and session.member_id=token.member_id
     and session.client_id=token.client_id
     and session.state='authenticated'
     and session.expires_at>transaction_timestamp()
    join crypto_key_registry as signing_key
      on signing_key.id=token.signing_key_id
     and signing_key.organization_id=token.organization_id
     and signing_key.purpose='oauth_signing'
     and signing_key.algorithm='ES256'
     and signing_key.public_jwk is not null
     and signing_key.compromised_at is null
    join system_instance as instance
      on instance.organization_id=token.organization_id
     and instance.canonical_resource_uri=token.resource_uri
   where token.jti=candidate_jti
     and token.revoked_at is null
     and token.expires_at>transaction_timestamp()
$$;

alter function boardagent_resolve_access_token(uuid) owner to boardagent_migrator;
revoke all on function boardagent_resolve_access_token(uuid) from public;
grant execute on function boardagent_resolve_access_token(uuid) to boardagent_server;
