-- BoardAgent Phase 1 / group 20: exact ballot/proxy evidence and voting authority.

alter table ballots
  add column statement_text text
    check (statement_text is null or length(statement_text) <= 500),
  add constraint ballots_statement_pair_ck check (
    (statement_text is null and statement_sha256 is null)
    or (statement_text is not null and statement_sha256 is not null)
  );

alter table proxy_grants
  add constraint proxy_grants_vote_relationship_id_uq
    unique (vote_id, principal_member_id, holder_member_id, id);

alter table ballots
  add constraint ballots_proxy_relationship_fk
    foreign key (vote_id, principal_member_id, caster_member_id, proxy_grant_id)
    references proxy_grants(vote_id, principal_member_id, holder_member_id, id)
    on delete restrict;

create index proxy_grants_vote_holder_idx
  on proxy_grants(vote_id, holder_member_id, granted_at, id);

create function boardagent_vote_actor_ready_for_scope(candidate_board uuid, required_scope text)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select required_scope in ('vote:act', 'proxy:manage')
     and boardagent_context_board_allowed(candidate_board)
     and exists (
       select 1
         from members as actor
         join board_memberships as membership
           on membership.organization_id = actor.organization_id
          and membership.member_id = actor.id
          and membership.board_id = candidate_board
         join access_token_records as token
           on token.organization_id = actor.organization_id
          and token.member_id = actor.id
          and token.client_id = boardagent_context_uuid('boardagent.client_id')
          and token.jti = boardagent_context_uuid('boardagent.token_jti')
         join oauth_clients as client on client.id = token.client_id
         join system_instance as instance
           on instance.organization_id = actor.organization_id
          and instance.canonical_resource_uri = token.resource_uri
        where actor.organization_id = boardagent_context_uuid('boardagent.organization_id')
          and actor.id = boardagent_context_uuid('boardagent.member_id')
          and actor.state = 'active'
          and membership.state = 'active'
          and membership.seat_role = 'voting_member'
          and membership.voting_weight > 0
          and membership.active_from <= transaction_timestamp()
          and (membership.active_until is null or membership.active_until > transaction_timestamp())
          and client.organization_id = actor.organization_id
          and client.state = 'active'
          and token.revoked_at is null
          and token.expires_at > transaction_timestamp()
          and required_scope = any(token.scope_set)
          and exists (
            select 1
              from onboarding_attestations as attestation
             where attestation.organization_id = actor.organization_id
               and attestation.member_id = actor.id
               and attestation.board_id = candidate_board
               and attestation.terms_version_id = (
                 select terms.id
                   from onboarding_terms_versions as terms
                  where terms.organization_id = actor.organization_id
                    and terms.seat_role = membership.seat_role
                    and terms.effective_at <= transaction_timestamp()
                  order by terms.effective_at desc, terms.version desc, terms.id desc
                  limit 1
               )
               and attestation.support_version_id = (
                 select support.id
                   from secretary_support_versions as support
                  where support.organization_id = actor.organization_id
                    and (support.board_id = candidate_board or support.board_id is null)
                    and support.effective_at <= transaction_timestamp()
                  order by (support.board_id = candidate_board) desc,
                           support.effective_at desc,
                           support.version desc,
                           support.id desc
                  limit 1
               )
          )
     )
$$;
alter function boardagent_vote_actor_ready_for_scope(uuid, text)
  owner to boardagent_migrator;
revoke all on function boardagent_vote_actor_ready_for_scope(uuid, text) from public;
grant execute on function boardagent_vote_actor_ready_for_scope(uuid, text)
  to boardagent_server;

create policy boardagent_server_ballot_dispositions_principal_insert
  on ballot_dispositions for insert to boardagent_server
  with check (
    effect = 'superseded'
    and superseding_ballot_id is not null
    and replacement_vote_id is null
    and exists (
      select 1
        from ballots as prior_ballot
        join ballots as new_ballot
          on new_ballot.id = superseding_ballot_id
         and new_ballot.vote_id = prior_ballot.vote_id
         and new_ballot.principal_member_id = prior_ballot.principal_member_id
       where prior_ballot.id = prior_ballot_id
         and prior_ballot.ballot_source = 'proxy'
         and new_ballot.ballot_source = 'own'
         and new_ballot.caster_member_id = new_ballot.principal_member_id
         and new_ballot.organization_id =
           boardagent_context_uuid('boardagent.organization_id')
         and boardagent_context_board_allowed(new_ballot.board_id)
         and boardagent_vote_actor_ready_for_scope(new_ballot.board_id, 'vote:act')
    )
  );
