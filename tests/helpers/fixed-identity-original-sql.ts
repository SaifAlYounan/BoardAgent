export const ORIGINAL_MEMBERS_SQL = `select jsonb_build_object(
           'member_id',member.id,'member_kind',member.member_kind,
           'display_name',member.display_name,'state',member.state,
           'accountable_principal_id',member.accountable_principal_id,
           'identity_generation',member.identity_generation::text,
           'onboarding_generation',member.onboarding_generation::text,
           'row_version',member.row_version::text,
           'membership',case when membership.id is null then null else jsonb_build_object(
              'membership_id',membership.id,'board_id',membership.board_id,
              'seat_role',membership.seat_role,'is_chair',membership.is_chair,
              'is_secretary',membership.is_secretary,
              'voting_weight',membership.voting_weight::text,'state',membership.state,
              'entitlement_generation',membership.entitlement_generation::text
           ) end,
           'created_at',to_char(member.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
         ) as item,
         to_char(member.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as cursor_at,
         member.id::text as cursor_id
         from members as member
         left join board_memberships as membership on membership.member_id=member.id
          and ($1::uuid is null or membership.board_id=$1)
        where ($1::uuid is null or membership.id is not null)
          and (boardagent_secretariat_for_board(membership.board_id) or exists (
            select 1 from organization_role_assignments as role_assignment
             where role_assignment.organization_id=member.organization_id
               and role_assignment.member_id=boardagent_context_uuid('boardagent.member_id')
               and role_assignment.role in ('secretariat','admin')
               and role_assignment.active_from<=transaction_timestamp()
               and (role_assignment.active_until is null
                    or role_assignment.active_until>transaction_timestamp())
          ))
          and ($2::text is null or member.state=$2)
          and ($3::timestamptz is null or (member.created_at,member.id)<($3::timestamptz,$4::uuid))
        order by member.created_at desc,member.id desc limit $5`;
export const ORIGINAL_ENROLLMENTS_SQL = `select jsonb_build_object(
           'invitation_id',invitation.id,'member_id',invitation.member_id,
           'issued_by',invitation.issued_by,'handoff_method',invitation.handoff_method,
           'state',case when invitation.revoked_at is not null then 'revoked'
             when invitation.consumed_at is not null then 'consumed'
             when invitation.expires_at<=transaction_timestamp() then 'expired' else 'issued' end,
           'issued_at',to_char(invitation.issued_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
           'expires_at',to_char(invitation.expires_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
           'consumed_at',case when invitation.consumed_at is null then null else
              to_char(invitation.consumed_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') end,
           'pending_activation_member_id',invitation.pending_activation_member_id
         ) as item,
         to_char(invitation.issued_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as cursor_at,
         invitation.id::text as cursor_id
         from enrollment_invitations as invitation
        where ($1::text is null or case when invitation.revoked_at is not null then 'revoked'
             when invitation.consumed_at is not null then 'consumed'
             when invitation.expires_at<=transaction_timestamp() then 'expired' else 'issued' end=$1)
          and ($2::timestamptz is null or
               (invitation.issued_at,invitation.id)<($2::timestamptz,$3::uuid))
        order by invitation.issued_at desc,invitation.id desc limit $4`;
