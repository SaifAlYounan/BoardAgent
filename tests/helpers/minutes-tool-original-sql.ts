// Frozen original get_minutes SQL; independent of the projection helper field maps.
export const ORIGINAL_MINUTES_TOOL_SQL = `select jsonb_build_object(
           'minutes_id',minutes.id,'board_id',minutes.board_id,'meeting_id',minutes.meeting_id,
           'state',minutes.state,'row_version',minutes.row_version::text,
           'correction_of_minutes_id',minutes.correction_of_minutes_id,
           'version',case when version_row.id is null then null else jsonb_build_object(
              'version_id',version_row.id,'version',version_row.version,
              'canonical_schema',version_row.canonical_schema,
              'canonical_text',version_row.canonical_text,
              'sha256',encode(version_row.canonical_sha256,'hex'),
              'package_base_sha256',encode(version_row.package_base_sha256,'hex'),
              'transcript_version_id',version_row.transcript_version_id,
              'transcript_sha256',case when version_row.transcript_sha256 is null then null
                else encode(version_row.transcript_sha256,'hex') end,
              'supersedes_id',version_row.supersedes_id,
              'created_at',to_char(version_row.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
           ) end,
           'signature_package',case when package.id is null then null else jsonb_build_object(
              'package_id',package.id,'version',package.version,
              'minutes_version_id',package.minutes_version_id,
              'minutes_sha256',encode(package.minutes_sha256,'hex'),
              'package_sha256',encode(package.package_sha256,'hex'),'state',package.state,
              'required_signers',coalesce((select jsonb_agg(jsonb_build_object(
                 'member_id',requirement.member_id,'seat_role',requirement.seat_role,
                 'requirement',requirement.requirement,
                 'snapshot_sha256',encode(requirement.member_snapshot_sha256,'hex')
               ) order by requirement.member_id) from minutes_signature_requirements as requirement
                where requirement.package_id=package.id),'[]'::jsonb),
              'signatures',coalesce((select jsonb_agg(jsonb_build_object(
                 'signature_id',signature.id,'signer_member_id',signature.signer_member_id,
                 'signer_seat_role',signature.signer_seat_role,
                 'record_sha256',encode(signature.signature_record_sha256,'hex'),
                 'signed_at',to_char(signature.signed_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
               ) order by signature.signed_at,signature.id) from minutes_signatures as signature
                where signature.package_id=package.id),'[]'::jsonb)
           ) end,
           'action_declaration',(
             select jsonb_build_object('declaration_id',declaration.id,
               'minutes_version_id',declaration.minutes_version_id,
               'declaration',declaration.declaration,
               'manifest_sha256',encode(declaration.manifest_sha256,'hex'),
               'declared_at',to_char(declaration.declared_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
              from minutes_action_declarations as declaration
             where declaration.minutes_id=minutes.id and declaration.minutes_version_id=version_row.id
             order by declaration.declared_at desc limit 1
           ),
           'finalized_at',case when minutes.finalized_at is null then null else
             to_char(minutes.finalized_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') end,
           'cancelled_at',case when minutes.cancelled_at is null then null else
             to_char(minutes.cancelled_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') end
         ) as view
         from minutes
         left join minutes_versions as version_row on version_row.id=minutes.current_version_id
         left join minutes_signature_packages as package on package.id=minutes.current_signature_package_id
        where minutes.id=$1`;
