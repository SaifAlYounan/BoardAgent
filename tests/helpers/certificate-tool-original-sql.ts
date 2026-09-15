// Exact frozen original tool SELECT; test-only, never a production fallback.
export const ORIGINAL_CERTIFICATE_TOOL_SQL = `select jsonb_build_object(
           'certificate_id',certificate.id,'vote_id',certificate.vote_id,
           'outcome_id',certificate.outcome_id,
           'public_id',translate(encode(certificate.public_id,'base64'),'+/=' || chr(10) || chr(13),'-_'),
           'schema_version',certificate.schema_version,
           'canonical_payload',convert_from(certificate.canonical_payload,'UTF8')::jsonb,
           'payload_sha256',encode(certificate.payload_sha256,'hex'),
           'signature_base64url',translate(encode(certificate.signature,'base64'),'+/=' || chr(10) || chr(13),'-_'),
           'signing_key_id',certificate.signing_key_id,'state',certificate.state,
           'supersedes_id',certificate.supersedes_id,
           'issued_at',to_char(certificate.issued_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
         ) as view,certificate.board_id from vote_certificates as certificate
        where certificate.vote_id=$1
          and not boardagent_member_vote_recused(certificate.vote_id,
            boardagent_context_uuid('boardagent.member_id'))
          and (($2::uuid is null and certificate.state='current') or certificate.id=$2)
        order by certificate.issued_at desc limit 1`;
