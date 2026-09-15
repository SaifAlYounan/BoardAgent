// Frozen original certificate resource SQL, test-only; no production fallback.
export const ORIGINAL_CERTIFICATE_RESOURCE_SQL = `select certificate.id,jsonb_build_object(
           'schema_version','boardagent.vote-certificate-bundle.v1',
           'certificate_id',certificate.id,'vote_id',certificate.vote_id,
           'outcome_id',certificate.outcome_id,
           'public_id',translate(encode(certificate.public_id,'base64'),'+/=' || chr(10) || chr(13),'-_'),
           'canonical_payload',convert_from(certificate.canonical_payload,'UTF8')::jsonb,
           'payload_sha256',encode(certificate.payload_sha256,'hex'),
           'signature_base64url',translate(encode(certificate.signature,'base64'),'+/=' || chr(10) || chr(13),'-_'),
           'signing_key',jsonb_build_object('id',key.id,'kid',key.kid,'algorithm',key.algorithm,
                                            'public_jwk',key.public_jwk),
           'issued_at',to_char(certificate.issued_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
         ) as payload
         from vote_certificates as certificate
         join crypto_key_registry as key on key.id=certificate.signing_key_id
        where certificate.board_id=$1 and certificate.vote_id=$2 and certificate.id=$3
          and not boardagent_member_vote_recused(certificate.vote_id,
            boardagent_context_uuid('boardagent.member_id'))`;
