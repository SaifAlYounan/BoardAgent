import { createHash } from "node:crypto";
import type { PoolClient } from "pg";
import type { JsonValue, TranscriptMediaType } from "@boardagent/contracts";
import {
  ResponseAllocationUnavailable,
  TRANSCRIPT_PROJECTION_FIXED,
  loadWithResponseAllocation,
  responseAllocationPlan,
  transcriptProjectionCost,
  type TranscriptProjectionScalars
} from "./response-allocation.js";

interface TranscriptMetadata {
  board_id: string;
  meeting_id: string;
  version_id: string;
  version: number;
  media_type: TranscriptMediaType;
  canonical_length: number;
  canonical_sha256: string;
  root_utf8: string;
  turn_count: string;
  turn_utf8: string;
  challenge_count: string;
  challenge_utf8: string;
  verification_count: string;
  verification_utf8: string;
}
export interface AdmittedTranscriptProjection {
  readonly board_id: string;
  readonly meeting_id: string;
  readonly version_id: string;
  readonly version: number;
  readonly media_type: TranscriptMediaType;
  readonly canonical_bytes: Buffer;
  readonly view: JsonValue;
}

// Only fixed SQL fragments are supplied here. Both statements retain the current
// root/version joins and child visibility; no payload leaves these scalar CTEs.
function metadataCtes(targetPredicate: string): string {
  return `authorized as materialized (
    select transcript.board_id,transcript.meeting_id,version_row.id as version_id,
           version_row.version,version_row.media_type,
           octet_length(version_row.canonical_bytes) as canonical_length,
           encode(version_row.canonical_sha256,'hex') as canonical_sha256,
           (octet_length(transcript.id::text)::numeric
            +octet_length(transcript.meeting_id::text)+octet_length(transcript.state)
            +octet_length(version_row.id::text)+octet_length(version_row.version::text)
            +octet_length(version_row.canonical_schema)+octet_length(version_row.media_type)
            +2*octet_length(version_row.canonical_sha256)+octet_length(version_row.source_type)
            +octet_length(version_row.verification_state)
            +coalesce(octet_length(version_row.supersedes_id::text),0)) as root_utf8
      from meeting_transcripts as transcript
      join meeting_transcript_versions as version_row on version_row.transcript_id=transcript.id
     where ${targetPredicate} limit 1
  ), scalar_cost as materialized (
    select authorized.*,
           turns.item_count as turn_count,turns.utf8 as turn_utf8,
           challenges.item_count as challenge_count,challenges.utf8 as challenge_utf8,
           verification.item_count as verification_count,verification.utf8 as verification_utf8
      from authorized
      cross join lateral (
        select count(*)::numeric as item_count,
               coalesce(sum(octet_length(turn.id::text)::numeric
                 +octet_length(turn.ordinal::text)+coalesce(octet_length(turn.speaker_member_id::text),0)
                 +octet_length(turn.speaker_label)+coalesce(octet_length(turn.starts_at_ms::text),0)
                 +coalesce(octet_length(turn.ends_at_ms::text),0)+octet_length(turn.canonical_text)
                 +2*octet_length(turn.text_sha256)),0) as utf8
          from transcript_turns as turn where turn.transcript_version_id=authorized.version_id
      ) as turns
      cross join lateral (
        select count(*)::numeric as item_count,
               coalesce(sum(octet_length(challenge.id::text)::numeric
                 +octet_length(challenge.turn_id::text)+octet_length(challenge.challenger_member_id::text)
                 +octet_length(challenge.canonical_comment)+2*octet_length(challenge.comment_sha256)
                 +octet_length(challenge.state)
                 +octet_length(to_char(challenge.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))),0) as utf8
          from transcript_challenges as challenge where challenge.transcript_version_id=authorized.version_id
      ) as challenges
      cross join lateral (
        select count(*)::numeric as item_count,coalesce(sum(selected.utf8),0) as utf8
          from (
            select octet_length(verification.id::text)::numeric
                   +2*octet_length(verification.transcript_sha256)
                   +octet_length(verification.secretary_member_id::text)+octet_length(verification.status)
                   +octet_length(to_char(verification.verified_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) as utf8
              from transcript_verifications as verification
             where verification.transcript_version_id=authorized.version_id
             order by verification.verified_at desc limit 1
          ) as selected
      ) as verification
  )`;
}

const scalarColumns = `board_id,meeting_id,version_id,version,media_type,canonical_length,canonical_sha256,
  root_utf8::text,turn_count::text,turn_utf8::text,challenge_count::text,challenge_utf8::text,
  verification_count::text,verification_utf8::text`;

export const TRANSCRIPT_PREFLIGHT_SQL = `with ${metadataCtes(
  "transcript.id=$1 and (($2::uuid is null and version_row.id=transcript.current_version_id) or version_row.id=$2)"
)} select ${scalarColumns} from scalar_cost`;

const fixed = TRANSCRIPT_PROJECTION_FIXED;
const freshViewBound = `${String(fixed.rootJson)}::numeric
  +6*(canonical_length::numeric+root_utf8+turn_utf8+challenge_utf8+verification_utf8)
  +${String(fixed.turnJson)}*turn_count+${String(fixed.challengeJson)}*challenge_count
  +${String(fixed.verificationJson)}*verification_count`;

// Construction occurs in separate scalar subqueries selected by CASE, not in a
// same-level aggregate or a payload-producing CTE. The fresh scalar and content
// branches run within this statement's snapshot under existing RLS.
export const TRANSCRIPT_CONTENT_SQL = `with ${metadataCtes(
  "transcript.id=$1 and version_row.id=$2 and version_row.version=$3" +
    " and octet_length(version_row.canonical_bytes)=$4 and version_row.canonical_sha256=$5" +
    " and version_row.media_type=$6 and transcript.board_id=$7 and transcript.meeting_id=$8"
)}, measured as materialized (
  select scalar_cost.*,(${freshViewBound}) as view_bound from scalar_cost
), decision as materialized (
  select measured.*,
    (view_bound <= $9::numeric and
      65536::numeric+80*canonical_length+8*(view_bound+${String(fixed.resultJson)})
      +256*(22+8*turn_count+7*challenge_count+5*verification_count)
      +512*(5+turn_count+challenge_count+verification_count) <= $10::numeric) as fits
    from measured
)
select ${scalarColumns},fits,
  case when fits then (
    select jsonb_build_object(
      'transcript_id',transcript.id,'meeting_id',transcript.meeting_id,
      'state',transcript.state,'version_id',version_row.id,'version',version_row.version,
      'canonical_schema',version_row.canonical_schema,'media_type',version_row.media_type,
      'canonical_body',convert_from(version_row.canonical_bytes,'UTF8'),
      'sha256',encode(version_row.canonical_sha256,'hex'),
      'source_type',version_row.source_type,'verification_state',version_row.verification_state,
      'supersedes_id',version_row.supersedes_id,
      'turns',coalesce((select jsonb_agg(jsonb_build_object(
        'turn_id',turn.id,'ordinal',turn.ordinal,'speaker_member_id',turn.speaker_member_id,
        'speaker_label',turn.speaker_label,'starts_at_ms',turn.starts_at_ms::text,
        'ends_at_ms',turn.ends_at_ms::text,'canonical_text',turn.canonical_text,
        'sha256',encode(turn.text_sha256,'hex')
      ) order by turn.ordinal,turn.id) from transcript_turns as turn
        where turn.transcript_version_id=version_row.id),'[]'::jsonb),
      'challenges',coalesce((select jsonb_agg(jsonb_build_object(
        'challenge_id',challenge.id,'turn_id',challenge.turn_id,
        'challenger_member_id',challenge.challenger_member_id,
        'canonical_comment',challenge.canonical_comment,
        'comment_sha256',encode(challenge.comment_sha256,'hex'),'state',challenge.state,
        'created_at',to_char(challenge.created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
      ) order by challenge.created_at,challenge.id) from transcript_challenges as challenge
        where challenge.transcript_version_id=version_row.id),'[]'::jsonb),
      'verification',(
        select jsonb_build_object('verification_id',verification.id,
          'sha256',encode(verification.transcript_sha256,'hex'),
          'secretary_member_id',verification.secretary_member_id,'status',verification.status,
          'verified_at',to_char(verification.verified_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
          from transcript_verifications as verification
         where verification.transcript_version_id=version_row.id
         order by verification.verified_at desc limit 1
      )
    )
    from meeting_transcripts as transcript
    join meeting_transcript_versions as version_row on version_row.transcript_id=transcript.id
   where transcript.id=$1 and version_row.id=decision.version_id
  ) else null end as view,
  case when fits then (
    select version_row.canonical_bytes
      from meeting_transcripts as transcript
      join meeting_transcript_versions as version_row on version_row.transcript_id=transcript.id
     where transcript.id=$1 and version_row.id=decision.version_id
  ) else null end as canonical_bytes
from decision`;

function projectionScalars(row: TranscriptMetadata): TranscriptProjectionScalars {
  return {
    rootUtf8Bytes: row.root_utf8,
    turnCount: row.turn_count,
    turnUtf8Bytes: row.turn_utf8,
    challengeCount: row.challenge_count,
    challengeUtf8Bytes: row.challenge_utf8,
    verificationCount: row.verification_count,
    verificationUtf8Bytes: row.verification_utf8
  };
}

export async function loadAdmittedTranscriptProjection(
  client: PoolClient,
  transcriptId: string,
  versionId: string | null
): Promise<AdmittedTranscriptProjection | null> {
  const preflight = await client.query<TranscriptMetadata>(TRANSCRIPT_PREFLIGHT_SQL, [
    transcriptId,
    versionId
  ]);
  const selected = preflight.rows[0];
  if (!selected) return null;
  const projection = projectionScalars(selected);
  const plan = responseAllocationPlan({
    kind: "transcript_tool",
    representation: "tool",
    sourceId: selected.version_id,
    sourceVersion: `${transcriptId}:${String(selected.version)}`,
    sha256: selected.canonical_sha256,
    canonicalBytes: selected.canonical_length,
    transcriptProjection: projection
  });
  const cost = transcriptProjectionCost(selected.canonical_length, projection);
  const loaded = await loadWithResponseAllocation(plan, () =>
    client.query<
      TranscriptMetadata & {
        fits: boolean;
        canonical_bytes: Buffer | null;
        view: JsonValue | null;
      }
    >(TRANSCRIPT_CONTENT_SQL, [
      transcriptId,
      selected.version_id,
      selected.version,
      selected.canonical_length,
      Buffer.from(selected.canonical_sha256, "hex"),
      selected.media_type,
      selected.board_id,
      selected.meeting_id,
      cost.viewJsonUpperBytes,
      cost.allocationBytes
    ])
  );
  const row = loaded.rows[0];
  if (!row) return null;
  if (!row.fits) throw new ResponseAllocationUnavailable();
  const bytes = row.canonical_bytes;
  if (
    !bytes ||
    row.view === null ||
    bytes.length !== selected.canonical_length ||
    createHash("sha256").update(bytes).digest("hex") !== selected.canonical_sha256
  )
    throw new Error("transcript projection failed integrity verification");
  return {
    board_id: row.board_id,
    meeting_id: row.meeting_id,
    version_id: row.version_id,
    version: row.version,
    media_type: row.media_type,
    canonical_bytes: bytes,
    view: row.view
  };
}
