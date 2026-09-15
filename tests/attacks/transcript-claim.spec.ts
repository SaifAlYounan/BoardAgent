import { describe, expect, it } from "vitest";

import {
  TRANSCRIPT_MARKDOWN_SCHEMA_VERSION,
  TRANSCRIPT_TURNS_SCHEMA_VERSION,
  parseTranscriptAnnex
} from "../../lib/contracts/src/transcript.js";
import { toolInputSchema } from "../../lib/contracts/src/surface-inputs.js";
import { testId } from "../helpers/authorized-actor.js";

describe("TH-42 transcript evidence claim boundary", () => {
  it("labels contributed bytes as an unverified annex and requires explicit secretary verification", () => {
    const markdown = parseTranscriptAnnex(
      "text/markdown; charset=utf-8",
      "# Contributed notes\n\nNo recording is stored and no transcription is claimed.\n"
    );
    expect(markdown).toEqual({
      canonicalSchema: TRANSCRIPT_MARKDOWN_SCHEMA_VERSION,
      canonicalBody:
        "# Contributed notes\n\nNo recording is stored and no transcription is claimed.\n",
      turns: []
    });

    const create = toolInputSchema("create_meeting_transcript_version").parse({
      schema_version: "boardagent.tool-input.v1",
      meeting_id: testId(42_002),
      transcript_id: testId(42_003),
      media_type: "text/markdown; charset=utf-8",
      canonical_body: markdown.canonicalBody,
      coverage_statement: "Contributed notes only; no audio source or transcription claim.",
      supersedes_version_id: null,
      idempotency_key: "transcript-claim-0001"
    });
    expect(create).toMatchObject({
      media_type: "text/markdown; charset=utf-8",
      coverage_statement: "Contributed notes only; no audio source or transcription claim."
    });
    expect(
      toolInputSchema("verify_meeting_transcript").safeParse({
        schema_version: "boardagent.tool-input.v1",
        transcript_id: testId(42_003),
        version_id: testId(42_004),
        sha256: "a".repeat(64),
        verification_statement: "audio_transcribed_accurately",
        idempotency_key: "transcript-claim-0002"
      }).success
    ).toBe(false);
    expect(TRANSCRIPT_TURNS_SCHEMA_VERSION).toBe("boardagent.transcript-turns.v1");
  });
});
