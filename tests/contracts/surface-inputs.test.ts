import { describe, expect, it } from "vitest";
import { z } from "zod";

import {
  BOARDAGENT_REGISTRY,
  TOOL_IDS,
  TOOL_INPUT_SCHEMA_VERSION,
  TOOL_INPUT_SCHEMAS,
  assertToolInputSchemaClosure,
  canonicalJson,
  toolInputSchema
} from "../../lib/contracts/src/index.js";

const V7_A = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e0f";
const V7_B = "018f47a1-1f5d-7c3a-8b22-0a0b0c0d0e10";

describe("frozen tool input schema closure", () => {
  it("has one strict versioned schema for every frozen tool and no hidden schema", () => {
    expect(assertToolInputSchemaClosure).not.toThrow();
    expect(Object.keys(TOOL_INPUT_SCHEMAS).toSorted()).toEqual([...TOOL_IDS].toSorted());
    expect(() => toolInputSchema("hidden_backdoor")).toThrow(
      "unregistered BoardAgent tool input schema"
    );

    for (const tool of TOOL_IDS) {
      const json = z.toJSONSchema(toolInputSchema(tool)) as {
        additionalProperties?: unknown;
        properties?: Record<string, { const?: unknown }>;
        required?: string[];
      };
      expect(json.additionalProperties, tool).toBe(false);
      expect(json.properties?.schema_version?.const, tool).toBe(TOOL_INPUT_SCHEMA_VERSION);
      expect(json.required, tool).toContain("schema_version");
    }
  });

  it("requires scoped idempotency on every direct and human-confirmed mutation", () => {
    for (const tool of BOARDAGENT_REGISTRY.tools) {
      const json = z.toJSONSchema(toolInputSchema(tool.name)) as {
        properties?: Record<string, unknown>;
        required?: string[];
      };
      if (tool.class === "R") {
        expect(json.properties, tool.name).not.toHaveProperty("idempotency_key");
      } else {
        expect(json.properties, tool.name).toHaveProperty("idempotency_key");
        expect(json.required, tool.name).toContain("idempotency_key");
      }
    }
  });

  it("rejects unknown fields and UUID versions at the public trust boundary", () => {
    const whoami = toolInputSchema("whoami");
    expect(
      whoami.safeParse({ schema_version: TOOL_INPUT_SCHEMA_VERSION, injected: true }).success
    ).toBe(false);
    expect(
      toolInputSchema("get_board").safeParse({
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        board_id: "11111111-1111-4111-8111-111111111111"
      }).success
    ).toBe(false);
  });

  it("rejects non-NFC and CR line endings before canonical content reaches a repository", () => {
    const base = {
      schema_version: TOOL_INPUT_SCHEMA_VERSION,
      question_id: V7_A,
      owner_member_id: V7_B,
      board_id: V7_A,
      due_at: "2026-09-02T10:00:00Z",
      citations: [],
      idempotency_key: "ask-management-0001"
    } as const;
    expect(
      toolInputSchema("ask_management").safeParse({ ...base, question: "Cafe\u0301" }).success
    ).toBe(false);
    expect(
      toolInputSchema("ask_management").safeParse({ ...base, question: "Line one\r\nLine two" })
        .success
    ).toBe(false);
    expect(
      toolInputSchema("ask_management").safeParse({ ...base, question: "Caf\u00e9\nLine two" })
        .success
    ).toBe(true);
  });

  it("accepts representative read, direct and confirmed inputs exactly", () => {
    expect(
      toolInputSchema("get_board").parse({
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        board_id: V7_A
      })
    ).toEqual({ schema_version: TOOL_INPUT_SCHEMA_VERSION, board_id: V7_A });

    expect(
      toolInputSchema("start_task").parse({
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        task_id: V7_A,
        idempotency_key: "start-task-00000001"
      })
    ).toMatchObject({ task_id: V7_A });

    expect(
      toolInputSchema("stage_ballot").parse({
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        vote_id: V7_A,
        principal_member_id: V7_B,
        choice: "yes",
        statement: "Approved on the exact package.",
        idempotency_key: "stage-ballot-000001"
      })
    ).toMatchObject({ vote_id: V7_A, principal_member_id: V7_B, choice: "yes" });
  });

  it("accepts only a strict canonical meeting agenda and unique attendee set", () => {
    const input = {
      schema_version: TOOL_INPUT_SCHEMA_VERSION,
      board_id: V7_A,
      meeting_id: V7_B,
      title: "Exploration committee",
      scheduled_start_at: "2026-10-01T09:00:00Z",
      scheduled_end_at: "2026-10-01T10:00:00Z",
      timezone: "Asia/Dubai",
      agenda: {
        schema_version: "boardagent.agenda.v1",
        values: { items: [{ title: "Approve drilling programme" }] }
      },
      attendee_member_ids: [V7_A],
      idempotency_key: "create-meeting-000001"
    } as const;
    expect(toolInputSchema("create_meeting").parse(input)).toMatchObject({
      agenda: {
        schema_version: "boardagent.agenda.v1",
        values: {
          items: [
            {
              title: "Approve drilling programme",
              source_document_version_id: null,
              source_document_sha256: null
            }
          ]
        }
      }
    });
    expect(
      toolInputSchema("create_meeting").safeParse({
        ...input,
        attendee_member_ids: [V7_A, V7_A]
      }).success
    ).toBe(false);
    expect(
      toolInputSchema("create_meeting").safeParse({
        ...input,
        agenda: {
          schema_version: "boardagent.agenda.v1",
          values: {
            items: [
              {
                title: "Mismatched source",
                source_document_version_id: V7_A,
                source_document_sha256: null
              }
            ]
          }
        }
      }).success
    ).toBe(false);
    expect(
      toolInputSchema("create_meeting").safeParse({
        ...input,
        agenda: { schema_version: "boardagent.dynamic-facts.v1", values: { items: [] } }
      }).success
    ).toBe(false);
    expect(
      toolInputSchema("rsvp").safeParse({
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        meeting_id: V7_A,
        response: "attending",
        note: "",
        idempotency_key: "meeting-rsvp-000001"
      }).success
    ).toBe(false);
  });

  it("accepts only canonical transcript annexes with strict unique immutable turns", () => {
    const canonicalBody = canonicalJson({
      schema_version: "boardagent.transcript-turns.v1",
      values: {
        turns: [
          {
            canonical_text: "What safeguards apply to the drilling programme?",
            ends_at_ms: 4200,
            speaker_label: "Director A",
            speaker_member_id: V7_A,
            starts_at_ms: 1200,
            turn_id: V7_B
          }
        ]
      }
    });
    const input = {
      schema_version: TOOL_INPUT_SCHEMA_VERSION,
      meeting_id: V7_A,
      transcript_id: V7_B,
      media_type: "application/json",
      canonical_body: canonicalBody,
      coverage_statement: "Covers the full called meeting from opening to adjournment.",
      supersedes_version_id: null,
      idempotency_key: "meeting-transcript-0001"
    } as const;

    expect(toolInputSchema("create_meeting_transcript_version").parse(input)).toMatchObject({
      canonical_body: canonicalBody,
      media_type: "application/json"
    });
    expect(
      toolInputSchema("create_meeting_transcript_version").safeParse({
        ...input,
        canonical_body: JSON.stringify(JSON.parse(canonicalBody), null, 2)
      }).success
    ).toBe(false);
    expect(
      toolInputSchema("create_meeting_transcript_version").safeParse({
        ...input,
        canonical_body: canonicalJson({
          schema_version: "boardagent.transcript-turns.v1",
          values: {
            turns: [
              {
                canonical_text: "Question one",
                ends_at_ms: null,
                injected: true,
                speaker_label: "Director A",
                speaker_member_id: null,
                starts_at_ms: null,
                turn_id: V7_A
              }
            ]
          }
        })
      }).success
    ).toBe(false);
    expect(
      toolInputSchema("create_meeting_transcript_version").safeParse({
        ...input,
        canonical_body: canonicalJson({
          schema_version: "boardagent.transcript-turns.v1",
          values: {
            turns: [
              {
                canonical_text: "Question one",
                ends_at_ms: 1000,
                speaker_label: "Director A",
                speaker_member_id: null,
                starts_at_ms: 1000,
                turn_id: V7_A
              },
              {
                canonical_text: "Duplicate identifier",
                ends_at_ms: null,
                speaker_label: "Director B",
                speaker_member_id: null,
                starts_at_ms: null,
                turn_id: V7_A
              }
            ]
          }
        })
      }).success
    ).toBe(false);
    expect(
      toolInputSchema("create_meeting_transcript_version").safeParse({
        ...input,
        media_type: "text/markdown; charset=utf-8",
        canonical_body: "# Meeting transcript\n\nNo recording is stored.\n"
      }).success
    ).toBe(true);
  });

  it("binds transcript link sets and challenge dispositions without ambiguous shapes", () => {
    expect(
      toolInputSchema("link_meeting_qna").safeParse({
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        transcript_version_id: V7_A,
        turn_ids: [V7_B, V7_B],
        question_id: V7_B,
        idempotency_key: "link-transcript-qna-0001"
      }).success
    ).toBe(false);
    expect(
      toolInputSchema("resolve_transcript_challenge").safeParse({
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        challenge_id: V7_A,
        disposition: "accept",
        reason: "The corrected annex now preserves the challenged statement.",
        corrected_version_id: null,
        idempotency_key: "resolve-transcript-0001"
      }).success
    ).toBe(false);
    expect(
      toolInputSchema("resolve_transcript_challenge").safeParse({
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        challenge_id: V7_A,
        disposition: "reject",
        reason: "The existing annex turn is retained.",
        corrected_version_id: V7_B,
        idempotency_key: "resolve-transcript-0002"
      }).success
    ).toBe(false);
  });

  it("fixes the one-call pending briefing at 1000 without widening ordinary pages", () => {
    const briefing = toolInputSchema("list_pending_actions");
    expect(briefing.parse({ schema_version: TOOL_INPUT_SCHEMA_VERSION, cursor: null })).toEqual({
      schema_version: TOOL_INPUT_SCHEMA_VERSION,
      cursor: null,
      limit: 1_000
    });
    expect(
      briefing.safeParse({
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        cursor: null,
        limit: 500
      }).success
    ).toBe(false);
    expect(
      toolInputSchema("list_my_updates").safeParse({
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        cursor: null,
        limit: 500
      }).success
    ).toBe(true);
    expect(
      toolInputSchema("list_my_updates").safeParse({
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        cursor: null,
        limit: 501
      }).success
    ).toBe(false);
  });
});
