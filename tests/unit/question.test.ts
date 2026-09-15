import { describe, expect, it } from "vitest";

import {
  prepareManagementQuestion,
  prepareManagementQuestionTurn
} from "../../lib/domain/src/index.js";

const id = (suffix: number): string =>
  `018f0000-0000-7000-8000-${suffix.toString(16).padStart(12, "0")}`;

describe("canonical management question preparation", () => {
  it("normalizes owner and visibility order into one stable request", () => {
    const first = prepareManagementQuestion({
      questionId: id(1),
      boardId: id(2),
      question: "What changed?\n",
      assignedOwnerIds: [id(4), id(3), id(4)],
      dueAt: "2026-09-02T12:00:00Z",
      citations: [
        {
          sourceDocumentVersionId: id(5),
          sourceDocumentSha256: "a".repeat(64),
          clause: "Section 4",
          locator: "lines 20-22"
        }
      ],
      visibility: [
        { granteeType: "seat_role", seatRole: "observer" },
        { granteeType: "member", memberId: id(6) },
        { granteeType: "member", memberId: id(7) },
        { granteeType: "seat_role", seatRole: "observer" }
      ]
    });
    const second = prepareManagementQuestion({
      questionId: id(1),
      boardId: id(2),
      question: "What changed?\n",
      assignedOwnerIds: [id(3), id(4)],
      dueAt: "2026-09-02T12:00:00Z",
      citations: [
        {
          sourceDocumentVersionId: id(5),
          sourceDocumentSha256: "a".repeat(64),
          clause: "Section 4",
          locator: "lines 20-22"
        }
      ],
      visibility: [
        { granteeType: "member", memberId: id(6) },
        { granteeType: "member", memberId: id(7) },
        { granteeType: "seat_role", seatRole: "observer" }
      ]
    });
    expect(first.assignedOwnerIds).toEqual([id(3), id(4)]);
    expect(first.visibility).toEqual([
      { granteeType: "member", memberId: id(6) },
      { granteeType: "member", memberId: id(7) },
      { granteeType: "seat_role", seatRole: "observer" }
    ]);
    expect(first.aclPolicy).toEqual({
      schemaVersion: "boardagent.question-acl.v1",
      grants: first.visibility
    });
    expect(first.requestSha256).toBe(second.requestSha256);
    expect(Buffer.from(first.canonicalPayload).toString("utf8")).toContain(
      '"schemaVersion":"boardagent.management-question.v1"'
    );
  });

  it("refuses noncanonical, blank, invalid-time, and oversized owner input", () => {
    const base = {
      questionId: id(1),
      boardId: id(2),
      assignedOwnerIds: [id(3)],
      dueAt: "2026-09-02T12:00:00Z",
      citations: [],
      visibility: [{ granteeType: "member" as const, memberId: id(4) }]
    };
    expect(() => prepareManagementQuestion({ ...base, question: "line\r\n" })).toThrow(
      /LF line endings/u
    );
    expect(() => prepareManagementQuestion({ ...base, question: "" })).toThrow(
      "management question must be nonblank"
    );
    expect(() =>
      prepareManagementQuestion({ ...base, question: "Question", dueAt: "not-a-time" })
    ).toThrow();
    expect(() =>
      prepareManagementQuestion({
        ...base,
        question: "Question",
        assignedOwnerIds: Array.from({ length: 1001 }, (_, index) => id(1000 + index))
      })
    ).toThrow(/1 through 1000/u);
    expect(() =>
      prepareManagementQuestion({ ...base, question: "Question", assignedOwnerIds: [] })
    ).toThrow(/1 through 1000/u);
  });

  it("enforces citation, visibility, and text bounds before hashing", () => {
    const citation = {
      sourceDocumentVersionId: id(5),
      sourceDocumentSha256: "a".repeat(64),
      clause: "Section 4",
      locator: "lines 20-22"
    };
    const base = {
      questionId: id(1),
      boardId: id(2),
      question: "Question",
      assignedOwnerIds: [id(3)],
      dueAt: "2026-09-02T12:00:00Z",
      citations: [] as (typeof citation)[],
      visibility: [{ granteeType: "member" as const, memberId: id(4) }]
    };
    expect(() =>
      prepareManagementQuestion({
        ...base,
        citations: Array.from({ length: 65 }, () => citation)
      })
    ).toThrow("cannot exceed 64");
    expect(
      prepareManagementQuestion({
        ...base,
        citations: Array.from({ length: 64 }, () => citation)
      }).citations
    ).toHaveLength(64);
    expect(() => prepareManagementQuestion({ ...base, visibility: [] })).toThrow("1 through 1003");
    expect(() =>
      prepareManagementQuestion({
        ...base,
        visibility: Array.from({ length: 1_004 }, () => ({
          granteeType: "member" as const,
          memberId: id(4)
        }))
      })
    ).toThrow("1 through 1003");
    expect(
      prepareManagementQuestion({
        ...base,
        visibility: Array.from({ length: 1_003 }, () => ({
          granteeType: "member" as const,
          memberId: id(4)
        }))
      }).visibility
    ).toEqual([{ granteeType: "member", memberId: id(4) }]);
    expect(() =>
      prepareManagementQuestion({
        ...base,
        visibility: [{ granteeType: "invalid" } as never]
      })
    ).toThrow("visibility grant is invalid");
    expect(() =>
      prepareManagementQuestion({
        ...base,
        visibility: [{ granteeType: "invalid", seatRole: "observer" } as never]
      })
    ).toThrow("visibility grant is invalid");
    for (const seatRole of ["voting_member", "management", "observer"] as const) {
      expect(
        prepareManagementQuestion({
          ...base,
          visibility: [{ granteeType: "seat_role", seatRole }]
        }).visibility
      ).toEqual([{ granteeType: "seat_role", seatRole }]);
    }
    expect(() =>
      prepareManagementQuestion({
        ...base,
        visibility: [{ granteeType: "seat_role", seatRole: "invalid" as never }]
      })
    ).toThrow("visibility grant is invalid");
    expect(() => prepareManagementQuestion({ ...base, question: "x".repeat(1_048_577) })).toThrow(
      "management question exceeds 1 MiB"
    );
    expect(
      prepareManagementQuestion({ ...base, question: "x".repeat(1_048_576) }).question
    ).toHaveLength(1_048_576);
    expect(
      prepareManagementQuestion({
        ...base,
        assignedOwnerIds: Array.from({ length: 1_000 }, (_, index) => id(10_000 + index))
      }).assignedOwnerIds
    ).toHaveLength(1_000);
  });

  it("binds answer and follow-up kinds into distinct canonical turn hashes", () => {
    const answer = prepareManagementQuestionTurn({
      questionId: id(1),
      turnKind: "answer",
      text: "Management answer\n",
      citations: []
    });
    const followUp = prepareManagementQuestionTurn({
      questionId: id(1),
      turnKind: "follow_up",
      text: "Management answer\n",
      citations: [],
      dueAt: "2026-09-03T12:00:00Z"
    });
    expect(answer.dueAt).toBeNull();
    expect(followUp.dueAt).toBe("2026-09-03T12:00:00Z");
    expect(answer.textSha256).toBe(followUp.textSha256);
    expect(answer.requestSha256).not.toBe(followUp.requestSha256);
    expect(() =>
      prepareManagementQuestionTurn({
        questionId: id(1),
        turnKind: "answer",
        text: "   ",
        citations: []
      })
    ).toThrow("management question turn must be nonblank");
    expect(() =>
      prepareManagementQuestionTurn({
        questionId: id(1),
        turnKind: "follow_up",
        text: "Please clarify",
        citations: [],
        dueAt: "not-a-time"
      })
    ).toThrow();
  });
});
