import {
  MinutesActionManifestSchema,
  MinutesRedlineSchema,
  canonicalSha256,
  canonicalText,
  safeHashEqual,
  sha256Hex,
  type MinutesActionManifest,
  type MinutesRedline
} from "@boardagent/contracts";

interface LineRange {
  readonly start: number;
  readonly endExclusive: number;
}

function lineRange(lines: readonly string[], redline: MinutesRedline): LineRange {
  if (redline.anchor.kind === "lines") {
    const start = redline.anchor.startLine - 1;
    const endExclusive = redline.anchor.endLine;
    if (endExclusive > lines.length) throw new Error("minutes line anchor is outside base");
    return { start, endExclusive };
  }

  let start = -1;
  let level = 0;
  for (const [index, line] of lines.entries()) {
    const match = /^(#{1,6})\s+(.+)/u.exec(line);
    if (match?.[2] === redline.anchor.section) {
      start = index;
      level = match[1]!.length;
      break;
    }
  }
  if (start < 0) throw new Error("minutes section anchor is absent from base");
  let endExclusive = lines.length;
  for (const [offset, line] of lines.slice(start + 1).entries()) {
    const index = start + 1 + offset;
    const match = /^(#{1,6})\s/u.exec(line);
    if (match && match[1]!.length <= level) {
      endExclusive = index;
      break;
    }
  }
  return { start, endExclusive };
}

function contentLines(value: string): { readonly lines: string[]; readonly terminalLf: boolean } {
  const terminalLf = value.endsWith("\n");
  const lines = value.split("\n");
  if (terminalLf) lines.pop();
  return { lines, terminalLf };
}

export function applyExactMinutesRedline(baseText: string, input: MinutesRedline): string {
  const base = canonicalText(baseText);
  const redline = MinutesRedlineSchema.parse(input);
  if (!safeHashEqual(redline.baseSha256, sha256Hex(base))) {
    throw new Error("minutes redline base hash mismatch");
  }
  const { lines, terminalLf } = contentLines(base);
  const range = lineRange(lines, redline);
  const anchored = lines.slice(range.start, range.endExclusive).join("\n");
  if (!safeHashEqual(redline.anchoredTextSha256, sha256Hex(anchored))) {
    throw new Error("minutes redline anchored text hash mismatch");
  }
  const proposed = contentLines(canonicalText(redline.proposedText)).lines;
  if (redline.operation === "replace") {
    lines.splice(range.start, range.endExclusive - range.start, ...proposed);
  } else if (redline.operation === "delete") {
    lines.splice(range.start, range.endExclusive - range.start);
  } else if (redline.operation === "insert_before") {
    lines.splice(range.start, 0, ...proposed);
  } else {
    lines.splice(range.endExclusive, 0, ...proposed);
  }
  return canonicalText(`${lines.join("\n")}${terminalLf ? "\n" : ""}`);
}

export interface MinutesReviewItemRef {
  readonly itemId: string;
  readonly kind: "comment" | "redline";
}

export function reviewIsResolved(
  items: readonly MinutesReviewItemRef[],
  withdrawals: readonly { readonly itemId: string }[],
  dispositions: readonly { readonly itemId: string }[]
): boolean {
  const itemMap = new Map<string, MinutesReviewItemRef>();
  for (const item of items) {
    if (itemMap.has(item.itemId)) throw new Error(`duplicate minutes review item: ${item.itemId}`);
    itemMap.set(item.itemId, item);
  }
  const withdrawn = new Set<string>();
  for (const withdrawal of withdrawals) {
    const item = itemMap.get(withdrawal.itemId);
    if (!item) throw new Error(`withdrawal references unknown item: ${withdrawal.itemId}`);
    if (item.kind !== "comment") throw new Error("redlines cannot be withdrawn");
    if (withdrawn.has(item.itemId)) throw new Error(`duplicate withdrawal: ${item.itemId}`);
    withdrawn.add(item.itemId);
  }
  const dispositioned = new Set<string>();
  for (const disposition of dispositions) {
    if (!itemMap.has(disposition.itemId)) {
      throw new Error(`disposition references unknown item: ${disposition.itemId}`);
    }
    if (dispositioned.has(disposition.itemId)) {
      throw new Error(`duplicate disposition: ${disposition.itemId}`);
    }
    if (withdrawn.has(disposition.itemId)) {
      throw new Error(`withdrawn item also dispositioned: ${disposition.itemId}`);
    }
    dispositioned.add(disposition.itemId);
  }
  return items.every((item) => withdrawn.has(item.itemId) || dispositioned.has(item.itemId));
}

export function minutesActionManifestHash(manifest: MinutesActionManifest): string {
  return canonicalSha256(MinutesActionManifestSchema.parse(manifest));
}

export interface DraftActionRef {
  readonly taskId: string;
  readonly state: "draft";
  readonly sourceMinutesSha256: string;
}

export function activationManifestHash(
  manifestInput: MinutesActionManifest,
  tasks: readonly DraftActionRef[]
): string {
  const manifest = MinutesActionManifestSchema.parse(manifestInput);
  const expectedIds =
    manifest.declaration === "items_logged"
      ? manifest.items.map((item) => item.itemId).toSorted()
      : [];
  const actualIds = tasks.map((task) => task.taskId).toSorted();
  if (canonicalSha256(expectedIds) !== canonicalSha256(actualIds)) {
    throw new Error("draft tasks do not match the exact action manifest");
  }
  for (const task of tasks) {
    if (!safeHashEqual(task.sourceMinutesSha256, manifest.minutesSha256)) {
      throw new Error("draft task source minutes hash mismatch");
    }
  }
  return canonicalSha256({
    schemaVersion: "boardagent.minutes-action-activation.v1",
    manifestSha256: minutesActionManifestHash(manifest),
    taskIds: actualIds
  });
}
