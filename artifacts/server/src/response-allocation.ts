import { AsyncLocalStorage } from "node:async_hooks";

// Allocation units cap admitted work, not RSS. These are internal candidate constants;
// qualifying the deployment memory envelope remains separate from this two-lane policy.
const UNIT_BYTES = 1_048_576;
const BASE_BYTES = 65_536;
const MAX_CANONICAL_BYTES = 10_485_760;
const TOTAL_UNITS = 2_048;
const SMALL_RESERVED_UNITS = 128;
const activeOwner = new AsyncLocalStorage<ResponseAllocationOwner>();

export class ResponseAllocationUnavailable extends Error {
  public constructor() {
    super("Response capacity is busy. Retry this read shortly.");
    this.name = "ResponseAllocationUnavailable";
  }
}

export interface ResponseAllocationPlan {
  readonly kind:
    | "document"
    | "export"
    | "transcript"
    | "transcript_tool"
    | "communications_list"
    | "canonical_resource"
    | "minutes_text"
    | "governance_list_projection"
    | "document_metadata_projection"
    | "fixed_read_projection"
    | "draft_resume_projection"
    | "meeting_list_projection"
    | "minutes_list_projection"
    | "minutes_tool_projection"
    | "meeting_tool_projection"
    | "board_vote_read_projection"
    | "identity_onboarding_projection"
    | "export_status_projection"
    | "json_resource"
    | "search_projection"
    | "board_projection"
    | "management_read_projection"
    | "question_projection"
    | "vote_projection"
    | "certificate_projection"
    | "certificate_tool_projection"
    | "vote_tool_projection"
    | "governance_tool_projection"
    | "minutes_lineage_projection"
    | "task_projection"
    | "task_tool_projection";
  readonly representation: "tool" | "resource";
  readonly sourceId: string;
  readonly sourceVersion: string;
  readonly sha256: string;
  readonly canonicalBytes: number;
  readonly transcriptProjection?: TranscriptProjectionScalars;
  readonly listProjection?: ListProjectionScalars;
  readonly wireUpperBytes: number;
  readonly units: number;
}

export interface ListProjectionScalars {
  readonly jsonUpperBytes: string;
  readonly propertyCount: string;
  readonly objectOrArrayCount: string;
}

// These are decimal scalar results, never child IDs, JSON, or payload strings.
export interface TranscriptProjectionScalars {
  readonly rootUtf8Bytes: string;
  readonly turnCount: string;
  readonly turnUtf8Bytes: string;
  readonly challengeCount: string;
  readonly challengeUtf8Bytes: string;
  readonly verificationCount: string;
  readonly verificationUtf8Bytes: string;
}

// Exact fixed-key/delimiter allowances, including PostgreSQL JSON whitespace.
// Each object uses 2 + sum(key.length + 10); arrays add two bytes per item.
export const TRANSCRIPT_PROJECTION_FIXED = Object.freeze({
  rootJson: 312,
  turnJson: 170,
  challengeJson: 159,
  verificationJson: 109,
  resultJson: 4_096
});

function projectionScalar(value: string, kind = "transcript"): bigint {
  if (typeof value !== "string") throw new TypeError(`${kind} projection scalar is invalid`);
  // A legitimate aggregate beyond this bounded parser is certainly inadmissible.
  if (value.length > 24) throw new ResponseAllocationUnavailable();
  if (!/^(0|[1-9][0-9]*)$/u.test(value))
    throw new TypeError(`${kind} projection scalar is invalid`);
  return BigInt(value);
}

export function transcriptProjectionCost(
  canonicalBytes: number,
  input: TranscriptProjectionScalars
): Readonly<{
  rawByteaBytes: number;
  viewJsonUpperBytes: number;
  allocationBytes: number;
  wireUpperBytes: number;
  propertyCount: number;
  objectOrArrayCount: number;
}> {
  if (
    !Number.isSafeInteger(canonicalBytes) ||
    canonicalBytes < 1 ||
    canonicalBytes > MAX_CANONICAL_BYTES
  )
    throw new RangeError("authorized response byte length is invalid");
  const n = BigInt(canonicalBytes);
  const root = projectionScalar(input.rootUtf8Bytes);
  const turns = projectionScalar(input.turnCount);
  const turnText = projectionScalar(input.turnUtf8Bytes);
  const challenges = projectionScalar(input.challengeCount);
  const challengeText = projectionScalar(input.challengeUtf8Bytes);
  const verification = projectionScalar(input.verificationCount);
  const verificationText = projectionScalar(input.verificationUtf8Bytes);
  if (verification > 1n) throw new TypeError("transcript projection verification count is invalid");
  const fixed = TRANSCRIPT_PROJECTION_FIXED;
  const view =
    BigInt(fixed.rootJson) +
    6n * (n + root + turnText + challengeText + verificationText) +
    BigInt(fixed.turnJson) * turns +
    BigInt(fixed.challengeJson) * challenges +
    BigInt(fixed.verificationJson) * verification;
  const properties = 22n + 8n * turns + 7n * challenges + 5n * verification;
  const objects = 5n + turns + challenges + verification;
  // Accounting policy, not measured RSS: 80N + 8*(6N + other projection costs)
  // retains at least the existing 128N body allowance and charges all child nodes.
  // The separate raw bytea return costs N; the remaining 79N is policy allowance.
  const allocation =
    BigInt(BASE_BYTES) +
    n +
    79n * n +
    8n * (view + BigInt(fixed.resultJson)) +
    256n * properties +
    512n * objects;
  // A valid serialized JSON string expands by at most 2x when quoted once more;
  // the tool's text copy plus structured copy therefore use at most 3x.
  const wire = BigInt(BASE_BYTES) + 3n * (view + BigInt(fixed.resultJson));
  const maximum = BigInt(Number.MAX_SAFE_INTEGER);
  if ([view, allocation, wire, properties, objects].some((value) => value > maximum))
    throw new ResponseAllocationUnavailable();
  return Object.freeze({
    rawByteaBytes: canonicalBytes,
    viewJsonUpperBytes: Number(view),
    allocationBytes: Number(allocation),
    wireUpperBytes: Number(wire),
    propertyCount: Number(properties),
    objectOrArrayCount: Number(objects)
  });
}

export function responseAllocationPlan(input: {
  readonly kind:
    | "document"
    | "export"
    | "transcript"
    | "transcript_tool"
    | "communications_list"
    | "canonical_resource"
    | "minutes_text"
    | "governance_list_projection"
    | "document_metadata_projection"
    | "fixed_read_projection"
    | "draft_resume_projection"
    | "meeting_list_projection"
    | "minutes_list_projection"
    | "minutes_tool_projection"
    | "meeting_tool_projection"
    | "board_vote_read_projection"
    | "identity_onboarding_projection"
    | "export_status_projection"
    | "json_resource"
    | "search_projection"
    | "board_projection"
    | "management_read_projection"
    | "question_projection"
    | "vote_projection"
    | "certificate_projection"
    | "certificate_tool_projection"
    | "vote_tool_projection"
    | "governance_tool_projection"
    | "minutes_lineage_projection"
    | "task_projection"
    | "task_tool_projection";
  readonly representation: "tool" | "resource";
  readonly sourceId: string;
  readonly sourceVersion: string;
  readonly sha256: string;
  readonly canonicalBytes: number;
  readonly transcriptProjection?: TranscriptProjectionScalars;
  readonly listProjection?: ListProjectionScalars;
}): ResponseAllocationPlan {
  if (
    ![
      "document",
      "export",
      "transcript",
      "transcript_tool",
      "communications_list",
      "canonical_resource",
      "minutes_text",
      "governance_list_projection",
      "document_metadata_projection",
      "fixed_read_projection",
      "draft_resume_projection",
      "meeting_list_projection",
      "minutes_list_projection",
      "minutes_tool_projection",
      "meeting_tool_projection",
      "board_vote_read_projection",
      "identity_onboarding_projection",
      "export_status_projection",
      "json_resource",
      "search_projection",
      "board_projection",
      "management_read_projection",
      "question_projection",
      "vote_projection",
      "certificate_projection",
      "certificate_tool_projection",
      "vote_tool_projection",
      "governance_tool_projection",
      "minutes_lineage_projection",
      "task_projection",
      "task_tool_projection"
    ].includes(input.kind) ||
    !["tool", "resource"].includes(input.representation)
  )
    throw new TypeError("response allocation representation is invalid");
  // A raw transcript annex is bounded; its composite tool result is a separate plan.
  if (input.kind === "transcript" && input.representation !== "resource")
    throw new TypeError("transcript allocation requires the resource representation");
  if (input.kind === "canonical_resource" && input.representation !== "resource")
    throw new TypeError("canonical version allocation requires the resource representation");
  if (input.kind === "minutes_text" && input.representation !== "resource")
    throw new TypeError("minutes text allocation requires the resource representation");
  if (input.kind === "json_resource" && input.representation !== "resource")
    throw new TypeError("JSON resource allocation requires the resource representation");
  // minutes_versions bounds characters; a valid UTF-8 character occupies up to four bytes.
  const n = input.canonicalBytes;
  if (
    !Number.isSafeInteger(n) ||
    n <
      (input.kind === "canonical_resource" || input.kind === "json_resource"
        ? 2
        : input.kind === "transcript" ||
            input.kind === "transcript_tool" ||
            input.kind === "minutes_text"
          ? 1
          : 0) ||
    (input.kind !== "communications_list" &&
      input.kind !== "json_resource" &&
      n > (input.kind === "minutes_text" ? 4 * MAX_CANONICAL_BYTES : MAX_CANONICAL_BYTES))
  )
    throw new RangeError("authorized response byte length is invalid");
  if (!/^[a-f0-9]{64}$/u.test(input.sha256))
    throw new TypeError("authorized response digest is invalid");
  if (
    !input.sourceId ||
    input.sourceId.length > 256 ||
    !input.sourceVersion ||
    input.sourceVersion.length > 256
  )
    throw new TypeError("authorized response identity is invalid");
  if (input.kind === "fixed_read_projection" && (n !== 0 || input.representation !== "tool"))
    throw new TypeError("fixed read requires tool representation without canonical bytes");
  if (input.kind === "search_projection" && n !== 0)
    throw new TypeError("search projection does not load canonical bytes");
  if (input.kind === "question_projection" && n !== 0)
    throw new TypeError("question projection does not load canonical bytes");
  if (input.kind === "vote_projection" && (n !== 0 || input.representation !== "resource"))
    throw new TypeError("vote projection requires resource representation without canonical bytes");
  if (input.kind === "certificate_projection" && (n !== 0 || input.representation !== "resource"))
    throw new TypeError(
      "certificate projection requires resource representation without canonical bytes"
    );
  if (input.kind === "certificate_tool_projection" && (n !== 0 || input.representation !== "tool"))
    throw new TypeError(
      "certificate tool projection requires tool representation without canonical bytes"
    );
  if (input.kind === "governance_list_projection" && (n !== 0 || input.representation !== "tool"))
    throw new TypeError(
      "governance list projection requires tool representation without canonical bytes"
    );
  if (input.kind === "document_metadata_projection" && (n !== 0 || input.representation !== "tool"))
    throw new TypeError(
      "document metadata projection requires tool representation without canonical bytes"
    );
  if (input.kind === "management_read_projection" && (n !== 0 || input.representation !== "tool"))
    throw new TypeError(
      "management read projection requires tool representation without canonical bytes"
    );
  if (input.kind === "meeting_list_projection" && (n !== 0 || input.representation !== "tool"))
    throw new TypeError(
      "meeting list projection requires tool representation without canonical bytes"
    );
  if (input.kind === "minutes_list_projection" && (n !== 0 || input.representation !== "tool"))
    throw new TypeError(
      "minutes list projection requires tool representation without canonical bytes"
    );
  if (input.kind === "export_status_projection" && (n !== 0 || input.representation !== "tool"))
    throw new TypeError("export status requires tool representation without canonical bytes");
  if (
    input.kind === "identity_onboarding_projection" &&
    (n !== 0 || input.representation !== "tool")
  )
    throw new TypeError("identity/onboarding requires tool representation without canonical bytes");
  if (input.kind === "board_vote_read_projection" && (n !== 0 || input.representation !== "tool"))
    throw new TypeError("board/vote reads require tool representation without canonical bytes");
  if (input.kind === "meeting_tool_projection" && (n !== 0 || input.representation !== "tool"))
    throw new TypeError(
      "meeting tool projection requires tool representation without canonical bytes"
    );
  if (input.kind === "minutes_tool_projection" && (n !== 0 || input.representation !== "tool"))
    throw new TypeError(
      "minutes tool projection requires tool representation without canonical bytes"
    );
  if (input.kind === "vote_tool_projection" && (n !== 0 || input.representation !== "tool"))
    throw new TypeError(
      "vote tool projection requires tool representation without canonical bytes"
    );
  if (input.kind === "governance_tool_projection" && (n !== 0 || input.representation !== "tool"))
    throw new TypeError(
      "governance tool projection requires tool representation without canonical bytes"
    );
  if (input.kind === "minutes_lineage_projection" && (n !== 0 || input.representation !== "tool"))
    throw new TypeError("minutes lineage requires tool representation without canonical bytes");
  if (input.kind === "task_projection" && (n !== 0 || input.representation !== "resource"))
    throw new TypeError("task projection requires resource representation without canonical bytes");
  if (input.kind === "task_tool_projection" && (n !== 0 || input.representation !== "tool"))
    throw new TypeError(
      "task tool projection requires tool representation without canonical bytes"
    );
  if (input.kind === "draft_resume_projection" && (n !== 0 || input.representation !== "tool"))
    throw new TypeError("draft resume requires tool representation without canonical bytes");
  if (input.kind === "board_projection") {
    if (n !== 0 || input.listProjection || input.transcriptProjection)
      throw new TypeError("board projection requires its fixed field allowance");
    // Each of the two existing board point views has ten flat fields. The board
    // name/timezone/slug storage limits and UUID/bigint/fixed-date fields fit a
    // 32 KiB serialized view even with JSON escaping. This does not admit a
    // board-version payload, child graph, list or snapshot under the same plan.
    // Private accounting policy, not a measured V8/RSS guarantee.
    const json = 32_768 + 4_096;
    const allocation = BASE_BYTES + 8 * json + 256 * 38 + 512 * 10;
    return Object.freeze({
      ...input,
      wireUpperBytes: BASE_BYTES + (input.representation === "tool" ? 3 : 2) * json,
      units: Math.ceil(allocation / UNIT_BYTES)
    });
  }
  if (
    input.kind === "communications_list" ||
    input.kind === "governance_list_projection" ||
    input.kind === "document_metadata_projection" ||
    input.kind === "fixed_read_projection" ||
    input.kind === "draft_resume_projection" ||
    input.kind === "meeting_list_projection" ||
    input.kind === "minutes_list_projection" ||
    input.kind === "minutes_tool_projection" ||
    input.kind === "meeting_tool_projection" ||
    input.kind === "board_vote_read_projection" ||
    input.kind === "identity_onboarding_projection" ||
    input.kind === "export_status_projection" ||
    input.kind === "search_projection" ||
    input.kind === "management_read_projection" ||
    input.kind === "question_projection" ||
    input.kind === "vote_projection" ||
    input.kind === "certificate_projection" ||
    input.kind === "certificate_tool_projection" ||
    input.kind === "vote_tool_projection" ||
    input.kind === "governance_tool_projection" ||
    input.kind === "minutes_lineage_projection" ||
    input.kind === "task_projection" ||
    input.kind === "task_tool_projection"
  ) {
    if (
      (input.kind !== "question_projection" &&
        input.kind !== "vote_projection" &&
        input.kind !== "certificate_projection" &&
        input.kind !== "task_projection" &&
        input.representation !== "tool") ||
      !input.listProjection ||
      input.transcriptProjection
    )
      throw new TypeError("list allocation requires its projection scalars");
    const projection = Object.freeze({ ...input.listProjection });
    const json = projectionScalar(projection.jsonUpperBytes, "list");
    const properties = projectionScalar(projection.propertyCount, "list");
    const containers = projectionScalar(projection.objectOrArrayCount, "list");
    // Communications retain raw inspection work. Search transfers no source text
    // and requires N=0; it charges measured response projection/encoding and graph work.
    // These are private policy estimates, not a measured memory guarantee.
    const allocation =
      BigInt(BASE_BYTES) +
      128n * BigInt(n) +
      8n * (json + 4_096n) +
      256n * properties +
      512n * containers;
    const wire = BigInt(BASE_BYTES) + (input.representation === "tool" ? 3n : 2n) * (json + 4_096n);
    if (allocation > BigInt(Number.MAX_SAFE_INTEGER) || wire > BigInt(Number.MAX_SAFE_INTEGER))
      throw new ResponseAllocationUnavailable();
    return Object.freeze({
      ...input,
      listProjection: projection,
      wireUpperBytes: Number(wire),
      units: Math.ceil(Number(allocation) / UNIT_BYTES)
    });
  }
  if (input.listProjection)
    throw new TypeError("list projection is not valid for this allocation kind");
  if (input.kind === "transcript_tool") {
    if (input.representation !== "tool" || !input.transcriptProjection)
      throw new TypeError("transcript tool allocation requires the complete projection");
    const projection = Object.freeze({ ...input.transcriptProjection });
    const cost = transcriptProjectionCost(n, projection);
    return Object.freeze({
      ...input,
      transcriptProjection: projection,
      wireUpperBytes: cost.wireUpperBytes,
      units: Math.ceil(cost.allocationBytes / UNIT_BYTES)
    });
  }
  if (input.transcriptProjection)
    throw new TypeError("transcript projection is not valid for this allocation kind");
  const canonicalText =
    input.kind === "document" ||
    input.kind === "transcript" ||
    input.kind === "canonical_resource" ||
    input.kind === "minutes_text" ||
    input.kind === "json_resource";
  const wireBody = canonicalText
    ? (input.representation === "tool" ? 18 : 6) * n
    : (input.representation === "tool" ? 2 : 1) * 4 * Math.ceil(n / 3);
  const wireUpperBytes = BASE_BYTES + wireBody;
  // Deliberately do not discount the unmeasured resource aliases from tool calibration.
  const allocationBytes = BASE_BYTES + (canonicalText ? 128 : 64) * n;
  if (!Number.isSafeInteger(wireUpperBytes) || !Number.isSafeInteger(allocationBytes))
    throw new RangeError("response allocation arithmetic overflow");
  return Object.freeze({
    ...input,
    wireUpperBytes,
    units: Math.ceil(allocationBytes / UNIT_BYTES)
  });
}

export interface ResponseAllocationReservation {
  increase(plan: ResponseAllocationPlan): void;
}

interface AllocationLease extends ResponseAllocationReservation {
  release(): void;
}
export class ResponseAllocationManager {
  private used = 0;
  private largeUsed = 0;

  public get accounting(): Readonly<{ usedUnits: number; largeUsedUnits: number }> {
    return { usedUnits: this.used, largeUsedUnits: this.largeUsed };
  }

  public openRequest(signal: AbortSignal): ResponseAllocationOwner {
    return new ResponseAllocationOwner(this, signal);
  }

  public tryReserve(plan: ResponseAllocationPlan): AllocationLease {
    // Recompute trusted arithmetic; do not accept a caller's invented unit count.
    let checked = responseAllocationPlan(plan);
    let units = checked.units;
    let large = units > 1;
    if (
      this.used + units > TOTAL_UNITS ||
      (large && this.largeUsed + units > TOTAL_UNITS - SMALL_RESERVED_UNITS)
    )
      throw new ResponseAllocationUnavailable();
    this.used += units;
    if (large) this.largeUsed += units;
    let released = false;
    return {
      increase: (nextPlan) => {
        if (released) throw new ResponseAllocationUnavailable();
        const next = responseAllocationPlan(nextPlan);
        if (
          checked.kind !== "communications_list" ||
          next.kind !== checked.kind ||
          next.representation !== checked.representation ||
          next.sourceId !== checked.sourceId ||
          next.sourceVersion !== checked.sourceVersion ||
          next.sha256 !== checked.sha256 ||
          next.canonicalBytes !== checked.canonicalBytes ||
          !checked.listProjection ||
          !next.listProjection
        )
          throw new TypeError("response allocation growth requires the same list frontier");
        for (const key of ["jsonUpperBytes", "propertyCount", "objectOrArrayCount"] as const)
          if (
            projectionScalar(next.listProjection[key], "list") <
            projectionScalar(checked.listProjection[key], "list")
          )
            throw new TypeError("response allocation growth cannot reduce a projection bound");
        const nextUsed = this.used - units + next.units;
        const nextLarge = this.largeUsed - (large ? units : 0) + (next.units > 1 ? next.units : 0);
        if (nextUsed > TOTAL_UNITS || nextLarge > TOTAL_UNITS - SMALL_RESERVED_UNITS)
          throw new ResponseAllocationUnavailable();
        // One atomic accounting transition: failed growth leaves the inspection
        // lease intact, and a small-to-large transition charges the entire lease.
        this.used = nextUsed;
        this.largeUsed = nextLarge;
        checked = next;
        units = next.units;
        large = units > 1;
      },
      release: () => {
        if (released) return;
        released = true;
        this.used -= units;
        if (large) this.largeUsed -= units;
      }
    };
  }
}

export class ResponseAllocationOwner {
  private readonly leases: AllocationLease[] = [];
  private producers = 0;
  private nativeEnded = false;
  private collectorEnded = false;
  private idleWaiters: Array<() => void> = [];
  public constructor(
    private readonly manager: ResponseAllocationManager,
    public readonly signal: AbortSignal
  ) {}

  public run<T>(work: () => T): T {
    return activeOwner.run(this, work);
  }

  // This scope MUST wrap the SDK Server super._wrapHandler promise, including output
  // validation, not just the application's callback promise.
  public async produce<T>(work: () => Promise<T>): Promise<T> {
    this.assertLive();
    this.producers += 1;
    try {
      const result = await this.run(work);
      // An already disconnected request must not hand its large result to SDK encoding.
      this.assertLive();
      return result;
    } finally {
      this.producers -= 1;
      if (this.producers === 0) {
        const waiters = this.idleWaiters.splice(0);
        for (const resolve of waiters) resolve();
      }
      this.maybeRelease();
    }
  }

  public reserve(plan: ResponseAllocationPlan): ResponseAllocationReservation {
    this.assertLive();
    if (this.producers === 0) throw new Error("response allocation requires an active producer");
    const lease = this.manager.tryReserve(plan);
    this.leases.push(lease);
    return Object.freeze({
      increase: (next: ResponseAllocationPlan) => {
        this.assertLive();
        if (this.producers === 0)
          throw new Error("response allocation requires an active producer");
        lease.increase(next);
      }
    });
  }

  public assertLive(): void {
    if (this.signal.aborted || this.nativeEnded) throw new ResponseAllocationUnavailable();
  }

  public nativeTerminal(): void {
    this.nativeEnded = true;
    this.maybeRelease();
  }
  public collectorSettled(): void {
    this.collectorEnded = true;
    this.maybeRelease();
  }
  public whenProducersDone(): Promise<void> {
    return this.producers === 0
      ? Promise.resolve()
      : new Promise((resolve) => this.idleWaiters.push(resolve));
  }

  private maybeRelease(): void {
    if (!this.nativeEnded || !this.collectorEnded || this.producers !== 0) return;
    for (const lease of this.leases.splice(0)) lease.release();
  }
}

export function currentResponseAllocationOwner(): ResponseAllocationOwner | undefined {
  return activeOwner.getStore();
}

export async function loadWithResponseAllocation<T>(
  plan: ResponseAllocationPlan,
  load: () => Promise<T>
): Promise<T> {
  const owner = activeOwner.getStore();
  if (!owner) throw new Error("native response allocation owner is required");
  owner.reserve(plan);
  owner.assertLive();
  return load();
}
