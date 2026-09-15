import { ACTIVE_REGISTRY_COUNTS } from "../../lib/contracts/src/registry/schema.js";

export interface VerificationPointer {
  readonly id: string;
  readonly implementation: string;
  readonly proof: string;
  readonly status: "PROVEN" | "UNRESOLVED";
}

function parseVerificationPointers(markdown: string): readonly VerificationPointer[] {
  const pointers: VerificationPointer[] = [];
  for (const line of markdown.split(/\r?\n/u)) {
    if (!/^\|\s*SR-\d{3}\s*\|/u.test(line)) continue;
    const cells = line
      .trim()
      .replace(/^\|/u, "")
      .replace(/\|$/u, "")
      .split("|")
      .map((cell) => cell.trim());
    if (cells.length !== 5) {
      throw new Error(`verification table width drift: ${line}`);
    }
    const [id, , implementation, proof, status] = cells;
    if (id === undefined || implementation === undefined || proof === undefined) {
      throw new Error(`malformed verification row: ${line}`);
    }
    if (status !== "PROVEN" && status !== "UNRESOLVED") {
      throw new Error(`invalid verification status for ${id}: ${status ?? "missing"}`);
    }
    pointers.push({ id, implementation, proof, status });
  }
  return pointers;
}

export function validateVerificationClosure(
  markdown: string,
  requireResolved = false
): readonly VerificationPointer[] {
  const pointers = parseVerificationPointers(markdown);
  if (pointers.length !== ACTIVE_REGISTRY_COUNTS.securityRequirements) {
    throw new Error(
      `verification row count drift: expected ${String(ACTIVE_REGISTRY_COUNTS.securityRequirements)}, got ${String(pointers.length)}`
    );
  }
  const seen = new Set<string>();
  pointers.forEach((pointer, index) => {
    const expected = `SR-${String(index + 1).padStart(3, "0")}`;
    if (pointer.id !== expected) {
      throw new Error(`verification sequence drift: expected ${expected}, got ${pointer.id}`);
    }
    if (seen.has(pointer.id)) throw new Error(`duplicate verification row: ${pointer.id}`);
    seen.add(pointer.id);
    if (pointer.status === "PROVEN") {
      if (!/`(?:artifacts|lib|scripts)\/[^`]+`/u.test(pointer.implementation)) {
        throw new Error(`${pointer.id} PROVEN without an exact product pointer`);
      }
      if (!/`tests\/[^`]+`/u.test(pointer.proof)) {
        throw new Error(`${pointer.id} PROVEN without an exact test pointer`);
      }
    }
    if (requireResolved && pointer.status !== "PROVEN") {
      throw new Error(`${pointer.id} is unresolved`);
    }
  });
  return pointers;
}
