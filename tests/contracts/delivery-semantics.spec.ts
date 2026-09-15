import { describe, expect, it } from "vitest";

import { registryData } from "../../lib/contracts/src/generated/registry.data.js";
import { EVENT_IDS } from "../../lib/contracts/src/generated/registry.ids.js";

describe("TH-49 delivery evidence semantics", () => {
  it("defines committed handoff without inventing human receipt or understanding", () => {
    expect(EVENT_IDS).toContain("notice_delivered");
    expect(EVENT_IDS.filter((event) => /human_(?:read|received|understood)/u.test(event))).toEqual(
      []
    );
    expect(registryData.securityRequirements.find(({ id }) => id === "SR-072")?.requirement).toBe(
      "`notice_delivered` means committed recipient feed/channel handoff only, never human receipt/reading."
    );
  });
});
