import { describe, expect, it } from "vitest";

import {
  activeTokenContext,
  MemoryTokenStore,
  TOKEN_RESOURCE,
  tokenFixture
} from "../helpers/token-fixture.js";

describe("TH-08 token audience confusion", () => {
  it("rejects wrong JWT audience, resource claim, and ledger resource before use", async () => {
    const store = new MemoryTokenStore();
    const fixture = await tokenFixture(store);

    await expect(
      fixture.verify(await fixture.sign({ audience: "https://other.test/mcp" }))
    ).rejects.toThrow("cryptographic verification failed");
    expect(store.lookups).toEqual([]);

    await expect(
      fixture.verify(await fixture.sign({ resource: "https://other.test/mcp" }))
    ).rejects.toThrow("token resource mismatch");
    expect(store.lookups).toEqual([]);

    store.current = activeTokenContext({ resourceUri: "https://other.test/mcp" });
    await expect(fixture.verify(await fixture.sign())).rejects.toThrow(
      "claims do not match the BoardAgent ledger"
    );
    expect(store.lookups).toEqual([expect.any(String)]);
    expect(TOKEN_RESOURCE).toBe("https://boardagent.test/mcp");
  });
});
