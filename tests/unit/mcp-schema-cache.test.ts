import { McpServer } from "@modelcontextprotocol/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { memoizeSchemaExports } from "../../artifacts/server/src/mcp-schema-cache.js";

const target = { target: "draft-2020-12" } as const;
afterEach(() => vi.restoreAllMocks());

describe("immutable MCP schema exports", () => {
  it("converts each direction once across fresh SDK registrations and freezes the shared graph", async () => {
    const original = z.object({ text: z.string().max(20) }).strict();
    const inputExport = vi.spyOn(original["~standard"].jsonSchema, "input");
    const outputExport = vi.spyOn(original["~standard"].jsonSchema, "output");
    const schema = memoizeSchemaExports(original);
    expect(memoizeSchemaExports(original)).toBe(schema);
    const servers = Array.from(
      { length: 3 },
      () => new McpServer({ name: "cache-fixture", version: "1" })
    );
    try {
      for (const server of servers) {
        server.registerTool("echo", { inputSchema: schema, outputSchema: schema }, ({ text }) => ({
          content: [{ type: "text", text }],
          structuredContent: { text }
        }));
      }
      expect(new Set(servers.map((server) => server.server)).size).toBe(3);
      const json = schema["~standard"].jsonSchema.output(target);
      const properties = json["properties"] as Record<string, Record<string, unknown>>;
      expect(Object.isFrozen(json)).toBe(true);
      expect(Object.isFrozen(properties)).toBe(true);
      expect(Object.isFrozen(properties["text"])).toBe(true);
      expect(Reflect.set(properties["text"]!, "maxLength", 999)).toBe(false);
      expect(schema["~standard"].jsonSchema.output(target)).toBe(json);
      expect(inputExport).toHaveBeenCalledTimes(1);
      expect(outputExport).toHaveBeenCalledTimes(1);
    } finally {
      await Promise.all(servers.map((server) => server.close()));
    }
  });

  it("delegates every validation with original transforms, async refinements and strictness", async () => {
    const original = z
      .object({
        text: z
          .string()
          .transform((text) => text.trim())
          .superRefine(async (text, ctx) => {
            await Promise.resolve();
            if (text !== "approved")
              ctx.addIssue({ code: "custom", message: "exact approval required" });
          })
      })
      .strict();
    const validate = vi.spyOn(original["~standard"], "validate");
    const schema = memoizeSchemaExports(original);
    const options = { libraryOptions: {} };
    expect(await schema["~standard"].validate({ text: " approved " }, options)).toEqual({
      value: { text: "approved" }
    });
    expect(validate).toHaveBeenLastCalledWith({ text: " approved " }, options);
    expect((await schema["~standard"].validate({ text: "denied" })).issues).toEqual(
      expect.arrayContaining([expect.objectContaining({ message: "exact approval required" })])
    );
    expect(
      (await schema["~standard"].validate({ text: "approved", injected: true })).issues
    ).toBeDefined();
    expect(validate).toHaveBeenCalledTimes(3);
  });

  it("does not reuse exports for different targets or library options", () => {
    const original = z.object({ text: z.string() });
    const inputExport = vi.spyOn(original["~standard"].jsonSchema, "input");
    const schema = memoizeSchemaExports(original);
    const first = schema["~standard"].jsonSchema.input(target);
    expect(schema["~standard"].jsonSchema.input(target)).toBe(first);
    const draft7 = schema["~standard"].jsonSchema.input({ target: "draft-07" });
    expect(draft7["$schema"]).toContain("draft-07");
    schema["~standard"].jsonSchema.input({ target: "draft-07" });
    schema["~standard"].jsonSchema.input({ ...target, libraryOptions: {} });
    schema["~standard"].jsonSchema.input({ ...target, libraryOptions: {} });
    expect(inputExport).toHaveBeenCalledTimes(5);
  });

  it("preserves conversion failures and retries without caching a failed graph", () => {
    const original = z.object({ text: z.string() });
    const convert = original["~standard"].jsonSchema.input;
    const inputExport = vi
      .spyOn(original["~standard"].jsonSchema, "input")
      .mockImplementationOnce(() => {
        throw new Error("synthetic conversion failure");
      })
      .mockImplementation(convert);
    const schema = memoizeSchemaExports(original);
    expect(() => schema["~standard"].jsonSchema.input(target)).toThrow(
      "synthetic conversion failure"
    );
    const json = schema["~standard"].jsonSchema.input(target);
    expect(schema["~standard"].jsonSchema.input(target)).toBe(json);
    expect(inputExport).toHaveBeenCalledTimes(2);
  });
});
