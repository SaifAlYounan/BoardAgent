import type { StandardSchemaWithJSON } from "@modelcontextprotocol/server";

type JsonExporter = StandardSchemaWithJSON["~standard"]["jsonSchema"]["input"];
const adapters = new WeakMap<object, StandardSchemaWithJSON>();

function freezeJsonGraph<T extends object>(value: T): T {
  const pending: object[] = [value];
  const seen = new WeakSet<object>();
  while (pending.length > 0) {
    const current = pending.pop()!;
    if (seen.has(current)) continue;
    seen.add(current);
    for (const child of Object.values(current) as unknown[]) {
      if (child !== null && typeof child === "object") pending.push(child);
    }
    Object.freeze(current);
  }
  return value;
}

function memoizedExporter(convert: JsonExporter): JsonExporter {
  let cached: Record<string, unknown> | undefined;
  return (options) => {
    // The pinned SDK requests this exact target without library options. Other
    // conversion settings retain the original behavior instead of reusing a graph
    // built for different settings. Successful exports alone enter the cache.
    if (options.target !== "draft-2020-12" || Object.keys(options).some((key) => key !== "target"))
      return convert(options);
    return (cached ??= freezeJsonGraph(convert(options)));
  };
}

/**
 * Share immutable exports of the frozen tool schemas across fresh SDK servers.
 * Validation always uses the original schema, including refinements and transforms.
 * This adapter deliberately does not replace Zod prompt-shape introspection.
 */
export function memoizeSchemaExports<Input, Output>(
  schema: StandardSchemaWithJSON<Input, Output>
): StandardSchemaWithJSON<Input, Output> {
  const existing = adapters.get(schema);
  if (existing) return existing as StandardSchemaWithJSON<Input, Output>;
  const standard = schema["~standard"];
  const adapter: StandardSchemaWithJSON<Input, Output> = Object.freeze({
    "~standard": Object.freeze({
      ...standard,
      validate: (value: unknown, options?: Parameters<typeof standard.validate>[1]) =>
        standard.validate(value, options),
      jsonSchema: Object.freeze({
        input: memoizedExporter((options) => standard.jsonSchema.input(options)),
        output: memoizedExporter((options) => standard.jsonSchema.output(options))
      })
    })
  });
  adapters.set(schema, adapter);
  return adapter;
}
