import { registryData } from "../generated/registry.data.js";

import { assertRegistryInvariants, registryDigest } from "./schema.js";

export * from "./schema.js";
export * from "../generated/registry.ids.js";

export const BOARDAGENT_REGISTRY = Object.freeze(assertRegistryInvariants(registryData));
export const BOARDAGENT_REGISTRY_DIGEST = registryDigest(BOARDAGENT_REGISTRY);

export const BOARDAGENT_TOOL_BY_NAME = new Map(
  BOARDAGENT_REGISTRY.tools.map((entry) => [entry.name, entry] as const)
);
export const BOARDAGENT_EVENT_BY_NAME = new Map(
  BOARDAGENT_REGISTRY.events.map((entry) => [entry.name, entry] as const)
);
