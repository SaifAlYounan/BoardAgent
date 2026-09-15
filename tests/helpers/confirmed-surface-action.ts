import type {
  BoardAgentSurfaceService,
  SurfacePrincipal
} from "../../artifacts/server/src/index.js";
import type { JsonValue } from "../../lib/contracts/src/index.js";

let sequence = 0;

/** Synthetic MRTR confirmation; never represents a user's personal acceptance. */
export async function confirmSyntheticSurfaceAction(
  service: BoardAgentSurfaceService,
  principal: SurfacePrincipal,
  tool: string,
  input: JsonValue
) {
  const label = `synthetic-surface-${++sequence}`;
  const prepared = await service.prepareHumanAction(principal, tool, input);
  const capabilities = { elicitation: { form: {} } };
  const requestState = `${label}-protected-state-bound-to-the-original-request`;
  await service.persistHumanStage({
    principal,
    tool,
    input,
    prepared,
    client_capabilities: capabilities,
    embedded_form: { type: "object", required: ["approve", "confirmation_code"] },
    embedded_result: { message: `Confirm ${tool}` },
    request_state: requestState,
    prepared_request_id: Buffer.from(`${label}-prepare`)
  });
  const resolution = await service.resolveHumanAction({
    principal,
    tool,
    input,
    stage_id: prepared.stage_id,
    client_capabilities: capabilities,
    request_state: requestState,
    retry_request_id: Buffer.from(`${label}-retry`),
    response_action: "accept",
    input_response: { approve: true, confirmation_code: prepared.confirmation_code }
  });
  if (!resolution.confirmed) throw new Error(`${tool}: ${resolution.reason}`);
  return { prepared, result: resolution.result };
}
