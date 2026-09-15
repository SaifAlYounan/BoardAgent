import type { PoolClient } from "pg";
import { expect } from "vitest";
import type { JsonValue } from "../../lib/contracts/src/canonical.js";
import type { SurfacePrincipal } from "../../artifacts/server/src/ports.js";
import {
  originalIdentityOnboarding,
  originalIdentityBound,
  identityObject
} from "./identity-onboarding-postgres-oracle.js";

export const identityNativeTools = ["whoami", "get_onboarding", "get_onboarding_status"] as const;
export type IdentityNativeTool = (typeof identityNativeTools)[number];

// The shared oracle executes the exact original SQL and measures normalized
// PostgreSQL JSON text. No production projection or estimator is imported.
export async function originalIdentityNativeResult(
  client: PoolClient,
  tool: IdentityNativeTool,
  boardId: string,
  principal: SurfacePrincipal
) {
  const kind = tool === "whoami" ? "whoami" : "onboarding";
  const parameters =
    kind === "whoami"
      ? [
          principal.memberId,
          principal.roles,
          principal.scopes,
          principal.boardIds,
          principal.protocolClientId,
          principal.accessTokenRecordId
        ]
      : [boardId, principal.memberId];
  const original = await originalIdentityOnboarding(client, kind, parameters);
  // This native supplement requires the already proved ordinary one-row
  // fixture. It makes no public absence or multi-membership selection claim.
  expect(original.views).toHaveLength(1);
  const view = original.views[0]!;
  const data: JsonValue =
    tool === "whoami"
      ? view
      : tool === "get_onboarding"
        ? { onboarding: view }
        : {
            board_id: boardId,
            status: identityObject(view).attested === true ? "current" : "required",
            terms_version_id: identityObject(identityObject(view).terms).version_id ?? null
          };
  const envelope = {
    schema_version: "boardagent.tool-result.v1",
    tool,
    status: "ok",
    reference: tool === "whoami" ? principal.memberId : tool === "get_onboarding" ? boardId : null,
    resource_uri: null,
    data
  };
  return {
    envelope,
    metadata: original.metadata,
    // get_onboarding_status retains the complete PG onboarding view despite
    // returning only three public fields. Count that graph and its bytes.
    retained: original.views.map((view) => ({ fits: true, view })),
    bound: originalIdentityBound(kind, original.metadata)
  };
}
