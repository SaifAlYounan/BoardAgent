import {
  OAuthError,
  OAuthErrorCode,
  bearerAuthChallengeResponse,
  getOAuthProtectedResourceMetadataUrl,
  requireBearerAuth,
  type McpHttpHandler,
  type OAuthTokenVerifier
} from "@modelcontextprotocol/server";

const BEARER_HEADER = /^Bearer [A-Za-z0-9._~-]+$/iu;
const GENERIC_INVALID_TOKEN = "Bearer token is invalid";

export interface ProtectedMcpHandlerOptions {
  readonly handler: McpHttpHandler;
  readonly resourceUri: string;
  readonly verifier: OAuthTokenVerifier;
  readonly requiredScopes?: readonly string[];
}

function canonicalResource(resourceUri: string): URL {
  let resource: URL;
  try {
    resource = new URL(resourceUri);
  } catch {
    throw new Error("canonical MCP resource URI must be an absolute URL");
  }
  if (
    resourceUri !== resource.href ||
    resource.username !== "" ||
    resource.password !== "" ||
    resource.search !== "" ||
    resource.hash !== ""
  ) {
    throw new Error("canonical MCP resource URI must be an exact origin plus path");
  }
  return resource;
}

function invalidTokenResponse(resourceMetadataUrl: string): Response {
  return bearerAuthChallengeResponse(
    new OAuthError(OAuthErrorCode.InvalidToken, GENERIC_INVALID_TOKEN),
    { resourceMetadataUrl }
  );
}

function exactResourceRequest(request: Request, resource: URL): boolean {
  const target = new URL(request.url);
  return (
    target.origin === resource.origin &&
    target.pathname === resource.pathname &&
    target.search === "" &&
    target.hash === ""
  );
}

/**
 * Protects the web-standard MCP handler at the canonical resource boundary.
 * Caller-supplied handler auth state is always replaced with verified bearer state.
 */
export function createProtectedMcpHandler(options: ProtectedMcpHandlerOptions): McpHttpHandler {
  const resource = canonicalResource(options.resourceUri);
  const resourceMetadataUrl = getOAuthProtectedResourceMetadataUrl(resource);
  const gate = requireBearerAuth({
    verifier: options.verifier,
    ...(options.requiredScopes === undefined
      ? {}
      : { requiredScopes: [...options.requiredScopes] }),
    resourceMetadataUrl
  });

  return {
    fetch: async (request, requestOptions) => {
      const authorization = request.headers.get("authorization");
      if (!authorization || !BEARER_HEADER.test(authorization)) {
        return invalidTokenResponse(resourceMetadataUrl);
      }

      const verified = await gate(request);
      if (verified instanceof Response) {
        return verified.status === 401 ? invalidTokenResponse(resourceMetadataUrl) : verified;
      }
      if (verified.resource?.href !== resource.href) {
        return invalidTokenResponse(resourceMetadataUrl);
      }
      if (!exactResourceRequest(request, resource)) {
        return Response.json({ error: "not_found" }, { status: 404 });
      }

      return options.handler.fetch(request, { ...requestOptions, authInfo: verified });
    },
    close: () => options.handler.close(),
    notify: options.handler.notify,
    bus: options.handler.bus
  };
}
