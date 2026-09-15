import { AsyncLocalStorage } from "node:async_hooks";
import type { IncomingMessage } from "node:http";
import type { Pool } from "pg";
import { UuidV7Schema } from "@boardagent/contracts";
import { withIdentityTransaction } from "@boardagent/db";
import type { AuthRequestBoundary } from "./auth-page.js";
import {
  PgWebAuthnAttemptLimiter,
  type PgRateLimiter,
  type WebAuthnRateLimitPolicies
} from "./pg-rate-limiter.js";
import type { WebAuthnAttemptContext, WebAuthnAttemptLimiter } from "./webauthn.js";

/** HTTP context stays local to its async request; client identity comes from the stored session. */
export class RequestWebAuthnAttemptLimiter implements WebAuthnAttemptLimiter {
  private readonly requests = new AsyncLocalStorage<IncomingMessage>();
  public constructor(
    private readonly pool: Pool,
    private readonly options: {
      readonly boundary: AuthRequestBoundary;
      readonly limiter: PgRateLimiter;
      readonly policies: WebAuthnRateLimitPolicies;
      readonly assumeRole?: "boardagent_server";
    }
  ) {}

  public run<T>(request: IncomingMessage, callback: () => T): T {
    return this.requests.run(request, callback);
  }

  public async consume(context: WebAuthnAttemptContext) {
    const request = this.requests.getStore();
    if (!request) throw new Error("passkey attempt requires its HTTP request context");
    const inspection = this.options.boundary.inspect(request, { stateChanging: true });
    const organizationId = UuidV7Schema.parse(context.organizationId);
    const memberId = context.memberId === null ? null : UuidV7Schema.parse(context.memberId);
    let clientId: string;
    if (context.sessionId === null) {
      const registration =
        ["enrollment", "recovery"].includes(context.purpose) &&
        ["registration_begin", "registration_complete"].includes(context.operation);
      // The activation restart is the one session-less assertion: the person re-proves with
      // the passkey they registered before they hold any OAuth client or session.
      const restartAssertion =
        context.purpose === "activation_restart" &&
        ["authentication_begin", "authentication_complete"].includes(context.operation);
      if ((!registration && !restartAssertion) || memberId === null) {
        throw new Error("sessionless passkey attempt is unavailable");
      }
      // A person redeeming an enrollment has not registered an OAuth client yet.
      clientId =
        context.purpose === "recovery"
          ? "builtin-recovery"
          : context.purpose === "activation_restart"
            ? "builtin-activation-restart"
            : "builtin-enrollment";
    } else {
      const sessionId = UuidV7Schema.parse(context.sessionId);
      clientId = await withIdentityTransaction(
        this.pool,
        { organizationId },
        async (client) => {
          const rows = await client.query<{ client_id: string }>(
            `select session.client_id from auth_sessions session
             join oauth_clients oauth on oauth.id=session.client_id
               and oauth.organization_id=session.organization_id and oauth.state='active'
            where session.id=$1 and session.organization_id=$2
              and session.exact_origin=$3 and session.state in ('anonymous','authenticated')
              and session.expires_at>transaction_timestamp()
              and ($4::uuid is null or session.member_id=$4)`,
            [sessionId, organizationId, inspection.canonicalOrigin, memberId]
          );
          if (rows.rows.length !== 1) throw new Error("passkey session client is unavailable");
          return UuidV7Schema.parse(rows.rows[0]!.client_id);
        },
        this.options.assumeRole === undefined ? {} : { assumeRole: this.options.assumeRole }
      );
    }
    return new PgWebAuthnAttemptLimiter(this.options.limiter, {
      trustedIpClass: inspection.clientIpClass,
      trustedClientId: clientId,
      policies: this.options.policies
    }).consume(context);
  }
}
