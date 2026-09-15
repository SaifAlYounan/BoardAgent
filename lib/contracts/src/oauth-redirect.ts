import { isIP } from "node:net";

import { z } from "zod";

const REVERSE_DOMAIN_SCHEME = /^[a-z][a-z0-9-]*(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/u;

/**
 * Loopback hosts a native client may listen on for its callback (RFC 8252 §7.3): the IPv4
 * loopback block, the IPv6 loopback address, and the `localhost` name that released
 * clients such as Claude Code use in practice.
 */
export function isLoopbackHostname(rawHostname: string): boolean {
  const hostname = rawHostname.startsWith("[") ? rawHostname.slice(1, -1) : rawHostname;
  return (
    hostname === "localhost" ||
    hostname === "::1" ||
    (isIP(hostname) === 4 && Number(hostname.split(".", 1)[0]) === 127)
  );
}

function loopbackRedirectKey(value: string): string | null {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" || url.port === "" || !isLoopbackHostname(url.hostname)) return null;
  return `${url.hostname}${url.pathname}${url.search}`;
}

/**
 * Whether a requested redirect URI matches a registered one. Exact string equality, or,
 * for two loopback callbacks on the same host and path, equality ignoring the port:
 * RFC 8252 §7.3 requires the authorization server to allow any port because a native
 * client binds an ephemeral port at every login. Nothing else is relaxed: scheme, host,
 * path and query must be identical, and a loopback registration never matches a
 * non-loopback request.
 */
export function redirectUriMatches(registered: string, requested: string): boolean {
  if (registered === requested) return true;
  const registeredKey = loopbackRedirectKey(registered);
  const requestedKey = loopbackRedirectKey(requested);
  return registeredKey !== null && requestedKey !== null && registeredKey === requestedKey;
}

/** Exact registered redirect classes; this does not authorize a redirect for a client. */
export const OAuthRedirectUriSchema = z
  .string()
  .min(1)
  .max(2048)
  .refine((value) => {
    if (Buffer.byteLength(value, "utf8") > 2048 || value !== value.normalize("NFC")) return false;
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      return false;
    }
    if (url.href !== value || url.username !== "" || url.password !== "" || url.hash !== "")
      return false;
    if (url.protocol === "https:" && url.hostname !== "") return true;
    if (url.protocol === "http:" && url.port !== "" && isLoopbackHostname(url.hostname))
      return true;
    const scheme = url.protocol.slice(0, -1);
    return (
      url.host === "" &&
      url.pathname.startsWith("/") &&
      scheme === scheme.toLowerCase() &&
      REVERSE_DOMAIN_SCHEME.test(scheme)
    );
  }, "OAuth redirect URI must be exact canonical HTTPS, explicit-port loopback, or reverse-domain native callback");
