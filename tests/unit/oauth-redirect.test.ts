import { describe, expect, it } from "vitest";

import {
  isLoopbackHostname,
  OAuthRedirectUriSchema,
  redirectUriMatches
} from "../../lib/contracts/src/oauth-redirect.js";

describe("OAuth redirect URI classes", () => {
  it.each([
    "https://agent.example/callback",
    "http://127.0.0.1:52341/callback",
    "http://127.0.0.2:8080/cb",
    "http://[::1]:52341/callback",
    "http://localhost:52341/callback",
    "com.example.agent:/callback"
  ])("accepts %s", (value) => {
    expect(OAuthRedirectUriSchema.safeParse(value).success).toBe(true);
  });

  it.each([
    ["loopback without an explicit port", "http://localhost/callback"],
    ["plain http on a public host", "http://agent.example/callback"],
    ["localhost subdomain", "http://api.localhost:8080/callback"],
    ["credentials in the URI", "https://user:pw@agent.example/callback"],
    ["fragment", "https://agent.example/callback#x"],
    ["non-canonical form", "HTTPS://agent.example/callback"]
  ])("refuses %s", (_label, value) => {
    expect(OAuthRedirectUriSchema.safeParse(value).success).toBe(false);
  });

  it("classifies loopback hostnames", () => {
    expect(isLoopbackHostname("localhost")).toBe(true);
    expect(isLoopbackHostname("127.0.0.1")).toBe(true);
    expect(isLoopbackHostname("127.255.255.254")).toBe(true);
    expect(isLoopbackHostname("[::1]")).toBe(true);
    expect(isLoopbackHostname("::1")).toBe(true);
    expect(isLoopbackHostname("api.localhost")).toBe(false);
    expect(isLoopbackHostname("128.0.0.1")).toBe(false);
    expect(isLoopbackHostname("agent.example")).toBe(false);
  });
});

describe("registered redirect matching (RFC 8252 §7.3 loopback ports)", () => {
  it("matches exact strings and loopback callbacks that differ only by port", () => {
    expect(redirectUriMatches("https://agent.example/cb", "https://agent.example/cb")).toBe(true);
    expect(
      redirectUriMatches("http://localhost:52341/callback", "http://localhost:61002/callback")
    ).toBe(true);
    expect(
      redirectUriMatches("http://127.0.0.1:52341/callback", "http://127.0.0.1:1024/callback")
    ).toBe(true);
    expect(redirectUriMatches("http://[::1]:52341/callback", "http://[::1]:7/callback")).toBe(true);
  });

  it.each([
    [
      "different loopback host",
      "http://localhost:52341/callback",
      "http://127.0.0.1:52341/callback"
    ],
    ["different path", "http://localhost:52341/callback", "http://localhost:52341/other"],
    ["different query", "http://localhost:52341/callback?a=1", "http://localhost:52341/callback"],
    ["https to loopback", "https://agent.example/callback", "http://localhost:52341/callback"],
    [
      "loopback to public host",
      "http://localhost:52341/callback",
      "http://agent.example:52341/callback"
    ],
    ["https port change", "https://agent.example:8443/cb", "https://agent.example:9443/cb"],
    ["scheme downgrade", "https://localhost:8443/cb", "http://localhost:8443/cb"],
    ["malformed request", "http://localhost:52341/callback", "not a url"]
  ])("refuses a %s", (_label, registered, requested) => {
    expect(redirectUriMatches(registered, requested)).toBe(false);
  });
});
