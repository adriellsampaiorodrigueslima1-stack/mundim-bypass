import { describe, expect, it } from "vitest";
import {
  assertPublicHttpsTarget,
  closeGatewaySession,
  createGatewayToken,
  heartbeatGatewaySession,
  parseAllowedTarget,
  readGatewayToken,
} from "./gateway";

describe("public HTTPS gateway", () => {
  it("accepts a public HTTPS target", async () => {
    const target = await parseAllowedTarget("https://example.com/game");
    expect(target.origin).toBe("https://example.com");
    expect(target.pathname).toBe("/game");
  });

  it("rejects non-HTTPS and private destinations", async () => {
    await expect(parseAllowedTarget("http://example.com/game")).rejects.toThrow("HTTPS");
    await expect(parseAllowedTarget("https://localhost:3000/")).rejects.toThrow("locais");
    await expect(assertPublicHttpsTarget(new URL("https://127.0.0.1/"))).rejects.toThrow("público");
  });

  it("creates an opaque JWE token for any public HTTPS host", async () => {
    const target = await parseAllowedTarget("https://example.com/");
    const token = await createGatewayToken(target);
    const claims = await readGatewayToken(token);

    expect(token).not.toContain("example");
    expect(token.split(".")).toHaveLength(5);
    expect(claims.sid).toMatch(/^[0-9a-f-]{36}$/);
    expect(claims.origin).toBe("https://example.com");
    expect(claims.initialPath).toBe("/");
    expect(claims.exp).toBeGreaterThan(Date.now());
  });

  it("keeps the session alive with heartbeat and closes it explicitly", async () => {
    const token = await createGatewayToken(await parseAllowedTarget("https://example.com/"));
    await heartbeatGatewaySession(token);
    await closeGatewaySession(token);
    await expect(readGatewayToken(token)).rejects.toThrow("Sessão fechada");
  });

  it("rejects a tampered token", async () => {
    const token = await createGatewayToken(await parseAllowedTarget("https://example.com/"));
    const parts = token.split(".");
    parts[3] = `${parts[3].slice(0, -1)}${parts[3].endsWith("a") ? "b" : "a"}`;
    const tampered = parts.join(".");
    await expect(readGatewayToken(tampered)).rejects.toThrow();
  });
});
