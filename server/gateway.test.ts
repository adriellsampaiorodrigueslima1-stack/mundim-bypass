import { describe, expect, it } from "vitest";
import {
  closeGatewaySession,
  createGatewayToken,
  heartbeatGatewaySession,
  parseAllowedTarget,
  readGatewayToken,
} from "./gateway";

describe("authorized gateway", () => {
  it("accepts an allowlisted HTTPS target", () => {
    const target = parseAllowedTarget("https://krunker.io/game");
    expect(target.origin).toBe("https://krunker.io");
    expect(target.pathname).toBe("/game");
  });

  it("rejects non-HTTPS and non-allowlisted destinations", () => {
    expect(() => parseAllowedTarget("http://krunker.io/game")).toThrow("HTTPS");
    expect(() => parseAllowedTarget("https://example.com")).toThrow("allowlist");
  });

  it("creates an opaque JWE token that round-trips into the original claims", async () => {
    const target = parseAllowedTarget("https://shellshock.io/");
    const token = await createGatewayToken(target);
    const claims = await readGatewayToken(token);

    expect(token).not.toContain("shellshock");
    expect(token.split(".")).toHaveLength(5);
    expect(claims.sid).toMatch(/^[0-9a-f-]{36}$/);
    expect(claims.origin).toBe("https://shellshock.io");
    expect(claims.initialPath).toBe("/");
    expect(claims.exp).toBeGreaterThan(Date.now());
  });

  it("keeps the session alive with heartbeat and closes it explicitly", async () => {
    const token = await createGatewayToken(parseAllowedTarget("https://krunker.io/"));
    await heartbeatGatewaySession(token);
    await closeGatewaySession(token);
    await expect(readGatewayToken(token)).rejects.toThrow("Sessão fechada");
  });

  it("rejects a tampered token", async () => {
    const token = await createGatewayToken(parseAllowedTarget("https://classic.minecraft.net/"));
    const tampered = `${token.slice(0, -1)}${token.endsWith("a") ? "b" : "a"}`;
    await expect(readGatewayToken(tampered)).rejects.toThrow();
  });
});
