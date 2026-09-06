import { describe, expect, it } from "vitest";
import { createGatewayToken, parseAllowedTarget, readGatewayToken } from "./gateway";

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
    expect(claims.origin).toBe("https://shellshock.io");
    expect(claims.initialPath).toBe("/");
    expect(claims.exp).toBeGreaterThan(Date.now());
  });

  it("rejects a tampered token", async () => {
    const token = await createGatewayToken(parseAllowedTarget("https://classic.minecraft.net/"));
    const tampered = `${token.slice(0, -1)}${token.endsWith("a") ? "b" : "a"}`;
    await expect(readGatewayToken(tampered)).rejects.toThrow();
  });
});
