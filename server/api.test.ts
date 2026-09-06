import express from "express";
import { createServer } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { registerArcadeApi } from "./api";

const app = express();
app.use(express.json());
registerArcadeApi(app);
const server = createServer(app);
let baseUrl = "";

beforeAll(async () => {
  process.env.ARCADE_API_KEYS = "arcade-test-key";
  await new Promise<void>((resolve) => server.listen(0, () => resolve()));
  const address = server.address();
  if (address && typeof address !== "string") baseUrl = `http://127.0.0.1:${address.port}`;
});

afterAll(() => server.close());

describe("arcade API v1", () => {
  it("reports health without credentials", async () => {
    const response = await fetch(`${baseUrl}/api/v1/health`);
    expect(response.status).toBe(200);
    expect((await response.json()).ok).toBe(true);
  });

  it("requires an API key to create a session", async () => {
    const response = await fetch(`${baseUrl}/api/v1/sessions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ url: "example.com" }),
    });
    expect(response.status).toBe(401);
  });

  it("creates a session for the arcade and returns gateway URLs", async () => {
    const response = await fetch(`${baseUrl}/api/v1/sessions`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-key": "arcade-test-key", "x-forwarded-proto": "http" },
      body: JSON.stringify({ url: "example.com" }),
    });
    const body = await response.json();
    expect(response.status).toBe(201);
    expect(body.ok).toBe(true);
    expect(body.session.token).toMatch(/^ey/);
    expect(body.session.gatewayUrl).toMatch(/^http:\/\/127\.0\.0\.1:/);
    expect(body.session.websocketUrl).toMatch(/^ws:\/\/127\.0\.0\.1:/);
    expect(body.session.heartbeatUrl).toContain("/api/v1/sessions/heartbeat");
  });
});
