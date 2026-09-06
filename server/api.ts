import { timingSafeEqual } from "node:crypto";
import type { Express, Request, Response } from "express";
import { closeGatewaySession, createGatewayToken, parseAllowedTarget, heartbeatGatewaySession } from "./gateway";

function configuredKeys() {
  return (process.env.ARCADE_API_KEYS || "")
    .split(",")
    .map((key) => key.trim())
    .filter(Boolean);
}

export function apiKeyAllowed(req: Request) {
  const keys = configuredKeys();
  // O cliente ArcadeX é distribuído como HTML/APK, então uma chave embutida
  // não seria secreta. A API continua protegida por HTTPS público + SSRF guard;
  // configure ARCADE_API_KEYS para exigir autenticação em uma instalação privada.
  if (!keys.length) return true;
  const supplied = String(req.header("x-api-key") || req.header("authorization")?.replace(/^Bearer\s+/i, "") || "");
  return keys.some((expected) => {
    const left = Buffer.from(supplied);
    const right = Buffer.from(expected);
    return left.length === right.length && timingSafeEqual(left, right);
  });
}

function corsOrigin(req: Request) {
  const configured = (process.env.ARCADE_CORS_ORIGINS || "*")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);
  const requestOrigin = req.header("origin");
  if (configured.includes("*")) return "*";
  return requestOrigin && configured.includes(requestOrigin) ? requestOrigin : "";
}

function setApiHeaders(req: Request, res: Response) {
  const origin = corsOrigin(req);
  if (origin) res.setHeader("access-control-allow-origin", origin);
  res.setHeader("access-control-allow-methods", "GET,POST,OPTIONS");
  res.setHeader("access-control-allow-headers", "content-type,x-api-key,authorization");
  res.setHeader("access-control-max-age", "600");
  res.setHeader("cache-control", "no-store");
}

function absoluteUrl(req: Request, path: string) {
  const forwardedProto = String(req.header("x-forwarded-proto") || "https").split(",")[0];
  return `${forwardedProto}://${req.get("host")}${path}`;
}

function unauthorized(res: Response) {
  return res.status(401).json({ ok: false, error: "API key ausente ou inválida." });
}

export function registerArcadeApi(app: Express) {
  app.use("/api/v1", (req, res, next) => {
    setApiHeaders(req, res);
    if (req.method === "OPTIONS") return res.status(204).end();
    next();
  });

  app.get("/api/v1", (_req, res) => {
    res.json({
      name: "bypassschool arcade API",
      version: "1",
      endpoints: {
        createSession: "POST /api/v1/sessions",
        heartbeat: "POST /api/v1/sessions/heartbeat",
        close: "POST /api/v1/sessions/close",
        health: "GET /api/v1/health",
      },
    });
  });

  app.get("/api/v1/health", (_req, res) => {
    res.json({ ok: true, service: "bypassschool-gateway", transport: "https + websocket" });
  });

  app.post("/api/v1/sessions", async (req, res) => {
    if (!apiKeyAllowed(req)) return unauthorized(res);
    try {
      const rawTarget = String(req.body?.url || req.body?.target || "").trim();
      if (!rawTarget) return res.status(400).json({ ok: false, error: "Campo 'url' é obrigatório." });
      const target = await parseAllowedTarget(rawTarget);
      const token = await createGatewayToken(target);
      const gatewayPath = `/gateway/${token}${target.pathname === "/" ? "/" : `${target.pathname}${target.search}`}`;
      const websocketPath = `/gateway-ws/${token}/`;
      return res.status(201).json({
        ok: true,
        session: {
          token,
          origin: target.origin,
          gatewayUrl: absoluteUrl(req, gatewayPath),
          websocketUrl: absoluteUrl(req, websocketPath).replace(/^http/, "ws"),
          heartbeatUrl: absoluteUrl(req, "/api/v1/sessions/heartbeat"),
          closeUrl: absoluteUrl(req, "/api/v1/sessions/close"),
          maxLifetimeHours: 24,
          idleTimeoutMinutes: 2,
        },
      });
    } catch (error) {
      return res.status(400).json({ ok: false, error: error instanceof Error ? error.message : "Destino inválido." });
    }
  });

  app.post("/api/v1/sessions/heartbeat", async (req, res) => {
    if (!apiKeyAllowed(req)) return unauthorized(res);
    try {
      await heartbeatGatewaySession(String(req.body?.token || ""));
      return res.status(204).end();
    } catch {
      return res.status(401).json({ ok: false, error: "Sessão fechada ou expirada." });
    }
  });

  app.post("/api/v1/sessions/close", async (req, res) => {
    if (!apiKeyAllowed(req)) return unauthorized(res);
    await closeGatewaySession(String(req.body?.token || ""));
    return res.status(204).end();
  });
}
