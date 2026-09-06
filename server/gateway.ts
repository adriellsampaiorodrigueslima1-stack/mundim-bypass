import { createHash, randomUUID } from "node:crypto";
import { Readable } from "node:stream";
import type { Express, Request, Response } from "express";
import { CompactEncrypt, compactDecrypt } from "jose";
import { ENV } from "./_core/env";

const SESSION_IDLE_TIMEOUT_MS = 2 * 60 * 1000;
const SESSION_MAX_TTL_MS = 24 * 60 * 60 * 1000;
const activeSessions = new Map<string, number>();
const DEFAULT_ALLOWED_ORIGINS = [
  "https://krunker.io",
  "https://classic.minecraft.net",
  "https://shellshock.io",
];

export type GatewayClaims = {
  sid: string;
  origin: string;
  initialPath: string;
  exp: number;
};

function allowedOrigins() {
  const configured = process.env.GATEWAY_ALLOWED_ORIGINS
    ?.split(",")
    .map((value) => value.trim())
    .filter(Boolean);

  return (configured?.length ? configured : DEFAULT_ALLOWED_ORIGINS).flatMap((value) => {
    try {
      const parsed = new URL(value);
      return parsed.protocol === "https:" && parsed.pathname === "/" && !parsed.search
        ? [parsed.origin]
        : [];
    } catch {
      return [];
    }
  });
}

export function getAllowedOrigins() {
  return allowedOrigins();
}

function encryptionKey() {
  const secret = ENV.cookieSecret || "bypassschool-local-development-only-key";
  return createHash("sha256").update(secret).digest();
}

export function parseAllowedTarget(rawTarget: string) {
  let target: URL;
  try {
    target = new URL(rawTarget);
  } catch {
    throw new Error("Informe uma URL válida.");
  }

  if (target.protocol !== "https:") {
    throw new Error("O gateway aceita somente destinos HTTPS.");
  }

  if (!getAllowedOrigins().includes(target.origin)) {
    throw new Error("Este destino ainda não está na allowlist autorizada.");
  }

  return target;
}

export async function createGatewayToken(target: URL) {
  const claims: GatewayClaims = {
    sid: randomUUID(),
    origin: target.origin,
    initialPath: `${target.pathname || "/"}${target.search}`,
    exp: Date.now() + SESSION_MAX_TTL_MS,
  };

  activeSessions.set(claims.sid, Date.now() + SESSION_IDLE_TIMEOUT_MS);

  return new CompactEncrypt(new TextEncoder().encode(JSON.stringify(claims)))
    .setProtectedHeader({ alg: "dir", enc: "A256GCM", typ: "BYPASS-GATEWAY" })
    .encrypt(encryptionKey());
}

export async function readGatewayToken(token: string): Promise<GatewayClaims> {
  const { plaintext } = await compactDecrypt(token, encryptionKey());
  const claims = JSON.parse(new TextDecoder().decode(plaintext)) as GatewayClaims;
  const idleUntil = activeSessions.get(claims.sid);

  if (
    !claims ||
    typeof claims.sid !== "string" ||
    typeof claims.origin !== "string" ||
    typeof claims.initialPath !== "string" ||
    typeof claims.exp !== "number" ||
    claims.exp < Date.now() ||
    typeof idleUntil !== "number" ||
    idleUntil < Date.now() ||
    !getAllowedOrigins().includes(claims.origin)
  ) {
    throw new Error("Sessão fechada, ociosa ou inválida.");
  }

  activeSessions.set(claims.sid, Date.now() + SESSION_IDLE_TIMEOUT_MS);
  return claims;
}

export async function heartbeatGatewaySession(token: string) {
  await readGatewayToken(token);
}

export async function closeGatewaySession(token: string) {
  try {
    const { plaintext } = await compactDecrypt(token, encryptionKey());
    const claims = JSON.parse(new TextDecoder().decode(plaintext)) as Partial<GatewayClaims>;
    if (claims.sid) activeSessions.delete(claims.sid);
  } catch {
    // Fechar uma sessão já inválida é idempotente.
  }
}

function proxyPath(token: string, target: URL) {
  const suffix = `${target.pathname || "/"}${target.search}`;
  return `/gateway/${token}${suffix === "/" ? "/" : suffix}`;
}

function rewriteHtml(html: string, upstreamUrl: URL, token: string) {
  const attributePattern = /(src|href|action|poster)=("|')([^"']+)(\2)/gi;

  return html.replace(attributePattern, (full, attribute: string, quote: string, value: string) => {
    if (/^(#|data:|mailto:|javascript:|blob:|about:)/i.test(value)) return full;

    try {
      const resolved = new URL(value, upstreamUrl);
      if (resolved.origin !== upstreamUrl.origin || resolved.protocol !== "https:") return full;
      return `${attribute}=${quote}${proxyPath(token, resolved)}${quote}`;
    } catch {
      return full;
    }
  });
}

function sessionHeartbeatScript(token: string) {
  const safeToken = JSON.stringify(token);
  return `<script data-bypassschool-session="heartbeat">(() => { const token = ${safeToken}; const beat = () => fetch('/api/gateway/heartbeat', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token }), keepalive: true }).catch(() => {}); beat(); window.setInterval(beat, 30000); window.addEventListener('pagehide', () => { navigator.sendBeacon('/api/gateway/close', new Blob([JSON.stringify({ token })], { type: 'application/json' })); }); })();</script>`;
}

function getRequestPath(req: Request, claims: GatewayClaims) {
  const wildcard = typeof req.params[0] === "string" ? req.params[0] : "";
  const queryIndex = req.originalUrl.indexOf("?");
  const query = queryIndex >= 0 ? req.originalUrl.slice(queryIndex) : "";
  if (!wildcard) return claims.initialPath;
  return `/${wildcard}${query}`;
}

function copyResponseHeaders(upstream: globalThis.Response, res: Response) {
  const contentType = upstream.headers.get("content-type");
  const cacheControl = upstream.headers.get("cache-control");
  const etag = upstream.headers.get("etag");
  const lastModified = upstream.headers.get("last-modified");

  if (contentType) res.setHeader("content-type", contentType);
  if (cacheControl) res.setHeader("cache-control", cacheControl);
  if (etag) res.setHeader("etag", etag);
  if (lastModified) res.setHeader("last-modified", lastModified);
  res.setHeader("x-bypassschool-gateway", "allowlisted-jwe-session");
  res.setHeader("x-content-type-options", "nosniff");
}

async function handleGatewayRequest(req: Request, res: Response) {
  const token = req.params.token;

  try {
    const claims = await readGatewayToken(token);
    const upstreamUrl = new URL(getRequestPath(req, claims), claims.origin);
    if (upstreamUrl.origin !== claims.origin || upstreamUrl.protocol !== "https:") {
      res.status(403).type("text").send("Destino bloqueado pela allowlist.");
      return;
    }

    const upstream = await fetch(upstreamUrl, {
      method: req.method === "HEAD" ? "HEAD" : "GET",
      redirect: "manual",
      signal: AbortSignal.timeout(15_000),
      headers: {
        accept: req.headers.accept || "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept-language": req.headers["accept-language"] || "pt-BR,pt;q=0.9,en;q=0.8",
        "user-agent": "bypassschool-authorized-gateway/0.2",
      },
    });

    if (upstream.status >= 300 && upstream.status < 400) {
      const location = upstream.headers.get("location");
      if (!location) {
        res.status(upstream.status).end();
        return;
      }
      const redirectTarget = new URL(location, upstreamUrl);
      if (redirectTarget.origin !== claims.origin || redirectTarget.protocol !== "https:") {
        res.status(403).type("text").send("Redirecionamento bloqueado pela allowlist.");
        return;
      }
      res.setHeader("location", proxyPath(token, redirectTarget));
      res.status(upstream.status).end();
      return;
    }

    copyResponseHeaders(upstream, res);
    res.status(upstream.status);

    const contentType = upstream.headers.get("content-type") || "";
    if (contentType.includes("text/html") && upstream.body) {
      const html = await upstream.text();
      const rewritten = rewriteHtml(html, upstreamUrl, token);
      res.removeHeader("content-length");
      res.send(rewritten.includes("</body>")
        ? rewritten.replace(/<\/body>/i, `${sessionHeartbeatScript(token)}</body>`)
        : `${rewritten}${sessionHeartbeatScript(token)}`);
      return;
    }

    if (!upstream.body) {
      res.end();
      return;
    }

    Readable.fromWeb(upstream.body as any).pipe(res);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Falha ao abrir a sessão.";
    const status = message.includes("Sessão") ? 401 : 502;
    res.status(status).type("text").send(message);
  }
}

export function registerGatewayRoutes(app: Express) {
  app.post("/api/gateway/heartbeat", async (req, res) => {
    try {
      await heartbeatGatewaySession(String(req.body?.token || ""));
      res.status(204).end();
    } catch {
      res.status(401).json({ error: "Sessão fechada ou expirada." });
    }
  });

  app.post("/api/gateway/close", async (req, res) => {
    await closeGatewaySession(String(req.body?.token || ""));
    res.status(204).end();
  });

  app.get("/gateway/:token", handleGatewayRequest);
  app.get("/gateway/:token/*", handleGatewayRequest);
}
