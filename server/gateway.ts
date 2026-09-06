import { createHash, randomUUID } from "node:crypto";
import dns from "node:dns/promises";
import net from "node:net";
import { Readable } from "node:stream";
import type { Express, Request, Response } from "express";
import { CompactEncrypt, compactDecrypt } from "jose";
import { ENV } from "./_core/env";

const SESSION_IDLE_TIMEOUT_MS = 2 * 60 * 1000;
const SESSION_MAX_TTL_MS = 24 * 60 * 60 * 1000;
const activeSessions = new Map<string, number>();

export type GatewayClaims = {
  sid: string;
  origin: string;
  initialPath: string;
  exp: number;
};

export function getAllowedOrigins() {
  return ["https://* (qualquer destino público) "];
}

function isBlockedAddress(address: string) {
  if (net.isIPv4(address)) {
    const [a, b] = address.split(".").map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 198 && (b === 18 || b === 19));
  }

  if (net.isIPv6(address)) {
    const normalized = address.toLowerCase();
    return normalized === "::" || normalized === "::1" || normalized.startsWith("fc") ||
      normalized.startsWith("fd") || normalized.startsWith("fe8") || normalized.startsWith("fe9") ||
      normalized.startsWith("fea") || normalized.startsWith("feb");
  }

  return true;
}

export async function assertPublicHttpsTarget(target: URL) {
  if (target.protocol !== "https:") throw new Error("O gateway aceita somente destinos HTTPS.");
  if (target.username || target.password) throw new Error("URLs com credenciais não são permitidas.");
  if (target.hostname === "localhost" || target.hostname.endsWith(".local") || target.hostname.endsWith(".internal")) {
    throw new Error("Destinos locais ou internos não são permitidos.");
  }

  const addresses = net.isIP(target.hostname)
    ? [target.hostname]
    : (await dns.lookup(target.hostname, { all: true, verbatim: true })).map(({ address }) => address);
  if (!addresses.length || addresses.some(isBlockedAddress)) {
    throw new Error("O destino precisa resolver para um endereço público.");
  }
}

export async function parseAllowedTarget(rawTarget: string) {
  let target: URL;
  try {
    target = new URL(rawTarget);
  } catch {
    throw new Error("Informe uma URL válida.");
  }

  await assertPublicHttpsTarget(target);
  return target;
}

function encryptionKey() {
  const secret = ENV.cookieSecret || "bypassschool-local-development-only-key";
  return createHash("sha256").update(secret).digest();
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

  if (!claims || typeof claims.sid !== "string" || typeof claims.origin !== "string" ||
      typeof claims.initialPath !== "string" || typeof claims.exp !== "number" ||
      claims.exp < Date.now() || typeof idleUntil !== "number" || idleUntil < Date.now()) {
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
  return `<script data-bypassschool-session="heartbeat">(() => { const token = ${safeToken}; const NativeWebSocket = window.WebSocket; const GatewayWebSocket = function(url, protocols) { try { const parsed = new URL(String(url), document.baseURI); if (parsed.protocol === 'ws:' || parsed.protocol === 'wss:') { const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:'; const proxied = protocol + '//' + location.host + '/gateway-ws/' + token + parsed.pathname + parsed.search; return protocols === undefined ? new NativeWebSocket(proxied) : new NativeWebSocket(proxied, protocols); } } catch {} return protocols === undefined ? new NativeWebSocket(url) : new NativeWebSocket(url, protocols); }; GatewayWebSocket.prototype = NativeWebSocket.prototype; window.WebSocket = GatewayWebSocket; const beat = () => fetch('/api/gateway/heartbeat', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token }), keepalive: true }).catch(() => {}); beat(); window.setInterval(beat, 30000); window.addEventListener('pagehide', () => { navigator.sendBeacon('/api/gateway/close', new Blob([JSON.stringify({ token })], { type: 'application/json' })); }); })();</script>`;
}

function getRequestPath(req: Request, claims: GatewayClaims) {
  const wildcard = typeof req.params[0] === "string" ? req.params[0] : "";
  const queryIndex = req.originalUrl.indexOf("?");
  const query = queryIndex >= 0 ? req.originalUrl.slice(queryIndex) : "";
  if (!wildcard) return claims.initialPath;
  return `/${wildcard}${query}`;
}

function copyResponseHeaders(upstream: globalThis.Response, res: Response) {
  for (const name of ["content-type", "cache-control", "etag", "last-modified"]) {
    const value = upstream.headers.get(name);
    if (value) res.setHeader(name, value);
  }
  res.setHeader("x-bypassschool-gateway", "public-https-session");
  res.setHeader("x-content-type-options", "nosniff");
}

async function handleGatewayRequest(req: Request, res: Response) {
  const token = req.params.token;
  try {
    const claims = await readGatewayToken(token);
    const upstreamUrl = new URL(getRequestPath(req, claims), claims.origin);
    await assertPublicHttpsTarget(upstreamUrl);

    const upstream = await fetch(upstreamUrl, {
      method: req.method === "HEAD" ? "HEAD" : "GET",
      redirect: "manual",
      signal: AbortSignal.timeout(15_000),
      headers: {
        accept: req.headers.accept || "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept-language": req.headers["accept-language"] || "pt-BR,pt;q=0.9,en;q=0.8",
        "user-agent": "bypassschool-authorized-gateway/0.3",
      },
    });

    if (upstream.status >= 300 && upstream.status < 400) {
      const location = upstream.headers.get("location");
      if (!location) return res.status(upstream.status).end();
      const redirectTarget = new URL(location, upstreamUrl);
      await assertPublicHttpsTarget(redirectTarget);
      res.setHeader("location", proxyPath(token, redirectTarget));
      return res.status(upstream.status).end();
    }

    copyResponseHeaders(upstream, res);
    res.status(upstream.status);
    const contentType = upstream.headers.get("content-type") || "";
    if (contentType.includes("text/html") && upstream.body) {
      const html = rewriteHtml(await upstream.text(), upstreamUrl, token);
      res.removeHeader("content-length");
      const sessionScript = sessionHeartbeatScript(token);
      return res.send(html.includes("</head>")
        ? html.replace(/<\/head>/i, `${sessionScript}</head>`)
        : html.includes("</body>")
          ? html.replace(/<\/body>/i, `${sessionScript}</body>`)
          : `${html}${sessionScript}`);
    }
    if (!upstream.body) return res.end();
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
