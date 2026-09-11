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
const closedSessions = new Set<string>();

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
  const trimmed = rawTarget.trim();
  const normalized = /^http:\/\//i.test(trimmed)
    ? `https://${trimmed.slice(7)}`
    : /^[a-z][a-z\d+.-]*:\/\//i.test(trimmed)
      ? trimmed
      : `https://${trimmed.replace(/^\/\//, "")}`;
  let target: URL;
  try {
    target = new URL(normalized);
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

  closedSessions.delete(claims.sid);
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
      claims.exp < Date.now() || closedSessions.has(claims.sid) ||
      (typeof idleUntil === "number" && idleUntil < Date.now())) {
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
    if (claims.sid) {
      activeSessions.delete(claims.sid);
      closedSessions.add(claims.sid);
    }
  } catch {
    // Fechar uma sessão já inválida é idempotente.
  }
}

function gatewayPath(token: string, target: URL) {
  const suffix = `${target.pathname || "/"}${target.search}`;
  return `/gateway/${token}${suffix === "/" ? "/" : suffix}`;
}

function gatewayHostPath(token: string, target: URL, sessionOrigin: string) {
  if (target.origin === sessionOrigin) return gatewayPath(token, target);
  return `/gateway/${token}/__host/${encodeURIComponent(target.host)}${target.pathname || "/"}${target.search}`;
}

function isRelatedGameHost(sessionOrigin: string, target: URL) {
  const sessionHost = new URL(sessionOrigin).hostname;
  if (target.protocol !== "https:") return false;
  if (target.hostname === sessionHost || target.hostname.endsWith(`.${sessionHost}`)) return true;
  return sessionHost === "2v2.io" && (target.hostname === "files.2v2.io" || target.hostname === "api.2v2.io");
}

function assertSessionHostAllowed(claimsOrigin: string, target: URL) {
  if (!isRelatedGameHost(claimsOrigin, target)) {
    throw new Error("O recurso está fora dos hosts autorizados da sessão.");
  }
}

function rewriteHtml(html: string, upstreamUrl: URL, token: string) {
  const attributePattern = /(src|href|action|poster)=("|')([^"']+)(\2)/gi;
  const rewritten = html.replace(attributePattern, (full, attribute: string, quote: string, value: string) => {
    if (/^(#|data:|mailto:|javascript:|blob:|about:)/i.test(value)) return full;
    try {
      const resolved = new URL(value, upstreamUrl);
      if (!isRelatedGameHost(upstreamUrl.origin, resolved)) return full;
      return `${attribute}=${quote}${gatewayHostPath(token, resolved, upstreamUrl.origin)}${quote}`;
    } catch {
      return full;
    }
  });
  if (new URL(upstreamUrl).hostname === "2v2.io") {
    return rewritten.replace(/https:\/\/(?:files|api)\.2v2\.io(?=\/|['"`\s])/g, (absolute) => {
      const host = absolute.slice("https://".length);
      return `/gateway/${token}/__host/${host}`;
    });
  }
  return rewritten;
}

function rewriteDynamicModuleBase(source: string, token: string) {
  return source.replace(/de\.p="\/"/g, `de.p="/gateway/${token}/"`);
}

function sessionHeartbeatScript(token: string, siteOrigin: string) {
  const safeToken = JSON.stringify(token);
  const safeSite = JSON.stringify(siteOrigin.replace(/^https?:\/\//, ""));
  return `<script data-bypassschool-session="bridge">(() => {
    const token = ${safeToken};
    const site = ${safeSite};
    const siteOrigin = 'https://' + site;
    const relatedHost = (hostname) => site === '2v2.io' && (hostname === 'files.2v2.io' || hostname === 'api.2v2.io');
    const gatewayHttpUrl = (value) => {
      try {
        const raw = String(value);
        if (raw.startsWith('/api/gateway') || raw.startsWith('/gateway')) return null;
        const base = raw.startsWith('/') || raw.startsWith('?') || raw.startsWith('#') ? siteOrigin : document.baseURI;
        const parsed = new URL(raw, base);
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
        const sameOrigin = parsed.origin === siteOrigin;
        const relatedSubdomain = (site === 'bloxd.io' && (parsed.hostname === 'bloxd.io' || parsed.hostname.endsWith('.bloxd.io'))) || relatedHost(parsed.hostname);
        if (!sameOrigin && !relatedSubdomain) return null;
        const hostPrefix = sameOrigin ? '' : '/__host/' + encodeURIComponent(parsed.host);
        return location.origin + '/gateway/' + token + hostPrefix + parsed.pathname + parsed.search;
      } catch { return null; }
    };
    const NativeFetch = window.fetch.bind(window);
    window.fetch = function(input, init) {
      const original = input instanceof Request ? input.url : String(input);
      const rewritten = gatewayHttpUrl(original);
      if (!rewritten) return NativeFetch(input, init);
      if (input instanceof Request) return NativeFetch(new Request(rewritten, input), init);
      return NativeFetch(rewritten, init);
    };
    const NativeXHR = window.XMLHttpRequest;
    const GatewayXHR = function() {
      const xhr = new NativeXHR();
      const open = xhr.open;
      xhr.open = function(method, url, ...rest) {
        const rewritten = gatewayHttpUrl(url);
        return open.call(xhr, method, rewritten || url, ...rest);
      };
      return xhr;
    };
    GatewayXHR.prototype = NativeXHR.prototype;
    window.XMLHttpRequest = GatewayXHR;
    const NativeWebSocket = window.WebSocket;
    const GatewayWebSocket = function(url, protocols) {
      try {
        const raw = String(url);
        const wsBase = siteOrigin.replace(/^https:/, 'wss:');
        const parsed = new URL(raw, raw.startsWith('/') ? wsBase : document.baseURI);
        if (parsed.protocol === 'ws:' || parsed.protocol === 'wss:') {
          const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
          const encodedHost = encodeURIComponent(parsed.host);
          const proxied = protocol + '//' + location.host + '/gateway-ws/' + token + '/__host/' + encodedHost + parsed.pathname + parsed.search;
          return protocols === undefined ? new NativeWebSocket(proxied) : new NativeWebSocket(proxied, protocols);
        }
      } catch {}
      return protocols === undefined ? new NativeWebSocket(url) : new NativeWebSocket(url, protocols);
    };
    GatewayWebSocket.prototype = NativeWebSocket.prototype;
    window.WebSocket = GatewayWebSocket;

    const style = document.createElement('style');
    style.textContent = '@keyframes bsSpin { to { transform: rotate(360deg); } } @keyframes bsPulse { 0%,100% { opacity:.5; } 50% { opacity:.9; } } @keyframes bsIn { from { opacity:0; transform:translateY(8px); } to { opacity:1; transform:translateY(0); } } #bypassschool-loader { position:fixed; inset:0; z-index:2147483646; display:grid; place-items:center; background:radial-gradient(circle at 50% 42%, #102642 0%, #050912 56%, #02040a 100%); color:#eaf7ff; font-family:system-ui,-apple-system,sans-serif; transition:opacity .42s ease, visibility .42s ease; } #bypassschool-loader.bs-ready { opacity:0; visibility:hidden; pointer-events:none; } .bs-loader-box { text-align:center; animation:bsIn .55s ease both; } .bs-loader-ring { width:58px; height:58px; margin:0 auto 20px; border:2px solid rgba(57,196,255,.2); border-top-color:#36c6ff; border-right-color:#8ef0ff; border-radius:50%; animation:bsSpin 1s linear infinite; box-shadow:0 0 26px rgba(35,184,255,.26); } .bs-loader-title { letter-spacing:.12em; text-transform:lowercase; font-size:14px; font-weight:600; } .bs-loader-sub { margin-top:9px; color:#80a3b9; font-size:11px; } #bypassschool-watermark { position:fixed; top:9px; right:12px; z-index:2147483645; display:flex; align-items:center; gap:5px; padding:4px 7px; border:1px solid rgba(74,191,239,.2); border-radius:5px; background:rgba(3,12,24,.68); box-shadow:0 3px 12px rgba(0,0,0,.16); color:#a9c8d8; font:9px ui-monospace,SFMono-Regular,monospace; backdrop-filter:blur(7px); animation:bsPulse 3.4s ease-in-out infinite; } .bs-watermark-name { color:#49c8ff; font-weight:700; } .bs-watermark-sep { color:#52798f; } #bypassschool-emergency { border:0; border-radius:3px; padding:2px 5px; background:#d92d3f; color:#fff; font:700 8px ui-monospace,monospace; cursor:pointer; pointer-events:auto; } #bypassschool-emergency:hover { background:#ff4658; }';
    document.head.appendChild(style);
    const loader = document.createElement('div');
    loader.id = 'bypassschool-loader';
    loader.innerHTML = '<div class="bs-loader-box"><div class="bs-loader-ring"></div><div class="bs-loader-title">carregando, aguarde....</div><div class="bs-loader-sub">preparando uma sessão segura</div></div>';
    document.documentElement.appendChild(loader);
    const watermark = document.createElement('div');
    watermark.id = 'bypassschool-watermark';
    watermark.innerHTML = '<span class="bs-watermark-name">Mundim Bypass</span><span class="bs-watermark-sep">·</span><span>' + site + '</span><span class="bs-watermark-sep">·</span><span id="bypassschool-ping">ping...</span><button id="bypassschool-emergency" type="button" title="Encerrar sessão (tecla 0)">SAIR</button>';
    document.documentElement.appendChild(watermark);
    const emergencyTargets = ['https://gemini.google.com/', 'https://chatgpt.com/', 'https://www.duolingo.com/', 'https://bibliotecavirtual.seduc.pi.gov.br/'];
    const emergency = () => {
      if (window.__bypassschoolEmergencyUsed) return;
      window.__bypassschoolEmergencyUsed = true;
      const payload = new Blob([JSON.stringify({ token })], { type:'application/json' });
      try { navigator.sendBeacon('/api/gateway/close', payload); } catch {}
      window.stop();
      window.location.replace(emergencyTargets[Math.floor(Math.random() * emergencyTargets.length)]);
    };
    document.getElementById('bypassschool-emergency').addEventListener('click', emergency);
    window.addEventListener('keydown', (event) => { if (event.key === '0') emergency(); });
    const dismissLoader = () => { loader.classList.add('bs-ready'); window.setTimeout(() => loader.remove(), 500); };
    if (document.readyState === 'complete') dismissLoader(); else window.addEventListener('load', dismissLoader, { once: true });
    window.setTimeout(dismissLoader, 7000);
    const beat = async () => { const started = performance.now(); try { await fetch('/api/gateway/heartbeat', { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({ token }), keepalive:true }); const ping = document.getElementById('bypassschool-ping'); if (ping) ping.textContent = Math.round(performance.now() - started) + 'ms'; } catch {} };
    beat();
    window.setInterval(beat, 30000);
    window.addEventListener('pagehide', () => { navigator.sendBeacon('/api/gateway/close', new Blob([JSON.stringify({ token })], { type:'application/json' })); });
  })();</script>`;
}

function getRequestPath(req: Request, claims: GatewayClaims) {
  const wildcard = typeof req.params[0] === "string" ? req.params[0] : "";
  const queryIndex = req.originalUrl.indexOf("?");
  const query = queryIndex >= 0 ? req.originalUrl.slice(queryIndex) : "";
  if (!wildcard) return claims.initialPath;
  return `/${wildcard}${query}`;
}

function getUpstreamUrl(req: Request, claims: GatewayClaims) {
  const requestPath = getRequestPath(req, claims);
  const marker = "/__host/";
  if (requestPath.startsWith(marker)) {
    const encodedHostAndPath = requestPath.slice(marker.length);
    const slashIndex = encodedHostAndPath.indexOf("/");
    if (slashIndex <= 0) throw new Error("Destino de recurso inválido.");
    const host = decodeURIComponent(encodedHostAndPath.slice(0, slashIndex));
    const path = encodedHostAndPath.slice(slashIndex) || "/";
    const target = new URL(`${path}`, `https://${host}`);
    return target;
  }
  return new URL(requestPath, claims.origin);
}

function copyResponseHeaders(upstream: globalThis.Response, res: Response) {
  for (const name of ["content-type", "cache-control", "etag", "last-modified", "content-range", "accept-ranges", "vary"]) {
    const value = upstream.headers.get(name);
    if (value) res.setHeader(name, value);
  }
  const setCookies = typeof upstream.headers.getSetCookie === "function"
    ? upstream.headers.getSetCookie()
    : (upstream.headers.get("set-cookie") ? [upstream.headers.get("set-cookie") as string] : []);
  for (const cookie of setCookies) {
    res.append("set-cookie", cookie.replace(/;\s*Domain=[^;]+/gi, ""));
  }
  res.setHeader("x-bypassschool-gateway", "public-https-session");
  res.setHeader("x-content-type-options", "nosniff");
}

async function handleGatewayRequest(req: Request, res: Response) {
  const token = req.params.token;
  try {
    const claims = await readGatewayToken(token);
    const upstreamUrl = getUpstreamUrl(req, claims);
    // O origin já foi validado ao criar o token. Revalidar DNS em cada asset
    // torna jogos com muitos scripts/imagens lentos e não acrescenta proteção
    // quando o recurso permanece no mesmo origin autorizado.
    if (upstreamUrl.origin !== claims.origin) {
      await assertPublicHttpsTarget(upstreamUrl);
      assertSessionHostAllowed(claims.origin, upstreamUrl);
    }

    const method = req.method.toUpperCase();
    const hasBody = !["GET", "HEAD"].includes(method);
    const requestBody = hasBody && req.body !== undefined
      ? (typeof req.body === "string" ? req.body : JSON.stringify(req.body))
      : undefined;
    const upstream = await fetch(upstreamUrl, {
      method,
      redirect: "manual",
      signal: AbortSignal.timeout(15_000),
      headers: {
        accept: req.headers.accept || "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept-language": req.headers["accept-language"] || "pt-BR,pt;q=0.9,en;q=0.8",
        "accept-encoding": req.headers["accept-encoding"] || "gzip, br, deflate",
        "user-agent": "bypassschool-authorized-gateway/0.3",
        ...(req.headers.cookie ? { cookie: req.headers.cookie } : {}),
        ...(req.headers.referer ? { referer: req.headers.referer } : {}),
        ...(req.headers["content-type"] ? { "content-type": req.headers["content-type"] } : {}),
        ...(req.headers.range ? { range: req.headers.range } : {}),
        ...(req.headers["if-none-match"] ? { "if-none-match": req.headers["if-none-match"] } : {}),
        ...(req.headers["if-modified-since"] ? { "if-modified-since": req.headers["if-modified-since"] } : {}),
      },
      body: requestBody,
    });

    if (upstream.status >= 300 && upstream.status < 400) {
      const location = upstream.headers.get("location");
      if (!location) return res.status(upstream.status).end();
      const redirectTarget = new URL(location, upstreamUrl);
      await assertPublicHttpsTarget(redirectTarget);
      assertSessionHostAllowed(claims.origin, redirectTarget);
      res.setHeader("location", gatewayPath(token, redirectTarget));
      return res.status(upstream.status).end();
    }

    copyResponseHeaders(upstream, res);
    res.status(upstream.status);
    const contentType = upstream.headers.get("content-type") || "";
    if (contentType.includes("text/html") && upstream.body) {
      const html = rewriteHtml(await upstream.text(), upstreamUrl, token);
      res.removeHeader("content-length");
      const sessionScript = sessionHeartbeatScript(token, claims.origin);
      return res.send(html.includes("</head>")
        ? html.replace(/<\/head>/i, `${sessionScript}</head>`)
        : html.includes("</body>")
          ? html.replace(/<\/body>/i, `${sessionScript}</body>`)
          : `${html}${sessionScript}`);
    }
    if (/(?:javascript|ecmascript|text\/js)/i.test(contentType) && upstream.body) {
      const source = await upstream.text();
      res.removeHeader("content-length");
      return res.send(rewriteDynamicModuleBase(source, token));
    }
    if (!upstream.body) return res.end();
    Readable.fromWeb(upstream.body as any).on("error", () => {
      if (!res.headersSent) res.status(502);
      res.end();
    }).pipe(res);
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
