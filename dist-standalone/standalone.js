// server/standalone.ts
import "dotenv/config";
import express from "express";
import { createServer } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

// server/gateway.ts
import { createHash, randomUUID } from "node:crypto";
import dns from "node:dns/promises";
import net from "node:net";
import { Readable } from "node:stream";
import { CompactEncrypt, compactDecrypt } from "jose";

// server/_core/env.ts
var ENV = {
  appId: process.env.VITE_APP_ID ?? "",
  cookieSecret: process.env.JWT_SECRET ?? "",
  databaseUrl: process.env.DATABASE_URL ?? "",
  oAuthServerUrl: process.env.OAUTH_SERVER_URL ?? "",
  ownerOpenId: process.env.OWNER_OPEN_ID ?? "",
  isProduction: process.env.NODE_ENV === "production",
  forgeApiUrl: process.env.BUILT_IN_FORGE_API_URL ?? "",
  forgeApiKey: process.env.BUILT_IN_FORGE_API_KEY ?? ""
};

// server/gateway.ts
var SESSION_IDLE_TIMEOUT_MS = 2 * 60 * 1e3;
var SESSION_MAX_TTL_MS = 24 * 60 * 60 * 1e3;
var UPSTREAM_TIMEOUT_MS = 3e4;
var RETRYABLE_METHODS = /* @__PURE__ */ new Set(["GET", "HEAD"]);
var activeSessions = /* @__PURE__ */ new Map();
var closedSessions = /* @__PURE__ */ new Set();
function isBlockedAddress(address) {
  if (net.isIPv4(address)) {
    const [a, b] = address.split(".").map(Number);
    return a === 0 || a === 10 || a === 127 || a === 100 && b >= 64 && b <= 127 || a === 169 && b === 254 || a === 172 && b >= 16 && b <= 31 || a === 192 && b === 168 || a === 198 && (b === 18 || b === 19);
  }
  if (net.isIPv6(address)) {
    const normalized = address.toLowerCase();
    return normalized === "::" || normalized === "::1" || normalized.startsWith("fc") || normalized.startsWith("fd") || normalized.startsWith("fe8") || normalized.startsWith("fe9") || normalized.startsWith("fea") || normalized.startsWith("feb");
  }
  return true;
}
async function assertPublicHttpsTarget(target) {
  if (target.protocol !== "https:") throw new Error("O gateway aceita somente destinos HTTPS.");
  if (target.username || target.password) throw new Error("URLs com credenciais n\xE3o s\xE3o permitidas.");
  if (target.hostname === "localhost" || target.hostname.endsWith(".local") || target.hostname.endsWith(".internal")) {
    throw new Error("Destinos locais ou internos n\xE3o s\xE3o permitidos.");
  }
  const addresses = net.isIP(target.hostname) ? [target.hostname] : (await dns.lookup(target.hostname, { all: true, verbatim: true })).map(({ address }) => address);
  if (!addresses.length || addresses.some(isBlockedAddress)) {
    throw new Error("O destino precisa resolver para um endere\xE7o p\xFAblico.");
  }
}
async function parseAllowedTarget(rawTarget) {
  const trimmed = rawTarget.trim();
  const normalized = /^http:\/\//i.test(trimmed) ? `https://${trimmed.slice(7)}` : /^[a-z][a-z\d+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed.replace(/^\/\//, "")}`;
  let target;
  try {
    target = new URL(normalized);
  } catch {
    throw new Error("Informe uma URL v\xE1lida.");
  }
  await assertPublicHttpsTarget(target);
  return target;
}
function encryptionKey() {
  const secret = ENV.cookieSecret || "bypassschool-local-development-only-key";
  return createHash("sha256").update(secret).digest();
}
async function createGatewayToken(target) {
  const claims = {
    sid: randomUUID(),
    origin: target.origin,
    initialPath: `${target.pathname || "/"}${target.search}`,
    exp: Date.now() + SESSION_MAX_TTL_MS
  };
  closedSessions.delete(claims.sid);
  activeSessions.set(claims.sid, Date.now() + SESSION_IDLE_TIMEOUT_MS);
  return new CompactEncrypt(new TextEncoder().encode(JSON.stringify(claims))).setProtectedHeader({ alg: "dir", enc: "A256GCM", typ: "BYPASS-GATEWAY" }).encrypt(encryptionKey());
}
async function readGatewayToken(token) {
  const { plaintext } = await compactDecrypt(token, encryptionKey());
  const claims = JSON.parse(new TextDecoder().decode(plaintext));
  const idleUntil = activeSessions.get(claims.sid);
  if (!claims || typeof claims.sid !== "string" || typeof claims.origin !== "string" || typeof claims.initialPath !== "string" || typeof claims.exp !== "number" || claims.exp < Date.now() || closedSessions.has(claims.sid) || typeof idleUntil === "number" && idleUntil < Date.now()) {
    throw new Error("Sess\xE3o fechada, ociosa ou inv\xE1lida.");
  }
  activeSessions.set(claims.sid, Date.now() + SESSION_IDLE_TIMEOUT_MS);
  return claims;
}
async function heartbeatGatewaySession(token) {
  await readGatewayToken(token);
}
async function closeGatewaySession(token) {
  try {
    const { plaintext } = await compactDecrypt(token, encryptionKey());
    const claims = JSON.parse(new TextDecoder().decode(plaintext));
    if (claims.sid) {
      activeSessions.delete(claims.sid);
      closedSessions.add(claims.sid);
    }
  } catch {
  }
}
function gatewayPath(token, target) {
  const suffix = `${target.pathname || "/"}${target.search}`;
  return `/gateway/${token}${suffix === "/" ? "/" : suffix}`;
}
function gatewayHostPath(token, target, sessionOrigin) {
  if (target.origin === sessionOrigin) return gatewayPath(token, target);
  return `/gateway/${token}/__host/${encodeURIComponent(target.host)}${target.pathname || "/"}${target.search}`;
}
function isRelatedGameHost(sessionOrigin, target) {
  const sessionHost = new URL(sessionOrigin).hostname;
  if (target.protocol !== "https:") return false;
  if (target.hostname === sessionHost || target.hostname.endsWith(`.${sessionHost}`)) return true;
  return sessionHost === "2v2.io" && (target.hostname === "files.2v2.io" || target.hostname === "api.2v2.io");
}
function assertSessionHostAllowed(claimsOrigin, target) {
  if (!isRelatedGameHost(claimsOrigin, target)) {
    throw new Error("O recurso est\xE1 fora dos hosts autorizados da sess\xE3o.");
  }
}
function rewriteHtml(html, upstreamUrl, token) {
  const attributePattern = /(src|href|action|poster)=("|')([^"']+)(\2)/gi;
  const rewritten = html.replace(attributePattern, (full, attribute, quote, value) => {
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
function rewriteDynamicModuleBase(source, token) {
  return source.replace(/de\.p="\/"/g, `de.p="/gateway/${token}/"`);
}
function sessionHeartbeatScript(token, siteOrigin) {
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
    loader.innerHTML = '<div class="bs-loader-box"><div class="bs-loader-ring"></div><div class="bs-loader-title">carregando, aguarde....</div><div class="bs-loader-sub">preparando uma sess\xE3o segura</div></div>';
    document.documentElement.appendChild(loader);
    const watermark = document.createElement('div');
    watermark.id = 'bypassschool-watermark';
    watermark.innerHTML = '<span class="bs-watermark-name">Mundim Bypass</span><span class="bs-watermark-sep">\xB7</span><span>' + site + '</span><span class="bs-watermark-sep">\xB7</span><span id="bypassschool-ping">ping...</span><button id="bypassschool-emergency" type="button" title="Encerrar sess\xE3o (tecla 0)">SAIR</button>';
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
function getRequestPath(req, claims) {
  const wildcard = typeof req.params[0] === "string" ? req.params[0] : "";
  const queryIndex = req.originalUrl.indexOf("?");
  const query = queryIndex >= 0 ? req.originalUrl.slice(queryIndex) : "";
  if (!wildcard) return claims.initialPath;
  return `/${wildcard}${query}`;
}
function getUpstreamUrl(req, claims) {
  const requestPath = getRequestPath(req, claims);
  const marker = "/__host/";
  if (requestPath.startsWith(marker)) {
    const encodedHostAndPath = requestPath.slice(marker.length);
    const slashIndex = encodedHostAndPath.indexOf("/");
    if (slashIndex <= 0) throw new Error("Destino de recurso inv\xE1lido.");
    const host = decodeURIComponent(encodedHostAndPath.slice(0, slashIndex));
    const path2 = encodedHostAndPath.slice(slashIndex) || "/";
    const target = new URL(`${path2}`, `https://${host}`);
    return target;
  }
  return new URL(requestPath, claims.origin);
}
function copyResponseHeaders(upstream, res) {
  for (const name of ["content-type", "cache-control", "etag", "last-modified", "content-range", "accept-ranges", "vary"]) {
    const value = upstream.headers.get(name);
    if (value) res.setHeader(name, value);
  }
  const setCookies = typeof upstream.headers.getSetCookie === "function" ? upstream.headers.getSetCookie() : upstream.headers.get("set-cookie") ? [upstream.headers.get("set-cookie")] : [];
  for (const cookie of setCookies) {
    res.append("set-cookie", cookie.replace(/;\s*Domain=[^;]+/gi, ""));
  }
  res.setHeader("x-bypassschool-gateway", "public-https-session");
  res.setHeader("x-content-type-options", "nosniff");
}
function applyGatewayCors(req, res) {
  const requestOrigin = typeof req.headers.origin === "string" ? req.headers.origin : "";
  const configured = (process.env.ARCADE_CORS_ORIGINS || "").split(",").map((value) => value.trim()).filter(Boolean);
  const allowed = requestOrigin && (configured.includes("*") || configured.includes(requestOrigin));
  if (allowed) {
    res.setHeader("access-control-allow-origin", requestOrigin);
    res.setHeader("access-control-allow-credentials", "true");
    res.setHeader("vary", "Origin");
  }
  res.setHeader("access-control-allow-methods", "GET,HEAD,POST,PUT,PATCH,OPTIONS");
  res.setHeader("access-control-allow-headers", "Content-Type, Range, If-None-Match, If-Modified-Since, X-Requested-With");
}
async function fetchUpstream(url, init, method) {
  const attempts = RETRYABLE_METHODS.has(method) ? 2 : 1;
  let lastError;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      return await fetch(url, { ...init, signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS) });
    } catch (error) {
      lastError = error;
      if (attempt + 1 < attempts) await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }
  throw lastError instanceof Error ? lastError : new Error("Falha ao conectar ao destino.");
}
async function handleGatewayRequest(req, res) {
  const token = req.params.token;
  try {
    applyGatewayCors(req, res);
    if (req.method === "OPTIONS") return res.status(204).end();
    const claims = await readGatewayToken(token);
    const upstreamUrl = getUpstreamUrl(req, claims);
    if (upstreamUrl.origin !== claims.origin) {
      await assertPublicHttpsTarget(upstreamUrl);
      assertSessionHostAllowed(claims.origin, upstreamUrl);
    }
    const method = req.method.toUpperCase();
    const hasBody = !["GET", "HEAD"].includes(method);
    const requestBody = hasBody && req.body !== void 0 ? Buffer.isBuffer(req.body) || typeof req.body === "string" ? req.body : JSON.stringify(req.body) : void 0;
    const upstream = await fetchUpstream(upstreamUrl, {
      method,
      redirect: "manual",
      headers: {
        accept: req.headers.accept || "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept-language": req.headers["accept-language"] || "pt-BR,pt;q=0.9,en;q=0.8",
        "accept-encoding": req.headers["accept-encoding"] || "gzip, br, deflate",
        "user-agent": "bypassschool-authorized-gateway/0.3",
        ...req.headers.cookie ? { cookie: req.headers.cookie } : {},
        ...req.headers.referer ? { referer: req.headers.referer } : {},
        ...req.headers["content-type"] ? { "content-type": req.headers["content-type"] } : {},
        ...req.headers.range ? { range: req.headers.range } : {},
        ...req.headers["if-none-match"] ? { "if-none-match": req.headers["if-none-match"] } : {},
        ...req.headers["if-modified-since"] ? { "if-modified-since": req.headers["if-modified-since"] } : {}
      },
      body: requestBody
    }, method);
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
      return res.send(html.includes("</head>") ? html.replace(/<\/head>/i, `${sessionScript}</head>`) : html.includes("</body>") ? html.replace(/<\/body>/i, `${sessionScript}</body>`) : `${html}${sessionScript}`);
    }
    if (/(?:javascript|ecmascript|text\/js)/i.test(contentType) && upstream.body) {
      const source = await upstream.text();
      res.removeHeader("content-length");
      return res.send(rewriteDynamicModuleBase(source, token));
    }
    if (!upstream.body) return res.end();
    Readable.fromWeb(upstream.body).on("error", () => {
      if (!res.headersSent) res.status(502);
      res.end();
    }).pipe(res);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Falha ao abrir a sess\xE3o.";
    const status = message.includes("Sess\xE3o") ? 401 : 502;
    res.status(status).type("text").send(message);
  }
}
function registerGatewayRoutes(app2) {
  app2.post("/api/gateway/heartbeat", async (req, res) => {
    try {
      await heartbeatGatewaySession(String(req.body?.token || ""));
      res.status(204).end();
    } catch {
      res.status(401).json({ error: "Sess\xE3o fechada ou expirada." });
    }
  });
  app2.post("/api/gateway/close", async (req, res) => {
    await closeGatewaySession(String(req.body?.token || ""));
    res.status(204).end();
  });
  app2.get("/gateway/:token", handleGatewayRequest);
  app2.get("/gateway/:token/*", handleGatewayRequest);
}

// server/websocketGateway.ts
import { WebSocket, WebSocketServer } from "ws";
var websocketServer = new WebSocketServer({ noServer: true });
function websocketTarget(request, token, claimsOrigin) {
  const requestUrl = new URL(request.url || "/", "http://gateway.local");
  const rawPath = requestUrl.pathname || "/";
  const hostMarker = "/__host/";
  if (rawPath.startsWith(hostMarker)) {
    const encodedHostAndPath = rawPath.slice(hostMarker.length);
    const slashIndex = encodedHostAndPath.indexOf("/");
    if (slashIndex <= 0) throw new Error("WebSocket sem host v\xE1lido.");
    const host = decodeURIComponent(encodedHostAndPath.slice(0, slashIndex));
    const path2 = encodedHostAndPath.slice(slashIndex) || "/";
    return new URL(`${path2}${requestUrl.search}`, `https://${host}`);
  }
  const upstream = new URL(`${rawPath}${requestUrl.search}`, claimsOrigin);
  return upstream;
}
function isAllowedWebSocketHost(origin, target) {
  const host = new URL(origin).hostname;
  return target.hostname === host || target.hostname.endsWith(`.${host}`) || host === "2v2.io" && ["files.2v2.io", "api.2v2.io"].includes(target.hostname);
}
function registerGatewayWebSockets(server2) {
  server2.on("upgrade", async (request, socket, head) => {
    const pathname = new URL(request.url || "/", "http://gateway.local").pathname;
    const match = pathname.match(/^\/gateway-ws\/([^/]+)(\/.*)?$/);
    if (!match) return;
    const token = match[1];
    try {
      const claims = await readGatewayToken(token);
      const upstreamHttps = websocketTarget(request, token, claims.origin);
      await assertPublicHttpsTarget(upstreamHttps);
      if (!isAllowedWebSocketHost(claims.origin, upstreamHttps)) throw new Error("WebSocket fora do host autorizado.");
      const upstreamUrl = upstreamHttps.toString().replace(/^https:/, "wss:");
      const protocolHeader = request.headers["sec-websocket-protocol"];
      const protocols = typeof protocolHeader === "string" ? protocolHeader.split(",").map((value) => value.trim()).filter(Boolean) : [];
      websocketServer.handleUpgrade(request, socket, head, (client) => {
        const upstream = new WebSocket(upstreamUrl, protocols.length ? protocols : void 0, {
          headers: {
            origin: claims.origin,
            ...request.headers.cookie ? { cookie: request.headers.cookie } : {},
            ...request.headers.referer ? { referer: request.headers.referer } : {},
            "user-agent": request.headers["user-agent"] || "Mundim-Bypass-Gateway/1.0"
          }
        });
        const keepAlive = setInterval(() => {
          if (client.readyState === WebSocket.OPEN) client.ping();
          if (upstream.readyState === WebSocket.OPEN) upstream.ping();
        }, 25e3);
        const closeBoth = (code = 1e3, reason = "") => {
          clearInterval(keepAlive);
          if (client.readyState === WebSocket.OPEN || client.readyState === WebSocket.CONNECTING) client.close(code, reason);
          if (upstream.readyState === WebSocket.OPEN || upstream.readyState === WebSocket.CONNECTING) upstream.close(code, reason);
        };
        client.on("message", (data, isBinary) => {
          if (upstream.readyState === WebSocket.OPEN) upstream.send(data, { binary: isBinary });
        });
        upstream.on("message", (data, isBinary) => {
          if (client.readyState === WebSocket.OPEN) client.send(data, { binary: isBinary });
        });
        client.on("close", () => closeBoth());
        upstream.on("close", (code, reason) => {
          if (client.readyState === WebSocket.OPEN) client.close(code, reason);
        });
        client.on("error", () => closeBoth(1011, "client error"));
        upstream.on("error", () => closeBoth(1011, "upstream error"));
      });
    } catch {
      socket.destroy();
    }
  });
}

// server/api.ts
import { timingSafeEqual } from "node:crypto";
function configuredKeys() {
  return (process.env.ARCADE_API_KEYS || "").split(",").map((key) => key.trim()).filter(Boolean);
}
function apiKeyAllowed(req) {
  const keys = configuredKeys();
  if (!keys.length) return true;
  const supplied = String(req.header("x-api-key") || req.header("authorization")?.replace(/^Bearer\s+/i, "") || "");
  return keys.some((expected) => {
    const left = Buffer.from(supplied);
    const right = Buffer.from(expected);
    return left.length === right.length && timingSafeEqual(left, right);
  });
}
function corsOrigin(req) {
  const configured = (process.env.ARCADE_CORS_ORIGINS || "*").split(",").map((origin) => origin.trim()).filter(Boolean);
  const requestOrigin = req.header("origin");
  if (configured.includes("*")) return "*";
  return requestOrigin && configured.includes(requestOrigin) ? requestOrigin : "";
}
function setApiHeaders(req, res) {
  const origin = corsOrigin(req);
  if (origin) res.setHeader("access-control-allow-origin", origin);
  res.setHeader("access-control-allow-methods", "GET,POST,OPTIONS");
  res.setHeader("access-control-allow-headers", "content-type,x-api-key,authorization");
  res.setHeader("access-control-max-age", "600");
  res.setHeader("cache-control", "no-store");
}
function absoluteUrl(req, path2) {
  const configured = process.env.PUBLIC_GATEWAY_BASE_URL?.trim();
  const publicBase = (configured || `${req.protocol}://${req.get("host")}`).replace(/\/+$/, "");
  return `${publicBase}${path2}`;
}
function unauthorized(res) {
  return res.status(401).json({ ok: false, error: "API key ausente ou inv\xE1lida." });
}
function registerArcadeApi(app2) {
  app2.use("/api/v1", (req, res, next) => {
    setApiHeaders(req, res);
    if (req.method === "OPTIONS") return res.status(204).end();
    next();
  });
  app2.get("/api/v1", (_req, res) => {
    res.json({
      name: "bypassschool arcade API",
      version: "1",
      endpoints: {
        createSession: "GET /api/v1/sessions?url=https%3A%2F%2Fexample.com",
        createSessionLegacy: "POST /api/v1/sessions",
        heartbeat: "POST /api/v1/sessions/heartbeat",
        close: "POST /api/v1/sessions/close",
        health: "GET /api/v1/health"
      }
    });
  });
  app2.get("/api/v1/health", (_req, res) => {
    res.json({ ok: true, service: "bypassschool-gateway", transport: "https + websocket" });
  });
  const createSession = async (req, res) => {
    if (!apiKeyAllowed(req)) return unauthorized(res);
    try {
      const rawTarget = String(req.query.url || req.query.target || req.body?.url || req.body?.target || "").trim();
      if (!rawTarget) return res.status(400).json({ ok: false, error: "Campo 'url' \xE9 obrigat\xF3rio." });
      const target = await parseAllowedTarget(rawTarget);
      const token = await createGatewayToken(target);
      const gatewayPath2 = `/gateway/${token}${target.pathname === "/" ? "/" : `${target.pathname}${target.search}`}`;
      const websocketPath = `/gateway-ws/${token}/`;
      return res.status(201).json({
        ok: true,
        session: {
          token,
          origin: target.origin,
          gatewayUrl: absoluteUrl(req, gatewayPath2),
          websocketUrl: absoluteUrl(req, websocketPath).replace(/^http/, "ws"),
          heartbeatUrl: absoluteUrl(req, "/api/v1/sessions/heartbeat"),
          closeUrl: absoluteUrl(req, "/api/v1/sessions/close"),
          maxLifetimeHours: 24,
          idleTimeoutMinutes: 2
        }
      });
    } catch (error) {
      return res.status(400).json({ ok: false, error: error instanceof Error ? error.message : "Destino inv\xE1lido." });
    }
  };
  app2.get("/api/v1/sessions", createSession);
  app2.post("/api/v1/sessions", createSession);
  app2.post("/api/v1/sessions/heartbeat", async (req, res) => {
    if (!apiKeyAllowed(req)) return unauthorized(res);
    try {
      await heartbeatGatewaySession(String(req.body?.token || ""));
      return res.status(204).end();
    } catch {
      return res.status(401).json({ ok: false, error: "Sess\xE3o fechada ou expirada." });
    }
  });
  app2.post("/api/v1/sessions/close", async (req, res) => {
    if (!apiKeyAllowed(req)) return unauthorized(res);
    await closeGatewaySession(String(req.body?.token || ""));
    return res.status(204).end();
  });
}

// server/standalone.ts
var __dirname = path.dirname(fileURLToPath(import.meta.url));
var publicDir = path.resolve(__dirname, "public");
var app = express();
var server = createServer(app);
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ limit: "10mb", extended: true }));
registerGatewayWebSockets(server);
registerArcadeApi(app);
registerGatewayRoutes(app);
app.get("/ArcadeX.html", (_req, res) => res.sendFile(path.resolve(process.cwd(), "ArcadeX.html")));
app.use(express.static(publicDir, { index: "index.html", redirect: false }));
app.get("*", (_req, res) => res.sendFile(path.join(publicDir, "index.html")));
var port = Number(process.env.PORT || 3e3);
server.listen(port, "0.0.0.0", () => {
  console.log(`[standalone] listening on 0.0.0.0:${port}`);
  console.log("[standalone] HTTPS destinations only; private networks blocked");
});
process.on("SIGTERM", () => server.close(() => process.exit(0)));
process.on("SIGINT", () => server.close(() => process.exit(0)));
