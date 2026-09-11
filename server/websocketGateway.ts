import type { IncomingMessage } from "node:http";
import type { Server } from "node:http";
import { WebSocket, WebSocketServer } from "ws";
import { readGatewayToken, assertPublicHttpsTarget, decodeGatewayTokenFromPath } from "./gateway";

const websocketServer = new WebSocketServer({ noServer: true });

function websocketTarget(request: IncomingMessage, token: string, claimsOrigin: string) {
  const requestUrl = new URL(request.url || "/", "http://gateway.local");
  const rawPath = requestUrl.pathname || "/";
  const hostMarker = "/__host/";
  if (rawPath.startsWith(hostMarker)) {
    const encodedHostAndPath = rawPath.slice(hostMarker.length);
    const slashIndex = encodedHostAndPath.indexOf("/");
    if (slashIndex <= 0) throw new Error("WebSocket sem host válido.");
    const host = decodeURIComponent(encodedHostAndPath.slice(0, slashIndex));
    const path = encodedHostAndPath.slice(slashIndex) || "/";
    return new URL(`${path}${requestUrl.search}`, `https://${host}`);
  }
  const upstream = new URL(`${rawPath}${requestUrl.search}`, claimsOrigin);
  return upstream;
}

function isAllowedWebSocketHost(origin: string, target: URL) {
  const host = new URL(origin).hostname;
  return target.hostname === host || target.hostname.endsWith(`.${host}`) ||
    (host === "2v2.io" && ["files.2v2.io", "api.2v2.io"].includes(target.hostname));
}

export function registerGatewayWebSockets(server: Server) {
  server.on("upgrade", async (request, socket, head) => {
    const pathname = new URL(request.url || "/", "http://gateway.local").pathname;
    const match = pathname.match(/^\/gateway-ws\/([^/]+)(\/.*)?$/);
    if (!match) return;

    const token = decodeGatewayTokenFromPath(decodeURIComponent(match[1]));
    try {
      const claims = await readGatewayToken(token);
      const upstreamHttps = websocketTarget(request, token, claims.origin);
      await assertPublicHttpsTarget(upstreamHttps);
      if (!isAllowedWebSocketHost(claims.origin, upstreamHttps)) throw new Error("WebSocket fora do host autorizado.");
      const upstreamUrl = upstreamHttps.toString().replace(/^https:/, "wss:");
      const protocolHeader = request.headers["sec-websocket-protocol"];
      const protocols = typeof protocolHeader === "string"
        ? protocolHeader.split(",").map(value => value.trim()).filter(Boolean)
        : [];

      websocketServer.handleUpgrade(request, socket, head, (client) => {
        const upstream = new WebSocket(upstreamUrl, protocols.length ? protocols : undefined, {
          headers: {
            origin: claims.origin,
            ...(request.headers.cookie ? { cookie: request.headers.cookie } : {}),
            ...(request.headers.referer ? { referer: request.headers.referer } : {}),
            "user-agent": request.headers["user-agent"] || "Mundim-Bypass-Gateway/1.0",
          },
        });

        const keepAlive = setInterval(() => {
          if (client.readyState === WebSocket.OPEN) client.ping();
          if (upstream.readyState === WebSocket.OPEN) upstream.ping();
        }, 25_000);

        const closeBoth = (code = 1000, reason = "") => {
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
