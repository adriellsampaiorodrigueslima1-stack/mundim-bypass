import type { IncomingMessage } from "node:http";
import type { Server } from "node:http";
import { WebSocket, WebSocketServer } from "ws";
import { readGatewayToken, assertPublicHttpsTarget } from "./gateway";

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

export function registerGatewayWebSockets(server: Server) {
  server.on("upgrade", async (request, socket, head) => {
    const pathname = new URL(request.url || "/", "http://gateway.local").pathname;
    const match = pathname.match(/^\/gateway-ws\/([^/]+)(\/.*)?$/);
    if (!match) return;

    const token = match[1];
    try {
      const claims = await readGatewayToken(token);
      const upstreamHttps = websocketTarget(request, token, claims.origin);
      await assertPublicHttpsTarget(upstreamHttps);
      const upstreamUrl = upstreamHttps.toString().replace(/^https:/, "wss:");

      websocketServer.handleUpgrade(request, socket, head, (client) => {
        const upstream = new WebSocket(upstreamUrl, {
          headers: {
            origin: claims.origin,
            "user-agent": "bypassschool-authorized-gateway/0.3",
          },
        });

        const closeBoth = (code = 1000, reason = "") => {
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
