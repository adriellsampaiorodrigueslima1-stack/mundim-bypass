const CACHE_NAME = "mundim-gateway-runtime-v1";

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});
self.addEventListener("fetch", (event) => {
  if (event.request.method === "GET" || event.request.method === "HEAD") {
    event.respondWith(fetch(event.request, { credentials: "include" }));
  }
});