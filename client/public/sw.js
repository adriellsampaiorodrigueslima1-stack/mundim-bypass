// client/public/sw.js
const PROXY_ENDPOINT = '/api/gateway';

self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', (event) => {
  const reqUrl = new URL(event.request.url);

  // Ignora requisições internas do painel do Mundim Bypass e da própria API
  if (
    reqUrl.pathname.startsWith('/src/') ||
    reqUrl.pathname.startsWith('/api/') ||
    reqUrl.pathname.startsWith('/@') ||
    reqUrl.pathname.startsWith('/node_modules/') ||
    reqUrl.pathname === '/sw.js' ||
    reqUrl.pathname === '/favicon.ico'
  ) {
    return;
  }

  // Intercepta chamadas do escopo de navegação proxied
  if (reqUrl.pathname.startsWith('/service/')) {
    event.respondWith(handleProxiedFetch(event));
  }
});

async function handleProxiedFetch(event) {
  const req = event.request;
  const currentUrl = new URL(req.url);

  // Remove o prefixo /service/ para recuperar o endereço de destino
  const pathAfterService = currentUrl.pathname.replace(/^\/service\//, '');
  let destinationUrl = null;

  if (pathAfterService.startsWith('http://') || pathAfterService.startsWith('https://')) {
    destinationUrl = pathAfterService + currentUrl.search;
  } else {
    // Caso de requisição relativa disparada dentro da página (ex: /assets/game.wasm)
    const client = await self.clients.get(event.clientId);
    if (client && client.url) {
      const clientUrlObj = new URL(client.url);
      const originParam = clientUrlObj.searchParams.get('origin');
      if (originParam) {
        destinationUrl = new URL(pathAfterService + currentUrl.search, originParam).toString();
      }
    }
  }

  if (!destinationUrl) {
    return fetch(req);
  }

  const gatewayUrl = `${PROXY_ENDPOINT}?url=${encodeURIComponent(destinationUrl)}`;

  const forwardHeaders = new Headers(req.headers);
  forwardHeaders.set('X-Proxy-Target', destinationUrl);

  const requestInit = {
    method: req.method,
    headers: forwardHeaders,
    mode: 'cors',
    credentials: 'include',
    redirect: 'manual',
  };

  // Repassa o corpo da requisição em métodos com payload
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    requestInit.body = await req.blob();
  }

  try {
    const upstreamResponse = await fetch(gatewayUrl, requestInit);
    return upstreamResponse;
  } catch (error) {
    return new Response('Falha de rede ao conectar ao gateway proxy.', {
      status: 502,
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    });
  }
}
