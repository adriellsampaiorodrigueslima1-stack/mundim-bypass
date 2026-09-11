# Mundim Bypass

Projeto full-stack do site Mundim Bypass, com frontend React/Tailwind, gateway Express/tRPC e suporte a sessões HTTPS autorizadas.

## Editar pelo celular

Abra este repositório no aplicativo GitHub ou no navegador. Navegue até o arquivo, toque em **Edit**, faça a alteração, use uma mensagem de commit descritiva e confirme em **Commit changes**. Para alterações maiores, crie uma branch antes de editar.

## Arquivos principais

- `client/src/pages/Home.tsx` — interface inicial.
- `client/src/index.css` — tema, cores e estilos globais.
- `server/gateway.ts` — sessões, streaming HTTP e reescrita controlada.
- `server/websocketGateway.ts` — encaminhamento WebSocket autorizado.
- `server/api.ts` — API REST v1.
- `ArcadeX.html` — launcher HTML complementar.

## Desenvolvimento local

```bash
pnpm install
pnpm test
pnpm exec tsc --noEmit
pnpm build
```

Não publique arquivos `.env`, chaves, tokens ou credenciais. O gateway mantém HTTPS obrigatório, bloqueio de redes privadas e validação de hosts para evitar SSRF.

## Implantação independente no Render

O arquivo `render.yaml` configura um serviço Node.js que serve a interface, a API REST e o WebSocket no mesmo domínio. No Render, escolha **New Blueprint**, conecte este repositório e defina `PUBLIC_GATEWAY_BASE_URL` com a URL HTTPS do serviço depois que ele for criado. `JWT_SECRET` é gerado pelo Render; `ARCADE_CORS_ORIGINS` pode receber a origem autorizada do launcher e `ARCADE_API_KEYS` é opcional.

O serviço independente usa `server/standalone.ts`, não depende do entrypoint Manus e inicia com `pnpm run start:standalone`. O endpoint de saúde é `/api/v1/health`.
