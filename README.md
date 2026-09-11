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
