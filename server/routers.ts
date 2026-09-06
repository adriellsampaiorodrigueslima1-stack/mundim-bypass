import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { COOKIE_NAME } from "@shared/const";
import { createGatewayToken, getAllowedOrigins, parseAllowedTarget } from "./gateway";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { publicProcedure, router } from "./_core/trpc";

export const appRouter = router({
  system: systemRouter,
  auth: router({
    me: publicProcedure.query((opts) => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      return { success: true } as const;
    }),
  }),
  gateway: router({
    config: publicProcedure.query(() => ({
      allowedOrigins: getAllowedOrigins(),
      sessionTtlMinutes: 15,
      transport: "HTTPS + JWE",
    })),
    createSession: publicProcedure
      .input(z.object({ target: z.string().trim().min(1).max(2048) }))
      .mutation(async ({ input }) => {
        let parsed: URL;
        try {
          parsed = parseAllowedTarget(input.target);
        } catch (error) {
          throw new TRPCError({
            code: "BAD_REQUEST",
            message: error instanceof Error ? error.message : "Destino não autorizado.",
          });
        }

        const token = await createGatewayToken(parsed);
        return {
          token,
          origin: parsed.origin,
          proxyUrl: `/gateway/${token}${parsed.pathname === "/" ? "/" : `${parsed.pathname}${parsed.search}`}`,
          expiresAt: Date.now() + 15 * 60 * 1000,
        };
      }),
  }),
});

export type AppRouter = typeof appRouter;
