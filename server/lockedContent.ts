import { createHash, timingSafeEqual } from "node:crypto";
import type { Express, Request, Response } from "express";

const PRIVATE_CODE_HASH = "73d94ec15dd0e3aac692aebae1b984b1e97f4398daa052711c057e17ab418566";
const privateLinks = [
  { name: "UGPhone (Cloud Android)", url: "https://ugphone.com" },
  { name: "CloudMoon (Nuvem Android)", url: "https://web.cloudmoonapp.com/pt/" },
  { name: "MyAndroid.org", url: "https://myandroid.org/" },
];

function matchesCode(value: string) {
  const received = createHash("sha256").update(value).digest();
  const expected = Buffer.from(PRIVATE_CODE_HASH, "hex");
  return received.length === expected.length && timingSafeEqual(received, expected);
}

export function registerLockedContentApi(app: Express) {
  app.post("/api/v1/locked-content/unlock", (req: Request, res: Response) => {
    const code = String(req.body?.code || "");
    if (!matchesCode(code)) return res.status(401).json({ ok: false, error: "Código inválido." });
    res.setHeader("cache-control", "no-store");
    return res.json({ ok: true, items: privateLinks });
  });
}
