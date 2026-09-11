import "dotenv/config";
import express from "express";
import { createServer } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { registerGatewayRoutes } from "./gateway";
import { registerGatewayWebSockets } from "./websocketGateway";
import { registerArcadeApi } from "./api";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.resolve(__dirname, "public");
const app = express();
const server = createServer(app);

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

const port = Number(process.env.PORT || 3000);
server.listen(port, "0.0.0.0", () => {
  console.log(`[standalone] listening on 0.0.0.0:${port}`);
  console.log("[standalone] HTTPS destinations only; private networks blocked");
});

process.on("SIGTERM", () => server.close(() => process.exit(0)));
process.on("SIGINT", () => server.close(() => process.exit(0)));
