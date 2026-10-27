/**
 * HTTP: `POST /salt { "jwt": "..." }` → `{ "salt": "<decimal>" }`, `GET /health`.
 *
 * Mjedisi: `SALT_MASTER_SEED` (hex, 32 bytes), `ALLOWED_AUDIENCES` (me presje), `PORT`,
 * `CORS_ORIGINS` (me presje, ose `*`), `RATE_LIMIT_PER_MIN` (parazgjedhja 30 për IP).
 */
import { createServer } from "node:http";

import { SaltError, createSaltService } from "./index.js";

const seedHex = process.env.SALT_MASTER_SEED ?? "";
if (!/^[0-9a-fA-F]{64}$/.test(seedHex)) {
  console.error("SALT_MASTER_SEED duhet të jetë 64 karaktere hex (32 bytes)");
  process.exit(1);
}
const allowedAudiences = (process.env.ALLOWED_AUDIENCES ?? "").split(",").map((s) => s.trim()).filter(Boolean);
if (allowedAudiences.length === 0) {
  console.error("ALLOWED_AUDIENCES mungon (client ID-të e OAuth)");
  process.exit(1);
}
const corsOrigins = (process.env.CORS_ORIGINS ?? "*").split(",").map((s) => s.trim());
const limit = Number(process.env.RATE_LIMIT_PER_MIN ?? 30);
const salt = createSaltService({ masterSeed: Buffer.from(seedHex, "hex"), allowedAudiences });

const hits = new Map<string, { n: number; reset: number }>();
function rateLimited(ip: string): boolean {
  const now = Date.now();
  const h = hits.get(ip);
  if (!h || now > h.reset) {
    hits.set(ip, { n: 1, reset: now + 60_000 });
    return false;
  }
  h.n += 1;
  return h.n > limit;
}

createServer(async (req, res) => {
  const origin = req.headers.origin ?? "";
  const allow = corsOrigins.includes("*") ? "*" : corsOrigins.includes(origin) ? origin : "";
  if (allow) res.setHeader("access-control-allow-origin", allow);
  res.setHeader("access-control-allow-headers", "content-type");
  res.setHeader("access-control-allow-methods", "POST, GET, OPTIONS");
  const json = (status: number, body: unknown) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
  };
  if (req.method === "OPTIONS") return res.writeHead(204).end();
  if (req.method === "GET" && req.url === "/health") return json(200, { ok: true });
  if (req.method !== "POST" || req.url !== "/salt") return json(404, { error: "not found" });
  const ip = (req.headers["x-forwarded-for"] as string | undefined)?.split(",")[0].trim() ?? req.socket.remoteAddress ?? "";
  if (rateLimited(ip)) return json(429, { error: "shumë kërkesa" });
  let body = "";
  for await (const chunk of req) {
    body += chunk;
    if (body.length > 16_384) return json(413, { error: "kërkesë shumë e madhe" });
  }
  try {
    const { jwt } = JSON.parse(body);
    const r = await salt(jwt);
    json(200, { salt: r.salt });
  } catch (e) {
    if (e instanceof SaltError) return json(e.status, { error: e.message });
    json(400, { error: "kërkesë e pavlefshme" });
  }
}).listen(Number(process.env.PORT ?? 8787), () => {
  console.log(`salt service në portin ${process.env.PORT ?? 8787}`);
});
