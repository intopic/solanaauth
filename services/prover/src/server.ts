/** `POST /v1` (si API e Mysten) → prover-i; `GET /health`. */
import { createServer } from "node:http";

import { RejectError, checkRequest } from "./index.js";

const upstream = process.env.UPSTREAM ?? "http://localhost:8081/v1";
const allowedAudiences = (process.env.ALLOWED_AUDIENCES ?? "").split(",").map((s) => s.trim()).filter(Boolean);
const corsOrigins = (process.env.CORS_ORIGINS ?? "*").split(",").map((s) => s.trim());
const limit = Number(process.env.RATE_LIMIT_PER_MIN ?? 10);
const maxSessionSecs = Number(process.env.MAX_SESSION_SECS ?? 30 * 86400);
if (allowedAudiences.length === 0) {
  console.error("ALLOWED_AUDIENCES mungon");
  process.exit(1);
}

const hits = new Map<string, { n: number; reset: number }>();
const limited = (ip: string) => {
  const now = Date.now();
  const h = hits.get(ip);
  if (!h || now > h.reset) return hits.set(ip, { n: 1, reset: now + 60_000 }), false;
  return ++h.n > limit;
};

createServer(async (req, res) => {
  const origin = req.headers.origin ?? "";
  const allow = corsOrigins.includes("*") ? "*" : corsOrigins.includes(origin) ? origin : "";
  if (allow) res.setHeader("access-control-allow-origin", allow);
  res.setHeader("access-control-allow-headers", "content-type");
  res.setHeader("access-control-allow-methods", "POST, GET, OPTIONS");
  const json = (s: number, b: unknown) => (res.writeHead(s, { "content-type": "application/json" }), res.end(JSON.stringify(b)));
  if (req.method === "OPTIONS") return res.writeHead(204).end();
  if (req.method === "GET" && req.url === "/health") return json(200, { ok: true });
  if (req.method !== "POST" || req.url !== "/v1") return json(404, { error: "not found" });
  const ip = (req.headers["x-forwarded-for"] as string | undefined)?.split(",")[0].trim() ?? req.socket.remoteAddress ?? "";
  if (limited(ip)) return json(429, { error: "shumë kërkesa" });
  let body = "";
  for await (const c of req) {
    body += c;
    if (body.length > 16_384) return json(413, { error: "kërkesë shumë e madhe" });
  }
  try {
    const r = checkRequest(JSON.parse(body), { allowedAudiences, maxSessionSecs });
    const up = await fetch(upstream, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(r) });
    res.writeHead(up.status, { "content-type": up.headers.get("content-type") ?? "application/json" });
    res.end(await up.text());
  } catch (e) {
    if (e instanceof RejectError) return json(e.status, { error: e.message });
    json(502, { error: "prover-i nuk u përgjigj" });
  }
}).listen(8080, () => console.log(`prover proxy → ${upstream}`));
