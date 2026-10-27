/** `POST /v1` (si API e Mysten) → prover-i; `GET /health`. */
import { createServer } from "node:http";
import { RateLimiter, requestIp } from "./rate-limit.js";

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

const limiter = new RateLimiter(limit);
const trustedProxies = (process.env.TRUSTED_PROXIES ?? "").split(",").map(s => s.trim()).filter(Boolean);

const server = createServer(async (req, res) => {
  const origin = req.headers.origin ?? "";
  const allow = corsOrigins.includes("*") ? "*" : corsOrigins.includes(origin) ? origin : "";
  if (allow) res.setHeader("access-control-allow-origin", allow);
  res.setHeader("access-control-allow-headers", "content-type");
  res.setHeader("access-control-allow-methods", "POST, GET, OPTIONS");
  const json = (s: number, b: unknown) => (res.writeHead(s, { "content-type": "application/json" }), res.end(JSON.stringify(b)));
  if (req.method === "OPTIONS") return res.writeHead(204).end();
  if (req.method === "GET" && req.url === "/health") return json(200, { ok: true });
  if (req.method !== "POST" || req.url !== "/v1") return json(404, { error: "not found" });
  const ip = requestIp(req, trustedProxies);
  if (!limiter.allow(ip)) return json(429, { error: "shumë kërkesa" });
  try {
    let body = "";
    for await (const c of req) {
      body += c;
      if (body.length > 16_384) return json(413, { error: "kërkesë shumë e madhe" });
    }
    const r = checkRequest(JSON.parse(body), { allowedAudiences, maxSessionSecs });
    const up = await fetch(upstream, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(r), signal: AbortSignal.timeout(30000) });
    res.writeHead(up.status, { "content-type": up.headers.get("content-type") ?? "application/json" });
    res.end(await up.text());
  } catch (e) {
    if (e instanceof RejectError) return json(e.status, { error: e.message });
    json(502, { error: "prover-i nuk u përgjigj" });
  }
});
server.listen(Number(process.env.PORT ?? 8080), () => console.log(`prover proxy port=${(server.address() as import("node:net").AddressInfo).port}`));
