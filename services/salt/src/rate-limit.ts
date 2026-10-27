import type { IncomingMessage } from "node:http";
import { isIP } from "node:net";

/** Forwarded headers are untrusted unless the socket peer is an explicitly trusted proxy. */
export function requestIp(req: IncomingMessage, trustedProxies: string[] = []): string {
  const peer = req.socket.remoteAddress ?? "unknown";
  if (!trustedProxies.includes(peer)) return peer;
  const header = req.headers["x-forwarded-for"];
  const value = (Array.isArray(header) ? header[0] : header)?.split(",")[0].trim();
  return value && isIP(value) ? value : peer;
}

export class RateLimiter {
  private hits = new Map<string, { n: number; reset: number }>();
  constructor(private limit: number, private capacity = 10000, private clock = Date.now) {
    if (!Number.isSafeInteger(limit) || limit <= 0 || capacity <= 0) throw new Error("invalid rate limit");
  }
  allow(ip: string): boolean {
    const now = this.clock();
    for (const [key, hit] of this.hits) {
      if (hit.reset > now) break;
      this.hits.delete(key);
    }
    const hit = this.hits.get(ip);
    if (hit) return ++hit.n <= this.limit;
    if (this.hits.size >= this.capacity) return false;
    this.hits.set(ip, { n: 1, reset: now + 60000 });
    return true;
  }
}
