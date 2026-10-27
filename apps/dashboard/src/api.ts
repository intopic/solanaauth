const BASE = import.meta.env.VITE_PLATFORM_URL ?? "http://localhost:8790";
const KEY = "solanaauth:dashboard";

export const token = {
  get: () => sessionStorage.getItem(KEY),
  set: (t: string) => sessionStorage.setItem(KEY, t),
  clear: () => sessionStorage.removeItem(KEY),
};

export async function api<T = any>(method: string, path: string, body?: unknown): Promise<T> {
  const r = await fetch(BASE + path, {
    method,
    headers: { "content-type": "application/json", ...(token.get() ? { authorization: `Bearer ${token.get()}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await r.json().catch(() => ({}));
  if (r.status === 401 && path !== "/auth/google") token.clear();
  if (!r.ok) throw new Error(data.error ?? `HTTP ${r.status}`);
  return data;
}

/** Hyrja me Google (id_token në fragment; nonce kundër replay). */
export function googleLogin() {
  const nonce = crypto.randomUUID();
  sessionStorage.setItem("solanaauth:nonce", nonce);
  const q = new URLSearchParams({
    client_id: import.meta.env.VITE_GOOGLE_CLIENT_ID ?? "",
    redirect_uri: window.location.origin,
    response_type: "id_token",
    scope: "openid email",
    nonce,
    prompt: "select_account",
  });
  window.location.assign(`https://accounts.google.com/o/oauth2/v2/auth?${q}`);
}

export async function finishLogin(): Promise<boolean> {
  const p = new URLSearchParams(window.location.hash.slice(1));
  const idToken = p.get("id_token");
  if (!idToken) return false;
  history.replaceState(null, "", window.location.pathname);
  const claims = JSON.parse(atob(idToken.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
  if (claims.nonce !== sessionStorage.getItem("solanaauth:nonce")) throw new Error("nonce nuk përputhet");
  const r = await api<{ token: string }>("POST", "/auth/google", { id_token: idToken });
  token.set(r.token);
  return true;
}

export const usd = (micro: number) => `$${(micro / 1e6).toFixed(micro !== 0 && Math.abs(micro) < 10_000 ? 4 : 2)}`;
