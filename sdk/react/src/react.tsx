import { TransactionInstruction } from "@solana/web3.js";
import { Session, SolanaAuth, SolanaAuthOptions } from "@solanaauth/core";
import { ReactNode, createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

import { BrowserLogin, BrowserLoginOptions, Provider } from "./login.js";

export type AuthStatus = "idle" | "redirecting" | "proving" | "ready" | "error";

export interface SolanaAuthState {
  status: AuthStatus;
  session: Session | null;
  /** `true` kur hyrja e fundit krijoi portofolin. */
  created: boolean;
  error: Error | null;
  login(provider: Provider): void;
  logout(onChain?: boolean): Promise<void>;
  /** Instruksione me vault-in si nënshkrues, brenda politikës së sesionit. */
  execute(instructions: TransactionInstruction[]): Promise<string>;
  auth: SolanaAuth;
}

const Ctx = createContext<SolanaAuthState | null>(null);

export interface SolanaAuthProviderProps extends BrowserLoginOptions {
  config: SolanaAuthOptions;
  children: ReactNode;
  /** Ku shkon përdoruesi pas kthimit (fragmenti me JWT-në fshihet nga historia). */
  onLogin?: (s: Session, created: boolean) => void;
}

export function SolanaAuthProvider({ config, children, onLogin, ...loginOpts }: SolanaAuthProviderProps) {
  const auth = useMemo(() => new SolanaAuth(config), [config]);
  const login = useMemo(() => new BrowserLogin(auth, loginOpts), [auth]); // eslint-disable-line react-hooks/exhaustive-deps
  const [session, setSession] = useState<Session | null>(() => (typeof window === "undefined" ? null : login.current()));
  const [status, setStatus] = useState<AuthStatus>(session ? "ready" : "idle");
  const [error, setError] = useState<Error | null>(null);
  const [created, setCreated] = useState(false);

  useEffect(() => {
    if (typeof window === "undefined" || !BrowserLogin.hasCallback(window.location.href)) return;
    const url = window.location.href;
    // JWT-ja nuk duhet të mbetet në histori.
    window.history.replaceState(null, "", window.location.pathname + window.location.search.replace(/[?&]id_token=[^&]*/, ""));
    setStatus("proving");
    login
      .finish(url)
      .then((r) => {
        setSession(r.session);
        setCreated(r.created);
        setStatus("ready");
        onLogin?.(r.session, r.created);
      })
      .catch((e: Error) => {
        setError(e);
        setStatus("error");
      });
  }, [login]); // eslint-disable-line react-hooks/exhaustive-deps

  const value = useMemo<SolanaAuthState>(
    () => ({
      status,
      session,
      created,
      error,
      auth,
      login(provider) {
        try {
          const url = login.start(provider);
          setStatus("redirecting");
          window.location.assign(url);
        } catch (e) {
          setError(e as Error);
          setStatus("error");
        }
      },
      async logout(onChain = true) {
        await login.logout(onChain);
        setSession(null);
        setStatus("idle");
      },
      async execute(instructions) {
        if (!session) throw new Error("pa sesion");
        return auth.execute(session, instructions);
      },
    }),
    [status, session, created, error, auth, login],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useSolanaAuth(): SolanaAuthState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useSolanaAuth duhet brenda <SolanaAuthProvider>");
  return v;
}

/** Bilanci i vault-it në lamports, rifreskohet çdo `intervalMs`. */
export function useVaultBalance(intervalMs = 10_000): bigint | null {
  const { session, auth } = useSolanaAuth();
  const [bal, setBal] = useState<bigint | null>(null);
  const load = useCallback(async () => {
    if (session) setBal(BigInt(await auth.connection.getBalance(session.vault)));
  }, [session, auth]);
  useEffect(() => {
    load().catch(() => null);
    const t = setInterval(() => load().catch(() => null), intervalMs);
    return () => clearInterval(t);
  }, [load, intervalMs]);
  return bal;
}
