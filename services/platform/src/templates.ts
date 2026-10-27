/**
 * Shabllonet e politikave (brief 4.4). Janë pikënisje: aplikacioni i përshtat dhe SDK-ja i dërgon
 * si `Policy`. Programet jepen me adresë; `{GAME_PROGRAM}` zëvendësohet nga aplikacioni.
 */
export interface PolicyTemplate {
  id: string;
  name: string;
  description: string;
  expiresIn: number;
  programs: string[];
  /** `mint`: "SOL", "USDC" ose adresë; `amount` në njësi bazë. */
  limits: { mint: string; amount: string; periodSecs: number }[];
}

export const SYSTEM = "11111111111111111111111111111111";
export const TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
export const MEMO = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

export const TEMPLATES: PolicyTemplate[] = [
  {
    id: "game",
    name: "Lojë",
    description: "Sesion 24 orë vetëm për programin e lojës; pa transferta.",
    expiresIn: 24 * 3600,
    programs: ["{GAME_PROGRAM}"],
    limits: [],
  },
  {
    id: "trading-agent",
    name: "Agjent trading",
    description: "7 ditë; vetëm programi i DEX-it dhe Token; limite ditore në USDC dhe SOL.",
    expiresIn: 7 * 86400,
    programs: ["{DEX_PROGRAM}", TOKEN],
    limits: [
      { mint: "USDC", amount: "100000000", periodSecs: 86400 },
      { mint: "SOL", amount: "500000000", periodSecs: 86400 },
    ],
  },
  {
    id: "x402-agent",
    name: "Agjent x402",
    description: "30 ditë; vetëm transferta USDC (Token + Memo); 20 USDC në ditë.",
    expiresIn: 30 * 86400,
    programs: [TOKEN, MEMO],
    limits: [{ mint: "USDC", amount: "20000000", periodSecs: 86400 }],
  },
  {
    id: "subscription",
    name: "Abonim",
    description: "30 ditë; një pagesë USDC në muaj deri në shumën e abonimit.",
    expiresIn: 30 * 86400,
    programs: [TOKEN],
    limits: [{ mint: "USDC", amount: "10000000", periodSecs: 30 * 86400 }],
  },
];
