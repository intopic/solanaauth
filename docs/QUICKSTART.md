# Quickstart: "Hyr me Google" → portofol Solana, në 10 minuta (devnet)

Në fund ke një faqe React ku përdoruesi hyn me Google, merr një portofol vetë-kujdestar (PDA, pa
frazë) dhe dërgon SOL brenda limitit të sesionit, pa asnjë dritare konfirmimi.

Paketat ende s'janë në npm; quickstart-i punon nga ky repo (npm workspaces). Kërkon Node 20+.

## 1. Merr kodin (1 min)

```bash
git clone https://github.com/intopic/solanaauth && cd solanaauth
npm ci
npm run build -w sdk/core -w sdk/react -w services/salt
```

## 2. Google OAuth client ID (3 min)

Google Cloud Console → APIs & Services → Credentials → **Create credentials → OAuth client ID** →
Web application. Shto `http://localhost:5173` si *Authorized JavaScript origin* dhe si
*Authorized redirect URI*. Kopjo Client ID.

## 3. Program ID në devnet (1 min)

Programi i devnet-it dhe `config`-u i tij janë te [`results/devnet-solanaauth.md`](../results/)
në `main` (i publikuar nga CI). Nëse s'është aty ende, deploy-oje vetë me një çelës devnet:
[`SELF-HOST.md`](SELF-HOST.md#programi).

## 4. Salt dhe prover (2 min)

```bash
# Salt-i: 32 bytes rastësorë. Ruaje: humbja e tij ndryshon identitetin zk (DIZAJNI D18).
SALT_MASTER_SEED=$(openssl rand -hex 32) ALLOWED_AUDIENCES=<CLIENT_ID> PORT=8787 npm start -w services/salt
```

Për prover-in ke dy rrugë:

- **E shpejtë (vetëm devnet):** prover-i dev i Mysten, `https://prover-dev.mystenlabs.com/v1`, me
  `VITE_VK_TEST=true`. Prova verifikohet me verifying key-n test, që programi e pranon vetëm kur
  `config.allow_test_vk = true` (devnet, D20).
- **E plotë:** prover-i yt me zkey-n e ceremonisë, ~16 GB RAM:
  `cd services/prover && ./fetch-zkey.sh && ALLOWED_AUDIENCES=<CLIENT_ID> docker compose up -d`.

## 5. Nis aplikacionin (2 min)

```bash
cp examples/quickstart/.env.example examples/quickstart/.env.local
# plotëso VITE_PROGRAM_ID, VITE_GOOGLE_CLIENT_ID, VITE_PROVER_URL, VITE_VK_TEST, VITE_SALT_URL=http://localhost:8787/salt
npm run dev -w examples/quickstart
```

Hap `http://localhost:5173` → **Hyr me Google**. Herën e parë krijohet portofoli; dërgo pak SOL
devnet te adresa e vault-it që shfaqet dhe provo një transfertë. Mbi 0.5 SOL në ditë programi e
refuzon me `SpendLimitExceeded`.

## Kodi që të duhet në aplikacionin tënd

```tsx
import { SolanaAuthProvider, useSolanaAuth } from "@solanaauth/react";
import { SYSTEM_PROGRAM_ID, solLimit } from "@solanaauth/core";

const policy = {
  expiresIn: 24 * 3600,                       // sesioni zgjat 24 orë
  label: "aplikacioni-im",
  allowedPrograms: [SYSTEM_PROGRAM_ID],       // vetëm këto programe
  limits: [solLimit(500_000_000n, 24 * 3600)] // 0.5 SOL në ditë
};

<SolanaAuthProvider config={{ connection, programId, proverUrl, saltUrl }}
  clientIds={{ google: GOOGLE_CLIENT_ID }} redirectUri={location.origin} policy={policy}>
  <App />
</SolanaAuthProvider>

function App() {
  const { session, login, execute } = useSolanaAuth();
  if (!session) return <button onClick={() => login("google")}>Hyr me Google</button>;
  return <button onClick={() => execute([transferIx(session.vault)])}>Dërgo</button>;
}
```

`execute` mbështjell instruksionet në `execute` të programit; vault-i (`session.vault`) është
adresa e përdoruesit dhe nënshkruesi i instruksioneve të tua.

## Hapat e mëtejshëm

- Kush paguan tarifat (përdoruesi, serveri yt, Kora, paymaster-i): [`SHEMBUJ.md`](SHEMBUJ.md#fee-payer)
- Lojë, pagesa, agjent x402: [`SHEMBUJ.md`](SHEMBUJ.md)
- Wallet Standard dhe `signMessage`: [`SIGN-MESSAGE.md`](SIGN-MESSAGE.md)
- Siguria dhe kufizimet: [`SECURITY.md`](SECURITY.md)
