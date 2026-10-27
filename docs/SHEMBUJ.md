# Shembuj

Çdo shembull ka një test që e ekzekuton kundër programit të vërtetë (`solanaauth.so`) në LiteSVM,
në CI, me paymaster ON dhe OFF ku ka kuptim. Fillo me [`QUICKSTART.md`](QUICKSTART.md).

| Shembulli | Ku | Testi në CI |
|---|---|---|
| Lojë: sesion 24 orë, asnjë konfirmim | [`examples/game`](../examples/game) | 20 veprime pa konfirmim, ON dhe OFF; Memo refuzohet (`ProgramNotAllowed`) |
| Agjent AI me 20 USDC/ditë që paguan me x402 | [`examples/agent-x402`](../examples/agent-x402) | 4 × 5 USDC kalojnë; e 5-ta refuzohet lokalisht dhe on-chain (`0x21`); revokimi e ndalon (`0x1f`) |
| Wallet Standard (çdo dApp) | [`sdk/wallet-standard`](../sdk/wallet-standard) | legacy + v0, limit, nënshkrues i huaj, `signMessage` |
| Pagesë me USDC | më poshtë | e mbuluar nga testi x402 (e njëjta rrugë `transferChecked`) |
| Kush paguan tarifat: përdoruesi, serveri, Kora, paymaster-i | më poshtë | `services/platform/test/demo-paymaster.test.mjs` |

## Lojë (sesion 24 orë)

Përdoruesi hyn një herë; sesioni lejon vetëm programin e lojës, pa asnjë limit aseti (deny by
default: s'mund të nxjerrë asnjë SOL apo token), për 24 orë. Çdo lëvizje është një `execute` që
nënshkruhet nga çelësi i sesionit në shfletues, pa dritare konfirmimi.

```ts
const policy = { expiresIn: 24 * 3600, label: "loja", allowedPrograms: [GAME_PROGRAM_ID], limits: [] };
// ...pas hyrjes:
await execute([join(GAME_PROGRAM_ID, session.vault)]); // një herë
await execute([play(GAME_PROGRAM_ID, session.vault)]); // çdo lëvizje, pa konfirmim
```

Programi i lojës (`programs/demo-game`) sheh vault-in si lojtarin nënshkrues. Paymaster ON:
`VITE_USE_PAYMASTER=true`, `VITE_PLATFORM_URL`, `VITE_API_KEY`; OFF: çelësi i sesionit paguan.

```bash
cargo build-sbf --manifest-path programs/demo-game/Cargo.toml
solana program deploy programs/demo-game/target/deploy/demo_game.so --url devnet   # → VITE_GAME_PROGRAM_ID
npm run dev -w examples/game   # http://localhost:5176
```

## Pagesë me USDC

Për një checkout, sesioni lejon vetëm Token Program dhe një limit në USDC:

```ts
import { associatedTokenAddress, transferChecked } from "@solanaauth/agent"; // ose @solana/spl-token
const USDC = new PublicKey("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"); // USDC devnet (Circle)
const policy = {
  expiresIn: 3600, label: "checkout",
  allowedPrograms: [TOKEN_PROGRAM_ID],
  limits: [{ mint: USDC, amount: 50_000_000n, periodSecs: 3600 }], // ≤ 50 USDC
};
const from = associatedTokenAddress(session.vault, USDC);
const to = associatedTokenAddress(MERCHANT, USDC);
await execute([transferChecked(from, USDC, to, session.vault, 12_500_000n, 6)]); // 12.5 USDC
```

Programi mat rënien e çdo token account-i të vault-it pas CPI-së; mbi limit tx-i refuzohet me
`SpendLimitExceeded` dhe asgjë s'lëviz.

## Agjent AI me x402

Agjenti hyn një herë me Google përmes loopback (`127.0.0.1`), ruan vetëm çelësin e sesionit dhe
paguan API-të që kthejnë `402 Payment Required` (skema `exact` në Solana).

```ts
import { loginAgent, x402Fetch } from "@solanaauth/agent";
const { wallet } = await loginAgent({ config, provider: "google", clientId, policy: {
  expiresIn: 7 * 86400, label: "agjent",
  allowedPrograms: [TOKEN_PROGRAM_ID],
  limits: [{ mint: USDC, amount: 20_000_000n, periodSecs: 86400 }], // 20 USDC/ditë
}});
const res = await x402Fetch(wallet, "https://api.shembull.com/weather");
```

`x402Fetch` lexon kërkesat e pagesës, kontrollon limitin lokalisht (`PolicyError`), ndërton
`transferChecked` brenda `execute` me facilitator-in si fee payer (`extra.feePayer`), e nënshkruan
me çelësin e sesionit dhe e dërgon në `X-PAYMENT`. Facilitator-i demo
(`examples/agent-x402/facilitator.mjs`) e verifikon (vetëm `execute` + `transferChecked` te
`payTo`, shuma e saktë, fee payer-i s'përdoret askund tjetër), e nënshkruan dhe e dërgon.

```bash
cd examples/agent-x402
PROGRAM_ID=... PAY_TO=... FACILITATOR_KEYPAIR=~/.config/solana/devnet.json node server.mjs
PROGRAM_ID=... PLATFORM_URL=... API_KEY=... GOOGLE_CLIENT_ID=... node agent.mjs  # USE_PAYMASTER=true për ON
```

Prompt injection: agjenti s'ka asgjë përveç çelësit të sesionit; limiti dhe programet zbatohen
on-chain ([`SECURITY.md`](SECURITY.md#37-prompt-injection-te-agjentët)).

## Fee payer

Tx-i i `execute` ka dy nënshkrues: çelësi i sesionit (autoriteti) dhe fee payer-i. Fee payer-i s'ka
asnjë autoritet mbi portofolin; programi lejon vetëm vault-in si nënshkrues të instruksioneve të
brendshme (D25), kështu një fee payer s'mund të "huazojë" nënshkrimin e vet brenda `execute`.

```ts
import { SolanaAuth, paymasterFeePayer, appServerFeePayer, koraFeePayer } from "@solanaauth/core";

// 1. Përdoruesi (parazgjedhja): çelësi i sesionit paguan; duhet pak SOL.
new SolanaAuth({ ...config });
// 2. Paymaster-i i platformës (opsional, OFF si parazgjedhje).
new SolanaAuth({ ...config, apiKey, feePayer: await paymasterFeePayer(PLATFORM_URL, apiKey) });
// 3. Serveri yt: POST { transaction } → { signature }, i njëjti protokoll si paymaster-i.
new SolanaAuth({ ...config, feePayer: appServerFeePayer("https://api.app-im.com/sponsor", SERVER_PUBKEY) });
// 4. Kora (JSON-RPC): getPayerSigner + signAndSendTransaction.
new SolanaAuth({ ...config, feePayer: await koraFeePayer("http://localhost:8080") });
```

### Kora si fee payer

[Kora](https://github.com/solana-foundation/kora) nënshkruan si fee payer tx-at që kalojnë
validimin e tij. Për solanaauth mjafton të lejojë programin solanaauth dhe ComputeBudget, dhe të
ndalojë çdo përdorim të fee payer-it përtej tarifës. Një shembull konfigurimi (emrat e fushave
ndryshojnë midis versioneve të Kora-s; kontrollo dokumentimin e versionit që përdor):

```toml
[validation]
max_signatures = 3
allowed_programs = [
  "<SOLANAAUTH_PROGRAM_ID>",
  "ComputeBudget111111111111111111111111111111",
]

[validation.fee_payer_policy]
allow_sol_transfers = false
allow_spl_transfers = false
allow_assign = false
```

`create_wallet` dhe `open_session` kërkojnë rent (portofoli ~0.0038 SOL, sesioni ~0.0053 SOL,
[`MATJET.md`](MATJET.md)). Me një `feePayer` të konfiguruar, SDK-ja e vendos atë edhe si pagues të
rent-it të hyrjes (CPI `create_account` nga programi). Nëse politika e Kora-s nuk e lejon këtë,
hyrja bëhet me çelësin e sesionit si pagues (`completeLogin(jwt, pending, policy, sessionKey)` ose
`BrowserLogin` pa `feePayer` + `fundSessionKey`) dhe Kora përdoret vetëm për `execute`.
Paymaster-i i platformës e paguan edhe rent-in, brenda limitit `perUserDailyAccounts` (D27).
