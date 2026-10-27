# signMessage për portofolin PDA (SAA-1271)

Portofoli solanaauth është një PDA (vault-i). Një PDA s'ka çelës privat, prandaj s'mund të
nënshkruajë mesazhe me Ed25519 si një portofol i zakonshëm. Si ERC-1271 në Ethereum, nënshkrimi
bëhet nga një çelës që portofoli e ka autorizuar: **çelësi i sesionit**, dhe verifikuesi kontrollon
on-chain që sesioni i përket portofolit dhe është ende aktiv.

## Formati

```
signatureType = "solanaauth-session-v1"

msg = "solanaauth signed message v1\n"   (29 bytes UTF-8)
   || wallet                             (32 bytes, adresa e llogarisë Wallet)
   || session                            (32 bytes, adresa e llogarisë Session)
   || sha256(message)                    (32 bytes)

signature = Ed25519(session_key, msg)    (64 bytes)
```

Prefiksi e ndan këtë nënshkrim nga çdo transaksion Solana dhe nga `signMessage` i portofoleve të
tjera. `wallet` dhe `session` brenda mesazhit e lidhin nënshkrimin me një portofol dhe sesion të
caktuar: i njëjti çelës sesioni s'mund të riciklohet për një portofol tjetër.

Objekti që i kthehet dApp-it:

```json
{ "signatureType": "solanaauth-session-v1", "wallet": "<base58>", "session": "<base58>", "signature": "<64 bytes>" }
```

Adresa që sheh dApp-i (Wallet Standard `account.address`) është **vault-i**. Vault-i nxirret nga
`wallet` me PDA `["vault", wallet]`.

## Verifikimi

Verifikuesi (server ose dApp) bën këto hapa, në këtë rend:

1. Lexon llogarinë `session` nga zinxhiri. Pronari duhet të jetë programi solanaauth.
2. Dekodon `Session` (640 bytes) dhe kontrollon që `session` = PDA `["session", wallet, session_key]`.
   Vetëm programi krijon llogari `Session` në këtë adresë, prandaj kjo vërteton që sesioni është
   i portofolit.
3. `Session.wallet == wallet`, `!revoked`, `now < expires_at` (ora e zinxhirit kur ka rëndësi).
4. Verifikon `signature` me Ed25519 mbi `msg` me `session_key` nga llogaria.
5. Nëse duhet adresa e vault-it: `vault == PDA(["vault", wallet])`.

Nënshkrimi është i vlefshëm vetëm sa sesioni është aktiv. Për prova afatgjata (p.sh. një marrëveshje
e nënshkruar), verifikuesi ruan slot-in dhe gjendjen e sesionit në momentin e verifikimit.

## SDK

```ts
import { signMessage, verifySessionMessage } from "@solanaauth/core";

const message = new TextEncoder().encode("Hyr te shembull.com, nonce 42");
const sig = signMessage({ wallet, session, sessionKey }, message);
const r = await verifySessionMessage(connection, programId, sig, message);
if (!r.valid) throw new Error(r.reason);
```

Wallet Standard (`@solanaauth/wallet-standard`) e ekspozon përmes veçorisë
`"solanaauth:session"`. Nuk reklamon `solana:signMessage`, sepse vault-i nuk ka çelës Ed25519.
Rezultati përmban `signatureType: "solanaauth-session-v1"`, `wallet`, `session`,
`signature` dhe `signedMessage` (mesazhi origjinal). Integrimet ekzistuese duhet të kalojnë te:

```ts
const info = wallet.features["solanaauth:session"]?.getSession(); // { wallet, session, vault, expiresAt }
const [sig] = await wallet.features["solanaauth:session"].signMessage({ account, message });
```
 Një dApp që verifikon me
Ed25519 kundër `account.publicKey` (vault-i) do të dështojë; duhet të përdorë `verifySessionMessage`
ose hapat më sipër. Një mesazh SIWS kërkon po këtë verifikim të sesionit; integrimet që kërkojnë
vetëm nënshkrim Ed25519 nga vault-i nuk janë të pajtueshme.

## On-chain (opsionale, e planifikuar)

Një instruksion read-only `verify_message(wallet, session, msg_hash, sig)` që përdor precompile-in
Ed25519 dhe kthen `return_data = 1` do t'u lejojë programeve të tjera ta verifikojnë me CPI. Nuk
është në programin aktual; verifikimi off-chain më sipër mjafton për SIWS dhe autentikimin e dApp-eve.
