# Produkti i plotë: solanaauth SDK

Brief-i për developer-in pas Hapit 1 (GO, 110,428 CU, shih [`HAPI-1-RAPORT.md`](HAPI-1-RAPORT.md) te PR #1).
Ky dokument përshkruan **gjithë produktin** që duhet ndërtuar: **të gjitha etapat M0–M6, pa ndalesë**.
Në fund, ne bëjmë testin e pranimit (seksioni i fundit). Puna shkon në `main`, me CI jeshile.

## 1. Çfarë po ndërtojmë

Një **SDK për kompanitë** (lojëra, aplikacione pagesash, platforma agjentësh AI) që u jep
përdoruesve të tyre një portofol Solana vetë-kujdestar me **"Hyr me Google / Apple"**, pa frazë
sekrete, ku:

- prova zkLogin (Groth16) verifikohet **on-chain** nga programi ynë;
- përdoruesi (ose agjenti i tij) vepron me **sesione me politika** që i zbaton programi on-chain
  (programet e lejuara, limite shpenzimi, skadim, anulim), sipas modelit të access keys të NEAR;
- **passkey** është faktori i dytë dhe rruga e rikuperimit;
- **paymaster-i është opsional**: çdo aplikacion zgjedh nëse e aktivizon.

### Vendime të marra (mos i ndrysho pa folur më parë)

| Vendimi | Përmbajtja |
|---|---|
| Lloji i produktit | **SDK + shërbime të hostuara**, jo portofol konsumatori. Plus një faqe e thjeshtë portofoli vetëm për rikuperim/tërheqje. |
| Kujdestaria | **Ne nuk mbajmë kurrë** çelësa privatë, pjesë çelësash apo fonde të përdoruesve. |
| Politikat | Zbatohen **në programin on-chain**. SDK-ja vetëm i krijon dhe i shfaq. |
| Fee payer | I konfigurueshëm: përdoruesi, serveri i aplikacionit, Kora, ose paymaster-i ynë (opsional). |
| Fee për transaksion | **Nuk** marrim fee nga transaksionet e përdoruesve. Paguhemi nga aplikacionet (plane sipas MAU / agjentëve aktivë) dhe nga marzhi i paymaster-it vetëm kur aplikacioni e aktivizon. |
| Open source | Programi on-chain, SDK-ja dhe prover-i janë open source (Apache-2.0); kushdo mund t'i hostojë vetë. |
| Matjet | Të vetmet numra që pranojmë janë ato të CI-së (GitHub Actions), të publikuara në `results/`. |

### Jashtë fushës tani

Portofol konsumatori i plotë, aplikacion mobile i yni, mainnet për klientë para auditimit,
zinxhirë të tjerë.

## 2. Arkitektura

```text
 Aplikacioni i klientit
   └── @solanaauth/sdk  ── login (Google/Apple) ──► Prover (i yni ose self-host)
          │                                           │ provë Groth16
          ▼                                           ▼
   Transaksion ────────────────► Programi on-chain `solanaauth`
     (fee payer: user / app / Kora / paymaster)
                                   ├── JWK registry   (çelësat e Google/Apple, multisig + timelock)
                                   ├── Wallet PDA     (fondet, autoritetet: zk identity + passkeys)
                                   └── Session PDA    (çelësi ephemeral + politikat)
   Shërbimet e hostuara (opsionale për klientin):
     Prover · Salt · Paymaster · Dashboard (aplikacione, API keys, politika, përdorim, faturim)
```

## 3. Programi on-chain

Bazohet te `zklogin-verifier` i Hapit 1. Një program, me këto pjesë:

### 3.1 JWK registry (prioriteti i sigurisë)
- Llogari për çdo `(iss, kid)` → hash i modulus-it, numri i bit-eve, `valid_from`, `valid_until`.
- Përditësohet nga një **multisig (Squads) + timelock**. Një bot (oracle) lexon JWKS e Google/Apple
  dhe propozon ndryshimet; çelësat e vjetër mbeten të vlefshëm deri në skadim.
- `verify_full` **pranon vetëm** modulus-e nga registry-ja. Sot programi pranon çdo çelës RSA; kjo
  është mbyllja e parë që duhet bërë.

### 3.2 Wallet PDA
- Adresa e portofolit duhet të jetë **e qëndrueshme** edhe nëse ndryshon salt-i apo passkey-ja.
  Rekomandim: wallet PDA me seed të qëndrueshëm, me një listë **autoritetesh të rrotullueshme**:
  - identiteti zkLogin (commitment nga `iss`, `aud`, `address_seed`);
  - 1+ passkey (secp256r1).
- Ekzekuton veprime me `invoke_signed` **vetëm** pasi kalojnë kontrollin e sesionit dhe politikave.
- Instruksione: `create_wallet`, `execute`, `add_authority`, `remove_authority`, `recover`.

### 3.3 Session PDA dhe politikat
- `open_session` = `verify_full` + krijimi i sesionit në një transaksion (buxheti ~120k CU).
- Sesioni ruan: `ephemeral_pubkey`, `expires_at`, `allowed_programs`,
  `spend_limits [{ mint, amount, period }]`, `max_fee`, `revoked`, `label` (p.sh. "agjenti X").
- `execute` me çelësin e sesionit: kontrollon nënshkrimin Ed25519, skadimin, `revoked`, që çdo
  CPI shkon te një program i lejuar, dhe **limitet e shpenzimit duke matur ndryshimin e bilancit
  para/pas CPI-së**, jo duke interpretuar instruksionet.
- `revoke_session` (nga përdoruesi, me Google ose passkey) dhe `close_session` (kthen rent-in).
- Disa sesione njëkohësisht (p.sh. një për lojën, një për çdo agjent).
- Veprimet mbi një prag (p.sh. tërheqje e madhe, ndryshim autoritetesh) kërkojnë **edhe passkey**.

### 3.4 Skadimi
Përcakto si lidhet `max_epoch` i qarkut me kohën e Solana-s (timestamp ose slot i koduar në nonce).
Zgjidhe, dokumentoje te `docs/DIZAJNI.md` dhe vazhdo.

### 3.5 Rikuperimi
- Humbi passkey-n → hyn me Google, shton passkey të re pas një **timelock** (p.sh. 48 orë), me
  njoftim; një passkey ekzistuese mund ta anulojë.
- Humbi aksesin në Google ose salt-in → me passkey rrotullon identitetin zkLogin.

### 3.6 Forcimi
- VK mainnet i fiksuar në prodhim (pa `vk_id` që e zgjedh thirrësi); VK test vetëm në build devnet.
- `groth16-solana` i pin-uar në një rev; varësitë e kontrolluara.
- Upgrade authority: multisig + timelock; plan për ta bërë immutable pas auditimit.
- Kontrollo licencën e qarqeve dhe key-ve të zkLogin para mainnet-it.

## 4. Shërbimet off-chain

### 4.1 Prover
- Prover-i i Mysten (Docker, zkey `zkLogin-main`) i hostuar nga ne, me API key, rate limit, metrika.
- Dokumentim për self-host nga klienti.
- **Mat në CI** kohën e gjenerimit të provës dhe kostot e serverit (na duhen për çmimet).

### 4.2 Salt
- v1: shërbim salt i hostuar (HKDF nga një master seed, me backup), sepse adresa nuk varet më vetëm
  nga salt-i (3.2), humbja e tij nuk e bllokon portofolin.
- Opsion: salt nga passkey (WebAuthn PRF) për klientët që nuk duan shërbimin tonë.

### 4.3 Paymaster (opsional, OFF si parazgjedhje)
- Aplikacioni e aktivizon nga dashboard-i. Nëse s'e aktivizon, nuk ndryshon asgjë.
- **Depozitë paraprake** (SOL ose USDC) për çdo aplikacion; ne nuk japim kredi.
- Për çdo transaksion: kostoja reale (base + priority fee) + marzh i konfigurueshëm
  (parazgjedhje **$0.0002**), merret nga depozita.
- Mbrojtje nga abuzimi: vetëm programet që lejon aplikacioni, limit për përdorues/ditë, limit
  global, ndalim automatik kur depozita mbaron, alarm kur bie nën prag.
- Alternativa pa ne: dokumentim + shembull me **Kora** ose me serverin e aplikacionit si fee payer.

### 4.4 Dashboard
- Regjistrimi i aplikacionit, OAuth client IDs (Google/Apple), API keys.
- Shabllone politikash (lojë, agjent trading, agjent x402, abonim).
- Përdorimi: MAU, agjentë aktivë, prova, transaksione të paymaster-it.
- Paymaster: aktivizim, depozitë, historik, limite.
- Faturimi: Stripe (kartë) dhe USDC në Solana. **Çmimet si konfigurim, jo në kod**:

| Plani | Çmimi | Përfshin | Mbi kuotë |
|---|---|---|---|
| Falas | $0 | devnet pa limit; 1,000 MAU; 5,000 tx paymaster | — |
| Starter | $49/muaj | 5,000 MAU; 25,000 tx paymaster | $0.03/MAU |
| Growth | $199/muaj | 25,000 MAU; 150,000 tx paymaster | $0.02/MAU |
| Enterprise | marrëveshje | prover i dedikuar, SLA | marrëveshje |
| Agjentë | — | — | $0.05–0.10 për agjent aktiv/muaj mbi kuotë |

### 4.5 Faqja e portofolit (rikuperim, pa lock-in)
Hyrje me Google/Apple ose passkey → sheh asetet, tërheq, anulon sesionet, menaxhon passkey-t.
Funksionon edhe nëse aplikacioni që e krijoi portofolin mbyllet.

## 5. SDK

- `@solanaauth/sdk` (TypeScript, browser + Node):
  - `login({ provider: 'google' | 'apple' })`, `getWallet()`
  - `createSession({ programs, spendLimits, expiresIn, label })`, `listSessions()`, `revoke(id)`
  - `execute(instructions, { feePayer: 'user' | 'app' | 'kora' | 'paymaster' })`
  - `addPasskey()`, `recover()`
- `@solanaauth/react`: provider, hooks, butoni "Hyr me Google/Apple".
- `@solanaauth/agent` (Node): agjenti mban vetëm çelësin e sesionit; `fromSession(...)`, `execute(...)`.
- Adapter për Solana Wallet Standard, që dApp-et ekzistuese ta përdorin pa ndryshime.
- **Pyetje e hapur:** `signMessage` për PDA (si ERC-1271). Propozo zgjidhjen; mund të bëhet standard publik.
- Dokumentim: quickstart 10-minutësh, shembuj për lojë, pagesë, agjent x402, fee payer me Kora.

## 6. Demo

1. **Lojë e thjeshtë** në devnet: hyrje me Google, sesion 24h vetëm për programin e lojës, pa konfirmime.
2. **Agjent AI** me limit 20 USDC/ditë që paguan me x402; demonstron refuzimin kur kalon limitin.
3. Të dyja me OAuth client-in tonë, me paymaster ON dhe OFF.

## 7. Matjet (CI, të publikuara në `results/`)

- CU dhe bytes për: `open_session`, `execute` (me dhe pa kontrollin e limiteve), `revoke_session`,
  `recover`, instruksionet e registry-së.
- Madhësia e PDA-ve dhe rent-i.
- Koha e gjenerimit të provës (p50/p95) dhe kostoja e prover-it për MAU.
- Testet negative: çdo shkelje politike, sesion i skaduar/i anuluar, JWK jashtë registry-së,
  autoritet i gabuar, depozitë paymaster e mbaruar.
- Teste E2E në devnet në çdo push në `main` (puna `devnet`).

## 8. Siguria

- `docs/SECURITY.md`: modeli i kërcënimeve (JWK registry, upgrade authority, prover, salt, paymaster,
  çelësat e sesionit, prompt injection te agjentët) dhe si mbrohet secili.
- Fuzz/property tests për parsimin e input-eve dhe kontrollin e politikave.
- Asnjë çelës mainnet në repo apo në Secrets. Secrets vetëm për devnet.
- Kodi gati për auditim: invariante të dokumentuara, `unsafe` i justifikuar, varësi të pin-uara.

## 9. Etapat (të gjitha bëhen, njëra pas tjetrës, pa pritur miratim)

| Etapa | Përmbajtja | Pranohet kur |
|---|---|---|
| **M0** | Merge PR #1, devnet i Hapit 1 | Nënshkrimet devnet në raport |
| **M1** | `docs/DIZAJNI.md`: PDA-t, registry-ja, skadimi, rikuperimi, `signMessage` | Dokumenti në `main`; vazhdo menjëherë me M2 |
| **M2** | JWK registry + wallet PDA + `open_session` + `execute` me politika | Teste + CU në CI |
| **M3** | Passkey, rikuperimi, revoke, veprimet mbi prag | Teste negative të plota |
| **M4** | Prover + salt të hostuar, SDK (core, react, agent) | Quickstart funksionon në devnet |
| **M5** | Paymaster opsional + dashboard + faturimi + faqja e portofolit | Demo me paymaster ON/OFF |
| **M6** | Demot, dokumentimi, `SECURITY.md`, gati për auditim | Testi ynë i pranimit (më poshtë) |

Pas çdo etape: commit/PR në `main` me CI jeshile dhe një përmbledhje e shkurtër (çfarë u bë, numrat nga CI).
Nëse diçka bllokon, zgjidh opsionin më të sigurt, shënoje te `docs/DIZAJNI.md` dhe vazhdo.

## 10. Testi ynë i pranimit (në fund)

Ne e kalojmë vetë këtë listë në devnet, pa ndihmë:

- [ ] Integroj SDK-në në një aplikacion të ri me quickstart-in në më pak se 30 minuta.
- [ ] Hyrje me Google dhe me Apple → portofol i krijuar, pa frazë, pa SOL te përdoruesi (paymaster ON).
- [ ] E njëjta gjë me paymaster OFF dhe fee payer me Kora / serverin e aplikacionit.
- [ ] Sesion loje: 20 veprime pa asnjë konfirmim; një veprim te një program jo i lejuar refuzohet.
- [ ] Agjent me limit ditor: paguan brenda limitit, refuzohet mbi të; anulimi e ndalon menjëherë.
- [ ] Shtoj passkey; tërheqja mbi prag kërkon passkey.
- [ ] Rikuperim: humbas passkey-n → rikuperoj me Google pas timelock-ut; dhe e kundërta.
- [ ] Faqja e portofolit: shoh asetet dhe tërheq pa aplikacionin origjinal.
- [ ] JWK i rremë / modulus jashtë registry-së refuzohet.
- [ ] Paymaster: depozita zbret saktë (kosto + marzh); ndalon kur mbaron; limitet për përdorues punojnë.
- [ ] Dashboard: MAU, agjentët dhe transaksionet përputhen me ato on-chain; fatura e saktë.
- [ ] Të gjitha matjet janë në `results/` nga CI dhe përputhen me ato që shohim.
- [ ] Self-host: prover-i dhe programi ngrihen nga dokumentimi pa shërbimet tona.
