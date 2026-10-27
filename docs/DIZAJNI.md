# Dizajni i programit `solanaauth` (M1)

Ky dokument fikson vendimet teknike për M2–M6. Bazohet te Hapi 1
([`HAPI-1-RAPORT.md`](HAPI-1-RAPORT.md): `verify_full` = 110,428 CU) dhe te
[`PRODUKTI-BRIEF.md`](PRODUKTI-BRIEF.md). Kur një vendim ndryshon, ndryshohet këtu në të njëjtin PR
me kodin. Seksioni i fundit ("Regjistri i vendimeve") mban çdo zgjedhje të bërë gjatë punës.

## 1. Përmbledhje

Një program i vetëm native (pinocchio, pa Anchor), `programs/solanaauth`, që përmban:

| Pjesa | Llogaria (PDA) | Kush e ndryshon |
|---|---|---|
| Konfigurimi global | `["config"]` | `admin` (Squads vault + timelock) |
| JWK registry | `["jwk", sha256(iss), sha256(kid)]` | propozim nga `admin`/oracle, aplikim pas timelock |
| Portofoli | `["wallet", wallet_id]` | autoritetet e portofolit |
| Vault-i (fondet) | `["vault", wallet]` (pa të dhëna, i sistemit) | vetëm programi me `invoke_signed` |
| Sesioni | `["session", wallet, session_key]` | autoritetet / vetë sesioni (vetëm `close`) |

Verifikuesi zkLogin i Hapit 1 (`zklogin-verifier`) bëhet librari (`no-entrypoint`) dhe përdoret nga
`solanaauth`. Programi i vjetër mbetet për matjet krahasuese.

## 2. Identiteti zkLogin dhe JWK registry

### 2.1 Çfarë lidh prova

Qarku v1 lidh në `all_inputs_hash`: `eph_pubkey`, `address_seed`, `max_epoch`, `iss` (copa base64 e
claim-it), `index_mod_4`, `header` dhe hash-in e modulus-it RSA. `address_seed` =
`Poseidon(H(sub), H(aud), Poseidon(salt))`, pra lidh përdoruesin (`sub`), aplikacionin (`aud`) dhe salt-in.

### 2.2 Identiteti

```
zk_identity = sha256("solanaauth:zk:v1" || iss || address_seed)
```

`iss` është vlera e dekoduar (`https://accounts.google.com`). Programi e dekodon on-chain copën
base64 (me `index_mod_4`) dhe nxjerr vlerën e `"iss":"..."`. Kjo e lidh identitetin me lëshuesin;
`aud` dhe `sub` janë brenda `address_seed`.

### 2.3 JWK registry

```
Jwk { iss_hash: [32], kid_hash: [32], modulus_hash: Fe, modulus_bits: u16,
      valid_from: i64, valid_until: i64, pending: Option<PendingJwk>, bump }
```

- `verify_full` merr hash-in e modulus-it **vetëm** nga llogaria JWK (modulus-i nuk kalon më në
  instruksion). Programi kontrollon: llogaria është PDA e saktë dhe në pronësi të programit,
  `sha256(iss) == iss_hash`, `valid_from <= now < valid_until`.
- `kid` nuk përdoret në verifikim: modulus-i vetë identifikon çelësin. `kid` shërben për
  menaxhim dhe për gjetjen e llogarisë nga klienti (header-i i JWT-së).
- Ndryshimet: `propose_jwk` (nga `config.admin` ose `config.oracle`) → `pending` me
  `eta = now + config.timelock`; `apply_jwk` (kushdo, pas `eta`); `revoke_jwk` (vetëm `admin`,
  menjëherë: emergjencë). Çelësat e vjetër mbeten të vlefshëm deri në `valid_until`.
- Në devnet `admin` është një keypair testi; në mainnet është vault-i i një multisig Squads.
  Bot-i oracle (`services/jwk-oracle`) lexon JWKS e Google/Apple dhe thërret `propose_jwk`.

### 2.4 Verifying key

- Build-i mainnet (feature `mainnet`) ka vetëm key-n `zkLogin-main`; instruksionet nuk kanë `vk_id`.
- Build-i devnet (parazgjedhja në CI) pranon edhe `zkLogin-test` përmes `config.allow_test_vk`,
  sepse prover-dev i Mysten përdor key-n test.

## 3. Skadimi (`max_epoch`) — vendim

**`max_epoch` = koha e skadimit në sekonda Unix (UTC).** Klienti e fut në nonce-in e JWT-së si çdo
klient zkLogin (`nonce = Poseidon(eph_pk_0, eph_pk_1, max_epoch, randomness)`), dhe programi kontrollon
`Clock::unix_timestamp < max_epoch`.

- Arsyeja: Solana ka `unix_timestamp` të besueshëm në `Clock`; slot-et nuk kanë kohëzgjatje fikse.
- `expires_at` i sesionit = `min(max_epoch, now + policy.expires_in)`; programi refuzon
  `max_epoch > now + 30 ditë` (`config.max_session_secs`).
- Prover-i i Mysten nuk e interpreton `max_epoch`, pra funksionon pa ndryshime.

## 4. Portofoli

```
Wallet { version, bump, vault_bump, wallet_id: [32], created_at: i64, nonce: u64,
         zk: [ZkAuthority; 2], passkeys: [Passkey; 4],
         threshold_lamports: u64, recovery: Option<Recovery>, session_count: u32 }
ZkAuthority { identity: [32], added_at: i64 }          // identity == 0 → bosh
Passkey     { pubkey: [u8; 33] (secp256r1, i ngjeshur), added_at: i64 }
```

- **Adresa e qëndrueshme.** `wallet_id = sha256("solanaauth:wallet:v1" || zk_identity_fillestar)`.
  Seed-i nuk ndryshon kurrë, edhe kur rrotullohen autoritetet (salt i ri, passkey i ri). Adresa që
  i tregohet përdoruesit për depozita është **vault-i** (`["vault", wallet]`).
- **Vault-i** nuk ka të dhëna dhe është në pronësi të System Program, që të mund të dërgojë SOL me
  `system::transfer` + `invoke_signed`. Token-at mbahen në ATA-t e vault-it.
- `create_wallet` = `verify_full` + krijimi i `Wallet` me autoritetin e parë zk. Mund të bashkohet me
  `open_session` në të njëjtin instruksion (`create_wallet_with_session`) për hyrjen e parë.

## 5. Sesionet dhe politikat

```
Session { wallet, session_key: [32], created_at, expires_at, revoked: bool, label: [u8; 32],
          allowed_programs: [Pubkey; 8] (n), spend_limits: [SpendLimit; 4] (n), max_fee: u64, bump }
SpendLimit { mint: Pubkey (default = SOL), amount: u64, period_secs: u32,
             window_start: i64, spent: u64 }
```

### 5.1 `open_session`
`verify_full` (me JWK nga registry) + kontrolli që `zk_identity` është autoritet i portofolit +
krijimi i `Session`. `session_key` = `eph_pubkey` i provës dhe **duhet të nënshkruajë transaksionin**,
kështu nuk ka nevojë për precompile Ed25519: runtime-i e verifikon nënshkrimin falas.

### 5.2 `execute`
Nënshkruhet nga `session_key`. Programi:
1. kontrollon `!revoked`, `now < expires_at`, nënshkruesin;
2. për çdo instruksion të brendshëm: programi ∈ `allowed_programs`; asnjë instruksion te
   `solanaauth`, te loader-at BPF apo te programet e ndaluara (lista fikse);
   `Wallet` dhe `Session` nuk kalojnë kurrë si llogari të shkrueshme;
3. **para** CPI-ve mat: lamport-et e vault-it dhe `amount` të çdo token account të shkrueshëm me
   `owner == vault`;
4. ekzekuton CPI-të me `invoke_signed(["vault", wallet, bump])`;
5. **pas** CPI-ve kontrollon invariantet:
   - vault-i ende në pronësi të System Program, pa të dhëna (kundër `assign`/`allocate`);
   - çdo token account i vault-it i matur: ende `owner == vault`, pa `delegate`, pa `close_authority`
     (kundër `Approve` / `SetAuthority`), ose i mbyllur vetëm nëse bilanci ishte 0;
   - rënia e bilancit për çdo aset ≤ hapësira e mbetur e limitit; asetet pa limit **nuk mund të
     zbresin** (deny by default). Dritarja rifillon kur `now >= window_start + period_secs`.
6. përditëson `spent`.

Kjo është "matja e ndryshimit të bilancit para/pas CPI-së" e brief-it: programi nuk interpreton
instruksionet e programeve të tjera.

### 5.3 Revokimi dhe mbyllja
- `revoke_session`: me një autoritet të portofolit (provë zk e re **ose** passkey). Efekt i menjëhershëm.
- `close_session`: kushdo pasi sesioni skadon ose revokohet; rent-i kthehet te vault-i.
- Disa sesione njëkohësisht: çdo `session_key` ka PDA-në e vet.

### 5.4 Madhësia e transaksionit
`open_session` me provë (256 B) + input-e (~220 B) + politikë (≤ 4 programe, ≤ 2 limite) mbetet
nën 1232 bytes. Politikat më të mëdha shtohen me `update_session_policy` (vetëm ngushtim) ose me
Address Lookup Tables. Numrat e saktë dalin në `results/`.

## 6. Passkey dhe veprimet mbi prag (M3)

- Verifikimi me **precompile-in secp256r1** (SIMD-0075): instruksioni i precompile-it në të njëjtin
  transaksion; programi lexon sysvar-in `Instructions` dhe kontrollon që çelësi publik është në
  `wallet.passkeys` dhe që mesazhi është
  `sha256("solanaauth:passkey:v1" || wallet || nonce || action_hash)`. `nonce` rritet pas çdo veprimi
  (kundër replay).
- Formati WebAuthn: mesazhi i nënshkruar nga shfletuesi është
  `authenticatorData || sha256(clientDataJSON)`; programi kontrollon që `challenge` në
  `clientDataJSON` = mesazhi i mësipërm (base64url).
- **Veprimet mbi prag** (kërkojnë passkey përveç sesionit/zk): `execute` kur daljet e SOL brenda
  24 orëve kalojnë `threshold_lamports` (D14), shtimi/heqja e passkey-ve, ndryshimi i pragut.
  Nëse portofoli nuk ka passkey, pragu nuk vlen (përdoruesi paralajmërohet nga SDK-ja).
- **Implementimi (M3):** precompile-i duhet të jetë instruksioni menjëherë para instruksionit
  tonë, me 1 nënshkrim dhe me të gjitha të dhënat brenda vetes. `action_hash =
  sha256(op || bytes para bllokut passkey || bytes pas tij || adresat e llogarive pa sysvar-in)`;
  kështu nënshkrimi lidh çdo byte të instruksionit dhe çdo llogari. Instruksionet: `add_passkey`
  (11), `remove_passkey` (12), `set_threshold` (13), `revoke_session` mode 2, `execute` me flag-un 1.
  Faktori zk shton passkey direkt vetëm kur portofoli s'ka asnjë passkey.

## 7. Rikuperimi (M3)

| Situata | Rruga | Timelock | Kush e anulon |
|---|---|---|---|
| Humbi passkey-n | provë zk → `begin_recovery(add passkey P')` | 48 orë (`config.recovery_delay`) | çdo passkey ekzistuese |
| Humbi Google / salt-in | passkey → `begin_recovery(add zk identity Z')` | 48 orë | çdo autoritet zk ekzistues |
| Pas timelock-ut | `finish_recovery` (kushdo) | — | — |

Implementimi (M3): `begin_recovery` (14) me `kind` 1 (zk → shto/zëvendëso passkey në slot) ose 2
(passkey + provë e identitetit të ri → shto/zëvendëso identitet zk në slot), `cancel_recovery` (15)
me çdo autoritet ekzistues (zk ose passkey), `finish_recovery` (16). Vetëm një rikuperim në pritje
njëherësh; programi log-on `solanaauth: RecoveryStarted`.

Gjatë një rikuperimi në pritje, sesionet ekzistuese mbeten aktive (përdoruesi mund t'i revokojë).
Njoftimi: SDK-ja/dashboard-i dëgjon event-in `RecoveryStarted` (log) dhe dërgon email.

## 8. `signMessage` për portofolin PDA (pyetja e hapur)

Propozimi **SAA-1271** (si ERC-1271):
1. Sesioni nënshkruan me Ed25519:
   `"solanaauth signed message v1\n" || wallet || session || sha256(message)`.
2. Verifikuesi off-chain lexon `Session`, kontrollon që `wallet` përputhet, `!revoked`,
   `now < expires_at`, dhe verifikon nënshkrimin me `session_key`.
3. Opsionalisht on-chain: instruksioni read-only `verify_message(wallet, session, msg_hash, sig)` që
   përdor precompile-in Ed25519 dhe kthen `return_data = 1`; programet e tjera e thërrasin me CPI.
4. Format i publikuar te `docs/SIGN-MESSAGE.md`; Wallet Standard adapter-i e ekspozon si
   `signMessage` dhe shton `signatureType: "solanaauth-session-v1"`.

## 9. Kërcënimet kryesore (detajet te `SECURITY.md`, M6)

- JWK i rremë → vetëm registry me timelock; revokim emergjent.
- Upgrade authority → multisig + timelock; immutable pas auditimit.
- Çelësi i sesionit i vjedhur → i kufizuar nga politika, skadim, revokim i menjëhershëm.
- Prompt injection te agjenti → agjenti ka vetëm çelësin e sesionit; limitet on-chain.
- Prover-i → nuk mban sekrete; prova pa JWT të vlefshme nuk ekziston. Salt-i → nuk jep akses pa JWT.

## 10. Regjistri i vendimeve

| # | Vendimi | Arsyeja |
|---|---|---|
| D1 | Program native me pinocchio, jo Anchor | CU më të ulët, vazhdimësi me Hapin 1, varësi minimale |
| D2 | `max_epoch` = timestamp Unix | `Clock` i besueshëm; s'ka nevojë për epoka të Sui-t |
| D3 | `session_key` nënshkruan tx-in | verifikim Ed25519 falas nga runtime-i |
| D4 | Vault pa të dhëna, i ndarë nga `Wallet` | `system::transfer` kërkon `from` pa të dhëna |
| D5 | Deny by default për asetet pa limit | më e sigurta: sesioni s'mund të nxjerrë asgjë që s'është lejuar shprehimisht |
| D6 | `kid` vetëm për menaxhim | modulus-i identifikon çelësin; shmang parsimin e header-it on-chain |
| D7 | Timelock 48h në të dy drejtimet e rikuperimit | një faktor i vjedhur s'mund ta marrë portofolin pa dijeninë e tjetrit |
| D8 | Programi i Hapit 1 mbetet; `solanaauth` e përdor si librari | matjet krahasuese mbeten të riprodhueshme |
| D9 | `max_fee` i politikës rezervohet; në M2 duhet të jetë 0 | pagesa e tarifave nga vault-i vjen me paymaster-in (M5); deri atëherë asnjë rrugë për të nxjerrë SOL jashtë limitit |
| D10 | `propose_jwk` merr modulus-in e plotë dhe llogarit hash-in on-chain | propozimi krahasohet drejtpërdrejt me JWKS publike gjatë timelock-ut; oracle s'mund të fusë një hash pa modulus |
| D11 | Rent-i i një token account-i të vault-it që mbyllet llogaritet si SOL i vault-it | mbyllja me destinacion tjetër do të nxirrte lamports pa limit |
| D12 | `Wallet` dhe `Session` nuk lejohen fare si llogari të instruksioneve të brendshme; maks. 24 llogari për instruksion, 8 token account-e të matura | thjeshtësi dhe kufij të qartë për CU/stack |
| D13 | `execute` nuk verifikon PDA-në e `Wallet`/`Session` me sha256: mjafton pronari (programi) + diskriminuesi + lidhja `session.wallet`/`session.session_key` | vetëm programi krijon këto llogari dhe vetëm në PDA-të e sakta; kursen CU |
| D14 | Pragu është ditor (24 orë, kumulativ për SOL), jo për transaksion | një faktor zk i vjedhur s'mund ta zbrazë portofolin me shumë transaksione nën prag; token-at mbeten nën limitet e sesionit |
| D15 | Faktori zk shton passkey direkt vetëm kur s'ka asnjë; përndryshe vetëm me rikuperim 48h | Google i vjedhur s'mund të shtojë passkey-n e sulmuesit pa dijeninë e pronarit |
| D16 | `rpIdHash` i `authenticatorData` nuk kontrollohet on-chain | passkey-t janë të lidhur me origjinën e tyre; çelësi publik i regjistruar në portofol e identifikon. SDK-ja regjistron vetëm passkey të krijuar në domenin e dashboard-it |
| D17 | `begin_recovery` kind 2 (provë + passkey) është ~1,200 bytes | afër limitit 1,232; SDK-ja përdor `clientDataJSON` minimal dhe, nëse duhet, Address Lookup Table për config/jwk |
| D18 | Salt = `HKDF-SHA256(master_seed, info = "solanaauth:salt:v1" ‖ iss ‖ 0 ‖ aud ‖ 0 ‖ sub)`, 16 bytes, `iss` në formën kanonike | deterministik pa bazë të dhënash. Humbja e `master_seed` ndryshon identitetin zk të çdo përdoruesi (jo fondet): portofoli rikuperohet me passkey (`begin_recovery` kind 2), por seed-i kërkon backup. Portofoli varet nga `aud` (si në Sui): aplikacione me client ID të ndryshëm kanë portofole të ndryshme |
| D19 | Oracle-i i JWK-ve vetëm propozon dhe aplikon; nuk revokon | një oracle i komprometuar s'mund të bllokojë hyrjet; çdo propozim duket on-chain gjatë timelock-ut; revokimi mbetet te admini |
| D20 | Në devnet `jwk_timelock_secs = 0` dhe `allow_test_vk = true` | quickstart-i punon menjëherë pas deploy-it; në mainnet build-i `mainnet` e ndalon VK-në test dhe timelock-u vendoset nga admini |
| D21 | Në shfletues çelësi i sesionit ruhet në `localStorage` | një XSS merr sesionin, por vetëm brenda politikës (programe, limite, skadim) dhe përdoruesi e revokon me zk ose passkey; alternativa (WebCrypto jo-eksportues) s'ka Ed25519 në të gjithë shfletuesit |
| D22 | Proxy-i i prover-it nuk verifikon nënshkrimin e JWT-së; kontrollon `aud`, `exp`, `keyClaimName = sub` dhe `maxEpoch ≤ tani + max_session_secs` | qarku verifikon RSA-në; proxy-i mbron vetëm kapacitetin |
| D23 | Agjentët hyjnë me loopback `127.0.0.1` (si CLI-të OAuth) dhe përdorin vetëm çelësin e sesionit | agjenti nuk sheh kurrë JWT-në e përdoruesit pas hyrjes dhe s'ka asnjë rrugë për të dalë nga politika |
| D24 | Pa paymaster (para M5) paguesi i hyrjes është vetë çelësi i sesionit; në devnet quickstart-i bën airdrop | asnjë çelës i hostuar; paymaster-i opsional vjen në M5 |
| D25 | Në `execute` vetëm vault-i mund të jetë nënshkrues i instruksioneve të brendshme | përndryshe çdo nënshkrues i tx-it (fee payer-i, paymaster-i, serveri i aplikacionit, Kora) do t'i jepte sesionit autoritetin e vet: një `system::transfer` nga paymaster-i brenda `execute` do ta zbrazte. Test negativ në `bench` |
| D26 | Paymaster-i sponsorizon vetëm instruksionet e `solanaauth` (+ ComputeBudget, secp256r1); paymaster-i mund të jetë vetëm fee payer ose paguesi i rent-it në `create_wallet`/`open_session`; kostoja matet me simulim para nënshkrimit dhe ka kufi për tx | asnjë rrugë për të nxjerrë SOL nga paymaster-i përtej tarifës dhe rent-it të portofolit/sesionit; ngarkesa = kosto reale e matur |
| D27 | Kufi i veçantë për hyrje të sponsorizuara (`perUserDailyAccounts`, parazgjedhja 3) | rent-i i një sesioni (~0.0053 SOL) kthehet te vault-i i përdoruesit kur mbyllet; pa kufi, një përdorues mund ta kthente depozitën e aplikacionit në SOL për vete |
| D28 | Marzhi i paymaster-it ($0.0002) merret vetëm mbi tx-at e përfshira në plan; devnet s'ngarkohet; depozita s'shkon nën zero (s'ka kredi) | brief 4.3–4.4: "tx paymaster" e planit = tx pa marzh; kostoja reale gjithmonë nga depozita |
| D29 | MAU dhe agjentët numërohen në salt-in e platformës (subjekt = sha256(iss‖sub), vetëm mainnet); plani Falas refuzon përdoruesit e rinj përtej kuotës | salt-i thirret në çdo hyrje dhe njeh `aud`-in e aplikacionit; s'ruhet asnjë identifikues i lexueshëm |
| D30 | Faqja e portofolit: tërheqja kërkon sesion (Google/Apple); me passkey vetëm revokim, prag, passkey dhe rikuperim; kur ka passkey, tërheqjet nënshkruhen edhe me passkey | `execute` kërkon sesion (D3). Pragu ditor mbron SOL; token-at mbrohen vetëm nga limitet e sesionit, prandaj faqja kërkon passkey kur ekziston (kufizim i njohur, te SECURITY.md) |
| D31 | Passkey-t e faqes së portofolit kanë `user.id` = adresa e portofolit | hyrja vetëm me passkey gjen portofolin pa server; çelësi publik gjendet duke verifikuar nënshkrimin kundër passkey-ve të portofolit |
| D32 | Pas rikuperimit me identitet të ri, SDK-ja e gjen portofolin me `getProgramAccounts` (identiteti te offset 56/96) | adresa e portofolit varet nga identiteti fillestar (seksioni 4) dhe nuk ndryshon |
| D33 | Sesioni i lojës demo lejon vetëm programin e lojës dhe s'ka asnjë limit aseti | deny by default (D5): sesioni s'mund të lëvizë asnjë SOL apo token; 24 orë veprime pa konfirmim pa asnjë rrezik për fondet |
| D34 | x402: facilitator-i është fee payer (`extra.feePayer`), agjenti kontrollon limitin lokalisht para se të paguajë, facilitator-i pranon vetëm `execute` me një `transferChecked` te `payTo` me shumën e saktë | skema `exact` e x402 në Solana; kontrolli lokal jep gabim të qartë, kontrolli përfundimtar mbetet on-chain; D25 e bën të pamundur përdorimin e fee payer-it brenda `execute` |
| D35 | Wallet Standard: `signAndSendTransaction`; nënshkrimet SAA-1271 vetëm përmes `solanaauth:session.signMessage`; pa `signTransaction` ose `solana:signMessage`; tx me address lookup tables refuzohen | një PDA s'ka çelës Ed25519; verifikuesi i SAA-1271 ka nevojë për `wallet` dhe `session`; ALT do të fshihnin llogari nga kontrolli i nënshkruesve |
| D36 | Koha e provës (p50/p95) matet me `scripts/prover-bench.mjs`, jo në CI | prova kërkon një JWT të freskët me nonce-in e një çelësi të ri, që merret vetëm me një hyrje reale në shfletues; një JWT apo token i ruajtur në Secrets do të ishte kredencial i vërtetë. Numrat lokalë s'shkruhen në `results/` |
| D37 | Devnet E2E në çdo push në `main` vetëm kur ekzistojnë çelësat devnet të programeve (upgrade, jo program i ri); përndryshe puna kalohet me shënim | një deploy i ri në çdo push do të krijonte një Program ID të ri dhe do të harxhonte ~1.3 SOL devnet; hyrja e plotë me Google mbulohet në CI nga LiteSVM me programin e vërtetë, sepse në devnet kërkon një person |
| D38 | Varësitë e programeve me `=` në `Cargo.toml`, `groth16-solana` në commit të fiksuar, `Cargo.lock` dhe `package-lock.json` në repo | build i riprodhueshëm për auditimin; çdo përditësim është ndryshim i qartë në diff |

## 11. SDK dhe shërbimet (M4)

| Pjesa | Ku | Çfarë bën | Sekretet |
|---|---|---|---|
| `@solanaauth/core` | `sdk/core` | PDA, instruksionet, blloku zk, politika, passkey (WebAuthn + secp256r1), dekodimi i llogarive, rrjedha e hyrjes | asnjë; çelësi i sesionit krijohet te klienti |
| `@solanaauth/react` | `sdk/react` | `SolanaAuthProvider`, `useSolanaAuth`, `useVaultBalance`, `BrowserLogin` (redirect → `id_token` → sesion) | çelësi i sesionit në `localStorage` |
| `@solanaauth/agent` | `sdk/agent` | `AgentWallet` (kontroll lokal i politikës, `transferSol`, `transferToken`), `loginAgent` me loopback `127.0.0.1` | skedari i sesionit me leje 0600 |
| salt service | `services/salt` | `POST /salt {jwt}` → salt deterministik pas verifikimit RS256, `aud` e lejuar, `exp` | `SALT_MASTER_SEED` (32 bytes, secret manager) |
| jwk-oracle | `services/jwk-oracle` | JWKS e Google/Apple → `propose_jwk`, pas timelock-ut `apply_jwk` | çelësi i oracle-it (vetëm propozon) |
| prover | `services/prover` | imazhet e Mysten (`prover-stable`, `prover-fe-stable`) + proxy me CORS, rate limit, `aud` e lejuar, kufi për `maxEpoch` | asnjë (zkey është publik) |
| quickstart | `examples/quickstart` | Vite + React: hyrje me Google, bilanci, transfertë brenda limitit, dalje me revokim | `.env.local` vetëm me ID publike |

Testet: vektorët Rust↔TS (`fixtures/sdk-vectors.json`, të kontrolluar në CI), krahasimi me `@mysten/sui` për `genAddressSeed`/`generateNonce`, dhe teste e2e të SDK-së, oracle-it dhe agjentit kundër `solanaauth.so` në LiteSVM.

### 11.1 Çfarë kërkon pronari i produktit për devnet

1. Secret-i `DEVNET_DEPLOYER_KEYPAIR` (dhe opsionalisht `DEVNET_SOLANAAUTH_PROGRAM_KEYPAIR` për një Program ID të qëndrueshëm), pastaj Actions → ci → Run workflow → `devnet`. Raporti del te `results/devnet-solanaauth.md`.
2. Një OAuth client ID i Google (Web) me redirect `http://localhost:5173` dhe domenin e dashboard-it. Apple kërkon Apple Developer account (Services ID).
3. Hosting për prover-in (≥ 16 GB RAM, ~3 s CPU për provë) dhe salt service-in, me `SALT_MASTER_SEED` në një secret manager me backup.

## 12. Paymaster, dashboard, faturimi dhe faqja e portofolit (M5)

| Pjesa | Ku | Çfarë bën |
|---|---|---|
| Platforma | `services/platform` | API e vetme: aplikacionet, API keys (vetëm hash), OAuth client IDs, `POST /v1/salt` dhe `/v1/prove` me matje përdorimi, `POST /v1/sponsor` (paymaster), Stripe Checkout + webhook, depozita USDC/SOL me referencë Solana Pay, fatura nga `config/pricing.json` |
| Dashboard | `apps/dashboard` | hyrje me Google; aplikacionet, çelësat, OAuth, shabllonet e politikave, përdorimi (MAU, agjentë, prova, tx paymaster), paymaster (ON/OFF, depozitë, limite, historik), faturimi |
| Faqja e portofolit | `apps/wallet` | hyrje me Google/Apple ose passkey; asetet, tërheqja, sesionet, passkey-t, pragu, rikuperimi në të dy drejtimet |
| SDK | `sdk/core` | `FeePayer`: `paymasterFeePayer`, `appServerFeePayer`, `koraFeePayer`; `execute(..., { feePayer })` |

Paymaster-i është OFF si parazgjedhje. Pa të, paguan përdoruesi (çelësi i sesionit), serveri i aplikacionit (`appServerFeePayer`, i njëjti protokoll si paymaster-i) ose Kora. Testi `services/platform/test/demo-paymaster.test.mjs` bën të njëjtën hyrje dhe `execute` me paymaster ON dhe OFF kundër programit të vërtetë.

Çmimet janë vetëm te `config/pricing.json`. Çelësat e Stripe dhe çelësi i paymaster-it vijnë nga mjedisi; në këtë fazë çelësi i paymaster-it është vetëm devnet.

## 13. Demot, siguria dhe gatishmëria për auditim (M6)

| Pjesa | Ku |
|---|---|
| Lojë demo (sesion 24h, pa konfirmime, paymaster ON/OFF) | `programs/demo-game`, `examples/game` |
| Agjent AI me 20 USDC/ditë që paguan me x402 | `sdk/agent/src/x402.ts`, `examples/agent-x402` |
| Wallet Standard + `signMessage` (SAA-1271) | `sdk/wallet-standard`, `sdk/core/src/message.ts`, `docs/SIGN-MESSAGE.md` |
| Modeli i kërcënimeve, invariantet, `unsafe` | `docs/SECURITY.md` |
| Teste property (parsimi, politikat, limitet) | `programs/solanaauth/tests/props.rs` |
| Quickstart, shembuj, self-host, matjet | `docs/QUICKSTART.md`, `docs/SHEMBUJ.md`, `docs/SELF-HOST.md`, `docs/MATJET.md` |
| Mjedisi i përbashkët i testeve JS (LiteSVM + programet e vërteta) | `testing/` (`@solanaauth/testkit`) |
