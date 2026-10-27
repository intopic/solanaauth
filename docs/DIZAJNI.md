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
- **Veprimet mbi prag** (kërkojnë passkey përveç sesionit/zk): `execute` që zbret SOL/token mbi
  `threshold_lamports` (ose ekuivalentin e konfiguruar për mint), `add_authority`,
  `remove_authority`. Nëse portofoli nuk ka passkey, pragu nuk vlen (përdoruesi paralajmërohet
  nga SDK-ja).

## 7. Rikuperimi (M3)

| Situata | Rruga | Timelock | Kush e anulon |
|---|---|---|---|
| Humbi passkey-n | provë zk → `begin_recovery(add passkey P')` | 48 orë (`config.recovery_delay`) | çdo passkey ekzistuese |
| Humbi Google / salt-in | passkey → `begin_recovery(add zk identity Z')` | 48 orë | çdo autoritet zk ekzistues |
| Pas timelock-ut | `finish_recovery` (kushdo) | — | — |

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
