# Siguria: modeli i kërcënimeve

Ky dokument përshkruan çfarë mbron solanaauth, kundër kujt, dhe çfarë mbetet jashtë. Vendimet e
përmendura (D1, D2, …) janë te [`DIZAJNI.md`](DIZAJNI.md) §10. Raportimi i dobësive: hap një
GitHub Security Advisory privat te repo-ja, jo issue publik.

**Gjendja:** kodi nuk është audituar ende. Mos e përdor në mainnet me fonde reale para auditimit.

## 1. Çfarë mbrojmë

| Aseti | Ku jeton | Kush ka autoritet |
|---|---|---|
| Fondet e përdoruesit (SOL, token-a) | vault-i, PDA `["vault", wallet]` pa çelës privat | vetëm programi, me autorizimin e portofolit |
| Kontrolli i portofolit | llogaria `Wallet` (identitetet zk, passkey-t, pragu, rikuperimi) | prova zkLogin e vlefshme ose passkey |
| Sesionet | llogaritë `Session` (çelësi Ed25519 i sesionit + politika) | çelësi i sesionit, vetëm brenda politikës |
| Depozita e aplikacionit te paymaster-i | platforma (ledger) + çelësi i paymaster-it (vetëm devnet tani) | operatori i platformës |

**Ne nuk mbajmë kurrë çelësa privatë të përdoruesve.** Asnjë shërbim (salt, prover, platforma,
paymaster) s'mund të lëvizë fondet e një përdoruesi: çdo `execute` kërkon nënshkrimin e çelësit të
sesionit, që gjenerohet dhe ruhet te pajisja e përdoruesit ose te agjenti.

## 2. Supozimet e besimit

1. Siguria e Groth16 dhe e qarkut zkLogin të Mysten (ceremonia e verifying key-t "main").
2. Ofruesi OAuth (Google, Apple) nuk lëshon JWT të rreme për një `sub` tjetër.
3. Admini i `config`-ut dhe upgrade authority veprojnë me ndershmëri gjatë timelock-ut (shih §3.1, §3.2).
4. Runtime-i i Solana (verifikimi Ed25519 i tx-it, precompile-i secp256r1, `sol_poseidon`, `alt_bn128`).

## 3. Kërcënimet dhe mbrojtjet

### 3.1 JWK registry

**Kërcënimi:** një çelës RSA i rremë në registry lejon këdo të prodhojë JWT "të vlefshme" për
çdo përdorues dhe të marrë çdo portofol të atij `iss`.

**Mbrojtja:**
- Modulus-i i JWK-së nuk vjen kurrë nga përdoruesi. `create_wallet`, `open_session` dhe
  rikuperimi lexojnë hash-in Poseidon të modulus-it vetëm nga llogaria `Jwk` e programit.
- `propose_jwk` merr modulus-in e plotë dhe llogarit hash-in on-chain (D10), kështu çdo propozim
  krahasohet drejtpërdrejt me JWKS publike të Google/Apple.
- Timelock midis `propose_jwk` dhe `apply_jwk` (`jwk_timelock_secs` në `config`). Gjatë timelock-ut
  kushdo mund ta krahasojë propozimin me `https://www.googleapis.com/oauth2/v3/certs` dhe admini e
  revokon me `revoke_jwk`, që vepron menjëherë.
- Oracle-i (`services/jwk-oracle`) vetëm propozon dhe aplikon; nuk revokon (D19). Një oracle i
  komprometuar s'mund të bllokojë hyrjet dhe çdo veprim i tij duket on-chain.
- Testi negativ "modulus jashtë registry-së" dhe "JWK ende në timelock" në `bench/tests/solanaauth.rs`.

**Mbetet:** në devnet timelock-u është 0 (D20). Në mainnet duhet ≥ 24 orë dhe një monitor që
krahason çdo propozim me JWKS publike.

### 3.2 Upgrade authority

**Kërcënimi:** kush mban upgrade authority mund të zëvendësojë programin dhe të marrë çdo vault.

**Mbrojtja e planifikuar për mainnet:**
- Upgrade authority në një multisig (p.sh. Squads) me timelock, jo një çelës i vetëm.
- Pas auditimit, programi bëhet immutable (`solana program set-upgrade-authority --final`) ose
  mbetet vetëm pas multisig + timelock, i publikuar.
- Build-i i verifikueshëm (`solana-verify`) që përputhet me tag-un e auditimit.
- `init_config` lejohet vetëm nga upgrade authority (test negativ), që askush tjetër të mos e
  pushtojë `config`-un pas deploy-it.

**Mbetet:** në devnet upgrade authority është çelësi devnet i CI-së (pa vlerë).

### 3.3 Prover-i

**Kërcënimi:** prover-i sheh JWT-në, salt-in dhe çelësin publik ephemeral.

**Mbrojtja:**
- Prover-i nuk ka sekrete dhe nuk merr asnjë çelës privat. Një provë lidhet me çelësin publik
  ephemeral përmes nonce-it të JWT-së; pa çelësin privat përkatës prova është e padobishme.
- Prover-i s'mund të prodhojë provë pa një JWT të vlefshme të nënshkruar nga ofruesi.
- Një prover keqdashës mund të refuzojë shërbimin (DoS) ose të ruajë JWT-të. JWT-ja e ruajtur, me
  salt-in, lejon lidhjen e identitetit OAuth me adresën e portofolit (privatësi), por jo fondet:
  çdo provë e re kërkon një JWT të re me nonce-in e një çelësi që sulmuesi s'e ka.
- Proxy-i (`services/prover/src`) kontrollon `aud` kundrejt listës së aplikacioneve, `exp`,
  `keyClaimName = sub` dhe `maxEpoch ≤ tani + max_session_secs` (D22), dhe kufizon kërkesat.
- Self-host: prover-i ngrihet nga `services/prover/docker-compose.yml` pa shërbimet tona.

### 3.4 Salt-i

**Kërcënimi:** humbja ose rrjedhja e `master_seed`.

- **Rrjedhja:** salt-i s'jep akses te fondet; për një provë duhet edhe JWT-ja. Rrjedhja lidh
  identitetet OAuth me portofolet (privatësi).
- **Humbja:** salt-i ndryshon, pra identiteti zk ndryshon (D18). Fondet s'humbin: portofoli
  rikuperohet me passkey (`begin_recovery` kind 2), dhe identiteti i ri zk shtohet pas timelock-ut.
  Përdoruesit pa passkey varen nga backup-i i seed-it. Seed-i mbahet në një secret manager, me backup.
- Salt-i kthehet vetëm për JWT me nënshkrim të vlefshëm (JWKS e ofruesit) dhe `aud` të lejuar.

### 3.5 Paymaster-i

**Kërcënimi:** një përdorues ose aplikacion i keq zbraz SOL-in e paymaster-it ose depozitën e
një aplikacioni tjetër.

**Mbrojtja** (`services/platform/src/paymaster.ts`, D26–D28):
- Paymaster-i nënshkruan vetëm tx ku të gjitha instruksionet janë të `solanaauth` (+ ComputeBudget,
  secp256r1), dhe programet brenda `execute` janë në listën e lejuar.
- Paymaster-i mund të jetë vetëm fee payer, ose paguesi i rent-it në `create_wallet`/`open_session`.
  Asnjë përdorim tjetër i adresës së tij (`PayerMisuse`).
- **D25 (programi):** brenda `execute` vetëm vault-i mund të jetë nënshkrues i instruksioneve të
  brendshme. Pa këtë, një `system::transfer` nga fee payer-i brenda `execute` do ta zbrazte
  paymaster-in. Test negativ në `bench`.
- Simulim para nënshkrimit; kufi për tx (`maxLamportsPerTx`), për priority fee, për përdorues/ditë
  (tx dhe llogari të reja, D27) dhe global/ditë. Depozita s'shkon nën zero.
- API key ruhet vetëm si hash; çdo kërkesë ngarkohet te aplikacioni i çelësit.

**Mbetet:** çelësi i paymaster-it është një hot key në server; në këtë fazë vetëm devnet.

### 3.6 Çelësat e sesionit

**V2:** çelësi i ekzekutimit është i ndryshëm nga çelësi OAuth i pronarit. Transaksioni i
miratimit lidh politikën dhe çelësin e deleguar. Agjenti merr vetëm çelësin e vet dhe verifikon
hash-in e politikës në llogarinë V2. Shih [AGENT-POLICIES.md](AGENT-POLICIES.md).
**V1:** modeli i vjetër lidh të njëjtin çelës me provën OAuth. Mos ia jep një agjenti të pabesuar:
prova publike dhe çelësi mund të përdoren si autoritet pronari. Revoko sesionet e vjetra të
eksportuara dhe ri-autorizo një çelës V2; përditësimi nuk i konverton automatikisht.

**Kërcënimi:** çelësi i sesionit vidhet (XSS, pajisje e komprometuar, agjent i komprometuar).

**Mbrojtja (on-chain, D5, D12, D14):**
- Politika: lista e programeve të lejuara, limite për çdo aset për dritare kohe, skadim. Asetet
  pa limit refuzohen (deny by default). `max_session_secs` kufizon jetëgjatësinë.
- Loader-at e programeve (upgrade/close) dhe vetë `solanaauth` s'lejohen kurrë në politikë, edhe po të jenë në listë.
- `Wallet` dhe `Session` s'mund të jenë llogari të instruksioneve të brendshme; invariantet e
  vault-it dhe të token account-eve kontrollohen pas çdo CPI.
- Pragu ditor: transfertat SOL mbi prag kërkojnë passkey.
- Revokimi i menjëhershëm nga sesioni, nga zk ose nga passkey (faqja e portofolit).
- Në shfletues çelësi ruhet në `localStorage` (D21): XSS merr sesionin, por vetëm brenda politikës.

**Kufizim i njohur (D30):** pragu me passkey mbron vetëm SOL. Token-at mbrohen vetëm nga limitet e
sesionit. Aplikacionet duhet të vendosin limite token konservative.

### 3.7 Prompt injection te agjentët

**Kërcënimi:** një faqe ose përgjigje API bind agjentin AI të dërgojë fonde te sulmuesi.

**Mbrojtja:**
- Në V2 agjenti ka vetëm çelësin e deleguar (D23); OAuth bëhet në wallet-in e klientit. Asgjë që agjenti "beson"
  s'e zgjeron politikën: limiti (p.sh. 20 USDC/ditë) dhe lista e programeve zbatohen on-chain.
- `AgentWallet.check` refuzon lokalisht para se të ndërtojë tx-in, por kontrolli përfundimtar është
  i programit (`examples/agent-x402/test`: pagesa e 5-të refuzohet edhe on-chain me `0x21`).
- Revokimi nga përdoruesi (faqja e portofolit) e ndalon agjentin menjëherë (`0x1f`).
- **Mbetet:** brenda limitit, agjenti mund të paguajë marrës të gabuar. Politika s'ka ende listë
  marrësish; aplikacionet me rrezik të lartë duhet të mbajnë limite të vogla.

### 3.8 Passkey dhe rikuperimi

- Faktori zk shton passkey direkt vetëm kur s'ka asnjë (D15); përndryshe vetëm me rikuperim 48 orë.
- Rikuperimi në të dy drejtimet ka timelock 48 orë (D7); faktori tjetër e anulon gjatë kësaj kohe.
- `clientDataJSON` kontrollohet për `type = webauthn.get` dhe challenge-in e saktë, një herë
  (teste property në `programs/solanaauth/tests/props.rs`). `rpIdHash` s'kontrollohet (D16).
- Nonce-i i portofolit parandalon përsëritjen e nënshkrimeve passkey.

### 3.9 signMessage

Nënshkrimi SAA-1271 bëhet nga çelësi i sesionit, i lidhur me portofolin dhe sesionin
([`SIGN-MESSAGE.md`](SIGN-MESSAGE.md)). Verifikuesi duhet të kontrollojë pronarin, adresën PDA,
revokimin dhe skadimin. Një sesion i vjedhur mund të nënshkruajë mesazhe deri në skadim/revokim.

## 4. Invariantet e programit

Këto kontrollohen nga programi në çdo instruksion dhe mbulohen nga testet negative në
`bench/tests/solanaauth*.rs` dhe nga testet property:

1. Vault-i lëviz fonde vetëm përmes `execute` (sesion aktiv, politikë) ose me autoritetin e plotë
   (zk/passkey) për veprimet administrative të portofolit.
2. Pas `execute`: rënia e lamports të vault-it ≤ limiti SOL i mbetur; për çdo token account të
   vault-it, rënia ≤ limiti i atij mint-i; pronari dhe të dhënat e vault-it s'ndryshojnë.
3. Për çdo dritare limiti: shuma e shpenzuar ≤ `amount` (property `spend_limit_holds`).
4. Vetëm vault-i mund të nënshkruajë instruksione të brendshme (D25).
5. `Wallet`/`Session` s'kalohen kurrë te programe të tjera (D12).
6. Asnjë parsim input-i s'shkakton panic (property për `Policy`, `ZkBlock`, `iss`, `clientDataJSON`).
7. Çdo llogari e programit kontrollohet për pronarin, gjatësinë dhe diskriminuesin para leximit.
8. Një provë zk pranohet vetëm me JWK aktiv, `iss` që përputhet, `max_epoch > now` dhe
   `max_epoch ≤ now + max_session_secs`.

## 5. Kodi gati për auditim

- **`unsafe`:** katër vende, secili me koment `SAFETY`:
  - `util.rs` `Account::{from_bytes, from_bytes_mut, init_bytes}`: cast i bytes të llogarisë në
    struct. Gjatësia dhe diskriminuesi kontrollohen më parë; `size_of == LEN` dhe `align_of == 1`
    kontrollohen në kohë kompilimi (`state.rs`).
  - `execute.rs`: slice mbi `MaybeUninit<InstructionAccount>` vetëm për `[0, n_acc)`, të
    inicializuara në ciklin paraprak.
  - `authority.rs`: syscall-i `sol_log_` me një `&str` të vlefshëm.
- **Varësitë:** versione të pin-uara me `=` te `programs/*/Cargo.toml`, `Cargo.lock` në repo,
  `groth16-solana` në një commit të fiksuar, `package-lock.json` për npm.
- **Testet:** LiteSVM me programin e ndërtuar (`bench`), teste property (`proptest`, 2,000 raste
  për veti), SDK end-to-end kundër programit të vërtetë, devnet E2E në CI.
- **Sekretet:** asnjë çelës mainnet në repo apo në GitHub Secrets. Secrets vetëm për devnet
  (`DEVNET_DEPLOYER_KEYPAIR`, pa vlerë reale).

## 6. Jashtë fushës

- Komprometimi i llogarisë Google/Apple të përdoruesit *dhe* i passkey-t njëkohësisht.
- Phishing-u i faqes së hyrjes (origjina OAuth mbrohet nga redirect URI-të e regjistruara).
- Sulmet ndaj vetë Solana-s ose ndaj ofruesit RPC (një RPC i rremë mund të gënjejë për bilancet,
  por s'mund të falsifikojë nënshkrime).
