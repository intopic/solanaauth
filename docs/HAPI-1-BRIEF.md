# Hapi 1 — Testi kritik: verifikimi i zkLogin në Solana

Version i repo-s së brief-it. Dokumenti i gjallë: <https://claude.ai/artifact/ViNiTBXKSRdr9nFq8hdZco>

## Qëllimi

Të provojmë në 1–2 javë nëse një program Solana mund të verifikojë një provë zkLogin ekzistuese (Groth16, nga qarku i Sui-t) dhe sa compute units (CU) kushton. Rezultati është një vendim **GO / NO-GO** për gjithë projektin "hyrje me Google/Apple pa frazë" në Solana.

Ky test **nuk** ndërton portofol, frontend apo hyrje me Google. Ndërton vetëm minimumin që përgjigjet në tri pyetje:

1. A pranohet prova e Sui-t nga një verifikues Groth16 në Solana (pas konvertimit të formatit)?
2. Sa CU kushton verifikimi i provës?
3. Sa CU kushton rillogaritja on-chain e input-it publik (hash Poseidon), dhe a futet gjithçka në një transaksion?

## Harta e projektit

Ky test është faza e parë nga pesë; rezultati i tij vendos nëse vazhdojnë të tjerat.

| Faza | Kohëzgjatja | Çfarë |
|---|---|---|
| **1. Testi kritik** (tani) | 1–2 javë | Groth16 + Poseidon në Solana, matje CU, GO / NO-GO |
| 2. Prototipi | 4–6 javë | Hyrje me Google, sesion PDA, transferta në devnet |
| 3. Passkey + rikuperim | — | secp256r1, salt nga passkey, JWK registry |
| 4. Auditimi | — | programi, qarku, menaxhimi i salt-it |
| 5. Grant | — | Solana Foundation, SDK publik |

**Vizioni:** çdo aplikacion në Solana të mund t'u japë përdoruesve një portofol vetë-kujdestar me "Hyr me Google/Apple", pa frazë sekrete dhe pa një kompani që mban apo bashkë-mban çelësin. Prova verifikohet nga vetë Solana; passkey-ja është faktori i dytë dhe rruga e rikuperimit. Kodi dhe matjet janë publike që nga dita e parë.

## Konteksti i shkurtër

**zkLogin në një paragraf:** përdoruesi hyn me Google dhe merr një JWT të nënshkruar nga Google. Në `nonce` të JWT-së futet hash-i i një çelësi të përkohshëm (ephemeral key) dhe një afat skadimi. Një provë Groth16 provon se JWT-ja është e nënshkruar nga Google dhe lidhet me adresën e portofolit, pa zbuluar email-in. Pas kësaj, transaksionet nënshkruhen me çelësin e përkohshëm deri sa të skadojë.

**Arkitektura që synojmë (e rëndësishme për interpretimin e matjeve):** prova verifikohet **një herë për sesion** (p.sh. 24 orë). Kur verifikohet, programi regjistron çelësin e përkohshëm në një PDA "sesioni". Transaksionet e tjera të sesionit kontrollojnë vetëm nënshkrimin Ed25519 të çelësit të përkohshëm, që është i lirë. Pra kostoja e provës paguhet rrallë, jo në çdo transaksion.

**Pse tani është e mundur:** verifikimi Groth16 me BN254 është aktiv native në Solana mainnet që nga Agave 4.0, dhe ekziston syscall-i `sol_poseidon` për hash-in Poseidon.

## Si të fillosh (dita 1)

- [ ] Merr akses në repo-n [`intopic/solanaauth`](https://github.com/intopic/solanaauth) me të drejta shkrimi.
- [ ] Instalo lokalisht: Rust (stable), Solana CLI nga Anza (`sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"`, versioni 4.x), Anchor (përmes `avm`), Node.js 20+.
- [ ] Lexo seksionet *Konteksti*, *Materialet* dhe *Kurthet* më poshtë para se të shkruash kod.
- [x] Struktura e repo-s dhe workflow-i i GitHub Actions ekzistojnë tashmë (skelet që kalon në CI).
- [ ] Plotëso `reference/` (Detyra 2) me verifikimin off-chain të provës referencë me `sui-crypto` dhe hiq `#[ignore]` nga testi. Kur kalon në CI, puna ka nisur zyrtarisht.

**Rregull:** të vetmet numra CU që pranojmë janë ato që prodhon GitHub Actions dhe publikohen në repo, jo matjet nga kompjuteri personal. Kështu çdokush mund t'i riprodhojë.

## Detyrat hap pas hapi

1. **Merr një provë zkLogin të vlefshme me të gjitha input-et.** Rruga më e shpejtë: test vectors e fiksuara në crate-in `sui-crypto` (prova nga `prover-dev` mbi një JWT të `jwt-tester.mystenlabs.com`, me çelës ephemeral nga seed `[0; 32]`). Alternativë: gjenero vetë një provë duke thirrur `https://prover-dev.mystenlabs.com/v1` (publik për devnet/testnet, pa regjistrim). Ruaji në `fixtures/`.
2. **Verifiko provën off-chain me kodin e Sui-t** (`sui-crypto` ose `fastcrypto-zkp`) në `reference/` për të konfirmuar që ke input-et e sakta dhe verifying key-n që i përket. Ky është "e vërteta referencë".
3. **Konverto verifying key-n** e zkLogin në formatin e `groth16-solana` (crate-i ka skript që lexon `verifyingkey.json` të snarkjs). Kujdes të përdorësh key-n që përputhet me prover-in (shih Kurthet). Skripti shkon në `scripts/`.
4. **Shkruaj programin Solana minimal** (Anchor ose native) në `programs/zklogin-verifier/` me dy instruksione:
   - `verify_proof(proof, public_input)`: vetëm verifikimi Groth16 me `groth16-solana`.
   - `verify_full(proof, inputs...)`: rillogarit `all_inputs_hash` on-chain me `sol_poseidon`, pastaj verifikon provën.
5. **Rillogarit input-in publik.** Qarku i Sui-t ka një input publik të vetëm: hash Poseidon i të gjitha input-eve (gjysmat e ephemeral public key, `max_epoch`, `address_seed`, të dhënat e `iss`, header-i, hash-i i modulus-it RSA të Google-it). Implemento të njëjtën logjikë si `calculate_all_inputs_hash` në `fastcrypto-zkp` dhe krahaso rezultatin bit për bit me versionin off-chain.
6. **Mat CU** për secilin instruksion në `bench/` (Mollusk / LiteSVM) dhe me `sol_log_compute_units`; pastaj deploy në devnet (puna manuale `devnet` në CI). Mat veçmas: verifikimin Groth16, çdo thirrje Poseidon, dhe totalin.
7. **Test negativ:** ndrysho 1 byte në provë dhe në input; programi duhet të refuzojë.
8. **Bonus (nëse mbetet kohë):** JWT e vërtetë nga Google me një OAuth client testi, prova nga `prover-dev`, e verifikuar në programin tënd.

## Materialet dhe mjetet që ekzistojnë

Pothuajse çdo pjesë ekziston; puna kryesore është t'i lidhësh saktë.

| Pjesa | Çfarë është | Ku gjendet |
|---|---|---|
| Verifikues Groth16 për Solana | Crate `groth16-solana` (Light Protocol): përdor syscall-et altbn254, sipas README-së verifikimi kushton nën 200,000 CU, i pajtueshëm me provat e Circom; versioni 0.0.1 u auditua në auditimin e Light Protocol v3 | [GitHub](https://github.com/Lightprotocol/groth16-solana), [docs.rs](https://docs.rs/crate/groth16-solana/0.2.0) |
| Hash Poseidon on-chain | Syscall `sol_poseidon`; crate `light-hasher` / `light-poseidon` (i pajtueshëm me Circom) | [Solana syscall reference](https://solana.com/docs/core/programs/syscall-reference), [light-hasher](https://www.mintlify.com/Lightprotocol/light-protocol/api/program-libs/hasher) |
| Verifikuesi referencë i Sui-t | `sui-crypto` (Rust, arkworks): ngarkon verifying key-n nga `zkLogin.vkey` | [verify.rs](https://docs.rs/sui-crypto/0.3.0/src/sui_crypto/zklogin/verify.rs.html) |
| Test vectors | Prova të fiksuara v1 dhe v2 me JWT testi dhe çelës ephemeral nga seed `[0; 32]` | [sui-crypto tests.rs](https://docs.rs/crate/sui-crypto/0.3.1/source/src/zklogin/tests.rs) |
| Prover publik | `https://prover-dev.mystenlabs.com/v1`, falas për devnet/testnet | [Sui integration guide](https://docs.sui.io/sui-stack/zklogin-integration/integration-guide), [demo](https://docs.sui.io/sui-stack/zklogin-integration/zklogin-demo) |
| Qarku dhe ceremonia | Qarqet Circom të zkLogin, të audituara nga zkSecurity në 2023; key-t e ceremonisë (test dhe main) | [Auditimi](https://reports.zksecurity.xyz/reports/mysten-labs-zklogin), [ceremony repo](https://learnblockchain.cn/article/8371) |
| Logjika e input-it publik | `calculate_all_inputs_hash` dhe hash-et ndihmëse | `fastcrypto-zkp` (MystenLabs/fastcrypto) |

Për orientim: Groth16 në Solana zakonisht kushton [170,000–500,000 CU](https://docs.chainstack.com/docs/solana-zk-proofs), në varësi të qarkut dhe numrit të input-eve publike.

## Kurthet e njohura

- **Endianness.** `groth16-solana` kërkon input-et [në big endian](https://github.com/Lightprotocol/groth16-solana); arkworks/Sui përdorin zakonisht little endian. Shumica e dështimeve të para vijnë nga këtu.
- **Negimi i `proof_a`.** Shembulli i crate-it e neg-on pikën A para verifikimit; ndiqe saktë.
- **Renditja e koordinatave G2.** Formatet ndryshojnë në renditjen e (c0, c1) për pikat G2 mes snarkjs, arkworks dhe syscall-eve të Solana-s. Testo me provën referencë para se të fajësosh kodin tjetër.
- **Verifying key i gabuar.** Ekzistojnë key test dhe main nga ceremonia, si dhe qarqe v1/v2. Prova nga `prover-dev` duhet verifikuar me key-n që i përket; verifiko fillimisht off-chain (Detyra 2).
- **Modulus-i RSA i Google-it.** Hash-i i modulus-it kërkon shumë thirrje Poseidon. Mat koston; nëse është e lartë, në prodhim do ta ruajmë të para-llogaritur në një llogari "JWK registry". Kjo vlen si zbulim, jo si dështim.
- **Poseidon me shumë input-e.** Sui përdor një variant që i ndan input-et në grupe kur janë më shumë se arity-ja e lejuar. Rezultati duhet të përputhet bit për bit me `fastcrypto`.
- **Limiti i CU.** Kërko buxhet me `ComputeBudgetProgram.setComputeUnitLimit`; pa të, instruksioni ndalon te limiti i parazgjedhur.
- **Licencat.** Para prodhimit, kontrollo licencën e qarqeve dhe key-ve të zkLogin; për testin nuk është pengesë.

## Repo dhe GitHub Actions

Repo-ja është publike nga dita e parë, me licencë Apache-2.0 (e njëjtë me `groth16-solana`). Çdo push në `main` ndërton, teston, mat CU dhe publikon rezultatet në repo. Struktura dhe workflow-i janë gati; shih [README](../README.md#ci) dhe [`.github/workflows/ci.yml`](../.github/workflows/ci.yml).

Ku plotëson developer-i:

| Skedari | Detyra |
|---|---|
| `fixtures/` | 1 — prova, input-et, verifying key |
| `reference/src/lib.rs` | 2 — verifikimi off-chain, hiq `#[ignore]` |
| `scripts/` | 3 — konvertimi i key-t |
| `programs/zklogin-verifier/` | 4–5 — programi; sapo shtohet `Cargo.toml`, CI e ndërton |
| `bench/tests/cu_report.rs` | 6–7 — matjet reale dhe testet negative (zëvendëso `None`) |
| `scripts/devnet.sh` | 6 — transaksioni real në devnet |

**Secrets** (vetëm për punën devnet): `DEVNET_DEPLOYER_KEYPAIR`, një çelës devnet pa vlerë reale, i financuar me SOL devnet (Settings → Secrets and variables → Actions). Asnjë çelës mainnet nuk vendoset në repo apo në Secrets në këtë fazë.

## Matjet, kriteret GO / NO-GO dhe dorëzimi

Kriteri vendimtar është kostoja totale e `verify_full` (Poseidon + Groth16) në një transaksion, krahasuar me limitin 1.4 milion CU të një transaksioni në Solana.

| Kostoja totale e `verify_full` | Vendimi | Çfarë do të thotë |
|---|---|---|
| Deri ~400,000 CU | **GO** | Verifikimi + regjistrimi i sesionit futen lehtë në një transaksion |
| ~400,000 – 1,000,000 CU | **GO me kujdes** | Funksionon, por regjistrimi i sesionit duhet të jetë transaksion më vete |
| 1,000,000 – 1,400,000 CU | **Rishikim** | Ndajmë punën (p.sh. modulus-i i para-llogaritur në JWK registry) |
| Mbi 1,400,000 CU ose prova s'pranohet | **NO-GO** për qasjen direkte | Shqyrtojmë alternativa (p.sh. qark i ri më i lehtë) |

**Çfarë dorëzohet:**

- [ ] Repo me programin, skriptet e testit dhe udhëzime për ta riprodhuar (`README`).
- [ ] Adresa e programit në devnet dhe 2–3 nënshkrime transaksionesh të suksesshme.
- [ ] Tabela e matjeve: CU për `verify_proof`, për çdo hap Poseidon, për `verify_full`.
- [ ] Rezultati i testeve negative.
- [ ] Raport i shkurtër (1 faqe, `docs/HAPI-1-RAPORT.md`): çfarë funksionoi, çfarë jo, problemet e formatit dhe si u zgjidhën, rekomandimi GO / NO-GO.

## Afati dhe pyetjet për t'u kthyer

**Afati:** 1–2 javë. Plan orientues:

1. Ditët 1–3: prova referencë verifikohet off-chain; verifying key i konvertuar.
2. Ditët 4–7: `verify_proof` funksionon në devnet dhe matet.
3. Ditët 8–10: `verify_full` me Poseidon, krahasim bit për bit, matje.
4. Ditët 11–14: teste negative, bonus me Google, raporti.

**Pikë kontrolli:** në fund të ditës 3, një mesazh i shkurtër: a u verifikua prova off-chain dhe a u konvertua key-i? Nëse jo, flasim para se të vazhdohet.

**Pyetjet që duhet t'i përgjigjet raporti:**

- Sa CU kushton saktësisht `verify_full`, dhe cila pjesë është më e shtrenjta?
- A duhet hash-i i modulus-it RSA të ruhet i para-llogaritur on-chain?
- Sa i madh është transaksioni (bytes) me provën dhe input-et, a futet në limitin e madhësisë së transaksionit?
- Çfarë problemesh formati u hasën (endianness, G2, key) dhe si u zgjidhën?
- Çfarë rekomandon për Hapin 2 (prototipi i portofolit)?

## Burimet

- [Lightprotocol/groth16-solana — GitHub](https://github.com/Lightprotocol/groth16-solana)
- [groth16-solana 0.2.0 — docs.rs](https://docs.rs/crate/groth16-solana/0.2.0)
- [Chainstack — Solana ZK proofs](https://docs.chainstack.com/docs/solana-zk-proofs)
- [Solana — Syscall reference](https://solana.com/docs/core/programs/syscall-reference)
- [Light Protocol — light-hasher](https://www.mintlify.com/Lightprotocol/light-protocol/api/program-libs/hasher)
- [sui-crypto — zklogin/verify.rs](https://docs.rs/sui-crypto/0.3.0/src/sui_crypto/zklogin/verify.rs.html)
- [sui-crypto — zklogin/tests.rs](https://docs.rs/crate/sui-crypto/0.3.1/source/src/zklogin/tests.rs)
- [Sui — zkLogin Integration Guide](https://docs.sui.io/sui-stack/zklogin-integration/integration-guide)
- [Sui — zkLogin demo](https://docs.sui.io/sui-stack/zklogin-integration/zklogin-demo)
- [zkSecurity — Audit of zkLogin circuits and ceremony](https://reports.zksecurity.xyz/reports/mysten-labs-zklogin)
- [Udhëzues për ceremony keys dhe prover-in lokal](https://learnblockchain.cn/article/8371)
- [Solana Compass — BN254 live në Solana](https://solanacompass.com/news/solana-activates-bn254-bls12-381-and-zk-elgamal-three-cryptographic-primitives-now-live)
