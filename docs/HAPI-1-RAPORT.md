# Hapi 1 — Raporti: verifikimi i zkLogin në Solana

**Vendimi: GO.** Një provë zkLogin e Sui-t, nga një JWT e vërtetë Google dhe e verifikuar me
key-n mainnet të ceremonisë, pranohet nga një program Solana. `verify_full` (rillogaritja e
input-it publik me Poseidon + Groth16) kushton **110,428 CU**, rreth 8% e limitit 1.4M CU,
dhe transaksioni është **954 bytes** (limiti 1232). Verifikimi + regjistrimi i sesionit futen lehtë
në një transaksion.

Burimi i numrave: GitHub Actions, puna `bench`
([run 40433569053](https://github.com/intopic/solanaauth/actions/runs/40433569053)), LiteSVM 0.17
me feature set-in e Agave 4.x, programi i ndërtuar me `solana-cli 4.3.2`. Tabela e plotë dhe e
përditësuar: [`results/cu-report.md`](../results/cu-report.md). Numrat e devnet-it shtohen te
[`results/devnet-report.md`](../results/devnet-report.md) pas punës manuale `devnet`.

## Matjet (Google, mainnet, qarku v1)

| Matja | CU |
|---|---:|
| `verify_proof` (vetëm Groth16, input-i publik jepet gati) | 78,368 |
| Poseidon: header (8 input-e) | 8,328 |
| Poseidon: iss (8 input-e) | 7,844 |
| Poseidon: modulus RSA 2048-bit (9 input-e) | 11,083 |
| Poseidon: `all_inputs_hash` (8 input-e) | 4,706 |
| **`verify_full` gjithsej** | **110,428** |
| `verify_full` me modulus të para-llogaritur (JWK registry) | 99,356 |

Prova dev v1 jep praktikisht të njëjtat numra (110,280). Testet negative: **28/28 të refuzuara**
(1 byte i ndryshuar në A, B, C, në input-in publik, në çelësin ephemeral, `max_epoch`,
`address_seed`, iss, `index_mod_4`, header, modulus, si dhe verifying key i gabuar).

## Përgjigjet e pyetjeve

**Sa kushton saktësisht `verify_full`, dhe cila pjesë është më e shtrenjta?** 110,428 CU. Groth16
është ~71% (78.4k: MSM me 1 input + pairing me 4 çifte); katër thirrjet Poseidon janë ~32k gjithsej.

**A duhet ruajtur hash-i i modulus-it RSA i para-llogaritur?** Për kosto, jo domosdoshmërisht: kursen
vetëm ~11k CU dhe 224 bytes. Por **po** për arsye të tjera: (1) programi gjithsesi duhet të dijë që
modulus-i është një JWK aktive e Google-it, që kërkon një registry on-chain; (2) qarku **v2**
(RSA deri në 8192-bit) e bën të detyrueshëm: modulus-i ndahet në 34 copa dhe Sui përdor Poseidon me
16 input-e, ndërsa `sol_poseidon` pranon deri në 12. Edhe transaksioni me modulus 8192-bit (1681 bytes)
nuk futet. Me modulus të para-llogaritur, v2 kushton 98,427 CU.

**Sa i madh është transaksioni?** 954 bytes me modulus-in e plotë (instruksioni 744 bytes: provë 256,
input-e ~230, modulus 256), 730 bytes me hash të para-llogaritur. Mbeten ~280–500 bytes për
instruksionin e regjistrimit të sesionit.

**Çfarë problemesh formati u hasën dhe si u zgjidhën?** Të gjitha u kapën nga testet në host para
SVM-it (`bench/tests/host.rs`):
- *Endianness:* gjithçka kalon si 32 bytes big endian; vlerat decimal të circom konvertohen me
  `BigUint::to_bytes_be`.
- *G2:* snarkjs/arkworks japin `[c0, c1]`, syscall-et alt_bn128 presin `c1 || c0` (EIP-197). Për key-n
  e bën gjeneratori i `groth16-solana`, për provën `bench::proof_bytes`.
- *Negimi i A:* bëhet on-chain me `negate_g1_be`, kështu klienti dërgon provën ashtu siç e jep prover-i.
- *Verifying key:* `zkLogin-main` dhe `zkLogin-test` merren direkt nga repo-ja e ceremonisë; testi
  negativ "key tjetër" konfirmon që key-t nuk ngatërrohen.
- *Poseidon:* paketimi është byte-aligned (copa 31-byte nga e djathta; vargjet mbushen djathtas,
  modulus-i majtas). `all_inputs_hash` del bit për bit i njëjtë me fastcrypto, si në host ashtu edhe
  brenda SVM-it (`compute_inputs_hash` + `sol_log_data`).
- `groth16-solana` 0.2.0 në crates.io është i vjetër dhe pa gjeneratorin e key-ve; përdorëm versionin
  në GitHub (rev `ac9d959`), që duhet të pin-ohet ose të publikohet para prodhimit.

## Çfarë mbetet jashtë këtij testi

- Transaksionet në devnet (2–3 nënshkrime) presin secret-in `DEVNET_DEPLOYER_KEYPAIR`; skripti është gati.
- Bonusi (JWT nga një OAuth client yni + prover-dev) nuk u bë; fixture-i i Google-it është JWT e
  vërtetë, por nga client-i i Sui-t.
- Licenca e qarqeve dhe e key-ve të zkLogin duhet kontrolluar para prodhimit.

## Rekomandimi për Hapin 2 (prototipi i portofolit)

1. Një instruksion `open_session` = `verify_full` + krijimi i PDA-së së sesionit (çelësi ephemeral,
   `max_epoch` → skadimi, `address_seed` → adresa), në një transaksion: buxheti ~110k + ~10k CU.
2. Një llogari **JWK registry** (iss, kid → hash i modulus-it + numri i bit-eve), e përditësuar nga
   një oracle/multisig; `verify_full` lexon hash-in prej saj. Kjo e bën programin gati edhe për v2.
3. Lidhja e `max_epoch` me kohën e Solana-s (p.sh. timestamp në nonce) duhet përcaktuar: në Sui
   është epoka e Sui-t, ndërsa këtu duhet një kuptim i ri.
4. Transaksionet e sesionit kontrollojnë vetëm Ed25519 të çelësit ephemeral (precompile, i lirë).
