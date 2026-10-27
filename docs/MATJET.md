# Matjet

Pranojmë vetëm numrat që prodhon CI dhe i publikon te [`results/`](../results/) në `main`. Ky
dokument tregon ku është secila matje dhe si prodhohet.

| Matja | Skedari në `results/` | Prodhohet nga |
|---|---|---|
| CU e verifikimit Groth16 + Poseidon (Hapi 1) | `cu-report.{md,json}` | `bench/tests/cu_report.rs` |
| CU dhe madhësia e tx për çdo instruksion, testet negative (M2) | `solanaauth-cu.{md,json}` | `bench/tests/solanaauth.rs` |
| CU e passkey, pragut, rikuperimit (M3) | `solanaauth-m3-cu.{md,json}` | `bench/tests/solanaauth_m3.rs` |
| Madhësia dhe rent-i i llogarive (PDA) | `solanaauth-accounts.{md,json}` | `bench/tests/solanaauth.rs` (llogaritë e skenarit) |
| Devnet: deploy, `config`, JWK, transaksione reale | `devnet-report.md`, `devnet-solanaauth.md` | `scripts/devnet.sh` (CI, kur ka secret devnet) |
| Koha e provës zkLogin p50/p95 | jo në CI (shih më poshtë) | `scripts/prover-bench.mjs` |

## Llogaritë dhe rent-i

Numrat e fundit janë te `results/solanaauth-accounts.md`. Përmbledhja e madhësive (fikse, nga
`programs/solanaauth/src/state.rs`):

| Llogaria | Bytes | Kush paguan | Kthehet? |
|---|---:|---|---|
| `Config` | 96 | deployer-i, një herë | jo |
| `Jwk` | 192 | oracle/admini, një për (iss, kid) | jo |
| `Wallet` | 416 | përdoruesi, aplikacioni ose paymaster-i, një herë | jo |
| Vault | 0 | (mban SOL-in e përdoruesit) | është vetë portofoli |
| `Session` | 640 | si `Wallet`, një për pajisje/agjent | po, te vault-i me `close_session` pas skadimit/revokimit |

Hyrja e parë e një përdoruesi kushton rent-in e `Wallet` + `Session` + tarifën e tx-it.

## Koha e provës (p50/p95)

Prova kërkon një JWT të freskët të Google/Apple, me nonce-in e një çelësi ephemeral të ri. Një JWT
e tillë merret vetëm kur një person hyn në shfletues, prandaj kjo matje s'mund të ekzekutohet në CI
pa ekspozuar kredenciale (DIZAJNI D36). Skripti:

```bash
npm run build -w sdk/core
node scripts/prover-bench.mjs --prover http://localhost:8080/v1 --client-id <GOOGLE_CLIENT_ID> --n 20
```

hap hyrjen me Google në shfletues (loopback `127.0.0.1`), pastaj thërret prover-in `n` herë me të
njëjtën JWT dhe printon p50, p95, min, max. Numrat e prodhuar kështu printohen në terminal dhe
**nuk** shkruhen në `results/`. Kur prover-i i hostuar të jetë gati, matja bëhet nga një makinë me
të njëjtat burime si prodhimi dhe publikohet me burimin e saj.
