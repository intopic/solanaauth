# Self-host: programi, salt-i, prover-i dhe platforma pa shërbimet tona

Çdo pjesë e solanaauth ngrihet nga ky repo. Asnjë pjesë s'ka nevojë për ne: programi është
on-chain, prover-i dhe salt-i janë shërbime pa gjendje, platforma (paymaster, dashboard) është
opsionale.

| Pjesa | Domosdoshme | Burime | Sekrete |
|---|---|---|---|
| Programi `solanaauth` | po | ~90 KB `.so`; rent-i i programit (~1.3 SOL, edhe në devnet) | upgrade authority (devnet: çelës pa vlerë) |
| Salt service | po | i vogël | `SALT_MASTER_SEED` (32 bytes, me backup) |
| Prover zkLogin | po | ~16 GB RAM, 4 vCPU; zkey ~600 MB | asnjë |
| Oracle i JWK-ve | po (cron) | i vogël | çelësi i oracle-it (vetëm propozon/aplikon JWK) |
| Platforma + dashboard | jo | i vogël | sesioni i dashboard-it, Stripe, çelësi i paymaster-it |

## Programi

```bash
cargo build-sbf --manifest-path programs/solanaauth/Cargo.toml              # devnet
cargo build-sbf --manifest-path programs/solanaauth/Cargo.toml --features mainnet  # ndalon VK-në test

solana-keygen new -o ~/.config/solana/devnet.json      # vetëm devnet, pa vlerë reale
solana airdrop 2 --url devnet -k ~/.config/solana/devnet.json
solana program deploy programs/solanaauth/target/deploy/solanaauth.so --url devnet -k ~/.config/solana/devnet.json

npm ci && npm run build -w sdk/core -w services/jwk-oracle
node examples/quickstart/scripts/setup-devnet.mjs <PROGRAM_ID> ~/.config/solana/devnet.json
```

`setup-devnet.mjs` krijon `config`-un (admin = oracle = deployer-i, timelock 0, VK test e lejuar:
vetëm devnet, D20) dhe regjistron çelësat aktualë të Google dhe Apple. `scripts/devnet.sh` bën të
njëjtën gjë në CI dhe ekzekuton transaksione reale.

**Mainnet** (pas auditimit): build me `--features mainnet`; upgrade authority në multisig me
timelock; `init_config` me `jwk_timelock_secs ≥ 86400`, `allow_test_vk = false`, oracle i ndarë
nga admini. Shih [`SECURITY.md`](SECURITY.md) §3.1–3.2.

## Oracle i JWK-ve

```bash
RPC_URL=<RPC_URL> PROGRAM_ID=<PROGRAM_ID> ORACLE_KEYPAIR=<oracle.json> node services/jwk-oracle/dist/cli.js
```

Krahason JWKS publike të Google/Apple me registry-në on-chain, propozon çelësat e rinj dhe i
aplikon pas timelock-ut, çdo `INTERVAL_SECS` (parazgjedhja 600; `--once` për cron). Nuk revokon (D19).

## Salt service

```bash
npm run build -w services/salt
SALT_MASTER_SEED=$(openssl rand -hex 32) ALLOWED_AUDIENCES=<client ID-të, me presje> PORT=8787 \
  npm start -w services/salt
# ose: docker build -f services/salt/Dockerfile -t solanaauth-salt .
```

`POST /salt { jwt }` → `{ salt }`. Salt = HKDF-SHA256 nga seed-i, `iss`, `aud`, `sub` (D18).
Seed-i ruhet në një secret manager me backup; humbja e tij ndryshon identitetin zk të çdo
përdoruesi (fondet rikuperohen me passkey).

## Prover

```bash
cd services/prover
./fetch-zkey.sh                                   # zkLogin-main.zkey; krahaso sha256 me ceremoninë
ALLOWED_AUDIENCES=<client ID-të> docker compose up -d
curl -s localhost:8080/health
```

Imazhet e Mysten (`mysten/zklogin:prover-stable`, `prover-fe-stable`) pas proxy-t tonë (CORS,
kufizim kërkesash, `aud` i lejuar, `maxEpoch` i kufizuar, D22). Koha e provës matet me
`scripts/prover-bench.mjs` ([`MATJET.md`](MATJET.md)).

## Platforma (opsionale)

Paymaster, API keys, matja e përdorimit, faturimi dhe dashboard-i: [`services/platform/README.md`](../services/platform/README.md).
Pa platformën, SDK-ja flet direkt me salt-in dhe prover-in tënd, dhe tarifat i paguan përdoruesi,
serveri yt ose Kora ([`SHEMBUJ.md`](SHEMBUJ.md#fee-payer)).

## Faqja e portofolit

```bash
VITE_PROGRAM_ID=<PROGRAM_ID> VITE_PROVER_URL=... VITE_SALT_URL=... VITE_GOOGLE_CLIENT_ID=... \
  npm run build -w apps/wallet   # apps/wallet/dist → çdo hosting statik
```

Përdoruesi sheh asetet, tërheq, revokon sesionet dhe menaxhon passkey-t pa aplikacionin origjinal.
