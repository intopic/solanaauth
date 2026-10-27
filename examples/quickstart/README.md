# Quickstart: hyrje me Google në një portofol Solana (devnet)

Një faqe React me rrjedhën e plotë: hyrja me Google → prova zkLogin → `create_wallet` (herën e parë)
ose `open_session` → transfertë SOL brenda limitit të sesionit → dalje me revokim on-chain.

## 1. Programi në devnet

Nëse programi është tashmë në devnet, Program ID është te `results/devnet-solanaauth.md` (main).
Përndryshe, me një çelës devnet pa vlerë reale:

```bash
solana program deploy programs/solanaauth/target/deploy/solanaauth.so --url devnet
npm ci && npm run build -w sdk/core -w services/jwk-oracle
node examples/quickstart/scripts/setup-devnet.mjs <PROGRAM_ID> ~/.config/solana/devnet.json
```

Skripti krijon `config`-un dhe regjistron çelësat aktualë të Google/Apple (timelock 0, vetëm devnet).

## 2. Salt service dhe prover

```bash
# salt (32 bytes rastësorë; në prodhim nga një secret manager, me backup)
SALT_MASTER_SEED=$(openssl rand -hex 32) ALLOWED_AUDIENCES=<GOOGLE_CLIENT_ID> \
  npm start -w services/salt

# prover (Docker, ~16 GB RAM)
cd services/prover && ./fetch-zkey.sh && ALLOWED_AUDIENCES=<GOOGLE_CLIENT_ID> docker compose up -d
```

## 3. Aplikacioni

Google Cloud Console → APIs & Services → Credentials → OAuth client ID (Web application), me
`http://localhost:5173` si Authorized JavaScript origin dhe Authorized redirect URI.

```bash
cp examples/quickstart/.env.example examples/quickstart/.env.local   # plotëso vlerat
npm run build -w sdk/core -w sdk/react
npm run dev -w examples/quickstart
```

Hap `http://localhost:5173`, hyr me Google, dërgo pak SOL devnet te adresa e vault-it, dhe provo një
transfertë. Mbi 0.5 SOL në ditë programi e refuzon me `SpendLimitExceeded`.

Në devnet çelësi i sesionit merr një airdrop të vogël për rent-in e portofolit dhe tarifën (pa
paymaster). Nëse faucet-i i devnet refuzon, dërgo 0.05 SOL te adresa e çelësit që shfaqet në gabim.
