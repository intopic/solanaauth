#!/usr/bin/env bash
# Deploy në devnet dhe ekzekutim i transaksioneve reale (Detyra 6).
# Thirret nga puna `devnet` në CI. Çelësi vjen VETËM nga secret-i DEVNET_DEPLOYER_KEYPAIR
# (një çelës devnet pa vlerë reale). Asnjë çelës mainnet.
set -euo pipefail

if [ -z "${DEVNET_DEPLOYER_KEYPAIR:-}" ]; then
  echo "::error::Secret-i DEVNET_DEPLOYER_KEYPAIR nuk është vendosur (Settings → Secrets and variables → Actions)."
  exit 1
fi

SO=programs/zklogin-verifier/target/deploy/zklogin_verifier.so
if [ ! -f "$SO" ]; then
  cargo build-sbf --manifest-path programs/zklogin-verifier/Cargo.toml
fi

KEYFILE="$(mktemp)"
trap 'rm -f "$KEYFILE"' EXIT
printf '%s' "$DEVNET_DEPLOYER_KEYPAIR" > "$KEYFILE"

solana config set --url "${DEVNET_RPC_URL:-https://api.devnet.solana.com}" --keypair "$KEYFILE" >/dev/null
echo "Deployer: $(solana address) · bilanci: $(solana balance)"

# Program ID i qëndrueshëm nëse jepet DEVNET_PROGRAM_KEYPAIR; përndryshe një adresë e re.
PROGRAM_ARGS=()
if [ -n "${DEVNET_PROGRAM_KEYPAIR:-}" ]; then
  PROGRAM_KEYFILE="$(mktemp)"
  trap 'rm -f "$KEYFILE" "$PROGRAM_KEYFILE"' EXIT
  printf '%s' "$DEVNET_PROGRAM_KEYPAIR" > "$PROGRAM_KEYFILE"
  PROGRAM_ARGS=(--program-id "$PROGRAM_KEYFILE")
fi

solana program deploy "${PROGRAM_ARGS[@]}" --output json "$SO" | tee /tmp/deploy.json
PROGRAM_ID="$(python3 -c 'import json;print(json.load(open("/tmp/deploy.json"))["programId"])')"

cargo run -q -p bench --bin export_ix -- target/devnet-ix.json
mkdir -p results
(cd scripts/devnet && npm ci --silent --no-audit --no-fund)
node scripts/devnet/run.mjs "$PROGRAM_ID" target/devnet-ix.json results/devnet-report.md

# --- solanaauth (M4): deploy, config dhe JWK-të e Google/Apple për quickstart-in ---
SA_SO=programs/solanaauth/target/deploy/solanaauth.so
if [ ! -f "$SA_SO" ]; then
  cargo build-sbf --manifest-path programs/solanaauth/Cargo.toml
fi
SA_ARGS=()
if [ -n "${DEVNET_SOLANAAUTH_PROGRAM_KEYPAIR:-}" ]; then
  SA_KEYFILE="$(mktemp)"
  printf '%s' "$DEVNET_SOLANAAUTH_PROGRAM_KEYPAIR" > "$SA_KEYFILE"
  SA_ARGS=(--program-id "$SA_KEYFILE")
fi
solana program deploy "${SA_ARGS[@]}" --output json "$SA_SO" | tee /tmp/deploy-sa.json
[ -n "${SA_KEYFILE:-}" ] && rm -f "$SA_KEYFILE"
SA_PROGRAM_ID="$(python3 -c 'import json;print(json.load(open("/tmp/deploy-sa.json"))["programId"])')"
npm ci --no-audit --no-fund
npm run build -w sdk/core -w services/jwk-oracle
node examples/quickstart/scripts/setup-devnet.mjs "$SA_PROGRAM_ID" "$KEYFILE" results/devnet-solanaauth.md
