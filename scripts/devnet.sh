#!/usr/bin/env bash
# Deploy në devnet dhe ekzekutim i një transaksioni real (Detyra 6).
# Thirret nga puna `devnet` në CI. Çelësi vjen VETËM nga secret-i DEVNET_DEPLOYER_KEYPAIR.
set -euo pipefail

if [ -z "${DEVNET_DEPLOYER_KEYPAIR:-}" ]; then
  echo "::error::Secret-i DEVNET_DEPLOYER_KEYPAIR nuk është vendosur."
  exit 1
fi
if [ ! -f programs/zklogin-verifier/Cargo.toml ]; then
  echo "::warning::Programi ende s'ekziston — asgjë për të bërë deploy."
  exit 0
fi

KEYFILE="$(mktemp)"
trap 'rm -f "$KEYFILE"' EXIT
printf '%s' "$DEVNET_DEPLOYER_KEYPAIR" > "$KEYFILE"

solana config set --url https://api.devnet.solana.com --keypair "$KEYFILE"
cargo build-sbf --manifest-path programs/zklogin-verifier/Cargo.toml
solana program deploy target/deploy/zklogin_verifier.so | tee /tmp/deploy.txt

# TODO(Detyra 6): dërgo transaksionin verify_full me provën nga fixtures/,
# me ComputeBudgetProgram.setComputeUnitLimit(1_400_000), dhe shkruaj
# adresën e programit + nënshkrimet në results/devnet-report.md
mkdir -p results
{ echo "## Devnet"; echo; cat /tmp/deploy.txt; } > results/devnet-report.md
