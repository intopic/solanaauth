# @solanaauth/platform

API e platformës së hostuar: aplikacionet dhe API keys, salt-i dhe prover-i me matje përdorimi, paymaster-i opsional, faturimi (Stripe + USDC/SOL). Self-host: e njëjta paketë, me mjedisin më poshtë.

```bash
npm run build -w sdk/core -w services/salt -w services/platform
NETWORK=devnet \
SALT_MASTER_SEED=$(openssl rand -hex 32) \
DASHBOARD_SESSION_SECRET=$(openssl rand -hex 32) \
DASHBOARD_GOOGLE_CLIENT_ID=<client ID i dashboard-it> \
PROVER_URL=http://localhost:8080/v1 \
PROGRAM_ID=<program ID> PAYMASTER_KEYPAIR=~/.config/solana/paymaster-devnet.json \
npm start -w services/platform
```

| Rruga | Kush | Çfarë |
|---|---|---|
| `POST /v1/salt` | SDK (`x-api-key`) | salt-i; `aud` duhet të jetë nga OAuth client ID-të e aplikacionit |
| `POST /v1/prove` | SDK | provë zkLogin përmes prover-it |
| `GET /v1/paymaster`, `POST /v1/sponsor` | SDK (`paymasterFeePayer`) | paymaster-i, nëse aplikacioni e ka aktivizuar |
| `GET /v1/templates` | kushdo | shabllonet e politikave |
| `POST /auth/google`, `/apps…` | dashboard | menaxhimi i aplikacioneve |
| `POST /webhooks/stripe` | Stripe | pagesat me kartë |

Çmimet: `config/pricing.json` (ose `PRICING_FILE`). Stripe: `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `DASHBOARD_URL`. Depozitat në Solana: `TREASURY` (adresë publike; thesari s'ka nevojë për çelës në server).

`FileStore` (JSON) mjafton për një instancë; për disa instanca zëvendësohet me një bazë të dhënash pas ndërfaqes `MemoryStore`.
