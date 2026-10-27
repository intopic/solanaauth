# Audit remediation and reproducible checks

The architecture remains a client wallet with delegated sessions and optional application policies.
The platform does not become a trading router. OAuth identities authorize sessions; agents receive
the session credentials and only the permissions granted by the wallet.

| Area | Change | Regression evidence |
| --- | --- | --- |
| CI | Build/test jobs run without devnet secrets; required job rejects skipped dependencies | Linux SBF, Rust reference/bench, JS integration, Windows, Docker jobs |
| Token authority | Final-state invariant scans newly created vault token accounts too | `sdk/core/test/token-invariants.test.mjs`: create+approve rollback, valid ATA creation, existing-account approval rejection |
| Paymaster | Shared per-app queue, durable reservations, transaction-message idempotence, atomic settlement | Concurrent quota/deposit requests, retry across restart, duplicate settlement tests |
| Confirmation | Confirmed instruction errors reject; logout retains credentials until revocation succeeds | RPC adapter failure and BrowserLogin retry tests |
| Attribution | Reject mixed-wallet batches; count every sponsored account operation | Batch tests |
| Fee abuse | Validate ComputeBudget instructions, duplicates, price and total priority fee | x402 negative and positive payment tests |
| Apple | Supported `code id_token` browser response; unsupported CLI loopback rejected early | URL and agent tests; live provider login still requires a registered Services ID and HTTPS callback |
| Wallet management | Attach passkey to existing OAuth state; separate case-insensitive filenames | Windows build and wallet-management regression tests |
| Plans | Expired paid plans use free quotas and pricing | Exact-boundary expiry tests |
| Serialization | Reject signed/unsigned overflow and unsafe JS integers | Numeric boundary tests |
| JWK registry | Renew expired/near-expiry keys; compare modulus for reused kid; retain admin revocation | Oracle planning tests and existing on-chain oracle integration |
| Wallet Standard | Session signatures use `solanaauth:session.signMessage`; import Buffer explicitly | Signature/account checks and v0 decoding without global Buffer |
| Amounts | Preserve zero-decimal amounts and reject malformed/overflowing amounts | Wallet utility tests |
| Services | Correct prover ESM build; bound rate-limit state; trust forwarded IP only from configured proxies | Shipped Docker image smoke tests and real HTTP spoofing tests |
| Portability | URL-to-filesystem conversion; newline-independent VK comparison | Windows build/tests and Rust VK check |

Run `npm ci`, `npm run build`, then `npm run test:security` for the portable regressions.
`npm test` additionally requires Linux/macOS LiteSVM and the current SBF artifacts. CI builds
those artifacts from the same checkout; it does not reuse an older deployed binary.

`FileStore` supports **one process/one store instance**. Multiple replicas require a transactional
database implementing the same reservation and settlement semantics. Transport failures retain
the reservation because a transaction may already have landed; retry the identical transaction.
Do not release an unresolved reservation based only on a network timeout. The RPC adapter bills
confirmed payer balance changes; custom adapters without `spent` use simulated cost.

Behind a reverse proxy, set `TRUSTED_PROXIES` to the actual immediate peer IPs and configure that
proxy to overwrite incoming `X-Forwarded-For`. Unconfigured forwarding headers are ignored.
For finite JWK validity, configure `renewBeforeSecs` to cover the registry timelock and polling
interval. An operator must still monitor oracle availability and top up any optional paymaster.

Live Google/Apple login and devnet deployment need application configuration/credentials and
are separate from deterministic CI. These changes are regression fixes, not an independent
external security audit or a production-readiness certification.
