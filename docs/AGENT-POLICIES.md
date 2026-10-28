# Optional agent policies (V2)

The client wallet approves the agent public key and the exact policy in an owner-signed Solana
transaction. The agent never receives the owner's ephemeral OAuth key, JWT, salt or proof.
After approval it signs `execute` using its own execution key. The program enforces the policy.
The app can use its own connection and submission flow; our hosted services are not required
for each trade. No new runtime dependencies were added for this feature.

```ts
const policy = {
  version: 2 as const,
  expiresIn: 86400,
  // allowedPrograms omitted: any program except the protocol's forbidden programs.
  // restrictAssets defaults to false: unlisted assets remain unrestricted.
  limits: [{ mint: USDC, amount: 300_000_000n, periodSecs: 86400, maxPerExecute: 50_000_000n }],
  frequency: { maxExecutions: 20, periodSecs: 3600 },
};
```

Every business rule is optional. `version: 2, expiresIn: 86400` alone enables unrestricted
programs/assets within the lifetime of the authorization. Protocol integrity protections always
apply. The owner's login proof still has a cryptographic expiry; it is not an unlimited key.

| Configuration | Meaning |
| --- | --- |
| `allowedPrograms` omitted | Programs unrestricted, except loaders and solanaauth itself |
| `allowedPrograms: []` | No programs permitted |
| `limits` omitted | No per-asset constraints |
| `restrictAssets: true` | Only mints listed in `limits` may be debited |
| Limit with only `mint` | Allow this asset without an amount cap when restrictAssets is true |
| `amount` + positive `periodSecs` | Cumulative measured debit cap, resetting at the first execute after the window expires |
| `maxPerExecute` | Independent maximum measured debit of that mint in one execute |
| Amount or maxPerExecute equal to zero | No debit allowed for this configured rule |
| `frequency` omitted | No execution frequency restriction |
| `maxExecutions: 0` | No execute calls allowed |

Per-asset constraints combine with AND. An omitted constraint never silently becomes zero.
Amount values use token base units, not USD valuation. Limits measure debit from tracked vault
account balances; they are not turnover, slippage, PnL or price guarantees. The per-execute cap
applies to one `execute` call, not an entire transaction containing multiple execute calls.
Frequency counts successful execute calls, not inner instructions or individual trades; a batch
inside one execute counts once. Failed transactions roll back counters and transfers atomically.
Network fees may still be paid. Quotas use fixed windows, not sliding windows, and are per session.

## Owner approval and agent connection

Agent side:

```ts
const result = await loginAgent({ config, policy, authorize: async request => {
  // Send only request.sessionKey (public) and policyToJson(request.policy) to the client wallet.
  // Return its PUBLIC receipt after the owner approves and the transaction confirms.
  return requestApprovalFromClientWallet(request);
} });
```

Client wallet side:

```ts
const { transaction, authorization, created } = await auth.authorizeAgent(
  jwt, pendingLogin, approvedPolicy, agentPublicKey, feePayerPublicKey,
);
// Owner signature is already attached. Add the payer signature without changing the message.
const signature = await submitAndConfirm(transaction);
// Return only { wallet: authorization.wallet, signature, created } to the agent.
```

`loginAgent` validates the program-owned V2 session, execution key, wallet, policy hash, revocation
and expiry before returning an AgentWallet. It no longer opens an OAuth callback inside the
agent process. To use proof inputs already fetched by the owner wallet, use `buildDelegation`.
`buildLogin` / BrowserLogin create a distinct delegated execution key automatically.

The wallet app includes **Autorizo agjent**: paste the public request, review all permissions,
explicitly approve, then copy the public receipt. `examples/agent-x402/agent.mjs` writes
`agent-session.json.request.json` and waits for `agent-session.json.approval.json`. Only the
final `agent-session.json` contains the agent's own execution secret and must remain private.
Delete an old public approval reply before requesting a fresh agent key.

## Compatibility and deployment

V1 instruction encodings and 640-byte sessions keep their existing deny-by-default semantics.
The new account is 728 bytes (the same 640-byte prefix plus rules/counters/policy hash). The SDK
discovers and decodes both. High-level login creates V2 delegations; existing explicit V1 policy
objects are promoted while preserving their asset restrictions. Explicit V2 objects default to
unrestricted unlisted assets. Never export a legacy OAuth-bound V1 key to an untrusted agent:
those credentials can represent owner authority. AgentWallet rejects legacy sessions; owners
must revoke them and approve a new V2 execution key. There is no automatic conversion of old keys.

Deploy the updated program before using the updated SDK. The old deployed binary cannot parse
V2 policies. No deployment is performed by adding this code. A public-key request does not itself
authorize anything; the owner must review it in a trusted client wallet and sign on-chain.

Deferred: shared budgets across sessions, minimum reserves, destination restrictions, generalized
token passkey thresholds, universal fee budgets, oracle/price/PnL rules. This is not the final
external security audit or a claim that the entire live product acceptance checklist has passed.
