# Security model

What this SDK guarantees, what the consuming host is responsible for, and where each guarantee is enforced and tested.

## What the SDK provides

- **Key material lifecycle primitives** (`@neotrade/wallet`): mnemonic generation (BIP-39, 128-bit), hierarchical derivation (BIP-32; per-agent venue wallets `m/44'/60'/0'/0/N` on the standard EVM address axis — wallet N is byte-identical to MetaMask account #N+1 from the same mnemonic, wallet 0 is the trading key), keystore encryption (scrypt N=2^17/r=8/p=1 KEK, AES-256-GCM, NFKC-normalized passphrase, versioned format), passphrase verification and rotation, mnemonic backup challenge, EIP-191 personal-message signing. Address derivation is implemented against @noble primitives directly — deliberately no viem here.
- **Order authorization policy** (`@neotrade/signing-gateway`): the gate every order intent passes — schema-validated structured orders only, fail-closed per-agent authorization (unknown, revoked or expired agents), market allowlists, time-limited sessions (TTL clamped to [1min, 24h]; `ttlMs: null` = explicit no-expiry), exactly-once idempotency per `(agentId, clientOrderId)` with conflict detection, and a log entry for every request. Policy predicates are re-evaluated after the async signer call resolves, so a `lock()`, revocation, expiry or allowlist change landing while an order is in flight still stops it. Every one of those is decidable WITHOUT knowing what a trade means, which is the line this package holds. Memory is bounded: the audit log keeps the newest `auditLimit` entries (default 10,000; a non-positive-integer limit is a construction-time rejection, never a silent unbounding); the exactly-once ledger defaults to a process-local store and accepts an injected `OrderLedgerStore` for persistence or host-chosen bounding — its `insertIfAbsent` is the atomic exactly-once primitive (one winner per key, losers receive the winning entry; there is deliberately no bare `set`), and the gateway itself never evicts, since dropping an entry would re-open that clientOrderId for a second signature.
- **Raw-key chain primitives** (`@neotrade/x402`): balance reads, Permit2, ERC-20/native transfers, x402 payment — the functions that accept a `0x…` private key parameter. Keys are parameters, never stored.

## What the consuming host is responsible for

- **Keystore persistence and in-memory custody**: where the encrypted keystore file lives (file mode, atomic writes), when it is decrypted, how long plaintext keys stay resident, and the session-expiry handling that clears them.
- **Key egress**: how raw keys from the unlocked wallet reach venue executors.
- **Cryptographic order signing**: the venue's real EIP-712 order signature is produced inside the host's venue executors (viem for Polymarket, ethers+SDK for predict.fun). The signing-gateway's `PolicyStampSigner` output (`devsig:<sha256>`) is an authorization stamp proving gateway passage, presence-checked and then discarded by submitters — it is not a cryptographic signature, and this SDK holds no signing keys.
- **Order sizing and every money threshold** (per-order caps, exposure caps, bankroll fractions, venue minimums). This gate deliberately holds none of them: a USD threshold cannot be judged correctly without knowing what an order MEANS. A BUY adds exposure and a SELL removes it, so a single cap applied here reads as risk control in one direction and as a capital trap in the other — which is exactly what happened (2026-08-16: the gate compared a SELL's `shares * priceUsd` against the cap, and a position that appreciated past it could no longer be closed). The host owns sizing because only the host has side semantics, bankroll, venue minimum and the live book.
- Approval flows, trade decision gates, RPC surfaces, and everything else in the runtime.

## Guarantees → enforcement → tests

| Guarantee | Enforced at | Tested in |
|---|---|---|
| No raw-hash signing API exists; structured orders only; unknown fields rejected | `signing-gateway/src/gateway.ts` (`OrderIntentSchema`, `.strict()` discriminated union; `signOrder` is the only entry point) | `signing-gateway/test/gateway.test.ts` ("structurally refuses anything that is not a well-formed order") |
| Per-agent authorization fails closed (locked session, unknown/revoked/expired agent, market allowlist) | `gateway.ts` `signOrder` ordered checks, each a rejection with no fallback | `gateway.test.ts` (fail-closed, expiry, allowlist cases) |
| Policy holds across the signer await: an order in flight when `lock()`/`revokeAgent()`/expiry/allowlist-tightening lands is rejected, never recorded | `gateway.ts` `policyRejection` re-run after `await signer.signOrder`, plus a post-await ledger re-check for racing identical orders | `gateway.test.ts` ("policy re-check after the signer await" cases) |
| Order size is NOT policed here, in either direction (it is the host's; see above) | `gateway.ts` `signOrder` performs no size comparison; `AgentSigningAuthorization` carries no cap field | `gateway.test.ts` ("does not police order size in either direction", "signs a SELL whose proceeds would have blown the retired cap") |
| Exactly-once per `(agentId, clientOrderId)`; replay returns the original signature; changed content is a conflict; distinct pairs can never collide (JSON-tuple ledger key, not a delimiter join) | `gateway.ts` `OrderLedgerStore` (injectable; Map default) + canonical `hashOrder` (fixed field order, side-aware quantity slot) | `gateway.test.ts` (replay + conflict + GAT-3 collision cases) |
| Every request leaves a log entry; retention bounded at `auditLimit` (default 10,000), oldest evicted first | `gateway.ts` `record` (all `reject`/sign/replay paths) | `gateway.test.ts` (rejection-logging + bounded-memory cases) |
| Derivation paths follow the standard EVM address axis (MetaMask-compatible); index range validated | `wallet/src/keys.ts` | `wallet/test/wallet.test.ts` |
| Keystore: scrypt+AES-256-GCM, versioned; wrong passphrase is indistinguishable from corrupt ciphertext (`KeystoreDecryptError` is opaque); right/wrong decided by the GCM auth tag | `wallet/src/keystore.ts` | `wallet/test/wallet.test.ts` |
| Minimum passphrase length enforced at every wrapping site | `wallet/src/wallet.ts` (`finalizeWallet`, `importWalletDirect`) + `keystore.ts` (`rewrapKeystore`) | `wallet/test/wallet.test.ts` |
| Backup verification before a wallet is usable | `wallet/src/backup.ts`, `wallet.ts` (`finalizeWallet`) | `wallet/test/wallet.test.ts` |
| EIP-191 sign/recover round-trip | `wallet/src/personal-message.ts` | `wallet/test/personal-message.test.ts` |
| Transfers/Permit2 take explicit structured parameters; no hidden key storage | `x402/src/*` | `x402/test/transfer.test.ts`, `x402/test/payment.test.ts` |

## Dependencies

Runtime dependencies across all three packages: `@noble/curves`, `@noble/hashes`, `@scure/bip32`, `@scure/bip39`, `zod`, `viem`, `@x402/evm` (pinned exact). `pnpm-lock.yaml` is committed.

Source-only ESM: `exports` point at `src/index.ts`; there is no build step.
