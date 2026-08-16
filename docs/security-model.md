# Security model

What this SDK guarantees, what the consuming host is responsible for, and where each guarantee is enforced and tested.

## What the SDK provides

- **Key material lifecycle primitives** (`@neotrade/wallet`): mnemonic generation (BIP-39, 128-bit), hierarchical derivation (BIP-32; trading key `m/44'/60'/0'/0/0`, proof signer `m/44'/60'/0'/0/1`, per-agent venue wallets `m/44'/60'/N'/0/0` on the hardened account axis, wallet 0 byte-identical to the legacy trading path), keystore encryption (scrypt N=2^17/r=8/p=1 KEK, AES-256-GCM, NFKC-normalized passphrase, versioned format), passphrase verification and rotation, mnemonic backup challenge, EIP-191 personal-message signing. Address derivation is implemented against @noble primitives directly — deliberately no viem here.
- **Order authorization policy** (`@neotrade/signing-gateway`): the gate every order intent passes — schema-validated structured orders only, fail-closed per-agent caps (`sizeFloorUsd` is a floor for the cap, never a waiver), market allowlists, time-limited sessions (TTL clamped to [1min, 24h]; `ttlMs: null` = explicit no-expiry), exactly-once idempotency per `(agentId, clientOrderId)` with conflict detection, and a log entry for every request.
- **Raw-key chain primitives** (`@neotrade/x402`): balance reads, Permit2, ERC-20/native transfers, x402 payment — the functions that accept a `0x…` private key parameter. Keys are parameters, never stored.

## What the consuming host is responsible for

- **Keystore persistence and in-memory custody**: where the encrypted keystore file lives (file mode, atomic writes), when it is decrypted, how long plaintext keys stay resident, and the session-expiry handling that clears them.
- **Key egress**: how raw keys from the unlocked wallet reach venue executors.
- **Cryptographic order signing**: the venue's real EIP-712 order signature is produced inside the host's venue executors (viem for Polymarket, ethers+SDK for predict.fun). The signing-gateway's `PolicyStampSigner` output (`devsig:<sha256>`) is an authorization stamp proving gateway passage, presence-checked and then discarded by submitters — it is not a cryptographic signature, and this SDK holds no signing keys.
- Approval flows, trade decision gates, RPC surfaces, and everything else in the runtime.

## Guarantees → enforcement → tests

| Guarantee | Enforced at | Tested in |
|---|---|---|
| No raw-hash signing API exists; structured orders only; unknown fields rejected | `signing-gateway/src/gateway.ts` (`OrderIntentSchema`, `.strict()` discriminated union; `signOrder` is the only entry point) | `signing-gateway/test/gateway.test.ts` ("structurally refuses anything that is not a well-formed order") |
| Per-agent limits fail closed (locked session, unknown/revoked/expired agent, market allowlist, per-order cap) | `gateway.ts` `signOrder` ordered checks, each a rejection with no fallback | `gateway.test.ts` (fail-closed, expiry, allowlist, cap, floor-not-waiver cases) |
| Exactly-once per `(agentId, clientOrderId)`; replay returns the original signature; changed content is a conflict | `gateway.ts` idempotency map + canonical `hashOrder` (fixed field order, side-aware quantity slot) | `gateway.test.ts` (replay + conflict cases) |
| Every request leaves a log entry | `gateway.ts` `reject`/sign/replay paths | `gateway.test.ts` (rejection-logging case) |
| Derivation paths are role-separated and per-wallet hardened; index range validated | `wallet/src/keys.ts` | `wallet/test/wallet.test.ts` |
| Keystore: scrypt+AES-256-GCM, versioned; wrong passphrase is indistinguishable from corrupt ciphertext (`KeystoreDecryptError` is opaque); right/wrong decided by the GCM auth tag | `wallet/src/keystore.ts` | `wallet/test/wallet.test.ts` |
| Minimum passphrase length enforced at every wrapping site | `wallet/src/wallet.ts` (`finalizeWallet`, `importWalletDirect`) + `keystore.ts` (`rewrapKeystore`) | `wallet/test/wallet.test.ts` |
| Backup verification before a wallet is usable | `wallet/src/backup.ts`, `wallet.ts` (`finalizeWallet`) | `wallet/test/wallet.test.ts` |
| EIP-191 sign/recover round-trip | `wallet/src/personal-message.ts` | `wallet/test/personal-message.test.ts` |
| Transfers/Permit2 take explicit structured parameters; no hidden key storage | `x402/src/*` | `x402/test/transfer.test.ts`, `x402/test/payment.test.ts` |

## Dependencies

Runtime dependencies across all three packages: `@noble/curves`, `@noble/hashes`, `@scure/bip32`, `@scure/bip39`, `zod`, `viem`, `@x402/evm` (pinned exact). `pnpm-lock.yaml` is committed.

Source-only ESM: `exports` point at `src/index.ts`; there is no build step and no published artifact — consumers install a tagged git commit, and pnpm pins the commit SHA in their lockfile.
