# neotrade-wallet-sdk

The wallet and key-security core of [neotrade](https://github.com/NeoSoul-AI/neotrade), maintained as a standalone SDK: three source-only ESM TypeScript packages, no build step.

| Package | What it is |
|---|---|
| `@neotrade/wallet` | BIP-39 mnemonic generation, BIP-32 derivation on the standard EVM address axis (`m/44'/60'/0'/0/N`, wallet N ≡ MetaMask account #N+1), scrypt+AES-256-GCM encrypted keystore, mnemonic backup verification, EIP-191 personal-message signing. Deps: @noble/curves, @noble/hashes, @scure/bip32, @scure/bip39 only. |
| `@neotrade/signing-gateway` | The policy gate every order intent passes before anything downstream acts on it: schema-validated structured orders only (no raw-hash API exists), fail-closed per-agent authorization and market allowlists, time-limited sessions, idempotent authorization, an append-only log of every decision. Order SIZING is deliberately not enforced here — judging it needs trading context this package does not have, so it belongs to the consuming host. **Not a cryptographic signing boundary** — the venue's EIP-712 signature is produced by the consuming host's venue executor. Deps: zod only. |
| `@neotrade/x402` | Generic EVM chain primitives that take a raw private key: balances, Permit2, ERC-20/native transfers, x402 payment. Deps: viem, @x402/evm. |

The three packages are mutually independent — no cross-references.

See [docs/security-model.md](docs/security-model.md) for what this SDK guarantees, what the consuming host is responsible for, and where each guarantee is tested.

## Development

```bash
pnpm install
pnpm typecheck   # tsc --noEmit in every package (strict, NodeNext, noUncheckedIndexedAccess, verbatimModuleSyntax)
pnpm test        # vitest run in every package
```

`tsconfig.base.json` matches the neotrade main repo verbatim, so code moves between the two without friction.

## Releases

One repo-level tag (e.g. `v1.0.0`) versions all three packages together.
