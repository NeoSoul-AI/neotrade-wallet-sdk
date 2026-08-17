import { HDKey } from "@scure/bip32";
import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";

/**
 * Key derivation for the neotrade local wallet.
 *
 * Wallets live on the standard EVM ADDRESS axis — the same one MetaMask
 * enumerates — so wallet N is byte-identical to MetaMask account #N+1 from
 * the same mnemonic:
 *   wallet N: m/44'/60'/0'/0/N
 * The owner can import the mnemonic into MetaMask (or vice versa) and see
 * exactly the same addresses in the same order; nothing here is reachable
 * only through neotrade.
 *
 * History: wallets 1+ briefly derived on the hardened ACCOUNT axis
 * (m/44'/60'/N'/0/0), and m/44'/60'/0'/0/1 was a dedicated "proof signer"
 * role. Both are retired — wallet 0 never moved, no account-axis wallet
 * beyond 0 ever shipped to a real deployment, and the old proof-signer path
 * is exactly today's wallet 1 (the host uses that identity for legacy
 * house-account sign-in until those accounts re-key to wallet 0).
 */

/** Non-hardened derivation bound (BIP-32): indexes 0..2^31-1. */
export const MAX_WALLET_INDEX = 0x7fffffff;

/** Wallet N's venue trading key path — the standard EVM ADDRESS axis,
 * matching MetaMask account #N+1 from the same mnemonic. */
export function tradingPathForIndex(walletIndex: number): string {
  if (!Number.isInteger(walletIndex) || walletIndex < 0 || walletIndex > MAX_WALLET_INDEX) {
    throw new Error(`walletIndex must be an integer in [0, ${MAX_WALLET_INDEX}]`);
  }
  return `m/44'/60'/0'/0/${walletIndex}`;
}

/** Derives wallet N's venue trading key. */
export function deriveTradingKeyForIndex(mnemonic: string, walletIndex: number): DerivedKey {
  const path = tradingPathForIndex(walletIndex);
  const normalized = mnemonic.trim();
  if (!validateMnemonic(normalized, wordlist)) {
    throw new Error("invalid mnemonic");
  }
  const seed = mnemonicToSeedSync(normalized);
  const node = HDKey.fromMasterSeed(seed).derive(path);
  if (!node.privateKey) {
    throw new Error(`no private key at path ${path}`);
  }
  return { privateKey: hex0x(node.privateKey), address: addressFromPrivateKey(node.privateKey) };
}

export interface DerivedKey {
  privateKey: `0x${string}`;
  address: `0x${string}`;
}

/** Generates a fresh 12-word (128-bit) mnemonic. */
export function generateWalletMnemonic(): string {
  return generateMnemonic(wordlist, 128);
}

export function isValidMnemonic(mnemonic: string): boolean {
  return validateMnemonic(mnemonic.trim(), wordlist);
}

const HEX = "0123456789abcdef";

export function hex0x(bytes: Uint8Array): `0x${string}` {
  let out = "";
  for (const b of bytes) {
    out += HEX[b >> 4]! + HEX[b & 0x0f]!;
  }
  return `0x${out}`;
}

/**
 * EVM address derivation without viem (venue-isolation invariant: viem is
 * reachable only through @neotrade/executor-polymarket). Standard recipe:
 * uncompressed secp256k1 public key → keccak256 → last 20 bytes → EIP-55
 * checksum casing. @noble/curves + @noble/hashes are already the audited
 * primitives underneath @scure/bip32 — no new supply-chain surface.
 * Pinned against the well-known anvil vectors in test/wallet.test.ts.
 *
 * Takes an UNCOMPRESSED (0x04-prefixed, 65-byte) secp256k1 public key.
 * Exported for personal-message.ts's recover path; not in the package barrel.
 */
export function addressFromUncompressedPublicKey(uncompressed: Uint8Array): `0x${string}` {
  const hash = keccak_256(uncompressed.slice(1));
  const lower = hex0x(hash.slice(-20)).slice(2);
  // EIP-55: uppercase every hex digit whose corresponding nibble in
  // keccak256(lowercase-ascii-address) is >= 8.
  const check = keccak_256(new TextEncoder().encode(lower));
  let out = "";
  for (let i = 0; i < lower.length; i++) {
    const nibble = i % 2 === 0 ? check[i >> 1]! >> 4 : check[i >> 1]! & 0x0f;
    out += nibble >= 8 ? lower[i]!.toUpperCase() : lower[i]!;
  }
  return `0x${out}`;
}

function addressFromPrivateKey(privateKey: Uint8Array): `0x${string}` {
  return addressFromUncompressedPublicKey(secp256k1.getPublicKey(privateKey, false));
}

/** Derives every requested venue-wallet key. `wallets` always contains
 * index 0 (≡ trading — the same object). The owner key is never derived
 * here. */
export function deriveWalletKeys(
  mnemonic: string,
  walletIndexes: readonly number[] = [],
): { trading: DerivedKey; wallets: Map<number, DerivedKey> } {
  const trading = deriveTradingKeyForIndex(mnemonic, 0);
  const wallets = new Map<number, DerivedKey>([[0, trading]]);
  for (const index of walletIndexes) {
    if (!wallets.has(index)) {
      wallets.set(index, deriveTradingKeyForIndex(mnemonic, index));
    }
  }
  return { trading, wallets };
}
