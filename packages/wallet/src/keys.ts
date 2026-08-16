import { HDKey } from "@scure/bip32";
import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";

/**
 * Key derivation for the neotrade local wallet.
 *
 * Three-key separation (spec §wallet): the owner main wallet never enters
 * neotrade. neotrade holds two derived keys, and even in the MVP they are at
 * least logically separated by derivation path so that a leaked proof key
 * cannot move funds:
 *   - trading key  (m/44'/60'/0'/0/0) — signs CLOB orders only
 *   - proof signer (m/44'/60'/0'/0/1) — signs observations / proofs only
 * Both are derived from one mnemonic but live at different paths / key ids.
 */

export type Role = "trading" | "proof";

const DERIVATION_PATH: Record<Role, string> = {
  trading: "m/44'/60'/0'/0/0",
  proof: "m/44'/60'/0'/0/1",
};

/** Hardened-derivation bound (BIP-32): indexes 0..2^31-1. */
export const MAX_WALLET_INDEX = 0x7fffffff;

/** Wallet N's venue trading key path — the hardened BIP-44 ACCOUNT axis.
 * Wallet 0 is byte-identical to the legacy trading path. */
export function tradingPathForIndex(walletIndex: number): string {
  if (!Number.isInteger(walletIndex) || walletIndex < 0 || walletIndex > MAX_WALLET_INDEX) {
    throw new Error(`walletIndex must be an integer in [0, ${MAX_WALLET_INDEX}]`);
  }
  return `m/44'/60'/${walletIndex}'/0/0`;
}

/** Derives wallet N's venue trading key. Index 0 ≡ deriveKey(mnemonic, "trading"). */
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
  return { role: "trading", privateKey: hex0x(node.privateKey), address: addressFromPrivateKey(node.privateKey) };
}

export interface DerivedKey {
  role: Role;
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

/** Derives one role's key from a mnemonic. Throws on an invalid mnemonic. */
export function deriveKey(mnemonic: string, role: Role): DerivedKey {
  const normalized = mnemonic.trim();
  if (!validateMnemonic(normalized, wordlist)) {
    throw new Error("invalid mnemonic");
  }
  const seed = mnemonicToSeedSync(normalized);
  const node = HDKey.fromMasterSeed(seed).derive(DERIVATION_PATH[role]);
  if (!node.privateKey) {
    throw new Error(`no private key at path ${DERIVATION_PATH[role]}`);
  }
  const privateKey = hex0x(node.privateKey);
  return { role, privateKey, address: addressFromPrivateKey(node.privateKey) };
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

/** Derives both fixed neotrade keys plus every requested venue-wallet key.
 * `wallets` always contains index 0 (≡ trading). The owner key is never
 * derived here. */
export function deriveWalletKeys(
  mnemonic: string,
  walletIndexes: readonly number[] = [],
): { trading: DerivedKey; proof: DerivedKey; wallets: Map<number, DerivedKey> } {
  const trading = deriveKey(mnemonic, "trading");
  const wallets = new Map<number, DerivedKey>([[0, trading]]);
  for (const index of walletIndexes) {
    if (!wallets.has(index)) {
      wallets.set(index, deriveTradingKeyForIndex(mnemonic, index));
    }
  }
  return { trading, proof: deriveKey(mnemonic, "proof"), wallets };
}
