import { describe, expect, it } from "vitest";
import {
  buildBackupChallenge,
  createWallet,
  decryptSecret,
  deriveWalletKeys,
  deriveTradingKeyForIndex,
  encryptSecret,
  finalizeWallet,
  generateWalletMnemonic,
  importWallet,
  importWalletDirect,
  isValidMnemonic,
  KeystoreDecryptError,
  rewrapKeystore,
  tradingPathForIndex,
  unlockWallet,
  verifyBackup,
  verifyPassphrase,
} from "../src/index.js";

// A fixed valid 24-word test mnemonic (all "abandon" + checksum "art").
const TEST_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

/** A deterministic pick() cycling through fixed values for testing. */
function fixedPicks(values: number[]): () => number {
  let i = 0;
  return () => values[i++ % values.length]!;
}

describe("key derivation", () => {
  it("generates a valid 12-word mnemonic", () => {
    const mnemonic = generateWalletMnemonic();
    expect(mnemonic.split(" ")).toHaveLength(12);
    expect(isValidMnemonic(mnemonic)).toBe(true);
  });

  it("rejects an invalid mnemonic", () => {
    expect(isValidMnemonic("not a real mnemonic phrase")).toBe(false);
    expect(() => deriveTradingKeyForIndex("not a real mnemonic", 0)).toThrow("invalid mnemonic");
  });

  it("derives distinct keys per wallet index from one mnemonic", () => {
    const { trading, wallets } = deriveWalletKeys(TEST_MNEMONIC, [1]);
    const w1 = wallets.get(1)!;
    expect(trading.privateKey).not.toBe(w1.privateKey);
    expect(trading.address).not.toBe(w1.address);
    // Address correctness against standard EVM derivation is pinned by the
    // anvil known-answer vectors below; here just assert EIP-55 shape.
    expect(trading.address).toMatch(/^0x[0-9a-fA-F]{40}$/);
  });

  it("is deterministic — same mnemonic yields the same keys", () => {
    expect(deriveWalletKeys(TEST_MNEMONIC)).toEqual(deriveWalletKeys(TEST_MNEMONIC));
  });
});

describe("backup verification", () => {
  it("builds a challenge of distinct sorted positions", () => {
    const challenge = buildBackupChallenge(TEST_MNEMONIC, 4, fixedPicks([0.1, 0.5, 0.9, 0.3, 0.1]));
    expect(challenge.positions).toHaveLength(4);
    expect([...challenge.positions].sort((a, b) => a - b)).toEqual(challenge.positions);
    expect(new Set(challenge.positions).size).toBe(4);
    for (const p of challenge.positions) {
      expect(p).toBeGreaterThanOrEqual(1);
      expect(p).toBeLessThanOrEqual(24);
    }
  });

  it("rejects an out-of-range count", () => {
    expect(() => buildBackupChallenge(TEST_MNEMONIC, 0, fixedPicks([0]))).toThrow();
    expect(() => buildBackupChallenge(TEST_MNEMONIC, 25, fixedPicks([0]))).toThrow();
  });

  it("accepts correct answers (case-insensitive) and rejects wrong ones", () => {
    const words = TEST_MNEMONIC.split(" ");
    const challenge = { positions: [1, 24] };
    // words[0] = "abandon", words[23] = "art"
    expect(verifyBackup(TEST_MNEMONIC, challenge, { 1: "ABANDON", 24: " art " })).toBe(true);
    expect(verifyBackup(TEST_MNEMONIC, challenge, { 1: "abandon", 24: "wrong" })).toBe(false);
    // A missing answer fails.
    expect(verifyBackup(TEST_MNEMONIC, challenge, { 1: words[0]! })).toBe(false);
  });
});

describe("keystore encryption", () => {
  it("round-trips a secret through encrypt/decrypt", () => {
    const keystore = encryptSecret(TEST_MNEMONIC, "correct horse battery staple");
    expect(keystore.version).toBe(1);
    expect(keystore.ciphertext).not.toContain("abandon"); // not plaintext
    expect(decryptSecret(keystore, "correct horse battery staple")).toBe(TEST_MNEMONIC);
  });

  it("rejects a wrong passphrase opaquely", () => {
    const keystore = encryptSecret(TEST_MNEMONIC, "right");
    expect(() => decryptSecret(keystore, "wrong")).toThrow(KeystoreDecryptError);
    expect(verifyPassphrase(keystore, "right")).toBe(true);
    expect(verifyPassphrase(keystore, "wrong")).toBe(false);
  });

  it("detects tampering via the GCM auth tag", () => {
    const keystore = encryptSecret(TEST_MNEMONIC, "pw");
    const tampered = { ...keystore, ciphertext: Buffer.from("tampered").toString("base64") };
    expect(() => decryptSecret(tampered, "pw")).toThrow(KeystoreDecryptError);
  });

  it("produces a distinct salt/iv per encryption", () => {
    const a = encryptSecret(TEST_MNEMONIC, "pw");
    const b = encryptSecret(TEST_MNEMONIC, "pw");
    expect(a.salt).not.toBe(b.salt);
    expect(a.iv).not.toBe(b.iv);
    expect(a.ciphertext).not.toBe(b.ciphertext);
  });
});

describe("wallet lifecycle", () => {
  it("create → finalize → unlock derives the same keys", () => {
    const created = createWallet();
    expect(isValidMnemonic(created.mnemonic)).toBe(true);

    // Answer the backup challenge correctly.
    const words = created.mnemonic.split(" ");
    const answers = Object.fromEntries(created.challenge.positions.map((p) => [p, words[p - 1]!]));
    const keystore = finalizeWallet(created, answers, "a-strong-passphrase");

    const unlocked = unlockWallet(keystore, "a-strong-passphrase");
    expect(unlocked.trading.address).toBe(deriveTradingKeyForIndex(created.mnemonic, 0).address);
  });

  it("refuses to finalize when the backup verification fails", () => {
    const created = createWallet();
    const wrong = Object.fromEntries(created.challenge.positions.map((p) => [p, "wrong"]));
    expect(() => finalizeWallet(created, wrong, "a-strong-passphrase")).toThrow(
      "backup verification failed",
    );
  });

  it("refuses a too-short passphrase even with a correct backup", () => {
    const created = createWallet();
    const words = created.mnemonic.split(" ");
    const answers = Object.fromEntries(created.challenge.positions.map((p) => [p, words[p - 1]!]));
    expect(() => finalizeWallet(created, answers, "short")).toThrow("at least 8 characters");
  });

  it("import validates the mnemonic and gates on backup", () => {
    const imported = importWallet(TEST_MNEMONIC);
    const words = TEST_MNEMONIC.split(" ");
    const answers = Object.fromEntries(imported.challenge.positions.map((p) => [p, words[p - 1]!]));
    const keystore = finalizeWallet(imported, answers, "passphrase123");
    const unlocked = unlockWallet(keystore, "passphrase123");
    expect(unlocked.trading.address).toBe(deriveTradingKeyForIndex(TEST_MNEMONIC, 0).address);

    expect(() => importWallet("clearly not valid words here")).toThrow("invalid mnemonic");
  });
});

describe("known-answer vectors (BIP-44 address axis + EIP-55)", () => {
  // The universally-known anvil/hardhat dev mnemonic. These vectors pin the
  // derivation paths, the private-key hex encoding, AND the EIP-55 checksum
  // casing of the address — so the address implementation can never silently
  // change (walletStatus exposes these addresses; operators compare them
  // against venue/deposit views by eye and by string equality). Wallet N is
  // MetaMask account #N+1 by construction; these anvil vectors ARE the
  // MetaMask address axis.
  const ANVIL =
    "test test test test test test test test test test test junk";
  it("wallet 0 (m/44'/60'/0'/0/0) matches anvil/MetaMask account #0", () => {
    const k = deriveTradingKeyForIndex(ANVIL, 0);
    expect(k.privateKey).toBe(
      "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    );
    expect(k.address).toBe("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
  });
  it("wallet 1 (m/44'/60'/0'/0/1) matches anvil/MetaMask account #1", () => {
    const k = deriveTradingKeyForIndex(ANVIL, 1);
    expect(k.privateKey).toBe(
      "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    );
    expect(k.address).toBe("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
  });
  it("wallet 2 (m/44'/60'/0'/0/2) matches anvil/MetaMask account #2", () => {
    const k = deriveTradingKeyForIndex(ANVIL, 2);
    expect(k.privateKey).toBe(
      "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    );
    expect(k.address).toBe("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC");
  });
});

describe("importWalletDirect (no backup challenge)", () => {
  const VALID =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  it("encrypts a valid mnemonic straight to a keystore, no challenge", () => {
    const ks = importWalletDirect(VALID, "passphrase123");
    // round-trips: unlocking yields the trading key derived from that mnemonic
    const keys = unlockWallet(ks, "passphrase123");
    expect(keys.trading.address).toMatch(/^0x[0-9a-fA-F]{40}$/);
  });
  it("rejects an invalid mnemonic", () => {
    expect(() => importWalletDirect("not a real mnemonic", "passphrase123")).toThrow(/invalid mnemonic/);
  });
  it("enforces the 8-char passphrase minimum", () => {
    expect(() => importWalletDirect(VALID, "short")).toThrow(/8 characters/);
  });
});

describe("per-index trading keys (wallet isolation)", () => {
  it("wallet 0 IS the legacy trading key (path + key equality)", () => {
    const legacy = deriveWalletKeys(TEST_MNEMONIC);
    const indexed = deriveTradingKeyForIndex(TEST_MNEMONIC, 0);
    expect(indexed.privateKey).toBe(legacy.trading.privateKey);
    expect(indexed.address).toBe(legacy.trading.address);
    expect(tradingPathForIndex(0)).toBe("m/44'/60'/0'/0/0");
  });

  it("derives distinct deterministic keys per index", () => {
    const keys = deriveWalletKeys(TEST_MNEMONIC, [1, 2]);
    const w0 = keys.wallets.get(0)!;
    const w1 = keys.wallets.get(1)!;
    const w2 = keys.wallets.get(2)!;
    expect(w0.privateKey).toBe(keys.trading.privateKey);
    const all = [w0.privateKey, w1.privateKey, w2.privateKey];
    expect(new Set(all).size).toBe(3); // all distinct
    // deterministic
    expect(deriveTradingKeyForIndex(TEST_MNEMONIC, 1).privateKey).toBe(w1.privateKey);
    expect(tradingPathForIndex(2)).toBe("m/44'/60'/0'/0/2");
  });

  it("always includes wallet 0 even when not requested", () => {
    const keys = deriveWalletKeys(TEST_MNEMONIC, [3]);
    expect(keys.wallets.get(0)?.privateKey).toBe(keys.trading.privateKey);
    expect([...keys.wallets.keys()].sort()).toEqual([0, 3]);
  });

  it("rejects invalid indexes (fail closed)", () => {
    for (const bad of [-1, 1.5, Number.NaN, 0x80000000]) {
      expect(() => tradingPathForIndex(bad)).toThrow(/walletIndex/);
    }
  });

  it("unlockWallet derives the requested index set", () => {
    const keystore = importWalletDirect(TEST_MNEMONIC, "passphrase123");
    const keys = unlockWallet(keystore, "passphrase123", [1]);
    expect(keys.wallets.get(1)?.privateKey).toBe(deriveTradingKeyForIndex(TEST_MNEMONIC, 1).privateKey);
    expect(keys.wallets.get(0)?.privateKey).toBe(keys.trading.privateKey);
  });
});

/**
 * Passphrase rotation. The failure that matters is a PARTIAL one: a re-wrap
 * that accepted the new passphrase but left the old one working, or that wrote
 * a keystore wrapping something other than the original mnemonic, is a wallet
 * the operator can no longer reason about. Each assertion below pins one of
 * those.
 */
describe("rewrapKeystore", () => {
  const OLD = "old-passphrase-1";
  const NEW = "new-passphrase-2";

  it("produces a keystore the new passphrase opens and the old one does not", () => {
    const original = encryptSecret(TEST_MNEMONIC, OLD);
    const rewrapped = rewrapKeystore(original, OLD, NEW);
    expect(decryptSecret(rewrapped, NEW)).toBe(TEST_MNEMONIC);
    expect(() => decryptSecret(rewrapped, OLD)).toThrow(KeystoreDecryptError);
  });

  it("rejects a wrong old passphrase without producing anything", () => {
    const original = encryptSecret(TEST_MNEMONIC, OLD);
    expect(() => rewrapKeystore(original, "not-the-passphrase", NEW)).toThrow(KeystoreDecryptError);
  });

  it("rejects a new passphrase under 8 characters, and checks it BEFORE the old one", () => {
    const original = encryptSecret(TEST_MNEMONIC, OLD);
    expect(() => rewrapKeystore(original, OLD, "short")).toThrow(/at least 8 characters/);
    // Length is a property of the new passphrase alone — a too-short new
    // passphrase is rejected even when the old one is also wrong, and without
    // spending an scrypt derivation on it.
    expect(() => rewrapKeystore(original, "also-wrong", "short")).toThrow(/at least 8 characters/);
  });

  it("draws a fresh salt and iv, so the two files never share key material", () => {
    const original = encryptSecret(TEST_MNEMONIC, OLD);
    const rewrapped = rewrapKeystore(original, OLD, NEW);
    expect(rewrapped.salt).not.toBe(original.salt);
    expect(rewrapped.iv).not.toBe(original.iv);
    expect(rewrapped.ciphertext).not.toBe(original.ciphertext);
    expect(rewrapped.version).toBe(1);
    expect(rewrapped.kdf).toBe("scrypt");
  });

  it("leaves the original keystore object untouched", () => {
    const original = encryptSecret(TEST_MNEMONIC, OLD);
    const snapshot = JSON.stringify(original);
    rewrapKeystore(original, OLD, NEW);
    expect(JSON.stringify(original)).toBe(snapshot);
  });
});
