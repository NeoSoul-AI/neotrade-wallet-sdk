import { randomBytes, scryptSync, createCipheriv, createDecipheriv } from "node:crypto";

/**
 * Encrypted keystore for the mnemonic (from which both neotrade keys derive).
 *
 * Portable, self-contained crypto — deliberately not OS-keychain-bound, so a
 * keystore file moves with the user. A passphrase-derived key wraps the
 * secret with AES-256-GCM; GCM's auth tag detects tampering and rejects a
 * wrong passphrase without leaking whether the ciphertext or the passphrase
 * was at fault.
 *
 * KDF note: the spec targets Argon2id. node:crypto ships scrypt (memory-hard,
 * built in, no native dependency), so the MVP uses scrypt with strong
 * parameters. Swapping to Argon2id later touches only `deriveKek` and the
 * `kdf` field — the keystore format is versioned for exactly this.
 */

const KDF = "scrypt" as const;
const CIPHER = "aes-256-gcm";
const KEY_LEN = 32;
const SALT_LEN = 16;
const IV_LEN = 12;
// scrypt cost: N=2^17 (~128 MiB), r=8, p=1 — interactive-unlock grade.
const SCRYPT_PARAMS = { N: 1 << 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

export interface EncryptedKeystore {
  version: 1;
  kdf: typeof KDF;
  kdfParams: { N: number; r: number; p: number };
  salt: string; // base64
  iv: string; // base64
  authTag: string; // base64
  ciphertext: string; // base64
}

function deriveKek(passphrase: string, salt: Buffer): Buffer {
  return scryptSync(passphrase.normalize("NFKC"), salt, KEY_LEN, SCRYPT_PARAMS);
}

/** Encrypts a secret (the mnemonic) under a passphrase. */
export function encryptSecret(secret: string, passphrase: string): EncryptedKeystore {
  const salt = randomBytes(SALT_LEN);
  const iv = randomBytes(IV_LEN);
  const kek = deriveKek(passphrase, salt);
  const cipher = createCipheriv(CIPHER, kek, iv);
  const ciphertext = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    version: 1,
    kdf: KDF,
    kdfParams: { N: SCRYPT_PARAMS.N, r: SCRYPT_PARAMS.r, p: SCRYPT_PARAMS.p },
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    authTag: authTag.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };
}

export class KeystoreDecryptError extends Error {
  constructor() {
    // Deliberately opaque: don't reveal whether the passphrase or the
    // ciphertext was wrong.
    super("failed to decrypt keystore (wrong passphrase or corrupt keystore)");
    this.name = "KeystoreDecryptError";
  }
}

/** Decrypts a keystore. Throws KeystoreDecryptError on any failure. */
export function decryptSecret(keystore: EncryptedKeystore, passphrase: string): string {
  if (keystore.version !== 1 || keystore.kdf !== KDF) {
    throw new KeystoreDecryptError();
  }
  try {
    const salt = Buffer.from(keystore.salt, "base64");
    const iv = Buffer.from(keystore.iv, "base64");
    const authTag = Buffer.from(keystore.authTag, "base64");
    const ciphertext = Buffer.from(keystore.ciphertext, "base64");
    const kek = scryptSync(passphrase.normalize("NFKC"), salt, KEY_LEN, {
      N: keystore.kdfParams.N,
      r: keystore.kdfParams.r,
      p: keystore.kdfParams.p,
      maxmem: 256 * 1024 * 1024,
    });
    const decipher = createDecipheriv(CIPHER, kek, iv);
    decipher.setAuthTag(authTag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return plaintext.toString("utf8");
  } catch {
    throw new KeystoreDecryptError();
  }
}

/**
 * Passphrase probe. Returns true iff the passphrase decrypts. Useful for an
 * unlock prompt without surfacing the plaintext. Right/wrong is decided by
 * the AES-GCM auth tag inside decryptSecret — a wrong passphrase derives a
 * wrong KEK and the tag check throws KeystoreDecryptError.
 */
export function verifyPassphrase(keystore: EncryptedKeystore, passphrase: string): boolean {
  try {
    decryptSecret(keystore, passphrase);
    return true;
  } catch {
    return false;
  }
}

/**
 * Re-encrypts an existing keystore under a new passphrase — the passphrase
 * rotation path. The wrapped secret is unchanged; only the wrapping is
 * replaced, with a fresh salt, iv and auth tag, and with the CURRENT
 * SCRYPT_PARAMS rather than whatever the old file recorded.
 *
 * The length rule lives here, next to `finalizeWallet` and
 * `importWalletDirect` in this package (wallet.ts), so all three
 * passphrase-setting paths enforce the same minimum in the same place. It is
 * checked BEFORE the old passphrase: length is a property of the new
 * passphrase alone, and rejecting first avoids an scrypt derivation for an
 * input that was never going to be accepted.
 *
 * Throws KeystoreDecryptError when `oldPassphrase` does not decrypt. Purely
 * functional: nothing is written and the input keystore is not mutated, so a
 * caller that throws is left exactly where it started.
 */
export function rewrapKeystore(
  keystore: EncryptedKeystore,
  oldPassphrase: string,
  newPassphrase: string,
): EncryptedKeystore {
  if (newPassphrase.length < 8) {
    throw new Error("passphrase must be at least 8 characters");
  }
  return encryptSecret(decryptSecret(keystore, oldPassphrase), newPassphrase);
}
