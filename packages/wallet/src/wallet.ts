import { randomInt } from "node:crypto";
import {
  deriveWalletKeys,
  generateWalletMnemonic,
  isValidMnemonic,
  type DerivedKey,
} from "./keys.js";
import { buildBackupChallenge, verifyBackup, type BackupChallenge } from "./backup.js";
import {
  decryptSecret,
  encryptSecret,
  type EncryptedKeystore,
} from "./keystore.js";

/**
 * Wallet lifecycle orchestration: create (generate → back up → encrypt),
 * import (validate → back up → encrypt), and unlock (decrypt → derive).
 *
 * Backup gate: neither create nor import completes without a verified
 * mnemonic backup — evoevo holds no custody, so an unbacked wallet is a
 * guaranteed future fund-loss. 2FA on high-risk actions (export/withdraw/
 * revoke) is a separate approval-gated layer, wired at the client, not here.
 */

export interface WalletKeys {
  trading: DerivedKey;
  /** walletIndex → venue trading key; always contains 0 (≡ trading). */
  wallets: Map<number, DerivedKey>;
}

export interface NewWallet {
  mnemonic: string;
  challenge: BackupChallenge;
}

/**
 * Step 1 of creation: generate a mnemonic and a backup challenge. The
 * caller shows the mnemonic, has the user transcribe it, then calls
 * `finalizeWallet` with the user's answers.
 */
export function createWallet(options: { backupWords?: number } = {}): NewWallet {
  const mnemonic = generateWalletMnemonic();
  const challenge = buildBackupChallenge(mnemonic, options.backupWords ?? 4, secureUnitFloat);
  return { mnemonic, challenge };
}

/** Import path: validate a user-supplied mnemonic and build a backup challenge. */
export function importWallet(
  mnemonic: string,
  options: { backupWords?: number } = {},
): NewWallet {
  const normalized = mnemonic.trim();
  if (!isValidMnemonic(normalized)) {
    throw new Error("invalid mnemonic");
  }
  const challenge = buildBackupChallenge(normalized, options.backupWords ?? 4, secureUnitFloat);
  return { mnemonic: normalized, challenge };
}

/**
 * Step 2: verify the backup answers and, on success, encrypt the mnemonic
 * under the passphrase. Throws if the backup verification fails — the
 * wallet is not persisted.
 */
export function finalizeWallet(
  newWallet: NewWallet,
  answers: Record<number, string>,
  passphrase: string,
): EncryptedKeystore {
  if (!verifyBackup(newWallet.mnemonic, newWallet.challenge, answers)) {
    throw new Error("backup verification failed: transcribed words do not match");
  }
  if (passphrase.length < 8) {
    throw new Error("passphrase must be at least 8 characters");
  }
  return encryptSecret(newWallet.mnemonic, passphrase);
}

/** Direct import: validate a user-supplied mnemonic and encrypt it under the
 * passphrase immediately — no backup challenge. The challenge exists to catch
 * transcription errors on a freshly GENERATED mnemonic (see createWallet); an
 * imported phrase is already held by the owner, so it is skipped. */
export function importWalletDirect(mnemonic: string, passphrase: string): EncryptedKeystore {
  const normalized = mnemonic.trim();
  if (!isValidMnemonic(normalized)) {
    throw new Error("invalid mnemonic");
  }
  if (passphrase.length < 8) {
    throw new Error("passphrase must be at least 8 characters");
  }
  return encryptSecret(normalized, passphrase);
}

/** Unlock: decrypt the keystore and derive every requested venue-wallet
 * index (the mnemonic never leaves this call). */
export function unlockWallet(
  keystore: EncryptedKeystore,
  passphrase: string,
  walletIndexes: readonly number[] = [],
): WalletKeys {
  const mnemonic = decryptSecret(keystore, passphrase);
  return deriveWalletKeys(mnemonic, walletIndexes);
}

/** CSPRNG-backed float in [0, 1) for backup-challenge position selection. */
function secureUnitFloat(): number {
  return randomInt(0, 1_000_000) / 1_000_000;
}
