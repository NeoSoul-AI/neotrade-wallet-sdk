export {
  generateWalletMnemonic,
  isValidMnemonic,
  deriveWalletKeys,
  deriveTradingKeyForIndex,
  tradingPathForIndex,
  MAX_WALLET_INDEX,
  type DerivedKey,
} from "./keys.js";

export {
  hashPersonalMessage,
  signPersonalMessage,
  recoverPersonalMessageAddress,
} from "./personal-message.js";

export {
  buildBackupChallenge,
  verifyBackup,
  type BackupChallenge,
} from "./backup.js";

export {
  encryptSecret,
  decryptSecret,
  rewrapKeystore,
  verifyPassphrase,
  KeystoreDecryptError,
  type EncryptedKeystore,
} from "./keystore.js";

export {
  createWallet,
  importWallet,
  importWalletDirect,
  finalizeWallet,
  unlockWallet,
  type NewWallet,
  type WalletKeys,
} from "./wallet.js";
