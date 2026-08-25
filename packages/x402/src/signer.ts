import { privateKeyToAccount } from "viem/accounts";

/** The minimal ClientEvmSigner @x402/evm's permit2 path needs: `address` +
 * `signTypedData`. NO chain connection — signing a payment is pure EIP-712,
 * which is why building one takes no RPC URL. (readContract/signTransaction on
 * that interface are only for the EIP-2612 gas-sponsoring extension, which this
 * client does not use: mUSDC has no EIP-2612 at all. Leaving them off is not an
 * omission — it is what keeps the scheme on the plain permit2 path.)
 *
 * This pair is also exactly what a browser has: `eth_accounts` supplies the
 * address and `eth_signTypedData_v4` the signature, so an injected wallet can
 * implement it directly — a private key is ONE way to build one, not a
 * requirement of the path. */
export interface TypedDataSigner {
  address: `0x${string}`;
  signTypedData(message: {
    domain: Record<string, unknown>;
    types: Record<string, unknown>;
    primaryType: string;
    message: Record<string, unknown>;
  }): Promise<`0x${string}`>;
}

export function toSigner(keyOrSigner: `0x${string}` | TypedDataSigner): TypedDataSigner {
  if (typeof keyOrSigner !== "string") {
    // Already a signer — pass it through untouched. The caller (a browser
    // wallet adapter, a hardware wallet) owns how the signature is produced.
    return keyOrSigner;
  }
  const account = privateKeyToAccount(keyOrSigner);
  return {
    address: account.address,
    // The SDK's signer interface types the argument loosely (four
    // Record<string, unknown> fields) while viem's own signTypedData is
    // generic over the type map. The cast bridges exactly that gap and nothing
    // else — the object handed in is passed through unmodified.
    signTypedData: (message) =>
      account.signTypedData(message as Parameters<typeof account.signTypedData>[0]),
  };
}
