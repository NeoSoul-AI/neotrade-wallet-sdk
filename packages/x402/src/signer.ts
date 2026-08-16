import { privateKeyToAccount } from "viem/accounts";

/** The minimal ClientEvmSigner @x402/evm's permit2 path needs: `address` +
 * `signTypedData`. NO chain connection — signing a payment is pure EIP-712,
 * which is why this function takes no RPC URL. (readContract/signTransaction on
 * that interface are only for the EIP-2612 gas-sponsoring extension, which this
 * client does not use: mUSDC has no EIP-2612 at all. Leaving them off is not an
 * omission — it is what keeps the scheme on the plain permit2 path.) */
export function toSigner(privateKey: `0x${string}`): {
  address: `0x${string}`;
  signTypedData(message: {
    domain: Record<string, unknown>;
    types: Record<string, unknown>;
    primaryType: string;
    message: Record<string, unknown>;
  }): Promise<`0x${string}`>;
} {
  const account = privateKeyToAccount(privateKey);
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
