import { createPublicClient, createWalletClient, encodeFunctionData, getAddress, http, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { chainOf } from "./permit2.js";
import type { ChainEndpoint } from "./types.js";

/**
 * Plain value transfers. Callers: the proof-funds migration ceremony
 * (`packages/sidecar/src/proof-migration.ts`) and the operator send surface
 * (`packages/sidecar/src/wallet-transfer.ts` — the 2026-08-12 spec supersedes
 * the §5 rejection the previous comment here recorded).
 *
 * They live here because this package is already the one place viem-based
 * chain primitives are allowed (`readErc20Balance`, `readNativeBalance`,
 * `approvePermit2`); a second viem entry point would erode that isolation
 * further (operator decision 2026-08-11).
 *
 * NOT idempotent, and nothing here pretends otherwise: a resend is a second
 * transfer. Crash safety belongs to the caller. The three-way error contract
 * (nothing-broadcast / TransferUnconfirmedError-with-txHash / reverted) exists
 * so the caller can tell `failed` from `unknown` — a broadcast whose receipt
 * wait timed out may still mine, and recording it as "nothing moved" invites
 * the double-send this whole file exists to avoid.
 */

/** Broadcast succeeded; confirmation is unknown. The transaction MAY still
 * mine — the caller must record the txHash and never resend automatically. */
export class TransferUnconfirmedError extends Error {
  constructor(readonly txHash: Hex, cause: unknown) {
    super(`transfer ${txHash} was broadcast but its receipt could not be read`, { cause });
  }
}

/** Broadcast succeeded, mined, reverted. DEFINITELY nothing moved, but gas
 * WAS burned — the caller must still record the txHash (the view docs
 * promise "failed — … or a revert, txHash present") and re-read balances
 * before any further step. */
export class TransferRevertedError extends Error {
  constructor(readonly txHash: Hex) {
    super(`transfer ${txHash} reverted on-chain`);
  }
}

const ERC20_TRANSFER = [
  {
    type: "function",
    name: "transfer",
    stateMutability: "nonpayable",
    inputs: [
      { name: "to", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [{ name: "", type: "bool" }],
  },
] as const;

/** Exported for the unit test: the calldata, with no chain involved. */
export function encodeErc20Transfer(to: Hex, amountAtomic: bigint): Hex {
  return encodeFunctionData({ abi: ERC20_TRANSFER, functionName: "transfer", args: [to, amountAtomic] });
}

async function send(
  e: ChainEndpoint,
  privateKey: Hex,
  tx: { to: Hex; data?: Hex; value?: bigint },
): Promise<{ txHash: Hex }> {
  const account = privateKeyToAccount(privateKey);
  const chain = chainOf(e);
  const wc = createWalletClient({ account, chain, transport: http(e.rpcUrl) });
  const pc = createPublicClient({ chain, transport: http(e.rpcUrl) });
  // A throw ABOVE this line means nothing was broadcast: plain error, the
  // caller may record `failed` and safely retry.
  const txHash = await wc.sendTransaction(tx);
  let receipt: Awaited<ReturnType<typeof pc.waitForTransactionReceipt>>;
  try {
    receipt = await pc.waitForTransactionReceipt({ hash: txHash });
  } catch (cause) {
    // Broadcast, then lost the answer. The transaction may still mine — this
    // is NOT `failed`, and the caller must get the hash to record `unknown`.
    throw new TransferUnconfirmedError(txHash, cause);
  }
  // Throw rather than return a hash for a reverted transfer: a caller that
  // recorded it as sent would report money as moved when it did not. The
  // typed error carries the hash structurally, not just in the message.
  if (receipt.status !== "success") {
    throw new TransferRevertedError(txHash);
  }
  return { txHash };
}

/**
 * Validate an operator-typed address and return its EIP-55 form. Throws on
 * anything malformed, and on a MIXED-CASE address whose checksum does not
 * match — the case a fat-fingered paste most needs caught. All-lowercase or
 * all-uppercase input carries no checksum and is accepted as such (EIP-55's
 * own rule, same as MetaMask).
 *
 * The mixed-case comparison is done here because viem's `getAddress` alone
 * does NOT do it — it normalises whatever hex it is given and returns the
 * correct checksum form without ever rejecting a wrong-case input.
 *
 * Lives here because address rules are viem's, and this package is the one
 * permitted viem home for generic chain primitives.
 */
export function checksumAddress(address: string): Hex {
  const trimmed = address.trim();
  const normalized = getAddress(trimmed.toLowerCase()); // throws on malformed input
  // The comparison is on the 40-char body with the prefix re-attached in
  // canonical form: EIP-55 checksums only the body, and some explorers emit
  // an uppercase "0X" prefix on an otherwise correctly-checksummed address —
  // comparing `trimmed` directly would reject those on the prefix alone.
  const body = trimmed.slice(2);
  if (/[A-F]/.test(body) && /[a-f]/.test(body) && `0x${body}` !== normalized) {
    throw new Error(`address checksum mismatch: ${trimmed} is not the EIP-55 form ${normalized}`);
  }
  return normalized;
}

export async function transferErc20(
  e: ChainEndpoint,
  asset: Hex,
  privateKey: Hex,
  to: Hex,
  amountAtomic: bigint,
): Promise<{ txHash: Hex }> {
  return send(e, privateKey, { to: asset, data: encodeErc20Transfer(to, amountAtomic) });
}

export async function transferNative(
  e: ChainEndpoint,
  privateKey: Hex,
  to: Hex,
  amountWei: bigint,
): Promise<{ txHash: Hex }> {
  return send(e, privateKey, { to, value: amountWei });
}

/**
 * An ESTIMATE of what a native transfer's own gas costs — reserve price ×
 * 21000 (the fixed cost of a plain value transfer, no calldata). Added for
 * the migration ceremony's `gasForSweep` (Task 9): the sweep must leave
 * enough native balance behind to pay for itself, and that figure must not
 * be hardcoded.
 *
 * The reserve price is `estimateFeesPerGas().maxFeePerGas`, not
 * `getGasPrice()`: `send()` above lets viem build the transaction, and on an
 * EIP-1559 chain viem picks a type-2 tx with `maxFeePerGas ≈ 1.2 × baseFee +
 * tip` — the node requires `value + 21000 × maxFeePerGas ≤ balance`, so
 * reserving only `getGasPrice()` (≈ baseFee + tip, no 1.2× headroom) gets the
 * sweep rejected pre-broadcast on exactly the chains that matter. Falls back
 * to `getGasPrice()` only if the chain doesn't support fee estimation (a
 * legacy, non-1559 chain), where it IS the number viem will use.
 * Over-reserving here is the safe direction: the unsent remainder stays on
 * the proof address and is still sweepable on the next run.
 *
 * Not unit tested — like `transferErc20`/`transferNative` above, it needs a
 * live chain response and this package draws the line at the pure calldata
 * helper (`encodeErc20Transfer`); covered by the manual testnet pass.
 */
export async function estimateNativeTransferGasCost(e: ChainEndpoint): Promise<bigint> {
  const pc = createPublicClient({ transport: http(e.rpcUrl) });
  let maxFeePerGas: bigint;
  try {
    ({ maxFeePerGas } = await pc.estimateFeesPerGas());
  } catch {
    maxFeePerGas = await pc.getGasPrice();
  }
  return maxFeePerGas * 21_000n;
}
