import { createPublicClient, createWalletClient, encodeFunctionData, http, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { chainOf } from "./permit2.js";
import type { ChainEndpoint } from "./types.js";

/**
 * Native → ERC-20 swaps against a PancakeSwap/Uniswap V3-periphery
 * SwapRouter (design: docs/specs/2026-08-18-pancake-v3-swap-design.md).
 * One direction only, one fee tier per call, single pool, no approve:
 * the router's pay() wraps msg.value when tokenIn is the wrapped-native
 * token, so the entire swap is a single transaction.
 *
 * Like transfer.ts, nothing here is idempotent and the caller owns crash
 * safety. The three-way error contract (nothing-broadcast /
 * SwapUnconfirmedError-with-txHash / SwapRevertedError) exists for the same
 * reason: an ambiguous failure that gets resent is a double-spend.
 *
 * No chain facts live here — router, quoter and token addresses are the
 * caller's, same rule as chainOf() refusing viem/chains presets.
 */

/** Broadcast succeeded; confirmation is unknown. The transaction MAY still
 * mine — the caller must record the txHash and never resend automatically. */
export class SwapUnconfirmedError extends Error {
  constructor(readonly txHash: Hex, cause: unknown) {
    super(`swap ${txHash} was broadcast but its receipt could not be read`, { cause });
  }
}

/** Broadcast succeeded, mined, reverted. Nothing was swapped, but gas WAS
 * burned — the caller must record the txHash and re-read balances. */
export class SwapRevertedError extends Error {
  constructor(readonly txHash: Hex) {
    super(`swap ${txHash} reverted on-chain`);
  }
}

/** The classic V3-periphery SwapRouter entrypoint, verified against
 * pancakeswap/pancake-v3-contracts v3-periphery: payable, deadline INSIDE
 * the struct (the SmartRouter/SwapRouter02 variant moves it to multicall —
 * that router is deliberately not supported). */
const EXACT_INPUT_SINGLE = [
  {
    type: "function",
    name: "exactInputSingle",
    stateMutability: "payable",
    inputs: [
      {
        name: "params",
        type: "tuple",
        components: [
          { name: "tokenIn", type: "address" },
          { name: "tokenOut", type: "address" },
          { name: "fee", type: "uint24" },
          { name: "recipient", type: "address" },
          { name: "deadline", type: "uint256" },
          { name: "amountIn", type: "uint256" },
          { name: "amountOutMinimum", type: "uint256" },
          { name: "sqrtPriceLimitX96", type: "uint160" },
        ],
      },
    ],
    outputs: [{ name: "amountOut", type: "uint256" }],
  },
] as const;

/** Exported for the unit test: the calldata, with no chain involved.
 * sqrtPriceLimitX96 is pinned to 0 — amountOutMinimum is the ONE slippage
 * guard; a second, untested guard is a place to be wrong. */
export function encodeExactInputSingle(p: {
  tokenIn: Hex;
  tokenOut: Hex;
  fee: number;
  recipient: Hex;
  deadline: bigint;
  amountIn: bigint;
  amountOutMinimum: bigint;
}): Hex {
  return encodeFunctionData({
    abi: EXACT_INPUT_SINGLE,
    functionName: "exactInputSingle",
    args: [
      {
        tokenIn: p.tokenIn,
        tokenOut: p.tokenOut,
        fee: p.fee,
        recipient: p.recipient,
        deadline: p.deadline,
        amountIn: p.amountIn,
        amountOutMinimum: p.amountOutMinimum,
        sqrtPriceLimitX96: 0n,
      },
    ],
  });
}

/** minOut math for callers: quote × (10000 − bps) / 10000, floor-rounded.
 * Floor is the safe direction — rounding up could demand more than the
 * quote itself at 0 bps. The SDK never picks a tolerance; where the number
 * comes from is the host's decision. */
export function applySlippageBps(amountOut: bigint, slippageBps: number): bigint {
  if (!Number.isInteger(slippageBps) || slippageBps < 0 || slippageBps > 10_000) {
    throw new Error(`slippageBps must be an integer in [0, 10000], got ${slippageBps}`);
  }
  return (amountOut * BigInt(10_000 - slippageBps)) / 10_000n;
}

const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

/** The ACTUAL amount received, from the receipt's ERC-20 Transfer logs
 * (address == tokenOut, to == recipient). Exported for the unit test.
 * Throws when a successful receipt carries no such transfer — that is not a
 * success we can report a number for. */
export function decodeSwapAmountOut(
  logs: readonly { address: Hex; topics: readonly Hex[]; data: Hex }[],
  tokenOut: Hex,
  recipient: Hex,
): bigint {
  const wantToken = tokenOut.toLowerCase();
  const wantTo = `0x${recipient.slice(2).toLowerCase().padStart(64, "0")}`;
  let total = 0n;
  let seen = false;
  for (const log of logs) {
    if (log.address.toLowerCase() !== wantToken) continue;
    if (log.topics[0]?.toLowerCase() !== TRANSFER_TOPIC) continue;
    if (log.topics[2]?.toLowerCase() !== wantTo) continue;
    seen = true;
    total += BigInt(log.data);
  }
  if (!seen) {
    throw new Error("swap succeeded but no tokenOut Transfer to the recipient was found in the receipt");
  }
  return total;
}

/** QuoterV2, verified against pancakeswap/pancake-v3-contracts. NOTE the
 * struct's field order differs from the router's: amountIn comes BEFORE fee.
 * quoteExactInputSingle is declared nonpayable (it state-reverts internally),
 * so it is called via simulateContract, never readContract. */
const QUOTER_V2 = [
  {
    type: "function",
    name: "quoteExactInputSingle",
    stateMutability: "nonpayable",
    inputs: [
      {
        name: "params",
        type: "tuple",
        components: [
          { name: "tokenIn", type: "address" },
          { name: "tokenOut", type: "address" },
          { name: "amountIn", type: "uint256" },
          { name: "fee", type: "uint24" },
          { name: "sqrtPriceLimitX96", type: "uint160" },
        ],
      },
    ],
    outputs: [
      { name: "amountOut", type: "uint256" },
      { name: "sqrtPriceX96After", type: "uint160" },
      { name: "initializedTicksCrossed", type: "uint32" },
      { name: "gasEstimate", type: "uint256" },
    ],
  },
] as const;

function assertFee(fee: number): void {
  if (!Number.isInteger(fee) || fee <= 0 || fee >= 2 ** 24) {
    throw new Error(`fee must be a uint24 tier in (0, 2^24), got ${fee}`);
  }
}

function assertAmountIn(amountInWei: bigint): void {
  if (amountInWei <= 0n) {
    throw new Error(`amountInWei must be positive, got ${amountInWei}`);
  }
}

/** One eth_call against QuoterV2. Read-only, zero cost. Reverts (as a thrown
 * error) when the pool for this fee tier does not exist. */
export async function quoteSwapNativeForErc20(
  e: ChainEndpoint,
  params: { quoter: Hex; tokenIn: Hex; tokenOut: Hex; fee: number; amountInWei: bigint },
): Promise<{ amountOut: bigint }> {
  assertFee(params.fee);
  assertAmountIn(params.amountInWei);
  const pc = createPublicClient({ transport: http(e.rpcUrl) });
  const { result } = await pc.simulateContract({
    address: params.quoter,
    abi: QUOTER_V2,
    functionName: "quoteExactInputSingle",
    args: [
      {
        tokenIn: params.tokenIn,
        tokenOut: params.tokenOut,
        amountIn: params.amountInWei,
        fee: params.fee,
        sqrtPriceLimitX96: 0n,
      },
    ],
  });
  return { amountOut: result[0] };
}

/**
 * The swap: exactInputSingle with msg.value = amountInWei. The recipient is
 * the key's own address, deliberately not a parameter — a swap's proceeds
 * have no business landing anywhere but the wallet that paid, and dropping
 * the field removes a place to paste the wrong address.
 *
 * Error contract (same as transfer.ts): a throw before broadcast means
 * nothing happened; SwapUnconfirmedError means it MAY still mine — record
 * the hash, never resend; SwapRevertedError means it mined and reverted.
 */
export async function swapNativeForErc20(
  e: ChainEndpoint,
  privateKey: Hex,
  params: {
    router: Hex;
    tokenIn: Hex;
    tokenOut: Hex;
    fee: number;
    amountInWei: bigint;
    amountOutMinimum: bigint;
    deadlineSeconds?: number;
  },
): Promise<{ txHash: Hex; amountOut: bigint }> {
  assertFee(params.fee);
  assertAmountIn(params.amountInWei);
  if (params.amountOutMinimum <= 0n) {
    throw new Error("amountOutMinimum must be positive — it is the only slippage guard");
  }
  const deadlineSeconds = params.deadlineSeconds ?? 120;
  if (!Number.isInteger(deadlineSeconds) || deadlineSeconds <= 0) {
    throw new Error(`deadlineSeconds must be a positive integer, got ${deadlineSeconds}`);
  }
  const account = privateKeyToAccount(privateKey);
  const chain = chainOf(e);
  const wc = createWalletClient({ account, chain, transport: http(e.rpcUrl) });
  const pc = createPublicClient({ chain, transport: http(e.rpcUrl) });
  const data = encodeExactInputSingle({
    tokenIn: params.tokenIn,
    tokenOut: params.tokenOut,
    fee: params.fee,
    recipient: account.address,
    deadline: BigInt(Math.floor(Date.now() / 1000) + deadlineSeconds),
    amountIn: params.amountInWei,
    amountOutMinimum: params.amountOutMinimum,
  });
  // A throw ABOVE this line means nothing was broadcast: plain error, the
  // caller may record `failed` and safely retry.
  const txHash = await wc.sendTransaction({ to: params.router, data, value: params.amountInWei });
  let receipt: Awaited<ReturnType<typeof pc.waitForTransactionReceipt>>;
  try {
    receipt = await pc.waitForTransactionReceipt({ hash: txHash });
  } catch (cause) {
    throw new SwapUnconfirmedError(txHash, cause);
  }
  if (receipt.status !== "success") {
    throw new SwapRevertedError(txHash);
  }
  return { txHash, amountOut: decodeSwapAmountOut(receipt.logs, params.tokenOut, account.address) };
}
