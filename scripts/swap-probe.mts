/**
 * PancakeSwap V3 swap probe — the manual live pass for
 * packages/x402/src/swap.ts (design:
 * docs/specs/2026-08-18-pancake-v3-swap-design.md).
 *
 * Phases (run one at a time):
 *   quote  read-only, ZERO SPEND: QuoterV2 price for BNB→USDT across the
 *          four Pancake fee tiers, so the operator can see where the
 *          liquidity is. Proves endpoint, addresses, ABI and decoding.
 *   swap   REAL MONEY (double-gated: explicit phase arg + interactive
 *          confirm): one exactInputSingle for a small BNB amount using the
 *          key in SWAP_PRIVATE_KEY. Proves the payable auto-wrap path, the
 *          receipt decode and the minOut guard end to end.
 *
 * Usage:
 *   pnpm probe:swap quote [amountBnb=0.01]
 *   SWAP_PRIVATE_KEY=0x... pnpm probe:swap swap <amountBnb> [feeTier=100] [slippageBps=50]
 * Env:
 *   SWAP_RPC_URL      BSC endpoint (default: https://bsc-dataseed.bnbchain.org)
 *   SWAP_PRIVATE_KEY  funded key, swap phase only; never printed
 *
 * These constants are BSC-mainnet facts and live HERE, not in the SDK —
 * packages/x402 takes every address as a parameter.
 */
import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import type { Hex } from "viem";
import {
  applySlippageBps,
  quoteSwapNativeForErc20,
  readDecimals,
  readErc20Balance,
  readNativeBalance,
  swapNativeForErc20,
} from "@neotrade/x402";

// Verified 2026-08-18: BscScan labels + on-chain probe (WBNB symbol()/bytecode).
const ROUTER = "0x1b81D678ffb9C0263b24A97847620C99d213eB14" as Hex; // PancakeSwap V3: Swap Router
const QUOTER = "0xB048Bbc1Ee6b733FFfCFb9e9CeF7375518e25997" as Hex; // PancakeSwap: Quoter v2
const WBNB = "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c" as Hex;
const USDT = "0x55d398326f99059fF775485246999027B3197955" as Hex;
const FEE_TIERS = [100, 500, 2500, 10000];

const e = { rpcUrl: process.env.SWAP_RPC_URL ?? "https://bsc-dataseed.bnbchain.org", chainId: 56 };

const toWei = (bnb: string): bigint => {
  const [whole = "0", frac = ""] = bnb.split(".");
  if (!/^\d+$/.test(whole) || (frac !== "" && !/^\d+$/.test(frac)) || frac.length > 18) {
    throw new Error(`bad BNB amount: ${bnb}`);
  }
  return BigInt(whole) * 10n ** 18n + BigInt(frac.padEnd(18, "0") || "0");
};
const fmt = (atomic: bigint, decimals: number): string => {
  const base = 10n ** BigInt(decimals);
  return `${atomic / base}.${(atomic % base).toString().padStart(decimals, "0").replace(/0+$/, "") || "0"}`;
};

async function quotePhase(amountBnb: string): Promise<void> {
  const amountInWei = toWei(amountBnb);
  const usdtDecimals = await readDecimals(e, USDT);
  console.log(`rpc: ${e.rpcUrl}`);
  console.log(`quoting ${amountBnb} BNB -> USDT (read-only, zero spend)`);
  for (const fee of FEE_TIERS) {
    try {
      const { amountOut } = await quoteSwapNativeForErc20(e, { quoter: QUOTER, tokenIn: WBNB, tokenOut: USDT, fee, amountInWei });
      console.log(`  fee ${String(fee).padStart(5)} (${(fee / 10_000).toFixed(2)}%): ${fmt(amountOut, usdtDecimals)} USDT`);
    } catch {
      console.log(`  fee ${String(fee).padStart(5)}: no quote (pool missing or empty)`);
    }
  }
}

async function swapPhase(amountBnb: string, fee: number, slippageBps: number): Promise<void> {
  const key = process.env.SWAP_PRIVATE_KEY as Hex | undefined;
  if (!key) throw new Error("swap phase needs SWAP_PRIVATE_KEY");
  const { privateKeyToAccount } = await import("viem/accounts");
  const address = privateKeyToAccount(key).address;
  const amountInWei = toWei(amountBnb);
  const usdtDecimals = await readDecimals(e, USDT);

  const bnbBefore = await readNativeBalance(e, address);
  const usdtBefore = await readErc20Balance(e, USDT, address);
  const { amountOut: quoted } = await quoteSwapNativeForErc20(e, { quoter: QUOTER, tokenIn: WBNB, tokenOut: USDT, fee, amountInWei });
  const minOut = applySlippageBps(quoted, slippageBps);

  console.log(`rpc: ${e.rpcUrl}`);
  console.log(`wallet ${address}: ${fmt(bnbBefore, 18)} BNB, ${fmt(usdtBefore, usdtDecimals)} USDT`);
  console.log(`swap ${amountBnb} BNB -> USDT | fee tier ${fee} | quote ${fmt(quoted, usdtDecimals)} | minOut ${fmt(minOut, usdtDecimals)} (${slippageBps} bps)`);
  const rl = createInterface({ input: stdin, output: stdout });
  const answer = await rl.question("REAL MONEY on BSC mainnet. Proceed? (yes/N) ");
  rl.close();
  if (answer.trim() !== "yes") {
    console.log("aborted, nothing sent");
    return;
  }

  const { txHash, amountOut } = await swapNativeForErc20(e, key, {
    router: ROUTER, tokenIn: WBNB, tokenOut: USDT, fee, amountInWei, amountOutMinimum: minOut,
  });
  console.log(`mined: https://bscscan.com/tx/${txHash}`);
  console.log(`received (from receipt logs): ${fmt(amountOut, usdtDecimals)} USDT`);
  const bnbAfter = await readNativeBalance(e, address);
  const usdtAfter = await readErc20Balance(e, USDT, address);
  console.log(`re-read balances: ${fmt(bnbAfter, 18)} BNB (spent ${fmt(bnbBefore - bnbAfter, 18)} incl. gas), ${fmt(usdtAfter, usdtDecimals)} USDT (received ${fmt(usdtAfter - usdtBefore, usdtDecimals)})`);
  if (usdtAfter - usdtBefore !== amountOut) {
    console.log("WARNING: balance delta and receipt-decoded amountOut disagree — investigate before trusting either");
  }
}

const [phase, amountArg, feeArg, slippageArg] = process.argv.slice(2);
if (phase === "quote") {
  await quotePhase(amountArg ?? "0.01");
} else if (phase === "swap") {
  if (!amountArg) throw new Error("usage: pnpm probe:swap swap <amountBnb> [feeTier=100] [slippageBps=50]");
  await swapPhase(amountArg, feeArg ? Number(feeArg) : 100, slippageArg ? Number(slippageArg) : 50);
} else {
  throw new Error("usage: pnpm probe:swap <quote|swap> ...");
}
