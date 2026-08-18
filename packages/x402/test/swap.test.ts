import { describe, expect, it } from "vitest";
import type { Hex } from "viem";
import {
  applySlippageBps,
  decodeSwapAmountOut,
  encodeExactInputSingle,
  quoteSwapNativeForErc20,
  swapNativeForErc20,
} from "../src/swap.js";

const TOKEN_OUT = "0x55d398326f99059fF775485246999027B3197955" as const;
// All-lowercase on purpose: carries no EIP-55 checksum, so viem accepts it.
const RECIPIENT = "0x2614e5588275b02b23cdbefed8e5da6d2f59d1c6" as const;
const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

const pad32 = (hex: string) => `0x${hex.slice(2).toLowerCase().padStart(64, "0")}` as Hex;
// topics = [Transfer, from, to] — `from` is filled with RECIPIENT on purpose:
// only topics[2] (the `to`) may ever be matched by the implementation.
const transferLog = (token: string, to: string, amount: bigint) => ({
  address: token as Hex,
  topics: [TRANSFER_TOPIC as Hex, pad32(RECIPIENT), pad32(to)],
  data: `0x${amount.toString(16).padStart(64, "0")}` as Hex,
});

describe("encodeExactInputSingle", () => {
  const params = {
    tokenIn: "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c" as Hex,
    tokenOut: TOKEN_OUT as Hex,
    fee: 500,
    recipient: RECIPIENT as Hex,
    deadline: 1_800_000_000n,
    amountIn: 10n ** 15n,
    amountOutMinimum: 123_456n,
  };

  it("encodes exactInputSingle(struct) — selector and 8-word layout", () => {
    const data = encodeExactInputSingle(params);
    expect(data.slice(0, 10)).toBe("0x414bf389"); // exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))
    expect(data).toHaveLength(2 + 8 + 64 * 8);    // selector + 8 static tuple words
  });

  it("places each field in its struct slot", () => {
    const data = encodeExactInputSingle(params);
    const word = (i: number) => data.slice(10 + i * 64, 10 + (i + 1) * 64);
    expect(word(0).endsWith(params.tokenIn.slice(2).toLowerCase())).toBe(true);
    expect(word(1).endsWith(params.tokenOut.slice(2).toLowerCase())).toBe(true);
    expect(BigInt(`0x${word(2)}`)).toBe(500n);
    expect(word(3).endsWith(params.recipient.slice(2).toLowerCase())).toBe(true);
    expect(BigInt(`0x${word(4)}`)).toBe(1_800_000_000n);
    expect(BigInt(`0x${word(5)}`)).toBe(10n ** 15n);
    expect(BigInt(`0x${word(6)}`)).toBe(123_456n);
    expect(BigInt(`0x${word(7)}`)).toBe(0n); // sqrtPriceLimitX96 always 0
  });
});

describe("applySlippageBps", () => {
  it("0 bps returns the amount unchanged", () => {
    expect(applySlippageBps(999n, 0)).toBe(999n);
  });

  it("floors, never rounds up — 999 at 50 bps is 994, not 994.005", () => {
    expect(applySlippageBps(999n, 50)).toBe(994n);
  });

  it("10000 bps returns zero", () => {
    expect(applySlippageBps(999n, 10_000)).toBe(0n);
  });

  it("rejects out-of-range and non-integer bps", () => {
    expect(() => applySlippageBps(1n, -1)).toThrow(/slippageBps/);
    expect(() => applySlippageBps(1n, 10_001)).toThrow(/slippageBps/);
    expect(() => applySlippageBps(1n, 0.5)).toThrow(/slippageBps/);
    expect(() => applySlippageBps(1n, Number.NaN)).toThrow(/slippageBps/);
  });
});

describe("decodeSwapAmountOut", () => {
  it("finds the tokenOut Transfer to the recipient among noise", () => {
    const logs = [
      transferLog("0x0000000000000000000000000000000000000001", RECIPIENT, 7n), // wrong token
      transferLog(TOKEN_OUT, "0x0000000000000000000000000000000000000002", 9n), // wrong recipient
      { address: TOKEN_OUT as Hex, topics: ["0x1234000000000000000000000000000000000000000000000000000000000000" as Hex], data: "0x" as Hex }, // wrong event
      transferLog(TOKEN_OUT, RECIPIENT, 42n),
    ];
    expect(decodeSwapAmountOut(logs, TOKEN_OUT, RECIPIENT)).toBe(42n);
  });

  it("sums multiple matching transfers", () => {
    const logs = [transferLog(TOKEN_OUT, RECIPIENT, 40n), transferLog(TOKEN_OUT, RECIPIENT, 2n)];
    expect(decodeSwapAmountOut(logs, TOKEN_OUT, RECIPIENT)).toBe(42n);
  });

  it("matches addresses case-insensitively", () => {
    const logs = [transferLog(TOKEN_OUT.toLowerCase(), RECIPIENT.toLowerCase(), 42n)];
    expect(decodeSwapAmountOut(logs, TOKEN_OUT, RECIPIENT)).toBe(42n);
  });

  it("throws when the receipt holds no matching transfer", () => {
    expect(() => decodeSwapAmountOut([], TOKEN_OUT, RECIPIENT)).toThrow(/no tokenOut Transfer/);
  });
});

// The endpoint points at a dead port: a validation gap would surface as a
// connection error, not the expected message — proving the checks run
// BEFORE any network traffic.
const DEAD_ENDPOINT = { rpcUrl: "http://127.0.0.1:9", chainId: 56 };
const DUMMY_KEY = `0x${"1".padStart(64, "0")}` as Hex;
const TOKEN_IN = "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c" as Hex;
const QUOTER = "0xB048Bbc1Ee6b733FFfCFb9e9CeF7375518e25997" as Hex;
const ROUTER = "0x1b81D678ffb9C0263b24A97847620C99d213eB14" as Hex;

describe("parameter validation happens before any network call", () => {
  const base = { router: ROUTER, tokenIn: TOKEN_IN, tokenOut: TOKEN_OUT as Hex, fee: 500, amountInWei: 10n ** 15n, amountOutMinimum: 1n };

  it("quote rejects a non-positive amountIn", async () => {
    await expect(
      quoteSwapNativeForErc20(DEAD_ENDPOINT, { quoter: QUOTER, tokenIn: TOKEN_IN, tokenOut: TOKEN_OUT as Hex, fee: 500, amountInWei: 0n }),
    ).rejects.toThrow(/amountInWei/);
  });

  it("quote rejects an out-of-range fee", async () => {
    await expect(
      quoteSwapNativeForErc20(DEAD_ENDPOINT, { quoter: QUOTER, tokenIn: TOKEN_IN, tokenOut: TOKEN_OUT as Hex, fee: 0.5, amountInWei: 1n }),
    ).rejects.toThrow(/fee/);
    await expect(
      quoteSwapNativeForErc20(DEAD_ENDPOINT, { quoter: QUOTER, tokenIn: TOKEN_IN, tokenOut: TOKEN_OUT as Hex, fee: 0, amountInWei: 1n }),
    ).rejects.toThrow(/fee/);
    await expect(
      quoteSwapNativeForErc20(DEAD_ENDPOINT, { quoter: QUOTER, tokenIn: TOKEN_IN, tokenOut: TOKEN_OUT as Hex, fee: 2 ** 24, amountInWei: 1n }),
    ).rejects.toThrow(/fee/);
  });

  it("swap rejects a zero amountOutMinimum — minOut is the only slippage guard", async () => {
    await expect(
      swapNativeForErc20(DEAD_ENDPOINT, DUMMY_KEY, { ...base, amountOutMinimum: 0n }),
    ).rejects.toThrow(/amountOutMinimum/);
  });

  it("swap rejects a non-positive amountIn and a bad deadline", async () => {
    await expect(
      swapNativeForErc20(DEAD_ENDPOINT, DUMMY_KEY, { ...base, amountInWei: 0n }),
    ).rejects.toThrow(/amountInWei/);
    await expect(
      swapNativeForErc20(DEAD_ENDPOINT, DUMMY_KEY, { ...base, deadlineSeconds: 0 }),
    ).rejects.toThrow(/deadlineSeconds/);
  });
});
