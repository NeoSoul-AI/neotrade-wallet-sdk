import { createPublicClient, createWalletClient, http, type Chain, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { createPermit2ApprovalTx, getPermit2AllowanceReadParams } from "@x402/evm/exact/client";
import type { ChainEndpoint } from "./types.js";

const ERC20_READ = [
  {
    type: "function",
    name: "balanceOf",
    stateMutability: "view",
    inputs: [{ name: "a", type: "address" }],
    outputs: [{ type: "uint256" }],
  },
  { type: "function", name: "decimals", stateMutability: "view", inputs: [], outputs: [{ type: "uint8" }] },
] as const;

/** A chain definition built from the operator's own endpoint. viem needs one to
 * send a transaction (it will not guess a chain id), and every field beyond the
 * id is display-only for our single use. Deliberately NOT one of viem/chains'
 * presets: those carry their own default RPC URLs, and a preset silently
 * outvoting the configured endpoint is exactly the third-party-RPC fallback
 * spec decision 3 forbids. */
export function chainOf(e: ChainEndpoint): Chain {
  return {
    id: e.chainId,
    name: `eip155:${e.chainId}`,
    nativeCurrency: { name: "native", symbol: "NATIVE", decimals: 18 },
    rpcUrls: { default: { http: [e.rpcUrl] } },
  };
}

export async function readPermit2Allowance(e: ChainEndpoint, asset: Hex, owner: Hex): Promise<bigint> {
  const pc = createPublicClient({ transport: http(e.rpcUrl) });
  return (await pc.readContract(
    getPermit2AllowanceReadParams({ tokenAddress: asset, ownerAddress: owner }),
  )) as bigint;
}

/** decimals() from the CONTRACT, never assumed. mUSDC is 18, not the 6 that the
 * name "USDC" implies — assuming 6 misreads a balance by 10^12. */
export async function readDecimals(e: ChainEndpoint, asset: Hex): Promise<number> {
  const pc = createPublicClient({ transport: http(e.rpcUrl) });
  return Number(await pc.readContract({ address: asset, abi: ERC20_READ, functionName: "decimals" }));
}

export async function readErc20Balance(e: ChainEndpoint, asset: Hex, owner: Hex): Promise<bigint> {
  const pc = createPublicClient({ transport: http(e.rpcUrl) });
  return (await pc.readContract({
    address: asset,
    abi: ERC20_READ,
    functionName: "balanceOf",
    args: [owner],
  })) as bigint;
}

export async function readNativeBalance(e: ChainEndpoint, owner: Hex): Promise<bigint> {
  return createPublicClient({ transport: http(e.rpcUrl) }).getBalance({ address: owner });
}

/**
 * The ONE gas-paying transaction in the whole flow: approve(Permit2,
 * MaxUint256) on the payment token. mUSDC has no EIP-2612 (DOMAIN_SEPARATOR()
 * and nonces() both revert), so there is no signature-only alternative.
 *
 * Waits for the receipt and THROWS on a reverted transaction: returning a hash
 * for a reverted approve would let the caller go on to sign a payment that
 * cannot possibly settle.
 */
export async function approvePermit2(
  e: ChainEndpoint,
  asset: Hex,
  privateKey: Hex,
): Promise<{ txHash: Hex }> {
  const account = privateKeyToAccount(privateKey);
  const chain = chainOf(e);
  const wc = createWalletClient({ account, chain, transport: http(e.rpcUrl) });
  const pc = createPublicClient({ chain, transport: http(e.rpcUrl) });
  const tx = createPermit2ApprovalTx(asset);
  const txHash = await wc.sendTransaction({ to: tx.to, data: tx.data });
  const receipt = await pc.waitForTransactionReceipt({ hash: txHash });
  if (receipt.status !== "success") {
    throw new Error(`x402: Permit2 approval ${txHash} reverted on-chain`);
  }
  return { txHash };
}
