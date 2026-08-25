import { ExactEvmScheme } from "@x402/evm/exact/client";
import { toSigner, type TypedDataSigner } from "./signer.js";
import type { PaymentQuote, SignedPayment } from "./types.js";

/**
 * Signs the 402 quote into a Permit2 payment payload. No transaction, no gas —
 * the one on-chain step is the Permit2 approval (permit2.ts), which happens
 * before this.
 *
 * WHY ExactEvmScheme AND NOT ExactEvmSchemeV1: the server answers
 * `x402Version: 1`, so the V1 class looks like the obvious choice, and it is the
 * wrong one. ExactEvmSchemeV1 signs an EIP-3009 transferWithAuthorization
 * unconditionally and never reads extra.assetTransferMethod; ExactEvmScheme is
 * the class that routes on it (`createPaymentPayload` reads
 * `paymentRequirements.extra?.assetTransferMethod ?? "eip3009"`). The protocol
 * version is a PARAMETER to createPaymentPayload, not a property of the class.
 *
 * WHY THE QUOTE IS TRANSLATED AND NOT PASSED THROUGH: the SDK's
 * PaymentRequirements names the atomic amount `amount`; the server names it
 * `maxAmountRequired`. Handing `accepts[0]` over unchanged leaves `amount`
 * undefined, which reaches `BigInt(undefined)` inside the Permit2 signer and
 * throws — the failure is loud, but it is also unnecessary, and the two names
 * are close enough that a reader will assume they match. They do not.
 *
 * All of the above was read out of @x402/evm@2.21.0's own compiled source
 * (`chunk-3QTA5JH4.mjs`, `chunk-JFVEMVMS.mjs`), not from its docs.
 *
 * THE SIGNER IS A UNION: a daemon holding key material passes the private key;
 * a browser passes the injected wallet as `{address, signTypedData}` — signing
 * is pure EIP-712, so that pair is the whole requirement. Existing callers are
 * byte-identical.
 */
export async function signPayment(
  quote: PaymentQuote,
  keyOrSigner: `0x${string}` | TypedDataSigner,
): Promise<SignedPayment> {
  const method = quote.extra?.["assetTransferMethod"];
  if (method !== "permit2") {
    throw new Error(
      `x402: unsupported assetTransferMethod ${String(method)} — only permit2 is verified against a real facilitator`,
    );
  }
  if (quote.asset === "" || quote.payTo === "") {
    throw new Error("x402: quote is missing asset or payTo");
  }
  if (!/^[0-9]+$/.test(quote.maxAmountRequired) || BigInt(quote.maxAmountRequired) <= 0n) {
    // Fail before signing rather than after: an amount the SDK cannot turn into
    // a positive BigInt produces either a throw deep inside viem or, for zero, a
    // perfectly valid signature authorising nothing. Zero is judged on the
    // parsed VALUE, not the literal "0" — "00" spells zero too.
    throw new Error(`x402: maxAmountRequired ${quote.maxAmountRequired} is not a positive integer string`);
  }

  const scheme = new ExactEvmScheme(toSigner(keyOrSigner));
  const result = await scheme.createPaymentPayload(1, {
    scheme: quote.scheme,
    network: quote.network as `${string}:${string}`,
    asset: quote.asset,
    amount: quote.maxAmountRequired,
    payTo: quote.payTo,
    maxTimeoutSeconds: quote.maxTimeoutSeconds,
    extra: quote.extra,
  });

  // scheme/network come from the QUOTE: PaymentPayloadResult is
  // `Pick<PaymentPayload, "x402Version" | "payload"> & { extensions? }` and
  // carries neither.
  return { x402Version: 1, scheme: quote.scheme, network: quote.network, payload: result.payload };
}
