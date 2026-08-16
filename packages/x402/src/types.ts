/** Our own face on x402. Deliberately NOT re-exporting @x402/core's types:
 * the isolation rule means the sidecar must never need to name a third-party
 * type to call us. Field names match the SERVER's `accepts[0]` verbatim so a
 * quote can be handed over untouched — one fewer place to typo a field. */
export interface PaymentQuote {
  scheme: string;
  network: string;
  asset: string;
  payTo: string;
  /** Atomic units as a DECIMAL STRING. Never a number — 5e18 does not fit.
   *
   * The server (x402Version 1) calls this `maxAmountRequired`; the SDK's own
   * PaymentRequirements calls it `amount`. payment.ts translates. See the note
   * there — passing this quote through untranslated is NOT safe. */
  maxAmountRequired: string;
  maxTimeoutSeconds: number;
  resource: string;
  description: string;
  /** The live server sends exactly two keys (assetTransferMethod,
   * signerAddress). Treat every other key as absent. */
  extra: Record<string, unknown>;
}

/**
 * A signed payment, ready to settle.
 *
 * ONLY `payload` goes on the wire. neo-billing's settle handler takes a JSON
 * STRING of this inner object (`{signature, permit2Authorization}`) — verified
 * against `internal/httpapi/payments_api.go`'s `Payment string` field and its
 * `nonceFromPayload`, which unmarshals `permit2Authorization` directly, plus
 * the reference probe `cmd/x402probe/main.go`, which posts
 * `json.Marshal(sdkPayload.Payload)` and nothing else. The three fields beside
 * it are ours, for the receipt and for reading a failure afterwards; wrapping
 * the payload in them before posting would produce a body the facilitator
 * cannot parse.
 */
export interface SignedPayment {
  x402Version: number;
  scheme: string;
  network: string;
  payload: Record<string, unknown>;
}

/** Where to reach the chain. Both required — no silent default to a public
 * third-party RPC (spec decision 3). */
export interface ChainEndpoint {
  rpcUrl: string;
  chainId: number;
}
