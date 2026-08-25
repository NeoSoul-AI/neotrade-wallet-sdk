import { describe, expect, it } from "vitest";
import { signPayment } from "../src/payment.js";
import type { PaymentQuote } from "../src/types.js";

// The LIVE 402 shape, verbatim (probed 2026-08-08). `extra` deliberately has
// only the two keys the server actually sends — INTEGRATION.md's example showed
// five, and a client that reads extra.name gets undefined where an EIP-712
// domain is required. If this fixture ever grows keys, that is a server change
// to verify, not a convenience to accept.
const QUOTE: PaymentQuote = {
  scheme: "exact",
  network: "eip155:97",
  asset: "0x7f281cf9ce0fa8fa6e4c8a90c849670b1f045209",
  payTo: "0x2802a1c8764caf920c90c6913599b568c2ab3efa",
  maxAmountRequired: "5000000000000000000",
  maxTimeoutSeconds: 60,
  resource: "/v1/credits/purchase",
  description: "topup_5",
  extra: {
    assetTransferMethod: "permit2",
    signerAddress: "0xa16706b18366b7f9fedff4c9a154745481af4023",
  },
};
// anvil #0 — a well-known throwaway test key, never a real one.
const PRIV = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as const;

describe("signPayment", () => {
  it("produces a permit2 payload, not an EIP-3009 one", async () => {
    const signed = await signPayment(QUOTE, PRIV);
    expect(signed.x402Version).toBe(1);
    expect(signed.scheme).toBe("exact");
    expect(signed.network).toBe("eip155:97");
    // The whole reason ExactEvmScheme is used instead of ExactEvmSchemeV1: V1
    // signs EIP-3009 (`authorization` + `signature`) unconditionally; it never
    // reads extra.assetTransferMethod. A permit2 payload carries
    // `permit2Authorization` instead. Getting this wrong yields a payload the
    // facilitator rejects — safe, but silently unbuyable, which is worth a test.
    expect(signed.payload).toHaveProperty("permit2Authorization");
    expect(signed.payload).toHaveProperty("signature");
    expect(signed.payload).not.toHaveProperty("authorization");
  });

  // NOT a determinism test, which is what this looked like it should be. The
  // SDK draws a fresh 32-byte Permit2 nonce per call (createPermit2Nonce) and
  // stamps a wall-clock deadline, so two signings of one quote differ by
  // construction — and that is the property worth pinning, because a Permit2
  // nonce is single-use on-chain: two payments sharing one would make the
  // second unsettleable.
  it("draws a fresh nonce per signature, so one quote never signs the same bytes twice", async () => {
    const a = await signPayment(QUOTE, PRIV);
    const b = await signPayment(QUOTE, PRIV);
    const nonceOf = (p: Record<string, unknown>) =>
      (p["permit2Authorization"] as { nonce: string }).nonce;
    expect(nonceOf(a.payload)).not.toBe(nonceOf(b.payload));
    expect(a.payload["signature"]).not.toBe(b.payload["signature"]);
  });

  // 5e18 is above Number.MAX_SAFE_INTEGER. Anything that routes the atomic
  // amount through a JS number silently changes what gets paid.
  it("never widens the atomic amount through a number", async () => {
    const signed = await signPayment(QUOTE, PRIV);
    expect(JSON.stringify(signed.payload)).toContain("5000000000000000000");
  });

  // The server calls it maxAmountRequired; the SDK's PaymentRequirements calls
  // it `amount`. Passing the quote through untranslated leaves the permitted
  // amount undefined. This test is the reason payment.ts maps the field.
  it("translates maxAmountRequired into the permitted amount", async () => {
    const signed = await signPayment(QUOTE, PRIV);
    const auth = signed.payload["permit2Authorization"] as {
      permitted: { amount: string; token: string };
      witness: { to: string };
    };
    expect(auth.permitted.amount).toBe("5000000000000000000");
    expect(auth.permitted.token.toLowerCase()).toBe(QUOTE.asset);
    expect(auth.witness.to.toLowerCase()).toBe(QUOTE.payTo);
  });

  it("refuses a quote whose transfer method is not permit2", async () => {
    // Fail closed: the permit2 path is the only one ever verified against a real
    // facilitator. Silently signing an untested scheme is how money moves in a
    // way no test covers.
    await expect(
      signPayment({ ...QUOTE, extra: { assetTransferMethod: "eip3009" } }, PRIV),
    ).rejects.toThrow(/permit2/);
    await expect(signPayment({ ...QUOTE, extra: {} }, PRIV)).rejects.toThrow(/permit2/);
  });

  it("refuses a quote with no asset or no payTo rather than signing a blank", async () => {
    await expect(signPayment({ ...QUOTE, asset: "" }, PRIV)).rejects.toThrow();
    await expect(signPayment({ ...QUOTE, payTo: "" }, PRIV)).rejects.toThrow();
  });

  it("refuses an amount that is not a positive integer string", async () => {
    // "0" signs cleanly and authorises nothing — the one bad amount that does
    // not announce itself.
    await expect(signPayment({ ...QUOTE, maxAmountRequired: "0" }, PRIV)).rejects.toThrow(/positive/);
    await expect(signPayment({ ...QUOTE, maxAmountRequired: "5.0" }, PRIV)).rejects.toThrow(/positive/);
    await expect(signPayment({ ...QUOTE, maxAmountRequired: "" }, PRIV)).rejects.toThrow(/positive/);
  });

  // The widened second parameter: a browser has no private key, only an
  // injected wallet exposing `{address, signTypedData}` — which is the entire
  // ClientEvmSigner surface the permit2 path touches. The recording signer
  // proves the pass-through: what it returns IS the payload's signature, its
  // address IS the payer, and what it is asked to sign is the Permit2 witness
  // transfer — not an EIP-3009 authorization.
  it("accepts an injected {address, signTypedData} signer and passes it through", async () => {
    const asked: Array<{ domain: Record<string, unknown>; primaryType: string }> = [];
    const signer = {
      address: "0xa16706b18366b7f9fedff4c9a154745481af4023" as const,
      signTypedData: async (message: { domain: Record<string, unknown>; primaryType: string }) => {
        asked.push({ domain: message.domain, primaryType: message.primaryType });
        return "0xdeadbeef" as const;
      },
    };
    const signed = await signPayment(QUOTE, signer);
    expect(signed.payload["signature"]).toBe("0xdeadbeef");
    const auth = signed.payload["permit2Authorization"] as { from: string };
    expect(auth.from.toLowerCase()).toBe(signer.address);
    expect(asked).toHaveLength(1);
    expect(asked[0]?.primaryType).toBe("PermitWitnessTransferFrom");
    expect(asked[0]?.domain["name"]).toBe("Permit2");
  });

  it("signs the same structure through an injected signer as through the key", async () => {
    // Same key both ways: once as the raw hex, once wrapped the way a browser
    // wallet would wrap itself. Nonce and deadline differ by construction, so
    // the pin is on everything that must not differ.
    const { privateKeyToAccount } = await import("viem/accounts");
    const account = privateKeyToAccount(PRIV);
    const viaKey = await signPayment(QUOTE, PRIV);
    const viaSigner = await signPayment(QUOTE, {
      address: account.address,
      signTypedData: (message) =>
        account.signTypedData(message as Parameters<typeof account.signTypedData>[0]),
    });
    const authOf = (p: Record<string, unknown>) =>
      p["permit2Authorization"] as {
        from: string;
        spender: string;
        permitted: { token: string; amount: string };
        witness: { to: string; validAfter: string };
      };
    expect(authOf(viaSigner.payload).from).toBe(authOf(viaKey.payload).from);
    expect(authOf(viaSigner.payload).spender).toBe(authOf(viaKey.payload).spender);
    expect(authOf(viaSigner.payload).permitted).toEqual(authOf(viaKey.payload).permitted);
    expect(authOf(viaSigner.payload).witness).toEqual(authOf(viaKey.payload).witness);
  });

  it("refuses leading-zero encodings of zero (PAY-1)", async () => {
    // "00" and "000" match the digit regex and are not the literal "0", yet
    // BigInt("00") is 0n — the zero guard must hold for every spelling of zero.
    await expect(signPayment({ ...QUOTE, maxAmountRequired: "00" }, PRIV)).rejects.toThrow(/positive/);
    await expect(signPayment({ ...QUOTE, maxAmountRequired: "000" }, PRIV)).rejects.toThrow(/positive/);
  });
});
