import { describe, expect, it } from "vitest";
import {
  hashPersonalMessage,
  recoverPersonalMessageAddress,
  signPersonalMessage,
} from "../src/personal-message.js";

// Golden vector generated once out-of-repo with viem 2.x (privateKeyToAccount
// + signMessage + recoverMessageAddress round-trip) against the well-known
// anvil #0 test key — pins this implementation to what EVM tooling verifies.
// MESSAGE is an arbitrary SIWE-shaped fixture, NOT a real server message: the
// signature below is pinned to these exact bytes, so editing the text (e.g.
// to match a deployment hostname) invalidates the vector. Leave it alone.
const PRIV = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as const;
const ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const MESSAGE =
  "billing.neosoul.ai wants you to sign in with your Ethereum account:\n" +
  "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266\n\n" +
  "URI: https://billing.neosoul.ai\nVersion: 1\nChain ID: 1\n" +
  // NOT a stale product name — these are the exact bytes the pinned hash and
  // signature below were generated over. A rename pass changed this nonce once
  // and broke all three vectors; the string is cryptographic input, not a
  // label, so it stays as generated.
  "Nonce: neoclaw-golden-vector\nIssued At: 2026-08-08T00:00:00Z";
const HASH = "0x687932497aa3310412053f3a1dfac25177af7d4c51fdaa63c881c66c5e4e1403";
const SIGNATURE =
  "0xdf3ddf32a69118f9e727e37b8dc416cfb95762ed909ce5ff10ce61e52fea451f09b38d62ca6d26f01fd91838b7951b25fe6864cfcdd2ab10e34fd223de36a4f51b";

describe("personal-message (EIP-191)", () => {
  it("hashes per EIP-191 (golden vector)", () => {
    const hex = Array.from(hashPersonalMessage(MESSAGE), (b) => b.toString(16).padStart(2, "0")).join("");
    expect(`0x${hex}`).toBe(HASH);
  });

  it("signs byte-identically to viem (deterministic RFC6979, low-s)", () => {
    expect(signPersonalMessage(PRIV, MESSAGE)).toBe(SIGNATURE);
  });

  it("recovers the checksummed signer address", () => {
    expect(recoverPersonalMessageAddress(MESSAGE, SIGNATURE)).toBe(ADDRESS);
  });

  // Tampering must never yield the real signer. It can fail EITHER way: the
  // recovery point may not exist on the curve (throws) or it may recover some
  // other address. Both are correct; asserting only the second would make this
  // test's outcome an accident of the pinned vector.
  it("a tampered message never recovers the real signer", () => {
    let recovered: string | undefined;
    try {
      recovered = recoverPersonalMessageAddress(`${MESSAGE}!`, SIGNATURE);
    } catch {
      recovered = undefined;
    }
    expect(recovered).not.toBe(ADDRESS);
  });

  it("rejects a malformed signature", () => {
    expect(() => recoverPersonalMessageAddress(MESSAGE, "0x1234")).toThrow(/65 bytes/);
  });
});
