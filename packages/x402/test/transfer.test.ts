import { describe, expect, it } from "vitest";
import { checksumAddress, encodeErc20Transfer } from "../src/transfer.js";

describe("encodeErc20Transfer", () => {
  it("encodes transfer(address,uint256)", () => {
    const data = encodeErc20Transfer("0x0000000000000000000000000000000000000002", 1_000_000n);
    expect(data.slice(0, 10)).toBe("0xa9059cbb");            // transfer(address,uint256)
    expect(data).toHaveLength(2 + 8 + 64 * 2);               // selector + 2 words
    expect(data.endsWith((1_000_000n).toString(16).padStart(64, "0"))).toBe(true);
  });
});

describe("checksumAddress", () => {
  const EIP55 = "0xA0Cf798816D4b9b9866b5330EEa46a18382f251e";

  it("normalises a lowercase address to its EIP-55 form", () => {
    expect(checksumAddress(EIP55.toLowerCase())).toBe(EIP55);
  });

  it("accepts a correctly checksummed address unchanged, trimming whitespace", () => {
    expect(checksumAddress(`  ${EIP55} `)).toBe(EIP55);
  });

  it("accepts all-uppercase input — no checksum carried, per EIP-55", () => {
    expect(checksumAddress(`0x${EIP55.slice(2).toUpperCase()}`)).toBe(EIP55);
  });

  it("accepts a correctly checksummed body behind an uppercase 0X prefix", () => {
    // EIP-55 checksums only the 40-char body; some explorers emit "0X". A
    // prefix-only case difference must not read as a checksum mismatch.
    expect(checksumAddress(`0X${EIP55.slice(2)}`)).toBe(EIP55);
  });

  it("rejects a mixed-case address whose checksum does not match", () => {
    // The valid form with its first hex letter's case flipped — the
    // fat-fingered paste this validation exists to catch. viem's getAddress
    // alone accepts this silently, which is why the check is ours.
    expect(() => checksumAddress(`0xa${EIP55.slice(3)}`)).toThrow(/checksum mismatch/);
  });

  it("rejects malformed input", () => {
    expect(() => checksumAddress("not-an-address")).toThrow();
    expect(() => checksumAddress("0x1234")).toThrow();
    expect(() => checksumAddress("")).toThrow();
  });
});
