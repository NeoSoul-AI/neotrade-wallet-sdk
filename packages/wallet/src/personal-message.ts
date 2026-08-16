import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { addressFromUncompressedPublicKey, hex0x } from "./keys.js";

/**
 * EIP-191 `personal_sign` primitives on @noble/* only (viem stays behind
 * executor-polymarket, ethers behind executor-predictfun).
 *
 * Scope is deliberately narrow: the sidecar's account module signs the billing
 * server's SIWE challenge text VERBATIM with the in-memory proof key. This is
 * NOT a signing-gateway method (the gateway signs structured orders only) and
 * is never exposed as an agent tool.
 */

export function hashPersonalMessage(message: string): Uint8Array {
  const body = new TextEncoder().encode(message);
  const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${body.length}`);
  const bytes = new Uint8Array(prefix.length + body.length);
  bytes.set(prefix);
  bytes.set(body, prefix.length);
  return keccak_256(bytes);
}

/** 65-byte r||s||v signature (v = 27/28), hex-encoded — what EVM verifiers
 * and viem's recoverMessageAddress expect. Deterministic (RFC6979, low-s). */
export function signPersonalMessage(privateKey: `0x${string}`, message: string): `0x${string}` {
  const raw = secp256k1.sign(hashPersonalMessage(message), hexToBytes(privateKey), {
    prehash: false,
    format: "recovered",
  });
  // noble's "recovered" layout is recovery||r||s — Ethereum wants r||s||v.
  const out = new Uint8Array(65);
  out.set(raw.subarray(1));
  out[64] = 27 + raw[0]!;
  return hex0x(out);
}

export function recoverPersonalMessageAddress(message: string, signature: `0x${string}`): `0x${string}` {
  const sig = hexToBytes(signature);
  if (sig.length !== 65) {
    throw new Error("personal message signature must be 65 bytes (r||s||v)");
  }
  const v = sig[64]!;
  const recovery = v >= 27 ? v - 27 : v;
  if (recovery !== 0 && recovery !== 1) {
    throw new Error(`invalid recovery byte: ${v}`);
  }
  const recovered = new Uint8Array(65);
  recovered[0] = recovery;
  recovered.set(sig.subarray(0, 64), 1);
  const point = secp256k1.Signature.fromBytes(recovered, "recovered").recoverPublicKey(
    hashPersonalMessage(message),
  );
  return addressFromUncompressedPublicKey(point.toBytes(false));
}

function hexToBytes(hex: `0x${string}`): Uint8Array {
  const body = hex.slice(2);
  if (body.length % 2 !== 0 || /[^0-9a-fA-F]/.test(body)) {
    throw new Error("invalid hex string");
  }
  const out = new Uint8Array(body.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(body.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
