import { createHash } from "node:crypto";
import type { OrderIntent, OrderSigner } from "./gateway.js";

/**
 * NOT A CRYPTOGRAPHIC SIGNER. Produces a deterministic sha256 digest of the
 * order intent — a policy stamp proving the intent passed the gateway's
 * checks (session, limits, idempotency, audit), nothing more. Venue
 * submitters verify the stamp is present and otherwise discard it; the
 * cryptographic order signature (EIP-712) is produced downstream by the
 * venue executor holding the trading key. The `devsig:` prefix is
 * historical — it predates the rename and is kept because receipt logs
 * store it.
 */
export class PolicyStampSigner implements OrderSigner {
  readonly address = "0xDEV0000000000000000000000000000000000000";

  async signOrder(order: OrderIntent): Promise<{ signature: string }> {
    const digest = createHash("sha256")
      .update(JSON.stringify(order))
      .digest("hex");
    return { signature: `devsig:${digest}` };
  }
}
