import { createHash } from "node:crypto";
import { z } from "zod";

/**
 * The signing gateway is the POLICY GATE every order intent must pass before
 * anything downstream will act on it — it is NOT a cryptographic signing
 * boundary. The injected OrderSigner produces an authorization stamp (see
 * PolicyStampSigner); the venue's real order signature (EIP-712) is produced
 * later, inside the venue executor that holds the trading key. What this
 * gateway enforces is structural:
 *
 * - **No blind signing exists.** The only entry point takes a
 *   schema-validated order intent. There is no method that accepts a raw
 *   hash or arbitrary bytes, so it cannot be talked into one.
 * - **Fail-closed.** Unknown agents, expired authorizations, locked
 *   sessions and malformed requests are all rejections, never fallbacks.
 * - **Exactly-once at the boundary.** A clientOrderId is signed at most
 *   once; replays return the original signature, and a replay with
 *   *different* order content is rejected as a conflict — retry loops
 *   upstream (bus, provider) can never double-spend here.
 * - **Auditable.** Every request leaves an audit entry, signed or refused.
 *
 * Every one of those is decidable WITHOUT knowing what a trade MEANS. That is
 * the line this package holds: structure, identity, session, allowlist and
 * exactly-once live here; sizing, pricing and risk live in the consuming host.
 */

/**
 * Quantity is side-aware. A BUY carries a USD notional; a SELL carries an
 * exact share count. Closing a position via a USD/price back-conversion is
 * lossy (tick-dependent), so SELL never expresses its size in USD — the
 * discriminated union makes the wrong field for a side a structural rejection.
 * `orderType` is per-order (was a submitter-constructor field) and defaults
 * per-side so pre-existing BUY callers keep working (GTC), while exits default
 * to a marketable FAK.
 *
 * SIZING IS NOT POLICY HERE (2026-08-16). Quantity and price are carried for
 * schema validation, idempotency hashing and audit only — this gate never
 * compares them against a money threshold. A USD threshold cannot be applied
 * correctly without knowing what the order MEANS: a BUY adds exposure and a
 * SELL removes it, so a single shared cap reads as risk control in one
 * direction and as a capital trap in the other (found live 2026-08-16: a
 * position that appreciated past the cap could no longer be sold, because the
 * cap was compared against `shares * priceUsd`). Direction semantics belong to
 * the trading domain, which docs/security-model.md assigns to the consuming
 * host — so the cap belongs there too, next to the bankroll, the venue minimum
 * and the live book it has to be reconciled against.
 */
export const OrderIntentSchema = z.discriminatedUnion("side", [
  z
    .object({
      agentId: z.string().min(1),
      /** Idempotency key; one signature per (agentId, clientOrderId), ever. */
      clientOrderId: z.string().min(1),
      market: z.string().min(1),
      side: z.literal("BUY"),
      outcome: z.enum(["YES", "NO"]),
      /** Prediction-market share price, strictly inside (0, 1). */
      priceUsd: z.number().gt(0).lt(1),
      /** BUY: order notional in USD. Carried for idempotency and audit; never
       * compared against a policy threshold here (see the sizing note above). */
      sizeUsd: z.number().positive().finite(),
      orderType: z.enum(["GTC", "FAK"]).default("GTC"),
    })
    .strict(),
  z
    .object({
      agentId: z.string().min(1),
      /** Idempotency key; one signature per (agentId, clientOrderId), ever. */
      clientOrderId: z.string().min(1),
      market: z.string().min(1),
      side: z.literal("SELL"),
      outcome: z.enum(["YES", "NO"]),
      /** Prediction-market share price, strictly inside (0, 1). */
      priceUsd: z.number().gt(0).lt(1),
      /** SELL: exact shares to sell, never a USD/price back-conversion. */
      shares: z.number().positive().finite(),
      orderType: z.enum(["GTC", "FAK"]).default("FAK"),
    })
    .strict(),
]);

export type OrderIntent = z.infer<typeof OrderIntentSchema>;

export interface AgentSigningAuthorization {
  agentId: string;
  /** Restrict to specific markets; absent means any market. */
  allowedMarkets?: readonly string[];
  /** Unix ms after which this authorization is dead. */
  expiresAt?: number;
}

export interface OrderSigner {
  readonly address: string;
  signOrder(order: OrderIntent): Promise<{ signature: string }>;
}

export type SignOrderResult =
  | { ok: true; signature: string; signerAddress: string; clientOrderId: string; replay: boolean }
  | { ok: false; code: SignRejectionCode; reason: string };

export type SignRejectionCode =
  | "locked"
  | "invalid_request"
  | "unauthorized_agent"
  | "authorization_expired"
  | "market_not_allowed"
  | "idempotency_conflict";

export interface AuditEntry {
  at: number;
  decision: "signed" | "replayed" | "rejected";
  agentId?: string;
  clientOrderId?: string;
  code?: SignRejectionCode;
  reason?: string;
}

export interface SigningGatewayOptions {
  signer: OrderSigner;
  now?: () => number;
  /** Bounds for FINITE session lengths; spec default is 1h within [1min, 24h].
   * They do not apply to `unlock({ ttlMs: null })`, which opens a session with
   * no expiry at all (closed only by `lock()` or process exit). */
  defaultSessionTtlMs?: number;
  maxSessionTtlMs?: number;
  minSessionTtlMs?: number;
}

export class SigningGateway {
  private readonly signer: OrderSigner;
  private readonly now: () => number;
  private readonly defaultSessionTtlMs: number;
  private readonly maxSessionTtlMs: number;
  private readonly minSessionTtlMs: number;
  private readonly authorizations = new Map<string, AgentSigningAuthorization>();
  private readonly signedOrders = new Map<string, { signature: string; orderHash: string }>();
  private readonly audit: AuditEntry[] = [];
  private sessionExpiresAt = 0;

  constructor(options: SigningGatewayOptions) {
    this.signer = options.signer;
    this.now = options.now ?? Date.now;
    this.defaultSessionTtlMs = options.defaultSessionTtlMs ?? 60 * 60 * 1000;
    this.minSessionTtlMs = options.minSessionTtlMs ?? 60 * 1000;
    this.maxSessionTtlMs = options.maxSessionTtlMs ?? 24 * 60 * 60 * 1000;
  }

  /** Opens a signing session (key unlocked by the user). A finite `ttlMs` is
   * clamped into [min, max]; `ttlMs: null` opens a session with NO expiry —
   * an explicit operator choice, distinct from `undefined` (the default TTL).
   * Represented as `expiresAt: Infinity`, never as a large finite epoch: a
   * fake far-future deadline would still be fed to expiry timers (and
   * overflow Node's 2^31-1 ms setTimeout ceiling). */
  unlock(options: { ttlMs?: number | null } = {}): { expiresAt: number } {
    if (options.ttlMs === null) {
      this.sessionExpiresAt = Number.POSITIVE_INFINITY;
      return { expiresAt: this.sessionExpiresAt };
    }
    const ttl = Math.min(
      Math.max(options.ttlMs ?? this.defaultSessionTtlMs, this.minSessionTtlMs),
      this.maxSessionTtlMs,
    );
    this.sessionExpiresAt = this.now() + ttl;
    return { expiresAt: this.sessionExpiresAt };
  }

  lock(): void {
    this.sessionExpiresAt = 0;
  }

  get unlocked(): boolean {
    return this.now() < this.sessionExpiresAt;
  }

  /** When the open session lapses (ms epoch), 0 when locked, or Infinity for
   * a no-expiry session. Expiry here is passive — `unlocked` is only a time
   * comparison, so a holder of decrypted key material needs this to know when
   * to drop it (and must NOT arm a timer, or serialize this as JSON, when it
   * is Infinity). */
  get sessionExpiry(): number {
    return this.sessionExpiresAt;
  }

  authorizeAgent(authorization: AgentSigningAuthorization): void {
    this.authorizations.set(authorization.agentId, authorization);
  }

  revokeAgent(agentId: string): void {
    this.authorizations.delete(agentId);
  }

  status(): { unlocked: boolean; signerAddress: string; authorizedAgents: number } {
    return {
      unlocked: this.unlocked,
      signerAddress: this.signer.address,
      authorizedAgents: this.authorizations.size,
    };
  }

  auditLog(): readonly AuditEntry[] {
    return this.audit;
  }

  async signOrder(request: unknown): Promise<SignOrderResult> {
    if (!this.unlocked) {
      return this.reject(undefined, "locked", "signing session locked or expired");
    }

    const parsed = OrderIntentSchema.safeParse(request);
    if (!parsed.success) {
      // Anything that is not a well-formed order intent — raw hashes,
      // arbitrary payloads, extra fields — dies here.
      return this.reject(undefined, "invalid_request", parsed.error.issues[0]?.message ?? "invalid order");
    }
    const order = parsed.data;

    const authorization = this.authorizations.get(order.agentId);
    if (!authorization) {
      return this.reject(order, "unauthorized_agent", `agent ${order.agentId} has no signing authorization`);
    }
    if (authorization.expiresAt !== undefined && this.now() >= authorization.expiresAt) {
      return this.reject(order, "authorization_expired", `authorization for ${order.agentId} expired`);
    }
    if (authorization.allowedMarkets && !authorization.allowedMarkets.includes(order.market)) {
      return this.reject(order, "market_not_allowed", `market ${order.market} not in allowlist`);
    }
    // NO SIZE CHECK HERE, BY DESIGN (see OrderIntentSchema's sizing note). The
    // per-order USD cap this gate used to enforce now has exactly one owner:
    // the host's order executor, which resolves sizing with the context this
    // gate lacks (side, bankroll, venue minimum, live book).

    const idempotencyKey = `${order.agentId} ${order.clientOrderId}`;
    const orderHash = hashOrder(order);
    const existing = this.signedOrders.get(idempotencyKey);
    if (existing) {
      if (existing.orderHash !== orderHash) {
        return this.reject(
          order,
          "idempotency_conflict",
          `clientOrderId ${order.clientOrderId} was already used for a different order`,
        );
      }
      this.audit.push({
        at: this.now(),
        decision: "replayed",
        agentId: order.agentId,
        clientOrderId: order.clientOrderId,
      });
      return {
        ok: true,
        signature: existing.signature,
        signerAddress: this.signer.address,
        clientOrderId: order.clientOrderId,
        replay: true,
      };
    }

    const { signature } = await this.signer.signOrder(order);
    this.signedOrders.set(idempotencyKey, { signature, orderHash });
    this.audit.push({
      at: this.now(),
      decision: "signed",
      agentId: order.agentId,
      clientOrderId: order.clientOrderId,
    });
    return {
      ok: true,
      signature,
      signerAddress: this.signer.address,
      clientOrderId: order.clientOrderId,
      replay: false,
    };
  }

  private reject(
    order: OrderIntent | undefined,
    code: SignRejectionCode,
    reason: string,
  ): SignOrderResult {
    this.audit.push({
      at: this.now(),
      decision: "rejected",
      agentId: order?.agentId,
      clientOrderId: order?.clientOrderId,
      code,
      reason,
    });
    return { ok: false, code, reason };
  }
}

function hashOrder(order: OrderIntent): string {
  // Fixed field order so hashing is independent of object key order. The
  // quantity slot is side-specific (sizeUsd for BUY, shares for SELL); `side`
  // is part of the canonical form, so a BUY and a SELL that happen to share a
  // numeric quantity can never collide, and the replay-conflict check works
  // per-variant.
  const quantity = order.side === "BUY" ? order.sizeUsd : order.shares;
  const canonical = JSON.stringify([
    order.agentId,
    order.clientOrderId,
    order.market,
    order.side,
    order.outcome,
    order.priceUsd,
    quantity,
    order.orderType,
  ]);
  return createHash("sha256").update(canonical).digest("hex");
}
