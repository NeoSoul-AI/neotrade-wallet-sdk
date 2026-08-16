import { describe, expect, it } from "vitest";
import { OrderIntentSchema, PolicyStampSigner, SigningGateway } from "../src/index.js";

type BuyOverrides = Partial<{
  agentId: string;
  clientOrderId: string;
  market: string;
  outcome: "YES" | "NO";
  priceUsd: number;
  sizeUsd: number;
  orderType: "GTC" | "FAK";
}>;

type SellOverrides = Partial<{
  agentId: string;
  clientOrderId: string;
  market: string;
  outcome: "YES" | "NO";
  priceUsd: number;
  shares: number;
  orderType: "GTC" | "FAK";
}>;

let clock: number;

function makeGateway(): SigningGateway {
  clock = 1_000_000;
  const gateway = new SigningGateway({ signer: new PolicyStampSigner(), now: () => clock });
  gateway.unlock({ ttlMs: 60 * 60 * 1000 });
  gateway.authorizeAgent({ agentId: "a1" });
  return gateway;
}

/** A well-formed BUY intent literal; `orderType` is intentionally omitted so
 * the schema default (GTC) exercises the additive-shaped choice. */
function order(overrides: BuyOverrides = {}): Record<string, unknown> {
  return {
    agentId: "a1",
    clientOrderId: "c-1",
    market: "market-x",
    side: "BUY",
    outcome: "YES",
    priceUsd: 0.62,
    sizeUsd: 10,
    ...overrides,
  };
}

/** A well-formed SELL intent literal — sized in exact shares, never sizeUsd. */
function sellOrder(overrides: SellOverrides = {}): Record<string, unknown> {
  return {
    agentId: "a1",
    clientOrderId: "s-1",
    market: "market-x",
    side: "SELL",
    outcome: "YES",
    priceUsd: 0.62,
    shares: 10,
    ...overrides,
  };
}

describe("SigningGateway", () => {
  it("signs a well-formed order from an authorized agent and audits it", async () => {
    const gateway = makeGateway();
    const result = await gateway.signOrder(order());
    expect(result).toMatchObject({ ok: true, replay: false, clientOrderId: "c-1" });
    if (!result.ok) throw new Error("unreachable");
    expect(result.signature).toMatch(/^devsig:/);
    expect(gateway.auditLog()).toEqual([
      { at: clock, decision: "signed", agentId: "a1", clientOrderId: "c-1" },
    ]);
  });

  it("rejects everything when locked, including after session expiry", async () => {
    const gateway = makeGateway();
    gateway.lock();
    expect(await gateway.signOrder(order())).toMatchObject({ ok: false, code: "locked" });

    gateway.unlock({ ttlMs: 60_000 });
    expect(gateway.unlocked).toBe(true);
    clock += 61_000;
    expect(gateway.unlocked).toBe(false);
    expect(await gateway.signOrder(order())).toMatchObject({ ok: false, code: "locked" });
  });

  it("clamps session ttl into the [min, max] window", () => {
    const gateway = makeGateway();
    expect(gateway.unlock({ ttlMs: 5 }).expiresAt).toBe(clock + 60_000);
    expect(gateway.unlock({ ttlMs: 999 * 60 * 60 * 1000 }).expiresAt).toBe(
      clock + 24 * 60 * 60 * 1000,
    );
  });

  it("opens a no-expiry session on ttlMs: null, outside the clamp, closed only by lock()", async () => {
    const gateway = makeGateway();
    expect(gateway.unlock({ ttlMs: null }).expiresAt).toBe(Number.POSITIVE_INFINITY);
    expect(gateway.sessionExpiry).toBe(Number.POSITIVE_INFINITY);

    // Way past maxSessionTtlMs — a clamped session would have lapsed long ago.
    clock += 365 * 24 * 60 * 60 * 1000;
    expect(gateway.unlocked).toBe(true);
    expect(await gateway.signOrder(order())).toMatchObject({ ok: true });

    gateway.lock();
    expect(gateway.unlocked).toBe(false);
    expect(await gateway.signOrder(order({ clientOrderId: "c-2" }))).toMatchObject({
      ok: false,
      code: "locked",
    });
  });

  it("is fail-closed for unknown and revoked agents", async () => {
    const gateway = makeGateway();
    expect(await gateway.signOrder(order({ agentId: "ghost" }))).toMatchObject({
      ok: false,
      code: "unauthorized_agent",
    });
    gateway.revokeAgent("a1");
    expect(await gateway.signOrder(order())).toMatchObject({
      ok: false,
      code: "unauthorized_agent",
    });
  });

  it("expires per-agent authorizations", async () => {
    const gateway = makeGateway();
    gateway.authorizeAgent({ agentId: "a2", expiresAt: clock + 1_000 });
    expect(await gateway.signOrder(order({ agentId: "a2" }))).toMatchObject({ ok: true });
    clock += 1_000;
    expect(
      await gateway.signOrder(order({ agentId: "a2", clientOrderId: "c-2" })),
    ).toMatchObject({ ok: false, code: "authorization_expired" });
  });

  it("enforces market allowlists", async () => {
    const gateway = makeGateway();
    gateway.authorizeAgent({
      agentId: "a3",
      allowedMarkets: ["market-x"],
    });
    expect(
      await gateway.signOrder(order({ agentId: "a3", market: "market-y" })),
    ).toMatchObject({ ok: false, code: "market_not_allowed" });
    expect(
      await gateway.signOrder(order({ agentId: "a3", market: "market-x" })),
    ).toMatchObject({ ok: true });
  });

  it("does not police order size in either direction (2026-08-16: sizing is the host's)", async () => {
    // The gateway used to hold a USD per-order cap, comparing sizeUsd on a BUY
    // and `shares * priceUsd` on a SELL. That could not be right here: this
    // package cannot see side semantics, bankroll, the venue minimum or the
    // live book, so one shared number read as risk control on the way in and
    // as a capital trap on the way out — a position that appreciated past the
    // cap became unsellable (found live). Sizing now has exactly one owner,
    // the host's order executor. What this gate must NOT do is re-introduce a
    // second opinion about size, so both directions are asserted.
    const gateway = makeGateway();
    expect(await gateway.signOrder(order({ sizeUsd: 1_000_000 }))).toMatchObject({ ok: true });
    expect(
      await gateway.signOrder(sellOrder({ clientOrderId: "c-sell-big", shares: 1_000_000, priceUsd: 0.99 })),
    ).toMatchObject({ ok: true });
  });

  it("an unknown field is still a structural rejection (sizeFloorUsd was retired with the cap)", async () => {
    // The floor existed only to lift the cap. With the cap gone the field has
    // no meaning here, and `.strict()` must reject it rather than ignore it —
    // otherwise a stale caller keeps sending sizing hints this gate silently
    // drops, which is exactly how a policy ends up with two owners again.
    const gateway = makeGateway();
    expect(
      await gateway.signOrder({ ...order({ sizeUsd: 10 }), sizeFloorUsd: 3.77 }),
    ).toMatchObject({ ok: false, code: "invalid_request" });
  });

  it("structurally refuses anything that is not a well-formed order", async () => {
    const gateway = makeGateway();
    const attempts: unknown[] = [
      { rawHash: "0xdeadbeef" },
      "sign this please",
      null,
      order({ priceUsd: 1.2 }),
      order({ sizeUsd: -5 }),
      { ...order(), extraField: "smuggled" },
    ];
    for (const attempt of attempts) {
      expect(await gateway.signOrder(attempt)).toMatchObject({
        ok: false,
        code: "invalid_request",
      });
    }
  });

  it("replays identical orders idempotently — one signature, ever", async () => {
    const gateway = makeGateway();
    const first = await gateway.signOrder(order());
    const second = await gateway.signOrder(order());
    if (!first.ok || !second.ok) throw new Error("unreachable");
    expect(second.replay).toBe(true);
    expect(second.signature).toBe(first.signature);
    expect(gateway.auditLog().map((entry) => entry.decision)).toEqual(["signed", "replayed"]);
  });

  it("rejects clientOrderId reuse with different order content", async () => {
    const gateway = makeGateway();
    await gateway.signOrder(order());
    expect(await gateway.signOrder(order({ sizeUsd: 99 }))).toMatchObject({
      ok: false,
      code: "idempotency_conflict",
    });
  });

  it("parses a BUY intent without orderType, defaulting it to GTC", () => {
    const parsed = OrderIntentSchema.safeParse(order());
    expect(parsed.success).toBe(true);
    if (!parsed.success) throw new Error("unreachable");
    expect(parsed.data).toMatchObject({ side: "BUY", sizeUsd: 10, orderType: "GTC" });
  });

  it("parses a SELL intent sized in shares, defaulting orderType to FAK", () => {
    const parsed = OrderIntentSchema.safeParse(sellOrder());
    expect(parsed.success).toBe(true);
    if (!parsed.success) throw new Error("unreachable");
    expect(parsed.data).toMatchObject({ side: "SELL", shares: 10, orderType: "FAK" });
    expect(parsed.data).not.toHaveProperty("sizeUsd");
  });

  it("rejects a SELL intent that carries sizeUsd instead of shares", async () => {
    const gateway = makeGateway();
    // A SELL must be sized in exact shares; a USD notional on the SELL branch is
    // both a missing-shares error and an unrecognized key under .strict().
    expect(
      await gateway.signOrder({
        agentId: "a1",
        clientOrderId: "s-bad",
        market: "market-x",
        side: "SELL",
        outcome: "YES",
        priceUsd: 0.62,
        sizeUsd: 10,
      }),
    ).toMatchObject({ ok: false, code: "invalid_request" });
  });

  it("signs a well-formed SELL intent from an authorized agent", async () => {
    const gateway = makeGateway();
    const result = await gateway.signOrder(sellOrder());
    expect(result).toMatchObject({ ok: true, replay: false, clientOrderId: "s-1" });
  });

  it("signs a SELL whose proceeds would have blown the retired cap", async () => {
    // The exact shape that failed in production on 2026-08-16: an appreciated
    // position worth ~$906 under a $500 cap. `shares * priceUsd` is no longer
    // computed here at all, so the close goes through.
    const gateway = makeGateway();
    expect(
      await gateway.signOrder(sellOrder({ shares: 1041.76, priceUsd: 0.87 })),
    ).toMatchObject({ ok: true });
  });

  it("rejects SELL clientOrderId reuse with a different share count", async () => {
    const gateway = makeGateway();
    await gateway.signOrder(sellOrder());
    expect(await gateway.signOrder(sellOrder({ shares: 9 }))).toMatchObject({
      ok: false,
      code: "idempotency_conflict",
    });
  });

  it("records every rejection in the audit log", async () => {
    const gateway = makeGateway();
    await gateway.signOrder(order({ agentId: "ghost" }));
    await gateway.signOrder({ garbage: true });
    const decisions = gateway.auditLog().map((entry) => [entry.decision, entry.code]);
    expect(decisions).toEqual([
      ["rejected", "unauthorized_agent"],
      ["rejected", "invalid_request"],
    ]);
  });
});
