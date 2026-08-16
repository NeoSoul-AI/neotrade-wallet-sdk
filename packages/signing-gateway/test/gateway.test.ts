import { describe, expect, it } from "vitest";
import { OrderIntentSchema, PolicyStampSigner, SigningGateway } from "../src/index.js";

type BuyOverrides = Partial<{
  agentId: string;
  clientOrderId: string;
  market: string;
  outcome: "YES" | "NO";
  priceUsd: number;
  sizeUsd: number;
  sizeFloorUsd: number;
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
  gateway.authorizeAgent({ agentId: "a1", maxOrderUsd: 100 });
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
    gateway.authorizeAgent({ agentId: "a2", maxOrderUsd: 100, expiresAt: clock + 1_000 });
    expect(await gateway.signOrder(order({ agentId: "a2" }))).toMatchObject({ ok: true });
    clock += 1_000;
    expect(
      await gateway.signOrder(order({ agentId: "a2", clientOrderId: "c-2" })),
    ).toMatchObject({ ok: false, code: "authorization_expired" });
  });

  it("enforces market allowlists and per-order caps", async () => {
    const gateway = makeGateway();
    gateway.authorizeAgent({
      agentId: "a3",
      maxOrderUsd: 50,
      allowedMarkets: ["market-x"],
    });
    expect(
      await gateway.signOrder(order({ agentId: "a3", market: "market-y" })),
    ).toMatchObject({ ok: false, code: "market_not_allowed" });
    expect(
      await gateway.signOrder(order({ agentId: "a3", sizeUsd: 51 })),
    ).toMatchObject({ ok: false, code: "over_limit" });
    expect(
      await gateway.signOrder(order({ agentId: "a3", sizeUsd: 50 })),
    ).toMatchObject({ ok: true });
  });

  it("a BUY carrying sizeFloorUsd may reach exactly that floor past maxOrderUsd", async () => {
    // Operator decision (2026-07-29): the venue's minimum order outranks the
    // per-order cap — an agent capped at $2 must still be able to place the
    // $3.77 minimum the venue demands. The floor comes from the signed intent
    // itself (the same trust level as priceUsd, see the cap comment), so it
    // is audited with the order.
    const gateway = makeGateway();
    gateway.authorizeAgent({ agentId: "a4", maxOrderUsd: 2 });
    expect(
      await gateway.signOrder(order({ agentId: "a4", sizeUsd: 3.77, sizeFloorUsd: 3.77 })),
    ).toMatchObject({ ok: true });
  });

  it("sizeFloorUsd is a floor for the cap, never a waiver: sizes above BOTH still reject", async () => {
    const gateway = makeGateway();
    gateway.authorizeAgent({ agentId: "a4", maxOrderUsd: 2 });
    expect(
      await gateway.signOrder(order({ agentId: "a4", sizeUsd: 5, sizeFloorUsd: 3.77 })),
    ).toMatchObject({ ok: false, code: "over_limit" });
  });

  it("without sizeFloorUsd the per-order cap is unchanged", async () => {
    const gateway = makeGateway();
    gateway.authorizeAgent({ agentId: "a4", maxOrderUsd: 2 });
    expect(await gateway.signOrder(order({ agentId: "a4", sizeUsd: 3.77 }))).toMatchObject({
      ok: false,
      code: "over_limit",
    });
  });

  it("sizeFloorUsd is part of the signed content: a replay with a different floor is an idempotency conflict", async () => {
    const gateway = makeGateway();
    const first = await gateway.signOrder(order({ sizeUsd: 10, sizeFloorUsd: 3.77 }));
    expect(first).toMatchObject({ ok: true, replay: false });
    expect(await gateway.signOrder(order({ sizeUsd: 10, sizeFloorUsd: 9.99 }))).toMatchObject({
      ok: false,
      code: "idempotency_conflict",
    });
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

  it("enforces the per-order cap on a SELL against shares * priceUsd", async () => {
    const gateway = makeGateway();
    gateway.authorizeAgent({ agentId: "a3", maxOrderUsd: 50 });
    // 100 shares * 0.62 = 62 USD-equivalent > 50 cap.
    expect(
      await gateway.signOrder(sellOrder({ agentId: "a3", shares: 100, priceUsd: 0.62 })),
    ).toMatchObject({ ok: false, code: "over_limit" });
    // 80 shares * 0.62 = 49.6 <= 50 cap.
    expect(
      await gateway.signOrder(sellOrder({ agentId: "a3", shares: 80, priceUsd: 0.62 })),
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
