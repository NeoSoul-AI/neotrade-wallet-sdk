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

  it("never lets distinct (agentId, clientOrderId) pairs share an idempotency slot (GAT-3)", async () => {
    // A space-joined key maps ("alice", "bob sell-1") and ("alice bob", "sell-1")
    // to the same slot, so the second agent's FIRST order — potentially a
    // position-closing SELL — is permanently rejected as a conflict.
    const gateway = makeGateway();
    gateway.authorizeAgent({ agentId: "alice" });
    gateway.authorizeAgent({ agentId: "alice bob" });
    expect(
      await gateway.signOrder(order({ agentId: "alice", clientOrderId: "bob sell-1" })),
    ).toMatchObject({ ok: true, replay: false });
    expect(
      await gateway.signOrder(order({ agentId: "alice bob", clientOrderId: "sell-1" })),
    ).toMatchObject({ ok: true, replay: false });
  });
});

/** A minimal in-memory OrderLedgerStore, the shape a persisting host would
 * wrap around its own storage. `lieOnGet` simulates a store whose reads are
 * stale (another process wrote between our read and our insert) — the case
 * the atomic insert exists for. */
function memoryLedger(options: { lieOnGet?: boolean } = {}) {
  const entries = new Map<string, { signature: string; orderHash: string }>();
  return {
    entries,
    get: (key: string) => (options.lieOnGet ? undefined : entries.get(key)),
    insertIfAbsent(key: string, entry: { signature: string; orderHash: string }) {
      const existing = entries.get(key);
      if (existing) return existing;
      entries.set(key, entry);
      return undefined;
    },
  };
}

describe("SigningGateway bounded memory (GAT-2)", () => {
  it("rejects an auditLimit that is not a positive integer, rather than silently unbounding", () => {
    // NaN makes `length >= limit` compare false forever, so the OOM guard
    // would be silently gone. Bad config must be a construction-time
    // rejection, fail-closed.
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, 0, -1, 1.5]) {
      expect(
        () => new SigningGateway({ signer: new PolicyStampSigner(), auditLimit: bad }),
      ).toThrow(/auditLimit/);
    }
  });

  it("bounds the audit log at auditLimit, dropping the oldest entries", async () => {
    clock = 1_000_000;
    const gateway = new SigningGateway({
      signer: new PolicyStampSigner(),
      now: () => clock,
      auditLimit: 2,
    });
    gateway.unlock({ ttlMs: 60 * 60 * 1000 });
    gateway.authorizeAgent({ agentId: "a1" });
    await gateway.signOrder(order({ clientOrderId: "c-1" }));
    await gateway.signOrder(order({ clientOrderId: "c-2" }));
    await gateway.signOrder(order({ clientOrderId: "c-3" }));
    expect(gateway.auditLog().map((entry) => entry.clientOrderId)).toEqual(["c-2", "c-3"]);
  });

  it("defaults the audit bound to 10_000 entries", async () => {
    const gateway = makeGateway();
    for (let i = 0; i < 10_050; i++) {
      await gateway.signOrder({ garbage: i });
    }
    expect(gateway.auditLog()).toHaveLength(10_000);
  });

  it("accepts an injected order ledger store, so the host can bound or persist it", async () => {
    clock = 1_000_000;
    const ledger = memoryLedger();
    const gateway = new SigningGateway({
      signer: new PolicyStampSigner(),
      now: () => clock,
      ledger,
    });
    gateway.unlock({ ttlMs: 60 * 60 * 1000 });
    gateway.authorizeAgent({ agentId: "a1" });
    const first = await gateway.signOrder(order());
    if (!first.ok) throw new Error("unreachable");
    expect(ledger.entries.size).toBe(1);

    // A second gateway sharing the store honours the existing entry: the
    // exactly-once guarantee survives a process restart when the host persists.
    const restarted = new SigningGateway({
      signer: new PolicyStampSigner(),
      now: () => clock,
      ledger,
    });
    restarted.unlock({ ttlMs: 60 * 60 * 1000 });
    restarted.authorizeAgent({ agentId: "a1" });
    const replayed = await restarted.signOrder(order());
    expect(replayed).toMatchObject({ ok: true, replay: true, signature: first.signature });
  });

  it("occupies the ledger slot through a single atomic insert, honouring a racing winner", async () => {
    // A shared persistent store gives no read-your-writes guarantee across
    // processes: `get` can miss an entry another process is committing. The
    // slot must therefore be taken by ONE atomic insert-if-absent, and when
    // that insert reports an occupant, the occupant's stamp is the answer —
    // never a second signature for the same clientOrderId.
    clock = 1_000_000;
    let calls = 0;
    const signer = {
      address: "0xDEV0000000000000000000000000000000000000",
      async signOrder() {
        calls += 1;
        return { signature: `devsig:unique-${calls}` };
      },
    };
    const gateway = new SigningGateway({
      signer,
      now: () => clock,
      ledger: memoryLedger({ lieOnGet: true }),
    });
    gateway.unlock({ ttlMs: 60 * 60 * 1000 });
    gateway.authorizeAgent({ agentId: "a1" });

    const first = await gateway.signOrder(order());
    if (!first.ok) throw new Error("unreachable");
    // Every pre-insert read said "empty"; only the atomic insert can know the
    // slot was already taken.
    const second = await gateway.signOrder(order());
    expect(second).toMatchObject({ ok: true, replay: true, signature: first.signature });
  });
});

describe("SigningGateway policy re-check after the signer await (GAT-4)", () => {
  /** A signer whose resolution the test controls, to hold an order in flight
   * across a policy mutation. */
  function deferredSigner(): {
    signer: { address: string; signOrder(): Promise<{ signature: string }> };
    release: () => void;
  } {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    let calls = 0;
    return {
      signer: {
        address: "0xDEV0000000000000000000000000000000000000",
        async signOrder() {
          await gate;
          calls += 1;
          return { signature: `devsig:deferred-${calls}` };
        },
      },
      release,
    };
  }

  function makeDeferredGateway(): { gateway: SigningGateway; release: () => void } {
    clock = 1_000_000;
    const { signer, release } = deferredSigner();
    const gateway = new SigningGateway({ signer, now: () => clock });
    gateway.unlock({ ttlMs: 60 * 60 * 1000 });
    gateway.authorizeAgent({ agentId: "a1" });
    return { gateway, release };
  }

  it("rejects an in-flight order when the session is locked during the await, recording nothing", async () => {
    const { gateway, release } = makeDeferredGateway();
    const pending = gateway.signOrder(order());
    gateway.lock();
    release();
    expect(await pending).toMatchObject({ ok: false, code: "locked" });
    expect(gateway.auditLog().at(-1)).toMatchObject({ decision: "rejected", code: "locked" });

    // The ledger must not hold the aborted order: after re-unlock the same
    // clientOrderId signs fresh rather than replaying a stamp that was never issued.
    gateway.unlock({ ttlMs: 60 * 60 * 1000 });
    expect(await gateway.signOrder(order())).toMatchObject({ ok: true, replay: false });
  });

  it("rejects an in-flight order when the agent is revoked during the await", async () => {
    const { gateway, release } = makeDeferredGateway();
    const pending = gateway.signOrder(order());
    gateway.revokeAgent("a1");
    release();
    expect(await pending).toMatchObject({ ok: false, code: "unauthorized_agent" });
  });

  it("rejects an in-flight order when the authorization expires during the await", async () => {
    const { gateway, release } = makeDeferredGateway();
    gateway.authorizeAgent({ agentId: "a1", expiresAt: clock + 1_000 });
    const pending = gateway.signOrder(order());
    clock += 1_000;
    release();
    expect(await pending).toMatchObject({ ok: false, code: "authorization_expired" });
  });

  it("rejects an in-flight order when the market allowlist is tightened during the await", async () => {
    const { gateway, release } = makeDeferredGateway();
    const pending = gateway.signOrder(order({ market: "market-x" }));
    gateway.authorizeAgent({ agentId: "a1", allowedMarkets: ["market-y"] });
    release();
    expect(await pending).toMatchObject({ ok: false, code: "market_not_allowed" });
  });

  it("issues exactly one signature when identical orders race through the await", async () => {
    // Same TOCTOU window, ledger side: two identical in-flight orders must not
    // both record and return distinct stamps.
    const { gateway, release } = makeDeferredGateway();
    const p1 = gateway.signOrder(order());
    const p2 = gateway.signOrder(order());
    release();
    const [r1, r2] = await Promise.all([p1, p2]);
    if (!r1.ok || !r2.ok) throw new Error("unreachable");
    expect(r2.signature).toBe(r1.signature);
    expect([r1.replay, r2.replay].sort()).toEqual([false, true]);
    expect(gateway.auditLog().map((entry) => entry.decision).sort()).toEqual([
      "replayed",
      "signed",
    ]);
  });
});
