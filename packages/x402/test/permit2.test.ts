import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { readNativeBalance } from "../src/permit2.js";

const OWNER = "0x017Bd9e021Ea9891e0f0AEe84247797a6647b193";
// Port 1 on loopback: nothing listens, so the connect is refused at once —
// the same "fetch failed" an unreachable public node produces.
const DEAD = "http://127.0.0.1:1";

describe("readNativeBalance with fallbackRpcUrls", () => {
  let server: Server;
  let url: string;
  const methods: string[] = [];

  beforeAll(async () => {
    server = createServer((req, res) => {
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        const { id, method } = JSON.parse(body) as { id: number; method: string };
        methods.push(method);
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ jsonrpc: "2.0", id, result: "0x2a" }));
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

  it("reads from the fallback when the primary node is unreachable", async () => {
    const balance = await readNativeBalance({ rpcUrl: DEAD, chainId: 56, fallbackRpcUrls: [url] }, OWNER);
    expect(balance).toBe(42n);
    expect(methods).toContain("eth_getBalance");
  });

  it("still fails without a fallback", async () => {
    await expect(readNativeBalance({ rpcUrl: DEAD, chainId: 56 }, OWNER)).rejects.toThrow();
  });
});
