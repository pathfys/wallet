// Minimal toncenter v2 JSON-RPC client (fetch-based, rate-limited, timeouts)
// plus the on-chain checks the order state machine relies on.
import { Address, Cell, TupleReader, beginCell } from "@ton/core";
import { ESCROW_CODE_HASH, readEscrowData, STATUS, KIND } from "./escrow.js";

function parseItem(s) {
  const [t, v] = s;
  if (t === "num") return { type: "int", value: v.startsWith("-") ? -BigInt(v.slice(1)) : BigInt(v) };
  if (t === "null") return { type: "null" };
  if (t === "cell") return { type: "cell", cell: Cell.fromBoc(Buffer.from(v.bytes, "base64"))[0] };
  if (t === "slice") return { type: "slice", cell: Cell.fromBoc(Buffer.from(v.bytes, "base64"))[0] };
  if ((t === "tuple" || t === "list") && v.elements.length === 0) return { type: "null" };
  throw new Error("unsupported stack item " + t);
}

export class Toncenter {
  constructor({ endpoint, apiKey, rps = 1, timeoutMs = 10_000, fetchImpl = fetch }) {
    Object.assign(this, { endpoint, apiKey, gap: Math.ceil(1000 / rps), timeoutMs, fetch: fetchImpl });
    this.next = 0;
  }
  async slot() {
    const t = Date.now(), at = Math.max(t, this.next);
    this.next = at + this.gap;
    if (at > t) await new Promise((r) => setTimeout(r, at - t));
  }
  async call(method, params, tries = 3) {
    let err;
    for (let i = 0; i < tries; i++) {
      await this.slot();
      const ctl = new AbortController(), timer = setTimeout(() => ctl.abort(), this.timeoutMs);
      try {
        const res = await this.fetch(this.endpoint, {
          method: "POST", signal: ctl.signal,
          headers: { "Content-Type": "application/json", ...(this.apiKey ? { "X-API-Key": this.apiKey } : {}) },
          body: JSON.stringify({ id: "1", jsonrpc: "2.0", method, params }),
        });
        const text = await res.text();
        if (text.length > 2_000_000) throw new Error("rpc response too large");
        const j = JSON.parse(text);
        if (res.status === 429 || res.status >= 500) throw Object.assign(new Error("rpc " + res.status), { retry: true });
        if (!j.ok) throw new Error("rpc error: " + String(j.error || j.result || "").slice(0, 200));
        return j.result;
      } catch (e) {
        err = e;
        if (!(e.retry || e.name === "AbortError" || e.name === "TypeError") || i === tries - 1) break;
        await new Promise((r) => setTimeout(r, 400 * 2 ** i));
      } finally { clearTimeout(timer); }
    }
    throw err;
  }
  async getAccount(addr) {
    const r = await this.call("getAddressInformation", { address: addr.toString() });
    const code = r.code ? Cell.fromBoc(Buffer.from(r.code, "base64"))[0] : null;
    return { balance: BigInt(r.balance), state: r.state, codeHash: code ? code.hash().toString("hex") : null };
  }
  async runGet(addr, method, stack = []) {
    const r = await this.call("runGetMethod", { address: addr.toString(), method, stack });
    if (r.exit_code !== 0 && r.exit_code !== 1) throw new Error(`get-method ${method} exit ${r.exit_code}`);
    return new TupleReader(r.stack.map(parseItem));
  }
  async sendBoc(b64) { return this.call("sendBoc", { boc: b64 }, 2); }
  async getTransactions(addr, limit = 30) { return this.call("getTransactions", { address: addr.toString(), limit, archival: true }); }
}

// High-level chain operations used by the P2P module (mockable in tests).
export function makeChain(cfg, rpc) {
  const usdtMaster = Address.parse(cfg.usdtMaster);
  const jwCache = new Map();
  return {
    async jettonWalletOf(owner) {
      const k = owner.toString();
      if (jwCache.has(k)) return jwCache.get(k);
      const r = await rpc.runGet(usdtMaster, "get_wallet_address", [["tvm.Slice", beginCell().storeAddress(owner).endCell().toBoc().toString("base64")]]);
      const a = r.readAddress();
      if (jwCache.size > 10_000) jwCache.clear();
      jwCache.set(k, a);
      return a;
    },
    async jettonBalance(jw) {
      const acc = await rpc.getAccount(jw);
      if (acc.state !== "active") return 0n;
      return (await rpc.runGet(jw, "get_wallet_data")).readBigNumber();
    },
    // -> { deployed, status, seqno, tonBalance, jettonBalance, jettonWallet, data }
    async escrowState(order) {
      const addr = Address.parse(order.escrow_address);
      const acc = await rpc.getAccount(addr);
      if (acc.state !== "active") return { deployed: false, tonBalance: acc.balance };
      if (acc.codeHash !== ESCROW_CODE_HASH) throw new Error("escrow code hash mismatch");
      const data = readEscrowData(await rpc.runGet(addr, "get_escrow_data"));
      const out = { deployed: true, status: data.status, seqno: data.seqno, tonBalance: acc.balance, jettonWallet: data.jettonWallet, data, jettonBalance: 0n };
      if (data.kind === KIND.jetton && data.jettonWallet) out.jettonBalance = await this.jettonBalance(data.jettonWallet);
      return out;
    },
    sendBoc: (b64) => rpc.sendBoc(b64),
    getTransactions: (addr, limit) => rpc.getTransactions(addr, limit),
  };
}

// Does the escrow hold everything the deal needs?  (status must still be open)
export function isFunded(order, st) {
  if (!st.deployed || st.status !== STATUS.open) return false;
  const need = BigInt(order.amount_units) + BigInt(order.seller_fee);
  if (order.asset === "GRAM") return st.tonBalance >= need + 30_000_000n; // MIN_STORAGE + EXT_GAS
  if (!st.jettonWallet || order.jetton_wallet && !st.jettonWallet.equals(Address.parse(order.jetton_wallet))) return false;
  return st.jettonBalance >= need && st.tonBalance >= 230_000_000n;    // 2 x JETTON_GAS + reserve
}
