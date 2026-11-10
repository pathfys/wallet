// Shared test helpers: signed Telegram initData, a signing API client, app boot.
import { createHmac, randomBytes, webcrypto, generateKeyPairSync, sign as edSign, createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Address } from "@ton/core";
import { WalletContractV4 } from "@ton/ton";
import { loadConfig } from "../src/config.js";
import { createApp, makeLog } from "../src/index.js";
import { startJobs } from "../src/jobs.js";
import { bindMessage } from "../src/security.js";

export const BOT = "123456789:" + "A".repeat(35);

export function initData(user, ageSec = 0) {
  const p = new URLSearchParams({ auth_date: String(Math.floor(Date.now() / 1000) - ageSec), query_id: "AAE", user: JSON.stringify(user) });
  const check = [...p.entries()].map(([k, v]) => `${k}=${v}`).sort().join("\n");
  const secret = createHmac("sha256", "WebAppData").update(BOT).digest();
  p.set("hash", createHmac("sha256", secret).update(check).digest("hex"));
  return p.toString();
}

export class Client {
  constructor(base, tgUser) { this.base = base; this.tg = tgUser; }
  async login() {
    this.kp = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
    const jwk = await webcrypto.subtle.exportKey("jwk", this.kp.publicKey);
    const r = await fetch(this.base + "/api/auth/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ initData: initData(this.tg), pub: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y } }) });
    const j = await r.json();
    if (r.ok) this.token = j.token;
    return { status: r.status, body: j };
  }
  async req(method, path, body, { raw, type } = {}) {
    const data = raw ? raw : body ? Buffer.from(JSON.stringify(body)) : Buffer.alloc(0);
    const ts = Date.now(), nonce = randomBytes(16).toString("base64url");
    const str = `${method}\n${path}\n${ts}\n${nonce}\n${createHash("sha256").update(data).digest("hex")}`;
    const sig = Buffer.from(await webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, this.kp.privateKey, Buffer.from(str))).toString("base64url");
    const headers = { authorization: "Bearer " + this.token, "x-pmr-ts": String(ts), "x-pmr-nonce": nonce, "x-pmr-sig": sig };
    if (data.length) headers["content-type"] = type || "application/json";
    const r = await fetch(this.base + path, { method, headers, body: data.length ? data : undefined });
    const ct = r.headers.get("content-type") || "";
    return { status: r.status, body: ct.includes("json") ? await r.json() : Buffer.from(await r.arrayBuffer()) };
  }
  async bindWallet() {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const pub = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
    const addr = WalletContractV4.create({ workchain: 0, publicKey: pub }).address;
    const ch = (await this.req("POST", "/api/wallet/challenge", {})).body.challenge;
    const sig = edSign(null, bindMessage(ch, this.tg.id, addr.toRawString()), privateKey).toString("base64");
    this.address = addr;
    return this.req("POST", "/api/wallet/bind", { address: addr.toString(), publicKey: pub.toString("hex"), signature: sig, challenge: ch });
  }
  // login + nick + wallet in one go
  async ready(nick) {
    await this.login();
    if (nick) await this.req("POST", "/api/me/nick", { nick });
    await this.bindWallet();
    return this;
  }
}

export const mockPrices = {
  async index(asset, fiat) {
    if (fiat === "USD") return asset === "USDT" ? 1_000_000n : 5_000_000n;
    if (fiat === "RUB(ПМР)") return asset === "USDT" ? 16_100_000n : 80_000_000n;
    return 0n;
  },
  async usdE6(a) { return a === "USDT" ? 1_000_000n : 5_000_000n; },
};

export function makeMockChain() {
  const state = new Map(), sent = [], txs = [], balances = new Map();
  let balanceDown = false;
  return {
    state, sent, txs, balances,
    setBalanceDown(v) { balanceDown = v; },
    // by default every wallet is rich; tests override per address (raw form)
    async walletBalances(owner) {
      if (balanceDown) throw new Error("rpc down");
      return balances.get(owner.toRawString()) || { ton: 100_000_000_000n, usdt: 100_000_000_000n };
    },
    async escrowState(o) { return state.get(o.escrow_address) || { deployed: false, tonBalance: 0n }; },
    async jettonWalletOf(owner) { return Address.parse("0:" + createHash("sha256").update(owner.toRawString()).digest("hex")); },
    async sendBoc(b64) { sent.push(b64); return { ok: true }; },
    async getTransactions() { return txs; },
    fund(o, extra = {}) {
      state.set(o.escrow_address, { deployed: true, status: 0, seqno: 0, tonBalance: 400_000_000n,
        jettonWallet: o.jetton_wallet ? Address.parse(o.jetton_wallet) : null, jettonBalance: BigInt(o.amount_units) + BigInt(o.seller_fee), ...extra });
    },
  };
}

export async function startApp({ env = {}, chain, prices = mockPrices, bot } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "pmrqa-"));
  const cfg = loadConfig({
    BOT_TOKEN: BOT, FEE_WALLET: "UQAtqU5yzF4yMzJqqvCSJxH9dgaOr8Mciuikl3ws66scVoaW", ARBITER_SECRET: randomBytes(32).toString("hex"),
    DATA_KEY: randomBytes(32).toString("hex"), ADMIN_IDS: "9000", DATA_DIR: dir, DISABLE_JOBS: "1", APPEAL_AFTER_MIN: "1", ...env,
  }, { dotenv: false });
  const app = createApp(cfg, { chain, prices, bot: bot || { notify() {} }, log: makeLog(true) });
  const jobs = startJobs(app.ctx); jobs.stop();
  await new Promise((r) => app.server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${app.server.address().port}`;
  return { app, jobs, base, cfg, close() { app.server.close(); app.ctx.db.close(); rmSync(dir, { recursive: true, force: true }); } };
}
