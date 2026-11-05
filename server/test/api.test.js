// End-to-end API tests: full Bybit-style order lifecycle + security checks.
// The blockchain, prices and Telegram bot are replaced by in-memory fakes.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createHmac, randomBytes, webcrypto, generateKeyPairSync, sign as edSign, createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Address, Cell } from "@ton/core";
import { WalletContractV4 } from "@ton/ton";
import { loadConfig } from "../src/config.js";
import { createApp, makeLog } from "../src/index.js";
import { startJobs } from "../src/jobs.js";
import { escrowAddress, decisionHash, edVerifyHash, STATUS, KIND, ACTION } from "../src/escrow.js";
import { bindMessage } from "../src/security.js";

const BOT = "123456789:" + "A".repeat(35);
const ADMIN_ID = 9000;
let app, base, dir, jobs;
const chainState = new Map(); // escrow raw address -> state
const sent = [];

function initData(user, ageSec = 0) {
  const p = new URLSearchParams({ auth_date: String(Math.floor(Date.now() / 1000) - ageSec), query_id: "AAE", user: JSON.stringify(user) });
  const check = [...p.entries()].map(([k, v]) => `${k}=${v}`).sort().join("\n");
  const secret = createHmac("sha256", "WebAppData").update(BOT).digest();
  p.set("hash", createHmac("sha256", secret).update(check).digest("hex"));
  return p.toString();
}

class Client {
  constructor(tgUser) { this.tg = tgUser; }
  async login(init) {
    this.kp = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
    const jwk = await webcrypto.subtle.exportKey("jwk", this.kp.publicKey);
    const r = await fetch(base + "/api/auth/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ initData: init || initData(this.tg), pub: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y } }) });
    const j = await r.json();
    if (r.ok) this.token = j.token;
    return { status: r.status, body: j };
  }
  async req(method, path, body, { nonce, ts, tamper, raw, type } = {}) {
    const data = raw ? raw : body ? Buffer.from(JSON.stringify(body)) : Buffer.alloc(0);
    ts = ts ?? Date.now(); nonce = nonce ?? randomBytes(16).toString("base64url");
    const str = `${method}\n${path}\n${ts}\n${nonce}\n${createHash("sha256").update(data).digest("hex")}`;
    const sig = Buffer.from(await webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, this.kp.privateKey, Buffer.from(str))).toString("base64url");
    const send = tamper ? Buffer.from(JSON.stringify(tamper)) : data;
    const headers = { authorization: "Bearer " + this.token, "x-pmr-ts": String(ts), "x-pmr-nonce": nonce, "x-pmr-sig": sig };
    if (send.length) headers["content-type"] = type || "application/json";
    const r = await fetch(base + path, { method, headers, body: send.length ? send : undefined });
    const ct = r.headers.get("content-type") || "";
    return { status: r.status, body: ct.includes("json") ? await r.json() : Buffer.from(await r.arrayBuffer()), nonce, ts };
  }
  async bindWallet() {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const pub = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
    const addr = WalletContractV4.create({ workchain: 0, publicKey: pub }).address;
    const ch = (await this.req("POST", "/api/wallet/challenge", {})).body.challenge;
    const sig = edSign(null, bindMessage(ch, this.tg.id, addr.toRawString()), privateKey).toString("base64");
    const r = await this.req("POST", "/api/wallet/bind", { address: addr.toString(), publicKey: pub.toString("hex"), signature: sig, challenge: ch });
    this.address = addr;
    return r;
  }
}

const seller = new Client({ id: 1001, first_name: "Sel", allows_write_to_pm: true });
const buyer = new Client({ id: 1002, first_name: "Buy", allows_write_to_pm: true });
const stranger = new Client({ id: 1003, first_name: "Str" });
const admin = new Client({ id: ADMIN_ID, first_name: "Adm" });

before(async () => {
  dir = mkdtempSync(join(tmpdir(), "pmr-"));
  const cfg = loadConfig({
    BOT_TOKEN: BOT, FEE_WALLET: "UQAtqU5yzF4yMzJqqvCSJxH9dgaOr8Mciuikl3ws66scVoaW", ARBITER_SECRET: randomBytes(32).toString("hex"),
    DATA_KEY: randomBytes(32).toString("hex"), ADMIN_IDS: String(ADMIN_ID), DATA_DIR: dir, DISABLE_JOBS: "1", APPEAL_AFTER_MIN: "1",
  }, { dotenv: false });
  const chain = {
    async escrowState(o) { return chainState.get(o.escrow_address) || { deployed: false, tonBalance: 0n }; },
    async jettonWalletOf(owner) { return Address.parse("0:" + createHash("sha256").update(owner.toRawString()).digest("hex")); },
    async sendBoc(b64) { sent.push(b64); return { ok: true }; },
    async getTransactions() { return []; },
  };
  const prices = { async index(asset, fiat) { return fiat === "USD" ? (asset === "USDT" ? 1_000_000n : 5_000_000n) : 0n; }, async usdE6(a) { return a === "USDT" ? 1_000_000n : 5_000_000n; } };
  app = createApp(cfg, { chain, prices, bot: { notify() {} }, log: makeLog(true) });
  jobs = startJobs(app.ctx); jobs.stop();
  await new Promise((r) => app.server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${app.server.address().port}`;
});
after(() => { app.server.close(); app.ctx.db.close(); rmSync(dir, { recursive: true, force: true }); });

let adId, orderId, order;

test("login rejects forged / expired initData and accepts a valid one", async () => {
  const forged = initData(seller.tg).replace(/hash=[0-9a-f]+/, "hash=" + "0".repeat(64));
  assert.equal((await seller.login(forged)).status, 401);
  assert.equal((await seller.login(initData(seller.tg, 3 * 86400))).status, 401);
  const tampered = initData(seller.tg).replace(/user=[^&]+/, "user=" + encodeURIComponent(JSON.stringify({ id: ADMIN_ID })));
  assert.equal((await seller.login(tampered)).status, 401);
  for (const c of [seller, buyer, stranger, admin]) assert.equal((await c.login()).status, 200);
  assert.equal((await admin.req("GET", "/api/me")).body.role, "admin");
  assert.equal((await seller.req("GET", "/api/me")).body.role, "user");
});

test("request signatures: replay, tampering, stale timestamp and missing signature are rejected", async () => {
  const ok = await seller.req("GET", "/api/me");
  assert.equal(ok.status, 200);
  assert.equal((await seller.req("GET", "/api/me", null, { nonce: ok.nonce })).status, 409, "replayed nonce");
  assert.equal((await seller.req("POST", "/api/me/nick", { nick: "seller_one" }, { tamper: { nick: "hacker" } })).status, 401, "tampered body");
  assert.equal((await seller.req("GET", "/api/me", null, { ts: Date.now() - 5 * 60_000 })).status, 401, "stale ts");
  const r = await fetch(base + "/api/me", { headers: { authorization: "Bearer " + seller.token } });
  assert.equal(r.status, 401, "unsigned request");
  // another device's key cannot use a stolen token
  const thief = new Client(seller.tg); await thief.login(); thief.token = seller.token;
  assert.equal((await thief.req("GET", "/api/me")).status, 401);
});

test("nicknames: validation, uniqueness, homoglyph impersonation, single change", async () => {
  assert.equal((await seller.req("POST", "/api/me/nick", { nick: "admin" })).status, 400);
  assert.equal((await seller.req("POST", "/api/me/nick", { nick: "x" })).status, 400);
  assert.equal((await seller.req("POST", "/api/me/nick", { nick: "seller_one" })).status, 200);
  assert.equal((await buyer.req("POST", "/api/me/nick", { nick: "SELLER_ONE" })).status, 409);
  assert.equal((await buyer.req("POST", "/api/me/nick", { nick: "buyer.two" })).status, 200);
  assert.equal((await stranger.req("POST", "/api/me/nick", { nick: "sеller_оne" })).status, 400, "mixed alphabet / homoglyph");
  assert.equal((await stranger.req("POST", "/api/me/nick", { nick: "stranger" })).status, 200);
  assert.equal((await stranger.req("POST", "/api/me/nick", { nick: "stranger2" })).status, 200);
  assert.equal((await stranger.req("POST", "/api/me/nick", { nick: "stranger3" })).status, 409, "only one change");
});

test("wallet binding needs a valid signature from the wallet key", async () => {
  const ch = (await seller.req("POST", "/api/wallet/challenge", {})).body.challenge;
  const { publicKey } = generateKeyPairSync("ed25519");
  const pub = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  const addr = WalletContractV4.create({ workchain: 0, publicKey: pub }).address;
  const bad = await seller.req("POST", "/api/wallet/bind", { address: addr.toString(), publicKey: pub.toString("hex"), signature: randomBytes(64).toString("base64"), challenge: ch });
  assert.equal(bad.status, 400);
  assert.equal((await seller.bindWallet()).status, 200);
  assert.equal((await buyer.bindWallet()).status, 200);
});

test("payment methods are private and encrypted at rest", async () => {
  const r = await seller.req("POST", "/api/payment-methods", { type: "АПБ", holder: "Иван И.", account: "4111 1111 1111 1111", bank: "АПБ" });
  assert.equal(r.status, 200);
  const row = app.ctx.db.get("SELECT details_enc FROM payment_methods WHERE id=?", r.body.id);
  assert.ok(row.details_enc.startsWith("v1:") && !row.details_enc.includes("4111"));
  assert.equal((await buyer.req("GET", "/api/payment-methods")).body.items.length, 0);
  const ad = await seller.req("POST", "/api/ads", { side: "sell", asset: "USDT", fiat: "USD", priceType: "fixed", price: "1.00", total: "100", min: "10", max: "100", payWindow: 15, pmIds: [r.body.id], remarks: "Только АПБ", idem: "ad-idem-0001" });
  assert.equal(ad.status, 200, JSON.stringify(ad.body));
  adId = ad.body.id;
  // idempotent re-submit returns the same ad
  assert.equal((await seller.req("POST", "/api/ads", { side: "sell", asset: "USDT", fiat: "USD", priceType: "fixed", price: "1.00", total: "100", min: "10", max: "100", payWindow: 15, pmIds: [r.body.id], idem: "ad-idem-0001" })).body.id, adId);
});

test("ads list and order creation (limits, own ad, idempotency)", async () => {
  const list = await buyer.req("GET", "/api/ads?side=sell&asset=USDT&fiat=USD");
  assert.equal(list.status, 200);
  assert.equal(list.body.items.length, 1);
  assert.equal(list.body.items[0].maker.nick, "seller_one");
  assert.equal(list.body.items[0].payTypes[0], "АПБ");
  assert.equal((await seller.req("POST", "/api/orders", { adId, amount: "20", payType: "АПБ", idem: "own-ad-0001" })).status, 400);
  assert.equal((await buyer.req("POST", "/api/orders", { adId, amount: "5", payType: "АПБ", idem: "small-0001" })).status, 400, "below min limit");
  const r = await buyer.req("POST", "/api/orders", { adId, fiat: "20", payType: "АПБ", idem: "order-0001" });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  order = r.body; orderId = order.id;
  assert.equal(order.status, 5);
  assert.equal(order.amount, "20");
  assert.equal(order.buyerFee, "0.1");
  assert.equal(order.sellerLocks, "20.1");
  assert.equal(order.buyerReceives, "19.9");
  assert.equal(order.payDetails, null, "buyer must not see payment details before escrow is funded");
  assert.equal((await buyer.req("POST", "/api/orders", { adId, fiat: "20", payType: "АПБ", idem: "order-0001" })).body.id, orderId, "idempotent");
  assert.equal((await buyer.req("GET", "/api/ads?side=sell&asset=USDT&fiat=USD")).body.items[0].available, "80");
});

test("strangers cannot read or act on someone else's order (IDOR)", async () => {
  assert.equal((await stranger.req("GET", `/api/orders/${orderId}`)).status, 404);
  assert.equal((await stranger.req("GET", `/api/orders/${orderId}/messages`)).status, 404);
  assert.equal((await stranger.req("POST", `/api/orders/${orderId}/messages`, { text: "hi" })).status, 404);
  assert.equal((await buyer.req("GET", `/api/orders/${orderId}/escrow-tx`)).status, 403);
});

test("escrow tx: address is reproducible from public params; setup is arbiter-signed", async () => {
  const r = await seller.req("GET", `/api/orders/${orderId}/escrow-tx`);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const e = r.body.escrow;
  const addr = escrowAddress({ dealId: BigInt(e.dealId), kind: e.kind, deadline: e.deadline, arbiterKeyHex: e.arbiterKey, buyerAmount: BigInt(e.buyerAmountUnits), feeAmount: BigInt(e.feeAmountUnits), seller: e.sellerAddress, buyer: e.buyerAddress, feeWallet: e.feeWallet });
  assert.ok(addr.equals(Address.parse(e.address)));
  assert.ok(Address.parse(e.sellerAddress).equals(seller.address));
  assert.equal(e.kind, KIND.jetton);
  assert.equal(r.body.messages.length, 2);
  assert.equal(r.body.messages[1].jettonAmountUnits, "20100000");
  assert.ok(r.body.setup.signature);
});

test("lifecycle: funded -> paid -> appeal guard -> chat -> released -> feedback", async () => {
  const o = app.ctx.db.get("SELECT * FROM orders WHERE id=?", orderId);
  chainState.set(o.escrow_address, { deployed: true, status: STATUS.open, seqno: 0, tonBalance: 300_000_000n, jettonWallet: Address.parse(o.jetton_wallet), jettonBalance: 20_100_000n });
  await jobs.checkOrder(o);
  let v = (await buyer.req("GET", `/api/orders/${orderId}`)).body;
  assert.equal(v.status, 10);
  assert.equal(v.payDetails.account, "4111 1111 1111 1111");
  assert.equal((await seller.req("POST", `/api/orders/${orderId}/paid`, {})).status, 403);
  assert.equal((await seller.req("POST", `/api/orders/${orderId}/cancel`, {})).status, 409, "seller cannot cancel after funding");
  assert.equal((await buyer.req("POST", `/api/orders/${orderId}/paid`, {})).status, 200);
  assert.equal((await buyer.req("POST", `/api/orders/${orderId}/appeal`, { reason: "Другое", description: "слишком рано для апелляции" })).status, 409);
  assert.equal((await buyer.req("POST", `/api/orders/${orderId}/messages`, { text: "Оплатил, проверьте" })).status, 200);
  const png = Buffer.concat([Buffer.from("89504e470d0a1a0a", "hex"), chunk("IHDR", Buffer.alloc(13)), chunk("tEXt", Buffer.from("GPS secret")), chunk("IEND", Buffer.alloc(0))]);
  const up = await buyer.req("POST", `/api/orders/${orderId}/files`, null, { raw: png, type: "image/png" });
  assert.equal(up.status, 200, JSON.stringify(up.body));
  const file = await seller.req("GET", `/api/files/${up.body.fileId}`);
  assert.equal(file.status, 200);
  assert.ok(!file.body.includes(Buffer.from("GPS secret")), "metadata stripped");
  assert.equal((await stranger.req("GET", `/api/files/${up.body.fileId}`)).status, 404);
  assert.equal((await buyer.req("POST", `/api/orders/${orderId}/files`, null, { raw: Buffer.from("<svg onload=alert(1)>" + "x".repeat(80)), type: "image/png" })).status, 400);
  const msgs = (await seller.req("GET", `/api/orders/${orderId}/messages`)).body.items;
  assert.ok(msgs.some((m) => m.from === "peer" && m.body === "Оплатил, проверьте"));
  assert.ok(msgs.some((m) => m.from === "system"));
  assert.equal((await seller.req("POST", `/api/orders/${orderId}/release-sent`, {})).status, 200);
  chainState.get(o.escrow_address).status = STATUS.released;
  await jobs.checkOrder(app.ctx.db.get("SELECT * FROM orders WHERE id=?", orderId));
  v = (await buyer.req("GET", `/api/orders/${orderId}`)).body;
  assert.equal(v.status, 50);
  assert.equal((await buyer.req("POST", `/api/orders/${orderId}/feedback`, { positive: true, comment: "Быстро" })).status, 200);
  assert.equal((await buyer.req("POST", `/api/orders/${orderId}/feedback`, { positive: true })).status, 409);
  const prof = (await stranger.req("GET", "/api/users/seller_one")).body;
  assert.equal(prof.stats.totalOrders, 1);
  assert.equal(prof.stats.positiveRate, 100);
});

function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  return Buffer.concat([len, Buffer.from(type, "latin1"), data, Buffer.alloc(4)]);
}

test("buyer cancel after funding triggers a valid arbiter refund to this exact escrow", async () => {
  const r = await buyer.req("POST", "/api/orders", { adId, amount: "10", payType: "АПБ", idem: "order-0002" });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const o = app.ctx.db.get("SELECT * FROM orders WHERE id=?", r.body.id);
  chainState.set(o.escrow_address, { deployed: true, status: STATUS.open, seqno: 3, tonBalance: 300_000_000n, jettonWallet: Address.parse("0:" + createHash("sha256").update(o.escrow_address).digest("hex")), jettonBalance: 10_050_000n });
  await seller.req("GET", `/api/orders/${o.id}/escrow-tx`);
  await jobs.checkOrder(app.ctx.db.get("SELECT * FROM orders WHERE id=?", o.id));
  assert.equal((await buyer.req("POST", `/api/orders/${o.id}/cancel`, {})).status, 200);
  sent.length = 0;
  await jobs.checkOrder(app.ctx.db.get("SELECT * FROM orders WHERE id=?", o.id));
  assert.equal(sent.length, 1);
  const msg = Cell.fromBoc(Buffer.from(sent[0], "base64"))[0].beginParse();
  msg.loadUint(2); msg.loadUint(2); const dest = msg.loadAddress(); msg.loadCoins(); msg.loadBit(); const body = msg.loadBit() ? msg.loadRef().beginParse() : msg;
  assert.ok(dest.equals(Address.parse(o.escrow_address)));
  const sig = body.loadBuffer(64);
  const payload = body.asCell();
  assert.ok(edVerifyHash(app.ctx.cfg.arbiter.publicKeyHex, decisionHash(o.escrow_address, payload), sig));
  const p = payload.beginParse();
  assert.equal(p.loadUint(32), 3, "uses on-chain seqno");
  p.loadUint(32);
  assert.equal(p.loadUint(8), ACTION.refund);
  assert.equal(p.loadCoins(), 10_050_000n, "refunds the actual jetton balance");
  assert.equal((await buyer.req("GET", "/api/ads?side=sell&asset=USDT&fiat=USD")).body.items[0].available, "80", "liquidity returned to the ad");
});

test("appeal -> admin resolves release; non-admin cannot use admin API", async () => {
  const r = await buyer.req("POST", "/api/orders", { adId, amount: "15", payType: "АПБ", idem: "order-0003" });
  const o = app.ctx.db.get("SELECT * FROM orders WHERE id=?", r.body.id);
  await seller.req("GET", `/api/orders/${o.id}/escrow-tx`);
  const o2 = app.ctx.db.get("SELECT * FROM orders WHERE id=?", o.id);
  chainState.set(o.escrow_address, { deployed: true, status: STATUS.open, seqno: 0, tonBalance: 300_000_000n, jettonWallet: Address.parse(o2.jetton_wallet), jettonBalance: 15_075_000n });
  await jobs.checkOrder(o2);
  await buyer.req("POST", `/api/orders/${o.id}/paid`, {});
  app.ctx.db.run("UPDATE orders SET paid_at=paid_at-120000 WHERE id=?", o.id);
  const ap = await buyer.req("POST", `/api/orders/${o.id}/appeal`, { reason: "Оплатил, продавец не отпускает", description: "Перевёл 15 USD, чек приложил" });
  assert.equal(ap.status, 200, JSON.stringify(ap.body));
  assert.equal((await buyer.req("GET", "/api/admin/appeals")).status, 403);
  const list = (await admin.req("GET", "/api/admin/appeals")).body.items;
  const mine = list.find((a) => a.orderId === o.id);
  assert.ok(mine);
  assert.equal((await admin.req("GET", `/api/orders/${o.id}/messages`)).status, 200, "support can read the chat");
  assert.equal((await admin.req("POST", `/api/orders/${o.id}/messages`, { text: "Поддержка подключилась" })).status, 200);
  const bm = (await buyer.req("GET", `/api/orders/${o.id}/messages`)).body.items;
  assert.ok(bm.some((m) => m.from === "support"));
  sent.length = 0;
  assert.equal((await admin.req("POST", `/api/admin/appeals/${mine.id}/resolve`, { decision: "release" })).status, 200);
  assert.equal(sent.length, 1);
  chainState.get(o.escrow_address).status = STATUS.released;
  await jobs.checkOrder(app.ctx.db.get("SELECT * FROM orders WHERE id=?", o.id));
  assert.equal((await buyer.req("GET", `/api/orders/${o.id}`)).body.status, 50);
  const stats = (await admin.req("GET", "/api/admin/stats?period=day")).body;
  assert.equal(stats.cur.trades, 2);
  assert.ok(stats.cur.volume >= 35);
});

test("timeouts: unpaid order is cancelled and counted against the buyer; 3 strikes block new orders", async () => {
  // one strike already exists: the buyer cancelled a funded order in the test above
  for (let i = 0; i < 2; i++) {
    const r = await buyer.req("POST", "/api/orders", { adId, amount: "10", payType: "АПБ", idem: "strike-000" + i });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    const o = app.ctx.db.get("SELECT * FROM orders WHERE id=?", r.body.id);
    await seller.req("GET", `/api/orders/${o.id}/escrow-tx`);
    const o2 = app.ctx.db.get("SELECT * FROM orders WHERE id=?", o.id);
    chainState.set(o.escrow_address, { deployed: true, status: STATUS.open, seqno: 0, tonBalance: 300_000_000n, jettonWallet: Address.parse(o2.jetton_wallet), jettonBalance: 10_050_000n });
    await jobs.checkOrder(o2);
    app.ctx.db.run("UPDATE orders SET pay_deadline=? WHERE id=?", Date.now() - 1000, o.id);
    await jobs.tick();
    assert.equal(app.ctx.db.get("SELECT status FROM orders WHERE id=?", o.id).status, 40);
  }
  const r = await buyer.req("POST", "/api/orders", { adId, amount: "10", payType: "АПБ", idem: "strike-0009" });
  assert.equal(r.status, 403);
  assert.equal(r.body.error, "cancel_limit");
});

test("banned users are locked out; admin actions are audited", async () => {
  assert.equal((await admin.req("POST", "/api/admin/bans", { userId: stranger.tg.id, reason: "spam" })).status, 200);
  assert.equal((await stranger.req("GET", "/api/ads?side=sell")).status, 401, "sessions revoked");
  await stranger.login();
  assert.equal((await stranger.req("GET", "/api/ads?side=sell")).status, 403);
  assert.equal((await stranger.req("GET", "/api/me")).body.banned, true);
  assert.equal((await admin.req("POST", "/api/admin/bans", { userId: ADMIN_ID })).status, 400);
  assert.ok(app.ctx.db.get("SELECT COUNT(*) n FROM audit WHERE action='ban'").n >= 1);
});

test("input hardening: oversized body, wrong content-type, bad JSON, unknown route", async () => {
  assert.equal((await buyer.req("POST", `/api/orders/${orderId}/messages`, { text: "x".repeat(40_000) })).status, 413);
  assert.equal((await buyer.req("POST", `/api/orders/${orderId}/messages`, null, { raw: Buffer.from("{bad"), type: "application/json" })).status, 400);
  assert.equal((await buyer.req("POST", `/api/orders/${orderId}/messages`, null, { raw: Buffer.from("a=b"), type: "text/plain" })).status, 415);
  assert.equal((await buyer.req("GET", "/api/../../etc/passwd")).status, 404);
  const r = await fetch(base + "/api/config", { headers: { origin: "https://evil.example" } });
  assert.equal(r.status, 403, "unknown CORS origin");
});
