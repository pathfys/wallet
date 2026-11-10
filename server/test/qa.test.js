// QA pass: chat in real time, bot notifications, buy-ads (taker sells), edge amounts,
// floating prices, ad edits, payment-method removal, pins, limits and races.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import WebSocket from "ws";
import { Address, beginCell } from "@ton/core";
import { Client, startApp, makeMockChain } from "./helpers.js";

let env, base, chain, notes = [];
const A = () => users.a, B = () => users.b;
const users = {};
const dbo = (id) => env.app.ctx.db.get("SELECT * FROM orders WHERE id=?", id);

before(async () => {
  chain = makeMockChain();
  env = await startApp({ chain, bot: { notify: (uid, text) => notes.push({ uid, text }) } });
  base = env.base;
  users.a = await new Client(base, { id: 2001, first_name: "A", allows_write_to_pm: true }).ready("maker_a");
  users.b = await new Client(base, { id: 2002, first_name: "B", allows_write_to_pm: true }).ready("taker_b");
  users.c = await new Client(base, { id: 2003, first_name: "C" }).ready("third_c");
  users.adm = await new Client(base, { id: 9000, first_name: "S" }).ready("helpdesk");
});
after(() => env.close());

const pmCache = new Map();
async function pm(c, type = "АПБ", account = "4111 0000 0000 0001") {
  const key = c.tg.id + ":" + type + ":" + account;
  if (pmCache.has(key)) return pmCache.get(key);
  const r = await c.req("POST", "/api/payment-methods", { type, holder: "Тест Тестов", account });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  pmCache.set(key, r.body.id);
  return r.body.id;
}
async function sellAd(c, over = {}) {
  const r = await c.req("POST", "/api/ads", { side: "sell", asset: "USDT", fiat: "RUB(ПМР)", priceType: "fixed", price: "16.10", total: "100", min: "100", max: "1610", payWindow: 15, pmIds: [await pm(c)], ...over });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return r.body;
}
async function fundAndGet(id) {
  await B().req("GET", `/api/orders/${id}`);
  const o = dbo(id);
  if (o.asset === "USDT" && !o.jetton_wallet) {
    const seller = o.seller_id === 2001 ? A() : o.seller_id === 2002 ? B() : users.c;
    await seller.req("GET", `/api/orders/${id}/escrow-tx`);
  }
  const o2 = dbo(id);
  chain.fund(o2);
  await env.jobs.checkOrder(o2);
  return dbo(id);
}
function wsConnect(c) {
  return new Promise(async (resolve, reject) => {
    const { ticket } = (await c.req("POST", "/api/ws-ticket", {})).body;
    const ws = new WebSocket(base.replace("http", "ws") + "/api/ws?ticket=" + ticket);
    const events = [];
    ws.on("message", (d) => { try { events.push(JSON.parse(String(d))); } catch {} });
    ws.on("open", () => resolve({ ws, events, ticket }));
    ws.on("error", reject);
  });
}
const waitFor = async (fn, ms = 3000) => { const end = Date.now() + ms; while (Date.now() < end) { const v = fn(); if (v) return v; await new Promise((r) => setTimeout(r, 30)); } return fn(); };

test("chat: both sides get each other's messages in real time over WebSocket", async () => {
  const ad = await sellAd(A());
  const o = (await B().req("POST", "/api/orders", { adId: ad.id, fiat: "161", payType: "АПБ", idem: "chat-order-1" })).body;
  const wa = await wsConnect(A()), wb = await wsConnect(B());
  // a ticket is single-use
  await assert.rejects(new Promise((res, rej) => { const w = new WebSocket(base.replace("http", "ws") + "/api/ws?ticket=" + wa.ticket); w.on("open", () => { w.close(); res(); }); w.on("error", rej); w.on("unexpected-response", (_, r) => rej(new Error("http " + r.statusCode))); }));
  assert.equal((await B().req("POST", `/api/orders/${o.id}/messages`, { text: "Привет, оплачиваю" })).status, 200);
  const ea = await waitFor(() => wa.events.find((e) => e.t === "msg" && e.message.body === "Привет, оплачиваю"));
  assert.ok(ea, "seller received buyer message live");
  assert.equal(ea.message.from, "peer");
  assert.ok(wb.events.find((e) => e.t === "msg" && e.message.body === "Привет, оплачиваю" && e.message.from === "me"), "sender sees own message as 'me'");
  assert.equal((await A().req("POST", `/api/orders/${o.id}/messages`, { text: "Жду" })).status, 200);
  const eb = await waitFor(() => wb.events.find((e) => e.t === "msg" && e.message.body === "Жду"));
  assert.equal(eb.message.from, "peer");
  // history is the same for both, in order
  const ha = (await A().req("GET", `/api/orders/${o.id}/messages`)).body.items.filter((m) => m.kind === "text").map((m) => m.body);
  const hb = (await B().req("GET", `/api/orders/${o.id}/messages`)).body.items.filter((m) => m.kind === "text").map((m) => m.body);
  assert.deepEqual(ha, ["Привет, оплачиваю", "Жду"]);
  assert.deepEqual(hb, ha);
  // order status changes are pushed too
  await fundAndGet(o.id);
  assert.ok(await waitFor(() => wb.events.find((e) => e.t === "order" && e.orderId === o.id && e.status === 10)), "status push");
  // text is stored and returned verbatim (escaping is the client's job), control chars stripped
  await B().req("POST", `/api/orders/${o.id}/messages`, { text: "<img src=x onerror=alert(1)>‮abc" });
  const last = (await A().req("GET", `/api/orders/${o.id}/messages`)).body.items.pop();
  assert.equal(last.body, "<img src=x onerror=alert(1)>abc");
  wa.ws.close(); wb.ws.close();
  await B().req("POST", `/api/orders/${o.id}/cancel`, {});
});

test("chat: offline counterpart gets one Telegram notification, not a flood", async () => {
  const ad = await sellAd(A());
  const o = (await B().req("POST", "/api/orders", { adId: ad.id, fiat: "161", payType: "АПБ", idem: "chat-order-2" })).body;
  notes = [];
  for (const t of ["раз", "два", "три"]) assert.equal((await B().req("POST", `/api/orders/${o.id}/messages`, { text: t })).status, 200);
  const toA = notes.filter((n) => n.uid === 2001 && /сообщение/i.test(n.text));
  assert.equal(toA.length, 1);
  await B().req("POST", `/api/orders/${o.id}/cancel`, {});
});

test("chat: rate limit, length limit, strangers and closed chats", async () => {
  const ad = await sellAd(A());
  const o = (await B().req("POST", "/api/orders", { adId: ad.id, fiat: "161", payType: "АПБ", idem: "chat-order-3" })).body;
  const codes = [];
  for (let i = 0; i < 7; i++) codes.push((await B().req("POST", `/api/orders/${o.id}/messages`, { text: "m" + i })).status);
  assert.ok(codes.includes(429), "burst is limited: " + codes);
  assert.equal((await A().req("POST", `/api/orders/${o.id}/messages`, { text: "x".repeat(1001) })).status, 400);
  assert.equal((await users.c.req("POST", `/api/orders/${o.id}/messages`, { text: "hi" })).status, 404);
  await B().req("POST", `/api/orders/${o.id}/cancel`, {});
  env.app.ctx.db.run("UPDATE orders SET cancelled_at=? WHERE id=?", Date.now() - 3 * 86_400_000, o.id);
  assert.equal((await A().req("POST", `/api/orders/${o.id}/messages`, { text: "поздно" })).status, 403);
  assert.equal((await A().req("GET", `/api/orders/${o.id}/messages`)).status, 200, "history stays readable");
});

test("entering exactly the minimum fiat amount is accepted (fiat mode keeps the entered sum)", async () => {
  const ad = await sellAd(A(), { min: "100", max: "1000" });
  const r = await B().req("POST", "/api/orders", { adId: ad.id, fiat: "100", payType: "АПБ", idem: "edge-min-1" });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.fiatAmount, "100");
  assert.equal(r.body.amount, "6.21");
  const r2 = await B().req("POST", "/api/orders", { adId: ad.id, fiat: "1000", payType: "АПБ", idem: "edge-max-1" });
  assert.equal(r2.status, 200, JSON.stringify(r2.body));
  assert.equal(r2.body.fiatAmount, "1000");
  assert.equal((await B().req("POST", "/api/orders", { adId: ad.id, fiat: "1000.01", payType: "АПБ", idem: "edge-max-2" })).status, 400);
  for (const id of [r.body.id, r2.body.id]) await B().req("POST", `/api/orders/${id}/cancel`, {});
});

test("buy ad: the taker is the seller, provides own payment details, locks and releases", async () => {
  const ad = (await A().req("POST", "/api/ads", { side: "buy", asset: "USDT", fiat: "RUB(ПМР)", priceType: "fixed", price: "15.80", total: "50", min: "100", max: "790", payWindow: 30, payTypes: ["Сбербанк", "АПБ"] })).body;
  assert.equal((await B().req("GET", "/api/ads?side=buy&asset=USDT")).body.items.some((x) => x.id === ad.id), true);
  // without own payment details of a matching type the taker cannot sell
  assert.equal((await B().req("POST", "/api/orders", { adId: ad.id, amount: "10", payType: "Сбербанк", idem: "buyad-0-xxxxxxxx" })).status, 400);
  const pmApb = await pm(B(), "АПБ", "4111 9999 8888 7777");
  assert.equal((await B().req("POST", "/api/orders", { adId: ad.id, amount: "10", payType: "Сбербанк", pmId: pmApb, idem: "buyad-1-xxxxxxxx" })).status, 400, "type mismatch");
  const r = await B().req("POST", "/api/orders", { adId: ad.id, amount: "10", payType: "АПБ", pmId: pmApb, idem: "buyad-2-xxxxxxxx" });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.role, "seller");
  assert.equal((await A().req("GET", `/api/orders/${r.body.id}/escrow-tx`)).status, 403, "maker is the buyer here");
  assert.equal((await B().req("GET", `/api/orders/${r.body.id}/escrow-tx`)).status, 200);
  await fundAndGet(r.body.id);
  const va = (await A().req("GET", `/api/orders/${r.body.id}`)).body;
  assert.equal(va.role, "buyer");
  assert.equal(va.payDetails.account, "4111 9999 8888 7777", "buyer sees the taker-seller's details");
  assert.equal((await A().req("POST", `/api/orders/${r.body.id}/paid`, {})).status, 200);
  assert.equal((await B().req("POST", `/api/orders/${r.body.id}/release-sent`, {})).status, 200);
  chain.state.get(dbo(r.body.id).escrow_address).status = 1;
  await env.jobs.checkOrder(dbo(r.body.id));
  assert.equal(dbo(r.body.id).status, 50);
});

test("floating price follows the market index; fixed-price edits do not touch existing orders", async () => {
  const fl = (await A().req("POST", "/api/ads", { side: "sell", asset: "USDT", fiat: "RUB(ПМР)", priceType: "floating", floatPct: "101.5", total: "100", min: "100", max: "1000", payWindow: 15, pmIds: [await pm(A())] })).body;
  assert.equal(fl.price, "16.34"); // 16.10 * 1.015 = 16.3415 -> 2 decimals
  assert.equal((await A().req("POST", "/api/ads", { side: "sell", asset: "USDT", fiat: "EUR", priceType: "floating", floatPct: "100", total: "10", min: "10", max: "100", payWindow: 15, pmIds: [await pm(A())] })).status, 400, "no index for EUR in mocks");
  const ad = await sellAd(A());
  const o = (await B().req("POST", "/api/orders", { adId: ad.id, amount: "10", payType: "АПБ", idem: "edit-1-xxxxxxxx" })).body;
  const ed = await A().req("POST", `/api/ads/${ad.id}`, { priceType: "fixed", price: "17", total: "100", min: "100", max: "1700", payWindow: 15, pmIds: ad.pmIds });
  assert.equal(ed.status, 200, JSON.stringify(ed.body));
  assert.equal((await B().req("GET", `/api/orders/${o.id}`)).body.price, "16.1");
  assert.equal((await A().req("POST", `/api/ads/${ad.id}`, { priceType: "fixed", price: "17", total: "5", min: "100", max: "1700", payWindow: 15, pmIds: ad.pmIds })).status, 400, "total below executed");
  assert.equal((await A().req("DELETE", `/api/ads/${ad.id}`)).status, 409, "active order blocks deletion");
  await B().req("POST", `/api/orders/${o.id}/cancel`, {});
  assert.equal((await A().req("DELETE", `/api/ads/${ad.id}`)).status, 200);
});

test("removing the only payment method takes a sell ad offline", async () => {
  const id = await pm(users.c, "СБП", "+373 777 00000");
  const ad = (await users.c.req("POST", "/api/ads", { side: "sell", asset: "USDT", fiat: "RUB(ПМР)", priceType: "fixed", price: "16", total: "10", min: "100", max: "160", payWindow: 15, pmIds: [id] })).body;
  assert.equal((await users.c.req("DELETE", `/api/payment-methods/${id}`)).status, 200);
  const mine = (await users.c.req("GET", "/api/ads/mine")).body.items.find((x) => x.id === ad.id);
  assert.equal(mine.status, "offline");
  assert.equal((await users.c.req("POST", `/api/ads/${ad.id}/status`, { status: "online" })).status, 400);
});

test("paid pin: on-chain payment with the invoice comment pins the ad and sorts it first", async () => {
  const ad = await sellAd(users.c, { price: "16.50" });
  const inv = (await users.c.req("POST", `/api/ads/${ad.id}/pin`, { hours: 6, asset: "GRAM" })).body;
  assert.equal(inv.amount, "0.6"); // $3 at $5 per GRAM
  // wrong amount is ignored, right amount with the comment is applied once
  chain.txs.push({ transaction_id: { hash: "h1" }, in_msg: { source: "EQ_x", value: "100", message: inv.comment } });
  await env.jobs.pins();
  assert.equal(env.app.ctx.db.get("SELECT status FROM pin_invoices WHERE id=?", inv.id).status, "pending");
  chain.txs.push({ transaction_id: { hash: "h2" }, in_msg: { source: "EQ_x", value: inv.amountUnits, message: inv.comment } });
  await env.jobs.pins();
  assert.equal(env.app.ctx.db.get("SELECT status FROM pin_invoices WHERE id=?", inv.id).status, "paid");
  const list = (await B().req("GET", "/api/ads?side=sell&asset=USDT&fiat=" + encodeURIComponent("RUB(ПМР)"))).body.items;
  assert.equal(list[0].id, ad.id);
  assert.equal(list[0].pinned, true);
  // the same transaction cannot pay a second invoice
  const inv2 = (await users.c.req("POST", `/api/ads/${ad.id}/pin`, { hours: 3, asset: "GRAM" })).body;
  chain.txs.push({ transaction_id: { hash: "h2" }, in_msg: { source: "EQ_x", value: inv2.amountUnits, message: inv2.comment } });
  await env.jobs.pins();
  assert.equal(env.app.ctx.db.get("SELECT status FROM pin_invoices WHERE id=?", inv2.id).status, "pending");
  await users.c.req("POST", `/api/ads/${ad.id}/status`, { status: "offline" });
});

test("concurrent orders cannot oversell an ad", async () => {
  const ad = await sellAd(users.c, { total: "10", min: "100", max: "161" });
  const d = await new Client(base, { id: 2010, first_name: "D" }).ready("racer_d");
  const res = await Promise.all([
    B().req("POST", "/api/orders", { adId: ad.id, amount: "10", payType: "АПБ", idem: "race-b-xxxxxxxx" }),
    d.req("POST", "/api/orders", { adId: ad.id, amount: "10", payType: "АПБ", idem: "race-d-xxxxxxxx" }),
  ]);
  assert.deepEqual(res.map((r) => r.status).sort(), [200, 400]);
  for (const r of res) if (r.status === 200) await (r.body.role === "buyer" && r.body.counterparty ? B() : d).req("POST", `/api/orders/${r.body.id}/cancel`, {}).catch(() => {});
});

test("taker requirements and the 5-active-orders limit", async () => {
  const ad = await sellAd(A(), { condMinOrders: 50 });
  const r = await users.c.req("POST", "/api/orders", { adId: ad.id, fiat: "161", payType: "АПБ", idem: "cond-1-xxxxxxxx" });
  assert.equal(r.status, 400);
  assert.equal(r.body.error, "conditions");
  const ad2 = await sellAd(A(), { total: "100" });
  const ids = [];
  for (let i = 0; i < 6; i++) {
    const x = await users.c.req("POST", "/api/orders", { adId: ad2.id, fiat: "161", payType: "АПБ", idem: "lim--xxxxxxxx" + i });
    if (x.status === 200) ids.push(x.body.id); else assert.equal(x.body.error, "too_many_orders");
  }
  assert.equal(ids.length, 5);
  for (const id of ids) await users.c.req("POST", `/api/orders/${id}/cancel`, {});
});

test("wallet cannot be swapped while orders are active; seller cannot cancel after funding", async () => {
  const ad = await sellAd(A());
  const o = (await B().req("POST", "/api/orders", { adId: ad.id, fiat: "161", payType: "АПБ", idem: "swap-1-xxxxxxxx" })).body;
  assert.equal((await B().bindWallet()).status, 409);
  await fundAndGet(o.id);
  assert.equal((await A().req("POST", `/api/orders/${o.id}/cancel`, {})).status, 409);
  assert.equal((await B().req("POST", `/api/orders/${o.id}/appeal/cancel`, {})).status, 403);
  await B().req("POST", `/api/orders/${o.id}/cancel`, {});
  assert.equal(dbo(o.id).status, 40);
});

test("seller who already sent the lock transaction gets a short grace period", async () => {
  const ad = await sellAd(A());
  const o = (await B().req("POST", "/api/orders", { adId: ad.id, fiat: "161", payType: "АПБ", idem: "grace-1-xxxxxxxx" })).body;
  await A().req("GET", `/api/orders/${o.id}/escrow-tx`);
  await A().req("POST", `/api/orders/${o.id}/escrow-sent`, {});
  env.app.ctx.db.run("UPDATE orders SET lock_deadline=?, lock_sent_at=?, chain_checked_at=? WHERE id=?", Date.now() - 70_000, Date.now() - 75_000, Date.now(), o.id);
  await env.jobs.tick();
  assert.equal(dbo(o.id).status, 5, "not cancelled while the lock tx may still be confirming");
  env.app.ctx.db.run("UPDATE orders SET lock_deadline=? WHERE id=?", Date.now() - 6 * 60_000, o.id);
  await env.jobs.tick();
  assert.equal(dbo(o.id).status, 40);
});

test("fees: every order shows the configured percentage per side and matches the escrow", async () => {
  const cfg = (await fetch(base + "/api/config").then((r) => r.json())).fee;
  assert.equal(cfg.sideBps, 200, "2% per side");
  assert.equal(cfg.orderBps, 400, "4% per order");
  assert.equal(cfg.maxSideUsd, 0, "no $ cap");
  const e = await new Client(base, { id: 2020, first_name: "E" }).ready("fee_maker");
  const ad = await sellAd(e, { total: "100", max: "1610" });
  const o = (await B().req("POST", "/api/orders", { adId: ad.id, amount: "100", payType: "АПБ", idem: "fee-1-xxxxxxxx" })).body;
  const side = (100_000_000n * BigInt(cfg.sideBps) + 9_999n) / 10_000n;
  assert.equal(o.buyerFee, (Number(side) / 1e6).toString());
  assert.equal(o.sellerFee, o.buyerFee);
  assert.equal(BigInt(o.escrow.feeAmountUnits), side * 2n);
  assert.equal(BigInt(o.escrow.buyerAmountUnits), 100_000_000n - side);
  await B().req("POST", `/api/orders/${o.id}/cancel`, {});
});
