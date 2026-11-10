// End-to-end with the REAL escrow contract running in @ton/sandbox:
// server builds the deal -> client code builds the StateInit -> seller deploys/funds ->
// server watcher sees it -> release by seller / refund and release by the arbiter.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { Blockchain } from "@ton/sandbox";
import { Address, Cell, toNano } from "@ton/core";
import { Client, startApp } from "./helpers.js";
import { ESCROW_CODE, readEscrowData, bodyRelease } from "../src/escrow.js";
import { makeEscrow } from "../src/escrow-core.js";

let bc, seller, buyer, feeW, env, A, B, adm, chainLog = [];
const clientEscrow = makeEscrow(ESCROW_CODE); // same helper the browser bundle uses

function sandboxChain() {
  return {
    async escrowState(o) {
      const addr = Address.parse(o.escrow_address);
      const sc = await bc.getContract(addr);
      if (sc.accountState?.type !== "active") return { deployed: false, tonBalance: sc.balance };
      const d = readEscrowData((await bc.runGetMethod(addr, "get_escrow_data")).stackReader);
      return { deployed: true, status: d.status, seqno: d.seqno, tonBalance: sc.balance, jettonWallet: d.jettonWallet, data: d, jettonBalance: 0n };
    },
    async sendBoc(b64) { const r = await bc.sendMessage(Cell.fromBoc(Buffer.from(b64, "base64"))[0]); chainLog.push(r); return { ok: true }; },
    async jettonWalletOf() { throw new Error("no jettons in this test"); },
    async getTransactions() { return []; },
  };
}
const sentTo = (r, to) => r.transactions.filter((t) => t.inMessage?.info.type === "internal" && t.inMessage.info.dest.equals(to)).reduce((a, t) => a + t.inMessage.info.value.coins, 0n);
const order = (id) => env.app.ctx.db.get("SELECT * FROM orders WHERE id=?", id);

before(async () => {
  bc = await Blockchain.create();
  bc.now = Math.floor(Date.now() / 1000);
  seller = await bc.treasury("seller"); buyer = await bc.treasury("buyer"); feeW = await bc.treasury("fees");
  env = await startApp({ chain: sandboxChain(), env: { FEE_WALLET: feeW.address.toString({ bounceable: false }) } });
  A = await new Client(env.base, { id: 3001, first_name: "S" }).ready("chain_seller");
  B = await new Client(env.base, { id: 3002, first_name: "B" }).ready("chain_buyer");
  adm = await new Client(env.base, { id: 9000, first_name: "Adm" }).ready("arbiter_one");
  // sandbox treasuries are not WalletV4, so bind their addresses directly
  env.app.ctx.db.run("UPDATE users SET wallet_address=? WHERE id=3001", seller.address.toRawString());
  env.app.ctx.db.run("UPDATE users SET wallet_address=? WHERE id=3002", buyer.address.toRawString());
  const pmId = (await A.req("POST", "/api/payment-methods", { type: "АПБ", holder: "Seller", account: "4111 1111 1111 1111" })).body.id;
  const ad = await A.req("POST", "/api/ads", { side: "sell", asset: "GRAM", fiat: "USD", priceType: "fixed", price: "5", total: "100", min: "10", max: "500", payWindow: 15, pmIds: [pmId] });
  assert.equal(ad.status, 200, JSON.stringify(ad.body));
  env.adId = ad.body.id;
});
after(() => env.close());

async function openAndFund(idem, amount = "20") {
  const o = await B.req("POST", "/api/orders", { adId: env.adId, amount, payType: "АПБ", idem });
  assert.equal(o.status, 200, JSON.stringify(o.body));
  const tx = (await A.req("GET", `/api/orders/${o.body.id}/escrow-tx`)).body;
  const e = tx.escrow;
  const p = { dealId: BigInt(e.dealId), kind: e.kind, deadline: e.deadline, arbiterKeyHex: e.arbiterKey, buyerAmount: BigInt(e.buyerAmountUnits), feeAmount: BigInt(e.feeAmountUnits), seller: e.sellerAddress, buyer: e.buyerAddress, feeWallet: e.feeWallet };
  const addr = clientEscrow.escrowAddress(p);
  assert.ok(addr.equals(Address.parse(e.address)), "client recomputes the same escrow address");
  await seller.send({ to: addr, value: BigInt(tx.messages[0].valueUnits), init: clientEscrow.escrowStateInit(p), bounce: true });
  await env.jobs.checkOrder(order(o.body.id));
  assert.equal(order(o.body.id).status, 10, "server saw the funded escrow");
  return { id: o.body.id, view: o.body, addr };
}

test("GRAM deal: seller locks, buyer pays, seller releases; buyer and fee wallet receive exact amounts", async () => {
  const { id, view, addr } = await openAndFund("chain-order-0001");
  assert.equal((await B.req("POST", `/api/orders/${id}/paid`, {})).status, 200);
  const r = await seller.send({ to: addr, value: toNano("0.05"), body: bodyRelease(1n), bounce: true });
  await A.req("POST", `/api/orders/${id}/release-sent`, {});
  assert.equal(sentTo(r, buyer.address), toNano(view.buyerReceives));
  assert.equal(sentTo(r, feeW.address), toNano(view.buyerFee) + toNano(view.sellerFee));
  // 20 GRAM deal: 2% from each side = 0.4 + 0.4 GRAM; the buyer gets 19.6, the seller locked 20.4
  assert.equal(view.buyerFee, "0.4"); assert.equal(view.sellerFee, "0.4");
  assert.equal(sentTo(r, feeW.address), toNano("0.8"), "fee wallet received exactly 4% of the deal");
  assert.equal(sentTo(r, buyer.address), toNano("19.6"));
  await env.jobs.checkOrder(order(id));
  assert.equal(order(id).status, 50);
});

test("buyer cancels after funding -> arbiter refund is executed by the contract", async () => {
  const { id, addr } = await openAndFund("chain-order-0002", "10");
  assert.equal((await B.req("POST", `/api/orders/${id}/cancel`, {})).status, 200);
  chainLog = [];
  await env.jobs.checkOrder(order(id));                       // watcher submits the signed refund
  assert.equal(chainLog.length, 1, "decision sent");
  const back = sentTo(chainLog[0], seller.address);
  assert.ok(back > toNano("10"), "seller got the deposit back: " + back);
  const d = readEscrowData((await bc.runGetMethod(addr, "get_escrow_data")).stackReader);
  assert.equal(d.status, 2);
  await env.jobs.checkOrder(order(id));
  assert.equal(order(id).refund_needed, 0);
});

test("appeal resolved by support: release decision pays the buyer through the contract", async () => {
  const { id, view } = await openAndFund("chain-order-0003", "10");
  await B.req("POST", `/api/orders/${id}/paid`, {});
  env.app.ctx.db.run("UPDATE orders SET paid_at=paid_at-600000 WHERE id=?", id);
  assert.equal((await B.req("POST", `/api/orders/${id}/appeal`, { reason: "Оплатил, продавец не отпускает", description: "Перевёл 50 USD, продавец молчит" })).status, 200);
  const ap = (await adm.req("GET", "/api/admin/appeals")).body.items.find((a) => a.orderId === id);
  chainLog = [];
  assert.equal((await adm.req("POST", `/api/admin/appeals/${ap.id}/resolve`, { decision: "release" })).status, 200);
  assert.equal(chainLog.length, 1);
  assert.equal(sentTo(chainLog[0], buyer.address), toNano(view.buyerReceives));
  await env.jobs.checkOrder(order(id));
  assert.equal(order(id).status, 50);
});
