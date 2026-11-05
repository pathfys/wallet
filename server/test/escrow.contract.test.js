// On-chain logic tests for contracts/pmr_escrow.fc in @ton/sandbox.
import { test, describe, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { Blockchain } from "@ton/sandbox";
import { Address, Cell, beginCell, external, toNano } from "@ton/core";
import { randomBytes } from "node:crypto";
import {
  escrowStateInit, escrowAddress, readEscrowData, arbiterKeyFromSeed, setupHash, edSignHash, buildSetupBody,
  buildDecisionExternal, decisionPayload, decisionHash, buildDecisionBody,
  bodyRelease, bodyCancel, bodyReclaim, bodySweep, ACTION, STATUS, KIND, OP,
} from "../src/escrow.js";

const arb = arbiterKeyFromSeed(randomBytes(32).toString("hex"));
const evil = arbiterKeyFromSeed(randomBytes(32).toString("hex"));

let bc, seller, buyer, fee, stranger;
async function setup() {
  bc = await Blockchain.create();
  bc.now = 1_800_000_000;
  seller = await bc.treasury("seller");
  buyer = await bc.treasury("buyer");
  fee = await bc.treasury("fee");
  stranger = await bc.treasury("stranger");
}
function params(over = {}) {
  return {
    dealId: 42n, kind: KIND.ton, deadline: bc.now + 14 * 86400, arbiterKeyHex: arb.publicKeyHex,
    buyerAmount: toNano("10"), feeAmount: toNano("0.1"),
    seller: seller.address.toString(), buyer: buyer.address.toString(), feeWallet: fee.address.toString(),
    ...over,
  };
}
async function deploy(p, value, body) {
  const addr = escrowAddress(p);
  const r = await seller.send({ to: addr, value, init: escrowStateInit(p), body, bounce: true });
  return { addr, r };
}
async function data(addr) { return readEscrowData((await bc.runGetMethod(addr, "get_escrow_data")).stackReader); }
async function bal(addr) { return (await bc.getContract(addr)).balance; }
function outTo(r, from, to) {
  return r.transactions.filter((t) => t.inMessage?.info.type === "internal" && t.inMessage.info.src.equals(from) && t.inMessage.info.dest.equals(to));
}
function sentValue(r, from, to) { return outTo(r, from, to).reduce((a, t) => a + t.inMessage.info.value.coins, 0n); }
function aborted(r, addr) { return r.transactions.find((t) => t.inMessage?.info.dest?.equals?.(addr))?.description?.aborted; }
async function sendExt(addr, body) { return bc.sendMessage(external({ to: addr, body })); }
async function extRejected(addr, body) {
  try { await sendExt(addr, body); return false; } catch (e) { return true; }
}

describe("TON deal", () => {
  beforeEach(setup);

  test("deploy stores params and status open", async () => {
    const p = params();
    const { addr } = await deploy(p, toNano("10.16"));
    const d = await data(addr);
    assert.equal(d.status, STATUS.open);
    assert.equal(d.seqno, 0);
    assert.equal(d.dealId, 42n);
    assert.ok(d.seller.equals(seller.address) && d.buyer.equals(buyer.address) && d.feeWallet.equals(fee.address));
    assert.equal(d.jettonWallet, null);
    assert.equal(d.arbiterKeyHex, arb.publicKeyHex);
  });

  test("seller release pays buyer exact amount, fee wallet, rest to seller; second release fails", async () => {
    const p = params();
    const { addr } = await deploy(p, toNano("10.16"));
    const r = await seller.send({ to: addr, value: toNano("0.05"), body: bodyRelease(1n) });
    assert.equal(aborted(r, addr), false);
    assert.equal(sentValue(r, addr, buyer.address), toNano("10"));
    assert.equal(sentValue(r, addr, fee.address), toNano("0.1"));
    assert.ok(sentValue(r, addr, seller.address) > toNano("0.05"), "unused gas reserve returns to the seller");
    assert.equal((await data(addr)).status, STATUS.released);
    assert.ok((await bal(addr)) <= toNano("0.01"));
    const r2 = await seller.send({ to: addr, value: toNano("0.05"), body: bodyRelease(2n) });
    assert.equal(aborted(r2, addr), true);
  });

  test("only the seller can release; only the buyer can cancel", async () => {
    const p = params();
    const { addr } = await deploy(p, toNano("10.16"));
    for (const w of [buyer, stranger, fee]) {
      const r = await w.send({ to: addr, value: toNano("0.05"), body: bodyRelease() });
      assert.equal(aborted(r, addr), true);
    }
    for (const w of [seller, stranger]) {
      const r = await w.send({ to: addr, value: toNano("0.05"), body: bodyCancel() });
      assert.equal(aborted(r, addr), true);
    }
    assert.equal((await data(addr)).status, STATUS.open);
  });

  test("under-funded escrow cannot be released", async () => {
    const p = params();
    const { addr } = await deploy(p, toNano("5"));
    const r = await seller.send({ to: addr, value: toNano("0.05"), body: bodyRelease() });
    assert.equal(aborted(r, addr), true);
    assert.equal((await data(addr)).status, STATUS.open);
  });

  test("buyer cancel refunds the seller", async () => {
    const p = params();
    const { addr } = await deploy(p, toNano("10.16"));
    const s0 = await seller.getBalance();
    const r = await buyer.send({ to: addr, value: toNano("0.05"), body: bodyCancel() });
    assert.equal(aborted(r, addr), false);
    assert.equal((await data(addr)).status, STATUS.refunded);
    assert.ok((await seller.getBalance()) - s0 > toNano("10.1"));
  });

  test("reclaim only after deadline", async () => {
    const p = params();
    const { addr } = await deploy(p, toNano("10.16"));
    let r = await seller.send({ to: addr, value: toNano("0.05"), body: bodyReclaim() });
    assert.equal(aborted(r, addr), true);
    bc.now = p.deadline + 1;
    r = await seller.send({ to: addr, value: toNano("0.05"), body: bodyReclaim() });
    assert.equal(aborted(r, addr), false);
    assert.equal((await data(addr)).status, STATUS.refunded);
  });

  test("unknown op bounces, plain top-up accepted", async () => {
    const p = params();
    const { addr } = await deploy(p, toNano("10.16"));
    const r = await stranger.send({ to: addr, value: toNano("1"), body: beginCell().storeUint(0xdeadbeef, 32).storeUint(0, 64).endCell() });
    assert.equal(aborted(r, addr), true);
    const before = await bal(addr);
    await stranger.send({ to: addr, value: toNano("1") });
    assert.ok((await bal(addr)) > before);
  });
});

describe("arbiter decisions (external messages)", () => {
  beforeEach(setup);

  test("valid release is executed once; replay, wrong seqno, expiry, wrong key and foreign escrow are rejected", async () => {
    const p = params();
    const { addr } = await deploy(p, toNano("10.16"));
    const other = (await deploy(params({ dealId: 43n }), toNano("10.16"))).addr;
    const vu = bc.now + 300;

    assert.ok(await extRejected(addr, buildDecisionExternal(evil.priv, addr, { seqno: 0, validUntil: vu, action: ACTION.release }).body));
    assert.ok(await extRejected(addr, buildDecisionExternal(arb.priv, addr, { seqno: 1, validUntil: vu, action: ACTION.release }).body));
    assert.ok(await extRejected(addr, buildDecisionExternal(arb.priv, addr, { seqno: 0, validUntil: bc.now - 1, action: ACTION.release }).body));
    // signature made for another escrow must not work here
    assert.ok(await extRejected(addr, buildDecisionExternal(arb.priv, other, { seqno: 0, validUntil: vu, action: ACTION.release }).body));
    // tampered payload (signed release, delivered as refund)
    const pl = decisionPayload({ seqno: 0, validUntil: vu, action: ACTION.release });
    const sig = edSignHash(arb.priv, decisionHash(addr, pl));
    assert.ok(await extRejected(addr, buildDecisionBody(sig, decisionPayload({ seqno: 0, validUntil: vu, action: ACTION.refund, amount: 0 }))));
    assert.equal((await bal(addr)) >= toNano("10.15"), true, "rejected externals must not spend contract gas");

    const good = buildDecisionExternal(arb.priv, addr, { seqno: 0, validUntil: vu, action: ACTION.release }).body;
    const rr = await sendExt(addr, good);
    assert.equal(sentValue(rr, addr, buyer.address), toNano("10"));
    assert.equal(sentValue(rr, addr, fee.address), toNano("0.1"));
    const d = await data(addr);
    assert.equal(d.status, STATUS.released);
    assert.equal(d.seqno, 1);
    assert.ok(await extRejected(addr, good), "replay must be rejected");
  });

  test("refund decision returns funds to the seller", async () => {
    const p = params();
    const { addr } = await deploy(p, toNano("10.16"));
    const s0 = await seller.getBalance();
    await sendExt(addr, buildDecisionExternal(arb.priv, addr, { seqno: 0, validUntil: bc.now + 60, action: ACTION.refund, amount: 0 }).body);
    assert.equal((await data(addr)).status, STATUS.refunded);
    assert.ok((await seller.getBalance()) - s0 > toNano("10.1"));
    assert.ok(await extRejected(addr, buildDecisionExternal(arb.priv, addr, { seqno: 1, validUntil: bc.now + 60, action: ACTION.release }).body));
  });

  test("recover is only possible after the deal is closed", async () => {
    const p = params();
    const { addr } = await deploy(p, toNano("10.16"));
    assert.ok(await extRejected(addr, buildDecisionExternal(arb.priv, addr, { seqno: 0, validUntil: bc.now + 60, action: ACTION.recoverBuyer, amount: toNano("1") }).body));
    await sendExt(addr, buildDecisionExternal(arb.priv, addr, { seqno: 0, validUntil: bc.now + 60, action: ACTION.refund, amount: 0 }).body);
    await stranger.send({ to: addr, value: toNano("2") }); // late top-up
    const rr = await sendExt(addr, buildDecisionExternal(arb.priv, addr, { seqno: 1, validUntil: bc.now + 60, action: ACTION.recoverBuyer, amount: toNano("1") }).body);
    assert.equal(sentValue(rr, addr, buyer.address), toNano("1"));
  });

  test("garbage external messages are not accepted", async () => {
    const p = params();
    const { addr } = await deploy(p, toNano("10.16"));
    const b = await bal(addr);
    for (let i = 0; i < 5; i++) assert.ok(await extRejected(addr, beginCell().storeBuffer(randomBytes(100)).endCell()));
    assert.equal(await bal(addr), b);
  });
});

describe("jetton deal", () => {
  beforeEach(setup);
  const fakeJw = () => Address.parse("0:" + randomBytes(32).toString("hex"));
  function jettonOuts(r, addr, jw) {
    return outTo(r, addr, jw).map((t) => {
      const s = t.inMessage.body.beginParse();
      const op = s.loadUint(32); s.loadUintBig(64);
      return { op, amount: s.loadCoins(), to: s.loadAddress(), resp: s.loadAddress() };
    });
  }

  test("setup requires a valid arbiter signature and happens once", async () => {
    const p = params({ kind: KIND.jetton, buyerAmount: 99_500_000n, feeAmount: 1_000_000n });
    const addr = escrowAddress(p);
    const jw = fakeJw();
    const badSig = edSignHash(evil.priv, setupHash(addr, jw));
    let r = await seller.send({ to: addr, value: toNano("0.3"), init: escrowStateInit(p), body: buildSetupBody(jw, badSig), bounce: true });
    assert.equal(aborted(r, addr), true);
    const sig = edSignHash(arb.priv, setupHash(addr, jw));
    r = await seller.send({ to: addr, value: toNano("0.3"), init: escrowStateInit(p), body: buildSetupBody(jw, sig), bounce: true });
    assert.equal(aborted(r, addr), false);
    assert.ok((await data(addr)).jettonWallet.equals(jw));
    const jw2 = fakeJw();
    r = await seller.send({ to: addr, value: toNano("0.05"), body: buildSetupBody(jw2, edSignHash(arb.priv, setupHash(addr, jw2))) });
    assert.equal(aborted(r, addr), true);
  });

  test("release sends buyer and fee transfers through the escrow jetton wallet", async () => {
    const p = params({ kind: KIND.jetton, buyerAmount: 99_500_000n, feeAmount: 1_000_000n });
    const addr = escrowAddress(p);
    const jw = fakeJw();
    await seller.send({ to: addr, value: toNano("0.3"), init: escrowStateInit(p), body: buildSetupBody(jw, edSignHash(arb.priv, setupHash(addr, jw))), bounce: true });
    const r = await seller.send({ to: addr, value: toNano("0.05"), body: bodyRelease(7n) });
    assert.equal(aborted(r, addr), false);
    const outs = jettonOuts(r, addr, jw);
    assert.equal(outs.length, 2);
    assert.equal(outs[0].op, OP.jettonTransfer);
    assert.equal(outs[0].amount, 99_500_000n);
    assert.ok(outs[0].to.equals(buyer.address));
    assert.ok(outs[0].resp.equals(seller.address));
    assert.equal(outs[1].amount, 1_000_000n);
    assert.ok(outs[1].to.equals(fee.address));
    assert.equal((await data(addr)).status, STATUS.released);
    // after a release the seller may not sweep jettons (they belong to the buyer)
    const s = await seller.send({ to: addr, value: toNano("0.2"), body: bodySweep(1n) });
    assert.equal(aborted(s, addr), true);
  });

  test("release without setup is impossible; refund then sweep works", async () => {
    const p = params({ kind: KIND.jetton, buyerAmount: 50_000_000n, feeAmount: 500_000n });
    const addr = escrowAddress(p);
    await seller.send({ to: addr, value: toNano("0.3"), init: escrowStateInit(p), bounce: true });
    let r = await seller.send({ to: addr, value: toNano("0.05"), body: bodyRelease() });
    assert.equal(aborted(r, addr), true);
    const jw = fakeJw();
    await seller.send({ to: addr, value: toNano("0.05"), body: buildSetupBody(jw, edSignHash(arb.priv, setupHash(addr, jw))) });
    r = await buyer.send({ to: addr, value: toNano("0.05"), body: bodyCancel() });
    const outs = jettonOuts(r, addr, jw);
    assert.equal(outs.length, 1);
    assert.equal(outs[0].amount, 50_500_000n);
    assert.ok(outs[0].to.equals(seller.address));
    r = await seller.send({ to: addr, value: toNano("0.2"), body: bodySweep(123n) });
    assert.equal(aborted(r, addr), false);
    assert.equal(jettonOuts(r, addr, jw)[0].amount, 123n);
  });

  test("arbiter refund may override the jetton amount (actual balance)", async () => {
    const p = params({ kind: KIND.jetton, buyerAmount: 50_000_000n, feeAmount: 500_000n });
    const addr = escrowAddress(p);
    const jw = fakeJw();
    await seller.send({ to: addr, value: toNano("0.3"), init: escrowStateInit(p), body: buildSetupBody(jw, edSignHash(arb.priv, setupHash(addr, jw))), bounce: true });
    const r = await sendExt(addr, buildDecisionExternal(arb.priv, addr, { seqno: 0, validUntil: bc.now + 60, action: ACTION.refund, amount: 20_000_000n }).body);
    const outs = jettonOuts(r, addr, jw);
    assert.equal(outs[0].amount, 20_000_000n);
    assert.ok(outs[0].to.equals(seller.address));
  });
});
