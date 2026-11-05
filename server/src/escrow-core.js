// Pure escrow helpers (only @ton/core). Shared verbatim by the backend and the
// browser bundle (vendor/pmr-vendor.js), so the client recomputes every escrow
// address with exactly the same code as the server.
import { Address, Cell, beginCell, contractAddress } from "@ton/core";

export const OP = {
  setup: 0x504d5201, release: 0x504d5202, cancel: 0x504d5203, reclaim: 0x504d5204, sweep: 0x504d5205,
  jettonTransfer: 0x0f8a7ea5,
};
export const TAG = { setup: 0x53455455, decision: 0x44454349 };
export const STATUS = { open: 0, released: 1, refunded: 2 };
export const ACTION = { release: 1, refund: 2, recoverBuyer: 3, recoverSeller: 4 };
export const KIND = { ton: 0, jetton: 1 };

// TON amounts (nanotons) the seller attaches when deploying an escrow.
// Unused TON always returns to the seller when the deal closes.
export const ESCROW_TON = {
  tonDealReserve: 60_000_000n,     // 0.06 TON on top of the deal amount (gas for payouts + storage)
  jettonDealDeploy: 300_000_000n,  // 0.30 TON: storage + 2 jetton transfers x 0.1 TON + decision gas
  jettonTransferValue: 150_000_000n, // value sent with the seller's own jetton transfer to the escrow
  releaseValue: 50_000_000n,       // value the seller attaches to a RELEASE message
};


export function makeEscrow(codeCell) {
  function buildEscrowData(p) {
    const addrs = beginCell()
      .storeAddress(Address.parse(String(p.seller)))
      .storeAddress(Address.parse(String(p.buyer)))
      .storeAddress(Address.parse(String(p.feeWallet)))
      .endCell();
    const params = beginCell()
      .storeUint(BigInt(p.dealId), 64)
      .storeUint(p.kind, 1)
      .storeUint(p.deadline, 32)
      .storeUint(BigInt("0x" + p.arbiterKeyHex), 256)
      .storeCoins(BigInt(p.buyerAmount))
      .storeCoins(BigInt(p.feeAmount))
      .storeRef(addrs)
      .endCell();
    return beginCell().storeUint(0, 8).storeUint(0, 32).storeAddress(null).storeRef(params).endCell();
  }
  const escrowStateInit = (p) => ({ code: codeCell, data: buildEscrowData(p) });
  const escrowAddress = (p) => contractAddress(0, escrowStateInit(p));
  return { buildEscrowData, escrowStateInit, escrowAddress };
}

export function setupHash(escrow, jettonWallet) {
  return beginCell().storeUint(TAG.setup, 32).storeAddress(Address.parse(String(escrow)))
    .storeAddress(Address.parse(String(jettonWallet))).endCell().hash();
}
export function buildSetupBody(jettonWallet, signature, queryId = 0n) {
  return beginCell().storeUint(OP.setup, 32).storeUint(BigInt(queryId), 64)
    .storeAddress(Address.parse(String(jettonWallet))).storeBuffer(Buffer.from(signature), 64).endCell();
}
export function decisionPayload({ seqno, validUntil, action, amount }) {
  const b = beginCell().storeUint(seqno, 32).storeUint(validUntil, 32).storeUint(action, 8);
  if (action !== ACTION.release) b.storeCoins(BigInt(amount || 0));
  return b.endCell();
}
export function decisionHash(escrow, payloadCell) {
  return beginCell().storeUint(TAG.decision, 32).storeAddress(Address.parse(String(escrow)))
    .storeSlice(payloadCell.beginParse()).endCell().hash();
}
export function buildDecisionBody(signature, payloadCell) {
  return beginCell().storeBuffer(Buffer.from(signature), 64).storeSlice(payloadCell.beginParse()).endCell();
}
export const bodyRelease = (q = 0n) => beginCell().storeUint(OP.release, 32).storeUint(BigInt(q), 64).endCell();
export const bodyCancel = (q = 0n) => beginCell().storeUint(OP.cancel, 32).storeUint(BigInt(q), 64).endCell();
export const bodyReclaim = (q = 0n) => beginCell().storeUint(OP.reclaim, 32).storeUint(BigInt(q), 64).endCell();
export const bodySweep = (amount = 0n, q = 0n) => beginCell().storeUint(OP.sweep, 32).storeUint(BigInt(q), 64).storeCoins(BigInt(amount)).endCell();

// TEP-74 jetton transfer from the sender's own jetton wallet; optional text comment as forward payload
export function jettonTransferBody({ amount, to, responseTo, queryId = 0n, forwardTon = 0n, comment = "" }) {
  const b = beginCell().storeUint(OP.jettonTransfer, 32).storeUint(BigInt(queryId), 64).storeCoins(BigInt(amount))
    .storeAddress(Address.parse(String(to))).storeAddress(Address.parse(String(responseTo)))
    .storeBit(false).storeCoins(BigInt(forwardTon));
  if (comment) b.storeBit(true).storeRef(beginCell().storeUint(0, 32).storeStringTail(comment).endCell());
  else b.storeBit(false);
  return b.endCell();
}

export function readEscrowData(r) {
  const status = r.readNumber(), seqno = r.readNumber(), dealId = r.readBigNumber(), kind = r.readNumber();
  const deadline = r.readNumber(), arbiterKey = r.readBigNumber(), buyerAmount = r.readBigNumber(), feeAmount = r.readBigNumber();
  const seller = r.readAddress(), buyer = r.readAddress(), feeWallet = r.readAddress(), jettonWallet = r.readAddressOpt();
  return { status, seqno, dealId, kind, deadline, arbiterKeyHex: arbiterKey.toString(16).padStart(64, "0"), buyerAmount, feeAmount, seller, buyer, feeWallet, jettonWallet };
}
