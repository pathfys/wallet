// Backend escrow helpers: compiled code + arbiter (Ed25519) signing via node:crypto.
// Pure layout/body helpers live in escrow-core.js and are shared with the browser.
import { Address, Cell, beginCell, external, storeMessage } from "@ton/core";
import { createPrivateKey, createPublicKey, sign as edSign, verify as edVerify } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { makeEscrow, decisionPayload, decisionHash, buildDecisionBody } from "./escrow-core.js";
export * from "./escrow-core.js";

const BUILD = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "contracts", "build", "pmr_escrow.json"), "utf8"));
export const ESCROW_CODE = Cell.fromBoc(Buffer.from(BUILD.codeBoc, "base64"))[0];
export const ESCROW_CODE_BOC = BUILD.codeBoc;
export const ESCROW_CODE_HASH = BUILD.codeHashHex;
export const { buildEscrowData, escrowStateInit, escrowAddress } = makeEscrow(ESCROW_CODE);

const PKCS8_ED25519 = Buffer.from("302e020100300506032b657004220420", "hex");
export function arbiterKeyFromSeed(seedHex) {
  const seed = Buffer.from(String(seedHex || ""), "hex");
  if (seed.length !== 32) throw new Error("ARBITER_SECRET must be 32 bytes hex");
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, seed]), format: "der", type: "pkcs8" });
  const pubDer = createPublicKey(priv).export({ format: "der", type: "spki" });
  return { priv, publicKeyHex: Buffer.from(pubDer).subarray(-32).toString("hex") };
}
export function edSignHash(priv, hash) { return edSign(null, hash, priv); }
export function edVerifyHash(pubHex, hash, sig) {
  const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(pubHex, "hex")]);
  return edVerify(null, hash, createPublicKey({ key: der, format: "der", type: "spki" }), sig);
}
// signed external message ready for toncenter sendBoc
export function buildDecisionExternal(priv, escrow, params) {
  const payload = decisionPayload(params);
  const sig = edSignHash(priv, decisionHash(escrow, payload));
  const body = buildDecisionBody(sig, payload);
  const msg = external({ to: Address.parse(String(escrow)), body });
  return { body, boc: beginCell().store(storeMessage(msg)).endCell().toBoc().toString("base64") };
}
