// Browser bundle for index.html: TON libraries + PMR escrow helpers, served from
// our own origin (no runtime CDNs) and pinned with Subresource Integrity.
import { Buffer } from "buffer";
import * as TonCrypto from "@ton/crypto";
import {
  TonClient, WalletContractV4, JettonMaster, JettonWallet, internal, external, toNano, fromNano, beginCell, Address, Cell,
  SendMode, contractAddress, storeMessage, storeStateInit, comment,
} from "@ton/ton";
import QRCode from "qrcode";
import jsQR from "jsqr";
import { getHttpEndpoint } from "@orbs-network/ton-access";
import * as EscrowCore from "../src/escrow-core.js";

const codeCell = Cell.fromBoc(Buffer.from(__ESCROW_CODE_BOC__, "base64"))[0];
if (codeCell.hash().toString("hex") !== __ESCROW_CODE_HASH__) throw new Error("escrow code hash mismatch");
const Escrow = Object.freeze({ ...EscrowCore, ...EscrowCore.makeEscrow(codeCell), codeCell, codeHash: __ESCROW_CODE_HASH__ });

globalThis.Buffer = globalThis.Buffer || Buffer;
Object.defineProperty(window, "__PMR_VENDOR__", {
  value: Object.freeze({
    Buffer, TonCrypto, QRCode, jsQR, getHttpEndpoint, Escrow,
    Ton: Object.freeze({ TonClient, WalletContractV4, JettonMaster, JettonWallet, internal, external, toNano, fromNano, beginCell, Address, Cell, SendMode, contractAddress, storeMessage, storeStateInit, comment }),
  }),
  writable: false, configurable: false,
});
