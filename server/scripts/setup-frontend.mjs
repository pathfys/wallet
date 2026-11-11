// Writes the values from .env that the frontend must pin into ../index.html:
//   CONFIG.ARBITER_PUBKEY  — clients refuse escrows signed by any other arbiter key
//   CONFIG.FEE_WALLET      — clients refuse escrows paying fees anywhere else
// and re-syncs the CSP hash of the inline script. Run after filling .env:  npm run setup:frontend
import { readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { loadConfig } from "../src/config.js";
import { syncCspHash, frontendConfig } from "../src/csp.js";

const cfg = loadConfig();
const file = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "index.html");
let html = readFileSync(file, "utf8");
const set = (k, val) => {
  const re = new RegExp(`(\\b${k}:")[^"]*(")`);
  if (!re.test(html)) throw new Error(`CONFIG.${k} not found in index.html`);
  html = html.replace(re, `$1${val}$2`);
};
set("ARBITER_PUBKEY", cfg.arbiter.publicKeyHex);
set("FEE_WALLET", cfg.feeWallet);
const { html: out, hash } = syncCspHash(html);
writeFileSync(file, out);
const fc = frontendConfig(out);
console.log(`index.html updated:\n  ARBITER_PUBKEY=${fc.arbiterPubkey}\n  FEE_WALLET=${fc.feeWallet}\n  CSP script hash ${hash}`);
