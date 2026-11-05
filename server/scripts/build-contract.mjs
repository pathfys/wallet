// Compiles contracts/pmr_escrow.fc and writes contracts/build/pmr_escrow.json
// (code BOC + code hash). The same code is embedded in the frontend; the client
// rebuilds every escrow address from this code and refuses mismatches.
import { compileFunc } from "@ton-community/func-js";
import { Cell } from "@ton/core";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const dir = join(dirname(fileURLToPath(import.meta.url)), "..", "contracts");
const res = await compileFunc({
  targets: ["pmr_escrow.fc"],
  sources: (p) => readFileSync(join(dir, p), "utf8"),
});
if (res.status !== "ok") { console.error(res.message); process.exit(1); }
if (res.warnings) console.warn(res.warnings);
const code = Cell.fromBoc(Buffer.from(res.codeBoc, "base64"))[0];
const out = { codeBoc: res.codeBoc, codeHashHex: code.hash().toString("hex"), bits: code.bits.length };
writeFileSync(join(dir, "build", "pmr_escrow.json"), JSON.stringify(out, null, 2) + "\n");
console.log("pmr_escrow compiled:", out.codeHashHex, `(${res.codeBoc.length} b64 chars)`);
