// Builds ../vendor/pmr-vendor.js and writes its SRI hash into ../index.html.
import { build } from "esbuild";
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = join(dirname(fileURLToPath(import.meta.url)), "..");
const contract = JSON.parse(readFileSync(join(here, "contracts/build/pmr_escrow.json"), "utf8"));
const outfile = join(here, "..", "vendor", "pmr-vendor.js");
await build({
  entryPoints: [join(here, "vendor-src/entry.js")],
  bundle: true, minify: true, format: "esm", platform: "browser", target: ["es2020", "safari15"],
  inject: [join(here, "vendor-src/buffer-shim.js")],
  define: { __ESCROW_CODE_BOC__: JSON.stringify(contract.codeBoc), __ESCROW_CODE_HASH__: JSON.stringify(contract.codeHashHex), global: "globalThis", "process.env.NODE_ENV": '"production"' },
  legalComments: "eof", outfile, logLevel: "warning",
});
const data = readFileSync(outfile);
const sri = "sha384-" + createHash("sha384").update(data).digest("base64");
const html = join(here, "..", "index.html");
const src = readFileSync(html, "utf8");
const next = src.replace(/(<script type="module" src="vendor\/pmr-vendor\.js" integrity=")[^"]*(")/, `$1${sri}$2`);
if (next !== src) writeFileSync(html, next);
console.log(`vendor/pmr-vendor.js ${(data.length / 1024).toFixed(0)} KB  ${sri}${next !== src ? "  (index.html updated)" : ""}`);
