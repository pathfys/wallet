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
let next = src.replace(/(<script type="module" src="vendor\/pmr-vendor\.js" integrity=")[^"]*(")/, `$1${sri}$2`);
// CSP: the app's only inline script is allowed by its SHA-256 hash instead of 'unsafe-inline',
// so an injected <script> or on*= handler (XSS) will not run.
const inline = [...next.matchAll(/<script type="module">([\s\S]*?)<\/script>/g)].map((m) => m[1]);
if (inline.length !== 1) throw new Error("expected exactly one inline <script type=module>, got " + inline.length);
const cspHash = "'sha256-" + createHash("sha256").update(inline[0], "utf8").digest("base64") + "'";
next = next.replace(/(script-src 'self' )(?:'unsafe-inline'|'sha256-[A-Za-z0-9+/=]+')/, `$1${cspHash}`);
if (!next.includes(cspHash)) throw new Error("CSP script-src not found in index.html");
if (next !== src) writeFileSync(html, next);
console.log(`vendor/pmr-vendor.js ${(data.length / 1024).toFixed(0)} KB  ${sri}  csp ${cspHash}${next !== src ? "  (index.html updated)" : ""}`);
