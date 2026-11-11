// The app's single inline <script type="module"> is allowed in the CSP <meta> by its SHA-256
// hash (no 'unsafe-inline'). Any edit of index.html (e.g. CONFIG) changes the hash, so every
// tool that writes index.html — and the static server itself — re-syncs it with this helper.
import { createHash } from "node:crypto";

const INLINE = /<script type="module">([\s\S]*?)<\/script>/g;
const SCRIPT_SRC = /(script-src 'self' )(?:'unsafe-inline'|'sha256-[A-Za-z0-9+/=]+')/;

export function inlineScriptHash(html) {
  const inline = [...html.matchAll(INLINE)].map((m) => m[1]);
  if (inline.length !== 1) throw new Error("expected exactly one inline <script type=module>, got " + inline.length);
  return "'sha256-" + createHash("sha256").update(inline[0], "utf8").digest("base64") + "'";
}

export function syncCspHash(html) {
  const h = inlineScriptHash(html);
  if (!SCRIPT_SRC.test(html)) throw new Error("CSP script-src not found in index.html");
  return { html: html.replace(SCRIPT_SRC, `$1${h}`), hash: h };
}

// values the backend and the frontend must agree on
export function frontendConfig(html) {
  const get = (k) => (new RegExp(`\\b${k}:"([^"]*)"`).exec(html) || [])[1];
  return { arbiterPubkey: get("ARBITER_PUBKEY"), feeWallet: get("FEE_WALLET"), apiBase: get("API_BASE") };
}
