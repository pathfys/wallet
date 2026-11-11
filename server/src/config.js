// Configuration from environment (optionally a .env file). Fails fast on
// missing/invalid secrets so the service never starts in an insecure state.
import { readFileSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Address } from "@ton/core";
import { arbiterKeyFromSeed } from "./escrow.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function loadDotEnv(file) {
  if (!existsSync(file)) return;
  for (const line of readFileSync(file, "utf8").split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (!m || line.trim().startsWith("#")) continue;
    let v = m[2];
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
    if (process.env[m[1]] === undefined) process.env[m[1]] = v;
  }
}

export function loadConfig(env = process.env, { dotenv = true } = {}) {
  if (dotenv && env === process.env) loadDotEnv(resolve(ROOT, ".env"));
  const e = (k, d) => (env[k] === undefined || env[k] === "" ? d : String(env[k]));
  const need = (k) => { const v = e(k); if (!v) throw new Error(`config: ${k} is required`); return v; };
  const int = (k, d, min, max) => {
    const v = Number(e(k, d));
    if (!Number.isInteger(v) || v < min || v > max) throw new Error(`config: ${k} must be an integer in [${min}, ${max}]`);
    return v;
  };
  const hex32 = (k) => { const v = need(k); if (!/^[0-9a-fA-F]{64}$/.test(v)) throw new Error(`config: ${k} must be 64 hex chars (32 bytes)`); return v.toLowerCase(); };

  const network = e("TON_NETWORK", "mainnet");
  if (!["mainnet", "testnet"].includes(network)) throw new Error("config: TON_NETWORK must be mainnet|testnet");

  const botToken = need("BOT_TOKEN");
  if (!/^\d{5,16}:[A-Za-z0-9_-]{30,64}$/.test(botToken)) throw new Error("config: BOT_TOKEN looks invalid");

  const feeWallet = need("FEE_WALLET");
  try { Address.parse(feeWallet); } catch { throw new Error("config: FEE_WALLET is not a TON address"); }
  const usdtMaster = e("USDT_MASTER", "EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs");
  Address.parse(usdtMaster);

  const arbiter = arbiterKeyFromSeed(hex32("ARBITER_SECRET"));
  const dataKey = Buffer.from(hex32("DATA_KEY"), "hex");

  const adminIds = e("ADMIN_IDS", "").split(",").map((s) => s.trim()).filter(Boolean).map((s) => {
    if (!/^\d{1,16}$/.test(s)) throw new Error("config: ADMIN_IDS must be comma-separated Telegram user ids");
    return Number(s);
  });

  const origins = e("ALLOWED_ORIGINS", "").split(",").map((s) => s.trim().replace(/\/$/, "")).filter(Boolean);
  for (const o of origins) if (!/^https?:\/\/[a-z0-9.-]+(:\d+)?$/i.test(o)) throw new Error(`config: bad origin ${o}`);

  const prb = e("PRB_PER_USD", "");
  if (prb && !/^\d{1,4}(\.\d{1,6})?$/.test(prb)) throw new Error("config: PRB_PER_USD must be a decimal number");

  const feeCap = e("P2P_FEE_MAX_SIDE_USD", "0");
  if (!/^\d{1,6}(\.\d{1,2})?$/.test(feeCap)) throw new Error("config: P2P_FEE_MAX_SIDE_USD must be a number (0 = no cap)");

  const staticDir = e("STATIC_DIR", "");

  // Telegram bot: how updates arrive and where the "Открыть" button leads
  const webAppUrl = e("WEBAPP_URL", "");
  if (webAppUrl && !/^https:\/\/[^\s"<>]+$/.test(webAppUrl)) throw new Error("config: WEBAPP_URL must be an https:// URL");
  const botMode = e("BOT_MODE", "polling");
  if (!["polling", "webhook", "off"].includes(botMode)) throw new Error("config: BOT_MODE must be polling | webhook | off");
  const botWebhookUrl = e("BOT_WEBHOOK_URL", ""), botWebhookSecret = e("BOT_WEBHOOK_SECRET", "");
  if (botMode === "webhook") {
    if (!/^https:\/\/[^\s"<>]+\/api\/tg\/webhook$/.test(botWebhookUrl)) throw new Error("config: BOT_WEBHOOK_URL must be https://<domain>/api/tg/webhook");
    if (!/^[A-Za-z0-9_-]{32,256}$/.test(botWebhookSecret)) throw new Error("config: BOT_WEBHOOK_SECRET must be 32-256 chars of A-Z a-z 0-9 _ - (openssl rand -hex 32)");
  }
  return Object.freeze({
    root: ROOT,
    host: e("HOST", "127.0.0.1"),
    port: int("PORT", "8080", 1, 65535),
    trustProxy: e("TRUST_PROXY", "0") === "1",
    allowedOrigins: origins,
    staticDir: staticDir ? resolve(ROOT, staticDir) : "",
    dataDir: resolve(ROOT, e("DATA_DIR", "./data")),
    botToken,
    botApi: e("TELEGRAM_API", "https://api.telegram.org"),
    tgAppLink: e("TG_APP_LINK", ""),
    webAppUrl, botMode, botWebhookUrl, botWebhookSecret,
    loginMaxAgeSec: int("LOGIN_MAX_AGE_SEC", "86400", 60, 7 * 86400),
    sessionTtlSec: int("SESSION_TTL_SEC", "43200", 300, 7 * 86400),
    adminIds,
    network,
    toncenter: e("TONCENTER_ENDPOINT", network === "testnet" ? "https://testnet.toncenter.com/api/v2/jsonRPC" : "https://toncenter.com/api/v2/jsonRPC"),
    toncenterKey: e("TONCENTER_API_KEY", ""),
    toncenterRps: int("TONCENTER_RPS", e("TONCENTER_API_KEY", "") ? "8" : "1", 1, 50),
    feeWallet: Address.parse(feeWallet).toString({ bounceable: false, testOnly: network === "testnet" }),
    usdtMaster: Address.parse(usdtMaster).toString(),
    arbiter,
    dataKey,
    prbPerUsd: prb,
    coingecko: e("COINGECKO_URL", "https://api.coingecko.com/api/v3/simple/price"),
    p2pFeeSideBps: int("P2P_FEE_SIDE_BPS", "200", 0, 1000),      // 200 = 2% per side
    p2pFeeMaxSideUsdE6: BigInt(Math.round(Number(feeCap) * 1e6)),  // 0 = no cap
    escrowReclaimDays: int("ESCROW_RECLAIM_DAYS", "14", 3, 60),
    lockWindowMin: int("ESCROW_LOCK_WINDOW_MIN", "15", 5, 60),
    appealAfterMin: int("APPEAL_AFTER_MIN", "10", 1, 240),
    autoAppealHours: int("AUTO_APPEAL_HOURS", "24", 1, 240),
    disableJobs: e("DISABLE_JOBS", "0") === "1",
  });
}
