// PMR Wallet backend entry point.
import { join } from "node:path";
import { readFileSync } from "node:fs";
import { frontendConfig } from "./csp.js";
import { loadConfig } from "./config.js";
import { openDb } from "./db.js";
import { makeRouter, makeServer, clientIp } from "./http.js";
import { RateLimiter, DbNonceCache, encryptJson, decryptJson } from "./security.js";
import { Toncenter, makeChain } from "./ton.js";
import { makePrices } from "./prices.js";
import { makeBot } from "./bot.js";
import { makeBotUpdates } from "./bot-updates.js";
import { makeHub, attachWs, registerChat } from "./chat.js";
import { registerAuth } from "./auth.js";
import { registerP2P } from "./p2p.js";
import { registerAdmin } from "./admin.js";
import { startJobs } from "./jobs.js";

const REDACT = /(bot\d+:[A-Za-z0-9_-]+|Bearer [A-Za-z0-9_-]+)/g;
export const makeLog = (quiet = false) => {
  const out = (lvl) => (msg, data) => {
    if (quiet && lvl !== "error") return;
    const line = JSON.stringify({ t: new Date().toISOString(), lvl, msg, ...(data || {}) }).replace(REDACT, "[redacted]");
    (lvl === "error" ? process.stderr : process.stdout).write(line + "\n");
  };
  return { info: out("info"), warn: out("warn"), error: out("error") };
};

export function createApp(cfg, deps = {}) {
  const log = deps.log || makeLog();
  const db = deps.db || openDb(join(cfg.dataDir, "pmr.sqlite"));
  const rpc = deps.rpc || new Toncenter({ endpoint: cfg.toncenter, apiKey: cfg.toncenterKey, rps: cfg.toncenterRps });
  const ctx = {
    cfg, db, log,
    chain: deps.chain || makeChain(cfg, rpc),
    prices: deps.prices || makePrices(cfg),
    limiter: new RateLimiter(),
    nonces: new DbNonceCache(db),
    hub: makeHub(),
    enc: (obj, aad) => encryptJson(cfg.dataKey, obj, aad),
    dec: (s, aad) => decryptJson(cfg.dataKey, s, aad),
    clientIp: (req) => clientIp(req, cfg.trustProxy),
  };
  ctx.bot = deps.bot || makeBot(cfg, db, log);
  const seen = new Set();
  ctx.touch = (uid) => {
    const hour = Math.floor(Date.now() / 3_600_000), k = uid + ":" + hour;
    if (seen.has(k)) return;
    if (seen.size > 100_000) seen.clear();
    seen.add(k);
    db.run("INSERT OR IGNORE INTO activity(user_id,hour) VALUES(?,?)", uid, hour);
    db.run("UPDATE users SET last_seen_at=? WHERE id=?", Date.now(), uid);
  };
  // roles follow ADMIN_IDS on every start (removing an id revokes access)
  db.run(`UPDATE users SET role='user' WHERE role='admin' AND id NOT IN (${cfg.adminIds.map(() => "?").join(",") || "NULL"})`, ...cfg.adminIds);

  const router = makeRouter();
  registerAuth(router, ctx);
  registerP2P(router, ctx);
  registerChat(router, ctx);
  registerAdmin(router, ctx);
  ctx.botUpdates = makeBotUpdates(ctx);
  ctx.botUpdates.registerRoute(router);
  const server = makeServer(ctx, router);
  attachWs(server, ctx);
  const jobs = cfg.disableJobs ? null : startJobs(ctx);
  if (!cfg.disableJobs && !deps.bot) ctx.botUpdates.start();
  return { server, ctx, router, jobs };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const cfg = loadConfig();
  const { server, ctx, jobs } = createApp(cfg);
  server.listen(cfg.port, cfg.host, () => ctx.log.info("listening", { host: cfg.host, port: cfg.port, network: cfg.network, arbiter: cfg.arbiter.publicKeyHex }));
  if (cfg.staticDir) {
    try {
      const fc = frontendConfig(readFileSync(join(cfg.staticDir, "index.html"), "utf8"));
      if (fc.arbiterPubkey !== cfg.arbiter.publicKeyHex) ctx.log.error("index.html CONFIG.ARBITER_PUBKEY does not match ARBITER_SECRET — run: npm run setup:frontend");
      if (fc.feeWallet && fc.feeWallet !== cfg.feeWallet) ctx.log.error("index.html CONFIG.FEE_WALLET differs from FEE_WALLET — run: npm run setup:frontend");
    } catch (e) { ctx.log.warn("index.html check skipped", { err: String(e) }); }
  }
  const stop = () => { ctx.log.info("shutdown"); jobs?.stop(); ctx.botUpdates.stop(); server.close(() => { ctx.db.close(); process.exit(0); }); setTimeout(() => process.exit(0), 5000).unref(); };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
  process.on("unhandledRejection", (e) => ctx.log.error("unhandledRejection", { err: String(e && e.stack || e) }));
}
