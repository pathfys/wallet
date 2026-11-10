// Login (Telegram initData -> session bound to a device key), profile, nickname,
// wallet ownership binding and the public client config.
import { randomBytes, createHash } from "node:crypto";
import { Address } from "@ton/core";
import { HttpError, bad, conflict, v, randomId, now, ASSETS, FIATS, PAY_TYPES, PAY_WINDOWS, PINS } from "./util.js";
import { verifyInitData, parseP256, verifyWalletProof, nickError, nickKey } from "./security.js";
import { ESCROW_CODE_HASH, ESCROW_TON } from "./escrow.js";

export function registerAuth(router, ctx) {
  const { cfg, db } = ctx;
  const ACTIVE_SQL = "status IN (5,10,20,30)";

  const publicConfig = () => ({
    network: cfg.network, feeWallet: cfg.feeWallet, arbiterKey: cfg.arbiter.publicKeyHex, escrowCodeHash: ESCROW_CODE_HASH,
    usdtMaster: cfg.usdtMaster, assets: Object.fromEntries(Object.entries(ASSETS).map(([k, a]) => [k, { dec: a.dec, step: a.step.toString() }])),
    fiats: FIATS, payTypes: PAY_TYPES, payWindows: PAY_WINDOWS, pins: PINS,
    fee: { sideBps: cfg.p2pFeeSideBps, orderBps: cfg.p2pFeeSideBps * 2, maxSideUsd: Number(cfg.p2pFeeMaxSideUsdE6) / 1e6 },
    escrowTon: Object.fromEntries(Object.entries(ESCROW_TON).map(([k, x]) => [k, x.toString()])),
    lockWindowMin: cfg.lockWindowMin, appealAfterMin: cfg.appealAfterMin,
  });
  const me = (u) => ({
    id: u.id, nick: u.nick, nickChangesLeft: u.nick_changes_left, role: u.role, firstName: u.first_name,
    wallet: u.wallet_address ? Address.parse(u.wallet_address).toString({ bounceable: false, testOnly: cfg.network === "testnet" }) : null,
    walletRaw: u.wallet_address, banned: !!u.banned_at, banReason: u.ban_reason || null, registeredAt: u.created_at,
    stats: ctx.userStats ? ctx.userStats(u.id) : null,
  });

  router.get("/api/config", { auth: "public" }, () => publicConfig());

  router.post("/api/auth/login", { auth: "public", limit: { key: "login", n: 60, ms: 60_000 } }, ({ body, ip }) => {
    const { user: tg, startParam } = verifyInitData(body.initData, cfg.botToken, cfg.loginMaxAgeSec);
    const { x, y } = parseP256(body.pub);
    const t = now();
    const role = cfg.adminIds.includes(tg.id) ? "admin" : "user";
    db.run(`INSERT INTO users(id, first_name, username, allows_pm, role, created_at, last_seen_at) VALUES(?,?,?,?,?,?,?)
      ON CONFLICT(id) DO UPDATE SET first_name=excluded.first_name, username=excluded.username,
        allows_pm=MAX(users.allows_pm, excluded.allows_pm), role=excluded.role, last_seen_at=excluded.last_seen_at`,
      tg.id, String(tg.first_name || "").slice(0, 64), String(tg.username || "").slice(0, 64), tg.allows_write_to_pm ? 1 : 0, role, t, t);
    const token = randomBytes(32).toString("base64url");
    const hash = createHash("sha256").update(token).digest("hex");
    db.tx(() => {
      db.run("INSERT INTO sessions(token_hash,user_id,pub_x,pub_y,created_at,expires_at,ip) VALUES(?,?,?,?,?,?,?)", hash, tg.id, x, y, t, t + cfg.sessionTtlSec * 1000, ip);
      // keep at most 5 live sessions per user
      db.run("DELETE FROM sessions WHERE user_id=? AND token_hash NOT IN (SELECT token_hash FROM sessions WHERE user_id=? ORDER BY created_at DESC LIMIT 5)", tg.id, tg.id);
    });
    const u = db.get("SELECT * FROM users WHERE id=?", tg.id);
    if (role === "admin") db.audit(tg.id, "admin_login", null, null, ip);
    return { token, expiresAt: t + cfg.sessionTtlSec * 1000, serverTime: Date.now(), me: me(u), config: publicConfig(), startParam: String(startParam).slice(0, 64) };
  });
  router.post("/api/auth/logout", { auth: "session-any" }, ({ tokenHash }) => { db.run("DELETE FROM sessions WHERE token_hash=?", tokenHash); return { ok: true }; });
  router.get("/api/me", { auth: "session-any" }, ({ user }) => me(user));
  router.get("/api/nick-check", { auth: "session-any", limit: { key: "nickchk", n: 60, ms: 60_000 } }, ({ user, query }) => {
    const nick = String(query.get("nick") || "").trim();
    const err = nickError(nick);
    if (err) return { ok: false, reason: err };
    const taken = db.get("SELECT id FROM users WHERE nick_key=?", nickKey(nick));
    return taken && taken.id !== user.id ? { ok: false, reason: "Такой ник уже занят" } : { ok: true, reason: "Ник свободен" };
  });

  router.post("/api/me/nick", { limit: { key: "nick", n: 10, ms: 3_600_000 } }, ({ user, body }) => {
    const nick = v.str(body.nick, "Ник", { min: 1, max: 16 });
    const err = nickError(nick);
    if (err) throw bad("bad_nick", err);
    if (user.nick) {
      if (user.nick_changes_left <= 0) throw conflict("nick_locked", "Ник уже менялся — повторная смена недоступна");
      if (nickKey(nick) === user.nick_key && nick === user.nick) throw bad("same_nick", "Это ваш текущий ник");
    }
    try {
      db.run("UPDATE users SET nick=?, nick_key=?, nick_changes_left=? WHERE id=?", nick, nickKey(nick), user.nick ? user.nick_changes_left - 1 : user.nick_changes_left, user.id);
    } catch (e) {
      if (/UNIQUE/.test(String(e))) throw conflict("nick_taken", "Такой ник уже занят");
      throw e;
    }
    db.audit(user.id, user.nick ? "nick_change" : "nick_set", null, { from: user.nick, to: nick });
    return me(db.get("SELECT * FROM users WHERE id=?", user.id));
  });

  // wallet binding: prove control of the WalletV4R2 key behind the address
  router.post("/api/wallet/challenge", { limit: { key: "wch", n: 20, ms: 600_000 } }, ({ user }) => {
    db.run("DELETE FROM wallet_challenges WHERE user_id=? OR created_at<?", user.id, now() - 600_000);
    const id = randomId(18);
    db.run("INSERT INTO wallet_challenges(id,user_id,created_at) VALUES(?,?,?)", id, user.id, now());
    return { challenge: id };
  });
  router.post("/api/wallet/bind", { limit: { key: "wbind", n: 20, ms: 600_000 } }, ({ user, body }) => {
    const ch = db.get("SELECT * FROM wallet_challenges WHERE id=? AND user_id=? AND used=0", String(body.challenge || ""), user.id);
    if (!ch || now() - ch.created_at > 300_000) throw bad("bad_challenge", "Запрос подтверждения устарел, повторите");
    db.run("UPDATE wallet_challenges SET used=1 WHERE id=?", ch.id); // single use, even if verification fails
    const addr = verifyWalletProof({ address: body.address, publicKeyHex: body.publicKey, signatureB64: body.signature, challenge: ch.id, userId: user.id });
    const raw = addr.toRawString();
    if (user.wallet_address === raw) return me(user);
    if (user.wallet_address && db.get(`SELECT COUNT(*) n FROM orders WHERE (buyer_id=? OR seller_id=?) AND ${ACTIVE_SQL}`, user.id, user.id).n)
      throw conflict("active_orders", "Нельзя сменить кошелёк при активных ордерах");
    try { db.run("UPDATE users SET wallet_address=?, wallet_pubkey=?, wallet_bound_at=? WHERE id=?", raw, String(body.publicKey).toLowerCase(), now(), user.id); }
    catch (e) { if (/UNIQUE/.test(String(e))) throw conflict("wallet_taken", "Этот кошелёк уже привязан к другому аккаунту"); throw e; }
    db.audit(user.id, "wallet_bind", raw);
    return me(db.get("SELECT * FROM users WHERE id=?", user.id));
  });
}
