// Support / admin panel API. Every route requires role=admin (checked
// server-side from ADMIN_IDS) and every state change is written to the audit log.
import { bad, conflict, notFound, v, now, ASSETS, toStr } from "./util.js";
import { ACTION } from "./escrow.js";
import { OS, ACTIVE } from "./p2p.js";

const HOUR = 3_600_000, DAY = 86_400_000;
const MON = ["Янв", "Фев", "Мар", "Апр", "Май", "Июн", "Июл", "Авг", "Сен", "Окт", "Ноя", "Дек"];
const DOW = ["Вс", "Пн", "Вт", "Ср", "Чт", "Пт", "Сб"];

export function registerAdmin(router, ctx) {
  const { db, bot } = ctx;
  const A = { auth: "admin" };

  // ------------------------------------------------------------------ stats
  function buckets(period) {
    const out = [], t = new Date();
    if (period === "day") {
      const h = new Date(t); h.setMinutes(0, 0, 0);
      for (let i = 23; i >= 0; i--) { const s = +h - i * HOUR; out.push({ s, e: s + HOUR, l: String(new Date(s).getHours()).padStart(2, "0") + ":00" }); }
    } else if (period === "week" || period === "month") {
      const n = period === "week" ? 7 : 30, d = new Date(t); d.setHours(0, 0, 0, 0);
      for (let i = n - 1; i >= 0; i--) { const s = new Date(d); s.setDate(d.getDate() - i); const e = new Date(s); e.setDate(s.getDate() + 1); out.push({ s: +s, e: +e, l: period === "week" ? DOW[s.getDay()] : String(s.getDate()) }); }
    } else {
      for (let i = 11; i >= 0; i--) { const s = new Date(t.getFullYear(), t.getMonth() - i, 1), e = new Date(t.getFullYear(), t.getMonth() - i + 1, 1); out.push({ s: +s, e: +e, l: MON[s.getMonth()] }); }
    }
    return out;
  }
  function usd(units, asset, usdE6) { return (Number(units) / 10 ** ASSETS[asset].dec) * (Number(usdE6) / 1e6); }
  function metrics(s, e) {
    const done = db.all("SELECT asset, amount_units, buyer_fee, seller_fee, usd_e6 FROM orders WHERE status=50 AND completed_at>=? AND completed_at<?", s, e);
    let volume = 0, fees = 0;
    for (const o of done) { volume += usd(o.amount_units, o.asset, o.usd_e6); fees += usd(o.buyer_fee + o.seller_fee, o.asset, o.usd_e6); }
    return {
      users: db.get("SELECT COUNT(DISTINCT user_id) n FROM activity WHERE hour>=? AND hour<?", Math.floor(s / HOUR), Math.ceil(e / HOUR)).n,
      ops: db.get("SELECT COUNT(*) n FROM orders WHERE created_at>=? AND created_at<?", s, e).n,
      trades: done.length, volume: Math.round(volume * 100) / 100, fees: Math.round(fees * 100) / 100,
      signups: db.get("SELECT COUNT(*) n FROM users WHERE created_at>=? AND created_at<?", s, e).n,
    };
  }
  router.get("/api/admin/stats", A, ({ query }) => {
    const period = v.oneOf(query.get("period") || "week", "period", ["day", "week", "month", "year"]);
    const bs = buckets(period);
    const series = bs.map((b) => ({ label: b.l, ...metrics(b.s, Math.min(b.e, now() + 1)) }));
    const start = bs[0].s, end = now() + 1, span = end - start;
    const cur = metrics(start, end), prev = metrics(start - span, start);
    const dist = db.all("SELECT status, COUNT(*) n FROM orders WHERE created_at>=? GROUP BY status", start);
    const by = (sts) => dist.filter((d) => sts.includes(d.status)).reduce((a, d) => a + d.n, 0);
    return {
      period, series, cur, prev,
      distribution: [
        { label: "Завершено", n: by([OS.COMPLETED]) }, { label: "Отменено", n: by([OS.CANCELLED]) },
        { label: "Апелляции", n: by([OS.APPEAL]) }, { label: "В процессе", n: by([OS.AWAIT_ESCROW, OS.AWAIT_PAY, OS.PAID]) },
      ],
      onlineAds: db.get("SELECT COUNT(*) n FROM ads WHERE status='online'").n,
      openAppeals: db.get("SELECT COUNT(*) n FROM appeals WHERE status='open'").n,
      newReports: db.get("SELECT COUNT(*) n FROM reports WHERE status='new'").n,
      totalUsers: db.get("SELECT COUNT(*) n FROM users").n,
    };
  });

  // ---------------------------------------------------------------- appeals
  const userBrief = (id) => { const u = db.get("SELECT id, nick, banned_at FROM users WHERE id=?", id); return u ? { id: u.id, nick: u.nick, banned: !!u.banned_at } : { id }; };
  router.get("/api/admin/appeals", A, ({ query }) => {
    const st = v.oneOf(query.get("status") || "open", "status", ["open", "closed"]);
    const rows = db.all(`SELECT a.*, o.asset, o.amount_units, o.fiat_cents, o.fiat, o.buyer_id, o.seller_id, o.escrow_deadline, o.status order_status FROM appeals a JOIN orders o ON o.id=a.order_id
      WHERE ${st === "open" ? "a.status='open'" : "a.status<>'open'"} ORDER BY a.id DESC LIMIT 200`);
    return { items: rows.map((r) => ({
      id: r.id, orderId: r.order_id, reason: r.reason, description: r.description, status: r.status, resolution: r.resolution,
      createdAt: r.created_at, resolvedAt: r.resolved_at, openedBy: userBrief(r.opened_by), buyer: userBrief(r.buyer_id), seller: userBrief(r.seller_id),
      amount: toStr(BigInt(r.amount_units), ASSETS[r.asset].dec), asset: r.asset, fiatAmount: toStr(BigInt(r.fiat_cents), 2), fiat: r.fiat,
      escrowDeadline: r.escrow_deadline, orderStatus: r.order_status,
    })) };
  });
  router.get("/api/admin/orders/:id", A, ({ user, params }) => {
    const o = ctx.orderFor(user, params.id);
    const view = ctx.orderView(o, user);
    view.appeals = db.all("SELECT * FROM appeals WHERE order_id=? ORDER BY id", o.id);
    return view;
  });
  router.post("/api/admin/appeals/:id/resolve", A, async ({ user, params, body, ip }) => {
    const ap = db.get("SELECT * FROM appeals WHERE id=?", v.int(params.id, "id", { min: 1 }));
    if (!ap || ap.status !== "open") throw notFound("Открытая апелляция не найдена");
    const decision = v.oneOf(body.decision, "Решение", ["release", "refund", "reject"]);
    const o = db.get("SELECT * FROM orders WHERE id=?", ap.order_id);
    if (decision === "reject") {
      const n = ctx.transition(o, [OS.APPEAL], ap.prev_status);
      if (!n) throw conflict("bad_status", "Статус ордера изменился");
      db.run("UPDATE appeals SET status='rejected', resolution='rejected', resolved_by=?, resolved_at=? WHERE id=?", user.id, now(), ap.id);
      ctx.sysMsg(o.id, "Поддержка закрыла апелляцию без изменения сделки.", ctx.participants(o));
    } else {
      if (o.status !== OS.APPEAL) throw conflict("bad_status", "Ордер не в статусе апелляции");
      await ctx.submitDecision(o, decision === "release" ? ACTION.release : ACTION.refund);
      db.run("UPDATE appeals SET status='resolved', resolution=?, resolved_by=?, resolved_at=? WHERE id=?", decision, user.id, now(), ap.id);
      ctx.sysMsg(o.id, decision === "release"
        ? "Решение поддержки: средства из эскроу переводятся покупателю. Ожидаем подтверждения в сети TON."
        : "Решение поддержки: средства из эскроу возвращаются продавцу. Ожидаем подтверждения в сети TON.", ctx.participants(o));
      for (const uid of ctx.participants(o)) bot.notify(uid, `Апелляция по ордеру #${o.id} решена: ${decision === "release" ? "средства переводятся покупателю" : "средства возвращаются продавцу"}.`);
    }
    db.audit(user.id, "appeal_resolve", "appeal:" + ap.id, { decision, orderId: o.id }, ip);
    return { ok: true };
  });

  // ---------------------------------------------------------------- reports
  router.get("/api/admin/reports", A, ({ query }) => {
    const f = v.oneOf(query.get("filter") || "active", "filter", ["active", "closed", "all"]);
    const where = f === "active" ? "status IN ('new','progress')" : f === "closed" ? "status IN ('resolved','dismissed')" : "1=1";
    const rows = db.all(`SELECT * FROM reports WHERE ${where} ORDER BY id DESC LIMIT 300`);
    const counts = db.get("SELECT SUM(status IN ('new','progress')) active, SUM(status IN ('resolved','dismissed')) closed, COUNT(*) total FROM reports");
    return { counts: { active: counts.active || 0, closed: counts.closed || 0, all: counts.total || 0 }, items: rows.map((r) => ({
      id: r.id, orderId: r.order_id, reason: r.reason, text: r.text, status: r.status, resolution: r.resolution, createdAt: r.created_at, resolvedAt: r.resolved_at,
      against: userBrief(r.against_id), by: userBrief(r.reporter_id),
    })) };
  });
  router.post("/api/admin/reports/:id/status", A, ({ user, params, body, ip }) => {
    const id = v.int(params.id, "id", { min: 1 });
    const st = v.oneOf(body.status, "status", ["new", "progress", "resolved", "dismissed"]);
    const res = st === "resolved" ? "Жалоба решена" : st === "dismissed" ? "Жалоба отклонена" : null;
    const r = db.run("UPDATE reports SET status=?, resolution=?, resolved_by=?, resolved_at=? WHERE id=?", st, res, res ? user.id : null, res ? now() : null, id);
    if (!r.changes) throw notFound();
    db.audit(user.id, "report_status", "report:" + id, { st }, ip);
    return { ok: true };
  });

  // ---------------------------------------------------------------- bans
  function ban(admin, id, reason, ip) {
    const u = db.get("SELECT * FROM users WHERE id=?", id);
    if (!u) throw notFound("Пользователь не найден (он ещё не открывал приложение)");
    if (u.role === "admin") throw bad("forbidden", "Нельзя заблокировать администратора");
    if (u.banned_at) throw conflict("already", "Пользователь уже заблокирован");
    db.tx(() => {
      db.run("UPDATE users SET banned_at=?, ban_reason=?, banned_by=? WHERE id=?", now(), reason, admin.id, id);
      db.run("UPDATE ads SET status='offline', updated_at=? WHERE user_id=? AND status='online'", now(), id);
      db.run("DELETE FROM sessions WHERE user_id=?", id);
    });
    db.audit(admin.id, "ban", "user:" + id, { reason }, ip);
  }
  router.get("/api/admin/bans", A, () => ({
    items: db.all("SELECT id, nick, ban_reason, banned_at FROM users WHERE banned_at IS NOT NULL ORDER BY banned_at DESC LIMIT 500")
      .map((u) => ({ id: u.id, nick: u.nick, reason: u.ban_reason, ts: u.banned_at })),
  }));
  router.post("/api/admin/bans", A, ({ user, body, ip }) => {
    const id = v.int(body.userId, "Telegram ID", { min: 1 });
    ban(user, id, v.str(body.reason, "Причина", { max: 200 }) || "Нарушение правил", ip);
    return { ok: true };
  });
  router.post("/api/admin/reports/:id/block", A, ({ user, params, ip }) => {
    const r = db.get("SELECT * FROM reports WHERE id=?", v.int(params.id, "id", { min: 1 }));
    if (!r) throw notFound();
    ban(user, r.against_id, "По жалобе: " + r.reason, ip);
    db.run("UPDATE reports SET status='resolved', resolution='Пользователь заблокирован', resolved_by=?, resolved_at=? WHERE id=?", user.id, now(), r.id);
    return { ok: true };
  });
  router.del("/api/admin/bans/:id", A, ({ user, params, ip }) => {
    const id = v.int(params.id, "id", { min: 1 });
    const r = db.run("UPDATE users SET banned_at=NULL, ban_reason=NULL, banned_by=NULL WHERE id=? AND banned_at IS NOT NULL", id);
    if (!r.changes) throw notFound();
    db.audit(user.id, "unban", "user:" + id, null, ip);
    return { ok: true };
  });
  router.get("/api/admin/users", A, ({ query }) => {
    const q = v.str(query.get("q") || "", "q", { min: 1, max: 32 });
    const rows = /^\d+$/.test(q) ? db.all("SELECT * FROM users WHERE id=?", Number(q)) : db.all("SELECT * FROM users WHERE nick_key LIKE ? ESCAPE '\\' LIMIT 20", q.toLowerCase().replace(/[%_\\]/g, (c) => "\\" + c) + "%");
    return { items: rows.map((u) => ({ id: u.id, nick: u.nick, role: u.role, banned: !!u.banned_at, wallet: u.wallet_address, createdAt: u.created_at, stats: ctx.userStats(u.id) })) };
  });

  // ---------------------------------------------------------------- ads moderation
  router.get("/api/admin/ads", A, () => ({
    items: db.all("SELECT a.*, u.nick FROM ads a JOIN users u ON u.id=a.user_id WHERE a.status='online' ORDER BY a.id DESC LIMIT 300").map((a) => ({
      id: a.id, nick: a.nick, userId: a.user_id, side: a.side, asset: a.asset, fiat: a.fiat, priceType: a.price_type,
      price: a.price_e6 ? toStr(BigInt(a.price_e6), 6) : null, floatPct: a.float_e2 ? toStr(BigInt(a.float_e2), 2) : null, payTypes: JSON.parse(a.pay_types),
    })),
  }));
  router.post("/api/admin/ads/:id/remove", A, ({ user, params, body, ip }) => {
    const id = v.int(params.id, "id", { min: 1 });
    const r = db.run("UPDATE ads SET status='removed', removed_reason=?, updated_at=? WHERE id=? AND status IN ('online','offline')", v.str(body.reason, "Причина", { max: 200 }) || "Нарушение правил площадки", now(), id);
    if (!r.changes) throw notFound();
    db.audit(user.id, "ad_remove", "ad:" + id, null, ip);
    return { ok: true };
  });

  // ---------------------------------------------------------------- broadcast
  router.post("/api/admin/broadcast", { auth: "admin", limit: { key: "bcast", n: 5, ms: 3_600_000 } }, ({ user, body, ip }) => {
    const text = v.str(body.text, "Текст", { min: 3, max: 2000, multiline: true });
    const ids = db.all("SELECT id FROM users WHERE allows_pm=1 AND banned_at IS NULL").map((r) => r.id);
    const r = db.run("INSERT INTO broadcasts(admin_id,text,total,status,created_at) VALUES(?,?,?,?,?)", user.id, text, ids.length, "sending", now());
    const bid = Number(r.lastInsertRowid);
    for (const id of ids) bot.notify(id, text, "", (ok) => db.run(`UPDATE broadcasts SET ${ok ? "sent=sent+1" : "failed=failed+1"} WHERE id=?`, bid));
    db.audit(user.id, "broadcast", "broadcast:" + bid, { recipients: ids.length }, ip);
    return { id: bid, recipients: ids.length };
  });
  router.get("/api/admin/broadcasts", A, () => ({ items: db.all("SELECT id, text, total, sent, failed, created_at FROM broadcasts ORDER BY id DESC LIMIT 20") }));
}
