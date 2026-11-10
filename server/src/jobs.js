// Background work: on-chain escrow watcher, Bybit-style timeouts, automatic
// refunds, paid-pin verification and housekeeping. Every external call is
// throttled by the RPC client; each tick processes a bounded batch.
import { Address, Cell } from "@ton/core";
import { STATUS, ACTION } from "./escrow.js";
import { isFunded } from "./ton.js";
import { OS } from "./p2p.js";
import { now, toStr, ASSETS } from "./util.js";

export function startJobs(ctx) {
  const { cfg, db, chain, log } = ctx;
  let busy = false;

  async function checkOrder(o) {
    db.run("UPDATE orders SET chain_checked_at=? WHERE id=?", now(), o.id);
    const st = await chain.escrowState(o);
    const parts = ctx.participants(o);
    if (st.deployed && st.status === STATUS.released && o.status !== OS.COMPLETED) {
      // released on-chain (also covers the rare race "cancelled by timeout while the seller released")
      if (o.status === OS.CANCELLED) db.run("UPDATE ads SET remaining_units=MAX(0, remaining_units-?) WHERE id=?", o.amount_units, o.ad_id);
      const n = ctx.transition(o, [o.status], OS.COMPLETED, { completed_at: now(), decision: null, refund_needed: 0 });
      if (n) {
        ctx.sysMsg(o.id, `Сделка завершена: ${toStr(BigInt(o.amount_units) - BigInt(o.buyer_fee), ASSETS[o.asset].dec)} ${o.asset} переведены покупателю из эскроу. Оставьте отзыв о контрагенте.`, parts);
        for (const uid of parts) ctx.bot.notify(uid, `Ордер #${o.id} завершён.`);
        db.run("UPDATE appeals SET status='resolved', resolution=COALESCE(resolution,'release'), resolved_at=COALESCE(resolved_at,?) WHERE order_id=? AND status='open'", now(), o.id);
      }
      return;
    }
    if (st.deployed && st.status === STATUS.refunded) {
      if (o.status === OS.CANCELLED) { db.run("UPDATE orders SET refund_needed=0, decision=NULL WHERE id=?", o.id); return; }
      const n = ctx.cancelOrder(o, { by: null, reason: o.decision === "refund" ? "решение поддержки — средства возвращены продавцу" : "средства возвращены продавцу из эскроу", fault: null });
      if (n) db.run("UPDATE orders SET refund_needed=0, decision=NULL WHERE id=?", o.id);
      db.run("UPDATE appeals SET status='resolved', resolution=COALESCE(resolution,'refund'), resolved_at=COALESCE(resolved_at,?) WHERE order_id=? AND status='open'", now(), o.id);
      return;
    }
    if (o.status === OS.AWAIT_ESCROW && isFunded(o, st)) {
      const n = ctx.transition(o, [OS.AWAIT_ESCROW], OS.AWAIT_PAY, { funded_at: now(), pay_deadline: now() + o.pay_window * 60_000 });
      if (n) {
        ctx.sysMsg(o.id, `Средства продавца заблокированы в смарт‑контракте эскроу. Покупатель, переведите ${toStr(BigInt(o.fiat_cents), 2)} ${o.fiat} по реквизитам в ордере в течение ${o.pay_window} мин. и нажмите «Я оплатил(а)».`, parts);
        ctx.bot.notify(o.buyer_id, `Ордер #${o.id}: средства продавца заблокированы. Оплатите в течение ${o.pay_window} мин.`, cfg.tgAppLink ? `${cfg.tgAppLink}?startapp=order_${o.id}` : "");
      }
      return;
    }
    // pending arbiter decision expired without effect -> sign & send again
    if (o.decision && o.decision_valid_until && o.decision_valid_until * 1000 < now() && st.deployed && st.status === STATUS.open) {
      await ctx.submitDecision(o, o.decision === "release" ? ACTION.release : ACTION.refund);
      return;
    }
    // cancelled order whose escrow still holds funds -> refund automatically
    if (o.status === OS.CANCELLED && o.refund_needed) {
      if (st.deployed && st.status === STATUS.open && !o.decision) await ctx.submitDecision(o, ACTION.refund);
      else if (!st.deployed && now() - o.cancelled_at > 2 * 86_400_000) db.run("UPDATE orders SET refund_needed=0 WHERE id=?", o.id);
    }
  }

  function timeouts() {
    const t = now();
    for (const o of db.all("SELECT * FROM orders WHERE status=? AND lock_deadline<? LIMIT 50", OS.AWAIT_ESCROW, t)) {
      // grace after the deadline: 60s for a last chain check, 5 min if the seller already sent the lock tx
      const grace = o.lock_sent_at && o.lock_sent_at <= o.lock_deadline + 60_000 ? 5 * 60_000 : 60_000;
      if (t - o.lock_deadline < grace) continue;
      ctx.cancelOrder(o, { by: null, reason: "продавец не заблокировал средства вовремя", fault: o.seller_id });
    }
    for (const o of db.all("SELECT * FROM orders WHERE status=? AND pay_deadline<? LIMIT 50", OS.AWAIT_PAY, t))
      ctx.cancelOrder(o, { by: null, reason: "время на оплату истекло", fault: o.buyer_id });
    for (const o of db.all("SELECT * FROM orders WHERE status=? AND paid_at<? AND release_sent_at IS NULL LIMIT 20", OS.PAID, t - cfg.autoAppealHours * 3_600_000)) {
      const n = ctx.transition(o, [OS.PAID], OS.APPEAL);
      if (n) {
        db.run("INSERT INTO appeals(order_id,opened_by,reason,description,status,prev_status,created_at) VALUES(?,?,?,?,?,?,?)", o.id, 0, "Другое", `Автоматическая апелляция: продавец не отпустил средства в течение ${cfg.autoAppealHours} ч после оплаты.`, "open", OS.PAID, t);
        ctx.sysMsg(o.id, "Открыта автоматическая апелляция: сделка подтверждена оплатой, но не завершена. Поддержка разберётся.", ctx.participants(o));
      }
    }
  }

  async function watch() {
    const t = now();
    const due = db.all(`SELECT * FROM orders WHERE
        (status=5 AND chain_checked_at<?) OR
        (status IN (10,20,30) AND (release_sent_at IS NOT NULL OR decision IS NOT NULL) AND chain_checked_at<?) OR
        (status IN (10,20,30) AND chain_checked_at<?) OR
        (status=40 AND refund_needed=1 AND chain_checked_at < CASE WHEN cancelled_at>? THEN ? ELSE ? END)
      ORDER BY chain_checked_at LIMIT 12`, t - 8_000, t - 6_000, t - 45_000, t - 600_000, t - 20_000, t - 300_000);
    for (const o of due) {
      try { await checkOrder(o); } catch (e) { log.warn("escrow check failed", { order: o.id, err: String(e.message || e).slice(0, 200) }); }
    }
  }

  // paid pins: look for incoming payments to the fee wallet with the invoice comment
  async function pins() {
    const pending = db.all("SELECT * FROM pin_invoices WHERE status='pending' AND expires_at>?", now() - 10 * 60_000);
    db.run("UPDATE pin_invoices SET status='expired' WHERE status='pending' AND expires_at<?", now() - 10 * 60_000);
    if (!pending.length) return;
    const fee = Address.parse(cfg.feeWallet);
    const txs = await chain.getTransactions(fee, 40);
    let usdtJw = null;
    if (pending.some((p) => p.asset === "USDT")) usdtJw = await chain.jettonWalletOf(fee);
    for (const tx of txs) {
      const m = tx.in_msg; if (!m || !m.source) continue;
      const hash = tx.transaction_id?.hash; if (!hash) continue;
      let comment = null, asset = null, amount = 0n;
      if (m.message) { comment = String(m.message).trim(); asset = "GRAM"; amount = BigInt(m.value || 0); }
      if (usdtJw && m.msg_data?.body) {
        try {
          const s = Cell.fromBoc(Buffer.from(m.msg_data.body, "base64"))[0].beginParse();
          if (s.remainingBits >= 32 && s.loadUint(32) === 0x7362d09c && Address.parse(m.source).equals(usdtJw)) {
            s.loadUintBig(64); amount = s.loadCoins(); s.loadAddress();
            const fp = s.loadBit() ? s.loadRef().beginParse() : s;
            if (fp.remainingBits >= 32 && fp.loadUint(32) === 0) { comment = fp.loadStringTail().trim(); asset = "USDT"; }
          }
        } catch {}
      }
      if (!comment || !comment.startsWith("PMR-PIN-")) continue;
      const inv = pending.find((p) => p.comment === comment && p.asset === asset);
      if (!inv || amount < BigInt(inv.amount_units)) continue;
      try {
        db.tx(() => {
          const r = db.run("UPDATE pin_invoices SET status='paid', tx_hash=?, paid_at=? WHERE id=? AND status='pending'", hash, now(), inv.id);
          if (r.changes) db.run("UPDATE ads SET pinned_until=MAX(pinned_until, ?) + ?, updated_at=? WHERE id=?", now(), inv.hours * 3_600_000, now(), inv.ad_id);
        });
        ctx.bot.notify(inv.user_id, `Оплата закрепления получена: объявление закреплено на ${inv.hours} ч.`);
      } catch (e) { log.warn("pin apply", { err: String(e) }); }
    }
  }

  function cleanup() {
    const t = now();
    db.run("DELETE FROM sessions WHERE expires_at<?", t);
    db.run("DELETE FROM wallet_challenges WHERE created_at<?", t - 3_600_000);
    db.run("DELETE FROM activity WHERE hour<?", Math.floor((t - 800 * 86_400_000) / 3_600_000));
    ctx.nonces.sweep();
    ctx.limiter.sweep();
  }

  const tick = async () => {
    if (busy) return;
    busy = true;
    try { timeouts(); await watch(); } catch (e) { log.error("jobs tick", { err: String(e.stack || e) }); } finally { busy = false; }
  };
  const timers = [setInterval(tick, 4_000), setInterval(() => pins().catch((e) => log.warn("pins", { err: String(e.message || e) })), 20_000), setInterval(cleanup, 600_000)];
  timers.forEach((x) => x.unref());
  return { stop: () => timers.forEach(clearInterval), tick, checkOrder, pins };
}
