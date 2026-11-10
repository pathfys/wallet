// Bybit-style P2P: ads -> orders -> on-chain escrow -> payment -> release,
// with timeouts, cancellations limits, appeals, feedback and merchant stats.
//
// Order statuses use Bybit's P2P API codes:
//   5  waiting for chain (seller locks funds in the escrow contract)
//   10 waiting for buyer to pay          20 waiting for seller to release
//   30 appealing                         40 cancelled          50 completed
import { Address } from "@ton/core";
import { HttpError, bad, forbidden, notFound, conflict, tooMany, v, randomId, randomU64, now, nowSec,
  ASSETS, FIATS, PAY_TYPES, PAY_WINDOWS, PINS, fiatCents, unitsForCents, sideFee, toStr, floorTo } from "./util.js";
import { escrowAddress, setupHash, edSignHash, buildDecisionExternal, ACTION, STATUS, KIND, ESCROW_TON, ESCROW_CODE_HASH } from "./escrow.js";
import { isFunded } from "./ton.js";

export const OS = { AWAIT_ESCROW: 5, AWAIT_PAY: 10, PAID: 20, APPEAL: 30, CANCELLED: 40, COMPLETED: 50 };
export const ACTIVE = [OS.AWAIT_ESCROW, OS.AWAIT_PAY, OS.PAID, OS.APPEAL];
const DAY = 86_400_000;
const MAX_ACTIVE_ADS = 10, MAX_TAKER_ORDERS = 5, CANCEL_LIMIT = 3, CHAT_AFTER_CLOSE = 2 * DAY;
const APPEAL_REASONS = ["Оплатил, продавец не отпускает", "Оплата не поступила", "Неверная сумма оплаты", "Мошенничество", "Другое"];
const REPORT_REASONS = ["Мошенничество", "Оскорбления", "Спам", "Поддельный чек", "Неверный курс", "Прочее"];
const placeholders = (n) => Array(n).fill("?").join(",");

export function registerP2P(router, ctx) {
  const { cfg, db, chain, prices, hub, bot, limiter, enc, dec, log } = ctx;

  // ------------------------------------------------------------------ helpers
  const statsCache = new Map();
  function userStats(uid) {
    const c = statsCache.get(uid);
    if (c && c.at > now() - 60_000) return c.v;
    const since = now() - 30 * DAY;
    const done30 = db.get("SELECT COUNT(*) n FROM orders WHERE status=50 AND completed_at>=? AND (buyer_id=? OR seller_id=?)", since, uid, uid).n;
    const fault30 = db.get("SELECT COUNT(*) n FROM orders WHERE status=40 AND cancelled_at>=? AND fault_user=?", since, uid).n;
    const total = db.get("SELECT COUNT(*) n FROM orders WHERE status=50 AND (buyer_id=? OR seller_id=?)", uid, uid).n;
    const rel = db.get("SELECT AVG(completed_at-paid_at) a FROM orders WHERE status=50 AND seller_id=? AND paid_at IS NOT NULL AND completed_at>=?", uid, since).a;
    const pay = db.get("SELECT AVG(paid_at-funded_at) a FROM orders WHERE buyer_id=? AND paid_at IS NOT NULL AND funded_at IS NOT NULL AND paid_at>=?", uid, since).a;
    const fb = db.get("SELECT COUNT(*) n, COALESCE(SUM(positive),0) p FROM feedback WHERE to_id=?", uid);
    const u = db.get("SELECT created_at FROM users WHERE id=?", uid);
    const val = {
      orders30d: done30, completion30d: done30 + fault30 ? Math.round((done30 / (done30 + fault30)) * 1000) / 10 : null,
      totalOrders: total, avgReleaseMin: rel ? Math.max(1, Math.round(rel / 60_000)) : null, avgPayMin: pay ? Math.max(1, Math.round(pay / 60_000)) : null,
      feedbackTotal: fb.n, feedbackPositive: fb.p, positiveRate: fb.n ? Math.round((fb.p / fb.n) * 1000) / 10 : null,
      registeredAt: u ? u.created_at : null,
    };
    if (statsCache.size > 20_000) statsCache.clear();
    statsCache.set(uid, { at: now(), v: val });
    return val;
  }
  const dropStats = (...ids) => ids.forEach((i) => statsCache.delete(i));
  const pubUser = (uid) => { const u = db.get("SELECT nick, banned_at FROM users WHERE id=?", uid); return { nick: u?.nick || "—", banned: !!u?.banned_at, stats: userStats(uid) }; };

  function requireTrader(user) {
    if (!user.nick) throw new HttpError(403, "need_nick", "Сначала задайте ник");
    if (!user.wallet_address) throw new HttpError(403, "need_wallet", "Подтвердите адрес кошелька");
  }
  const friendly = (raw) => Address.parse(raw).toString({ bounceable: false, testOnly: cfg.network === "testnet" });

  // ---- реальный баланс продавца в блокчейне ----
  // Продавец должен держать на кошельке сумму сделки + свою комиссию, а для USDT ещё и GRAM на газ эскроу.
  const NET_GAS = 20_000_000n; // запас на комиссию сети за саму транзакцию
  const pctTxt = () => (cfg.p2pFeeSideBps / 100).toString().replace(".", ",");
  async function sellerFunding(rawAddress, asset, lockUnits) {
    let bal;
    try { bal = await chain.walletBalances(Address.parse(rawAddress)); }
    catch { throw new HttpError(503, "balance_unavailable", "Не удалось проверить баланс в блокчейне. Повторите через минуту"); }
    if (asset === "USDT") {
      const gas = ESCROW_TON.jettonDealDeploy + ESCROW_TON.jettonTransferValue + NET_GAS;
      return { coinsOk: bal.usdt >= lockUnits, gasOk: bal.ton >= gas, have: bal.usdt, need: lockUnits, haveGas: bal.ton, needGas: gas };
    }
    const need = lockUnits + ESCROW_TON.tonDealReserve + NET_GAS;
    return { coinsOk: bal.ton >= need, gasOk: true, have: bal.ton, need };
  }
  function ownFundingError(asset, f) {
    const d = ASSETS[asset].dec;
    if (!f.coinsOk) return bad("insufficient_balance", `Недостаточно ${asset} на кошельке: есть ${toStr(f.have, d)}, нужно ${toStr(f.need, d)} (сумма + комиссия ${pctTxt()}%${asset === "GRAM" ? " + газ эскроу" : ""}). Уменьшите количество или пополните кошелёк.`);
    return bad("insufficient_gas", `Для сделок в USDT нужно ≈${toStr(f.needGas, 9)} GRAM на газ эскроу (неиспользованное вернётся). Сейчас на кошельке ${toStr(f.haveGas, 9)} GRAM.`);
  }
  const lockFor = async (units, asset) => BigInt(units) + sideFee(units, asset, await prices.usdE6(asset), cfg.p2pFeeSideBps, cfg.p2pFeeMaxSideUsdE6);

  async function adPriceE6(ad) {
    if (ad.price_type === "fixed") return BigInt(ad.price_e6);
    const idx = await prices.index(ad.asset, ad.fiat);
    if (!idx) return 0n;
    return floorTo((idx * BigInt(ad.float_e2)) / 10_000n, 10_000n); // 2 decimals
  }
  function adView(ad, priceE6, viewerId) {
    const a = ASSETS[ad.asset];
    const fiatOfRemaining = priceE6 ? fiatCents(ad.remaining_units, a.dec, priceE6) : 0n;
    const maxEff = BigInt(ad.max_cents) < fiatOfRemaining ? BigInt(ad.max_cents) : fiatOfRemaining;
    return {
      id: ad.id, side: ad.side, asset: ad.asset, fiat: ad.fiat, priceType: ad.price_type,
      price: priceE6 ? toStr(priceE6, 6) : null, floatPct: ad.float_e2 ? toStr(BigInt(ad.float_e2), 2) : null,
      fixedPrice: ad.price_e6 ? toStr(BigInt(ad.price_e6), 6) : null,
      total: toStr(BigInt(ad.total_units), a.dec), available: toStr(BigInt(ad.remaining_units), a.dec),
      min: toStr(BigInt(ad.min_cents), 2), max: toStr(BigInt(ad.max_cents), 2), maxEffective: toStr(maxEff, 2),
      payWindow: ad.pay_window, payTypes: JSON.parse(ad.pay_types), remarks: ad.remarks,
      condMinOrders: ad.cond_min_orders, condRegDays: ad.cond_reg_days, status: ad.status,
      pinned: ad.pinned_until > now(), pinnedUntil: ad.pinned_until || null, mine: ad.user_id === viewerId,
      maker: pubUser(ad.user_id), createdAt: ad.created_at,
      ...(ad.user_id === viewerId ? { pmIds: JSON.parse(ad.pm_ids), removedReason: ad.removed_reason || null } : {}),
    };
  }

  function sysMsg(orderId, text, notifyIds = []) {
    const r = db.run("INSERT INTO messages(order_id,sender_id,kind,body,created_at) VALUES(?,?,?,?,?)", orderId, 0, "system", text, now());
    const m = { id: Number(r.lastInsertRowid), orderId, kind: "system", body: text, from: "system", createdAt: now() };
    if (notifyIds.length) hub.toUsers(notifyIds, { t: "msg", orderId, message: m });
    return m;
  }
  const participants = (o) => [o.buyer_id, o.seller_id];
  function pushOrder(o) { hub.toUsers(participants(o), { t: "order", orderId: o.id, status: o.status }); }
  function orderOf(id) { const o = db.get("SELECT * FROM orders WHERE id=?", id); if (!o) throw notFound("Ордер не найден"); return o; }
  function orderFor(user, id) {
    const o = orderOf(v.int(id, "id", { min: 1 }));
    if (o.buyer_id !== user.id && o.seller_id !== user.id && user.role !== "admin") throw notFound("Ордер не найден");
    return o;
  }
  const appLink = (o) => (cfg.tgAppLink ? `${cfg.tgAppLink}?startapp=order_${o.id}` : "");
  const tell = (uid, text, o) => bot.notify(uid, text, o ? appLink(o) : "");

  // optimistic state transition: only applies if the order is still in one of `from`
  function transition(o, from, to, patch = {}) {
    const cols = Object.keys(patch);
    const sets = ["status=?", "updated_at=?", ...cols.map((c) => `${c}=?`)].join(",");
    const r = db.run(`UPDATE orders SET ${sets} WHERE id=? AND status IN (${placeholders(from.length)})`, to, now(), ...cols.map((c) => patch[c]), o.id, ...from);
    if (r.changes !== 1) return null;
    if (to === OS.CANCELLED) db.run("UPDATE ads SET remaining_units=remaining_units+?, updated_at=? WHERE id=?", o.amount_units, now(), o.ad_id);
    if (to === OS.CANCELLED || to === OS.COMPLETED) dropStats(o.buyer_id, o.seller_id);
    const n = db.get("SELECT * FROM orders WHERE id=?", o.id);
    pushOrder(n);
    return n;
  }
  ctx.transition = transition;
  ctx.sysMsg = sysMsg;

  // arbiter decision -> signed external message sent to the escrow contract
  async function submitDecision(o, action) {
    const st = await chain.escrowState(o);
    if (!st.deployed || st.status !== STATUS.open) return st;
    // refund exactly what the escrow's jetton wallet holds (0 jettons -> only TON is returned)
    const amount = action === ACTION.refund && o.asset === "USDT" ? st.jettonBalance : 0n;
    const validUntil = nowSec() + 300;
    const { boc } = buildDecisionExternal(cfg.arbiter.priv, o.escrow_address, { seqno: st.seqno, validUntil, action, amount });
    await chain.sendBoc(boc);
    db.run("UPDATE orders SET decision=?, decision_valid_until=?, chain_checked_at=0, updated_at=? WHERE id=?", action === ACTION.release ? "release" : "refund", validUntil, now(), o.id);
    db.audit(null, "arbiter_decision", "order:" + o.id, { action, seqno: st.seqno, validUntil });
    return st;
  }
  ctx.submitDecision = submitDecision;

  function cancelOrder(o, { by, reason, fault }) {
    const funded = o.status !== OS.AWAIT_ESCROW;
    const n = transition(o, [o.status], OS.CANCELLED, { cancelled_at: now(), cancel_reason: reason, cancelled_by: by ?? null, fault_user: fault ?? null, refund_needed: 1 });
    if (!n) return null;
    sysMsg(o.id, `Ордер отменён: ${reason}.${funded ? " Средства продавца возвращаются из эскроу автоматически." : ""}`, participants(o));
    for (const uid of participants(o)) if (uid !== by) tell(uid, `Ордер #${o.id} отменён: ${reason}.`, o);
    return n;
  }
  ctx.cancelOrder = cancelOrder;

  function orderView(o, user) {
    const a = ASSETS[o.asset];
    const role = o.buyer_id === user.id ? "buyer" : o.seller_id === user.id ? "seller" : "admin";
    const cp = role === "buyer" ? o.seller_id : o.buyer_id;
    const showPay = (role === "buyer" && [OS.AWAIT_PAY, OS.PAID, OS.APPEAL].includes(o.status)) || role === "seller" || role === "admin";
    let pay = null;
    if (showPay) { try { pay = dec(o.pay_details_enc, "order:" + o.id); } catch { pay = null; } }
    const appeal = db.get("SELECT id, opened_by, reason, description, status, resolution, created_at FROM appeals WHERE order_id=? ORDER BY id DESC LIMIT 1", o.id);
    const myFb = db.get("SELECT positive, comment FROM feedback WHERE order_id=? AND from_id=?", o.id, user.id);
    const buyerAmount = BigInt(o.amount_units) - BigInt(o.buyer_fee), feeAmount = BigInt(o.buyer_fee) + BigInt(o.seller_fee);
    return {
      id: o.id, status: o.status, role, asset: o.asset, fiat: o.fiat, side: role === "buyer" ? "buy" : "sell",
      price: toStr(BigInt(o.price_e6), 6), amount: toStr(BigInt(o.amount_units), a.dec), fiatAmount: toStr(BigInt(o.fiat_cents), 2),
      buyerFee: toStr(BigInt(o.buyer_fee), a.dec), sellerFee: toStr(BigInt(o.seller_fee), a.dec),
      buyerReceives: toStr(buyerAmount, a.dec), sellerLocks: toStr(BigInt(o.amount_units) + BigInt(o.seller_fee), a.dec),
      payType: o.pay_type, payWindow: o.pay_window, payDetails: pay, remarks: o.remarks,
      counterparty: role === "admin" ? null : pubUser(cp),
      ...(role === "admin" ? { buyer: { id: o.buyer_id, ...pubUser(o.buyer_id) }, seller: { id: o.seller_id, ...pubUser(o.seller_id) } } : {}),
      maker: o.maker_id === user.id, adId: o.ad_id,
      escrow: {
        address: friendlyAddrBounce(o.escrow_address), kind: a.kind, dealId: o.deal_id, deadline: o.escrow_deadline,
        buyerAmountUnits: buyerAmount.toString(), feeAmountUnits: feeAmount.toString(), arbiterKey: cfg.arbiter.publicKeyHex,
        feeWallet: cfg.feeWallet, sellerAddress: friendly(o.seller_address), buyerAddress: friendly(o.buyer_address),
        jettonWallet: o.jetton_wallet ? friendlyAddrBounce(o.jetton_wallet) : null, codeHash: ESCROW_CODE_HASH,
      },
      lockDeadline: o.lock_deadline, payDeadline: o.pay_deadline, fundedAt: o.funded_at, paidAt: o.paid_at,
      completedAt: o.completed_at, cancelledAt: o.cancelled_at, cancelReason: o.cancel_reason,
      appealAvailableAt: o.paid_at ? o.paid_at + cfg.appealAfterMin * 60_000 : null,
      lockSentAt: o.lock_sent_at, releaseSentAt: o.release_sent_at, decision: o.decision,
      appeal: appeal ? { ...appeal, mine: appeal.opened_by === user.id, opened_by: undefined } : null,
      feedback: myFb ? { positive: !!myFb.positive, comment: myFb.comment } : null,
      createdAt: o.created_at,
    };
  }
  const friendlyAddrBounce = (raw) => Address.parse(raw).toString({ bounceable: true, testOnly: cfg.network === "testnet" });
  ctx.orderView = orderView;

  // ------------------------------------------------------------- payment methods
  router.get("/api/payment-methods", {}, ({ user }) => ({
    items: db.all("SELECT id,type,details_enc,created_at FROM payment_methods WHERE user_id=? AND deleted=0 ORDER BY id", user.id)
      .map((p) => ({ id: p.id, type: p.type, ...dec(p.details_enc, "pm:" + user.id), createdAt: p.created_at })),
  }));
  router.post("/api/payment-methods", { limit: { key: "pm", n: 20, ms: 3_600_000 } }, ({ user, body }) => {
    const type = v.oneOf(body.type, "Способ оплаты", PAY_TYPES);
    const cash = type === "Наличные";
    const details = {
      holder: v.str(body.holder, "Получатель", { min: 2, max: 64 }),
      account: v.str(body.account, cash ? "Место встречи" : "Номер счёта/карты/телефона", { min: 3, max: 64 }),
      bank: v.str(body.bank, "Банк", { max: 64 }),
      comment: v.str(body.comment, "Комментарий", { max: 200, multiline: true }),
    };
    if (db.get("SELECT COUNT(*) n FROM payment_methods WHERE user_id=? AND deleted=0", user.id).n >= 10) throw bad("limit", "Максимум 10 способов оплаты");
    const r = db.run("INSERT INTO payment_methods(user_id,type,details_enc,created_at) VALUES(?,?,?,?)", user.id, type, enc(details, "pm:" + user.id), now());
    return { id: Number(r.lastInsertRowid), type, ...details };
  });
  router.del("/api/payment-methods/:id", {}, ({ user, params }) => {
    const id = v.int(params.id, "id", { min: 1 });
    const r = db.run("UPDATE payment_methods SET deleted=1 WHERE id=? AND user_id=? AND deleted=0", id, user.id);
    if (!r.changes) throw notFound();
    for (const ad of db.all("SELECT id, pm_ids FROM ads WHERE user_id=? AND status IN ('online','offline')", user.id)) {
      const ids = JSON.parse(ad.pm_ids).filter((x) => x !== id);
      db.run("UPDATE ads SET pm_ids=?, status=CASE WHEN ?=0 AND side='sell' THEN 'offline' ELSE status END, updated_at=? WHERE id=?", JSON.stringify(ids), ids.length, now(), ad.id);
    }
    return { ok: true };
  });

  // ------------------------------------------------------------------- ads
  async function parseAd(body, user, existing) {
    const side = existing ? existing.side : v.oneOf(body.side, "Тип", ["buy", "sell"]);
    const asset = existing ? existing.asset : v.oneOf(body.asset, "Актив", Object.keys(ASSETS));
    const fiat = existing ? existing.fiat : v.oneOf(body.fiat, "Валюта", FIATS);
    const a = ASSETS[asset];
    const priceType = v.oneOf(body.priceType, "Тип цены", ["fixed", "floating"]);
    let priceE6 = null, floatE2 = null;
    if (priceType === "fixed") priceE6 = v.dec(body.price, "Цена", 6, { min: 1, max: 1_000_000_000_000_000n });
    else {
      floatE2 = v.dec(body.floatPct, "Процент от рыночной цены", 2, { min: 8000, max: 12000 });
      if (!(await prices.index(asset, fiat))) throw bad("no_index", "Для этой валюты нет рыночного курса — используйте фиксированную цену");
    }
    const total = floorTo(v.dec(body.total, "Количество", a.dec, { min: a.step, max: a.maxUnits }), a.step);
    const min = v.dec(body.min, "Мин. лимит", 2, { min: 100, max: 100_000_000_000n });
    const max = v.dec(body.max, "Макс. лимит", 2, { min: 100, max: 100_000_000_000n });
    if (max < min) throw bad("bad_limits", "Макс. лимит меньше минимального");
    const payWindow = v.int(body.payWindow, "Время на оплату", { min: 15, max: 60 });
    if (!PAY_WINDOWS.includes(payWindow)) throw bad("bad_input", "Время на оплату: 15, 30 или 60 минут");
    let pmIds = [], payTypes = [];
    if (side === "sell") {
      pmIds = [...new Set(v.arr(body.pmIds, "Способы оплаты", { max: 5 }).map((x) => v.int(x, "pmId", { min: 1 })))];
      if (!pmIds.length) throw bad("need_pm", "Добавьте хотя бы один способ оплаты");
      const rows = db.all(`SELECT id,type FROM payment_methods WHERE user_id=? AND deleted=0 AND id IN (${placeholders(pmIds.length)})`, user.id, ...pmIds);
      if (rows.length !== pmIds.length) throw bad("bad_pm", "Способ оплаты не найден");
      payTypes = [...new Set(rows.map((r) => r.type))];
    } else {
      payTypes = [...new Set(v.arr(body.payTypes, "Способы оплаты", { max: 6 }).map((x) => v.oneOf(x, "Способ оплаты", PAY_TYPES)))];
      if (!payTypes.length) throw bad("need_pm", "Выберите хотя бы один способ оплаты");
    }
    return {
      side, asset, fiat, priceType, priceE6, floatE2, total, min, max, payWindow, pmIds, payTypes,
      remarks: v.str(body.remarks, "Условия", { max: 500, multiline: true }),
      condMinOrders: v.int(body.condMinOrders ?? 0, "Мин. число сделок", { min: 0, max: 10_000 }),
      condRegDays: v.int(body.condRegDays ?? 0, "Мин. дней с регистрации", { min: 0, max: 3650 }),
    };
  }

  router.get("/api/ads", {}, async ({ user, query }) => {
    const side = v.oneOf(query.get("side") || "sell", "side", ["buy", "sell"]);
    const asset = query.get("asset") ? v.oneOf(query.get("asset"), "asset", Object.keys(ASSETS)) : null;
    const fiat = query.get("fiat") ? v.oneOf(query.get("fiat"), "fiat", FIATS) : null;
    const pay = query.get("pay") ? v.oneOf(query.get("pay"), "pay", PAY_TYPES) : null;
    const amount = query.get("amount") ? v.dec(query.get("amount"), "amount", 2) : null;
    const rows = db.all(`SELECT ads.* FROM ads JOIN users u ON u.id=ads.user_id
      WHERE ads.status='online' AND ads.side=? AND (? IS NULL OR ads.asset=?) AND (? IS NULL OR ads.fiat=?) AND u.banned_at IS NULL
      ORDER BY ads.id DESC LIMIT 500`, side, asset, asset, fiat, fiat);
    const out = [];
    for (const ad of rows) {
      if (pay && !JSON.parse(ad.pay_types).includes(pay)) continue;
      const p = await adPriceE6(ad);
      if (!p) continue;
      const view = adView(ad, p, user.id);
      const maxC = v.dec(view.maxEffective, "x", 2), minC = BigInt(ad.min_cents);
      if (maxC < minC) continue;
      if (amount !== null && (amount < minC || amount > maxC)) continue;
      view._p = p;
      out.push(view);
    }
    const t = now();
    out.sort((x, y) => (y.pinned - x.pinned) || (side === "sell" ? (x._p < y._p ? -1 : x._p > y._p ? 1 : 0) : (x._p > y._p ? -1 : x._p < y._p ? 1 : 0)) || (y.createdAt - x.createdAt));
    return { items: out.slice(0, 100).map(({ _p, ...r }) => r), serverTime: t };
  });
  router.get("/api/index-price", {}, async ({ query }) => {
    const asset = v.oneOf(query.get("asset"), "asset", Object.keys(ASSETS));
    const fiat = v.oneOf(query.get("fiat"), "fiat", FIATS);
    const p = await prices.index(asset, fiat);
    return { price: p ? toStr(p, 6) : null };
  });
  router.get("/api/ads/mine", {}, async ({ user }) => {
    const rows = db.all("SELECT * FROM ads WHERE user_id=? AND status IN ('online','offline','removed') ORDER BY id DESC", user.id);
    const items = [];
    for (const ad of rows) items.push(adView(ad, await adPriceE6(ad), user.id));
    return { items };
  });
  router.post("/api/ads", { limit: { key: "adnew", n: 30, ms: DAY } }, async ({ user, body }) => {
    requireTrader(user);
    const p = await parseAd(body, user);
    const idem = body.idem ? v.str(body.idem, "idem", { min: 8, max: 64, re: /^[A-Za-z0-9_-]+$/ }) : null;
    if (idem) { const ex = db.get("SELECT * FROM ads WHERE idem=? AND user_id=?", idem, user.id); if (ex) return adView(ex, await adPriceE6(ex), user.id); }
    if (db.get("SELECT COUNT(*) n FROM ads WHERE user_id=? AND status IN ('online','offline')", user.id).n >= MAX_ACTIVE_ADS) throw bad("limit", `Максимум ${MAX_ACTIVE_ADS} объявлений`);
    if (p.side === "sell") {   // продать можно только то, что реально лежит на кошельке
      const f = await sellerFunding(user.wallet_address, p.asset, await lockFor(p.total, p.asset));
      if (!f.coinsOk || !f.gasOk) throw ownFundingError(p.asset, f);
    }
    const t = now();
    const r = db.run(`INSERT INTO ads(user_id,side,asset,fiat,price_type,price_e6,float_e2,total_units,remaining_units,min_cents,max_cents,pay_window,pay_types,pm_ids,remarks,cond_min_orders,cond_reg_days,status,idem,created_at,updated_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'online',?,?,?)`, user.id, p.side, p.asset, p.fiat, p.priceType, p.priceE6, p.floatE2,
      p.total, p.total, p.min, p.max, p.payWindow, JSON.stringify(p.payTypes), JSON.stringify(p.pmIds), p.remarks, p.condMinOrders, p.condRegDays, idem, t, t);
    const ad = db.get("SELECT * FROM ads WHERE id=?", Number(r.lastInsertRowid));
    return adView(ad, await adPriceE6(ad), user.id);
  });
  function myAd(user, id) {
    const ad = db.get("SELECT * FROM ads WHERE id=? AND user_id=?", v.int(id, "id", { min: 1 }), user.id);
    if (!ad || ad.status === "deleted") throw notFound("Объявление не найдено");
    return ad;
  }
  router.post("/api/ads/:id", {}, async ({ user, body, params }) => {
    const ad = myAd(user, params.id);
    if (ad.status === "removed") throw forbidden("Объявление снято модератором");
    const p = await parseAd(body, user, ad);
    const executed = BigInt(ad.total_units) - BigInt(ad.remaining_units);
    if (p.total < executed) throw bad("bad_total", `Количество не может быть меньше уже исполненного (${toStr(executed, ASSETS[ad.asset].dec)})`);
    if (ad.side === "sell" && p.total > BigInt(ad.total_units)) {   // увеличение объёма — снова проверяем кошелёк
      const f = await sellerFunding(user.wallet_address, ad.asset, await lockFor(p.total - executed, ad.asset));
      if (!f.coinsOk || !f.gasOk) throw ownFundingError(ad.asset, f);
    }
    db.run(`UPDATE ads SET price_type=?,price_e6=?,float_e2=?,total_units=?,remaining_units=?,min_cents=?,max_cents=?,pay_window=?,pay_types=?,pm_ids=?,remarks=?,cond_min_orders=?,cond_reg_days=?,updated_at=? WHERE id=?`,
      p.priceType, p.priceE6, p.floatE2, p.total, p.total - executed, p.min, p.max, p.payWindow, JSON.stringify(p.payTypes), JSON.stringify(p.pmIds), p.remarks, p.condMinOrders, p.condRegDays, now(), ad.id);
    const n = db.get("SELECT * FROM ads WHERE id=?", ad.id);
    return adView(n, await adPriceE6(n), user.id);
  });
  router.post("/api/ads/:id/status", {}, ({ user, body, params }) => {
    const ad = myAd(user, params.id);
    if (ad.status === "removed") throw forbidden("Объявление снято модератором");
    const st = v.oneOf(body.status, "status", ["online", "offline"]);
    if (st === "online") requireTrader(user);
    if (st === "online" && ad.side === "sell" && !JSON.parse(ad.pm_ids).length) throw bad("need_pm", "Добавьте способ оплаты в объявление");
    db.run("UPDATE ads SET status=?, updated_at=? WHERE id=?", st, now(), ad.id);
    return { ok: true, status: st };
  });
  router.del("/api/ads/:id", {}, ({ user, params }) => {
    const ad = myAd(user, params.id);
    if (db.get(`SELECT COUNT(*) n FROM orders WHERE ad_id=? AND status IN (${placeholders(ACTIVE.length)})`, ad.id, ...ACTIVE).n)
      throw conflict("has_orders", "По объявлению есть активные ордеры — сначала завершите их");
    db.run("UPDATE ads SET status='deleted', updated_at=? WHERE id=?", now(), ad.id);
    return { ok: true };
  });

  // paid pinning: invoice paid on-chain to the fee wallet with a unique comment
  router.post("/api/ads/:id/pin", { limit: { key: "pin", n: 20, ms: 3_600_000 } }, async ({ user, body, params }) => {
    const ad = myAd(user, params.id);
    if (ad.status !== "online") throw bad("offline", "Закрепить можно только активное объявление");
    const pin = PINS.find((p) => p.h === v.int(body.hours, "hours", { min: 1, max: 24 }));
    if (!pin) throw bad("bad_input", "Недопустимый срок закрепления");
    const asset = v.oneOf(body.asset || "USDT", "asset", ["USDT", "GRAM"]);
    if (asset === "USDT" && cfg.network === "testnet") throw bad("testnet", "USDT недоступен в Testnet");
    const usd = await prices.usdE6(asset);
    if (!usd) throw new HttpError(503, "no_price", "Курс временно недоступен");
    const units = (BigInt(pin.usd) * 1_000_000n * 10n ** BigInt(ASSETS[asset].dec) + usd - 1n) / usd;
    const id = randomId(9), comment = `PMR-PIN-${id}`;
    db.run("INSERT INTO pin_invoices(id,ad_id,user_id,hours,asset,amount_units,comment,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?)",
      id, ad.id, user.id, pin.h, asset, units, comment, now(), now() + 30 * 60_000);
    return { id, asset, amount: toStr(units, ASSETS[asset].dec), amountUnits: units.toString(), to: cfg.feeWallet, comment, hours: pin.h, usd: pin.usd, expiresAt: now() + 30 * 60_000 };
  });
  router.get("/api/pins/:id", {}, ({ user, params }) => {
    const p = db.get("SELECT id,status,ad_id,hours,paid_at,expires_at FROM pin_invoices WHERE id=? AND user_id=?", String(params.id).slice(0, 32), user.id);
    if (!p) throw notFound();
    return p;
  });

  // ------------------------------------------------------------------ orders
  router.post("/api/orders", { limit: { key: "ordnew", n: 30, ms: 3_600_000 } }, async ({ user, body }) => {
    requireTrader(user);
    const idem = v.str(body.idem, "idem", { min: 8, max: 64, re: /^[A-Za-z0-9_-]+$/ });
    const dup = db.get("SELECT * FROM orders WHERE idem=? AND taker_id=?", idem, user.id);
    if (dup) return orderView(dup, user);
    const ad = db.get("SELECT * FROM ads WHERE id=?", v.int(body.adId, "adId", { min: 1 }));
    if (!ad || ad.status !== "online") throw bad("ad_unavailable", "Объявление недоступно");
    if (ad.user_id === user.id) throw bad("own_ad", "Нельзя открыть ордер по своему объявлению");
    const maker = db.get("SELECT * FROM users WHERE id=?", ad.user_id);
    if (!maker || maker.banned_at || !maker.wallet_address) throw bad("ad_unavailable", "Объявление недоступно");
    if (maker.wallet_address === user.wallet_address) throw bad("same_wallet", "Кошельки участников совпадают");

    const st = userStats(user.id);
    if (st.totalOrders < ad.cond_min_orders) throw bad("conditions", `Нужно не менее ${ad.cond_min_orders} завершённых сделок`);
    if (now() - user.created_at < ad.cond_reg_days * DAY) throw bad("conditions", `Аккаунт должен быть зарегистрирован не менее ${ad.cond_reg_days} дн.`);
    const takerIsBuyer = ad.side === "sell";
    if (takerIsBuyer) {
      const c = db.get("SELECT COUNT(*) n, MIN(cancelled_at) first FROM orders WHERE buyer_id=? AND status=40 AND fault_user=? AND cancelled_at>=?", user.id, user.id, now() - DAY);
      if (c.n >= CANCEL_LIMIT) throw new HttpError(403, "cancel_limit", `Вы отменили ${c.n} ордера за сутки. Создание ордеров на покупку доступно после ${new Date(c.first + DAY).toLocaleString("ru-RU", { timeZone: "Europe/Chisinau" })}`);
    }
    if (db.get(`SELECT COUNT(*) n FROM orders WHERE taker_id=? AND status IN (${placeholders(ACTIVE.length)})`, user.id, ...ACTIVE).n >= MAX_TAKER_ORDERS)
      throw bad("too_many_orders", `Не более ${MAX_TAKER_ORDERS} активных ордеров одновременно`);

    const a = ASSETS[ad.asset];
    const priceE6 = await adPriceE6(ad);
    if (!priceE6) throw new HttpError(503, "no_price", "Рыночный курс временно недоступен");
    // Как на Bybit: введённая сумма в фиате остаётся точной, количество крипты округляется вниз;
    // при вводе количества сумма в фиате считается по цене.
    let units, cents;
    if (body.amount != null && body.amount !== "") {
      units = floorTo(v.dec(body.amount, "Количество", a.dec, { min: 1, max: a.maxUnits }), a.step);
      cents = fiatCents(units, a.dec, priceE6);
    } else {
      cents = v.dec(body.fiat, "Сумма", 2, { min: 1, max: 100_000_000_000n });
      units = unitsForCents(cents, ad.asset, priceE6);
    }
    if (units <= 0n) throw bad("bad_amount", "Слишком маленькая сумма");
    if (cents < BigInt(ad.min_cents) || cents > BigInt(ad.max_cents)) throw bad("limits", `Сумма вне лимитов: ${toStr(BigInt(ad.min_cents), 2)}–${toStr(BigInt(ad.max_cents), 2)} ${ad.fiat}`);
    if (units > BigInt(ad.remaining_units)) throw bad("no_liquidity", "Недостаточно доступного количества в объявлении");
    const usd = await prices.usdE6(ad.asset);
    if (!usd) throw new HttpError(503, "no_price", "Курс временно недоступен");
    const fee = sideFee(units, ad.asset, usd, cfg.p2pFeeSideBps, cfg.p2pFeeMaxSideUsdE6);
    if (units - fee <= 0n) throw bad("bad_amount", "Слишком маленькая сумма");

    // payment details: always the SELLER's account, snapshotted for this order
    const payType = v.oneOf(body.payType, "Способ оплаты", JSON.parse(ad.pay_types));
    let pmRow;
    if (takerIsBuyer) {
      const ids = JSON.parse(ad.pm_ids);
      pmRow = ids.length && db.get(`SELECT * FROM payment_methods WHERE user_id=? AND deleted=0 AND type=? AND id IN (${placeholders(ids.length)}) ORDER BY id LIMIT 1`, ad.user_id, payType, ...ids);
      if (!pmRow) throw bad("ad_unavailable", "У продавца нет реквизитов для этого способа оплаты");
    } else {
      pmRow = db.get("SELECT * FROM payment_methods WHERE id=? AND user_id=? AND deleted=0", v.int(body.pmId, "Реквизиты", { min: 1 }), user.id);
      if (!pmRow || pmRow.type !== payType) throw bad("need_pm", "Выберите свои реквизиты для получения оплаты");
    }
    const seller = takerIsBuyer ? maker : user, buyer = takerIsBuyer ? user : maker;
    // у продавца в блокчейне должны быть монеты на эту сделку (+ комиссия), иначе ордер не создаём
    const funding = await sellerFunding(seller.wallet_address, ad.asset, units + fee);
    if (!funding.coinsOk || !funding.gasOk) {
      if (!takerIsBuyer) throw ownFundingError(ad.asset, funding);
      const minUnits = unitsForCents(ad.min_cents, ad.asset, priceE6);
      const minF = await sellerFunding(seller.wallet_address, ad.asset, minUnits + sideFee(minUnits, ad.asset, usd, cfg.p2pFeeSideBps, cfg.p2pFeeMaxSideUsdE6));
      if (!minF.coinsOk || !minF.gasOk) {   // не хватает даже на минимальный ордер — прячем объявление
        const r = db.run("UPDATE ads SET status='offline', updated_at=? WHERE id=? AND status='online'", now(), ad.id);
        if (r.changes) tell(ad.user_id, `Объявление #${ad.id} скрыто: на кошельке не хватает ${ad.asset}${minF.coinsOk ? " или GRAM на газ" : ""} даже на минимальную сделку. Пополните кошелёк и включите объявление снова.`, null);
      }
      throw conflict("seller_insufficient", "У продавца сейчас недостаточно средств для этой сделки. Выберите меньшую сумму или другое объявление.");
    }
    const details = { type: pmRow.type, ...dec(pmRow.details_enc, "pm:" + pmRow.user_id) };
    const dealId = randomU64();
    const escrowDeadline = nowSec() + cfg.escrowReclaimDays * 86400;
    const escrowParams = {
      dealId, kind: a.kind, deadline: escrowDeadline, arbiterKeyHex: cfg.arbiter.publicKeyHex,
      buyerAmount: units - fee, feeAmount: fee * 2n, seller: seller.wallet_address, buyer: buyer.wallet_address, feeWallet: cfg.feeWallet,
    };
    const escrowRaw = escrowAddress(escrowParams).toRawString();
    const t = now();
    const order = db.tx(() => {
      const upd = db.run("UPDATE ads SET remaining_units=remaining_units-?, updated_at=? WHERE id=? AND status='online' AND remaining_units>=?", units, t, ad.id, units);
      if (upd.changes !== 1) throw bad("no_liquidity", "Недостаточно доступного количества в объявлении");
      const r = db.run(`INSERT INTO orders(ad_id,maker_id,taker_id,buyer_id,seller_id,asset,fiat,price_e6,amount_units,fiat_cents,buyer_fee,seller_fee,usd_e6,
        pay_type,pay_details_enc,pay_window,remarks,status,deal_id,escrow_address,seller_address,buyer_address,escrow_deadline,lock_deadline,idem,created_at,updated_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        ad.id, ad.user_id, user.id, buyer.id, seller.id, ad.asset, ad.fiat, priceE6, units, cents, fee, fee, usd,
        payType, "", ad.pay_window, ad.remarks, OS.AWAIT_ESCROW, dealId.toString(), escrowRaw, seller.wallet_address, buyer.wallet_address,
        escrowDeadline, t + cfg.lockWindowMin * 60_000, idem, t, t);
      const id = Number(r.lastInsertRowid);
      db.run("UPDATE orders SET pay_details_enc=? WHERE id=?", enc(details, "order:" + id), id);
      return db.get("SELECT * FROM orders WHERE id=?", id);
    });
    sysMsg(order.id, `Ордер создан: ${toStr(units, a.dec)} ${ad.asset} за ${toStr(cents, 2)} ${ad.fiat}. Продавец должен заблокировать ${toStr(units + fee, a.dec)} ${ad.asset} в смарт‑контракте эскроу в течение ${cfg.lockWindowMin} мин.`);
    sysMsg(order.id, "Безопасность: продавец отпускает крипту только после поступления оплаты на свой счёт. Не общайтесь вне этого чата, не переходите по ссылкам и не отправляйте средства «в поддержку».");
    tell(ad.user_id, `Новый ордер #${order.id} по вашему объявлению: ${toStr(units, a.dec)} ${ad.asset} / ${toStr(cents, 2)} ${ad.fiat}.${takerIsBuyer ? " Заблокируйте средства в эскроу." : ""}`, order);
    pushOrder(order);
    return orderView(order, user);
  });

  router.get("/api/orders", {}, ({ user, query }) => {
    const scope = v.oneOf(query.get("scope") || "active", "scope", ["active", "done", "all"]);
    const limit = v.int(query.get("limit") || 50, "limit", { min: 1, max: 100 });
    const offset = v.int(query.get("offset") || 0, "offset", { min: 0, max: 100_000 });
    const sts = scope === "active" ? ACTIVE : scope === "done" ? [OS.CANCELLED, OS.COMPLETED] : [...ACTIVE, OS.CANCELLED, OS.COMPLETED];
    const rows = db.all(`SELECT * FROM orders WHERE (buyer_id=? OR seller_id=?) AND status IN (${placeholders(sts.length)}) ORDER BY id DESC LIMIT ? OFFSET ?`, user.id, user.id, ...sts, limit, offset);
    return { items: rows.map((o) => { const x = orderView(o, user); delete x.payDetails; return x; }), activeCount: db.get(`SELECT COUNT(*) n FROM orders WHERE (buyer_id=? OR seller_id=?) AND status IN (${placeholders(ACTIVE.length)})`, user.id, user.id, ...ACTIVE).n };
  });
  router.get("/api/orders/:id", {}, ({ user, params }) => orderView(orderFor(user, params.id), user));

  // everything the seller's wallet needs to deploy + fund the escrow
  router.get("/api/orders/:id/escrow-tx", {}, async ({ user, params }) => {
    const o = orderFor(user, params.id);
    if (o.seller_id !== user.id) throw forbidden("Только продавец блокирует средства");
    if (o.status !== OS.AWAIT_ESCROW) throw conflict("bad_status", "Средства уже заблокированы или ордер закрыт");
    const need = BigInt(o.amount_units) + BigInt(o.seller_fee);
    const view = orderView(o, user);
    const out = { orderId: o.id, kind: ASSETS[o.asset].kind, escrow: view.escrow, lockDeadline: o.lock_deadline };
    if (o.asset === "GRAM") {
      out.messages = [{ to: view.escrow.address, valueUnits: (need + ESCROW_TON.tonDealReserve).toString(), withStateInit: true, body: null, bounce: true }];
    } else {
      let jw = o.jetton_wallet ? Address.parse(o.jetton_wallet) : null;
      if (!jw) {
        jw = await chain.jettonWalletOf(Address.parse(o.escrow_address));
        db.run("UPDATE orders SET jetton_wallet=? WHERE id=?", jw.toRawString(), o.id);
      }
      const sig = edSignHash(cfg.arbiter.priv, setupHash(o.escrow_address, jw.toRawString()));
      out.escrow.jettonWallet = jw.toString({ bounceable: true, testOnly: cfg.network === "testnet" });
      out.setup = { jettonWallet: out.escrow.jettonWallet, signature: Buffer.from(sig).toString("base64") };
      out.messages = [
        { to: view.escrow.address, valueUnits: ESCROW_TON.jettonDealDeploy.toString(), withStateInit: true, body: "setup", bounce: true },
        { to: "own_jetton_wallet", valueUnits: ESCROW_TON.jettonTransferValue.toString(), jettonAmountUnits: need.toString(), jettonTo: view.escrow.address },
      ];
    }
    return out;
  });
  router.post("/api/orders/:id/escrow-sent", {}, ({ user, params }) => {
    const o = orderFor(user, params.id);
    if (o.seller_id !== user.id) throw forbidden();
    if (o.status === OS.AWAIT_ESCROW && !(o.lock_sent_at > now() - 600_000)) sysMsg(o.id, "Продавец отправил транзакцию блокировки. Ожидаем подтверждения в сети TON…", participants(o));
    db.run("UPDATE orders SET chain_checked_at=0, lock_sent_at=? WHERE id=?", now(), o.id);
    return { ok: true };
  });
  router.post("/api/orders/:id/paid", {}, ({ user, params }) => {
    const o = orderFor(user, params.id);
    if (o.buyer_id !== user.id) throw forbidden("Только покупатель отмечает оплату");
    const n = transition(o, [OS.AWAIT_PAY], OS.PAID, { paid_at: now() });
    if (!n) throw conflict("bad_status", o.status === OS.AWAIT_ESCROW ? "Дождитесь блокировки средств продавцом" : "Статус ордера изменился");
    sysMsg(o.id, `Покупатель отметил оплату ${toStr(BigInt(o.fiat_cents), 2)} ${o.fiat}. Продавец, проверьте поступление на свой счёт и только потом отпускайте средства.`, participants(o));
    tell(o.seller_id, `Ордер #${o.id}: покупатель отметил оплату. Проверьте поступление и отпустите средства.`, o);
    return orderView(n, user);
  });
  router.post("/api/orders/:id/cancel", {}, ({ user, params, body }) => {
    const o = orderFor(user, params.id);
    const isBuyer = o.buyer_id === user.id, isSeller = o.seller_id === user.id;
    if (isSeller && !isBuyer) {
      if (o.status !== OS.AWAIT_ESCROW) throw conflict("seller_cannot_cancel", "После блокировки средств продавец не может отменить ордер. Если покупатель не оплатил — дождитесь таймаута или откройте апелляцию.");
      const n = cancelOrder(o, { by: user.id, reason: "продавец отказался от сделки", fault: user.id });
      if (!n) throw conflict("bad_status", "Статус ордера изменился");
      return orderView(n, user);
    }
    if (!isBuyer) throw forbidden();
    if (![OS.AWAIT_ESCROW, OS.AWAIT_PAY, OS.PAID, OS.APPEAL].includes(o.status)) throw conflict("bad_status", "Ордер уже закрыт");
    if (o.status === OS.PAID || o.status === OS.APPEAL) { if (!v.bool(body.confirmNotPaid)) throw bad("confirm", "Подтвердите, что вы не переводили оплату"); }
    const n = cancelOrder(o, { by: user.id, reason: "покупатель отменил ордер", fault: o.status === OS.AWAIT_ESCROW ? null : user.id });
    if (!n) throw conflict("bad_status", "Статус ордера изменился");
    if (o.status === OS.APPEAL) db.run("UPDATE appeals SET status='cancelled', resolved_at=? WHERE order_id=? AND status='open'", now(), o.id);
    return orderView(n, user);
  });
  router.post("/api/orders/:id/release-sent", {}, ({ user, params }) => {
    const o = orderFor(user, params.id);
    if (o.seller_id !== user.id) throw forbidden();
    if (![OS.AWAIT_PAY, OS.PAID, OS.APPEAL].includes(o.status)) throw conflict("bad_status", "Статус ордера изменился");
    db.run("UPDATE orders SET release_sent_at=?, chain_checked_at=0 WHERE id=?", now(), o.id);
    sysMsg(o.id, "Продавец подтвердил получение оплаты и отпускает средства. Ожидаем подтверждения в сети TON…", participants(o));
    return { ok: true };
  });
  router.post("/api/orders/:id/appeal", { limit: { key: "appeal", n: 10, ms: DAY } }, ({ user, params, body }) => {
    const o = orderFor(user, params.id);
    if (o.buyer_id !== user.id && o.seller_id !== user.id) throw forbidden();
    if (o.status !== OS.PAID) throw conflict("bad_status", "Апелляция доступна после того, как покупатель отметил оплату");
    if (now() < o.paid_at + cfg.appealAfterMin * 60_000) throw conflict("too_early", `Апелляция станет доступна через ${Math.ceil((o.paid_at + cfg.appealAfterMin * 60_000 - now()) / 60_000)} мин.`);
    const reason = v.oneOf(body.reason, "Причина", APPEAL_REASONS);
    const description = v.str(body.description, "Описание", { min: 10, max: 1000, multiline: true });
    const n = transition(o, [OS.PAID], OS.APPEAL);
    if (!n) throw conflict("bad_status", "Статус ордера изменился");
    db.run("INSERT INTO appeals(order_id,opened_by,reason,description,status,prev_status,created_at) VALUES(?,?,?,?,?,?,?)", o.id, user.id, reason, description, "open", OS.PAID, now());
    sysMsg(o.id, `Открыта апелляция (${reason}). Сотрудник поддержки подключится к чату. Приложите доказательства: чеки и скриншоты.`, participants(o));
    tell(o.buyer_id === user.id ? o.seller_id : o.buyer_id, `По ордеру #${o.id} открыта апелляция. Ответьте в чате ордера.`, o);
    for (const a of db.all("SELECT id FROM users WHERE role='admin'")) tell(a.id, `Новая апелляция по ордеру #${o.id}: ${reason}`, null);
    return orderView(n, user);
  });
  router.post("/api/orders/:id/appeal/cancel", {}, ({ user, params }) => {
    const o = orderFor(user, params.id);
    const ap = db.get("SELECT * FROM appeals WHERE order_id=? AND status='open'", o.id);
    if (!ap || ap.opened_by !== user.id) throw forbidden("Отменить апелляцию может только её автор");
    const n = transition(o, [OS.APPEAL], ap.prev_status);
    if (!n) throw conflict("bad_status", "Статус ордера изменился");
    db.run("UPDATE appeals SET status='cancelled', resolved_at=? WHERE id=?", now(), ap.id);
    sysMsg(o.id, "Апелляция отменена её автором.", participants(o));
    return orderView(n, user);
  });
  router.post("/api/orders/:id/feedback", {}, ({ user, params, body }) => {
    const o = orderFor(user, params.id);
    if (o.status !== OS.COMPLETED || (o.buyer_id !== user.id && o.seller_id !== user.id)) throw conflict("bad_status", "Отзыв можно оставить после завершения сделки");
    const to = o.buyer_id === user.id ? o.seller_id : o.buyer_id;
    try {
      db.run("INSERT INTO feedback(order_id,from_id,to_id,positive,comment,created_at) VALUES(?,?,?,?,?,?)", o.id, user.id, to, v.bool(body.positive) ? 1 : 0, v.str(body.comment, "Комментарий", { max: 300 }), now());
    } catch { throw conflict("exists", "Отзыв уже оставлен"); }
    dropStats(to);
    return { ok: true };
  });

  router.post("/api/reports", { limit: { key: "report", n: 10, ms: DAY } }, ({ user, body }) => {
    const o = orderFor(user, body.orderId);
    if (o.buyer_id !== user.id && o.seller_id !== user.id) throw forbidden();
    const against = o.buyer_id === user.id ? o.seller_id : o.buyer_id;
    db.run("INSERT INTO reports(reporter_id,against_id,order_id,reason,text,created_at) VALUES(?,?,?,?,?,?)", user.id, against, o.id,
      v.oneOf(body.reason, "Причина", REPORT_REASONS), v.str(body.text, "Описание", { min: 5, max: 1000, multiline: true }), now());
    return { ok: true };
  });

  router.get("/api/users/:nick", {}, ({ params }) => {
    const nick = v.str(params.nick, "nick", { min: 1, max: 32 });
    const u = db.get("SELECT id, nick, created_at FROM users WHERE nick=?", nick);
    if (!u) throw notFound("Пользователь не найден");
    const fb = db.all("SELECT f.positive, f.comment, f.created_at, u.nick FROM feedback f JOIN users u ON u.id=f.from_id WHERE f.to_id=? ORDER BY f.id DESC LIMIT 20", u.id);
    return { nick: u.nick, stats: userStats(u.id), feedback: fb.map((f) => ({ positive: !!f.positive, comment: f.comment, from: f.nick, createdAt: f.created_at })) };
  });

  ctx.orderFor = orderFor;
  ctx.participants = participants;
  ctx.userStats = userStats;
  ctx.APPEAL_REASONS = APPEAL_REASONS;
  ctx.REPORT_REASONS = REPORT_REASONS;
  ctx.CHAT_AFTER_CLOSE = CHAT_AFTER_CLOSE;
  ctx.isFunded = isFunded;
}
