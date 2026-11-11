// Telegram Bot API notifications with a bounded, rate-limited queue
// (Telegram allows ~30 msg/s globally and ~1 msg/s per chat).
export function makeBot(cfg, db, log, fetchImpl = fetch) {
  const q = [];
  const MAX_Q = 50_000;
  let running = false;
  const lastPerChat = new Map();

  // generic Bot API call with a timeout; never throws
  async function call(method, payload, timeoutMs = 10_000) {
    const ctl = new AbortController(), t = setTimeout(() => ctl.abort(), timeoutMs);
    try {
      const r = await fetchImpl(`${cfg.botApi}/bot${cfg.botToken}/${method}`, { method: "POST", signal: ctl.signal, headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload || {}) });
      const j = await r.json().catch(() => ({}));
      return { status: r.status, ok: r.ok && j.ok !== false, result: j.result, retryAfter: r.status === 429 ? (j.parameters?.retry_after || 5) * 1000 : 0, error: j.description };
    } catch (e) { return { status: 0, ok: false, error: String(e && e.name === "AbortError" ? "timeout" : e) }; }
    finally { clearTimeout(t); }
  }
  function notifyBody(chatId, text, link) {
    const body = { chat_id: chatId, text: String(text).slice(0, 3500), disable_web_page_preview: true };
    if (link && /^https:\/\/t\.me\//.test(link)) body.reply_markup = { inline_keyboard: [[{ text: "Открыть PMR Wallet", url: link }]] };
    return body;
  }
  async function sendNow(job) {
    const r = await call("sendMessage", job.body || notifyBody(job.chatId, job.text, job.link));
    // user blocked the bot -> stop notifying them
    if (r.status === 403) db.run("UPDATE users SET allows_pm=0 WHERE id=?", job.chatId);
    return r;
  }
  async function pump() {
    if (running) return;
    running = true;
    try {
      while (q.length) {
        // first job whose chat is not throttled; otherwise sleep until the earliest one is
        let idx = -1, minWait = Infinity;
        for (let i = 0; i < q.length && i < 500; i++) {
          const w = (lastPerChat.get(q[i].chatId) || 0) + 1100 - Date.now();
          if (w <= 0) { idx = i; break; }
          if (w < minWait) minWait = w;
        }
        if (idx < 0) { await new Promise((r) => setTimeout(r, Math.max(50, Math.min(minWait, 1100)))); continue; }
        const [job] = q.splice(idx, 1);
        const res = await sendNow(job);
        lastPerChat.set(job.chatId, Date.now());
        if (lastPerChat.size > 100_000) lastPerChat.clear();
        if (res.retryAfter) { q.unshift(job); await new Promise((r) => setTimeout(r, Math.min(res.retryAfter, 60_000))); continue; }
        job.done?.(!!res.ok);
        await new Promise((r) => setTimeout(r, 40)); // <= 25 msg/s
      }
    } finally { running = false; }
  }
  return {
    notify(userId, text, link = "", done) {
      const u = db.get("SELECT allows_pm, banned_at FROM users WHERE id=?", userId);
      if (!u || !u.allows_pm) { done?.(false); return; }
      if (q.length >= MAX_Q) { log.warn("bot queue full"); done?.(false); return; }
      q.push({ chatId: userId, text, link, done });
      pump().catch((e) => log.error("bot pump", { err: String(e) }));
    },
    // direct reply to a chat (bot commands); same per-chat throttling, no allows_pm check
    send(chatId, body, done) {
      if (q.length >= MAX_Q) { done?.(false); return; }
      q.unshift({ chatId, body: { ...body, chat_id: chatId }, done });
      pump().catch((e) => log.error("bot pump", { err: String(e) }));
    },
    call,
    queueSize: () => q.length,
  };
}
