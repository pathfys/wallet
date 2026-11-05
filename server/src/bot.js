// Telegram Bot API notifications with a bounded, rate-limited queue
// (Telegram allows ~30 msg/s globally and ~1 msg/s per chat).
export function makeBot(cfg, db, log, fetchImpl = fetch) {
  const q = [];
  const MAX_Q = 50_000;
  let running = false;
  const lastPerChat = new Map();

  async function sendNow(chatId, text, link) {
    const body = { chat_id: chatId, text: String(text).slice(0, 3500), disable_web_page_preview: true };
    if (link && /^https:\/\/t\.me\//.test(link)) body.reply_markup = { inline_keyboard: [[{ text: "Открыть PMR Wallet", url: link }]] };
    const ctl = new AbortController(), t = setTimeout(() => ctl.abort(), 10_000);
    try {
      const r = await fetchImpl(`${cfg.botApi}/bot${cfg.botToken}/sendMessage`, { method: "POST", signal: ctl.signal, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      if (r.status === 429) { const j = await r.json().catch(() => ({})); return { retryAfter: (j.parameters?.retry_after || 5) * 1000 }; }
      return { ok: r.ok };
    } catch { return { ok: false }; } finally { clearTimeout(t); }
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
        const res = await sendNow(job.chatId, job.text, job.link);
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
    queueSize: () => q.length,
  };
}
