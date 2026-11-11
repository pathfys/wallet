// Incoming Telegram updates: /start welcome, /help, fallback reply, block/unblock tracking.
// Two transports:
//   * webhook — POST /api/tg/webhook, authenticated by the secret_token header Telegram
//     sends with every update (constant-time compare); updates are deduplicated by update_id;
//   * long polling — getUpdates loop, offset persisted in SQLite (survives restarts).
// Only private chats are answered; per-chat rate limit stops reply loops and spam.
import { timingSafeEqual, createHash } from "node:crypto";
import { HttpError } from "./util.js";
import { WELCOME, HELP, FALLBACK, OPEN_BUTTON, ORDER_BUTTON } from "./bot-texts.js";

const escHtml = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const START_PARAM = /^[A-Za-z0-9_-]{1,64}$/;

export function secretOk(cfg, header) {
  if (!cfg.botWebhookSecret || typeof header !== "string") return false;
  const a = createHash("sha256").update(header).digest(), b = createHash("sha256").update(cfg.botWebhookSecret).digest();
  return timingSafeEqual(a, b);
}

export function makeBotUpdates(ctx) {
  const { cfg, db, log, bot, limiter } = ctx;
  const recent = new Set(); // update_id dedupe (Telegram re-delivers on timeouts)

  function appButton(startParam) {
    if (startParam && cfg.tgAppLink) return { text: startParam.startsWith("order_") ? ORDER_BUTTON : OPEN_BUTTON, url: `${cfg.tgAppLink}?startapp=${startParam}` };
    if (cfg.webAppUrl) return { text: OPEN_BUTTON, web_app: { url: cfg.webAppUrl } };
    if (cfg.tgAppLink) return { text: OPEN_BUTTON, url: cfg.tgAppLink };
    return null;
  }
  function reply(chatId, text, startParam = "") {
    const btn = appButton(startParam);
    bot.send(chatId, { text, parse_mode: "HTML", disable_web_page_preview: true, ...(btn ? { reply_markup: { inline_keyboard: [[btn]] } } : {}) });
  }

  function handle(u) {
    if (!u || !Number.isSafeInteger(u.update_id)) return;
    if (recent.has(u.update_id)) return;
    recent.add(u.update_id);
    if (recent.size > 5000) for (const id of recent) { recent.delete(id); if (recent.size <= 4000) break; }

    // user blocked / unblocked the bot -> stop / resume notifications
    const mcm = u.my_chat_member;
    if (mcm && mcm.chat?.type === "private" && Number.isSafeInteger(mcm.from?.id)) {
      const st = mcm.new_chat_member?.status;
      if (st === "kicked") db.run("UPDATE users SET allows_pm=0 WHERE id=?", mcm.from.id);
      else if (st === "member") db.run("UPDATE users SET allows_pm=1 WHERE id=?", mcm.from.id);
      return;
    }

    const m = u.message;
    if (!m || m.chat?.type !== "private" || !m.from || m.from.is_bot || !Number.isSafeInteger(m.from.id)) return;
    const uid = m.from.id;
    if (!limiter.take("botmsg:" + uid, 8, 60_000)) return; // flood: silently ignore
    const text = typeof m.text === "string" ? m.text.trim() : "";
    const cmd = /^\/([a-z]+)(?:@\w+)?(?:\s+(.*))?$/i.exec(text);
    const name = escHtml(String(m.from.first_name || "друг").slice(0, 64));

    if (cmd && cmd[1].toLowerCase() === "start") {
      db.run("UPDATE users SET allows_pm=1 WHERE id=?", uid); // started the bot -> may receive notifications
      const p = String(cmd[2] || "").trim();
      reply(uid, WELCOME.replace("{name}", name), START_PARAM.test(p) ? p : "");
      log.info("bot start", { user: uid });
    } else if (cmd && cmd[1].toLowerCase() === "help") {
      reply(uid, HELP);
    } else {
      reply(uid, FALLBACK);
    }
  }

  // ---------------------------------------------------------------- transports
  let stopped = false;
  async function setup() {
    // commands + menu button (the "Открыть" button next to the input field)
    await bot.call("setMyCommands", { commands: [{ command: "start", description: "Главное меню" }, { command: "help", description: "Как пользоваться и правила безопасности" }] });
    if (cfg.webAppUrl) await bot.call("setChatMenuButton", { menu_button: { type: "web_app", text: "Кошелёк", web_app: { url: cfg.webAppUrl } } });
    if (cfg.botMode === "webhook") {
      const r = await bot.call("setWebhook", { url: cfg.botWebhookUrl, secret_token: cfg.botWebhookSecret, allowed_updates: ["message", "my_chat_member"], max_connections: 20 });
      log[r.ok ? "info" : "error"]("bot webhook", { ok: r.ok, error: r.error });
    } else if (cfg.botMode === "polling") {
      await bot.call("deleteWebhook", {});
      poll();
    }
  }
  async function poll() {
    let offset = Number(db.get("SELECT v FROM kv WHERE k='bot_offset'")?.v || 0);
    let backoff = 1000;
    while (!stopped) {
      const r = await bot.call("getUpdates", { offset, timeout: 25, allowed_updates: ["message", "my_chat_member"] }, 35_000);
      if (stopped) break;
      if (!r.ok || !Array.isArray(r.result)) {
        if (r.status === 409) log.warn("bot polling conflict: another getUpdates/webhook is active");
        await new Promise((res) => setTimeout(res, r.retryAfter || backoff));
        backoff = Math.min(backoff * 2, 60_000);
        continue;
      }
      backoff = 1000;
      for (const u of r.result) {
        try { handle(u); } catch (e) { log.error("bot update", { err: String(e) }); }
        offset = Math.max(offset, u.update_id + 1);
      }
      if (r.result.length) db.run("INSERT INTO kv(k,v) VALUES('bot_offset',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", String(offset));
    }
  }

  return {
    handle,
    start() { if (cfg.botMode !== "off") setup().catch((e) => log.error("bot setup", { err: String(e) })); },
    stop() { stopped = true; },
    // webhook route: always 200 for an authenticated call so Telegram does not retry forever
    registerRoute(router) {
      router.post("/api/tg/webhook", { auth: "public", maxBody: 256 * 1024 }, ({ body, headers }) => {
        if (cfg.botMode !== "webhook" || !secretOk(cfg, headers["x-telegram-bot-api-secret-token"])) throw new HttpError(401, "unauthorized", "Нет доступа");
        try { handle(body); } catch (e) { log.error("bot update", { err: String(e) }); }
        return { ok: true };
      });
    },
  };
}
