// Telegram bot: /start welcome, /help, webhook secret, dedupe, block tracking, polling.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { startApp, Client, BOT } from "./helpers.js";
import { makeBot } from "../src/bot.js";
import { makeBotUpdates } from "../src/bot-updates.js";
import { makeLog } from "../src/index.js";
import { RateLimiter } from "../src/security.js";

const SECRET = "s".repeat(20) + "ecret_token_0123456789";
const sent = [];
const fakeBot = { notify() {}, send(chatId, body) { sent.push({ chatId, ...body }); }, async call() { return { ok: true, result: [] }; } };
let t, uid = 7001, upd = 1;

const hook = (update, secret = SECRET) => fetch(t.base + "/api/tg/webhook", {
  method: "POST", headers: { "content-type": "application/json", ...(secret ? { "x-telegram-bot-api-secret-token": secret } : {}) }, body: JSON.stringify(update),
});
const msg = (text, from = { id: uid, first_name: "Иван" }, chat = { id: from.id, type: "private" }) => ({ update_id: upd++, message: { message_id: upd, date: 1, chat, from, text } });

before(async () => {
  t = await startApp({ bot: fakeBot, env: { BOT_MODE: "webhook", BOT_WEBHOOK_URL: "https://wallet.example/api/tg/webhook", BOT_WEBHOOK_SECRET: SECRET, WEBAPP_URL: "https://wallet.example/", TG_APP_LINK: "https://t.me/pmr_bot/app" } });
});
after(() => t.close());

test("/start: welcome text with the PMR WALLET pitch and a Mini App button", async () => {
  // existing user who had notifications off
  const c = new Client(t.base, { id: uid, first_name: "Иван" }); await c.login();
  t.app.ctx.db.run("UPDATE users SET allows_pm=0 WHERE id=?", uid);
  const r = await hook(msg("/start"));
  assert.equal(r.status, 200);
  const m = sent.at(-1);
  assert.equal(m.chatId, uid);
  assert.equal(m.parse_mode, "HTML");
  assert.match(m.text, /PMR WALLET<\/b> — пространство криптовалюты в Приднестровье\./);
  assert.match(m.text, /Устал от постоянных скамеров и «треугольников»\? <b>Ты по адресу!<\/b>/);
  assert.match(m.text, /Привет, Иван!/);
  assert.deepEqual(m.reply_markup.inline_keyboard[0][0].web_app, { url: "https://wallet.example/" });
  assert.equal(t.app.ctx.db.get("SELECT allows_pm FROM users WHERE id=?", uid).allows_pm, 1, "started the bot -> notifications on");
});

test("/start with a deep link opens that order; /help; fallback; names are HTML-escaped", async () => {
  await hook(msg("/start order_42"));
  assert.deepEqual(sent.at(-1).reply_markup.inline_keyboard[0][0], { text: "📄 Открыть ордер", url: "https://t.me/pmr_bot/app?startapp=order_42" });
  await hook(msg("/start <script>"));
  assert.ok(sent.at(-1).reply_markup.inline_keyboard[0][0].web_app, "bad payload ignored");
  await hook(msg("/help"));
  assert.match(sent.at(-1).text, /треугольник/);
  await hook(msg("привет"));
  assert.match(sent.at(-1).text, /Я бот <b>PMR WALLET<\/b>/);
  await hook(msg("/start", { id: 7002, first_name: "<b>x</b>&" }));
  assert.match(sent.at(-1).text, /Привет, &lt;b&gt;x&lt;\/b&gt;&amp;!/);
});

test("webhook: wrong/missing secret is refused, duplicates and group chats are ignored, floods are cut", async () => {
  const n = sent.length;
  assert.equal((await hook(msg("/start"), "wrong-secret-wrong-secret-wrong-secret")).status, 401);
  assert.equal((await hook(msg("/start"), null)).status, 401);
  assert.equal(sent.length, n);
  const u = msg("/start");
  await hook(u); await hook(u);
  assert.equal(sent.length, n + 1, "same update_id handled once");
  await hook(msg("/start", { id: 7003, first_name: "G" }, { id: -100, type: "supergroup" }));
  await hook(msg("/start", { id: 7004, first_name: "Bot", is_bot: true }));
  assert.equal(sent.length, n + 1);
  for (let i = 0; i < 20; i++) await hook(msg("spam", { id: 7005, first_name: "S" }));
  assert.equal(sent.filter((m) => m.chatId === 7005).length, 8, "per-chat flood limit");
});

test("blocking the bot turns notifications off, unblocking turns them on", async () => {
  const mcm = (status) => ({ update_id: upd++, my_chat_member: { chat: { id: uid, type: "private" }, from: { id: uid }, new_chat_member: { status } } });
  await hook(mcm("kicked"));
  assert.equal(t.app.ctx.db.get("SELECT allows_pm FROM users WHERE id=?", uid).allows_pm, 0);
  await hook(mcm("member"));
  assert.equal(t.app.ctx.db.get("SELECT allows_pm FROM users WHERE id=?", uid).allows_pm, 1);
});

test("Bot API: 403 from Telegram (user blocked the bot) disables notifications; polling persists offset", async () => {
  const db = t.app.ctx.db, log = makeLog(true);
  const calls = [];
  let polls = 0;
  const fetchImpl = async (url, init) => {
    const method = url.split("/").pop(), body = JSON.parse(init.body);
    calls.push({ method, body });
    if (method === "sendMessage") return new Response(JSON.stringify({ ok: false, description: "Forbidden: bot was blocked by the user" }), { status: 403 });
    if (method === "getUpdates") {
      polls++;
      if (polls === 1) return new Response(JSON.stringify({ ok: true, result: [msg("/start", { id: 7010, first_name: "P" })] }));
      await new Promise((r) => setTimeout(r, 30));
      return new Response(JSON.stringify({ ok: true, result: [] }));
    }
    return new Response(JSON.stringify({ ok: true, result: true }));
  };
  const cfg = { ...t.cfg, botMode: "polling", botToken: BOT };
  const bot = makeBot(cfg, db, log, fetchImpl);
  const ups = makeBotUpdates({ cfg, db, log, bot, limiter: new RateLimiter() });
  db.run("UPDATE users SET allows_pm=1 WHERE id=?", uid);
  ups.start();
  for (let i = 0; i < 100 && !calls.some((c) => c.method === "sendMessage"); i++) await new Promise((r) => setTimeout(r, 20));
  ups.stop();
  assert.ok(calls.some((c) => c.method === "setMyCommands"));
  assert.ok(calls.some((c) => c.method === "setChatMenuButton" && c.body.menu_button.web_app.url === "https://wallet.example/"));
  assert.ok(calls.some((c) => c.method === "deleteWebhook"));
  const reply = calls.find((c) => c.method === "sendMessage");
  assert.equal(reply.body.chat_id, 7010);
  assert.match(reply.body.text, /пространство криптовалюты в Приднестровье/);
  assert.ok(Number(db.get("SELECT v FROM kv WHERE k='bot_offset'").v) >= 1, "offset saved");
  // notification to a user who blocked the bot
  await new Promise((done) => bot.notify(uid, "test", "", done));
  assert.equal(db.get("SELECT allows_pm FROM users WHERE id=?", uid).allows_pm, 0);
});
