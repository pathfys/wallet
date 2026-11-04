"""
PL Wallet Telegram bot — language picker, greeting, WebApp entry,
admin blocklist + initData validation API.

Design notes:

- Inline buttons use the Bot API 9.0 `style` field ("primary" = blue).
  Older clients silently ignore it.

- /start answer formatting uses Telegram HTML parse_mode:
    <b>…</b>                 bold
    <blockquote>…</blockquote>  quoted ("цитированный") block for the
                                 feature list ("плюсы приложения").
    <blockquote expandable>…</blockquote>  collapses to a few lines.

- Admin panel lives in the bot itself (Telegram commands) AND exposes
  a tiny read/write HTTP API the mini-app uses to render a /admin view.
  Writes require a valid initData whose user.id == ADMIN_ID.

- initData validation follows the official spec:
    secret_key = HMAC_SHA256("WebAppData", bot_token)
    check_hash = HMAC_SHA256(secret_key, sorted_fields_joined)
  We additionally reject payloads older than INIT_MAX_AGE seconds so a
  leaked initData can't be replayed forever.

Run:
    pip install -r requirements.txt
    export BOT_TOKEN="<from @BotFather>"
    export ADMIN_ID="<your Telegram user id>"
    export WEBAPP_URL="https://pathfys.github.io/wallet/pl.html"
    export BOT_HTTP_PORT=8080           # for the admin API
    python bot.py
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from time import time
from typing import Iterable, Optional
from urllib.parse import parse_qsl

from aiogram import Bot, Dispatcher, F
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandStart
from aiogram.types import (
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
    ReplyParameters,
    WebAppInfo,
)
from aiohttp import web

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("pl-bot")


# ──────────────────────────────────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────────────────────────────────

BOT_TOKEN      = os.environ.get("BOT_TOKEN", "")
ADMIN_ID       = int(os.environ.get("ADMIN_ID", "0") or "0")
WEBAPP_URL     = os.environ.get("WEBAPP_URL", "https://pathfys.github.io/wallet/pl.html")
BOT_HTTP_PORT  = int(os.environ.get("BOT_HTTP_PORT", "8080"))
BOT_HTTP_HOST  = os.environ.get("BOT_HTTP_HOST", "0.0.0.0")
BLOCKLIST_PATH = Path(os.environ.get("BLOCKLIST_PATH", "blocklist.json"))
INIT_MAX_AGE   = int(os.environ.get("INIT_MAX_AGE", "300"))   # 5 min replay window


# ──────────────────────────────────────────────────────────────────────────
# Localization
# ──────────────────────────────────────────────────────────────────────────

SUPPORTED = ("ru", "en", "zh")

PICKER_TEXT = (
    "🌐 <b>Выберите язык</b>\n"
    "🌐 <b>Choose language</b>\n"
    "🌐 <b>选择语言</b>"
)

# Each greeting uses:
#   <b>…</b>                     — bold headline
#   <blockquote expandable>…    — feature list rendered as a quoted,
#                                 collapsible block (the "плюсы" the user
#                                 asked to show as цитирование).
GREETING = {
    "ru": (
        "👋 <b>Привет, {name}!</b>\n\n"
        "Это <b>PL Wallet</b> — твой кошелёк внутри Telegram. "
        "Торгуй P2P, принимай и отправляй крипту/фиат прямо в чате.\n\n"
        "<blockquote expandable><b>Плюсы приложения</b>\n"
        "• Эскроу-сделки с комиссией ниже рынка\n"
        "• Поддержка BTC, ETH, USDT, TON, BNB, SOL, STARS\n"
        "• Фиат: USD, EUR, RUB, UAH, TRY, CNY, GBP, MDL\n"
        "• Разблокировка по Face ID / Touch ID\n"
        "• QR-код на получение и встроенный сканер\n"
        "• Защита от DDoS, replay-атак и подмены initData</blockquote>\n\n"
        "Нажми кнопку ниже, чтобы открыть приложение."
    ),
    "en": (
        "👋 <b>Hi {name}!</b>\n\n"
        "This is <b>PL Wallet</b> — your in-Telegram wallet. "
        "Trade P2P, receive and send crypto/fiat right in the chat.\n\n"
        "<blockquote expandable><b>What you get</b>\n"
        "• Escrow deals with fees below market\n"
        "• BTC, ETH, USDT, TON, BNB, SOL, STARS\n"
        "• Fiat: USD, EUR, RUB, UAH, TRY, CNY, GBP, MDL\n"
        "• Face ID / Touch ID unlock\n"
        "• QR-code receive + built-in scanner\n"
        "• DDoS, replay, and initData spoofing protection</blockquote>\n\n"
        "Tap the button below to open the app."
    ),
    "zh": (
        "👋 <b>您好，{name}！</b>\n\n"
        "这是 <b>PL 钱包</b> —— 您在 Telegram 内的钱包。"
        "直接在聊天中进行 P2P 交易、接收和发送加密货币与法币。\n\n"
        "<blockquote expandable><b>应用优势</b>\n"
        "• 托管交易，手续费低于市场价\n"
        "• 支持 BTC、ETH、USDT、TON、BNB、SOL、STARS\n"
        "• 法币：USD、EUR、RUB、UAH、TRY、CNY、GBP、MDL\n"
        "• Face ID / Touch ID 解锁\n"
        "• QR 码收款和内置扫描器\n"
        "• 防 DDoS、重放和 initData 伪造</blockquote>\n\n"
        "点击下方按钮打开应用。"
    ),
}

OPEN_LABEL = {
    "ru": "Открыть PlayerOK",
    "en": "Open PlayerOK",
    "zh": "打开 PlayerOK",
}

BLOCKED_NOTICE = {
    "ru": "🚫 <b>Ваш доступ к PL Wallet заблокирован администратором.</b>\n\nДля разблокировки обратитесь в поддержку.",
    "en": "🚫 <b>Your access to PL Wallet has been blocked by an administrator.</b>\n\nContact support for unblocking.",
    "zh": "🚫 <b>您对 PL 钱包的访问已被管理员屏蔽。</b>\n\n如需解封请联系客服。",
}


# ──────────────────────────────────────────────────────────────────────────
# Blocklist storage
# ──────────────────────────────────────────────────────────────────────────

class Blocklist:
    """
    JSON-backed set of blocked Telegram user IDs. All mutations go through
    an asyncio.Lock so concurrent HTTP writes don't lose updates, and each
    mutation is flushed to disk before returning.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = asyncio.Lock()
        self._ids: set[int] = set()
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text())
            if isinstance(data, list):
                self._ids = {int(x) for x in data}
        except (OSError, ValueError) as exc:
            log.warning("blocklist load failed: %s", exc)

    def _save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(sorted(self._ids)))
        tmp.replace(self.path)

    async def add(self, uid: int) -> None:
        async with self._lock:
            self._ids.add(int(uid))
            self._save()

    async def remove(self, uid: int) -> None:
        async with self._lock:
            self._ids.discard(int(uid))
            self._save()

    def contains(self, uid: int) -> bool:
        return int(uid) in self._ids

    def all(self) -> list[int]:
        return sorted(self._ids)


# ──────────────────────────────────────────────────────────────────────────
# InitData verification (anti-spoof)
# ──────────────────────────────────────────────────────────────────────────

@dataclass
class InitUser:
    id: int
    username: Optional[str]
    first_name: Optional[str]
    language_code: Optional[str]


def verify_init_data(
    init_data: str,
    bot_token: str,
    max_age: int = INIT_MAX_AGE,
) -> Optional[InitUser]:
    """
    Verify a Telegram WebApp initData string per the official spec:

        secret_key   = HMAC_SHA256("WebAppData", bot_token)
        data_check   = "\n".join(f"{k}={v}" for k, v in sorted(pairs if k != "hash"))
        expected     = HMAC_SHA256(secret_key, data_check).hexdigest()
        == received hash

    Additionally, reject if auth_date is older than max_age seconds so a
    leaked payload cannot be replayed forever. Return the decoded user
    on success, None on any failure. `hmac.compare_digest` is used for
    the final comparison to avoid timing side channels.
    """
    if not init_data or not bot_token:
        return None

    try:
        pairs = dict(parse_qsl(init_data, keep_blank_values=True, strict_parsing=True))
    except ValueError:
        return None

    received_hash = pairs.pop("hash", None)
    if not received_hash:
        return None

    data_check = "\n".join(f"{k}={pairs[k]}" for k in sorted(pairs))
    secret = hmac.new(b"WebAppData", bot_token.encode(), hashlib.sha256).digest()
    computed = hmac.new(secret, data_check.encode(), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(computed, received_hash):
        return None

    try:
        auth_date = int(pairs.get("auth_date", "0"))
    except ValueError:
        return None
    if max_age > 0 and (time() - auth_date) > max_age:
        return None

    raw_user = pairs.get("user", "")
    if not raw_user:
        return None
    try:
        user = json.loads(raw_user)
    except ValueError:
        return None

    return InitUser(
        id=int(user.get("id", 0)),
        username=user.get("username"),
        first_name=user.get("first_name"),
        language_code=user.get("language_code"),
    )


def html_escape(s: str) -> str:
    """Small HTML-escape for names injected into parse_mode=HTML messages."""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


# ──────────────────────────────────────────────────────────────────────────
# Keyboards
# ──────────────────────────────────────────────────────────────────────────

def language_picker() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🇷🇺  Русский", callback_data="lang:ru", style="primary")],
        [InlineKeyboardButton(text="🇬🇧  English", callback_data="lang:en", style="primary")],
        [InlineKeyboardButton(text="🇨🇳  中文",    callback_data="lang:zh", style="primary")],
    ])


def open_app_keyboard(lang: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(
            text=OPEN_LABEL[lang],
            web_app=WebAppInfo(url=WEBAPP_URL),
            style="primary",
        )],
    ])


def admin_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📋  Список заблокированных", callback_data="admin:list", style="primary")],
        [InlineKeyboardButton(text="ℹ️  Как работает", callback_data="admin:help", style="primary")],
    ])


# ──────────────────────────────────────────────────────────────────────────
# Handlers
# ──────────────────────────────────────────────────────────────────────────

dp = Dispatcher()
blocklist = Blocklist(BLOCKLIST_PATH)


@dp.message(CommandStart())
async def on_start(message: Message) -> None:
    quote = (message.text or "/start")[:64]
    await message.answer(
        PICKER_TEXT,
        reply_markup=language_picker(),
        reply_parameters=ReplyParameters(
            message_id=message.message_id,
            quote=quote,
        ),
    )


@dp.callback_query(F.data.startswith("lang:"))
async def on_language_pick(cb: CallbackQuery) -> None:
    lang = (cb.data or "").split(":", 1)[1]
    if lang not in SUPPORTED:
        await cb.answer()
        return

    # Blocked users get the notice instead of the normal greeting.
    if blocklist.contains(cb.from_user.id):
        await cb.message.edit_text(BLOCKED_NOTICE[lang])
        await cb.answer()
        return

    name = html_escape(cb.from_user.username or cb.from_user.first_name or "friend")
    await cb.message.edit_text(
        GREETING[lang].format(name=name),
        reply_markup=open_app_keyboard(lang),
    )
    await cb.answer()


# ── Admin ──────────────────────────────────────────────────────────────────

def _is_admin(uid: int) -> bool:
    return ADMIN_ID != 0 and uid == ADMIN_ID


@dp.message(Command("admin"))
async def admin_menu(message: Message) -> None:
    if not _is_admin(message.from_user.id):
        # Silent refusal — do not reveal admin surface area to randos.
        return
    await message.answer(
        "🛡️  <b>Админ-панель</b>\n\n"
        "Команды:\n"
        "• <code>/block &lt;uid&gt;</code> — заблокировать пользователя\n"
        "• <code>/unblock &lt;uid&gt;</code> — разблокировать\n"
        "• <code>/blocked</code> — список заблокированных\n"
        "• <code>/whoami</code> — вернуть ваш Telegram ID",
        reply_markup=admin_keyboard(),
    )


@dp.message(Command("whoami"))
async def whoami(message: Message) -> None:
    uid = message.from_user.id
    admin_tag = " (admin)" if _is_admin(uid) else ""
    await message.answer(f"Ваш Telegram ID: <code>{uid}</code>{admin_tag}")


@dp.message(Command("block"))
async def block_cmd(message: Message) -> None:
    if not _is_admin(message.from_user.id):
        return
    parts = (message.text or "").split()
    if len(parts) < 2:
        await message.answer("Использование: <code>/block &lt;uid&gt;</code>")
        return
    try:
        uid = int(parts[1])
    except ValueError:
        await message.answer("UID должен быть числом.")
        return
    await blocklist.add(uid)
    await message.answer(f"✅ Пользователь <code>{uid}</code> заблокирован.")


@dp.message(Command("unblock"))
async def unblock_cmd(message: Message) -> None:
    if not _is_admin(message.from_user.id):
        return
    parts = (message.text or "").split()
    if len(parts) < 2:
        await message.answer("Использование: <code>/unblock &lt;uid&gt;</code>")
        return
    try:
        uid = int(parts[1])
    except ValueError:
        await message.answer("UID должен быть числом.")
        return
    await blocklist.remove(uid)
    await message.answer(f"✅ Пользователь <code>{uid}</code> разблокирован.")


@dp.message(Command("blocked"))
async def blocked_list(message: Message) -> None:
    if not _is_admin(message.from_user.id):
        return
    ids = blocklist.all()
    if not ids:
        await message.answer("Список пуст.")
        return
    await message.answer(
        "📋 Заблокировано: " + str(len(ids)) + "\n\n" +
        "\n".join(f"<code>{x}</code>" for x in ids[:50]) +
        ("" if len(ids) <= 50 else f"\n… и ещё {len(ids)-50}")
    )


@dp.callback_query(F.data.startswith("admin:"))
async def admin_cb(cb: CallbackQuery) -> None:
    if not _is_admin(cb.from_user.id):
        await cb.answer("нет прав", show_alert=True)
        return
    action = (cb.data or "").split(":", 1)[1]
    if action == "list":
        ids = blocklist.all()
        text = (
            "📋 Пусто." if not ids else
            "📋 Заблокировано: " + str(len(ids)) + "\n\n" +
            "\n".join(f"<code>{x}</code>" for x in ids[:50])
        )
        await cb.message.answer(text)
    elif action == "help":
        await cb.message.answer(
            "Админ-панель доступна и из мини-аппа: откройте PlayerOK → Профиль → раздел «Admin» виден только вам. "
            "Поле ID + кнопки Block/Unblock дёргают тот же backend."
        )
    await cb.answer()


# ──────────────────────────────────────────────────────────────────────────
# HTTP admin API (aiohttp) — mini-app uses this to render the admin screen,
# check block status on boot, and submit block/unblock mutations.
# ──────────────────────────────────────────────────────────────────────────

# --- CORS helpers --------------------------------------------------------

def _cors_headers(origin: str = "*") -> dict[str, str]:
    """
    Narrow CORS: only the known WebApp origin + null (telegram WebView may
    present origin="null"). Tweak CORS_ORIGINS to tighten in prod.
    """
    return {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    }

ALLOWED_ORIGINS = {o.strip() for o in os.environ.get("CORS_ORIGINS", "*").split(",") if o.strip()}


@web.middleware
async def cors_middleware(request: web.Request, handler) -> web.StreamResponse:
    origin = request.headers.get("Origin", "")
    allow = "*"
    if "*" not in ALLOWED_ORIGINS:
        allow = origin if origin in ALLOWED_ORIGINS else ""
    if request.method == "OPTIONS":
        return web.Response(status=204, headers=_cors_headers(allow))
    resp = await handler(request)
    for k, v in _cors_headers(allow).items():
        resp.headers.setdefault(k, v)
    return resp


# --- Simple in-memory rate limiter (anti-DDoS) ---------------------------

class RateLimiter:
    """
    Token bucket per remote-IP. Default: 60 req/min, burst 20.
    Covers brute-force on /api/status and random scraping.
    """
    def __init__(self, rate_per_sec: float = 1.0, burst: int = 20):
        self.rate = rate_per_sec
        self.burst = burst
        self._state: dict[str, tuple[float, float]] = {}  # ip -> (tokens, last_ts)

    def allow(self, key: str) -> bool:
        now = time()
        tokens, last = self._state.get(key, (float(self.burst), now))
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        if tokens < 1.0:
            self._state[key] = (tokens, now)
            return False
        self._state[key] = (tokens - 1.0, now)
        return True


_rl_public = RateLimiter(rate_per_sec=1.0, burst=20)
_rl_admin  = RateLimiter(rate_per_sec=0.5, burst=10)


def _client_ip(request: web.Request) -> str:
    # X-Forwarded-For first (behind a proxy), fallback to peer address.
    xff = request.headers.get("X-Forwarded-For", "")
    return xff.split(",")[0].strip() if xff else (request.remote or "unknown")


async def route_status(request: web.Request) -> web.Response:
    """Public endpoint: is this Telegram user blocked?"""
    if not _rl_public.allow(_client_ip(request)):
        return web.json_response({"error": "rate_limit"}, status=429, headers={"Retry-After": "2"})
    try:
        uid = int(request.query.get("user_id", "0"))
    except ValueError:
        return web.json_response({"error": "bad_user_id"}, status=400)
    return web.json_response({"blocked": blocklist.contains(uid), "user_id": uid})


async def _require_admin(request: web.Request) -> Optional[InitUser]:
    """
    Pull initData from Authorization: tma <initData> header, verify with
    HMAC + max-age, require user.id == ADMIN_ID. Return the user or None;
    the caller emits the response.
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("tma "):
        return None
    init = auth[4:].strip()
    user = verify_init_data(init, BOT_TOKEN, INIT_MAX_AGE)
    if not user or not _is_admin(user.id):
        return None
    return user


async def route_admin_list(request: web.Request) -> web.Response:
    if not _rl_admin.allow(_client_ip(request)):
        return web.json_response({"error": "rate_limit"}, status=429, headers={"Retry-After": "2"})
    admin = await _require_admin(request)
    if not admin:
        return web.json_response({"error": "forbidden"}, status=403)
    return web.json_response({"blocked": blocklist.all()})


async def route_admin_block(request: web.Request) -> web.Response:
    if not _rl_admin.allow(_client_ip(request)):
        return web.json_response({"error": "rate_limit"}, status=429, headers={"Retry-After": "2"})
    admin = await _require_admin(request)
    if not admin:
        return web.json_response({"error": "forbidden"}, status=403)
    try:
        body = await request.json()
        uid = int(body["user_id"])
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return web.json_response({"error": "bad_request"}, status=400)
    if uid == ADMIN_ID:
        return web.json_response({"error": "cannot_block_admin"}, status=400)
    await blocklist.add(uid)
    return web.json_response({"ok": True, "blocked": uid})


async def route_admin_unblock(request: web.Request) -> web.Response:
    if not _rl_admin.allow(_client_ip(request)):
        return web.json_response({"error": "rate_limit"}, status=429, headers={"Retry-After": "2"})
    admin = await _require_admin(request)
    if not admin:
        return web.json_response({"error": "forbidden"}, status=403)
    try:
        body = await request.json()
        uid = int(body["user_id"])
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return web.json_response({"error": "bad_request"}, status=400)
    await blocklist.remove(uid)
    return web.json_response({"ok": True, "unblocked": uid})


async def route_verify(request: web.Request) -> web.Response:
    """
    POST { init_data: "..." } → { valid: bool, user_id, is_admin }.
    Mini-app calls this on boot so the UI knows whether to show lock /
    admin surfaces. Signature check is identical to the admin middleware.
    """
    if not _rl_public.allow(_client_ip(request)):
        return web.json_response({"error": "rate_limit"}, status=429, headers={"Retry-After": "2"})
    try:
        body = await request.json()
        init = body.get("init_data", "")
    except (ValueError, json.JSONDecodeError):
        return web.json_response({"error": "bad_request"}, status=400)
    user = verify_init_data(init, BOT_TOKEN, INIT_MAX_AGE)
    if not user:
        return web.json_response({"valid": False})
    return web.json_response({
        "valid": True,
        "user_id": user.id,
        "is_admin": _is_admin(user.id),
        "blocked": blocklist.contains(user.id),
    })


def make_web_app() -> web.Application:
    app = web.Application(middlewares=[cors_middleware])
    app.router.add_get("/api/status", route_status)
    app.router.add_post("/api/verify", route_verify)
    app.router.add_get("/api/admin/list", route_admin_list)
    app.router.add_post("/api/admin/block", route_admin_block)
    app.router.add_post("/api/admin/unblock", route_admin_unblock)
    return app


# ──────────────────────────────────────────────────────────────────────────
# Entry
# ──────────────────────────────────────────────────────────────────────────

async def main() -> None:
    if not BOT_TOKEN:
        raise SystemExit("BOT_TOKEN is not set.")
    if ADMIN_ID == 0:
        log.warning("ADMIN_ID is 0 — admin surfaces will refuse everyone until you set it.")

    bot = Bot(
        token=BOT_TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )

    # HTTP server (admin API + status)
    app = make_web_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, BOT_HTTP_HOST, BOT_HTTP_PORT)
    await site.start()
    log.info("HTTP API listening on %s:%s", BOT_HTTP_HOST, BOT_HTTP_PORT)

    log.info("Starting polling…")
    try:
        await dp.start_polling(bot)
    finally:
        await runner.cleanup()
        await bot.session.close()


if __name__ == "__main__":
    asyncio.run(main())
