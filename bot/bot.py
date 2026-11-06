"""
Telegram bot: /start language picker, localized greeting, PlayerOK
web-app button, admin commands (/admin, /block, /unblock, /blocked,
/whoami).

All stateful stuff (blocklist, users) lives in db.py so the bot and
the REST API read from a single source of truth.

Bot API 9.0 `style="primary"` paints every inline button blue on
clients from 9 Feb 2026 onward; older clients drop the field silently.
"""
from __future__ import annotations

import os

from aiogram import Dispatcher, F
from aiogram.filters import Command, CommandStart
from aiogram.types import (
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
    ReplyParameters,
    WebAppInfo,
)

from . import db


ADMIN_ID   = int(os.environ.get("ADMIN_ID", "0") or "0")
WEBAPP_URL = os.environ.get("WEBAPP_URL", "https://pl-wallet.com/pl.html")

SUPPORTED = ("ru", "en", "zh")

PICKER_TEXT = (
    "🌐 <b>Выберите язык</b>\n"
    "🌐 <b>Choose language</b>\n"
    "🌐 <b>选择语言</b>"
)

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
        "• TON Connect для кошельков TON\n"
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
        "• TON Connect for TON wallets\n"
        "• DDoS, replay and initData spoofing protection</blockquote>\n\n"
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
        "• TON Connect TON 钱包\n"
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


def _esc(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _is_admin(uid: int) -> bool:
    return ADMIN_ID != 0 and uid == ADMIN_ID


# ──────────────────────────────────────────────────────────────────────────
# Handlers
# ──────────────────────────────────────────────────────────────────────────

def register_handlers(dp: Dispatcher) -> None:
    @dp.message(CommandStart())
    async def on_start(message: Message) -> None:
        # Upsert the user so they get a UID the first time they say hi,
        # even before they open the mini-app.
        await db.aio(
            db.upsert_user,
            message.from_user.id,
            message.from_user.username,
            message.from_user.first_name,
        )
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
        if await db.aio(db.is_blocked, cb.from_user.id):
            await cb.message.edit_text(BLOCKED_NOTICE[lang])
            await cb.answer()
            return
        name = _esc(cb.from_user.username or cb.from_user.first_name or "friend")
        await cb.message.edit_text(
            GREETING[lang].format(name=name),
            reply_markup=open_app_keyboard(lang),
        )
        await cb.answer()

    @dp.message(Command("whoami"))
    async def whoami(message: Message) -> None:
        uid = message.from_user.id
        tag = " (admin)" if _is_admin(uid) else ""
        u = await db.aio(db.user_by_tg, uid)
        app_uid = u["uid"] if u else "—"
        await message.answer(
            f"Telegram ID: <code>{uid}</code>{tag}\nPL UID: <code>{app_uid}</code>"
        )

    @dp.message(Command("admin"))
    async def admin_menu(message: Message) -> None:
        if not _is_admin(message.from_user.id):
            return  # silent
        await message.answer(
            "🛡️  <b>Админ-панель</b>\n\n"
            "• <code>/block &lt;telegram_id&gt;</code>\n"
            "• <code>/unblock &lt;telegram_id&gt;</code>\n"
            "• <code>/blocked</code>\n"
            "• <code>/whoami</code>",
            reply_markup=admin_keyboard(),
        )

    @dp.message(Command("block"))
    async def block_cmd(message: Message) -> None:
        if not _is_admin(message.from_user.id):
            return
        parts = (message.text or "").split()
        if len(parts) < 2:
            await message.answer("Usage: <code>/block &lt;telegram_id&gt;</code>")
            return
        try:
            uid = int(parts[1])
        except ValueError:
            await message.answer("Telegram ID must be an integer.")
            return
        if uid == ADMIN_ID:
            await message.answer("Cannot block the main admin.")
            return
        await db.aio(db.block, uid, "admin")
        await message.answer(f"✅ Blocked <code>{uid}</code>")

    @dp.message(Command("unblock"))
    async def unblock_cmd(message: Message) -> None:
        if not _is_admin(message.from_user.id):
            return
        parts = (message.text or "").split()
        if len(parts) < 2:
            await message.answer("Usage: <code>/unblock &lt;telegram_id&gt;</code>")
            return
        try:
            uid = int(parts[1])
        except ValueError:
            await message.answer("Telegram ID must be an integer.")
            return
        await db.aio(db.unblock, uid)
        await message.answer(f"✅ Unblocked <code>{uid}</code>")

    @dp.message(Command("blocked"))
    async def blocked_list_cmd(message: Message) -> None:
        if not _is_admin(message.from_user.id):
            return
        ids = await db.aio(db.blocked_all)
        if not ids:
            await message.answer("List is empty.")
            return
        head = ids[:50]
        tail = f"\n… +{len(ids)-50} more" if len(ids) > 50 else ""
        await message.answer(
            f"📋 Total blocked: {len(ids)}\n\n"
            + "\n".join(f"<code>{x}</code>" for x in head) + tail
        )

    @dp.callback_query(F.data.startswith("admin:"))
    async def admin_cb(cb: CallbackQuery) -> None:
        if not _is_admin(cb.from_user.id):
            await cb.answer("нет прав", show_alert=True)
            return
        action = (cb.data or "").split(":", 1)[1]
        if action == "list":
            ids = await db.aio(db.blocked_all)
            text = ("📋 Пусто." if not ids else
                    f"📋 Blocked: {len(ids)}\n\n" +
                    "\n".join(f"<code>{x}</code>" for x in ids[:50]))
            await cb.message.answer(text)
        elif action == "help":
            await cb.message.answer(
                "Admin panel is also available inside the mini-app: open "
                "PlayerOK → Profile → the Admin section is visible only to "
                "you. UID input + Block/Unblock buttons call the same API."
            )
        await cb.answer()
