"""
PL Wallet Telegram bot — language picker + greeting + WebApp entry.

Button-color note (Bot API 9.0+, confirmed Nov 2026):
    InlineKeyboardButton has an optional `style` field. Accepted values
    are "primary" (blue), "success" (green) and "danger" (red); omitting
    it falls back to the client's default accent. The `style` field was
    added in Bot API 9.0 and renders colored only on Telegram client
    builds dated 9 Feb 2026 or later — older clients just ignore it and
    draw the standard accent button, so sending it is backwards-safe.

    Every inline button in this bot therefore ships with style="primary"
    so they render in the Telegram blue the user asked for. The
    PlayerOK button inside the opened Mini App is additionally styled
    from within pl.html via Telegram.WebApp.MainButton.color (set to
    PL-blue #2563EB).

Run:
    pip install -r requirements.txt
    export BOT_TOKEN="<from @BotFather>"
    export WEBAPP_URL="https://pathfys.github.io/wallet/pl.html"
    python bot.py
"""

from __future__ import annotations

import asyncio
import logging
import os

from aiogram import Bot, Dispatcher, F
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import CommandStart
from aiogram.types import (
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
    ReplyParameters,
    WebAppInfo,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("pl-bot")


# ──────────────────────────────────────────────────────────────────────────
# Localization
# ──────────────────────────────────────────────────────────────────────────

SUPPORTED = ("ru", "en", "zh")

PICKER_TEXT = (
    "🌐 <b>Выберите язык</b>\n"
    "🌐 <b>Choose language</b>\n"
    "🌐 <b>选择语言</b>"
)

GREETING = {
    "ru": (
        "👋 Привет, <b>{name}</b>!\n\n"
        "Это <b>PL Wallet</b> — твой кошелёк внутри Telegram. "
        "Торгуй P2P, принимай и отправляй крипту/фиат прямо в чате, "
        "а комиссия эскроу ниже рынка.\n\n"
        "Нажми кнопку ниже, чтобы открыть приложение."
    ),
    "en": (
        "👋 Hi <b>{name}</b>!\n\n"
        "This is <b>PL Wallet</b> — your in-Telegram wallet. "
        "Trade P2P, receive and send crypto/fiat right in the chat, "
        "with escrow fees below the market.\n\n"
        "Tap the button below to open the app."
    ),
    "zh": (
        "👋 您好，<b>{name}</b>！\n\n"
        "这是 <b>PL 钱包</b> —— 您在 Telegram 内的钱包。"
        "直接在聊天中进行 P2P 交易、接收和发送加密货币与法币，"
        "托管手续费低于市场价。\n\n"
        "点击下方按钮打开应用。"
    ),
}

OPEN_LABEL = {
    "ru": "Открыть PlayerOK",
    "en": "Open PlayerOK",
    "zh": "打开 PlayerOK",
}


# ──────────────────────────────────────────────────────────────────────────
# Keyboards
# ──────────────────────────────────────────────────────────────────────────

def language_picker() -> InlineKeyboardMarkup:
    """
    3 language options as inline buttons, all painted BLUE via
    style="primary" (Bot API 9.0+). Older client builds ignore the field
    and draw the regular accent button, so this is backwards-safe.
    """
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🇷🇺  Русский", callback_data="lang:ru", style="primary")],
        [InlineKeyboardButton(text="🇬🇧  English", callback_data="lang:en", style="primary")],
        [InlineKeyboardButton(text="🇨🇳  中文",    callback_data="lang:zh", style="primary")],
    ])


def open_app_keyboard(webapp_url: str, lang: str) -> InlineKeyboardMarkup:
    """
    Single web_app button that launches pl.html as a Telegram Mini App.
    style="primary" paints it blue; inside the Mini App, our own
    MainButton.color (#2563EB) picks up the thread.
    """
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(
            text=OPEN_LABEL[lang],
            web_app=WebAppInfo(url=webapp_url),
            style="primary",
        )],
    ])


# ──────────────────────────────────────────────────────────────────────────
# Handlers
# ──────────────────────────────────────────────────────────────────────────

dp = Dispatcher()


@dp.message(CommandStart())
async def on_start(message: Message) -> None:
    """
    Reply to /start with the language picker. Uses reply_parameters so
    the client shows the user's own `/start` message quoted above our
    reply (that's "с цитированием" = "with quoting").
    """
    quote = (message.text or "/start")[:64]  # Telegram caps quote length
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
    """
    User tapped one of the language buttons. Edit the previous message
    in place so the picker becomes the localized greeting + PlayerOK
    button — this keeps the chat tidy (one message, one bubble).
    """
    lang = cb.data.split(":", 1)[1] if cb.data else ""
    if lang not in SUPPORTED:
        await cb.answer()
        return

    # Prefer username → first_name → fallback. Escape HTML to stop a
    # crafted first_name from hijacking our parse_mode=HTML formatting.
    raw_name = cb.from_user.username or cb.from_user.first_name or "friend"
    name = (
        raw_name
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )

    webapp_url = os.environ.get("WEBAPP_URL", "https://pathfys.github.io/wallet/pl.html")

    await cb.message.edit_text(
        GREETING[lang].format(name=name),
        reply_markup=open_app_keyboard(webapp_url, lang),
    )
    # Dismisses the little spinner on the tapped button; no toast.
    await cb.answer()


# ──────────────────────────────────────────────────────────────────────────
# Entry
# ──────────────────────────────────────────────────────────────────────────

async def main() -> None:
    token = os.environ.get("BOT_TOKEN")
    if not token:
        raise SystemExit("BOT_TOKEN is not set. Export it or put it in your shell env.")

    bot = Bot(
        token=token,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )
    log.info("Starting polling…")
    try:
        await dp.start_polling(bot)
    finally:
        await bot.session.close()


if __name__ == "__main__":
    asyncio.run(main())
