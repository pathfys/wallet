"""
Entry point: runs the Telegram bot (polling) and the REST API (aiohttp)
on the same asyncio loop.

Deploy in one line:
    pip install -r requirements.txt
    export BOT_TOKEN=...   ADMIN_ID=...   WEBAPP_URL=https://pl-wallet.com/pl.html
    python -m bot.main

Serve it behind nginx at api.pl-wallet.com (config in deploy/nginx.conf).
"""
from __future__ import annotations

import asyncio
import logging
import os

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiohttp import web

from . import api, db
from .bot import register_handlers

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("pl")


BOT_TOKEN     = os.environ.get("BOT_TOKEN", "")
BOT_HTTP_HOST = os.environ.get("BOT_HTTP_HOST", "0.0.0.0")
BOT_HTTP_PORT = int(os.environ.get("BOT_HTTP_PORT", "8080"))


async def main() -> None:
    if not BOT_TOKEN:
        raise SystemExit("BOT_TOKEN is not set.")

    db.init_db()
    log.info("DB initialized at %s", db.DB_PATH)

    dp = Dispatcher()
    register_handlers(dp)

    bot = Bot(
        token=BOT_TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )

    # HTTP API
    app = api.make_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, BOT_HTTP_HOST, BOT_HTTP_PORT)
    await site.start()
    log.info("API listening on %s:%s", BOT_HTTP_HOST, BOT_HTTP_PORT)

    # Telegram polling in parallel
    try:
        await dp.start_polling(bot)
    finally:
        await runner.cleanup()
        await bot.session.close()


if __name__ == "__main__":
    asyncio.run(main())
