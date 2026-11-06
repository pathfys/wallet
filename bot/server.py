"""
PL Wallet — self-contained backend (Telegram bot + REST API + SQLite).

One file to deploy. Everything inside: schema, initData verification,
the aiogram handlers, the aiohttp routes, and the main asyncio entry.

Run:
    pip install 'aiogram>=3.29,<4' 'aiohttp>=3.9'
    export BOT_TOKEN="<from @BotFather>"
    export ADMIN_ID="<your Telegram id>"
    export WEBAPP_URL="https://pl-wallet.com/pl.html"
    python server.py

Env vars (all optional except BOT_TOKEN):
    BOT_TOKEN, ADMIN_ID, WEBAPP_URL
    BOT_HTTP_HOST (default 0.0.0.0)
    BOT_HTTP_PORT (default 8080)
    DB_PATH       (default data.db)
    INIT_MAX_AGE  (default 300 seconds — initData replay window)
    CORS_ORIGINS  (comma-separated; default:
                   https://pl-wallet.com,https://www.pl-wallet.com,null)
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import random
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from functools import wraps
from pathlib import Path
from time import time as now_s
from typing import Any, Callable, Iterator, Optional
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
log = logging.getLogger("pl")


# ═══════════════════════════════════════════════════════════════════════════
# Config
# ═══════════════════════════════════════════════════════════════════════════

BOT_TOKEN      = os.environ.get("BOT_TOKEN", "")
ADMIN_ID       = int(os.environ.get("ADMIN_ID", "0") or "0")
WEBAPP_URL     = os.environ.get("WEBAPP_URL", "https://pl-wallet.com/pl.html")
BOT_HTTP_HOST  = os.environ.get("BOT_HTTP_HOST", "0.0.0.0")
BOT_HTTP_PORT  = int(os.environ.get("BOT_HTTP_PORT", "8080"))
DB_PATH        = Path(os.environ.get("DB_PATH", "data.db"))
INIT_MAX_AGE   = int(os.environ.get("INIT_MAX_AGE", "300"))
ALLOWED_ORIGINS = {
    o.strip() for o in os.environ.get(
        "CORS_ORIGINS", "https://pl-wallet.com,https://www.pl-wallet.com,null"
    ).split(",") if o.strip()
}
MAX_MSG_LEN  = 1000
MAX_LINKS    = 10
MAX_LINK_LEN = 500


# ═══════════════════════════════════════════════════════════════════════════
# SQLite — schema + repository
# ═══════════════════════════════════════════════════════════════════════════

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous  = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  telegram_id INTEGER NOT NULL UNIQUE,
  uid INTEGER NOT NULL UNIQUE,
  username TEXT,
  first_name TEXT,
  status TEXT NOT NULL DEFAULT 'Beginner',
  total_deals INTEGER NOT NULL DEFAULT 0,
  successful_deals INTEGER NOT NULL DEFAULT 0,
  cancelled_deals INTEGER NOT NULL DEFAULT 0,
  disputed_deals INTEGER NOT NULL DEFAULT 0,
  activity_pct INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS wallets (
  user_id INTEGER NOT NULL,
  currency TEXT NOT NULL,
  address TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, currency),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS balances (
  user_id INTEGER NOT NULL,
  currency TEXT NOT NULL,
  balance REAL NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, currency),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS deals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  initiator_id INTEGER NOT NULL,
  buyer_id INTEGER,
  seller_id INTEGER,
  crypto_amount REAL NOT NULL DEFAULT 0,
  crypto_currency TEXT NOT NULL DEFAULT '',
  fiat_amount REAL NOT NULL DEFAULT 0,
  fiat_currency TEXT NOT NULL DEFAULT '',
  links TEXT NOT NULL DEFAULT '',
  gift_name TEXT,
  status TEXT NOT NULL DEFAULT 'awaiting_acceptance',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY (initiator_id) REFERENCES users(id),
  FOREIGN KEY (buyer_id)  REFERENCES users(id),
  FOREIGN KEY (seller_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_deals_buyer     ON deals(buyer_id);
CREATE INDEX IF NOT EXISTS idx_deals_seller    ON deals(seller_id);
CREATE INDEX IF NOT EXISTS idx_deals_initiator ON deals(initiator_id);
CREATE INDEX IF NOT EXISTS idx_deals_status    ON deals(status);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  deal_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  text TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (deal_id) REFERENCES deals(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_msg_deal ON messages(deal_id, id);

CREATE TABLE IF NOT EXISTS blocklist (
  user_id INTEGER PRIMARY KEY,
  blocked_at INTEGER NOT NULL,
  reason TEXT
);
"""

VALID_STATUSES = {
    "awaiting_acceptance", "awaiting_payment", "paid",
    "payment_confirmed", "goods_sent", "completed",
    "cancelled", "disputed",
}


@contextmanager
def _conn() -> Iterator[sqlite3.Connection]:
    c = sqlite3.connect(DB_PATH, isolation_level=None)  # autocommit
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON")
    try:
        yield c
    finally:
        c.close()


def db_init() -> None:
    with _conn() as c:
        c.executescript(SCHEMA)


def _row(r: sqlite3.Row | None) -> Optional[dict[str, Any]]:
    return dict(r) if r is not None else None


# ── Users ────────────────────────────────────────────────────────────────

def _fresh_uid(c: sqlite3.Connection) -> int:
    for _ in range(10):
        candidate = random.randint(10_000_000, 99_999_999)
        if not c.execute("SELECT 1 FROM users WHERE uid = ?", (candidate,)).fetchone():
            return candidate
    raise RuntimeError("UID pool exhausted")


def upsert_user(telegram_id: int, username: str | None, first_name: str | None) -> dict[str, Any]:
    with _conn() as c:
        row = c.execute("SELECT * FROM users WHERE telegram_id = ?", (telegram_id,)).fetchone()
        if row:
            c.execute(
                "UPDATE users SET username = ?, first_name = ? WHERE telegram_id = ?",
                (username, first_name, telegram_id),
            )
            return _row(c.execute(
                "SELECT * FROM users WHERE telegram_id = ?", (telegram_id,)).fetchone())  # type: ignore[return-value]
        c.execute(
            "INSERT INTO users (telegram_id, uid, username, first_name, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (telegram_id, _fresh_uid(c), username, first_name, int(now_s())),
        )
        return _row(c.execute(
            "SELECT * FROM users WHERE telegram_id = ?", (telegram_id,)).fetchone())  # type: ignore[return-value]


def user_by_tg(telegram_id: int) -> Optional[dict[str, Any]]:
    with _conn() as c:
        return _row(c.execute("SELECT * FROM users WHERE telegram_id = ?", (telegram_id,)).fetchone())


def bump_user_stats(user_id: int, successful: int = 0, cancelled: int = 0, disputed: int = 0) -> None:
    with _conn() as c:
        c.execute(
            "UPDATE users SET "
            " total_deals      = total_deals      + ?, "
            " successful_deals = successful_deals + ?, "
            " cancelled_deals  = cancelled_deals  + ?, "
            " disputed_deals   = disputed_deals   + ? "
            "WHERE id = ?",
            (successful + cancelled + disputed, successful, cancelled, disputed, user_id),
        )


# ── Wallets / balances ───────────────────────────────────────────────────

def save_wallet(user_id: int, currency: str, address: str) -> None:
    with _conn() as c:
        c.execute(
            "INSERT INTO wallets (user_id, currency, address, updated_at) "
            "VALUES (?, ?, ?, strftime('%s','now')) "
            "ON CONFLICT(user_id, currency) DO UPDATE SET "
            " address = excluded.address, updated_at = excluded.updated_at",
            (user_id, currency, address),
        )


def delete_wallet(user_id: int, currency: str) -> None:
    with _conn() as c:
        c.execute("DELETE FROM wallets WHERE user_id = ? AND currency = ?", (user_id, currency))


def wallets_of(user_id: int) -> dict[str, str]:
    with _conn() as c:
        rows = c.execute("SELECT currency, address FROM wallets WHERE user_id = ?", (user_id,)).fetchall()
    return {r["currency"]: r["address"] for r in rows}


def balances_of(user_id: int) -> list[dict[str, Any]]:
    with _conn() as c:
        rows = c.execute("SELECT currency, balance FROM balances WHERE user_id = ?", (user_id,)).fetchall()
    return [dict(r) for r in rows]


# ── Deals ────────────────────────────────────────────────────────────────

def deal_with_parties(deal_id: int) -> Optional[dict[str, Any]]:
    """Return the deal with buyer/seller/initiator user objects attached."""
    with _conn() as c:
        row = c.execute("SELECT * FROM deals WHERE id = ?", (deal_id,)).fetchone()
        if not row:
            return None
        deal = dict(row)
        for slot in ("initiator_id", "buyer_id", "seller_id"):
            uid = deal.get(slot)
            key = slot.replace("_id", "")
            if uid is None:
                deal[key] = None
                continue
            u = c.execute(
                "SELECT uid, username, first_name, status FROM users WHERE id = ?", (uid,)
            ).fetchone()
            deal[key] = dict(u) if u else None
        return deal


def create_direct_deal(
    initiator_id: int,
    role: str,                     # "buyer" | "seller"
    currency: str,
    amount: float,
    links: list[str],
) -> dict[str, Any]:
    if role not in ("buyer", "seller"):
        raise ValueError("role must be 'buyer' or 'seller'")
    buyer  = initiator_id if role == "buyer"  else None
    seller = initiator_id if role == "seller" else None
    links_blob = "\n".join(l.strip() for l in links if l and l.strip())
    now = int(now_s())
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO deals (initiator_id, buyer_id, seller_id, "
            " fiat_amount, fiat_currency, links, status, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, 'awaiting_acceptance', ?, ?)",
            (initiator_id, buyer, seller, float(amount), currency, links_blob, now, now),
        )
        return deal_with_parties(cur.lastrowid)  # type: ignore[return-value]


def assign_counterparty(deal_id: int, user_id: int) -> Optional[dict[str, Any]]:
    """When a stranger opens the deal link, slot them into the empty side."""
    with _conn() as c:
        row = c.execute("SELECT * FROM deals WHERE id = ?", (deal_id,)).fetchone()
        if not row:
            return None
        if user_id in (row["buyer_id"], row["seller_id"], row["initiator_id"]):
            return deal_with_parties(deal_id)
        if row["status"] != "awaiting_acceptance":
            return None
        if row["buyer_id"] is None:
            c.execute("UPDATE deals SET buyer_id = ?, updated_at = ? WHERE id = ?",
                      (user_id, int(now_s()), deal_id))
        elif row["seller_id"] is None:
            c.execute("UPDATE deals SET seller_id = ?, updated_at = ? WHERE id = ?",
                      (user_id, int(now_s()), deal_id))
        else:
            return None
    return deal_with_parties(deal_id)


def deals_for(user_id: int) -> list[dict[str, Any]]:
    with _conn() as c:
        rows = c.execute(
            "SELECT id FROM deals WHERE initiator_id = ? OR buyer_id = ? OR seller_id = ? "
            "ORDER BY updated_at DESC LIMIT 200",
            (user_id, user_id, user_id),
        ).fetchall()
    return [deal_with_parties(r["id"]) or {} for r in rows]


def update_deal_status(deal_id: int, new_status: str) -> None:
    if new_status not in VALID_STATUSES:
        raise ValueError(f"bad status: {new_status}")
    with _conn() as c:
        c.execute(
            "UPDATE deals SET status = ?, updated_at = ? WHERE id = ?",
            (new_status, int(now_s()), deal_id),
        )


# ── Messages ─────────────────────────────────────────────────────────────

def add_message(deal_id: int, user_id: int, text: str) -> dict[str, Any]:
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO messages (deal_id, user_id, text, created_at) VALUES (?, ?, ?, ?)",
            (deal_id, user_id, text, int(now_s())),
        )
        return dict(c.execute("SELECT * FROM messages WHERE id = ?", (cur.lastrowid,)).fetchone())


def messages_of(deal_id: int, limit: int = 200) -> list[dict[str, Any]]:
    with _conn() as c:
        rows = c.execute(
            "SELECT m.id, m.deal_id, m.user_id, m.text, m.created_at, "
            " u.username, u.first_name, u.uid "
            "FROM messages m JOIN users u ON u.id = m.user_id "
            "WHERE m.deal_id = ? ORDER BY m.id ASC LIMIT ?",
            (deal_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]


# ── Blocklist ────────────────────────────────────────────────────────────

def block(user_tg_id: int, reason: str | None = None) -> None:
    with _conn() as c:
        c.execute(
            "INSERT INTO blocklist (user_id, blocked_at, reason) VALUES (?, ?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET "
            " blocked_at = excluded.blocked_at, reason = excluded.reason",
            (user_tg_id, int(now_s()), reason),
        )


def unblock(user_tg_id: int) -> None:
    with _conn() as c:
        c.execute("DELETE FROM blocklist WHERE user_id = ?", (user_tg_id,))


def is_blocked(user_tg_id: int) -> bool:
    with _conn() as c:
        return c.execute("SELECT 1 FROM blocklist WHERE user_id = ?", (user_tg_id,)).fetchone() is not None


def blocked_all() -> list[int]:
    with _conn() as c:
        rows = c.execute("SELECT user_id FROM blocklist ORDER BY blocked_at DESC").fetchall()
    return [r["user_id"] for r in rows]


# Async wrappers — handlers call these so disk I/O doesn't block the loop.
async def aio(fn: Callable, *args, **kwargs):
    return await asyncio.to_thread(fn, *args, **kwargs)


# ═══════════════════════════════════════════════════════════════════════════
# initData verification
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class InitUser:
    id: int
    username: Optional[str]
    first_name: Optional[str]
    language_code: Optional[str]


def verify_init_data(init_data: str, bot_token: str, max_age: int = INIT_MAX_AGE) -> Optional[InitUser]:
    """
    Official Telegram WebApp HMAC check + max-age replay guard.
      secret_key = HMAC_SHA256("WebAppData", bot_token)
      expected   = HMAC_SHA256(secret_key, "\n".join(sorted "k=v" except "hash"))
    """
    if not init_data or not bot_token:
        return None
    try:
        pairs = dict(parse_qsl(init_data, keep_blank_values=True, strict_parsing=True))
    except ValueError:
        return None
    received = pairs.pop("hash", None)
    if not received:
        return None
    data_check = "\n".join(f"{k}={pairs[k]}" for k in sorted(pairs))
    secret = hmac.new(b"WebAppData", bot_token.encode(), hashlib.sha256).digest()
    computed = hmac.new(secret, data_check.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(computed, received):
        return None
    try:
        auth_date = int(pairs.get("auth_date", "0"))
    except ValueError:
        return None
    if max_age > 0 and (now_s() - auth_date) > max_age:
        return None
    raw_user = pairs.get("user", "")
    if not raw_user:
        return None
    try:
        u = json.loads(raw_user)
    except ValueError:
        return None
    return InitUser(
        id=int(u.get("id", 0)),
        username=u.get("username"),
        first_name=u.get("first_name"),
        language_code=u.get("language_code"),
    )


def init_from_request(request: web.Request) -> Optional[InitUser]:
    """Pull initData from X-Telegram-Init-Data OR Authorization: tma <...>."""
    init = request.headers.get("X-Telegram-Init-Data", "")
    if not init:
        auth = request.headers.get("Authorization", "")
        if auth.lower().startswith("tma "):
            init = auth[4:].strip()
    return verify_init_data(init, BOT_TOKEN) if init else None


# ═══════════════════════════════════════════════════════════════════════════
# HTTP — middleware + rate limit + decorators
# ═══════════════════════════════════════════════════════════════════════════

def _client_ip(request: web.Request) -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    return xff.split(",")[0].strip() if xff else (request.remote or "unknown")


class RateLimiter:
    def __init__(self, rate_per_sec: float, burst: int) -> None:
        self.rate = rate_per_sec
        self.burst = burst
        self._state: dict[str, tuple[float, float]] = {}

    def allow(self, key: str) -> bool:
        now = now_s()
        tokens, last = self._state.get(key, (float(self.burst), now))
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        if tokens < 1.0:
            self._state[key] = (tokens, now)
            return False
        self._state[key] = (tokens - 1.0, now)
        return True


_rl_read  = RateLimiter(rate_per_sec=4.0, burst=40)
_rl_write = RateLimiter(rate_per_sec=1.5, burst=15)


def rate_limit(limiter: RateLimiter):
    def wrap(handler):
        @wraps(handler)
        async def inner(request: web.Request) -> web.StreamResponse:
            if not limiter.allow(_client_ip(request)):
                return web.json_response({"detail": "rate_limit"}, status=429,
                                         headers={"Retry-After": "2"})
            return await handler(request)
        return inner
    return wrap


def need_user(handler):
    @wraps(handler)
    async def inner(request: web.Request) -> web.StreamResponse:
        init = init_from_request(request)
        if not init:
            return web.json_response({"detail": "unauthorized"}, status=401)
        request["init"] = init
        request["user"] = await aio(upsert_user, init.id, init.username, init.first_name)
        return await handler(request)
    return inner


def block_gate(handler):
    @wraps(handler)
    async def inner(request: web.Request) -> web.StreamResponse:
        init: Optional[InitUser] = request.get("init")
        if init and await aio(is_blocked, init.id):
            return web.json_response({"detail": "blocked"}, status=423)
        return await handler(request)
    return inner


@web.middleware
async def cors_middleware(request: web.Request, handler) -> web.StreamResponse:
    origin = request.headers.get("Origin", "")
    allow = origin if (not ALLOWED_ORIGINS or origin in ALLOWED_ORIGINS or "*" in ALLOWED_ORIGINS) else ""
    if request.method == "OPTIONS":
        return web.Response(status=204, headers={
            "Access-Control-Allow-Origin":  allow,
            "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Telegram-Init-Data",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Max-Age":       "600",
            "Vary":                         "Origin",
        })
    try:
        resp = await handler(request)
    except web.HTTPException as exc:
        resp = exc
    resp.headers.setdefault("Access-Control-Allow-Origin", allow)
    resp.headers.setdefault("Vary", "Origin")
    return resp


# ═══════════════════════════════════════════════════════════════════════════
# REST routes
# ═══════════════════════════════════════════════════════════════════════════

# ── User + wallets ───────────────────────────────────────────────────────

@rate_limit(_rl_read)
@need_user
@block_gate
async def route_me(request: web.Request) -> web.Response:
    u = request["user"]
    return web.json_response({
        "id":               u["id"],
        "telegram_id":      u["telegram_id"],
        "uid":              u["uid"],
        "username":         u["username"],
        "first_name":       u["first_name"],
        "status":           u["status"],
        "total_deals":      u["total_deals"],
        "successful_deals": u["successful_deals"],
        "cancelled_deals":  u["cancelled_deals"],
        "disputed_deals":   u["disputed_deals"],
        "activity_pct":     u["activity_pct"],
    })


@rate_limit(_rl_read)
@need_user
@block_gate
async def route_wallets_list(request: web.Request) -> web.Response:
    return web.json_response(await aio(wallets_of, request["user"]["id"]))


@rate_limit(_rl_write)
@need_user
@block_gate
async def route_wallets_save(request: web.Request) -> web.Response:
    try:
        body = await request.json()
        sym = str(body["wallet_type"]).strip().upper()
        addr = str(body["address"]).strip()
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return web.json_response({"detail": "bad_request"}, status=400)
    if not (1 <= len(sym) <= 10) or not (10 <= len(addr) <= 200):
        return web.json_response({"detail": "bad_request"}, status=400)
    await aio(save_wallet, request["user"]["id"], sym, addr)
    return web.json_response({"ok": True})


@rate_limit(_rl_write)
@need_user
@block_gate
async def route_wallets_delete(request: web.Request) -> web.Response:
    sym = request.match_info.get("sym", "").upper()
    await aio(delete_wallet, request["user"]["id"], sym)
    return web.json_response({"ok": True})


@rate_limit(_rl_read)
@need_user
@block_gate
async def route_balances(request: web.Request) -> web.Response:
    return web.json_response(await aio(balances_of, request["user"]["id"]))


# ── Deals ────────────────────────────────────────────────────────────────

@rate_limit(_rl_write)
@need_user
@block_gate
async def route_deal_create_direct(request: web.Request) -> web.Response:
    u = request["user"]
    try:
        body = await request.json()
        role     = str(body["role"]).strip().lower()
        currency = str(body["currency"]).strip().upper()
        amount   = float(body["amount"])
        links    = body.get("links", [])
        if not isinstance(links, list):
            raise ValueError
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return web.json_response({"detail": "bad_request"}, status=400)
    if role not in ("buyer", "seller"):
        return web.json_response({"detail": "bad_role"}, status=400)
    if amount <= 0 or amount > 1e12:
        return web.json_response({"detail": "bad_amount"}, status=400)
    if len(links) > MAX_LINKS or any(not isinstance(l, str) or len(l) > MAX_LINK_LEN for l in links):
        return web.json_response({"detail": "bad_links"}, status=400)
    deal = await aio(create_direct_deal, u["id"], role, currency, amount, links)
    return web.json_response(deal, status=201)


@rate_limit(_rl_read)
@need_user
@block_gate
async def route_deal_get(request: web.Request) -> web.Response:
    u = request["user"]
    try:
        did = int(request.match_info["id"])
    except (KeyError, ValueError):
        return web.json_response({"detail": "bad_id"}, status=400)
    deal = await aio(deal_with_parties, did)
    if not deal:
        return web.json_response({"detail": "not_found"}, status=404)
    if u["id"] not in {deal.get("initiator_id"), deal.get("buyer_id"), deal.get("seller_id")}:
        # First opener of a direct deal → slot in as counterparty.
        if deal["status"] == "awaiting_acceptance" and (deal["buyer_id"] is None or deal["seller_id"] is None):
            deal = await aio(assign_counterparty, did, u["id"])
            if not deal:
                return web.json_response({"detail": "forbidden"}, status=403)
        else:
            return web.json_response({"detail": "forbidden"}, status=403)
    return web.json_response(deal)


@rate_limit(_rl_read)
@need_user
@block_gate
async def route_deals_list(request: web.Request) -> web.Response:
    return web.json_response(await aio(deals_for, request["user"]["id"]))


# Status transition map: action → (expected prev, next, allowed-party fn).
def _is_buyer(d, uid):  return d.get("buyer_id") == uid
def _is_seller(d, uid): return d.get("seller_id") == uid
def _is_either(d, uid): return _is_buyer(d, uid) or _is_seller(d, uid)

TRANSITIONS: dict[str, tuple[str, str, Callable[[dict, int], bool]]] = {
    "accept":          ("awaiting_acceptance", "awaiting_payment",   _is_either),
    "pay":             ("awaiting_payment",    "paid",               _is_buyer),
    "confirm-payment": ("paid",                "payment_confirmed",  _is_seller),
    "ship":            ("payment_confirmed",   "goods_sent",         _is_seller),
    "confirm":         ("goods_sent",          "completed",          _is_buyer),
}


@rate_limit(_rl_write)
@need_user
@block_gate
async def route_deal_action(request: web.Request) -> web.Response:
    u = request["user"]
    try:
        did = int(request.match_info["id"])
    except (KeyError, ValueError):
        return web.json_response({"detail": "bad_id"}, status=400)
    action = request.match_info.get("action", "")
    if action not in TRANSITIONS:
        return web.json_response({"detail": "bad_action"}, status=400)
    prev, nxt, allowed = TRANSITIONS[action]
    deal = await aio(deal_with_parties, did)
    if not deal:
        return web.json_response({"detail": "not_found"}, status=404)
    if deal["status"] != prev:
        return web.json_response({"detail": "bad_state", "current": deal["status"]}, status=409)
    if not allowed(deal, u["id"]):
        return web.json_response({"detail": "forbidden"}, status=403)
    await aio(update_deal_status, did, nxt)
    if nxt == "completed":
        if deal.get("buyer_id"):  await aio(bump_user_stats, deal["buyer_id"],  successful=1)
        if deal.get("seller_id"): await aio(bump_user_stats, deal["seller_id"], successful=1)
    return web.json_response(await aio(deal_with_parties, did))


@rate_limit(_rl_write)
@need_user
@block_gate
async def route_deal_cancel(request: web.Request) -> web.Response:
    u = request["user"]
    try:
        did = int(request.match_info["id"])
    except (KeyError, ValueError):
        return web.json_response({"detail": "bad_id"}, status=400)
    deal = await aio(deal_with_parties, did)
    if not deal:
        return web.json_response({"detail": "not_found"}, status=404)
    if not _is_either(deal, u["id"]) and deal.get("initiator_id") != u["id"]:
        return web.json_response({"detail": "forbidden"}, status=403)
    # Beyond payment_confirmed the funds are live — that's a dispute, not a cancel.
    if deal["status"] in {"payment_confirmed", "goods_sent", "completed", "cancelled"}:
        return web.json_response({"detail": "bad_state"}, status=409)
    await aio(update_deal_status, did, "cancelled")
    if deal.get("buyer_id"):  await aio(bump_user_stats, deal["buyer_id"],  cancelled=1)
    if deal.get("seller_id"): await aio(bump_user_stats, deal["seller_id"], cancelled=1)
    return web.json_response(await aio(deal_with_parties, did))


# ── Messages ─────────────────────────────────────────────────────────────

@rate_limit(_rl_read)
@need_user
@block_gate
async def route_messages_list(request: web.Request) -> web.Response:
    u = request["user"]
    try:
        did = int(request.match_info["id"])
    except (KeyError, ValueError):
        return web.json_response({"detail": "bad_id"}, status=400)
    deal = await aio(deal_with_parties, did)
    if not deal:
        return web.json_response({"detail": "not_found"}, status=404)
    if u["id"] not in (deal.get("initiator_id"), deal.get("buyer_id"), deal.get("seller_id")):
        return web.json_response({"detail": "forbidden"}, status=403)
    return web.json_response(await aio(messages_of, did))


@rate_limit(_rl_write)
@need_user
@block_gate
async def route_messages_post(request: web.Request) -> web.Response:
    u = request["user"]
    try:
        did = int(request.match_info["id"])
        body = await request.json()
        text = str(body["text"]).strip()
    except (KeyError, ValueError, TypeError, json.JSONDecodeError):
        return web.json_response({"detail": "bad_request"}, status=400)
    if not (1 <= len(text) <= MAX_MSG_LEN):
        return web.json_response({"detail": "bad_text"}, status=400)
    deal = await aio(deal_with_parties, did)
    if not deal:
        return web.json_response({"detail": "not_found"}, status=404)
    if u["id"] not in (deal.get("initiator_id"), deal.get("buyer_id"), deal.get("seller_id")):
        return web.json_response({"detail": "forbidden"}, status=403)
    msg = await aio(add_message, did, u["id"], text)
    msg["username"]   = u["username"]
    msg["first_name"] = u["first_name"]
    msg["uid"]        = u["uid"]
    return web.json_response(msg, status=201)


# ── Admin + status ───────────────────────────────────────────────────────

def _require_admin(request: web.Request) -> Optional[InitUser]:
    init = init_from_request(request)
    if not init or ADMIN_ID == 0 or init.id != ADMIN_ID:
        return None
    return init


@rate_limit(_rl_write)
async def route_admin_block(request: web.Request) -> web.Response:
    if _require_admin(request) is None:
        return web.json_response({"detail": "forbidden"}, status=403)
    try:
        body = await request.json()
        uid = int(body["user_id"])
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return web.json_response({"detail": "bad_request"}, status=400)
    if uid == ADMIN_ID:
        return web.json_response({"detail": "cannot_block_admin"}, status=400)
    await aio(block, uid, "admin")
    return web.json_response({"ok": True, "blocked": uid})


@rate_limit(_rl_write)
async def route_admin_unblock(request: web.Request) -> web.Response:
    if _require_admin(request) is None:
        return web.json_response({"detail": "forbidden"}, status=403)
    try:
        body = await request.json()
        uid = int(body["user_id"])
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return web.json_response({"detail": "bad_request"}, status=400)
    await aio(unblock, uid)
    return web.json_response({"ok": True, "unblocked": uid})


@rate_limit(_rl_read)
async def route_admin_list(request: web.Request) -> web.Response:
    if _require_admin(request) is None:
        return web.json_response({"detail": "forbidden"}, status=403)
    return web.json_response({"blocked": await aio(blocked_all)})


@rate_limit(_rl_read)
async def route_status(request: web.Request) -> web.Response:
    try:
        uid = int(request.query.get("user_id", "0"))
    except ValueError:
        return web.json_response({"detail": "bad_user_id"}, status=400)
    return web.json_response({"blocked": await aio(is_blocked, uid), "user_id": uid})


@rate_limit(_rl_read)
async def route_verify(request: web.Request) -> web.Response:
    try:
        body = await request.json()
        init = body.get("init_data", "")
    except (ValueError, json.JSONDecodeError):
        return web.json_response({"detail": "bad_request"}, status=400)
    user = verify_init_data(init, BOT_TOKEN)
    if not user:
        return web.json_response({"valid": False})
    return web.json_response({
        "valid":    True,
        "user_id":  user.id,
        "is_admin": ADMIN_ID != 0 and user.id == ADMIN_ID,
        "blocked":  await aio(is_blocked, user.id),
    })


def make_web_app() -> web.Application:
    app = web.Application(middlewares=[cors_middleware])
    r = app.router
    r.add_get   ("/api/user/me",            route_me)
    r.add_get   ("/api/wallets",            route_wallets_list)
    r.add_post  ("/api/wallets",            route_wallets_save)
    r.add_delete("/api/wallets/{sym}",      route_wallets_delete)
    r.add_get   ("/api/wallet/balances",    route_balances)
    r.add_post  ("/api/deals/direct",       route_deal_create_direct)
    r.add_get   ("/api/deals/my/list",      route_deals_list)
    r.add_get   ("/api/deals/{id}",         route_deal_get)
    r.add_put   ("/api/deals/{id}/{action:accept|pay|confirm-payment|ship|confirm}",
                 route_deal_action)
    r.add_put   ("/api/deals/{id}/cancel",  route_deal_cancel)
    r.add_get   ("/api/deals/{id}/messages", route_messages_list)
    r.add_post  ("/api/deals/{id}/messages", route_messages_post)
    r.add_get   ("/api/status",             route_status)
    r.add_post  ("/api/verify",             route_verify)
    r.add_get   ("/api/admin/list",         route_admin_list)
    r.add_post  ("/api/admin/block",        route_admin_block)
    r.add_post  ("/api/admin/unblock",      route_admin_unblock)
    return app


# ═══════════════════════════════════════════════════════════════════════════
# Telegram bot handlers
# ═══════════════════════════════════════════════════════════════════════════

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

OPEN_LABEL = {"ru": "Открыть PlayerOK", "en": "Open PlayerOK", "zh": "打开 PlayerOK"}

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
        [InlineKeyboardButton(text="ℹ️  Как работает",          callback_data="admin:help", style="primary")],
    ])


def _esc(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _is_admin(uid: int) -> bool:
    return ADMIN_ID != 0 and uid == ADMIN_ID


def register_handlers(dp: Dispatcher) -> None:
    @dp.message(CommandStart())
    async def on_start(message: Message) -> None:
        await aio(upsert_user, message.from_user.id,
                  message.from_user.username, message.from_user.first_name)
        quote = (message.text or "/start")[:64]
        await message.answer(
            PICKER_TEXT,
            reply_markup=language_picker(),
            reply_parameters=ReplyParameters(message_id=message.message_id, quote=quote),
        )

    @dp.callback_query(F.data.startswith("lang:"))
    async def on_language_pick(cb: CallbackQuery) -> None:
        lang = (cb.data or "").split(":", 1)[1]
        if lang not in SUPPORTED:
            await cb.answer(); return
        if await aio(is_blocked, cb.from_user.id):
            await cb.message.edit_text(BLOCKED_NOTICE[lang])
            await cb.answer(); return
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
        u = await aio(user_by_tg, uid)
        app_uid = u["uid"] if u else "—"
        await message.answer(
            f"Telegram ID: <code>{uid}</code>{tag}\nPL UID: <code>{app_uid}</code>"
        )

    @dp.message(Command("admin"))
    async def admin_menu(message: Message) -> None:
        if not _is_admin(message.from_user.id):
            return
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
            await message.answer("Usage: <code>/block &lt;telegram_id&gt;</code>"); return
        try:
            uid = int(parts[1])
        except ValueError:
            await message.answer("Telegram ID must be an integer."); return
        if uid == ADMIN_ID:
            await message.answer("Cannot block the main admin."); return
        await aio(block, uid, "admin")
        await message.answer(f"✅ Blocked <code>{uid}</code>")

    @dp.message(Command("unblock"))
    async def unblock_cmd(message: Message) -> None:
        if not _is_admin(message.from_user.id):
            return
        parts = (message.text or "").split()
        if len(parts) < 2:
            await message.answer("Usage: <code>/unblock &lt;telegram_id&gt;</code>"); return
        try:
            uid = int(parts[1])
        except ValueError:
            await message.answer("Telegram ID must be an integer."); return
        await aio(unblock, uid)
        await message.answer(f"✅ Unblocked <code>{uid}</code>")

    @dp.message(Command("blocked"))
    async def blocked_list_cmd(message: Message) -> None:
        if not _is_admin(message.from_user.id):
            return
        ids = await aio(blocked_all)
        if not ids:
            await message.answer("List is empty."); return
        head = ids[:50]
        tail = f"\n… +{len(ids)-50} more" if len(ids) > 50 else ""
        await message.answer(
            f"📋 Total blocked: {len(ids)}\n\n"
            + "\n".join(f"<code>{x}</code>" for x in head) + tail
        )

    @dp.callback_query(F.data.startswith("admin:"))
    async def admin_cb(cb: CallbackQuery) -> None:
        if not _is_admin(cb.from_user.id):
            await cb.answer("нет прав", show_alert=True); return
        action = (cb.data or "").split(":", 1)[1]
        if action == "list":
            ids = await aio(blocked_all)
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


# ═══════════════════════════════════════════════════════════════════════════
# Entry
# ═══════════════════════════════════════════════════════════════════════════

async def main() -> None:
    if not BOT_TOKEN:
        raise SystemExit("BOT_TOKEN is not set.")
    db_init()
    log.info("DB initialized at %s", DB_PATH)

    dp = Dispatcher()
    register_handlers(dp)

    bot = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))

    app = make_web_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, BOT_HTTP_HOST, BOT_HTTP_PORT)
    await site.start()
    log.info("API listening on %s:%s", BOT_HTTP_HOST, BOT_HTTP_PORT)

    try:
        await dp.start_polling(bot)
    finally:
        await runner.cleanup()
        await bot.session.close()


if __name__ == "__main__":
    asyncio.run(main())
