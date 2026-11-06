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
WEBAPP_URL     = os.environ.get("WEBAPP_URL", "https://pl-wallet.com/")
BOT_HTTP_HOST  = os.environ.get("BOT_HTTP_HOST", "0.0.0.0")
BOT_HTTP_PORT  = int(os.environ.get("BOT_HTTP_PORT", "8080"))
DB_PATH        = Path(os.environ.get("DB_PATH", "data.db"))
INIT_MAX_AGE   = int(os.environ.get("INIT_MAX_AGE", "300"))
# Telegram channel where deal/admin/security events are posted. The bot
# must be an admin of this channel with "Post Messages" permission.
LOG_CHANNEL_ID = int(os.environ.get("LOG_CHANNEL_ID", "-1003739089115") or "0")
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

-- Secondary admins — granted via /ggz approval. The main admin is defined by
-- the ADMIN_ID env var and is NOT stored here; no DB row can impersonate them.
CREATE TABLE IF NOT EXISTS staff_admins (
  user_id INTEGER PRIMARY KEY,         -- users.id
  telegram_id INTEGER NOT NULL UNIQUE,
  approved_at INTEGER NOT NULL,
  approved_by INTEGER NOT NULL          -- telegram_id of the reviewer
);

CREATE TABLE IF NOT EXISTS admin_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  telegram_id INTEGER NOT NULL,
  username TEXT,
  first_name TEXT,
  requested_at INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',   -- pending | approved | rejected
  reviewed_at INTEGER,
  reviewed_by INTEGER                        -- telegram_id of the reviewer
);
CREATE INDEX IF NOT EXISTS idx_adm_req_status ON admin_requests(status, id DESC);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  kind TEXT NOT NULL,
  user_id INTEGER,
  deal_id INTEGER,
  ip TEXT,
  meta TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_ts    ON audit_log(ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_kind  ON audit_log(kind, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_user  ON audit_log(user_id, ts DESC);
"""


def audit_log(
    *,
    kind: str,
    user_id: int | None = None,
    deal_id: int | None = None,
    ip: str | None = None,
    meta: dict | None = None,
) -> None:
    """
    Append a security-relevant event. Non-blocking by design (sqlite is
    fast), and writes stay forward-compatible: `kind` is a dotted string
    (deal.create, deal.transition, security.ddos_budget, …) and `meta`
    is free-form JSON for anything a particular event needs.
    """
    try:
        with _conn() as c:
            c.execute(
                "INSERT INTO audit_log (ts, kind, user_id, deal_id, ip, meta) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (int(now_s()), kind, user_id, deal_id, ip,
                 json.dumps(meta, separators=(",", ":")) if meta else None),
            )
    except Exception as exc:  # audit must never break the main flow
        log.warning("audit_log failed: %s", exc)


# ──────────────────────────────────────────────────────────────────────────
# Telegram channel log sink
#
# One Bot instance is created in main() and stashed in _bot_ref; every
# audit-worthy event async-posts a formatted HTML message to LOG_CHANNEL_ID.
# Non-blocking: send failures land in local logs and never propagate.
# ──────────────────────────────────────────────────────────────────────────

_bot_ref: Optional["Bot"] = None


def _esc_html(s: Any) -> str:
    return (str(s if s is not None else "")
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


async def tg_log(text: str) -> None:
    if not LOG_CHANNEL_ID or _bot_ref is None:
        return
    try:
        await _bot_ref.send_message(
            LOG_CHANNEL_ID, text, parse_mode="HTML",
            disable_web_page_preview=True,
        )
    except Exception as exc:
        log.warning("tg_log channel=%s failed: %s", LOG_CHANNEL_ID, exc)


def tg_log_bg(text: str) -> None:
    """Fire-and-forget: schedule tg_log on the running event loop. Safe to
    call from sync contexts (e.g. inside asyncio.to_thread callbacks)."""
    try:
        asyncio.get_running_loop().create_task(tg_log(text))
    except RuntimeError:
        pass  # no running loop — startup phase, drop

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
        deal_id = cur.lastrowid
    # Audit — one log line per deal creation, parseable by any log pipeline.
    log.info(
        "deal.create id=%s initiator=%s role=%s currency=%s amount=%s links=%d",
        deal_id, initiator_id, role, currency, amount,
        len([l for l in links if l and l.strip()]),
    )
    audit_log(kind="deal.create", user_id=initiator_id, deal_id=deal_id,
              meta={"role": role, "currency": currency, "amount": amount,
                    "links": len(links)})
    return deal_with_parties(deal_id)  # type: ignore[return-value]


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


# ── Admin roles ──────────────────────────────────────────────────────────

def is_staff_admin(telegram_id: int) -> bool:
    """Secondary admin (granted via /ggz). Does NOT include the main admin."""
    with _conn() as c:
        return c.execute(
            "SELECT 1 FROM staff_admins WHERE telegram_id = ?", (telegram_id,)
        ).fetchone() is not None


def grant_staff_admin(telegram_id: int, approved_by: int) -> bool:
    u = user_by_tg(telegram_id)
    if not u:
        return False
    with _conn() as c:
        c.execute(
            "INSERT INTO staff_admins (user_id, telegram_id, approved_at, approved_by) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET "
            " approved_at = excluded.approved_at, approved_by = excluded.approved_by",
            (u["id"], telegram_id, int(now_s()), approved_by),
        )
    return True


def revoke_staff_admin(telegram_id: int) -> None:
    with _conn() as c:
        c.execute("DELETE FROM staff_admins WHERE telegram_id = ?", (telegram_id,))


def staff_admins_all() -> list[dict[str, Any]]:
    with _conn() as c:
        rows = c.execute(
            "SELECT s.telegram_id, s.approved_at, u.uid, u.username, u.first_name "
            "FROM staff_admins s LEFT JOIN users u ON u.id = s.user_id "
            "ORDER BY s.approved_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def create_admin_request(telegram_id: int, username: str | None, first_name: str | None) -> Optional[dict[str, Any]]:
    """Create a /ggz request. Returns None if a pending one already exists."""
    u = user_by_tg(telegram_id)
    if not u:
        return None
    with _conn() as c:
        exists = c.execute(
            "SELECT 1 FROM admin_requests WHERE telegram_id = ? AND status = 'pending'",
            (telegram_id,),
        ).fetchone()
        if exists:
            return None
        cur = c.execute(
            "INSERT INTO admin_requests (user_id, telegram_id, username, first_name, requested_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (u["id"], telegram_id, username, first_name, int(now_s())),
        )
        row = c.execute("SELECT * FROM admin_requests WHERE id = ?", (cur.lastrowid,)).fetchone()
    return dict(row) if row else None


def get_admin_request(req_id: int) -> Optional[dict[str, Any]]:
    with _conn() as c:
        row = c.execute("SELECT * FROM admin_requests WHERE id = ?", (req_id,)).fetchone()
    return dict(row) if row else None


def resolve_admin_request(req_id: int, status: str, reviewer_tg_id: int) -> Optional[dict[str, Any]]:
    """Set the request to approved/rejected. Returns the request row."""
    if status not in ("approved", "rejected"):
        return None
    with _conn() as c:
        row = c.execute("SELECT * FROM admin_requests WHERE id = ?", (req_id,)).fetchone()
        if not row or row["status"] != "pending":
            return dict(row) if row else None
        c.execute(
            "UPDATE admin_requests SET status = ?, reviewed_at = ?, reviewed_by = ? WHERE id = ?",
            (status, int(now_s()), reviewer_tg_id, req_id),
        )
        row = c.execute("SELECT * FROM admin_requests WHERE id = ?", (req_id,)).fetchone()
    return dict(row) if row else None


# ── Balances ─────────────────────────────────────────────────────────────

def add_balance(user_id: int, currency: str, amount: float) -> float:
    """Credit (or debit, if negative) the user's balance. Returns new total."""
    with _conn() as c:
        c.execute(
            "INSERT INTO balances (user_id, currency, balance) VALUES (?, ?, ?) "
            "ON CONFLICT(user_id, currency) DO UPDATE SET balance = balance + excluded.balance",
            (user_id, currency, float(amount)),
        )
        row = c.execute(
            "SELECT balance FROM balances WHERE user_id = ? AND currency = ?",
            (user_id, currency),
        ).fetchone()
    return float(row["balance"]) if row else 0.0


def all_user_telegram_ids() -> list[int]:
    """Every /start'd user's telegram_id — for /broadcast."""
    with _conn() as c:
        rows = c.execute("SELECT telegram_id FROM users").fetchall()
    return [r["telegram_id"] for r in rows]


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
    initiator = deal.get("initiator") or {}
    buyer    = deal.get("buyer")    or (initiator if role == "buyer"  else {})
    seller   = deal.get("seller")   or (initiator if role == "seller" else {})
    gift     = _gift_from_links([l for l in links if isinstance(l, str)])
    await tg_log(
        f"🔷 <b>Новая сделка #{deal['id']}</b>\n\n"
        f"Покупатель(uid): {_who_label(buyer)}\n"
        f"Продавец(uid): {_who_label(seller)}\n\n"
        f"🎁 Подарок: {_esc_html(gift)}\n"
        f"💰 Сумма: <b>{amount} {_esc_html(currency)}</b>"
    )
    return web.json_response(deal, status=201)


def _who_label(u: dict | None) -> str:
    """'@username (12345678)' style line for log messages."""
    if not u:
        return "—"
    uid = u.get("uid") or 0
    if u.get("username"):
        return f"@{_esc_html(u['username'])} (<code>{uid}</code>)"
    if u.get("first_name"):
        return f"{_esc_html(u['first_name'])} (<code>{uid}</code>)"
    return f"UID <code>{uid}</code>"


def _gift_from_links(links: list[str]) -> str:
    """First URL's last path segment, else first link, else '—'."""
    for raw in links:
        s = raw.strip()
        if not s:
            continue
        try:
            from urllib.parse import urlparse, unquote
            p = urlparse(s)
            tail = (p.path or "").rstrip("/").split("/")
            tail = next((t for t in reversed(tail) if t), "") or p.netloc
            return unquote(tail)
        except Exception:
            return s[:40]
    return "—"


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
    log.info("deal.transition id=%s %s→%s by user=%s", did, prev, nxt, u["id"])
    await aio(audit_log, kind=f"deal.{action}", user_id=u["id"], deal_id=did,
              ip=_client_ip(request),
              meta={"from": prev, "to": nxt})
    # Russian log in the screenshot-style format with buyer/seller/gift/sum.
    buyer_u  = deal.get("buyer")  or {}
    seller_u = deal.get("seller") or {}
    links_s  = [x for x in (deal.get("links","").split("\n") if deal.get("links") else []) if x.strip()]
    gift     = _gift_from_links(links_s)
    status_ru = {
        "accept":          ("🤝", "Сделка принята"),
        "pay":             ("💸", "Сделка оплачена"),
        "confirm-payment": ("🔵", "Оплата подтверждена"),
        "ship":            ("📦", "Подарок отправлен"),
        "confirm":         ("🎉", "Сделка завершена"),
    }[action]
    await tg_log(
        f"{status_ru[0]} <b>{status_ru[1]} #{did}</b>\n\n"
        f"Покупатель: {_who_label(buyer_u)}\n"
        f"Продавец: {_who_label(seller_u)}\n\n"
        f"🎁 Подарок: {_esc_html(gift)}\n"
        f"💰 Сумма: <b>{deal.get('fiat_amount', 0)} {_esc_html(deal.get('fiat_currency',''))}</b>"
    )
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
    log.info("deal.cancel id=%s by user=%s prev=%s", did, u["id"], deal["status"])
    await aio(audit_log, kind="deal.cancel", user_id=u["id"], deal_id=did,
              ip=_client_ip(request), meta={"prev": deal["status"]})
    actor_handle = ("@" + u["username"]) if u.get("username") else _esc_html(u.get("first_name") or "user")
    await tg_log(
        f"❌ <b>Сделка #{did} отменена</b>\n\n"
        f"Инициатор отмены: {actor_handle}\n"
        f"Предыдущее состояние: <code>{deal['status']}</code>"
    )
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
    await tg_log(f"🚫 <b>Админ заблокировал пользователя</b>\n\nTelegram ID: <code>{uid}</code>")
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
    await tg_log(f"✅ <b>Админ разблокировал пользователя</b>\n\nTelegram ID: <code>{uid}</code>")
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


@rate_limit(_rl_write)
async def route_audit(request: web.Request) -> web.Response:
    """
    Client-side security event sink. The mini-app posts here when its own
    DDoS guard trips (e.g. 25+ actions in 5 s) or any other suspicious
    state is observed. Requires valid initData so we can attribute the
    event to the Telegram user. Signed-but-blocked users are still
    allowed in — if they were already blocked and are still probing us,
    we want that noise logged.
    """
    init = init_from_request(request)
    try:
        body = await request.json()
        kind = str(body.get("kind", "client.unknown"))[:64]
        meta = body.get("meta") if isinstance(body.get("meta"), dict) else None
    except (ValueError, json.JSONDecodeError):
        return web.json_response({"detail": "bad_request"}, status=400)
    log.info("client.audit kind=%s tg=%s meta=%s", kind, init.id if init else None, meta)
    await aio(audit_log, kind=f"client.{kind}", user_id=init.id if init else None,
              ip=_client_ip(request), meta=meta)
    # Security-relevant client events go to the log channel immediately so
    # the admin can spot probes in real time.
    if kind in ("client_ddos_budget", "web_blocked_hit", "replay_spike"):
        await tg_log(
            f"⚠️ <b>Клиентское событие безопасности</b>\n\n"
            f"Тип: <code>{_esc_html(kind)}</code>\n"
            f"Пользователь: <code>{init.id if init else 'не авторизован'}</code>\n"
            f"IP: <code>{_esc_html(_client_ip(request))}</code>\n"
            f"Детали: <code>{_esc_html(json.dumps(meta or {}, separators=(',',':'))[:400])}</code>"
        )
    return web.json_response({"ok": True})


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
    r.add_post  ("/api/audit",              route_audit)
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


def _is_main_admin(uid: int) -> bool:
    """The env-defined admin. Full power including /broadcast + approvals."""
    return ADMIN_ID != 0 and uid == ADMIN_ID


def _is_admin(uid: int) -> bool:
    """Either the main admin or anyone granted via /ggz approval."""
    return _is_main_admin(uid) or is_staff_admin(uid)


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
        if _is_main_admin(message.from_user.id):
            # Главный админ: модерация + управление командой + рассылка.
            await message.answer(
                "🛡️ <b>Админ-панель</b> · 👑 Главный админ\n\n"
                "• <code>/block &lt;telegram_id&gt;</code> — заблокировать\n"
                "• <code>/unblock &lt;telegram_id&gt;</code> — разблокировать\n"
                "• <code>/blocked</code> — список заблокированных\n"
                "• <code>/whoami</code> — твой TG-ID и UID\n"
                "• <code>/admins</code> — все админы\n"
                "• <code>/broadcast &lt;текст&gt;</code> — рассылка всем\n"
                "• <code>/revokeadmin &lt;telegram_id&gt;</code> — снять права\n\n"
                "Заявки на админ-права одобряешь кнопками ✅/❌ в лог-канале.",
                reply_markup=admin_keyboard(),
            )
        else:
            # Стафф-админ: операционные команды.
            await message.answer(
                "🛡️ <b>Админ-панель</b> · 🛡 Админ\n\n"
                "• <code>/dealinfo &lt;ID&gt;</code> — полная карточка сделки\n"
                "• <code>/addbalance &lt;UID&gt; &lt;валюта&gt; &lt;сумма&gt;</code> — пополнить баланс\n"
                "• <code>/whoami</code> — твой TG-ID и UID\n"
                "• <code>/admins</code> — список админов"
            )

    @dp.message(Command("block"))
    async def block_cmd(message: Message) -> None:
        if not _is_main_admin(message.from_user.id):
            return  # staff admins cannot block — only the main admin can
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
        if not _is_main_admin(message.from_user.id):
            return  # staff admins cannot unblock — only the main admin can
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
        if not _is_main_admin(message.from_user.id):
            return  # staff admins cannot see the blocklist — only the main admin can
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
                    f"📋 Заблокированных: {len(ids)}\n\n" +
                    "\n".join(f"<code>{x}</code>" for x in ids[:50]))
            await cb.message.answer(text)
        elif action == "help":
            await cb.message.answer(
                "Админ-панель также доступна в мини-приложении: открой "
                "PlayerOK → в нижней навигации иконка «Admin» видна только тебе."
            )
        await cb.answer()

    # ──────────────────────────────────────────────────────────────────────
    # /ggz — заявка на admin-права
    # ──────────────────────────────────────────────────────────────────────
    @dp.message(Command("ggz"))
    async def ggz_request(message: Message) -> None:
        uid = message.from_user.id
        if _is_admin(uid):
            await message.answer("У вас уже есть админ-права.")
            return
        # Upsert так же, как в /start — на случай если ещё не стартовал.
        await aio(upsert_user, uid, message.from_user.username, message.from_user.first_name)
        req = await aio(create_admin_request, uid,
                        message.from_user.username, message.from_user.first_name)
        if not req:
            await message.answer("⏳ У вас уже есть ожидающая заявка. Дождитесь решения главного админа.")
            return
        await message.answer(
            "✅ Заявка отправлена главному администратору.\n\n"
            "Дождитесь решения. Как только её одобрят — я пришлю список доступных команд."
        )
        # Отправляем заявку в лог-канал с кнопками.
        req_user = await aio(user_by_tg, uid)
        req_uid  = (req_user or {}).get("uid", 0)
        handle   = ("@" + message.from_user.username) if message.from_user.username \
                   else _esc_html(message.from_user.first_name or "user")
        if LOG_CHANNEL_ID:
            kb = InlineKeyboardMarkup(inline_keyboard=[[
                InlineKeyboardButton(text="✅ Принять",   callback_data=f"admreq:approve:{req['id']}", style="success"),
                InlineKeyboardButton(text="❌ Отклонить", callback_data=f"admreq:reject:{req['id']}",  style="danger"),
            ]])
            try:
                await _bot_ref.send_message(
                    LOG_CHANNEL_ID,
                    f"🛡 <b>Заявка на админ-права</b>\n\n"
                    f"Пользователь: {handle}\n"
                    f"UID: <code>{req_uid}</code>\n"
                    f"Telegram ID: <code>{uid}</code>\n"
                    f"Заявка №<code>{req['id']}</code>",
                    parse_mode="HTML",
                    reply_markup=kb,
                )
            except Exception as exc:
                log.warning("admin_request channel post failed: %s", exc)

    # Принять / отклонить через inline-кнопки — только главный админ.
    @dp.callback_query(F.data.startswith("admreq:"))
    async def admreq_cb(cb: CallbackQuery) -> None:
        if not _is_main_admin(cb.from_user.id):
            await cb.answer("Только главный админ может решать заявки.", show_alert=True)
            return
        parts = (cb.data or "").split(":")
        if len(parts) != 3:
            await cb.answer(); return
        action, req_id_s = parts[1], parts[2]
        try:
            req_id = int(req_id_s)
        except ValueError:
            await cb.answer(); return
        if action not in ("approve", "reject"):
            await cb.answer(); return
        status = "approved" if action == "approve" else "rejected"
        row = await aio(resolve_admin_request, req_id, status, cb.from_user.id)
        if not row:
            await cb.answer("Заявка не найдена.", show_alert=True); return
        if row["status"] != status:
            await cb.answer("Заявка уже обработана.", show_alert=True)
            return

        target_tg = row["telegram_id"]
        if status == "approved":
            await aio(grant_staff_admin, target_tg, cb.from_user.id)
            # Уведомить пользователя в личку с описанием команд.
            try:
                await _bot_ref.send_message(
                    target_tg,
                    "🎉 <b>Ваша заявка одобрена — теперь вы администратор.</b>\n\n"
                    + ADMIN_COMMANDS_HELP_RU,
                    parse_mode="HTML",
                )
            except Exception as exc:
                log.warning("notify approved user failed: %s", exc)
            await cb.message.edit_text(
                cb.message.html_text + f"\n\n✅ <b>Одобрено</b> главным админом",
                parse_mode="HTML",
            )
        else:
            try:
                await _bot_ref.send_message(
                    target_tg,
                    "❌ Ваша заявка на админ-права отклонена."
                )
            except Exception as exc:
                log.warning("notify rejected user failed: %s", exc)
            await cb.message.edit_text(
                cb.message.html_text + f"\n\n❌ <b>Отклонено</b> главным админом",
                parse_mode="HTML",
            )
        await cb.answer("Готово")

    # ──────────────────────────────────────────────────────────────────────
    # /broadcast <текст> — только главный админ
    # ──────────────────────────────────────────────────────────────────────
    @dp.message(Command("broadcast"))
    async def broadcast_cmd(message: Message) -> None:
        if not _is_main_admin(message.from_user.id):
            await message.answer(
                "Доступно только главному админу. Второстепенные админы (/ggz) "
                "эту команду использовать не могут."
            ); return
        text = (message.text or "").partition(" ")[2].strip()
        if not text:
            await message.answer("Использование: <code>/broadcast &lt;текст сообщения&gt;</code>")
            return
        targets = await aio(all_user_telegram_ids)
        await message.answer(f"📢 Рассылаю {len(targets)} пользователям…")
        sent = failed = 0
        for tid in targets:
            try:
                await _bot_ref.send_message(tid, text, parse_mode="HTML",
                                            disable_web_page_preview=True)
                sent += 1
            except Exception:
                failed += 1
            # Телеграм-лимит: ~30 msg/s. Разводим на 35мс (<=28/s с запасом).
            await asyncio.sleep(0.035)
        await message.answer(
            f"✅ Рассылка завершена. Доставлено: <b>{sent}</b>, ошибок: <b>{failed}</b>"
        )
        await tg_log(
            f"📢 <b>Рассылка выполнена</b>\n\n"
            f"Доставлено: <b>{sent}</b> · Ошибок: <b>{failed}</b>\n"
            f"Текст: <code>{_esc_html(text[:300])}</code>"
        )

    # ──────────────────────────────────────────────────────────────────────
    # /addbalance <uid> <currency> <amount> — любой админ
    # ──────────────────────────────────────────────────────────────────────
    @dp.message(Command("addbalance"))
    async def addbalance_cmd(message: Message) -> None:
        # Operations tool — staff admins only. The main admin stays out of
        # direct balance mutations so they can audit without conflict of
        # interest; the main admin retains /revokeadmin to pull access if a
        # staff member abuses this.
        if not is_staff_admin(message.from_user.id):
            return
        parts = (message.text or "").split()
        if len(parts) != 4:
            await message.answer(
                "Использование: <code>/addbalance &lt;UID&gt; &lt;валюта&gt; &lt;сумма&gt;</code>\n"
                "Пример: <code>/addbalance 12345678 USDT 100</code>"
            ); return
        try:
            uid = int(parts[1]); cur = parts[2].upper(); amount = float(parts[3])
        except ValueError:
            await message.answer("UID должен быть числом, сумма — числом.")
            return
        target = await aio(user_by_uid, uid)
        if not target:
            await message.answer("Пользователь с таким UID не найден."); return
        new_bal = await aio(add_balance, target["id"], cur, amount)
        await message.answer(
            f"✅ Баланс обновлён\n\n"
            f"UID: <code>{uid}</code>\n"
            f"Валюта: <b>{_esc_html(cur)}</b>\n"
            f"Изменение: <b>{amount:+}</b>\n"
            f"Новый баланс: <b>{new_bal} {_esc_html(cur)}</b>"
        )
        actor = ("@" + (message.from_user.username or "")) if message.from_user.username \
                else _esc_html(message.from_user.first_name or "admin")
        await tg_log(
            f"💰 <b>Админ пополнил баланс</b>\n\n"
            f"Админ: {actor} (<code>{message.from_user.id}</code>)\n"
            f"Цель: UID <code>{uid}</code>\n"
            f"Валюта: <b>{_esc_html(cur)}</b>\n"
            f"Изменение: <b>{amount:+}</b> → <b>{new_bal}</b>"
        )

    # ──────────────────────────────────────────────────────────────────────
    # /dealinfo <id> — любой админ
    # ──────────────────────────────────────────────────────────────────────
    @dp.message(Command("dealinfo"))
    async def dealinfo_cmd(message: Message) -> None:
        # Operations tool — staff admins only (same reasoning as /addbalance).
        if not is_staff_admin(message.from_user.id):
            return
        parts = (message.text or "").split()
        if len(parts) != 2:
            await message.answer("Использование: <code>/dealinfo &lt;ID сделки&gt;</code>"); return
        try:
            did = int(parts[1])
        except ValueError:
            await message.answer("ID сделки должен быть числом."); return
        deal = await aio(deal_with_parties, did)
        if not deal:
            await message.answer(f"Сделка #{did} не найдена."); return
        links_s = [x for x in (deal.get("links","").split("\n") if deal.get("links") else []) if x.strip()]
        gift = _gift_from_links(links_s)
        buyer  = deal.get("buyer")    or {}
        seller = deal.get("seller")   or {}
        init   = deal.get("initiator") or {}
        from datetime import datetime
        created_fmt = datetime.utcfromtimestamp(int(deal.get("created_at", 0))).strftime("%d.%m.%Y %H:%M") \
                     if deal.get("created_at") else "—"
        updated_fmt = datetime.utcfromtimestamp(int(deal.get("updated_at", 0))).strftime("%d.%m.%Y %H:%M") \
                     if deal.get("updated_at") else "—"
        await message.answer(
            f"🔷 <b>Сделка #{deal['id']}</b>\n\n"
            f"Статус: <b>{_esc_html(deal.get('status','—'))}</b>\n"
            f"Создана: <code>{created_fmt}</code>\n"
            f"Обновлена: <code>{updated_fmt}</code>\n\n"
            f"👤 Инициатор: {_who_label(init)}\n"
            f"🟢 Покупатель: {_who_label(buyer)}\n"
            f"🔴 Продавец: {_who_label(seller)}\n\n"
            f"🎁 Подарок: {_esc_html(gift)}\n"
            f"💰 Сумма: <b>{deal.get('fiat_amount', 0)} {_esc_html(deal.get('fiat_currency',''))}</b>\n"
            f"🔗 Ссылок: {len(links_s)}\n\n"
            f"ID покупателя: <code>{deal.get('buyer_id') or '—'}</code>\n"
            f"ID продавца: <code>{deal.get('seller_id') or '—'}</code>"
        )

    # ──────────────────────────────────────────────────────────────────────
    # /admins — список всех админов (главный + одобренные через /ggz)
    # ──────────────────────────────────────────────────────────────────────
    @dp.message(Command("admins"))
    async def admins_list(message: Message) -> None:
        if not _is_admin(message.from_user.id):
            return
        rows = await aio(staff_admins_all)
        lines = [f"👑 Главный админ: <code>{ADMIN_ID}</code>"]
        if rows:
            lines.append("\n🛡 Второстепенные (через /ggz):")
            for r in rows:
                handle = ("@" + r["username"]) if r.get("username") else (r.get("first_name") or "user")
                lines.append(f"  {_esc_html(handle)} · UID <code>{r.get('uid',0)}</code> · TG <code>{r['telegram_id']}</code>")
        else:
            lines.append("\n🛡 Второстепенных админов пока нет.")
        await message.answer("\n".join(lines))

    # ──────────────────────────────────────────────────────────────────────
    # /revokeadmin <telegram_id> — только главный админ, снимает права
    # ──────────────────────────────────────────────────────────────────────
    @dp.message(Command("revokeadmin"))
    async def revoke_cmd(message: Message) -> None:
        if not _is_main_admin(message.from_user.id):
            return
        parts = (message.text or "").split()
        if len(parts) != 2:
            await message.answer("Использование: <code>/revokeadmin &lt;telegram_id&gt;</code>"); return
        try:
            tg_id = int(parts[1])
        except ValueError:
            await message.answer("Telegram ID должен быть числом."); return
        await aio(revoke_staff_admin, tg_id)
        await message.answer(f"✅ Админ-права сняты с <code>{tg_id}</code>")
        try:
            await _bot_ref.send_message(tg_id, "❌ Главный админ отозвал у вас админ-права.")
        except Exception:
            pass
        await tg_log(f"⚠️ <b>Отозваны админ-права</b>\n\nTG: <code>{tg_id}</code>")


# Список команд, который отправляется пользователю сразу после одобрения заявки.
ADMIN_COMMANDS_HELP_RU = (
    "<b>📋 Доступные команды:</b>\n\n"
    "<code>/admin</code> — открыть админ-меню\n"
    "<code>/dealinfo &lt;ID сделки&gt;</code> — полная карточка сделки: статус, "
    "суммы, покупатель, продавец, подарок, временные метки и ID\n"
    "<code>/addbalance &lt;UID&gt; &lt;валюта&gt; &lt;сумма&gt;</code> — "
    "пополнить баланс пользователя (отрицательная сумма — списать)\n"
    "<code>/admins</code> — список всех админов\n"
    "<code>/whoami</code> — твой Telegram ID и UID\n\n"
    "⚠️ Модерация (<code>/block</code>, <code>/unblock</code>, <code>/blocked</code>) "
    "и рассылка (<code>/broadcast</code>) доступны только главному администратору."
)


# ═══════════════════════════════════════════════════════════════════════════
# Entry
# ═══════════════════════════════════════════════════════════════════════════

async def main() -> None:
    global _bot_ref
    if not BOT_TOKEN:
        raise SystemExit("BOT_TOKEN is not set.")
    db_init()
    log.info("DB initialized at %s", DB_PATH)

    dp = Dispatcher()
    register_handlers(dp)

    bot = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    _bot_ref = bot  # make the bot available to tg_log() from anywhere
    if LOG_CHANNEL_ID:
        log.info("Channel logging enabled → %s", LOG_CHANNEL_ID)
        try:
            await bot.send_message(LOG_CHANNEL_ID,
                "🟢 <b>PL Wallet бэкенд запущен</b>", parse_mode="HTML")
        except Exception as exc:
            log.warning("startup channel ping failed: %s", exc)

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
