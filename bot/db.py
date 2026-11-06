"""
SQLite schema + repository for PL Wallet.

All mutations go through `with conn()` which opens a per-call connection
(SQLite handles concurrency fine with WAL mode, and short-lived cursors
are cheaper than a shared pool here). Writes are issued from aiohttp /
aiogram handlers via `await asyncio.to_thread(repo_fn, ...)` so the event
loop isn't blocked on disk IO.

The schema is forward-compatible: adding a new column goes through
`ALTER TABLE` statements in `_migrate()`. Never drop a column — rename
or migrate out of band.
"""
from __future__ import annotations

import asyncio
import os
import random
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional

DB_PATH = Path(os.environ.get("DB_PATH", "data.db"))


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


@contextmanager
def conn() -> Iterator[sqlite3.Connection]:
    c = sqlite3.connect(DB_PATH, isolation_level=None)  # autocommit
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON")
    try:
        yield c
    finally:
        c.close()


def init_db() -> None:
    with conn() as c:
        c.executescript(SCHEMA)


def row_to_dict(row: sqlite3.Row | None) -> Optional[dict[str, Any]]:
    return dict(row) if row is not None else None


# ──────────────────────────────────────────────────────────────────────────
# Users
# ──────────────────────────────────────────────────────────────────────────

def _fresh_uid(c: sqlite3.Connection) -> int:
    """Return an 8-digit UID that isn't already taken. Retries up to 10×."""
    for _ in range(10):
        candidate = random.randint(10_000_000, 99_999_999)
        if not c.execute("SELECT 1 FROM users WHERE uid = ?", (candidate,)).fetchone():
            return candidate
    raise RuntimeError("UID pool exhausted — this should not happen")


def upsert_user(telegram_id: int, username: str | None, first_name: str | None) -> dict[str, Any]:
    now = int(time.time())
    with conn() as c:
        row = c.execute(
            "SELECT * FROM users WHERE telegram_id = ?", (telegram_id,)
        ).fetchone()
        if row:
            # Keep username/first_name fresh on every init.
            c.execute(
                "UPDATE users SET username = ?, first_name = ? WHERE telegram_id = ?",
                (username, first_name, telegram_id),
            )
            return row_to_dict(c.execute(
                "SELECT * FROM users WHERE telegram_id = ?", (telegram_id,)
            ).fetchone())  # type: ignore[return-value]
        uid = _fresh_uid(c)
        c.execute(
            "INSERT INTO users (telegram_id, uid, username, first_name, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (telegram_id, uid, username, first_name, now),
        )
        return row_to_dict(c.execute(
            "SELECT * FROM users WHERE telegram_id = ?", (telegram_id,)
        ).fetchone())  # type: ignore[return-value]


def user_by_id(user_id: int) -> Optional[dict[str, Any]]:
    with conn() as c:
        return row_to_dict(c.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone())


def user_by_uid(uid: int) -> Optional[dict[str, Any]]:
    with conn() as c:
        return row_to_dict(c.execute(
            "SELECT * FROM users WHERE uid = ?", (uid,)
        ).fetchone())


def user_by_tg(telegram_id: int) -> Optional[dict[str, Any]]:
    with conn() as c:
        return row_to_dict(c.execute(
            "SELECT * FROM users WHERE telegram_id = ?", (telegram_id,)
        ).fetchone())


def bump_user_stats(user_id: int, successful: int = 0, cancelled: int = 0, disputed: int = 0) -> None:
    with conn() as c:
        c.execute(
            "UPDATE users SET "
            "total_deals = total_deals + ?, "
            "successful_deals = successful_deals + ?, "
            "cancelled_deals  = cancelled_deals + ?, "
            "disputed_deals   = disputed_deals + ? "
            "WHERE id = ?",
            (successful + cancelled + disputed, successful, cancelled, disputed, user_id),
        )


# ──────────────────────────────────────────────────────────────────────────
# Wallets + balances
# ──────────────────────────────────────────────────────────────────────────

def save_wallet(user_id: int, currency: str, address: str) -> None:
    with conn() as c:
        c.execute(
            "INSERT INTO wallets (user_id, currency, address, updated_at) "
            "VALUES (?, ?, ?, strftime('%s','now')) "
            "ON CONFLICT(user_id, currency) DO UPDATE SET "
            "address = excluded.address, updated_at = excluded.updated_at",
            (user_id, currency, address),
        )


def delete_wallet(user_id: int, currency: str) -> None:
    with conn() as c:
        c.execute(
            "DELETE FROM wallets WHERE user_id = ? AND currency = ?",
            (user_id, currency),
        )


def wallets_of(user_id: int) -> dict[str, str]:
    with conn() as c:
        rows = c.execute(
            "SELECT currency, address FROM wallets WHERE user_id = ?",
            (user_id,),
        ).fetchall()
    return {r["currency"]: r["address"] for r in rows}


def balances_of(user_id: int) -> list[dict[str, Any]]:
    with conn() as c:
        rows = c.execute(
            "SELECT currency, balance FROM balances WHERE user_id = ?",
            (user_id,),
        ).fetchall()
    return [dict(r) for r in rows]


# ──────────────────────────────────────────────────────────────────────────
# Deals
# ──────────────────────────────────────────────────────────────────────────

VALID_STATUSES = {
    "awaiting_acceptance", "awaiting_payment", "paid",
    "payment_confirmed", "goods_sent", "completed",
    "cancelled", "disputed",
}


def create_direct_deal(
    initiator_id: int,
    role: str,                     # "buyer" | "seller"
    currency: str,
    amount: float,
    links: list[str],
) -> dict[str, Any]:
    """
    A "direct" deal has no counterparty at creation time. The initiator
    chooses whether they will be the buyer or the seller; whichever slot
    they don't fill gets assigned when the other side opens the deal
    link (see `assign_counterparty`).
    """
    if role not in ("buyer", "seller"):
        raise ValueError("role must be 'buyer' or 'seller'")
    now = int(time.time())
    buyer  = initiator_id if role == "buyer"  else None
    seller = initiator_id if role == "seller" else None
    links_blob = "\n".join(l.strip() for l in links if l and l.strip())

    with conn() as c:
        cur = c.execute(
            "INSERT INTO deals ("
            " initiator_id, buyer_id, seller_id,"
            " fiat_amount, fiat_currency, links,"
            " status, created_at, updated_at"
            ") VALUES (?, ?, ?, ?, ?, ?, 'awaiting_acceptance', ?, ?)",
            (initiator_id, buyer, seller, float(amount), currency, links_blob, now, now),
        )
        deal_id = cur.lastrowid
        return deal_with_parties(deal_id)  # type: ignore[return-value]


def assign_counterparty(deal_id: int, user_id: int) -> Optional[dict[str, Any]]:
    """
    Called when a non-initiator opens the deal. Assigns them to the empty
    buyer/seller slot. No-op if the deal already has both parties and the
    caller is one of them.
    """
    with conn() as c:
        row = c.execute("SELECT * FROM deals WHERE id = ?", (deal_id,)).fetchone()
        if not row:
            return None
        if row["buyer_id"] == user_id or row["seller_id"] == user_id or row["initiator_id"] == user_id:
            return deal_with_parties(deal_id)
        if row["status"] != "awaiting_acceptance":
            # Too late — deal already has a counterparty and the status moved on.
            return None
        if row["buyer_id"] is None:
            c.execute("UPDATE deals SET buyer_id = ?, updated_at = ? WHERE id = ?",
                      (user_id, int(time.time()), deal_id))
        elif row["seller_id"] is None:
            c.execute("UPDATE deals SET seller_id = ?, updated_at = ? WHERE id = ?",
                      (user_id, int(time.time()), deal_id))
        else:
            return None
    return deal_with_parties(deal_id)


def deal_with_parties(deal_id: int) -> Optional[dict[str, Any]]:
    """
    Return the deal row plus:
      - initiator: {uid, username, first_name, status}
      - buyer, seller: same shape (may be None if unassigned)
    Mirrors the frontend's expectations.
    """
    with conn() as c:
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
                "SELECT uid, username, first_name, status FROM users WHERE id = ?",
                (uid,),
            ).fetchone()
            deal[key] = dict(u) if u else None
        return deal


def deals_for(user_id: int) -> list[dict[str, Any]]:
    """
    Deals where the user is initiator, buyer or seller, newest first.
    """
    with conn() as c:
        rows = c.execute(
            "SELECT id FROM deals WHERE initiator_id = ? OR buyer_id = ? OR seller_id = ? "
            "ORDER BY updated_at DESC LIMIT 200",
            (user_id, user_id, user_id),
        ).fetchall()
    return [deal_with_parties(r["id"]) or {} for r in rows]


def update_deal_status(deal_id: int, new_status: str) -> None:
    if new_status not in VALID_STATUSES:
        raise ValueError(f"bad status: {new_status}")
    with conn() as c:
        c.execute(
            "UPDATE deals SET status = ?, updated_at = ? WHERE id = ?",
            (new_status, int(time.time()), deal_id),
        )


# ──────────────────────────────────────────────────────────────────────────
# Messages
# ──────────────────────────────────────────────────────────────────────────

def add_message(deal_id: int, user_id: int, text: str) -> dict[str, Any]:
    now = int(time.time())
    with conn() as c:
        cur = c.execute(
            "INSERT INTO messages (deal_id, user_id, text, created_at) VALUES (?, ?, ?, ?)",
            (deal_id, user_id, text, now),
        )
        row = c.execute("SELECT * FROM messages WHERE id = ?", (cur.lastrowid,)).fetchone()
    return dict(row)


def messages_of(deal_id: int, limit: int = 200) -> list[dict[str, Any]]:
    with conn() as c:
        rows = c.execute(
            "SELECT m.id, m.deal_id, m.user_id, m.text, m.created_at, u.username, u.first_name, u.uid "
            "FROM messages m JOIN users u ON u.id = m.user_id "
            "WHERE m.deal_id = ? ORDER BY m.id ASC LIMIT ?",
            (deal_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]


# ──────────────────────────────────────────────────────────────────────────
# Blocklist
# ──────────────────────────────────────────────────────────────────────────

def block(user_tg_id: int, reason: str | None = None) -> None:
    with conn() as c:
        c.execute(
            "INSERT INTO blocklist (user_id, blocked_at, reason) VALUES (?, ?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET blocked_at = excluded.blocked_at, reason = excluded.reason",
            (user_tg_id, int(time.time()), reason),
        )


def unblock(user_tg_id: int) -> None:
    with conn() as c:
        c.execute("DELETE FROM blocklist WHERE user_id = ?", (user_tg_id,))


def is_blocked(user_tg_id: int) -> bool:
    with conn() as c:
        return c.execute(
            "SELECT 1 FROM blocklist WHERE user_id = ?",
            (user_tg_id,),
        ).fetchone() is not None


def blocked_all() -> list[int]:
    with conn() as c:
        rows = c.execute("SELECT user_id FROM blocklist ORDER BY blocked_at DESC").fetchall()
    return [r["user_id"] for r in rows]


# ──────────────────────────────────────────────────────────────────────────
# Async wrappers — all repo functions above are sync; handlers call these.
# ──────────────────────────────────────────────────────────────────────────

async def aio(fn, *args, **kwargs):
    return await asyncio.to_thread(fn, *args, **kwargs)
