"""
REST API for pl.html — deals, wallets, messages, admin.

Mounted by main.py on its aiohttp Application alongside the admin
routes. Every route goes through:

  @need_user   → verify X-Telegram-Init-Data (HMAC+age) and 401 if bad
  @block_gate  → 423 if the current user is on the blocklist
  rate_limit   → per-IP token bucket, 429 with Retry-After on burst

Deal lifecycle:
    awaiting_acceptance → awaiting_payment → paid → payment_confirmed
                        → goods_sent → completed
                        (or → cancelled from any pre-payment_confirmed)
"""
from __future__ import annotations

import json
import os
import time
from functools import wraps
from typing import Awaitable, Callable, Optional

from aiohttp import web

from . import db
from .auth import InitUser, init_from_request


# ──────────────────────────────────────────────────────────────────────────
# Config / middleware
# ──────────────────────────────────────────────────────────────────────────

BOT_TOKEN      = os.environ.get("BOT_TOKEN", "")
ADMIN_ID       = int(os.environ.get("ADMIN_ID", "0") or "0")
MAX_MSG_LEN    = 1000
MAX_LINKS      = 10
MAX_LINK_LEN   = 500


def _client_ip(request: web.Request) -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    return xff.split(",")[0].strip() if xff else (request.remote or "unknown")


class RateLimiter:
    """Simple token bucket per key."""
    def __init__(self, rate_per_sec: float, burst: int) -> None:
        self.rate = rate_per_sec
        self.burst = burst
        self._state: dict[str, tuple[float, float]] = {}

    def allow(self, key: str) -> bool:
        now = time.time()
        tokens, last = self._state.get(key, (float(self.burst), now))
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        if tokens < 1.0:
            self._state[key] = (tokens, now)
            return False
        self._state[key] = (tokens - 1.0, now)
        return True


_rl_read   = RateLimiter(rate_per_sec=4.0, burst=40)   # GETs — browsing
_rl_write  = RateLimiter(rate_per_sec=1.5, burst=15)   # POST/PUT/DELETE


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
    """Resolve the Telegram user from initData and upsert them. Attach the
    DB row to request['user']; 401 if initData is missing or bad."""
    @wraps(handler)
    async def inner(request: web.Request) -> web.StreamResponse:
        init = init_from_request(request, BOT_TOKEN)
        if not init:
            return web.json_response({"detail": "unauthorized"}, status=401)
        # Reflect any fresh username/first_name into the DB so the profile
        # shows what the client sees.
        user = await db.aio(db.upsert_user, init.id, init.username, init.first_name)
        request["user"] = user
        request["init"] = init
        return await handler(request)
    return inner


def block_gate(handler):
    @wraps(handler)
    async def inner(request: web.Request) -> web.StreamResponse:
        init: Optional[InitUser] = request.get("init")
        if init and await db.aio(db.is_blocked, init.id):
            return web.json_response({"detail": "blocked"}, status=423)
        return await handler(request)
    return inner


# CORS: strict allowlist. The mini-app lives at pl-wallet.com; allow the
# telegram WebView origin ("null") too.
ALLOWED_ORIGINS = {o.strip() for o in os.environ.get(
    "CORS_ORIGINS", "https://pl-wallet.com,https://www.pl-wallet.com,null"
).split(",") if o.strip()}


@web.middleware
async def cors_middleware(request: web.Request, handler) -> web.StreamResponse:
    origin = request.headers.get("Origin", "")
    allow = origin if (not ALLOWED_ORIGINS or origin in ALLOWED_ORIGINS or "*" in ALLOWED_ORIGINS) else ""
    if request.method == "OPTIONS":
        return web.Response(status=204, headers={
            "Access-Control-Allow-Origin": allow,
            "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Telegram-Init-Data",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Max-Age": "600",
            "Vary": "Origin",
        })
    try:
        resp = await handler(request)
    except web.HTTPException as exc:
        resp = exc
    resp.headers.setdefault("Access-Control-Allow-Origin", allow)
    resp.headers.setdefault("Vary", "Origin")
    return resp


# ──────────────────────────────────────────────────────────────────────────
# User + wallets
# ──────────────────────────────────────────────────────────────────────────

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
    u = request["user"]
    return web.json_response(await db.aio(db.wallets_of, u["id"]))


@rate_limit(_rl_write)
@need_user
@block_gate
async def route_wallets_save(request: web.Request) -> web.Response:
    u = request["user"]
    try:
        body = await request.json()
        sym = str(body["wallet_type"]).strip().upper()
        addr = str(body["address"]).strip()
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return web.json_response({"detail": "bad_request"}, status=400)
    if not (1 <= len(sym) <= 10) or not (10 <= len(addr) <= 200):
        return web.json_response({"detail": "bad_request"}, status=400)
    await db.aio(db.save_wallet, u["id"], sym, addr)
    return web.json_response({"ok": True})


@rate_limit(_rl_write)
@need_user
@block_gate
async def route_wallets_delete(request: web.Request) -> web.Response:
    u = request["user"]
    sym = request.match_info.get("sym", "").upper()
    await db.aio(db.delete_wallet, u["id"], sym)
    return web.json_response({"ok": True})


@rate_limit(_rl_read)
@need_user
@block_gate
async def route_balances(request: web.Request) -> web.Response:
    u = request["user"]
    return web.json_response(await db.aio(db.balances_of, u["id"]))


# ──────────────────────────────────────────────────────────────────────────
# Deals
# ──────────────────────────────────────────────────────────────────────────

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
    deal = await db.aio(db.create_direct_deal, u["id"], role, currency, amount, links)
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
    deal = await db.aio(db.deal_with_parties, did)
    if not deal:
        return web.json_response({"detail": "not_found"}, status=404)
    me = u["id"]
    parties = {deal.get("initiator_id"), deal.get("buyer_id"), deal.get("seller_id")}
    if me not in parties:
        # First opener of a direct deal → auto-register as counterparty.
        if deal["status"] == "awaiting_acceptance" and (deal["buyer_id"] is None or deal["seller_id"] is None):
            deal = await db.aio(db.assign_counterparty, did, me)
            if not deal:
                return web.json_response({"detail": "forbidden"}, status=403)
        else:
            return web.json_response({"detail": "forbidden"}, status=403)
    return web.json_response(deal)


@rate_limit(_rl_read)
@need_user
@block_gate
async def route_deals_list(request: web.Request) -> web.Response:
    u = request["user"]
    rows = await db.aio(db.deals_for, u["id"])
    return web.json_response(rows)


# ── Status transitions ────────────────────────────────────────────────────

# Mapping: endpoint action → (expected prev status, next status, who may do it)
# "who" is a function of the deal + user_id → bool.
def _is_buyer(deal: dict, uid: int) -> bool:   return deal.get("buyer_id") == uid
def _is_seller(deal: dict, uid: int) -> bool:  return deal.get("seller_id") == uid
def _is_either(deal: dict, uid: int) -> bool:  return _is_buyer(deal, uid) or _is_seller(deal, uid)

TRANSITIONS: dict[str, tuple[str, str, Callable[[dict, int], bool]]] = {
    "accept":          ("awaiting_acceptance", "awaiting_payment",   _is_either),
    "pay":             ("awaiting_payment",    "paid",               _is_buyer),
    "confirm-payment": ("paid",                "payment_confirmed",  _is_seller),
    "ship":            ("payment_confirmed",   "goods_sent",         _is_seller),
    "confirm":         ("goods_sent",          "completed",          _is_buyer),
}


async def _apply_status_change(
    request: web.Request, action: str
) -> web.Response:
    u = request["user"]
    try:
        did = int(request.match_info["id"])
    except (KeyError, ValueError):
        return web.json_response({"detail": "bad_id"}, status=400)
    if action not in TRANSITIONS:
        return web.json_response({"detail": "bad_action"}, status=400)
    prev, nxt, allowed = TRANSITIONS[action]

    deal = await db.aio(db.deal_with_parties, did)
    if not deal:
        return web.json_response({"detail": "not_found"}, status=404)
    if deal["status"] != prev:
        return web.json_response({"detail": "bad_state", "current": deal["status"]}, status=409)
    if not allowed(deal, u["id"]):
        return web.json_response({"detail": "forbidden"}, status=403)

    await db.aio(db.update_deal_status, did, nxt)

    # Terminal-status side effects on the stats counters.
    if nxt == "completed":
        if deal.get("buyer_id"):  await db.aio(db.bump_user_stats, deal["buyer_id"],  successful=1)
        if deal.get("seller_id"): await db.aio(db.bump_user_stats, deal["seller_id"], successful=1)

    return web.json_response(await db.aio(db.deal_with_parties, did))


@rate_limit(_rl_write)
@need_user
@block_gate
async def route_deal_action(request: web.Request) -> web.Response:
    return await _apply_status_change(request, request.match_info.get("action", ""))


@rate_limit(_rl_write)
@need_user
@block_gate
async def route_deal_cancel(request: web.Request) -> web.Response:
    u = request["user"]
    try:
        did = int(request.match_info["id"])
    except (KeyError, ValueError):
        return web.json_response({"detail": "bad_id"}, status=400)
    deal = await db.aio(db.deal_with_parties, did)
    if not deal:
        return web.json_response({"detail": "not_found"}, status=404)
    if not _is_either(deal, u["id"]) and deal.get("initiator_id") != u["id"]:
        return web.json_response({"detail": "forbidden"}, status=403)
    # You can only cancel before the seller confirms payment — after that,
    # the funds are live and a cancel is actually a dispute, not a cancel.
    if deal["status"] in {"payment_confirmed", "goods_sent", "completed", "cancelled"}:
        return web.json_response({"detail": "bad_state"}, status=409)
    await db.aio(db.update_deal_status, did, "cancelled")
    if deal.get("buyer_id"):  await db.aio(db.bump_user_stats, deal["buyer_id"],  cancelled=1)
    if deal.get("seller_id"): await db.aio(db.bump_user_stats, deal["seller_id"], cancelled=1)
    return web.json_response(await db.aio(db.deal_with_parties, did))


# ──────────────────────────────────────────────────────────────────────────
# Messages
# ──────────────────────────────────────────────────────────────────────────

@rate_limit(_rl_read)
@need_user
@block_gate
async def route_messages_list(request: web.Request) -> web.Response:
    u = request["user"]
    try:
        did = int(request.match_info["id"])
    except (KeyError, ValueError):
        return web.json_response({"detail": "bad_id"}, status=400)
    deal = await db.aio(db.deal_with_parties, did)
    if not deal:
        return web.json_response({"detail": "not_found"}, status=404)
    if u["id"] not in (deal.get("initiator_id"), deal.get("buyer_id"), deal.get("seller_id")):
        return web.json_response({"detail": "forbidden"}, status=403)
    return web.json_response(await db.aio(db.messages_of, did))


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
    deal = await db.aio(db.deal_with_parties, did)
    if not deal:
        return web.json_response({"detail": "not_found"}, status=404)
    if u["id"] not in (deal.get("initiator_id"), deal.get("buyer_id"), deal.get("seller_id")):
        return web.json_response({"detail": "forbidden"}, status=403)
    msg = await db.aio(db.add_message, did, u["id"], text)
    # Decorate with sender's handle so the frontend doesn't need a second
    # lookup.
    msg["username"]   = u["username"]
    msg["first_name"] = u["first_name"]
    msg["uid"]        = u["uid"]
    return web.json_response(msg, status=201)


# ──────────────────────────────────────────────────────────────────────────
# Admin routes (block / unblock / list)
# ──────────────────────────────────────────────────────────────────────────

def _require_admin(request: web.Request) -> Optional[InitUser]:
    init = init_from_request(request, BOT_TOKEN)
    if not init:
        return None
    if ADMIN_ID == 0 or init.id != ADMIN_ID:
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
    await db.aio(db.block, uid, "admin")
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
    await db.aio(db.unblock, uid)
    return web.json_response({"ok": True, "unblocked": uid})


@rate_limit(_rl_read)
async def route_admin_list(request: web.Request) -> web.Response:
    if _require_admin(request) is None:
        return web.json_response({"detail": "forbidden"}, status=403)
    return web.json_response({"blocked": await db.aio(db.blocked_all)})


# ──────────────────────────────────────────────────────────────────────────
# Public /api/status — anyone (the mini-app) can poll block state for a UID.
# ──────────────────────────────────────────────────────────────────────────

@rate_limit(_rl_read)
async def route_status(request: web.Request) -> web.Response:
    try:
        uid = int(request.query.get("user_id", "0"))
    except ValueError:
        return web.json_response({"detail": "bad_user_id"}, status=400)
    return web.json_response({"blocked": await db.aio(db.is_blocked, uid), "user_id": uid})


@rate_limit(_rl_read)
async def route_verify(request: web.Request) -> web.Response:
    try:
        body = await request.json()
        init = body.get("init_data", "")
    except (ValueError, json.JSONDecodeError):
        return web.json_response({"detail": "bad_request"}, status=400)
    from .auth import verify_init_data
    user = verify_init_data(init, BOT_TOKEN)
    if not user:
        return web.json_response({"valid": False})
    return web.json_response({
        "valid":    True,
        "user_id":  user.id,
        "is_admin": ADMIN_ID != 0 and user.id == ADMIN_ID,
        "blocked":  await db.aio(db.is_blocked, user.id),
    })


# ──────────────────────────────────────────────────────────────────────────
# Routes assembly
# ──────────────────────────────────────────────────────────────────────────

def make_app() -> web.Application:
    app = web.Application(middlewares=[cors_middleware])
    r = app.router

    # User + wallets
    r.add_get   ("/api/user/me",            route_me)
    r.add_get   ("/api/wallets",            route_wallets_list)
    r.add_post  ("/api/wallets",            route_wallets_save)
    r.add_delete("/api/wallets/{sym}",      route_wallets_delete)
    r.add_get   ("/api/wallet/balances",    route_balances)

    # Deals
    r.add_post  ("/api/deals/direct",       route_deal_create_direct)
    r.add_get   ("/api/deals/my/list",      route_deals_list)
    r.add_get   ("/api/deals/{id}",         route_deal_get)
    r.add_put   ("/api/deals/{id}/{action:accept|pay|confirm-payment|ship|confirm}",
                 route_deal_action)
    r.add_put   ("/api/deals/{id}/cancel",  route_deal_cancel)

    # Messages
    r.add_get   ("/api/deals/{id}/messages",  route_messages_list)
    r.add_post  ("/api/deals/{id}/messages",  route_messages_post)

    # Admin + status
    r.add_get   ("/api/status",             route_status)
    r.add_post  ("/api/verify",             route_verify)
    r.add_get   ("/api/admin/list",         route_admin_list)
    r.add_post  ("/api/admin/block",        route_admin_block)
    r.add_post  ("/api/admin/unblock",      route_admin_unblock)

    return app
