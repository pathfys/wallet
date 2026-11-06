"""
Telegram WebApp initData verification. One import point for both bot.py
and api.py so the HMAC check never diverges between them.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from time import time
from typing import Optional
from urllib.parse import parse_qsl


INIT_MAX_AGE = int(os.environ.get("INIT_MAX_AGE", "300"))


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
    Official Telegram WebApp HMAC check:
        secret_key   = HMAC_SHA256("WebAppData", bot_token)
        data_check   = "\n".join(sorted "k=v" pairs, excluding "hash")
        expected_hex = HMAC_SHA256(secret_key, data_check).hex()
    Rejects payloads older than max_age seconds so a leaked initData
    can't be replayed forever. Timing-safe comparison via hmac.compare_digest.
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
    if max_age > 0 and (time() - auth_date) > max_age:
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


def init_from_request(request, bot_token: str) -> Optional[InitUser]:
    """
    Pull the initData from either the standard `X-Telegram-Init-Data`
    header (what the current frontend sends) or an `Authorization: tma
    <initData>` header (what the admin surface uses). Verify and return
    the parsed user, or None.
    """
    init = request.headers.get("X-Telegram-Init-Data", "")
    if not init:
        auth = request.headers.get("Authorization", "")
        if auth.lower().startswith("tma "):
            init = auth[4:].strip()
    if not init:
        return None
    return verify_init_data(init, bot_token)
