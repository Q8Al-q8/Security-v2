import asyncio
import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from urllib.parse import quote, urlencode, urlparse

from aiohttp import ClientError, ClientSession, web

try:
    from pymongo import MongoClient, UpdateOne
    from pymongo.errors import PyMongoError
except Exception:
    MongoClient = None
    UpdateOne = None

    class PyMongoError(Exception):
        pass


SITE_NAME = os.getenv("SITE_NAME", "ARAB SECURITY").strip() or "ARAB SECURITY"
OWNER_NAME = os.getenv("OWNER_NAME", "سعود الظفيري").strip() or "كايد"
ADMIN_USER_ID = os.getenv("ADMIN_USER_ID", "1395418036919468073").strip() or "1395418036919468073"

DEFAULT_DOMAIN_URL = "https://3rabsecurity.de5.net"
DEFAULT_REDIRECT_URI = f"{DEFAULT_DOMAIN_URL}/callback"
SUPPORT_SERVER_URL = os.getenv("SUPPORT_SERVER_URL", "https://discord.gg/khQXQCtjMS").strip()

HOST = os.getenv("HOST", "0.0.0.0").strip() or "0.0.0.0"
PORT = int(os.getenv("PORT", "8080") or "8080")

EXPLICIT_MAIN_URL = os.getenv("MAIN_SITE_URL", DEFAULT_DOMAIN_URL).strip().rstrip("/")
EXPLICIT_WEB_URL = os.getenv("WEB_BASE_URL", DEFAULT_DOMAIN_URL).strip().rstrip("/")
EXPLICIT_REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI", DEFAULT_REDIRECT_URI).strip()

BOT_INVITE_URL = os.getenv(
    "BOT_INVITE_URL",
    "https://discord.com/oauth2/authorize?client_id=1573635674551357550&permissions=8&integration_type=0&scope=bot%20applications.commands",
).strip()

MONGO_DB_NAME = os.getenv("MONGO_DB", "arab_security").strip() or "arab_security"
MONGO_USER = os.getenv("MONGO_USER", "soudfares02_db_user").strip()
MONGO_PASS = os.getenv("MONGO_PASS", "YCVAVw2LXBy5XSbO").strip()
MONGO_HOST = os.getenv("MONGO_HOST", "").strip()
MONGO_URI = os.getenv("MONGO_URI", "").strip()

if not MONGO_URI and MONGO_HOST and MONGO_USER and MONGO_PASS:
    safe_user = quote(MONGO_USER, safe="")
    safe_pass = quote(MONGO_PASS, safe="")
    clean_host = MONGO_HOST.replace("mongodb+srv://", "").replace("mongodb://", "").strip("/")
    MONGO_URI = f"mongodb+srv://{safe_user}:{safe_pass}@{clean_host}/{MONGO_DB_NAME}?retryWrites=true&w=majority"

SESSION_SECRET = (
    os.getenv("SESSION_SECRET")
    or "sOQnMK8W9_sc2dG43DfyS4U2opgODUaM"
).strip()
BOT_SYNC_SECRET = (os.getenv("BOT_SYNC_SECRET") or SESSION_SECRET).strip()
RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", "180") or "180")
AUTH_RATE_LIMIT_PER_MIN = int(os.getenv("AUTH_RATE_LIMIT_PER_MIN", "35") or "35")

TRUST_PROXY = os.getenv("TRUST_PROXY", "true").strip().lower() in ("1", "true", "yes", "on")
TRUSTED_PROXY_IPS = {
    ip.strip()
    for ip in os.getenv("TRUSTED_PROXY_IPS", "").split(",")
    if ip.strip()
}

DISCORD_CLIENT_ID = os.getenv("1573635674551357550", "1573635674551357550").strip()
DISCORD_CLIENT_SECRET = os.getenv("sOQnMK8W9_sc2dG43DfyS4U2opgODUaM", "sOQnMK8W9_sc2dG43DfyS4U2opgODUaM").strip()

if not SESSION_SECRET or len(SESSION_SECRET) < 16:
    raise RuntimeError("SESSION_SECRET مطلوب ويجب أن يكون بطول 16 حرفاً على الأقل.")
if not ADMIN_USER_ID.isdigit():
    raise RuntimeError("ADMIN_USER_ID يجب أن يكون رقماً صحيحاً.")

ANTINUKE_RULE_KEYS = (
    "anti_ban",
    "anti_kick",
    "anti_role_create",
    "anti_role_delete",
    "anti_channel_create",
    "anti_channel_delete",
    "anti_webhook_create",
    "anti_bot_add",
    "anti_guild_update",
)

SHIELD_TOGGLE_KEYS = (
    "anti_webhook_abuse",
    "anti_app_abuse",
    "anti_privilege_escalation",
    "anti_role_tamper",
    "anti_channel_perms_tamper",
    "audit_log_watch",
    "anti_mass_unban",
    "anti_mass_kick",
    "anti_mass_timeout",
    "admin_behavior_analysis",
    "trusted_admins_enabled",
    "perms_snapshot_enabled",
    "auto_rollback_enabled",
    "gradual_attack_detect",
    "collusion_detect",
    "false_punishment_guard",
    "emergency_mode",
    "auto_perms_audit",
    "silent_mode",
    "anti_invites",
    "voice_lock",
)


def _fresh_default_guild_cfg() -> dict:
    return {
        "prefix": "!",
        "maintenance": False,
        "mod_log_channel": "",
        "anti_spam": True,
        "anti_link": False,
        "anti_invites": True,
        "voice_lock": False,
        "silent_mode": False,
        "beast_mode": False,
        "anti_raid": False,
        "verification": False,
        "lockdown": False,
        "anti_new_accounts": False,
        "min_account_age_days": 7,
        "dangerous_perms_guard": True,
        "alert_on_trigger": True,
        "anti_webhook_abuse": True,
        "anti_app_abuse": True,
        "anti_privilege_escalation": True,
        "anti_role_tamper": True,
        "anti_channel_perms_tamper": True,
        "audit_log_watch": True,
        "anti_mass_unban": True,
        "anti_mass_kick": True,
        "anti_mass_timeout": True,
        "admin_behavior_analysis": True,
        "trusted_admins_enabled": True,
        "perms_snapshot_enabled": True,
        "auto_rollback_enabled": True,
        "gradual_attack_detect": True,
        "collusion_detect": True,
        "false_punishment_guard": True,
        "emergency_mode": False,
        "auto_perms_audit": True,
        "trusted_admins": [ADMIN_USER_ID],
        "perms_snapshots": [],
        "antinuke": {
            "anti_ban": {"enabled": True, "limit": 1, "punishment": "Kick"},
            "anti_kick": {"enabled": True, "limit": 1, "punishment": "Kick"},
            "anti_role_create": {"enabled": True, "limit": 1, "punishment": "Kick"},
            "anti_role_delete": {"enabled": True, "limit": 1, "punishment": "Ban"},
            "anti_channel_create": {"enabled": True, "limit": 2, "punishment": "Kick"},
            "anti_channel_delete": {"enabled": True, "limit": 1, "punishment": "Ban"},
            "anti_webhook_create": {"enabled": True, "limit": 1, "punishment": "Ban"},
            "anti_bot_add": {"enabled": True, "limit": 1, "punishment": "Ban"},
            "anti_guild_update": {"enabled": True, "limit": 1, "punishment": "Kick"},
        },
        "whitelist": [],
        "guild_profile": {
            "bio": "",
            "avatar_url": "",
            "banner_url": "",
        },
        "premium_perks": {
            "ultra_fortress_mode": False,
            "instant_rollback_enabled": True,
            "priority_shield_response": True,
            "alert_channel_id": "",
            "alert_webhook_url": "",
            "last_restored_snapshot": "",
        },
    }


MEM_LOGS: deque[dict] = deque(maxlen=300)
MEM_INCIDENTS: deque[dict] = deque(maxlen=200)
MEM_GUILDS: dict[str, dict] = {}
MEM_GUILD_CFG: dict[str, dict] = defaultdict(_fresh_default_guild_cfg)
MEM_QUEUE: deque[dict] = deque(maxlen=200)
MEM_PREMIUM: set[str] = {ADMIN_USER_ID}
MEM_ADMINS: set[str] = {ADMIN_USER_ID}
MEM_VISITORS: dict[str, object] = {
    "total_visits": 0,
    "unique_hashes": deque(maxlen=5000),
    "unique_seen": set(),
}
MEM_BACKUPS: deque[dict] = deque(maxlen=25)
MEM_BOT_HEARTBEAT: dict[str, str] = {
    "status": "ONLINE",
    "last_seen": "",
    "latency_ms": "6ms",
}

_CFG_CACHE: dict[str, tuple[float, dict]] = {}
_CFG_TTL = 10.0

_PERM_CACHE: dict[str, tuple[float, bool]] = {}
_PERM_TTL = 15.0

_GUILDS_CACHE: tuple[float, list[dict]] = (0.0, [])
_GUILDS_TTL = 2.0

_VISIT_STATS_CACHE: tuple[float, int, int] = (0.0, 0, 0)
_VISIT_STATS_TTL = 8.0

_PENDING_VISITS = 0
_PENDING_UNIQUE: list[str] = []
_LAST_VISIT_FLUSH = 0.0

CSRF_TOKENS: dict[str, dict] = {}
OAUTH_STATES: dict[str, float] = {}
USED_NONCES: dict[str, float] = {}
RATE_BUCKETS: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=500))
AUTH_RATE_BUCKETS: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=150))
SESSIONS: dict[str, dict] = {}


def esc(val) -> str:
    return html.escape(str(val or ""), quote=True)


def sanitize_http_url(raw_url: str | None) -> str:
    val = str(raw_url or "").strip()[:400]
    if not val:
        return ""
    try:
        parsed = urlparse(val)
    except Exception:
        return ""
    if parsed.scheme.lower() not in ("https", "http") or not parsed.netloc:
        return ""
    return val


def sanitize_flash_msg(raw_msg: str | None) -> str:
    cleaned = "".join(ch for ch in str(raw_msg or "") if ch.isprintable()).strip()
    return cleaned[:240]


def _now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _safe_exp(val) -> float:
    if isinstance(val, dict):
        val = val.get("exp", 0)
    try:
        return float(val)
    except Exception:
        return 0.0


def _cleanup_expired() -> None:
    now = time.time()
    for k, meta in list(CSRF_TOKENS.items()):
        if _safe_exp(meta.get("exp", 0)) <= now:
            CSRF_TOKENS.pop(k, None)
    for st, exp in list(OAUTH_STATES.items()):
        if _safe_exp(exp) <= now:
            OAUTH_STATES.pop(st, None)
    for n, exp in list(USED_NONCES.items()):
        if _safe_exp(exp) <= now:
            USED_NONCES.pop(n, None)
    for sid, sess in list(SESSIONS.items()):
        if _safe_exp(sess.get("exp", 0)) <= now:
            SESSIONS.pop(sid, None)


def issue_oauth_state() -> str:
    _cleanup_expired()
    st = secrets.token_urlsafe(24)
    if len(OAUTH_STATES) >= 2000:
        oldest = next(iter(OAUTH_STATES))
        OAUTH_STATES.pop(oldest, None)
    OAUTH_STATES[st] = time.time() + 600.0
    return st


def consume_oauth_state(state_val: str | None) -> bool:
    _cleanup_expired()
    clean = str(state_val or "").strip()
    if not clean or clean not in OAUTH_STATES:
        return False
    exp = _safe_exp(OAUTH_STATES.pop(clean))
    return exp > time.time()


def issue_csrf_token(session_id: str) -> str:
    _cleanup_expired()
    tok = secrets.token_hex(24)
    if len(CSRF_TOKENS) >= 5000:
        oldest = next(iter(CSRF_TOKENS))
        CSRF_TOKENS.pop(oldest, None)
    CSRF_TOKENS[tok] = {
        "sid": str(session_id or ""),
        "exp": time.time() + 3600.0,
    }
    return tok


def consume_csrf_token(tok: str | None, session_id: str | None) -> bool:
    _cleanup_expired()
    clean_tok = str(tok or "").strip()
    clean_sid = str(session_id or "").strip()
    if not clean_tok or not clean_sid or clean_tok not in CSRF_TOKENS:
        return False
    meta = CSRF_TOKENS.pop(clean_tok)
    if _safe_exp(meta.get("exp", 0)) <= time.time():
        return False
    return hmac.compare_digest(str(meta.get("sid", "")), clean_sid)


def is_replay_request(nonce: str | None) -> bool:
    _cleanup_expired()
    clean = str(nonce or "").strip()
    if not clean:
        return False
    if clean in USED_NONCES:
        return True
    if len(USED_NONCES) >= 5000:
        oldest = next(iter(USED_NONCES))
        USED_NONCES.pop(oldest, None)
    USED_NONCES[clean] = time.time() + 300.0
    return False


def _sign_hmac(msg: str) -> str:
    return hmac.new(SESSION_SECRET.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()


db = None
logs_col = None
incidents_col = None
bot_guilds_col = None
guild_settings_col = None
queue_col = None
premium_col = None
admins_col = None
stats_col = None
backups_col = None

if MONGO_URI and MongoClient is not None:
    try:
        client = MongoClient(
            MONGO_URI,
            serverSelectionTimeoutMS=900,
            connectTimeoutMS=900,
            socketTimeoutMS=1200,
            maxPoolSize=30,
        )
        client.admin.command("ping")
        db = client[MONGO_DB_NAME]
        logs_col = db["activity_logs"]
        incidents_col = db["security_incidents"]
        bot_guilds_col = db["bot_guilds"]
        guild_settings_col = db["guild_settings"]
        queue_col = db["remote_commands"]
        premium_col = db["premium_users"]
        admins_col = db["site_admins"]
        stats_col = db["site_stats"]
        backups_col = db["db_backups"]

        premium_col.update_one(
            {"user_id": ADMIN_USER_ID},
            {"$set": {"user_id": ADMIN_USER_ID, "granted_by": "system", "updated_at": _now_str()}},
            upsert=True,
        )
        admins_col.update_one(
            {"user_id": ADMIN_USER_ID},
            {"$set": {"user_id": ADMIN_USER_ID, "granted_by": "owner", "updated_at": _now_str()}},
            upsert=True,
        )
    except (PyMongoError, Exception) as exc:
        print(f"[DB] تنبيه: تشغيل بالذاكرة الاحتياطية ({type(exc).__name__})")


def _invalidate_perm_cache(uid: str = "") -> None:
    if uid:
        for k in list(_PERM_CACHE.keys()):
            if k.endswith(f":{uid}"):
                _PERM_CACHE.pop(k, None)
    else:
        _PERM_CACHE.clear()


def _invalidate_guilds_cache() -> None:
    global _GUILDS_CACHE
    _GUILDS_CACHE = (0.0, [])


def get_client_ip(request: web.Request) -> str:
    remote_ip = str(request.remote or "").strip()
    can_trust_xff = TRUST_PROXY and (not TRUSTED_PROXY_IPS or remote_ip in TRUSTED_PROXY_IPS)
    if can_trust_xff:
        xff_parts = [p.strip() for p in request.headers.get("X-Forwarded-For", "").split(",") if p.strip()]
        if xff_parts:
            return xff_parts[-1][:64]
    return (remote_ip or "unknown")[:64]


def flush_visits_if_needed(force: bool = False) -> None:
    global _PENDING_VISITS, _PENDING_UNIQUE, _LAST_VISIT_FLUSH
    now = time.time()
    if not force and (now - _LAST_VISIT_FLUSH) < 6.0 and _PENDING_VISITS < 30:
        return
    if stats_col is None or (_PENDING_VISITS == 0 and not _PENDING_UNIQUE):
        _LAST_VISIT_FLUSH = now
        return
    inc_v = _PENDING_VISITS
    uniq_batch = list(_PENDING_UNIQUE)
    _PENDING_VISITS = 0
    _PENDING_UNIQUE = []
    _LAST_VISIT_FLUSH = now
    try:
        if inc_v > 0:
            stats_col.update_one(
                {"_id": "visitors"},
                {"$inc": {"total_visits": inc_v}, "$set": {"updated_at": _now_str()}},
                upsert=True,
            )
        for vh in uniq_batch[:40]:
            stats_col.update_one(
                {"_id": f"uv_{vh}"},
                {"$set": {"hash": vh, "seen_at": _now_str()}},
                upsert=True,
            )
    except PyMongoError:
        pass


def record_site_visit(request: web.Request) -> None:
    global _PENDING_VISITS, _PENDING_UNIQUE
    if request.path.startswith(("/health", "/api/")):
        return
    ip = get_client_ip(request)
    ua = request.headers.get("User-Agent", "")
    v_hash = hashlib.sha256(f"{ip}|{ua}|{SESSION_SECRET}".encode("utf-8")).hexdigest()[:24]

    MEM_VISITORS["total_visits"] = int(MEM_VISITORS.get("total_visits", 0)) + 1
    _PENDING_VISITS += 1

    u_deque: deque = MEM_VISITORS["unique_hashes"]  # type: ignore[assignment]
    u_seen: set = MEM_VISITORS["unique_seen"]  # type: ignore[assignment]
    if v_hash not in u_seen:
        if len(u_deque) == u_deque.maxlen:
            evicted = u_deque.popleft()
            u_seen.discard(evicted)
        u_deque.append(v_hash)
        u_seen.add(v_hash)
        _PENDING_UNIQUE.append(v_hash)

    flush_visits_if_needed(force=False)


def get_visitor_stats() -> tuple[int, int]:
    global _VISIT_STATS_CACHE
    now = time.time()
    if (now - _VISIT_STATS_CACHE[0]) < _VISIT_STATS_TTL:
        return _VISIT_STATS_CACHE[1], _VISIT_STATS_CACHE[2]

    mem_total = int(MEM_VISITORS.get("total_visits", 0))
    mem_unique = len(MEM_VISITORS.get("unique_seen", set()))  # type: ignore[arg-type]
    db_total = 0
    db_unique = mem_unique
    if stats_col is not None:
        try:
            vdoc = stats_col.find_one({"_id": "visitors"}, {"total_visits": 1})
            if vdoc:
                db_total = int(vdoc.get("total_visits", 0) or 0)
        except PyMongoError:
            pass
    tot = max(mem_total, db_total)
    uniq = max(mem_unique, db_unique, 1 if tot > 0 else 0)
    _VISIT_STATS_CACHE = (now, tot, uniq)
    return tot, uniq


def is_site_admin(user: dict | None) -> bool:
    if not user:
        return False
    uid = str(user.get("id", "")).strip()
    if not uid.isdigit():
        return False
    if uid == ADMIN_USER_ID or uid in MEM_ADMINS:
        return True
    cache_key = f"admin:{uid}"
    cached = _PERM_CACHE.get(cache_key)
    if cached and (time.time() - cached[0]) < _PERM_TTL:
        return cached[1]
    res = False
    if admins_col is not None:
        try:
            if admins_col.find_one({"user_id": uid}, {"_id": 1}) is not None:
                MEM_ADMINS.add(uid)
                res = True
        except PyMongoError:
            pass
    _PERM_CACHE[cache_key] = (time.time(), res)
    return res


def get_admin_list() -> list[dict]:
    items: dict[str, dict] = {
        ADMIN_USER_ID: {"user_id": ADMIN_USER_ID, "granted_by": "owner", "updated_at": "-"}
    }
    for uid in MEM_ADMINS:
        if uid not in items:
            items[uid] = {"user_id": uid, "granted_by": "admin", "updated_at": "-"}
    if admins_col is not None:
        try:
            for doc in admins_col.find({}, {"_id": 0}).limit(100):
                uid = str(doc.get("user_id", "")).strip()
                if uid.isdigit():
                    items[uid] = {
                        "user_id": uid,
                        "granted_by": str(doc.get("granted_by", "owner")),
                        "updated_at": str(doc.get("updated_at", "-")),
                    }
        except PyMongoError:
            pass
    return list(items.values())


def set_admin_user(user_id: str, enabled: bool, granted_by: str = "") -> bool:
    uid = str(user_id or "").strip()
    if not uid.isdigit():
        return False
    _invalidate_perm_cache(uid)
    if enabled:
        MEM_ADMINS.add(uid)
        MEM_PREMIUM.add(uid)
        if admins_col is not None:
            try:
                admins_col.update_one(
                    {"user_id": uid},
                    {"$set": {"user_id": uid, "granted_by": granted_by or ADMIN_USER_ID, "updated_at": _now_str()}},
                    upsert=True,
                )
            except PyMongoError:
                pass
        if premium_col is not None:
            try:
                premium_col.update_one(
                    {"user_id": uid},
                    {"$set": {"user_id": uid, "granted_by": granted_by or ADMIN_USER_ID, "updated_at": _now_str()}},
                    upsert=True,
                )
            except PyMongoError:
                pass
        return True
    if uid == ADMIN_USER_ID:
        return False
    MEM_ADMINS.discard(uid)
    if admins_col is not None:
        try:
            admins_col.delete_one({"user_id": uid})
        except PyMongoError:
            pass
    return True


def is_premium_user(user: dict | None) -> bool:
    if not user:
        return False
    uid = str(user.get("id", "")).strip()
    if not uid.isdigit():
        return False
    if is_site_admin(user) or uid in MEM_PREMIUM:
        return True
    cache_key = f"prem:{uid}"
    cached = _PERM_CACHE.get(cache_key)
    if cached and (time.time() - cached[0]) < _PERM_TTL:
        return cached[1]
    res = False
    if premium_col is not None:
        try:
            if premium_col.find_one({"user_id": uid}, {"_id": 1}) is not None:
                MEM_PREMIUM.add(uid)
                res = True
        except PyMongoError:
            pass
    _PERM_CACHE[cache_key] = (time.time(), res)
    return res


def get_premium_list() -> list[dict]:
    items: dict[str, dict] = {
        ADMIN_USER_ID: {"user_id": ADMIN_USER_ID, "granted_by": "owner", "updated_at": "-"}
    }
    for uid in MEM_PREMIUM:
        if uid not in items:
            items[uid] = {"user_id": uid, "granted_by": "admin", "updated_at": "-"}
    if premium_col is not None:
        try:
            for doc in premium_col.find({}, {"_id": 0}).limit(150):
                uid = str(doc.get("user_id", "")).strip()
                if uid.isdigit():
                    items[uid] = {
                        "user_id": uid,
                        "granted_by": str(doc.get("granted_by", "admin")),
                        "updated_at": str(doc.get("updated_at", "-")),
                    }
        except PyMongoError:
            pass
    return list(items.values())


def set_premium_user(user_id: str, enabled: bool, granted_by: str = "") -> bool:
    uid = str(user_id or "").strip()
    if not uid.isdigit():
        return False
    _invalidate_perm_cache(uid)
    if enabled:
        MEM_PREMIUM.add(uid)
        if premium_col is not None:
            try:
                premium_col.update_one(
                    {"user_id": uid},
                    {"$set": {"user_id": uid, "granted_by": granted_by or ADMIN_USER_ID, "updated_at": _now_str()}},
                    upsert=True,
                )
            except PyMongoError:
                pass
        return True
    if uid == ADMIN_USER_ID:
        return False
    MEM_PREMIUM.discard(uid)
    if premium_col is not None:
        try:
            premium_col.delete_one({"user_id": uid})
        except PyMongoError:
            pass
    return True


def record_incident(guild_id: str, category: str, summary: str, severity: str = "HIGH") -> None:
    inc = {
        "time": _now_str(),
        "guild_id": str(guild_id)[:22],
        "category": str(category)[:40],
        "severity": str(severity)[:12],
        "summary": str(summary)[:260],
    }
    MEM_INCIDENTS.appendleft(dict(inc))
    if incidents_col is not None:
        try:
            incidents_col.insert_one(dict(inc))
        except PyMongoError:
            pass


def get_incidents(guild_id: str = "", limit: int = 30) -> list[dict]:
    if incidents_col is not None:
        try:
            flt = {"guild_id": guild_id} if str(guild_id).isdigit() else {}
            docs = list(incidents_col.find(flt, {"_id": 0}).sort("_id", -1).limit(limit))
            if docs:
                return docs
        except PyMongoError:
            pass
    items = list(MEM_INCIDENTS)
    if str(guild_id).isdigit():
        items = [x for x in items if x.get("guild_id") == str(guild_id)]
    return items[:limit]


def log_event(msg: str, guild_id: str = "", level: str = "WEB") -> None:
    entry = {
        "time": _now_str(),
        "level": str(level)[:12],
        "guild_id": str(guild_id)[:22],
        "message": str(msg)[:300],
    }
    MEM_LOGS.appendleft(dict(entry))
    if logs_col is not None:
        try:
            logs_col.insert_one(dict(entry))
        except PyMongoError:
            pass
    if level in ("NUKE", "ADMIN", "SEC", "WARN", "ERROR"):
        record_incident(guild_id or "GLOBAL", level, msg, "CRITICAL" if level in ("NUKE", "ERROR") else "MEDIUM")


def get_recent_logs(limit: int = 50) -> list[dict]:
    if logs_col is not None:
        try:
            docs = list(logs_col.find({}, {"_id": 0}).sort("_id", -1).limit(limit))
            if docs:
                return docs
        except PyMongoError:
            pass
    return list(MEM_LOGS)[:limit]


def upsert_bot_guilds(guilds_payload: list[dict], replace_missing: bool = False) -> list[dict]:
    stamp = _now_str()
    cleaned: dict[str, dict] = {}
    for item in guilds_payload or []:
        if not isinstance(item, dict):
            continue
        gid = str(item.get("id", "")).strip()
        if not gid.isdigit():
            continue
        cleaned[gid] = {
            "id": gid,
            "name": str(item.get("name", f"Server {gid}"))[:100],
            "icon": str(item.get("icon", "") or "").strip()[:60],
            "member_count": int(item.get("member_count", 0) or 0),
            "owner_id": str(item.get("owner_id", "") or "").strip(),
            "updated_at": stamp,
        }

    if replace_missing:
        MEM_GUILDS.clear()
    for gid, doc in cleaned.items():
        MEM_GUILDS[gid] = dict(doc)

    if bot_guilds_col is not None:
        try:
            if replace_missing:
                active_ids = list(cleaned.keys())
                if active_ids:
                    bot_guilds_col.delete_many({"id": {"$nin": active_ids}})
                else:
                    bot_guilds_col.delete_many({})
            if cleaned and UpdateOne is not None:
                ops = [
                    UpdateOne({"id": gid}, {"$set": doc}, upsert=True)
                    for gid, doc in cleaned.items()
                ]
                bot_guilds_col.bulk_write(ops, ordered=False)
        except PyMongoError:
            pass

    _invalidate_guilds_cache()
    return get_all_guilds()


def get_all_guilds() -> list[dict]:
    global _GUILDS_CACHE
    now = time.time()
    if (now - _GUILDS_CACHE[0]) < _GUILDS_TTL and (_GUILDS_CACHE[1] or not MEM_GUILDS):
        return [dict(x) for x in _GUILDS_CACHE[1]]

    result: dict[str, dict] = {k: dict(v) for k, v in MEM_GUILDS.items()}
    if bot_guilds_col is not None:
        try:
            for g in bot_guilds_col.find({}, {"_id": 0}).limit(500):
                gid = str(g.get("id", "")).strip()
                if gid.isdigit():
                    result[gid] = {
                        "id": gid,
                        "name": str(g.get("name", f"Server {gid}"))[:100],
                        "icon": str(g.get("icon", "")).strip(),
                        "member_count": int(g.get("member_count", 0) or 0),
                        "owner_id": str(g.get("owner_id", "")).strip(),
                        "updated_at": str(g.get("updated_at", "")).strip(),
                    }
        except PyMongoError:
            pass
    out = list(result.values())
    _GUILDS_CACHE = (now, out)
    return [dict(x) for x in out]


def get_user_visible_guilds(user: dict | None) -> tuple[list[dict], bool]:
    if not user:
        return [], False

    user_guilds = user.get("guilds")
    bot_guilds = get_all_guilds()
    bot_map = {g["id"]: g for g in bot_guilds}
    uid = str(user.get("id", "")).strip()

    matched: list[dict] = []
    seen: set[str] = set()

    if isinstance(user_guilds, list) and user_guilds:
        for ug in user_guilds:
            gid = str(ug.get("id", "")).strip()
            if not gid.isdigit() or gid in seen:
                continue
            perms = int(ug.get("permissions", 0) or 0)
            is_owner = bool(ug.get("owner", False))
            has_admin_or_manage = is_owner or bool(perms & 0x8) or bool(perms & 0x20) or is_site_admin(user)
            if not has_admin_or_manage:
                continue
            seen.add(gid)
            if gid in bot_map:
                info = dict(bot_map[gid])
                info["bot_missing"] = False
                if ug.get("icon"):
                    info["icon"] = str(ug["icon"])
                matched.append(info)
            else:
                matched.append(
                    {
                        "id": gid,
                        "name": str(ug.get("name", f"Server {gid}"))[:100],
                        "icon": str(ug.get("icon", "")).strip(),
                        "member_count": 0,
                        "bot_missing": True,
                    }
                )
        return matched, True

    # في حال عدم توفر قائمة سيرفرات OAuth بعد أو عند الدخول المباشر، اعرض السيرفرات المسجلة للبوت
    for bg in bot_guilds:
        gid = bg["id"]
        if gid in seen:
            continue
        if is_site_admin(user) or (uid and bg.get("owner_id") == uid):
            seen.add(gid)
            info = dict(bg)
            info["bot_missing"] = False
            matched.append(info)

    return matched, bool(matched)


def user_can_manage_guild(guild_id: str, user: dict | None, require_bot_present: bool = False) -> dict | None:
    gid = str(guild_id or "").strip()
    if not gid.isdigit() or not user:
        return None
    visible, _ = get_user_visible_guilds(user)
    for g in visible:
        if g["id"] == gid:
            if require_bot_present and g.get("bot_missing"):
                return None
            return g
    if is_site_admin(user):
        bot_map = {g["id"]: g for g in get_all_guilds()}
        if gid in bot_map:
            info = dict(bot_map[gid])
            info["bot_missing"] = False
            return info
    return None


def resolve_guild_info(guild_id: str, user: dict | None = None) -> dict | None:
    return user_can_manage_guild(guild_id, user, require_bot_present=False)


def resolve_guild_id_from_input(raw_input: str, user: dict | None = None) -> str:
    val = str(raw_input or "").strip()
    if not val or not user:
        return ""
    visible, _ = get_user_visible_guilds(user)
    if val.isdigit():
        if any(g["id"] == val for g in visible):
            return val
        if is_site_admin(user) and any(g["id"] == val for g in get_all_guilds()):
            return val
        return ""
    low = val.lower()
    for g in visible:
        if str(g.get("name", "")).strip().lower() == low:
            return g["id"]
    for g in visible:
        if low in str(g.get("name", "")).strip().lower():
            return g["id"]
    return ""


def get_guild_cfg(guild_id: str) -> dict:
    gid = str(guild_id or "").strip()
    cfg = _fresh_default_guild_cfg()
    if not gid.isdigit():
        return cfg

    now = time.time()
    cached = _CFG_CACHE.get(gid)
    if cached and (now - cached[0]) < _CFG_TTL:
        return json.loads(json.dumps(cached[1]))

    mem = MEM_GUILD_CFG[gid]
    for k, v in mem.items():
        if k == "antinuke" and isinstance(v, dict):
            for ak, av in v.items():
                if ak in cfg["antinuke"] and isinstance(av, dict):
                    cfg["antinuke"][ak].update(av)
        elif k in ("guild_profile", "premium_perks") and isinstance(v, dict):
            cfg[k].update(v)
        else:
            cfg[k] = v
    if guild_settings_col is not None:
        try:
            doc = guild_settings_col.find_one({"guild_id": gid}, {"_id": 0})
            if doc:
                for k in cfg:
                    if k == "antinuke" and isinstance(doc.get("antinuke"), dict):
                        for ak, av in doc["antinuke"].items():
                            if ak in cfg["antinuke"] and isinstance(av, dict):
                                cfg["antinuke"][ak].update(av)
                    elif k in ("guild_profile", "premium_perks") and isinstance(doc.get(k), dict):
                        cfg[k].update(doc[k])
                    elif k in doc:
                        cfg[k] = doc[k]
        except PyMongoError:
            pass

    _CFG_CACHE[gid] = (now, json.loads(json.dumps(cfg)))
    return cfg


def save_guild_cfg(guild_id: str, updates: dict) -> dict:
    gid = str(guild_id or "").strip()
    _CFG_CACHE.pop(gid, None)
    if updates.get("reset_defaults"):
        fresh = _fresh_default_guild_cfg()
        if gid.isdigit():
            MEM_GUILD_CFG[gid] = json.loads(json.dumps(fresh))
            if guild_settings_col is not None:
                try:
                    guild_settings_col.update_one(
                        {"guild_id": gid},
                        {"$set": {"guild_id": gid, **fresh, "updated_at": _now_str()}},
                        upsert=True,
                    )
                except PyMongoError:
                    pass
        _CFG_CACHE[gid] = (time.time(), json.loads(json.dumps(fresh)))
        return fresh

    cfg = get_guild_cfg(gid)
    for key in (
        "maintenance",
        "anti_spam",
        "anti_link",
        "beast_mode",
        "anti_raid",
        "verification",
        "lockdown",
        "anti_new_accounts",
        "dangerous_perms_guard",
        "alert_on_trigger",
        *SHIELD_TOGGLE_KEYS,
    ):
        if key in updates:
            cfg[key] = bool(updates[key])
    if "min_account_age_days" in updates:
        try:
            days = int(updates["min_account_age_days"])
            cfg["min_account_age_days"] = max(1, min(365, days))
        except Exception:
            cfg["min_account_age_days"] = 7
    if "prefix" in updates:
        p = str(updates["prefix"] or "!").strip()[:6]
        cfg["prefix"] = p or "!"
    if "mod_log_channel" in updates:
        ch = str(updates["mod_log_channel"] or "").strip()
        cfg["mod_log_channel"] = ch if ch.isdigit() else ""
    if "antinuke_updates" in updates and isinstance(updates["antinuke_updates"], dict):
        for ak, av in updates["antinuke_updates"].items():
            if ak in cfg["antinuke"]:
                cfg["antinuke"][ak].update(av)
    if "guild_profile" in updates and isinstance(updates["guild_profile"], dict):
        prof = cfg["guild_profile"]
        if "bio" in updates["guild_profile"]:
            prof["bio"] = str(updates["guild_profile"]["bio"] or "").strip()[:190]
        if "avatar_url" in updates["guild_profile"]:
            prof["avatar_url"] = sanitize_http_url(updates["guild_profile"]["avatar_url"])
        if "banner_url" in updates["guild_profile"]:
            prof["banner_url"] = sanitize_http_url(updates["guild_profile"]["banner_url"])
    if "premium_perks" in updates and isinstance(updates["premium_perks"], dict):
        perks = cfg["premium_perks"]
        p_upd = updates["premium_perks"]
        for bool_k in ("ultra_fortress_mode", "instant_rollback_enabled", "priority_shield_response"):
            if bool_k in p_upd:
                perks[bool_k] = bool(p_upd[bool_k])
        if "alert_channel_id" in p_upd:
            ch_val = str(p_upd["alert_channel_id"] or "").strip()
            perks["alert_channel_id"] = ch_val if ch_val.isdigit() else ""
        if "alert_webhook_url" in p_upd:
            perks["alert_webhook_url"] = sanitize_http_url(p_upd["alert_webhook_url"])
        if "last_restored_snapshot" in p_upd:
            perks["last_restored_snapshot"] = str(p_upd["last_restored_snapshot"] or "").strip()[:32]
    if "whitelist_add" in updates:
        uid = str(updates["whitelist_add"] or "").strip()
        if uid.isdigit() and uid not in cfg["whitelist"]:
            cfg["whitelist"].append(uid)
    if "whitelist_remove" in updates:
        uid = str(updates["whitelist_remove"] or "").strip()
        cfg["whitelist"] = [x for x in cfg["whitelist"] if x != uid]
    if "trusted_add" in updates:
        uid = str(updates["trusted_add"] or "").strip()
        if uid.isdigit() and uid not in cfg["trusted_admins"]:
            cfg["trusted_admins"].append(uid)
    if "trusted_remove" in updates:
        uid = str(updates["trusted_remove"] or "").strip()
        if uid != ADMIN_USER_ID:
            cfg["trusted_admins"] = [x for x in cfg["trusted_admins"] if x != uid]
    if "save_snapshot" in updates and updates["save_snapshot"]:
        snap = {
            "id": secrets.token_hex(4),
            "saved_at": _now_str(),
            "rules_count": len(cfg.get("antinuke", {})),
            "trusted_count": len(cfg.get("trusted_admins", [])),
            "whitelist_count": len(cfg.get("whitelist", [])),
            "snapshot_hash": hashlib.sha256(
                json.dumps(cfg.get("antinuke", {}), sort_keys=True).encode("utf-8")
            ).hexdigest()[:12],
        }
        snaps = list(cfg.get("perms_snapshots", []))
        snaps.insert(0, snap)
        cfg["perms_snapshots"] = snaps[:10]
    if gid.isdigit():
        MEM_GUILD_CFG[gid] = json.loads(json.dumps(cfg))
        if guild_settings_col is not None:
            try:
                guild_settings_col.update_one(
                    {"guild_id": gid},
                    {"$set": {"guild_id": gid, **cfg, "updated_at": _now_str()}},
                    upsert=True,
                )
            except PyMongoError:
                pass
        _CFG_CACHE[gid] = (time.time(), json.loads(json.dumps(cfg)))
    return cfg


def calculate_security_score(cfg: dict) -> tuple[int, str]:
    score = 20
    for item in (cfg.get("antinuke") or {}).values():
        if isinstance(item, dict) and item.get("enabled"):
            score += 4
    for key in (
        "anti_privilege_escalation",
        "anti_role_tamper",
        "anti_channel_perms_tamper",
        "anti_webhook_abuse",
        "anti_app_abuse",
        "audit_log_watch",
        "anti_mass_unban",
        "anti_mass_kick",
        "anti_mass_timeout",
        "admin_behavior_analysis",
        "trusted_admins_enabled",
        "perms_snapshot_enabled",
        "auto_rollback_enabled",
        "gradual_attack_detect",
        "collusion_detect",
        "false_punishment_guard",
        "auto_perms_audit",
        "anti_invites",
        "voice_lock",
    ):
        if cfg.get(key):
            score += 2
    if (cfg.get("premium_perks") or {}).get("ultra_fortress_mode"):
        score += 5
    score = max(0, min(100, score))
    if score >= 85:
        grade = "A+ (محصّن بالكامل)"
    elif score >= 65:
        grade = "B+ (حماية قوية)"
    else:
        grade = "C (يحتاج تفعيل قواعد إضافية)"
    return score, grade


def run_auto_perms_audit(guild_id: str) -> list[str]:
    cfg = get_guild_cfg(guild_id)
    findings: list[str] = []
    if not cfg.get("anti_privilege_escalation"):
        findings.append("قاعدة منع تصعيد الصلاحيات متوقفة.")
    if not cfg.get("anti_role_tamper"):
        findings.append("قاعدة منع التلاعب بالرتب متوقفة.")
    if not cfg.get("anti_channel_perms_tamper"):
        findings.append("قاعدة منع التلاعب بصلاحيات القنوات متوقفة.")
    if not cfg.get("perms_snapshots"):
        findings.append("لا توجد نسخة محفوظة من الصلاحيات بعد.")
    if not findings:
        findings.append("جميع الصلاحيات والقواعد الحساسة سليمة ومطابقة لمعايير الأمان.")
    return findings


def run_attack_simulation(guild_id: str, scenario: str) -> str:
    cfg = get_guild_cfg(guild_id)
    score, _ = calculate_security_score(cfg)
    blocked = score >= 50 or bool(cfg.get("emergency_mode")) or bool((cfg.get("premium_perks") or {}).get("ultra_fortress_mode"))
    outcome = "تم صد المحاكاة وتفعيل الاسترجاع التلقائي" if blocked else "رصدت المحاكاة ثغرة تحتاج تفعيل الحماية"
    record_incident(guild_id, "SIMULATION", f"محاكاة [{scenario}]: {outcome}", "INFO")
    return f"{outcome} (مستوى الأمان الحالي: {score}/100)."


def create_db_backup() -> dict:
    snapshot = {
        "backup_id": secrets.token_hex(5),
        "created_at": _now_str(),
        "guilds_count": len(get_all_guilds()),
        "admins_count": len(get_admin_list()),
        "premium_count": len(get_premium_list()),
        "logs_count": len(get_recent_logs(60)),
        "signature": _sign_hmac(f"backup|{_now_str()}")[:16],
    }
    MEM_BACKUPS.appendleft(dict(snapshot))
    if backups_col is not None:
        try:
            backups_col.insert_one(dict(snapshot))
        except PyMongoError:
            pass
    return snapshot


def get_db_backups() -> list[dict]:
    if backups_col is not None:
        try:
            docs = list(backups_col.find({}, {"_id": 0}).sort("_id", -1).limit(10))
            if docs:
                return docs
        except PyMongoError:
            pass
    return list(MEM_BACKUPS)[:10]


def test_backup_restore(backup_id: str = "") -> tuple[bool, str]:
    backups = get_db_backups()
    if not backups:
        b = create_db_backup()
        backups = [b]
    target = next((x for x in backups if x.get("backup_id") == backup_id), backups[0])
    ok = bool(target.get("backup_id")) and bool(target.get("signature"))
    msg = (
        f"نجح اختبار استعادة النسخة [{target.get('backup_id')}] ({target.get('guilds_count', 0)} سيرفر، {target.get('admins_count', 0)} أدمن)."
        if ok
        else "فشل التحقق من سلامة النسخة الاحتياطية."
    )
    return ok, msg


def enqueue_remote_action(guild_id: str, action: str, target: str, extra: dict | None = None) -> None:
    payload = {
        "guild_id": str(guild_id),
        "action": str(action),
        "target": str(target),
        "extra": extra or {},
        "status": "pending",
        "created_at": datetime.now(timezone.utc),
    }
    if queue_col is not None:
        try:
            queue_col.insert_one(dict(payload))
        except PyMongoError:
            MEM_QUEUE.append(payload)
    else:
        MEM_QUEUE.append(payload)


def detect_base_url(request: web.Request) -> str:
    if EXPLICIT_WEB_URL:
        return EXPLICIT_WEB_URL
    if EXPLICIT_MAIN_URL:
        return EXPLICIT_MAIN_URL
    remote_ip = str(request.remote or "").strip()
    can_trust = TRUST_PROXY and (not TRUSTED_PROXY_IPS or remote_ip in TRUSTED_PROXY_IPS)
    host = (
        (request.headers.get("X-Forwarded-Host", "").split(",")[0].strip() if can_trust else "")
        or request.headers.get("Host", "").strip()
    )
    proto = (request.headers.get("X-Forwarded-Proto", "").split(",")[0].strip() if can_trust else "https") or "https"
    if host:
        return f"{proto}://{host}".rstrip("/")
    return DEFAULT_DOMAIN_URL


def detect_main_url(request: web.Request) -> str:
    return EXPLICIT_MAIN_URL or detect_base_url(request)


def detect_redirect_uri(request: web.Request) -> str:
    if EXPLICIT_REDIRECT_URI:
        return EXPLICIT_REDIRECT_URI
    return f"{detect_base_url(request)}/callback"


def sign_session(payload: dict) -> str:
    sid = secrets.token_urlsafe(24)
    exp_val = float(payload.get("exp", time.time() + 86400 * 7))
    record = {
        "sid": sid,
        "id": str(payload.get("id", "")),
        "username": str(payload.get("username", "User"))[:40],
        "avatar": str(payload.get("avatar", "") or "")[:40],
        "guilds": payload.get("guilds") or [],
        "exp": exp_val,
    }
    if len(SESSIONS) >= 5000:
        oldest_sid = next(iter(SESSIONS))
        SESSIONS.pop(oldest_sid, None)
    SESSIONS[sid] = record
    raw_b64 = json.dumps({"sid": sid, "exp": exp_val}, separators=(",", ":")).encode("utf-8")
    token_body = base64.urlsafe_b64encode(raw_b64).decode("ascii")
    sig = _sign_hmac(token_body)
    return f"{token_body}.{sig}"


def verify_session(token: str | None) -> tuple[str, dict] | None:
    _cleanup_expired()
    if not token or "." not in token:
        return None
    parts = token.rsplit(".", 1)
    if len(parts) != 2:
        return None
    token_body, sig = parts
    expected_sig = _sign_hmac(token_body)
    if not hmac.compare_digest(sig, expected_sig):
        return None
    try:
        padded = token_body + "=" * (-len(token_body) % 4)
        meta = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except Exception:
        return None
    sid = str(meta.get("sid", "")).strip()
    exp_val = _safe_exp(meta.get("exp", 0))
    if not sid or exp_val <= time.time():
        SESSIONS.pop(sid, None)
        return None
    sess = SESSIONS.get(sid)
    if not sess or _safe_exp(sess.get("exp", 0)) <= time.time():
        SESSIONS.pop(sid, None)
        return None
    return sid, sess


def get_discord_session_with_id(request: web.Request) -> tuple[str, dict] | None:
    tok = request.cookies.get("arab_sec_session") or request.headers.get("X-Arab-Session")
    return verify_session(tok)


def get_discord_session(request: web.Request) -> dict | None:
    pair = get_discord_session_with_id(request)
    return pair[1] if pair else None


def get_lang(request: web.Request) -> str:
    q = str(request.query.get("lang", "")).strip().lower()
    if q in ("ar", "en"):
        return q
    c = str(request.cookies.get("arab_sec_lang", "")).strip().lower()
    if c in ("ar", "en"):
        return c
    return "ar"


def is_rate_limited(ip: str, is_sensitive: bool = False) -> bool:
    now = time.time()
    bucket = AUTH_RATE_BUCKETS[ip] if is_sensitive else RATE_BUCKETS[ip]
    limit = AUTH_RATE_LIMIT_PER_MIN if is_sensitive else RATE_LIMIT_PER_MIN
    while bucket and now - bucket[0] > 60.0:
        bucket.popleft()
    if len(bucket) >= limit:
        return True
    bucket.append(now)
    return False


async def read_post_safe(request: web.Request, max_bytes: int = 131072) -> dict | None:
    content_length = request.content_length
    if content_length is not None and content_length > max_bytes:
        return None
    try:
        data = await request.post()
        return dict(data)
    except Exception:
        return None


def _is_valid_bot_sync_request(request: web.Request) -> bool:
    provided = str(
        request.headers.get("X-Bot-Secret")
        or request.headers.get("Authorization", "").replace("Bearer ", "")
        or ""
    ).strip()
    if not provided or not BOT_SYNC_SECRET:
        return False
    return hmac.compare_digest(provided, BOT_SYNC_SECRET)


async def api_bot_sync_guilds(request: web.Request) -> web.Response:
    if not _is_valid_bot_sync_request(request):
        return web.json_response({"ok": False, "error": "Unauthorized"}, status=401)
    try:
        body = await request.json()
    except Exception:
        return web.json_response({"ok": False, "error": "Invalid JSON"}, status=400)

    guilds_raw = body.get("guilds") if isinstance(body, dict) else None
    if not isinstance(guilds_raw, list):
        return web.json_response({"ok": False, "error": "guilds list required"}, status=400)

    replace_missing = bool(body.get("replace_missing", True))
    synced = upsert_bot_guilds(guilds_raw, replace_missing=replace_missing)
    MEM_BOT_HEARTBEAT["status"] = "ONLINE"
    MEM_BOT_HEARTBEAT["last_seen"] = _now_str()
    if isinstance(body, dict) and body.get("latency_ms") is not None:
        MEM_BOT_HEARTBEAT["latency_ms"] = (
            f"{int(body['latency_ms'])}ms"
            if str(body["latency_ms"]).isdigit()
            else str(body["latency_ms"])[:12]
        )

    return web.json_response({"ok": True, "count": len(synced)})


async def api_bot_pending_commands(request: web.Request) -> web.Response:
    if not _is_valid_bot_sync_request(request):
        return web.json_response({"ok": False, "error": "Unauthorized"}, status=401)

    items: list[dict] = []
    if queue_col is not None:
        try:
            docs = list(queue_col.find({"status": "pending"}).sort("_id", 1).limit(20))
            for d in docs:
                queue_col.update_one({"_id": d["_id"]}, {"$set": {"status": "done", "done_at": _now_str()}})
                items.append(
                    {
                        "id": str(d.get("_id")),
                        "guild_id": str(d.get("guild_id", "")),
                        "action": str(d.get("action", "")),
                        "target": str(d.get("target", "")),
                        "extra": d.get("extra") or {},
                    }
                )
        except PyMongoError:
            pass

    while MEM_QUEUE and len(items) < 20:
        d = MEM_QUEUE.popleft()
        items.append(
            {
                "id": "mem",
                "guild_id": str(d.get("guild_id", "")),
                "action": str(d.get("action", "")),
                "target": str(d.get("target", "")),
                "extra": d.get("extra") or {},
            }
        )

    return web.json_response({"ok": True, "commands": items})


def render_page(
    title: str,
    active_nav: str,
    content_html: str,
    request: web.Request,
    flash: str = "",
    require_auth_view: bool = False,
) -> str:
    lang = get_lang(request)
    is_en = lang == "en"
    dir_attr = "ltr" if is_en else "rtl"
    user = get_discord_session(request)
    is_admin = is_site_admin(user)
    is_prem = is_premium_user(user)
    safe_flash = sanitize_flash_msg(flash)

    L = {
        "home": "Home" if is_en else "الرئيسية",
        "servers": "My Servers" if is_en else "سيرفراتي",
        "guild": "Security Panel" if is_en else "لوحة الحماية",
        "premium": "Premium" if is_en else "البريميوم",
        "admin": "Admin Panel" if is_en else "لوحة الإدارة",
        "services": "Services" if is_en else "الخدمات",
        "updates": "Updates & Logs" if is_en else "التحديثات والسجلات",
        "links": "Links" if is_en else "الروابط",
        "invite": "Invite Arab Security Bot",
        "login_discord": "Login with Discord",
        "logout": "Logout" if is_en else "تسجيل الخروج",
        "auth_sub": "DISCORD ACCOUNT REQUIRED" if is_en else "ربط حساب ديسكورد مطلوب",
        "auth_title": "Connect Your Discord Account" if is_en else "ربط الحساب بديسكورد",
        "auth_desc": (
            "Sign in with Discord to manage your servers, configure protection systems, and unlock Premium perks."
            if is_en
            else "سجّل دخولك عبر ديسكورد للوصول إلى السيرفرات، ضبط أنظمة الحماية، وتفعيل مزايا البريميوم."
        ),
        "supervised": "Supervised by" if is_en else "بإشراف",
        "menu": "Menu" if is_en else "القائمة",
    }

    if user:
        uid = esc(user.get("id", ""))
        ava = esc(user.get("avatar", ""))
        uname_safe = esc(user.get("username", "Member"))
        avatar_html = (
            f"<img class='avatar-img' src='https://cdn.discordapp.com/avatars/{uid}/{ava}.png?size=128' alt='' loading='lazy' referrerpolicy='no-referrer'>"
            if uid and ava
            else f"<div class='avatar'>{(uname_safe[:1]).upper()}</div>"
        )
        badge_txt = "ADMIN" if is_admin else ("PREMIUM" if is_prem else "MEMBER")
        account_block = (
            f"<div class='user-box'>{avatar_html}"
            f"<div style='min-width:0;'><div class='uname'>{uname_safe} <span class='tag'>{badge_txt}</span></div>"
            f"<div class='uhandle'>ID: <code>{uid}</code></div></div></div>"
            f"<a class='nav-item danger' href='/logout'><span>⎋</span><span>{L['logout']}</span></a>"
        )
    else:
        account_block = f"<a class='login-btn' href='/login'>{L['login_discord']}</a>"

    if require_auth_view and not user:
        bot_servers_count = len(get_all_guilds())
        total_visits, unique_visitors = get_visitor_stats()
        final_content = f"""
        <div class="auth-gate glass-card">
          <div class="hero-chip">🔐 {L['auth_sub']}</div>
          <h1 style="margin:6px 0 10px;font-size:26px;font-weight:900;">{L['auth_title']}</h1>
          <p class="muted" style="margin:0 auto 20px;max-width:520px;line-height:1.7;">{L['auth_desc']}</p>
          <a class="btn-discord" href="/login">{L['login_discord']}</a>

          <div class="start-stats-stack">
            <div class="start-stat-box">
              <div class="start-stat-val">{bot_servers_count:,}</div>
              <div class="start-stat-lbl">{('Servers With Bot Inside' if is_en else 'عدد السيرفرات التي البوت داخلها')}</div>
            </div>
            <div class="start-stat-box">
              <div class="start-stat-val">{unique_visitors:,}</div>
              <div class="start-stat-lbl">{(f'Website Visitors ({total_visits:,} visits)' if is_en else f'عدد الأشخاص الذين زاروا الموقع ({total_visits:,} زيارة)')}</div>
            </div>
          </div>
        </div>
        """
    else:
        final_content = content_html

    flash_banner = f"<div class='flash' role='status'>{esc(safe_flash)}</div>" if safe_flash else ""

    nav_items = [
        ("home", "/", "◈", L["home"]),
        ("servers", "/servers", "❖", L["servers"]),
        ("guild", "/guild", "🛡", L["guild"]),
    ]
    if is_prem:
        nav_items.append(("premium", "/premium", "✦", L["premium"]))
    if is_admin:
        nav_items.append(("admin", "/admin", "⚡", L["admin"]))
    nav_items.extend(
        [
            ("services", "/services", "◈", L["services"]),
            ("updates", "/updates", "▤", L["updates"]),
            ("links", "/links", "⛓", L["links"]),
        ]
    )

    nav_links_html = "".join(
        f"<a class='nav-item {'active' if active_nav == key else ''}' href='{href}'><span>{ico}</span><span>{lbl}</span></a>"
        for key, href, ico, lbl in nav_items
    )

    next_lang = "ar" if is_en else "en"
    lang_label = "العربية" if is_en else "English"
    safe_invite_url = esc(sanitize_http_url(BOT_INVITE_URL) or "https://discord.com")
    db_pill = "DB ONLINE" if db is not None else "MEM CACHE"

    return f"""<!DOCTYPE html>
<html lang="{lang}" dir="{dir_attr}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)} — {esc(SITE_NAME)}</title>
<style>
  :root {{
    --bg-void: #050711;
    --bg-mesh:
      radial-gradient(circle at 12% 8%, rgba(124, 58, 237, 0.25), transparent 42%),
      radial-gradient(circle at 88% 14%, rgba(6, 182, 212, 0.18), transparent 40%),
      #050711;
    --glass: rgba(16, 19, 38, 0.86);
    --glass-strong: rgba(21, 25, 50, 0.94);
    --glass-soft: rgba(255, 255, 255, 0.03);
    --border: rgba(148, 163, 184, 0.16);
    --border-glow: rgba(139, 92, 246, 0.65);
    --cyan: #06b6d4;
    --emerald: #10b981;
    --text: #f8fafc;
    --muted: #94a3b8;
    --sidebar-w: 268px;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    background: var(--bg-void);
    background-image: var(--bg-mesh);
    color: var(--text);
    min-height: 100vh;
    overflow-x: hidden;
  }}

  .nav-progress {{
    position: fixed;
    top: 0;
    left: 0;
    height: 3px;
    width: 0%;
    z-index: 95;
    background: linear-gradient(90deg, #22d3ee, #8b5cf6, #10b981);
    opacity: 0;
    transition: width 0.14s ease, opacity 0.16s ease;
    pointer-events: none;
  }}
  .nav-progress.active {{ opacity: 1; width: 85%; }}

  .glass-card, .metric-card, .server-tile, .rule-box, .btn-v, .btn-g, .btn-c, .btn-discord, .pill-btn, .lang-btn, .burger {{
    transition: transform 0.1s ease, border-color 0.12s ease, background 0.12s ease;
    will-change: transform;
  }}
  .btn-v:active, .btn-g:active, .btn-c:active, .btn-discord:active, .pill-btn:active, .lang-btn:active, .burger:active {{
    transform: scale(0.96);
  }}
  @media (hover: hover) {{
    .glass-card:hover, .metric-card:hover, .server-tile:hover, .rule-box:hover {{
      transform: translateY(-2px);
      border-color: var(--border-glow);
    }}
    .btn-v:hover, .btn-g:hover, .btn-c:hover, .btn-discord:hover, .pill-btn:hover, .lang-btn:hover, .burger:hover {{
      border-color: var(--border-glow);
    }}
  }}

  .app-shell {{ display: flex; min-height: 100vh; }}
  .sidebar {{
    position: fixed;
    top: 0;
    {('left' if is_en else 'right')}: 0;
    width: var(--sidebar-w);
    height: 100vh;
    background: rgba(9, 12, 26, 0.96);
    border-{('right' if is_en else 'left')}: 1px solid var(--border);
    padding: 18px 14px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    z-index: 65;
    overflow-y: auto;
    transition: transform 0.16s ease;
  }}
  .main-stage {{
    flex: 1;
    min-width: 0;
    {('margin-left' if is_en else 'margin-right')}: var(--sidebar-w);
    display: flex;
    flex-direction: column;
  }}
  .mobile-bar {{
    display: none;
    position: sticky;
    top: 0;
    z-index: 40;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 12px 16px;
    background: rgba(9, 12, 26, 0.94);
    border-bottom: 1px solid var(--border);
  }}
  .overlay {{
    display: none;
    position: fixed;
    inset: 0;
    background: rgba(2, 6, 23, 0.72);
    z-index: 60;
  }}
  .overlay.open {{ display: block; }}

  @media (max-width: 900px) {{
    .sidebar {{
      transform: translateX({('-105%' if is_en else '105%')});
      width: 278px;
      max-width: 86vw;
    }}
    .sidebar.open {{ transform: translateX(0); }}
    .main-stage {{ {('margin-left' if is_en else 'margin-right')}: 0; }}
    .mobile-bar {{ display: flex; }}
  }}

  .brand-row {{
    display: flex;
    align-items: center;
    gap: 11px;
    text-decoration: none;
    color: #fff;
    padding: 4px 6px 10px;
  }}
  .brand-mark {{
    width: 40px;
    height: 40px;
    border-radius: 13px;
    background: linear-gradient(135deg, #7c3aed, #06b6d4);
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 900;
    font-size: 15px;
    color: #fff;
    flex-shrink: 0;
  }}
  .brand-name {{ font-weight: 900; font-size: 15px; }}
  .brand-owner {{ font-size: 11px; color: var(--muted); }}

  .status-strip {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 8px 10px;
    border-radius: 12px;
    background: var(--glass-soft);
    border: 1px solid var(--border);
    font-size: 11px;
    color: #cbd5e1;
    margin-bottom: 6px;
  }}
  .pulse-dot {{
    width: 8px;
    height: 8px;
    border-radius: 999px;
    background: var(--emerald);
    display: inline-block;
    margin-{('right' if is_en else 'left')}: 6px;
  }}

  .user-box {{
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 11px;
    border-radius: 14px;
    background: var(--glass);
    border: 1px solid var(--border);
    margin-bottom: 6px;
  }}
  .avatar, .avatar-img {{
    width: 40px;
    height: 40px;
    border-radius: 999px;
    object-fit: cover;
    flex-shrink: 0;
  }}
  .avatar {{
    background: linear-gradient(135deg, #7c3aed, #4f46e5);
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 800;
    color: #fff;
  }}
  .uname {{ font-weight: 800; font-size: 13px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
  .uhandle {{ font-size: 11px; color: var(--muted); }}
  .tag {{
    display: inline-block;
    font-size: 9px;
    padding: 2px 6px;
    border-radius: 6px;
    background: rgba(34, 211, 238, 0.15);
    border: 1px solid rgba(34, 211, 238, 0.35);
    color: #a5f3fc;
    font-weight: 800;
  }}
  .login-btn {{
    display: block;
    text-align: center;
    padding: 11px 12px;
    border-radius: 12px;
    background: linear-gradient(135deg, #2563eb, #4f46e5);
    color: #fff;
    text-decoration: none;
    font-weight: 800;
    font-size: 13px;
    margin-bottom: 6px;
  }}
  .nav-item {{
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 13px;
    border-radius: 12px;
    color: #cbd5e1;
    text-decoration: none;
    font-size: 13.5px;
    font-weight: 700;
    border: 1px solid transparent;
  }}
  .nav-item:hover {{ background: rgba(255, 255, 255, 0.05); color: #fff; }}
  .nav-item.active {{
    background: linear-gradient(135deg, rgba(124, 58, 237, 0.28), rgba(6, 182, 212, 0.14));
    border-color: rgba(139, 92, 246, 0.5);
    color: #fff;
  }}
  .nav-item.danger {{ color: #fca5a5; }}
  .sep {{ height: 1px; background: var(--border); margin: 8px 0; }}
  .lang-btn, .burger {{
    padding: 8px 12px;
    border-radius: 10px;
    border: 1px solid var(--border);
    background: var(--glass-strong);
    color: #fff;
    font-size: 12px;
    font-weight: 800;
    cursor: pointer;
  }}

  .content-wrap {{
    width: 100%;
    max-width: 980px;
    margin: 0 auto;
    padding: 24px 20px 52px;
  }}
  .top-toolbar {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 18px;
    flex-wrap: wrap;
  }}
  @media (max-width: 900px) {{
    .top-toolbar {{ display: none; }}
    .content-wrap {{ padding: 16px 14px 44px; }}
  }}

  .auth-gate {{
    text-align: center;
    padding: 32px 22px;
    background: linear-gradient(145deg, rgba(22, 26, 56, 0.92), rgba(11, 14, 30, 0.96));
  }}
  .start-stats-stack {{
    max-width: 440px;
    margin: 22px auto 0;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }}
  .start-stat-box {{
    background: rgba(9, 12, 28, 0.85);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 14px 16px;
  }}
  .start-stat-val {{
    font-size: 26px;
    font-weight: 900;
    color: #fff;
  }}
  .start-stat-lbl {{
    font-size: 13px;
    color: var(--muted);
    font-weight: 700;
    margin-top: 3px;
  }}

  .cyber-hero {{
    background: linear-gradient(145deg, rgba(22, 26, 56, 0.9), rgba(11, 14, 30, 0.96));
    border: 1px solid var(--border);
    border-radius: 24px;
    padding: 30px 24px;
    margin-bottom: 20px;
  }}
  .hero-chip {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 5px 13px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 800;
    color: #a5f3fc;
    background: rgba(6, 182, 212, 0.14);
    border: 1px solid rgba(34, 211, 238, 0.35);
    margin-bottom: 12px;
  }}
  .hero-h1 {{
    margin: 0;
    font-size: 32px;
    font-weight: 900;
    background: linear-gradient(90deg, #ffffff 0%, #ddd6fe 55%, #67e8f9 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }}
  .hero-p {{
    margin: 10px 0 22px;
    max-width: 640px;
    color: #cbd5e1;
    font-size: 14.5px;
    line-height: 1.7;
  }}
  .cta-row {{ display: flex; flex-wrap: wrap; gap: 12px; }}
  .btn-v {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 12px 20px;
    border-radius: 13px;
    background: linear-gradient(135deg, #7c3aed, #6d28d9);
    color: #fff;
    text-decoration: none;
    font-weight: 800;
    font-size: 14px;
    border: 1px solid rgba(167, 139, 250, 0.45);
    cursor: pointer;
  }}
  .btn-g {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 12px 20px;
    border-radius: 13px;
    background: var(--glass-strong);
    color: #fff;
    text-decoration: none;
    font-weight: 800;
    font-size: 14px;
    border: 1px solid var(--border);
    cursor: pointer;
  }}
  .btn-c {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 12px 20px;
    border-radius: 13px;
    background: linear-gradient(135deg, #0891b2, #0284c7);
    color: #fff;
    text-decoration: none;
    font-weight: 800;
    font-size: 14px;
    border: 1px solid rgba(34, 211, 238, 0.45);
    cursor: pointer;
  }}
  .btn-discord {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 13px 26px;
    border-radius: 13px;
    background: linear-gradient(135deg, #2563eb, #4f46e5);
    color: #fff;
    text-decoration: none;
    font-weight: 800;
    font-size: 15px;
    border: 1px solid rgba(96, 165, 250, 0.5);
  }}
  .btn-sm {{ padding: 8px 14px; font-size: 12.5px; border-radius: 10px; }}
  .btn-danger {{ background: rgba(239, 68, 68, 0.16); border-color: rgba(239, 68, 68, 0.55); color: #fca5a5; }}
  .btn-gold {{ background: linear-gradient(135deg, rgba(245, 158, 11, 0.25), rgba(217, 119, 6, 0.25)); border-color: rgba(251, 191, 36, 0.55); color: #fde68a; }}

  .metrics-grid {{
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 14px;
    margin-bottom: 22px;
  }}
  @media (max-width: 720px) {{ .metrics-grid {{ grid-template-columns: 1fr; }} }}
  .metric-card {{
    background: var(--glass);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 20px;
  }}
  .metric-top {{ display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; }}
  .metric-ico {{
    width: 38px;
    height: 38px;
    border-radius: 12px;
    background: rgba(124, 58, 237, 0.2);
    border: 1px solid rgba(139, 92, 246, 0.35);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 17px;
  }}
  .metric-val {{ font-size: 30px; font-weight: 900; color: #fff; }}
  .metric-lbl {{ font-size: 13px; color: var(--muted); font-weight: 700; margin-top: 4px; }}

  .section-bar {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin: 22px 0 14px;
  }}
  .section-bar h2 {{ margin: 0; font-size: 20px; font-weight: 900; }}

  .glass-card {{
    background: var(--glass);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 20px;
    margin-bottom: 16px;
  }}
  .feature-head {{ display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }}
  .feature-left {{ display: flex; align-items: center; gap: 14px; }}
  .feature-badge-ico {{
    width: 48px;
    height: 48px;
    border-radius: 15px;
    background: linear-gradient(135deg, rgba(124, 58, 237, 0.35), rgba(6, 182, 212, 0.25));
    border: 1px solid rgba(167, 139, 250, 0.4);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 21px;
    flex-shrink: 0;
  }}
  .chip-v {{ display: inline-block; padding: 3px 10px; border-radius: 999px; font-size: 11px; font-weight: 800; background: rgba(124, 58, 237, 0.24); color: #ddd6fe; border: 1px solid rgba(139, 92, 246, 0.42); }}
  .chip-c {{ display: inline-block; padding: 3px 10px; border-radius: 999px; font-size: 11px; font-weight: 800; background: rgba(6, 182, 212, 0.16); color: #67e8f9; border: 1px solid rgba(34, 211, 238, 0.38); }}
  .chip-g {{ display: inline-block; padding: 3px 10px; border-radius: 999px; font-size: 11px; font-weight: 800; background: rgba(16, 185, 129, 0.18); color: #6ee7b7; border: 1px solid rgba(16, 185, 129, 0.38); }}
  .launch-btn {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 10px 16px;
    border-radius: 12px;
    background: linear-gradient(135deg, #7c3aed, #4f46e5);
    color: #fff;
    text-decoration: none;
    font-weight: 800;
    font-size: 13px;
  }}

  .page-head {{ margin-bottom: 18px; }}
  .page-head .eyebrow {{ font-size: 11px; letter-spacing: 2px; color: #67e8f9; font-weight: 800; text-transform: uppercase; }}
  .page-head h1 {{ margin: 4px 0 0; font-size: 26px; font-weight: 900; }}

  .score-track {{
    width: 100%;
    height: 10px;
    border-radius: 999px;
    background: rgba(255, 255, 255, 0.08);
    overflow: hidden;
    margin: 10px 0 6px;
  }}
  .score-fill {{
    height: 100%;
    border-radius: 999px;
    background: linear-gradient(90deg, #7c3aed, #06b6d4, #10b981);
  }}

  .grid-2 {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }}
  .grid-cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 14px; }}
  .pill-btn {{
    display: block;
    text-align: center;
    padding: 11px 10px;
    border-radius: 13px;
    background: var(--glass);
    border: 1px solid var(--border);
    color: #e2e8f0;
    text-decoration: none;
    font-weight: 800;
    font-size: 13px;
  }}
  .pill-btn.active {{
    border-color: var(--cyan);
    background: linear-gradient(135deg, rgba(124, 58, 237, 0.3), rgba(6, 182, 212, 0.18));
    color: #fff;
  }}
  .rule-box {{
    background: var(--glass);
    border: 1px solid var(--border);
    border-radius: 18px;
    padding: 18px;
    text-align: center;
    margin-bottom: 14px;
  }}
  .rule-box h3 {{ margin: 0 0 10px; font-size: 15px; font-weight: 900; color: #e0e7ff; }}
  .lbl {{ display: block; font-size: 12.5px; color: var(--muted); margin: 10px 0 6px; font-weight: 700; }}
  .inp {{
    width: 100%;
    max-width: 360px;
    background: rgba(9, 12, 28, 0.9);
    border: 1px solid var(--border);
    color: #fff;
    border-radius: 12px;
    padding: 10px 12px;
    font-size: 14px;
    text-align: center;
  }}
  .inp:focus {{ outline: none; border-color: var(--cyan); }}
  .check-wrap {{ margin-top: 12px; display: flex; justify-content: center; }}
  .check-sq {{
    width: 42px;
    height: 42px;
    border-radius: 12px;
    background: linear-gradient(135deg, #7c3aed, #4f46e5);
    border: 1px solid rgba(167, 139, 250, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
  }}
  .check-sq input {{ width: 19px; height: 19px; accent-color: #22d3ee; cursor: pointer; }}
  .switch-list {{ display: flex; flex-direction: column; gap: 9px; margin-top: 12px; }}
  .switch-row {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 11px 13px;
    border-radius: 13px;
    background: rgba(255, 255, 255, 0.03);
    border: 1px solid rgba(148, 163, 184, 0.12);
    font-size: 13.5px;
  }}
  .server-tile {{
    background: var(--glass);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 16px;
    text-align: center;
    color: var(--text);
    text-decoration: none;
    display: block;
  }}
  .server-banner {{
    width: 100%;
    height: 128px;
    border-radius: 14px;
    background: linear-gradient(135deg, rgba(124, 58, 237, 0.55), rgba(6, 182, 212, 0.35));
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 30px;
    font-weight: 900;
    color: #fff;
    margin: 10px 0;
    object-fit: cover;
  }}
  .kpi-grid {{
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 10px;
    margin-top: 14px;
  }}
  @media (max-width: 640px) {{ .kpi-grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }} }}
  .kpi-box {{
    background: rgba(9, 12, 28, 0.8);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 12px 10px;
    text-align: center;
  }}
  .kpi-n {{ font-size: 20px; font-weight: 900; color: #fff; }}
  .kpi-t {{ font-size: 11px; color: var(--muted); margin-top: 3px; }}
  .list-row {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 10px;
    padding: 11px 13px;
    border-radius: 13px;
    background: rgba(255, 255, 255, 0.025);
    border: 1px solid rgba(148, 163, 184, 0.1);
    margin-bottom: 8px;
  }}
  .list-row:last-child {{ margin-bottom: 0; }}
  .log-line {{ padding: 10px 0; border-bottom: 1px solid rgba(148, 163, 184, 0.12); font-size: 13px; }}
  .log-line:last-child {{ border-bottom: none; }}
  .flash {{
    background: linear-gradient(135deg, rgba(124, 58, 237, 0.28), rgba(6, 182, 212, 0.2));
    border: 1px solid rgba(34, 211, 238, 0.55);
    color: #f8fafc;
    padding: 12px 16px;
    border-radius: 15px;
    margin-bottom: 16px;
    font-weight: 800;
    font-size: 13.5px;
  }}
  .muted {{ color: var(--muted); font-size: 13px; }}
  code {{ background: rgba(15, 23, 42, 0.85); border: 1px solid var(--border); padding: 2px 6px; border-radius: 6px; font-size: 12px; }}
</style>
</head>
<body>
<div id="nav-progress" class="nav-progress" aria-hidden="true"></div>
<div id="overlay" class="overlay" onclick="toggleDrawer(false)"></div>

<div class="app-shell">
  <aside id="drawer" class="sidebar" aria-label="{L['menu']}">
    <a class="brand-row" href="/">
      <div class="brand-mark">AS</div>
      <div>
        <div class="brand-name">{esc(SITE_NAME)}</div>
        <div class="brand-owner">{L['supervised']} {esc(OWNER_NAME)}</div>
      </div>
    </a>

    <div class="status-strip">
      <span><span class="pulse-dot"></span>{('BOT ONLINE' if is_en else 'البوت متصل')}</span>
      <code>{esc(db_pill)}</code>
    </div>

    {account_block}
    <div class="sep"></div>
    {nav_links_html}
    <div class="sep"></div>
    <a class="nav-item" href="{safe_invite_url}" target="_blank" rel="noopener noreferrer"><span>＋</span><span>{L['invite']}</span></a>
  </aside>

  <div class="main-stage">
    <header class="mobile-bar">
      <a class="brand-row" href="/" style="padding:0;">
        <div class="brand-mark" style="width:34px;height:34px;font-size:13px;">AS</div>
        <div><div class="brand-name" style="font-size:14px;">{esc(SITE_NAME)}</div></div>
      </a>
      <div style="display:flex;align-items:center;gap:8px;">
        <button class="lang-btn" type="button" onclick="switchLang('{next_lang}')">{lang_label}</button>
        <button class="burger" type="button" onclick="toggleDrawer(true)" aria-label="{L['menu']}">☰</button>
      </div>
    </header>

    <main class="content-wrap">
      <div class="top-toolbar">
        <div class="muted"><strong>{esc(SITE_NAME)}</strong> • {('Cyber Security & Server Management' if is_en else 'منظومة الحماية وإدارة السيرفرات')}</div>
        <div style="display:flex;align-items:center;gap:8px;">
          <a class="btn-g btn-sm" href="{safe_invite_url}" target="_blank" rel="noopener noreferrer">{L['invite']}</a>
          <button class="lang-btn" type="button" onclick="switchLang('{next_lang}')">{lang_label}</button>
        </div>
      </div>

      {flash_banner}
      {final_content}
    </main>
  </div>
</div>

<script>
function startProgress() {{
  var bar = document.getElementById("nav-progress");
  if (bar) bar.classList.add("active");
}}
function toggleDrawer(open) {{
  document.getElementById("drawer").classList.toggle("open", open);
  document.getElementById("overlay").classList.toggle("open", open);
}}
function switchLang(targetLang) {{
  startProgress();
  try {{
    document.cookie = "arab_sec_lang=" + encodeURIComponent(targetLang) + "; path=/; max-age=" + (86400 * 365) + "; SameSite=Lax";
  }} catch (e) {{}}
  var url = new URL(window.location.href);
  url.searchParams.set("lang", targetLang);
  window.location.href = url.toString();
}}
function filterServers() {{
  var inp = document.getElementById("server-search");
  if (!inp) return;
  var q = inp.value.trim().toLowerCase();
  document.querySelectorAll("[data-server-card]").forEach(function(card) {{
    var name = (card.getAttribute("data-server-name") || "").toLowerCase();
    var id = (card.getAttribute("data-server-id") || "").toLowerCase();
    card.style.display = (!q || name.indexOf(q) !== -1 || id.indexOf(q) !== -1) ? "" : "none";
  }});
}}
(function() {{
  try {{ localStorage.removeItem("arab_sec_tok"); }} catch (e) {{}}
  document.querySelectorAll("a[href^='/']").forEach(function(a) {{
    a.addEventListener("click", function(ev) {{
      if (!ev.ctrlKey && !ev.metaKey && !ev.shiftKey && a.target !== "_blank") {{
        startProgress();
      }}
    }});
  }});
  document.querySelectorAll("form").forEach(function(frm) {{
    frm.addEventListener("submit", function() {{ startProgress(); }});
  }});
}})();
</script>
</body>
</html>"""


async def home_handler(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    user = get_discord_session(request)
    flash = sanitize_flash_msg(request.query.get("msg"))
    bot_servers_count = len(get_all_guilds())
    total_visits, unique_visitors = get_visitor_stats()

    if not user:
        guest_body = f"""
        <section class="auth-gate glass-card">
          <div class="hero-chip">✦ {('ARAB SECURITY COMMAND' if is_en else 'منظومة ARAB SECURITY')}</div>
          <h1 class="hero-h1" style="margin-bottom:10px;">{esc(SITE_NAME)}</h1>
          <p class="muted" style="margin:0 auto 22px;max-width:540px;line-height:1.7;">{('Sign in with Discord to manage your servers, configure protection systems, and unlock Premium perks.' if is_en else 'سجّل دخولك عبر ديسكورد للتحكم بالسيرفرات، ضبط أنظمة الحماية، وتفعيل مزايا البريميوم.')}</p>
          <a class="btn-discord" href="/login">Login with Discord</a>

          <div class="start-stats-stack">
            <div class="start-stat-box">
              <div class="start-stat-val">{bot_servers_count:,}</div>
              <div class="start-stat-lbl">{('Servers With Bot Inside' if is_en else 'عدد السيرفرات التي البوت داخلها')}</div>
            </div>
            <div class="start-stat-box">
              <div class="start-stat-val">{unique_visitors:,}</div>
              <div class="start-stat-lbl">{(f'Website Visitors ({total_visits:,} visits)' if is_en else f'عدد الأشخاص الذين زاروا الموقع ({total_visits:,} زيارة)')}</div>
            </div>
          </div>
        </section>
        """
        return web.Response(
            text=render_page("Login" if is_en else "تسجيل الدخول", "home", guest_body, request, flash=flash),
            content_type="text/html",
        )

    safe_invite = esc(sanitize_http_url(BOT_INVITE_URL) or "https://discord.com")

    hero_html = f"""
    <section class="cyber-hero">
      <div class="hero-chip">✦ {('NEXT-GEN DISCORD DEFENSE' if is_en else 'الجيل المطور لحماية سيرفرات ديسكورد')}</div>
      <h1 class="hero-h1">{esc(SITE_NAME)}</h1>
      <p class="hero-p">{('Real-time Anti-Nuke defense, behavior intelligence, permission snapshots, attack simulations, DB backups, and per-server Premium automation.' if is_en else 'حماية فورية ضد النيوك والتلاعب بالصلاحيات، تحليل سلوك الإداريين، لقطات الصلاحيات والاسترجاع، محاكاة الهجمات، نسخ قاعدة البيانات، ومزايا بريميوم متقدمة لكل سيرفر.')}</p>
      <div class="cta-row">
        <a class="btn-v" href="/servers">{('Launch Command Center' if is_en else 'دخول لوحة التحكم')}</a>
        <a class="btn-c" href="{safe_invite}" target="_blank" rel="noopener noreferrer">{('Invite Bot' if is_en else 'إضافة البوت للسيرفر')}</a>
        <a class="btn-g" href="/services">{('Explore Plans' if is_en else 'الخدمات والمزايا')}</a>
      </div>
    </section>
    """

    metrics_html = f"""
    <section class="metrics-grid">
      <div class="metric-card">
        <div class="metric-top">
          <span class="chip-v">ACTIVE NODES</span>
          <div class="metric-ico">🛡</div>
        </div>
        <div class="metric-val">{bot_servers_count:,}</div>
        <div class="metric-lbl">{('Servers With Bot Inside' if is_en else 'عدد السيرفرات التي البوت داخلها')}</div>
      </div>

      <div class="metric-card">
        <div class="metric-top">
          <span class="chip-c">VISITORS</span>
          <div class="metric-ico">◈</div>
        </div>
        <div class="metric-val">{unique_visitors:,}</div>
        <div class="metric-lbl">{(f'Website Visitors ({total_visits:,} visits)' if is_en else f'عدد الأشخاص الذين زاروا الموقع ({total_visits:,} زيارة)')}</div>
      </div>

      <div class="metric-card">
        <div class="metric-top">
          <span class="chip-g">LATENCY</span>
          <div class="metric-ico">⚡</div>
        </div>
        <div class="metric-val">{esc(MEM_BOT_HEARTBEAT.get('latency_ms', '6ms'))}</div>
        <div class="metric-lbl">{('Core Shield Response' if is_en else 'استجابة منظومة الحماية')}</div>
      </div>
    </section>
    """

    modules_html = f"""
    <div class="section-bar">
      <h2>{('Core Modules' if is_en else 'الأنظمة الرئيسية')}</h2>
      <span class="muted">{('Fast Control Suite' if is_en else 'واجهة تحكم سريعة')}</span>
    </div>

    <div class="glass-card">
      <div class="feature-head">
        <div class="feature-left">
          <div class="feature-badge-ico">🛡</div>
          <div>
            <span class="chip-v">{('SHIELD ENGINE' if is_en else 'محرك الحماية')}</span>
            <h3 style="margin:5px 0 2px;font-size:18px;font-weight:900;">{('Anti-Nuke, Snapshots, Audit & Attack Simulation' if is_en else 'منظومة Anti-Nuke، لقطات الصلاحيات، التدقيق، والمحاكاة')}</h3>
          </div>
        </div>
        <a class="launch-btn" href="/guild">{('Open Panel' if is_en else 'فتح اللوحة')} →</a>
      </div>
      <p class="muted" style="margin:12px 0 0;line-height:1.65;">{('Protects webhooks, apps, bots, roles, channels, and mass actions with live security scoring, trusted admins, incident timelines, and automated rollback.' if is_en else 'تحمي الويب هوك والتطبيقات والبوتات والرتب والقنوات والإجراءات الجماعية مع تقييم أمان مباشر، إداريين موثوقين، سجل حوادث، واسترجاع تلقائي.')}</p>
    </div>

    <div class="glass-card">
      <div class="feature-head">
        <div class="feature-left">
          <div class="feature-badge-ico">✦</div>
          <div>
            <span class="chip-c">{('PREMIUM SUITE' if is_en else 'باقة البريميوم المطورة')}</span>
            <h3 style="margin:5px 0 2px;font-size:18px;font-weight:900;">{('Per-Server Profile, Ultra Fortress, Rollback & Alerts' if is_en else 'تخصيص البوت لكل سيرفر، الحصن الفائق، الاسترجاع الفوري، والتنبيهات')}</h3>
          </div>
        </div>
        <a class="launch-btn" href="/premium">{('Open Premium' if is_en else 'فتح البريميوم')} →</a>
      </div>
      <p class="muted" style="margin:12px 0 0;line-height:1.65;">{('Customize avatar, banner, and bio per server, toggle Ultra Fortress Mode, restore saved permission snapshots, and route instant breach alerts.' if is_en else 'تخصيص صورة وبنر وبايو البوت لكل سيرفر على حدة، تفعيل وضع الحصن الفائق، استرجاع لقطات الصلاحيات فوراً، وإرسال تنبيهات الاختراق لقناة أو ويب هوك مخصص.')}</p>
    </div>
    """

    body = hero_html + metrics_html + modules_html
    return web.Response(
        text=render_page("Home" if is_en else "الرئيسية", "home", body, request, flash=flash),
        content_type="text/html",
    )


async def handle_servers(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    user = get_discord_session(request)
    if not user:
        return web.Response(
            text=render_page("Servers" if is_en else "سيرفراتي", "servers", "", request, require_auth_view=True),
            content_type="text/html",
        )

    guilds, has_oauth_guilds = get_user_visible_guilds(user)
    safe_invite = esc(sanitize_http_url(BOT_INVITE_URL) or "https://discord.com")
    cards = ""
    for g in guilds:
        gid_raw = g["id"]
        gname_raw = g["name"]
        gid = esc(gid_raw)
        gname = esc(gname_raw)
        icon = esc(str(g.get("icon", "")).strip())
        mcount = int(g.get("member_count", 0) or 0)
        missing = bool(g.get("bot_missing"))
        if icon:
            thumb = f"<img class='server-banner' src='https://cdn.discordapp.com/icons/{gid}/{icon}.png?size=256' alt='' loading='lazy' referrerpolicy='no-referrer'>"
        else:
            initial = esc((gname_raw[:2] or "SV").upper())
            thumb = f"<div class='server-banner'>{initial}</div>"

        target_href = safe_invite if missing else f"/guild?id={gid}&tab=antinuke"
        target_attr = " target='_blank' rel='noopener noreferrer'" if missing else ""
        badge = (
            f"<span class='chip-c'>{'Add Bot' if is_en else 'إضافة البوت'}</span>"
            if missing
            else f"<span class='chip-g'>{mcount} {'members' if is_en else 'عضو'}</span>"
        )
        cards += f"""
        <a class="server-tile" data-server-card="1" data-server-name="{gname}" data-server-id="{gid}" href="{target_href}"{target_attr}>
          <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;">
            <span class="muted">#{gid}</span>
            {badge}
          </div>
          {thumb}
          <div style="font-weight:900;font-size:16px;">{gname}</div>
        </a>
        """

    if not cards:
        note = (
            (
                "No servers with Administrator/Manage Server permissions were found for your account."
                if is_en
                else "لا توجد سيرفرات تملك فيها صلاحية الإدارة (Administrator أو Manage Server) أو لم يتم جلب قائمة سيرفراتك."
            )
            if has_oauth_guilds
            else (
                "No manageable servers available for this session. Try logging in again."
                if is_en
                else "لا توجد سيرفرات متاحة لحسابك في هذه الجلسة. أعد تسجيل الدخول لتحديث القائمة."
            )
        )
        cards = f"""
        <div class="glass-card" style="text-align:center;grid-column:1/-1;">
          <p class="muted">{esc(note)}</p>
          <a class="btn-v" href="{safe_invite}" target="_blank" rel="noopener noreferrer">Invite Arab Security Bot</a>
        </div>
        """

    body = f"""
    <div class="page-head">
      <div class="eyebrow">{('WORKSPACE' if is_en else 'مساحة الإدارة')}</div>
      <h1>{('My Servers' if is_en else 'سيرفراتي')}</h1>
    </div>
    <div class="glass-card" style="padding:14px 18px;">
      <input id="server-search" class="inp" style="max-width:100%;text-align:{'left' if is_en else 'right'};" type="search" oninput="filterServers()" placeholder="{('Search server by name or ID...' if is_en else 'ابحث عن سيرفر بالاسم أو ID...')}">
    </div>
    <div class="grid-cards">
      {cards}
    </div>
    """
    return web.Response(text=render_page("Servers" if is_en else "سيرفراتي", "servers", body, request), content_type="text/html")


async def handle_guild(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    sess_pair = get_discord_session_with_id(request)
    if not sess_pair:
        return web.Response(
            text=render_page("Security Panel" if is_en else "لوحة الحماية", "guild", "", request, require_auth_view=True),
            content_type="text/html",
        )
    session_id, user = sess_pair

    guilds, _ = get_user_visible_guilds(user)
    gid = str(request.query.get("id", "")).strip()
    if not gid and guilds:
        gid = guilds[0]["id"]
    active_tab = str(request.query.get("tab", "antinuke")).strip().lower()
    if active_tab not in ("general", "antinuke", "beast", "raid", "verify", "mod", "whitelist", "logs"):
        active_tab = "antinuke"

    flash = ""
    if request.method == "GET" and request.query.get("id") is not None:
        raw_q = str(request.query.get("id", "")).strip()
        if raw_q:
            matched_id = resolve_guild_id_from_input(raw_q, user)
            if matched_id:
                gid = matched_id
            else:
                gid = ""
                flash = (
                    "Server not found or you lack Manage Server / Administrator permission."
                    if is_en
                    else "السيرفر غير موجود أو لا تملك صلاحية الإدارة (Manage Server / Administrator) عليه."
                )

    if request.method == "POST":
        form = await read_post_safe(request)
        if form is None:
            flash = "Payload too large or invalid form data." if is_en else "حجم البيانات كبير جداً أو صيغة الطلب غير صالحة."
        else:
            csrf_val = str(form.get("csrf_token", "")).strip()
            nonce_val = str(form.get("req_nonce", "")).strip()
            if not consume_csrf_token(csrf_val, session_id):
                flash = "Session or CSRF token invalid/expired, please try again." if is_en else "انتهت صلاحية الجلسة أو رمز CSRF، أعد المحاولة."
            elif is_replay_request(nonce_val):
                flash = "Duplicate request blocked." if is_en else "تم منع إعادة إرسال طلب مكرر (Replay Guard)."
            else:
                raw_posted_gid = str(form.get("guild_id", gid)).strip()
                posted_gid = resolve_guild_id_from_input(raw_posted_gid, user)
                authorized_guild = user_can_manage_guild(posted_gid, user) if posted_gid else None
                if not authorized_guild:
                    flash = (
                        "Unauthorized: you do not have Manage Server / Administrator permission for this server."
                        if is_en
                        else "غير مصرح: لا تملك صلاحية الإدارة على هذا السيرفر."
                    )
                else:
                    gid = authorized_guild["id"]
                    section = str(form.get("section", active_tab)).strip().lower()

                    if section == "antinuke":
                        if form.get("reset_defaults") == "on":
                            save_guild_cfg(gid, {"reset_defaults": True})
                            flash = "Default shield settings restored." if is_en else "تمت استعادة الإعدادات الافتراضية للحماية."
                            log_event(f"إعادة ضبط إعدادات الحماية الافتراضية للسيرفر {gid}", guild_id=gid, level="SEC")
                        else:
                            an_updates = {}
                            for key in ANTINUKE_RULE_KEYS:
                                lim_raw = str(form.get(f"{key}_limit", "1")).strip()
                                lim = max(1, min(50, int(lim_raw))) if lim_raw.isdigit() else 1
                                pun = str(form.get(f"{key}_punishment", "Kick")).strip()
                                if pun not in ("Kick", "Ban", "Remove Roles"):
                                    pun = "Kick"
                                en = form.get(f"{key}_enabled") == "on"
                                an_updates[key] = {"enabled": en, "limit": lim, "punishment": pun}

                            extra_shield = {"antinuke_updates": an_updates}
                            for sk in SHIELD_TOGGLE_KEYS:
                                extra_shield[sk] = form.get(sk) == "on"
                            if form.get("save_snapshot") == "on":
                                extra_shield["save_snapshot"] = True

                            save_guild_cfg(gid, extra_shield)
                            if form.get("run_audit") == "on":
                                audit_res = run_auto_perms_audit(gid)
                                flash = " | ".join(audit_res)
                            elif form.get("sim_scenario"):
                                flash = run_attack_simulation(gid, str(form.get("sim_scenario")))
                            else:
                                flash = "Anti-Nuke & shield settings saved." if is_en else "تم حفظ إعدادات Anti Nuke وأنظمة الحماية بنجاح."
                            log_event(f"تحديث إعدادات الحماية والتدقيق للسيرفر {gid}", guild_id=gid, level="NUKE")

                    elif section == "general":
                        save_guild_cfg(
                            gid,
                            {
                                "prefix": form.get("prefix", "!"),
                                "mod_log_channel": form.get("mod_log_channel", ""),
                                "maintenance": form.get("maintenance") == "on",
                                "anti_spam": form.get("anti_spam") == "on",
                                "anti_link": form.get("anti_link") == "on",
                                "anti_invites": form.get("anti_invites") == "on",
                                "voice_lock": form.get("voice_lock") == "on",
                                "silent_mode": form.get("silent_mode") == "on",
                                "lockdown": form.get("lockdown") == "on",
                                "emergency_mode": form.get("emergency_mode") == "on",
                            },
                        )
                        log_event(f"تحديث الإعدادات العامة ووضع الطوارئ للسيرفر {gid}", guild_id=gid, level="WEB")
                        flash = "General settings saved." if is_en else "تم حفظ الإعدادات العامة بنجاح."

                    elif section in ("beast", "raid", "verify"):
                        mapping = {"beast": "beast_mode", "raid": "anti_raid", "verify": "verification"}
                        field_name = mapping[section]
                        extra_updates = {field_name: form.get(field_name) == "on"}
                        if section == "raid":
                            extra_updates["anti_new_accounts"] = form.get("anti_new_accounts") == "on"
                            extra_updates["min_account_age_days"] = form.get("min_account_age_days", "7")
                        save_guild_cfg(gid, extra_updates)
                        log_event(f"تحديث {field_name} للسيرفر {gid}", guild_id=gid, level="SEC")
                        flash = "Status updated." if is_en else "تم حفظ التفعيل بنجاح."

                    elif section == "mod":
                        cmd = str(form.get("cmd_action", "")).strip()
                        target_user = str(form.get("target_user", "")).strip()
                        if cmd in ("kick", "ban", "timeout", "unban") and target_user.isdigit():
                            enqueue_remote_action(gid, cmd, target_user)
                            log_event(f"أمر {cmd} للعضو {target_user} في السيرفر {gid}", guild_id=gid, level="MOD")
                            flash = f"Sent {cmd} for {target_user}." if is_en else f"تم إرسال أمر {cmd} للعضو {target_user}."
                        else:
                            flash = "Enter a valid User ID." if is_en else "أدخل User ID صحيح واختر الإجراء."

                    elif section == "whitelist":
                        add_id = str(form.get("wl_add", "")).strip()
                        rem_id = str(form.get("wl_remove", "")).strip()
                        tr_add = str(form.get("trusted_add", "")).strip()
                        tr_rem = str(form.get("trusted_remove", "")).strip()
                        if add_id.isdigit():
                            save_guild_cfg(gid, {"whitelist_add": add_id})
                            flash = f"Added {add_id} to whitelist." if is_en else f"تمت إضافة {add_id} إلى القائمة البيضاء."
                        if rem_id.isdigit():
                            save_guild_cfg(gid, {"whitelist_remove": rem_id})
                            flash = f"Removed {rem_id} from whitelist." if is_en else f"تمت إزالة {rem_id} من القائمة البيضاء."
                        if tr_add.isdigit():
                            save_guild_cfg(gid, {"trusted_add": tr_add})
                            flash = f"Added {tr_add} to trusted admins." if is_en else f"تمت إضافة {tr_add} إلى الإداريين الموثوقين."
                        if tr_rem.isdigit():
                            save_guild_cfg(gid, {"trusted_remove": tr_rem})
                            flash = f"Removed {tr_rem} from trusted admins." if is_en else f"تمت إزالة {tr_rem} من الإداريين الموثوقين."

    cfg = get_guild_cfg(gid) if gid else _fresh_default_guild_cfg()
    score, grade = calculate_security_score(cfg)
    csrf_tok = issue_csrf_token(session_id)
    req_nonce = secrets.token_hex(12)

    guild_options_html = "".join(
        f"<option value='{esc(g['id'])}' {'selected' if g['id'] == gid else ''}>{esc(g['name'])} ({esc(g['id'])})</option>"
        for g in guilds
    )

    tabs = [
        ("antinuke", "🛡 Anti-Nuke"),
        ("general", "⚙ العام" if not is_en else "⚙ General"),
        ("beast", "⚡ Beast Mode"),
        ("raid", "🚨 Anti-Raid"),
        ("verify", "✓ التحقق" if not is_en else "✓ Verify"),
        ("mod", "🔨 الإدارة" if not is_en else "🔨 Mod"),
        ("whitelist", "📋 البيضاء والموثوقون" if not is_en else "📋 Whitelist & Trusted"),
        ("logs", "📜 الحوادث" if not is_en else "📜 Incidents"),
    ]
    tabs_html = "".join(
        f"<a class='pill-btn {'active' if active_tab == t_key else ''}' href='/guild?id={esc(gid)}&tab={t_key}'>{t_lbl}</a>"
        for t_key, t_lbl in tabs
    )

    section_html = ""
    if active_tab == "antinuke":
        rules_cards = ""
        for rk in ANTINUKE_RULE_KEYS:
            rcfg = (cfg.get("antinuke") or {}).get(rk, {})
            r_en = bool(rcfg.get("enabled", True))
            r_lim = int(rcfg.get("limit", 1) or 1)
            r_pun = str(rcfg.get("punishment", "Kick") or "Kick")
            rules_cards += f"""
            <div class="rule-box">
              <h3>{esc(rk)}</h3>
              <label class="lbl">{('Limit' if is_en else 'الحد الأقصى')}</label>
              <input class="inp" type="number" min="1" max="50" name="{rk}_limit" value="{r_lim}">
              <label class="lbl">{('Punishment' if is_en else 'العقوبة')}</label>
              <select class="inp" name="{rk}_punishment">
                <option value="Kick" {'selected' if r_pun == 'Kick' else ''}>Kick</option>
                <option value="Ban" {'selected' if r_pun == 'Ban' else ''}>Ban</option>
                <option value="Remove Roles" {'selected' if r_pun == 'Remove Roles' else ''}>Remove Roles</option>
              </select>
              <div class="check-wrap">
                <label class="check-sq" title="{('Enabled' if is_en else 'تفعيل')}">
                  <input type="checkbox" name="{rk}_enabled" {'checked' if r_en else ''}>
                </label>
              </div>
            </div>
            """

        toggles_html = "".join(
            f"<label class='switch-row'><span>{esc(sk)}</span><input type='checkbox' name='{sk}' {'checked' if cfg.get(sk) else ''}></label>"
            for sk in SHIELD_TOGGLE_KEYS
        )

        section_html = f"""
        <form method="post">
          <input type="hidden" name="csrf_token" value="{esc(csrf_tok)}">
          <input type="hidden" name="req_nonce" value="{esc(req_nonce)}">
          <input type="hidden" name="guild_id" value="{esc(gid)}">
          <input type="hidden" name="section" value="antinuke">
          <div class="grid-cards">{rules_cards}</div>
          <div class="glass-card">
            <h3 style="margin:0 0 8px;">{('Advanced Shield Systems' if is_en else 'أنظمة الحماية المتقدمة')}</h3>
            <div class="switch-list">{toggles_html}</div>
          </div>
          <div class="glass-card">
            <div class="cta-row">
              <button class="btn-v" type="submit">{('Save Protection Settings' if is_en else 'حفظ إعدادات الحماية')}</button>
              <button class="btn-c" type="submit" name="save_snapshot" value="on">{('Save Snapshot' if is_en else 'حفظ لقطة صلاحيات')}</button>
              <button class="btn-g" type="submit" name="run_audit" value="on">{('Run Audit' if is_en else 'فحص الصلاحيات')}</button>
              <button class="btn-g btn-danger" type="submit" name="reset_defaults" value="on">{('Reset Defaults' if is_en else 'استعادة الافتراضي')}</button>
            </div>
          </div>
        </form>
        """
    elif active_tab == "general":
        section_html = f"""
        <form method="post" class="glass-card">
          <input type="hidden" name="csrf_token" value="{esc(csrf_tok)}">
          <input type="hidden" name="req_nonce" value="{esc(req_nonce)}">
          <input type="hidden" name="guild_id" value="{esc(gid)}">
          <input type="hidden" name="section" value="general">
          <label class="lbl">{('Command Prefix' if is_en else 'بادئة الأوامر (Prefix)')}</label>
          <input class="inp" type="text" name="prefix" maxlength="6" value="{esc(cfg.get('prefix', '!'))}">
          <label class="lbl">{('Mod Log Channel ID' if is_en else 'آيدي قناة السجلات (Channel ID)')}</label>
          <input class="inp" type="text" name="mod_log_channel" value="{esc(cfg.get('mod_log_channel', ''))}">
          <div class="switch-list">
            <label class="switch-row"><span>anti_spam</span><input type="checkbox" name="anti_spam" {'checked' if cfg.get('anti_spam') else ''}></label>
            <label class="switch-row"><span>anti_link</span><input type="checkbox" name="anti_link" {'checked' if cfg.get('anti_link') else ''}></label>
            <label class="switch-row"><span>anti_invites</span><input type="checkbox" name="anti_invites" {'checked' if cfg.get('anti_invites') else ''}></label>
            <label class="switch-row"><span>voice_lock</span><input type="checkbox" name="voice_lock" {'checked' if cfg.get('voice_lock') else ''}></label>
            <label class="switch-row"><span>silent_mode</span><input type="checkbox" name="silent_mode" {'checked' if cfg.get('silent_mode') else ''}></label>
            <label class="switch-row"><span>lockdown</span><input type="checkbox" name="lockdown" {'checked' if cfg.get('lockdown') else ''}></label>
            <label class="switch-row"><span>emergency_mode</span><input type="checkbox" name="emergency_mode" {'checked' if cfg.get('emergency_mode') else ''}></label>
            <label class="switch-row"><span>maintenance</span><input type="checkbox" name="maintenance" {'checked' if cfg.get('maintenance') else ''}></label>
          </div>
          <div style="margin-top:14px;"><button class="btn-v" type="submit">{('Save' if is_en else 'حفظ الإعدادات')}</button></div>
        </form>
        """
    elif active_tab in ("beast", "raid", "verify"):
        key_map = {"beast": "beast_mode", "raid": "anti_raid", "verify": "verification"}
        k_name = key_map[active_tab]
        extra_raid = (
            f"""
            <label class='switch-row'><span>anti_new_accounts</span><input type='checkbox' name='anti_new_accounts' {'checked' if cfg.get('anti_new_accounts') else ''}></label>
            <label class='lbl'>{('Min Account Age (days)' if is_en else 'الحد الأدنى لعمر الحساب (أيام)')}</label>
            <input class='inp' type='number' min='1' max='365' name='min_account_age_days' value='{int(cfg.get('min_account_age_days', 7) or 7)}'>
            """
            if active_tab == "raid"
            else ""
        )
        section_html = f"""
        <form method="post" class="glass-card">
          <input type="hidden" name="csrf_token" value="{esc(csrf_tok)}">
          <input type="hidden" name="req_nonce" value="{esc(req_nonce)}">
          <input type="hidden" name="guild_id" value="{esc(gid)}">
          <input type="hidden" name="section" value="{active_tab}">
          <div class="switch-list">
            <label class="switch-row"><span>{esc(k_name)}</span><input type="checkbox" name="{k_name}" {'checked' if cfg.get(k_name) else ''}></label>
            {extra_raid}
          </div>
          <div style="margin-top:14px;"><button class="btn-v" type="submit">{('Save' if is_en else 'حفظ')}</button></div>
        </form>
        """
    elif active_tab == "mod":
        section_html = f"""
        <form method="post" class="glass-card">
          <input type="hidden" name="csrf_token" value="{esc(csrf_tok)}">
          <input type="hidden" name="req_nonce" value="{esc(req_nonce)}">
          <input type="hidden" name="guild_id" value="{esc(gid)}">
          <input type="hidden" name="section" value="mod">
          <label class="lbl">{('Target User ID' if is_en else 'آيدي العضو (User ID)')}</label>
          <input class="inp" type="text" name="target_user" placeholder="123456789012345678">
          <label class="lbl">{('Action' if is_en else 'الإجراء')}</label>
          <select class="inp" name="cmd_action">
            <option value="kick">Kick</option>
            <option value="ban">Ban</option>
            <option value="timeout">Timeout</option>
            <option value="unban">Unban</option>
          </select>
          <div style="margin-top:14px;"><button class="btn-c" type="submit">{('Dispatch Action' if is_en else 'إرسال الأمر للبوت')}</button></div>
        </form>
        """
    elif active_tab == "whitelist":
        wl_rows = "".join(f"<div class='list-row'><code>{esc(x)}</code></div>" for x in (cfg.get("whitelist") or [])) or f"<p class='muted'>{('Empty' if is_en else 'فارغة')}</p>"
        tr_rows = "".join(f"<div class='list-row'><code>{esc(x)}</code></div>" for x in (cfg.get("trusted_admins") or [])) or f"<p class='muted'>{('Empty' if is_en else 'فارغة')}</p>"
        section_html = f"""
        <form method="post" class="glass-card">
          <input type="hidden" name="csrf_token" value="{esc(csrf_tok)}">
          <input type="hidden" name="req_nonce" value="{esc(req_nonce)}">
          <input type="hidden" name="guild_id" value="{esc(gid)}">
          <input type="hidden" name="section" value="whitelist">
          <div class="grid-2">
            <div>
              <label class="lbl">{('Add to Whitelist (ID)' if is_en else 'إضافة للقائمة البيضاء')}</label>
              <input class="inp" type="text" name="wl_add" placeholder="User ID">
              <label class="lbl">{('Remove from Whitelist (ID)' if is_en else 'إزالة من القائمة البيضاء')}</label>
              <input class="inp" type="text" name="wl_remove" placeholder="User ID">
            </div>
            <div>
              <label class="lbl">{('Add Trusted Admin (ID)' if is_en else 'إضافة إداري موثوق')}</label>
              <input class="inp" type="text" name="trusted_add" placeholder="User ID">
              <label class="lbl">{('Remove Trusted Admin (ID)' if is_en else 'إزالة إداري موثوق')}</label>
              <input class="inp" type="text" name="trusted_remove" placeholder="User ID">
            </div>
          </div>
          <div style="margin-top:14px;"><button class="btn-v" type="submit">{('Update Lists' if is_en else 'تحديث القوائم')}</button></div>
        </form>
        <div class="grid-2">
          <div class="glass-card"><h3 style="margin:0 0 10px;">Whitelist</h3>{wl_rows}</div>
          <div class="glass-card"><h3 style="margin:0 0 10px;">Trusted Admins</h3>{tr_rows}</div>
        </div>
        """
    elif active_tab == "logs":
        incs = get_incidents(gid, 25)
        inc_html = "".join(
            f"<div class='log-line'><strong>[{esc(i.get('severity'))}]</strong> <code>{esc(i.get('category'))}</code> — {esc(i.get('summary'))} <span class='muted'>({esc(i.get('time'))})</span></div>"
            for i in incs
        ) or f"<p class='muted'>{('No incidents recorded.' if is_en else 'لا توجد حوادث مسجلة لهذا السيرفر.')}</p>"
        section_html = f"<div class='glass-card'><h3 style='margin:0 0 10px;'>{('Security Incidents' if is_en else 'سجل الحوادث الأمنية')}</h3>{inc_html}</div>"

    body = f"""
    <div class="page-head">
      <div class="eyebrow">{('SHIELD CONTROL' if is_en else 'تحكم الحماية')}</div>
      <h1>{('Security Panel' if is_en else 'لوحة الحماية')}</h1>
    </div>

    <div class="glass-card">
      <form method="get" action="/guild" style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;">
        <input type="hidden" name="tab" value="{esc(active_tab)}">
        <select class="inp" name="id" style="max-width:420px;text-align:{'left' if is_en else 'right'};">
          {guild_options_html or f"<option value=''>{'No servers' if is_en else 'لا توجد سيرفرات'}</option>"}
        </select>
        <button class="btn-v btn-sm" type="submit">{('Switch Server' if is_en else 'اختيار السيرفر')}</button>
      </form>
      <div style="margin-top:14px;">
        <div style="display:flex;justify-content:space-between;font-size:13px;font-weight:800;">
          <span>{('Security Score' if is_en else 'مؤشر أمان السيرفر')}: {score}/100</span>
          <span>{esc(grade)}</span>
        </div>
        <div class="score-track"><div class="score-fill" style="width:{score}%;"></div></div>
      </div>
    </div>

    <div class="grid-cards" style="grid-template-columns:repeat(auto-fit,minmax(130px,1fr));margin-bottom:16px;">
      {tabs_html}
    </div>

    {section_html}
    """
    return web.Response(
        text=render_page("Security Panel" if is_en else "لوحة الحماية", "guild", body, request, flash=flash),
        content_type="text/html",
    )


async def handle_premium(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    sess_pair = get_discord_session_with_id(request)
    if not sess_pair:
        return web.Response(
            text=render_page("Premium" if is_en else "البريميوم", "premium", "", request, require_auth_view=True),
            content_type="text/html",
        )
    session_id, user = sess_pair
    if not is_premium_user(user):
        return web.Response(
            text=render_page(
                "Premium" if is_en else "البريميوم",
                "premium",
                f"<div class='glass-card'><h2>{'Premium Required' if is_en else 'اشتراك البريميوم مطلوب'}</h2><p class='muted'>{'This account does not have active Premium access.' if is_en else 'حسابك لا يملك صلاحية البريميوم حالياً.'}</p></div>",
                request,
            ),
            content_type="text/html",
        )

    # عرض جميع السيرفرات المتاحة للمستخدم أو السيرفرات المدارة بدون حجبها بسبب حالة البوت
    guilds, _ = get_user_visible_guilds(user)
    if not guilds and is_site_admin(user):
        guilds = get_all_guilds()

    gid = str(request.query.get("id", "")).strip()
    if not gid and guilds:
        gid = guilds[0]["id"]

    flash = ""
    if request.method == "POST":
        form = await read_post_safe(request)
        if form is None:
            flash = "Invalid form data." if is_en else "بيانات النموذج غير صالحة."
        elif not consume_csrf_token(str(form.get("csrf_token", "")), session_id):
            flash = "CSRF token invalid/expired." if is_en else "انتهت صلاحية الجلسة، أعد المحاولة."
        elif is_replay_request(str(form.get("req_nonce", ""))):
            flash = "Duplicate request blocked." if is_en else "تم منع طلب مكرر."
        else:
            posted_gid = str(form.get("guild_id", gid)).strip()
            if posted_gid.isdigit():
                gid = posted_gid
                save_guild_cfg(
                    gid,
                    {
                        "guild_profile": {
                            "bio": str(form.get("bio", "")),
                            "avatar_url": str(form.get("avatar_url", "")),
                            "banner_url": str(form.get("banner_url", "")),
                        },
                        "premium_perks": {
                            "ultra_fortress_mode": form.get("ultra_fortress_mode") == "on",
                            "instant_rollback_enabled": form.get("instant_rollback_enabled") == "on",
                            "priority_shield_response": form.get("priority_shield_response") == "on",
                            "alert_channel_id": str(form.get("alert_channel_id", "")),
                            "alert_webhook_url": str(form.get("alert_webhook_url", "")),
                        },
                    },
                )
                enqueue_remote_action(gid, "sync_premium", gid)
                log_event(f"تحديث إعدادات البريميوم للسيرفر {gid}", guild_id=gid, level="SEC")
                flash = "Premium settings saved." if is_en else "تم حفظ إعدادات البريميوم للسيرفر بنجاح."

    cfg = get_guild_cfg(gid) if gid else _fresh_default_guild_cfg()
    prof = cfg.get("guild_profile") or {}
    perks = cfg.get("premium_perks") or {}
    csrf_tok = issue_csrf_token(session_id)
    req_nonce = secrets.token_hex(12)

    options_html = "".join(
        f"<option value='{esc(g['id'])}' {'selected' if g['id'] == gid else ''}>{esc(g['name'])} ({esc(g['id'])})</option>"
        for g in guilds
    ) or f"<option value=''>{('No servers found' if is_en else 'لا توجد سيرفرات متاحة')}</option>"

    body = f"""
    <div class="page-head">
      <div class="eyebrow">PREMIUM SUITE</div>
      <h1>{('Premium Controls' if is_en else 'تحكم البريميوم')}</h1>
    </div>

    <form method="post" class="glass-card">
      <input type="hidden" name="csrf_token" value="{esc(csrf_tok)}">
      <input type="hidden" name="req_nonce" value="{esc(req_nonce)}">

      <label class="lbl">{('Select Server' if is_en else 'اختر السيرفر')}</label>
      <select class="inp" name="guild_id" onchange="window.location='/premium?id='+encodeURIComponent(this.value)">
        {options_html}
      </select>

      <label class="lbl">{('Bot Bio (Per Server)' if is_en else 'نبذة البوت (Bio) للسيرفر')}</label>
      <input class="inp" type="text" name="bio" maxlength="190" value="{esc(prof.get('bio', ''))}">

      <label class="lbl">{('Avatar URL' if is_en else 'رابط صورة البوت')}</label>
      <input class="inp" type="url" name="avatar_url" value="{esc(prof.get('avatar_url', ''))}">

      <label class="lbl">{('Banner URL' if is_en else 'رابط بنر البوت')}</label>
      <input class="inp" type="url" name="banner_url" value="{esc(prof.get('banner_url', ''))}">

      <label class="lbl">{('Alert Channel ID' if is_en else 'آيدي قناة التنبيهات')}</label>
      <input class="inp" type="text" name="alert_channel_id" value="{esc(perks.get('alert_channel_id', ''))}">

      <label class="lbl">{('Alert Webhook URL' if is_en else 'رابط Webhook للتنبيهات')}</label>
      <input class="inp" type="url" name="alert_webhook_url" value="{esc(perks.get('alert_webhook_url', ''))}">

      <div class="switch-list">
        <label class="switch-row"><span>ultra_fortress_mode</span><input type="checkbox" name="ultra_fortress_mode" {'checked' if perks.get('ultra_fortress_mode') else ''}></label>
        <label class="switch-row"><span>instant_rollback_enabled</span><input type="checkbox" name="instant_rollback_enabled" {'checked' if perks.get('instant_rollback_enabled') else ''}></label>
        <label class="switch-row"><span>priority_shield_response</span><input type="checkbox" name="priority_shield_response" {'checked' if perks.get('priority_shield_response') else ''}></label>
      </div>

      <div style="margin-top:16px;">
        <button class="btn-v btn-gold" type="submit">{('Save Premium Perks' if is_en else 'حفظ مزايا البريميوم')}</button>
      </div>
    </form>
    """
    return web.Response(
        text=render_page("Premium" if is_en else "البريميوم", "premium", body, request, flash=flash),
        content_type="text/html",
    )


async def handle_admin(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    sess_pair = get_discord_session_with_id(request)
    if not sess_pair:
        return web.Response(
            text=render_page("Admin Panel" if is_en else "لوحة الإدارة", "admin", "", request, require_auth_view=True),
            content_type="text/html",
        )
    session_id, user = sess_pair
    if not is_site_admin(user):
        return web.Response(
            text=render_page(
                "Admin Panel" if is_en else "لوحة الإدارة",
                "admin",
                f"<div class='glass-card'><h2>{'Access Denied' if is_en else 'دخول غير مصرح'}</h2></div>",
                request,
            ),
            content_type="text/html",
        )

    flash = ""
    if request.method == "POST":
        form = await read_post_safe(request)
        if form is None:
            flash = "Invalid form data." if is_en else "بيانات النموذج غير صالحة."
        elif not consume_csrf_token(str(form.get("csrf_token", "")), session_id):
            flash = "CSRF token invalid/expired." if is_en else "انتهت صلاحية الجلسة، أعد المحاولة."
        elif is_replay_request(str(form.get("req_nonce", ""))):
            flash = "Duplicate request blocked." if is_en else "تم منع طلب مكرر."
        else:
            act = str(form.get("admin_action", "")).strip()
            target_uid = str(form.get("target_user_id", "")).strip()
            if act == "grant_premium" and target_uid.isdigit():
                set_premium_user(target_uid, True, granted_by=str(user.get("id", "")))
                flash = f"Granted Premium to {target_uid}." if is_en else f"تم منح البريميوم للحساب {target_uid}."
            elif act == "revoke_premium" and target_uid.isdigit():
                if set_premium_user(target_uid, False):
                    flash = f"Revoked Premium from {target_uid}." if is_en else f"تم سحب البريميوم من الحساب {target_uid}."
                else:
                    flash = "Cannot revoke owner." if is_en else "لا يمكن سحب الصلاحية من المالك."
            elif act == "grant_admin" and target_uid.isdigit():
                set_admin_user(target_uid, True, granted_by=str(user.get("id", "")))
                flash = f"Granted Admin to {target_uid}." if is_en else f"تم منح صلاحية الأدمن للحساب {target_uid}."
            elif act == "revoke_admin" and target_uid.isdigit():
                if set_admin_user(target_uid, False):
                    flash = f"Revoked Admin from {target_uid}." if is_en else f"تم سحب صلاحية الأدمن من الحساب {target_uid}."
                else:
                    flash = "Cannot revoke owner." if is_en else "لا يمكن سحب الصلاحية من المالك."
            elif act == "broadcast":
                b_msg = str(form.get("broadcast_msg", "")).strip()[:240]
                if b_msg:
                    enqueue_remote_action("ALL", "broadcast", b_msg)
                    log_event(f"تنبيه عام: {b_msg}", guild_id="GLOBAL", level="ADMIN")
                    flash = "Broadcast queued." if is_en else "تم إرسال التنبيه العام إلى قائمة البوت."
            elif act == "backup_now":
                b = create_db_backup()
                flash = f"Backup created: {b['backup_id']}" if is_en else f"تم إنشاء نسخة احتياطية برقم {b['backup_id']}."
            elif act == "test_backup":
                _, r_msg = test_backup_restore()
                flash = r_msg

    all_bot_guilds = get_all_guilds()
    prem_list = get_premium_list()
    adm_list = get_admin_list()
    backups = get_db_backups()
    csrf_tok = issue_csrf_token(session_id)
    req_nonce = secrets.token_hex(12)

    guilds_rows = "".join(
        f"<div class='list-row'><div><strong>{esc(g.get('name'))}</strong> <span class='muted'>({esc(g.get('id'))})</span></div><span class='chip-g'>{int(g.get('member_count', 0))} {'members' if is_en else 'عضو'}</span></div>"
        for g in all_bot_guilds
    ) or f"<p class='muted'>{('No servers registered by the bot yet.' if is_en else 'لا توجد سيرفرات مسجلة للبوت حالياً.')}</p>"

    prem_rows = "".join(
        f"<div class='list-row'><code>{esc(p['user_id'])}</code><span class='muted'>{esc(p.get('granted_by', ''))}</span></div>"
        for p in prem_list
    )

    backup_rows = "".join(
        f"<div class='list-row'><code>{esc(b.get('backup_id'))}</code><span class='muted'>{esc(b.get('created_at'))} • {int(b.get('guilds_count', 0))} {'guilds' if is_en else 'سيرفر'}</span></div>"
        for b in backups
    ) or f"<p class='muted'>{('No backups saved yet.' if is_en else 'لا توجد نسخ محفوظة بعد.')}</p>"

    body = f"""
    <div class="page-head">
      <div class="eyebrow">OWNER / ADMIN COMMAND</div>
      <h1>{('Admin Panel' if is_en else 'لوحة الإدارة')}</h1>
    </div>

    <form method="post" class="glass-card">
      <input type="hidden" name="csrf_token" value="{esc(csrf_tok)}">
      <input type="hidden" name="req_nonce" value="{esc(req_nonce)}">
      <label class="lbl">{('User ID' if is_en else 'آيدي المستخدم (User ID)')}</label>
      <input class="inp" type="text" name="target_user_id" placeholder="1395418036919468073">
      <div class="cta-row" style="margin-top:12px;">
        <button class="btn-v btn-gold btn-sm" type="submit" name="admin_action" value="grant_premium">{('Grant Premium' if is_en else 'إعطاء بريميوم')}</button>
        <button class="btn-g btn-danger btn-sm" type="submit" name="admin_action" value="revoke_premium">{('Revoke Premium' if is_en else 'سحب بريميوم')}</button>
        <button class="btn-c btn-sm" type="submit" name="admin_action" value="grant_admin">{('Grant Admin' if is_en else 'إعطاء أدمن')}</button>
        <button class="btn-g btn-danger btn-sm" type="submit" name="admin_action" value="revoke_admin">{('Revoke Admin' if is_en else 'سحب أدمن')}</button>
      </div>
    </form>

    <form method="post" class="glass-card">
      <input type="hidden" name="csrf_token" value="{esc(csrf_tok)}">
      <input type="hidden" name="req_nonce" value="{esc(req_nonce)}">
      <h3 style="margin:0 0 8px;">{('Broadcast, Backup & Health' if is_en else 'تنبيه عام، النسخ الاحتياطي، ومراقبة البوت')}</h3>
      <input class="inp" style="max-width:100%;" type="text" name="broadcast_msg" placeholder="{('Global broadcast message' if is_en else 'رسالة تنبيه عامة للبوت')}">
      <div class="cta-row" style="margin-top:12px;">
        <button class="btn-v btn-gold btn-sm" type="submit" name="admin_action" value="broadcast">{('Send Broadcast' if is_en else 'إرسال تنبيه')}</button>
        <button class="btn-v btn-sm" type="submit" name="admin_action" value="backup_now">{('Create Backup' if is_en else 'إنشاء نسخة احتياطية')}</button>
        <button class="btn-g btn-sm" type="submit" name="admin_action" value="test_backup">{('Test Restore' if is_en else 'فحص تشغيل البوت والنسخ')}</button>
      </div>
      <div style="margin-top:14px;">{backup_rows}</div>
    </form>

    <div class="glass-card">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">
        <h3 style="margin:0;">{('Bot Guilds' if is_en else 'السيرفرات المتواجدة فيها البوت')}</h3>
        <span class="chip-v">{len(all_bot_guilds)}</span>
      </div>
      {guilds_rows}
    </div>

    <div class="glass-card">
      <h3 style="margin:0 0 10px;">{('Premium & Admins' if is_en else 'حسابات البريميوم والإدارة')} ({len(prem_list)} / {len(adm_list)})</h3>
      {prem_rows}
    </div>
    """
    return web.Response(
        text=render_page("Admin Panel" if is_en else "لوحة الإدارة", "admin", body, request, flash=flash),
        content_type="text/html",
    )


async def handle_services(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    body = f"""
    <div class="page-head">
      <div class="eyebrow">CAPABILITIES</div>
      <h1>{('Services & Protection Suite' if is_en else 'الخدمات وأنظمة الحماية')}</h1>
    </div>
    <div class="glass-card">
      <h3 style="margin:0 0 8px;">🛡 Anti-Nuke & Shield Engine</h3>
      <p class="muted" style="margin:0;line-height:1.7;">{('Monitors webhooks, bots, roles, channels, and mass moderation actions in real time with instant punishment and rollback support.' if is_en else 'يراقب الويب هوك والبوتات والرتب والقنوات والإجراءات الجماعية لحظياً مع تنفيذ العقوبات وحفظ لقطات الصلاحيات.')}</p>
    </div>
    <div class="glass-card">
      <h3 style="margin:0 0 8px;">✦ Premium Server Perks</h3>
      <p class="muted" style="margin:0;line-height:1.7;">{('Per-guild bot profile customization, Ultra Fortress Mode, instant rollback, and custom breach alert channels or webhooks.' if is_en else 'تخصيص هوية البوت لكل سيرفر، وضع الحصن الفائق، الاسترجاع الفوري، وقنوات أو ويب هوك التنبيهات.')}</p>
    </div>
    """
    return web.Response(text=render_page("Services" if is_en else "الخدمات", "services", body, request), content_type="text/html")


async def handle_updates(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    logs = get_recent_logs(40)
    rows = "".join(
        f"<div class='log-line'><strong>[{esc(l.get('level'))}]</strong> {esc(l.get('message'))} <span class='muted'>({esc(l.get('time'))})</span></div>"
        for l in logs
    ) or f"<p class='muted'>{('No logs yet.' if is_en else 'لا توجد سجلات بعد.')}</p>"
    body = f"""
    <div class="page-head">
      <div class="eyebrow">ACTIVITY STREAM</div>
      <h1>{('Updates & Logs' if is_en else 'التحديثات والسجلات')}</h1>
    </div>
    <div class="glass-card">{rows}</div>
    """
    return web.Response(text=render_page("Updates & Logs" if is_en else "التحديثات والسجلات", "updates", body, request), content_type="text/html")


async def handle_links(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    safe_invite = esc(sanitize_http_url(BOT_INVITE_URL) or "https://discord.com")
    safe_support = esc(sanitize_http_url(SUPPORT_SERVER_URL) or "https://discord.com")
    body = f"""
    <div class="page-head">
      <div class="eyebrow">DIRECTORY</div>
      <h1>{('Official Links' if is_en else 'الروابط الرسمية')}</h1>
    </div>
    <div class="glass-card">
      <div class="cta-row">
        <a class="btn-v" href="{safe_invite}" target="_blank" rel="noopener noreferrer">{('Invite Bot' if is_en else 'رابط إضافة البوت')}</a>
        <a class="btn-c" href="{safe_support}" target="_blank" rel="noopener noreferrer">{('Support Server' if is_en else 'سيرفر الدعم الفني')}</a>
      </div>
    </div>
    """
    return web.Response(text=render_page("Links" if is_en else "الروابط", "links", body, request), content_type="text/html")


async def handle_login(request: web.Request) -> web.Response:
    ip = get_client_ip(request)
    if is_rate_limited(ip, is_sensitive=True):
        return web.Response(text="Too many login requests.", status=429)
    if not DISCORD_CLIENT_ID or not DISCORD_CLIENT_SECRET:
        return web.Response(
            text="DISCORD_CLIENT_ID أو DISCORD_CLIENT_SECRET غير مضبوط في متغيرات البيئة.",
            status=500,
        )
    state = issue_oauth_state()
    redirect_uri = detect_redirect_uri(request)
    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "identify guilds",
        "state": state,
    }
    raise web.HTTPFound(f"https://discord.com/oauth2/authorize?{urlencode(params)}")


async def handle_callback(request: web.Request) -> web.Response:
    ip = get_client_ip(request)
    if is_rate_limited(ip, is_sensitive=True):
        return web.Response(text="Too many callback requests.", status=429)
    if request.query.get("error"):
        raise web.HTTPFound("/?msg=" + quote("تم إلغاء تسجيل الدخول عبر ديسكورد."))

    state = request.query.get("state", "")
    code = request.query.get("code", "")
    if not consume_oauth_state(state) or not code:
        raise web.HTTPFound("/?msg=" + quote("رمز التحقق غير صالح أو منتهي الصلاحية."))

    redirect_uri = detect_redirect_uri(request)
    user_info: dict = {}
    compact_guilds: list[dict] = []

    try:
        async with ClientSession() as session:
            token_resp = await session.post(
                "https://discord.com/api/oauth2/token",
                data={
                    "client_id": DISCORD_CLIENT_ID,
                    "client_secret": DISCORD_CLIENT_SECRET,
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            token_data = await token_resp.json()
            access_token = str(token_data.get("access_token", "")).strip()
            if not access_token:
                raise web.HTTPFound("/?msg=" + quote("تعذر الحصول على رمز الوصول من ديسكورد."))

            auth_headers = {"Authorization": f"Bearer {access_token}"}
            u_resp = await session.get("https://discord.com/api/users/@me", headers=auth_headers)
            user_info = await u_resp.json()

            g_resp = await session.get("https://discord.com/api/users/@me/guilds", headers=auth_headers)
            g_list = await g_resp.json()
            if isinstance(g_list, list):
                # رفع الحد إلى 200 سيرفر حتى لا تُقتطع السيرفرات
                for g in g_list[:200]:
                    if isinstance(g, dict) and str(g.get("id", "")).isdigit():
                        compact_guilds.append(
                            {
                                "id": str(g["id"]),
                                "name": str(g.get("name", ""))[:100],
                                "icon": str(g.get("icon", "") or "")[:60],
                                "owner": bool(g.get("owner", False)),
                                "permissions": int(g.get("permissions", 0) or 0),
                            }
                        )
    except ClientError:
        raise web.HTTPFound("/?msg=" + quote("حدث خطأ أثناء الاتصال بخوادم ديسكورد."))

    uid = str(user_info.get("id", "")).strip()
    if not uid.isdigit():
        raise web.HTTPFound("/?msg=" + quote("تعذر قراءة بيانات الحساب."))

    signed_tok = sign_session(
        {
            "id": uid,
            "username": str(user_info.get("username", "User"))[:40],
            "avatar": str(user_info.get("avatar", "") or "")[:40],
            "guilds": compact_guilds,
            "exp": time.time() + 86400 * 7,
        }
    )
    resp = web.HTTPFound("/servers")
    resp.set_cookie(
        "arab_sec_session",
        signed_tok,
        max_age=86400 * 7,
        httponly=True,
        secure=True,
        samesite="Lax",
        path="/",
    )
    log_event(f"تسجيل دخول المستخدم {uid}", level="WEB")
    return resp


async def handle_logout(request: web.Request) -> web.Response:
    pair = get_discord_session_with_id(request)
    if pair:
        SESSIONS.pop(pair[0], None)
    resp = web.HTTPFound("/")
    resp.del_cookie("arab_sec_session", path="/")
    return resp


async def health_handler(request: web.Request) -> web.Response:
    return web.json_response(
        {
            "ok": True,
            "site": SITE_NAME,
            "bot_guilds_count": len(get_all_guilds()),
            "db_online": db is not None,
        }
    )


@web.middleware
async def security_and_visit_middleware(request: web.Request, handler):
    ip = get_client_ip(request)
    is_auth = request.path in ("/login", "/callback")
    if is_rate_limited(ip, is_sensitive=is_auth):
        return web.Response(text="Rate limit exceeded.", status=429)

    record_site_visit(request)
    response = await handler(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


def create_app() -> web.Application:
    app = web.Application(middlewares=[security_and_visit_middleware])
    app.router.add_get("/", home_handler)
    app.router.add_get("/servers", handle_servers)
    app.router.add_get("/guild", handle_guild)
    app.router.add_post("/guild", handle_guild)
    app.router.add_get("/premium", handle_premium)
    app.router.add_post("/premium", handle_premium)
    app.router.add_get("/admin", handle_admin)
    app.router.add_post("/admin", handle_admin)
    app.router.add_get("/services", handle_services)
    app.router.add_get("/updates", handle_updates)
    app.router.add_get("/links", handle_links)
    app.router.add_get("/login", handle_login)
    app.router.add_get("/callback", handle_callback)
    app.router.add_get("/logout", handle_logout)
    app.router.add_get("/health", health_handler)
    app.router.add_post("/api/bot/sync-guilds", api_bot_sync_guilds)
    app.router.add_get("/api/bot/pending-commands", api_bot_pending_commands)
    return app


if __name__ == "__main__":
    web.run_app(create_app(), host=HOST, port=PORT)
