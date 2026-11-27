import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from urllib.parse import quote, urlencode, urlparse

from aiohttp import ClientError, ClientSession, ClientTimeout, web

try:
    from pymongo import MongoClient, ReturnDocument, UpdateOne
    from pymongo.errors import PyMongoError
except Exception:
    MongoClient = None
    ReturnDocument = None
    UpdateOne = None

    class PyMongoError(Exception):
        pass


SITE_NAME = (os.getenv("SITE_NAME", "ARAB SECURITY") or "ARAB SECURITY").strip()[:60]
OWNER_NAME = (os.getenv("OWNER_NAME", "SAUD") or "سعود السويط").strip()[:60]
ADMIN_USER_ID = (os.getenv("ADMIN_USER_ID", "1395418036919468073") or "1395418036919468073").strip()

DEFAULT_DOMAIN_URL = "https://arabsecurity.de5.net"
SUPPORT_SERVER_URL = (os.getenv("SUPPORT_SERVER_URL", "https://discord.gg/vV84RqJNks") or "").strip()

HOST = (os.getenv("HOST", "0.0.0.0") or "0.0.0.0").strip()
PORT = int((os.getenv("PORT", "8080") or "8080").strip())

EXPLICIT_MAIN_URL = (os.getenv("MAIN_SITE_URL", DEFAULT_DOMAIN_URL) or DEFAULT_DOMAIN_URL).strip().rstrip("/")
EXPLICIT_WEB_URL = (os.getenv("WEB_BASE_URL", DEFAULT_DOMAIN_URL) or DEFAULT_DOMAIN_URL).strip().rstrip("/")
EXPLICIT_REDIRECT_URI = (os.getenv("DISCORD_REDIRECT_URI", "") or "").strip()

BOT_INVITE_URL = (
    os.getenv(
        "BOT_INVITE_URL",
        "https://discord.com/oauth2/authorize?client_id=1573635674551357550&permissions=8&integration_type=0&scope=bot%20applications.commands",
    )
    or ""
).strip()

MONGO_DB_NAME = (os.getenv("MONGO_DB", "arab_security") or "arab_security").strip()
DEFAULT_MONGO_URI = "mongodb+srv://soudfares02_db_user:QiADlkDohqCpFP6z@cluster0.hzhfdxt.mongodb.net/arab_security?retryWrites=true&w=majority"
MONGO_URI = (os.getenv("MONGO_URI", DEFAULT_MONGO_URI) or DEFAULT_MONGO_URI).strip()

DEFAULT_SYNC_SECRET = "OzLxgLklbMjEbhRg7__f8HvtQo1BK584"

_env_secret = (os.environ.get("SESSION_SECRET") or "").strip()
SESSION_SECRET = (
    _env_secret
    if len(_env_secret) >= 16
    else "ArabSecurity_Session_Secret_2026_x9K#mP2vL8qR5tW7zY3nB6jH4cF1gD0sA"
)
BOT_SYNC_SECRET = (
    (os.environ.get("BOT_SYNC_SECRET") or "").strip()
    or (os.environ.get("SILENT_SECRET") or "").strip()
    or DEFAULT_SYNC_SECRET
)

RATE_LIMIT_PER_MIN = max(30, min(1000, int((os.getenv("RATE_LIMIT_PER_MIN", "180") or "180").strip())))
AUTH_RATE_LIMIT_PER_MIN = max(10, min(200, int((os.getenv("AUTH_RATE_LIMIT_PER_MIN", "35") or "35").strip())))

TRUST_PROXY = (os.getenv("TRUST_PROXY", "true") or "true").strip().lower() in ("1", "true", "yes", "on")
TRUSTED_PROXY_IPS = {
    ip.strip()
    for ip in (os.getenv("TRUSTED_PROXY_IPS", "") or "").split(",")
    if ip.strip()
}
COOKIE_SECURE_ENV = (os.getenv("COOKIE_SECURE", "") or "").strip().lower()

DISCORD_CLIENT_ID = (os.getenv("DISCORD_CLIENT_ID", "1573635674551357550") or "").strip()
DISCORD_CLIENT_SECRET = (os.getenv("DISCORD_CLIENT_SECRET", "OzLxgLklbMjEbhRg7__f8HvtQo1BK584") or "").strip()

MAX_IMAGE_BYTES = 10_000_000
MAX_IMAGE_DATA_URL_LEN = 14_000_000
MAX_BIO_CHARS = 270

MANAGE_GUILD_PERM = 0x20
ADMIN_PERM = 0x8

ADMIN_PERMISSION_KEYS = (
    "manage_premium",
    "manage_admins",
    "remote_actions",
    "simulations",
    "backups",
    "view_logs",
)

STAFF_ROLE_OPTIONS = ("Co owner", "Staff")

ANTINUKE_RULE_KEYS = (
    "anti_ban",
    "anti_kick",
    "anti_role_create",
    "anti_role_delete",
    "anti_role_edit",
    "anti_channel_create",
    "anti_channel_delete",
    "anti_webhook_create",
    "anti_bot_add",
    "anti_guild_update",
    "anti_emoji_delete",
)

GENERAL_TOGGLE_KEYS = (
    "lockdown",
    "voice_lock",
    "silent_mode",
    "beast_mode",
    "maintenance",
    "verification",
    "alert_on_trigger",
)

ANTINUKE_TOGGLE_KEYS = (
    "anti_role_delete",
    "anti_role_edit",
    "dangerous_perms_guard",
    "anti_app_abuse",
    "anti_channel_perms_tamper",
    "quarantine_on_sabotage",
    "anti_privilege_escalation",
    "anti_vanity_tamper",
    "anti_webhook_abuse",
    "anti_mass_unban",
    "anti_mass_kick",
    "anti_mass_timeout",
    "audit_log_watch",
    "admin_behavior_analysis",
    "trusted_admins_enabled",
    "perms_snapshot_enabled",
    "auto_rollback_enabled",
    "gradual_attack_detect",
    "collusion_detect",
    "false_punishment_guard",
    "emergency_mode",
    "auto_perms_audit",
    "role_hierarchy_guard",
    "auto_quarantine",
)

PREMIUM_PROTECTION_TOGGLE_KEYS = (
    "anti_guild_icon_change",
    "anti_selfbot",
)

ANTIRAID_TOGGLE_KEYS = (
    "anti_raid",
    "anti_new_accounts",
    "anti_bot_raid",
)

MODERATION_TOGGLE_KEYS = (
    "anti_link",
    "anti_invites",
    "anti_mention_spam",
    "anti_spam",
)

SHIELD_TOGGLE_KEYS = (
    *GENERAL_TOGGLE_KEYS,
    *ANTINUKE_TOGGLE_KEYS,
    *PREMIUM_PROTECTION_TOGGLE_KEYS,
    *ANTIRAID_TOGGLE_KEYS,
    *MODERATION_TOGGLE_KEYS,
)


def _full_admin_perms() -> dict[str, bool]:
    return {k: True for k in ADMIN_PERMISSION_KEYS}


def _default_sub_admin_perms(custom: dict | None = None) -> dict[str, bool]:
    base = {
        "manage_premium": True,
        "manage_admins": False,
        "remote_actions": True,
        "simulations": True,
        "backups": False,
        "view_logs": True,
    }
    if isinstance(custom, dict):
        for k in ADMIN_PERMISSION_KEYS:
            if k in custom:
                base[k] = bool(custom[k])
    return base


def _sanitize_staff_role(raw_role: str | None, uid: str = "") -> str:
    if uid == ADMIN_USER_ID:
        return "Owner"
    val = str(raw_role or "").strip()
    if val in STAFF_ROLE_OPTIONS:
        return val
    low = val.lower()
    if low in ("co owner", "co-owner", "coowner"):
        return "Co owner"
    if low == "staff":
        return "Staff"
    return "Staff"


def _fresh_default_guild_cfg() -> dict:
    return {
        "prefix": "!",
        "maintenance": False,
        "mod_log_channel": "",
        "anti_spam": True,
        "spam_punishment": "Timeout",
        "spam_timeout_seconds": 600,
        "anti_link": True,
        "link_punishment": "Delete & Timeout",
        "link_timeout_seconds": 300,
        "anti_invites": True,
        "voice_lock": False,
        "silent_mode": False,
        "beast_mode": False,
        "anti_raid": True,
        "verification": False,
        "lockdown": False,
        "anti_new_accounts": True,
        "min_account_age_days": 7,
        "dangerous_perms_guard": True,
        "dangerous_perms_punishment": "Remove Roles",
        "alert_on_trigger": True,
        "anti_selfbot": True,
        "selfbot_punishment": "Ban",
        "anti_webhook_abuse": True,
        "anti_app_abuse": True,
        "app_abuse_punishment": "Ban",
        "anti_privilege_escalation": True,
        "anti_role_delete": True,
        "anti_role_edit": True,
        "anti_channel_perms_tamper": True,
        "audit_log_watch": True,
        "anti_mass_unban": True,
        "anti_mass_kick": True,
        "anti_mass_timeout": True,
        "anti_mention_spam": True,
        "admin_behavior_analysis": True,
        "trusted_admins_enabled": True,
        "perms_snapshot_enabled": True,
        "auto_rollback_enabled": True,
        "gradual_attack_detect": True,
        "collusion_detect": True,
        "false_punishment_guard": True,
        "emergency_mode": False,
        "auto_perms_audit": True,
        "anti_bot_raid": True,
        "anti_vanity_tamper": True,
        "anti_guild_icon_change": True,
        "guild_icon_punishment": "Ban",
        "quarantine_on_sabotage": True,
        "role_hierarchy_guard": True,
        "auto_quarantine": True,
        "trusted_admins": [ADMIN_USER_ID],
        "perms_snapshots": [],
        "antinuke": {
            "anti_ban": {"enabled": True, "limit": 1, "punishment": "Ban"},
            "anti_kick": {"enabled": True, "limit": 1, "punishment": "Ban"},
            "anti_role_create": {"enabled": True, "limit": 1, "punishment": "Kick"},
            "anti_role_delete": {"enabled": True, "limit": 1, "punishment": "Ban"},
            "anti_role_edit": {"enabled": True, "limit": 1, "punishment": "Remove Roles"},
            "anti_channel_create": {"enabled": True, "limit": 2, "punishment": "Kick"},
            "anti_channel_delete": {"enabled": True, "limit": 1, "punishment": "Ban"},
            "anti_webhook_create": {"enabled": True, "limit": 1, "punishment": "Ban"},
            "anti_bot_add": {"enabled": True, "limit": 1, "punishment": "Ban"},
            "anti_guild_update": {"enabled": True, "limit": 1, "punishment": "Kick"},
            "anti_emoji_delete": {"enabled": True, "limit": 2, "punishment": "Kick"},
        },
        "guild_profile": {
            "bio": "",
            "avatar_data_url": "",
            "avatar_name": "",
            "banner_data_url": "",
            "banner_name": "",
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
MEM_PREMIUM: dict[str, dict] = {
    ADMIN_USER_ID: {
        "user_id": ADMIN_USER_ID,
        "username": OWNER_NAME,
        "handle": OWNER_NAME,
        "granted_by": "owner",
        "source": "owner",
        "granted_at": "",
        "expires_at": 0.0,
        "permanent": True,
    }
}
MEM_ADMINS: dict[str, dict] = {
    ADMIN_USER_ID: {
        "user_id": ADMIN_USER_ID,
        "role_tag": "Owner",
        "granted_by": "owner",
        "updated_at": "",
        "permissions": _full_admin_perms(),
    }
}
MEM_VISITORS: dict[str, object] = {
    "total_visits": 0,
    "unique_hashes": deque(maxlen=5000),
    "unique_seen": set(),
}
MEM_BACKUPS: deque[dict] = deque(maxlen=25)
MEM_BOT_HEARTBEAT: dict[str, str] = {
    "status": "ONLINE",
    "last_seen": "",
}

_CFG_CACHE: dict[str, tuple[float, dict]] = {}
_CFG_TTL = 2.0
_PERM_CACHE: dict[str, tuple[float, object]] = {}
_PERM_TTL = 1.0
_GUILDS_CACHE: tuple[float, list[dict]] = (0.0, [])
_GUILDS_TTL = 1.0
_VISIT_STATS_CACHE: tuple[float, int, int] = (0.0, 0, 0)
_VISIT_STATS_TTL = 8.0
_PENDING_VISITS = 0
_PENDING_UNIQUE: list[str] = []
_LAST_VISIT_FLUSH = 0.0

CSRF_TOKENS: dict[str, dict] = {}
OAUTH_STATES: dict[str, dict] = {}
USED_NONCES: dict[str, float] = {}
RATE_BUCKETS: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=500))
AUTH_RATE_BUCKETS: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=150))
SESSIONS: dict[str, dict] = {}


def sanitize_next_url(raw_next: str | None) -> str:
    val = str(raw_next or "").strip()
    if not val.startswith("/") or val.startswith("//") or "\\" in val:
        return "/"
    return val[:120]


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


def sanitize_image_data_url(raw_val: str | None, max_len: int = MAX_IMAGE_DATA_URL_LEN) -> str:
    val = str(raw_val or "").strip()
    if not val:
        return ""
    if val.startswith("data:image/"):
        if len(val) > max_len or ";base64," not in val:
            return ""
        header, b64_part = val.split(";base64,", 1)
        allowed_mimes = ("data:image/png", "data:image/jpeg", "data:image/jpg", "data:image/webp", "data:image/gif")
        if header.lower() not in allowed_mimes or not b64_part:
            return ""
        try:
            decoded = base64.b64decode(b64_part, validate=True)
            if not decoded or len(decoded) > MAX_IMAGE_BYTES:
                return ""
            return f"{header.lower()};base64,{base64.b64encode(decoded).decode('ascii')}"
        except Exception:
            return ""
    return sanitize_http_url(val)


def sanitize_bio_text(raw_bio: str | None) -> str:
    txt = str(raw_bio or "").replace("\r\n", "\n").replace("\r", "\n")
    cleaned = "".join(ch for ch in txt if ch.isprintable() or ch == "\n").strip()
    return cleaned[:MAX_BIO_CHARS]


def _now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _parse_expires_ts(val) -> float:
    if isinstance(val, dict):
        for k in ("exp", "expires_at", "timestamp", "ts"):
            if k in val:
                val = val.get(k)
                break
        else:
            return 0.0
    if val is None or isinstance(val, bool):
        return 0.0
    if isinstance(val, datetime):
        dt = val if val.tzinfo is not None else val.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    if isinstance(val, (int, float)):
        return float(val)
    if isinstance(val, str):
        s = val.strip()
        if not s:
            return 0.0
        try:
            return float(s)
        except Exception:
            pass
        try:
            iso_s = s[:-1] + "+00:00" if s.endswith("Z") else s
            dt = datetime.fromisoformat(iso_s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except Exception:
            return 0.0
    return 0.0


def _safe_exp(val) -> float:
    return _parse_expires_ts(val)


def _normalize_premium_doc(doc: dict) -> dict:
    clean = dict(doc)
    uid = str(clean.get("user_id") or clean.get("id") or "").strip()
    clean["user_id"] = uid
    clean["username"] = str(clean.get("username") or clean.get("name") or f"User {uid}").strip()[:40]
    raw_handle = str(clean.get("handle") or f"@{clean['username']}").strip()[:44]
    clean["handle"] = raw_handle if raw_handle.startswith("@") else f"@{raw_handle.lstrip('@')}"
    clean["source"] = str(clean.get("source") or clean.get("granted_by") or "manual").strip()
    clean["granted_by"] = str(clean.get("granted_by") or clean["source"] or "bot").strip()
    clean["permanent"] = bool(clean.get("permanent")) or uid == ADMIN_USER_ID
    clean["expires_at"] = 0.0 if clean["permanent"] else _parse_expires_ts(clean.get("expires_at", 0.0))
    return clean


def _is_premium_record_active(rec: dict, now: float) -> bool:
    uid = str(rec.get("user_id") or "").strip()
    if not uid.isdigit():
        return False
    if uid == ADMIN_USER_ID or bool(rec.get("permanent")) or rec.get("source") == "boost":
        return True
    return _parse_expires_ts(rec.get("expires_at", 0.0)) > now


client = None
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
sessions_col = None


def hydrate_from_db() -> None:
    if db is None:
        return
    now = time.time()
    try:
        if bot_guilds_col is not None:
            for g in bot_guilds_col.find({}, {"_id": 0}).limit(1000):
                gid = str(g.get("id", "")).strip()
                if gid.isdigit():
                    MEM_GUILDS[gid] = {
                        "id": gid,
                        "name": str(g.get("name", f"Server {gid}"))[:100],
                        "icon": str(g.get("icon", "") or "").strip()[:80],
                        "member_count": int(g.get("member_count", 0) or 0),
                        "owner_id": str(g.get("owner_id", "") or "").strip(),
                        "updated_at": str(g.get("updated_at", "") or "").strip(),
                    }

        if guild_settings_col is not None:
            for doc in guild_settings_col.find({}, {"_id": 0}).limit(1000):
                gid = str(doc.get("guild_id", "")).strip()
                if gid.isdigit():
                    base = _fresh_default_guild_cfg()
                    for k in base:
                        if k == "antinuke" and isinstance(doc.get("antinuke"), dict):
                            for ak, av in doc["antinuke"].items():
                                if ak in base["antinuke"] and isinstance(av, dict):
                                    base["antinuke"][ak].update(av)
                        elif k in ("guild_profile", "premium_perks") and isinstance(doc.get(k), dict):
                            base[k].update(doc[k])
                        elif k in doc:
                            base[k] = doc[k]
                    MEM_GUILD_CFG[gid] = base

        if premium_col is not None:
            for doc in premium_col.find({}, {"_id": 0}).limit(500):
                norm = _normalize_premium_doc(doc)
                uid = norm["user_id"]
                if not uid.isdigit():
                    continue
                if not _is_premium_record_active(norm, now):
                    continue
                MEM_PREMIUM[uid] = norm

        if admins_col is not None:
            for doc in admins_col.find({}, {"_id": 0}).limit(200):
                uid = str(doc.get("user_id", "")).strip()
                if uid.isdigit():
                    MEM_ADMINS[uid] = {
                        "user_id": uid,
                        "role_tag": _sanitize_staff_role(doc.get("role_tag"), uid=uid),
                        "granted_by": str(doc.get("granted_by", "owner")),
                        "updated_at": str(doc.get("updated_at", "-")),
                        "permissions": _full_admin_perms()
                        if uid == ADMIN_USER_ID
                        else _default_sub_admin_perms(doc.get("permissions")),
                    }

        if backups_col is not None:
            for b in list(backups_col.find({}, {"_id": 0}).sort("_id", -1).limit(25)):
                MEM_BACKUPS.append(dict(b))

        if logs_col is not None:
            for l in reversed(list(logs_col.find({}, {"_id": 0}).sort("_id", -1).limit(100))):
                MEM_LOGS.appendleft(dict(l))

        if incidents_col is not None:
            for inc in reversed(list(incidents_col.find({}, {"_id": 0}).sort("_id", -1).limit(100))):
                MEM_INCIDENTS.appendleft(dict(inc))

        if stats_col is not None:
            vdoc = stats_col.find_one({"_id": "visitors"}, {"total_visits": 1})
            if vdoc:
                MEM_VISITORS["total_visits"] = max(
                    int(MEM_VISITORS.get("total_visits", 0)),
                    int(vdoc.get("total_visits", 0) or 0),
                )
    except PyMongoError:
        pass


if MONGO_URI and MongoClient is not None:
    try:
        client = MongoClient(
            MONGO_URI,
            serverSelectionTimeoutMS=3000,
            connectTimeoutMS=3000,
            socketTimeoutMS=3000,
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
        sessions_col = db["web_sessions"]

        premium_col.update_one(
            {"user_id": ADMIN_USER_ID},
            {
                "$set": {
                    "user_id": ADMIN_USER_ID,
                    "username": OWNER_NAME,
                    "handle": OWNER_NAME,
                    "granted_by": "owner",
                    "source": "owner",
                    "permanent": True,
                    "expires_at": 0.0,
                    "updated_at": _now_str(),
                }
            },
            upsert=True,
        )
        admins_col.update_one(
            {"user_id": ADMIN_USER_ID},
            {
                "$set": {
                    "user_id": ADMIN_USER_ID,
                    "role_tag": "Owner",
                    "granted_by": "owner",
                    "updated_at": _now_str(),
                    "permissions": _full_admin_perms(),
                }
            },
            upsert=True,
        )
        hydrate_from_db()
        print(f"[WEB DB] Connected & hydrated persistently from MongoDB ({MONGO_DB_NAME})")
    except (PyMongoError, Exception) as exc:
        print(f"[WEB DB] Fallback memory mode ({type(exc).__name__})")


def _store_session_record(sid: str, record: dict) -> None:
    if len(SESSIONS) >= 5000:
        oldest_sid = next(iter(SESSIONS))
        SESSIONS.pop(oldest_sid, None)
    SESSIONS[sid] = dict(record)
    if sessions_col is not None:
        try:
            sessions_col.update_one({"sid": sid}, {"$set": {**record, "sid": sid}}, upsert=True)
        except PyMongoError:
            pass


def _load_session_record(sid: str) -> dict | None:
    now = time.time()
    mem_sess = SESSIONS.get(sid)
    if mem_sess:
        if _safe_exp(mem_sess.get("exp", 0)) <= now:
            SESSIONS.pop(sid, None)
        else:
            return mem_sess

    if sessions_col is not None:
        try:
            doc = sessions_col.find_one({"sid": sid}, {"_id": 0})
            if doc:
                if _safe_exp(doc.get("exp", 0)) <= now:
                    sessions_col.delete_one({"sid": sid})
                    return None
                SESSIONS[sid] = dict(doc)
                return dict(doc)
        except PyMongoError:
            pass
    return None


def _delete_session_record(sid: str) -> None:
    SESSIONS.pop(sid, None)
    if sessions_col is not None:
        try:
            sessions_col.delete_one({"sid": sid})
        except PyMongoError:
            pass


def _cleanup_expired() -> None:
    now = time.time()
    for k, meta in list(CSRF_TOKENS.items()):
        if _safe_exp(meta.get("exp", 0)) <= now:
            CSRF_TOKENS.pop(k, None)
    for st, meta in list(OAUTH_STATES.items()):
        if _safe_exp(meta.get("exp", 0)) <= now:
            OAUTH_STATES.pop(st, None)
    for n, exp in list(USED_NONCES.items()):
        if _safe_exp(exp) <= now:
            USED_NONCES.pop(n, None)
    for sid, sess in list(SESSIONS.items()):
        if _safe_exp(sess.get("exp", 0)) <= now:
            SESSIONS.pop(sid, None)
    if sessions_col is not None:
        try:
            sessions_col.delete_many({"exp": {"$lte": now}})
        except PyMongoError:
            pass


def issue_oauth_state(next_url: str = "/") -> str:
    _cleanup_expired()
    st = secrets.token_urlsafe(24)
    if len(OAUTH_STATES) >= 2000:
        oldest = next(iter(OAUTH_STATES))
        OAUTH_STATES.pop(oldest, None)
    OAUTH_STATES[st] = {"exp": time.time() + 600.0, "next": sanitize_next_url(next_url)}
    return st


def consume_oauth_state(state_val: str | None) -> tuple[bool, str]:
    _cleanup_expired()
    clean = str(state_val or "").strip()
    if not clean or clean not in OAUTH_STATES:
        return False, "/"
    meta = OAUTH_STATES.pop(clean)
    exp = _safe_exp(meta.get("exp", 0))
    nxt = sanitize_next_url(meta.get("next", "/"))
    return (exp > time.time()), nxt


def _sign_hmac(msg: str) -> str:
    return hmac.new(SESSION_SECRET.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()


def _invalidate_perm_cache(uid: str = "") -> None:
    if uid:
        for k in list(_PERM_CACHE.keys()):
            if k.endswith(f":{uid}") or k == uid:
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


def should_use_secure_cookie(request: web.Request) -> bool:
    if COOKIE_SECURE_ENV in ("1", "true", "yes", "on"):
        return True
    if COOKIE_SECURE_ENV in ("0", "false", "no", "off"):
        return False
    remote_ip = str(request.remote or "").strip()
    can_trust = TRUST_PROXY and (not TRUSTED_PROXY_IPS or remote_ip in TRUSTED_PROXY_IPS)
    proto = (
        (request.headers.get("X-Forwarded-Proto", "").split(",")[0].strip().lower() if can_trust else "")
        or str(request.scheme or "").lower()
    )
    return proto == "https"


def flush_visits_if_needed(force: bool = False) -> None:
    global _PENDING_VISITS, _PENDING_UNIQUE, _LAST_VISIT_FLUSH
    now = time.time()
    if not force and (now - _LAST_VISIT_FLUSH) < 2.0 and _PENDING_VISITS < 10:
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


def get_total_visits() -> int:
    global _VISIT_STATS_CACHE
    now = time.time()
    if (now - _VISIT_STATS_CACHE[0]) < _VISIT_STATS_TTL:
        return _VISIT_STATS_CACHE[1]

    mem_total = int(MEM_VISITORS.get("total_visits", 0))
    db_total = 0
    if stats_col is not None:
        try:
            vdoc = stats_col.find_one({"_id": "visitors"}, {"total_visits": 1})
            if vdoc:
                db_total = int(vdoc.get("total_visits", 0) or 0)
        except PyMongoError:
            pass
    tot = max(mem_total, db_total)
    _VISIT_STATS_CACHE = (now, tot, 0)
    return tot


def _get_admin_record(uid: str, force_db: bool = False) -> dict | None:
    if not uid.isdigit():
        return None
    if uid == ADMIN_USER_ID:
        return {
            "user_id": ADMIN_USER_ID,
            "role_tag": "Owner",
            "granted_by": "owner",
            "updated_at": "-",
            "permissions": _full_admin_perms(),
        }
    rec = MEM_ADMINS.get(uid)
    if (not rec or force_db) and admins_col is not None:
        try:
            doc = admins_col.find_one({"user_id": uid}, {"_id": 0})
            if doc:
                rec = {
                    "user_id": uid,
                    "role_tag": _sanitize_staff_role(doc.get("role_tag"), uid=uid),
                    "granted_by": str(doc.get("granted_by", "owner")),
                    "updated_at": str(doc.get("updated_at", "-")),
                    "permissions": _default_sub_admin_perms(doc.get("permissions")),
                }
                MEM_ADMINS[uid] = rec
            elif force_db:
                MEM_ADMINS.pop(uid, None)
                rec = None
        except PyMongoError:
            pass
    if rec:
        copy_rec = dict(rec)
        copy_rec["role_tag"] = _sanitize_staff_role(rec.get("role_tag"), uid=uid)
        copy_rec["permissions"] = _default_sub_admin_perms(rec.get("permissions"))
        return copy_rec
    return None


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
        return bool(cached[1])
    res = _get_admin_record(uid, force_db=True) is not None
    _PERM_CACHE[cache_key] = (time.time(), res)
    return res


def has_admin_perm(user: dict | None, perm_key: str) -> bool:
    if not user:
        return False
    uid = str(user.get("id", "")).strip()
    if not uid.isdigit():
        return False
    if uid == ADMIN_USER_ID:
        return True
    rec = _get_admin_record(uid)
    if not rec:
        return False
    perms = rec.get("permissions") or {}
    return bool(perms.get(perm_key, False))


def get_admin_list() -> list[dict]:
    items: dict[str, dict] = {
        ADMIN_USER_ID: {
            "user_id": ADMIN_USER_ID,
            "role_tag": "Owner",
            "granted_by": "owner",
            "updated_at": "-",
            "permissions": _full_admin_perms(),
        }
    }
    for uid, rec in MEM_ADMINS.items():
        if uid not in items:
            items[uid] = {
                "user_id": uid,
                "role_tag": _sanitize_staff_role(rec.get("role_tag"), uid=uid),
                "granted_by": str(rec.get("granted_by", "admin")),
                "updated_at": str(rec.get("updated_at", "-")),
                "permissions": _default_sub_admin_perms(rec.get("permissions")),
            }
    if admins_col is not None:
        try:
            for doc in admins_col.find({}, {"_id": 0}).limit(100):
                uid = str(doc.get("user_id", "")).strip()
                if uid.isdigit():
                    items[uid] = {
                        "user_id": uid,
                        "role_tag": _sanitize_staff_role(doc.get("role_tag"), uid=uid),
                        "granted_by": str(doc.get("granted_by", "owner")),
                        "updated_at": str(doc.get("updated_at", "-")),
                        "permissions": _full_admin_perms()
                        if uid == ADMIN_USER_ID
                        else _default_sub_admin_perms(doc.get("permissions")),
                    }
        except PyMongoError:
            pass
    return list(items.values())


def set_admin_user(
    user_id: str,
    enabled: bool,
    granted_by: str = "",
    permissions: dict[str, bool] | None = None,
    role_tag: str = "Staff",
) -> bool:
    uid = str(user_id or "").strip()
    if not uid.isdigit():
        return False
    _invalidate_perm_cache("")
    if enabled:
        perms_clean = _full_admin_perms() if uid == ADMIN_USER_ID else _default_sub_admin_perms(permissions)
        clean_tag = _sanitize_staff_role(role_tag, uid=uid)
        stamp = _now_str()
        rec = {
            "user_id": uid,
            "role_tag": clean_tag,
            "granted_by": granted_by or ADMIN_USER_ID,
            "updated_at": stamp,
            "permissions": perms_clean,
        }
        MEM_ADMINS[uid] = rec
        set_premium_user(uid, True, days=365, hours=0, granted_by=granted_by or ADMIN_USER_ID, source="admin")
        if admins_col is not None:
            try:
                admins_col.update_one({"user_id": uid}, {"$set": rec}, upsert=True)
            except PyMongoError:
                pass
        return True
    if uid == ADMIN_USER_ID:
        return False
    MEM_ADMINS.pop(uid, None)
    if admins_col is not None:
        try:
            admins_col.delete_one({"user_id": uid})
        except PyMongoError:
            pass
    return True


def _get_premium_record(uid: str, force_db: bool = False) -> dict | None:
    if not uid.isdigit():
        return None
    if uid == ADMIN_USER_ID:
        return {
            "user_id": ADMIN_USER_ID,
            "username": OWNER_NAME,
            "handle": OWNER_NAME,
            "granted_by": "owner",
            "source": "owner",
            "permanent": True,
            "expires_at": 0.0,
        }
    now = time.time()
    rec = MEM_PREMIUM.get(uid)
    if premium_col is not None and (force_db or not rec):
        try:
            doc = premium_col.find_one({"user_id": uid}, {"_id": 0})
            if doc:
                rec = _normalize_premium_doc(doc)
                MEM_PREMIUM[uid] = rec
            elif rec and rec.get("source") == "boost":
                MEM_PREMIUM.pop(uid, None)
                return None
            elif force_db:
                MEM_PREMIUM.pop(uid, None)
                return None
        except PyMongoError:
            pass
    if not rec:
        return None
    norm = _normalize_premium_doc(rec)
    if not _is_premium_record_active(norm, now):
        set_premium_user(uid, False)
        return None
    MEM_PREMIUM[uid] = norm
    return norm


def is_premium_user(user: dict | None) -> bool:
    if not user:
        return False
    uid = str(user.get("id", "")).strip()
    if not uid.isdigit():
        return False
    if is_site_admin(user):
        return True
    cache_key = f"prem:{uid}"
    cached = _PERM_CACHE.get(cache_key)
    if cached and (time.time() - cached[0]) < _PERM_TTL:
        return bool(cached[1])
    res = _get_premium_record(uid, force_db=True) is not None
    _PERM_CACHE[cache_key] = (time.time(), res)
    return res


def format_remaining_time(rec: dict, is_en: bool = False) -> str:
    norm = _normalize_premium_doc(rec or {})
    if norm.get("permanent"):
        return "Lifetime" if is_en else "دائم"
    if norm.get("source") == "boost":
        return "Active via Server Boost" if is_en else "مفعل عبر دعم البوست"
    rem = max(0.0, _parse_expires_ts(norm.get("expires_at", 0.0)) - time.time())
    days = int(rem // 86400)
    hours = int((rem % 86400) // 3600)
    mins = int((rem % 3600) // 60)
    if days > 0:
        return f"{days}d {hours}h left" if is_en else f"{days} يوم و {hours} ساعة"
    if hours > 0:
        return f"{hours}h {mins}m left" if is_en else f"{hours} ساعة و {mins} دقيقة"
    return f"{max(1, mins)}m left" if is_en else f"{max(1, mins)} دقيقة متبقية"


def get_premium_list() -> list[dict]:
    now = time.time()
    items: dict[str, dict] = {}
    if premium_col is not None:
        try:
            for doc in premium_col.find({}, {"_id": 0}).limit(250):
                norm = _normalize_premium_doc(doc)
                uid = norm["user_id"]
                if not uid.isdigit():
                    continue
                if not _is_premium_record_active(norm, now):
                    try:
                        premium_col.delete_one({"user_id": uid})
                    except PyMongoError:
                        pass
                    MEM_PREMIUM.pop(uid, None)
                    continue
                items[uid] = dict(norm)
                MEM_PREMIUM[uid] = dict(norm)
        except PyMongoError:
            pass
    for uid, rec in list(MEM_PREMIUM.items()):
        if uid in items:
            continue
        norm = _normalize_premium_doc(rec)
        if not _is_premium_record_active(norm, now):
            MEM_PREMIUM.pop(uid, None)
            continue
        items[uid] = dict(norm)
    return list(items.values())


def set_premium_user(
    user_id: str,
    enabled: bool,
    days: int = 0,
    hours: int = 0,
    granted_by: str = "",
    username: str = "",
    handle: str = "",
    source: str = "manual",
) -> bool:
    uid = str(user_id or "").strip()
    if not uid.isdigit():
        return False
    _invalidate_perm_cache("")
    if enabled:
        now = time.time()
        is_perm = uid == ADMIN_USER_ID
        total_seconds = max(60, int(days or 0) * 86400 + int(hours or 0) * 3600)
        existing = MEM_PREMIUM.get(uid) or {}
        clean_uname = str(username or existing.get("username") or f"User {uid}").strip()[:40]
        clean_handle = str(handle or existing.get("handle") or f"@{clean_uname}").strip()[:44]
        rec = {
            "user_id": uid,
            "username": clean_uname,
            "handle": clean_handle,
            "granted_by": granted_by or ADMIN_USER_ID,
            "source": source,
            "duration_days": int(days or 0),
            "duration_hours": int(hours or 0),
            "granted_at": _now_str(),
            "expires_at": 0.0 if is_perm else (now + total_seconds),
            "permanent": is_perm,
        }
        MEM_PREMIUM[uid] = rec
        if premium_col is not None:
            try:
                premium_col.update_one({"user_id": uid}, {"$set": rec}, upsert=True)
            except PyMongoError:
                pass
        return True
    if uid == ADMIN_USER_ID:
        return False
    MEM_PREMIUM.pop(uid, None)
    if premium_col is not None:
        try:
            premium_col.delete_one({"user_id": uid})
        except PyMongoError:
            pass
    return True


def sync_boosters_premium(boosters: list[dict]) -> tuple[int, int]:
    stamp = _now_str()
    active_map: dict[str, dict] = {}
    for b in boosters or []:
        if not isinstance(b, dict):
            continue
        uid = str(b.get("user_id", "")).strip()
        if not uid.isdigit() or uid == ADMIN_USER_ID:
            continue
        uname = str(b.get("username") or f"Booster {uid}").strip()[:40]
        active_map[uid] = {
            "user_id": uid,
            "username": uname,
            "handle": f"@{uname.lstrip('@')}",
            "granted_by": "boost",
            "source": "boost",
            "granted_at": stamp,
            "expires_at": 0.0,
            "permanent": False,
        }

    for uid, rec in list(MEM_PREMIUM.items()):
        if uid == ADMIN_USER_ID:
            continue
        if rec.get("source") == "boost" and uid not in active_map:
            MEM_PREMIUM.pop(uid, None)
            _invalidate_perm_cache(uid)

    if premium_col is not None:
        try:
            if active_map:
                premium_col.delete_many({"source": "boost", "user_id": {"$nin": list(active_map.keys())}})
            else:
                premium_col.delete_many({"source": "boost"})
        except PyMongoError:
            pass

    for uid, rec in active_map.items():
        existing_mem = MEM_PREMIUM.get(uid)
        existing_db = None
        if not existing_mem and premium_col is not None:
            try:
                existing_db = premium_col.find_one({"user_id": uid}, {"_id": 0})
            except PyMongoError:
                existing_db = None
        current_src = (existing_mem or existing_db or {}).get("source")
        if current_src in ("manual", "admin", "owner"):
            continue

        preserved_granted = (existing_mem or existing_db or {}).get("granted_at") or stamp
        record_to_save = {**rec, "granted_at": preserved_granted}
        MEM_PREMIUM[uid] = dict(record_to_save)
        _invalidate_perm_cache(uid)
        if premium_col is not None:
            try:
                premium_col.update_one({"user_id": uid}, {"$set": record_to_save}, upsert=True)
            except PyMongoError:
                pass

    return len(active_map), len(get_premium_list())


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
    if level in ("ALERT", "ADMIN", "SEC", "WARN", "ERROR"):
        record_incident(guild_id or "GLOBAL", level, msg, "HIGH" if level in ("ALERT", "ERROR") else "MEDIUM")


def get_recent_logs(limit: int = 50) -> list[dict]:
    if logs_col is not None:
        try:
            return list(logs_col.find({}, {"_id": 0}).sort("_id", -1).limit(limit))
        except PyMongoError:
            pass
    return list(MEM_LOGS)[:limit]


def get_recent_incidents(limit: int = 30) -> list[dict]:
    if incidents_col is not None:
        try:
            return list(incidents_col.find({}, {"_id": 0}).sort("_id", -1).limit(limit))
        except PyMongoError:
            pass
    return list(MEM_INCIDENTS)[:limit]


def get_recent_backups(limit: int = 15) -> list[dict]:
    if backups_col is not None:
        try:
            return list(backups_col.find({}, {"_id": 0}).sort("_id", -1).limit(limit))
        except PyMongoError:
            pass
    return list(MEM_BACKUPS)[:limit]


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
            "icon": str(item.get("icon", "") or "").strip()[:80],
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
                ops = [UpdateOne({"id": gid}, {"$set": doc}, upsert=True) for gid, doc in cleaned.items()]
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
            for g in bot_guilds_col.find({}, {"_id": 0}).limit(1000):
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
    if not isinstance(user_guilds, list) or not user_guilds:
        return [], False

    bot_guilds = get_all_guilds()
    bot_map = {str(g["id"]).strip(): g for g in bot_guilds if str(g.get("id", "")).strip().isdigit()}

    matched: list[dict] = []
    seen: set[str] = set()

    for ug in user_guilds:
        if not isinstance(ug, dict):
            continue
        gid = str(ug.get("id", "")).strip()
        if not gid.isdigit() or gid in seen:
            continue

        perms = int(ug.get("permissions", 0) or 0)
        is_owner = bool(ug.get("owner", False))
        can_manage = is_owner or bool(perms & ADMIN_PERM) or bool(perms & MANAGE_GUILD_PERM)
        if not can_manage:
            continue

        seen.add(gid)
        if gid in bot_map:
            info = dict(bot_map[gid])
            info["bot_missing"] = False
            if ug.get("icon") and not info.get("icon"):
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

    matched.sort(key=lambda item: (bool(item.get("bot_missing")), str(item.get("name", "")).lower()))
    return matched, True


def user_can_manage_guild(guild_id: str, user: dict | None, require_bot_present: bool = True) -> dict | None:
    gid = str(guild_id or "").strip()
    if not gid.isdigit() or not user:
        return None
    visible, _ = get_user_visible_guilds(user)
    for g in visible:
        if g["id"] == gid:
            if require_bot_present and g.get("bot_missing"):
                return None
            return g
    return None


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


def save_guild_cfg(guild_id: str, updates: dict, is_premium: bool = False) -> dict:
    gid = str(guild_id or "").strip()
    _CFG_CACHE.pop(gid, None)
    cfg = get_guild_cfg(gid)
    for key in SHIELD_TOGGLE_KEYS:
        if key in updates:
            if key in PREMIUM_PROTECTION_TOGGLE_KEYS and not is_premium:
                continue
            cfg[key] = bool(updates[key])

    if "spam_punishment" in updates:
        sp = str(updates["spam_punishment"] or "Timeout").strip()
        if sp in ("Delete Only", "Timeout", "Kick", "Ban"):
            cfg["spam_punishment"] = sp
    if "link_punishment" in updates:
        lp = str(updates["link_punishment"] or "Delete & Timeout").strip()
        if lp in ("Delete Only", "Delete & Timeout", "Kick", "Ban"):
            cfg["link_punishment"] = lp
    if "dangerous_perms_punishment" in updates:
        dp = str(updates["dangerous_perms_punishment"] or "Remove Roles").strip()
        if dp in ("Remove Roles", "Kick", "Ban", "Quarantine"):
            cfg["dangerous_perms_punishment"] = dp
    if "selfbot_punishment" in updates and is_premium:
        sbp = str(updates["selfbot_punishment"] or "Ban").strip()
        if sbp in ("Kick", "Ban", "Timeout"):
            cfg["selfbot_punishment"] = sbp
    if "app_abuse_punishment" in updates:
        aap = str(updates["app_abuse_punishment"] or "Ban").strip()
        if aap in ("Remove Roles", "Kick", "Ban"):
            cfg["app_abuse_punishment"] = aap
    if "guild_icon_punishment" in updates and is_premium:
        gip = str(updates["guild_icon_punishment"] or "Ban").strip()
        if gip in ("Rollback", "Kick", "Ban"):
            cfg["guild_icon_punishment"] = gip

    for sec_key, def_val, min_v, max_v in (
        ("spam_timeout_seconds", 600, 10, 2419200),
        ("link_timeout_seconds", 300, 10, 2419200),
        ("min_account_age_days", 7, 1, 365),
    ):
        if sec_key in updates:
            try:
                cfg[sec_key] = max(min_v, min(max_v, int(updates[sec_key])))
            except Exception:
                cfg[sec_key] = def_val

    if "antinuke" in updates and isinstance(updates["antinuke"], dict):
        an_cfg = cfg.setdefault("antinuke", {})
        for rk, rv in updates["antinuke"].items():
            if rk in ANTINUKE_RULE_KEYS and isinstance(rv, dict):
                cur = an_cfg.setdefault(rk, {"enabled": True, "limit": 1, "punishment": "Ban"})
                if "enabled" in rv:
                    cur["enabled"] = bool(rv["enabled"])
                if "limit" in rv:
                    try:
                        cur["limit"] = max(1, min(50, int(rv["limit"])))
                    except Exception:
                        pass
                if "punishment" in rv:
                    pun = str(rv["punishment"] or "Ban").strip()
                    if pun in ("Ban", "Kick", "Remove Roles", "Quarantine", "Timeout"):
                        cur["punishment"] = pun

    if is_premium and "guild_profile" in updates and isinstance(updates["guild_profile"], dict):
        prof = cfg.setdefault("guild_profile", {})
        p_upd = updates["guild_profile"]
        if "bio" in p_upd:
            prof["bio"] = sanitize_bio_text(p_upd["bio"])
        if "avatar_data_url" in p_upd:
            prof["avatar_data_url"] = sanitize_image_data_url(p_upd["avatar_data_url"])
        if "banner_data_url" in p_upd:
            prof["banner_data_url"] = sanitize_image_data_url(p_upd["banner_data_url"])

    if is_premium and "premium_perks" in updates and isinstance(updates["premium_perks"], dict):
        perks = cfg.setdefault("premium_perks", {})
        pk_upd = updates["premium_perks"]
        for b_key in ("ultra_fortress_mode", "instant_rollback_enabled", "priority_shield_response"):
            if b_key in pk_upd:
                perks[b_key] = bool(pk_upd[b_key])
        if "alert_channel_id" in pk_upd:
            ch = str(pk_upd["alert_channel_id"] or "").strip()[:24]
            perks["alert_channel_id"] = ch if (not ch or ch.isdigit()) else perks.get("alert_channel_id", "")
        if "alert_webhook_url" in pk_upd:
            perks["alert_webhook_url"] = sanitize_http_url(pk_upd["alert_webhook_url"])

    if gid.isdigit():
        MEM_GUILD_CFG[gid] = json.loads(json.dumps(cfg))
        if guild_settings_col is not None:
            try:
                guild_settings_col.update_one(
                    {"guild_id": gid},
                    {"$set": {"guild_id": gid, **cfg, "is_premium": bool(is_premium), "updated_at": _now_str()}},
                    upsert=True,
                )
            except PyMongoError:
                pass
        _CFG_CACHE[gid] = (time.time(), json.loads(json.dumps(cfg)))
    return cfg


def calculate_security_score(cfg: dict) -> int:
    score = 22
    for item in (cfg.get("antinuke") or {}).values():
        if isinstance(item, dict) and item.get("enabled"):
            score += 4
    for key in SHIELD_TOGGLE_KEYS:
        if cfg.get(key):
            score += 2
    perks = cfg.get("premium_perks") or {}
    if perks.get("ultra_fortress_mode"):
        score += 5
    if perks.get("instant_rollback_enabled"):
        score += 2
    return max(0, min(100, score))


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
    log_event(f"Backup created [{snapshot['backup_id']}]", level="ADMIN")
    return snapshot


def enqueue_remote_action(
    guild_id: str,
    action: str,
    target: str,
    extra: dict | None = None,
    actor_user_id: str | None = None,
) -> None:
    safe_extra: dict = {}
    if isinstance(extra, dict):
        for k, v in extra.items():
            safe_extra[k] = v

    uid = str(actor_user_id or safe_extra.get("user_id") or safe_extra.get("actor_id") or "").strip()
    if uid.isdigit():
        safe_extra.setdefault("user_id", uid)
        safe_extra.setdefault("actor_id", uid)

    payload: dict = {
        "guild_id": str(guild_id),
        "action": str(action),
        "target": str(target),
        "extra": safe_extra,
        "status": "pending",
        "created_at": datetime.now(timezone.utc),
    }
    if uid.isdigit():
        payload["user_id"] = uid
        payload["actor_id"] = uid

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


def detect_redirect_uri(request: web.Request) -> str:
    if EXPLICIT_REDIRECT_URI:
        return EXPLICIT_REDIRECT_URI
    return f"{detect_base_url(request)}/callback"


def sign_session(payload: dict) -> str:
    _cleanup_expired()
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
    _store_session_record(sid, record)
    raw_b64 = json.dumps({"sid": sid, "exp": exp_val}, separators=(",", ":")).encode("utf-8")
    token_body = base64.urlsafe_b64encode(raw_b64).decode("ascii")
    sig = _sign_hmac(token_body)
    return f"{token_body}.{sig}"


def verify_session(token: str | None) -> tuple[str, dict] | None:
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
    now = time.time()
    if not sid or exp_val <= now:
        _delete_session_record(sid)
        return None
    sess = _load_session_record(sid)
    if not sess or _safe_exp(sess.get("exp", 0)) <= now:
        _delete_session_record(sid)
        return None
    return sid, sess


def get_discord_session_with_id(request: web.Request) -> tuple[str, dict] | None:
    tok = request.cookies.get("arab_sec_session") or request.headers.get("X-Arab-Session")
    return verify_session(tok)


def get_discord_session(request: web.Request) -> dict | None:
    pair = get_discord_session_with_id(request)
    return pair[1] if pair else None


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


def _is_valid_bot_sync_request(request: web.Request) -> bool:
    provided = str(
        request.headers.get("X-Bot-Secret")
        or request.headers.get("X-Silent-Secret")
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

    event_type = str(body.get("event", "")).strip() if isinstance(body, dict) else ""
    if event_type == "guild_join":
        joined_name = str(body.get("guild_name", "")).strip()
        log_event(f"Bot joined server ({joined_name})", level="BOT")
    return web.json_response({"ok": True, "count": len(synced)})


async def api_bot_boost_sync(request: web.Request) -> web.Response:
    if not _is_valid_bot_sync_request(request):
        return web.json_response({"ok": False, "error": "Unauthorized"}, status=401)
    try:
        body = await request.json()
    except Exception:
        return web.json_response({"ok": False, "error": "Invalid JSON"}, status=400)

    boosters_raw = body.get("boosters") if isinstance(body, dict) else None
    if not isinstance(boosters_raw, list):
        return web.json_response({"ok": False, "error": "boosters list required"}, status=400)

    active_boosters, total_premium = sync_boosters_premium(boosters_raw)
    log_event(f"Synced {active_boosters} boost premium subscribers (total premium: {total_premium})", level="BOT")
    return web.json_response({"ok": True, "boost_count": active_boosters, "total_premium": total_premium})


async def api_bot_pending_commands(request: web.Request) -> web.Response:
    if not _is_valid_bot_sync_request(request):
        return web.json_response({"ok": False, "error": "Unauthorized"}, status=401)

    MEM_BOT_HEARTBEAT["status"] = "ONLINE"
    MEM_BOT_HEARTBEAT["last_seen"] = _now_str()

    items: list[dict] = []
    if queue_col is not None:
        try:
            done_stamp = _now_str()
            ret_opt = ReturnDocument.AFTER if ReturnDocument is not None else True
            for _ in range(25):
                d = queue_col.find_one_and_update(
                    {"status": "pending"},
                    {"$set": {"status": "done", "done_at": done_stamp}},
                    sort=[("_id", 1)],
                    return_document=ret_opt,
                )
                if not d:
                    break
                extra_d = d.get("extra") if isinstance(d.get("extra"), dict) else {}
                uid_val = str(d.get("user_id") or extra_d.get("user_id") or "").strip()
                cmd_item = {
                    "id": str(d.get("_id")),
                    "guild_id": str(d.get("guild_id", "")),
                    "action": str(d.get("action", "")),
                    "target": str(d.get("target", "")),
                    "extra": extra_d,
                }
                if uid_val.isdigit():
                    cmd_item["user_id"] = uid_val
                    cmd_item["actor_id"] = uid_val
                items.append(cmd_item)
        except PyMongoError:
            pass

    while MEM_QUEUE and len(items) < 25:
        d = MEM_QUEUE.popleft()
        extra_d = d.get("extra") if isinstance(d.get("extra"), dict) else {}
        uid_val = str(d.get("user_id") or extra_d.get("user_id") or "").strip()
        cmd_item = {
            "id": "mem",
            "guild_id": str(d.get("guild_id", "")),
            "action": str(d.get("action", "")),
            "target": str(d.get("target", "")),
            "extra": extra_d,
        }
        if uid_val.isdigit():
            cmd_item["user_id"] = uid_val
            cmd_item["actor_id"] = uid_val
        items.append(cmd_item)

    return web.json_response({"ok": True, "commands": items})


async def api_ui_state(request: web.Request) -> web.Response:
    user = get_discord_session(request)
    guilds = get_all_guilds()
    visible_guilds, _ = get_user_visible_guilds(user)
    is_prem = is_premium_user(user)
    is_adm = is_site_admin(user)
    uid = str(user.get("id", "")).strip() if user else ""
    ava = str(user.get("avatar", "")).strip() if user else ""
    prem_rec = _get_premium_record(uid) if (user and is_prem) else None

    days_left = 0
    remaining_label = "غير مفعل"
    if prem_rec:
        remaining_label = format_remaining_time(prem_rec, is_en=False)
        if prem_rec.get("permanent"):
            days_left = 999
        else:
            rem_sec = max(0.0, _parse_expires_ts(prem_rec.get("expires_at", 0.0)) - time.time())
            days_left = max(1, int(rem_sec // 86400)) if rem_sec > 0 else 0

    avatar_url = (
        f"https://cdn.discordapp.com/avatars/{uid}/{ava}.png?size=128"
        if uid and ava
        else "https://placehold.co/160x160/7c5cff/ffffff?text=AS"
    )
    active_guilds_list = [g for g in (visible_guilds if user else guilds) if not g.get("bot_missing")]
    req_gid = str(request.query.get("guild_id", "") or "").strip()
    valid_ids = {g["id"] for g in (active_guilds_list or guilds)}
    selected_gid = req_gid if req_gid in valid_ids else (active_guilds_list[0]["id"] if active_guilds_list else (guilds[0]["id"] if guilds else ""))
    cfg = get_guild_cfg(selected_gid) if selected_gid else _fresh_default_guild_cfg()

    can_view_logs = bool(is_adm and has_admin_perm(user, "view_logs"))
    logs_raw = get_recent_logs(40) if can_view_logs else []
    formatted_logs = [
        {
            "id": idx + 1,
            "time": str(item.get("time", ""))[-8:] or "--:--:--",
            "type": str(item.get("level", "WEB")),
            "level": "CRITICAL"
            if str(item.get("level", "")).upper() in ("ALERT", "ERROR", "SEC")
            else ("WARN" if str(item.get("level", "")).upper() in ("WARN", "ADMIN") else "INFO"),
            "text": str(item.get("message", "")),
        }
        for idx, item in enumerate(logs_raw)
    ]

    admins_data = get_admin_list() if (is_adm and has_admin_perm(user, "manage_admins")) else []
    premium_list_data = get_premium_list() if (is_adm and has_admin_perm(user, "manage_premium")) else []
    backups_data = get_recent_backups(12) if (is_adm and has_admin_perm(user, "backups")) else []
    incidents_data = get_recent_incidents(20) if can_view_logs else []
    perks_cfg = cfg.get("premium_perks") or {}

    return web.json_response(
        {
            "ok": True,
            "isAuthenticated": bool(user),
            "isPremium": is_prem,
            "isAdmin": is_adm,
            "adminPerms": {
                k: has_admin_perm(user, k) for k in ADMIN_PERMISSION_KEYS
            } if is_adm else {k: False for k in ADMIN_PERMISSION_KEYS},
            "user": {
                "id": uid,
                "username": str(user.get("username", "مستخدم")) if user else "زائر غير مسجل",
                "avatar": avatar_url,
            },
            "selectedGuildId": selected_gid,
            "botHeartbeat": MEM_BOT_HEARTBEAT,
            "guilds": [
                {
                    "id": g["id"],
                    "name": g["name"],
                    "members": int(g.get("member_count", 0) or 0),
                    "protectionScore": calculate_security_score(get_guild_cfg(g["id"])),
                    "premium": is_prem,
                    "status": "محمي بالكامل",
                    "iconText": (str(g.get("name", "AS"))[:2] or "AS").upper(),
                }
                for g in (active_guilds_list or guilds)[:20]
            ],
            "protection": {
                **{k: bool(cfg.get(k, False)) for k in SHIELD_TOGGLE_KEYS},
                "spamPunishment": str(cfg.get("spam_punishment", "Timeout")),
                "spamTimeoutSeconds": int(cfg.get("spam_timeout_seconds", 600) or 600),
                "linkPunishment": str(cfg.get("link_punishment", "Delete & Timeout")),
                "linkTimeoutSeconds": int(cfg.get("link_timeout_seconds", 300) or 300),
                "minAccountAgeDays": int(cfg.get("min_account_age_days", 7) or 7),
                "dangerousPermsPunishment": str(cfg.get("dangerous_perms_punishment", "Remove Roles")),
                "selfbotPunishment": str(cfg.get("selfbot_punishment", "Ban")),
                "appAbusePunishment": str(cfg.get("app_abuse_punishment", "Ban")),
                "guildIconPunishment": str(cfg.get("guild_icon_punishment", "Ban")),
                "antinuke": cfg.get("antinuke") or {},
            },
            "premium": {
                "active": is_prem,
                "planName": "بريميوم السيرفرات الماسي",
                "daysLeft": days_left,
                "remainingLabel": remaining_label,
                "customBio": sanitize_bio_text((cfg.get("guild_profile") or {}).get("bio", ""))
                or "درع الحماية المتكامل لصد هجمات النيوك والسبام وحفظ السيرفر تلقائياً.",
                "customAvatar": sanitize_image_data_url((cfg.get("guild_profile") or {}).get("avatar_data_url", ""))
                or "https://placehold.co/180x180/7c5cff/ffffff?text=VIP",
                "customBanner": sanitize_image_data_url((cfg.get("guild_profile") or {}).get("banner_data_url", ""))
                or "https://placehold.co/900x260/16132e/9a82ff?text=ARAB+SECURITY+SHIELD",
                "perks": {
                    "ultraFortressMode": bool(perks_cfg.get("ultra_fortress_mode", False)),
                    "instantRollbackEnabled": bool(perks_cfg.get("instant_rollback_enabled", True)),
                    "priorityShieldResponse": bool(perks_cfg.get("priority_shield_response", True)),
                    "alertChannelId": str(perks_cfg.get("alert_channel_id", "") or ""),
                    "alertWebhookUrl": str(perks_cfg.get("alert_webhook_url", "") or ""),
                },
                "lastBackupTime": backups_data[0]["created_at"] if backups_data else "منذ دقائق",
            },
            "logs": formatted_logs,
            "incidents": incidents_data,
            "backups": backups_data,
            "admins": admins_data,
            "premiumUsers": [
                {
                    "user_id": p["user_id"],
                    "username": p["username"],
                    "source": p["source"],
                    "remaining": format_remaining_time(p, is_en=False),
                }
                for p in premium_list_data
            ],
        }
    )


async def api_ui_action(request: web.Request) -> web.Response:
    user = get_discord_session(request)
    if not user:
        return web.json_response({"ok": False, "error": "Login required"}, status=401)
    try:
        payload = await request.json()
    except Exception:
        return web.json_response({"ok": False, "error": "Invalid JSON"}, status=400)

    actor_uid = str(user.get("id", "")).strip()
    kind = str(payload.get("kind", "")).strip()
    raw_gid = str(payload.get("guild_id", "")).strip()
    visible_guilds, _ = get_user_visible_guilds(user)
    active_guilds = [g for g in visible_guilds if not g.get("bot_missing")]

    if raw_gid.isdigit() and user_can_manage_guild(raw_gid, user, require_bot_present=True):
        gid = raw_gid
    elif active_guilds:
        gid = active_guilds[0]["id"]
    else:
        gid = ""

    if kind == "save_protection":
        if not gid:
            return web.json_response({"ok": False, "error": "No managed server available"}, status=400)
        prot = payload.get("protection") if isinstance(payload.get("protection"), dict) else {}
        mapped: dict = {k: bool(prot.get(k, False)) for k in SHIELD_TOGGLE_KEYS if k in prot}
        if "spamPunishment" in prot:
            mapped["spam_punishment"] = str(prot["spamPunishment"])
        if "spamTimeoutSeconds" in prot:
            mapped["spam_timeout_seconds"] = prot["spamTimeoutSeconds"]
        if "linkPunishment" in prot:
            mapped["link_punishment"] = str(prot["linkPunishment"])
        if "linkTimeoutSeconds" in prot:
            mapped["link_timeout_seconds"] = prot["linkTimeoutSeconds"]
        if "minAccountAgeDays" in prot:
            mapped["min_account_age_days"] = prot["minAccountAgeDays"]
        if "dangerousPermsPunishment" in prot:
            mapped["dangerous_perms_punishment"] = str(prot["dangerousPermsPunishment"])
        if "selfbotPunishment" in prot:
            mapped["selfbot_punishment"] = str(prot["selfbotPunishment"])
        if "appAbusePunishment" in prot:
            mapped["app_abuse_punishment"] = str(prot["appAbusePunishment"])
        if "guildIconPunishment" in prot:
            mapped["guild_icon_punishment"] = str(prot["guildIconPunishment"])
        if isinstance(prot.get("antinuke"), dict):
            mapped["antinuke"] = prot["antinuke"]

        save_guild_cfg(gid, mapped, is_premium=is_premium_user(user))
        enqueue_remote_action(gid, "sync_guild_cfg", gid, extra={"guild_id": gid, "user_id": actor_uid}, actor_user_id=actor_uid)
        log_event(f"Synced full protection settings for {gid}", guild_id=gid, level="SEC")
        return web.json_response({"ok": True})

    if kind == "save_premium":
        if not is_premium_user(user):
            return web.json_response({"ok": False, "error": "Premium required"}, status=403)
        if not gid:
            return web.json_response({"ok": False, "error": "No managed server available"}, status=400)
        prof_in = payload.get("premium") if isinstance(payload.get("premium"), dict) else {}
        bio_clean = sanitize_bio_text(prof_in.get("customBio", ""))
        ava_clean = sanitize_image_data_url(prof_in.get("customAvatar", ""))
        ban_clean = sanitize_image_data_url(prof_in.get("customBanner", ""))
        perks_in = prof_in.get("perks") if isinstance(prof_in.get("perks"), dict) else {}
        perks_mapped = {
            "ultra_fortress_mode": bool(perks_in.get("ultraFortressMode", False)),
            "instant_rollback_enabled": bool(perks_in.get("instantRollbackEnabled", True)),
            "priority_shield_response": bool(perks_in.get("priorityShieldResponse", True)),
            "alert_channel_id": str(perks_in.get("alertChannelId", "") or "").strip(),
            "alert_webhook_url": str(perks_in.get("alertWebhookUrl", "") or "").strip(),
        }
        save_guild_cfg(
            gid,
            {
                "guild_profile": {
                    "bio": bio_clean,
                    "avatar_data_url": ava_clean,
                    "banner_data_url": ban_clean,
                },
                "premium_perks": perks_mapped,
            },
            is_premium=True,
        )
        enqueue_remote_action(
            gid,
            "update_bot_profile",
            gid,
            extra={
                "guild_id": gid,
                "user_id": actor_uid,
                "actor_id": actor_uid,
                "bio": bio_clean,
                "bio_changed": True,
                "avatar_changed": bool(ava_clean),
                "banner_changed": bool(ban_clean),
                "avatar_data_url": ava_clean,
                "banner_data_url": ban_clean,
                "premium_perks": perks_mapped,
            },
            actor_user_id=actor_uid,
        )
        enqueue_remote_action(gid, "sync_guild_cfg", gid, extra={"guild_id": gid, "user_id": actor_uid}, actor_user_id=actor_uid)
        log_event(f"Updated premium profile & perks for {gid}", guild_id=gid, level="ADMIN")
        return web.json_response({"ok": True})

    if kind == "backup":
        if not is_site_admin(user) or not has_admin_perm(user, "backups"):
            return web.json_response({"ok": False, "error": "Backup permission required"}, status=403)
        snap = create_db_backup()
        return web.json_response({"ok": True, "backup_id": snap.get("backup_id")})

    if kind == "broadcast":
        if not is_site_admin(user) or not has_admin_perm(user, "remote_actions"):
            return web.json_response({"ok": False, "error": "Admin permission required"}, status=403)
        if not gid:
            return web.json_response({"ok": False, "error": "No managed server available"}, status=400)
        msg = str(payload.get("text", "")).strip()[:400]
        if msg:
            enqueue_remote_action(gid, "broadcast", msg, extra={"user_id": actor_uid}, actor_user_id=actor_uid)
            log_event(f"Broadcast queued: {msg}", guild_id=gid, level="ADMIN")
        return web.json_response({"ok": True})

    if kind == "mod_action":
        if not is_site_admin(user) or not has_admin_perm(user, "remote_actions"):
            return web.json_response({"ok": False, "error": "Admin permission required"}, status=403)
        if not gid:
            return web.json_response({"ok": False, "error": "No managed server available"}, status=400)
        act = str(payload.get("action", "timeout")).strip()
        target = str(payload.get("target", "")).strip()
        if act in ("kick", "ban", "unban", "timeout") and target.isdigit():
            enqueue_remote_action(gid, act, target, extra={"user_id": actor_uid}, actor_user_id=actor_uid)
            log_event(f"Remote [{act}] on {target} in {gid}", guild_id=gid, level="ADMIN")
        return web.json_response({"ok": True})

    if kind == "set_premium_user":
        if not is_site_admin(user) or not has_admin_perm(user, "manage_premium"):
            return web.json_response({"ok": False, "error": "Premium management permission required"}, status=403)
        target_uid = str(payload.get("target_user_id", "")).strip()
        enabled = bool(payload.get("enabled", True))
        days = max(0, min(3650, int(payload.get("days", 30) or 0)))
        hours = max(0, min(720, int(payload.get("hours", 0) or 0)))
        if not target_uid.isdigit():
            return web.json_response({"ok": False, "error": "Invalid User ID"}, status=400)
        ok = set_premium_user(target_uid, enabled, days=days, hours=hours, granted_by=actor_uid, source="manual")
        if not ok:
            return web.json_response({"ok": False, "error": "Cannot revoke owner premium"}, status=400)
        log_event(f"{'Granted' if enabled else 'Revoked'} premium for {target_uid}", level="ADMIN")
        return web.json_response({"ok": True})

    if kind == "set_admin_user":
        if not is_site_admin(user) or not has_admin_perm(user, "manage_admins"):
            return web.json_response({"ok": False, "error": "Admin management permission required"}, status=403)
        target_uid = str(payload.get("target_user_id", "")).strip()
        enabled = bool(payload.get("enabled", True))
        role_tag = str(payload.get("role_tag", "Staff") or "Staff")
        perms_in = payload.get("permissions") if isinstance(payload.get("permissions"), dict) else None
        if not target_uid.isdigit():
            return web.json_response({"ok": False, "error": "Invalid User ID"}, status=400)
        ok = set_admin_user(target_uid, enabled, granted_by=actor_uid, permissions=perms_in, role_tag=role_tag)
        if not ok:
            return web.json_response({"ok": False, "error": "Cannot revoke owner admin"}, status=400)
        log_event(f"{'Added' if enabled else 'Removed'} admin {target_uid} ({role_tag})", level="ADMIN")
        return web.json_response({"ok": True})

    return web.json_response({"ok": False, "error": "Unsupported action"}, status=400)


async def handle_modern_ui(request: web.Request) -> web.Response:
    user = get_discord_session(request)
    is_auth_json = "true" if user else "false"
    uid = str(user.get("id", "")).strip() if user else ""
    ava = str(user.get("avatar", "")).strip() if user else ""
    site_name_json = json.dumps(SITE_NAME)
    uname_json = json.dumps(str(user.get("username", "مستخدم")) if user else "زائر غير مسجل")
    avatar_url = (
        f"https://cdn.discordapp.com/avatars/{uid}/{ava}.png?size=128"
        if uid and ava
        else "https://placehold.co/160x160/7c5cff/ffffff?text=AS"
    )
    avatar_json = json.dumps(avatar_url)
    invite_href_json = json.dumps(sanitize_http_url(BOT_INVITE_URL) or "/invite")
    support_href_json = json.dumps(sanitize_http_url(SUPPORT_SERVER_URL) or "https://discord.gg/vV84RqJNks")

    html_page = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{site_name_json[1:-1]} — منظومة الحماية والإدارة المتقدمة</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link
    href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;500;600;700;800;900&family=IBM+Plex+Sans+Arabic:wght@400;500;600;700&display=swap"
    rel="stylesheet"
  />
  <script>
    tailwind.config = {{
      theme: {{
        extend: {{
          fontFamily: {{
            sans: ['"Cairo"', '"IBM Plex Sans Arabic"', 'sans-serif'],
            body: ['"IBM Plex Sans Arabic"', '"Cairo"', 'sans-serif'],
          }},
          colors: {{
            obsidian: '#07080f',
            midnight: '#0c0e1a',
            panel: '#111426',
            card: '#15192e',
            violetcore: '#7c5cff',
            violetglow: '#9a82ff',
            emeraldsafe: '#10b981',
            coralalert: '#ff6b6b',
            amberwarn: '#f59e0b',
          }},
          boxShadow: {{
            glass: '0 24px 60px -15px rgba(3, 4, 10, 0.85), inset 0 1px 0 0 rgba(255,255,255,0.06)',
            violet: '0 12px 35px -6px rgba(124, 92, 255, 0.45)',
            emeraldglow: '0 10px 28px -6px rgba(16, 185, 129, 0.35)',
          }},
        }},
      }},
    }};
  </script>
  <style>
    :root {{
      --bg-base: #07080f;
      --bg-elevated: #0e1120;
      --accent-primary: #7c5cff;
      --accent-secondary: #10b981;
      --accent-warn: #f59e0b;
      --accent-danger: #ff6b6b;
    }}
    * {{ box-sizing: border-box; }}
    html, body {{
      margin: 0;
      padding: 0;
      background-color: var(--bg-base);
      color: #f3f4f8;
      font-family: "Cairo", "IBM Plex Sans Arabic", sans-serif;
      overflow-x: clip;
      scroll-behavior: smooth;
    }}
    .ambient-grid {{
      background-image:
        radial-gradient(circle at 18% 12%, rgba(124, 92, 255, 0.16), transparent 42%),
        radial-gradient(circle at 82% 18%, rgba(58, 134, 255, 0.12), transparent 40%),
        radial-gradient(circle at 50% 88%, rgba(16, 185, 129, 0.08), transparent 45%),
        linear-gradient(to right, rgba(255, 255, 255, 0.025) 1px, transparent 1px),
        linear-gradient(to bottom, rgba(255, 255, 255, 0.025) 1px, transparent 1px);
      background-size: 100% 100%, 100% 100%, 100% 100%, 44px 44px, 44px 44px;
    }}
    @keyframes floatSlow {{
      0%, 100% {{ transform: translateY(0px); }}
      50% {{ transform: translateY(-6px); }}
    }}
    @keyframes pulseOrb {{
      0%, 100% {{ transform: scale(1); box-shadow: 0 0 0 0 rgba(124, 92, 255, 0.45); }}
      50% {{ transform: scale(1.04); box-shadow: 0 0 28px 6px rgba(124, 92, 255, 0.25); }}
    }}
    @keyframes fadeSlideUp {{
      from {{ opacity: 0; transform: translateY(14px) scale(0.985); }}
      to {{ opacity: 1; transform: translateY(0) scale(1); }}
    }}
    @keyframes drawerSlideIn {{
      from {{ opacity: 0; transform: translateX(36px); }}
      to {{ opacity: 1; transform: translateX(0); }}
    }}
    @keyframes scanLine {{
      0% {{ transform: translateY(-100%); opacity: 0; }}
      25% {{ opacity: 0.65; }}
      75% {{ opacity: 0.65; }}
      100% {{ transform: translateY(260%); opacity: 0; }}
    }}
    .animate-float-slow {{ animation: floatSlow 4.5s ease-in-out infinite; }}
    .animate-pulse-orb {{ animation: pulseOrb 3s ease-in-out infinite; }}
    .animate-panel-enter {{ animation: fadeSlideUp 0.38s cubic-bezier(0.22, 1, 0.36, 1) both; }}
    .animate-drawer-in {{ animation: drawerSlideIn 0.3s cubic-bezier(0.22, 1, 0.36, 1) both; }}
    .radar-scan {{ animation: scanLine 4.2s linear infinite; }}
    .security-tag {{
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
      padding: 0.38rem 0.85rem;
      border-radius: 9999px;
      font-size: 0.78rem;
      font-weight: 700;
      letter-spacing: 0.01em;
      border: 1px solid rgba(255, 255, 255, 0.09);
      background: linear-gradient(135deg, rgba(255, 255, 255, 0.05), rgba(255, 255, 255, 0.015));
      backdrop-filter: blur(10px);
      transition: transform 0.22s cubic-bezier(0.22, 1, 0.36, 1), border-color 0.22s ease, box-shadow 0.22s ease;
    }}
    .security-tag:hover {{
      transform: translateY(-2px) scale(1.02);
      border-color: rgba(154, 130, 255, 0.45);
      box-shadow: 0 8px 20px -6px rgba(124, 92, 255, 0.35);
    }}
    .toggle-track {{
      position: relative;
      width: 48px;
      height: 26px;
      border-radius: 9999px;
      transition: background-color 0.24s ease, box-shadow 0.24s ease;
      flex-shrink: 0;
    }}
    .toggle-thumb {{
      position: absolute;
      top: 3px;
      right: 3px;
      width: 20px;
      height: 20px;
      border-radius: 9999px;
      background: #ffffff;
      box-shadow: 0 2px 6px rgba(0, 0, 0, 0.45);
      transition: transform 0.24s cubic-bezier(0.22, 1, 0.36, 1);
    }}
    input.sr-toggle:checked + .toggle-track .toggle-thumb {{
      transform: translateX(-22px);
    }}
  </style>
</head>
<body class="ambient-grid min-h-screen text-slate-100 antialiased selection:bg-violetcore/30 selection:text-white">
  <div id="app" class="min-h-screen flex flex-col">
    <header class="sticky top-0 z-40 border-b border-white/[0.07] bg-[#090b16]/80 backdrop-blur-xl">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-3">
        <div class="flex items-center gap-3 min-w-0">
          <button
            id="open-drawer-btn"
            type="button"
            aria-label="فتح القائمة"
            onclick="openDrawer()"
            class="group relative p-2.5 rounded-xl bg-white/[0.04] hover:bg-violetcore/20 border border-white/[0.08] hover:border-violetcore/50 transition-all duration-200 active:scale-95"
          >
            <svg class="w-5 h-5 text-slate-200 group-hover:text-violetglow transition-colors" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M4 6h16M4 12h16M4 18h11" />
            </svg>
          </button>

          <button
            type="button"
            onclick="navigateTo('home')"
            class="flex items-center gap-2.5 text-right group focus:outline-none min-w-0"
          >
            <div class="relative w-10 h-10 rounded-2xl bg-gradient-to-br from-violetcore via-indigo-500 to-emeraldsafe p-[1.5px] shadow-violet group-hover:scale-105 transition-transform duration-200 shrink-0">
              <div class="w-full h-full rounded-[14px] bg-[#0c0f1f] flex items-center justify-center">
                <svg class="w-5 h-5 text-violetglow" fill="none" stroke="currentColor" stroke-width="2.2" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M12 3l7 3v6c0 4.85-3.02 9.16-7 10.75C8.02 21.16 5 16.85 5 12V6l7-3z" />
                  <path stroke-linecap="round" stroke-linejoin="round" d="M9.5 12.2l1.7 1.7 3.3-3.5" />
                </svg>
              </div>
            </div>
            <div class="truncate">
              <div class="flex items-center gap-2">
                <span class="font-extrabold text-base sm:text-lg tracking-tight text-white">{site_name_json[1:-1]}</span>
                <span class="hidden sm:inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-bold bg-emeraldsafe/15 text-emeraldsafe border border-emeraldsafe/30">
                  <span class="w-1.5 h-1.5 rounded-full bg-emeraldsafe animate-pulse"></span>
                  نشط
                </span>
              </div>
              <p class="text-[11px] text-slate-400 truncate">منظومة الحماية والأمن الرقمي للسيرفرات</p>
            </div>
          </button>
        </div>

        <nav id="desktop-nav" class="hidden lg:flex items-center gap-1.5 bg-white/[0.03] p-1 rounded-2xl border border-white/[0.06]">
          <button type="button" data-nav="home" onclick="navigateTo('home')" class="nav-pill px-3.5 py-1.5 rounded-xl text-xs font-bold transition-all">الرئيسية</button>
          <button type="button" data-nav="protection" onclick="navigateTo('protection')" class="nav-pill px-3.5 py-1.5 rounded-xl text-xs font-bold transition-all">لوحة الحماية</button>
          <button type="button" data-nav="premium" onclick="navigateTo('premium')" class="nav-pill px-3.5 py-1.5 rounded-xl text-xs font-bold transition-all">البريميوم</button>
          <button type="button" data-nav="admin" onclick="navigateTo('admin')" class="nav-pill px-3.5 py-1.5 rounded-xl text-xs font-bold transition-all">لوحة الإدارة</button>
        </nav>

        <div class="flex items-center gap-2">
          <div id="header-user-chip" class="hidden sm:flex items-center gap-2 pl-2 pr-1.5 py-1 rounded-full bg-white/[0.04] border border-white/[0.08]">
            <img
              id="header-user-avatar"
              src="https://placehold.co/64x64/7c5cff/ffffff?text=AS"
              onerror="this.src='https://placehold.co/64x64/7c5cff/ffffff?text=AS'"
              alt="صورة المستخدم"
              class="w-7 h-7 rounded-full object-cover ring-1 ring-violetcore/50"
            />
            <span id="header-user-name" class="text-xs font-bold text-slate-200 max-w-[110px] truncate">مستخدم</span>
          </div>
          <a href="/login?next=/" class="px-3 py-1.5 rounded-xl text-xs font-extrabold bg-violetcore/20 hover:bg-violetcore/30 border border-violetcore/40 text-violetglow transition-all">
            دخول ديسكورد
          </a>
        </div>
      </div>
    </header>

    <div id="toast-container" class="fixed bottom-5 left-5 right-5 sm:left-auto sm:right-6 z-50 flex flex-col gap-2 max-w-sm pointer-events-none"></div>

    <div id="drawer-backdrop" class="fixed inset-0 z-50 hidden bg-black/70 backdrop-blur-sm transition-opacity" onclick="closeDrawer()">
      <aside
        id="nav-drawer"
        onclick="event.stopPropagation()"
        class="animate-drawer-in fixed top-0 right-0 bottom-0 w-[84vw] max-w-xs bg-[#0d1020] border-l border-white/[0.09] shadow-2xl flex flex-col justify-between p-5"
      >
        <div>
          <div class="flex items-center justify-between pb-4 border-b border-white/[0.07]">
            <span class="text-sm font-extrabold text-white tracking-tight">القائمة الرئيسية</span>
            <button
              type="button"
              onclick="closeDrawer()"
              aria-label="إغلاق القائمة"
              class="p-2 rounded-xl bg-white/[0.04] hover:bg-coralalert/20 text-slate-300 hover:text-coralalert border border-white/[0.07] transition-colors"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2.2" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          <div id="drawer-profile-box" class="mt-4 p-4 rounded-2xl bg-gradient-to-br from-violetcore/15 via-panel to-midnight border border-violetcore/25 flex items-center gap-3.5">
            <img
              id="drawer-avatar"
              src="https://placehold.co/96x96/7c5cff/ffffff?text=AS"
              onerror="this.src='https://placehold.co/96x96/7c5cff/ffffff?text=AS'"
              alt="صورة الحساب"
              class="w-14 h-14 rounded-2xl object-cover ring-2 ring-violetglow/60 shadow-violet shrink-0"
            />
            <div class="min-w-0">
              <p class="text-[11px] font-semibold text-violetglow mb-0.5">الحساب المتصل</p>
              <h3 id="drawer-username" class="text-base font-extrabold text-white truncate">مستخدم</h3>
            </div>
          </div>

          <div class="mt-5 space-y-1.5">
            <button type="button" data-drawer-nav="home" onclick="navigateTo('home'); closeDrawer();" class="drawer-item w-full flex items-center gap-3 px-3.5 py-3 rounded-xl text-sm font-bold transition-all">
              <span>الرئيسية</span>
            </button>
            <button type="button" data-drawer-nav="protection" onclick="navigateTo('protection'); closeDrawer();" class="drawer-item w-full flex items-center gap-3 px-3.5 py-3 rounded-xl text-sm font-bold transition-all">
              <span>لوحة الحماية</span>
            </button>
            <button type="button" data-drawer-nav="premium" onclick="navigateTo('premium'); closeDrawer();" class="drawer-item w-full flex items-center gap-3 px-3.5 py-3 rounded-xl text-sm font-bold transition-all">
              <span>البريميوم</span>
            </button>
            <button type="button" data-drawer-nav="admin" onclick="navigateTo('admin'); closeDrawer();" class="drawer-item w-full flex items-center gap-3 px-3.5 py-3 rounded-xl text-sm font-bold transition-all">
              <span>لوحة الإدارة</span>
            </button>
          </div>
        </div>

        <div class="pt-4 border-t border-white/[0.07] space-y-2">
          <a href="/login?next=/" class="block w-full text-center py-2.5 px-4 rounded-xl text-xs font-extrabold bg-gradient-to-r from-violetcore to-indigo-500 text-white shadow-violet">
            تسجيل الدخول بديسكورد
          </a>
          <a href="/logout" class="block w-full text-center py-2 px-4 rounded-xl text-xs font-bold bg-white/[0.04] text-slate-300 hover:text-white">
            تسجيل الخروج
          </a>
        </div>
      </aside>
    </div>

    <main id="main-content" class="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-7 sm:py-10"></main>

    <footer class="border-t border-white/[0.06] bg-[#080a14]/75 backdrop-blur-md mt-auto">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-5 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-400">
        <div class="flex items-center gap-2">
          <span class="font-extrabold text-slate-200">{site_name_json[1:-1]}</span>
          <span>•</span>
          <span>جميع الحقوق محفوظة © 2026</span>
        </div>
        <div class="flex items-center gap-4">
          <span id="footer-bot-status" class="inline-flex items-center gap-1.5 text-emeraldsafe font-semibold">
            <span class="w-2 h-2 rounded-full bg-emeraldsafe"></span>
            الرادار الأمني متصل
          </span>
        </div>
      </div>
    </footer>
  </div>

  <script>
    const SITE_BRAND_NAME = {site_name_json};
    const INVITE_URL = {invite_href_json};
    const SUPPORT_URL = {support_href_json};
    let state = {{
      isAuthenticated: {is_auth_json},
      isPremium: false,
      isAdmin: false,
      adminPerms: {{}},
      activePage: "home",
      user: {{
        id: "",
        username: {uname_json},
        avatar: {avatar_json},
      }},
      selectedGuildId: "",
      botHeartbeat: {{ status: "ONLINE", last_seen: "" }},
      guilds: [],
      protection: {{
        anti_spam: true,
        spamPunishment: "Timeout",
        spamTimeoutSeconds: 600,
        anti_link: true,
        linkPunishment: "Delete & Timeout",
        linkTimeoutSeconds: 300,
        anti_invites: true,
        anti_raid: true,
        anti_new_accounts: true,
        minAccountAgeDays: 7,
        anti_role_delete: true,
        anti_role_edit: true,
        anti_channel_perms_tamper: true,
        anti_mass_unban: true,
        anti_mass_kick: true,
        anti_mass_timeout: true,
        anti_mention_spam: true,
        anti_selfbot: true,
        selfbotPunishment: "Ban",
        anti_webhook_abuse: true,
        anti_app_abuse: true,
        appAbusePunishment: "Ban",
        dangerous_perms_guard: true,
        dangerousPermsPunishment: "Remove Roles",
        anti_guild_icon_change: true,
        guildIconPunishment: "Ban",
        lockdown: false,
        voice_lock: false,
        silent_mode: false,
        beast_mode: false,
        maintenance: false,
        verification: false,
        alert_on_trigger: true,
        emergency_mode: false,
        auto_quarantine: true,
        auto_rollback_enabled: true,
        antinuke: {{}},
      }},
      premium: {{
        active: false,
        planName: "بريميوم السيرفرات الماسي",
        daysLeft: 0,
        remainingLabel: "غير مفعل",
        customBio: "درع الحماية المتكامل لصد هجمات النيوك والسبام وحفظ السيرفر تلقائياً.",
        customAvatar: "https://placehold.co/180x180/7c5cff/ffffff?text=VIP",
        customBanner: "https://placehold.co/900x260/16132e/9a82ff?text=ARAB+SECURITY+SHIELD",
        perks: {{
          ultraFortressMode: false,
          instantRollbackEnabled: true,
          priorityShieldResponse: true,
          alertChannelId: "",
          alertWebhookUrl: "",
        }},
        lastBackupTime: "منذ دقائق",
      }},
      admin: {{
        broadcastText: "",
        targetUserId: "",
        logFilter: "ALL",
        logs: [],
        incidents: [],
        backups: [],
        admins: [],
        premiumUsers: [],
      }},
    }};

    function escapeHtml(str) {{
      return String(str || "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
    }}

    function showToast(message, tone = "info") {{
      const container = document.getElementById("toast-container");
      if (!container) return;
      const palette = {{
        success: "border-emeraldsafe/40 bg-[#0d1f1b]/95 text-emerald-200",
        warn: "border-amberwarn/40 bg-[#231b0c]/95 text-amber-200",
        danger: "border-coralalert/40 bg-[#271117]/95 text-rose-200",
        info: "border-violetcore/45 bg-[#15132b]/95 text-indigo-100",
      }};
      const toast = document.createElement("div");
      toast.className = "animate-panel-enter pointer-events-auto flex items-center gap-3 px-4 py-3 rounded-2xl border shadow-2xl backdrop-blur-xl text-xs sm:text-sm font-bold " + (palette[tone] || palette.info);
      toast.textContent = message;
      container.appendChild(toast);
      setTimeout(() => {{
        toast.style.opacity = "0";
        setTimeout(() => toast.remove(), 250);
      }}, 3000);
    }}

    async function hydrateLiveState(overrideGuildId = "") {{
      try {{
        const gidParam = overrideGuildId || state.selectedGuildId || "";
        const url = gidParam ? `/api/ui-state?guild_id=${{encodeURIComponent(gidParam)}}` : "/api/ui-state";
        const res = await fetch(url, {{ cache: "no-store" }});
        if (!res.ok) return;
        const data = await res.json();
        if (!data || !data.ok) return;
        state.isAuthenticated = Boolean(data.isAuthenticated);
        state.isPremium = Boolean(data.isPremium);
        state.isAdmin = Boolean(data.isAdmin);
        state.adminPerms = data.adminPerms || {{}};
        if (data.user) state.user = {{ ...state.user, ...data.user }};
        state.selectedGuildId = data.selectedGuildId || "";
        if (data.botHeartbeat) state.botHeartbeat = data.botHeartbeat;
        state.guilds = Array.isArray(data.guilds) ? data.guilds : [];
        if (data.protection) {{
          state.protection = {{
            ...state.protection,
            ...data.protection,
            antinuke: data.protection.antinuke || {{}},
          }};
        }}
        if (data.premium) {{
          state.premium = {{
            ...state.premium,
            ...data.premium,
            perks: {{ ...state.premium.perks, ...(data.premium.perks || {{}}) }},
          }};
        }}
        if (Array.isArray(data.logs)) state.admin.logs = data.logs;
        if (Array.isArray(data.incidents)) state.admin.incidents = data.incidents;
        if (Array.isArray(data.backups)) state.admin.backups = data.backups;
        if (Array.isArray(data.admins)) state.admin.admins = data.admins;
        if (Array.isArray(data.premiumUsers)) state.admin.premiumUsers = data.premiumUsers;
        render();
      }} catch (e) {{}}
    }}

    async function postUiAction(payload) {{
      const res = await fetch("/api/ui-action", {{
        method: "POST",
        headers: {{ "Content-Type": "application/json" }},
        body: JSON.stringify({{ ...payload, guild_id: state.selectedGuildId }}),
      }});
      return res.json();
    }}

    async function selectGuild(gid) {{
      if (!gid) return;
      state.selectedGuildId = gid;
      await hydrateLiveState(gid);
      showToast("تم تبديل السيرفر المحدد", "info");
    }}

    function navigateTo(pageKey) {{
      const valid = ["home", "protection", "premium", "admin"];
      state.activePage = valid.includes(pageKey) ? pageKey : "home";
      syncHeaderAndDrawer();
      render();
      window.scrollTo({{ top: 0, behavior: "smooth" }});
    }}

    function openDrawer() {{
      syncHeaderAndDrawer();
      document.getElementById("drawer-backdrop")?.classList.remove("hidden");
    }}

    function closeDrawer() {{
      document.getElementById("drawer-backdrop")?.classList.add("hidden");
    }}

    function syncHeaderAndDrawer() {{
      const chip = document.getElementById("header-user-chip");
      const hAvatar = document.getElementById("header-user-avatar");
      const hName = document.getElementById("header-user-name");
      const dAvatar = document.getElementById("drawer-avatar");
      const dUsername = document.getElementById("drawer-username");
      const fStatus = document.getElementById("footer-bot-status");

      if (fStatus) {{
        const online = (state.botHeartbeat?.status || "ONLINE") === "ONLINE";
        fStatus.className = online
          ? "inline-flex items-center gap-1.5 text-emeraldsafe font-semibold"
          : "inline-flex items-center gap-1.5 text-amberwarn font-semibold";
        fStatus.innerHTML = `<span class="w-2 h-2 rounded-full ${{online ? "bg-emeraldsafe" : "bg-amberwarn"}}"></span>${{online ? "الرادار الأمني متصل" : "بانتظار نبض البوت"}}`;
      }}

      if (chip) {{
        if (state.isAuthenticated) {{
          chip.classList.remove("hidden");
          chip.classList.add("sm:flex");
          if (hAvatar) hAvatar.src = state.user.avatar;
          if (hName) hName.textContent = state.user.username;
        }} else {{
          chip.classList.add("hidden");
          chip.classList.remove("sm:flex");
        }}
      }}
      if (dAvatar && dUsername) {{
        dAvatar.src = state.isAuthenticated ? state.user.avatar : "https://placehold.co/120x120/1a1e36/9a82ff?text=GUEST";
        dUsername.textContent = state.isAuthenticated ? state.user.username : "زائر غير مسجل";
      }}
      document.querySelectorAll(".nav-pill").forEach((btn) => {{
        const active = btn.getAttribute("data-nav") === state.activePage;
        btn.className = active
          ? "nav-pill px-3.5 py-1.5 rounded-xl text-xs font-extrabold bg-violetcore text-white shadow-sm transition-all"
          : "nav-pill px-3.5 py-1.5 rounded-xl text-xs font-bold text-slate-400 hover:text-white hover:bg-white/[0.04] transition-all";
      }});
      document.querySelectorAll(".drawer-item").forEach((btn) => {{
        const active = btn.getAttribute("data-drawer-nav") === state.activePage;
        btn.className = active
          ? "drawer-item w-full flex items-center gap-3 px-3.5 py-3 rounded-xl text-sm font-extrabold bg-violetcore/20 text-white border border-violetcore/40 shadow-sm transition-all"
          : "drawer-item w-full flex items-center gap-3 px-3.5 py-3 rounded-xl text-sm font-bold text-slate-300 hover:text-white hover:bg-white/[0.04] border border-transparent transition-all";
      }});
    }}

    function getActiveGuild() {{
      return state.guilds.find((g) => g.id === state.selectedGuildId) || state.guilds[0] || {{
        id: "0",
        name: "سيرفر افتراضي",
        members: 0,
        protectionScore: 90,
        premium: false,
        status: "نشط",
        iconText: "AS",
      }};
    }}

    function renderGuildSelectorBar() {{
      if (!state.guilds.length) return "";
      return `
        <div class="flex flex-wrap items-center justify-between gap-3 p-3.5 rounded-2xl bg-[#0c0f1f]/90 border border-white/[0.07]">
          <span class="text-xs font-extrabold text-slate-300">تبديل السيرفر النشط:</span>
          <select onchange="selectGuild(this.value)" class="rounded-xl bg-[#15192e] border border-white/[0.12] px-3 py-2 text-xs font-bold text-white">
            ${{state.guilds.map((g) => `
              <option value="${{escapeHtml(g.id)}}" ${{g.id === state.selectedGuildId ? "selected" : ""}}>
                ${{escapeHtml(g.name)}} (${{escapeHtml(String(g.protectionScore || 90))}}%)
              </option>
            `).join("")}}
          </select>
        </div>
      `;
    }}

    function renderLoginGate() {{
      return `
        <section class="animate-panel-enter min-h-[72vh] flex items-center justify-center px-2 py-8">
          <div class="relative w-full max-w-md rounded-[28px] bg-gradient-to-b from-[#161932]/95 via-[#111426]/95 to-[#0c0e1c]/95 border border-white/[0.09] shadow-glass p-7 sm:p-9 text-center overflow-hidden">
            <div class="pointer-events-none absolute -top-24 left-1/2 -translate-x-1/2 w-64 h-44 rounded-full bg-violetcore/25 blur-3xl"></div>
            <div class="relative mx-auto mb-6 w-20 h-20 rounded-full bg-gradient-to-b from-[#8b6eff] via-violetcore to-[#5638d6] p-[2px] shadow-violet animate-pulse-orb flex items-center justify-center">
              <div class="w-full h-full rounded-full bg-gradient-to-b from-[#7a5cf6] to-[#5a3cd8] flex items-center justify-center">
                <svg class="w-8 h-8 text-white drop-shadow" fill="none" stroke="currentColor" stroke-width="2.3" viewBox="0 0 24 24">
                  <rect x="5" y="11" width="14" height="10" rx="2.5" />
                  <path stroke-linecap="round" stroke-linejoin="round" d="M8 11V7a4 4 0 018 0v4" />
                </svg>
              </div>
            </div>
            <h1 class="relative text-2xl sm:text-[26px] font-black text-white tracking-tight mb-3">تسجيل الدخول مطلوب</h1>
            <p class="relative text-sm sm:text-[15px] text-slate-300/90 leading-relaxed max-w-xs mx-auto mb-7">
              لوحات الحماية وإدارة السيرفرات مقفلة. سجل دخولك بديسكورد أولاً للوصول إلى نظام <span class="text-violetglow font-extrabold">${{escapeHtml(SITE_BRAND_NAME)}}</span>.
            </p>
            <a
              href="/login?next=/"
              class="relative w-full py-3.5 px-6 rounded-2xl bg-gradient-to-r from-[#d8d4ff] via-[#e9e6ff] to-[#c9c2ff] text-[#17142e] font-extrabold text-sm sm:text-base shadow-[0_10px_28px_-4px_rgba(154,130,255,0.5)] flex items-center justify-center gap-2.5"
            >
              <span>تسجيل الدخول بديسكورد</span>
            </a>
          </div>
        </section>
      `;
    }}

    function renderTagsShowcase() {{
      const tags = [
        {{ label: "Anti-Nuke Pro", dot: "bg-emeraldsafe", badge: "لحظي" }},
        {{ label: "Real-Time Shield", dot: "bg-violetglow", badge: "24/7" }},
        {{ label: "Zero-Trust Guard", dot: "bg-sky-400", badge: "صارم" }},
        {{ label: "Auto-Recovery 12h", dot: "bg-amberwarn", badge: "نسخ" }},
        {{ label: "Boost VIP Perks", dot: "bg-pink-400", badge: "مميز" }},
      ];
      return `
        <div class="flex flex-wrap items-center gap-2.5">
          ${{tags.map((t) => `
            <span class="security-tag text-slate-100">
              <span class="w-2 h-2 rounded-full ${{t.dot}}"></span>
              <span>${{escapeHtml(t.label)}}</span>
              <span class="px-1.5 py-0.5 rounded-full text-[10px] font-extrabold bg-white/[0.06] text-slate-300">${{escapeHtml(t.badge)}}</span>
            </span>
          `).join("")}}
        </div>
      `;
    }}

    function renderQuickLinksSection() {{
      return `
        <section class="mt-8">
          <div class="mb-4">
            <h2 class="text-lg sm:text-xl font-extrabold text-white">الروابط السريعة</h2>
            <p class="text-xs text-slate-400 mt-0.5">إضافة البوت إلى سيرفرك أو التواصل المباشر مع فريق الدعم الفني</p>
          </div>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <a href="${{escapeHtml(INVITE_URL)}}" target="_blank" rel="noopener noreferrer" class="group relative rounded-2xl bg-gradient-to-br from-violetcore/15 via-panel to-card border border-violetcore/30 hover:border-violetglow/70 p-5 flex items-center justify-between gap-4 shadow-glass transition-all">
              <div class="min-w-0">
                <div class="flex items-center gap-2 flex-wrap">
                  <span class="font-extrabold text-base text-white group-hover:text-violetglow transition-colors">Invite ${{escapeHtml(SITE_BRAND_NAME)}} Bot</span>
                  <span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-violetcore/25 text-violetglow border border-violetcore/40">دعوة رسمية</span>
                </div>
                <p class="text-xs text-slate-400 mt-1 truncate">أضف بوت أراب سيكيوريتي بصلاحيات الحماية المتكاملة إلى سيرفرك</p>
              </div>
            </a>
            <a href="${{escapeHtml(SUPPORT_URL)}}" target="_blank" rel="noopener noreferrer" class="group relative rounded-2xl bg-gradient-to-br from-emeraldsafe/15 via-panel to-card border border-emeraldsafe/30 hover:border-emeraldsafe/70 p-5 flex items-center justify-between gap-4 shadow-glass transition-all">
              <div class="min-w-0">
                <div class="flex items-center gap-2 flex-wrap">
                  <span class="font-extrabold text-base text-white group-hover:text-emeraldsafe transition-colors">سيرفر الدعم الفني</span>
                  <span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emeraldsafe/20 text-emeraldsafe border border-emeraldsafe/35">مساعدة فورية</span>
                </div>
                <p class="text-xs text-slate-400 mt-1 truncate">انضم إلى سيرفر الدعم الفني للحصول على المساعدة وتقارير التحديثات</p>
              </div>
            </a>
          </div>
        </section>
      `;
    }}

    function renderHomePage() {{
      const guild = getActiveGuild();
      const activeGuardsCount = Object.entries(state.protection).filter(([k, v]) => typeof v === "boolean" && v).length;
      return `
        <div class="animate-panel-enter space-y-8">
          <section class="relative rounded-[28px] bg-gradient-to-br from-[#161a34] via-[#111529] to-[#0c0f1e] border border-white/[0.09] p-6 sm:p-9 shadow-glass overflow-hidden">
            <div class="relative flex flex-col lg:flex-row lg:items-center justify-between gap-7">
              <div class="space-y-4 max-w-2xl">
                <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-violetcore/15 border border-violetcore/35 text-xs font-extrabold text-violetglow">
                  <span>الجيل الجديد من منظومة ${{escapeHtml(SITE_BRAND_NAME)}}</span>
                </div>
                <h1 class="text-2xl sm:text-4xl font-black text-white leading-tight">
                  حماية فورية وذكية لسيرفراتك ضد
                  <span class="bg-gradient-to-l from-violetglow via-violetcore to-emeraldsafe bg-clip-text text-transparent">التخريب والسبام والرايد</span>
                </h1>
                <p class="text-sm sm:text-base text-slate-300 leading-relaxed">
                  تحكم كامل في أنظمة الحماية، النسخ الاحتياطية والاسترجاع التلقائي، مزايا البريميوم، ومركز قيادة الإدارة المرتبط مباشرة بقاعدة البيانات.
                </p>
                <div class="pt-1">${{renderTagsShowcase()}}</div>
                <div class="pt-2 flex flex-wrap items-center gap-3">
                  <button type="button" onclick="navigateTo('protection')" class="px-5 py-3 rounded-2xl bg-gradient-to-r from-violetcore to-indigo-500 text-white font-extrabold text-sm shadow-violet">الدخول إلى لوحة الحماية</button>
                  <button type="button" onclick="navigateTo('premium')" class="px-5 py-3 rounded-2xl bg-white/[0.05] text-amberwarn border border-amberwarn/30 font-extrabold text-sm">استعراض مزايا البريميوم</button>
                  <button type="button" onclick="navigateTo('admin')" class="px-5 py-3 rounded-2xl bg-white/[0.05] text-slate-200 border border-white/[0.1] font-extrabold text-sm">لوحة الإدارة</button>
                </div>
              </div>

              <div class="relative w-full lg:w-80 rounded-2xl bg-[#0b0e1c]/90 border border-white/[0.08] p-5 overflow-hidden shrink-0 animate-float-slow">
                <div class="radar-scan pointer-events-none absolute inset-x-0 h-12 bg-gradient-to-b from-transparent via-violetcore/20 to-transparent"></div>
                <div class="flex items-center justify-between mb-4">
                  <span class="text-xs font-extrabold text-slate-300">حالة السيرفر النشط</span>
                  <span class="px-2.5 py-0.5 rounded-full text-[11px] font-extrabold bg-emeraldsafe/15 text-emeraldsafe border border-emeraldsafe/30">${{escapeHtml(guild.status)}}</span>
                </div>
                <div class="font-extrabold text-white text-sm truncate">${{escapeHtml(guild.name)}}</div>
                <div class="text-xs text-slate-400 mt-0.5">${{Number(guild.members || 0).toLocaleString("en-US")}} عضو</div>
                <div class="mt-4 space-y-2 text-xs">
                  <div class="flex justify-between text-slate-300">
                    <span>مؤشر الأمان</span>
                    <span class="font-extrabold text-emeraldsafe">${{escapeHtml(String(guild.protectionScore || 90))}}%</span>
                  </div>
                  <div class="h-2 rounded-full bg-white/[0.06] overflow-hidden">
                    <div class="h-full rounded-full bg-gradient-to-r from-violetcore to-emeraldsafe" style="width: ${{escapeHtml(String(guild.protectionScore || 90))}}%"></div>
                  </div>
                </div>
              </div>
            </div>
          </section>

          <section class="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <div class="rounded-2xl bg-card/90 border border-white/[0.07] p-4 sm:p-5">
              <p class="text-xs text-slate-400 font-semibold">الأنظمة الأمنية المفعلة</p>
              <p class="text-2xl font-black text-white mt-1.5">${{activeGuardsCount}} <span class="text-xs font-bold text-violetglow">نظام</span></p>
            </div>
            <div class="rounded-2xl bg-card/90 border border-white/[0.07] p-4 sm:p-5">
              <p class="text-xs text-slate-400 font-semibold">نسبة صد الهجمات</p>
              <p class="text-2xl font-black text-emeraldsafe mt-1.5">99.8%</p>
            </div>
            <div class="rounded-2xl bg-card/90 border border-white/[0.07] p-4 sm:p-5">
              <p class="text-xs text-slate-400 font-semibold">النسخ والاسترجاع</p>
              <p class="text-2xl font-black text-amberwarn mt-1.5">12h <span class="text-xs font-bold text-slate-300">+ دائم</span></p>
            </div>
            <div class="rounded-2xl bg-card/90 border border-white/[0.07] p-4 sm:p-5">
              <p class="text-xs text-slate-400 font-semibold">السيرفرات المدارة</p>
              <p class="text-2xl font-black text-sky-400 mt-1.5">${{state.guilds.length}}</p>
            </div>
          </section>

          ${{renderQuickLinksSection()}}
        </div>
      `;
    }}

    function renderToggleRow(key, title, desc) {{
      const checked = Boolean(state.protection[key]);
      return `
        <label class="flex items-center justify-between gap-4 p-3.5 rounded-2xl bg-[#0e1121]/85 hover:bg-[#13182e] border border-white/[0.07] transition-all cursor-pointer">
          <div class="min-w-0">
            <div class="flex items-center gap-2 flex-wrap">
              <span class="font-extrabold text-sm text-white">${{escapeHtml(title)}}</span>
              <span class="px-2 py-0.5 rounded-full text-[10px] font-bold ${{checked ? "bg-emeraldsafe/15 text-emeraldsafe border border-emeraldsafe/30" : "bg-white/[0.05] text-slate-400 border border-white/[0.08]"}}">
                ${{checked ? "نشط" : "متوقف"}}
              </span>
            </div>
            <p class="text-xs text-slate-400 mt-0.5 leading-relaxed">${{escapeHtml(desc)}}</p>
          </div>
          <div class="relative inline-flex items-center">
            <input type="checkbox" class="sr-only sr-toggle" ${{checked ? "checked" : ""}} onchange="toggleProtection('${{key}}', this.checked)" />
            <div class="toggle-track ${{checked ? "bg-gradient-to-r from-violetcore to-emeraldsafe shadow-violet" : "bg-slate-700/80"}}">
              <div class="toggle-thumb"></div>
            </div>
          </div>
        </label>
      `;
    }}

    function renderProtectionPage() {{
      const guild = getActiveGuild();
      const p = state.protection;
      const anRules = [
        ["anti_ban", "حظر الأعضاء"],
        ["anti_kick", "طرد الأعضاء"],
        ["anti_role_create", "إنشاء رتب"],
        ["anti_role_delete", "حذف رتب"],
        ["anti_role_edit", "تعديل رتب"],
        ["anti_channel_create", "إنشاء قنوات"],
        ["anti_channel_delete", "حذف قنوات"],
        ["anti_webhook_create", "إنشاء ويب هوك"],
        ["anti_bot_add", "إضافة بوتات"],
        ["anti_guild_update", "تعديل السيرفر"],
        ["anti_emoji_delete", "حذف إيموجيات"],
      ];
      return `
        <div class="animate-panel-enter space-y-6">
          <div class="rounded-[26px] bg-gradient-to-r from-[#161a33] via-[#12162b] to-[#0d1122] border border-white/[0.09] p-6 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-glass">
            <div>
              <h1 class="text-2xl font-black text-white">لوحة الحماية المتقدمة</h1>
              <p class="text-xs sm:text-sm text-slate-400 mt-1">السيرفر المحدد: <span class="text-white font-bold">${{escapeHtml(guild.name)}}</span> • مؤشر الأمان: <span class="text-emeraldsafe font-extrabold">${{escapeHtml(String(guild.protectionScore || 90))}}%</span></p>
            </div>
            <div class="flex flex-wrap items-center gap-2.5">
              <button type="button" onclick="enableAllGuards()" class="px-4 py-2.5 rounded-xl text-xs font-extrabold bg-emeraldsafe/15 text-emeraldsafe border border-emeraldsafe/35">تفعيل كافة الدروع</button>
              <button type="button" onclick="saveProtectionConfig()" class="px-5 py-2.5 rounded-xl text-xs font-extrabold bg-gradient-to-r from-violetcore to-indigo-500 text-white shadow-violet">حفظ ومزامنة الإعدادات</button>
            </div>
          </div>

          ${{renderGuildSelectorBar()}}

          <div class="rounded-3xl bg-card/85 border border-white/[0.08] p-5 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div>
              <label class="block text-xs font-extrabold text-slate-300 mb-1">عقوبة السبام</label>
              <select onchange="state.protection.spamPunishment = this.value" class="w-full rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-3 py-2 text-xs text-white">
                ${{["Delete Only", "Timeout", "Kick", "Ban"].map((opt) => `<option value="${{opt}}" ${{p.spamPunishment === opt ? "selected" : ""}}>${{opt}}</option>`).join("")}}
              </select>
            </div>
            <div>
              <label class="block text-xs font-extrabold text-slate-300 mb-1">مدة تايم أوت السبام (ثانية)</label>
              <input type="number" min="10" max="2419200" value="${{escapeHtml(String(p.spamTimeoutSeconds || 600))}}" onchange="state.protection.spamTimeoutSeconds = Number(this.value || 600)" class="w-full rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-3 py-2 text-xs text-white" />
            </div>
            <div>
              <label class="block text-xs font-extrabold text-slate-300 mb-1">عقوبة الروابط</label>
              <select onchange="state.protection.linkPunishment = this.value" class="w-full rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-3 py-2 text-xs text-white">
                ${{["Delete Only", "Delete & Timeout", "Kick", "Ban"].map((opt) => `<option value="${{opt}}" ${{p.linkPunishment === opt ? "selected" : ""}}>${{opt}}</option>`).join("")}}
              </select>
            </div>
            <div>
              <label class="block text-xs font-extrabold text-slate-300 mb-1">الحد الأدنى لعمر الحساب (أيام)</label>
              <input type="number" min="1" max="365" value="${{escapeHtml(String(p.minAccountAgeDays || 7))}}" onchange="state.protection.minAccountAgeDays = Number(this.value || 7)" class="w-full rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-3 py-2 text-xs text-white" />
            </div>
          </div>

          <div class="grid grid-cols-1 lg:grid-cols-2 gap-5">
            <div class="rounded-3xl bg-card/85 border border-white/[0.08] p-5 space-y-2.5">
              <h2 class="text-base font-black text-white mb-2">حماية الشات والرايد والحسابات والسيرفر</h2>
              ${{renderToggleRow("anti_spam", "منع السبام (Anti-Spam)", "رصد الرسائل المتكررة السريعة وتطبيق العقوبة تلقائياً.")}}
              ${{renderToggleRow("anti_link", "منع الروابط الخارجية (Anti-Link)", "حذف الروابط غير المصرح بها.")}}
              ${{renderToggleRow("anti_invites", "منع روابط الدعوات (Anti-Invites)", "منع نشر دعوات السيرفرات.")}}
              ${{renderToggleRow("anti_mention_spam", "منع سبام المنشن", "صد المنشن الجماعي المفرط.")}}
              ${{renderToggleRow("anti_raid", "مضاد هجمات الرايد (Anti-Raid)", "التصدي للدخول الجماعي المفاجئ.")}}
              ${{renderToggleRow("anti_new_accounts", "حماية الحسابات الحديثة", "فحص عمر الحسابات الجديدة.")}}
              ${{renderToggleRow("anti_bot_raid", "منع هجوم البوتات", "رصد الإضافة المفاجئة للبوتات.")}}
              ${{renderToggleRow("lockdown", "قفل السيرفر (Lockdown)", "تقييد إرسال الرسائل أثناء الطوارئ.")}}
              ${{renderToggleRow("voice_lock", "قفل القنوات الصوتية", "منع الدخول للرومات الصوتية.")}}
              ${{renderToggleRow("silent_mode", "الوضع الصامت", "تقليل التنبيهات العامة.")}}
              ${{renderToggleRow("beast_mode", "وضع الوحش (Beast Mode)", "تشديد الرقابة الأمنية القصوى.")}}
              ${{renderToggleRow("maintenance", "وضع الصيانة", "إشعار الصيانة للعمليات.")}}
              ${{renderToggleRow("verification", "نظام التحقق", "تفعيل التحقق للأعضاء.")}}
              ${{renderToggleRow("alert_on_trigger", "تنبيه عند التفعيل", "إرسال تنبيه فوري عند رصد مخالفة.")}}
            </div>
            <div class="rounded-3xl bg-card/85 border border-white/[0.08] p-5 space-y-2.5">
              <h2 class="text-base font-black text-white mb-2">منظومة Anti-Nuke والصلاحيات والاسترجاع</h2>
              ${{renderToggleRow("anti_role_delete", "حماية حذف الرتب", "منع الحذف العشوائي للرتب.")}}
              ${{renderToggleRow("anti_role_edit", "حماية تعديل الرتب", "رصد تعديل الرتب الحساسة.")}}
              ${{renderToggleRow("anti_channel_perms_tamper", "حماية صلاحيات القنوات", "صد تعديل صلاحيات الرومات.")}}
              ${{renderToggleRow("dangerous_perms_guard", "حارس الصلاحيات الخطيرة", "مراقبة الصلاحيات العالية.")}}
              ${{renderToggleRow("anti_privilege_escalation", "منع تصعيد الصلاحيات", "منع منح صلاحيات غير مصرح بها.")}}
              ${{renderToggleRow("anti_vanity_tamper", "حماية رابط السيرفر المخصص", "رصد العبث بالـ Vanity.")}}
              ${{renderToggleRow("anti_webhook_abuse", "حماية الويب هوك", "منع إساءة استخدام Webhooks.")}}
              ${{renderToggleRow("anti_app_abuse", "حماية التطبيقات", "منع إساءة استخدام Integrations/Apps.")}}
              ${{renderToggleRow("anti_mass_unban", "منع فك الحظر الجماعي", "رصد فك الحظر المتكرر.")}}
              ${{renderToggleRow("anti_mass_kick", "منع الطرد الجماعي", "حماية الأعضاء من الطرد الجماعي.")}}
              ${{renderToggleRow("anti_mass_timeout", "منع التايم أوت الجماعي", "رصد التايم أوت المتكرر.")}}
              ${{renderToggleRow("audit_log_watch", "مراقبة سجل التدقيق", "متابعة Audit Log باستمرار.")}}
              ${{renderToggleRow("admin_behavior_analysis", "تحليل سلوك المشرفين", "كشف الأنماط المشبوهة.")}}
              ${{renderToggleRow("trusted_admins_enabled", "تفعيل المشرفين الموثوقين", "قائمة الموثوقين في السيرفر.")}}
              ${{renderToggleRow("perms_snapshot_enabled", "لقطات الصلاحيات", "حفظ لقطات الصلاحيات دورياً.")}}
              ${{renderToggleRow("auto_rollback_enabled", "الاسترجاع التلقائي", "استعادة التغييرات التخريبية تلقائياً.")}}
              ${{renderToggleRow("gradual_attack_detect", "رصد الهجمات التدريجية", "كشف الهجمات البطيئة.")}}
              ${{renderToggleRow("collusion_detect", "رصد التواطؤ", "كشف التنسيق المشبوه.")}}
              ${{renderToggleRow("false_punishment_guard", "حماية من العقوبات الكاذبة", "التحقق قبل العقوبة.")}}
              ${{renderToggleRow("emergency_mode", "وضع الطوارئ", "تأمين شامل فوري.")}}
              ${{renderToggleRow("auto_perms_audit", "تدقيق الصلاحيات التلقائي", "فحص دوري للصلاحيات.")}}
              ${{renderToggleRow("role_hierarchy_guard", "حارس تسلسل الرتب", "حماية هرمية الرتب.")}}
              ${{renderToggleRow("auto_quarantine", "العزل التلقائي", "عزل الحسابات المخالفة تلقائياً.")}}
              ${{renderToggleRow("anti_guild_icon_change", "حماية أيقونة السيرفر (بريميوم)", "منع تغيير صورة السيرفر.")}}
              ${{renderToggleRow("anti_selfbot", "منع السيلف بوت (بريميوم)", "رصد حسابات السيلف بوت.")}}
            </div>
          </div>

          <div class="rounded-3xl bg-card/85 border border-white/[0.08] p-5 space-y-3">
            <h2 class="text-base font-black text-white">حدود قواعد Anti-Nuke التفصيلية</h2>
            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              ${{anRules.map(([rk, rLabel]) => {{
                const cur = (p.antinuke && p.antinuke[rk]) || {{ enabled: true, limit: 1, punishment: "Ban" }};
                return `
                  <div class="p-3.5 rounded-2xl bg-[#0e1121] border border-white/[0.07] space-y-2">
                    <div class="flex items-center justify-between">
                      <span class="text-xs font-extrabold text-white">${{escapeHtml(rLabel)}}</span>
                      <input type="checkbox" ${{cur.enabled ? "checked" : ""}} onchange="setAntinukeRule('${{rk}}', 'enabled', this.checked)" />
                    </div>
                    <div class="flex items-center gap-2 text-xs">
                      <span class="text-slate-400">الحد:</span>
                      <input type="number" min="1" max="50" value="${{escapeHtml(String(cur.limit || 1))}}" onchange="setAntinukeRule('${{rk}}', 'limit', Number(this.value || 1))" class="w-16 rounded-lg bg-[#15192e] border border-white/[0.1] px-2 py-1 text-white" />
                      <select onchange="setAntinukeRule('${{rk}}', 'punishment', this.value)" class="flex-1 rounded-lg bg-[#15192e] border border-white/[0.1] px-2 py-1 text-white">
                        ${{["Ban", "Kick", "Remove Roles", "Quarantine", "Timeout"].map((pun) => `<option value="${{pun}}" ${{cur.punishment === pun ? "selected" : ""}}>${{pun}}</option>`).join("")}}
                      </select>
                    </div>
                  </div>
                `;
              }}).join("")}}
            </div>
          </div>
        </div>
      `;
    }}

    function toggleProtection(key, value) {{
      state.protection[key] = Boolean(value);
      render();
    }}

    function setAntinukeRule(ruleKey, field, val) {{
      if (!state.protection.antinuke) state.protection.antinuke = {{}};
      if (!state.protection.antinuke[ruleKey]) {{
        state.protection.antinuke[ruleKey] = {{ enabled: true, limit: 1, punishment: "Ban" }};
      }}
      state.protection.antinuke[ruleKey][field] = val;
    }}

    function enableAllGuards() {{
      Object.keys(state.protection).forEach((k) => {{
        if (typeof state.protection[k] === "boolean") state.protection[k] = true;
      }});
      render();
      showToast("تم تفعيل جميع أنظمة الحماية محلياً — اضغط حفظ للمزامنة", "info");
    }}

    async function saveProtectionConfig() {{
      const out = await postUiAction({{ kind: "save_protection", protection: state.protection }});
      if (out && out.ok) {{
        await hydrateLiveState();
        showToast("تم حفظ إعدادات الحماية ومزامنتها مع البوت", "success");
      }} else {{
        showToast(out?.error || "تعذر الحفظ", "danger");
      }}
    }}

    function renderPremiumPage() {{
      const pr = state.premium;
      const perks = pr.perks || {{}};
      const guild = getActiveGuild();
      return `
        <div class="animate-panel-enter space-y-6">
          <section class="relative rounded-[28px] bg-gradient-to-br from-[#231b3d] via-[#15182e] to-[#0d1020] border border-amberwarn/30 p-6 sm:p-8 shadow-glass">
            <div class="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
              <div>
                <span class="inline-block px-3 py-1 rounded-full bg-amberwarn/15 border border-amberwarn/35 text-amberwarn text-xs font-extrabold mb-2">${{escapeHtml(SITE_BRAND_NAME)}} PREMIUM • ${{escapeHtml(pr.remainingLabel || "غير مفعل")}}</span>
                <h1 class="text-2xl sm:text-3xl font-black text-white">${{escapeHtml(pr.planName)}}</h1>
                <p class="text-xs sm:text-sm text-slate-300 mt-1">السيرفر المحدد: <strong class="text-white">${{escapeHtml(guild.name)}}</strong> • آخر نسخة: <span class="text-amberwarn">${{escapeHtml(pr.lastBackupTime)}}</span></p>
              </div>
              <button type="button" onclick="triggerInstantBackup()" class="px-4 py-2.5 rounded-xl text-xs font-extrabold bg-emeraldsafe/15 text-emeraldsafe border border-emeraldsafe/35">أخذ نسخة احتياطية الآن</button>
            </div>
          </section>

          ${{renderGuildSelectorBar()}}

          <section class="grid grid-cols-1 lg:grid-cols-2 gap-5">
            <div class="rounded-3xl bg-card/90 border border-white/[0.08] p-6 space-y-4">
              <h2 class="text-lg font-black text-white">استوديو الهوية والمزايا الحصرية</h2>
              <div>
                <label class="block text-xs font-extrabold text-slate-300 mb-1.5">رابط صورة الأفتار</label>
                <input id="prem-avatar-input" type="text" value="${{escapeHtml(pr.customAvatar)}}" class="w-full rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-3.5 py-2.5 text-xs text-white" />
              </div>
              <div>
                <label class="block text-xs font-extrabold text-slate-300 mb-1.5">رابط صورة البنر</label>
                <input id="prem-banner-input" type="text" value="${{escapeHtml(pr.customBanner)}}" class="w-full rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-3.5 py-2.5 text-xs text-white" />
              </div>
              <div>
                <label class="block text-xs font-extrabold text-slate-300 mb-1.5">النبذة التعريفية (Bio — حد أقصى 270 حرفاً)</label>
                <textarea id="prem-bio-input" maxlength="270" rows="3" class="w-full rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-3.5 py-2.5 text-xs text-white">${{escapeHtml(pr.customBio)}}</textarea>
              </div>
              <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 border-t border-white/[0.07]">
                <div>
                  <label class="block text-xs font-extrabold text-slate-300 mb-1">قناة التنبيهات (Channel ID)</label>
                  <input id="prem-alert-ch" type="text" value="${{escapeHtml(perks.alertChannelId || "")}}" placeholder="123456789012345678" class="w-full rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-3 py-2 text-xs text-white" />
                </div>
                <div>
                  <label class="block text-xs font-extrabold text-slate-300 mb-1">رابط Webhook للتنبيهات</label>
                  <input id="prem-alert-wh" type="text" value="${{escapeHtml(perks.alertWebhookUrl || "")}}" placeholder="https://discord.com/api/webhooks/..." class="w-full rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-3 py-2 text-xs text-white" />
                </div>
              </div>
              <div class="space-y-2 pt-2">
                <label class="flex items-center justify-between text-xs font-bold text-slate-200">
                  <span>وضع الحصن الفائق (Ultra Fortress Mode)</span>
                  <input id="prem-ultra-fortress" type="checkbox" ${{perks.ultraFortressMode ? "checked" : ""}} />
                </label>
                <label class="flex items-center justify-between text-xs font-bold text-slate-200">
                  <span>الاسترجاع الفوري (Instant Rollback)</span>
                  <input id="prem-instant-rollback" type="checkbox" ${{perks.instantRollbackEnabled !== false ? "checked" : ""}} />
                </label>
                <label class="flex items-center justify-between text-xs font-bold text-slate-200">
                  <span>أولوية استجابة الدرع (Priority Shield Response)</span>
                  <input id="prem-priority-shield" type="checkbox" ${{perks.priorityShieldResponse !== false ? "checked" : ""}} />
                </label>
              </div>
              <button type="button" onclick="savePremiumProfile()" class="px-5 py-2.5 rounded-xl text-xs font-extrabold bg-gradient-to-r from-violetcore to-indigo-500 text-white shadow-violet">حفظ تخصيص البريميوم</button>
            </div>
            <div class="rounded-3xl bg-card/90 border border-white/[0.08] p-6">
              <span class="text-xs font-extrabold text-violetglow">معاينة مباشرة للهوية</span>
              <div class="mt-3 rounded-2xl overflow-hidden border border-white/[0.08] bg-[#0b0e1c]">
                <img src="${{escapeHtml(pr.customBanner)}}" alt="بنر" class="w-full h-32 object-cover" />
                <div class="p-4 flex items-start gap-3.5">
                  <img src="${{escapeHtml(pr.customAvatar)}}" alt="أفتار" class="w-14 h-14 rounded-2xl object-cover ring-2 ring-violetcore -mt-9 bg-[#12152a] shrink-0" />
                  <div>
                    <h3 class="font-black text-sm text-white">${{escapeHtml(guild.name)}}</h3>
                    <p class="text-xs text-slate-300 mt-1">${{escapeHtml(pr.customBio)}}</p>
                  </div>
                </div>
              </div>
            </div>
          </section>
        </div>
      `;
    }}

    async function savePremiumProfile() {{
      const payload = {{
        customAvatar: document.getElementById("prem-avatar-input")?.value.trim() || "",
        customBanner: document.getElementById("prem-banner-input")?.value.trim() || "",
        customBio: document.getElementById("prem-bio-input")?.value.trim() || "",
        perks: {{
          alertChannelId: document.getElementById("prem-alert-ch")?.value.trim() || "",
          alertWebhookUrl: document.getElementById("prem-alert-wh")?.value.trim() || "",
          ultraFortressMode: Boolean(document.getElementById("prem-ultra-fortress")?.checked),
          instantRollbackEnabled: Boolean(document.getElementById("prem-instant-rollback")?.checked),
          priorityShieldResponse: Boolean(document.getElementById("prem-priority-shield")?.checked),
        }},
      }};
      const out = await postUiAction({{ kind: "save_premium", premium: payload }});
      if (out && out.ok) {{
        await hydrateLiveState();
        showToast("تم حفظ تخصيص البريميوم والمزايا وإرسالها للبوت", "success");
      }} else {{
        showToast(out?.error || "يلزم اشتراك بريميوم فعال", "warn");
      }}
    }}

    async function triggerInstantBackup() {{
      const out = await postUiAction({{ kind: "backup" }});
      if (out && out.ok) {{
        await hydrateLiveState();
        showToast("تم إنشاء نسخة احتياطية: " + (out.backup_id || ""), "success");
      }} else {{
        showToast(out?.error || "صلاحية النسخ الاحتياطي مطلوبة", "danger");
      }}
    }}

    function renderAdminPage() {{
      const activeGuild = getActiveGuild();
      const filter = state.admin.logFilter || "ALL";
      const filteredLogs = state.admin.logs.filter((item) => (filter === "ALL" ? true : item.level === filter));
      return `
        <div class="animate-panel-enter space-y-6">
          <section class="rounded-[26px] bg-gradient-to-r from-[#141932] via-[#101426] to-[#0b0e1b] border border-white/[0.09] p-6 flex flex-col lg:flex-row lg:items-center justify-between gap-4 shadow-glass">
            <div>
              <h1 class="text-2xl font-black text-white">لوحة الإدارة — مركز القيادة</h1>
              <p class="text-xs sm:text-sm text-slate-400 mt-1">السيرفر المحدد: <strong class="text-white">${{escapeHtml(activeGuild.name)}}</strong></p>
            </div>
            <button type="button" onclick="hydrateLiveState(); showToast('تم تحديث البيانات المباشرة', 'success');" class="px-4 py-2.5 rounded-xl text-xs font-extrabold bg-violetcore text-white shadow-violet">تحديث السجلات الآن</button>
          </section>

          ${{renderGuildSelectorBar()}}

          <section class="grid grid-cols-1 lg:grid-cols-12 gap-5">
            <div class="lg:col-span-5 rounded-3xl bg-card/90 border border-white/[0.08] p-5 sm:p-6 space-y-4">
              <h2 class="text-base font-black text-white">إطلاق أمر عن بُعد</h2>
              <div class="flex gap-2">
                <input id="admin-broadcast-input" type="text" placeholder="رسالة بث عامة..." class="flex-1 rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-3 py-2.5 text-xs text-white" />
                <button type="button" onclick="sendAdminBroadcast()" class="px-4 py-2.5 rounded-xl text-xs font-extrabold bg-violetcore text-white">إرسال</button>
              </div>
              <div class="pt-2 border-t border-white/[0.07] space-y-3">
                <input id="admin-target-user" type="text" placeholder="معرف العضو (User ID)" class="w-full rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-3 py-2.5 text-xs text-white" />
                <div class="grid grid-cols-4 gap-2">
                  <button type="button" onclick="runQuickModAction('timeout')" class="py-2.5 px-1.5 rounded-xl text-[11px] font-extrabold bg-amberwarn/15 text-amberwarn border border-amberwarn/30">Timeout</button>
                  <button type="button" onclick="runQuickModAction('kick')" class="py-2.5 px-1.5 rounded-xl text-[11px] font-extrabold bg-sky-500/15 text-sky-300 border border-sky-500/30">Kick</button>
                  <button type="button" onclick="runQuickModAction('ban')" class="py-2.5 px-1.5 rounded-xl text-[11px] font-extrabold bg-coralalert/15 text-coralalert border border-coralalert/30">Ban</button>
                  <button type="button" onclick="runQuickModAction('unban')" class="py-2.5 px-1.5 rounded-xl text-[11px] font-extrabold bg-emeraldsafe/15 text-emeraldsafe border border-emeraldsafe/30">Unban</button>
                </div>
              </div>
            </div>

            <div class="lg:col-span-7 rounded-3xl bg-card/90 border border-white/[0.08] p-5 sm:p-6 flex flex-col">
              <div class="flex flex-wrap items-center justify-between gap-2 mb-4">
                <h2 class="text-base font-black text-white">سجل العمليات والحوادث المباشر</h2>
                <div class="flex items-center gap-1 bg-[#0b0e1c] p-1 rounded-xl border border-white/[0.08]">
                  ${{["ALL", "CRITICAL", "WARN", "INFO"].map((lvl) => `
                    <button type="button" onclick="setAdminLogFilter('${{lvl}}')" class="px-2.5 py-1 rounded-lg text-[11px] font-extrabold ${{filter === lvl ? "bg-violetcore text-white" : "text-slate-400"}}">
                      ${{lvl === "ALL" ? "الكل" : lvl}}
                    </button>
                  `).join("")}}
                </div>
              </div>
              <div class="space-y-2.5 max-h-[320px] overflow-y-auto pr-1">
                ${{filteredLogs.map((log) => `
                  <div class="p-3.5 rounded-2xl bg-[#0b0e1c]/90 border border-white/[0.06]">
                    <div class="flex items-center gap-2 mb-1">
                      <span class="px-2 py-0.5 rounded-full text-[10px] font-extrabold bg-violetcore/20 text-violetglow">${{escapeHtml(log.level)}}</span>
                      <span class="text-[11px] font-bold text-slate-400">${{escapeHtml(log.type)}} • ${{escapeHtml(log.time)}}</span>
                    </div>
                    <p class="text-xs text-slate-200 leading-relaxed">${{escapeHtml(log.text)}}</p>
                  </div>
                `).join("")}}
              </div>
            </div>
          </section>

          <section class="grid grid-cols-1 lg:grid-cols-2 gap-5">
            <div class="rounded-3xl bg-card/90 border border-white/[0.08] p-5 space-y-3">
              <h2 class="text-base font-black text-white">إدارة اشتراكات البريميوم</h2>
              <div class="flex flex-wrap gap-2">
                <input id="adm-prem-uid" type="text" placeholder="User ID" class="flex-1 min-w-[140px] rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-3 py-2 text-xs text-white" />
                <input id="adm-prem-days" type="number" min="1" max="3650" value="30" placeholder="أيام" class="w-20 rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-2.5 py-2 text-xs text-white" />
                <button type="button" onclick="submitAdminPremium(true)" class="px-3.5 py-2 rounded-xl text-xs font-extrabold bg-emeraldsafe text-slate-950">منح</button>
                <button type="button" onclick="submitAdminPremium(false)" class="px-3.5 py-2 rounded-xl text-xs font-extrabold bg-coralalert/20 text-coralalert border border-coralalert/35">إلغاء</button>
              </div>
              <div class="space-y-1.5 max-h-48 overflow-y-auto text-xs">
                ${{state.admin.premiumUsers.map((pu) => `
                  <div class="flex items-center justify-between px-3 py-2 rounded-xl bg-[#0b0e1c] border border-white/[0.06]">
                    <span class="font-bold text-white">${{escapeHtml(pu.username)}} (${{escapeHtml(pu.user_id)}})</span>
                    <span class="text-amberwarn font-bold">${{escapeHtml(pu.remaining)}}</span>
                  </div>
                `).join("")}}
              </div>
            </div>

            <div class="rounded-3xl bg-card/90 border border-white/[0.08] p-5 space-y-3">
              <h2 class="text-base font-black text-white">إدارة الأدمن الفرعيين والنسخ الاحتياطية</h2>
              <div class="flex flex-wrap gap-2">
                <input id="adm-staff-uid" type="text" placeholder="User ID" class="flex-1 min-w-[140px] rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-3 py-2 text-xs text-white" />
                <select id="adm-staff-role" class="rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-2.5 py-2 text-xs text-white">
                  <option value="Staff">Staff</option>
                  <option value="Co owner">Co owner</option>
                </select>
                <button type="button" onclick="submitAdminStaff(true)" class="px-3.5 py-2 rounded-xl text-xs font-extrabold bg-violetcore text-white">إضافة</button>
                <button type="button" onclick="submitAdminStaff(false)" class="px-3.5 py-2 rounded-xl text-xs font-extrabold bg-coralalert/20 text-coralalert border border-coralalert/35">إزالة</button>
              </div>
              <div class="space-y-1.5 max-h-48 overflow-y-auto text-xs">
                ${{state.admin.admins.map((ad) => `
                  <div class="flex items-center justify-between px-3 py-2 rounded-xl bg-[#0b0e1c] border border-white/[0.06]">
                    <span class="font-bold text-white">${{escapeHtml(ad.user_id)}}</span>
                    <span class="text-violetglow font-bold">${{escapeHtml(ad.role_tag)}}</span>
                  </div>
                `).join("")}}
              </div>
              <div class="pt-2 border-t border-white/[0.07] space-y-1 text-[11px] text-slate-400">
                ${{state.admin.backups.slice(0, 4).map((bk) => `
                  <div>نسخة <strong class="text-slate-200">${{escapeHtml(bk.backup_id)}}</strong> — ${{escapeHtml(bk.created_at)}}</div>
                `).join("")}}
              </div>
            </div>
          </section>
        </div>
      `;
    }}

    async function sendAdminBroadcast() {{
      const text = (document.getElementById("admin-broadcast-input")?.value || "").trim();
      if (!text) return showToast("اكتب نص الرسالة أولاً", "warn");
      const out = await postUiAction({{ kind: "broadcast", text }});
      if (out && out.ok) {{
        await hydrateLiveState();
        showToast("تم إرسال البث العام للقائمة", "success");
      }} else {{
        showToast(out?.error || "صلاحية الإدارة مطلوبة", "danger");
      }}
    }}

    async function runQuickModAction(action) {{
      const target = (document.getElementById("admin-target-user")?.value || "").trim();
      if (!target) return showToast("أدخل معرف العضو أولاً", "warn");
      const out = await postUiAction({{ kind: "mod_action", action, target }});
      if (out && out.ok) {{
        await hydrateLiveState();
        showToast("تم إرسال أمر " + action.toUpperCase() + " بنجاح", "success");
      }} else {{
        showToast(out?.error || "صلاحية الإدارة مطلوبة", "danger");
      }}
    }}

    async function submitAdminPremium(enabled) {{
      const target_user_id = (document.getElementById("adm-prem-uid")?.value || "").trim();
      const days = Number(document.getElementById("adm-prem-days")?.value || 30);
      const out = await postUiAction({{ kind: "set_premium_user", target_user_id, enabled, days }});
      if (out && out.ok) {{
        await hydrateLiveState();
        showToast(enabled ? "تم منح البريميوم" : "تم إلغاء البريميوم", "success");
      }} else {{
        showToast(out?.error || "تعذر تنفيذ العملية", "danger");
      }}
    }}

    async function submitAdminStaff(enabled) {{
      const target_user_id = (document.getElementById("adm-staff-uid")?.value || "").trim();
      const role_tag = document.getElementById("adm-staff-role")?.value || "Staff";
      const out = await postUiAction({{ kind: "set_admin_user", target_user_id, enabled, role_tag }});
      if (out && out.ok) {{
        await hydrateLiveState();
        showToast(enabled ? "تم تحديث صلاحيات الأدمن" : "تم إزالة الأدمن", "success");
      }} else {{
        showToast(out?.error || "تعذر تنفيذ العملية", "danger");
      }}
    }}

    function setAdminLogFilter(lvl) {{
      state.admin.logFilter = lvl;
      render();
    }}

    function render() {{
      syncHeaderAndDrawer();
      const main = document.getElementById("main-content");
      if (!main) return;
      if (!state.isAuthenticated && state.activePage !== "home") {{
        main.innerHTML = renderLoginGate();
        return;
      }}
      if (state.activePage === "protection") main.innerHTML = renderProtectionPage();
      else if (state.activePage === "premium") main.innerHTML = renderPremiumPage();
      else if (state.activePage === "admin") main.innerHTML = renderAdminPage();
      else main.innerHTML = renderHomePage();
    }}

    render();
    hydrateLiveState();
  </script>
</body>
</html>"""
    return web.Response(text=html_page, content_type="text/html")


async def handle_invite_redirect(request: web.Request) -> web.Response:
    user = get_discord_session(request)
    if not user:
        raise web.HTTPFound("/login?next=" + quote("/invite"))
    target_invite = sanitize_http_url(BOT_INVITE_URL) or "https://discord.com"
    raise web.HTTPFound(target_invite)


async def handle_login(request: web.Request) -> web.Response:
    next_url = sanitize_next_url(request.query.get("next") or "/")
    if not DISCORD_CLIENT_ID or not DISCORD_CLIENT_SECRET:
        raise web.HTTPFound("/")

    state = issue_oauth_state(next_url=next_url)
    redirect_uri = detect_redirect_uri(request)
    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "identify guilds",
        "state": state,
    }
    raise web.HTTPFound("https://discord.com/api/oauth2/authorize?" + urlencode(params))


async def handle_callback(request: web.Request) -> web.Response:
    state_val = request.query.get("state")
    ok_state, next_url = consume_oauth_state(state_val)
    if not ok_state or request.query.get("error"):
        raise web.HTTPFound("/")

    code = str(request.query.get("code", "")).strip()
    if not code:
        raise web.HTTPFound("/")

    redirect_uri = detect_redirect_uri(request)
    timeout = ClientTimeout(total=10)
    try:
        async with ClientSession(timeout=timeout) as session:
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
            if token_resp.status != 200:
                raise web.HTTPFound("/")
            token_data = await token_resp.json()
            access_token = str(token_data.get("access_token", "")).strip()
            if not access_token:
                raise web.HTTPFound("/")

            auth_headers = {"Authorization": f"Bearer {access_token}"}
            user_resp = await session.get("https://discord.com/api/users/@me", headers=auth_headers)
            if user_resp.status != 200:
                raise web.HTTPFound("/")
            u_data = await user_resp.json()

            guilds_list: list[dict] = []
            guilds_resp = await session.get("https://discord.com/api/users/@me/guilds", headers=auth_headers)
            if guilds_resp.status == 200:
                g_raw = await guilds_resp.json()
                if isinstance(g_raw, list):
                    for g in g_raw[:150]:
                        if isinstance(g, dict) and str(g.get("id", "")).isdigit():
                            guilds_list.append(
                                {
                                    "id": str(g["id"]),
                                    "name": str(g.get("name", f"Server {g['id']}"))[:100],
                                    "icon": str(g.get("icon", "") or "")[:80],
                                    "permissions": int(g.get("permissions", 0) or 0),
                                    "owner": bool(g.get("owner", False)),
                                }
                            )
    except (ClientError, asyncio.TimeoutError, Exception):
        raise web.HTTPFound("/")

    uid = str(u_data.get("id", "")).strip()
    if not uid.isdigit():
        raise web.HTTPFound("/")

    uname = str(u_data.get("global_name") or u_data.get("username") or f"User {uid}")[:40]
    ava = str(u_data.get("avatar", "") or "")[:40]
    exp_ts = time.time() + 86400 * 7
    token = sign_session(
        {
            "id": uid,
            "username": uname,
            "avatar": ava,
            "guilds": guilds_list,
            "exp": exp_ts,
        }
    )

    _invalidate_perm_cache(uid)
    log_event(f"User {uname} ({uid}) logged in via Discord", level="WEB")
    resp = web.HTTPFound(next_url)
    resp.set_cookie(
        "arab_sec_session",
        token,
        max_age=86400 * 7,
        path="/",
        httponly=True,
        secure=should_use_secure_cookie(request),
        samesite="Lax",
    )
    return resp


async def handle_logout(request: web.Request) -> web.Response:
    pair = get_discord_session_with_id(request)
    if pair:
        _delete_session_record(pair[0])
    resp = web.HTTPFound("/")
    resp.del_cookie("arab_sec_session", path="/")
    return resp


async def handle_health(request: web.Request) -> web.Response:
    return web.json_response(
        {
            "ok": True,
            "service": SITE_NAME,
            "bot_status": MEM_BOT_HEARTBEAT.get("status", "ONLINE"),
            "guilds_count": len(get_all_guilds()),
            "total_visits": get_total_visits(),
        }
    )


@web.middleware
async def security_and_metrics_middleware(request: web.Request, handler):
    ip = get_client_ip(request)
    is_auth_path = request.path in ("/login", "/callback")
    if is_rate_limited(ip, is_sensitive=is_auth_path):
        return web.json_response({"ok": False, "error": "Too many requests"}, status=429)

    if request.method == "GET":
        record_site_visit(request)

    try:
        resp = await handler(request)
    except web.HTTPException as ex:
        resp = ex

    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return resp


async def _on_startup(app: web.Application) -> None:
    flush_visits_if_needed(force=True)


async def _on_cleanup(app: web.Application) -> None:
    flush_visits_if_needed(force=True)
    if client is not None:
        try:
            client.close()
        except Exception:
            pass


def create_app() -> web.Application:
    app = web.Application(
        client_max_size=MAX_IMAGE_BYTES + 2_000_000,
        middlewares=[security_and_metrics_middleware],
    )
    app.on_startup.append(_on_startup)
    app.on_cleanup.append(_on_cleanup)

    app.router.add_get("/", handle_modern_ui)
    app.router.add_get("/ui", handle_modern_ui)
    app.router.add_get("/invite", handle_invite_redirect)
    app.router.add_route("*", "/guild", handle_modern_ui)
    app.router.add_route("*", "/premium", handle_modern_ui)
    app.router.add_route("*", "/admin", handle_modern_ui)
    app.router.add_get("/login", handle_login)
    app.router.add_get("/callback", handle_callback)
    app.router.add_get("/logout", handle_logout)
    app.router.add_get("/health", handle_health)

    app.router.add_post("/api/bot/sync-guilds", api_bot_sync_guilds)
    app.router.add_post("/api/bot/boost-sync", api_bot_boost_sync)
    app.router.add_post("/api/bot/pending-commands", api_bot_pending_commands)
    app.router.add_get("/api/ui-state", api_ui_state)
    app.router.add_post("/api/ui-action", api_ui_action)
    return app


if __name__ == "__main__":
    web.run_app(create_app(), host=HOST, port=PORT)
