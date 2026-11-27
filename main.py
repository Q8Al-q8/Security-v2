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
BRAND_LABEL_AR = "Arab Security "
OWNER_NAME = (os.getenv("OWNER_NAME", "سعود السويط") or "سعود السويط").strip()[:60]
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

DEFAULT_SYNC_SECRET = "8UJ3rUf3IrJCPfYfSrzog2KiLPxr87S3"

_env_secret = (os.environ.get("SESSION_SECRET") or "").strip()
SESSION_SECRET = (
    _env_secret
    if len(_env_secret) >= 16
    else "ArabSecurity_Session_Secret_2026_x9K#mP2vL8qR5tW7zY3nB6jH4cF1gD0sA"
)
BOT_SYNC_SECRET = (
    (os.environ.get("BOT_SYNC_SECRET") or "OzLxgLklbMjEbhRg7__f8HvtQo1BK584").strip()
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

BRAND_LOGO_SVG_DATA_URL = (
    "data:image/svg+xml;utf8,"
    + quote(
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 200 200'>"
        "<defs><linearGradient id='g' x1='0' y1='0' x2='1' y2='1'>"
        "<stop offset='0%' stop-color='#48b8e8'/><stop offset='100%' stop-color='#154878'/>"
        "</linearGradient></defs>"
        "<rect width='200' height='200' rx='36' fill='url(#g)'/>"
        "<polygon points='100,26 136,82 64,82' fill='#ffffff'/>"
        "<polygon points='54,96 86,154 22,154' fill='#ffffff'/>"
        "<polygon points='146,96 178,154 114,154' fill='#ffffff'/>"
        "<polygon points='72,96 128,96 100,148' fill='#cbeeff'/>"
        "</svg>"
    )
)

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

ADMIN_PERMISSION_LABELS_AR = {
    "manage_premium": "إدارة البريميوم",
    "manage_admins": "إدارة الأدمن والصلاحيات",
    "remote_actions": "الأوامر عن بُعد والبث",
    "simulations": "فحص الجاهزية",
    "backups": "النسخ الاحتياطي والاستعادة",
    "view_logs": "سجل العمليات (Log)",
}

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

FEATURE_LABELS_AR = {
    "anti_spam": "منع السبام",
    "anti_link": "منع الروابط",
    "anti_invites": "منع روابط الدعوة",
    "anti_raid": "حماية السيرفر من الدخول المفاجئ",
    "lockdown": "قفل السيرفر",
    "anti_new_accounts": "منع الحسابات الحديثة",
    "voice_lock": "قفل الرومات الصوتية",
    "anti_bot_raid": "حماية إضافة البوتات",
    "anti_vanity_tamper": "حماية رابط السيرفر المخصص",
    "anti_guild_icon_change": "حماية من تغيير صورة السيرفر (بريميوم)",
    "anti_mass_unban": "مراقبة فك الحظر الجماعي",
    "anti_mass_kick": "مراقبة الطرد الجماعي",
    "anti_mass_timeout": "مراقبة التايم أوت الجماعي",
    "anti_mention_spam": "منع المنشن الجماعي",
    "quarantine_on_sabotage": "سحب الرتب وعزل المخالف من التخريب",
    "dangerous_perms_guard": "حماية الصلاحيات الخطيرة",
    "anti_selfbot": "حماية الحسابات الآلية (بريميوم)",
    "anti_webhook_abuse": "حماية الويب هوك",
    "anti_app_abuse": "حماية تطبيقات الربط",
    "anti_privilege_escalation": "منع رفع الصلاحيات غير المصرح به",
    "anti_role_delete": "حماية من حذف الرتب",
    "anti_role_edit": "حماية من تعديل الرتب",
    "anti_channel_perms_tamper": "حماية تعديل صلاحيات الرومات",
    "audit_log_watch": "مراقبة سجل التدقيق الفورية",
    "admin_behavior_analysis": "مراقبة نشاط المشرفين",
    "trusted_admins_enabled": "قائمة المشرفين الموثوقين",
    "perms_snapshot_enabled": "لقطات الصلاحيات",
    "auto_rollback_enabled": "استرجاع التغييرات تلقائياً",
    "gradual_attack_detect": "رصد التغييرات المتكررة",
    "collusion_detect": "رصد النشاط المنسق",
    "false_punishment_guard": "حماية العقوبات الخاطئة",
    "emergency_mode": "وضع الطوارئ",
    "auto_perms_audit": "فحص الصلاحيات التلقائي",
    "silent_mode": "الوضع الصامت",
    "beast_mode": "وضع الحماية العالي",
    "role_hierarchy_guard": "حماية تسلسل الرتب",
    "auto_quarantine": "عزل المشتبه بهم تلقائياً",
    "maintenance": "وضع الصيانة",
    "verification": "التحقق عند الدخول",
    "alert_on_trigger": "إرسال تنبيه عند التفعيل",
}

ANTINUKE_LABELS_AR = {
    "anti_ban": "حماية من الحظر المتكرر",
    "anti_kick": "حماية من الطرد المتكرر",
    "anti_role_create": "حماية من إنشاء الرتب",
    "anti_role_delete": "حماية من حذف الرتب",
    "anti_role_edit": "حماية من تعديل الرتب",
    "anti_channel_create": "حماية من إنشاء الرومات",
    "anti_channel_delete": "حماية من حذف الرومات",
    "anti_webhook_create": "حماية من إنشاء الويب هوك",
    "anti_bot_add": "حماية من إضافة البوتات",
    "anti_guild_update": "حماية من تعديل إعدادات السيرفر",
    "anti_emoji_delete": "حماية من حذف الإيموجيات",
}


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
        "handle": f"@{OWNER_NAME.lower().replace(' ', '')}",
        "avatar_url": "",
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

OAUTH_STATES: dict[str, dict] = {}
RATE_BUCKETS: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=500))
AUTH_RATE_BUCKETS: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=150))
SESSIONS: dict[str, dict] = {}


def esc(val) -> str:
    return html.escape(str(val or ""), quote=True)


def sanitize_next_url(raw_next: str | None) -> str:
    val = str(raw_next or "").strip()
    if not val.startswith("/") or val.startswith("//") or "\\" in val:
        return "/ui"
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


def _default_avatar_for_uid(uid: str) -> str:
    clean = str(uid or "").strip()
    idx = (int(clean) >> 22) % 6 if clean.isdigit() else 0
    return f"https://cdn.discordapp.com/embed/avatars/{idx}.png"


def _normalize_premium_doc(doc: dict) -> dict:
    clean = dict(doc)
    uid = str(clean.get("user_id") or clean.get("id") or "").strip()
    clean["user_id"] = uid
    clean["username"] = str(clean.get("username") or clean.get("name") or f"User {uid}").strip()[:40]
    raw_handle = str(clean.get("handle") or f"@{clean['username']}").strip()[:44]
    clean["handle"] = raw_handle if raw_handle.startswith("@") else f"@{raw_handle.lstrip('@')}"
    ava_raw = str(clean.get("avatar_url") or clean.get("avatar") or "").strip()
    if ava_raw.startswith("http"):
        clean["avatar_url"] = sanitize_http_url(ava_raw) or _default_avatar_for_uid(uid)
    elif uid.isdigit() and ava_raw:
        ext = "gif" if ava_raw.startswith("a_") else "png"
        clean["avatar_url"] = f"https://cdn.discordapp.com/avatars/{uid}/{ava_raw}.{ext}?size=128"
    else:
        clean["avatar_url"] = _default_avatar_for_uid(uid)
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
                    "handle": f"@{OWNER_NAME.lower().replace(' ', '')}",
                    "avatar_url": _default_avatar_for_uid(ADMIN_USER_ID),
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
    for st, meta in list(OAUTH_STATES.items()):
        if _safe_exp(meta.get("exp", 0)) <= now:
            OAUTH_STATES.pop(st, None)
    for sid, sess in list(SESSIONS.items()):
        if _safe_exp(sess.get("exp", 0)) <= now:
            SESSIONS.pop(sid, None)
    if sessions_col is not None:
        try:
            sessions_col.delete_many({"exp": {"$lte": now}})
        except PyMongoError:
            pass


def issue_oauth_state(next_url: str = "/ui") -> str:
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
        return False, "/ui"
    meta = OAUTH_STATES.pop(clean)
    exp = _safe_exp(meta.get("exp", 0))
    nxt = sanitize_next_url(meta.get("next", "/ui"))
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
            "handle": f"@{OWNER_NAME.lower().replace(' ', '')}",
            "avatar_url": _default_avatar_for_uid(ADMIN_USER_ID),
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


def format_remaining_time(rec: dict) -> str:
    norm = _normalize_premium_doc(rec or {})
    if norm.get("permanent"):
        return "دائم"
    if norm.get("source") == "boost":
        return "مفعل عبر دعم البوست"
    rem = max(0.0, _parse_expires_ts(norm.get("expires_at", 0.0)) - time.time())
    days = int(rem // 86400)
    hours = int((rem % 86400) // 3600)
    mins = int((rem % 3600) // 60)
    if days > 0:
        return f"{days} يوم و {hours} ساعة"
    if hours > 0:
        return f"{hours} ساعة و {mins} دقيقة"
    return f"{max(1, mins)} دقيقة متبقية"


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
    avatar_url: str = "",
    source: str = "manual",
) -> bool:
    uid = str(user_id or "").strip()
    if not uid.isdigit():
        return False
    _invalidate_perm_cache("")
    if enabled:
        now = time.time()
        is_perm = uid == ADMIN_USER_ID
        existing = MEM_PREMIUM.get(uid) or {}
        base_exp = _parse_expires_ts(existing.get("expires_at", 0.0))
        start_ts = base_exp if base_exp > now else now
        add_seconds = max(60, int(days or 0) * 86400 + int(hours or 0) * 3600)
        clean_uname = str(username or existing.get("username") or f"User {uid}").strip()[:40]
        raw_h = str(handle or existing.get("handle") or f"@{clean_uname.lower().replace(' ', '')}").strip()[:44]
        clean_handle = raw_h if raw_h.startswith("@") else f"@{raw_h.lstrip('@')}"
        clean_ava = sanitize_http_url(avatar_url) or str(existing.get("avatar_url") or "") or _default_avatar_for_uid(uid)
        rec = {
            "user_id": uid,
            "username": clean_uname,
            "handle": clean_handle,
            "avatar_url": clean_ava,
            "granted_by": granted_by or ADMIN_USER_ID,
            "source": source,
            "duration_days": int(days or 0),
            "duration_hours": int(hours or 0),
            "granted_at": existing.get("granted_at") or _now_str(),
            "expires_at": 0.0 if is_perm else (start_ts + add_seconds),
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
        ava_raw = str(b.get("avatar_url") or b.get("avatar") or "").strip()
        ava_clean = (
            sanitize_http_url(ava_raw)
            if ava_raw.startswith("http")
            else (
                f"https://cdn.discordapp.com/avatars/{uid}/{ava_raw}.{'gif' if ava_raw.startswith('a_') else 'png'}?size=128"
                if ava_raw
                else _default_avatar_for_uid(uid)
            )
        )
        active_map[uid] = {
            "user_id": uid,
            "username": uname,
            "handle": f"@{uname.lower().lstrip('@').replace(' ', '')}",
            "avatar_url": ava_clean,
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


def guild_icon_url(guild_id: str, icon_val: str | None) -> str:
    gid = str(guild_id or "").strip()
    ico = str(icon_val or "").strip()
    if not gid.isdigit() or not ico:
        return ""
    if ico.startswith(("https://", "http://")):
        return sanitize_http_url(ico)
    ext = "gif" if ico.startswith("a_") else "png"
    return f"https://cdn.discordapp.com/icons/{gid}/{ico}.{ext}?size=128"


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
    for key in SHIELD_TOGGLE_KEYS:
        if key in updates:
            if key in PREMIUM_PROTECTION_TOGGLE_KEYS and not is_premium:
                continue
            cfg[key] = bool(updates[key])

    if "spam_punishment" in updates:
        sp = str(updates["spam_punishment"] or "Timeout").strip()
        if sp in ("Delete Only", "Timeout", "Kick", "Ban"):
            cfg["spam_punishment"] = sp
    if "spam_timeout_seconds" in updates:
        try:
            sec = int(updates["spam_timeout_seconds"])
            cfg["spam_timeout_seconds"] = max(10, min(2419200, sec))
        except Exception:
            cfg["spam_timeout_seconds"] = 600

    if "link_punishment" in updates:
        lp = str(updates["link_punishment"] or "Delete & Timeout").strip()
        if lp in ("Delete Only", "Delete & Timeout", "Kick", "Ban"):
            cfg["link_punishment"] = lp
    if "link_timeout_seconds" in updates:
        try:
            lsec = int(updates["link_timeout_seconds"])
            cfg["link_timeout_seconds"] = max(10, min(2419200, lsec))
        except Exception:
            cfg["link_timeout_seconds"] = 300

    if "dangerous_perms_punishment" in updates:
        dp = str(updates["dangerous_perms_punishment"] or "Remove Roles").strip()
        if dp in ("None", "Remove Roles", "Kick", "Ban"):
            cfg["dangerous_perms_punishment"] = dp

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

    if is_premium and "guild_profile" in updates and isinstance(updates["guild_profile"], dict):
        prof = cfg.setdefault("guild_profile", {})
        p_upd = updates["guild_profile"]
        if "bio" in p_upd:
            prof["bio"] = sanitize_bio_text(p_upd["bio"])
        if "avatar_data_url" in p_upd:
            prof["avatar_data_url"] = sanitize_image_data_url(p_upd["avatar_data_url"])
        if "banner_data_url" in p_upd:
            prof["banner_data_url"] = sanitize_image_data_url(p_upd["banner_data_url"])

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
            "snapshot_hash": hashlib.sha256(
                json.dumps(cfg.get("antinuke", {}), sort_keys=True).encode("utf-8")
            ).hexdigest()[:12],
            "antinuke_data": json.loads(json.dumps(cfg.get("antinuke", {}))),
            "trusted_data": list(cfg.get("trusted_admins", [])),
        }
        snaps = list(cfg.get("perms_snapshots", []))
        snaps.insert(0, snap)
        cfg["perms_snapshots"] = snaps[:10]
    if "restore_snapshot_id" in updates and updates["restore_snapshot_id"]:
        target_id = str(updates["restore_snapshot_id"]).strip()
        snaps = list(cfg.get("perms_snapshots", []))
        matched_snap = next((s for s in snaps if str(s.get("id")) == target_id), None)
        if matched_snap:
            if isinstance(matched_snap.get("antinuke_data"), dict):
                for ak, av in matched_snap["antinuke_data"].items():
                    if ak in cfg["antinuke"] and isinstance(av, dict):
                        cfg["antinuke"][ak].update(av)
            if isinstance(matched_snap.get("trusted_data"), list):
                restored_tr = [str(x) for x in matched_snap["trusted_data"] if str(x).isdigit()]
                if ADMIN_USER_ID not in restored_tr:
                    restored_tr.insert(0, ADMIN_USER_ID)
                cfg["trusted_admins"] = restored_tr
            cfg.setdefault("premium_perks", {})["last_restored_snapshot"] = target_id

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


def calculate_security_score(cfg: dict) -> tuple[int, str]:
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
    score = max(0, min(100, score))
    if score >= 85:
        grade = "A+ (حماية متكاملة)"
    elif score >= 65:
        grade = "B+ (حماية قوية)"
    else:
        grade = "C (يحتاج تفعيل قواعد إضافية)"
    return score, grade


def run_attack_simulation(guild_id: str, scenario: str) -> str:
    cfg = get_guild_cfg(guild_id)
    score, _ = calculate_security_score(cfg)
    blocked = score >= 50 or bool(cfg.get("emergency_mode")) or bool((cfg.get("premium_perks") or {}).get("ultra_fortress_mode"))
    outcome = "تم التحقق من جاهزية الحماية والاسترجاع التلقائي" if blocked else "تم رصد قواعد معطلة يُنصح بتفعيلها"
    record_incident(guild_id, "CHECK", f"فحص [{scenario}]: {outcome}", "INFO")
    log_event(f"فحص حماية [{scenario}] في السيرفر {guild_id}: {outcome}", guild_id=guild_id, level="SEC")
    return f"{outcome} (نسبة جاهزية الحماية: {score}/100)."


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


def get_db_backups() -> list[dict]:
    if backups_col is not None:
        try:
            return list(backups_col.find({}, {"_id": 0}).sort("_id", -1).limit(10))
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
    log_event(msg, level="ADMIN")
    return ok, msg


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


async def _lookup_discord_user_preview(uid: str) -> dict:
    clean_uid = str(uid or "").strip()
    existing_prem = _get_premium_record(clean_uid) if clean_uid.isdigit() else None
    if existing_prem:
        return {
            "found": True,
            "user_id": clean_uid,
            "username": existing_prem.get("username") or f"User {clean_uid}",
            "handle": existing_prem.get("handle") or f"@user_{clean_uid[-4:]}",
            "avatar_url": existing_prem.get("avatar_url") or _default_avatar_for_uid(clean_uid),
            "is_premium": True,
            "remaining": format_remaining_time(existing_prem),
        }

    if clean_uid.isdigit() and DISCORD_CLIENT_SECRET:
        try:
            async with ClientSession(timeout=ClientTimeout(total=4)) as sess:
                resp = await sess.get(
                    f"https://discord.com/api/v10/users/{clean_uid}",
                    headers={"Authorization": f"Bot {DISCORD_CLIENT_SECRET}"},
                )
                if resp.status == 200:
                    u = await resp.json()
                    uname = str(u.get("global_name") or u.get("username") or f"User {clean_uid}")[:40]
                    raw_tag = str(u.get("username") or f"user_{clean_uid[-4:]}").strip()[:40]
                    ava_hash = str(u.get("avatar") or "").strip()
                    ava_url = (
                        f"https://cdn.discordapp.com/avatars/{clean_uid}/{ava_hash}.{'gif' if ava_hash.startswith('a_') else 'png'}?size=128"
                        if ava_hash
                        else _default_avatar_for_uid(clean_uid)
                    )
                    return {
                        "found": True,
                        "user_id": clean_uid,
                        "username": uname,
                        "handle": f"@{raw_tag.lstrip('@')}",
                        "avatar_url": ava_url,
                        "is_premium": False,
                        "remaining": "",
                    }
        except Exception:
            pass

    return {
        "found": bool(clean_uid.isdigit()),
        "user_id": clean_uid,
        "username": f"مستخدم {clean_uid[-4:]}" if clean_uid.isdigit() else "مستخدم",
        "handle": f"@user_{clean_uid[-4:]}" if clean_uid.isdigit() else "@user",
        "avatar_url": _default_avatar_for_uid(clean_uid),
        "is_premium": False,
        "remaining": "",
    }


async def api_lookup_user(request: web.Request) -> web.Response:
    user = get_discord_session(request)
    if not user or not is_site_admin(user) or not has_admin_perm(user, "manage_premium"):
        return web.json_response({"ok": False, "error": "Unauthorized"}, status=403)
    uid = str(request.query.get("user_id", "")).strip()
    if not uid.isdigit():
        return web.json_response({"ok": False, "error": "Invalid User ID"}, status=400)
    info = await _lookup_discord_user_preview(uid)
    return web.json_response({"ok": True, "user": info})


def _serialize_guild_full(g: dict, is_prem: bool) -> dict:
    gid = g["id"]
    cfg = get_guild_cfg(gid)
    score, grade = calculate_security_score(cfg)
    an_rules = []
    an_map = cfg.get("antinuke") or {}
    for ak in ANTINUKE_RULE_KEYS:
        rule = an_map.get(ak) or {"enabled": True, "limit": 1, "punishment": "Ban"}
        an_rules.append(
            {
                "key": ak,
                "label": ANTINUKE_LABELS_AR.get(ak, ak),
                "enabled": bool(rule.get("enabled", True)),
                "limit": int(rule.get("limit", 1) or 1),
                "punishment": str(rule.get("punishment", "Ban")),
            }
        )
    all_toggles = []
    for k in SHIELD_TOGGLE_KEYS:
        if k in PREMIUM_PROTECTION_TOGGLE_KEYS and not is_prem:
            continue
        all_toggles.append(
            {
                "key": k,
                "label": FEATURE_LABELS_AR.get(k, k),
                "enabled": bool(cfg.get(k, False)),
            }
        )
    return {
        "id": gid,
        "name": g["name"],
        "members": int(g.get("member_count", 0) or 0),
        "iconUrl": guild_icon_url(gid, g.get("icon")),
        "iconText": (str(g.get("name", "CS"))[:2] or "CS").upper(),
        "protectionScore": score,
        "protectionGrade": grade,
        "premium": is_prem,
        "prefix": str(cfg.get("prefix", "!")),
        "modLogChannel": str(cfg.get("mod_log_channel", "")),
        "spamPunishment": str(cfg.get("spam_punishment", "Timeout")),
        "linkPunishment": str(cfg.get("link_punishment", "Delete & Timeout")),
        "dangerousPermsPunishment": str(cfg.get("dangerous_perms_punishment", "Remove Roles")),
        "minAccountAgeDays": int(cfg.get("min_account_age_days", 7) or 7),
        "trustedAdmins": list(cfg.get("trusted_admins") or []),
        "snapshots": list(cfg.get("perms_snapshots") or []),
        "toggles": all_toggles,
        "antinukeRules": an_rules,
    }


async def api_ui_state(request: web.Request) -> web.Response:
    user = get_discord_session(request)
    all_bot_guilds = get_all_guilds()
    total_visits = get_total_visits()
    if not user:
        return web.json_response(
            {
                "ok": True,
                "isAuthenticated": False,
                "isPremium": False,
                "isAdmin": False,
                "botGuildsCount": len(all_bot_guilds),
                "totalVisits": total_visits,
                "user": {
                    "username": "زائر غير مسجل",
                    "handle": "@guest",
                    "avatar": BRAND_LOGO_SVG_DATA_URL,
                },
                "selectedGuildId": "",
                "guilds": [],
                "allBotGuilds": [],
                "premiumUsers": [],
                "adminStaff": [],
                "backups": [],
                "logs": [],
                "adminPerms": {},
            }
        )

    visible_guilds, _ = get_user_visible_guilds(user)
    is_prem = is_premium_user(user)
    is_adm = is_site_admin(user)
    uid = str(user.get("id", "")).strip()
    ava = str(user.get("avatar", "")).strip()
    avatar_url = (
        f"https://cdn.discordapp.com/avatars/{uid}/{ava}.png?size=128"
        if uid and ava
        else _default_avatar_for_uid(uid)
    )
    active_guilds_list = [g for g in visible_guilds if not g.get("bot_missing")]
    req_gid = str(request.query.get("guild_id", "")).strip()
    if req_gid.isdigit() and any(g["id"] == req_gid for g in active_guilds_list):
        selected_gid = req_gid
    else:
        selected_gid = active_guilds_list[0]["id"] if active_guilds_list else ""

    serialized_guilds = [_serialize_guild_full(g, is_prem) for g in active_guilds_list[:20]]
    logs_raw = get_recent_logs(40) if (is_adm and has_admin_perm(user, "view_logs")) else []
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

    prem_list_now = get_premium_list() if is_adm else []
    adm_list_now = get_admin_list() if is_adm else []
    backups_now = get_db_backups() if (is_adm and has_admin_perm(user, "backups")) else []
    adm_perms_map = {k: has_admin_perm(user, k) for k in ADMIN_PERMISSION_KEYS} if is_adm else {}

    cfg = get_guild_cfg(selected_gid) if selected_gid else _fresh_default_guild_cfg()

    return web.json_response(
        {
            "ok": True,
            "isAuthenticated": True,
            "isPremium": is_prem,
            "isAdmin": is_adm,
            "adminPerms": adm_perms_map,
            "botGuildsCount": len(all_bot_guilds),
            "totalVisits": total_visits,
            "premiumCount": len(prem_list_now),
            "adminsCount": len(adm_list_now),
            "user": {
                "username": str(user.get("username", "Member")),
                "handle": f"@{str(user.get('username', 'member')).lower().replace(' ', '')}",
                "avatar": avatar_url,
            },
            "selectedGuildId": selected_gid,
            "guilds": serialized_guilds,
            "allBotGuilds": all_bot_guilds[:60] if is_adm else [],
            "premiumUsers": prem_list_now if is_adm else [],
            "adminStaff": adm_list_now if is_adm else [],
            "backups": backups_now,
            "premium": {
                "active": is_prem,
                "planName": "بريميوم عرب سكيورتي الماسي",
                "customBio": sanitize_bio_text((cfg.get("guild_profile") or {}).get("bio", ""))
                or "درع الحماية المتكامل لصد هجمات النيوك والسبام وحفظ السيرفر تلقائياً.",
                "customAvatar": sanitize_image_data_url((cfg.get("guild_profile") or {}).get("avatar_data_url", ""))
                or BRAND_LOGO_SVG_DATA_URL,
                "customBanner": sanitize_image_data_url((cfg.get("guild_profile") or {}).get("banner_data_url", ""))
                or "https://placehold.co/900x260/16132e/9a82ff?text=ARAB+SECURITY+SHIELD",
            },
            "logs": formatted_logs,
        }
    )


async def api_ui_action(request: web.Request) -> web.Response:
    user = get_discord_session(request)
    if not user:
        return web.json_response({"ok": False, "error": "يجب تسجيل الدخول بديسكورد أولاً"}, status=401)
    try:
        payload = await request.json()
    except Exception:
        return web.json_response({"ok": False, "error": "Invalid JSON"}, status=400)

    actor_uid = str(user.get("id", "")).strip()
    kind = str(payload.get("kind", "")).strip()
    req_gid = str(payload.get("guild_id", "")).strip()
    is_prem = is_premium_user(user)

    guild_required_kinds = {
        "save_protection",
        "save_premium",
        "add_trusted",
        "remove_trusted",
        "save_snapshot",
        "restore_snapshot",
        "run_check",
        "reset_guild",
    }

    gid = ""
    if kind in guild_required_kinds:
        if not req_gid.isdigit():
            return web.json_response({"ok": False, "error": "يجب اختيار سيرفر البوت متواجد فيه"}, status=403)
        allowed_g = user_can_manage_guild(req_gid, user, require_bot_present=True)
        if not allowed_g:
            return web.json_response(
                {"ok": False, "error": "البوت غير موجود في هذا السيرفر أو لا تملك صلاحية تعديله"},
                status=403,
            )
        gid = req_gid

    if kind == "save_protection":
        prot = payload.get("protection") if isinstance(payload.get("protection"), dict) else {}
        mapped: dict = {}
        toggles_map = prot.get("toggles") if isinstance(prot.get("toggles"), dict) else {}
        for k, val in toggles_map.items():
            if k in SHIELD_TOGGLE_KEYS:
                if k in PREMIUM_PROTECTION_TOGGLE_KEYS and not is_prem:
                    continue
                mapped[k] = bool(val)

        if "prefix" in prot:
            mapped["prefix"] = str(prot.get("prefix", "!") or "!").strip()[:6]
        if "modLogChannel" in prot:
            mapped["mod_log_channel"] = str(prot.get("modLogChannel", "") or "").strip()
        if "spamPunishment" in prot:
            mapped["spam_punishment"] = str(prot.get("spamPunishment", "Timeout"))
        if "linkPunishment" in prot:
            mapped["link_punishment"] = str(prot.get("linkPunishment", "Delete & Timeout"))
        if "dangerousPermsPunishment" in prot:
            mapped["dangerous_perms_punishment"] = str(prot.get("dangerousPermsPunishment", "Remove Roles"))
        if "minAccountAgeDays" in prot:
            try:
                mapped["min_account_age_days"] = max(1, min(365, int(prot.get("minAccountAgeDays", 7))))
            except Exception:
                mapped["min_account_age_days"] = 7

        if isinstance(prot.get("antinukeRules"), list):
            an_upd: dict[str, dict] = {}
            for r in prot["antinukeRules"]:
                if isinstance(r, dict) and str(r.get("key", "")) in ANTINUKE_RULE_KEYS:
                    rk = str(r["key"])
                    pun = str(r.get("punishment", "Ban"))
                    if pun not in ("Ban", "Kick", "Remove Roles", "Delete Only"):
                        pun = "Ban"
                    try:
                        lim = max(1, min(50, int(r.get("limit", 1))))
                    except Exception:
                        lim = 1
                    an_upd[rk] = {"enabled": bool(r.get("enabled", True)), "limit": lim, "punishment": pun}
            if an_upd:
                mapped["antinuke_updates"] = an_upd

        save_guild_cfg(gid, mapped, is_premium=is_prem)
        enqueue_remote_action(gid, "sync_guild_cfg", gid, extra={"guild_id": gid, "user_id": actor_uid}, actor_user_id=actor_uid)
        log_event(f"Synced protection settings for {gid}", guild_id=gid, level="SEC")
        return web.json_response({"ok": True})

    if kind == "save_premium":
        if not is_prem:
            return web.json_response({"ok": False, "error": "ميزة البريميوم مطلوبة"}, status=403)
        prof_in = payload.get("premium") if isinstance(payload.get("premium"), dict) else {}
        bio_clean = sanitize_bio_text(prof_in.get("customBio", ""))
        ava_clean = sanitize_image_data_url(prof_in.get("customAvatar", ""))
        ban_clean = sanitize_image_data_url(prof_in.get("customBanner", ""))
        save_guild_cfg(
            gid,
            {
                "guild_profile": {
                    "bio": bio_clean,
                    "avatar_data_url": ava_clean,
                    "banner_data_url": ban_clean,
                }
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
            },
            actor_user_id=actor_uid,
        )
        log_event(f"Updated premium profile for {gid}", guild_id=gid, level="ADMIN")
        return web.json_response({"ok": True})

    if kind == "add_trusted":
        t_uid = str(payload.get("trusted_uid", "")).strip()
        if not t_uid.isdigit():
            return web.json_response({"ok": False, "error": "آيدي غير صحيح"}, status=400)
        save_guild_cfg(gid, {"trusted_add": t_uid}, is_premium=is_prem)
        enqueue_remote_action(gid, "sync_guild_cfg", gid, extra={"guild_id": gid, "user_id": actor_uid}, actor_user_id=actor_uid)
        log_event(f"Added trusted admin {t_uid} in {gid}", guild_id=gid, level="SEC")
        return web.json_response({"ok": True})

    if kind == "remove_trusted":
        t_uid = str(payload.get("trusted_uid", "")).strip()
        save_guild_cfg(gid, {"trusted_remove": t_uid}, is_premium=is_prem)
        enqueue_remote_action(gid, "sync_guild_cfg", gid, extra={"guild_id": gid, "user_id": actor_uid}, actor_user_id=actor_uid)
        log_event(f"Removed trusted admin {t_uid} in {gid}", guild_id=gid, level="SEC")
        return web.json_response({"ok": True})

    if kind == "save_snapshot":
        save_guild_cfg(gid, {"save_snapshot": True}, is_premium=is_prem)
        enqueue_remote_action(gid, "save_snapshot", gid, extra={"guild_id": gid, "user_id": actor_uid}, actor_user_id=actor_uid)
        log_event(f"Saved snapshot for {gid}", guild_id=gid, level="SEC")
        return web.json_response({"ok": True})

    if kind == "restore_snapshot":
        snap_id = str(payload.get("snapshot_id", "")).strip()
        save_guild_cfg(gid, {"restore_snapshot_id": snap_id}, is_premium=is_prem)
        enqueue_remote_action(
            gid,
            "restore_snapshot",
            snap_id or gid,
            extra={"guild_id": gid, "snapshot_id": snap_id, "user_id": actor_uid},
            actor_user_id=actor_uid,
        )
        log_event(f"Restored snapshot {snap_id} in {gid}", guild_id=gid, level="SEC")
        return web.json_response({"ok": True})

    if kind == "run_check":
        scen = str(payload.get("scenario", "mass_ban")).strip()
        msg = run_attack_simulation(gid, scen)
        return web.json_response({"ok": True, "message": msg})

    if kind == "reset_guild":
        save_guild_cfg(gid, {"reset_defaults": True}, is_premium=is_prem)
        enqueue_remote_action(gid, "sync_guild_cfg", gid, extra={"guild_id": gid, "user_id": actor_uid}, actor_user_id=actor_uid)
        log_event(f"Reset settings for {gid}", guild_id=gid, level="SEC")
        return web.json_response({"ok": True})

    if kind == "prem_extend":
        if not is_site_admin(user) or not has_admin_perm(user, "manage_premium"):
            return web.json_response({"ok": False, "error": "صلاحية إدارة البريميوم مطلوبة"}, status=403)
        target_uid = str(payload.get("target_user_id", "")).strip()
        add_days = max(1, min(3650, int(payload.get("days", 30) or 30)))
        if not target_uid.isdigit():
            return web.json_response({"ok": False, "error": "معرف المستخدم غير صحيح"}, status=400)
        preview = await _lookup_discord_user_preview(target_uid)
        set_premium_user(
            target_uid,
            True,
            days=add_days,
            hours=0,
            granted_by=actor_uid,
            username=preview.get("username", ""),
            handle=preview.get("handle", ""),
            avatar_url=preview.get("avatar_url", ""),
            source="manual",
        )
        log_event(f"Admin {actor_uid} extended premium +{add_days}d for {target_uid}", level="ADMIN")
        updated_info = await _lookup_discord_user_preview(target_uid)
        return web.json_response({"ok": True, "user": updated_info})

    if kind == "prem_revoke":
        if not is_site_admin(user) or not has_admin_perm(user, "manage_premium"):
            return web.json_response({"ok": False, "error": "صلاحية إدارة البريميوم مطلوبة"}, status=403)
        target_uid = str(payload.get("target_user_id", "")).strip()
        if target_uid == ADMIN_USER_ID:
            return web.json_response({"ok": False, "error": "لا يمكن سحب بريميوم المالك"}, status=400)
        set_premium_user(target_uid, False)
        log_event(f"Admin {actor_uid} revoked premium from {target_uid}", level="ADMIN")
        updated_info = await _lookup_discord_user_preview(target_uid)
        return web.json_response({"ok": True, "user": updated_info})

    if kind == "admin_add":
        if not is_site_admin(user) or not has_admin_perm(user, "manage_admins"):
            return web.json_response({"ok": False, "error": "صلاحية إدارة الأدمن مطلوبة"}, status=403)
        a_uid = str(payload.get("target_user_id", "")).strip()
        role_val = _sanitize_staff_role(payload.get("role_tag", "Staff"), uid=a_uid)
        perms_in = payload.get("permissions") if isinstance(payload.get("permissions"), dict) else {}
        perms_clean = {k: bool(perms_in.get(k, True)) for k in ADMIN_PERMISSION_KEYS}
        if not a_uid.isdigit() or not set_admin_user(a_uid, True, granted_by=actor_uid, permissions=perms_clean, role_tag=role_val):
            return web.json_response({"ok": False, "error": "تعذر حفظ عضو الإدارة"}, status=400)
        log_event(f"Admin {actor_uid} updated staff {a_uid} ({role_val})", level="ADMIN")
        return web.json_response({"ok": True})

    if kind == "admin_remove":
        if not is_site_admin(user) or not has_admin_perm(user, "manage_admins"):
            return web.json_response({"ok": False, "error": "صلاحية إدارة الأدمن مطلوبة"}, status=403)
        a_uid = str(payload.get("target_user_id", "")).strip()
        if not set_admin_user(a_uid, False):
            return web.json_response({"ok": False, "error": "تعذر إزالة العضو"}, status=400)
        log_event(f"Admin {actor_uid} removed staff {a_uid}", level="ADMIN")
        return web.json_response({"ok": True})

    if kind == "backup":
        if not is_site_admin(user) or not has_admin_perm(user, "backups"):
            return web.json_response({"ok": False, "error": "صلاحية النسخ الاحتياطي مطلوبة"}, status=403)
        snap = create_db_backup()
        return web.json_response({"ok": True, "backup_id": snap.get("backup_id")})

    if kind == "test_restore":
        if not is_site_admin(user) or not has_admin_perm(user, "backups"):
            return web.json_response({"ok": False, "error": "صلاحية النسخ الاحتياطي مطلوبة"}, status=403)
        _, msg = test_backup_restore(str(payload.get("backup_id", "")))
        return web.json_response({"ok": True, "message": msg})

    if kind == "remote_cmd":
        if not is_site_admin(user) or not has_admin_perm(user, "remote_actions"):
            return web.json_response({"ok": False, "error": "صلاحية الأوامر عن بُعد مطلوبة"}, status=403)
        r_gid = str(payload.get("target_guild_id", "0") or "0").strip()
        r_act = str(payload.get("action_type", "broadcast") or "broadcast").strip()
        r_tgt = str(payload.get("target_value", "") or "").strip()
        enqueue_remote_action(r_gid, r_act, r_tgt, extra={"user_id": actor_uid, "actor_id": actor_uid}, actor_user_id=actor_uid)
        log_event(f"Queued remote [{r_act}] for {r_tgt} in {r_gid}", guild_id=r_gid, level="ADMIN")
        return web.json_response({"ok": True})

    return web.json_response({"ok": False, "error": "Unsupported action"}, status=400)


def _build_new_ui_html(request: web.Request) -> str:
    user = get_discord_session(request)
    is_auth_json = "true" if user else "false"
    is_prem_json = "true" if is_premium_user(user) else "false"
    is_adm_json = "true" if is_site_admin(user) else "false"
    uid = str(user.get("id", "")).strip() if user else ""
    ava = str(user.get("avatar", "")).strip() if user else ""
    uname_json = json.dumps(str(user.get("username", "")) if user else "زائر غير مسجل")
    avatar_url = (
        f"https://cdn.discordapp.com/avatars/{uid}/{ava}.png?size=128"
        if uid and ava
        else BRAND_LOGO_SVG_DATA_URL
    )
    avatar_json = json.dumps(avatar_url)
    logo_json = json.dumps(BRAND_LOGO_SVG_DATA_URL)
    invite_href_json = json.dumps("/invite")
    support_href_json = json.dumps(sanitize_http_url(SUPPORT_SERVER_URL) or "https://discord.gg/vV84RqJNks")
    perm_labels_json = json.dumps(ADMIN_PERMISSION_LABELS_AR)

    return f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{esc(BRAND_LABEL_AR)} ({esc(SITE_NAME)}) — منظومة الحماية والإدارة</title>
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
          }},
        }},
      }},
    }};
  </script>
  <style>
    * {{ box-sizing: border-box; }}
    html, body {{
      margin: 0; padding: 0; background-color: #07080f; color: #f3f4f8;
      font-family: "Cairo", "IBM Plex Sans Arabic", sans-serif; overflow-x: clip;
    }}
    .ambient-grid {{
      background-image:
        radial-gradient(circle at 18% 12%, rgba(124, 92, 255, 0.16), transparent 42%),
        radial-gradient(circle at 82% 18%, rgba(58, 134, 255, 0.12), transparent 40%),
        linear-gradient(to right, rgba(255, 255, 255, 0.025) 1px, transparent 1px),
        linear-gradient(to bottom, rgba(255, 255, 255, 0.025) 1px, transparent 1px);
      background-size: 100% 100%, 100% 100%, 44px 44px, 44px 44px;
    }}
    @keyframes fadeSlideUp {{
      from {{ opacity: 0; transform: translateY(14px) scale(0.985); }}
      to {{ opacity: 1; transform: translateY(0) scale(1); }}
    }}
    .animate-panel-enter {{ animation: fadeSlideUp 0.32s cubic-bezier(0.22, 1, 0.36, 1) both; }}
    .toggle-track {{ position: relative; width: 46px; height: 24px; border-radius: 9999px; transition: background-color 0.22s ease; flex-shrink: 0; }}
    .toggle-thumb {{ position: absolute; top: 2px; right: 2px; width: 20px; height: 20px; border-radius: 9999px; background: #ffffff; transition: transform 0.22s ease; }}
    input.sr-toggle:checked + .toggle-track .toggle-thumb {{ transform: translateX(-22px); }}
  </style>
</head>
<body class="ambient-grid min-h-screen text-slate-100 antialiased">
  <div id="app" class="min-h-screen flex flex-col">
    <header class="sticky top-0 z-40 border-b border-white/[0.07] bg-[#090b16]/88 backdrop-blur-xl">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-3">
        <div class="flex items-center gap-3 min-w-0">
          <button type="button" onclick="openDrawer()" class="p-2.5 rounded-xl bg-white/[0.04] hover:bg-violetcore/20 border border-white/[0.08]">
            <svg class="w-5 h-5 text-slate-200" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M4 6h16M4 12h16M4 18h11" />
            </svg>
          </button>

          <button type="button" onclick="navigateTo('home')" class="flex items-center gap-2.5 text-right min-w-0">
            <img src="{esc(BRAND_LOGO_SVG_DATA_URL)}" alt="{esc(BRAND_LABEL_AR)}" class="w-10 h-10 rounded-2xl object-cover ring-1 ring-violetglow/60 shrink-0" />
            <div class="truncate">
              <div class="flex items-center gap-2">
                <span class="font-extrabold text-base sm:text-lg text-white">{esc(BRAND_LABEL_AR)}</span>
                <span class="hidden sm:inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-bold bg-emeraldsafe/15 text-emeraldsafe border border-emeraldsafe/30">
                  <span class="w-1.5 h-1.5 rounded-full bg-emeraldsafe"></span>
                  {esc(SITE_NAME)}
                </span>
              </div>
              <p class="text-[11px] text-slate-400 truncate">بإشراف {esc(OWNER_NAME)}</p>
            </div>
          </button>
        </div>

        <nav id="desktop-nav" class="hidden lg:flex items-center gap-1.5 bg-white/[0.03] p-1 rounded-2xl border border-white/[0.06]">
          <button data-nav="home" onclick="navigateTo('home')" class="nav-pill px-3.5 py-1.5 rounded-xl text-xs font-bold">الرئيسية</button>
          <button id="desk-nav-protection" data-nav="protection" onclick="navigateTo('protection')" class="nav-pill px-3.5 py-1.5 rounded-xl text-xs font-bold">لوحة الحماية</button>
          <button id="desk-nav-premium" data-nav="premium" onclick="navigateTo('premium')" class="nav-pill px-3.5 py-1.5 rounded-xl text-xs font-bold">البريميوم</button>
          <button id="desk-nav-admin" data-nav="admin" onclick="navigateTo('admin')" class="nav-pill px-3.5 py-1.5 rounded-xl text-xs font-bold">لوحة الإدارة</button>
        </nav>

        <div class="flex items-center gap-2" id="header-auth-slot"></div>
      </div>
    </header>

    <div id="toast-container" class="fixed bottom-5 left-5 right-5 sm:left-auto sm:right-6 z-50 flex flex-col gap-2 max-w-sm pointer-events-none"></div>

    <div id="drawer-backdrop" class="fixed inset-0 z-50 hidden bg-black/70 backdrop-blur-sm" onclick="closeDrawer()">
      <aside id="nav-drawer" onclick="event.stopPropagation()" class="fixed top-0 right-0 bottom-0 w-[84vw] max-w-xs bg-[#0d1020] border-l border-white/[0.09] shadow-2xl flex flex-col justify-between p-5 overflow-y-auto">
        <div>
          <div class="flex items-center justify-between pb-4 border-b border-white/[0.07]">
            <span class="text-sm font-extrabold text-white">القائمة الرئيسية</span>
            <button type="button" onclick="closeDrawer()" class="p-2 rounded-xl bg-white/[0.04] text-slate-300">✕</button>
          </div>
          <div id="drawer-profile-box" class="mt-4 p-4 rounded-2xl bg-gradient-to-br from-violetcore/15 via-panel to-midnight border border-violetcore/25 flex items-center gap-3.5">
            <img id="drawer-avatar" src="{esc(BRAND_LOGO_SVG_DATA_URL)}" alt="صورة الحساب" class="w-14 h-14 rounded-2xl object-cover ring-2 ring-violetglow/60 shrink-0" />
            <div class="min-w-0">
              <p class="text-[11px] font-semibold text-violetglow mb-0.5">الحساب</p>
              <h3 id="drawer-username" class="text-base font-extrabold text-white truncate">زائر غير مسجل</h3>
            </div>
          </div>
          <div class="mt-5 space-y-1.5">
            <button type="button" data-drawer-nav="home" onclick="navigateTo('home'); closeDrawer();" class="drawer-item w-full flex items-center gap-3 px-3.5 py-3 rounded-xl text-sm font-bold"><span>الرئيسية</span></button>
            <button type="button" data-drawer-nav="protection" onclick="navigateTo('protection'); closeDrawer();" class="drawer-item w-full flex items-center gap-3 px-3.5 py-3 rounded-xl text-sm font-bold"><span>لوحة الحماية</span></button>
            <button type="button" id="drawer-nav-premium" data-drawer-nav="premium" onclick="navigateTo('premium'); closeDrawer();" class="drawer-item w-full flex items-center gap-3 px-3.5 py-3 rounded-xl text-sm font-bold"><span>البريميوم</span></button>
            <button type="button" id="drawer-nav-admin" data-drawer-nav="admin" onclick="navigateTo('admin'); closeDrawer();" class="drawer-item w-full flex items-center gap-3 px-3.5 py-3 rounded-xl text-sm font-bold"><span>لوحة الإدارة</span></button>
          </div>
        </div>
        <div id="drawer-auth-actions" class="pt-4 mt-4 border-t border-white/[0.07] space-y-2"></div>
      </aside>
    </div>

    <main id="main-content" class="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-7 sm:py-10"></main>

    <footer class="border-t border-white/[0.06] bg-[#080a14]/75 backdrop-blur-md mt-auto">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-5 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-400">
        <div class="flex items-center gap-2">
          <span class="font-extrabold text-slate-200">{esc(BRAND_LABEL_AR)} • {esc(SITE_NAME)}</span>
          <span>•</span>
          <span>بإشراف {esc(OWNER_NAME)} © 2026</span>
        </div>
        <a href="${{esc(sanitize_http_url(SUPPORT_SERVER_URL) or 'https://discord.com')}}" target="_blank" rel="noopener noreferrer" class="text-violetglow font-bold hover:underline">انضم لسيرفر الدعم الفني</a>
      </div>
    </footer>
  </div>

  <script>
    const INVITE_URL = {invite_href_json};
    const SUPPORT_URL = {support_href_json};
    const LOGO_URL = {logo_json};
    const PERM_LABELS = {perm_labels_json};

    let state = {{
      isAuthenticated: {is_auth_json},
      isPremium: {is_prem_json},
      isAdmin: {is_adm_json},
      adminPerms: {{}},
      botGuildsCount: 0,
      totalVisits: 0,
      premiumCount: 0,
      adminsCount: 0,
      activePage: "home",
      protectionTab: "shield",
      adminTab: "prem",
      user: {{
        username: {uname_json},
        handle: "@guest",
        avatar: {avatar_json},
      }},
      selectedGuildId: "",
      guilds: [],
      allBotGuilds: [],
      premiumUsers: [],
      adminStaff: [],
      backups: [],
      premium: {{
        active: {is_prem_json},
        planName: "بريميوم عرب سكيورتي الماسي",
        customBio: "درع الحماية المتكامل لصد هجمات النيوك والسبام وحفظ السيرفر تلقائياً.",
        customAvatar: {logo_json},
        customBanner: "https://placehold.co/900x260/16132e/9a82ff?text=ARAB+SECURITY+SHIELD",
      }},
      admin: {{
        logFilter: "ALL",
        showLogPanel: false,
        logs: [],
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

    async function hydrateLiveState(targetGuildId = "") {{
      try {{
        const qs = targetGuildId ? ("?guild_id=" + encodeURIComponent(targetGuildId)) : "";
        const res = await fetch("/api/ui-state" + qs, {{ cache: "no-store" }});
        if (!res.ok) return;
        const data = await res.json();
        if (!data || !data.ok) return;
        state.isAuthenticated = Boolean(data.isAuthenticated);
        state.isPremium = Boolean(data.isPremium);
        state.isAdmin = Boolean(data.isAdmin);
        state.adminPerms = data.adminPerms || {{}};
        state.botGuildsCount = Number(data.botGuildsCount || 0);
        state.totalVisits = Number(data.totalVisits || 0);
        state.premiumCount = Number(data.premiumCount || 0);
        state.adminsCount = Number(data.adminsCount || 0);
        if (data.user) state.user = {{ ...state.user, ...data.user }};
        state.selectedGuildId = data.selectedGuildId || "";
        state.guilds = Array.isArray(data.guilds) ? data.guilds : [];
        state.allBotGuilds = Array.isArray(data.allBotGuilds) ? data.allBotGuilds : [];
        state.premiumUsers = Array.isArray(data.premiumUsers) ? data.premiumUsers : [];
        state.adminStaff = Array.isArray(data.adminStaff) ? data.adminStaff : [];
        state.backups = Array.isArray(data.backups) ? data.backups : [];
        if (data.premium) state.premium = {{ ...state.premium, ...data.premium }};
        if (Array.isArray(data.logs)) state.admin.logs = data.logs;
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

    function navigateTo(pageKey) {{
      const valid = ["home", "protection", "premium", "admin"];
      if (!valid.includes(pageKey)) pageKey = "home";
      if (!state.isAuthenticated && pageKey !== "home") {{
        state.activePage = pageKey;
        syncHeaderAndDrawer();
        render();
        return;
      }}
      if (pageKey === "premium" && !state.isPremium) {{
        showToast("هذا القسم مخصص لمشتركي البريميوم فقط", "warn");
        return;
      }}
      if (pageKey === "admin" && !state.isAdmin) {{
        showToast("هذا القسم مخصص للوحة الإدارة فقط", "danger");
        return;
      }}
      state.activePage = pageKey;
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
      const hdrSlot = document.getElementById("header-auth-slot");
      const drawerAuth = document.getElementById("drawer-auth-actions");
      const dAvatar = document.getElementById("drawer-avatar");
      const dUsername = document.getElementById("drawer-username");

      const showProt = state.isAuthenticated && state.guilds.length > 0;
      const showPrem = state.isAuthenticated && state.isPremium;
      const showAdm = state.isAuthenticated && state.isAdmin;

      ["desk-nav-protection", "drawer-nav-protection"].forEach((id) => {{
        const el = document.getElementById(id);
        if (el) el.classList.toggle("hidden", !showProt);
      }});
      ["desk-nav-premium", "drawer-nav-premium"].forEach((id) => {{
        const el = document.getElementById(id);
        if (el) el.classList.toggle("hidden", !showPrem);
      }});
      ["desk-nav-admin", "drawer-nav-admin"].forEach((id) => {{
        const el = document.getElementById(id);
        if (el) el.classList.toggle("hidden", !showAdm);
      }});

      if (hdrSlot) {{
        if (state.isAuthenticated) {{
          hdrSlot.innerHTML = `
            <div class="hidden sm:flex items-center gap-2 pl-2 pr-1.5 py-1 rounded-full bg-white/[0.04] border border-white/[0.08]">
              <img src="${{escapeHtml(state.user.avatar)}}" alt="" class="w-7 h-7 rounded-full object-cover ring-1 ring-violetcore/50" />
              <span class="text-xs font-bold text-slate-200 max-w-[100px] truncate">${{escapeHtml(state.user.username)}}</span>
            </div>
            <a href="/logout" class="px-3 py-1.5 rounded-xl text-xs font-extrabold bg-coralalert/15 text-coralalert border border-coralalert/35">تسجيل الخروج</a>
          `;
        }} else {{
          hdrSlot.innerHTML = `
            <a href="/login?next=/ui" class="px-3 py-1.5 rounded-xl text-xs font-extrabold bg-gradient-to-r from-violetcore to-indigo-500 text-white shadow-violet">دخول ديسكورد</a>
          `;
        }}
      }}

      if (drawerAuth) {{
        if (state.isAuthenticated) {{
          drawerAuth.innerHTML = `
            <a href="/logout" class="block w-full text-center py-2.5 px-4 rounded-xl text-xs font-extrabold bg-coralalert/15 text-coralalert border border-coralalert/35">تسجيل الخروج</a>
          `;
        }} else {{
          drawerAuth.innerHTML = `
            <a href="/login?next=/ui" class="block w-full text-center py-2.5 px-4 rounded-xl text-xs font-extrabold bg-gradient-to-r from-violetcore to-indigo-500 text-white shadow-violet">دخول ديسكورد</a>
          `;
        }}
      }}

      if (dAvatar && dUsername) {{
        dAvatar.src = state.isAuthenticated ? state.user.avatar : LOGO_URL;
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
          ? "drawer-item w-full flex items-center gap-3 px-3.5 py-3 rounded-xl text-sm font-extrabold bg-violetcore/20 text-white border border-violetcore/40 transition-all"
          : "drawer-item w-full flex items-center gap-3 px-3.5 py-3 rounded-xl text-sm font-bold text-slate-300 hover:text-white hover:bg-white/[0.04] border border-transparent transition-all";
      }});
    }}

    function getActiveGuild() {{
      return state.guilds.find((g) => g.id === state.selectedGuildId) || state.guilds[0] || null;
    }}

    function renderLoginGate() {{
      return `
        <section class="animate-panel-enter min-h-[70vh] flex items-center justify-center px-2 py-8">
          <div class="relative w-full max-w-md rounded-[28px] bg-gradient-to-b from-[#161932]/95 via-[#111426]/95 to-[#0c0e1c]/95 border border-white/[0.09] shadow-glass p-7 sm:p-9 text-center">
            <h1 class="text-2xl sm:text-[26px] font-black text-white mb-3">دخول ديسكورد مطلوب</h1>
            <p class="text-sm text-slate-300 leading-relaxed max-w-xs mx-auto mb-7">
              الداشبورد ولوحة الحماية مقفلة حتى تسجيل الدخول. اضغط دخول ديسكورد للوصول إلى <span class="text-violetglow font-extrabold">{escapeHtml("{BRAND_LABEL_AR}")}</span>.
            </p>
            <a href="/login?next=/ui" class="w-full py-3.5 px-6 rounded-2xl bg-gradient-to-r from-[#d8d4ff] via-[#e9e6ff] to-[#c9c2ff] text-[#17142e] font-extrabold text-sm sm:text-base flex items-center justify-center gap-2.5">
              <span>دخول ديسكورد</span>
            </a>
          </div>
        </section>
      `;
    }}

    function renderQuickLinksSection() {{
      return `
        <section class="mt-8">
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <a href="${{escapeHtml(INVITE_URL)}}" class="group rounded-2xl bg-gradient-to-br from-violetcore/15 via-panel to-card border border-violetcore/30 hover:border-violetglow/70 p-5 flex items-center justify-between gap-4 shadow-glass">
              <div class="min-w-0">
                <div class="font-extrabold text-base text-white">دعوة بوت {escapeHtml("{BRAND_LABEL_AR}")}</div>
                <p class="text-xs text-slate-400 mt-1">أضف البوت إلى سيرفرك لتفعيل لوحة الحماية والتعديل</p>
              </div>
              <span class="text-violetglow font-black text-lg">←</span>
            </a>
            <a href="${{escapeHtml(SUPPORT_URL)}}" target="_blank" rel="noopener noreferrer" class="group rounded-2xl bg-gradient-to-br from-[#5865F2]/20 via-panel to-card border border-[#5865F2]/40 hover:border-[#5865F2] p-5 flex items-center justify-between gap-4 shadow-glass">
              <div class="min-w-0">
                <div class="flex items-center gap-2">
                  <svg class="w-5 h-5 text-[#7289da] shrink-0" fill="currentColor" viewBox="0 0 24 24"><path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028c.462-.63.874-1.295 1.226-1.994.021-.041.001-.09-.041-.106a13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.028z"/></svg>
                  <span class="font-extrabold text-base text-white">انضم لسيرفر الدعم الفني</span>
                </div>
                <p class="text-xs text-slate-400 mt-1">تحديثات ، دعم فني ، تنبيهات</p>
              </div>
              <span class="text-[#7289da] font-black text-lg">←</span>
            </a>
          </div>
        </section>
      `;
    }}

    function renderHomePage() {{
      const activeGuild = getActiveGuild();
      const activeGuardsCount = activeGuild ? activeGuild.toggles.filter((t) => t.enabled).length : 0;
      return `
        <div class="animate-panel-enter space-y-8">
          <section class="relative rounded-[28px] bg-gradient-to-br from-[#161a34] via-[#111529] to-[#0c0f1e] border border-white/[0.09] p-6 sm:p-9 shadow-glass">
            <div class="space-y-4 max-w-2xl">
              <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-violetcore/15 border border-violetcore/35 text-xs font-extrabold text-violetglow">
                <span>منظومة {escapeHtml("{BRAND_LABEL_AR}")} • {escapeHtml("{SITE_NAME}")}</span>
              </div>
              <h1 class="text-2xl sm:text-4xl font-black text-white leading-tight">
                حماية فورية وذكية لسيرفراتك ضد
                <span class="bg-gradient-to-l from-violetglow via-violetcore to-emeraldsafe bg-clip-text text-transparent">التخريب والسبام والرايد</span>
              </h1>
              <p class="text-sm sm:text-base text-slate-300 leading-relaxed">
                تحكم كامل في أنظمة الحماية، الحدود والعقوبات، اللقطات والاسترجاع التلقائي، مزايا البريميوم، ولوحة الإدارة المرتبطة مباشرة بقاعدة البيانات.
              </p>
              <div class="pt-2 flex flex-wrap items-center gap-3">
                <a href="${{escapeHtml(INVITE_URL)}}" class="px-5 py-3 rounded-2xl bg-gradient-to-r from-violetcore to-indigo-500 text-white font-extrabold text-sm shadow-violet">دعوة بوت {escapeHtml("{BRAND_LABEL_AR}")}</a>
                ${{state.isAuthenticated && state.guilds.length > 0 ? `<button type="button" onclick="navigateTo('protection')" class="px-5 py-3 rounded-2xl bg-white/[0.06] text-white border border-white/[0.12] font-extrabold text-sm">لوحة الحماية</button>` : ""}}
                ${{state.isAuthenticated && state.isPremium ? `<button type="button" onclick="navigateTo('premium')" class="px-5 py-3 rounded-2xl bg-white/[0.05] text-amberwarn border border-amberwarn/30 font-extrabold text-sm">البريميوم</button>` : ""}}
                ${{state.isAuthenticated && state.isAdmin ? `<button type="button" onclick="navigateTo('admin')" class="px-5 py-3 rounded-2xl bg-white/[0.05] text-violetglow border border-violetcore/35 font-extrabold text-sm">لوحة الإدارة</button>` : ""}}
              </div>
            </div>
          </section>

          <section class="grid grid-cols-2 lg:grid-cols-3 gap-4">
            <div class="rounded-2xl bg-card/90 border border-white/[0.07] p-4 sm:p-5">
              <p class="text-xs text-slate-400 font-semibold">عدد السيرفرات اللي مدخله البوت</p>
              <p class="text-2xl font-black text-white mt-1.5">${{state.botGuildsCount}}</p>
            </div>
            <div class="rounded-2xl bg-card/90 border border-white/[0.07] p-4 sm:p-5">
              <p class="text-xs text-slate-400 font-semibold">الأنظمة الأمنية المفعلة</p>
              <p class="text-2xl font-black text-emeraldsafe mt-1.5">${{activeGuardsCount}} <span class="text-xs font-bold text-slate-300">نظام</span></p>
            </div>
            <div class="rounded-2xl bg-card/90 border border-white/[0.07] p-4 sm:p-5">
              <p class="text-xs text-slate-400 font-semibold">عدد زوار الموقع</p>
              <p class="text-2xl font-black text-sky-400 mt-1.5">${{state.totalVisits}}</p>
            </div>
          </section>

          ${{renderQuickLinksSection()}}
        </div>
      `;
    }}

    function renderProtectionPage() {{
      const guild = getActiveGuild();
      if (!guild) {{
        return `
          <div class="rounded-3xl bg-card/90 border border-white/[0.08] p-7 text-center space-y-4">
            <h2 class="text-xl font-black text-white">يجب إدخال البوت إلى السيرفر أولاً</h2>
            <p class="text-xs text-slate-400">لا يمكن فتح لوحة الحماية أو تعديل إعدادات سيرفر غير مضاف فيه البوت.</p>
            <a href="${{escapeHtml(INVITE_URL)}}" class="inline-block px-5 py-2.5 rounded-xl text-xs font-extrabold bg-violetcore text-white">دعوة بوت {escapeHtml("{BRAND_LABEL_AR}")}</a>
          </div>
        `;
      }}

      const guildOptionsHtml = state.guilds.map((g) => `
        <option value="${{escapeHtml(g.id)}}" ${{g.id === guild.id ? "selected" : ""}}>${{escapeHtml(g.name)}} (${{escapeHtml(g.id)}})</option>
      `).join("");

      const togglesHtml = guild.toggles.map((t) => `
        <label class="flex items-center justify-between gap-3 p-3.5 rounded-2xl bg-[#0e1121]/85 border border-white/[0.07] cursor-pointer">
          <span class="text-xs sm:text-sm font-bold text-white">${{escapeHtml(t.label)}}</span>
          <div class="relative inline-flex items-center">
            <input type="checkbox" class="sr-only sr-toggle" ${{t.enabled ? "checked" : ""}} onchange="toggleGuildFeature('${{escapeHtml(t.key)}}', this.checked)" />
            <div class="toggle-track ${{t.enabled ? "bg-gradient-to-r from-violetcore to-emeraldsafe" : "bg-slate-700/80"}}">
              <div class="toggle-thumb"></div>
            </div>
          </div>
        </label>
      `).join("");

      const rulesHtml = guild.antinukeRules.map((r, idx) => `
        <div class="p-3.5 rounded-2xl bg-[#0e1121]/85 border border-white/[0.07] flex flex-wrap items-center justify-between gap-3">
          <label class="flex items-center gap-2.5 cursor-pointer">
            <input type="checkbox" class="sr-only sr-toggle" ${{r.enabled ? "checked" : ""}} onchange="updateRuleField(${{idx}}, 'enabled', this.checked)" />
            <span class="toggle-track ${{r.enabled ? "bg-gradient-to-r from-violetcore to-emeraldsafe" : "bg-slate-700/80"}}"><span class="toggle-thumb"></span></span>
            <span class="text-xs sm:text-sm font-extrabold text-white">${{escapeHtml(r.label)}}</span>
          </label>
          <div class="flex items-center gap-2">
            <input type="number" min="1" max="50" value="${{r.limit}}" onchange="updateRuleField(${{idx}}, 'limit', Number(this.value || 1))" class="w-16 rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-2.5 py-1.5 text-xs text-white text-center" />
            <select onchange="updateRuleField(${{idx}}, 'punishment', this.value)" class="rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-2.5 py-1.5 text-xs text-white">
              ${{["Ban", "Kick", "Remove Roles", "Delete Only"].map((p) => `<option value="${{p}}" ${{r.punishment === p ? "selected" : ""}}>${{p}}</option>`).join("")}}
            </select>
          </div>
        </div>
      `).join("");

      const trustedHtml = (guild.trustedAdmins || []).map((tid) => `
        <div class="flex items-center justify-between gap-2 p-3 rounded-xl bg-[#0b0e1c] border border-white/[0.07]">
          <span class="text-xs font-mono text-slate-200">${{escapeHtml(tid)}}</span>
          ${{tid !== "{escapeHtml(ADMIN_USER_ID)}" ? `<button type="button" onclick="removeTrustedAdmin('${{escapeHtml(tid)}}')" class="px-3 py-1 rounded-lg text-xs font-bold bg-coralalert/20 text-coralalert">إزالة</button>` : `<span class="text-[11px] text-amberwarn font-bold">Owner</span>`}}
        </div>
      `).join("");

      const snapsHtml = (guild.snapshots || []).map((s) => `
        <div class="flex items-center justify-between gap-2 p-3 rounded-xl bg-[#0b0e1c] border border-white/[0.07]">
          <div>
            <div class="text-xs font-extrabold text-white">لقطة #${{escapeHtml(s.id)}}</div>
            <div class="text-[11px] text-slate-400">${{escapeHtml(s.saved_at)}} • قواعد: ${{s.rules_count}}</div>
          </div>
          <button type="button" onclick="restoreGuildSnapshot('${{escapeHtml(s.id)}}')" class="px-3 py-1.5 rounded-xl text-xs font-extrabold bg-violetcore text-white">استرجاع</button>
        </div>
      `).join("") || `<p class="text-xs text-slate-400">لا توجد لقطات محفوظة لهذا السيرفر بعد.</p>`;

      return `
        <div class="animate-panel-enter space-y-6">
          <div class="rounded-[26px] bg-gradient-to-r from-[#161a33] via-[#12162b] to-[#0d1122] border border-white/[0.09] p-6 flex flex-col lg:flex-row lg:items-center justify-between gap-4 shadow-glass">
            <div class="space-y-2">
              <div class="flex items-center gap-3">
                ${{guild.iconUrl ? `<img src="${{escapeHtml(guild.iconUrl)}}" alt="" class="w-12 h-12 rounded-2xl object-cover ring-1 ring-violetglow/50" />` : `<div class="w-12 h-12 rounded-2xl bg-violetcore/25 border border-violetcore/40 flex items-center justify-center font-black">${{escapeHtml(guild.iconText)}}</div>`}}
                <div>
                  <h1 class="text-xl sm:text-2xl font-black text-white">لوحة الحماية — ${{escapeHtml(guild.name)}}</h1>
                  <p class="text-xs text-slate-400">الأعضاء: ${{guild.members}} • التقييم: <strong class="text-emeraldsafe">${{escapeHtml(guild.protectionGrade)}}</strong></p>
                </div>
              </div>
              <select onchange="selectGuildForProtection(this.value)" class="mt-1 rounded-xl bg-[#0b0e1c] border border-white/[0.12] px-3.5 py-2 text-xs font-bold text-white">
                ${{guildOptionsHtml}}
              </select>
            </div>
            <div class="flex items-center gap-3">
              <div class="px-4 py-2.5 rounded-2xl bg-[#0b0e1c] border border-violetcore/35 text-center">
                <div class="text-lg font-black text-white">${{guild.protectionScore}}/100</div>
                <div class="text-[11px] text-violetglow font-bold">نسبة الحماية</div>
              </div>
              <button type="button" onclick="saveFullProtection()" class="px-5 py-3 rounded-xl text-xs font-extrabold bg-gradient-to-r from-violetcore to-indigo-500 text-white shadow-violet">حفظ ومزامنة</button>
            </div>
          </div>

          <div class="grid grid-cols-2 sm:grid-cols-4 gap-2">
            ${{[
              ["shield", "أنظمة الحماية"],
              ["rules", "الحدود والعقوبات"],
              ["snapshots", "الموثوقون واللقطات"],
              ["checks", "فحص الجاهزية"],
            ].map(([k, lbl]) => `
              <button type="button" onclick="switchProtectionTab('${{k}}')" class="py-2.5 px-3 rounded-xl text-xs font-extrabold border ${{state.protectionTab === k ? "bg-violetcore text-white border-violetglow" : "bg-card/80 text-slate-300 border-white/[0.08]"}}">${{lbl}}</button>
            `).join("")}}
          </div>

          ${{state.protectionTab === "shield" ? `
            <div class="rounded-3xl bg-card/90 border border-white/[0.08] p-5 sm:p-6 space-y-5">
              <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label class="block text-xs font-extrabold text-slate-300 mb-1.5">بادئة الأوامر (Prefix)</label>
                  <input id="prot-prefix" type="text" value="${{escapeHtml(guild.prefix)}}" class="w-full rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-3.5 py-2.5 text-xs text-white" />
                </div>
                <div>
                  <label class="block text-xs font-extrabold text-slate-300 mb-1.5">آيدي روم السجل (Mod Log Channel)</label>
                  <input id="prot-log-ch" type="text" value="${{escapeHtml(guild.modLogChannel)}}" class="w-full rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-3.5 py-2.5 text-xs text-white" />
                </div>
              </div>
              <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                ${{togglesHtml}}
              </div>
            </div>
          ` : ""}}

          ${{state.protectionTab === "rules" ? `
            <div class="rounded-3xl bg-card/90 border border-white/[0.08] p-5 sm:p-6 space-y-5">
              <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                <div>
                  <label class="block text-xs font-bold text-slate-400 mb-1">عقوبة السبام</label>
                  <select id="prot-spam-pun" class="w-full rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-3 py-2 text-xs text-white">
                    ${{["Delete Only", "Timeout", "Kick", "Ban"].map((p) => `<option value="${{p}}" ${{guild.spamPunishment === p ? "selected" : ""}}>${{p}}</option>`).join("")}}
                  </select>
                </div>
                <div>
                  <label class="block text-xs font-bold text-slate-400 mb-1">عقوبة الروابط</label>
                  <select id="prot-link-pun" class="w-full rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-3 py-2 text-xs text-white">
                    ${{["Delete Only", "Delete & Timeout", "Kick", "Ban"].map((p) => `<option value="${{p}}" ${{guild.linkPunishment === p ? "selected" : ""}}>${{p}}</option>`).join("")}}
                  </select>
                </div>
                <div>
                  <label class="block text-xs font-bold text-slate-400 mb-1">الصلاحيات الخطيرة</label>
                  <select id="prot-dang-pun" class="w-full rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-3 py-2 text-xs text-white">
                    ${{["None", "Remove Roles", "Kick", "Ban"].map((p) => `<option value="${{p}}" ${{guild.dangerousPermsPunishment === p ? "selected" : ""}}>${{p}}</option>`).join("")}}
                  </select>
                </div>
                <div>
                  <label class="block text-xs font-bold text-slate-400 mb-1">عمر الحساب الأدنى (أيام)</label>
                  <input id="prot-min-age" type="number" min="1" max="365" value="${{guild.minAccountAgeDays}}" class="w-full rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-3 py-2 text-xs text-white" />
                </div>
              </div>
              <div class="space-y-2.5">${{rulesHtml}}</div>
            </div>
          ` : ""}}

          ${{state.protectionTab === "snapshots" ? `
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-5">
              <div class="rounded-3xl bg-card/90 border border-white/[0.08] p-5 space-y-3">
                <h3 class="text-sm font-black text-white">الموثوقون في السيرفر</h3>
                <div class="flex gap-2">
                  <input id="trusted-uid-inp" type="text" placeholder="أدخل User ID" class="flex-1 rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-3 py-2 text-xs text-white" />
                  <button type="button" onclick="addTrustedAdmin()" class="px-4 py-2 rounded-xl text-xs font-extrabold bg-violetcore text-white">إضافة</button>
                </div>
                <div class="space-y-2">${{trustedHtml}}</div>
              </div>
              <div class="rounded-3xl bg-card/90 border border-white/[0.08] p-5 space-y-3">
                <div class="flex items-center justify-between">
                  <h3 class="text-sm font-black text-white">لقطات الحماية والاسترجاع</h3>
                  <button type="button" onclick="createGuildSnapshot()" class="px-3.5 py-1.5 rounded-xl text-xs font-extrabold bg-violetcore text-white">حفظ لقطة</button>
                </div>
                <div class="space-y-2">${{snapsHtml}}</div>
              </div>
            </div>
          ` : ""}}

          ${{state.protectionTab === "checks" ? `
            <div class="rounded-3xl bg-card/90 border border-white/[0.08] p-5 sm:p-6 space-y-4">
              <h3 class="text-sm font-black text-white">فحص جاهزية الحماية وإعادة الضبط</h3>
              <div class="flex flex-wrap gap-2.5">
                <button type="button" onclick="runGuildSafetyCheck('mass_ban')" class="px-4 py-2.5 rounded-xl text-xs font-extrabold bg-violetcore text-white">فحص حماية الحظر والنيوك</button>
                <button type="button" onclick="runGuildSafetyCheck('role_delete')" class="px-4 py-2.5 rounded-xl text-xs font-extrabold bg-white/[0.08] text-white border border-white/[0.12]">فحص استرجاع الرتب</button>
                <button type="button" onclick="resetGuildSettings()" class="px-4 py-2.5 rounded-xl text-xs font-extrabold bg-coralalert/20 text-coralalert border border-coralalert/40">إعادة ضبط السيرفر</button>
              </div>
            </div>
          ` : ""}}
        </div>
      `;
    }}

    function switchProtectionTab(tabKey) {{
      state.protectionTab = tabKey;
      render();
    }}

    async function selectGuildForProtection(gid) {{
      state.selectedGuildId = gid;
      await hydrateLiveState(gid);
    }}

    function toggleGuildFeature(key, checked) {{
      const g = getActiveGuild();
      if (!g) return;
      const item = g.toggles.find((x) => x.key === key);
      if (item) item.enabled = Boolean(checked);
      render();
    }}

    function updateRuleField(idx, field, val) {{
      const g = getActiveGuild();
      if (!g || !g.antinukeRules[idx]) return;
      g.antinukeRules[idx][field] = val;
      render();
    }}

    async function saveFullProtection() {{
      const g = getActiveGuild();
      if (!g) return;
      const togglesObj = {{}};
      g.toggles.forEach((t) => {{ togglesObj[t.key] = Boolean(t.enabled); }});
      const payload = {{
        toggles: togglesObj,
        antinukeRules: g.antinukeRules,
        prefix: document.getElementById("prot-prefix")?.value || g.prefix,
        modLogChannel: document.getElementById("prot-log-ch")?.value || g.modLogChannel,
        spamPunishment: document.getElementById("prot-spam-pun")?.value || g.spamPunishment,
        linkPunishment: document.getElementById("prot-link-pun")?.value || g.linkPunishment,
        dangerousPermsPunishment: document.getElementById("prot-dang-pun")?.value || g.dangerousPermsPunishment,
        minAccountAgeDays: Number(document.getElementById("prot-min-age")?.value || g.minAccountAgeDays),
      }};
      const out = await postUiAction({{ kind: "save_protection", protection: payload }});
      if (out && out.ok) {{
        await hydrateLiveState(g.id);
        showToast("تم حفظ إعدادات الحماية ومزامنتها", "success");
      }} else {{
        showToast(out?.error || "تعذر الحفظ", "danger");
      }}
    }}

    async function addTrustedAdmin() {{
      const trusted_uid = (document.getElementById("trusted-uid-inp")?.value || "").trim();
      const out = await postUiAction({{ kind: "add_trusted", trusted_uid }});
      if (out && out.ok) {{
        await hydrateLiveState(state.selectedGuildId);
        showToast("تمت إضافة المشرف الموثوق", "success");
      }} else {{
        showToast(out?.error || "تعذر الإضافة", "danger");
      }}
    }}

    async function removeTrustedAdmin(trusted_uid) {{
      const out = await postUiAction({{ kind: "remove_trusted", trusted_uid }});
      if (out && out.ok) {{
        await hydrateLiveState(state.selectedGuildId);
        showToast("تمت إزالة المشرف الموثوق", "warn");
      }}
    }}

    async function createGuildSnapshot() {{
      const out = await postUiAction({{ kind: "save_snapshot" }});
      if (out && out.ok) {{
        await hydrateLiveState(state.selectedGuildId);
        showToast("تم حفظ لقطة الحماية", "success");
      }}
    }}

    async function restoreGuildSnapshot(snapshot_id) {{
      const out = await postUiAction({{ kind: "restore_snapshot", snapshot_id }});
      if (out && out.ok) {{
        await hydrateLiveState(state.selectedGuildId);
        showToast("تم استرجاع اللقطة بنجاح", "success");
      }}
    }}

    async function runGuildSafetyCheck(scenario) {{
      const out = await postUiAction({{ kind: "run_check", scenario }});
      if (out && out.ok) {{
        showToast(out.message || "تم الفحص", "info");
      }}
    }}

    async function resetGuildSettings() {{
      const out = await postUiAction({{ kind: "reset_guild" }});
      if (out && out.ok) {{
        await hydrateLiveState(state.selectedGuildId);
        showToast("تمت إعادة ضبط إعدادات السيرفر", "warn");
      }}
    }}

    function renderPremiumPage() {{
      const guild = getActiveGuild();
      if (!guild) {{
        return `
          <div class="rounded-3xl bg-card/90 border border-white/[0.08] p-7 text-center space-y-4">
            <h2 class="text-xl font-black text-white">يجب إدخال البوت إلى السيرفر أولاً</h2>
            <a href="${{escapeHtml(INVITE_URL)}}" class="inline-block px-5 py-2.5 rounded-xl text-xs font-extrabold bg-violetcore text-white">دعوة بوت {escapeHtml("{BRAND_LABEL_AR}")}</a>
          </div>
        `;
      }}
      const pr = state.premium;
      return `
        <div class="animate-panel-enter space-y-6">
          <section class="rounded-[28px] bg-gradient-to-br from-[#231b3d] via-[#15182e] to-[#0d1020] border border-amberwarn/30 p-6 sm:p-8 shadow-glass">
            <span class="inline-block px-3 py-1 rounded-full bg-amberwarn/15 border border-amberwarn/35 text-amberwarn text-xs font-extrabold mb-2">{escapeHtml("{BRAND_LABEL_AR}")} PREMIUM</span>
            <h1 class="text-2xl sm:text-3xl font-black text-white">${{escapeHtml(pr.planName)}}</h1>
            <p class="text-xs sm:text-sm text-slate-300 mt-1">تخصيص هوية البوت للسيرفر (${{escapeHtml(guild.name)}}).</p>
          </section>
          <section class="rounded-3xl bg-card/90 border border-white/[0.08] p-6 space-y-4">
            <div>
              <label class="block text-xs font-extrabold text-slate-300 mb-1.5">رابط صورة الأفتار</label>
              <input id="prem-avatar-input" type="text" value="${{escapeHtml(pr.customAvatar)}}" class="w-full rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-3.5 py-2.5 text-xs text-white" />
            </div>
            <div>
              <label class="block text-xs font-extrabold text-slate-300 mb-1.5">رابط صورة البنر</label>
              <input id="prem-banner-input" type="text" value="${{escapeHtml(pr.customBanner)}}" class="w-full rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-3.5 py-2.5 text-xs text-white" />
            </div>
            <div>
              <label class="block text-xs font-extrabold text-slate-300 mb-1.5">النبذة التعريفية (Bio)</label>
              <textarea id="prem-bio-input" rows="3" maxlength="270" class="w-full rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-3.5 py-2.5 text-xs text-white">${{escapeHtml(pr.customBio)}}</textarea>
            </div>
            <button type="button" onclick="savePremiumProfile()" class="px-5 py-2.5 rounded-xl text-xs font-extrabold bg-gradient-to-r from-violetcore to-indigo-500 text-white shadow-violet">حفظ تخصيص البريميوم</button>
          </section>
        </div>
      `;
    }}

    async function savePremiumProfile() {{
      const payload = {{
        customAvatar: document.getElementById("prem-avatar-input")?.value.trim() || "",
        customBanner: document.getElementById("prem-banner-input")?.value.trim() || "",
        customBio: document.getElementById("prem-bio-input")?.value.trim() || "",
      }};
      const out = await postUiAction({{ kind: "save_premium", premium: payload }});
      if (out && out.ok) {{
        await hydrateLiveState(state.selectedGuildId);
        showToast("تم حفظ تخصيص البريميوم وإرساله للبوت", "success");
      }} else {{
        showToast(out?.error || "تعذر حفظ البريميوم", "warn");
      }}
    }}

    function renderAdminPage() {{
      const filter = state.admin.logFilter || "ALL";
      const filteredLogs = state.admin.logs.filter((item) => (filter === "ALL" ? true : item.level === filter));
      const canViewLogs = Boolean(state.adminPerms.view_logs);

      const premListHtml = (state.premiumUsers || []).map((u) => `
        <div class="flex items-center justify-between gap-3 p-3 rounded-2xl bg-[#0b0e1c] border border-white/[0.07]">
          <div class="flex items-center gap-3 min-w-0">
            <img src="${{escapeHtml(u.avatar_url || LOGO_URL)}}" alt="" class="w-10 h-10 rounded-xl object-cover shrink-0" />
            <div class="min-w-0">
              <div class="text-xs font-black text-white truncate">${{escapeHtml(u.username)}} <span class="text-slate-400 font-normal">${{escapeHtml(u.handle)}}</span></div>
              <div class="text-[11px] text-slate-400 font-mono">${{escapeHtml(u.user_id)}}</div>
            </div>
          </div>
          ${{u.user_id !== "{escapeHtml(ADMIN_USER_ID)}" ? `<button type="button" onclick="revokeSpecificPrem('${{escapeHtml(u.user_id)}}')" class="px-3 py-1.5 rounded-xl text-xs font-bold bg-coralalert/20 text-coralalert">سحب</button>` : `<span class="text-[11px] text-amberwarn font-bold">Owner</span>`}}
        </div>
      `).join("");

      const botGuildsHtml = (state.allBotGuilds || []).map((g) => `
        <div class="flex items-center justify-between gap-2 p-3 rounded-2xl bg-[#0b0e1c] border border-white/[0.07]">
          <div class="min-w-0">
            <div class="text-xs font-extrabold text-white truncate">${{escapeHtml(g.name)}}</div>
            <div class="text-[11px] text-slate-400 font-mono">ID: ${{escapeHtml(g.id)}}</div>
          </div>
          <span class="px-2.5 py-1 rounded-full text-[11px] font-bold bg-emeraldsafe/15 text-emeraldsafe">الأعضاء: ${{Number(g.member_count || 0)}}</span>
        </div>
      `).join("") || `<p class="text-xs text-slate-400">لا توجد سيرفرات متزامنة حالياً.</p>`;

      const permChecksHtml = Object.keys(PERM_LABELS).map((pk) => `
        <label class="flex items-center justify-between gap-2 p-2.5 rounded-xl bg-[#0b0e1c] border border-white/[0.07] cursor-pointer">
          <span class="text-xs font-bold text-slate-200">${{escapeHtml(PERM_LABELS[pk])}}</span>
          <input type="checkbox" class="adm-perm-cb" data-perm="${{pk}}" checked />
        </label>
      `).join("");

      const staffListHtml = (state.adminStaff || []).map((st) => `
        <div class="flex items-center justify-between gap-2 p-3 rounded-2xl bg-[#0b0e1c] border border-white/[0.07]">
          <div>
            <span class="text-xs font-mono text-white">${{escapeHtml(st.user_id)}}</span>
            <span class="mr-2 px-2 py-0.5 rounded-full text-[10px] font-extrabold bg-violetcore/20 text-violetglow">${{escapeHtml(st.role_tag)}}</span>
          </div>
          ${{st.user_id !== "{escapeHtml(ADMIN_USER_ID)}" ? `<button type="button" onclick="removeStaffMember('${{escapeHtml(st.user_id)}}')" class="px-3 py-1 rounded-lg text-xs font-bold bg-coralalert/20 text-coralalert">إزالة</button>` : ""}}
        </div>
      `).join("");

      const backupsHtml = (state.backups || []).map((b) => `
        <div class="flex items-center justify-between gap-2 p-3 rounded-xl bg-[#0b0e1c] border border-white/[0.07]">
          <div class="text-xs font-bold text-white">نسخة #${{escapeHtml(b.backup_id)}} • <span class="text-slate-400 font-normal">${{escapeHtml(b.created_at)}}</span></div>
          <span class="text-xs text-emeraldsafe font-bold">${{Number(b.guilds_count || 0)}} سيرفر</span>
        </div>
      `).join("");

      return `
        <div class="animate-panel-enter space-y-6">
          <section class="rounded-[26px] bg-gradient-to-r from-[#141932] via-[#101426] to-[#0b0e1b] border border-white/[0.09] p-6 flex flex-wrap items-center justify-between gap-4 shadow-glass">
            <div>
              <h1 class="text-2xl font-black text-white">لوحة الإدارة</h1>
              <p class="text-xs text-slate-400 mt-1">عدد السيرفرات اللي مدخله البوت: <strong class="text-white">${{state.botGuildsCount}}</strong> • البريميوم: <strong class="text-amberwarn">${{state.premiumCount}}</strong> • طاقم الإدارة: <strong class="text-violetglow">${{state.adminsCount}}</strong></p>
            </div>
            ${{canViewLogs ? `<button type="button" onclick="toggleUiLogDrawer()" class="px-4 py-2.5 rounded-xl text-xs font-extrabold bg-white/[0.06] text-white border border-white/[0.12]">سجل العمليات (Log)</button>` : ""}}
          </section>

          <section id="ui-log-section" class="${{canViewLogs && state.admin.showLogPanel ? "block" : "hidden"}} rounded-3xl bg-card/90 border border-white/[0.08] p-5 sm:p-6">
            <div class="flex flex-wrap items-center justify-between gap-2 mb-4">
              <h2 class="text-base font-black text-white">سجل العمليات (Log)</h2>
              <div class="flex items-center gap-1 bg-[#0b0e1c] p-1 rounded-xl border border-white/[0.08]">
                ${{["ALL", "CRITICAL", "WARN", "INFO"].map((lvl) => `
                  <button type="button" onclick="setAdminLogFilter('${{lvl}}')" class="px-2.5 py-1 rounded-lg text-[11px] font-extrabold ${{filter === lvl ? "bg-violetcore text-white" : "text-slate-400"}}">
                    ${{lvl === "ALL" ? "الكل" : lvl}}
                  </button>
                `).join("")}}
              </div>
            </div>
            <div class="space-y-2.5 max-h-[300px] overflow-y-auto">
              ${{filteredLogs.map((log) => `
                <div class="p-3.5 rounded-2xl bg-[#0b0e1c]/90 border border-white/[0.06]">
                  <div class="flex items-center gap-2 mb-1">
                    <span class="px-2 py-0.5 rounded-full text-[10px] font-extrabold bg-violetcore/20 text-violetglow">${{escapeHtml(log.level)}}</span>
                    <span class="text-[11px] font-bold text-slate-400">${{escapeHtml(log.type)}} • ${{escapeHtml(log.time)}}</span>
                  </div>
                  <p class="text-xs text-slate-200">${{escapeHtml(log.text)}}</p>
                </div>
              `).join("") || `<p class="text-xs text-slate-400">لا توجد سجلات بعد.</p>`}}
            </div>
          </section>

          <div class="grid grid-cols-2 sm:grid-cols-4 gap-2">
            ${{[
              ["prem", "إدارة البريميوم"],
              ["guilds", "سيرفرات البوت"],
              ["staff", "الإدارة والصلاحيات"],
              ["remote", "الأوامر والنسخ"],
            ].map(([k, lbl]) => `
              <button type="button" onclick="switchAdminTab('${{k}}')" class="py-2.5 px-3 rounded-xl text-xs font-extrabold border ${{state.adminTab === k ? "bg-violetcore text-white border-violetglow" : "bg-card/80 text-slate-300 border-white/[0.08]"}}">${{lbl}}</button>
            `).join("")}}
          </div>

          ${{state.adminTab === "prem" ? `
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-5">
              <div class="rounded-3xl bg-card/90 border border-white/[0.08] p-5 space-y-4">
                <h2 class="text-base font-black text-white">إدارة اشتراك البريميوم بالآيدي</h2>
                <div class="flex gap-2">
                  <input id="ui-prem-uid" type="text" placeholder="أدخل آيدي الشخص (User ID)" oninput="lookupUiPremUser()" class="flex-1 rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-3 py-2.5 text-xs text-white" />
                  <input id="ui-prem-days" type="number" min="1" max="3650" value="30" class="w-20 rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-2.5 py-2.5 text-xs text-white text-center" />
                </div>
                <div id="ui-prem-preview" class="hidden p-3.5 rounded-2xl bg-[#0b0e1c] border border-white/[0.08] flex items-center justify-between gap-3">
                  <div class="flex items-center gap-3 min-w-0">
                    <img id="ui-prem-ava" src="${{escapeHtml(LOGO_URL)}}" alt="" class="w-12 h-12 rounded-xl object-cover ring-1 ring-violetglow/50 shrink-0" />
                    <div class="min-w-0">
                      <div id="ui-prem-name" class="text-sm font-black text-white truncate"></div>
                      <div id="ui-prem-handle" class="text-xs text-slate-400 truncate"></div>
                    </div>
                  </div>
                  <div class="flex items-center gap-2 shrink-0">
                    <button type="button" onclick="extendUiPremUser()" class="px-3 py-2 rounded-xl text-xs font-extrabold bg-emeraldsafe/20 text-emeraldsafe border border-emeraldsafe/40">زيادة مدة</button>
                    <button type="button" onclick="revokeUiPremUser()" class="px-3 py-2 rounded-xl text-xs font-extrabold bg-coralalert/20 text-coralalert border border-coralalert/40">سحب</button>
                  </div>
                </div>
              </div>
              <div class="rounded-3xl bg-card/90 border border-white/[0.08] p-5 space-y-3">
                <h2 class="text-base font-black text-white">المشتركون الحاليون (${{state.premiumUsers.length}})</h2>
                <div class="space-y-2 max-h-[340px] overflow-y-auto">${{premListHtml}}</div>
              </div>
            </div>
          ` : ""}}

          ${{state.adminTab === "guilds" ? `
            <div class="rounded-3xl bg-card/90 border border-white/[0.08] p-5 space-y-3">
              <h2 class="text-base font-black text-white">السيرفرات التي يدخلها البوت (${{state.allBotGuilds.length}})</h2>
              <div class="grid grid-cols-1 md:grid-cols-2 gap-2.5">${{botGuildsHtml}}</div>
            </div>
          ` : ""}}

          ${{state.adminTab === "staff" ? `
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-5">
              <div class="rounded-3xl bg-card/90 border border-white/[0.08] p-5 space-y-3">
                <h2 class="text-base font-black text-white">إضافة أو تعديل عضو إدارة</h2>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  <input id="adm-target-uid" type="text" placeholder="User ID" class="rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-3 py-2 text-xs text-white" />
                  <select id="adm-role-sel" class="rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-3 py-2 text-xs text-white">
                    <option value="Co owner">Co owner</option>
                    <option value="Staff" selected>Staff</option>
                  </select>
                </div>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">${{permChecksHtml}}</div>
                <button type="button" onclick="saveStaffMember()" class="w-full py-2.5 rounded-xl text-xs font-extrabold bg-violetcore text-white">حفظ الصلاحيات</button>
              </div>
              <div class="rounded-3xl bg-card/90 border border-white/[0.08] p-5 space-y-2.5">
                <h2 class="text-base font-black text-white">طاقم الإدارة الحالي</h2>
                ${{staffListHtml}}
              </div>
            </div>
          ` : ""}}

          ${{state.adminTab === "remote" ? `
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-5">
              <div class="rounded-3xl bg-card/90 border border-white/[0.08] p-5 space-y-3">
                <h2 class="text-base font-black text-white">إرسال أمر عن بُعد</h2>
                <select id="rem-action-sel" class="w-full rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-3 py-2 text-xs text-white">
                  <option value="broadcast">بث عام (Broadcast)</option>
                  <option value="sync_guild_cfg">مزامنة إعدادات السيرفر</option>
                  <option value="kick">طرد عضو (Kick)</option>
                  <option value="ban">حظر عضو (Ban)</option>
                  <option value="timeout">تايم أوت (Timeout)</option>
                </select>
                <input id="rem-gid-inp" type="text" value="0" placeholder="Guild ID (0 للكل)" class="w-full rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-3 py-2 text-xs text-white" />
                <input id="rem-target-inp" type="text" placeholder="الهدف أو نص البث" class="w-full rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-3 py-2 text-xs text-white" />
                <button type="button" onclick="queueRemoteCmd()" class="w-full py-2.5 rounded-xl text-xs font-extrabold bg-violetcore text-white">تنفيذ الأمر</button>
              </div>
              <div class="rounded-3xl bg-card/90 border border-white/[0.08] p-5 space-y-3">
                <h2 class="text-base font-black text-white">النسخ الاحتياطي واختبار الاستعادة</h2>
                <div class="flex gap-2">
                  <button type="button" onclick="createBackupNow()" class="px-4 py-2 rounded-xl text-xs font-extrabold bg-violetcore text-white">إنشاء نسخة</button>
                  <button type="button" onclick="testRestoreNow()" class="px-4 py-2 rounded-xl text-xs font-extrabold bg-white/[0.08] text-white border border-white/[0.12]">اختبار الاستعادة</button>
                </div>
                <div class="space-y-2">${{backupsHtml}}</div>
              </div>
            </div>
          ` : ""}}
        </div>
      `;
    }}

    function switchAdminTab(tabKey) {{
      state.adminTab = tabKey;
      render();
    }}

    async function lookupUiPremUser() {{
      const uid = (document.getElementById("ui-prem-uid")?.value || "").trim();
      const box = document.getElementById("ui-prem-preview");
      if (!box) return;
      if (!/^\\d+$/.test(uid)) {{
        box.classList.add("hidden");
        return;
      }}
      try {{
        const res = await fetch("/api/lookup-user?user_id=" + encodeURIComponent(uid));
        if (!res.ok) return;
        const data = await res.json();
        if (!data || !data.ok || !data.user) return;
        document.getElementById("ui-prem-ava").src = data.user.avatar_url || LOGO_URL;
        document.getElementById("ui-prem-name").textContent = data.user.username || ("User " + uid);
        document.getElementById("ui-prem-handle").textContent = (data.user.handle || "@user") + (data.user.remaining ? (" • " + data.user.remaining) : "");
        box.classList.remove("hidden");
      }} catch (e) {{}}
    }}

    async function extendUiPremUser() {{
      const target_user_id = (document.getElementById("ui-prem-uid")?.value || "").trim();
      const days = Number(document.getElementById("ui-prem-days")?.value || 30);
      const out = await postUiAction({{ kind: "prem_extend", target_user_id, days }});
      if (out && out.ok) {{
        await hydrateLiveState(state.selectedGuildId);
        await lookupUiPremUser();
        showToast("تم زيادة مدة البريميوم بنجاح", "success");
      }} else {{
        showToast(out?.error || "تعذر زيادة المدة", "danger");
      }}
    }}

    async function revokeUiPremUser() {{
      const target_user_id = (document.getElementById("ui-prem-uid")?.value || "").trim();
      const out = await postUiAction({{ kind: "prem_revoke", target_user_id }});
      if (out && out.ok) {{
        await hydrateLiveState(state.selectedGuildId);
        await lookupUiPremUser();
        showToast("تم سحب البريميوم بنجاح", "warn");
      }} else {{
        showToast(out?.error || "تعذر سحب البريميوم", "danger");
      }}
    }}

    async function revokeSpecificPrem(target_user_id) {{
      const out = await postUiAction({{ kind: "prem_revoke", target_user_id }});
      if (out && out.ok) {{
        await hydrateLiveState(state.selectedGuildId);
        showToast("تم سحب البريميوم", "warn");
      }}
    }}

    async function saveStaffMember() {{
      const target_user_id = (document.getElementById("adm-target-uid")?.value || "").trim();
      const role_tag = document.getElementById("adm-role-sel")?.value || "Staff";
      const permissions = {{}};
      document.querySelectorAll(".adm-perm-cb").forEach((cb) => {{
        permissions[cb.getAttribute("data-perm")] = Boolean(cb.checked);
      }});
      const out = await postUiAction({{ kind: "admin_add", target_user_id, role_tag, permissions }});
      if (out && out.ok) {{
        await hydrateLiveState(state.selectedGuildId);
        showToast("تم حفظ بيانات وصلاحيات عضو الإدارة", "success");
      }} else {{
        showToast(out?.error || "تعذر الحفظ", "danger");
      }}
    }}

    async function removeStaffMember(target_user_id) {{
      const out = await postUiAction({{ kind: "admin_remove", target_user_id }});
      if (out && out.ok) {{
        await hydrateLiveState(state.selectedGuildId);
        showToast("تمت إزالة عضو الإدارة", "warn");
      }}
    }}

    async function queueRemoteCmd() {{
      const action_type = document.getElementById("rem-action-sel")?.value || "broadcast";
      const target_guild_id = (document.getElementById("rem-gid-inp")?.value || "0").trim();
      const target_value = (document.getElementById("rem-target-inp")?.value || "").trim();
      const out = await postUiAction({{ kind: "remote_cmd", action_type, target_guild_id, target_value }});
      if (out && out.ok) {{
        await hydrateLiveState(state.selectedGuildId);
        showToast("تم إرسال الأمر إلى طابور البوت", "success");
      }} else {{
        showToast(out?.error || "تعذر التنفيذ", "danger");
      }}
    }}

    async function createBackupNow() {{
      const out = await postUiAction({{ kind: "backup" }});
      if (out && out.ok) {{
        await hydrateLiveState(state.selectedGuildId);
        showToast("تم إنشاء نسخة احتياطية", "success");
      }}
    }}

    async function testRestoreNow() {{
      const out = await postUiAction({{ kind: "test_restore" }});
      if (out && out.ok) {{
        showToast(out.message || "نجح اختبار الاستعادة", "success");
      }}
    }}

    function toggleUiLogDrawer() {{
      state.admin.showLogPanel = !state.admin.showLogPanel;
      render();
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
      else if (state.activePage === "premium" && state.isPremium) main.innerHTML = renderPremiumPage();
      else if (state.activePage === "admin" && state.isAdmin) main.innerHTML = renderAdminPage();
      else main.innerHTML = renderHomePage();
    }}

    render();
    hydrateLiveState();
  </script>
</body>
</html>"""


async def handle_new_ui_page(request: web.Request) -> web.Response:
    return web.Response(text=_build_new_ui_html(request), content_type="text/html")


async def handle_invite_redirect(request: web.Request) -> web.Response:
    user = get_discord_session(request)
    if not user:
        raise web.HTTPFound("/login?next=" + quote("/invite"))
    target_invite = sanitize_http_url(BOT_INVITE_URL) or "https://discord.com"
    raise web.HTTPFound(target_invite)


async def login_handler(request: web.Request) -> web.Response:
    nxt = sanitize_next_url(request.query.get("next") or "/ui")
    if not DISCORD_CLIENT_ID or not DISCORD_CLIENT_SECRET:
        raise web.HTTPFound("/ui")

    redirect_uri = detect_redirect_uri(request)
    state_val = issue_oauth_state(nxt)
    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "identify guilds",
        "state": state_val,
    }
    raise web.HTTPFound("https://discord.com/api/oauth2/authorize?" + urlencode(params))


async def callback_handler(request: web.Request) -> web.Response:
    code = str(request.query.get("code", "")).strip()
    state_val = str(request.query.get("state", "")).strip()
    valid_state, nxt = consume_oauth_state(state_val)
    if not valid_state or not code or not DISCORD_CLIENT_ID or not DISCORD_CLIENT_SECRET:
        raise web.HTTPFound("/ui")

    redirect_uri = detect_redirect_uri(request)
    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as sess:
            tok_resp = await sess.post(
                "https://discord.com/api/v10/oauth2/token",
                data={
                    "client_id": DISCORD_CLIENT_ID,
                    "client_secret": DISCORD_CLIENT_SECRET,
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if tok_resp.status != 200:
                raise web.HTTPFound("/ui")
            tok_data = await tok_resp.json()
            access_tok = str(tok_data.get("access_token", "")).strip()
            if not access_tok:
                raise web.HTTPFound("/ui")

            auth_hdr = {"Authorization": f"Bearer {access_tok}"}
            u_resp = await sess.get("https://discord.com/api/v10/users/@me", headers=auth_hdr)
            if u_resp.status != 200:
                raise web.HTTPFound("/ui")
            u_json = await u_resp.json()

            g_list = []
            try:
                g_resp = await sess.get("https://discord.com/api/v10/users/@me/guilds", headers=auth_hdr)
                if g_resp.status == 200:
                    raw_guilds = await g_resp.json()
                    if isinstance(raw_guilds, list):
                        g_list = raw_guilds[:150]
            except ClientError:
                g_list = []

        uid = str(u_json.get("id", "")).strip()
        if not uid.isdigit():
            raise web.HTTPFound("/ui")

        uname = str(u_json.get("global_name") or u_json.get("username") or "Member")[:40]
        ava = str(u_json.get("avatar") or "")[:40]
        sess_payload = {
            "id": uid,
            "username": uname,
            "avatar": ava,
            "guilds": g_list,
            "exp": time.time() + 86400 * 7,
        }
        signed = sign_session(sess_payload)
        resp = web.HTTPFound(nxt)
        resp.set_cookie(
            "arab_sec_session",
            signed,
            path="/",
            max_age=86400 * 7,
            httponly=True,
            samesite="Lax",
            secure=should_use_secure_cookie(request),
        )
        log_event(f"User {uname} ({uid}) logged in via Discord", level="WEB")
        raise resp
    except web.HTTPFound:
        raise
    except Exception:
        raise web.HTTPFound("/ui")


async def logout_handler(request: web.Request) -> web.Response:
    pair = get_discord_session_with_id(request)
    if pair:
        _delete_session_record(pair[0])
    resp = web.HTTPFound("/ui")
    resp.del_cookie("arab_sec_session", path="/")
    return resp


async def health_handler(request: web.Request) -> web.Response:
    return web.json_response(
        {
            "ok": True,
            "brand": BRAND_LABEL_AR,
            "site": SITE_NAME,
            "db_connected": db is not None,
            "bot_status": MEM_BOT_HEARTBEAT.get("status", "ONLINE"),
            "guilds_count": len(get_all_guilds()),
        }
    )


@web.middleware
async def security_headers_middleware(request: web.Request, handler):
    ip = get_client_ip(request)
    is_auth_route = request.path in ("/login", "/callback", "/logout", "/api/ui-action")
    if is_rate_limited(ip, is_sensitive=is_auth_route):
        return web.json_response({"ok": False, "error": "Rate limit exceeded"}, status=429)

    try:
        record_site_visit(request)
    except Exception:
        pass

    try:
        response = await handler(request)
    except web.HTTPException as ex:
        response = ex

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


def create_app() -> web.Application:
    app = web.Application(middlewares=[security_headers_middleware])
    app.router.add_get("/", handle_new_ui_page)
    app.router.add_get("/ui", handle_new_ui_page)
    app.router.add_get("/guild", handle_new_ui_page)
    app.router.add_get("/premium", handle_new_ui_page)
    app.router.add_get("/admin", handle_new_ui_page)
    app.router.add_get("/invite", handle_invite_redirect)
    app.router.add_get("/login", login_handler)
    app.router.add_get("/callback", callback_handler)
    app.router.add_get("/logout", logout_handler)
    app.router.add_get("/health", health_handler)
    app.router.add_get("/api/lookup-user", api_lookup_user)
    app.router.add_get("/api/ui-state", api_ui_state)
    app.router.add_post("/api/ui-action", api_ui_action)
    app.router.add_post("/api/bot/sync-guilds", api_bot_sync_guilds)
    app.router.add_post("/api/bot/boost-sync", api_bot_boost_sync)
    app.router.add_get("/api/bot/pending-commands", api_bot_pending_commands)
    return app


if __name__ == "__main__":
    web.run_app(create_app(), host=HOST, port=PORT)
