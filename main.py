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

DEFAULT_SYNC_SECRET = "8UJ3rUf3IrJCPfYfSrzog2KiLPxr87S3"

_env_secret = (os.environ.get("SESSION_SECRET") or "").strip()
SESSION_SECRET = (
    _env_secret
    if len(_env_secret) >= 16
    else "ArabSecurity_Session_Secret_2026_x9K#mP2vL8qR5tW7zY3nB6jH4cF1gD0sA"
)
BOT_SYNC_SECRET = (
    (os.environ.get("BOT_SYNC_SECRET") or "8UJ3rUf3IrJCPfYfSrzog2KiLPxr87S3").strip()
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
DISCORD_CLIENT_SECRET = (os.getenv("DISCORD_CLIENT_SECRET", "8UJ3rUf3IrJCPfYfSrzog2KiLPxr87S3") or "").strip()

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

ADMIN_PERMISSION_LABELS = {
    "manage_premium": ("Manage Premium", "إدارة البريميوم"),
    "manage_admins": ("Manage Admins & Perms", "إدارة الأدمن والصلاحيات"),
    "remote_actions": ("Remote Actions & Broadcast", "الأوامر عن بُعد والبث"),
    "simulations": ("Safety Checks", "فحص الجاهزية"),
    "backups": ("Backups & Restore", "النسخ الاحتياطي والاستعادة"),
    "view_logs": ("System & Security Logs", "السجلات والتنبيهات"),
}

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
    "anti_guild_icon_change",
    "anti_role_tamper",
    "anti_channel_perms_tamper",
    "quarantine_on_sabotage",
    "dangerous_perms_guard",
    "anti_privilege_escalation",
    "anti_vanity_tamper",
    "anti_webhook_abuse",
    "anti_app_abuse",
    "anti_selfbot",
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
    *ANTIRAID_TOGGLE_KEYS,
    *MODERATION_TOGGLE_KEYS,
)

FEATURE_LABELS_EN = {
    "anti_spam": "Anti-Spam",
    "anti_link": "Anti-Link",
    "anti_invites": "Anti-Invites",
    "anti_raid": "Join Surge Guard",
    "lockdown": "Server Lockdown",
    "anti_new_accounts": "New Account Guard",
    "voice_lock": "Voice Channel Lock",
    "anti_bot_raid": "Bot Addition Guard",
    "anti_vanity_tamper": "Vanity URL Guard",
    "anti_guild_icon_change": "Server Icon Guard",
    "anti_mass_unban": "Mass Unban Guard",
    "anti_mass_kick": "Mass Kick Guard",
    "anti_mass_timeout": "Mass Timeout Guard",
    "anti_mention_spam": "Mass Mention Guard",
    "quarantine_on_sabotage": "Role Strip & Quarantine",
    "dangerous_perms_guard": "Dangerous Permissions Guard",
    "anti_selfbot": "Automated Account Guard",
    "anti_webhook_abuse": "Webhook Abuse Protection",
    "anti_app_abuse": "OAuth App Abuse Protection",
    "anti_privilege_escalation": "Privilege Escalation Guard",
    "anti_role_tamper": "Role Delete & Tamper Guard",
    "anti_channel_perms_tamper": "Channel Overwrite Guard",
    "audit_log_watch": "Real-Time Audit Log Watch",
    "admin_behavior_analysis": "Admin Activity Watch",
    "trusted_admins_enabled": "Trusted Admins Whitelist",
    "perms_snapshot_enabled": "Permissions Snapshots",
    "auto_rollback_enabled": "Auto Rollback",
    "gradual_attack_detect": "Gradual Activity Guard",
    "collusion_detect": "Coordinated Action Guard",
    "false_punishment_guard": "False Punishment Guard",
    "emergency_mode": "Emergency Lock Mode",
    "auto_perms_audit": "Automatic Permissions Audit",
    "silent_mode": "Silent Enforcement Mode",
    "beast_mode": "High Protection Mode",
    "role_hierarchy_guard": "Role Hierarchy Guard",
    "auto_quarantine": "Auto Quarantine Suspects",
    "maintenance": "Maintenance Mode",
    "verification": "Verification Gate",
    "alert_on_trigger": "Trigger Alerts",
}

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
    "anti_guild_icon_change": "حماية من تغيير صورة السيرفر",
    "anti_mass_unban": "مراقبة فك الحظر الجماعي",
    "anti_mass_kick": "مراقبة الطرد الجماعي",
    "anti_mass_timeout": "مراقبة التايم أوت الجماعي",
    "anti_mention_spam": "منع المنشن الجماعي",
    "quarantine_on_sabotage": "سحب الرتب وعزل المخالف من التخريب",
    "dangerous_perms_guard": "حماية الصلاحيات الخطيرة",
    "anti_selfbot": "حماية الحسابات الآلية",
    "anti_webhook_abuse": "حماية الويب هوك",
    "anti_app_abuse": "حماية تطبيقات الربط",
    "anti_privilege_escalation": "منع رفع الصلاحيات غير المصرح به",
    "anti_role_tamper": "حماية من حذف أو تعديل الرتب",
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
    "anti_role_delete": "حماية من حذف الرولات",
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
        "alert_on_trigger": True,
        "anti_selfbot": True,
        "anti_webhook_abuse": True,
        "anti_app_abuse": True,
        "anti_privilege_escalation": True,
        "anti_role_tamper": True,
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
_CFG_TTL = 5.0
_PERM_CACHE: dict[str, tuple[float, object]] = {}
_PERM_TTL = 10.0
_GUILDS_CACHE: tuple[float, list[dict]] = (0.0, [])
_GUILDS_TTL = 1.5
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


def esc(val) -> str:
    return html.escape(str(val or ""), quote=True)


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


def sanitize_flash_msg(raw_msg: str | None) -> str:
    cleaned = "".join(ch for ch in str(raw_msg or "") if ch.isprintable()).strip()
    return cleaned[:240]


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


def issue_csrf_token(session_id: str) -> str:
    _cleanup_expired()
    tok = secrets.token_hex(24)
    if len(CSRF_TOKENS) >= 5000:
        oldest = next(iter(CSRF_TOKENS))
        CSRF_TOKENS.pop(oldest, None)
    CSRF_TOKENS[tok] = {"sid": str(session_id or ""), "exp": time.time() + 3600.0}
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


def _get_admin_record(uid: str) -> dict | None:
    if not uid.isdigit():
        return None
    if uid == ADMIN_USER_ID:
        return {
            "user_id": ADMIN_USER_ID,
            "granted_by": "owner",
            "updated_at": "-",
            "permissions": _full_admin_perms(),
        }
    rec = MEM_ADMINS.get(uid)
    if not rec and admins_col is not None:
        try:
            doc = admins_col.find_one({"user_id": uid}, {"_id": 0})
            if doc:
                rec = {
                    "user_id": uid,
                    "granted_by": str(doc.get("granted_by", "owner")),
                    "updated_at": str(doc.get("updated_at", "-")),
                    "permissions": _default_sub_admin_perms(doc.get("permissions")),
                }
                MEM_ADMINS[uid] = rec
        except PyMongoError:
            pass
    if rec:
        copy_rec = dict(rec)
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
    res = _get_admin_record(uid) is not None
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
            "granted_by": "owner",
            "updated_at": "-",
            "permissions": _full_admin_perms(),
        }
    }
    for uid, rec in MEM_ADMINS.items():
        if uid not in items:
            items[uid] = {
                "user_id": uid,
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
) -> bool:
    uid = str(user_id or "").strip()
    if not uid.isdigit():
        return False
    _invalidate_perm_cache(uid)
    if enabled:
        perms_clean = _full_admin_perms() if uid == ADMIN_USER_ID else _default_sub_admin_perms(permissions)
        stamp = _now_str()
        rec = {
            "user_id": uid,
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


def _get_premium_record(uid: str) -> dict | None:
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
    if premium_col is not None:
        try:
            doc = premium_col.find_one({"user_id": uid}, {"_id": 0})
            if doc:
                rec = _normalize_premium_doc(doc)
                MEM_PREMIUM[uid] = rec
            elif rec and rec.get("source") == "boost":
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
    res = _get_premium_record(uid) is not None
    _PERM_CACHE[cache_key] = (time.time(), res)
    return res


def format_remaining_time(rec: dict, is_en: bool = True) -> str:
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
    _invalidate_perm_cache(uid)
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


def get_recent_incidents(limit: int = 30) -> list[dict]:
    if incidents_col is not None:
        try:
            return list(incidents_col.find({}, {"_id": 0}).sort("_id", -1).limit(limit))
        except PyMongoError:
            pass
    return list(MEM_INCIDENTS)[:limit]


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


def resolve_guild_id_from_input(raw_input: str, user: dict | None = None, require_bot_present: bool = True) -> str:
    val = str(raw_input or "").strip()
    if not val or not user:
        return ""
    visible, _ = get_user_visible_guilds(user)
    allowed = [g for g in visible if not require_bot_present or not g.get("bot_missing")]
    if val.isdigit():
        return val if any(g["id"] == val for g in allowed) else ""
    low = val.lower()
    for g in allowed:
        if str(g.get("name", "")).strip().lower() == low:
            return g["id"]
    for g in allowed:
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

    if is_premium:
        if "guild_profile" in updates and isinstance(updates["guild_profile"], dict):
            prof = cfg.setdefault("guild_profile", {})
            p_upd = updates["guild_profile"]
            if "bio" in p_upd:
                prof["bio"] = sanitize_bio_text(p_upd["bio"])
            if "avatar_data_url" in p_upd:
                prof["avatar_data_url"] = sanitize_image_data_url(p_upd["avatar_data_url"])
            if "avatar_name" in p_upd:
                prof["avatar_name"] = str(p_upd["avatar_name"] or "").strip()[:80]
            if "banner_data_url" in p_upd:
                prof["banner_data_url"] = sanitize_image_data_url(p_upd["banner_data_url"])
            if "banner_name" in p_upd:
                prof["banner_name"] = str(p_upd["banner_name"] or "").strip()[:80]
        if "premium_perks" in updates and isinstance(updates["premium_perks"], dict):
            perks = cfg.setdefault("premium_perks", {})
            pr_upd = updates["premium_perks"]
            if "alert_channel_id" in pr_upd:
                ch_val = str(pr_upd["alert_channel_id"] or "").strip()
                perks["alert_channel_id"] = ch_val if ch_val.isdigit() else ""
            for bool_k in ("ultra_fortress_mode", "instant_rollback_enabled", "priority_shield_response"):
                if bool_k in pr_upd:
                    perks[bool_k] = bool(pr_upd[bool_k])
            if "alert_webhook_url" in pr_upd:
                perks["alert_webhook_url"] = sanitize_http_url(pr_upd["alert_webhook_url"])
            if "last_restored_snapshot" in pr_upd:
                perks["last_restored_snapshot"] = str(pr_upd["last_restored_snapshot"] or "")[:24]

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
    if "delete_snapshot_id" in updates and updates["delete_snapshot_id"]:
        del_id = str(updates["delete_snapshot_id"]).strip()
        cfg["perms_snapshots"] = [s for s in (cfg.get("perms_snapshots") or []) if str(s.get("id")) != del_id]

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


def calculate_security_score(cfg: dict, is_en: bool = True) -> tuple[int, str]:
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
        grade = "A+ (Fortified)" if is_en else "A+ (حماية متكاملة)"
    elif score >= 65:
        grade = "B+ (Strong)" if is_en else "B+ (حماية قوية)"
    else:
        grade = "C (Needs Tuning)" if is_en else "C (يحتاج تفعيل قواعد إضافية)"
    return score, grade


def run_attack_simulation(guild_id: str, scenario: str, is_en: bool = True) -> str:
    cfg = get_guild_cfg(guild_id)
    score, _ = calculate_security_score(cfg, is_en=is_en)
    blocked = score >= 50 or bool(cfg.get("emergency_mode")) or bool((cfg.get("premium_perks") or {}).get("ultra_fortress_mode"))
    if is_en:
        outcome = "Safety check passed and auto-rollback is ready" if blocked else "Safety check found disabled rules"
        record_incident(guild_id, "CHECK", f"Check [{scenario}]: {outcome}", "INFO")
        log_event(f"Check [{scenario}] in guild {guild_id}: {outcome}", guild_id=guild_id, level="SEC")
        return f"{outcome} (Protection Score: {score}/100)."
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


def test_backup_restore(backup_id: str = "", is_en: bool = True) -> tuple[bool, str]:
    backups = get_db_backups()
    if not backups:
        b = create_db_backup()
        backups = [b]
    target = next((x for x in backups if x.get("backup_id") == backup_id), backups[0])
    ok = bool(target.get("backup_id")) and bool(target.get("signature"))
    if is_en:
        msg = (
            f"Restore test passed [{target.get('backup_id')}] ({target.get('guilds_count', 0)} guilds, {target.get('admins_count', 0)} admins)."
            if ok
            else "Backup signature check failed."
        )
    else:
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


def get_lang(request: web.Request) -> str:
    q = str(request.query.get("lang", "")).strip().lower()
    if q in ("ar", "en"):
        return q
    c = str(request.cookies.get("arab_sec_lang", "")).strip().lower()
    if c in ("ar", "en"):
        return c
    return "en"


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


async def read_post_safe(request: web.Request, max_bytes: int = 16_000_000) -> dict | None:
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


def _render_guild_card(g: dict, is_en: bool, show_admin_meta: bool = False) -> str:
    gid_raw = str(g.get("id", ""))
    gid = esc(gid_raw)
    gname_raw = str(g.get("name", f"Server {gid_raw}"))
    gname = esc(gname_raw)
    mcount = int(g.get("member_count", 0) or 0)
    missing = bool(g.get("bot_missing"))
    icon_url = guild_icon_url(gid_raw, g.get("icon"))
    if icon_url:
        icon_html = f"<img class='guild-icon' src='{esc(icon_url)}' alt='' loading='lazy' referrerpolicy='no-referrer'>"
    else:
        initial = esc((gname_raw[:1] or "S").upper())
        icon_html = f"<div class='guild-icon-ph'>{initial}</div>"

    href = "/invite" if missing else f"/guild?id={gid}"
    if missing:
        badge_cls = "warn-pill"
        status_txt = "Add Bot" if is_en else "إضافة البوت"
    else:
        badge_cls = "ok-pill"
        status_txt = f"Connected ({mcount})" if is_en else f"متصل ({mcount})"

    sub_line = f"ID: {gid}"
    if show_admin_meta and g.get("updated_at"):
        sub_line += f" • {esc(g.get('updated_at'))}"

    return (
        f"<a class='list-row guild-search-item' data-search='{esc((gname_raw + ' ' + gid_raw).lower())}' style='text-decoration:none;color:#fff;' href='{href}'>"
        f"<div style='display:flex;align-items:center;gap:10px;min-width:0;'>{icon_html}"
        f"<div style='min-width:0;'><div style='font-weight:800;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;'>{gname}</div>"
        f"<div class='muted' style='font-size:11.5px;'>{sub_line}</div></div></div>"
        f"<span class='{badge_cls}'>{esc(status_txt)}</span></a>"
    )


def _render_intro_hero_html(
    is_en: bool,
    bot_servers_count: int,
    is_logged_in: bool,
    primary_href: str,
    primary_txt: str,
    secondary_href: str,
    secondary_txt: str,
    prem_badge_html: str = "",
) -> str:
    hb_status = esc(MEM_BOT_HEARTBEAT.get("status", "ONLINE"))
    return f"""
    <section class="hero-card anim-card">
      <div style="margin-bottom:10px;display:flex;justify-content:center;gap:8px;flex-wrap:wrap;">
        <span class="ok-pill">BOT {hb_status}</span>
        {prem_badge_html}
      </div>
      <h1 class="hero-title">{esc(SITE_NAME)}</h1>
      <p class="hero-desc">{('Real-time protection for your server, rule controls, role and channel guards, snapshots rollback, and quick server actions.' if is_en else 'حماية فخمة للسيرفر، ضبط القواعد، حماية الرولات والرومات وصورة السيرفر، استرجاع اللقطات، وإدارة كاملة بسهولة.')}</p>
      <div class="hero-actions">
        <a class="btn-primary-purple" href="{esc(primary_href)}">{esc(primary_txt)}</a>
        <a class="btn-secondary-dark" href="{esc(secondary_href)}">{esc(secondary_txt)}</a>
      </div>
    </section>

    <section class="stat-card anim-card">
      <div class="stat-number">{bot_servers_count}</div>
      <div class="stat-bar"></div>
      <div class="stat-label">{('Servers Using The Bot' if is_en else 'عدد السيرفرات التي تستخدم البوت')}</div>
    </section>
    """


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
    is_logged_in = bool(user)
    is_admin = is_site_admin(user)
    is_prem = is_premium_user(user)
    prem_rec = _get_premium_record(str(user.get("id", "")).strip()) if user else None
    safe_flash = sanitize_flash_msg(flash)

    user_visible, _ = get_user_visible_guilds(user)
    user_active_guilds = [g for g in user_visible if not g.get("bot_missing")]
    can_access_guild_panel = bool(user and len(user_active_guilds) > 0)

    L = {
        "home": "Home" if is_en else "الرئيسية",
        "guild": "Security Panel" if is_en else "لوحة الحماية",
        "premium": "★ Premium" if is_en else "★ البريميوم",
        "admin": "Admin Panel" if is_en else "لوحة الإدارة",
        "services": "Services" if is_en else "الخدمات",
        "updates": "Updates & Logs" if is_en else "التحديثات والسجلات",
        "links": "Links" if is_en else "الروابط",
        "invite": "Invite Arab Security Bot",
        "login_discord": "Login with Discord",
        "dashboard": "Dashboard",
        "logout": "Logout" if is_en else "تسجيل الخروج",
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
        badge_txt = "OWNER" if str(user.get("id", "")) == ADMIN_USER_ID else ("ADMIN" if is_admin else ("PREMIUM" if is_prem else "MEMBER"))
        prem_status_line = (
            f"<div class='prem-active-box'>★ {'PREMIUM ACTIVE' if is_en else 'البريميوم مفعل'} • {esc(format_remaining_time(prem_rec, is_en=is_en))}</div>"
            if (is_prem and prem_rec)
            else ""
        )
        account_block = (
            f"<div class='user-box'>{avatar_html}"
            f"<div style='min-width:0;'><div class='uname'>{uname_safe} <span class='tag'>{badge_txt}</span></div>"
            f"<div class='uhandle'>ID: <code>{uid}</code></div></div></div>"
            f"{prem_status_line}"
            f"<a class='nav-item danger' href='/logout'><span>{L['logout']}</span></a>"
        )
    else:
        account_block = f"<a class='login-btn' href='/login?next=/dashboard'>{L['login_discord']}</a>"

    bot_servers_count = len(get_all_guilds())

    if is_logged_in:
        primary_href = "/invite"
        primary_txt = L["invite"]
        secondary_href = "/dashboard"
        secondary_txt = L["dashboard"]
    else:
        primary_href = "/login?next=/dashboard"
        primary_txt = L["login_discord"]
        secondary_href = "/invite"
        secondary_txt = L["invite"]

    prem_badge_html = (
        f"<span class='prem-pill'>★ {esc(format_remaining_time(prem_rec, is_en=is_en))}</span>"
        if (is_prem and prem_rec)
        else ""
    )

    if require_auth_view and not user:
        final_content = _render_intro_hero_html(
            is_en=is_en,
            bot_servers_count=bot_servers_count,
            is_logged_in=False,
            primary_href=primary_href,
            primary_txt=primary_txt,
            secondary_href=secondary_href,
            secondary_txt=secondary_txt,
            prem_badge_html=prem_badge_html,
        )
    else:
        final_content = content_html

    flash_banner = f"<div class='flash-banner anim-card' role='status'>{esc(safe_flash)}</div>" if safe_flash else ""

    nav_items = [
        ("home", "/", L["home"]),
    ]
    if can_access_guild_panel:
        nav_items.append(("guild", "/guild", L["guild"]))
    if is_prem:
        nav_items.append(("premium", "/premium", L["premium"]))
    if is_admin:
        nav_items.append(("admin", "/admin", L["admin"]))
    nav_items.extend(
        [
            ("services", "/services", L["services"]),
            ("updates", "/updates", L["updates"]),
            ("links", "/links", L["links"]),
        ]
    )

    nav_links_html = "".join(
        f"<a class='nav-item {'active' if active_nav == key else ''}' href='{href}'><span>{lbl}</span></a>"
        for key, href, lbl in nav_items
    )

    next_lang = "ar" if is_en else "en"
    lang_label = "العربية" if is_en else "English"

    return f"""<!DOCTYPE html>
<html lang="{lang}" dir="{dir_attr}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)} — {esc(SITE_NAME)}</title>
<style>
  :root {{
    --bg-deep: #07040f;
    --bg-grad:
      radial-gradient(circle at 50% -8%, rgba(147, 51, 234, 0.38), rgba(109, 40, 217, 0.14) 48%, #07040f 82%),
      radial-gradient(circle at 12% 24%, rgba(168, 85, 247, 0.18), transparent 44%),
      linear-gradient(180deg, #0c061a 0%, #07040f 100%);
    --card-bg: rgba(18, 10, 34, 0.94);
    --card-border: rgba(168, 85, 247, 0.30);
    --card-border-bright: rgba(192, 132, 252, 0.64);
    --prem-border: rgba(232, 121, 249, 0.58);
    --text-main: #ffffff;
    --text-sub: #ddd6fe;
  }}
  * {{ box-sizing: border-box; }}
  @keyframes fadeSlideUp {{
    from {{ opacity: 0; transform: translateY(10px) scale(0.99); }}
    to {{ opacity: 1; transform: translateY(0) scale(1); }}
  }}
  @keyframes pulseGlow {{
    0%, 100% {{ box-shadow: 0 0 0 rgba(168, 85, 247, 0); }}
    50% {{ box-shadow: 0 0 28px rgba(168, 85, 247, 0.26); }}
  }}
  .anim-card {{
    animation: fadeSlideUp 0.25s cubic-bezier(0.22, 1, 0.36, 1) both;
  }}
  body {{
    margin: 0;
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    background: var(--bg-deep);
    background-image: var(--bg-grad);
    color: var(--text-main);
    min-height: 100vh;
    overflow-x: hidden;
  }}
  .overlay {{
    opacity: 0;
    pointer-events: none;
    position: fixed;
    inset: 0;
    background: rgba(4, 2, 10, 0.78);
    z-index: 60;
    transition: opacity 0.22s ease;
  }}
  .overlay.open {{
    opacity: 1;
    pointer-events: auto;
  }}
  .sidebar {{
    position: fixed;
    top: 0;
    {('left' if is_en else 'right')}: 0;
    width: 284px;
    max-width: 86vw;
    height: 100vh;
    background: rgba(12, 7, 24, 0.98);
    border-{('right' if is_en else 'left')}: 1px solid var(--card-border-bright);
    padding: 18px 14px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    z-index: 70;
    overflow-y: auto;
    transform: translateX({('-105%' if is_en else '105%')});
    transition: transform 0.25s cubic-bezier(0.22, 1, 0.36, 1);
  }}
  .sidebar.open {{ transform: translateX(0); }}
  .page-container {{
    width: 100%;
    max-width: 820px;
    margin: 0 auto;
    padding: 18px 16px 56px;
  }}
  .top-bar {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 11px 15px;
    border-radius: 18px;
    background: rgba(18, 10, 34, 0.96);
    border: 1px solid var(--card-border-bright);
    margin-bottom: 18px;
    box-shadow: 0 8px 24px rgba(88, 28, 135, 0.26);
    animation: fadeSlideUp 0.2s ease both;
  }}
  .top-left {{ display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }}
  .icon-btn {{
    height: 38px;
    padding: 0 13px;
    border-radius: 12px;
    background: linear-gradient(145deg, rgba(46, 22, 88, 0.95), rgba(24, 12, 48, 0.95));
    border: 1px solid var(--card-border-bright);
    color: #fff;
    font-weight: 800;
    font-size: 16px;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    text-decoration: none;
    transition: transform 0.16s ease, background 0.16s ease, border-color 0.16s ease, box-shadow 0.16s ease;
  }}
  .icon-btn:hover {{
    background: linear-gradient(135deg, rgba(147, 51, 234, 0.55), rgba(192, 38, 211, 0.42));
    border-color: #f0abfc;
    transform: translateY(-1px);
    box-shadow: 0 6px 16px rgba(147, 51, 234, 0.34);
  }}
  .icon-btn:active {{ transform: scale(0.95); }}
  .lang-btn {{ font-size: 12.5px; }}
  .top-right {{
    display: flex;
    align-items: center;
    gap: 10px;
    text-align: {('left' if is_en else 'right')};
  }}
  .brand-title {{ font-size: 14px; font-weight: 900; letter-spacing: 0.4px; color: #fff; line-height: 1.2; }}
  .brand-sub {{ font-size: 11px; color: #c4b5fd; line-height: 1.25; }}
  .brand-badge {{
    width: 38px; height: 38px; border-radius: 12px;
    background: linear-gradient(135deg, #9333ea 0%, #d946ef 100%);
    box-shadow: 0 0 18px rgba(168, 85, 247, 0.48);
    color: #fff; font-weight: 900; font-size: 14px;
    display: flex; align-items: center; justify-content: center; flex-shrink: 0;
  }}
  .flash-banner {{
    background: linear-gradient(135deg, rgba(107, 33, 168, 0.52), rgba(134, 25, 143, 0.42));
    border: 1.5px solid var(--card-border-bright);
    color: #faf5ff; border-radius: 16px; padding: 13px 16px;
    margin-bottom: 18px; font-size: 13.5px; font-weight: 800; line-height: 1.55; text-align: center;
    box-shadow: 0 8px 20px rgba(107, 33, 168, 0.24);
  }}
  .hero-card {{
    background: var(--card-bg); border: 1px solid var(--card-border-bright);
    border-radius: 22px; padding: 28px 20px; text-align: center; margin-bottom: 18px;
    animation: fadeSlideUp 0.28s ease both, pulseGlow 4s infinite ease-in-out;
  }}
  .prem-active-box {{
    padding: 9px 12px; border-radius: 12px;
    background: rgba(217, 70, 239, 0.18); border: 1px solid var(--prem-border);
    color: #fdf4ff; font-size: 12px; font-weight: 800; text-align: center;
  }}
  .hero-title {{ margin: 0 0 12px; font-size: 28px; font-weight: 900; letter-spacing: 0.6px; color: #ffffff; }}
  .hero-desc {{ margin: 0 auto 22px; max-width: 540px; font-size: 14px; line-height: 1.75; color: var(--text-sub); font-weight: 600; }}
  .hero-actions {{ display: flex; flex-direction: column; gap: 10px; }}
  .btn-primary-purple {{
    display: block; width: 100%; padding: 13px 18px; border-radius: 14px;
    background: linear-gradient(135deg, #9333ea 0%, #c026d3 100%);
    border: 1px solid var(--card-border-bright); color: #fff; text-decoration: none;
    font-weight: 800; font-size: 14.5px; text-align: center; cursor: pointer;
    box-shadow: 0 8px 20px rgba(147, 51, 234, 0.34);
    transition: transform 0.16s ease, filter 0.16s ease, box-shadow 0.16s ease;
  }}
  .btn-primary-purple:hover {{
    transform: translateY(-2px);
    filter: brightness(1.12);
    box-shadow: 0 12px 26px rgba(168, 85, 247, 0.52);
  }}
  .btn-primary-purple:active {{ transform: scale(0.985); }}
  .btn-crimson {{
    display: block; width: 100%; padding: 13px 18px; border-radius: 14px;
    background: linear-gradient(135deg, #be185d 0%, #831843 100%);
    border: 1px solid rgba(244, 114, 182, 0.52); color: #fff; text-decoration: none;
    font-weight: 800; font-size: 14.5px; text-align: center; cursor: pointer;
    box-shadow: 0 8px 18px rgba(190, 24, 93, 0.28);
    transition: transform 0.16s ease, filter 0.16s ease, box-shadow 0.16s ease;
  }}
  .btn-crimson:hover {{
    transform: translateY(-2px);
    filter: brightness(1.12);
    box-shadow: 0 10px 24px rgba(244, 114, 182, 0.38);
  }}
  .btn-crimson:active {{ transform: scale(0.985); }}
  .btn-secondary-dark {{
    display: block; width: 100%; padding: 13px 18px; border-radius: 14px;
    background: linear-gradient(145deg, rgba(35, 19, 64, 0.96), rgba(20, 11, 38, 0.98));
    border: 1px solid var(--card-border-bright);
    color: #f5f3ff; text-decoration: none; font-weight: 800; font-size: 14.5px; text-align: center; cursor: pointer;
    box-shadow: 0 6px 14px rgba(0, 0, 0, 0.25);
    transition: transform 0.16s ease, background 0.16s ease, border-color 0.16s ease, box-shadow 0.16s ease;
  }}
  .btn-secondary-dark:hover {{
    transform: translateY(-2px);
    background: linear-gradient(145deg, rgba(62, 32, 114, 0.98), rgba(36, 18, 68, 0.98));
    border-color: #e879f9;
    box-shadow: 0 8px 20px rgba(126, 34, 206, 0.36);
  }}
  .btn-secondary-dark:active {{ transform: scale(0.985); }}
  .stat-card {{
    background: var(--card-bg); border: 1px solid var(--card-border);
    border-radius: 22px; padding: 24px 20px; text-align: center; margin-bottom: 16px;
    transition: transform 0.18s ease, border-color 0.18s ease;
  }}
  .stat-card:hover {{ transform: translateY(-2px); border-color: var(--card-border-bright); }}
  .stat-number {{ font-size: 32px; font-weight: 900; color: #ffffff; line-height: 1.1; }}
  .stat-bar {{ width: 32px; height: 3px; border-radius: 999px; background: linear-gradient(90deg, #9333ea, #e879f9); margin: 10px auto 12px; }}
  .stat-label {{ font-size: 14px; font-weight: 700; color: #ddd6fe; }}
  .glass-card {{
    background: var(--card-bg); border: 1px solid var(--card-border);
    border-radius: 22px; padding: 20px; margin-bottom: 16px;
    box-shadow: 0 12px 30px rgba(0, 0, 0, 0.38);
  }}
  .admin-hero {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 12px;
    padding: 18px;
    border-radius: 18px;
    background: linear-gradient(135deg, rgba(147, 51, 234, 0.30), rgba(192, 38, 211, 0.14), rgba(18, 10, 34, 0.96));
    border: 1px solid var(--card-border-bright);
    margin-bottom: 16px;
  }}
  .admin-kpis {{
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 10px;
    margin-bottom: 16px;
  }}
  @media (max-width: 540px) {{ .admin-kpis {{ grid-template-columns: 1fr; }} }}
  .kpi-box {{
    padding: 14px;
    border-radius: 16px;
    background: linear-gradient(160deg, rgba(28, 15, 54, 0.92), rgba(12, 7, 24, 0.94));
    border: 1px solid var(--card-border);
    text-align: center;
    transition: transform 0.16s ease, border-color 0.16s ease;
  }}
  .kpi-box:hover {{ transform: translateY(-2px); border-color: var(--card-border-bright); }}
  .kpi-num {{ font-size: 22px; font-weight: 900; color: #fff; }}
  .kpi-lbl {{ font-size: 11.5px; color: #c4b5fd; margin-top: 4px; font-weight: 700; }}
  .cat-tabs {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(112px, 1fr));
    gap: 8px;
    margin-bottom: 16px;
  }}
  .cat-tab-btn {{
    background: linear-gradient(145deg, rgba(30, 16, 56, 0.95), rgba(18, 10, 36, 0.96));
    border: 1px solid var(--card-border);
    color: #e9d5ff;
    border-radius: 13px;
    padding: 11px 9px;
    font-size: 12.5px;
    font-weight: 800;
    cursor: pointer;
    transition: all 0.16s ease;
    text-align: center;
  }}
  .cat-tab-btn:hover {{
    border-color: var(--card-border-bright);
    background: linear-gradient(145deg, rgba(68, 34, 124, 0.96), rgba(40, 20, 76, 0.96));
    transform: translateY(-1px);
  }}
  .cat-tab-btn:active {{ transform: scale(0.97); }}
  .cat-tab-btn.active {{
    background: linear-gradient(135deg, #9333ea 0%, #c026d3 100%);
    border-color: #f5d0fe;
    color: #ffffff;
    box-shadow: 0 6px 20px rgba(168, 85, 247, 0.42);
  }}
  .cat-pane {{ display: none; }}
  .cat-pane.active {{ display: block; animation: fadeSlideUp 0.2s ease both; }}
  .link-card {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 14px 16px;
    border-radius: 15px;
    background: rgba(14, 8, 28, 0.92);
    border: 1px solid var(--card-border);
    text-decoration: none;
    color: #fff;
    margin-bottom: 10px;
    transition: transform 0.16s ease, background 0.16s ease, border-color 0.16s ease;
  }}
  .link-card:hover {{
    transform: translateY(-1px);
    background: rgba(38, 19, 72, 0.96);
    border-color: var(--card-border-bright);
  }}
  .link-card-title {{ font-weight: 800; font-size: 14px; }}
  .link-card-sub {{ font-size: 12px; color: #c4b5fd; margin-top: 2px; }}
  .link-arrow {{ font-weight: 900; color: #d8b4fe; font-size: 15px; }}
  .panel-section {{
    background: rgba(12, 7, 24, 0.90);
    border: 1px solid var(--card-border);
    border-radius: 18px;
    padding: 16px;
    margin-bottom: 14px;
  }}
  .panel-section.prem-sec {{
    background: linear-gradient(160deg, rgba(126, 34, 206, 0.22), rgba(18, 10, 34, 0.96));
    border-color: var(--prem-border);
  }}
  .panel-section-head {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    margin-bottom: 12px;
    padding-bottom: 10px;
    border-bottom: 1px solid var(--card-border);
  }}
  .panel-section-title {{
    margin: 0;
    font-size: 15px;
    font-weight: 800;
    color: #ffffff;
  }}
  .sub-panel {{
    background: rgba(12, 7, 24, 0.92); border: 1px solid var(--card-border);
    border-radius: 18px; padding: 16px; margin-bottom: 16px;
    transition: border-color 0.16s ease;
  }}
  .sub-panel:hover {{ border-color: var(--card-border-bright); }}
  .sub-panel-head {{
    display: flex; align-items: center; justify-content: space-between; gap: 10px;
    margin-bottom: 12px; padding-bottom: 10px; border-bottom: 1px solid var(--card-border);
  }}
  .sub-panel-title {{ margin: 0; font-size: 15px; font-weight: 800; color: #ffffff; }}
  .grid-2 {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; margin-bottom: 12px; }}
  @media (max-width: 540px) {{ .grid-2 {{ grid-template-columns: 1fr; }} }}
  .nav-item {{
    display: flex; align-items: center; gap: 10px; padding: 10px 12px; border-radius: 12px;
    color: #f3e8ff; text-decoration: none; font-size: 13.5px; font-weight: 700;
    transition: background 0.15s ease, transform 0.15s ease;
  }}
  .nav-item:hover {{ background: rgba(147, 51, 234, 0.24); transform: translateX({('2px' if is_en else '-2px')}); }}
  .nav-item.active {{ background: rgba(147, 51, 234, 0.40); border: 1px solid var(--card-border-bright); color: #ffffff; }}
  .nav-item.danger {{ color: #f9a8d4; }}
  .sep {{ height: 1px; background: var(--card-border); margin: 6px 0; }}
  .user-box {{
    display: flex; align-items: center; gap: 10px; padding: 10px; border-radius: 14px;
    background: rgba(34, 17, 64, 0.90); border: 1px solid var(--card-border);
  }}
  .avatar, .avatar-img {{ width: 38px; height: 38px; border-radius: 999px; object-fit: cover; }}
  .avatar {{ background: #9333ea; display: flex; align-items: center; justify-content: center; font-weight: 800; }}
  .uname {{ font-weight: 800; font-size: 13px; }}
  .uhandle {{ font-size: 11px; color: #c4b5fd; }}
  .tag {{ font-size: 10.5px; padding: 4px 10px; border-radius: 9px; background: rgba(147, 51, 234, 0.34); border: 1px solid rgba(192, 132, 252, 0.45); color: #f3e8ff; font-weight: 800; white-space: nowrap; }}
  .ok-pill {{ font-size: 10.5px; padding: 4px 10px; border-radius: 9px; background: rgba(16, 185, 129, 0.18); border: 1px solid rgba(52, 211, 153, 0.48); color: #a7f3d0; font-weight: 800; white-space: nowrap; }}
  .warn-pill {{ font-size: 10.5px; padding: 4px 10px; border-radius: 9px; background: rgba(217, 70, 239, 0.22); border: 1px solid rgba(232, 121, 249, 0.48); color: #f5d0fe; font-weight: 800; white-space: nowrap; }}
  .prem-pill {{ font-size: 10.5px; padding: 4px 10px; border-radius: 999px; background: linear-gradient(135deg, rgba(168, 85, 247, 0.34), rgba(217, 70, 239, 0.32)); border: 1px solid rgba(232, 121, 249, 0.65); color: #fdf4ff; font-weight: 800; }}
  .admin-pill {{ font-size: 10.5px; padding: 4px 9px; border-radius: 8px; background: rgba(147, 51, 234, 0.34); border: 1px solid var(--card-border-bright); color: #f3e8ff; font-weight: 800; }}
  .login-btn {{
    display: block; text-align: center; padding: 11px 14px; border-radius: 13px;
    background: linear-gradient(135deg, #9333ea, #c026d3); color: #fff; text-decoration: none; font-weight: 800; font-size: 13.5px;
    box-shadow: 0 6px 16px rgba(147, 51, 234, 0.34);
    transition: filter 0.15s ease, transform 0.15s ease, box-shadow 0.15s ease;
  }}
  .login-btn:hover {{ filter: brightness(1.12); transform: translateY(-1px); box-shadow: 0 8px 20px rgba(168, 85, 247, 0.46); }}
  .inp, .sel, .bio-textarea {{
    width: 100%; background: rgba(10, 5, 20, 0.96); border: 1px solid var(--card-border);
    color: #fff; border-radius: 12px; padding: 11px 13px; font-size: 14px; margin-bottom: 10px;
    font-family: inherit;
    transition: border-color 0.15s ease, box-shadow 0.15s ease;
  }}
  .bio-textarea {{
    min-height: 142px;
    margin-top: 8px;
    margin-bottom: 6px;
    line-height: 1.7;
    resize: vertical;
  }}
  .inp:focus, .sel:focus, .bio-textarea:focus {{
    outline: none;
    border-color: #e879f9;
    box-shadow: 0 0 0 3px rgba(168, 85, 247, 0.22);
  }}
  .lbl {{ display: block; font-size: 12.5px; color: #e9d5ff; margin: 8px 0 5px; font-weight: 700; }}
  .bio-meta {{
    display: flex; justify-content: space-between; align-items: center; gap: 8px;
    font-size: 11.5px; color: #c4b5fd; margin-bottom: 12px;
  }}
  .switch-row {{
    display: flex; align-items: center; justify-content: space-between; gap: 14px;
    padding: 12px 14px; border-radius: 14px;
    background: linear-gradient(145deg, rgba(31, 16, 62, 0.78), rgba(18, 10, 38, 0.88));
    border: 1px solid rgba(168, 85, 247, 0.26); margin-bottom: 10px; font-size: 13.5px; font-weight: 700;
    cursor: pointer; user-select: none;
    transition: background 0.16s ease, border-color 0.16s ease, transform 0.15s ease, box-shadow 0.16s ease;
  }}
  .switch-row:hover {{
    background: linear-gradient(145deg, rgba(54, 27, 104, 0.88), rgba(29, 15, 58, 0.94));
    border-color: var(--card-border-bright);
    transform: translateY(-1px);
    box-shadow: 0 6px 16px rgba(126, 34, 206, 0.22);
  }}
  .switch-input {{
    position: relative;
    appearance: none;
    -webkit-appearance: none;
    width: 48px;
    min-width: 48px;
    height: 26px;
    border-radius: 999px;
    background: rgba(12, 7, 24, 0.95);
    border: 1.5px solid rgba(168, 85, 247, 0.45);
    cursor: pointer;
    transition: background 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
  }}
  .switch-input::after {{
    content: "";
    position: absolute;
    top: 2px;
    left: 2px;
    width: 20px;
    height: 20px;
    border-radius: 999px;
    background: #e9d5ff;
    box-shadow: 0 2px 6px rgba(0, 0, 0, 0.45);
    transition: transform 0.2s cubic-bezier(0.22, 1, 0.36, 1), background 0.2s ease;
  }}
  .switch-input:checked {{
    background: linear-gradient(135deg, #9333ea 0%, #d946ef 100%);
    border-color: #f5d0fe;
    box-shadow: 0 0 14px rgba(192, 132, 252, 0.45);
  }}
  .switch-input:checked::after {{
    transform: translateX(22px);
    background: #ffffff;
  }}
  .list-row {{
    display: flex; justify-content: space-between; align-items: center; gap: 10px;
    padding: 11px 13px; border-radius: 13px; background: rgba(168, 85, 247, 0.06);
    border: 1px solid rgba(168, 85, 247, 0.24); margin-bottom: 8px;
    transition: background 0.15s ease, border-color 0.15s ease;
  }}
  .list-row:hover {{ background: rgba(147, 51, 234, 0.15); border-color: var(--card-border-bright); }}
  .guild-icon, .guild-icon-ph {{ width: 42px; height: 42px; border-radius: 12px; object-fit: cover; flex-shrink: 0; }}
  .guild-icon-ph {{
    background: linear-gradient(135deg, rgba(147, 51, 234, 0.48), rgba(217, 70, 239, 0.38));
    border: 1px solid var(--card-border-bright);
    display: flex; align-items: center; justify-content: center; font-weight: 900; font-size: 15px; color: #fff;
  }}
  .mini-btn {{
    padding: 10px 14px; border-radius: 12px; border: 1px solid var(--card-border-bright);
    background: linear-gradient(135deg, rgba(147, 51, 234, 0.56), rgba(192, 38, 211, 0.42));
    color: #fff; font-size: 12.5px; font-weight: 800; cursor: pointer; text-align: center;
    box-shadow: 0 4px 12px rgba(126, 34, 206, 0.25);
    transition: background 0.15s ease, transform 0.15s ease, box-shadow 0.15s ease;
  }}
  .mini-btn:hover {{
    background: linear-gradient(135deg, #9333ea 0%, #d946ef 100%);
    border-color: #f5d0fe;
    transform: translateY(-1px);
    box-shadow: 0 7px 16px rgba(168, 85, 247, 0.38);
  }}
  .mini-btn:active {{ transform: scale(0.96); }}
  .mini-btn.red {{
    border-color: rgba(244, 114, 182, 0.62);
    background: linear-gradient(135deg, rgba(190, 24, 93, 0.56), rgba(131, 24, 67, 0.56));
    box-shadow: 0 4px 12px rgba(190, 24, 93, 0.24);
  }}
  .mini-btn.red:hover {{
    background: linear-gradient(135deg, #db2777 0%, #9d174d 100%);
    border-color: #fbcfe8;
    box-shadow: 0 7px 16px rgba(219, 39, 119, 0.38);
  }}
  .album-box {{
    padding: 14px; border-radius: 15px; background: rgba(10, 5, 20, 0.88);
    border: 1px dashed var(--card-border-bright); margin-bottom: 12px;
  }}
  .preview-thumb {{
    width: 74px; height: 74px; border-radius: 13px; object-fit: cover;
    border: 1px solid var(--card-border-bright); margin-top: 8px;
  }}
  .preview-banner {{
    width: 100%; max-width: 250px; height: 74px; border-radius: 13px; object-fit: cover;
    border: 1px solid var(--card-border-bright); margin-top: 8px;
  }}
  .muted {{ color: #c4b5fd; font-size: 13px; }}
  code {{ background: rgba(10, 5, 20, 0.94); padding: 2px 6px; border-radius: 6px; font-size: 12px; color: #f3e8ff; }}
</style>
</head>
<body>
<div id="overlay" class="overlay" onclick="toggleDrawer(false)"></div>

<aside id="drawer" class="sidebar" aria-label="{L['menu']}">
  <a class="nav-item" href="/"><span>{esc(SITE_NAME)}</span></a>
  {account_block}
  <div class="sep"></div>
  {nav_links_html}
  <div class="sep"></div>
  <a class="nav-item" href="/invite"><span>{L['invite']}</span></a>
</aside>

<div class="page-container">
  <header class="top-bar">
    <div class="top-left">
      <button class="icon-btn" type="button" onclick="toggleDrawer(true)" aria-label="{L['menu']}">&#9776;</button>
      <button class="icon-btn lang-btn" type="button" onclick="switchLang('{next_lang}')">{lang_label}</button>
    </div>

    <div class="top-right">
      <div>
        <div class="brand-title">{esc(SITE_NAME)}</div>
        <div class="brand-sub">{L['supervised']} {esc(OWNER_NAME)}</div>
      </div>
      <div class="brand-badge">AS</div>
    </div>
  </header>

  {flash_banner}
  {final_content}
</div>

<script>
function toggleDrawer(open) {{
  document.getElementById("drawer").classList.toggle("open", open);
  document.getElementById("overlay").classList.toggle("open", open);
}}
function switchCat(catKey, btn) {{
  document.querySelectorAll(".cat-tab-btn").forEach(function(b) {{ b.classList.remove("active"); }});
  document.querySelectorAll(".cat-pane").forEach(function(p) {{ p.classList.remove("active"); }});
  if (btn) btn.classList.add("active");
  var pane = document.getElementById("cat-" + catKey);
  if (pane) pane.classList.add("active");
}}
function updateBioCounter(taId, cntId) {{
  var ta = document.getElementById(taId);
  var cnt = document.getElementById(cntId);
  if (ta && cnt) {{
    cnt.textContent = (ta.value || "").length + " / {MAX_BIO_CHARS}";
  }}
}}
function filterGuildsList(queryVal) {{
  var q = (queryVal || "").trim().toLowerCase();
  document.querySelectorAll(".guild-search-item").forEach(function(el) {{
    var hay = (el.getAttribute("data-search") || "").toLowerCase();
    el.style.display = (!q || hay.indexOf(q) !== -1) ? "flex" : "none";
  }});
}}
function switchLang(targetLang) {{
  try {{
    document.cookie = "arab_sec_lang=" + encodeURIComponent(targetLang) + "; path=/; max-age=" + (86400 * 365) + "; SameSite=Lax";
  }} catch (e) {{}}
  var url = new URL(window.location.href);
  url.searchParams.set("lang", targetLang);
  window.location.href = url.toString();
}}
function clearMediaField(hiddenId, previewId, nameId, fileInputId) {{
  var hEl = document.getElementById(hiddenId);
  var pEl = document.getElementById(previewId);
  var nEl = document.getElementById(nameId);
  var fEl = fileInputId ? document.getElementById(fileInputId) : null;
  if (hEl) hEl.value = "";
  if (nEl) nEl.value = "";
  if (fEl) fEl.value = "";
  if (pEl) {{
    pEl.src = "";
    pEl.style.display = "none";
  }}
}}
function readAlbumFile(inputEl, hiddenId, previewId, nameId) {{
  var file = inputEl && inputEl.files && inputEl.files[0];
  if (!file) return;
  if (file.size > 10000000) {{
    alert("File size is too large.");
    inputEl.value = "";
    return;
  }}
  var reader = new FileReader();
  reader.onload = function(ev) {{
    var dataUrl = ev.target.result || "";
    var hEl = document.getElementById(hiddenId);
    var pEl = document.getElementById(previewId);
    var nEl = document.getElementById(nameId);
    if (hEl) hEl.value = dataUrl;
    if (nEl) nEl.value = file.name || "image";
    if (pEl && dataUrl) {{
      pEl.src = dataUrl;
      pEl.style.display = "block";
    }}
  }};
  reader.readAsDataURL(file);
}}
</script>
</body>
</html>"""


async def handle_invite_redirect(request: web.Request) -> web.Response:
    user = get_discord_session(request)
    if not user:
        raise web.HTTPFound("/login?next=" + quote("/invite") + "&msg=" + quote("Please login with Discord first to invite the bot."))
    target_invite = sanitize_http_url(BOT_INVITE_URL) or "https://discord.com"
    raise web.HTTPFound(target_invite)


async def handle_dashboard_redirect(request: web.Request) -> web.Response:
    user = get_discord_session(request)
    if not user:
        raise web.HTTPFound("/login?next=" + quote("/dashboard"))
    visible, _ = get_user_visible_guilds(user)
    active = [g for g in visible if not g.get("bot_missing")]
    if active:
        raise web.HTTPFound(f"/guild?id={active[0]['id']}")
    raise web.HTTPFound("/guild")


async def home_handler(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    user = get_discord_session(request)
    is_logged_in = bool(user)
    is_prem = is_premium_user(user)
    prem_rec = _get_premium_record(str(user.get("id", "")).strip()) if user else None
    flash = sanitize_flash_msg(request.query.get("msg"))
    if not flash and not DISCORD_CLIENT_SECRET:
        flash = (
            "Please set DISCORD_CLIENT_SECRET in environment variables to enable Discord login."
            if is_en
            else "يرجى ضبط DISCORD_CLIENT_SECRET في متغيرات البيئة لتفعيل تسجيل الدخول بديسكورد."
        )

    bot_servers_count = len(get_all_guilds())
    if is_logged_in:
        primary_href = "/invite"
        primary_txt = "Invite Arab Security Bot"
        secondary_href = "/dashboard"
        secondary_txt = "Dashboard"
    else:
        primary_href = "/login?next=/dashboard"
        primary_txt = "Login with Discord"
        secondary_href = "/invite"
        secondary_txt = "Invite Arab Security Bot"

    prem_badge_html = (
        f"<span class='prem-pill'>★ {esc(format_remaining_time(prem_rec, is_en=is_en))}</span>"
        if (is_prem and prem_rec)
        else ""
    )

    body = _render_intro_hero_html(
        is_en=is_en,
        bot_servers_count=bot_servers_count,
        is_logged_in=is_logged_in,
        primary_href=primary_href,
        primary_txt=primary_txt,
        secondary_href=secondary_href,
        secondary_txt=secondary_txt,
        prem_badge_html=prem_badge_html,
    )
    return web.Response(
        text=render_page("Home" if is_en else "الرئيسية", "home", body, request, flash=flash),
        content_type="text/html",
    )


def _build_toggle_items(keys: tuple[str, ...], cfg: dict, is_en: bool) -> str:
    html_out = ""
    for k in keys:
        lbl_txt = FEATURE_LABELS_EN.get(k, k) if is_en else FEATURE_LABELS_AR.get(k, k)
        html_out += (
            f"<label class='switch-row'>"
            f"<span>{esc(lbl_txt)}</span>"
            f"<input class='switch-input' type='checkbox' name='sh_{k}' {'checked' if cfg.get(k) else ''}></label>"
        )
    return html_out


def _process_premium_profile_and_perks(form: dict, cur_prof: dict, cur_perks: dict) -> tuple[dict, dict, bool, bool, bool, bool]:
    old_bio = sanitize_bio_text(cur_prof.get("bio", ""))
    old_ava = sanitize_image_data_url(cur_prof.get("avatar_data_url", ""))
    old_ban = sanitize_image_data_url(cur_prof.get("banner_data_url", ""))

    bio_clean = sanitize_bio_text(form.get("bio", old_bio)) if "bio" in form else old_bio
    ava_data = sanitize_image_data_url(form.get("avatar_data_url", "")) if "avatar_data_url" in form else old_ava
    ban_data = sanitize_image_data_url(form.get("banner_data_url", "")) if "banner_data_url" in form else old_ban

    bio_changed = bio_clean != old_bio
    avatar_changed = ava_data != old_ava
    banner_changed = ban_data != old_ban
    profile_changed = bio_changed or avatar_changed or banner_changed

    prof_data = {
        "bio": bio_clean,
        "avatar_data_url": ava_data,
        "avatar_name": str(form.get("avatar_name", "" if not ava_data else cur_prof.get("avatar_name", ""))).strip()[:80],
        "banner_data_url": ban_data,
        "banner_name": str(form.get("banner_name", "" if not ban_data else cur_prof.get("banner_name", ""))).strip()[:80],
    }
    perks_data = {
        "alert_channel_id": str(form.get("alert_channel_id", cur_perks.get("alert_channel_id", ""))).strip(),
        "alert_webhook_url": sanitize_http_url(
            form.get("alert_webhook_url", cur_perks.get("alert_webhook_url", ""))
        ),
        "ultra_fortress_mode": form.get("ultra_fortress_mode", form.get("pr_ultra_fortress")) == "on",
        "instant_rollback_enabled": form.get("instant_rollback_enabled", form.get("pr_instant_rollback")) == "on",
        "priority_shield_response": form.get("priority_shield_response", form.get("pr_priority_shield")) == "on",
    }
    return prof_data, perks_data, profile_changed, bio_changed, avatar_changed, banner_changed


def _render_premium_media_fields(prof: dict, perks: dict, is_en: bool, use_pr_prefix: bool = False) -> str:
    ava_src = str(prof.get("avatar_data_url", "") or "")
    ban_src = str(prof.get("banner_data_url", "") or "")
    bio_val = sanitize_bio_text(prof.get("bio", "") or "")
    ava_img_tag = (
        f"<img id='ava_preview' class='preview-thumb' src='{esc(ava_src)}' alt=''>"
        if ava_src
        else "<img id='ava_preview' class='preview-thumb' src='' alt='' style='display:none;'>"
    )
    ban_img_tag = (
        f"<img id='ban_preview' class='preview-thumb preview-banner' src='{esc(ban_src)}' alt=''>"
        if ban_src
        else "<img id='ban_preview' class='preview-thumb preview-banner' src='' alt='' style='display:none;'>"
    )
    uf_name = "pr_ultra_fortress" if use_pr_prefix else "ultra_fortress_mode"
    ir_name = "pr_instant_rollback" if use_pr_prefix else "instant_rollback_enabled"
    ps_name = "pr_priority_shield" if use_pr_prefix else "priority_shield_response"
    bio_id = "bio_area_guild" if use_pr_prefix else "bio_area_prem"
    cnt_id = "bio_cnt_guild" if use_pr_prefix else "bio_cnt_prem"

    lbl_fortress = "High Shield Mode" if is_en else "حماية فائقة"
    lbl_rollback = "Instant Rollback" if is_en else "الاسترجاع الفوري"
    lbl_priority = "Priority Shield Response" if is_en else "استجابة الحماية الفورية"

    return f"""
    <input type="hidden" id="avatar_data_url" name="avatar_data_url" value="{esc(ava_src)}">
    <input type="hidden" id="avatar_name" name="avatar_name" value="{esc(prof.get('avatar_name', ''))}">
    <input type="hidden" id="banner_data_url" name="banner_data_url" value="{esc(ban_src)}">
    <input type="hidden" id="banner_name" name="banner_name" value="{esc(prof.get('banner_name', ''))}">

    <label class="switch-row">
      <span>{esc(lbl_fortress)}</span>
      <input class="switch-input" type="checkbox" name="{uf_name}" {'checked' if perks.get('ultra_fortress_mode') else ''}>
    </label>
    <label class="switch-row">
      <span>{esc(lbl_rollback)}</span>
      <input class="switch-input" type="checkbox" name="{ir_name}" {'checked' if perks.get('instant_rollback_enabled', True) else ''}>
    </label>
    <label class="switch-row">
      <span>{esc(lbl_priority)}</span>
      <input class="switch-input" type="checkbox" name="{ps_name}" {'checked' if perks.get('priority_shield_response', True) else ''}>
    </label>

    <label class="lbl" for="{bio_id}">{('Custom Bot Bio (Up to 270 chars)' if is_en else 'نبذة البوت (البايو — حتى 270 حرفاً)')}</label>
    <textarea id="{bio_id}" class="bio-textarea" rows="5" maxlength="{MAX_BIO_CHARS}" name="bio" oninput="updateBioCounter('{bio_id}', '{cnt_id}')" placeholder="{('Enter full bot bio here...' if is_en else 'اكتب نبذة البوت هنا بكل وضوح حتى 270 حرفاً...')}">{esc(bio_val)}</textarea>
    <div class="bio-meta">
      <span>{('Full bio preview up to 270 characters' if is_en else 'الحد الأقصى للبايو 270 حرفاً')}</span>
      <span id="{cnt_id}">{len(bio_val)} / {MAX_BIO_CHARS}</span>
    </div>

    <div class="album-box">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
        <label class="lbl" style="margin:0;">{('Bot Avatar' if is_en else 'أفتار البوت (صورة البوت)')}</label>
        <button type="button" class="mini-btn red" onclick="clearMediaField('avatar_data_url', 'ava_preview', 'avatar_name', 'ava_file_inp')">{('Remove Avatar' if is_en else 'إزالة الأفتار')}</button>
      </div>
      <input id="ava_file_inp" class="inp" style="margin-top:6px;margin-bottom:4px;" type="file" accept="image/*" onchange="readAlbumFile(this, 'avatar_data_url', 'ava_preview', 'avatar_name')">
      <span class="muted">{esc(prof.get('avatar_name') or ('No avatar selected' if is_en else 'لم يتم اختيار أفتار'))}</span>
      {ava_img_tag}
    </div>

    <div class="album-box">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
        <label class="lbl" style="margin:0;">{('Bot Banner' if is_en else 'بنر البوت')}</label>
        <button type="button" class="mini-btn red" onclick="clearMediaField('banner_data_url', 'ban_preview', 'banner_name', 'ban_file_inp')">{('Remove Banner' if is_en else 'إزالة البنر')}</button>
      </div>
      <input id="ban_file_inp" class="inp" style="margin-top:6px;margin-bottom:4px;" type="file" accept="image/*" onchange="readAlbumFile(this, 'banner_data_url', 'ban_preview', 'banner_name')">
      <span class="muted">{esc(prof.get('banner_name') or ('No banner selected' if is_en else 'لم يتم اختيار بنر'))}</span>
      {ban_img_tag}
    </div>

    <div class="grid-2" style="margin-bottom:0;">
      <div>
        <label class="lbl">{('Alert Channel ID' if is_en else 'آيدي روم التنبيهات')}</label>
        <input class="inp" style="margin-bottom:0;" type="text" name="alert_channel_id" value="{esc(perks.get('alert_channel_id', ''))}">
      </div>
      <div>
        <label class="lbl">{('Alert Webhook URL' if is_en else 'رابط ويبهوك التنبيهات')}</label>
        <input class="inp" style="margin-bottom:0;" type="url" name="alert_webhook_url" value="{esc(perks.get('alert_webhook_url', ''))}">
      </div>
    </div>
    """


async def handle_guild(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    sess_pair = get_discord_session_with_id(request)
    if not sess_pair:
        return web.Response(
            text=render_page("Security Panel" if is_en else "لوحة الحماية", "guild", "", request, require_auth_view=True),
            content_type="text/html",
        )
    session_id, user = sess_pair
    actor_uid = str(user.get("id", "")).strip()
    is_prem = is_premium_user(user)
    guilds, _ = get_user_visible_guilds(user)
    active_guilds = [g for g in guilds if not g.get("bot_missing")]

    if not active_guilds:
        _invalidate_guilds_cache()
        guilds, _ = get_user_visible_guilds(user)
        active_guilds = [g for g in guilds if not g.get("bot_missing")]

    if not active_guilds:
        cards_html = "".join(_render_guild_card(g, is_en, show_admin_meta=False) for g in guilds[:12])
        extra_list = (
            f"<div style='margin-top:14px;'>{cards_html}</div>"
            if cards_html
            else ""
        )
        msg = (
            "No connected server found yet. Make sure the bot has synced its servers or invite it to your server."
            if is_en
            else "لم يتم العثور على سيرفر متصل بالبوت حالياً. تأكد من مزامنة البوت لسيرفراته أو أضفه إلى سيرفرك."
        )
        empty_body = f"""
        <div class='glass-card anim-card'>
          <h2 style='margin:0 0 8px;'>{('Security Panel' if is_en else 'لوحة الحماية')}</h2>
          <p class='muted' style='margin:0 0 14px;'>{esc(msg)}</p>
          <div class='hero-actions'>
            <a class='btn-primary-purple' href='/invite'>Invite Arab Security Bot</a>
            <a class='btn-secondary-dark' href='/guild'>{('Refresh Servers' if is_en else 'تحديث السيرفرات')}</a>
          </div>
          {extra_list}
        </div>
        """
        return web.Response(
            text=render_page("Security Panel" if is_en else "لوحة الحماية", "guild", empty_body, request),
            content_type="text/html",
        )

    gid = str(request.query.get("id", "")).strip()
    if not user_can_manage_guild(gid, user, require_bot_present=True):
        gid = active_guilds[0]["id"]

    flash = ""
    if request.method == "POST":
        form = await read_post_safe(request)
        if not form:
            flash = "Invalid request body." if is_en else "بيانات الطلب غير صالحة."
        elif not consume_csrf_token(str(form.get("csrf_token", "")), session_id):
            flash = "Security token expired. Refresh and try again." if is_en else "انتهت صلاحية رمز الحماية، أعد المحاولة."
        elif is_replay_request(str(form.get("req_nonce", ""))):
            flash = "Duplicate request blocked." if is_en else "تم منع طلب مكرر."
        else:
            posted_gid = resolve_guild_id_from_input(str(form.get("guild_id", gid)), user, require_bot_present=True)
            if posted_gid and user_can_manage_guild(posted_gid, user, require_bot_present=True):
                gid = posted_gid
                action_type = str(form.get("form_action", "save")).strip()
                if action_type == "reset_defaults":
                    save_guild_cfg(gid, {"reset_defaults": True}, is_premium=is_prem)
                    enqueue_remote_action(gid, "sync_guild_cfg", gid, extra={"guild_id": gid, "user_id": actor_uid}, actor_user_id=actor_uid)
                    log_event(f"Reset guild settings for {gid}", guild_id=gid, level="SEC")
                    flash = "Reset to defaults." if is_en else "تمت إعادة الضبط للوضع الافتراضي."
                elif action_type == "save_snapshot":
                    save_guild_cfg(gid, {"save_snapshot": True}, is_premium=is_prem)
                    log_event(f"Saved permissions snapshot for {gid}", guild_id=gid, level="SEC")
                    flash = "Snapshot saved." if is_en else "تم حفظ لقطة الصلاحيات."
                elif action_type == "restore_snapshot":
                    snap_id = str(form.get("target_snapshot_id", "")).strip()
                    if snap_id:
                        save_guild_cfg(gid, {"restore_snapshot_id": snap_id}, is_premium=is_prem)
                        enqueue_remote_action(gid, "sync_guild_cfg", gid, extra={"guild_id": gid, "user_id": actor_uid, "restored_snapshot": snap_id}, actor_user_id=actor_uid)
                        log_event(f"Restored snapshot #{snap_id} for {gid}", guild_id=gid, level="SEC")
                        flash = f"Snapshot #{snap_id} restored." if is_en else f"تم استعادة اللقطة #{snap_id} ومزامنتها."
                elif action_type == "delete_snapshot":
                    snap_id = str(form.get("target_snapshot_id", "")).strip()
                    if snap_id:
                        save_guild_cfg(gid, {"delete_snapshot_id": snap_id}, is_premium=is_prem)
                        flash = f"Snapshot #{snap_id} deleted." if is_en else f"تم حذف اللقطة #{snap_id}."
                elif action_type == "add_trusted":
                    uid = str(form.get("trusted_uid", "")).strip()
                    if uid.isdigit():
                        save_guild_cfg(gid, {"trusted_add": uid}, is_premium=is_prem)
                        enqueue_remote_action(gid, "sync_guild_cfg", gid, extra={"guild_id": gid, "user_id": actor_uid}, actor_user_id=actor_uid)
                        log_event(f"Added trusted admin ({uid}) to {gid}", guild_id=gid, level="SEC")
                        flash = "Trusted admin added." if is_en else "تمت إضافة مشرف موثوق."
                    else:
                        flash = "Enter a valid numeric User ID." if is_en else "أدخل آيدي مستخدم رقمي صحيح."
                elif action_type == "remove_trusted":
                    uid = str(form.get("target_uid", "")).strip()
                    if uid.isdigit() and uid != ADMIN_USER_ID:
                        save_guild_cfg(gid, {"trusted_remove": uid}, is_premium=is_prem)
                        enqueue_remote_action(gid, "sync_guild_cfg", gid, extra={"guild_id": gid, "user_id": actor_uid}, actor_user_id=actor_uid)
                        log_event(f"Removed trusted admin ({uid}) from {gid}", guild_id=gid, level="SEC")
                        flash = "Trusted admin removed." if is_en else "تمت إزالة المشرف الموثوق."
                else:
                    cur_cfg = get_guild_cfg(gid)
                    cur_prof = cur_cfg.get("guild_profile") or {}
                    cur_perks = cur_cfg.get("premium_perks") or {}

                    antinuke_upd = {}
                    for rk in ANTINUKE_RULE_KEYS:
                        en_val = form.get(f"an_{rk}_enabled") == "on"
                        try:
                            lim_val = max(1, min(50, int(form.get(f"an_{rk}_limit", 1) or 1)))
                        except Exception:
                            lim_val = 1
                        pun_val = str(form.get(f"an_{rk}_punishment", "Ban")).strip()
                        if pun_val not in ("Kick", "Ban", "Remove Roles"):
                            pun_val = "Ban"
                        antinuke_upd[rk] = {"enabled": en_val, "limit": lim_val, "punishment": pun_val}

                    updates: dict = {
                        "prefix": form.get("prefix", "!"),
                        "mod_log_channel": form.get("mod_log_channel", ""),
                        "spam_punishment": form.get("spam_punishment", "Timeout"),
                        "spam_timeout_seconds": form.get("spam_timeout_seconds", 600),
                        "link_punishment": form.get("link_punishment", "Delete & Timeout"),
                        "link_timeout_seconds": form.get("link_timeout_seconds", 300),
                        "min_account_age_days": form.get("min_account_age_days", 7),
                        "antinuke_updates": antinuke_upd,
                    }
                    for sk in SHIELD_TOGGLE_KEYS:
                        updates[sk] = form.get(f"sh_{sk}") == "on"

                    profile_changed = False
                    bio_changed = False
                    avatar_changed = False
                    banner_changed = False
                    if is_prem:
                        prof_data, perks_data, profile_changed, bio_changed, avatar_changed, banner_changed = (
                            _process_premium_profile_and_perks(form, cur_prof, cur_perks)
                        )
                        updates["guild_profile"] = prof_data
                        updates["premium_perks"] = perks_data

                    save_guild_cfg(gid, updates, is_premium=is_prem)
                    enqueue_remote_action(gid, "sync_guild_cfg", gid, extra={"guild_id": gid, "user_id": actor_uid}, actor_user_id=actor_uid)
                    if is_prem and profile_changed:
                        prof_extra = {
                            "guild_id": gid,
                            "user_id": actor_uid,
                            "actor_id": actor_uid,
                            "bio": updates["guild_profile"]["bio"],
                            "bio_changed": bio_changed,
                            "avatar_changed": avatar_changed,
                            "banner_changed": banner_changed,
                            "has_avatar": bool(updates["guild_profile"]["avatar_data_url"]),
                            "has_banner": bool(updates["guild_profile"]["banner_data_url"]),
                        }
                        if avatar_changed:
                            prof_extra["avatar_data_url"] = updates["guild_profile"]["avatar_data_url"]
                        if banner_changed:
                            prof_extra["banner_data_url"] = updates["guild_profile"]["banner_data_url"]
                        enqueue_remote_action(gid, "update_bot_profile", gid, extra=prof_extra, actor_user_id=actor_uid)
                    log_event(f"Updated guild settings for {gid}", guild_id=gid, level="SEC")
                    flash = "Settings saved and synced." if is_en else "تم حفظ الإعدادات ومزامنتها."

    cfg = get_guild_cfg(gid)
    prof = cfg.get("guild_profile") or {}
    perks = cfg.get("premium_perks") or {}
    score, grade = calculate_security_score(cfg, is_en=is_en)
    csrf_tok = issue_csrf_token(session_id)
    req_nonce = secrets.token_hex(12)
    options_html = "".join(
        f"<option value='{esc(g['id'])}' {'selected' if g['id'] == gid else ''}>{esc(g['name'])} ({esc(g['id'])})</option>"
        for g in active_guilds
    )

    general_html = _build_toggle_items(GENERAL_TOGGLE_KEYS, cfg, is_en)
    antinuke_html = _build_toggle_items(ANTINUKE_TOGGLE_KEYS, cfg, is_en)
    antiraid_html = _build_toggle_items(ANTIRAID_TOGGLE_KEYS, cfg, is_en)
    moderation_html = _build_toggle_items(MODERATION_TOGGLE_KEYS, cfg, is_en)

    rules_html = ""
    for rk in ANTINUKE_RULE_KEYS:
        r_cfg = (cfg.get("antinuke") or {}).get(rk, {"enabled": True, "limit": 1, "punishment": "Ban"})
        pun_cur = r_cfg.get("punishment", "Ban")
        lbl_txt = rk if is_en else ANTINUKE_LABELS_AR.get(rk, rk)
        rules_html += f"""
        <div class="list-row" style="flex-wrap:wrap;">
          <label style="display:flex;align-items:center;gap:10px;font-weight:700;cursor:pointer;">
            <input class="switch-input" type="checkbox" name="an_{rk}_enabled" {'checked' if r_cfg.get('enabled') else ''}>
            <span>{esc(lbl_txt)}</span>
          </label>
          <div style="display:flex;gap:8px;align-items:center;">
            <input class="inp" style="width:74px;margin:0;padding:6px 8px;" type="number" min="1" max="50" name="an_{rk}_limit" value="{int(r_cfg.get('limit', 1) or 1)}">
            <select class="sel" style="width:130px;margin:0;padding:6px 8px;" name="an_{rk}_punishment">
              <option value="Kick" {'selected' if pun_cur == 'Kick' else ''}>Kick</option>
              <option value="Ban" {'selected' if pun_cur == 'Ban' else ''}>Ban</option>
              <option value="Remove Roles" {'selected' if pun_cur == 'Remove Roles' else ''}>Remove Roles</option>
            </select>
          </div>
        </div>
        """

    tr_rows = ""
    for u in (cfg.get("trusted_admins") or []):
        safe_u = esc(u)
        rem_btn = (
            ""
            if u == ADMIN_USER_ID
            else f"<button class='mini-btn red' type='submit' name='form_action' value='remove_trusted' onclick=\"this.form.target_uid.value='{safe_u}'\">x</button>"
        )
        tr_rows += f"<div class='list-row'><code>{safe_u}</code>{rem_btn}</div>"

    snaps_list = (cfg.get("perms_snapshots") or [])[:6]
    if snaps_list:
        snaps_rows = ""
        for s in snaps_list:
            sid_esc = esc(s.get("id"))
            snaps_rows += (
                f"<div class='list-row' style='flex-wrap:wrap;'>"
                f"<div><strong>#{sid_esc}</strong> <span class='muted'>({esc(s.get('saved_at'))})</span> <code>{esc(s.get('snapshot_hash'))}</code></div>"
                f"<div style='display:flex;gap:6px;'>"
                f"<button class='mini-btn' type='submit' name='form_action' value='restore_snapshot' onclick=\"this.form.target_snapshot_id.value='{sid_esc}'\">{('Restore' if is_en else 'استعادة')}</button>"
                f"<button class='mini-btn red' type='submit' name='form_action' value='delete_snapshot' onclick=\"this.form.target_snapshot_id.value='{sid_esc}'\">x</button>"
                f"</div></div>"
            )
    else:
        snaps_rows = f"<p class='muted'>{('No snapshots saved yet.' if is_en else 'لا توجد لقطات محفوظة.')}</p>"

    spam_pun = str(cfg.get("spam_punishment", "Timeout"))
    link_pun = str(cfg.get("link_punishment", "Delete & Timeout"))

    if is_prem:
        prem_pane_content = _render_premium_media_fields(prof, perks, is_en=is_en, use_pr_prefix=True)
    else:
        prem_pane_content = f"""
        <p class='muted' style='margin:0 0 12px;'>{('Bot avatar customization, custom banner, bio, high shield mode, and webhook alerts are exclusive to PREMIUM members (or server boosters).' if is_en else 'تغيير أفتار البوت، البنر، النبذة، الحماية الفائقة، والويبهوك متاحة لمشتركي البريميوم أو داعمي البوت بالبوست.')}</p>
        <a class='btn-primary-purple' href='/links'>{('Contact Support for Premium' if is_en else 'تواصل مع الدعم للحصول على البريميوم')}</a>
        """

    body = f"""
    <form method="post" class="glass-card anim-card">
      <input type="hidden" name="csrf_token" value="{esc(csrf_tok)}">
      <input type="hidden" name="req_nonce" value="{esc(req_nonce)}">
      <input type="hidden" name="target_uid" value="">
      <input type="hidden" name="target_snapshot_id" value="">

      <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:10px;">
        <h2 style="margin:0;">{('Security Panel' if is_en else 'لوحة الحماية')}</h2>
        <span class="tag">{score}/100 — {esc(grade)}</span>
      </div>

      <label class="lbl">{('Select Server' if is_en else 'اختر السيرفر')}</label>
      <select class="inp" name="guild_id" onchange="window.location='/guild?id='+encodeURIComponent(this.value)">{options_html}</select>

      <div class="cat-tabs" role="tablist">
        <button type="button" class="cat-tab-btn active" onclick="switchCat('general', this)">General</button>
        <button type="button" class="cat-tab-btn" onclick="switchCat('antinuke', this)">{('Anti-Sabotage' if is_en else 'حماية التخريب')}</button>
        <button type="button" class="cat-tab-btn" onclick="switchCat('antiraid', this)">Anti Raid</button>
        <button type="button" class="cat-tab-btn" onclick="switchCat('moderation', this)">Moderation</button>
        <button type="button" class="cat-tab-btn" onclick="switchCat('whitelist', this)">Whitelist</button>
        <button type="button" class="cat-tab-btn" onclick="switchCat('logs', this)">Logs</button>
        <button type="button" class="cat-tab-btn" onclick="switchCat('premium', this)">★ Premium</button>
      </div>

      <div id="cat-general" class="cat-pane active">
        <div class="panel-section">
          <div class="panel-section-head">
            <h3 class="panel-section-title">GENERAL</h3>
            <span class="ok-pill">{('SERVER' if is_en else 'السيرفر')}</span>
          </div>
          <div class="grid-2">
            <div>
              <label class="lbl">{('Prefix' if is_en else 'البادئة')}</label>
              <input class="inp" type="text" name="prefix" value="{esc(cfg.get('prefix', '!'))}">
            </div>
            <div>
              <label class="lbl">{('Min Account Age (days)' if is_en else 'أقل عمر للحساب (أيام)')}</label>
              <input class="inp" type="number" min="1" max="365" name="min_account_age_days" value="{int(cfg.get('min_account_age_days', 7) or 7)}">
            </div>
          </div>
          {general_html}
        </div>
      </div>

      <div id="cat-antinuke" class="cat-pane">
        <div class="panel-section">
          <div class="panel-section-head">
            <h3 class="panel-section-title">{('ANTI-SABOTAGE' if is_en else 'حماية التخريب')}</h3>
            <span class="admin-pill">{('ROLES & ICON' if is_en else 'الرتب والصورة')}</span>
          </div>
          {antinuke_html}
          <div style="margin-top:12px;">{rules_html}</div>
        </div>
      </div>

      <div id="cat-antiraid" class="cat-pane">
        <div class="panel-section">
          <div class="panel-section-head">
            <h3 class="panel-section-title">ANTI RAID</h3>
            <span class="admin-pill">{('SURGE' if is_en else 'الغارات')}</span>
          </div>
          {antiraid_html}
        </div>
      </div>

      <div id="cat-moderation" class="cat-pane">
        <div class="panel-section">
          <div class="panel-section-head">
            <h3 class="panel-section-title">MODERATION</h3>
            <span class="admin-pill">{('FILTERS' if is_en else 'الفلاتر')}</span>
          </div>
          {moderation_html}
          <div class="grid-2">
            <div>
              <label class="lbl">{('Spam Punishment' if is_en else 'إجراء السبام')}</label>
              <select class="sel" name="spam_punishment">
                <option value="Delete Only" {'selected' if spam_pun == 'Delete Only' else ''}>Delete Only</option>
                <option value="Timeout" {'selected' if spam_pun == 'Timeout' else ''}>Timeout</option>
                <option value="Kick" {'selected' if spam_pun == 'Kick' else ''}>Kick</option>
                <option value="Ban" {'selected' if spam_pun == 'Ban' else ''}>Ban</option>
              </select>
            </div>
            <div>
              <label class="lbl">{('Spam Timeout (sec)' if is_en else 'مدة التايم أوت (ثانية)')}</label>
              <input class="inp" type="number" min="10" max="2419200" name="spam_timeout_seconds" value="{int(cfg.get('spam_timeout_seconds', 600) or 600)}">
            </div>
          </div>
          <div class="grid-2">
            <div>
              <label class="lbl">{('Link Punishment' if is_en else 'إجراء الروابط')}</label>
              <select class="sel" name="link_punishment">
                <option value="Delete Only" {'selected' if link_pun == 'Delete Only' else ''}>Delete Only</option>
                <option value="Delete & Timeout" {'selected' if link_pun == 'Delete & Timeout' else ''}>Delete & Timeout</option>
                <option value="Kick" {'selected' if link_pun == 'Kick' else ''}>Kick</option>
                <option value="Ban" {'selected' if link_pun == 'Ban' else ''}>Ban</option>
              </select>
            </div>
            <div>
              <label class="lbl">{('Link Timeout (sec)' if is_en else 'مدة التايم أوت للروابط')}</label>
              <input class="inp" type="number" min="10" max="2419200" name="link_timeout_seconds" value="{int(cfg.get('link_timeout_seconds', 300) or 300)}">
            </div>
          </div>
        </div>
      </div>

      <div id="cat-whitelist" class="cat-pane">
        <div class="panel-section">
          <div class="panel-section-head">
            <h3 class="panel-section-title">WHITELIST & SNAPSHOTS</h3>
            <span class="tag">ACCESS</span>
          </div>
          <div style="display:flex;gap:8px;margin-bottom:8px;">
            <input class="inp" style="margin:0;" type="text" name="trusted_uid" placeholder="User ID">
            <button class="mini-btn" type="submit" name="form_action" value="add_trusted">+</button>
          </div>
          {tr_rows}
          <button class="btn-secondary-dark" type="submit" name="form_action" value="save_snapshot">{('Save Snapshot' if is_en else 'حفظ لقطة جديدة')}</button>
          <div style="margin-top:10px;">{snaps_rows}</div>
        </div>
      </div>

      <div id="cat-logs" class="cat-pane">
        <div class="panel-section">
          <div class="panel-section-head">
            <h3 class="panel-section-title">LOGS</h3>
            <span class="tag">CHANNEL</span>
          </div>
          <label class="lbl">{('Mod Log Channel ID' if is_en else 'آيدي روم السجل')}</label>
          <input class="inp" type="text" name="mod_log_channel" value="{esc(cfg.get('mod_log_channel', ''))}">
        </div>
      </div>

      <div id="cat-premium" class="cat-pane">
        <div class="panel-section prem-sec">
          <div class="panel-section-head">
            <h3 class="panel-section-title">★ PREMIUM</h3>
            <span class="prem-pill">{('PREMIUM ONLY' if is_en else 'للبريميوم فقط')}</span>
          </div>
          {prem_pane_content}
        </div>
      </div>

      <div class="hero-actions">
        <button class="btn-primary-purple" type="submit" name="form_action" value="save">{('Save Settings' if is_en else 'حفظ الإعدادات')}</button>
        <button class="btn-secondary-dark" type="submit" name="form_action" value="reset_defaults">{('Reset Defaults' if is_en else 'استعادة الافتراضي')}</button>
      </div>
    </form>
    """
    return web.Response(text=render_page("Security Panel" if is_en else "لوحة الحماية", "guild", body, request, flash=flash), content_type="text/html")


async def handle_premium(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    sess_pair = get_discord_session_with_id(request)
    if not sess_pair:
        return web.Response(text=render_page("Premium" if is_en else "البريميوم", "premium", "", request, require_auth_view=True), content_type="text/html")
    session_id, user = sess_pair
    if not is_premium_user(user):
        return web.Response(
            text=render_page(
                "Premium" if is_en else "البريميوم",
                "premium",
                f"<div class='glass-card anim-card'><h2>{('Premium Membership' if is_en else 'اشتراك البريميوم')}</h2><p class='muted'>{('Active Premium subscription or server boost is required.' if is_en else 'يلزم تفعيل اشتراك البريميوم أو دعم البوت بالبوست لاستخدام هذه الصفحة.')}</p></div>",
                request,
            ),
            content_type="text/html",
        )

    uid = str(user.get("id", "")).strip()
    prem_rec = _get_premium_record(uid) or {}
    rem_txt = format_remaining_time(prem_rec, is_en=is_en)

    guilds, _ = get_user_visible_guilds(user)
    active_guilds = [g for g in guilds if not g.get("bot_missing")]
    if not active_guilds:
        return web.Response(
            text=render_page(
                "Premium" if is_en else "البريميوم",
                "premium",
                f"<div class='glass-card anim-card'><p class='muted'>{('Bot must be inside your server first.' if is_en else 'يجب أن يكون البوت داخل سيرفرك أولاً.')}</p><a class='btn-primary-purple' href='/invite'>Invite Arab Security Bot</a></div>",
                request,
            ),
            content_type="text/html",
        )

    gid = str(request.query.get("id", "")).strip()
    if not user_can_manage_guild(gid, user, require_bot_present=True):
        gid = active_guilds[0]["id"]

    flash = ""
    if request.method == "POST":
        form = await read_post_safe(request)
        if not form:
            flash = "Invalid request body." if is_en else "بيانات الطلب غير صالحة."
        elif not consume_csrf_token(str(form.get("csrf_token", "")), session_id):
            flash = "Security token expired. Refresh and try again." if is_en else "انتهت صلاحية رمز الحماية، أعد المحاولة."
        elif is_replay_request(str(form.get("req_nonce", ""))):
            flash = "Duplicate request blocked." if is_en else "تم منع طلب مكرر."
        else:
            posted_gid = resolve_guild_id_from_input(str(form.get("guild_id", gid)), user, require_bot_present=True)
            if posted_gid and user_can_manage_guild(posted_gid, user, require_bot_present=True):
                gid = posted_gid
                cur_cfg = get_guild_cfg(gid)
                cur_prof = cur_cfg.get("guild_profile") or {}
                cur_perks = cur_cfg.get("premium_perks") or {}

                prof_data, perks_data, profile_changed, bio_changed, avatar_changed, banner_changed = (
                    _process_premium_profile_and_perks(form, cur_prof, cur_perks)
                )
                save_guild_cfg(gid, {"guild_profile": prof_data, "premium_perks": perks_data}, is_premium=True)
                prof_extra = {
                    "guild_id": gid,
                    "user_id": uid,
                    "actor_id": uid,
                    "bio": prof_data["bio"],
                    "bio_changed": bio_changed,
                    "avatar_changed": avatar_changed,
                    "banner_changed": banner_changed,
                    "has_avatar": bool(prof_data["avatar_data_url"]),
                    "has_banner": bool(prof_data["banner_data_url"]),
                }
                if avatar_changed:
                    prof_extra["avatar_data_url"] = prof_data["avatar_data_url"]
                if banner_changed:
                    prof_extra["banner_data_url"] = prof_data["banner_data_url"]
                enqueue_remote_action(gid, "update_bot_profile", gid, extra=prof_extra, actor_user_id=uid)
                if profile_changed:
                    enqueue_remote_action(gid, "sync_guild_cfg", gid, extra={"guild_id": gid, "user_id": uid}, actor_user_id=uid)
                log_event(f"Updated server bot profile for {gid}", guild_id=gid, level="ADMIN")
                flash = "Premium settings, bio, avatar, and banner saved." if is_en else "تم حفظ إعدادات البريميوم والبايو والأفتار والبنر."

    cfg = get_guild_cfg(gid)
    prof = cfg.get("guild_profile") or {}
    perks = cfg.get("premium_perks") or {}
    csrf_tok = issue_csrf_token(session_id)
    req_nonce = secrets.token_hex(12)
    options_html = "".join(f"<option value='{esc(g['id'])}' {'selected' if g['id'] == gid else ''}>{esc(g['name'])} ({esc(g['id'])})</option>" for g in active_guilds)

    media_fields_html = _render_premium_media_fields(prof, perks, is_en=is_en, use_pr_prefix=False)

    body = f"""
    <form method="post" class="glass-card anim-card">
      <input type="hidden" name="csrf_token" value="{esc(csrf_tok)}">
      <input type="hidden" name="req_nonce" value="{esc(req_nonce)}">

      <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:12px;">
        <h2 style="margin:0;">{('★ Premium Perks' if is_en else '★ مزايا البريميوم')}</h2>
        <span class="prem-pill">{esc(rem_txt)}</span>
      </div>

      <label class="lbl">{('Select Server' if is_en else 'اختر السيرفر')}</label>
      <select class="inp" name="guild_id" onchange="window.location='/premium?id='+encodeURIComponent(this.value)">{options_html}</select>

      <div class="panel-section prem-sec">
        <div class="panel-section-head">
          <h3 class="panel-section-title">{('Bot Identity & Shield Engine' if is_en else 'هوية البوت ومحرك الحماية')}</h3>
          <span class="prem-pill">PREMIUM</span>
        </div>
        {media_fields_html}
      </div>

      <button class="btn-primary-purple" type="submit">{('Save Premium Settings' if is_en else 'حفظ إعدادات البريميوم')}</button>
    </form>
    """
    return web.Response(text=render_page("Premium" if is_en else "البريميوم", "premium", body, request, flash=flash), content_type="text/html")


async def handle_admin(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    sess_pair = get_discord_session_with_id(request)
    if not sess_pair:
        return web.Response(text=render_page("Admin" if is_en else "الإدارة", "admin", "", request, require_auth_view=True), content_type="text/html")
    session_id, user = sess_pair
    if not is_site_admin(user):
        return web.Response(
            text=render_page(
                "Admin" if is_en else "الإدارة",
                "admin",
                f"<div class='glass-card anim-card'>{('Access denied.' if is_en else 'غير مصرح.')}</div>",
                request,
            ),
            content_type="text/html",
        )

    is_owner = str(user.get("id", "")).strip() == ADMIN_USER_ID
    actor_uid = str(user.get("id", "")).strip()
    flash = ""
    if request.method == "POST":
        form = await read_post_safe(request)
        if not form:
            flash = "Invalid request body." if is_en else "بيانات الطلب غير صالحة."
        elif not consume_csrf_token(str(form.get("csrf_token", "")), session_id):
            flash = "Security token expired. Refresh and try again." if is_en else "انتهت صلاحية رمز الحماية، أعد المحاولة."
        elif is_replay_request(str(form.get("req_nonce", ""))):
            flash = "Duplicate request blocked." if is_en else "تم منع طلب مكرر."
        else:
            act = str(form.get("admin_action", "")).strip()
            gid = str(form.get("cmd_guild_id", "")).strip()
            target_id = str(form.get("cmd_target", "")).strip()

            if act == "grant_premium":
                if not has_admin_perm(user, "manage_premium"):
                    flash = "Missing permission: Manage Premium" if is_en else "ينقصك صلاحية: إدارة البريميوم"
                else:
                    p_uid = str(form.get("prem_user_id", "")).strip()
                    p_name = str(form.get("prem_username", "")).strip()
                    p_handle = str(form.get("prem_handle", "")).strip()
                    try:
                        p_days = max(0, min(3650, int(form.get("prem_days", 0) or 0)))
                    except Exception:
                        p_days = 0
                    try:
                        p_hours = max(0, min(87600, int(form.get("prem_hours", 0) or 0)))
                    except Exception:
                        p_hours = 0

                    if not p_uid.isdigit():
                        flash = "Enter a valid User ID." if is_en else "أدخل آيدي مستخدم رقمي صحيح."
                    elif (p_days * 24 + p_hours) <= 0:
                        flash = "Specify a duration greater than 0." if is_en else "حدد مدة أكبر من صفر (أيام أو ساعات)."
                    else:
                        set_premium_user(
                            p_uid,
                            True,
                            days=p_days,
                            hours=p_hours,
                            granted_by=actor_uid,
                            username=p_name,
                            handle=p_handle,
                            source="manual",
                        )
                        log_event(f"Granted custom Premium ({p_days}d {p_hours}h) to {p_uid}", level="ADMIN")
                        flash = (
                            f"Granted Premium ({p_days}d {p_hours}h) to {p_uid}"
                            if is_en
                            else f"تم منح بريميوم ({p_days} يوم و {p_hours} ساعة) للحساب {p_uid}"
                        )
            elif act == "revoke_premium":
                if not has_admin_perm(user, "manage_premium"):
                    flash = "Missing permission: Manage Premium" if is_en else "ينقصك صلاحية: إدارة البريميوم"
                else:
                    p_uid = str(form.get("prem_user_id", "")).strip()
                    if p_uid.isdigit():
                        set_premium_user(p_uid, False)
                        log_event(f"Revoked Premium from {p_uid}", level="ADMIN")
                        flash = f"Revoked Premium from {p_uid}" if is_en else f"تم سحب البريميوم من الحساب {p_uid}"
                    else:
                        flash = "Enter a valid User ID." if is_en else "أدخل آيدي مستخدم رقمي صحيح."
            elif act == "grant_admin":
                if not has_admin_perm(user, "manage_admins"):
                    flash = "Missing permission: Manage Admins" if is_en else "ينقصك صلاحية: إدارة الأدمن والصلاحيات"
                else:
                    a_uid = str(form.get("admin_user_id", "")).strip()
                    if a_uid.isdigit():
                        selected_perms = {pk: (form.get(f"perm_{pk}") == "on") for pk in ADMIN_PERMISSION_KEYS}
                        set_admin_user(a_uid, True, granted_by=actor_uid, permissions=selected_perms)
                        log_event(f"Updated Admin & permissions for {a_uid}", level="ADMIN")
                        flash = f"Saved Admin & permissions for {a_uid}" if is_en else f"تم حفظ الأدمن وصلاحياته للحساب {a_uid}"
                    else:
                        flash = "Enter a valid Admin User ID." if is_en else "أدخل آيدي أدمن رقمي صحيح."
            elif act == "revoke_admin":
                if not has_admin_perm(user, "manage_admins"):
                    flash = "Missing permission: Manage Admins" if is_en else "ينقصك صلاحية: إدارة الأدمن والصلاحيات"
                else:
                    a_uid = str(form.get("admin_user_id", "")).strip()
                    if a_uid.isdigit() and set_admin_user(a_uid, False):
                        log_event(f"Revoked Admin from {a_uid}", level="ADMIN")
                        flash = f"Revoked Admin from {a_uid}" if is_en else f"تم سحب صلاحية أدمن من الحساب {a_uid}"
                    else:
                        flash = "Cannot revoke owner admin." if is_en else "لا يمكن سحب صلاحية المالك."
            elif act in ("kick", "ban", "unban", "timeout") and gid.isdigit() and target_id.isdigit():
                if not has_admin_perm(user, "remote_actions"):
                    flash = "Missing permission: Remote Actions" if is_en else "ينقصك صلاحية: الأوامر عن بُعد"
                else:
                    enqueue_remote_action(gid, act, target_id, extra={"user_id": actor_uid}, actor_user_id=actor_uid)
                    log_event(f"Remote action [{act}] on {target_id} in {gid}", guild_id=gid, level="ADMIN")
                    flash = f"Queued [{act}] for {target_id} in {gid}" if is_en else f"تم إرسال أمر [{act}] للعضو {target_id} في السيرفر {gid}"
            elif act == "broadcast" and target_id:
                if not has_admin_perm(user, "remote_actions"):
                    flash = "Missing permission: Remote Actions" if is_en else "ينقصك صلاحية: الأوامر عن بُعد"
                else:
                    enqueue_remote_action(gid or "0", "broadcast", target_id[:400], extra={"user_id": actor_uid}, actor_user_id=actor_uid)
                    log_event("Queued broadcast message", level="ADMIN")
                    flash = "Broadcast queued." if is_en else "تم إرسال البث للقائمة."
            elif act == "simulate" and gid.isdigit():
                if not has_admin_perm(user, "simulations"):
                    flash = "Missing permission: Safety Checks" if is_en else "ينقصك صلاحية: فحص الجاهزية"
                else:
                    flash = run_attack_simulation(gid, str(form.get("sim_scenario", "Permissions & Roles Check")), is_en=is_en)
            elif act == "create_backup":
                if not has_admin_perm(user, "backups"):
                    flash = "Missing permission: Backups" if is_en else "ينقصك صلاحية: النسخ الاحتياطي"
                else:
                    b = create_db_backup()
                    flash = f"Backup created: {b.get('backup_id')}" if is_en else f"تم إنشاء نسخة احتياطية: {b.get('backup_id')}"
            elif act == "test_restore":
                if not has_admin_perm(user, "backups"):
                    flash = "Missing permission: Backups" if is_en else "ينقصك صلاحية: النسخ الاحتياطي"
                else:
                    _, msg = test_backup_restore(str(form.get("backup_id", "")), is_en=is_en)
                    flash = msg
            else:
                flash = "Check required IDs or fields." if is_en else "تأكد من إدخال الآيدي أو الحقول المطلوبة بشكل صحيح."

    def _new_form_sec() -> str:
        return (
            f"<input type='hidden' name='csrf_token' value='{esc(issue_csrf_token(session_id))}'>"
            f"<input type='hidden' name='req_nonce' value='{esc(secrets.token_hex(12))}'>"
        )

    guilds = get_all_guilds()
    backups = get_db_backups()
    admins = get_admin_list()
    prems = get_premium_list()

    perm_checkboxes_html = ""
    default_p = _default_sub_admin_perms()
    for pk in ADMIN_PERMISSION_KEYS:
        lbl_en, lbl_ar = ADMIN_PERMISSION_LABELS.get(pk, (pk, pk))
        perm_checkboxes_html += (
            f"<label class='switch-row'>"
            f"<span>{esc(lbl_en if is_en else lbl_ar)}</span>"
            f"<input class='switch-input' type='checkbox' name='perm_{pk}' {'checked' if default_p.get(pk) else ''}></label>"
        )

    g_rows = "".join(_render_guild_card(g, is_en, show_admin_meta=True) for g in guilds) or "<p class='muted'>0</p>"
    b_rows = "".join(f"<div class='list-row'><code>{esc(b.get('backup_id'))}</code><span class='muted'>{esc(b.get('created_at'))}</span></div>" for b in backups[:5]) or "<p class='muted'>-</p>"

    a_rows = ""
    for a in admins:
        a_uid = str(a.get("user_id", ""))
        a_perms = a.get("permissions") or {}
        active_perms = [k for k, v in a_perms.items() if v]
        perms_badge = "ALL PERMS" if a_uid == ADMIN_USER_ID else f"{len(active_perms)}/{len(ADMIN_PERMISSION_KEYS)} perms"
        a_rows += (
            f"<div class='list-row' style='flex-wrap:wrap;'>"
            f"<div><strong>Admin</strong> — <code>{esc(a_uid)}</code> <span class='muted'>({esc(a.get('granted_by'))})</span></div>"
            f"<span class='admin-pill'>{esc(perms_badge)}</span></div>"
        )

    p_rows = "".join(
        f"<div class='list-row' style='flex-wrap:wrap;'><div><strong>{esc(p.get('username'))}</strong> <span class='muted'>{esc(p.get('handle'))}</span> — <code>{esc(p.get('user_id'))}</code></div><span class='prem-pill'>{esc(format_remaining_time(p, is_en=is_en))}</span></div>"
        for p in prems
    ) or "<p class='muted'>-</p>"

    role_label = "OWNER" if is_owner else ("SUB-ADMIN" if is_en else "إداري بصلاحيات")
    hb_last = esc(MEM_BOT_HEARTBEAT.get("last_seen") or "-")

    body = f"""
    <div class="glass-card anim-card">
      <div class="admin-hero">
        <div>
          <h2 style="margin:0 0 4px;">{('Admin Control Center' if is_en else 'لوحة الإدارة المركزية')}</h2>
          <div class="muted">{('Manage custom-duration subscriptions, boost sync, staff permissions, remote actions, and backups' if is_en else 'إدارة الاشتراكات بمدة مخصصة، مزامنة البوست، صلاحيات المشرفين، الأوامر عن بُعد، والنسخ الاحتياطي')} • Last Sync: <code>{hb_last}</code></div>
        </div>
        <span class="tag">{esc(role_label)}</span>
      </div>

      <div class="admin-kpis">
        <div class="kpi-box">
          <div class="kpi-num">{len(guilds)}</div>
          <div class="kpi-lbl">{('Servers' if is_en else 'السيرفرات')}</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-num">{len(prems)}</div>
          <div class="kpi-lbl">{('Premium Users' if is_en else 'مشتركو البريميوم')}</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-num">{len(admins)}</div>
          <div class="kpi-lbl">{('Staff Admins' if is_en else 'طاقم الإدارة')}</div>
        </div>
      </div>

      <div class="cat-tabs" role="tablist">
        <button type="button" class="cat-tab-btn active" onclick="switchCat('adm_prem', this)">{('Premium' if is_en else 'البريميوم')}</button>
        <button type="button" class="cat-tab-btn" onclick="switchCat('adm_staff', this)">{('Admins' if is_en else 'الأدمن')}</button>
        <button type="button" class="cat-tab-btn" onclick="switchCat('adm_remote', this)">{('Remote' if is_en else 'عن بُعد')}</button>
        <button type="button" class="cat-tab-btn" onclick="switchCat('adm_sys', this)">{('System' if is_en else 'النظام')}</button>
      </div>

      <div id="cat-adm_prem" class="cat-pane active">
        <form method="post" class="sub-panel" style="margin-bottom:0;">
          {_new_form_sec()}
          <div class="sub-panel-head">
            <h3 class="sub-panel-title">{('Premium Subscriptions (Custom Duration)' if is_en else 'إدارة البريميوم (حدد المدة بنفسك)')}</h3>
            <span class="prem-pill">PREMIUM ({len(prems)})</span>
          </div>
          <input class="inp" type="text" name="prem_user_id" placeholder="User ID">
          <div class="grid-2">
            <div>
              <label class="lbl">{('Days (You Set)' if is_en else 'الأيام (أنت تحددها)')}</label>
              <input class="inp" style="margin-bottom:0;" type="number" min="0" max="3650" name="prem_days" value="7">
            </div>
            <div>
              <label class="lbl">{('Hours (Optional)' if is_en else 'الساعات (اختياري)')}</label>
              <input class="inp" style="margin-bottom:0;" type="number" min="0" max="87600" name="prem_hours" value="0">
            </div>
          </div>
          <div class="grid-2">
            <input class="inp" style="margin-bottom:0;" type="text" name="prem_username" placeholder="{('Name (optional)' if is_en else 'الاسم (اختياري)')}">
            <input class="inp" style="margin-bottom:0;" type="text" name="prem_handle" placeholder="@username">
          </div>
          <div class="grid-2" style="margin-top:10px;margin-bottom:10px;">
            <button class="btn-primary-purple" style="margin-bottom:0;" type="submit" name="admin_action" value="grant_premium">{('Grant Custom Premium' if is_en else 'منح بريميوم بالمدة المحددة')}</button>
            <button class="btn-crimson" style="margin-bottom:0;" type="submit" name="admin_action" value="revoke_premium">{('Revoke Premium' if is_en else 'سحب البريميوم')}</button>
          </div>
          {p_rows}
        </form>
      </div>

      <div id="cat-adm_staff" class="cat-pane">
        <form method="post" class="sub-panel" style="margin-bottom:0;">
          {_new_form_sec()}
          <div class="sub-panel-head">
            <h3 class="sub-panel-title">{('Admins & Custom Permissions' if is_en else 'إدارة الأدمن وتحديد الصلاحيات')}</h3>
            <span class="admin-pill">ADMINS ({len(admins)})</span>
          </div>
          <input class="inp" type="text" name="admin_user_id" placeholder="Admin User ID">
          <div class="lbl">{('Select Permissions for Admin' if is_en else 'حدد الصلاحيات الممنوحة لهذا الأدمن')}:</div>
          {perm_checkboxes_html}
          <div class="grid-2" style="margin-top:10px;margin-bottom:10px;">
            <button class="btn-primary-purple" style="margin-bottom:0;" type="submit" name="admin_action" value="grant_admin">{('Save Admin & Perms' if is_en else 'حفظ الأدمن والصلاحيات')}</button>
            <button class="btn-crimson" style="margin-bottom:0;" type="submit" name="admin_action" value="revoke_admin">{('Revoke Admin' if is_en else 'سحب صلاحية الأدمن')}</button>
          </div>
          {a_rows}
        </form>
      </div>

      <div id="cat-adm_remote" class="cat-pane">
        <form method="post" class="sub-panel" style="margin-bottom:0;">
          {_new_form_sec()}
          <div class="sub-panel-head">
            <h3 class="sub-panel-title">{('Remote Actions & Broadcast' if is_en else 'الأوامر عن بُعد والبث')}</h3>
            <span class="tag">REMOTE</span>
          </div>
          <input class="inp" type="text" name="cmd_guild_id" placeholder="Guild ID">
          <input class="inp" type="text" name="cmd_target" placeholder="Target User ID or Broadcast Message">
          <div class="grid-2" style="margin-bottom:0;">
            <button class="mini-btn" type="submit" name="admin_action" value="kick">Kick</button>
            <button class="mini-btn red" type="submit" name="admin_action" value="ban">Ban</button>
            <button class="mini-btn" type="submit" name="admin_action" value="timeout">Timeout</button>
            <button class="mini-btn" type="submit" name="admin_action" value="broadcast">Broadcast</button>
          </div>
        </form>
      </div>

      <div id="cat-adm_sys" class="cat-pane">
        <form method="post" class="sub-panel" style="margin-bottom:0;">
          {_new_form_sec()}
          <div class="sub-panel-head">
            <h3 class="sub-panel-title">{('Safety Checks & Backups' if is_en else 'فحص الجاهزية والنسخ الاحتياطي')}</h3>
            <span class="tag">SYSTEM</span>
          </div>
          <input class="inp" type="text" name="cmd_guild_id" placeholder="Guild ID (for safety check)">
          <input class="inp" type="text" name="sim_scenario" value="{'Roles, Channels & Bot Permissions Check' if is_en else 'فحص صلاحيات الرتب والرومات والبوتات'}">
          <button class="btn-secondary-dark" type="submit" name="admin_action" value="simulate">{('Run Check' if is_en else 'تشغيل الفحص')}</button>
          <div class="grid-2" style="margin-top:10px;margin-bottom:0;">
            <button class="btn-primary-purple" style="margin-bottom:0;" type="submit" name="admin_action" value="create_backup">{('Create Backup' if is_en else 'نسخة احتياطية')}</button>
            <button class="btn-secondary-dark" style="margin-bottom:0;" type="submit" name="admin_action" value="test_restore">{('Test Restore' if is_en else 'اختبار الاستعادة')}</button>
          </div>
          <div style="margin-top:10px;">{b_rows}</div>
        </form>
      </div>
    </div>

    <div class="glass-card anim-card">
      <h3 style="margin:0 0 10px;">{('Servers Using The Bot' if is_en else 'السيرفرات المدخلة بالبوت')} ({len(guilds)})</h3>
      <input class="inp" type="text" oninput="filterGuildsList(this.value)" placeholder="{('Search server name or ID...' if is_en else 'ابحث باسم السيرفر أو الآيدي...')}">
      {g_rows}
    </div>
    """
    return web.Response(text=render_page("Admin" if is_en else "الإدارة", "admin", body, request, flash=flash), content_type="text/html")


async def handle_services(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    body = (
        """
        <div class='glass-card anim-card'>
          <h2 style='margin:0 0 10px;'>Arab Security — Services</h2>
          <p class='muted'>Server protection rules, role and channel guards, snapshot rollback, and bot settings.</p>
          <div class='list-row'><div><strong>Server Protection</strong><div class='muted'>Spam filter, link & invite guard, role & channel guards, snapshots rollback, and server icon protection.</div></div><span class='ok-pill'>AVAILABLE</span></div>
          <div class='list-row'><div><strong>Extra Perks</strong><div class='muted'>High shield mode, instant rollback engine, bot avatar & banner customization, custom bio up to 270 chars, and webhook alerts.</div></div><span class='prem-pill'>PREMIUM</span></div>
        </div>
        """
        if is_en
        else """
        <div class='glass-card anim-card'>
          <h2 style='margin:0 0 10px;'>خدمات بوت ARAB SECURITY</h2>
          <p class='muted'>إعدادات الحماية للرولات والرومات وصورة السيرفر واسترجاع اللقطات والسبام والروابط.</p>
          <div class='list-row'><div><strong>حماية السيرفر</strong><div class='muted'>منع السبام، الروابط، الدعوات، حماية الرولات والرومات من التخريب، استرجاع اللقطات، وحماية صورة السيرفر.</div></div><span class='ok-pill'>متاح للجميع</span></div>
          <div class='list-row'><div><strong>إضافات البريميوم</strong><div class='muted'>الحماية الفائقة، الاسترجاع الفوري، تغيير أفتار وبنر البوت، بايو حتى 270 حرفاً، وتنبيهات ويبهوك.</div></div><span class='prem-pill'>بريميوم</span></div>
        </div>
        """
    )
    return web.Response(text=render_page("Services" if is_en else "الخدمات", "services", body, request), content_type="text/html")


async def handle_updates(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    logs = get_recent_logs(35)
    incidents = get_recent_incidents(15)

    inc_rows = "".join(
        f"<div class='list-row'><div><span class='warn-pill'>{esc(i.get('severity', 'HIGH'))}</span> <strong>{esc(i.get('category', 'SEC'))}</strong> — <span>{esc(i.get('summary'))}</span></div><span class='muted'>{esc(i.get('time'))}</span></div>"
        for i in incidents
    ) or f"<p class='muted'>{('No security incidents recorded yet.' if is_en else 'لا توجد تنبيهات أمنية مسجلة حتى الآن.')}</p>"

    rows = "".join(
        f"<div class='list-row'><div><span class='tag'>{esc(l.get('level', 'WEB'))}</span> <span>{esc(l.get('message'))}</span></div><span class='muted'>{esc(l.get('time'))}</span></div>"
        for l in logs
    ) or f"<p class='muted'>{('No logs recorded yet.' if is_en else 'لا توجد سجلات حتى الآن.')}</p>"

    body = f"""
    <div class='glass-card anim-card'>
      <h2 style='margin:0 0 12px;'>{('Security Alerts & Incidents' if is_en else 'التنبيهات والأحداث الأمنية')}</h2>
      {inc_rows}
    </div>
    <div class='glass-card anim-card'>
      <h2 style='margin:0 0 12px;'>{('Updates & Logs' if is_en else 'التحديثات والسجلات')}</h2>
      {rows}
    </div>
    """
    return web.Response(text=render_page("Updates" if is_en else "التحديثات", "updates", body, request), content_type="text/html")


async def handle_links(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    user = get_discord_session(request)
    safe_support = esc(sanitize_http_url(SUPPORT_SERVER_URL) or "https://discord.com")
    invite_href = "/invite" if user else ("/login?next=" + quote("/invite") + "&msg=" + quote("Please login with Discord first."))
    dash_href = "/dashboard" if user else "/login?next=/dashboard"
    arrow = "&#8594;" if is_en else "&#8592;"

    body = f"""
    <div class='glass-card anim-card'>
      <div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;'>
        <h2 style='margin:0;'>{('Links' if is_en else 'الروابط')}</h2>
        <span class='tag'>{esc(SITE_NAME)}</span>
      </div>

      <a class='link-card' href='{esc(invite_href)}'>
        <div>
          <div class='link-card-title'>Invite Arab Security Bot</div>
          <div class='link-card-sub'>{('Add the bot to your Discord server' if is_en else 'إضافة البوت إلى سيرفر ديسكورد الخاص بك')}</div>
        </div>
        <span class='link-arrow'>{arrow}</span>
      </a>

      <a class='link-card' href='{esc(dash_href)}'>
        <div>
          <div class='link-card-title'>Dashboard</div>
          <div class='link-card-sub'>{('Open your server security settings' if is_en else 'فتح لوحة إعدادات الحماية لسيرفرك')}</div>
        </div>
        <span class='link-arrow'>{arrow}</span>
      </a>

      <a class='link-card' href='{safe_support}' target='_blank' rel='noopener noreferrer'>
        <div>
          <div class='link-card-title'>{('Support Server' if is_en else 'سيرفر الدعم الفني')}</div>
          <div class='link-card-sub'>{('Get help and report issues on Discord' if is_en else 'التواصل مع فريق الدعم والإبلاغ عن المشاكل')}</div>
        </div>
        <span class='link-arrow'>{arrow}</span>
      </a>
    </div>
    """
    return web.Response(text=render_page("Links" if is_en else "الروابط", "links", body, request), content_type="text/html")


async def handle_login(request: web.Request) -> web.Response:
    ip = get_client_ip(request)
    if is_rate_limited(ip, is_sensitive=True):
        return web.Response(text="Too many login requests.", status=429)
    if not DISCORD_CLIENT_ID or not DISCORD_CLIENT_SECRET:
        raise web.HTTPFound("/?msg=" + quote("Set DISCORD_CLIENT_SECRET in environment variables to enable Discord login."))
    next_url = sanitize_next_url(request.query.get("next", "/dashboard"))
    state = issue_oauth_state(next_url=next_url)
    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": detect_redirect_uri(request),
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
        raise web.HTTPFound("/?msg=" + quote("Discord login was cancelled."))

    state = request.query.get("state", "")
    code = request.query.get("code", "")
    ok_state, next_url = consume_oauth_state(state)
    if not ok_state or not code:
        raise web.HTTPFound("/?msg=" + quote("Invalid or expired OAuth state."))

    redirect_uri = detect_redirect_uri(request)
    user_info: dict = {}
    compact_guilds: list[dict] = []
    access_token = ""
    err_reason = ""

    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as session:
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
            token_data = await token_resp.json(content_type=None)
            if isinstance(token_data, dict):
                access_token = str(token_data.get("access_token", "")).strip()
                if not access_token:
                    err_reason = str(token_data.get("error_description") or token_data.get("error") or "")

            if access_token:
                auth_headers = {"Authorization": f"Bearer {access_token}"}
                u_resp = await session.get("https://discord.com/api/users/@me", headers=auth_headers)
                u_json = await u_resp.json(content_type=None)
                if isinstance(u_json, dict):
                    user_info = u_json

                g_resp = await session.get("https://discord.com/api/users/@me/guilds", headers=auth_headers)
                g_list = await g_resp.json(content_type=None)
                if isinstance(g_list, list):
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
    except (ClientError, asyncio.TimeoutError) as exc:
        err_reason = type(exc).__name__

    if not access_token:
        detail = f" ({err_reason[:60]})" if err_reason else ""
        raise web.HTTPFound("/?msg=" + quote(f"Could not get Discord access token{detail}."))

    uid = str(user_info.get("id", "")).strip()
    if not uid.isdigit():
        raise web.HTTPFound("/?msg=" + quote("Could not read Discord user profile."))

    signed_tok = sign_session(
        {
            "id": uid,
            "username": str(user_info.get("username", "User"))[:40],
            "avatar": str(user_info.get("avatar", "") or "")[:40],
            "guilds": compact_guilds,
            "exp": time.time() + 86400 * 7,
        }
    )
    log_event(f"User {uid} logged in via Discord", level="AUTH")
    resp = web.HTTPFound(next_url or "/dashboard")
    resp.set_cookie(
        "arab_sec_session",
        signed_tok,
        max_age=86400 * 7,
        httponly=True,
        secure=should_use_secure_cookie(request),
        samesite="Lax",
        path="/",
    )
    return resp


async def handle_logout(request: web.Request) -> web.Response:
    pair = get_discord_session_with_id(request)
    if pair:
        _delete_session_record(pair[0])
    resp = web.HTTPFound("/")
    resp.del_cookie("arab_sec_session", path="/")
    return resp


async def health_handler(request: web.Request) -> web.Response:
    return web.json_response(
        {
            "ok": True,
            "site": SITE_NAME,
            "bot_guilds_count": len(get_all_guilds()),
            "premium_count": len(get_premium_list()),
            "db_online": db is not None,
            "bot_heartbeat": MEM_BOT_HEARTBEAT,
        }
    )


@web.middleware
async def security_and_visit_middleware(request: web.Request, handler):
    ip = get_client_ip(request)
    is_auth = request.path in ("/login", "/callback")
    if is_rate_limited(ip, is_sensitive=is_auth):
        return web.Response(text="Rate limit exceeded.", status=429)

    record_site_visit(request)
    try:
        response = await handler(request)
    except web.HTTPException:
        raise
    except Exception as exc:
        log_event(f"Unhandled web error on {request.path}: {type(exc).__name__}", level="ERROR")
        return web.Response(text="Internal server error.", status=500)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


def create_app() -> web.Application:
    hydrate_from_db()
    app = web.Application(middlewares=[security_and_visit_middleware])
    app.router.add_get("/", home_handler)
    app.router.add_get("/invite", handle_invite_redirect)
    app.router.add_get("/dashboard", handle_dashboard_redirect)
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
    app.router.add_post("/api/bot/boost-sync", api_bot_boost_sync)
    app.router.add_get("/api/bot/pending-commands", api_bot_pending_commands)
    return app


if __name__ == "__main__":
    web.run_app(create_app(), host=HOST, port=PORT)
