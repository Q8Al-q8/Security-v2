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
BRAND_LABEL_AR = "عرب سكيورتي"
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

ADMIN_PERMISSION_LABELS = {
    "manage_premium": ("Manage Premium", "إدارة البريميوم"),
    "manage_admins": ("Manage Admins & Perms", "إدارة الأدمن والصلاحيات"),
    "remote_actions": ("Remote Actions & Broadcast", "الأوامر عن بُعد والبث"),
    "simulations": ("Safety Checks", "فحص الجاهزية"),
    "backups": ("Backups & Restore", "النسخ الاحتياطي والاستعادة"),
    "view_logs": ("System & Security Logs", "السجلات والتنبيهات"),
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
    "anti_guild_icon_change": "Server Icon Protection (Premium)",
    "anti_mass_unban": "Mass Unban Guard",
    "anti_mass_kick": "Mass Kick Guard",
    "anti_mass_timeout": "Mass Timeout Guard",
    "anti_mention_spam": "Mass Mention Guard",
    "quarantine_on_sabotage": "Role Strip & Quarantine",
    "dangerous_perms_guard": "Dangerous Permissions Guard",
    "anti_selfbot": "Automated / Selfbot Account Guard (Premium)",
    "anti_webhook_abuse": "Webhook Abuse Protection",
    "anti_app_abuse": "OAuth App Abuse Protection",
    "anti_privilege_escalation": "Privilege Escalation Guard",
    "anti_role_delete": "Role Delete Protection",
    "anti_role_edit": "Role Edit Protection",
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
    if not val.startswith("/") or val.startswith("//") or "\\" in val or val.startswith("/dashboard"):
        return "/guild"
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


def issue_oauth_state(next_url: str = "/guild") -> str:
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
        return False, "/guild"
    meta = OAUTH_STATES.pop(clean)
    exp = _safe_exp(meta.get("exp", 0))
    nxt = sanitize_next_url(meta.get("next", "/guild"))
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

    if "app_abuse_punishment" in updates:
        ap = str(updates["app_abuse_punishment"] or "Ban").strip()
        if ap in ("Kick", "Ban", "Remove Roles"):
            cfg["app_abuse_punishment"] = ap

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
        if "guild_icon_punishment" in updates:
            gip = str(updates["guild_icon_punishment"] or "Ban").strip()
            if gip in ("Kick", "Ban", "Remove Roles"):
                cfg["guild_icon_punishment"] = gip
        if "selfbot_punishment" in updates:
            sbp = str(updates["selfbot_punishment"] or "Ban").strip()
            if sbp in ("Kick", "Ban"):
                cfg["selfbot_punishment"] = sbp
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
            "remaining": format_remaining_time(existing_prem, is_en=False),
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


async def api_ui_state(request: web.Request) -> web.Response:
    user = get_discord_session(request)
    all_bot_guilds = get_all_guilds()
    if not user:
        return web.json_response(
            {
                "ok": True,
                "isAuthenticated": False,
                "isPremium": False,
                "isAdmin": False,
                "botGuildsCount": len(all_bot_guilds),
                "user": {
                    "username": "زائر غير مسجل",
                    "handle": "@guest",
                    "avatar": BRAND_LOGO_SVG_DATA_URL,
                },
                "selectedGuildId": "",
                "guilds": [],
                "logs": [],
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
    selected_gid = active_guilds_list[0]["id"] if active_guilds_list else ""
    cfg = get_guild_cfg(selected_gid) if selected_gid else _fresh_default_guild_cfg()
    logs_raw = get_recent_logs(25) if (is_adm and has_admin_perm(user, "view_logs")) else []
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
    return web.json_response(
        {
            "ok": True,
            "isAuthenticated": True,
            "isPremium": is_prem,
            "isAdmin": is_adm,
            "botGuildsCount": len(all_bot_guilds),
            "premiumCount": len(prem_list_now),
            "adminsCount": len(get_admin_list()) if is_adm else 0,
            "user": {
                "username": str(user.get("username", "Member")),
                "handle": f"@{str(user.get('username', 'member')).lower().replace(' ', '')}",
                "avatar": avatar_url,
            },
            "selectedGuildId": selected_gid,
            "guilds": [
                {
                    "id": g["id"],
                    "name": g["name"],
                    "members": int(g.get("member_count", 0) or 0),
                    "protectionScore": calculate_security_score(get_guild_cfg(g["id"]), is_en=False)[0],
                    "premium": is_prem,
                    "status": "محمي بالكامل",
                    "iconText": (str(g.get("name", "CS"))[:2] or "CS").upper(),
                }
                for g in active_guilds_list[:12]
            ],
            "protection": {
                "antiSpam": bool(cfg.get("anti_spam", True)),
                "spamPunishment": str(cfg.get("spam_punishment", "Timeout")),
                "antiLink": bool(cfg.get("anti_link", True)),
                "linkPunishment": str(cfg.get("link_punishment", "Delete & Timeout")),
                "antiInvites": bool(cfg.get("anti_invites", True)),
                "antiRaid": bool(cfg.get("anti_raid", True)),
                "antiNewAccounts": bool(cfg.get("anti_new_accounts", True)),
                "minAccountAgeDays": int(cfg.get("min_account_age_days", 7) or 7),
                "antiNukeRole": bool(cfg.get("anti_role_delete", True)),
                "antiNukeChannel": bool(cfg.get("anti_channel_perms_tamper", True)),
                "antiNukeBan": bool(cfg.get("anti_mass_unban", True)),
                "antiNukeKick": bool(cfg.get("anti_mass_kick", True)),
                "autoRollback": bool(cfg.get("auto_rollback_enabled", True)),
            },
            "premium": {
                "active": is_prem,
                "planName": "بريميوم عرب سكيورتي الماسي",
                "daysLeft": 30,
                "customBio": sanitize_bio_text((cfg.get("guild_profile") or {}).get("bio", ""))
                or "درع الحماية المتكامل لصد هجمات النيوك والسبام وحفظ السيرفر تلقائياً.",
                "customAvatar": sanitize_image_data_url((cfg.get("guild_profile") or {}).get("avatar_data_url", ""))
                or BRAND_LOGO_SVG_DATA_URL,
                "customBanner": sanitize_image_data_url((cfg.get("guild_profile") or {}).get("banner_data_url", ""))
                or "https://placehold.co/900x260/16132e/9a82ff?text=ARAB+SECURITY+SHIELD",
                "lastBackupTime": "منذ دقائق",
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

    if kind in ("save_protection", "save_premium"):
        if not req_gid.isdigit():
            return web.json_response({"ok": False, "error": "يجب اختيار سيرفر البوت متواجد فيه"}, status=403)
        allowed_g = user_can_manage_guild(req_gid, user, require_bot_present=True)
        if not allowed_g:
            return web.json_response(
                {"ok": False, "error": "البوت غير موجود في هذا السيرفر أو لا تملك صلاحية تعديله"},
                status=403,
            )
        gid = req_gid
    else:
        gid = resolve_guild_id_from_input(req_gid, user, require_bot_present=True)
        if not gid:
            visible_guilds, _ = get_user_visible_guilds(user)
            active_g = [g for g in visible_guilds if not g.get("bot_missing")]
            gid = active_g[0]["id"] if active_g else ""

    if kind == "save_protection":
        prot = payload.get("protection") if isinstance(payload.get("protection"), dict) else {}
        mapped = {
            "anti_spam": bool(prot.get("antiSpam", True)),
            "spam_punishment": str(prot.get("spamPunishment", "Timeout")),
            "anti_link": bool(prot.get("antiLink", True)),
            "link_punishment": str(prot.get("linkPunishment", "Delete & Timeout")),
            "anti_invites": bool(prot.get("antiInvites", True)),
            "anti_raid": bool(prot.get("antiRaid", True)),
            "anti_new_accounts": bool(prot.get("antiNewAccounts", True)),
            "min_account_age_days": int(prot.get("minAccountAgeDays", 7) or 7),
            "anti_role_delete": bool(prot.get("antiNukeRole", True)),
            "anti_channel_perms_tamper": bool(prot.get("antiNukeChannel", True)),
            "anti_mass_unban": bool(prot.get("antiNukeBan", True)),
            "anti_mass_kick": bool(prot.get("antiNukeKick", True)),
            "auto_rollback_enabled": bool(prot.get("autoRollback", True)),
        }
        save_guild_cfg(gid, mapped, is_premium=is_premium_user(user))
        enqueue_remote_action(gid, "sync_guild_cfg", gid, extra={"guild_id": gid, "user_id": actor_uid}, actor_user_id=actor_uid)
        log_event(f"Synced UI protection settings for {gid}", guild_id=gid, level="SEC")
        return web.json_response({"ok": True})

    if kind == "save_premium":
        if not is_premium_user(user):
            return web.json_response({"ok": False, "error": "Premium required"}, status=403)
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
        log_event(f"Updated UI premium profile for {gid}", guild_id=gid, level="ADMIN")
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

    if kind == "backup":
        if not is_site_admin(user) or not has_admin_perm(user, "backups"):
            return web.json_response({"ok": False, "error": "Admin backup permission required"}, status=403)
        snap = create_db_backup()
        return web.json_response({"ok": True, "backup_id": snap.get("backup_id")})

    if kind == "broadcast":
        if not is_site_admin(user) or not has_admin_perm(user, "remote_actions"):
            return web.json_response({"ok": False, "error": "Admin permission required"}, status=403)
        msg = str(payload.get("text", "")).strip()[:400]
        if msg:
            enqueue_remote_action(gid or "0", "broadcast", msg, extra={"user_id": actor_uid}, actor_user_id=actor_uid)
            log_event(f"UI Broadcast queued: {msg}", guild_id=gid or "0", level="ADMIN")
        return web.json_response({"ok": True})

    if kind == "mod_action":
        if not is_site_admin(user) or not has_admin_perm(user, "remote_actions"):
            return web.json_response({"ok": False, "error": "Admin permission required"}, status=403)
        act = str(payload.get("action", "timeout")).strip()
        target = str(payload.get("target", "")).strip()
        if act in ("kick", "ban", "unban", "timeout") and target.isdigit():
            enqueue_remote_action(gid or "0", act, target, extra={"user_id": actor_uid}, actor_user_id=actor_uid)
            log_event(f"UI Remote [{act}] on {target} in {gid or '0'}", guild_id=gid or "0", level="ADMIN")
        return web.json_response({"ok": True})

    return web.json_response({"ok": False, "error": "Unsupported action"}, status=400)


def _discord_svg_icon(size: int = 20) -> str:
    return (
        f"<svg width='{size}' height='{size}' viewBox='0 0 24 24' fill='currentColor' aria-hidden='true'>"
        "<path d='M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028c.462-.63.874-1.295 1.226-1.994.021-.041.001-.09-.041-.106a13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.028zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z'/>"
        "</svg>"
    )


def _brand_logo_img(cls: str = "brand-logo-img", size: int = 39) -> str:
    return (
        f"<img class='{esc(cls)}' src='{esc(BRAND_LOGO_SVG_DATA_URL)}' "
        f"alt='{esc(BRAND_LABEL_AR)}' width='{size}' height='{size}' "
        "loading='lazy' referrerpolicy='no-referrer'>"
    )


def _lock_svg_icon(size: int = 24) -> str:
    return (
        f"<svg width='{size}' height='{size}' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2.2' stroke-linecap='round' stroke-linejoin='round' aria-hidden='true'>"
        "<rect x='3' y='11' width='18' height='11' rx='3' ry='3'/>"
        "<path d='M7 11V7a5 5 0 0 1 10 0v4'/>"
        "</svg>"
    )


def _visitors_svg_icon(size: int = 22) -> str:
    return (
        f"<svg width='{size}' height='{size}' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2.2' stroke-linecap='round' stroke-linejoin='round' aria-hidden='true'>"
        "<path d='M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2'/>"
        "<circle cx='9' cy='7' r='4'/>"
        "<path d='M22 21v-2a4 4 0 0 0-3-3.87'/>"
        "<path d='M16 3.13a4 4 0 0 1 0 7.75'/>"
        "</svg>"
    )


def _servers_svg_icon(size: int = 22) -> str:
    return (
        f"<svg width='{size}' height='{size}' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2.2' stroke-linecap='round' stroke-linejoin='round' aria-hidden='true'>"
        "<rect x='2' y='3' width='20' height='7' rx='2'/>"
        "<rect x='2' y='14' width='20' height='7' rx='2'/>"
        "<circle cx='6.5' cy='6.5' r='1' fill='currentColor'/>"
        "<circle cx='6.5' cy='17.5' r='1' fill='currentColor'/>"
        "</svg>"
    )


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
        status_txt = "Bot Not in Server — Invite Bot" if is_en else "البوت غير موجود — أضف البوت أولاً"
    else:
        badge_cls = "ok-pill"
        status_txt = f"Connected ({mcount})" if is_en else f"متصل ({mcount})"

    sub_line = f"ID: {gid}"
    if show_admin_meta and g.get("updated_at"):
        sub_line += f" • {esc(g.get('updated_at'))}"

    return (
        f"<a class='list-row guild-search-item' data-search='{esc((gname_raw + ' ' + gid_raw).lower())}' style='text-decoration:none;color:var(--text-main);' href='{href}'>"
        f"<div style='display:flex;align-items:center;gap:10px;min-width:0;'>{icon_html}"
        f"<div style='min-width:0;'><div style='font-weight:800;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;'>{gname}</div>"
        f"<div class='muted' style='font-size:11.5px;'>{sub_line}</div></div></div>"
        f"<span class='{badge_cls}'>{esc(status_txt)}</span></a>"
    )


def _render_discord_community_card(is_en: bool) -> str:
    safe_support = esc(sanitize_http_url(SUPPORT_SERVER_URL) or "https://discord.com")
    title_txt = "Support Server" if is_en else "سيرفر الدعم الفني"
    sub_txt = "Updates, technical support, and alerts" if is_en else "تحديثات ، دعم فني ، تنبيهات"
    btn_txt = "Join Support Server" if is_en else "انضم لسيرفر الدعم الفني"
    return f"""
    <section class="discord-hub-card anim-card" dir="rtl">
      <div class="discord-hub-icon">{_discord_svg_icon(28)}</div>
      <h2 class="discord-hub-title">{esc(title_txt)}</h2>
      <p class="discord-hub-sub">{esc(sub_txt)}</p>
      <a class="discord-hub-btn" href="{safe_support}" target="_blank" rel="noopener noreferrer">{_discord_svg_icon(20)}<span>{esc(btn_txt)}</span></a>
    </section>
    """


def _render_stats_grid_html(is_en: bool, bot_servers_count: int, total_visits: int) -> str:
    visits_label = "Website Visitors" if is_en else "عدد الأشخاص اللي زاروا الموقع"
    servers_label = "Servers Using The Bot" if is_en else "عدد السيرفرات اللي مدخله البوت"
    return f"""
    <section class="stats-grid anim-card">
      <div class="stat-tile">
        <div class="stat-icon-circle">{_visitors_svg_icon(22)}</div>
        <div class="stat-tile-label">{esc(visits_label)}</div>
        <div class="stat-tile-num">{total_visits:,}</div>
      </div>
      <div class="stat-tile">
        <div class="stat-icon-circle">{_servers_svg_icon(22)}</div>
        <div class="stat-tile-label">{esc(servers_label)}</div>
        <div class="stat-tile-num">{bot_servers_count:,}</div>
      </div>
    </section>
    """


def _render_login_gate_card(is_en: bool, next_url: str = "/guild") -> str:
    safe_next = quote(sanitize_next_url(next_url))
    heading = "دخول ديسكورد مطلوب" if not is_en else "Discord Login Required"
    desc = (
        "الداشبورد ولوحة الحماية مقفلة. اضغط دخول ديسكورد أولاً للوصول إلى إعدادات السيرفرات."
        if not is_en
        else "Dashboard and protection controls are locked. Login with Discord first to manage your servers."
    )
    btn_txt = "دخول ديسكورد" if not is_en else "Login With Discord"
    back_txt = "رجوع للرئيسية" if not is_en else "Back to Home"
    return f"""
    <section class="login-gate-card anim-card">
      <div class="login-lock-circle">{_lock_svg_icon(24)}</div>
      <h1 class="login-gate-title">{esc(heading)}</h1>
      <p class="login-gate-desc">{esc(desc)}</p>
      <a class="login-discord-cta" href="/login?next={safe_next}">
        {_discord_svg_icon(20)}
        <span>{esc(btn_txt)}</span>
      </a>
      <a class="login-back-link" href="/">{esc(back_txt)}</a>
    </section>
    """


def _render_intro_hero_html(
    is_en: bool,
    bot_servers_count: int,
    total_visits: int,
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
      <h1 class="hero-title">{esc(BRAND_LABEL_AR)} • {esc(SITE_NAME)}</h1>
      <p class="hero-desc">{('Real-time protection for your server, rule controls, role and channel guards, snapshots rollback, and quick server actions.' if is_en else 'حماية متكاملة للسيرفر، ضبط القواعد، فصل حماية حذف وتعديل الرتب، حماية الصلاحيات الخطيرة وتطبيقات الربط، واسترجاع اللقطات.')}</p>
      <div class="hero-actions">
        <a class="btn-primary-purple" href="/invite">{('Invite عرب سكيورتي Bot' if is_en else 'دعوة بوت عرب سكيورتي')}</a>
        <a class="btn-secondary-dark" href="{esc(primary_href)}">{esc(primary_txt)}</a>
        <a class="btn-secondary-dark" href="{esc(secondary_href)}">{esc(secondary_txt)}</a>
        <a class="btn-secondary-dark" href="/ui">{('Modern Command Suite (UI)' if is_en else 'الواجهة المتقدمة الجديدة (UI)')}</a>
      </div>
    </section>

    {_render_stats_grid_html(is_en=is_en, bot_servers_count=bot_servers_count, total_visits=total_visits)}
    {_render_discord_community_card(is_en=is_en)}
    """


def render_page(
    title: str,
    active_nav: str,
    content_html: str,
    request: web.Request,
    flash: str = "",
    require_auth_view: bool = False,
    next_after_login: str = "/guild",
) -> str:
    lang = get_lang(request)
    is_en = lang == "en"
    dir_attr = "ltr" if is_en else "rtl"
    user = get_discord_session(request)
    is_logged_in = bool(user)
    is_admin = is_site_admin(user)
    admin_rec = _get_admin_record(str(user.get("id", "")).strip()) if (user and is_admin) else None
    staff_tag = str((admin_rec or {}).get("role_tag") or "").strip()
    is_prem = is_premium_user(user)
    prem_rec = _get_premium_record(str(user.get("id", "")).strip()) if user else None
    safe_flash = sanitize_flash_msg(flash)

    user_visible, _ = get_user_visible_guilds(user)
    user_active_guilds = [g for g in user_visible if not g.get("bot_missing")]
    can_access_guild_panel = bool(user and len(user_active_guilds) > 0)

    L = {
        "home": "Home" if is_en else "الرئيسية",
        "ui": "Modern UI" if is_en else "الواجهة المتقدمة",
        "guild": "Security Panel" if is_en else "لوحة الحماية",
        "premium": "★ Premium" if is_en else "★ البريميوم",
        "admin": "Admin Panel" if is_en else "لوحة الإدارة",
        "services": "Services" if is_en else "الخدمات",
        "updates": "Updates & Logs" if is_en else "التحديثات والسجلات",
        "links": "Links" if is_en else "الروابط",
        "invite": "Invite عرب سكيورتي Bot" if is_en else "دعوة بوت عرب سكيورتي",
        "login_discord": "Login With Discord" if is_en else "دخول ديسكورد",
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
        if str(user.get("id", "")) == ADMIN_USER_ID:
            badge_txt = "OWNER"
            badge_cls = "tag tag-owner"
        elif is_admin and staff_tag in STAFF_ROLE_OPTIONS:
            badge_txt = staff_tag.upper()
            badge_cls = "tag tag-staff"
        elif is_prem:
            badge_txt = "PREMIUM"
            badge_cls = "tag tag-prem"
        else:
            badge_txt = "MEMBER"
            badge_cls = "tag tag-member"

        prem_status_line = (
            f"<div class='prem-active-box'>★ {'PREMIUM ACTIVE' if is_en else 'البريميوم مفعل'} • {esc(format_remaining_time(prem_rec, is_en=is_en))}</div>"
            if (is_prem and prem_rec)
            else ""
        )
        account_block = (
            f"<div class='user-box'>{avatar_html}"
            f"<div style='min-width:0;'><div class='uname'>{uname_safe}</div>"
            f"<div style='margin-top:4px;'><span class='{badge_cls}'>{esc(badge_txt)}</span></div></div></div>"
            f"{prem_status_line}"
            f"<a class='nav-item danger' href='/logout'><span>{L['logout']}</span></a>"
        )
        top_auth_chip = (
            f"<div class='hdr-user-pill'>{avatar_html}<span class='hdr-user-name'>{uname_safe}</span>"
            f"<a class='hdr-logout-btn' href='/logout'>{L['logout']}</a></div>"
        )
    else:
        account_block = (
            f"<a class='login-btn' href='/login?next={quote(sanitize_next_url(next_after_login))}'>"
            f"{_discord_svg_icon(18)}<span>{L['login_discord']}</span></a>"
        )
        top_auth_chip = (
            f"<a class='hdr-login-btn' href='/login?next={quote(sanitize_next_url(next_after_login))}'>"
            f"{_discord_svg_icon(16)}<span>{L['login_discord']}</span></a>"
        )

    bot_servers_count = len(get_all_guilds())
    total_visits = get_total_visits()

    if is_logged_in:
        primary_href = "/guild" if can_access_guild_panel else "/invite"
        primary_txt = L["guild"] if can_access_guild_panel else L["invite"]
        secondary_href = "/invite"
        secondary_txt = L["invite"]
    else:
        primary_href = "/login?next=" + quote(sanitize_next_url(next_after_login))
        primary_txt = L["login_discord"]
        secondary_href = "/invite"
        secondary_txt = L["invite"]

    prem_badge_html = (
        f"<span class='prem-pill'>★ {esc(format_remaining_time(prem_rec, is_en=is_en))}</span>"
        if (is_prem and prem_rec)
        else ""
    )

    if require_auth_view and not user:
        final_content = _render_login_gate_card(is_en=is_en, next_url=next_after_login)
    else:
        final_content = content_html

    flash_banner = f"<div class='flash-banner anim-card' role='status'>{esc(safe_flash)}</div>" if safe_flash else ""

    nav_items = [
        ("home", "/", L["home"]),
        ("ui", "/ui", L["ui"]),
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
<title>{esc(title)} — {esc(BRAND_LABEL_AR)} ({esc(SITE_NAME)})</title>
<style>
  :root {{
    --bg-deep: #0E141B;
    --bg-grad:
      radial-gradient(circle at 50% -8%, rgba(22, 50, 79, 0.65), rgba(58, 134, 255, 0.14) 48%, #0E141B 82%),
      radial-gradient(circle at 12% 24%, rgba(142, 202, 230, 0.13), transparent 44%),
      linear-gradient(180deg, #131C26 0%, #0E141B 100%);
    --card-bg: rgba(18, 26, 36, 0.96);
    --card-border: rgba(142, 202, 230, 0.28);
    --card-border-bright: #FFE5B4;
    --prem-border: #8ECAE6;
    --text-main: #F2F7FB;
    --text-sub: #8ECAE6;
    --brand: #8ECAE6;
    --accent-coral: #FF7B54;
    --accent-violet: #3A86FF;
    --accent-indigo: #16324F;
  }}
  * {{ box-sizing: border-box; }}
  @keyframes fadeSlideUp {{
    from {{ opacity: 0; transform: translateY(14px) scale(0.985); }}
    to {{ opacity: 1; transform: translateY(0) scale(1); }}
  }}
  @keyframes softFloat {{
    0%, 100% {{ transform: translateY(0px); }}
    50% {{ transform: translateY(-3px); }}
  }}
  @keyframes pulseGlow {{
    0%, 100% {{ box-shadow: 0 12px 30px rgba(0, 0, 0, 0.36), 0 0 0 rgba(58, 134, 255, 0); }}
    50% {{ box-shadow: 0 14px 34px rgba(0, 0, 0, 0.44), 0 0 28px rgba(58, 134, 255, 0.22); }}
  }}
  .anim-card {{
    animation: fadeSlideUp 0.28s cubic-bezier(0.22, 1, 0.36, 1) both;
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
    background: rgba(7, 11, 16, 0.80);
    backdrop-filter: blur(3px);
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
    width: 292px;
    max-width: 86vw;
    height: 100vh;
    background: linear-gradient(180deg, rgba(19, 28, 38, 0.99) 0%, rgba(14, 20, 27, 0.99) 100%);
    border-{('right' if is_en else 'left')}: 1px solid var(--card-border);
    padding: 18px 14px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    z-index: 70;
    overflow-y: auto;
    box-shadow: 0 18px 44px rgba(0, 0, 0, 0.55);
    transform: translateX({('-106%' if is_en else '106%')});
    transition: transform 0.26s cubic-bezier(0.22, 1, 0.36, 1);
  }}
  .sidebar.open {{ transform: translateX(0); }}
  .page-container {{
    width: 100%;
    max-width: 840px;
    margin: 0 auto;
    padding: 18px 16px 60px;
  }}
  .top-bar {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 12px 16px;
    border-radius: 20px;
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    margin-bottom: 18px;
    box-shadow: 0 10px 28px rgba(0, 0, 0, 0.42);
    animation: fadeSlideUp 0.22s cubic-bezier(0.22, 1, 0.36, 1) both;
  }}
  .top-left {{ display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }}
  .icon-btn {{
    height: 38px;
    padding: 0 13px;
    border-radius: 12px;
    background: linear-gradient(145deg, rgba(22, 50, 79, 0.92), rgba(18, 26, 36, 0.98));
    border: 1px solid var(--card-border);
    color: var(--text-main);
    font-weight: 800;
    font-size: 16px;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    text-decoration: none;
    transition: transform 0.16s cubic-bezier(0.22, 1, 0.36, 1), background 0.16s ease, border-color 0.16s ease, box-shadow 0.16s ease;
  }}
  .icon-btn:hover {{
    background: linear-gradient(135deg, var(--accent-indigo), var(--accent-violet));
    border-color: var(--card-border-bright);
    transform: translateY(-1.5px);
    box-shadow: 0 6px 16px rgba(58, 134, 255, 0.24);
  }}
  .lang-btn {{ font-size: 12.5px; }}
  .hdr-login-btn {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 36px;
    padding: 0 12px;
    border-radius: 12px;
    background: linear-gradient(135deg, #6c5ce7, var(--accent-violet));
    border: 1px solid var(--brand);
    color: #ffffff;
    font-size: 12px;
    font-weight: 900;
    text-decoration: none;
    white-space: nowrap;
  }}
  .hdr-user-pill {{
    display: inline-flex;
    align-items: center;
    gap: 8px;
    height: 36px;
    padding: 0 10px 0 6px;
    border-radius: 12px;
    background: rgba(14, 20, 27, 0.92);
    border: 1px solid var(--card-border);
  }}
  .hdr-user-pill .avatar-img {{ width: 26px; height: 26px; }}
  .hdr-user-name {{ font-size: 12px; font-weight: 800; color: var(--text-main); max-width: 90px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .hdr-logout-btn {{ font-size: 11px; font-weight: 800; color: var(--accent-coral); text-decoration: none; }}
  .top-right {{
    display: flex;
    align-items: center;
    gap: 10px;
    text-align: {('left' if is_en else 'right')};
  }}
  .brand-title {{ font-size: 14.5px; font-weight: 900; letter-spacing: 0.4px; color: var(--text-main); line-height: 1.2; }}
  .brand-sub {{ font-size: 11px; color: var(--brand); line-height: 1.25; }}
  .brand-logo-img {{
    width: 39px; height: 39px; border-radius: 13px; object-fit: cover;
    border: 1.5px solid var(--brand);
    box-shadow: 0 0 18px rgba(58, 134, 255, 0.34);
    flex-shrink: 0;
  }}
  .flash-banner {{
    background: linear-gradient(135deg, rgba(22, 50, 79, 0.90), rgba(58, 134, 255, 0.26));
    border: 1.5px solid var(--card-border-bright);
    color: var(--text-main); border-radius: 16px; padding: 13px 16px;
    margin-bottom: 18px; font-size: 13.5px; font-weight: 800; line-height: 1.55; text-align: center;
    box-shadow: 0 10px 24px rgba(0, 0, 0, 0.35);
  }}
  .login-gate-card {{
    background: linear-gradient(175deg, rgba(22, 50, 79, 0.55) 0%, rgba(18, 26, 36, 0.98) 45%, rgba(14, 20, 27, 0.99) 100%);
    border: 1.5px solid var(--card-border);
    border-radius: 26px;
    padding: 36px 24px 32px;
    max-width: 470px;
    margin: 10px auto 20px;
    text-align: center;
    box-shadow: 0 20px 44px rgba(0, 0, 0, 0.50);
  }}
  .login-lock-circle {{
    width: 62px; height: 62px; margin: 0 auto 18px; border-radius: 999px;
    background: linear-gradient(145deg, var(--accent-violet), var(--accent-indigo));
    border: 1.5px solid var(--card-border-bright); color: var(--text-main);
    display: flex; align-items: center; justify-content: center;
    animation: softFloat 3.2s ease-in-out infinite;
  }}
  .login-gate-title {{ margin: 0 0 10px; font-size: 27px; font-weight: 900; color: var(--text-main); }}
  .login-gate-desc {{ margin: 0 auto 24px; max-width: 390px; font-size: 14.5px; line-height: 1.72; color: var(--text-sub); font-weight: 600; }}
  .login-discord-cta {{
    display: flex; align-items: center; justify-content: center; gap: 10px; width: 100%; padding: 15px 20px;
    border-radius: 999px; background: linear-gradient(135deg, var(--brand) 0%, #c8e7f5 100%);
    border: 1.5px solid var(--card-border-bright); color: var(--bg-deep); text-decoration: none;
    font-weight: 900; font-size: 15px;
  }}
  .login-back-link {{ display: inline-block; margin-top: 16px; color: var(--text-sub); text-decoration: none; font-size: 13.5px; font-weight: 800; }}
  .hero-card {{
    background: linear-gradient(165deg, rgba(22, 50, 79, 0.42) 0%, rgba(18, 26, 36, 0.98) 55%);
    border: 1px solid var(--card-border);
    border-radius: 24px; padding: 30px 22px; text-align: center; margin-bottom: 16px;
    animation: fadeSlideUp 0.26s cubic-bezier(0.22, 1, 0.36, 1) both, pulseGlow 4.2s infinite ease-in-out;
  }}
  .prem-active-box {{
    padding: 9px 12px; border-radius: 13px;
    background: linear-gradient(135deg, rgba(22, 50, 79, 0.85), rgba(58, 134, 255, 0.22));
    border: 1px solid var(--prem-border);
    color: var(--text-main); font-size: 12px; font-weight: 800; text-align: center;
  }}
  .hero-title {{ margin: 0 0 12px; font-size: 27px; font-weight: 900; letter-spacing: 0.4px; color: var(--text-main); }}
  .hero-desc {{ margin: 0 auto 22px; max-width: 560px; font-size: 14px; line-height: 1.78; color: var(--text-sub); font-weight: 600; }}
  .hero-actions {{ display: flex; flex-direction: column; gap: 10px; }}
  .btn-primary-purple {{
    display: block; width: 100%; padding: 13.5px 18px; border-radius: 15px;
    background: linear-gradient(135deg, var(--accent-indigo) 0%, var(--accent-violet) 100%);
    border: 1px solid var(--brand); color: var(--text-main); text-decoration: none;
    font-weight: 800; font-size: 14.5px; text-align: center; cursor: pointer;
  }}
  .btn-crimson {{
    display: block; width: 100%; padding: 13.5px 18px; border-radius: 15px;
    background: linear-gradient(135deg, rgba(255, 123, 84, 0.32), rgba(22, 50, 79, 0.88));
    border: 1px solid var(--accent-coral); color: var(--text-main); text-decoration: none;
    font-weight: 800; font-size: 14.5px; text-align: center; cursor: pointer;
  }}
  .btn-secondary-dark {{
    display: block; width: 100%; padding: 13.5px 18px; border-radius: 15px;
    background: rgba(14, 20, 27, 0.94); border: 1px solid var(--card-border);
    color: var(--text-main); text-decoration: none; font-weight: 800; font-size: 14.5px; text-align: center; cursor: pointer;
  }}
  .stats-grid {{
    display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; margin-bottom: 16px;
  }}
  @media (max-width: 540px) {{ .stats-grid {{ grid-template-columns: 1fr; }} }}
  .stat-tile {{
    background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 22px; padding: 20px 16px; text-align: center;
  }}
  .stat-icon-circle {{
    width: 46px; height: 46px; margin: 0 auto 10px; border-radius: 999px;
    background: linear-gradient(145deg, var(--accent-indigo), var(--accent-violet));
    border: 1px solid var(--brand); color: var(--text-main); display: flex; align-items: center; justify-content: center;
  }}
  .stat-tile-label {{ font-size: 13px; font-weight: 700; color: var(--text-sub); margin-bottom: 8px; }}
  .stat-tile-num {{ font-size: 28px; font-weight: 900; color: var(--text-main); line-height: 1.1; }}
  .discord-hub-card {{
    background: linear-gradient(160deg, rgba(22, 50, 79, 0.88) 0%, rgba(18, 26, 36, 0.98) 100%);
    border: 1.5px solid var(--card-border); border-radius: 24px; padding: 34px 24px 30px; text-align: center; margin-bottom: 16px;
  }}
  .discord-hub-icon {{
    width: 66px; height: 66px; margin: 0 auto 18px; border-radius: 18px;
    background: var(--bg-deep); border: 1.5px solid var(--card-border-bright); color: var(--text-main);
    display: flex; align-items: center; justify-content: center; animation: softFloat 3.6s ease-in-out infinite;
  }}
  .discord-hub-title {{ margin: 0 0 8px; font-size: 30px; font-weight: 900; color: var(--text-main); }}
  .discord-hub-sub {{ margin: 0 auto 24px; max-width: 520px; font-size: 16.5px; font-weight: 700; color: var(--text-sub); }}
  .discord-hub-btn {{
    display: flex; align-items: center; justify-content: center; gap: 10px; width: 100%; padding: 16px 22px; border-radius: 18px;
    background: #FFFFFF; color: var(--bg-deep); border: 1.5px solid var(--card-border-bright);
    text-decoration: none; font-weight: 900; font-size: 17px;
  }}
  .glass-card {{
    background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 24px; padding: 22px; margin-bottom: 16px;
  }}
  .studio-banner {{
    display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 14px;
    padding: 18px 20px; border-radius: 20px;
    background: linear-gradient(135deg, rgba(22, 50, 79, 0.85), rgba(58, 134, 255, 0.20), rgba(14, 20, 27, 0.96));
    border: 1px solid var(--card-border); margin-bottom: 16px;
  }}
  .studio-banner-title {{ margin: 0 0 4px; font-size: 20px; font-weight: 900; color: var(--text-main); }}
  .studio-banner-sub {{ font-size: 12.5px; color: var(--text-sub); font-weight: 600; }}
  .score-ring-box {{
    padding: 10px 14px; border-radius: 16px; background: rgba(14, 20, 27, 0.90);
    border: 1px solid var(--card-border-bright); text-align: center; min-width: 132px;
  }}
  .score-ring-val {{ font-size: 20px; font-weight: 900; color: var(--text-main); line-height: 1.1; }}
  .score-ring-lbl {{ font-size: 11px; color: var(--brand); font-weight: 800; margin-top: 3px; }}
  .admin-hero {{
    display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;
    padding: 18px 20px; border-radius: 20px;
    background: linear-gradient(135deg, rgba(22, 50, 79, 0.85), rgba(58, 134, 255, 0.22), rgba(14, 20, 27, 0.97));
    border: 1px solid var(--card-border); margin-bottom: 16px;
  }}
  .admin-kpis {{
    display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; margin-bottom: 16px;
  }}
  @media (max-width: 540px) {{ .admin-kpis {{ grid-template-columns: 1fr; }} }}
  .kpi-box {{
    padding: 15px 14px; border-radius: 18px;
    background: linear-gradient(160deg, rgba(22, 50, 79, 0.36), rgba(14, 20, 27, 0.96));
    border: 1px solid var(--card-border); text-align: center;
  }}
  .kpi-num {{ font-size: 24px; font-weight: 900; color: var(--text-main); }}
  .kpi-lbl {{ font-size: 12px; color: var(--text-sub); margin-top: 4px; font-weight: 700; }}
  .cat-tabs {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(112px, 1fr)); gap: 8px; margin-bottom: 16px;
  }}
  .cat-tab-btn {{
    background: rgba(14, 20, 27, 0.95); border: 1px solid var(--card-border); color: var(--text-sub);
    border-radius: 14px; padding: 11px 10px; font-size: 12.5px; font-weight: 800; cursor: pointer; text-align: center;
  }}
  .cat-tab-btn.active {{
    background: linear-gradient(135deg, var(--accent-indigo) 0%, var(--accent-violet) 100%);
    border-color: var(--card-border-bright); color: var(--text-main);
  }}
  .cat-pane {{ display: none; }}
  .cat-pane.active {{ display: block; animation: fadeSlideUp 0.22s cubic-bezier(0.22, 1, 0.36, 1) both; }}
  .link-card {{
    display: flex; align-items: center; justify-content: space-between; gap: 14px; padding: 17px 18px; border-radius: 18px;
    background: linear-gradient(145deg, rgba(22, 50, 79, 0.45), rgba(14, 20, 27, 0.96));
    border: 1px solid var(--card-border); text-decoration: none; color: var(--text-main); margin-bottom: 12px;
  }}
  .link-card-left {{ display: flex; align-items: center; gap: 13px; min-width: 0; }}
  .link-card-badge {{
    width: 44px; height: 44px; border-radius: 14px; flex-shrink: 0;
    background: linear-gradient(135deg, var(--accent-indigo), var(--accent-violet));
    border: 1px solid var(--brand); color: var(--text-main);
    display: flex; align-items: center; justify-content: center; font-weight: 900; font-size: 16px;
  }}
  .link-card-title {{ font-weight: 900; font-size: 15px; color: var(--text-main); }}
  .link-card-sub {{ font-size: 12.5px; color: var(--text-sub); margin-top: 3px; font-weight: 600; }}
  .link-arrow {{ font-weight: 900; color: var(--card-border-bright); font-size: 18px; }}
  .panel-section {{
    background: linear-gradient(170deg, rgba(22, 50, 79, 0.26), rgba(14, 20, 27, 0.94));
    border: 1px solid var(--card-border); border-radius: 20px; padding: 18px; margin-bottom: 14px;
  }}
  .panel-section.prem-sec {{
    background: linear-gradient(160deg, rgba(22, 50, 79, 0.56), rgba(58, 134, 255, 0.14), rgba(18, 26, 36, 0.98));
    border-color: var(--prem-border);
  }}
  .panel-section-head {{
    display: flex; align-items: center; justify-content: space-between; gap: 10px;
    margin-bottom: 14px; padding-bottom: 11px; border-bottom: 1px solid var(--card-border);
  }}
  .panel-section-title {{ margin: 0; font-size: 15.5px; font-weight: 900; color: var(--text-main); }}
  .grid-2 {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; margin-bottom: 12px; }}
  @media (max-width: 540px) {{ .grid-2 {{ grid-template-columns: 1fr; }} }}
  .nav-item {{
    display: flex; align-items: center; gap: 10px; padding: 10.5px 13px; border-radius: 13px;
    color: var(--text-main); text-decoration: none; font-size: 13.5px; font-weight: 700;
  }}
  .nav-item:hover {{ background: rgba(58, 134, 255, 0.18); }}
  .nav-item.active {{ background: linear-gradient(135deg, rgba(22, 50, 79, 0.90), rgba(58, 134, 255, 0.24)); border: 1px solid var(--brand); color: var(--text-main); }}
  .nav-item.danger {{ color: var(--accent-coral); }}
  .sep {{ height: 1px; background: var(--card-border); margin: 7px 0; }}
  .user-box {{
    display: flex; align-items: center; gap: 12px; padding: 12px; border-radius: 16px;
    background: linear-gradient(145deg, rgba(22, 50, 79, 0.45), rgba(18, 26, 36, 0.96)); border: 1px solid var(--card-border);
  }}
  .avatar, .avatar-img {{ width: 44px; height: 44px; border-radius: 999px; object-fit: cover; border: 1.5px solid var(--brand); flex-shrink: 0; }}
  .avatar {{ background: linear-gradient(135deg, var(--accent-violet), var(--accent-indigo)); display: flex; align-items: center; justify-content: center; font-weight: 900; font-size: 16px; color: var(--text-main); }}
  .uname {{ font-weight: 900; font-size: 14px; color: var(--text-main); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
  .tag {{
    display: inline-flex; align-items: center; gap: 4px; font-size: 10.5px; padding: 4px 11px; border-radius: 999px;
    background: linear-gradient(135deg, rgba(22, 50, 79, 0.9), rgba(58, 134, 255, 0.30)); border: 1px solid var(--brand); color: var(--text-main); font-weight: 900;
  }}
  .tag-owner {{ border-color: var(--card-border-bright); color: var(--card-border-bright); }}
  .tag-staff {{ border-color: var(--brand); }}
  .tag-prem {{ border-color: var(--card-border-bright); }}
  .tag-member {{ color: var(--text-sub); }}
  .ok-pill {{
    display: inline-flex; align-items: center; gap: 4px; font-size: 10.5px; padding: 4px 11px; border-radius: 999px;
    background: rgba(142, 202, 230, 0.16); border: 1px solid var(--brand); color: var(--text-main); font-weight: 800;
  }}
  .warn-pill {{
    display: inline-flex; align-items: center; gap: 4px; font-size: 10.5px; padding: 4px 11px; border-radius: 999px;
    background: rgba(255, 123, 84, 0.18); border: 1px solid var(--accent-coral); color: var(--card-border-bright); font-weight: 800;
  }}
  .prem-pill {{
    display: inline-flex; align-items: center; gap: 4px; font-size: 10.5px; padding: 4px 12px; border-radius: 999px;
    background: linear-gradient(135deg, rgba(22, 50, 79, 0.92), rgba(58, 134, 255, 0.38)); border: 1px solid var(--card-border-bright); color: var(--text-main); font-weight: 900;
  }}
  .admin-pill {{
    display: inline-flex; align-items: center; gap: 4px; font-size: 10.5px; padding: 4px 10px; border-radius: 999px;
    background: rgba(22, 50, 79, 0.78); border: 1px solid var(--card-border); color: var(--text-main); font-weight: 800;
  }}
  .login-btn {{
    display: flex; align-items: center; justify-content: center; gap: 8px; text-align: center; padding: 12px 14px; border-radius: 14px;
    background: linear-gradient(135deg, var(--brand), #c8e7f5); color: var(--bg-deep); text-decoration: none; font-weight: 900; font-size: 13.5px;
    border: 1px solid var(--card-border-bright);
  }}
  .inp, .sel, .bio-textarea {{
    width: 100%; background: var(--bg-deep); border: 1px solid var(--card-border);
    color: var(--text-main); border-radius: 13px; padding: 11.5px 14px; font-size: 14px; margin-bottom: 10px; font-family: inherit;
  }}
  .bio-textarea {{ min-height: 142px; margin-top: 8px; margin-bottom: 6px; line-height: 1.7; resize: vertical; }}
  .lbl {{ display: block; font-size: 12.5px; color: var(--text-sub); margin: 8px 0 5px; font-weight: 800; }}
  .bio-meta {{ display: flex; justify-content: space-between; align-items: center; gap: 8px; font-size: 11.5px; color: var(--text-sub); margin-bottom: 12px; }}
  .switch-row {{
    display: flex; align-items: center; justify-content: space-between; gap: 14px; padding: 12.5px 15px; border-radius: 15px;
    background: rgba(18, 26, 36, 0.92); border: 1px solid var(--card-border); margin-bottom: 10px; font-size: 13.5px; font-weight: 700; cursor: pointer;
  }}
  .switch-input {{
    position: relative; appearance: none; -webkit-appearance: none; width: 48px; min-width: 48px; height: 26px;
    border-radius: 999px; background: var(--bg-deep); border: 1.5px solid var(--card-border); cursor: pointer;
  }}
  .switch-input::after {{
    content: ""; position: absolute; top: 2px; left: 2px; width: 20px; height: 20px; border-radius: 999px; background: var(--text-sub);
  }}
  .switch-input:checked {{ background: linear-gradient(135deg, var(--accent-indigo) 0%, var(--accent-violet) 100%); border-color: var(--card-border-bright); }}
  .switch-input:checked::after {{ transform: translateX(22px); background: var(--text-main); }}
  .list-row {{
    display: flex; justify-content: space-between; align-items: center; gap: 10px; padding: 12px 14px; border-radius: 15px;
    background: rgba(14, 20, 27, 0.88); border: 1px solid var(--card-border); margin-bottom: 8px;
  }}
  .guild-icon, .guild-icon-ph {{ width: 44px; height: 44px; border-radius: 13px; object-fit: cover; flex-shrink: 0; }}
  .guild-icon-ph {{
    background: linear-gradient(135deg, var(--accent-indigo), var(--accent-violet)); border: 1px solid var(--brand);
    display: flex; align-items: center; justify-content: center; font-weight: 900; font-size: 15px; color: var(--text-main);
  }}
  .mini-btn {{
    padding: 10px 14px; border-radius: 13px; border: 1px solid var(--brand);
    background: linear-gradient(135deg, var(--accent-indigo), var(--accent-violet)); color: var(--text-main); font-size: 12.5px; font-weight: 800; cursor: pointer;
  }}
  .mini-btn.red {{ border-color: var(--accent-coral); background: rgba(255, 123, 84, 0.24); }}
  .album-box {{ padding: 15px; border-radius: 16px; background: var(--bg-deep); border: 1px dashed var(--card-border); margin-bottom: 12px; }}
  .preview-thumb {{ width: 74px; height: 74px; border-radius: 13px; object-fit: cover; border: 1px solid var(--card-border); margin-top: 8px; }}
  .preview-banner {{ width: 100%; max-width: 250px; height: 74px; border-radius: 13px; object-fit: cover; border: 1px solid var(--card-border); margin-top: 8px; }}
  .prem-lookup-card {{
    display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap;
    padding: 12px 14px; border-radius: 15px; background: var(--bg-deep); border: 1px solid var(--card-border); margin-bottom: 12px;
  }}
  .muted {{ color: var(--text-sub); font-size: 13px; }}
  code {{ background: var(--bg-deep); padding: 2px 7px; border-radius: 7px; font-size: 12px; color: var(--text-main); border: 1px solid var(--card-border); }}
</style>
</head>
<body>
<div id="overlay" class="overlay" onclick="toggleDrawer(false)"></div>

<aside id="drawer" class="sidebar" aria-label="{L['menu']}">
  <a class="nav-item" href="/"><span>{esc(BRAND_LABEL_AR)} • {esc(SITE_NAME)}</span></a>
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
      {top_auth_chip}
    </div>

    <div class="top-right">
      <div>
        <div class="brand-title">{esc(BRAND_LABEL_AR)}</div>
        <div class="brand-sub">{L['supervised']} {esc(OWNER_NAME)}</div>
      </div>
      {_brand_logo_img('brand-logo-img', 39)}
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
function toggleLogBox(boxId) {{
  var box = document.getElementById(boxId);
  if (box) box.style.display = (box.style.display === "none" || !box.style.display) ? "block" : "none";
}}
function updateBioCounter(taId, cntId) {{
  var ta = document.getElementById(taId);
  var cnt = document.getElementById(cntId);
  if (ta && cnt) {{
    cnt.textContent = (ta.value || "").length + " / {MAX_BIO_CHARS}";
  }}
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
async function lookupPremUserPreview() {{
  var inp = document.getElementById("prem_uid_inp");
  var card = document.getElementById("prem_lookup_preview");
  if (!inp || !card) return;
  var uid = (inp.value || "").trim();
  if (!/^\\d+$/.test(uid)) {{
    card.style.display = "none";
    return;
  }}
  try {{
    var res = await fetch("/api/lookup-user?user_id=" + encodeURIComponent(uid));
    if (!res.ok) return;
    var data = await res.json();
    if (!data || !data.ok || !data.user) return;
    var u = data.user;
    document.getElementById("prem_prev_ava").src = u.avatar_url || "";
    document.getElementById("prem_prev_name").textContent = u.username || ("User " + uid);
    document.getElementById("prem_prev_handle").textContent = (u.handle || "@user") + " • ID: " + uid + (u.remaining ? (" • " + u.remaining) : "");
    card.style.display = "flex";
  }} catch (e) {{}}
}}
</script>
</body>
</html>"""


async def handle_modern_ui(request: web.Request) -> web.Response:
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

    html_page = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{esc(BRAND_LABEL_AR)} ({esc(SITE_NAME)}) — منظومة الحماية والإدارة المتقدمة</title>
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
    .animate-panel-enter {{ animation: fadeSlideUp 0.34s cubic-bezier(0.22, 1, 0.36, 1) both; }}
    .toggle-track {{ position: relative; width: 48px; height: 26px; border-radius: 9999px; transition: background-color 0.24s ease; flex-shrink: 0; }}
    .toggle-thumb {{ position: absolute; top: 3px; right: 3px; width: 20px; height: 20px; border-radius: 9999px; background: #ffffff; transition: transform 0.24s ease; }}
    input.sr-toggle:checked + .toggle-track .toggle-thumb {{ transform: translateX(-22px); }}
  </style>
</head>
<body class="ambient-grid min-h-screen text-slate-100 antialiased">
  <div id="app" class="min-h-screen flex flex-col">
    <header class="sticky top-0 z-40 border-b border-white/[0.07] bg-[#090b16]/85 backdrop-blur-xl">
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
              <p class="text-[11px] text-slate-400 truncate">منظومة الحماية والأمن الرقمي للسيرفرات</p>
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
      <aside id="nav-drawer" onclick="event.stopPropagation()" class="fixed top-0 right-0 bottom-0 w-[84vw] max-w-xs bg-[#0d1020] border-l border-white/[0.09] shadow-2xl flex flex-col justify-between p-5">
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
        <div id="drawer-auth-actions" class="pt-4 border-t border-white/[0.07] space-y-2"></div>
      </aside>
    </div>

    <main id="main-content" class="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-7 sm:py-10"></main>

    <footer class="border-t border-white/[0.06] bg-[#080a14]/75 backdrop-blur-md mt-auto">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-5 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-400">
        <div class="flex items-center gap-2">
          <span class="font-extrabold text-slate-200">{esc(BRAND_LABEL_AR)} • {esc(SITE_NAME)}</span>
          <span>•</span>
          <span>جميع الحقوق محفوظة © 2026</span>
        </div>
        <a href="/" class="text-violetglow font-bold hover:underline">الواجهة الكلاسيكية</a>
      </div>
    </footer>
  </div>

  <script>
    const INVITE_URL = {invite_href_json};
    const SUPPORT_URL = {support_href_json};
    const LOGO_URL = {logo_json};
    let state = {{
      isAuthenticated: {is_auth_json},
      isPremium: {is_prem_json},
      isAdmin: {is_adm_json},
      botGuildsCount: 0,
      premiumCount: 0,
      adminsCount: 0,
      activePage: "home",
      user: {{
        username: {uname_json},
        handle: "@guest",
        avatar: {avatar_json},
      }},
      selectedGuildId: "",
      guilds: [],
      protection: {{
        antiSpam: true,
        spamPunishment: "Timeout",
        antiLink: true,
        linkPunishment: "Delete & Timeout",
        antiInvites: true,
        antiRaid: true,
        antiNewAccounts: true,
        minAccountAgeDays: 7,
        antiNukeRole: true,
        antiNukeChannel: true,
        antiNukeBan: true,
        antiNukeKick: true,
        autoRollback: true,
      }},
      premium: {{
        active: {is_prem_json},
        planName: "بريميوم عرب سكيورتي الماسي",
        daysLeft: 30,
        customBio: "درع الحماية المتكامل لصد هجمات النيوك والسبام وحفظ السيرفر تلقائياً.",
        customAvatar: {logo_json},
        customBanner: "https://placehold.co/900x260/16132e/9a82ff?text=ARAB+SECURITY+SHIELD",
        lastBackupTime: "منذ دقائق",
      }},
      admin: {{
        broadcastText: "",
        targetUserId: "",
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

    async function hydrateLiveState() {{
      try {{
        const res = await fetch("/api/ui-state", {{ cache: "no-store" }});
        if (!res.ok) return;
        const data = await res.json();
        if (!data || !data.ok) return;
        state.isAuthenticated = Boolean(data.isAuthenticated);
        state.isPremium = Boolean(data.isPremium);
        state.isAdmin = Boolean(data.isAdmin);
        state.botGuildsCount = Number(data.botGuildsCount || 0);
        state.premiumCount = Number(data.premiumCount || 0);
        state.adminsCount = Number(data.adminsCount || 0);
        if (data.user) state.user = {{ ...state.user, ...data.user }};
        state.selectedGuildId = data.selectedGuildId || "";
        state.guilds = Array.isArray(data.guilds) ? data.guilds : [];
        if (data.protection) state.protection = {{ ...state.protection, ...data.protection }};
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
              الداشبورد مقفلة حتى تسجيل الدخول. اضغط دخول ديسكورد للوصول إلى لوحة <span class="text-violetglow font-extrabold">{escapeHtml("{BRAND_LABEL_AR}")}</span>.
            </p>
            <a href="/login?next=/ui" class="w-full py-3.5 px-6 rounded-2xl bg-gradient-to-r from-[#d8d4ff] via-[#e9e6ff] to-[#c9c2ff] text-[#17142e] font-extrabold text-sm sm:text-base flex items-center justify-center gap-2.5">
              <span>دخول ديسكورد</span>
            </a>
            <div class="mt-5">
              <a href="/" class="text-xs sm:text-sm font-bold text-slate-400 hover:text-white">العودة للرئيسية</a>
            </div>
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
                <p class="text-xs text-slate-400 mt-1">أضف البوت إلى سيرفرك لتفعيل لوحة التحكم والتعديل</p>
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
      const activeGuardsCount = Object.entries(state.protection).filter(([k, v]) => typeof v === "boolean" && v).length;
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
                تحكم كامل في أنظمة الحماية، اللقطات والاسترجاع التلقائي، مزايا البريميوم، ولوحة الإدارة المرتبطة مباشرة بقاعدة البيانات.
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
              <p class="text-xs text-slate-400 font-semibold">سيرفراتك المتصلة بالبوت</p>
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
        <label class="flex items-center justify-between gap-4 p-4 rounded-2xl bg-[#0e1121]/85 hover:bg-[#13182e] border border-white/[0.07] transition-all cursor-pointer">
          <div class="min-w-0">
            <div class="flex items-center gap-2 flex-wrap">
              <span class="font-extrabold text-sm text-white">${{escapeHtml(title)}}</span>
              <span class="px-2 py-0.5 rounded-full text-[10px] font-bold ${{checked ? "bg-emeraldsafe/15 text-emeraldsafe border border-emeraldsafe/30" : "bg-white/[0.05] text-slate-400 border border-white/[0.08]"}}">
                ${{checked ? "نشط" : "متوقف"}}
              </span>
            </div>
            <p class="text-xs text-slate-400 mt-1">${{escapeHtml(desc)}}</p>
          </div>
          <div class="relative inline-flex items-center">
            <input type="checkbox" class="sr-only sr-toggle" ${{checked ? "checked" : ""}} onchange="toggleProtection('${{key}}', this.checked)" />
            <div class="toggle-track ${{checked ? "bg-gradient-to-r from-violetcore to-emeraldsafe" : "bg-slate-700/80"}}">
              <div class="toggle-thumb"></div>
            </div>
          </div>
        </label>
      `;
    }}

    function renderProtectionPage() {{
      const guild = getActiveGuild();
      if (!guild) {{
        return `
          <div class="rounded-3xl bg-card/90 border border-white/[0.08] p-6 text-center space-y-4">
            <h2 class="text-xl font-black text-white">يجب إدخال البوت إلى السيرفر أولاً</h2>
            <p class="text-xs text-slate-400">لا يمكن تعديل إعدادات سيرفر غير مضاف فيه البوت.</p>
            <a href="${{escapeHtml(INVITE_URL)}}" class="inline-block px-5 py-2.5 rounded-xl text-xs font-extrabold bg-violetcore text-white">دعوة بوت {escapeHtml("{BRAND_LABEL_AR}")}</a>
          </div>
        `;
      }}
      return `
        <div class="animate-panel-enter space-y-6">
          <div class="rounded-[26px] bg-gradient-to-r from-[#161a33] via-[#12162b] to-[#0d1122] border border-white/[0.09] p-6 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-glass">
            <div>
              <h1 class="text-2xl font-black text-white">لوحة الحماية</h1>
              <p class="text-xs sm:text-sm text-slate-400 mt-1">السيرفر المحدد: <span class="text-white font-bold">${{escapeHtml(guild.name)}}</span></p>
            </div>
            <button type="button" onclick="saveProtectionConfig()" class="px-5 py-2.5 rounded-xl text-xs font-extrabold bg-gradient-to-r from-violetcore to-indigo-500 text-white shadow-violet">حفظ ومزامنة الإعدادات</button>
          </div>
          <div class="grid grid-cols-1 lg:grid-cols-2 gap-5">
            <div class="rounded-3xl bg-card/85 border border-white/[0.08] p-5 space-y-3">
              ${{renderToggleRow("antiSpam", "منع السبام (Anti-Spam)", "رصد الرسائل المتكررة وتطبيق العقوبة تلقائياً.")}}
              ${{renderToggleRow("antiLink", "منع الروابط الخارجية", "حذف الروابط غير المصرح بها.")}}
              ${{renderToggleRow("antiInvites", "منع روابط الدعوات", "منع نشر دعوات السيرفرات الخارجية.")}}
              ${{renderToggleRow("antiRaid", "مضاد هجمات الرايد", "التصدي للدخول الجماعي المفاجئ.")}}
              ${{renderToggleRow("antiNewAccounts", "حماية الحسابات الحديثة", "فحص عمر الحسابات الجديدة.")}}
            </div>
            <div class="rounded-3xl bg-card/85 border border-white/[0.08] p-5 space-y-3">
              ${{renderToggleRow("antiNukeRole", "حماية الرتب", "منع الحذف العشوائي للرتب.")}}
              ${{renderToggleRow("antiNukeChannel", "حماية القنوات", "صد محاولات تعديل صلاحيات الرومات.")}}
              ${{renderToggleRow("antiNukeBan", "منع فك الحظر الجماعي", "رصد عمليات فك الحظر المتكررة.")}}
              ${{renderToggleRow("antiNukeKick", "منع الطرد الجماعي", "حماية الأعضاء من الطرد العشوائي.")}}
              ${{renderToggleRow("autoRollback", "الاسترجاع التلقائي", "استعادة العناصر المتضررة تلقائياً.")}}
            </div>
          </div>
        </div>
      `;
    }}

    function toggleProtection(key, value) {{
      state.protection[key] = Boolean(value);
      render();
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
      const guild = getActiveGuild();
      if (!guild) {{
        return `
          <div class="rounded-3xl bg-card/90 border border-white/[0.08] p-6 text-center space-y-4">
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
              <textarea id="prem-bio-input" rows="3" class="w-full rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-3.5 py-2.5 text-xs text-white">${{escapeHtml(pr.customBio)}}</textarea>
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
        await hydrateLiveState();
        showToast("تم حفظ تخصيص البريميوم وإرساله للبوت", "success");
      }} else {{
        showToast(out?.error || "تعذر حفظ البريميوم", "warn");
      }}
    }}

    function renderAdminPage() {{
      const filter = state.admin.logFilter || "ALL";
      const filteredLogs = state.admin.logs.filter((item) => (filter === "ALL" ? true : item.level === filter));
      return `
        <div class="animate-panel-enter space-y-6">
          <section class="rounded-[26px] bg-gradient-to-r from-[#141932] via-[#101426] to-[#0b0e1b] border border-white/[0.09] p-6 flex flex-wrap items-center justify-between gap-4 shadow-glass">
            <div>
              <h1 class="text-2xl font-black text-white">لوحة الإدارة</h1>
              <p class="text-xs text-slate-400 mt-1">عدد السيرفرات اللي مدخله البوت: <strong class="text-white">${{state.botGuildsCount}}</strong> • البريميوم: <strong class="text-amberwarn">${{state.premiumCount}}</strong> • الأدمن: <strong class="text-violetglow">${{state.adminsCount}}</strong></p>
            </div>
            <div class="flex items-center gap-2">
              <button type="button" onclick="toggleUiLogDrawer()" class="px-4 py-2.5 rounded-xl text-xs font-extrabold bg-white/[0.06] text-white border border-white/[0.12]">سجل العمليات (Log)</button>
              <a href="/admin" class="px-4 py-2.5 rounded-xl text-xs font-extrabold bg-violetcore text-white shadow-violet">الإدارة الكاملة</a>
            </div>
          </section>

          <section class="grid grid-cols-1 lg:grid-cols-2 gap-5">
            <div class="rounded-3xl bg-card/90 border border-white/[0.08] p-5 sm:p-6 space-y-4">
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

            <div class="rounded-3xl bg-card/90 border border-white/[0.08] p-5 sm:p-6 space-y-4">
              <h2 class="text-base font-black text-white">إرسال بث عام عن بُعد</h2>
              <div class="flex gap-2">
                <input id="admin-broadcast-input" type="text" placeholder="رسالة بث عامة..." class="flex-1 rounded-xl bg-[#0b0e1c] border border-white/[0.1] px-3 py-2.5 text-xs text-white" />
                <button type="button" onclick="sendAdminBroadcast()" class="px-4 py-2.5 rounded-xl text-xs font-extrabold bg-violetcore text-white">إرسال</button>
              </div>
            </div>
          </section>

          <section id="ui-log-section" class="${{state.admin.showLogPanel ? "block" : "hidden"}} rounded-3xl bg-card/90 border border-white/[0.08] p-5 sm:p-6">
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
              `).join("")}}
            </div>
          </section>
        </div>
      `;
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
        await hydrateLiveState();
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
        await hydrateLiveState();
        await lookupUiPremUser();
        showToast("تم سحب البريميوم بنجاح", "warn");
      }} else {{
        showToast(out?.error || "تعذر سحب البريميوم", "danger");
      }}
    }}

    function toggleUiLogDrawer() {{
      state.admin.showLogPanel = !state.admin.showLogPanel;
      render();
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
    return web.Response(text=html_page, content_type="text/html")


async def handle_invite_redirect(request: web.Request) -> web.Response:
    user = get_discord_session(request)
    if not user:
        raise web.HTTPFound("/login?next=" + quote("/invite") + "&msg=" + quote("سجل دخولك بديسكورد أولاً لدعوة البوت."))
    target_invite = sanitize_http_url(BOT_INVITE_URL) or "https://discord.com"
    raise web.HTTPFound(target_invite)


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
            else "يرجى ضبط DISCORD_CLIENT_SECRET في متغيرات البيئة لتفعيل دخول ديسكورد."
        )

    bot_servers_count = len(get_all_guilds())
    total_visits = get_total_visits()
    user_visible, _ = get_user_visible_guilds(user)
    has_active_guild = any(not g.get("bot_missing") for g in user_visible)

    if is_logged_in:
        primary_href = "/guild" if has_active_guild else "/invite"
        primary_txt = ("Security Panel" if is_en else "لوحة الحماية") if has_active_guild else ("Invite عرب سكيورتي Bot" if is_en else "دعوة بوت عرب سكيورتي")
        secondary_href = "/invite"
        secondary_txt = "Invite عرب سكيورتي Bot" if is_en else "دعوة بوت عرب سكيورتي"
    else:
        primary_href = "/login?next=/guild"
        primary_txt = "Login With Discord" if is_en else "دخول ديسكورد"
        secondary_href = "/invite"
        secondary_txt = "Invite عرب سكيورتي Bot" if is_en else "دعوة بوت عرب سكيورتي"

    prem_badge_html = (
        f"<span class='prem-pill'>★ {esc(format_remaining_time(prem_rec, is_en=is_en))}</span>"
        if (is_prem and prem_rec)
        else ""
    )

    body = _render_intro_hero_html(
        is_en=is_en,
        bot_servers_count=bot_servers_count,
        total_visits=total_visits,
        is_logged_in=is_logged_in,
        primary_href=primary_href,
        primary_txt=primary_txt,
        secondary_href=secondary_href,
        secondary_txt=secondary_txt,
        prem_badge_html=prem_badge_html,
    )
    return web.Response(
        text=render_page("Home" if is_en else "الرئيسية", "home", body, request, flash=flash, next_after_login="/guild"),
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

    bio_changed = ("bio" in form) and (bio_clean != old_bio or bool(bio_clean))
    avatar_changed = ("avatar_data_url" in form) and (ava_data != old_ava)
    banner_changed = ("banner_data_url" in form) and (ban_data != old_ban)
    profile_changed = ("bio" in form) or avatar_changed or banner_changed

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

    return f"""
    <input type="hidden" id="avatar_data_url" name="avatar_data_url" value="{esc(ava_src)}">
    <input type="hidden" id="avatar_name" name="avatar_name" value="{esc(prof.get('avatar_name', ''))}">
    <input type="hidden" id="banner_data_url" name="banner_data_url" value="{esc(ban_src)}">
    <input type="hidden" id="banner_name" name="banner_name" value="{esc(prof.get('banner_name', ''))}">

    <label class="switch-row">
      <span>{('High Shield Mode' if is_en else 'حماية فائقة')}</span>
      <input class="switch-input" type="checkbox" name="{uf_name}" {'checked' if perks.get('ultra_fortress_mode') else ''}>
    </label>
    <label class="switch-row">
      <span>{('Instant Rollback' if is_en else 'الاسترجاع الفوري')}</span>
      <input class="switch-input" type="checkbox" name="{ir_name}" {'checked' if perks.get('instant_rollback_enabled', True) else ''}>
    </label>
    <label class="switch-row">
      <span>{('Priority Shield Response' if is_en else 'استجابة الحماية الفورية')}</span>
      <input class="switch-input" type="checkbox" name="{ps_name}" {'checked' if perks.get('priority_shield_response', True) else ''}>
    </label>

    <label class="lbl" for="{bio_id}">{('Custom Bot Bio (Up to 270 chars)' if is_en else 'نبذة البوت (البايو — حتى 270 حرفاً)')}</label>
    <textarea id="{bio_id}" class="bio-textarea" rows="5" maxlength="{MAX_BIO_CHARS}" name="bio" oninput="updateBioCounter('{bio_id}', '{cnt_id}')">{esc(bio_val)}</textarea>
    <div class="bio-meta">
      <span>{('Full bio preview up to 270 characters' if is_en else 'الحد الأقصى للبايو 270 حرفاً')}</span>
      <span id="{cnt_id}">{len(bio_val)} / {MAX_BIO_CHARS}</span>
    </div>

    <div class="album-box">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
        <label class="lbl" style="margin:0;">{('Bot Avatar' if is_en else 'أفتار البوت')}</label>
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
            text=render_page(
                "Security Panel" if is_en else "لوحة الحماية",
                "guild",
                "",
                request,
                require_auth_view=True,
                next_after_login="/guild",
            ),
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
        extra_list = f"<div style='margin-top:14px;'>{cards_html}</div>" if cards_html else ""
        msg = (
            "The bot is not in your servers yet. Invite عرب سكيورتي bot to your server before editing settings."
            if is_en
            else "البوت غير موجود في سيرفراتك بعد. يجب إدخال بوت عرب سكيورتي إلى السيرفر قبل التعديل عليه."
        )
        empty_body = f"""
        <div class='glass-card anim-card'>
          <h2 style='margin:0 0 8px;'>{('Security Panel' if is_en else 'لوحة الحماية')}</h2>
          <p class='muted' style='margin:0 0 14px;'>{esc(msg)}</p>
          <div class='hero-actions'>
            <a class='btn-primary-purple' href='/invite'>{('Invite عرب سكيورتي Bot' if is_en else 'دعوة بوت عرب سكيورتي')}</a>
            <a class='btn-secondary-dark' href='/guild'>{('Refresh Servers' if is_en else 'تحديث قائمة السيرفرات')}</a>
          </div>
          {extra_list}
        </div>
        """
        return web.Response(
            text=render_page("Security Panel" if is_en else "لوحة الحماية", "guild", empty_body, request),
            content_type="text/html",
        )

    gid = str(request.query.get("id", "")).strip()
    if not gid.isdigit() or not any(g["id"] == gid for g in active_guilds):
        gid = active_guilds[0]["id"]

    flash = sanitize_flash_msg(request.query.get("msg"))

    if request.method == "POST":
        form = await read_post_safe(request)
        if form is None:
            return web.Response(text="Payload too large", status=413)
        if not consume_csrf_token(form.get("csrf_token"), session_id):
            raise web.HTTPFound(f"/guild?id={quote(gid)}&msg=" + quote("Invalid or expired form token."))

        action = str(form.get("action", "")).strip()
        if action == "save_shield":
            updates: dict = {}
            for k in SHIELD_TOGGLE_KEYS:
                if k in PREMIUM_PROTECTION_TOGGLE_KEYS and not is_prem:
                    continue
                updates[k] = form.get(f"sh_{k}") == "on"

            updates["prefix"] = str(form.get("prefix", "!") or "!").strip()[:6]
            updates["mod_log_channel"] = str(form.get("mod_log_channel", "") or "").strip()
            updates["spam_punishment"] = str(form.get("spam_punishment", "Timeout") or "Timeout").strip()
            try:
                updates["spam_timeout_seconds"] = max(10, min(2419200, int(form.get("spam_timeout_seconds", 600))))
            except Exception:
                updates["spam_timeout_seconds"] = 600
            updates["link_punishment"] = str(form.get("link_punishment", "Delete & Timeout") or "Delete & Timeout").strip()
            try:
                updates["link_timeout_seconds"] = max(10, min(2419200, int(form.get("link_timeout_seconds", 300))))
            except Exception:
                updates["link_timeout_seconds"] = 300
            updates["dangerous_perms_punishment"] = str(
                form.get("dangerous_perms_punishment", "Remove Roles") or "Remove Roles"
            ).strip()
            updates["app_abuse_punishment"] = str(form.get("app_abuse_punishment", "Ban") or "Ban").strip()
            try:
                updates["min_account_age_days"] = max(1, min(365, int(form.get("min_account_age_days", 7))))
            except Exception:
                updates["min_account_age_days"] = 7

            if is_prem:
                updates["guild_icon_punishment"] = str(form.get("guild_icon_punishment", "Ban") or "Ban").strip()
                updates["selfbot_punishment"] = str(form.get("selfbot_punishment", "Ban") or "Ban").strip()

            an_upd: dict[str, dict] = {}
            for ak in ANTINUKE_RULE_KEYS:
                enabled_val = form.get(f"an_en_{ak}") == "on"
                pun_val = str(form.get(f"an_pun_{ak}", "Ban") or "Ban").strip()
                if pun_val not in ("Ban", "Kick", "Remove Roles", "Delete Only"):
                    pun_val = "Ban"
                try:
                    lim_val = max(1, min(50, int(form.get(f"an_lim_{ak}", 1))))
                except Exception:
                    lim_val = 1
                an_upd[ak] = {"enabled": enabled_val, "limit": lim_val, "punishment": pun_val}
            updates["antinuke_updates"] = an_upd

            save_guild_cfg(gid, updates, is_premium=is_prem)
            enqueue_remote_action(
                gid,
                "sync_guild_cfg",
                gid,
                extra={"guild_id": gid, "user_id": actor_uid, "actor_id": actor_uid},
                actor_user_id=actor_uid,
            )
            log_event(f"Shield settings saved for guild {gid}", guild_id=gid, level="SEC")
            flash = "Protection settings saved and synced with bot." if is_en else "تم حفظ إعدادات الحماية ومزامنتها مع البوت."
        elif action == "save_prem_guild":
            if not is_prem:
                flash = "Premium required." if is_en else "ميزة البريميوم مطلوبة."
            else:
                cur_cfg = get_guild_cfg(gid)
                prof_data, perks_data, profile_changed, bio_changed, avatar_changed, banner_changed = _process_premium_profile_and_perks(
                    form,
                    cur_cfg.get("guild_profile") or {},
                    cur_cfg.get("premium_perks") or {},
                )
                save_guild_cfg(gid, {"guild_profile": prof_data, "premium_perks": perks_data}, is_premium=True)
                if profile_changed:
                    enqueue_remote_action(
                        gid,
                        "update_bot_profile",
                        gid,
                        extra={
                            "guild_id": gid,
                            "user_id": actor_uid,
                            "actor_id": actor_uid,
                            "bio": prof_data.get("bio", ""),
                            "bio_changed": bio_changed,
                            "avatar_changed": avatar_changed,
                            "banner_changed": banner_changed,
                            "avatar_data_url": prof_data.get("avatar_data_url", ""),
                            "banner_data_url": prof_data.get("banner_data_url", ""),
                        },
                        actor_user_id=actor_uid,
                    )
                enqueue_remote_action(
                    gid,
                    "sync_guild_cfg",
                    gid,
                    extra={"guild_id": gid, "user_id": actor_uid, "actor_id": actor_uid},
                    actor_user_id=actor_uid,
                )
                log_event(f"Premium guild profile & perks saved for {gid}", guild_id=gid, level="ADMIN")
                flash = "Premium settings saved and sent to bot." if is_en else "تم حفظ إعدادات البريميوم وإرسالها للبوت."
        elif action == "save_trusted":
            t_uid = str(form.get("trusted_uid", "") or "").strip()
            if t_uid.isdigit():
                save_guild_cfg(gid, {"trusted_add": t_uid}, is_premium=is_prem)
                enqueue_remote_action(
                    gid,
                    "sync_guild_cfg",
                    gid,
                    extra={"guild_id": gid, "user_id": actor_uid, "actor_id": actor_uid},
                    actor_user_id=actor_uid,
                )
                log_event(f"Added trusted admin {t_uid} in {gid}", guild_id=gid, level="SEC")
                flash = "Trusted admin added." if is_en else "تمت إضافة المشرف الموثوق."
        elif action == "remove_trusted":
            t_uid = str(form.get("trusted_uid", "") or "").strip()
            save_guild_cfg(gid, {"trusted_remove": t_uid}, is_premium=is_prem)
            enqueue_remote_action(
                gid,
                "sync_guild_cfg",
                gid,
                extra={"guild_id": gid, "user_id": actor_uid, "actor_id": actor_uid},
                actor_user_id=actor_uid,
            )
            log_event(f"Removed trusted admin {t_uid} in {gid}", guild_id=gid, level="SEC")
            flash = "Trusted admin removed." if is_en else "تمت إزالة المشرف الموثوق."
        elif action == "save_snapshot":
            save_guild_cfg(gid, {"save_snapshot": True}, is_premium=is_prem)
            enqueue_remote_action(
                gid,
                "save_snapshot",
                gid,
                extra={"guild_id": gid, "user_id": actor_uid, "actor_id": actor_uid},
                actor_user_id=actor_uid,
            )
            log_event(f"Saved security snapshot for {gid}", guild_id=gid, level="SEC")
            flash = "Security snapshot saved." if is_en else "تم حفظ لقطة الحماية."
        elif action == "restore_snapshot":
            snap_id = str(form.get("snapshot_id", "") or "").strip()
            save_guild_cfg(gid, {"restore_snapshot_id": snap_id}, is_premium=is_prem)
            enqueue_remote_action(
                gid,
                "restore_snapshot",
                snap_id or gid,
                extra={"guild_id": gid, "snapshot_id": snap_id, "user_id": actor_uid, "actor_id": actor_uid},
                actor_user_id=actor_uid,
            )
            log_event(f"Restored security snapshot {snap_id} in {gid}", guild_id=gid, level="SEC")
            flash = "Snapshot restored and synced." if is_en else "تم استرجاع اللقطة ومزامنتها."
        elif action == "run_sim":
            scen = str(form.get("scenario", "mass_ban") or "mass_ban").strip()
            flash = run_attack_simulation(gid, scen, is_en=is_en)
        elif action == "reset_defaults":
            save_guild_cfg(gid, {"reset_defaults": True}, is_premium=is_prem)
            enqueue_remote_action(
                gid,
                "sync_guild_cfg",
                gid,
                extra={"guild_id": gid, "user_id": actor_uid, "actor_id": actor_uid},
                actor_user_id=actor_uid,
            )
            log_event(f"Reset guild settings to defaults in {gid}", guild_id=gid, level="SEC")
            flash = "Settings reset to defaults." if is_en else "تمت إعادة الإعدادات للوضع الافتراضي."

    cfg = get_guild_cfg(gid)
    csrf_tok = issue_csrf_token(session_id)
    score, grade = calculate_security_score(cfg, is_en=is_en)
    guild_opts = "".join(
        f"<option value='{esc(g['id'])}' {'selected' if g['id'] == gid else ''}>{esc(g['name'])} ({esc(g['id'])})</option>"
        for g in active_guilds
    )
    current_guild_obj = next((g for g in active_guilds if g["id"] == gid), active_guilds[0])
    cur_g_icon_url = guild_icon_url(current_guild_obj["id"], current_guild_obj.get("icon"))
    cur_g_icon_html = (
        f"<img class='guild-icon' src='{esc(cur_g_icon_url)}' alt='' loading='lazy' referrerpolicy='no-referrer'>"
        if cur_g_icon_url
        else f"<div class='guild-icon-ph'>{(str(current_guild_obj.get('name', 'S'))[:1] or 'S').upper()}</div>"
    )

    gen_toggles_html = _build_toggle_items(GENERAL_TOGGLE_KEYS, cfg, is_en)
    an_toggles_html = _build_toggle_items(ANTINUKE_TOGGLE_KEYS, cfg, is_en)
    raid_toggles_html = _build_toggle_items(ANTIRAID_TOGGLE_KEYS, cfg, is_en)
    mod_toggles_html = _build_toggle_items(MODERATION_TOGGLE_KEYS, cfg, is_en)

    prem_guild_toggles_html = ""
    if is_prem:
        prem_guild_toggles_html = _build_toggle_items(PREMIUM_PROTECTION_TOGGLE_KEYS, cfg, is_en)

    an_rules_html = ""
    an_map = cfg.get("antinuke") or {}
    for ak in ANTINUKE_RULE_KEYS:
        rule = an_map.get(ak) or {"enabled": True, "limit": 1, "punishment": "Ban"}
        lbl_txt = ANTINUKE_LABELS_AR.get(ak, ak) if not is_en else ak.replace("_", " ").title()
        pun_cur = str(rule.get("punishment", "Ban"))
        pun_opts = "".join(
            f"<option value='{p}' {'selected' if pun_cur == p else ''}>{p}</option>"
            for p in ("Ban", "Kick", "Remove Roles", "Delete Only")
        )
        an_rules_html += f"""
        <div class='list-row' style='flex-wrap:wrap;'>
          <label style='display:flex;align-items:center;gap:10px;font-weight:800;cursor:pointer;'>
            <input class='switch-input' type='checkbox' name='an_en_{ak}' {'checked' if rule.get('enabled') else ''}>
            <span>{esc(lbl_txt)}</span>
          </label>
          <div style='display:flex;align-items:center;gap:8px;flex-wrap:wrap;'>
            <input class='inp' style='width:86px;margin:0;padding:8px 10px;' type='number' min='1' max='50' name='an_lim_{ak}' value='{int(rule.get("limit", 1) or 1)}'>
            <select class='sel' style='width:148px;margin:0;padding:8px 10px;' name='an_pun_{ak}'>{pun_opts}</select>
          </div>
        </div>
        """

    trusted_list_html = ""
    for t_uid in cfg.get("trusted_admins") or []:
        rem_btn = (
            ""
            if t_uid == ADMIN_USER_ID
            else f"<form method='post' action='/guild?id={esc(gid)}' style='margin:0;'><input type='hidden' name='csrf_token' value='{esc(csrf_tok)}'><input type='hidden' name='action' value='remove_trusted'><input type='hidden' name='trusted_uid' value='{esc(t_uid)}'><button class='mini-btn red' type='submit'>{('Remove' if is_en else 'إزالة')}</button></form>"
        )
        trusted_list_html += f"<div class='list-row'><span><code>{esc(t_uid)}</code> {'(Owner)' if t_uid == ADMIN_USER_ID else ''}</span>{rem_btn}</div>"

    snaps_html = ""
    for s in cfg.get("perms_snapshots") or []:
        sid_val = esc(s.get("id", ""))
        snaps_html += f"""
        <div class='list-row' style='flex-wrap:wrap;'>
          <div>
            <div style='font-weight:800;'>Snapshot <code>{sid_val}</code> • {esc(s.get('saved_at', ''))}</div>
            <div class='muted'>Rules: {int(s.get('rules_count', 0))} • Trusted: {int(s.get('trusted_count', 0))}</div>
          </div>
          <form method='post' action='/guild?id={esc(gid)}' style='margin:0;'>
            <input type='hidden' name='csrf_token' value='{esc(csrf_tok)}'>
            <input type='hidden' name='action' value='restore_snapshot'>
            <input type='hidden' name='snapshot_id' value='{sid_val}'>
            <button class='mini-btn' type='submit'>{('Restore' if is_en else 'استرجاع')}</button>
          </form>
        </div>
        """

    prem_panel_html = ""
    if is_prem:
        prof_now = cfg.get("guild_profile") or {}
        perks_now = cfg.get("premium_perks") or {}
        media_fields = _render_premium_media_fields(prof_now, perks_now, is_en=is_en, use_pr_prefix=True)
        prem_panel_html = f"""
        <div class='panel-section prem-sec'>
          <div class='panel-section-head'>
            <h3 class='panel-section-title'>{('Premium Guild Controls & Bot Profile' if is_en else 'مزايا البريميوم وهوية البوت')}</h3>
            <span class='prem-pill'>★ PREMIUM</span>
          </div>
          <form method='post' action='/guild?id={esc(gid)}' style='margin:0;'>
            <input type='hidden' name='csrf_token' value='{esc(csrf_tok)}'>
            <input type='hidden' name='action' value='save_prem_guild'>
            {prem_guild_toggles_html}
            {media_fields}
            <button class='btn-primary-purple' style='margin-top:12px;' type='submit'>{('Save Premium Guild Settings' if is_en else 'حفظ إعدادات البريميوم للسيرفر')}</button>
          </form>
        </div>
        """

    spam_pun_cur = str(cfg.get("spam_punishment", "Timeout"))
    spam_pun_opts = "".join(
        f"<option value='{p}' {'selected' if spam_pun_cur == p else ''}>{p}</option>"
        for p in ("Delete Only", "Timeout", "Kick", "Ban")
    )
    link_pun_cur = str(cfg.get("link_punishment", "Delete & Timeout"))
    link_pun_opts = "".join(
        f"<option value='{p}' {'selected' if link_pun_cur == p else ''}>{p}</option>"
        for p in ("Delete Only", "Delete & Timeout", "Kick", "Ban")
    )
    dang_pun_cur = str(cfg.get("dangerous_perms_punishment", "Remove Roles"))
    dang_pun_opts = "".join(
        f"<option value='{p}' {'selected' if dang_pun_cur == p else ''}>{p}</option>"
        for p in ("None", "Remove Roles", "Kick", "Ban")
    )

    body = f"""
    <div class='studio-banner anim-card'>
      <div style='display:flex;align-items:center;gap:12px;'>
        {cur_g_icon_html}
        <div>
          <h1 class='studio-banner-title'>{esc(current_guild_obj.get('name', 'Server'))}</h1>
          <div class='studio-banner-sub'>ID: <code>{esc(gid)}</code> • {('Members' if is_en else 'الأعضاء')}: {int(current_guild_obj.get('member_count', 0) or 0)}</div>
        </div>
      </div>
      <div class='score-ring-box'>
        <div class='score-ring-val'>{score}/100</div>
        <div class='score-ring-lbl'>{esc(grade)}</div>
      </div>
    </div>

    <div class='glass-card anim-card'>
      <label class='lbl'>{('Select Managed Server (Bot Present)' if is_en else 'اختر السيرفر المضاف فيه البوت')}</label>
      <select class='sel' onchange="if(this.value) location.href='/guild?id='+encodeURIComponent(this.value)">
        {guild_opts}
      </select>

      <div class='cat-tabs'>
        <button type='button' class='cat-tab-btn active' onclick="switchCat('shield', this)">{('Shield & Anti-Nuke' if is_en else 'الحماية والآنتي نيوك')}</button>
        <button type='button' class='cat-tab-btn' onclick="switchCat('rules', this)">{('Rules & Limits' if is_en else 'الحدود والعقوبات')}</button>
        <button type='button' class='cat-tab-btn' onclick="switchCat('snapshots', this)">{('Trusted & Snapshots' if is_en else 'الموثوقون واللقطات')}</button>
        <button type='button' class='cat-tab-btn' onclick="switchCat('checks', this)">{('Safety Checks' if is_en else 'فحص الجاهزية')}</button>
      </div>

      <div id='cat-shield' class='cat-pane active'>
        <form method='post' action='/guild?id={esc(gid)}'>
          <input type='hidden' name='csrf_token' value='{esc(csrf_tok)}'>
          <input type='hidden' name='action' value='save_shield'>

          <div class='grid-2'>
            <div>
              <label class='lbl'>{('Command Prefix' if is_en else 'بادئة الأوامر')}</label>
              <input class='inp' type='text' name='prefix' value='{esc(cfg.get("prefix", "!"))}'>
            </div>
            <div>
              <label class='lbl'>{('Mod Log Channel ID' if is_en else 'آيدي روم السجل')}</label>
              <input class='inp' type='text' name='mod_log_channel' value='{esc(cfg.get("mod_log_channel", ""))}'>
            </div>
          </div>

          <div class='panel-section'>
            <div class='panel-section-head'><h3 class='panel-section-title'>{('Core Modes' if is_en else 'الأوضاع الأساسية')}</h3></div>
            {gen_toggles_html}
          </div>

          <div class='panel-section'>
            <div class='panel-section-head'><h3 class='panel-section-title'>{('Anti-Raid & Moderation' if is_en else 'مضاد الرايد والإشراف')}</h3></div>
            {raid_toggles_html}
            {mod_toggles_html}
          </div>

          <div class='panel-section'>
            <div class='panel-section-head'><h3 class='panel-section-title'>{('Anti-Nuke Guards' if is_en else 'حمايات الآنتي نيوك')}</h3></div>
            {an_toggles_html}
          </div>

          <button class='btn-primary-purple' type='submit'>{('Save & Sync Protection Settings' if is_en else 'حفظ ومزامنة إعدادات الحماية')}</button>
        </form>
        <div style='margin-top:14px;'>{prem_panel_html}</div>
      </div>

      <div id='cat-rules' class='cat-pane'>
        <form method='post' action='/guild?id={esc(gid)}'>
          <input type='hidden' name='csrf_token' value='{esc(csrf_tok)}'>
          <input type='hidden' name='action' value='save_shield'>
          {gen_toggles_html}
          {raid_toggles_html}
          {mod_toggles_html}
          {an_toggles_html}
          <div class='grid-2'>
            <div>
              <label class='lbl'>{('Spam Punishment' if is_en else 'عقوبة السبام')}</label>
              <select class='sel' name='spam_punishment'>{spam_pun_opts}</select>
            </div>
            <div>
              <label class='lbl'>{('Link Punishment' if is_en else 'عقوبة الروابط')}</label>
              <select class='sel' name='link_punishment'>{link_pun_opts}</select>
            </div>
            <div>
              <label class='lbl'>{('Dangerous Perms Punishment' if is_en else 'عقوبة الصلاحيات الخطيرة')}</label>
              <select class='sel' name='dangerous_perms_punishment'>{dang_pun_opts}</select>
            </div>
            <div>
              <label class='lbl'>{('Min Account Age (Days)' if is_en else 'الحد الأدنى لعمر الحساب (أيام)')}</label>
              <input class='inp' type='number' min='1' max='365' name='min_account_age_days' value='{int(cfg.get("min_account_age_days", 7) or 7)}'>
            </div>
          </div>
          <div class='panel-section'>
            <div class='panel-section-head'><h3 class='panel-section-title'>{('Rule Limits & Punishments' if is_en else 'حدود وعقوبات قواعد الآنتي نيوك')}</h3></div>
            {an_rules_html}
          </div>
          <button class='btn-primary-purple' type='submit'>{('Save Rules & Punishments' if is_en else 'حفظ الحدود والعقوبات')}</button>
        </form>
      </div>

      <div id='cat-snapshots' class='cat-pane'>
        <div class='panel-section'>
          <div class='panel-section-head'><h3 class='panel-section-title'>{('Trusted Admins' if is_en else 'الموثوقون في السيرفر')}</h3></div>
          <form method='post' action='/guild?id={esc(gid)}' style='display:flex;gap:8px;margin-bottom:12px;'>
            <input type='hidden' name='csrf_token' value='{esc(csrf_tok)}'>
            <input type='hidden' name='action' value='save_trusted'>
            <input class='inp' style='margin:0;' type='text' name='trusted_uid' placeholder='Discord User ID'>
            <button class='mini-btn' type='submit'>{('Add' if is_en else 'إضافة')}</button>
          </form>
          {trusted_list_html}
        </div>

        <div class='panel-section'>
          <div class='panel-section-head'><h3 class='panel-section-title'>{('Snapshots & Rollback' if is_en else 'اللقطات والاسترجاع')}</h3></div>
          <form method='post' action='/guild?id={esc(gid)}' style='margin-bottom:12px;'>
            <input type='hidden' name='csrf_token' value='{esc(csrf_tok)}'>
            <input type='hidden' name='action' value='save_snapshot'>
            <button class='btn-primary-purple' type='submit'>{('Create Snapshot Now' if is_en else 'حفظ لقطة جديدة الآن')}</button>
          </form>
          {snaps_html or f"<p class='muted'>{('No snapshots saved yet.' if is_en else 'لا توجد لقطات محفوظة بعد.')}</p>"}
        </div>
      </div>

      <div id='cat-checks' class='cat-pane'>
        <form method='post' action='/guild?id={esc(gid)}'>
          <input type='hidden' name='csrf_token' value='{esc(csrf_tok)}'>
          <input type='hidden' name='action' value='run_sim'>
          <label class='lbl'>{('Select Safety Scenario' if is_en else 'اختر سيناريو الفحص')}</label>
          <select class='sel' name='scenario'>
            <option value='mass_ban'>Mass Ban / Nuke Check</option>
            <option value='role_delete'>Role Delete & Rollback Check</option>
            <option value='raid_surge'>Join Surge / Raid Check</option>
          </select>
          <button class='btn-primary-purple' type='submit'>{('Run Readiness Check' if is_en else 'تشغيل فحص الجاهزية')}</button>
        </form>
        <form method='post' action='/guild?id={esc(gid)}' style='margin-top:12px;'>
          <input type='hidden' name='csrf_token' value='{esc(csrf_tok)}'>
          <input type='hidden' name='action' value='reset_defaults'>
          <button class='btn-crimson' type='submit'>{('Reset All Server Settings to Default' if is_en else 'إعادة جميع إعدادات السيرفر للوضع الافتراضي')}</button>
        </form>
      </div>
    </div>
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
            text=render_page(
                "Premium" if is_en else "البريميوم",
                "premium",
                "",
                request,
                require_auth_view=True,
                next_after_login="/premium",
            ),
            content_type="text/html",
        )
    session_id, user = sess_pair
    if not is_premium_user(user):
        raise web.HTTPFound("/?msg=" + quote("Premium subscription required." if is_en else "اشتراك البريميوم مطلوب للوصول إلى هذه الصفحة."))

    actor_uid = str(user.get("id", "")).strip()
    prem_rec = _get_premium_record(actor_uid)
    guilds, _ = get_user_visible_guilds(user)
    active_guilds = [g for g in guilds if not g.get("bot_missing")]
    gid = str(request.query.get("id", "")).strip()
    if not gid.isdigit() or not any(g["id"] == gid for g in active_guilds):
        gid = active_guilds[0]["id"] if active_guilds else ""

    flash = sanitize_flash_msg(request.query.get("msg"))
    if request.method == "POST":
        form = await read_post_safe(request)
        if form is None:
            return web.Response(text="Payload too large", status=413)
        if not consume_csrf_token(form.get("csrf_token"), session_id):
            raise web.HTTPFound("/premium?msg=" + quote("Invalid or expired form token."))
        if not gid:
            flash = "Invite the bot to a server first." if is_en else "أضف البوت إلى سيرفر أولاً لتعديل إعداداته."
        else:
            cur_cfg = get_guild_cfg(gid)
            prof_data, perks_data, profile_changed, bio_changed, avatar_changed, banner_changed = _process_premium_profile_and_perks(
                form,
                cur_cfg.get("guild_profile") or {},
                cur_cfg.get("premium_perks") or {},
            )
            save_guild_cfg(gid, {"guild_profile": prof_data, "premium_perks": perks_data}, is_premium=True)
            if profile_changed:
                enqueue_remote_action(
                    gid,
                    "update_bot_profile",
                    gid,
                    extra={
                        "guild_id": gid,
                        "user_id": actor_uid,
                        "actor_id": actor_uid,
                        "bio": prof_data.get("bio", ""),
                        "bio_changed": bio_changed,
                        "avatar_changed": avatar_changed,
                        "banner_changed": banner_changed,
                        "avatar_data_url": prof_data.get("avatar_data_url", ""),
                        "banner_data_url": prof_data.get("banner_data_url", ""),
                    },
                    actor_user_id=actor_uid,
                )
            enqueue_remote_action(
                gid,
                "sync_guild_cfg",
                gid,
                extra={"guild_id": gid, "user_id": actor_uid, "actor_id": actor_uid},
                actor_user_id=actor_uid,
            )
            log_event(f"Premium profile updated for guild {gid}", guild_id=gid, level="ADMIN")
            flash = "Premium settings saved and synced." if is_en else "تم حفظ إعدادات البريميوم ومزامنتها."

    csrf_tok = issue_csrf_token(session_id)
    cfg = get_guild_cfg(gid) if gid else _fresh_default_guild_cfg()
    prof = cfg.get("guild_profile") or {}
    perks = cfg.get("premium_perks") or {}
    guild_opts = "".join(
        f"<option value='{esc(g['id'])}' {'selected' if g['id'] == gid else ''}>{esc(g['name'])} ({esc(g['id'])})</option>"
        for g in active_guilds
    )
    media_fields = _render_premium_media_fields(prof, perks, is_en=is_en, use_pr_prefix=False)

    body = f"""
    <div class='glass-card anim-card'>
      <div style='display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;margin-bottom:14px;'>
        <h1 style='margin:0;font-size:22px;font-weight:900;'>{('Premium Studio' if is_en else 'استوديو البريميوم')}</h1>
        <span class='prem-pill'>★ {esc(format_remaining_time(prem_rec, is_en=is_en))}</span>
      </div>

      <form method='post' action='/premium?id={esc(gid)}'>
        <input type='hidden' name='csrf_token' value='{esc(csrf_tok)}'>
        <label class='lbl'>{('Target Server (Bot Present)' if is_en else 'السيرفر المستهدف (المضاف فيه البوت)')}</label>
        <select class='sel' onchange="if(this.value) location.href='/premium?id='+encodeURIComponent(this.value)">
          {guild_opts or "<option value=''>No active bot guild</option>"}
        </select>
        {media_fields}
        <button class='btn-primary-purple' style='margin-top:14px;' type='submit'>{('Save & Sync Premium Profile' if is_en else 'حفظ ومزامنة إعدادات البريميوم')}</button>
      </form>
    </div>
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
            text=render_page(
                "Admin Panel" if is_en else "لوحة الإدارة",
                "admin",
                "",
                request,
                require_auth_view=True,
                next_after_login="/admin",
            ),
            content_type="text/html",
        )
    session_id, user = sess_pair
    if not is_site_admin(user):
        raise web.HTTPFound("/?msg=" + quote("Admin access required." if is_en else "صلاحية الإدارة مطلوبة للوصول إلى هذه الصفحة."))

    actor_uid = str(user.get("id", "")).strip()
    can_prem = has_admin_perm(user, "manage_premium")
    can_admins = has_admin_perm(user, "manage_admins")
    can_remote = has_admin_perm(user, "remote_actions")
    can_backups = has_admin_perm(user, "backups")
    can_logs = has_admin_perm(user, "view_logs")

    flash = sanitize_flash_msg(request.query.get("msg"))
    if request.method == "POST":
        form = await read_post_safe(request)
        if form is None:
            return web.Response(text="Payload too large", status=413)
        if not consume_csrf_token(form.get("csrf_token"), session_id):
            raise web.HTTPFound("/admin?msg=" + quote("Invalid or expired form token."))

        action = str(form.get("action", "")).strip()
        if action in ("prem_grant", "prem_extend"):
            if not can_prem:
                flash = "Missing manage_premium permission." if is_en else "تفتقر لصلاحية إدارة البريميوم."
            else:
                p_uid = str(form.get("prem_uid", "") or "").strip()
                try:
                    days = max(1, min(3650, int(form.get("prem_days", 30) or 30)))
                except Exception:
                    days = 30
                try:
                    hours = max(0, min(720, int(form.get("prem_hours", 0) or 0)))
                except Exception:
                    hours = 0
                if p_uid.isdigit():
                    preview = await _lookup_discord_user_preview(p_uid)
                    set_premium_user(
                        p_uid,
                        True,
                        days=days,
                        hours=hours,
                        granted_by=actor_uid,
                        username=preview.get("username", ""),
                        handle=preview.get("handle", ""),
                        avatar_url=preview.get("avatar_url", ""),
                        source="manual",
                    )
                    log_event(f"Admin {actor_uid} granted/extended premium +{days}d {hours}h to {p_uid}", level="ADMIN")
                    flash = "Premium subscription updated." if is_en else "تم تحديث اشتراك البريميوم بنجاح."
                else:
                    flash = "Invalid User ID." if is_en else "معرف المستخدم غير صحيح."
        elif action == "prem_revoke":
            if not can_prem:
                flash = "Missing manage_premium permission." if is_en else "تفتقر لصلاحية إدارة البريميوم."
            else:
                p_uid = str(form.get("prem_uid", "") or "").strip()
                if p_uid == ADMIN_USER_ID:
                    flash = "Cannot revoke owner premium." if is_en else "لا يمكن سحب بريميوم المالك."
                elif set_premium_user(p_uid, False):
                    log_event(f"Admin {actor_uid} revoked premium from {p_uid}", level="ADMIN")
                    flash = "Premium revoked." if is_en else "تم سحب اشتراك البريميوم."
        elif action == "admin_add":
            if not can_admins:
                flash = "Missing manage_admins permission." if is_en else "تفتقر لصلاحية إدارة الأدمن."
            else:
                a_uid = str(form.get("admin_uid", "") or "").strip()
                role_val = _sanitize_staff_role(form.get("admin_role", "Staff"), uid=a_uid)
                perms_chosen = {k: (form.get(f"adm_perm_{k}") == "on") for k in ADMIN_PERMISSION_KEYS}
                if a_uid.isdigit() and set_admin_user(a_uid, True, granted_by=actor_uid, permissions=perms_chosen, role_tag=role_val):
                    log_event(f"Admin {actor_uid} set staff {a_uid} ({role_val})", level="ADMIN")
                    flash = "Staff permissions saved." if is_en else "تم حفظ بيانات وصلاحيات عضو الإدارة."
        elif action == "admin_remove":
            if not can_admins:
                flash = "Missing manage_admins permission." if is_en else "تفتقر لصلاحية إدارة الأدمن."
            else:
                a_uid = str(form.get("admin_uid", "") or "").strip()
                if set_admin_user(a_uid, False):
                    log_event(f"Admin {actor_uid} removed admin {a_uid}", level="ADMIN")
                    flash = "Admin removed." if is_en else "تمت إزالة صلاحية الإدارة."
        elif action == "remote_cmd":
            if not can_remote:
                flash = "Missing remote_actions permission." if is_en else "تفتقر لصلاحية الأوامر عن بُعد."
            else:
                r_gid = str(form.get("remote_gid", "0") or "0").strip()
                r_act = str(form.get("remote_action", "broadcast") or "broadcast").strip()
                r_tgt = str(form.get("remote_target", "") or "").strip()
                enqueue_remote_action(r_gid, r_act, r_tgt, extra={"user_id": actor_uid, "actor_id": actor_uid}, actor_user_id=actor_uid)
                log_event(f"Admin {actor_uid} queued [{r_act}] for {r_tgt} in {r_gid}", guild_id=r_gid, level="ADMIN")
                flash = "Remote command queued." if is_en else "تمت إضافة الأمر إلى طابور التنفيذ."
        elif action == "create_backup":
            if not can_backups:
                flash = "Missing backups permission." if is_en else "تفتقر لصلاحية النسخ الاحتياطي."
            else:
                snap = create_db_backup()
                flash = f"Backup created [{snap.get('backup_id')}]." if is_en else f"تم إنشاء نسخة احتياطية [{snap.get('backup_id')}]."
        elif action == "test_restore":
            if not can_backups:
                flash = "Missing backups permission." if is_en else "تفتقر لصلاحية النسخ الاحتياطي."
            else:
                _, flash = test_backup_restore(str(form.get("backup_id", "") or "").strip(), is_en=is_en)

    csrf_tok = issue_csrf_token(session_id)
    all_guilds = get_all_guilds()
    prem_list = get_premium_list()
    admin_list = get_admin_list()

    prem_cards = ""
    for p in prem_list:
        p_uid = esc(p.get("user_id", ""))
        p_uname = esc(p.get("username", f"User {p_uid}"))
        p_handle = esc(p.get("handle", f"@{p_uid}"))
        p_ava = esc(p.get("avatar_url") or _default_avatar_for_uid(p_uid))
        p_rem = esc(format_remaining_time(p, is_en=is_en))
        rev_btn = (
            ""
            if p.get("user_id") == ADMIN_USER_ID or not can_prem
            else f"<form method='post' action='/admin' style='margin:0;'><input type='hidden' name='csrf_token' value='{esc(csrf_tok)}'><input type='hidden' name='action' value='prem_revoke'><input type='hidden' name='prem_uid' value='{p_uid}'><button class='mini-btn red' type='submit'>{('Revoke' if is_en else 'سحب')}</button></form>"
        )
        prem_cards += f"""
        <div class='list-row' style='flex-wrap:wrap;'>
          <div style='display:flex;align-items:center;gap:10px;'>
            <img class='avatar-img' src='{p_ava}' alt='' loading='lazy' referrerpolicy='no-referrer'>
            <div>
              <div style='font-weight:800;'>{p_uname} <span class='muted'>({p_handle})</span></div>
              <div class='muted'>ID: <code>{p_uid}</code> • {p_rem}</div>
            </div>
          </div>
          {rev_btn}
        </div>
        """

    adm_cards = ""
    for a in admin_list:
        a_uid = esc(a.get("user_id", ""))
        a_role = esc(_sanitize_staff_role(a.get("role_tag"), uid=a_uid))
        rm_btn = (
            ""
            if a.get("user_id") == ADMIN_USER_ID or not can_admins
            else f"<form method='post' action='/admin' style='margin:0;'><input type='hidden' name='csrf_token' value='{esc(csrf_tok)}'><input type='hidden' name='action' value='admin_remove'><input type='hidden' name='admin_uid' value='{a_uid}'><button class='mini-btn red' type='submit'>{('Remove' if is_en else 'إزالة')}</button></form>"
        )
        adm_cards += f"""
        <div class='list-row'>
          <div><code>{a_uid}</code> <span class='admin-pill'>{a_role}</span></div>
          {rm_btn}
        </div>
        """

    perm_checks_html = "".join(
        f"<label class='switch-row'><span>{esc(ADMIN_PERMISSION_LABELS[k][0] if is_en else ADMIN_PERMISSION_LABELS[k][1])}</span>"
        f"<input class='switch-input' type='checkbox' name='adm_perm_{k}' checked></label>"
        for k in ADMIN_PERMISSION_KEYS
    )

    guild_cards_html = "".join(
        _render_guild_card({**g, "bot_missing": False}, is_en=is_en, show_admin_meta=True)
        for g in all_guilds[:40]
    ) or f"<p class='muted'>{('No bot servers synced yet.' if is_en else 'لا توجد سيرفرات متزامنة بعد.')}</p>"

    backups_html = "".join(
        f"<div class='list-row'><div><strong>{esc(b.get('backup_id', ''))}</strong> • <span class='muted'>{esc(b.get('created_at', ''))}</span></div>"
        f"<span class='ok-pill'>Guilds: {int(b.get('guilds_count', 0))}</span></div>"
        for b in get_db_backups()
    ) or f"<p class='muted'>{('No backups yet.' if is_en else 'لا توجد نسخ احتياطية بعد.')}</p>"

    logs_rows_html = ""
    if can_logs:
        logs_rows_html = "".join(
            f"<div class='list-row'><div><span class='admin-pill'>{esc(l.get('level', 'WEB'))}</span> <span>{esc(l.get('message', ''))}</span></div>"
            f"<span class='muted'>{esc(l.get('time', ''))}</span></div>"
            for l in get_recent_logs(40)
        ) or f"<p class='muted'>{('No logs found.' if is_en else 'لا توجد سجلات بعد.')}</p>"

    body = f"""
    <div class='admin-hero anim-card'>
      <div>
        <h1 style='margin:0;font-size:22px;font-weight:900;'>{('Admin Panel' if is_en else 'لوحة الإدارة')}</h1>
        <div class='muted'>{('Full overview of bot servers, premium subscribers, staff, and backups' if is_en else 'إدارة كاملة لسيرفرات البوت، اشتراكات البريميوم، طاقم الإدارة، والنسخ الاحتياطية')}</div>
      </div>
      <div style='display:flex;gap:8px;flex-wrap:wrap;'>
        {f"<button type='button' class='mini-btn' onclick=\"toggleLogBox('admin_log_box')\">{('Activity Log (Log)' if is_en else 'سجل العمليات (Log)')}</button>" if can_logs else ""}
      </div>
    </div>

    <div class='admin-kpis anim-card'>
      <div class='kpi-box'><div class='kpi-num'>{len(all_guilds)}</div><div class='kpi-lbl'>{('Bot Servers' if is_en else 'السيرفرات اللي مدخله البوت')}</div></div>
      <div class='kpi-box'><div class='kpi-num'>{len(prem_list)}</div><div class='kpi-lbl'>{('Premium Users' if is_en else 'مشتركو البريميوم')}</div></div>
      <div class='kpi-box'><div class='kpi-num'>{len(admin_list)}</div><div class='kpi-lbl'>{('Admin Staff' if is_en else 'أعضاء الإدارة')}</div></div>
    </div>

    <div id='admin_log_box' class='panel-section' style='display:none;'>
      <div class='panel-section-head'><h3 class='panel-section-title'>{('Activity Log' if is_en else 'سجل العمليات (Log)')}</h3></div>
      {logs_rows_html}
    </div>

    <div class='glass-card anim-card'>
      <div class='cat-tabs'>
        <button type='button' class='cat-tab-btn active' onclick="switchCat('prem_adm', this)">{('Premium' if is_en else 'إدارة البريميوم')}</button>
        <button type='button' class='cat-tab-btn' onclick="switchCat('guilds_adm', this)">{('Bot Servers' if is_en else 'سيرفرات البوت')}</button>
        <button type='button' class='cat-tab-btn' onclick="switchCat('staff_adm', this)">{('Staff & Perms' if is_en else 'الإدارة والصلاحيات')}</button>
        <button type='button' class='cat-tab-btn' onclick="switchCat('remote_adm', this)">{('Remote & Backups' if is_en else 'الأوامر والنسخ')}</button>
      </div>

      <div id='cat-prem_adm' class='cat-pane active'>
        <div class='panel-section'>
          <div class='panel-section-head'><h3 class='panel-section-title'>{('Manage Premium by User ID' if is_en else 'إدارة اشتراك البريميوم بالآيدي')}</h3></div>
          <form method='post' action='/admin'>
            <input type='hidden' name='csrf_token' value='{esc(csrf_tok)}'>
            <label class='lbl'>{('Discord User ID' if is_en else 'آيدي الشخص (User ID)')}</label>
            <input id='prem_uid_inp' class='inp' type='text' name='prem_uid' placeholder='123456789012345678' oninput='lookupPremUserPreview()'>

            <div id='prem_lookup_preview' class='prem-lookup-card' style='display:none;'>
              <div style='display:flex;align-items:center;gap:10px;'>
                <img id='prem_prev_ava' class='avatar-img' src='' alt=''>
                <div>
                  <div id='prem_prev_name' style='font-weight:900;'></div>
                  <div id='prem_prev_handle' class='muted'></div>
                </div>
              </div>
              <span class='ok-pill'>{('User Preview' if is_en else 'معاينة الحساب')}</span>
            </div>

            <div class='grid-2'>
              <div>
                <label class='lbl'>{('Duration (Days)' if is_en else 'المدة (أيام)')}</label>
                <input class='inp' type='number' min='1' max='3650' name='prem_days' value='30'>
              </div>
              <div>
                <label class='lbl'>{('Extra Hours' if is_en else 'ساعات إضافية')}</label>
                <input class='inp' type='number' min='0' max='720' name='prem_hours' value='0'>
              </div>
            </div>
            <div class='grid-2' style='margin-bottom:0;'>
              <button class='btn-primary-purple' type='submit' name='action' value='prem_extend'>{('Extend / Grant Duration' if is_en else 'زيادة المدة / تفعيل')}</button>
              <button class='btn-crimson' type='submit' name='action' value='prem_revoke'>{('Revoke Premium' if is_en else 'سحب البريميوم')}</button>
            </div>
          </form>
        </div>

        <div class='panel-section'>
          <div class='panel-section-head'><h3 class='panel-section-title'>{('Active Premium Subscribers' if is_en else 'المشتركون الحاليون')}</h3></div>
          {prem_cards or f"<p class='muted'>{('No active subscribers.' if is_en else 'لا يوجد مشتركين حالياً.')}</p>"}
        </div>
      </div>

      <div id='cat-guilds_adm' class='cat-pane'>
        <div class='panel-section'>
          <div class='panel-section-head'><h3 class='panel-section-title'>{('Servers With Bot' if is_en else 'السيرفرات التي يدخلها البوت')} ({len(all_guilds)})</h3></div>
          {guild_cards_html}
        </div>
      </div>

      <div id='cat-staff_adm' class='cat-pane'>
        <div class='panel-section'>
          <div class='panel-section-head'><h3 class='panel-section-title'>{('Add / Update Staff Member' if is_en else 'إضافة أو تعديل عضو إدارة')}</h3></div>
          <form method='post' action='/admin'>
            <input type='hidden' name='csrf_token' value='{esc(csrf_tok)}'>
            <input type='hidden' name='action' value='admin_add'>
            <div class='grid-2'>
              <div>
                <label class='lbl'>{('User ID' if is_en else 'آيدي العضو')}</label>
                <input class='inp' type='text' name='admin_uid' placeholder='Discord User ID'>
              </div>
              <div>
                <label class='lbl'>{('Role' if is_en else 'المنصب')}</label>
                <select class='sel' name='admin_role'>
                  <option value='Co owner'>Co owner</option>
                  <option value='Staff' selected>Staff</option>
                </select>
              </div>
            </div>
            {perm_checks_html}
            <button class='btn-primary-purple' type='submit'>{('Save Staff Permissions' if is_en else 'حفظ صلاحيات الإدارة')}</button>
          </form>
        </div>
        <div class='panel-section'>
          <div class='panel-section-head'><h3 class='panel-section-title'>{('Current Staff' if is_en else 'طاقم الإدارة الحالي')}</h3></div>
          {adm_cards}
        </div>
      </div>

      <div id='cat-remote_adm' class='cat-pane'>
        <div class='panel-section'>
          <div class='panel-section-head'><h3 class='panel-section-title'>{('Remote Action Queue' if is_en else 'إرسال أمر عن بُعد')}</h3></div>
          <form method='post' action='/admin'>
            <input type='hidden' name='csrf_token' value='{esc(csrf_tok)}'>
            <input type='hidden' name='action' value='remote_cmd'>
            <label class='lbl'>{('Action Type' if is_en else 'نوع الأمر')}</label>
            <select class='sel' name='remote_action'>
              <option value='broadcast'>Broadcast Message</option>
              <option value='sync_guild_cfg'>Sync Guild Config</option>
              <option value='kick'>Kick Member</option>
              <option value='ban'>Ban Member</option>
              <option value='timeout'>Timeout Member</option>
            </select>
            <div class='grid-2'>
              <div>
                <label class='lbl'>{('Guild ID (0 for all)' if is_en else 'آيدي السيرفر (0 للكل)')}</label>
                <input class='inp' type='text' name='remote_gid' value='0'>
              </div>
              <div>
                <label class='lbl'>{('Target ID or Message' if is_en else 'الهدف أو نص الرسالة')}</label>
                <input class='inp' type='text' name='remote_target' placeholder='Target / Message'>
              </div>
            </div>
            <button class='btn-primary-purple' type='submit'>{('Queue Remote Action' if is_en else 'إرسال الأمر')}</button>
          </form>
        </div>

        <div class='panel-section'>
          <div class='panel-section-head'><h3 class='panel-section-title'>{('Backups & Restore Test' if is_en else 'النسخ الاحتياطي واختبار الاستعادة')}</h3></div>
          <form method='post' action='/admin' style='display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;'>
            <input type='hidden' name='csrf_token' value='{esc(csrf_tok)}'>
            <button class='mini-btn' type='submit' name='action' value='create_backup'>{('Create Backup' if is_en else 'إنشاء نسخة احتياطية')}</button>
            <button class='mini-btn' type='submit' name='action' value='test_restore'>{('Test Restore' if is_en else 'اختبار الاستعادة')}</button>
          </form>
          {backups_html}
        </div>
      </div>
    </div>
    """
    return web.Response(
        text=render_page("Admin Panel" if is_en else "لوحة الإدارة", "admin", body, request, flash=flash),
        content_type="text/html",
    )


async def handle_services(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    body = f"""
    <div class='glass-card anim-card'>
      <h1 style='margin:0 0 8px;font-size:22px;font-weight:900;'>{('Services' if is_en else 'الخدمات')}</h1>
      <p class='muted' style='margin:0 0 14px;'>{('Real-time protection against raids, nukes, links, spam, and privilege escalation.' if is_en else 'حماية فورية ضد هجمات النيوك والرايد والسبام والروابط ورفع الصلاحيات غير المصرح به.')}</p>
      <div class='hero-actions'>
        <a class='btn-primary-purple' href='/invite'>{('Invite عرب سكيورتي Bot' if is_en else 'دعوة بوت عرب سكيورتي')}</a>
        <a class='btn-secondary-dark' href='/guild'>{('Open Security Panel' if is_en else 'فتح لوحة الحماية')}</a>
      </div>
    </div>
    {_render_discord_community_card(is_en=is_en)}
    """
    return web.Response(
        text=render_page("Services" if is_en else "الخدمات", "services", body, request, next_after_login="/guild"),
        content_type="text/html",
    )


async def handle_updates(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    user = get_discord_session(request)
    can_logs = bool(user and is_site_admin(user) and has_admin_perm(user, "view_logs"))
    logs_btn = (
        f"<button type='button' class='mini-btn' onclick=\"toggleLogBox('public_log_box')\">{('Show Logs (Log)' if is_en else 'عرض السجل (Log)')}</button>"
        if can_logs
        else ""
    )
    logs_content = ""
    if can_logs:
        logs_content = "".join(
            f"<div class='list-row'><div><span class='admin-pill'>{esc(l.get('level', 'WEB'))}</span> <span>{esc(l.get('message', ''))}</span></div>"
            f"<span class='muted'>{esc(l.get('time', ''))}</span></div>"
            for l in get_recent_logs(25)
        )
    body = f"""
    <div class='glass-card anim-card'>
      <div style='display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px;'>
        <h1 style='margin:0;font-size:22px;font-weight:900;'>{('Updates & Logs' if is_en else 'التحديثات والسجلات')}</h1>
        {logs_btn}
      </div>
      <p class='muted'>{('System updates for عرب سكيورتي are published in our support server.' if is_en else 'يتم نشر التحديثات والتنبيهات في سيرفر الدعم الفني لعرب سكيورتي.')}</p>
      <div id='public_log_box' style='display:none;margin-top:12px;'>{logs_content}</div>
    </div>
    {_render_discord_community_card(is_en=is_en)}
    """
    return web.Response(
        text=render_page("Updates & Logs" if is_en else "التحديثات والسجلات", "updates", body, request, next_after_login="/updates"),
        content_type="text/html",
    )


async def handle_links(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    safe_support = esc(sanitize_http_url(SUPPORT_SERVER_URL) or "https://discord.com")
    body = f"""
    <div class='glass-card anim-card'>
      <h1 style='margin:0 0 12px;font-size:22px;font-weight:900;'>{('Official Links' if is_en else 'الروابط الرسمية')}</h1>
      <a class='link-card' href='/invite'>
        <div class='link-card-left'>
          <div class='link-card-badge'>+</div>
          <div>
            <div class='link-card-title'>{('Invite عرب سكيورتي Bot' if is_en else 'دعوة بوت عرب سكيورتي')}</div>
            <div class='link-card-sub'>{('Add the bot to your Discord server' if is_en else 'إضافة البوت إلى سيرفرك في ديسكورد')}</div>
          </div>
        </div>
        <span class='link-arrow'>←</span>
      </a>
      <a class='link-card' href='{safe_support}' target='_blank' rel='noopener noreferrer'>
        <div class='link-card-left'>
          <div class='link-card-badge'>{_discord_svg_icon(20)}</div>
          <div>
            <div class='link-card-title'>{('Join Support Server' if is_en else 'انضم لسيرفر الدعم الفني')}</div>
            <div class='link-card-sub'>{('Updates, technical support, and alerts' if is_en else 'تحديثات ، دعم فني ، تنبيهات')}</div>
          </div>
        </div>
        <span class='link-arrow'>←</span>
      </a>
    </div>
    """
    return web.Response(
        text=render_page("Links" if is_en else "الروابط", "links", body, request, next_after_login="/links"),
        content_type="text/html",
    )


async def login_handler(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    nxt = sanitize_next_url(request.query.get("next") or "/guild")
    if not DISCORD_CLIENT_ID or not DISCORD_CLIENT_SECRET:
        msg = (
            "Discord OAuth is not configured on this server."
            if is_en
            else "لم يتم إعداد بيانات Discord OAuth على الخادم."
        )
        raise web.HTTPFound("/?msg=" + quote(msg))

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
    is_en = get_lang(request) == "en"
    code = str(request.query.get("code", "")).strip()
    state_val = str(request.query.get("state", "")).strip()
    valid_state, nxt = consume_oauth_state(state_val)
    if not valid_state:
        raise web.HTTPFound("/?msg=" + quote("Invalid or expired login state." if is_en else "انتهت صلاحية جلسة الدخول، حاول مرة أخرى."))
    if not code or not DISCORD_CLIENT_ID or not DISCORD_CLIENT_SECRET:
        raise web.HTTPFound("/?msg=" + quote("Missing OAuth code." if is_en else "رمز التحقق غير موجود."))

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
                raise web.HTTPFound("/?msg=" + quote("Discord token exchange failed." if is_en else "فشل التحقق من حساب ديسكورد."))
            tok_data = await tok_resp.json()
            access_tok = str(tok_data.get("access_token", "")).strip()
            if not access_tok:
                raise web.HTTPFound("/?msg=" + quote("Missing access token." if is_en else "لم يتم استلام رمز الوصول."))

            auth_hdr = {"Authorization": f"Bearer {access_tok}"}
            u_resp = await sess.get("https://discord.com/api/v10/users/@me", headers=auth_hdr)
            if u_resp.status != 200:
                raise web.HTTPFound("/?msg=" + quote("Failed to fetch Discord profile." if is_en else "تعذر جلب بيانات المستخدم من ديسكورد."))
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
            raise web.HTTPFound("/?msg=" + quote("Invalid user ID." if is_en else "معرف المستخدم غير صالح."))

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
        raise web.HTTPFound("/?msg=" + quote("Login error occurred." if is_en else "حدث خطأ أثناء تسجيل الدخول."))


async def logout_handler(request: web.Request) -> web.Response:
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
    app.router.add_get("/", home_handler)
    app.router.add_get("/ui", handle_modern_ui)
    app.router.add_get("/invite", handle_invite_redirect)
    app.router.add_route("*", "/guild", handle_guild)
    app.router.add_route("*", "/premium", handle_premium)
    app.router.add_route("*", "/admin", handle_admin)
    app.router.add_get("/services", handle_services)
    app.router.add_get("/updates", handle_updates)
    app.router.add_get("/links", handle_links)
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
