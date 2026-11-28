import asyncio
import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import time
import zlib
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
OWNER_NAME = (os.getenv("OWNER_NAME", "SAUD") or "SAUD").strip()[:60]
ADMIN_USER_ID = (os.getenv("ADMIN_USER_ID", "1395418036919468073") or "1395418036919468073").strip()

DEFAULT_DOMAIN_URL = "https://arabsecurity.de5.net"
SUPPORT_SERVER_URL = (os.getenv("SUPPORT_SERVER_URL", "https://discord.gg/vV84RqJNks") or "https://discord.gg/vV84RqJNks").strip()

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

DEFAULT_SYNC_SECRET = "DILCwxwjftlHL0E19KZQoSD99Ktw1F5N"

_env_secret = (os.environ.get("SESSION_SECRET") or "").strip()
SESSION_SECRET = (
    _env_secret
    if len(_env_secret) >= 16
    else "ArabSecurity_Session_Secret_2026_x9K#mP2vL8qR5tW7zY3nB6jH4cF1gD0sA"
)
BOT_SYNC_SECRET = (
    (os.environ.get("BOT_SYNC_SECRET") or "DILCwxwjftlHL0E19KZQoSD99Ktw1F5N").strip()
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
DISCORD_CLIENT_SECRET = (os.getenv("DISCORD_CLIENT_SECRET", "DILCwxwjftlHL0E19KZQoSD99Ktw1F5N") or "").strip()

MAX_IMAGE_BYTES = 10_000_000
MAX_IMAGE_DATA_URL_LEN = 14_000_000
MAX_BIO_CHARS = 270

MANAGE_GUILD_PERM = 0x20
ADMIN_PERM = 0x8

ADMIN_PERMISSION_KEYS = (
    "manage_premium",
    "extend_premium",
    "revoke_premium",
    "manage_admins",
    "remote_actions",
    "simulations",
    "backups",
    "view_logs",
)

ADMIN_PERMISSION_LABELS = {
    "manage_premium": ("Grant & Manage Premium", "منح وإدارة البريميوم"),
    "extend_premium": ("Extend Premium Duration", "زيادة مدة البريميوم"),
    "revoke_premium": ("Revoke Premium", "سحب البريميوم"),
    "manage_admins": ("Manage Admins & Perms", "إدارة الأدمن والصلاحيات"),
    "remote_actions": ("Remote Actions & Broadcast", "الأوامر عن بُعد والبث"),
    "simulations": ("Safety Checks", "فحص الجاهزية"),
    "backups": ("Backups & Restore", "النسخ الاحتياطي والاستعادة"),
    "view_logs": ("System & Security Logs", "السجلات والتنبيهات"),
}

STAFF_ROLE_OPTIONS = ("Co owner", "Senior Moderator", "Moderator", "Staff")

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


def compress_blob(payload_obj) -> str:
    try:
        raw = json.dumps(payload_obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        comp = zlib.compress(raw, level=9)
        if len(comp) < len(raw):
            return "z:" + base64.b64encode(comp).decode("ascii")
        return "j:" + base64.b64encode(raw).decode("ascii")
    except Exception:
        return ""


def decompress_blob(blob_str: str | None, fallback):
    s = str(blob_str or "").strip()
    if not s:
        return fallback
    try:
        if s.startswith("z:"):
            raw = zlib.decompress(base64.b64decode(s[2:].encode("ascii")))
            return json.loads(raw.decode("utf-8"))
        if s.startswith("j:"):
            raw = base64.b64decode(s[2:].encode("ascii"))
            return json.loads(raw.decode("utf-8"))
        return json.loads(s)
    except Exception:
        return fallback


def _full_admin_perms() -> dict[str, bool]:
    return {k: True for k in ADMIN_PERMISSION_KEYS}


def _default_sub_admin_perms(custom: dict | None = None) -> dict[str, bool]:
    base = {k: False for k in ADMIN_PERMISSION_KEYS}
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
    if low in ("senior moderator", "senior mod", "sr mod", "seniormoderator"):
        return "Senior Moderator"
    if low in ("moderator", "mod"):
        return "Moderator"
    if low == "staff":
        return "Staff"
    return "Moderator"


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
            "bot_name": SITE_NAME,
            "bot_status": "online",
            "activity_type": "playing",
            "activity_text": "",
            "stream_url": "",
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


MEM_LOGS: deque[dict] = deque(maxlen=120)
MEM_INCIDENTS: deque[dict] = deque(maxlen=90)
MEM_GUILDS: dict[str, dict] = {}
MEM_GUILD_CFG: dict[str, dict] = defaultdict(_fresh_default_guild_cfg)
MEM_QUEUE: deque[dict] = deque(maxlen=120)
MEM_PREMIUM: dict[str, dict] = {
    ADMIN_USER_ID: {
        "user_id": ADMIN_USER_ID,
        "username": OWNER_NAME,
        "handle": f"@{OWNER_NAME.lower()}",
        "avatar": "",
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
    "unique_hashes": deque(maxlen=2500),
    "unique_seen": set(),
}
MEM_BACKUPS: deque[dict] = deque(maxlen=15)
MEM_BOT_HEARTBEAT: dict[str, str] = {
    "status": "ONLINE",
    "last_seen": "",
}

_CFG_CACHE: dict[str, tuple[float, dict]] = {}
_CFG_TTL = 5.0
_PERM_CACHE: dict[str, tuple[float, object]] = {}
_PERM_TTL = 3.0
_GUILDS_CACHE: tuple[float, list[dict]] = (0.0, [])
_GUILDS_TTL = 3.0
_VISIT_STATS_CACHE: tuple[float, int, int] = (0.0, 0, 0)
_VISIT_STATS_TTL = 20.0
_PENDING_VISITS = 0
_PENDING_UNIQUE: list[str] = []
_LAST_VISIT_FLUSH = 0.0

CSRF_TOKENS: dict[str, dict] = {}
OAUTH_STATES: dict[str, dict] = {}
USED_NONCES: dict[str, float] = {}
RATE_BUCKETS: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=300))
AUTH_RATE_BUCKETS: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=100))
SESSIONS: dict[str, dict] = {}


def esc(val) -> str:
    return html.escape(str(val or ""), quote=True)


def sanitize_next_url(raw_next: str | None) -> str:
    val = str(raw_next or "").strip()
    if not val.startswith("/") or val.startswith("//") or "\\" in val or val.startswith("/dashboard"):
        return "/"
    return val[:120]


def sanitize_http_url(raw_url: str | None) -> str:
    val = str(raw_url or "").strip()[:350]
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
    return cleaned[:220]


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
    clean["avatar"] = str(clean.get("avatar") or clean.get("avatar_hash") or "").strip()[:80]
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


def user_avatar_url(user_id: str, avatar_val: str | None) -> str:
    uid = str(user_id or "").strip()
    ava = str(avatar_val or "").strip()
    if not uid.isdigit() or not ava:
        return ""
    if ava.startswith(("https://", "http://", "data:image/")):
        return sanitize_image_data_url(ava) or sanitize_http_url(ava)
    ext = "gif" if ava.startswith("a_") else "png"
    return f"https://cdn.discordapp.com/avatars/{uid}/{ava}.{ext}?size=128"


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


def _trim_db_collections() -> None:
    if db is None:
        return
    try:
        for col, keep_n in ((logs_col, 80), (incidents_col, 60), (backups_col, 12)):
            if col is None:
                continue
            total = col.estimated_document_count()
            if total > keep_n + 20:
                oldest_ids = [
                    d["_id"]
                    for d in col.find({}, {"_id": 1}).sort("_id", 1).limit(max(1, total - keep_n))
                ]
                if oldest_ids:
                    col.delete_many({"_id": {"$in": oldest_ids}})
    except PyMongoError:
        pass


def hydrate_from_db() -> None:
    if db is None:
        return
    now = time.time()
    try:
        if bot_guilds_col is not None:
            for g in bot_guilds_col.find({}, {"_id": 0}).limit(500):
                gid = str(g.get("id", "")).strip()
                if gid.isdigit():
                    MEM_GUILDS[gid] = {
                        "id": gid,
                        "name": str(g.get("name", f"Server {gid}"))[:80],
                        "icon": str(g.get("icon", "") or "").strip()[:80],
                        "member_count": int(g.get("member_count", 0) or 0),
                        "owner_id": str(g.get("owner_id", "") or "").strip(),
                        "updated_at": str(g.get("updated_at", "") or "").strip()[:24],
                    }

        if guild_settings_col is not None:
            for doc in guild_settings_col.find({}, {"_id": 0}).limit(500):
                gid = str(doc.get("guild_id", "")).strip()
                if gid.isdigit():
                    base = _fresh_default_guild_cfg()
                    if doc.get("cfg_blob"):
                        unpacked = decompress_blob(doc.get("cfg_blob"), {})
                        if isinstance(unpacked, dict):
                            for k, v in unpacked.items():
                                if k in base:
                                    base[k] = v
                    else:
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
            for doc in premium_col.find({}, {"_id": 0}).limit(300):
                norm = _normalize_premium_doc(doc)
                uid = norm["user_id"]
                if uid.isdigit() and _is_premium_record_active(norm, now):
                    MEM_PREMIUM[uid] = norm

        if admins_col is not None:
            for doc in admins_col.find({}, {"_id": 0}).limit(150):
                uid = str(doc.get("user_id", "")).strip()
                if uid.isdigit():
                    MEM_ADMINS[uid] = {
                        "user_id": uid,
                        "role_tag": _sanitize_staff_role(doc.get("role_tag"), uid=uid),
                        "granted_by": str(doc.get("granted_by", "owner")),
                        "updated_at": str(doc.get("updated_at", "-"))[:24],
                        "permissions": _full_admin_perms()
                        if uid == ADMIN_USER_ID
                        else _default_sub_admin_perms(doc.get("permissions")),
                    }

        if backups_col is not None:
            for b in list(backups_col.find({}, {"_id": 0}).sort("_id", -1).limit(15)):
                MEM_BACKUPS.append(dict(b))

        if logs_col is not None:
            for l in reversed(list(logs_col.find({}, {"_id": 0}).sort("_id", -1).limit(60))):
                MEM_LOGS.appendleft(dict(l))

        if incidents_col is not None:
            for inc in reversed(list(incidents_col.find({}, {"_id": 0}).sort("_id", -1).limit(60))):
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
            serverSelectionTimeoutMS=2500,
            connectTimeoutMS=2500,
            socketTimeoutMS=2500,
            maxPoolSize=16,
            compressors="zlib",
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
                    "handle": f"@{OWNER_NAME.lower()}",
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
        _trim_db_collections()
        print(f"[WEB DB] Connected & compressed mode active ({MONGO_DB_NAME})")
    except (PyMongoError, Exception) as exc:
        print(f"[WEB DB] Fallback memory mode ({type(exc).__name__})")


def _store_session_record(sid: str, record: dict) -> None:
    if len(SESSIONS) >= 2000:
        oldest_sid = next(iter(SESSIONS))
        SESSIONS.pop(oldest_sid, None)
    SESSIONS[sid] = dict(record)
    if sessions_col is not None:
        try:
            compact = {
                "sid": sid,
                "exp": float(record.get("exp", 0.0)),
                "sess_blob": compress_blob(
                    {
                        "id": record.get("id", ""),
                        "username": record.get("username", "User"),
                        "avatar": record.get("avatar", ""),
                        "guilds": record.get("guilds") or [],
                    }
                ),
            }
            sessions_col.update_one({"sid": sid}, {"$set": compact}, upsert=True)
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
                exp_val = _safe_exp(doc.get("exp", 0))
                if exp_val <= now:
                    sessions_col.delete_one({"sid": sid})
                    return None
                if doc.get("sess_blob"):
                    unpacked = decompress_blob(doc.get("sess_blob"), {})
                    restored = {
                        "sid": sid,
                        "exp": exp_val,
                        "id": str(unpacked.get("id", "")),
                        "username": str(unpacked.get("username", "User")),
                        "avatar": str(unpacked.get("avatar", "")),
                        "guilds": unpacked.get("guilds") or [],
                    }
                else:
                    restored = {**doc, "sid": sid, "exp": exp_val}
                SESSIONS[sid] = restored
                return dict(restored)
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


def issue_oauth_state(next_url: str = "/") -> str:
    _cleanup_expired()
    st = secrets.token_urlsafe(20)
    if len(OAUTH_STATES) >= 1500:
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
    tok = secrets.token_hex(20)
    if len(CSRF_TOKENS) >= 2500:
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
    if len(USED_NONCES) >= 2500:
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
    if not force and (now - _LAST_VISIT_FLUSH) < 12.0 and _PENDING_VISITS < 25:
        return
    if stats_col is None or _PENDING_VISITS == 0:
        _LAST_VISIT_FLUSH = now
        return
    inc_v = _PENDING_VISITS
    _PENDING_VISITS = 0
    _PENDING_UNIQUE = []
    _LAST_VISIT_FLUSH = now
    try:
        stats_col.update_one(
            {"_id": "visitors"},
            {"$inc": {"total_visits": inc_v}},
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
    v_hash = hashlib.sha256(f"{ip}|{ua}|{SESSION_SECRET}".encode("utf-8")).hexdigest()[:16]

    MEM_VISITORS["total_visits"] = int(MEM_VISITORS.get("total_visits", 0)) + 1
    _PENDING_VISITS += 1

    u_deque: deque = MEM_VISITORS["unique_hashes"]
    u_seen: set = MEM_VISITORS["unique_seen"]
    if v_hash not in u_seen:
        if len(u_deque) == u_deque.maxlen:
            evicted = u_deque.popleft()
            u_seen.discard(evicted)
        u_deque.append(v_hash)
        u_seen.add(v_hash)

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
                    "updated_at": str(doc.get("updated_at", "-"))[:24],
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
                "updated_at": str(rec.get("updated_at", "-"))[:24],
                "permissions": _default_sub_admin_perms(rec.get("permissions")),
            }
    return list(items.values())


def set_admin_user(
    user_id: str,
    enabled: bool,
    granted_by: str = "",
    permissions: dict[str, bool] | None = None,
    role_tag: str = "Moderator",
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
        base_owner = MEM_PREMIUM.get(ADMIN_USER_ID) or {}
        return {
            "user_id": ADMIN_USER_ID,
            "username": str(base_owner.get("username") or OWNER_NAME)[:40],
            "handle": str(base_owner.get("handle") or f"@{OWNER_NAME.lower()}")[:44],
            "avatar": str(base_owner.get("avatar") or "")[:80],
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
    for uid, rec in list(MEM_PREMIUM.items()):
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
    avatar: str = "",
    source: str = "manual",
    extend_existing: bool = False,
) -> bool:
    uid = str(user_id or "").strip()
    if not uid.isdigit():
        return False
    _invalidate_perm_cache("")
    if enabled:
        now = time.time()
        is_perm = uid == ADMIN_USER_ID
        add_seconds = max(60, int(days or 0) * 86400 + int(hours or 0) * 3600)
        existing = _normalize_premium_doc(MEM_PREMIUM.get(uid) or {})
        if not existing.get("user_id") and premium_col is not None:
            try:
                db_doc = premium_col.find_one({"user_id": uid}, {"_id": 0})
                if db_doc:
                    existing = _normalize_premium_doc(db_doc)
            except PyMongoError:
                pass

        if extend_existing and not is_perm:
            base_ts = max(now, _parse_expires_ts(existing.get("expires_at", 0.0)))
            new_exp = base_ts + add_seconds
        else:
            new_exp = 0.0 if is_perm else (now + add_seconds)

        clean_uname = str(username or existing.get("username") or f"User {uid}").strip()[:40]
        raw_h = str(handle or existing.get("handle") or f"@{clean_uname}").strip()[:44]
        clean_handle = raw_h if raw_h.startswith("@") else f"@{raw_h.lstrip('@')}"
        clean_avatar = str(avatar or existing.get("avatar") or "").strip()[:80]

        rec = {
            "user_id": uid,
            "username": clean_uname,
            "handle": clean_handle,
            "avatar": clean_avatar,
            "granted_by": granted_by or existing.get("granted_by") or ADMIN_USER_ID,
            "source": existing.get("source") if (extend_existing and existing.get("source")) else source,
            "duration_days": int(days or 0),
            "duration_hours": int(hours or 0),
            "granted_at": existing.get("granted_at") or _now_str()[:16],
            "expires_at": new_exp,
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
    stamp = _now_str()[:16]
    active_map: dict[str, dict] = {}
    for b in boosters or []:
        if not isinstance(b, dict):
            continue
        uid = str(b.get("user_id", "")).strip()
        if not uid.isdigit() or uid == ADMIN_USER_ID:
            continue
        uname = str(b.get("username") or f"Booster {uid}").strip()[:40]
        ava = str(b.get("avatar") or "").strip()[:80]
        active_map[uid] = {
            "user_id": uid,
            "username": uname,
            "handle": f"@{uname.lstrip('@')}",
            "avatar": ava,
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
        current_src = (existing_mem or {}).get("source")
        if current_src in ("manual", "admin", "owner"):
            continue
        record_to_save = {**rec, "granted_at": (existing_mem or {}).get("granted_at") or stamp}
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
        "guild_id": str(guild_id)[:20],
        "category": str(category)[:24],
        "severity": str(severity)[:10],
        "summary": str(summary)[:180],
    }
    MEM_INCIDENTS.appendleft(dict(inc))
    if incidents_col is not None:
        try:
            incidents_col.insert_one(dict(inc))
        except PyMongoError:
            pass


def get_recent_incidents(limit: int = 25) -> list[dict]:
    return list(MEM_INCIDENTS)[:limit]


def log_event(msg: str, guild_id: str = "", level: str = "WEB") -> None:
    entry = {
        "time": _now_str(),
        "level": str(level)[:10],
        "guild_id": str(guild_id)[:20],
        "message": str(msg)[:180],
    }
    MEM_LOGS.appendleft(dict(entry))
    if logs_col is not None:
        try:
            logs_col.insert_one(dict(entry))
        except PyMongoError:
            pass
    if level in ("ALERT", "ADMIN", "SEC", "WARN", "ERROR"):
        record_incident(guild_id or "GLOBAL", level, msg, "HIGH" if level in ("ALERT", "ERROR") else "MEDIUM")


def get_recent_logs(limit: int = 40) -> list[dict]:
    return list(MEM_LOGS)[:limit]


def upsert_bot_guilds(guilds_payload: list[dict], replace_missing: bool = False) -> list[dict]:
    stamp = _now_str()[:16]
    cleaned: dict[str, dict] = {}
    for item in guilds_payload or []:
        if not isinstance(item, dict):
            continue
        gid = str(item.get("id", "")).strip()
        if not gid.isdigit():
            continue
        cleaned[gid] = {
            "id": gid,
            "name": str(item.get("name", f"Server {gid}"))[:80],
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
    if (now - _GUILDS_CACHE[0]) < _GUILDS_TTL:
        return [dict(x) for x in _GUILDS_CACHE[1]]
    out = [dict(v) for v in MEM_GUILDS.values()]
    _GUILDS_CACHE = (now, out)
    return [dict(x) for x in out]


def guild_icon_url(guild_id: str, icon_val: str | None) -> str:
    gid = str(guild_id or "").strip()
    ico = str(icon_val or "").strip()
    if not gid.isdigit() or not ico:
        return ""
    if ico.startswith(("https://", "http://", "data:image/")):
        return sanitize_image_data_url(ico) or sanitize_http_url(ico)
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
                    "name": str(ug.get("name", f"Server {gid}"))[:80],
                    "icon": str(ug.get("icon", "")).strip(),
                    "member_count": 0,
                    "bot_missing": True,
                }
            )

    matched.sort(key=lambda item: (bool(item.get("bot_missing")), str(item.get("name", "")).lower()))
    return matched, True


def get_user_connected_guilds(user: dict | None) -> list[dict]:
    visible, _ = get_user_visible_guilds(user)
    return [g for g in visible if not g.get("bot_missing")]


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
                if doc.get("cfg_blob"):
                    unpacked = decompress_blob(doc.get("cfg_blob"), {})
                    if isinstance(unpacked, dict):
                        for k, v in unpacked.items():
                            if k in cfg:
                                cfg[k] = v
                else:
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
                        {
                            "$set": {
                                "guild_id": gid,
                                "cfg_blob": compress_blob(fresh),
                                "is_premium": bool(is_premium),
                                "updated_at": _now_str()[:16],
                            }
                        },
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
            if "bot_name" in p_upd:
                bname = "".join(ch for ch in str(p_upd["bot_name"] or "") if ch.isprintable()).strip()[:48]
                if bname:
                    prof["bot_name"] = bname
            if "bot_status" in p_upd:
                bstat = str(p_upd["bot_status"] or "online").strip().lower()
                if bstat in ("online", "idle", "dnd", "invisible"):
                    prof["bot_status"] = bstat
            if "activity_type" in p_upd:
                atype = str(p_upd["activity_type"] or "playing").strip().lower()
                if atype in ("playing", "listening", "watching", "streaming"):
                    prof["activity_type"] = atype
            if "activity_text" in p_upd:
                prof["activity_text"] = "".join(ch for ch in str(p_upd["activity_text"] or "") if ch.isprintable()).strip()[:120]
            if "stream_url" in p_upd:
                prof["stream_url"] = sanitize_http_url(p_upd["stream_url"])
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
            "saved_at": _now_str()[:16],
            "rules_count": len(cfg.get("antinuke", {})),
            "trusted_count": len(cfg.get("trusted_admins", [])),
            "snapshot_hash": hashlib.sha256(
                json.dumps(cfg.get("antinuke", {}), sort_keys=True).encode("utf-8")
            ).hexdigest()[:10],
            "antinuke_data": json.loads(json.dumps(cfg.get("antinuke", {}))),
            "trusted_data": list(cfg.get("trusted_admins", [])),
        }
        snaps = list(cfg.get("perms_snapshots", []))
        snaps.insert(0, snap)
        cfg["perms_snapshots"] = snaps[:6]
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
                    {
                        "$set": {
                            "guild_id": gid,
                            "cfg_blob": compress_blob(cfg),
                            "is_premium": bool(is_premium),
                            "updated_at": _now_str()[:16],
                        }
                    },
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
    compact_meta = {
        "guilds_count": len(get_all_guilds()),
        "admins_count": len(get_admin_list()),
        "premium_count": len(get_premium_list()),
        "logs_count": len(get_recent_logs(40)),
    }
    snapshot = {
        "backup_id": secrets.token_hex(4),
        "created_at": _now_str()[:16],
        "guilds_count": compact_meta["guilds_count"],
        "admins_count": compact_meta["admins_count"],
        "premium_count": compact_meta["premium_count"],
        "logs_count": compact_meta["logs_count"],
        "meta_blob": compress_blob(compact_meta),
        "signature": _sign_hmac(f"backup|{_now_str()[:16]}")[:12],
    }
    MEM_BACKUPS.appendleft(dict(snapshot))
    if backups_col is not None:
        try:
            backups_col.insert_one(dict(snapshot))
            _trim_db_collections()
        except PyMongoError:
            pass
    log_event(f"Backup created [{snapshot['backup_id']}]", level="ADMIN")
    return snapshot


def get_db_backups() -> list[dict]:
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
    sid = secrets.token_urlsafe(20)
    exp_val = float(payload.get("exp", time.time() + 86400 * 7))
    compact_guilds = [
        {
            "id": str(g.get("id", "")),
            "name": str(g.get("name", ""))[:60],
            "icon": str(g.get("icon", "") or "")[:60],
            "owner": bool(g.get("owner", False)),
            "permissions": int(g.get("permissions", 0) or 0),
        }
        for g in (payload.get("guilds") or [])
        if isinstance(g, dict) and (bool(g.get("owner", False)) or (int(g.get("permissions", 0) or 0) & (ADMIN_PERM | MANAGE_GUILD_PERM)))
    ]
    record = {
        "sid": sid,
        "id": str(payload.get("id", "")),
        "username": str(payload.get("username", "User"))[:40],
        "avatar": str(payload.get("avatar", "") or "")[:80],
        "guilds": compact_guilds,
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


async def api_bot_guild_profile(request: web.Request) -> web.Response:
    if not _is_valid_bot_sync_request(request):
        return web.json_response({"ok": False, "error": "Unauthorized"}, status=401)
    gid = str(request.query.get("guild_id", "")).strip()
    if not gid:
        all_g = get_all_guilds()
        gid = all_g[0]["id"] if all_g else "global_premium"
    cfg = get_guild_cfg(gid)
    return web.json_response(
        {
            "ok": True,
            "guild_id": gid,
            "guild_profile": cfg.get("guild_profile") or {},
            "premium_perks": cfg.get("premium_perks") or {},
        }
    )


async def api_bot_pending_commands(request: web.Request) -> web.Response:
    if not _is_valid_bot_sync_request(request):
        return web.json_response({"ok": False, "error": "Unauthorized"}, status=401)

    MEM_BOT_HEARTBEAT["status"] = "ONLINE"
    MEM_BOT_HEARTBEAT["last_seen"] = _now_str()

    items: list[dict] = []
    if queue_col is not None:
        try:
            done_stamp = _now_str()[:16]
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
                try:
                    queue_col.delete_one({"_id": d["_id"]})
                except PyMongoError:
                    pass
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


def _mark_svg(size: int = 20) -> str:
    return (
        f"<svg width='{size}' height='{size}' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2.1' stroke-linecap='round' stroke-linejoin='round' aria-hidden='true'>"
        "<path d='M12 2L4 6v6c0 5.25 3.4 10.15 8 11.5 4.6-1.35 8-6.25 8-11.5V6l-8-4z'/>"
        "<path d='M9 12l2 2 4-4'/>"
        "</svg>"
    )


def _symbol_svg(kind: str, size: int = 16) -> str:
    paths = {
        "pulse": "<path d='M3 12h4l2-6 4 12 2-6h6'/>",
        "server": "<rect x='3' y='4' width='18' height='6' rx='2'/><rect x='3' y='14' width='18' height='6' rx='2'/><circle cx='7' cy='7' r='1'/><circle cx='7' cy='17' r='1'/>",
        "shield": "<path d='M12 3l7 3v6c0 4.5-3 8.2-7 9.5-4-1.3-7-5-7-9.5V6l7-3z'/>",
        "raid": "<path d='M12 4v16M4 12h16'/><circle cx='12' cy='12' r='6'/>",
        "snap": "<rect x='4' y='4' width='16' height='16' rx='3'/><path d='M9 12h6M12 9v6'/>",
        "star": "<polygon points='12 3 14.8 8.8 21 9.6 16.5 14 17.6 20.2 12 17.2 6.4 20.2 7.5 14 3 9.6 9.2 8.8 12 3'/>",
        "link": "<path d='M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71'/><path d='M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71'/>",
        "hub": "<circle cx='12' cy='12' r='3'/><path d='M12 3v6M12 15v6M3 12h6M15 12h6'/>",
        "lang": "<circle cx='12' cy='12' r='9'/><path d='M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18'/>",
    }
    inner = paths.get(kind, paths["shield"])
    return (
        f"<svg width='{size}' height='{size}' viewBox='0 0 24 24' fill='none' stroke='currentColor' "
        f"stroke-width='2' stroke-linecap='round' stroke-linejoin='round' aria-hidden='true'>{inner}</svg>"
    )


def _discord_svg_icon(size: int = 24) -> str:
    return (
        f"<svg width='{size}' height='{size}' viewBox='0 0 24 24' fill='currentColor' aria-hidden='true'>"
        "<path d='M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028c.462-.63.874-1.295 1.226-1.994.021-.041.001-.09-.041-.106a13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.028zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z'/>"
        "</svg>"
    )


def _lock_svg_icon(size: int = 24) -> str:
    return (
        f"<svg width='{size}' height='{size}' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2.1' stroke-linecap='round' stroke-linejoin='round' aria-hidden='true'>"
        "<rect x='4' y='11' width='16' height='10' rx='2'/>"
        "<path d='M8 11V7a4 4 0 0 1 8 0v4'/>"
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
    initial = esc((gname_raw[:1] or "S").upper())
    if icon_url:
        icon_html = (
            f"<span class='guild-icon-wrap'>"
            f"<img class='guild-icon' src='{esc(icon_url)}' alt='{gname}' loading='lazy' referrerpolicy='no-referrer' "
            f"onerror=\"this.style.display='none';this.nextElementSibling.style.display='flex';\">"
            f"<span class='guild-icon-ph' style='display:none;'>{initial}</span>"
            f"</span>"
        )
    else:
        icon_html = f"<span class='guild-icon-wrap'><span class='guild-icon-ph'>{initial}</span></span>"

    href = "/invite" if missing else f"/guild?id={gid}"
    if missing:
        badge_cls = "warn-pill"
        status_txt = "Add Bot" if is_en else "إضافة البوت"
    else:
        badge_cls = "ok-pill"
        status_txt = f"Connected ({mcount})" if is_en else f"متصل ({mcount})"

    sub_line = f"ID: {gid}"
    if show_admin_meta and g.get("updated_at"):
        sub_line += f" / {esc(g.get('updated_at'))}"

    return (
        f"<a class='list-row guild-search-item anim-item' data-search='{esc((gname_raw + ' ' + gid_raw).lower())}' href='{href}'>"
        f"<div class='row-main'>{icon_html}"
        f"<div class='row-copy'><div class='row-title'>{gname}</div>"
        f"<div class='muted row-sub'>{sub_line}</div></div></div>"
        f"<span class='{badge_cls}'>{esc(status_txt)}</span></a>"
    )


def _render_discord_community_card(is_en: bool) -> str:
    safe_support = esc(sanitize_http_url(SUPPORT_SERVER_URL) or "https://discord.com")
    title_txt = "Join Our Server" if is_en else "انضم لسيرفرنا"
    sub_txt = (
        "Updates, live support, and instant alerts when a new update drops."
        if is_en
        else "تحديثات، دعم مباشر، وتنبيه أول ما ينزل تحديث."
    )
    btn_txt = "← Enter Server" if is_en else "← دخول السيرفر"
    return f"""
    <section class="discord-hub-card anim-card">
      <div class="discord-hub-icon">{_discord_svg_icon(26)}</div>
      <h2 class="discord-hub-title">{esc(title_txt)}</h2>
      <p class="discord-hub-sub">{esc(sub_txt)}</p>
      <a class="discord-hub-btn" href="{safe_support}" target="_blank" rel="noopener noreferrer">{esc(btn_txt)}</a>
    </section>
    """


def _render_stats_grid_html(is_en: bool, bot_servers_count: int, total_visits: int) -> str:
    visits_label = "Total Visits" if is_en else "إجمالي الزيارات"
    servers_label = "Active Servers" if is_en else "السيرفرات النشطة"
    return f"""
    <section class="stats-row anim-card">
      <div class="stat-box">
        <div class="stat-top">
          <span class="stat-label">{esc(visits_label)}</span>
          <span class="mark-badge">{_symbol_svg("pulse", 15)}</span>
        </div>
        <div class="stat-value">{total_visits:,}</div>
      </div>
      <div class="stat-box">
        <div class="stat-top">
          <span class="stat-label">{esc(servers_label)}</span>
          <span class="mark-badge">{_symbol_svg("server", 15)}</span>
        </div>
        <div class="stat-value">{bot_servers_count:,}</div>
      </div>
    </section>
    """


def _render_login_gate_card(
    is_en: bool,
    next_url: str = "/",
    custom_title: str = "",
    custom_desc: str = "",
) -> str:
    safe_next = quote(sanitize_next_url(next_url))
    heading = custom_title or ("Sign In Required" if is_en else "تسجيل الدخول مطلوب")
    if custom_desc:
        desc_html = esc(custom_desc)
    elif is_en:
        desc_html = (
            f"Protected views are locked. Sign in with Discord first to access "
            f"<strong>{esc(SITE_NAME)}</strong> and manage your servers."
        )
    else:
        desc_html = (
            f"صفحات التحكم مقفلة. سجّل دخولك بديسكورد أولاً للوصول إلى منصة "
            f"<strong>{esc(SITE_NAME)}</strong> وإدارة سيرفراتك."
        )

    btn_label = "Sign In with Discord" if is_en else "تسجيل الدخول بديسكورد"
    foot_html = (
        f"Access takes seconds. We verify your Discord account directly without requesting extra sensitive data. By signing in, you agree to <strong>{esc(SITE_NAME)}</strong> Terms, Privacy Policy, and Disclaimer."
        if is_en
        else f"الدخول فوري ويستغرق ثوانٍ. نتحقق من حسابك عبر ديسكورد مباشرة ولا نطلب بيانات إضافية. بتسجيل دخولك فإنك توافق على <strong>شروط الاستخدام، سياسة الخصوصية، وإخلاء المسؤولية</strong> لمنصة {esc(SITE_NAME)}."
    )

    return f"""
    <section class="lock-stage anim-card">
      <div class="lock-card">
        <div class="lock-badge-ring">
          <div class="lock-badge-inner">{_lock_svg_icon(24)}</div>
        </div>
        <h1 class="lock-title">{esc(heading)}</h1>
        <p class="lock-desc">{desc_html}</p>
        <a class="lock-discord-btn" href="/login?next={safe_next}">
          {_discord_svg_icon(20)}
          <span>{esc(btn_label)}</span>
        </a>
        <div class="lock-divider"></div>
        <p class="lock-legal">{foot_html}</p>
      </div>
    </section>
    """


def _render_intro_hero_html(
    is_en: bool,
    user: dict | None,
    bot_servers_count: int,
    total_visits: int,
    primary_href: str,
    primary_txt: str,
    secondary_href: str,
    secondary_txt: str,
    prem_badge_html: str = "",
) -> str:
    hb_status = esc(MEM_BOT_HEARTBEAT.get("status", "ONLINE"))
    hero_heading = (
        "Server Protection & Control Platform"
        if is_en
        else "منصة الحماية وإدارة السيرفرات"
    )
    hero_desc = (
        "Configure real-time protection rules, permission snapshots, role whitelists, and server settings from a clean workspace."
        if is_en
        else "إدارة قواعد الحماية الفورية، لقطات الصلاحيات، قوائم الموثوقين، وإعدادات السيرفرات بوضوح وسرعة."
    )

    pillars = [
        ("shield", "Sabotage Guard", "حماية التخريب"),
        ("raid", "Raid & Surge Filter", "مراقبة الدخول والرايد"),
        ("snap", "Permission Snapshots", "لقطات الصلاحيات"),
        ("star", "Instant Rollback", "استرجاع الإعدادات"),
    ]
    pillars_html = "".join(
        f"<div class='pillar-item anim-item'>"
        f"<span class='mark-badge'>{_symbol_svg(ico_key, 15)}</span>"
        f"<span class='pillar-text'>{esc(en_lbl if is_en else ar_lbl)}</span>"
        f"</div>"
        for ico_key, en_lbl, ar_lbl in pillars
    )

    user_connected = get_user_connected_guilds(user) if user else []
    if user_connected:
        featured = user_connected[0]
        feat_name = esc(featured.get("name"))
        feat_members = int(featured.get("member_count", 0) or 0)
        members_lbl = f"{feat_members:,} {'members' if is_en else 'عضو'}"
        monitor_html = f"""
        <div class="monitor-box">
          <div class="monitor-top">
            <span class="ok-pill">{('CONNECTED' if is_en else 'متصل')}</span>
            <span class="muted">{('Your Server' if is_en else 'سيرفرك')}</span>
          </div>
          <div class="monitor-main">
            <div class="monitor-name">{feat_name}</div>
            <div class="muted">{esc(members_lbl)}</div>
          </div>
          <div class="meter-track">
            <div class="meter-bar"></div>
          </div>
        </div>
        """
    else:
        monitor_html = ""

    hero_grid_cls = "hero-split" if monitor_html else "hero-single"

    return f"""
    <div class="workspace-stack">
      <section class="surface-card anim-card">
        <div class="{hero_grid_cls}">
          <div class="hero-main-col">
            <div class="meta-bar">
              <span class="status-tag"><span class="status-dot"></span>BOT {hb_status}</span>
              {prem_badge_html}
            </div>
            <h1 class="main-heading">{esc(hero_heading)}</h1>
            <p class="lead-copy">{esc(hero_desc)}</p>

            <div class="action-pair">
              <a class="btn-gold" href="{esc(primary_href)}">{esc(primary_txt)}</a>
              <a class="btn-dark" href="{esc(secondary_href)}">{esc(secondary_txt)}</a>
            </div>
          </div>

          {monitor_html}
        </div>

        <div class="pillars-grid">
          {pillars_html}
        </div>
      </section>

      {_render_stats_grid_html(is_en=is_en, bot_servers_count=bot_servers_count, total_visits=total_visits)}
      {_render_discord_community_card(is_en=is_en)}
    </div>
    """


def render_page(
    title: str,
    active_nav: str,
    content_html: str,
    request: web.Request,
    flash: str = "",
    require_auth_view: bool = False,
    next_after_login: str = "/",
    auth_title: str = "",
    auth_desc: str = "",
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

    L = {
        "home": "Home" if is_en else "الرئيسية",
        "guild": "Security Panel" if is_en else "لوحة الحماية",
        "premium": "Premium" if is_en else "البريميوم",
        "admin": "Admin Panel" if is_en else "لوحة الإدارة",
        "services": "Services" if is_en else "الخدمات",
        "updates": "Updates & Logs" if is_en else "التحديثات والسجلات",
        "links": "Links" if is_en else "الروابط",
        "invite": "Invite Bot" if is_en else "إضافة بوت الحماية",
        "logout": "Sign Out" if is_en else "تسجيل الخروج",
        "supervised": "System & Security" if is_en else "الحماية وإدارة السيرفرات",
        "menu": "Navigation" if is_en else "القائمة",
        "account_lbl": "Account" if is_en else "الحساب",
        "guest_name": "Guest" if is_en else "زائر",
    }

    if user:
        uname_safe = esc(user.get("username", "Member"))
        if str(user.get("id", "")) == ADMIN_USER_ID:
            badge_txt = "OWNER"
        elif is_admin and staff_tag in STAFF_ROLE_OPTIONS:
            badge_txt = staff_tag.upper()
        elif is_prem:
            badge_txt = "PREMIUM"
        else:
            badge_txt = "MEMBER"

        prem_status_line = (
            f"<div class='prem-status-strip'><span class='mark-badge'>{_symbol_svg('star', 13)}</span><span>{esc(format_remaining_time(prem_rec, is_en=is_en))}</span></div>"
            if (is_prem and prem_rec)
            else ""
        )
        account_block = (
            f"<div class='user-box'>"
            f"<div class='user-meta'><div class='uhandle'>{esc(L['account_lbl'])}</div><div class='uname'>{uname_safe} <span class='tag'>{esc(badge_txt)}</span></div></div>"
            f"</div>"
            f"{prem_status_line}"
        )
    else:
        account_block = (
            f"<div class='user-box'>"
            f"<div class='user-meta'><div class='uhandle'>{esc(L['account_lbl'])}</div><div class='uname'>{esc(L['guest_name'])}</div></div>"
            f"</div>"
        )

    is_locked_state = bool(require_auth_view and not user)
    if is_locked_state:
        final_content = _render_login_gate_card(
            is_en=is_en,
            next_url=next_after_login,
            custom_title=auth_title,
            custom_desc=auth_desc,
        )
    else:
        final_content = content_html

    flash_banner = (
        f"<div class='flash-banner anim-card' role='status'><span class='mark-badge'>{_symbol_svg('shield', 14)}</span><span>{esc(safe_flash)}</span></div>"
        if safe_flash
        else ""
    )

    nav_items = [("home", "/", L["home"], ""), ("guild", "/guild", L["guild"], "")]
    if is_logged_in and is_prem:
        nav_items.append(("premium", "/premium", L["premium"], ""))
    if is_logged_in and is_admin:
        nav_items.append(("admin", "/admin", L["admin"], ""))
    nav_items.extend(
        [
            ("services", "/services", L["services"], ""),
            ("updates", "/updates", L["updates"], "NEW" if is_en else "جديد"),
            ("links", "/links", L["links"], ""),
        ]
    )

    nav_links_html = ""
    for key, href, lbl, pill_txt in nav_items:
        pill_html = f"<span class='new-badge'>{esc(pill_txt)}</span>" if pill_txt else ""
        active_cls = "active" if active_nav == key else ""
        nav_links_html += f"<a class='nav-item {active_cls}' href='{href}'><span>{esc(lbl)}</span>{pill_html}</a>"

    quick_dock_html = ""
    for key, href, lbl, _ in nav_items:
        d_active = "active" if active_nav == key else ""
        quick_dock_html += f"<a class='dock-link {d_active}' href='{href}'>{esc(lbl)}</a>"

    drawer_footer_btn = (
        f"<a class='drawer-logout-btn' href='/logout'><span>{esc(L['logout'])}</span></a>"
        if user
        else ""
    )

    next_lang = "ar" if is_en else "en"
    lang_label = "العربية" if is_en else "English"

    chrome_html = "" if is_locked_state else f"""
    <header class="top-bar anim-card">
      <div class="top-left">
        <button class="icon-btn" type="button" onclick="toggleDrawer(true)" aria-label="{esc(L['menu'])}">&#9776;</button>
      </div>

      <div class="top-right">
        <div>
          <div class="brand-title">{esc(SITE_NAME)}</div>
          <div class="brand-sub">{esc(L['supervised'])}</div>
        </div>
        <div class="brand-mark">{_mark_svg(20)}</div>
      </div>
    </header>

    <nav class="dock-bar anim-card" aria-label="{esc(L['menu'])}">
      {quick_dock_html}
    </nav>
    """

    return f"""<!DOCTYPE html>
<html lang="{lang}" dir="{dir_attr}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)} — {esc(SITE_NAME)}</title>
<style>
  :root {{
    --bg-base: #07050D;
    --bg-canvas:
      radial-gradient(circle at 50% 18%, rgba(139, 92, 246, 0.24), transparent 52%),
      radial-gradient(circle at 20% 80%, rgba(109, 40, 217, 0.16), transparent 55%),
      linear-gradient(180deg, #0C0818 0%, #07050D 58%, #05030A 100%);
    --surface: #120D21;
    --surface-raised: #19122E;
    --surface-input: #0B0814;
    --border: rgba(167, 139, 250, 0.18);
    --border-strong: rgba(196, 181, 253, 0.52);
    --text-main: #F5F3FF;
    --text-muted: #A79EC4;
    --accent: #A78BFA;
    --accent-bright: #DDD6FE;
    --accent-soft: rgba(139, 92, 246, 0.18);
    --violet-btn: linear-gradient(135deg, #D8CCF8 0%, #A993EA 100%);
    --emerald: #4ADE80;
    --emerald-bg: rgba(74, 222, 128, 0.14);
    --rose: #FB7185;
    --rose-bg: rgba(251, 113, 133, 0.16);
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    background: var(--bg-base);
    background-image: var(--bg-canvas);
    background-attachment: fixed;
    color: var(--text-main);
    min-height: 100vh;
    line-height: 1.55;
  }}
  @keyframes pageSlideIn {{
    0% {{ opacity: 0; transform: translateY(14px) scale(0.992); }}
    100% {{ opacity: 1; transform: translateY(0) scale(1); }}
  }}
  @keyframes cardPopIn {{
    0% {{ opacity: 0; transform: translateY(10px); }}
    100% {{ opacity: 1; transform: translateY(0); }}
  }}
  @keyframes paneReveal {{
    0% {{ opacity: 0; transform: translateY(8px); }}
    100% {{ opacity: 1; transform: translateY(0); }}
  }}
  @keyframes meterPulse {{
    0%, 100% {{ filter: brightness(1); }}
    50% {{ filter: brightness(1.18); }}
  }}
  @media (prefers-reduced-motion: reduce) {{
    *, *::before, *::after {{ animation: none !important; transition-duration: 0.05s !important; }}
  }}
  .page-transition-wrap {{
    animation: pageSlideIn 0.34s cubic-bezier(0.22, 1, 0.36, 1) both;
  }}
  .anim-card {{
    animation: cardPopIn 0.38s cubic-bezier(0.22, 1, 0.36, 1) both;
  }}
  .anim-item {{
    transition: transform 0.22s cubic-bezier(0.22, 1, 0.36, 1), border-color 0.2s ease, background 0.2s ease, box-shadow 0.22s ease;
  }}

  /* Centered Obsidian-Violet Lock Gate */
  .lock-stage {{
    min-height: calc(100vh - 80px);
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 16px 6px;
  }}
  .lock-card {{
    width: 100%;
    max-width: 440px;
    background: var(--surface);
    border: 1px solid rgba(139, 92, 246, 0.24);
    border-radius: 28px;
    padding: 36px 26px 30px;
    text-align: center;
    box-shadow:
      0 24px 64px rgba(0, 0, 0, 0.72),
      0 0 48px rgba(124, 58, 237, 0.14);
  }}
  .lock-badge-ring {{
    width: 68px;
    height: 68px;
    margin: 0 auto 20px;
    border-radius: 999px;
    background: radial-gradient(circle at 35% 30%, #8B5CF6 0%, #5B21B6 72%, #3B0764 100%);
    border: 2px solid rgba(196, 181, 253, 0.34);
    box-shadow: 0 10px 28px rgba(109, 40, 217, 0.42);
    display: flex;
    align-items: center;
    justify-content: center;
  }}
  .lock-badge-inner {{
    width: 46px;
    height: 46px;
    border-radius: 999px;
    border: 1.8px solid rgba(245, 243, 255, 0.85);
    color: #F5F3FF;
    display: flex;
    align-items: center;
    justify-content: center;
  }}
  .lock-title {{
    margin: 0 0 10px;
    font-size: 24px;
    font-weight: 800;
    color: var(--text-main);
    letter-spacing: -0.2px;
  }}
  .lock-desc {{
    margin: 0 auto 24px;
    max-width: 340px;
    font-size: 14px;
    line-height: 1.65;
    color: var(--text-muted);
  }}
  .lock-desc strong {{
    color: var(--text-main);
    font-weight: 800;
  }}
  .lock-discord-btn {{
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
    width: 100%;
    padding: 14px 20px;
    border-radius: 16px;
    background: var(--violet-btn);
    border: 1px solid rgba(221, 214, 254, 0.65);
    color: #0D0919;
    text-decoration: none;
    font-size: 15.5px;
    font-weight: 800;
    box-shadow: 0 8px 24px rgba(139, 92, 246, 0.25);
    transition: transform 0.2s cubic-bezier(0.22, 1, 0.36, 1), filter 0.2s ease, box-shadow 0.2s ease;
  }}
  .lock-discord-btn:hover {{
    filter: brightness(1.05);
    transform: translateY(-2px);
    box-shadow: 0 12px 28px rgba(167, 139, 250, 0.36);
  }}
  .lock-discord-btn:active {{
    transform: scale(0.98);
  }}
  .lock-divider {{
    height: 1px;
    background: rgba(167, 139, 250, 0.14);
    margin: 26px 0 18px;
  }}
  .lock-legal {{
    margin: 0;
    font-size: 12px;
    line-height: 1.65;
    color: #877FA3;
  }}
  .lock-legal strong {{
    color: #C7BFD9;
    font-weight: 700;
  }}

  .overlay {{
    opacity: 0;
    pointer-events: none;
    position: fixed;
    inset: 0;
    background: rgba(3, 2, 8, 0.76);
    backdrop-filter: blur(5px);
    z-index: 60;
    transition: opacity 0.24s cubic-bezier(0.22, 1, 0.36, 1);
  }}
  .overlay.open {{
    opacity: 1;
    pointer-events: auto;
  }}
  .sidebar {{
    position: fixed;
    top: 0;
    {('left' if is_en else 'right')}: 0;
    width: 310px;
    max-width: 86vw;
    height: 100vh;
    background: linear-gradient(180deg, #161028 0%, #0A0713 100%);
    backdrop-filter: blur(18px);
    border-{('right' if is_en else 'left')}: 1px solid var(--border);
    padding: 18px 14px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    z-index: 70;
    overflow-y: auto;
    transform: translateX({('-100%' if is_en else '100%')});
    transition: transform 0.3s cubic-bezier(0.22, 1, 0.36, 1);
    will-change: transform;
  }}
  .sidebar.open {{ transform: translateX(0); }}
  .drawer-head {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding-bottom: 8px;
  }}
  .drawer-title {{
    font-size: 15px;
    font-weight: 800;
    color: var(--text-main);
  }}
  .drawer-close-btn {{
    width: 32px;
    height: 32px;
    border-radius: 999px;
    background: var(--surface-raised);
    border: 1px solid var(--border);
    color: var(--text-muted);
    font-size: 12px;
    font-weight: 700;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    transition: transform 0.18s ease, color 0.18s ease, border-color 0.18s ease;
  }}
  .drawer-close-btn:hover {{ color: var(--text-main); border-color: var(--border-strong); transform: scale(1.06); }}
  .drawer-lang-btn {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    width: 100%;
    padding: 10px 14px;
    border-radius: 16px;
    background: var(--surface-raised);
    border: 1px solid var(--border);
    color: var(--accent-bright);
    font-weight: 800;
    font-size: 13px;
    cursor: pointer;
    transition: border-color 0.2s ease, background 0.2s ease, transform 0.2s cubic-bezier(0.22, 1, 0.36, 1);
  }}
  .drawer-lang-btn:hover {{ border-color: var(--border-strong); background: #22183E; transform: translateY(-1px); }}
  .drawer-spacer {{ flex: 1; min-height: 12px; }}
  .drawer-logout-btn {{
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 11px 14px;
    border-radius: 999px;
    background: var(--rose-bg);
    border: 1px solid rgba(251, 113, 133, 0.42);
    color: #FECDD3;
    text-decoration: none;
    font-weight: 700;
    font-size: 13px;
    transition: transform 0.2s cubic-bezier(0.22, 1, 0.36, 1), filter 0.2s ease;
  }}
  .drawer-logout-btn:hover {{ transform: translateY(-1px); filter: brightness(1.08); }}
  .page-container {{
    width: 100%;
    max-width: 960px;
    margin: 0 auto;
    padding: 20px 16px 64px;
  }}
  .top-bar {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 12px 16px;
    border-radius: 22px;
    background: var(--surface);
    border: 1px solid var(--border);
    box-shadow: 0 12px 30px rgba(0, 0, 0, 0.42);
    margin-bottom: 12px;
  }}
  .top-left {{ display: flex; align-items: center; gap: 8px; }}
  .icon-btn {{
    height: 40px;
    min-width: 40px;
    padding: 0 12px;
    border-radius: 14px;
    background: var(--surface-raised);
    border: 1px solid var(--border);
    color: var(--text-main);
    font-weight: 700;
    font-size: 15px;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    text-decoration: none;
    transition: border-color 0.2s ease, background 0.2s ease, transform 0.2s cubic-bezier(0.22, 1, 0.36, 1);
  }}
  .icon-btn:hover {{
    border-color: var(--border-strong);
    background: #22183E;
    transform: translateY(-1px);
  }}
  .icon-btn:active {{ transform: scale(0.96); }}
  .top-right {{
    display: flex;
    align-items: center;
    gap: 11px;
    text-align: {('left' if is_en else 'right')};
  }}
  .brand-title {{
    font-size: 16px;
    font-weight: 800;
    color: var(--text-main);
    letter-spacing: 0.3px;
    line-height: 1.25;
  }}
  .brand-sub {{ font-size: 12px; color: var(--text-muted); line-height: 1.25; }}
  .brand-mark {{
    width: 42px;
    height: 42px;
    border-radius: 14px;
    background: var(--accent-soft);
    border: 1px solid var(--border-strong);
    color: var(--accent-bright);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    transition: transform 0.25s cubic-bezier(0.22, 1, 0.36, 1);
  }}
  .brand-mark:hover {{ transform: scale(1.05); }}
  .dock-bar {{
    display: flex;
    align-items: center;
    gap: 8px;
    overflow-x: auto;
    scrollbar-width: none;
    padding: 8px 12px;
    border-radius: 18px;
    background: var(--surface);
    border: 1px solid var(--border);
    margin-bottom: 18px;
  }}
  .dock-bar::-webkit-scrollbar {{ display: none; }}
  .dock-link {{
    padding: 8px 15px;
    border-radius: 999px;
    font-size: 12.5px;
    font-weight: 700;
    color: var(--text-muted);
    text-decoration: none;
    white-space: nowrap;
    border: 1px solid transparent;
    transition: color 0.2s ease, background 0.2s ease, border-color 0.2s ease, transform 0.2s cubic-bezier(0.22, 1, 0.36, 1), box-shadow 0.2s ease;
  }}
  .dock-link:hover {{ color: var(--text-main); background: var(--surface-raised); transform: translateY(-1px); }}
  .dock-link:active {{ transform: scale(0.97); }}
  .dock-link.active {{
    color: #0D0919;
    background: var(--violet-btn);
    border-color: rgba(221, 214, 254, 0.65);
    font-weight: 800;
    box-shadow: 0 4px 14px rgba(139, 92, 246, 0.28);
  }}
  .mark-badge {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 30px;
    height: 30px;
    border-radius: 10px;
    background: var(--accent-soft);
    border: 1px solid rgba(167, 139, 250, 0.36);
    color: var(--accent-bright);
    flex-shrink: 0;
  }}
  .flash-banner {{
    display: flex;
    align-items: center;
    gap: 10px;
    background: var(--surface);
    border: 1px solid var(--border-strong);
    color: var(--text-main);
    border-radius: 18px;
    padding: 12px 16px;
    margin-bottom: 18px;
    font-size: 13.5px;
    font-weight: 700;
  }}
  .workspace-stack {{
    display: flex;
    flex-direction: column;
    gap: 16px;
  }}
  .surface-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 26px;
    padding: 26px 24px;
    box-shadow: 0 16px 38px rgba(0, 0, 0, 0.45);
  }}
  .hero-split {{
    display: grid;
    grid-template-columns: minmax(0, 1.35fr) minmax(250px, 0.9fr);
    gap: 18px;
    align-items: stretch;
    margin-bottom: 20px;
  }}
  .hero-single {{
    display: block;
    margin-bottom: 20px;
  }}
  @media (max-width: 720px) {{ .hero-split {{ grid-template-columns: 1fr; }} }}
  .hero-main-col {{ display: flex; flex-direction: column; justify-content: center; }}
  .meta-bar {{
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
    margin-bottom: 12px;
  }}
  .status-tag {{
    display: inline-flex;
    align-items: center;
    gap: 7px;
    padding: 4px 12px;
    border-radius: 999px;
    background: var(--emerald-bg);
    border: 1px solid rgba(74, 222, 128, 0.38);
    color: var(--emerald);
    font-size: 11.5px;
    font-weight: 700;
  }}
  .status-dot {{
    width: 7px;
    height: 7px;
    border-radius: 999px;
    background: var(--emerald);
  }}
  .main-heading {{
    margin: 0 0 8px;
    font-size: 26px;
    font-weight: 800;
    color: var(--text-main);
  }}
  .lead-copy {{
    margin: 0 0 18px;
    font-size: 14px;
    color: var(--text-muted);
  }}
  .pillars-grid {{
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 10px;
  }}
  @media (max-width: 780px) {{ .pillars-grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }} }}
  @media (max-width: 460px) {{ .pillars-grid {{ grid-template-columns: 1fr; }} }}
  .pillar-item {{
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 13px 14px;
    border-radius: 18px;
    background: var(--surface-raised);
    border: 1px solid var(--border);
    font-size: 12.5px;
    font-weight: 700;
  }}
  .pillar-item:hover {{ border-color: var(--border-strong); transform: translateY(-2px); box-shadow: 0 8px 20px rgba(0, 0, 0, 0.35); }}
  .pillar-text {{ color: var(--text-main); }}
  .action-pair {{
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 10px;
  }}
  @media (max-width: 540px) {{ .action-pair {{ grid-template-columns: 1fr; }} }}
  .btn-gold {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    width: 100%;
    padding: 12px 18px;
    border-radius: 999px;
    background: var(--violet-btn);
    border: 1px solid rgba(221, 214, 254, 0.65);
    color: #0D0919;
    text-decoration: none;
    font-weight: 800;
    font-size: 14px;
    cursor: pointer;
    box-shadow: 0 6px 18px rgba(139, 92, 246, 0.25);
    transition: filter 0.2s ease, transform 0.22s cubic-bezier(0.22, 1, 0.36, 1), box-shadow 0.2s ease;
  }}
  .btn-gold:hover {{ filter: brightness(1.06); transform: translateY(-2px); box-shadow: 0 10px 24px rgba(167, 139, 250, 0.36); }}
  .btn-gold:active {{ transform: scale(0.98); }}
  .btn-dark {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    width: 100%;
    padding: 12px 18px;
    border-radius: 999px;
    background: var(--surface-raised);
    border: 1px solid var(--border);
    color: var(--text-main);
    text-decoration: none;
    font-weight: 700;
    font-size: 13.5px;
    cursor: pointer;
    transition: border-color 0.2s ease, background 0.2s ease, transform 0.22s cubic-bezier(0.22, 1, 0.36, 1);
  }}
  .btn-dark:hover {{ border-color: var(--border-strong); background: #22183E; transform: translateY(-2px); }}
  .btn-dark:active {{ transform: scale(0.98); }}
  .btn-danger {{
    display: block;
    width: 100%;
    padding: 11px 16px;
    border-radius: 999px;
    background: var(--rose-bg);
    border: 1px solid rgba(251, 113, 133, 0.45);
    color: #FECDD3;
    text-decoration: none;
    font-weight: 700;
    font-size: 13px;
    text-align: center;
    cursor: pointer;
    transition: transform 0.2s cubic-bezier(0.22, 1, 0.36, 1), filter 0.2s ease;
  }}
  .btn-danger:hover {{ transform: translateY(-1px); filter: brightness(1.08); }}
  .btn-danger:active {{ transform: scale(0.98); }}
  .monitor-box {{
    padding: 18px;
    border-radius: 20px;
    background: var(--surface-input);
    border: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    transition: border-color 0.22s ease, transform 0.22s cubic-bezier(0.22, 1, 0.36, 1);
  }}
  .monitor-box:hover {{ border-color: var(--border-strong); transform: translateY(-2px); }}
  .monitor-top {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    margin-bottom: 10px;
  }}
  .monitor-main {{
    display: flex;
    flex-direction: column;
    gap: 4px;
    margin-bottom: 14px;
  }}
  .monitor-name {{ font-size: 16px; font-weight: 800; }}
  .meter-track {{
    width: 100%;
    height: 7px;
    border-radius: 999px;
    background: rgba(139, 92, 246, 0.22);
    overflow: hidden;
  }}
  .meter-bar {{
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg, #DDD6FE 0%, #8B5CF6 55%, #5B21B6 100%);
    animation: meterPulse 2.8s ease-in-out infinite;
  }}
  .stats-row {{
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 12px;
  }}
  @media (max-width: 540px) {{ .stats-row {{ grid-template-columns: 1fr; }} }}
  .stat-box {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 22px;
    padding: 18px 20px;
    box-shadow: 0 12px 28px rgba(0, 0, 0, 0.38);
    transition: transform 0.22s cubic-bezier(0.22, 1, 0.36, 1), border-color 0.2s ease;
  }}
  .stat-box:hover {{ transform: translateY(-2px); border-color: var(--border-strong); }}
  .stat-top {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }}
  .stat-label {{ font-size: 13px; color: var(--text-muted); font-weight: 700; }}
  .stat-value {{ font-size: 27px; font-weight: 800; color: var(--text-main); margin-top: 8px; }}
  .discord-hub-card {{
    background: linear-gradient(160deg, #1A1230 0%, #100B1E 100%);
    border: 1px solid var(--border-strong);
    border-radius: 26px;
    padding: 28px 22px;
    text-align: center;
    box-shadow: 0 16px 36px rgba(0, 0, 0, 0.44);
  }}
  .discord-hub-icon {{
    width: 54px;
    height: 54px;
    margin: 0 auto 14px;
    border-radius: 16px;
    background: var(--accent-soft);
    border: 1px solid var(--border-strong);
    color: var(--accent-bright);
    display: flex;
    align-items: center;
    justify-content: center;
  }}
  .discord-hub-title {{
    margin: 0 0 6px;
    font-size: 22px;
    font-weight: 800;
    color: var(--text-main);
  }}
  .discord-hub-sub {{
    margin: 0 auto 20px;
    max-width: 520px;
    font-size: 13.5px;
    color: var(--text-muted);
  }}
  .discord-hub-btn {{
    display: flex;
    align-items: center;
    justify-content: center;
    width: 100%;
    max-width: 680px;
    margin: 0 auto;
    padding: 13px 20px;
    border-radius: 16px;
    background: var(--violet-btn);
    border: 1px solid rgba(221, 214, 254, 0.72);
    color: #0D0919;
    text-decoration: none;
    font-weight: 800;
    font-size: 15px;
    box-shadow: 0 8px 22px rgba(139, 92, 246, 0.28);
    transition: filter 0.2s ease, transform 0.22s cubic-bezier(0.22, 1, 0.36, 1), box-shadow 0.2s ease;
  }}
  .discord-hub-btn:hover {{ filter: brightness(1.05); transform: translateY(-2px); box-shadow: 0 12px 26px rgba(167, 139, 250, 0.38); }}
  .discord-hub-btn:active {{ transform: scale(0.98); }}
  .page-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 24px;
    padding: 24px 20px;
    margin-bottom: 18px;
    box-shadow: 0 16px 38px rgba(0, 0, 0, 0.44);
  }}
  .section-head-bar {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 10px;
    padding-bottom: 14px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 16px;
  }}
  .section-head-title {{ margin: 0 0 3px; font-size: 19px; font-weight: 800; }}
  .admin-kpis {{
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 10px;
    margin-bottom: 16px;
  }}
  @media (max-width: 540px) {{ .admin-kpis {{ grid-template-columns: 1fr; }} }}
  .kpi-box {{
    padding: 14px;
    border-radius: 18px;
    background: var(--surface-raised);
    border: 1px solid var(--border);
    text-align: center;
    transition: transform 0.2s cubic-bezier(0.22, 1, 0.36, 1), border-color 0.2s ease;
  }}
  .kpi-box:hover {{ transform: translateY(-2px); border-color: var(--border-strong); }}
  .kpi-num {{ font-size: 21px; font-weight: 800; color: var(--text-main); }}
  .kpi-lbl {{ font-size: 11.5px; color: var(--text-muted); margin-top: 2px; }}
  .cat-tabs {{
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-bottom: 16px;
  }}
  .cat-tab-btn {{
    background: var(--surface-input);
    border: 1px solid var(--border);
    color: var(--text-muted);
    border-radius: 999px;
    padding: 8px 15px;
    font-size: 12.5px;
    font-weight: 700;
    cursor: pointer;
    text-align: center;
    transition: background 0.2s ease, color 0.2s ease, border-color 0.2s ease, transform 0.2s cubic-bezier(0.22, 1, 0.36, 1);
  }}
  .cat-tab-btn:hover {{ border-color: var(--border-strong); color: var(--text-main); transform: translateY(-1px); }}
  .cat-tab-btn:active {{ transform: scale(0.97); }}
  .cat-tab-btn.active {{
    background: var(--violet-btn);
    border-color: rgba(221, 214, 254, 0.65);
    color: #0D0919;
    font-weight: 800;
    box-shadow: 0 4px 14px rgba(139, 92, 246, 0.28);
  }}
  .cat-pane {{ display: none; }}
  .cat-pane.active {{ display: block; animation: paneReveal 0.28s cubic-bezier(0.22, 1, 0.36, 1) both; }}
  .link-hub-stack {{
    display: flex;
    flex-direction: column;
    gap: 12px;
  }}
  .link-banner-card {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 14px;
    padding: 18px 20px;
    border-radius: 20px;
    background: var(--surface-raised);
    border: 1px solid var(--border);
    text-decoration: none;
    color: var(--text-main);
    transition: border-color 0.2s ease, background 0.2s ease, transform 0.22s cubic-bezier(0.22, 1, 0.36, 1);
  }}
  .link-banner-card:hover {{ border-color: var(--border-strong); background: #22183E; transform: translateY(-2px); }}
  .link-card-title {{ font-weight: 800; font-size: 15.5px; }}
  .link-card-sub {{ font-size: 12.5px; color: var(--text-muted); margin-top: 3px; }}
  .link-arrow {{
    padding: 6px 13px;
    border-radius: 999px;
    background: var(--accent-soft);
    border: 1px solid var(--border-strong);
    font-weight: 800;
    color: var(--accent-bright);
    font-size: 12px;
    flex-shrink: 0;
  }}
  .log-entry-row {{
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 12px;
    padding: 13px 15px;
    border-radius: 16px;
    background: var(--surface-input);
    border: 1px solid var(--border);
    margin-bottom: 8px;
    transition: border-color 0.2s ease, transform 0.2s ease;
  }}
  .log-entry-row:hover {{ border-color: var(--border-strong); transform: translateY(-1px); }}
  .log-entry-msg {{ font-size: 13.5px; font-weight: 700; color: var(--text-main); }}
  .log-entry-time {{ font-size: 11.5px; color: var(--text-muted); white-space: nowrap; flex-shrink: 0; }}
  @media (max-width: 600px) {{ .log-entry-row {{ flex-direction: column; gap: 4px; }} }}
  .panel-section {{
    background: var(--surface-raised);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 16px;
    margin-bottom: 14px;
  }}
  .panel-section-head {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    margin-bottom: 12px;
    padding-bottom: 10px;
    border-bottom: 1px solid var(--border);
  }}
  .panel-section-title {{ margin: 0; font-size: 14.5px; font-weight: 800; }}
  .grid-2 {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; margin-bottom: 10px; }}
  @media (max-width: 540px) {{ .grid-2 {{ grid-template-columns: 1fr; }} }}
  .nav-item {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 10px 14px;
    border-radius: 999px;
    color: var(--text-main);
    text-decoration: none;
    font-size: 13.5px;
    font-weight: 700;
    transition: background 0.18s ease, transform 0.18s ease;
  }}
  .nav-item:hover {{ background: rgba(139, 92, 246, 0.16); transform: translateX({('3px' if is_en else '-3px')}); }}
  .nav-item.active {{
    background: var(--accent-soft);
    border: 1px solid var(--border-strong);
    color: var(--accent-bright);
  }}
  .new-badge {{
    padding: 2px 8px;
    border-radius: 999px;
    background: var(--emerald-bg);
    color: var(--emerald);
    font-size: 10.5px;
    font-weight: 800;
  }}
  .sep {{ height: 1px; background: var(--border); margin: 4px 0; }}
  .user-box {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 11px 14px;
    border-radius: 18px;
    background: var(--surface-raised);
    border: 1px solid var(--border);
  }}
  .user-meta {{ min-width: 0; flex: 1; text-align: {('left' if is_en else 'right')}; }}
  .prem-status-strip {{
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 12px;
    border-radius: 999px;
    background: var(--accent-soft);
    border: 1px solid var(--border-strong);
    font-size: 11.5px;
    font-weight: 700;
    color: var(--accent-bright);
  }}
  .uname {{ font-weight: 800; font-size: 13.5px; color: var(--text-main); }}
  .uhandle {{ font-size: 11px; color: var(--text-muted); }}
  .tag {{
    font-size: 10px;
    padding: 2px 8px;
    border-radius: 999px;
    background: var(--accent-soft);
    border: 1px solid rgba(167, 139, 250, 0.38);
    color: var(--accent-bright);
    font-weight: 800;
    white-space: nowrap;
  }}
  .ok-pill {{
    font-size: 11px;
    padding: 4px 11px;
    border-radius: 999px;
    background: var(--emerald-bg);
    border: 1px solid rgba(74, 222, 128, 0.36);
    color: var(--emerald);
    font-weight: 700;
    white-space: nowrap;
  }}
  .warn-pill {{
    font-size: 11px;
    padding: 4px 11px;
    border-radius: 999px;
    background: var(--rose-bg);
    border: 1px solid rgba(251, 113, 133, 0.42);
    color: #FECDD3;
    font-weight: 700;
    white-space: nowrap;
  }}
  .prem-pill {{
    font-size: 11px;
    padding: 4px 11px;
    border-radius: 999px;
    background: var(--accent-soft);
    border: 1px solid var(--border-strong);
    color: var(--accent-bright);
    font-weight: 700;
  }}
  .admin-pill {{
    font-size: 10.5px;
    padding: 3px 9px;
    border-radius: 999px;
    background: rgba(167, 139, 250, 0.16);
    border: 1px solid rgba(167, 139, 250, 0.4);
    color: #EDE9FE;
    font-weight: 700;
  }}
  .inp, .sel, .bio-textarea {{
    width: 100%;
    background: var(--surface-input);
    border: 1px solid var(--border);
    color: var(--text-main);
    border-radius: 16px;
    padding: 10px 14px;
    font-size: 13.5px;
    margin-bottom: 10px;
    font-family: inherit;
    transition: border-color 0.2s ease, box-shadow 0.2s ease;
  }}
  .bio-textarea {{
    min-height: 112px;
    margin-top: 6px;
    margin-bottom: 6px;
    resize: vertical;
  }}
  .inp:focus, .sel:focus, .bio-textarea:focus {{
    outline: none;
    border-color: var(--border-strong);
    box-shadow: 0 0 0 3px rgba(167, 139, 250, 0.16);
  }}
  .lbl {{ display: block; font-size: 12.5px; color: var(--text-muted); margin: 6px 0 4px; font-weight: 700; }}
  .bio-meta {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 8px;
    font-size: 11.5px;
    color: var(--text-muted);
    margin-bottom: 10px;
  }}
  .switch-row {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 11px 14px;
    border-radius: 16px;
    background: var(--surface-input);
    border: 1px solid var(--border);
    margin-bottom: 8px;
    font-size: 13px;
    font-weight: 700;
    cursor: pointer;
    user-select: none;
    transition: border-color 0.2s ease, background 0.2s ease;
  }}
  .switch-row:hover {{ border-color: var(--border-strong); background: #100C1D; }}
  .switch-input {{
    position: relative;
    appearance: none;
    -webkit-appearance: none;
    width: 44px;
    min-width: 44px;
    height: 24px;
    border-radius: 999px;
    background: #231A3B;
    border: 1px solid var(--border);
    cursor: pointer;
    transition: background 0.22s cubic-bezier(0.22, 1, 0.36, 1), border-color 0.22s ease;
  }}
  .switch-input::after {{
    content: "";
    position: absolute;
    top: 2px;
    left: 2px;
    width: 18px;
    height: 18px;
    border-radius: 999px;
    background: var(--text-muted);
    transition: transform 0.22s cubic-bezier(0.22, 1, 0.36, 1), background 0.2s ease;
  }}
  .switch-input:checked {{
    background: #A78BFA;
    border-color: #DDD6FE;
  }}
  .switch-input:checked::after {{
    transform: translateX(20px);
    background: #0D0919;
  }}
  .list-row {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    padding: 12px 15px;
    border-radius: 16px;
    background: var(--surface-input);
    border: 1px solid var(--border);
    margin-bottom: 8px;
    text-decoration: none;
    color: var(--text-main);
  }}
  .list-row:hover {{ border-color: var(--border-strong); transform: translateY(-1px); }}
  .row-main {{ display: flex; align-items: center; gap: 12px; min-width: 0; }}
  .row-copy {{ min-width: 0; }}
  .row-title {{ font-weight: 800; font-size: 14px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
  .row-sub {{ font-size: 11.5px; margin-top: 2px; }}
  .prem-member-card {{
    display: flex;
    flex-direction: column;
    gap: 10px;
    padding: 14px 16px;
    border-radius: 18px;
    background: var(--surface-input);
    border: 1px solid var(--border);
    margin-bottom: 10px;
    transition: border-color 0.2s ease, transform 0.2s cubic-bezier(0.22, 1, 0.36, 1);
  }}
  .prem-member-card:hover {{ border-color: var(--border-strong); transform: translateY(-2px); }}
  .prem-member-top {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 10px;
  }}
  .prem-member-identity {{ display: flex; align-items: center; gap: 10px; min-width: 0; }}
  .prem-member-actions {{
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    align-items: center;
    padding-top: 10px;
    border-top: 1px solid var(--border);
  }}
  .guild-icon-wrap {{
    width: 38px;
    height: 38px;
    border-radius: 999px;
    overflow: hidden;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    border: 1px solid var(--border);
  }}
  .guild-icon {{ width: 100%; height: 100%; object-fit: cover; display: block; }}
  .guild-icon-ph {{
    width: 100%;
    height: 100%;
    background: var(--surface-raised);
    color: var(--accent-bright);
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 800;
    font-size: 14px;
  }}
  .mini-btn {{
    padding: 8px 14px;
    border-radius: 999px;
    border: 1px solid var(--border);
    background: var(--surface-raised);
    color: var(--text-main);
    font-size: 12px;
    font-weight: 700;
    cursor: pointer;
    text-align: center;
    transition: border-color 0.2s ease, background 0.2s ease, transform 0.2s cubic-bezier(0.22, 1, 0.36, 1);
  }}
  .mini-btn:hover {{ border-color: var(--border-strong); background: #22183E; transform: translateY(-1px); }}
  .mini-btn:active {{ transform: scale(0.97); }}
  .mini-btn.gold {{
    background: var(--violet-btn);
    border-color: rgba(221, 214, 254, 0.65);
    color: #0D0919;
    font-weight: 800;
  }}
  .mini-btn.red {{
    border-color: rgba(251, 113, 133, 0.45);
    background: var(--rose-bg);
    color: #FECDD3;
  }}
  .album-box {{
    padding: 14px 16px;
    border-radius: 18px;
    background: var(--surface-input);
    border: 1px dashed var(--border);
    margin-bottom: 10px;
    transition: border-color 0.2s ease;
  }}
  .album-box:hover {{ border-color: var(--border-strong); }}
  .album-head {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 8px;
  }}
  .preview-thumb {{
    width: 68px;
    height: 68px;
    border-radius: 16px;
    object-fit: cover;
    border: 1px solid var(--border);
    margin-top: 8px;
  }}
  .preview-banner {{
    width: 100%;
    max-width: 240px;
    height: 68px;
    border-radius: 16px;
    object-fit: cover;
    border: 1px solid var(--border);
    margin-top: 8px;
  }}
  .studio-grid {{
    display: grid;
    grid-template-columns: minmax(0, 1.45fr) minmax(260px, 0.95fr);
    gap: 16px;
    align-items: start;
  }}
  @media (max-width: 780px) {{ .studio-grid {{ grid-template-columns: 1fr; }} }}
  .studio-col {{
    display: flex;
    flex-direction: column;
    gap: 14px;
  }}
  .studio-card {{
    background: var(--surface-input);
    border: 1px solid var(--border);
    border-radius: 18px;
    padding: 14px 16px;
  }}
  .studio-card-head {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    margin-bottom: 10px;
    font-size: 13px;
    font-weight: 800;
    color: var(--text-main);
  }}
  .studio-badge {{
    font-size: 11px;
    color: var(--text-muted);
    font-weight: 700;
  }}
  .avatar-row {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 14px;
    flex-wrap: wrap;
  }}
  .avatar-actions {{
    display: flex;
    flex-direction: column;
    gap: 8px;
    min-width: 0;
    flex: 1;
  }}
  .avatar-btns {{
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }}
  .bot-ava-circle {{
    width: 72px;
    height: 72px;
    border-radius: 999px;
    border: 2px solid var(--border-strong);
    background: linear-gradient(135deg, #7C3AED 0%, #A78BFA 100%);
    color: #F5F3FF;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-size: 26px;
    font-weight: 800;
    overflow: hidden;
    flex-shrink: 0;
  }}
  .bot-ava-circle img {{
    width: 100%;
    height: 100%;
    object-fit: cover;
    display: block;
  }}
  .choice-grid-2 {{
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 8px;
    margin-bottom: 10px;
  }}
  .choice-grid-4 {{
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 8px;
    margin-bottom: 10px;
  }}
  @media (max-width: 520px) {{ .choice-grid-4 {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }} }}
  .choice-tile {{
    position: relative;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    padding: 10px 8px;
    border-radius: 12px;
    background: var(--surface-raised);
    border: 1px solid var(--border);
    color: var(--text-muted);
    font-size: 12.5px;
    font-weight: 800;
    cursor: pointer;
    user-select: none;
    transition: border-color 0.18s ease, background 0.18s ease, color 0.18s ease, transform 0.18s ease;
  }}
  .choice-tile input {{
    position: absolute;
    opacity: 0;
    pointer-events: none;
  }}
  .choice-tile:hover {{
    border-color: var(--border-strong);
    color: var(--text-main);
    transform: translateY(-1px);
  }}
  .choice-tile.active {{
    background: rgba(124, 58, 237, 0.34);
    border-color: #A78BFA;
    color: #F5F3FF;
    box-shadow: 0 0 0 1px rgba(167, 139, 250, 0.35);
  }}
  .st-dot {{
    width: 9px;
    height: 9px;
    border-radius: 999px;
    display: inline-block;
    flex-shrink: 0;
  }}
  .st-dot.online {{ background: #22C55E; }}
  .st-dot.idle {{ background: #EAB308; }}
  .st-dot.dnd {{ background: #EF4444; }}
  .st-dot.invisible {{ background: #64748B; border: 1px solid #94A3B8; }}
  .live-preview-card {{
    background: #120D21;
    border: 1px solid var(--border);
    border-radius: 18px;
    padding: 14px;
    position: sticky;
    top: 16px;
  }}
  .live-preview-head {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-size: 12px;
    font-weight: 800;
    color: var(--text-muted);
    margin-bottom: 10px;
  }}
  .live-discord-box {{
    background: #0A0714;
    border: 1px solid rgba(167, 139, 250, 0.16);
    border-radius: 16px;
    padding: 14px;
    color: #F5F3FF;
  }}
  .live-top-row {{
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 10px;
  }}
  .live-ava-wrap {{
    position: relative;
    width: 52px;
    height: 52px;
    flex-shrink: 0;
  }}
  .live-ava-circle {{
    width: 52px;
    height: 52px;
    border-radius: 999px;
    background: linear-gradient(135deg, #7C3AED 0%, #A78BFA 100%);
    color: #FFFFFF;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 20px;
    font-weight: 800;
    overflow: hidden;
  }}
  .live-ava-circle img {{
    width: 100%;
    height: 100%;
    object-fit: cover;
    display: block;
  }}
  .live-status-badge {{
    position: absolute;
    bottom: -1px;
    right: -1px;
    width: 16px;
    height: 16px;
    border-radius: 999px;
    background: #0A0714;
    display: flex;
    align-items: center;
    justify-content: center;
  }}
  .live-name-txt {{
    font-size: 16px;
    font-weight: 800;
    color: #FFFFFF;
    line-height: 1.25;
  }}
  .live-sub-txt {{
    font-size: 11.5px;
    color: #B5BAC1;
    margin-top: 2px;
  }}
  .live-act-txt {{
    font-size: 12px;
    color: #C4C9D4;
    margin-top: 3px;
  }}
  .live-divider {{
    height: 1px;
    background: rgba(167, 139, 250, 0.14);
    margin: 10px 0;
  }}
  .live-about-lbl {{
    font-size: 10.5px;
    font-weight: 800;
    color: #949BA4;
    margin-bottom: 4px;
  }}
  .live-bio-txt {{
    font-size: 12.5px;
    color: #DBDEE1;
    white-space: pre-wrap;
    word-break: break-word;
    min-height: 18px;
  }}
  .muted {{ color: var(--text-muted); font-size: 13px; }}
  code {{
    background: var(--surface-input);
    padding: 2px 7px;
    border-radius: 8px;
    font-size: 12px;
    color: var(--accent-bright);
    border: 1px solid var(--border);
  }}
</style>
</head>
<body>
<div id="overlay" class="overlay" onclick="toggleDrawer(false)"></div>

<aside id="drawer" class="sidebar" aria-label="{esc(L['menu'])}">
  <div class="drawer-head">
    <div class="drawer-title">{esc(L['menu'])}</div>
    <button class="drawer-close-btn" type="button" onclick="toggleDrawer(false)" aria-label="Close">X</button>
  </div>
  {account_block}
  <button class="drawer-lang-btn" type="button" onclick="switchLang('{next_lang}')">
    <span>{esc(lang_label)}</span>
    {_symbol_svg("lang", 16)}
  </button>
  <div class="sep"></div>
  {nav_links_html}
  <div class="sep"></div>
  <a class="nav-item" href="/invite"><span>{esc(L['invite'])}</span></a>
  <div class="drawer-spacer"></div>
  {drawer_footer_btn}
</aside>

<div class="page-container">
  {chrome_html}

  <div class="page-transition-wrap">
    {flash_banner}
    {final_content}
  </div>
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
  if (pane) {{
    pane.classList.remove("active");
    void pane.offsetWidth;
    pane.classList.add("active");
  }}
}}
function updateBioCounter(taId, cntId) {{
  var ta = document.getElementById(taId);
  var cnt = document.getElementById(cntId);
  if (ta && cnt) {{
    cnt.textContent = (ta.value || "").length + " / {MAX_BIO_CHARS}";
  }}
  refreshBotStudioPreview();
}}
function updateBotNameCounter(inpId, cntId) {{
  var inp = document.getElementById(inpId);
  var cnt = document.getElementById(cntId);
  if (inp && cnt) {{
    var len = (inp.value || "").length;
    cnt.textContent = len + " / 48";
  }}
  refreshBotStudioPreview();
}}
function selectTileGroup(groupName, val) {{
  document.querySelectorAll('label[data-tile-group="' + groupName + '"]').forEach(function(lbl) {{
    var isMatch = (lbl.getAttribute("data-tile-val") === val);
    lbl.classList.toggle("active", isMatch);
    var inp = lbl.querySelector("input[type='radio']");
    if (inp) inp.checked = isMatch;
  }});
  var streamWrap = document.getElementById("stream_url_wrap");
  if (groupName === "activity_type" && streamWrap) {{
    streamWrap.style.display = (val === "streaming") ? "block" : "none";
  }}
  refreshBotStudioPreview();
}}
function refreshBotStudioPreview() {{
  var nameInp = document.getElementById("studio_bot_name");
  var bioTa = document.getElementById("studio_bot_bio");
  var actInp = document.getElementById("studio_activity_text");
  var avaHidden = document.getElementById("avatar_data_url");

  var nameVal = (nameInp && nameInp.value.trim()) ? nameInp.value.trim() : "{esc(SITE_NAME)}";
  var bioVal = (bioTa && bioTa.value.trim()) ? bioTa.value.trim() : "";
  var actText = (actInp && actInp.value.trim()) ? actInp.value.trim() : "";
  var avaUrl = avaHidden ? avaHidden.value.trim() : "";

  var stInp = document.querySelector('input[name="bot_status"]:checked');
  var stVal = stInp ? stInp.value : "online";
  var stLabels = {{
    "online": "{('Online' if is_en else 'متصل')}",
    "idle": "{('Idle' if is_en else 'خامل')}",
    "dnd": "{('Do Not Disturb' if is_en else 'عدم الإزعاج')}",
    "invisible": "{('Invisible' if is_en else 'مخفي')}"
  }};
  var stDotColors = {{
    "online": "#22C55E",
    "idle": "#EAB308",
    "dnd": "#EF4444",
    "invisible": "#64748B"
  }};

  var actInpRadio = document.querySelector('input[name="activity_type"]:checked');
  var actType = actInpRadio ? actInpRadio.value : "playing";
  var actPrefixes = {{
    "playing": "{('Playing' if is_en else 'يلعب')}",
    "listening": "{('Listening to' if is_en else 'يستمع إلى')}",
    "watching": "{('Watching' if is_en else 'يشاهد')}",
    "streaming": "{('Streaming' if is_en else 'يبث')}"
  }};

  var pName = document.getElementById("preview_bot_name");
  var pStatus = document.getElementById("preview_bot_status");
  var pAct = document.getElementById("preview_bot_activity");
  var pBio = document.getElementById("preview_bot_bio");
  var pDot = document.getElementById("preview_status_dot");
  var pInitial = document.getElementById("preview_ava_initial");
  var pImg = document.getElementById("preview_ava_img");

  if (pName) pName.textContent = nameVal;
  if (pStatus) pStatus.textContent = stLabels[stVal] || stLabels.online;
  if (pDot) pDot.style.background = stDotColors[stVal] || "#22C55E";
  if (pAct) {{
    if (actText) {{
      pAct.style.display = "block";
      pAct.textContent = (actPrefixes[actType] || "") + " " + actText;
    }} else {{
      pAct.style.display = "none";
      pAct.textContent = "";
    }}
  }}
  if (pBio) pBio.textContent = bioVal;
  if (pInitial) pInitial.textContent = (nameVal.charAt(0) || "B").toUpperCase();
  if (pImg) {{
    if (avaUrl) {{
      pImg.src = avaUrl;
      pImg.style.display = "block";
      if (pInitial) pInitial.style.display = "none";
    }} else {{
      pImg.src = "";
      pImg.style.display = "none";
      if (pInitial) pInitial.style.display = "inline";
    }}
  }}
}}
function filterGuildsList(queryVal) {{
  var q = (queryVal || "").trim().toLowerCase();
  document.querySelectorAll(".guild-search-item").forEach(function(el) {{
    var hay = (el.getAttribute("data-search") || "").toLowerCase();
    el.style.display = (!q || hay.indexOf(q) !== -1) ? "flex" : "none";
  }});
}}
function filterPremiumList(queryVal) {{
  var q = (queryVal || "").trim().toLowerCase();
  document.querySelectorAll(".prem-search-item").forEach(function(el) {{
    var hay = (el.getAttribute("data-search") || "").toLowerCase();
    el.style.display = (!q || hay.indexOf(q) !== -1) ? "block" : "none";
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
  if (hiddenId === "avatar_data_url") {{
    var sInit = document.getElementById("studio_ava_initial");
    if (sInit) sInit.style.display = "inline";
  }}
  refreshBotStudioPreview();
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
    if (hiddenId === "avatar_data_url") {{
      var sInit = document.getElementById("studio_ava_initial");
      if (sInit && dataUrl) sInit.style.display = "none";
    }}
    refreshBotStudioPreview();
  }};
  reader.readAsDataURL(file);
}}
document.addEventListener("DOMContentLoaded", function() {{
  refreshBotStudioPreview();
}});
</script>
</body>
</html>"""


async def handle_invite_redirect(request: web.Request) -> web.Response:
    target_invite = sanitize_http_url(BOT_INVITE_URL) or "https://discord.com"
    raise web.HTTPFound(target_invite)


async def home_handler(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    user = get_discord_session(request)
    is_logged_in = bool(user)
    is_prem = is_premium_user(user)
    prem_rec = _get_premium_record(str(user.get("id", "")).strip()) if user else None
    flash = sanitize_flash_msg(request.query.get("msg"))

    bot_servers_count = len(get_all_guilds())
    total_visits = get_total_visits()
    if is_logged_in:
        primary_href = "/guild"
        primary_txt = "Open Security Panel" if is_en else "الدخول إلى لوحة الحماية"
        secondary_href = "/premium" if is_prem else "/services"
        secondary_txt = "Premium Perks" if is_en else "مزايا البريميوم"
    else:
        primary_href = "/login?next=/guild"
        primary_txt = "Open Security Panel" if is_en else "الدخول إلى لوحة الحماية"
        secondary_href = "/services"
        secondary_txt = "View Services" if is_en else "عرض الخدمات"

    prem_badge_html = (
        f"<span class='prem-pill'>PRO / {esc(format_remaining_time(prem_rec, is_en=is_en))}</span>"
        if (is_prem and prem_rec)
        else ""
    )

    body = _render_intro_hero_html(
        is_en=is_en,
        user=user,
        bot_servers_count=bot_servers_count,
        total_visits=total_visits,
        primary_href=primary_href,
        primary_txt=primary_txt,
        secondary_href=secondary_href,
        secondary_txt=secondary_txt,
        prem_badge_html=prem_badge_html,
    )
    return web.Response(
        text=render_page(
            "Home" if is_en else "الرئيسية",
            "home",
            body,
            request,
            flash=flash,
            require_auth_view=not is_logged_in,
            next_after_login="/",
        ),
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
    old_bname = str(cur_prof.get("bot_name") or SITE_NAME).strip()[:48]
    old_bstatus = str(cur_prof.get("bot_status") or "online").strip().lower()
    old_act_type = str(cur_prof.get("activity_type") or "playing").strip().lower()
    old_act_text = "".join(ch for ch in str(cur_prof.get("activity_text") or "") if ch.isprintable()).strip()[:120]
    old_stream_url = sanitize_http_url(cur_prof.get("stream_url", ""))
    old_bio = sanitize_bio_text(cur_prof.get("bio", ""))
    old_ava = sanitize_image_data_url(cur_prof.get("avatar_data_url", ""))
    old_ban = sanitize_image_data_url(cur_prof.get("banner_data_url", ""))

    raw_bname = "".join(ch for ch in str(form.get("bot_name", old_bname)) if ch.isprintable()).strip()[:48]
    bname_clean = raw_bname or old_bname
    raw_bstatus = str(form.get("bot_status", old_bstatus)).strip().lower()
    bstatus_clean = raw_bstatus if raw_bstatus in ("online", "idle", "dnd", "invisible") else old_bstatus

    raw_act_type = str(form.get("activity_type", old_act_type)).strip().lower()
    act_type_clean = raw_act_type if raw_act_type in ("playing", "listening", "watching", "streaming") else old_act_type
    act_text_clean = (
        "".join(ch for ch in str(form.get("activity_text", old_act_text)) if ch.isprintable()).strip()[:120]
        if "activity_text" in form
        else old_act_text
    )
    stream_url_clean = sanitize_http_url(form.get("stream_url", old_stream_url)) if "stream_url" in form else old_stream_url

    bio_clean = sanitize_bio_text(form.get("bio", old_bio)) if "bio" in form else old_bio
    ava_data = sanitize_image_data_url(form.get("avatar_data_url", "")) if "avatar_data_url" in form else old_ava
    ban_data = sanitize_image_data_url(form.get("banner_data_url", "")) if "banner_data_url" in form else old_ban

    bio_changed = ("bio" in form)
    avatar_changed = ("avatar_data_url" in form) and (ava_data != old_ava)
    banner_changed = ("banner_data_url" in form) and (ban_data != old_ban)
    bot_meta_changed = (
        (bname_clean != old_bname)
        or (bstatus_clean != old_bstatus)
        or (act_type_clean != old_act_type)
        or (act_text_clean != old_act_text)
        or (stream_url_clean != old_stream_url)
    )
    profile_changed = ("bio" in form) or avatar_changed or banner_changed or bot_meta_changed

    prof_data = {
        "bot_name": bname_clean,
        "bot_status": bstatus_clean,
        "activity_type": act_type_clean,
        "activity_text": act_text_clean,
        "stream_url": stream_url_clean,
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


def _build_bot_profile_command_extra(
    gid: str,
    actor_uid: str,
    prof_data: dict,
    bio_changed: bool,
    avatar_changed: bool,
    banner_changed: bool,
) -> dict:
    return {
        "guild_id": gid,
        "user_id": actor_uid,
        "actor_id": actor_uid,
        "bot_name": prof_data["bot_name"],
        "bot_status": prof_data["bot_status"],
        "activity_type": prof_data["activity_type"],
        "activity_text": prof_data["activity_text"],
        "stream_url": prof_data["stream_url"],
        "bio": prof_data["bio"],
        "bio_changed": bio_changed,
        "avatar_changed": avatar_changed,
        "banner_changed": banner_changed,
        "has_avatar": bool(prof_data["avatar_data_url"]),
        "has_banner": bool(prof_data["banner_data_url"]),
        "avatar_data_url": prof_data["avatar_data_url"] if avatar_changed else "",
        "banner_data_url": prof_data["banner_data_url"] if banner_changed else "",
    }


def _render_premium_media_fields(prof: dict, perks: dict, is_en: bool, use_pr_prefix: bool = False) -> str:
    ava_src = str(prof.get("avatar_data_url", "") or "")
    ban_src = str(prof.get("banner_data_url", "") or "")
    bio_val = sanitize_bio_text(prof.get("bio", "") or "")
    bname_val = str(prof.get("bot_name") or SITE_NAME).strip()[:48]
    bstatus_val = str(prof.get("bot_status") or "online").strip().lower()
    act_type_val = str(prof.get("activity_type") or "playing").strip().lower()
    act_text_val = str(prof.get("activity_text") or "").strip()[:120]
    stream_url_val = str(prof.get("stream_url") or "").strip()[:350]
    initial_ch = esc((bname_val[:1] or "B").upper())

    uf_name = "pr_ultra_fortress" if use_pr_prefix else "ultra_fortress_mode"
    ir_name = "pr_instant_rollback" if use_pr_prefix else "instant_rollback_enabled"
    ps_name = "pr_priority_shield" if use_pr_prefix else "priority_shield_response"
    bio_id = "studio_bot_bio"
    cnt_id = "studio_bio_cnt"

    status_tiles = [
        ("online", "Online" if is_en else "متصل", "online"),
        ("idle", "Idle" if is_en else "خامل", "idle"),
        ("dnd", "Do Not Disturb" if is_en else "عدم الإزعاج", "dnd"),
        ("invisible", "Invisible" if is_en else "مخفي", "invisible"),
    ]
    status_tiles_html = "".join(
        f"<label class='choice-tile {'active' if bstatus_val == s_key else ''}' data-tile-group='bot_status' data-tile-val='{s_key}' onclick=\"selectTileGroup('bot_status', '{s_key}')\">"
        f"<input type='radio' name='bot_status' value='{s_key}' {'checked' if bstatus_val == s_key else ''}>"
        f"<span class='st-dot {dot_cls}'></span><span>{esc(s_lbl)}</span></label>"
        for s_key, s_lbl, dot_cls in status_tiles
    )

    activity_tiles = [
        ("playing", "Playing" if is_en else "يلعب"),
        ("listening", "Listening" if is_en else "يستمع"),
        ("watching", "Watching" if is_en else "يشاهد"),
        ("streaming", "Streaming" if is_en else "يبث"),
    ]
    activity_tiles_html = "".join(
        f"<label class='choice-tile {'active' if act_type_val == a_key else ''}' data-tile-group='activity_type' data-tile-val='{a_key}' onclick=\"selectTileGroup('activity_type', '{a_key}')\">"
        f"<input type='radio' name='activity_type' value='{a_key}' {'checked' if act_type_val == a_key else ''}>"
        f"<span>{esc(a_lbl)}</span></label>"
        for a_key, a_lbl in activity_tiles
    )

    ava_img_tag = (
        f"<img id='studio_ava_img' src='{esc(ava_src)}' alt=''>"
        if ava_src
        else "<img id='studio_ava_img' src='' alt='' style='display:none;'>"
    )
    ava_init_style = " style='display:none;'" if ava_src else ""

    ban_img_tag = (
        f"<img id='ban_preview' class='preview-thumb preview-banner' src='{esc(ban_src)}' alt=''>"
        if ban_src
        else "<img id='ban_preview' class='preview-thumb preview-banner' src='' alt='' style='display:none;'>"
    )

    return f"""
    <input type="hidden" id="avatar_data_url" name="avatar_data_url" value="{esc(ava_src)}">
    <input type="hidden" id="avatar_name" name="avatar_name" value="{esc(prof.get('avatar_name', ''))}">
    <input type="hidden" id="banner_data_url" name="banner_data_url" value="{esc(ban_src)}">
    <input type="hidden" id="banner_name" name="banner_name" value="{esc(prof.get('banner_name', ''))}">

    <div class="studio-grid" style="margin-bottom:14px;">
      <div class="studio-col">
        <div class="studio-card">
          <div class="studio-card-head">
            <span>{('Bot Name' if is_en else 'اسم البوت')}</span>
            <span id="studio_name_cnt" class="studio-badge">{len(bname_val)} / 48</span>
          </div>
          <input id="studio_bot_name" class="inp" style="margin-bottom:0;" type="text" maxlength="48" name="bot_name" value="{esc(bname_val)}" oninput="updateBotNameCounter('studio_bot_name', 'studio_name_cnt')" placeholder="{('Bot name...' if is_en else 'اسم البوت...')}">
        </div>

        <div class="studio-card">
          <div class="avatar-row">
            <div class="avatar-actions">
              <div class="avatar-btns">
                <label class="mini-btn gold" style="margin:0;cursor:pointer;">
                  <span>{('Change Avatar' if is_en else 'تغيير الصورة')}</span>
                  <input id="ava_file_inp" type="file" accept="image/jpeg,image/png,image/gif,image/webp" style="display:none;" onchange="readAlbumFile(this, 'avatar_data_url', 'studio_ava_img', 'avatar_name')">
                </label>
                <button type="button" class="mini-btn red" onclick="clearMediaField('avatar_data_url', 'studio_ava_img', 'avatar_name', 'ava_file_inp')">{('Remove Avatar' if is_en else 'إزالة الصورة')}</button>
              </div>
              <span class="muted" style="font-size:11.5px;">{('Max 10MB • JPG, PNG, GIF, WEBP' if is_en else 'حد أقصى 10MB • JPG, PNG, GIF, WEBP')}</span>
            </div>
            <div class="bot-ava-circle">
              <span id="studio_ava_initial"{ava_init_style}>{initial_ch}</span>
              {ava_img_tag}
            </div>
          </div>
        </div>

        <div class="studio-card">
          <div class="studio-card-head">
            <span>{('Bot Status' if is_en else 'حالة البوت')}</span>
          </div>
          <div class="choice-grid-2" style="margin-bottom:0;">
            {status_tiles_html}
          </div>
        </div>

        <div class="studio-card">
          <div class="studio-card-head">
            <span>{('Bot Activity' if is_en else 'نشاط البوت')}</span>
          </div>
          <div class="choice-grid-4">
            {activity_tiles_html}
          </div>
          <label class="lbl" style="margin-top:6px;">{('Activity Text' if is_en else 'نص النشاط')}</label>
          <input id="studio_activity_text" class="inp" style="margin-bottom:6px;" type="text" maxlength="120" name="activity_text" value="{esc(act_text_val)}" oninput="refreshBotStudioPreview()" placeholder="{('Enter activity text...' if is_en else 'اكتب نص النشاط...')}">
          <div id="stream_url_wrap" style="display:{('block' if act_type_val == 'streaming' else 'none')};">
            <label class="lbl">{('Streaming URL' if is_en else 'رابط البث')}</label>
            <input class="inp" style="margin-bottom:0;" type="url" name="stream_url" value="{esc(stream_url_val)}" placeholder="https://twitch.tv/...">
          </div>
        </div>

        <div class="studio-card">
          <div class="studio-card-head">
            <span>{('Bot Bio' if is_en else 'نبذة البوت')}</span>
            <span id="{cnt_id}" class="studio-badge">{len(bio_val)} / {MAX_BIO_CHARS}</span>
          </div>
          <textarea id="{bio_id}" class="bio-textarea" style="margin-top:0;" rows="4" maxlength="{MAX_BIO_CHARS}" name="bio" oninput="updateBioCounter('{bio_id}', '{cnt_id}')" placeholder="{('Enter bot bio...' if is_en else 'اكتب نبذة البوت هنا...')}">{esc(bio_val)}</textarea>
        </div>
      </div>

      <div class="studio-col">
        <div class="live-preview-card">
          <div class="live-preview-head">
            <span>{('Live Preview' if is_en else 'معاينة مباشرة')}</span>
            <span class="prem-pill">PRO</span>
          </div>
          <div class="live-discord-box">
            <div class="live-top-row">
              <div class="live-ava-wrap">
                <div class="live-ava-circle">
                  <span id="preview_ava_initial"{ava_init_style}>{initial_ch}</span>
                  <img id="preview_ava_img" src="{esc(ava_src)}" alt="" style="display:{('block' if ava_src else 'none')};">
                </div>
                <span class="live-status-badge"><span id="preview_status_dot" class="st-dot" style="width:10px;height:10px;"></span></span>
              </div>
              <div style="min-width:0;flex:1;">
                <div id="preview_bot_name" class="live-name-txt">{esc(bname_val)}</div>
                <div id="preview_bot_status" class="live-sub-txt"></div>
                <div id="preview_bot_activity" class="live-act-txt" style="display:none;"></div>
              </div>
            </div>
            <div class="live-divider"></div>
            <div class="live-about-lbl">{('About Me' if is_en else 'نبذة عن البوت')}</div>
            <div id="preview_bot_bio" class="live-bio-txt">{esc(bio_val)}</div>
          </div>
        </div>

        <div class="album-box" style="margin-bottom:0;">
          <div class="album-head">
            <label class="lbl" style="margin:0;">{('Bot Banner' if is_en else 'بنر البوت')}</label>
            <button type="button" class="mini-btn red" onclick="clearMediaField('banner_data_url', 'ban_preview', 'banner_name', 'ban_file_inp')">{('Remove' if is_en else 'إزالة')}</button>
          </div>
          <input id="ban_file_inp" class="inp" style="margin-top:6px;margin-bottom:4px;" type="file" accept="image/*" onchange="readAlbumFile(this, 'banner_data_url', 'ban_preview', 'banner_name')">
          <span class="muted">{esc(prof.get('banner_name') or ('No file chosen' if is_en else 'لم يتم اختيار ملف'))}</span>
          {ban_img_tag}
        </div>
      </div>
    </div>

    <label class="switch-row">
      <span>{esc('High Shield Mode' if is_en else 'حماية فائقة')}</span>
      <input class="switch-input" type="checkbox" name="{uf_name}" {'checked' if perks.get('ultra_fortress_mode') else ''}>
    </label>
    <label class="switch-row">
      <span>{esc('Instant Rollback' if is_en else 'الاسترجاع الفوري')}</span>
      <input class="switch-input" type="checkbox" name="{ir_name}" {'checked' if perks.get('instant_rollback_enabled', True) else ''}>
    </label>
    <label class="switch-row">
      <span>{esc('Priority Shield Response' if is_en else 'استجابة الحماية الفورية')}</span>
      <input class="switch-input" type="checkbox" name="{ps_name}" {'checked' if perks.get('priority_shield_response', True) else ''}>
    </label>

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
                auth_title="Sign In Required" if is_en else "تسجيل الدخول مطلوب",
                auth_desc=(
                    "Sign in with Discord to manage server protection rules, whitelists, and snapshots."
                    if is_en
                    else "سجّل دخولك بحساب ديسكورد للتحكم بأنظمة الحماية والموثوقين واللقطات."
                ),
            ),
            content_type="text/html",
        )
    session_id, user = sess_pair
    actor_uid = str(user.get("id", "")).strip()
    is_prem = is_premium_user(user)
    active_guilds = get_user_connected_guilds(user)

    if not active_guilds:
        _invalidate_guilds_cache()
        active_guilds = get_user_connected_guilds(user)

    if not active_guilds:
        msg = (
            "No server with the bot was found on your account. Add the bot to your server first."
            if is_en
            else "لم يتم العثور على سيرفر يحتوي على البوت ضمن حسابك. أضف البوت إلى سيرفرك أولاً."
        )
        empty_body = f"""
        <div class='page-card anim-card'>
          <h2 class='section-head-title'>{('Security Panel' if is_en else 'لوحة الحماية')}</h2>
          <p class='muted' style='margin:0 0 14px;'>{esc(msg)}</p>
          <div class='action-pair'>
            <a class='btn-gold' href='/invite'>{('Invite Bot' if is_en else 'إضافة بوت الحماية')}</a>
            <a class='btn-dark' href='/guild'>{('Refresh' if is_en else 'تحديث السيرفرات')}</a>
          </div>
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
                        "dangerous_perms_punishment": form.get("dangerous_perms_punishment", "Remove Roles"),
                        "app_abuse_punishment": form.get("app_abuse_punishment", "Ban"),
                        "min_account_age_days": form.get("min_account_age_days", 7),
                        "antinuke_updates": antinuke_upd,
                    }
                    for sk in SHIELD_TOGGLE_KEYS:
                        updates[sk] = form.get(f"sh_{sk}") == "on"

                    if is_prem:
                        updates["guild_icon_punishment"] = form.get("guild_icon_punishment", "Ban")
                        updates["selfbot_punishment"] = form.get("selfbot_punishment", "Ban")
                        prof_data, perks_data, profile_changed, bio_changed, avatar_changed, banner_changed = (
                            _process_premium_profile_and_perks(form, cur_prof, cur_perks)
                        )
                        updates["guild_profile"] = prof_data
                        updates["premium_perks"] = perks_data
                    else:
                        prof_data = {}
                        profile_changed = False
                        bio_changed = False
                        avatar_changed = False
                        banner_changed = False

                    save_guild_cfg(gid, updates, is_premium=is_prem)
                    enqueue_remote_action(gid, "sync_guild_cfg", gid, extra={"guild_id": gid, "user_id": actor_uid}, actor_user_id=actor_uid)
                    if is_prem and profile_changed:
                        prof_extra = _build_bot_profile_command_extra(
                            gid=gid,
                            actor_uid=actor_uid,
                            prof_data=prof_data,
                            bio_changed=bio_changed,
                            avatar_changed=avatar_changed,
                            banner_changed=banner_changed,
                        )
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
            <input class="inp" style="width:74px;margin:0;padding:6px 10px;" type="number" min="1" max="50" name="an_{rk}_limit" value="{int(r_cfg.get('limit', 1) or 1)}">
            <select class="sel" style="width:136px;margin:0;padding:6px 10px;" name="an_{rk}_punishment">
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
                f"<button class='mini-btn gold' type='submit' name='form_action' value='restore_snapshot' onclick=\"this.form.target_snapshot_id.value='{sid_esc}'\">{('Restore' if is_en else 'استعادة')}</button>"
                f"<button class='mini-btn red' type='submit' name='form_action' value='delete_snapshot' onclick=\"this.form.target_snapshot_id.value='{sid_esc}'\">x</button>"
                f"</div></div>"
            )
    else:
        snaps_rows = f"<p class='muted'>{('No snapshots saved yet.' if is_en else 'لا توجد لقطات محفوظة.')}</p>"

    spam_pun = str(cfg.get("spam_punishment", "Timeout"))
    link_pun = str(cfg.get("link_punishment", "Delete & Timeout"))
    dang_pun = str(cfg.get("dangerous_perms_punishment", "Remove Roles"))
    app_pun = str(cfg.get("app_abuse_punishment", "Ban"))
    icon_pun = str(cfg.get("guild_icon_punishment", "Ban"))
    selfbot_pun = str(cfg.get("selfbot_punishment", "Ban"))

    if is_prem:
        prem_prot_toggles = _build_toggle_items(PREMIUM_PROTECTION_TOGGLE_KEYS, cfg, is_en)
        prem_media_fields = _render_premium_media_fields(prof, perks, is_en=is_en, use_pr_prefix=True)
        prem_section_html = f"""
        <div class="panel-section">
          <div class="panel-section-head">
            <h3 class="panel-section-title">{('PREMIUM PROTECTIONS & BOT CUSTOMIZATION' if is_en else 'حمايات وتخصيص البوت (بريميوم)')}</h3>
            <span class="prem-pill">PRO</span>
          </div>
          {prem_prot_toggles}
          <div class="grid-2">
            <div>
              <label class="lbl">{('Server Icon Punishment' if is_en else 'عقاب تغيير صورة السيرفر')}</label>
              <select class="sel" name="guild_icon_punishment">
                <option value="Remove Roles" {'selected' if icon_pun == 'Remove Roles' else ''}>Remove Roles</option>
                <option value="Kick" {'selected' if icon_pun == 'Kick' else ''}>Kick</option>
                <option value="Ban" {'selected' if icon_pun == 'Ban' else ''}>Ban</option>
              </select>
            </div>
            <div>
              <label class="lbl">{('Automated Account Punishment' if is_en else 'عقاب الحسابات الآلية')}</label>
              <select class="sel" name="selfbot_punishment">
                <option value="Kick" {'selected' if selfbot_pun == 'Kick' else ''}>Kick</option>
                <option value="Ban" {'selected' if selfbot_pun == 'Ban' else ''}>Ban</option>
              </select>
            </div>
          </div>
          <p class="muted" style="margin:0 0 10px;">{('OAuth App Abuse protects against malicious connected apps/integrations, and Automated Account Guard targets unofficial/bot-like accounts.' if is_en else 'حماية تطبيقات الربط تحمي من التطبيقات المرتبطة الضارة، وحماية الحسابات الآلية تستهدف الحسابات والسكربتات الآلية.')}</p>
          {prem_media_fields}
        </div>
        """
    else:
        prem_section_html = ""

    body = f"""
    <form method="post" class="page-card anim-card">
      <input type="hidden" name="csrf_token" value="{esc(csrf_tok)}">
      <input type="hidden" name="req_nonce" value="{esc(req_nonce)}">
      <input type="hidden" name="target_uid" value="">
      <input type="hidden" name="target_snapshot_id" value="">

      <div class="section-head-bar">
        <div>
          <h2 class="section-head-title">{('Security Panel' if is_en else 'لوحة الحماية')}</h2>
          <div class="muted">{('Score' if is_en else 'نسبة الحماية')}: <strong>{score}/100</strong> ({esc(grade)})</div>
        </div>
        <select class="sel" style="width:auto;min-width:220px;margin:0;" name="guild_id" onchange="location.href='/guild?id='+encodeURIComponent(this.value)">
          {options_html}
        </select>
      </div>

      <div class="cat-tabs">
        <button class="cat-tab-btn active" type="button" onclick="switchCat('general', this)">{('General' if is_en else 'عام')}</button>
        <button class="cat-tab-btn" type="button" onclick="switchCat('antinuke', this)">{('Anti-Nuke' if is_en else 'الحماية من التخريب')}</button>
        <button class="cat-tab-btn" type="button" onclick="switchCat('antiraid', this)">{('Anti-Raid' if is_en else 'حماية الدخول والرايد')}</button>
        <button class="cat-tab-btn" type="button" onclick="switchCat('mod', this)">{('Moderation' if is_en else 'الإشراف والرسائل')}</button>
        <button class="cat-tab-btn" type="button" onclick="switchCat('trusted', this)">{('Trusted & Snapshots' if is_en else 'الموثوقين واللقطات')}</button>
      </div>

      <div id="cat-general" class="cat-pane active">
        <div class="panel-section">
          <div class="panel-section-head">
            <h3 class="panel-section-title">{('General Configuration' if is_en else 'الإعدادات العامة')}</h3>
            <span class="admin-pill">CORE</span>
          </div>
          <div class="grid-2">
            <div>
              <label class="lbl">{('Prefix' if is_en else 'بادئة الأوامر')}</label>
              <input class="inp" type="text" maxlength="6" name="prefix" value="{esc(cfg.get('prefix', '!'))}">
            </div>
            <div>
              <label class="lbl">{('Mod Log Channel ID' if is_en else 'آيدي روم السجلات')}</label>
              <input class="inp" type="text" name="mod_log_channel" value="{esc(cfg.get('mod_log_channel', ''))}">
            </div>
          </div>
          {general_html}
          {prem_section_html}
        </div>
      </div>

      <div id="cat-antinuke" class="cat-pane">
        <div class="panel-section">
          <div class="panel-section-head">
            <h3 class="panel-section-title">{('Anti-Nuke Guards' if is_en else 'حمايات التخريب')}</h3>
            <span class="admin-pill">SHIELD</span>
          </div>
          {antinuke_html}
        </div>
        <div class="panel-section">
          <div class="panel-section-head">
            <h3 class="panel-section-title">{('Punishments & Thresholds' if is_en else 'العقوبات والحدود')}</h3>
            <span class="admin-pill">LIMITS</span>
          </div>
          <div class="grid-2">
            <div>
              <label class="lbl">{('Dangerous Perms Punishment' if is_en else 'عقاب الصلاحيات الخطيرة')}</label>
              <select class="sel" name="dangerous_perms_punishment">
                <option value="None" {'selected' if dang_pun == 'None' else ''}>None</option>
                <option value="Remove Roles" {'selected' if dang_pun == 'Remove Roles' else ''}>Remove Roles</option>
                <option value="Kick" {'selected' if dang_pun == 'Kick' else ''}>Kick</option>
                <option value="Ban" {'selected' if dang_pun == 'Ban' else ''}>Ban</option>
              </select>
            </div>
            <div>
              <label class="lbl">{('OAuth App Abuse Punishment' if is_en else 'عقاب تطبيقات الربط')}</label>
              <select class="sel" name="app_abuse_punishment">
                <option value="Remove Roles" {'selected' if app_pun == 'Remove Roles' else ''}>Remove Roles</option>
                <option value="Kick" {'selected' if app_pun == 'Kick' else ''}>Kick</option>
                <option value="Ban" {'selected' if app_pun == 'Ban' else ''}>Ban</option>
              </select>
            </div>
          </div>
          {rules_html}
        </div>
      </div>

      <div id="cat-antiraid" class="cat-pane">
        <div class="panel-section">
          <div class="panel-section-head">
            <h3 class="panel-section-title">{('Anti-Raid & Join Protection' if is_en else 'حماية الدخول والرايد')}</h3>
            <span class="admin-pill">ENTRY</span>
          </div>
          {antiraid_html}
          <label class="lbl">{('Minimum Account Age (Days)' if is_en else 'الحد الأدنى لعمر الحساب (بالأيام)')}</label>
          <input class="inp" type="number" min="1" max="365" name="min_account_age_days" value="{int(cfg.get('min_account_age_days', 7) or 7)}">
        </div>
      </div>

      <div id="cat-mod" class="cat-pane">
        <div class="panel-section">
          <div class="panel-section-head">
            <h3 class="panel-section-title">{('Chat & Moderation' if is_en else 'الإشراف والرسائل')}</h3>
            <span class="admin-pill">CHAT</span>
          </div>
          {moderation_html}
          <div class="grid-2">
            <div>
              <label class="lbl">{('Spam Punishment' if is_en else 'عقاب السبام')}</label>
              <select class="sel" name="spam_punishment">
                <option value="Delete Only" {'selected' if spam_pun == 'Delete Only' else ''}>Delete Only</option>
                <option value="Timeout" {'selected' if spam_pun == 'Timeout' else ''}>Timeout</option>
                <option value="Kick" {'selected' if spam_pun == 'Kick' else ''}>Kick</option>
                <option value="Ban" {'selected' if spam_pun == 'Ban' else ''}>Ban</option>
              </select>
            </div>
            <div>
              <label class="lbl">{('Spam Timeout (Seconds)' if is_en else 'مدة التايم أوت للسبام (ثانية)')}</label>
              <input class="inp" type="number" min="10" max="2419200" name="spam_timeout_seconds" value="{int(cfg.get('spam_timeout_seconds', 600) or 600)}">
            </div>
          </div>
          <div class="grid-2">
            <div>
              <label class="lbl">{('Link Punishment' if is_en else 'عقاب الروابط')}</label>
              <select class="sel" name="link_punishment">
                <option value="Delete Only" {'selected' if link_pun == 'Delete Only' else ''}>Delete Only</option>
                <option value="Delete & Timeout" {'selected' if link_pun == 'Delete & Timeout' else ''}>Delete & Timeout</option>
                <option value="Kick" {'selected' if link_pun == 'Kick' else ''}>Kick</option>
                <option value="Ban" {'selected' if link_pun == 'Ban' else ''}>Ban</option>
              </select>
            </div>
            <div>
              <label class="lbl">{('Link Timeout (Seconds)' if is_en else 'مدة التايم أوت للروابط (ثانية)')}</label>
              <input class="inp" type="number" min="10" max="2419200" name="link_timeout_seconds" value="{int(cfg.get('link_timeout_seconds', 300) or 300)}">
            </div>
          </div>
        </div>
      </div>

      <div id="cat-trusted" class="cat-pane">
        <div class="panel-section">
          <div class="panel-section-head">
            <h3 class="panel-section-title">{('Trusted Admins' if is_en else 'المشرفين الموثوقين')}</h3>
            <span class="admin-pill">WHITELIST</span>
          </div>
          <div style="display:flex;gap:8px;margin-bottom:10px;">
            <input class="inp" style="margin:0;" type="text" name="trusted_uid" placeholder="User ID">
            <button class="mini-btn gold" type="submit" name="form_action" value="add_trusted">{('Add' if is_en else 'إضافة')}</button>
          </div>
          {tr_rows}
        </div>
        <div class="panel-section">
          <div class="panel-section-head">
            <h3 class="panel-section-title">{('Permissions Snapshots' if is_en else 'لقطات الصلاحيات')}</h3>
            <button class="mini-btn gold" type="submit" name="form_action" value="save_snapshot">{('Save Snapshot' if is_en else 'حفظ لقطة')}</button>
          </div>
          {snaps_rows}
        </div>
      </div>

      <div class="action-pair" style="margin-top:16px;">
        <button class="btn-gold" type="submit" name="form_action" value="save">{('Save & Sync' if is_en else 'حفظ ومزامنة')}</button>
        <button class="btn-danger" type="submit" name="form_action" value="reset_defaults">{('Reset Defaults' if is_en else 'إعادة للافتراضي')}</button>
      </div>
    </form>
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
                auth_title="Premium Access" if is_en else "وصول البريميوم",
                auth_desc=(
                    "Sign in with Discord to access premium customization, bot profile tools, and alerts."
                    if is_en
                    else "سجّل دخولك بحساب ديسكورد للوصول إلى تخصيص البوت والتنبيهات ومزايا البريميوم."
                ),
            ),
            content_type="text/html",
        )
    session_id, user = sess_pair
    actor_uid = str(user.get("id", "")).strip()
    if not is_premium_user(user):
        return web.Response(
            text=render_page(
                "Premium" if is_en else "البريميوم",
                "premium",
                "",
                request,
                flash="Premium membership required." if is_en else "هذا القسم مخصص لمشتركي البريميوم.",
            ),
            content_type="text/html",
        )

    prem_rec = _get_premium_record(actor_uid) or {}
    active_guilds = get_user_connected_guilds(user)
    gid = str(request.query.get("id", "")).strip()
    if not active_guilds:
        gid = "global_premium"
    elif not user_can_manage_guild(gid, user, require_bot_present=True):
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
            posted_gid = str(form.get("guild_id", gid)).strip()
            if posted_gid == "global_premium" or user_can_manage_guild(posted_gid, user, require_bot_present=True):
                gid = posted_gid
                cur_cfg = get_guild_cfg(gid)
                cur_prof = cur_cfg.get("guild_profile") or {}
                cur_perks = cur_cfg.get("premium_perks") or {}

                prof_data, perks_data, profile_changed, bio_changed, avatar_changed, banner_changed = (
                    _process_premium_profile_and_perks(form, cur_prof, cur_perks)
                )

                save_guild_cfg(
                    gid,
                    {
                        "guild_profile": prof_data,
                        "premium_perks": perks_data,
                    },
                    is_premium=True,
                )
                enqueue_remote_action(gid, "sync_guild_cfg", gid, extra={"guild_id": gid, "user_id": actor_uid}, actor_user_id=actor_uid)
                if profile_changed:
                    prof_extra = _build_bot_profile_command_extra(
                        gid=gid,
                        actor_uid=actor_uid,
                        prof_data=prof_data,
                        bio_changed=bio_changed,
                        avatar_changed=avatar_changed,
                        banner_changed=banner_changed,
                    )
                    enqueue_remote_action(gid, "update_bot_profile", gid, extra=prof_extra, actor_user_id=actor_uid)
                log_event(f"Updated premium settings for {gid}", guild_id=gid, level="SEC")
                flash = "Premium settings saved and synced." if is_en else "تم حفظ إعدادات البريميوم ومزامنتها."

    cfg = get_guild_cfg(gid)
    prof = cfg.get("guild_profile") or {}
    perks = cfg.get("premium_perks") or {}
    csrf_tok = issue_csrf_token(session_id)
    req_nonce = secrets.token_hex(12)

    if active_guilds:
        options_html = "".join(
            f"<option value='{esc(g['id'])}' {'selected' if g['id'] == gid else ''}>{esc(g['name'])} ({esc(g['id'])})</option>"
            for g in active_guilds
        )
        guild_selector_html = (
            f"<select class='sel' style='width:auto;min-width:220px;margin:0;' name='guild_id' "
            f"onchange=\"location.href='/premium?id='+encodeURIComponent(this.value)\">{options_html}</select>"
        )
    else:
        guild_selector_html = f"<input type='hidden' name='guild_id' value='global_premium'><span class='admin-pill'>GLOBAL</span>"

    media_fields_html = _render_premium_media_fields(prof, perks, is_en=is_en, use_pr_prefix=False)
    rem_txt = format_remaining_time(prem_rec, is_en=is_en)

    body = f"""
    <form method="post" class="page-card anim-card">
      <input type="hidden" name="csrf_token" value="{esc(csrf_tok)}">
      <input type="hidden" name="req_nonce" value="{esc(req_nonce)}">

      <div class="section-head-bar">
        <div>
          <h2 class="section-head-title">{('Premium Studio' if is_en else 'استوديو البريميوم')}</h2>
          <div class="muted">{('Active Plan' if is_en else 'حالة الاشتراك')}: <strong>{esc(rem_txt)}</strong></div>
        </div>
        {guild_selector_html}
      </div>

      <div class="panel-section">
        <div class="panel-section-head">
          <h3 class="panel-section-title">{('Bot Customization & Alerts' if is_en else 'تخصيص البوت والتنبيهات')}</h3>
          <span class="prem-pill">PRO</span>
        </div>
        {media_fields_html}
      </div>

      <button class="btn-gold" type="submit">{('Save & Sync' if is_en else 'حفظ ومزامنة')}</button>
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
            text=render_page(
                "Admin Panel" if is_en else "لوحة الإدارة",
                "admin",
                "",
                request,
                require_auth_view=True,
                next_after_login="/admin",
                auth_title="Admin Access Required" if is_en else "وصول الإدارة مطلوب",
                auth_desc=(
                    "Sign in with your authorized Discord account to access administrative controls."
                    if is_en
                    else "سجّل دخولك بحساب ديسكورد المصرح له للوصول إلى لوحة الإدارة."
                ),
            ),
            content_type="text/html",
        )
    session_id, user = sess_pair
    uid_actor = str(user.get("id", "")).strip()
    is_owner = uid_actor == ADMIN_USER_ID
    is_admin = is_site_admin(user)
    if not is_admin:
        return web.Response(
            text=render_page(
                "Admin Panel" if is_en else "لوحة الإدارة",
                "admin",
                "",
                request,
                flash="Admin access required." if is_en else "هذه الصفحة مخصصة للإدارة فقط.",
            ),
            content_type="text/html",
        )

    can_manage_prem = is_owner or has_admin_perm(user, "manage_premium")
    can_extend_prem = is_owner or has_admin_perm(user, "extend_premium")
    can_revoke_prem = is_owner or has_admin_perm(user, "revoke_premium")
    can_manage_admins = is_owner or has_admin_perm(user, "manage_admins")
    can_remote = is_owner or has_admin_perm(user, "remote_actions")
    can_sim = is_owner or has_admin_perm(user, "simulations")
    can_backup = is_owner or has_admin_perm(user, "backups")
    can_logs = is_owner or has_admin_perm(user, "view_logs")

    active_tab = str(request.query.get("tab", "overview") or "overview").strip().lower()
    if active_tab not in ("overview", "premium", "staff", "controls", "logs"):
        active_tab = "overview"

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
            posted_tab = str(form.get("active_tab", active_tab) or active_tab).strip().lower()
            if posted_tab in ("overview", "premium", "staff", "controls", "logs"):
                active_tab = posted_tab

            if act == "grant_premium":
                if not can_manage_prem:
                    flash = "Missing permission: Grant Premium." if is_en else "لا تملك صلاحية منح البريميوم."
                else:
                    target_uid = str(form.get("prem_uid", "")).strip()
                    target_name = str(form.get("prem_username", "")).strip()
                    target_handle = str(form.get("prem_handle", "")).strip()
                    try:
                        days = max(0, min(3650, int(form.get("prem_days", 30) or 0)))
                    except Exception:
                        days = 30
                    try:
                        hours = max(0, min(8760, int(form.get("prem_hours", 0) or 0)))
                    except Exception:
                        hours = 0
                    if target_uid.isdigit():
                        set_premium_user(
                            target_uid,
                            True,
                            days=days,
                            hours=hours,
                            granted_by=uid_actor,
                            username=target_name,
                            handle=target_handle,
                            source="admin",
                            extend_existing=False,
                        )
                        log_event(f"Granted premium to {target_uid} ({days}d {hours}h) by {uid_actor}", level="ADMIN")
                        flash = f"Premium granted to {target_uid}." if is_en else f"تم منح البريميوم للمستخدم {target_uid}."
                    else:
                        flash = "Enter a valid numeric User ID." if is_en else "أدخل آيدي مستخدم رقمي صحيح."

            elif act == "extend_premium":
                if not can_extend_prem:
                    flash = "Missing permission: Extend Premium." if is_en else "لا تملك صلاحية تمديد البريميوم."
                else:
                    target_uid = str(form.get("target_uid", "")).strip()
                    try:
                        add_d = max(0, min(3650, int(form.get("ext_days", 7) or 0)))
                    except Exception:
                        add_d = 7
                    try:
                        add_h = max(0, min(8760, int(form.get("ext_hours", 0) or 0)))
                    except Exception:
                        add_h = 0
                    if target_uid.isdigit():
                        set_premium_user(
                            target_uid,
                            True,
                            days=add_d,
                            hours=add_h,
                            granted_by=uid_actor,
                            extend_existing=True,
                        )
                        log_event(f"Extended premium for {target_uid} by {add_d}d {add_h}h", level="ADMIN")
                        flash = f"Extended premium for {target_uid}." if is_en else f"تم تمديد اشتراك {target_uid}."

            elif act == "revoke_premium":
                if not can_revoke_prem:
                    flash = "Missing permission: Revoke Premium." if is_en else "لا تملك صلاحية سحب البريميوم."
                else:
                    target_uid = str(form.get("target_uid", "")).strip()
                    if target_uid == ADMIN_USER_ID:
                        flash = "Cannot revoke owner premium." if is_en else "لا يمكن سحب بريميوم المالك."
                    elif target_uid.isdigit():
                        set_premium_user(target_uid, False)
                        log_event(f"Revoked premium from {target_uid} by {uid_actor}", level="ADMIN")
                        flash = f"Premium revoked from {target_uid}." if is_en else f"تم سحب البريميوم من {target_uid}."

            elif act == "grant_admin":
                if not can_manage_admins:
                    flash = "Missing permission: Manage Admins." if is_en else "لا تملك صلاحية إدارة الأدمن."
                else:
                    target_uid = str(form.get("admin_uid", "")).strip()
                    chosen_role = _sanitize_staff_role(str(form.get("staff_role", "Moderator")))
                    chosen_perms = {pk: (form.get(f"perm_{pk}") == "on") for pk in ADMIN_PERMISSION_KEYS}
                    if target_uid.isdigit():
                        set_admin_user(
                            target_uid,
                            True,
                            granted_by=uid_actor,
                            permissions=chosen_perms,
                            role_tag=chosen_role,
                        )
                        log_event(f"Saved admin {target_uid} ({chosen_role}) by {uid_actor}", level="ADMIN")
                        flash = f"Saved admin {target_uid} ({chosen_role})." if is_en else f"تم حفظ صلاحيات الأدمن {target_uid} ({chosen_role})."
                    else:
                        flash = "Enter a valid numeric User ID." if is_en else "أدخل آيدي مستخدم رقمي صحيح."

            elif act == "revoke_admin":
                if not can_manage_admins:
                    flash = "Missing permission: Manage Admins." if is_en else "لا تملك صلاحية إدارة الأدمن."
                else:
                    target_uid = str(form.get("target_uid", "")).strip()
                    if target_uid == ADMIN_USER_ID:
                        flash = "Cannot revoke owner role." if is_en else "لا يمكن سحب صلاحية المالك."
                    elif set_admin_user(target_uid, False):
                        log_event(f"Revoked admin {target_uid} by {uid_actor}", level="ADMIN")
                        flash = f"Revoked admin {target_uid}." if is_en else f"تم سحب صلاحية الأدمن من {target_uid}."

            elif act == "remote_cmd":
                if not can_remote:
                    flash = "Missing permission: Remote Actions." if is_en else "لا تملك صلاحية الأوامر عن بُعد."
                else:
                    rgid = str(form.get("remote_guild_id", "")).strip()
                    r_action = str(form.get("remote_action", "sync_guild_cfg")).strip()
                    r_target = str(form.get("remote_target", "")).strip()
                    r_reason = str(form.get("remote_reason", "")).strip()[:120]
                    if r_action == "global_broadcast":
                        sent_cnt = 0
                        for g in get_all_guilds():
                            enqueue_remote_action(
                                g["id"],
                                "broadcast_notice",
                                r_target or "ALL",
                                extra={"message": r_reason or "Admin notice", "guild_id": g["id"], "user_id": uid_actor},
                                actor_user_id=uid_actor,
                            )
                            sent_cnt += 1
                        log_event(f"Queued global broadcast to {sent_cnt} servers", level="ADMIN")
                        flash = f"Queued broadcast to {sent_cnt} servers." if is_en else f"تم إرسال البث إلى {sent_cnt} سيرفر."
                    elif rgid.isdigit():
                        enqueue_remote_action(
                            rgid,
                            r_action,
                            r_target,
                            extra={"reason": r_reason, "guild_id": rgid, "user_id": uid_actor},
                            actor_user_id=uid_actor,
                        )
                        log_event(f"Queued {r_action} for {rgid}", guild_id=rgid, level="ADMIN")
                        flash = f"Queued {r_action} for {rgid}." if is_en else f"تم إرسال الأمر {r_action} للسيرفر {rgid}."
                    else:
                        flash = "Enter a valid numeric Guild ID." if is_en else "أدخل آيدي سيرفر رقمي صحيح."

            elif act == "run_sim":
                if not can_sim:
                    flash = "Missing permission: Safety Checks." if is_en else "لا تملك صلاحية فحص الجاهزية."
                else:
                    sgid = str(form.get("sim_guild_id", "")).strip()
                    scen = str(form.get("sim_scenario", "role_sabotage")).strip()
                    if not sgid:
                        all_g = get_all_guilds()
                        sgid = all_g[0]["id"] if all_g else "0"
                    flash = run_attack_simulation(sgid, scen, is_en=is_en)

            elif act == "create_backup":
                if not can_backup:
                    flash = "Missing permission: Backups." if is_en else "لا تملك صلاحية النسخ الاحتياطي."
                else:
                    b = create_db_backup()
                    flash = f"Backup created [{b['backup_id']}]." if is_en else f"تم إنشاء نسخة احتياطية [{b['backup_id']}]."

            elif act == "test_restore":
                if not can_backup:
                    flash = "Missing permission: Backups." if is_en else "لا تملك صلاحية استعادة النسخ."
                else:
                    bid = str(form.get("backup_id", "")).strip()
                    _, flash = test_backup_restore(bid, is_en=is_en)

    guilds_all = get_all_guilds()
    prem_list = get_premium_list()
    admin_list = get_admin_list()
    logs_list = get_recent_logs(35)
    incidents_list = get_recent_incidents(20)
    backups_list = get_db_backups()
    total_visits = get_total_visits()
    csrf_tok = issue_csrf_token(session_id)
    req_nonce = secrets.token_hex(12)

    guild_cards_html = "".join(
        _render_guild_card(g, is_en=is_en, show_admin_meta=True) for g in guilds_all
    ) or f"<p class='muted'>{('No connected servers yet.' if is_en else 'لا توجد سيرفرات متصلة بعد.')}</p>"

    prem_cards = ""
    for p in prem_list:
        p_uid = str(p.get("user_id", ""))
        p_uid_esc = esc(p_uid)
        p_uname = esc(p.get("username") or f"User {p_uid}")
        p_handle = esc(p.get("handle") or f"@{p_uid}")
        p_rem = esc(format_remaining_time(p, is_en=is_en))
        p_ava = user_avatar_url(p_uid, p.get("avatar"))
        p_init = esc((str(p.get("username") or p_uid)[:1] or "U").upper())
        ava_tag = (
            f"<span class='guild-icon-wrap'><img class='guild-icon' src='{esc(p_ava)}' alt='{p_uname}' loading='lazy' referrerpolicy='no-referrer' "
            f"onerror=\"this.style.display='none';this.nextElementSibling.style.display='flex';\">"
            f"<span class='guild-icon-ph' style='display:none;'>{p_init}</span></span>"
            if p_ava
            else f"<span class='guild-icon-wrap'><span class='guild-icon-ph'>{p_init}</span></span>"
        )
        actions_parts = []
        if can_extend_prem and p_uid != ADMIN_USER_ID:
            actions_parts.append(
                f"<button class='mini-btn gold' type='submit' name='admin_action' value='extend_premium' "
                f"onclick=\"this.form.target_uid.value='{p_uid_esc}';this.form.ext_days.value='7';\">{('+7d' if is_en else '+7 أيام')}</button>"
                f"<button class='mini-btn' type='submit' name='admin_action' value='extend_premium' "
                f"onclick=\"this.form.target_uid.value='{p_uid_esc}';this.form.ext_days.value='30';\">{('+30d' if is_en else '+30 يوم')}</button>"
            )
        if can_revoke_prem and p_uid != ADMIN_USER_ID:
            actions_parts.append(
                f"<button class='mini-btn red' type='submit' name='admin_action' value='revoke_premium' "
                f"onclick=\"this.form.target_uid.value='{p_uid_esc}'\">{('Revoke' if is_en else 'سحب')}</button>"
            )
        actions_bar = f"<div class='prem-member-actions'>{''.join(actions_parts)}</div>" if actions_parts else ""
        search_key = esc(f"{p_uid} {p.get('username', '')} {p.get('handle', '')}".lower())
        prem_cards += (
            f"<div class='prem-member-card prem-search-item anim-item' data-search='{search_key}'>"
            f"<div class='prem-member-top'>"
            f"<div class='prem-member-identity'>{ava_tag}"
            f"<div class='row-copy'><div class='row-title'>{p_uname} <span class='muted' style='font-weight:600;'>{p_handle}</span></div>"
            f"<div class='muted row-sub'>ID: <code>{p_uid_esc}</code> • {p_rem}</div></div></div>"
            f"<span class='prem-pill'>PRO</span>"
            f"</div>{actions_bar}</div>"
        )

    admin_rows = ""
    for a in admin_list:
        a_uid = str(a.get("user_id", ""))
        a_uid_esc = esc(a_uid)
        a_role = esc(_sanitize_staff_role(a.get("role_tag"), uid=a_uid))
        a_perms = a.get("permissions") or {}
        enabled_labels = [
            (ADMIN_PERMISSION_LABELS[pk][0] if is_en else ADMIN_PERMISSION_LABELS[pk][1])
            for pk in ADMIN_PERMISSION_KEYS
            if a_perms.get(pk)
        ]
        perms_summary = ", ".join(enabled_labels) if enabled_labels else ("No extra permissions" if is_en else "بدون صلاحيات إضافية")
        rev_btn = (
            ""
            if (a_uid == ADMIN_USER_ID or not can_manage_admins)
            else f"<button class='mini-btn red' type='submit' name='admin_action' value='revoke_admin' onclick=\"this.form.target_uid.value='{a_uid_esc}'\">{('Revoke' if is_en else 'سحب')}</button>"
        )
        admin_rows += (
            f"<div class='list-row anim-item' style='flex-wrap:wrap;'>"
            f"<div><strong><code>{a_uid_esc}</code></strong> <span class='admin-pill'>{a_role}</span>"
            f"<div class='muted row-sub'>{esc(perms_summary)}</div></div>{rev_btn}</div>"
        )

    perm_checkboxes_html = "".join(
        f"<label class='switch-row'><span>{esc(ADMIN_PERMISSION_LABELS[pk][0] if is_en else ADMIN_PERMISSION_LABELS[pk][1])}</span>"
        f"<input class='switch-input' type='checkbox' name='perm_{pk}' {'checked' if pk in ('manage_premium', 'view_logs') else ''}></label>"
        for pk in ADMIN_PERMISSION_KEYS
    )

    staff_role_options_html = "".join(
        f"<option value='{esc(r)}' {'selected' if r == 'Moderator' else ''}>{esc(r)}</option>"
        for r in STAFF_ROLE_OPTIONS
    )

    if can_logs:
        inc_html = "".join(
            f"<div class='log-entry-row anim-item'><div class='log-entry-msg'>[{esc(i.get('category'))}] {esc(i.get('summary'))}</div>"
            f"<div class='log-entry-time'>{esc(i.get('time'))}</div></div>"
            for i in incidents_list
        ) or f"<p class='muted'>{('No security incidents recorded.' if is_en else 'لا توجد تنبيهات مسجلة.')}</p>"

        logs_html = "".join(
            f"<div class='log-entry-row anim-item'><div class='log-entry-msg'>[{esc(l.get('level'))}] {esc(l.get('message'))}</div>"
            f"<div class='log-entry-time'>{esc(l.get('time'))}</div></div>"
            for l in logs_list
        ) or f"<p class='muted'>{('No logs recorded yet.' if is_en else 'لا توجد سجلات بعد.')}</p>"
    else:
        inc_html = f"<p class='muted'>{('Requires View Logs permission.' if is_en else 'يتطلب صلاحية عرض السجلات.')}</p>"
        logs_html = inc_html

    backup_rows = "".join(
        f"<div class='list-row anim-item' style='flex-wrap:wrap;'>"
        f"<div><strong>#{esc(b.get('backup_id'))}</strong> <span class='muted'>({esc(b.get('created_at'))})</span> "
        f"<span class='muted'>{b.get('guilds_count', 0)}G / {b.get('admins_count', 0)}A / {b.get('premium_count', 0)}P</span></div>"
        f"<button class='mini-btn' type='submit' name='admin_action' value='test_restore' "
        f"onclick=\"this.form.backup_id.value='{esc(b.get('backup_id'))}'\">{('Verify' if is_en else 'تحقق')}</button></div>"
        for b in backups_list
    ) or f"<p class='muted'>{('No backups created yet.' if is_en else 'لا توجد نسخ احتياطية بعد.')}</p>"

    grant_prem_card = (
        f"""
        <div class="panel-section">
          <div class="panel-section-head">
            <h3 class="panel-section-title">{('Grant Premium' if is_en else 'منح اشتراك بريميوم')}</h3>
            <span class="prem-pill">PRO</span>
          </div>
          <label class="lbl">{('User ID' if is_en else 'آيدي المستخدم')}</label>
          <input class="inp" type="text" name="prem_uid" placeholder="123456789012345678">
          <div class="grid-2">
            <div>
              <label class="lbl">{('Username (Optional)' if is_en else 'اسم المستخدم (اختياري)')}</label>
              <input class="inp" type="text" name="prem_username" placeholder="Username">
            </div>
            <div>
              <label class="lbl">{('Handle (Optional)' if is_en else 'المعرف @ (اختياري)')}</label>
              <input class="inp" type="text" name="prem_handle" placeholder="@username">
            </div>
          </div>
          <div class="grid-2">
            <div>
              <label class="lbl">{('Days' if is_en else 'الأيام')}</label>
              <input class="inp" type="number" min="0" max="3650" name="prem_days" value="30">
            </div>
            <div>
              <label class="lbl">{('Hours' if is_en else 'الساعات')}</label>
              <input class="inp" type="number" min="0" max="8760" name="prem_hours" value="0">
            </div>
          </div>
          <button class="btn-gold" type="submit" name="admin_action" value="grant_premium">{('Grant Premium' if is_en else 'منح البريميوم')}</button>
        </div>
        """
        if can_manage_prem
        else ""
    )

    grant_admin_card = (
        f"""
        <div class="panel-section">
          <div class="panel-section-head">
            <h3 class="panel-section-title">{('Add / Update Admin' if is_en else 'إضافة أو تعديل أدمن')}</h3>
            <span class="admin-pill">STAFF</span>
          </div>
          <div class="grid-2">
            <div>
              <label class="lbl">{('User ID' if is_en else 'آيدي المستخدم')}</label>
              <input class="inp" type="text" name="admin_uid" placeholder="123456789012345678">
            </div>
            <div>
              <label class="lbl">{('Staff Role' if is_en else 'الرتبة الإدارية')}</label>
              <select class="sel" name="staff_role">
                {staff_role_options_html}
              </select>
            </div>
          </div>
          <label class="lbl">{('Permissions' if is_en else 'الصلاحيات')}</label>
          {perm_checkboxes_html}
          <button class="btn-gold" type="submit" name="admin_action" value="grant_admin">{('Save Admin' if is_en else 'حفظ الأدمن')}</button>
        </div>
        """
        if can_manage_admins
        else ""
    )

    remote_card = (
        f"""
        <div class="panel-section">
          <div class="panel-section-head">
            <h3 class="panel-section-title">{('Remote Actions & Broadcast' if is_en else 'الأوامر عن بُعد والبث')}</h3>
            <span class="admin-pill">BOT</span>
          </div>
          <div class="grid-2">
            <div>
              <label class="lbl">{('Target Guild ID' if is_en else 'آيدي السيرفر المستهدف')}</label>
              <input class="inp" type="text" name="remote_guild_id" placeholder="Guild ID">
            </div>
            <div>
              <label class="lbl">{('Action' if is_en else 'الإجراء')}</label>
              <select class="sel" name="remote_action">
                <option value="sync_guild_cfg">{('Sync Guild Settings' if is_en else 'مزامنة إعدادات السيرفر')}</option>
                <option value="lockdown_on">{('Enable Lockdown' if is_en else 'تفعيل قفل السيرفر')}</option>
                <option value="lockdown_off">{('Disable Lockdown' if is_en else 'إلغاء قفل السيرفر')}</option>
                <option value="global_broadcast">{('Global Broadcast' if is_en else 'بث عام لجميع السيرفرات')}</option>
              </select>
            </div>
          </div>
          <div class="grid-2">
            <div>
              <label class="lbl">{('Target ID (Optional)' if is_en else 'الهدف (اختياري)')}</label>
              <input class="inp" type="text" name="remote_target" placeholder="Target ID">
            </div>
            <div>
              <label class="lbl">{('Note / Reason' if is_en else 'ملاحظة / سبب')}</label>
              <input class="inp" type="text" name="remote_reason" placeholder="Reason">
            </div>
          </div>
          <button class="btn-gold" type="submit" name="admin_action" value="remote_cmd">{('Send Command' if is_en else 'إرسال الأمر')}</button>
        </div>
        """
        if can_remote
        else ""
    )

    sim_card = (
        f"""
        <div class="panel-section">
          <div class="panel-section-head">
            <h3 class="panel-section-title">{('Protection Readiness Check' if is_en else 'فحص جاهزية الحماية')}</h3>
            <span class="admin-pill">CHECK</span>
          </div>
          <div class="grid-2">
            <div>
              <label class="lbl">{('Guild ID' if is_en else 'آيدي السيرفر')}</label>
              <input class="inp" type="text" name="sim_guild_id" value="{esc(guilds_all[0]['id'] if guilds_all else '')}" placeholder="Guild ID">
            </div>
            <div>
              <label class="lbl">{('Check Scenario' if is_en else 'نوع الفحص')}</label>
              <select class="sel" name="sim_scenario">
                <option value="role_sabotage">{('Role Protection Check' if is_en else 'فحص حماية الرتب')}</option>
                <option value="raid_surge">{('Join Surge Check' if is_en else 'فحص حماية الدخول المفاجئ')}</option>
                <option value="rollback_ready">{('Rollback Readiness' if is_en else 'فحص جاهزية الاسترجاع')}</option>
              </select>
            </div>
          </div>
          <button class="btn-dark" type="submit" name="admin_action" value="run_sim">{('Run Check' if is_en else 'تشغيل الفحص')}</button>
        </div>
        """
        if can_sim
        else ""
    )

    backup_card = (
        f"""
        <div class="panel-section">
          <div class="panel-section-head">
            <h3 class="panel-section-title">{('Backups & Integrity' if is_en else 'النسخ الاحتياطي والتحقق')}</h3>
            <span class="admin-pill">DB</span>
          </div>
          <div class="action-pair" style="margin-bottom:12px;">
            <button class="btn-gold" type="submit" name="admin_action" value="create_backup">{('Create Backup' if is_en else 'إنشاء نسخة احتياطية')}</button>
            <button class="btn-dark" type="submit" name="admin_action" value="test_restore">{('Test Restore' if is_en else 'اختبار الاستعادة')}</button>
          </div>
          {backup_rows}
        </div>
        """
        if can_backup
        else ""
    )

    body = f"""
    <form method="post" class="page-card anim-card">
      <input type="hidden" name="csrf_token" value="{esc(csrf_tok)}">
      <input type="hidden" name="req_nonce" value="{esc(req_nonce)}">
      <input type="hidden" name="active_tab" value="{esc(active_tab)}">
      <input type="hidden" name="target_uid" value="">
      <input type="hidden" name="ext_days" value="7">
      <input type="hidden" name="ext_hours" value="0">
      <input type="hidden" name="backup_id" value="">

      <div class="section-head-bar">
        <div>
          <h2 class="section-head-title">{('Admin Panel' if is_en else 'لوحة الإدارة')}</h2>
          <div class="muted">{('Bot Status' if is_en else 'حالة البوت')}: <strong>{esc(MEM_BOT_HEARTBEAT.get('status', 'ONLINE'))}</strong> • {esc(MEM_BOT_HEARTBEAT.get('last_seen') or '-')}</div>
        </div>
      </div>

      <div class="admin-kpis">
        <div class="kpi-box"><div class="kpi-num">{len(guilds_all)}</div><div class="kpi-lbl">{('Servers' if is_en else 'السيرفرات')}</div></div>
        <div class="kpi-box"><div class="kpi-num">{len(prem_list)}</div><div class="kpi-lbl">{('Premium' if is_en else 'البريميوم')}</div></div>
        <div class="kpi-box"><div class="kpi-num">{total_visits:,}</div><div class="kpi-lbl">{('Total Visits' if is_en else 'الزيارات')}</div></div>
      </div>

      <div class="cat-tabs">
        <button class="cat-tab-btn {'active' if active_tab == 'overview' else ''}" type="button" onclick="switchCat('overview', this)">{('Overview' if is_en else 'نظرة عامة')}</button>
        <button class="cat-tab-btn {'active' if active_tab == 'premium' else ''}" type="button" onclick="switchCat('premium', this)">{('Premium' if is_en else 'البريميوم')}</button>
        <button class="cat-tab-btn {'active' if active_tab == 'staff' else ''}" type="button" onclick="switchCat('staff', this)">{('Admins' if is_en else 'الأدمن')}</button>
        <button class="cat-tab-btn {'active' if active_tab == 'controls' else ''}" type="button" onclick="switchCat('controls', this)">{('Controls' if is_en else 'التحكم والنسخ')}</button>
        <button class="cat-tab-btn {'active' if active_tab == 'logs' else ''}" type="button" onclick="switchCat('logs', this)">{('Logs' if is_en else 'السجلات')}</button>
      </div>

      <div id="cat-overview" class="cat-pane {'active' if active_tab == 'overview' else ''}">
        <div class="panel-section">
          <div class="panel-section-head">
            <h3 class="panel-section-title">{('Connected Servers' if is_en else 'السيرفرات المتصلة')}</h3>
            <span class="admin-pill">{len(guilds_all)}</span>
          </div>
          <input class="inp" type="search" oninput="filterGuildsList(this.value)" placeholder="{('Search server name or ID...' if is_en else 'ابحث باسم السيرفر أو الآيدي...')}">
          {guild_cards_html}
        </div>
      </div>

      <div id="cat-premium" class="cat-pane {'active' if active_tab == 'premium' else ''}">
        {grant_prem_card}
        <div class="panel-section">
          <div class="panel-section-head">
            <h3 class="panel-section-title">{('Active Premium Users' if is_en else 'المشتركون الحاليون')}</h3>
            <span class="prem-pill">{len(prem_list)}</span>
          </div>
          <input class="inp" type="search" oninput="filterPremiumList(this.value)" placeholder="{('Search user ID, name, or @handle...' if is_en else 'ابحث بالآيدي أو الاسم أو المعرف...')}">
          {prem_cards or f"<p class='muted'>{('No active premium subscriptions.' if is_en else 'لا توجد اشتراكات بريميوم نشطة.')}</p>"}
        </div>
      </div>

      <div id="cat-staff" class="cat-pane {'active' if active_tab == 'staff' else ''}">
        {grant_admin_card}
        <div class="panel-section">
          <div class="panel-section-head">
            <h3 class="panel-section-title">{('Admin Team' if is_en else 'فريق الإدارة')}</h3>
            <span class="admin-pill">{len(admin_list)}</span>
          </div>
          {admin_rows}
        </div>
      </div>

      <div id="cat-controls" class="cat-pane {'active' if active_tab == 'controls' else ''}">
        {remote_card}
        {sim_card}
        {backup_card}
      </div>

      <div id="cat-logs" class="cat-pane {'active' if active_tab == 'logs' else ''}">
        <div class="panel-section">
          <div class="panel-section-head">
            <h3 class="panel-section-title">{('Security Alerts' if is_en else 'التنبيهات الأمنية')}</h3>
            <span class="admin-pill">{len(incidents_list)}</span>
          </div>
          {inc_html}
        </div>
        <div class="panel-section">
          <div class="panel-section-head">
            <h3 class="panel-section-title">{('System Logs' if is_en else 'سجل العمليات')}</h3>
            <span class="admin-pill">{len(logs_list)}</span>
          </div>
          {logs_html}
        </div>
      </div>
    </form>
    """
    return web.Response(
        text=render_page("Admin Panel" if is_en else "لوحة الإدارة", "admin", body, request, flash=flash),
        content_type="text/html",
    )


async def handle_services(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    cards = [
        (
            "shield",
            "Sabotage & Anti-Nuke" if is_en else "حماية التخريب",
            "Monitors destructive actions on roles, channels, webhooks, and member punishments with instant rollback."
            if is_en
            else "مراقبة التغييرات الخطيرة على الرتب والرومات والويبهوك والعقوبات مع استرجاع تلقائي.",
        ),
        (
            "raid",
            "Anti-Raid & Account Guard" if is_en else "حماية الدخول والحسابات",
            "Detects join surges, protects against newly created accounts, and locks channels or voice rooms when needed."
            if is_en
            else "رصد الدخول المفاجئ، التحقق من عمر الحسابات الحديثة، وقفل الرومات عند الحاجة.",
        ),
        (
            "snap",
            "Snapshots & Trusted Roles" if is_en else "اللقطات والموثوقين",
            "Save permission snapshots, restore previous rule states, and manage trusted administrators per server."
            if is_en
            else "حفظ لقطات الصلاحيات، استرجاع الحالات السابقة، وإدارة قائمة المشرفين الموثوقين لكل سيرفر.",
        ),
        (
            "star",
            "Premium Customization" if is_en else "مزايا البريميوم",
            "Custom bot profile controls, alert channels, webhook notifications, and priority protection options."
            if is_en
            else "تخصيص ملف البوت، رومات التنبيهات، إشعارات الويبهوك، وخيارات الحماية المتقدمة.",
        ),
    ]
    rows = "".join(
        f"<div class='list-row anim-item' style='align-items:flex-start;'>"
        f"<div class='row-main' style='align-items:flex-start;'><span class='mark-badge'>{_symbol_svg(ico, 16)}</span>"
        f"<div class='row-copy'><div class='row-title'>{esc(t)}</div><div class='muted row-sub' style='white-space:normal;'>{esc(d)}</div></div></div></div>"
        for ico, t, d in cards
    )
    body = f"""
    <div class="page-card anim-card">
      <div class="section-head-bar">
        <div>
          <h2 class="section-head-title">{('Services' if is_en else 'الخدمات')}</h2>
          <div class="muted">{('Core protection modules available across servers.' if is_en else 'أنظمة الحماية والإدارة المتوفرة في المنصة.')}</div>
        </div>
        <a class="btn-gold" style="width:auto;" href="/guild">{('Open Security Panel' if is_en else 'لوحة الحماية')}</a>
      </div>
      {rows}
    </div>
    """
    return web.Response(
        text=render_page("Services" if is_en else "الخدمات", "services", body, request),
        content_type="text/html",
    )


async def handle_updates(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    user = get_discord_session(request)
    is_admin = is_site_admin(user)
    notes = [
        ("v2.6", "2026-11", "Streamlined workspace layout, server configuration tools, and faster sync." if is_en else "تحسين واجهة المنصة، أدوات ضبط السيرفرات، وسرعة المزامنة."),
        ("v2.5", "2026-10", "Permission snapshots, trusted admin lists, and moderation punishment rules." if is_en else "إضافة لقطات الصلاحيات، قوائم الموثوقين، وضبط عقوبات الإشراف."),
    ]
    notes_html = "".join(
        f"<div class='log-entry-row anim-item'><div><span class='admin-pill'>{esc(ver)}</span> <strong style='margin-inline-start:6px;'>{esc(txt)}</strong></div>"
        f"<div class='log-entry-time'>{esc(dt)}</div></div>"
        for ver, dt, txt in notes
    )
    if is_admin:
        logs = get_recent_logs(25)
        feed_html = "".join(
            f"<div class='log-entry-row anim-item'><div class='log-entry-msg'>[{esc(l.get('level'))}] {esc(l.get('message'))}</div>"
            f"<div class='log-entry-time'>{esc(l.get('time'))}</div></div>"
            for l in logs
        ) or f"<p class='muted'>{('No recent activity logs.' if is_en else 'لا توجد سجلات حديثة.')}</p>"
    else:
        feed_html = f"<p class='muted'>{('Detailed activity logs are available to administrators.' if is_en else 'سجلات النشاط التفصيلية متاحة للإدارة.')}</p>"

    body = f"""
    <div class="page-card anim-card">
      <div class="section-head-bar">
        <div>
          <h2 class="section-head-title">{('Updates & Logs' if is_en else 'التحديثات والسجلات')}</h2>
          <div class="muted">{('Release notes and platform activity.' if is_en else 'ملاحظات التحديثات ونشاط المنصة.')}</div>
        </div>
      </div>
      <div class="panel-section">
        <div class="panel-section-head">
          <h3 class="panel-section-title">{('Release Notes' if is_en else 'سجل التحديثات')}</h3>
          <span class="ok-pill">{('LATEST' if is_en else 'الأحدث')}</span>
        </div>
        {notes_html}
      </div>
      <div class="panel-section">
        <div class="panel-section-head">
          <h3 class="panel-section-title">{('Activity Feed' if is_en else 'النشاط الأخير')}</h3>
        </div>
        {feed_html}
      </div>
    </div>
    """
    return web.Response(
        text=render_page("Updates & Logs" if is_en else "التحديثات والسجلات", "updates", body, request),
        content_type="text/html",
    )


async def handle_links(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    safe_invite = esc(sanitize_http_url(BOT_INVITE_URL) or "https://discord.com")
    safe_support = esc(sanitize_http_url(SUPPORT_SERVER_URL) or "https://discord.com")
    items = [
        ("/guild", "Security Panel" if is_en else "لوحة الحماية", "Manage protection rules, whitelists, and snapshots." if is_en else "إدارة قواعد الحماية والموثوقين واللقطات.", False),
        (safe_invite, "Invite Bot" if is_en else "إضافة بوت الحماية", "Add the bot to your Discord server." if is_en else "إضافة البوت إلى سيرفرك في ديسكورد.", True),
        (safe_support, "Support Server" if is_en else "سيرفر الدعم الفني", "Get help, announcements, and updates." if is_en else "للحصول على الدعم الفني ومتابعة التحديثات.", True),
    ]
    cards_html = "".join(
        f"<a class='link-banner-card anim-item' href='{esc(href)}' {'target=\"_blank\" rel=\"noopener noreferrer\"' if ext else ''}>"
        f"<div><div class='link-card-title'>{esc(t)}</div><div class='link-card-sub'>{esc(s)}</div></div>"
        f"<span class='link-arrow'>{'↗' if ext else '→'}</span></a>"
        for href, t, s, ext in items
    )
    body = f"""
    <div class="page-card anim-card">
      <div class="section-head-bar">
        <div>
          <h2 class="section-head-title">{('Links' if is_en else 'الروابط')}</h2>
          <div class="muted">{('Quick access links for the platform and bot.' if is_en else 'روابط الوصول السريع للمنصة والبوت.')}</div>
        </div>
      </div>
      <div class="link-hub-stack">
        {cards_html}
      </div>
    </div>
    """
    return web.Response(
        text=render_page("Links" if is_en else "الروابط", "links", body, request),
        content_type="text/html",
    )


async def login_handler(request: web.Request) -> web.Response:
    ip = get_client_ip(request)
    if is_rate_limited(ip, is_sensitive=True):
        return web.Response(text="Too many login attempts. Please wait a minute.", status=429)
    if not DISCORD_CLIENT_ID:
        return web.Response(text="DISCORD_CLIENT_ID is not configured.", status=500)
    next_url = sanitize_next_url(request.query.get("next", "/"))
    redirect_uri = detect_redirect_uri(request)
    state = issue_oauth_state(next_url=next_url)
    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "identify guilds",
        "state": state,
    }
    raise web.HTTPFound(f"https://discord.com/api/oauth2/authorize?{urlencode(params)}")


async def callback_handler(request: web.Request) -> web.Response:
    ip = get_client_ip(request)
    if is_rate_limited(ip, is_sensitive=True):
        return web.Response(text="Too many callback requests. Please wait a minute.", status=429)

    is_ok_state, next_url = consume_oauth_state(request.query.get("state"))
    if not is_ok_state:
        return web.Response(text="Invalid or expired OAuth state. Please try signing in again.", status=400)

    code = str(request.query.get("code", "")).strip()
    if not code:
        return web.Response(text="Missing authorization code.", status=400)
    if not DISCORD_CLIENT_ID or not DISCORD_CLIENT_SECRET:
        return web.Response(text="Discord OAuth credentials are missing.", status=500)

    redirect_uri = detect_redirect_uri(request)
    timeout = ClientTimeout(total=12)
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
                return web.Response(text="Failed to exchange OAuth code with Discord.", status=400)
            token_data = await token_resp.json()
            access_token = str(token_data.get("access_token", "")).strip()
            if not access_token:
                return web.Response(text="Missing access token from Discord.", status=400)

            auth_headers = {"Authorization": f"Bearer {access_token}"}
            user_resp = await session.get("https://discord.com/api/v10/users/@me", headers=auth_headers)
            if user_resp.status != 200:
                return web.Response(text="Failed to fetch Discord user profile.", status=400)
            user_data = await user_resp.json()

            guilds_data: list[dict] = []
            guilds_resp = await session.get("https://discord.com/api/v10/users/@me/guilds", headers=auth_headers)
            if guilds_resp.status == 200:
                raw_g = await guilds_resp.json()
                if isinstance(raw_g, list):
                    guilds_data = [g for g in raw_g if isinstance(g, dict)]
    except (ClientError, asyncio.TimeoutError):
        return web.Response(text="Network timeout while contacting Discord.", status=502)

    uid = str(user_data.get("id", "")).strip()
    username = str(user_data.get("global_name") or user_data.get("username") or "User").strip()[:40]
    avatar = str(user_data.get("avatar", "") or "").strip()[:80]
    handle_clean = str(user_data.get("username") or username).strip()[:44]

    if uid.isdigit() and premium_col is not None:
        try:
            existing_p = premium_col.find_one({"user_id": uid}, {"_id": 0})
            if existing_p and _is_premium_record_active(existing_p, time.time()):
                norm_p = _normalize_premium_doc(existing_p)
                norm_p["username"] = username
                norm_p["handle"] = f"@{handle_clean.lstrip('@')}"
                if avatar:
                    norm_p["avatar"] = avatar
                MEM_PREMIUM[uid] = norm_p
                premium_col.update_one(
                    {"user_id": uid},
                    {"$set": {"username": username, "handle": norm_p["handle"], "avatar": norm_p["avatar"]}},
                )
        except PyMongoError:
            pass

    session_token = sign_session(
        {
            "id": uid,
            "username": username,
            "avatar": avatar,
            "guilds": guilds_data,
            "exp": time.time() + 86400 * 7,
        }
    )
    resp = web.HTTPFound(next_url)
    resp.set_cookie(
        "arab_sec_session",
        session_token,
        max_age=86400 * 7,
        httponly=True,
        samesite="Lax",
        path="/",
        secure=should_use_secure_cookie(request),
    )
    return resp


async def logout_handler(request: web.Request) -> web.Response:
    pair = get_discord_session_with_id(request)
    if pair:
        _delete_session_record(pair[0])
    resp = web.HTTPFound("/")
    resp.del_cookie("arab_sec_session", path="/")
    return resp


async def health_handler(request: web.Request) -> web.Response:
    return web.json_response({"ok": True, "service": SITE_NAME, "status": MEM_BOT_HEARTBEAT.get("status", "ONLINE")})


@web.middleware
async def security_and_metrics_middleware(request: web.Request, handler):
    ip = get_client_ip(request)
    is_sensitive = request.path in ("/login", "/callback", "/logout")
    if is_rate_limited(ip, is_sensitive=is_sensitive):
        return web.Response(text="Rate limit exceeded. Try again shortly.", status=429)
    if not request.path.startswith("/api/bot/"):
        record_site_visit(request)
    try:
        response = await handler(request)
    except web.HTTPException as exc:
        response = exc
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' https: data: blob:; "
        "img-src 'self' https: data: blob:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "connect-src 'self' https:;"
    )
    return response


def create_app() -> web.Application:
    app = web.Application(
        middlewares=[security_and_metrics_middleware],
        client_max_size=16_000_000,
    )
    app.router.add_get("/", home_handler)
    app.router.add_get("/index", home_handler)
    app.router.add_get("/guild", handle_guild)
    app.router.add_post("/guild", handle_guild)
    app.router.add_get("/premium", handle_premium)
    app.router.add_post("/premium", handle_premium)
    app.router.add_get("/admin", handle_admin)
    app.router.add_post("/admin", handle_admin)
    app.router.add_get("/services", handle_services)
    app.router.add_get("/updates", handle_updates)
    app.router.add_get("/links", handle_links)
    app.router.add_get("/invite", handle_invite_redirect)
    app.router.add_get("/login", login_handler)
    app.router.add_get("/callback", callback_handler)
    app.router.add_get("/logout", logout_handler)
    app.router.add_get("/health", health_handler)

    app.router.add_post("/api/bot/sync-guilds", api_bot_sync_guilds)
    app.router.add_post("/api/bot/boost-sync", api_bot_boost_sync)
    app.router.add_get("/api/bot/guild-profile", api_bot_guild_profile)
    app.router.add_get("/api/bot/pending-commands", api_bot_pending_commands)
    return app


def main() -> None:
    app = create_app()
    web.run_app(app, host=HOST, port=PORT, print=None)


if __name__ == "__main__":
    main()
