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
from urllib.parse import quote, urlencode

from aiohttp import ClientSession, web

try:
    from pymongo import MongoClient
except Exception:
    MongoClient = None


SITE_NAME = os.getenv("SITE_NAME", "ARAB SECURITY").strip() or "ARAB SECURITY"
OWNER_NAME = os.getenv("OWNER_NAME", "كايد").strip() or "كايد"
ADMIN_USER_ID = os.getenv("ADMIN_USER_ID", "1395418036919468073").strip()

DEFAULT_DOMAIN_URL = "https://3rabsecurity.de5.net"
DEFAULT_REDIRECT_URI = f"{DEFAULT_DOMAIN_URL}/callback"

HOST = os.getenv("HOST", "0.0.0.0").strip() or "0.0.0.0"
PORT = int(os.getenv("PORT", "8080") or "8080")

EXPLICIT_MAIN_URL = os.getenv("MAIN_SITE_URL", DEFAULT_DOMAIN_URL).strip().rstrip("/")
EXPLICIT_WEB_URL = os.getenv("WEB_BASE_URL", DEFAULT_DOMAIN_URL).strip().rstrip("/")
EXPLICIT_REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI", DEFAULT_REDIRECT_URI).strip()

BOT_INVITE_URL = os.getenv(
    "BOT_INVITE_URL",
    "https://discord.com/oauth2/authorize?client_id=1573635674551357550&permissions=8&integration_type=0&scope=bot%20applications.commands",
).strip()

MONGO_URI = os.getenv("MONGO_URI", "").strip()
MONGO_DB_NAME = os.getenv("MONGO_DB", "arab_security").strip() or "arab_security"

SESSION_SECRET = os.getenv("SESSION_SECRET", "").strip() or secrets.token_hex(24)
RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", "120") or "120")

DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "1573635674551357550").strip()
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "Fww6a2APclzPG0ivHXRGkY15WfFMc7tD").strip()

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

DEFAULT_GUILD_CFG = {
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
    "trusted_admins": [ADMIN_USER_ID] if ADMIN_USER_ID else [],
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
}

MEM_LOGS: deque[dict] = deque(maxlen=350)
MEM_INCIDENTS: deque[dict] = deque(maxlen=250)
MEM_GUILDS: dict[str, dict] = {}
MEM_GUILD_CFG: dict[str, dict] = defaultdict(lambda: json.loads(json.dumps(DEFAULT_GUILD_CFG)))
MEM_QUEUE: deque[dict] = deque(maxlen=200)
MEM_PREMIUM: set[str] = {ADMIN_USER_ID} if ADMIN_USER_ID else set()
MEM_ADMINS: set[str] = {ADMIN_USER_ID} if ADMIN_USER_ID else set()
MEM_VISITORS: dict[str, dict] = {
    "total_visits": 0,
    "unique_hashes": set(),
}
MEM_BACKUPS: deque[dict] = deque(maxlen=25)
MEM_BOT_HEARTBEAT: dict[str, str] = {
    "status": "ONLINE",
    "last_seen": "",
    "latency_ms": "24ms",
}
CSRF_TOKENS: dict[str, float] = {}
USED_NONCES: dict[str, float] = {}
RATE_BUCKETS: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=400))
SESSIONS: dict[str, dict] = {}


def esc(val) -> str:
    return html.escape(str(val or ""), quote=True)


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
    for k in [k for k, exp in CSRF_TOKENS.items() if now > _safe_exp(exp)]:
        CSRF_TOKENS.pop(k, None)
    for n in [n for n, exp in USED_NONCES.items() if now > _safe_exp(exp)]:
        USED_NONCES.pop(n, None)
    for sid, sess in list(SESSIONS.items()):
        if _safe_exp(sess.get("exp", 0)) <= now:
            SESSIONS.pop(sid, None)


def issue_csrf_token() -> str:
    _cleanup_expired()
    tok = secrets.token_hex(24)
    CSRF_TOKENS[tok] = time.time() + 3600.0
    return tok


def verify_csrf_token(tok: str | None) -> bool:
    _cleanup_expired()
    if not tok or tok not in CSRF_TOKENS:
        return False
    if time.time() > _safe_exp(CSRF_TOKENS[tok]):
        CSRF_TOKENS.pop(tok, None)
        return False
    return True


def is_replay_request(nonce: str | None) -> bool:
    _cleanup_expired()
    clean = str(nonce or "").strip()
    if not clean:
        return False
    if clean in USED_NONCES:
        return True
    USED_NONCES[clean] = time.time() + 300.0
    return False


def encrypt_secret(plain_text: str) -> str:
    raw = str(plain_text or "").encode("utf-8")
    key = hashlib.sha256(SESSION_SECRET.encode("utf-8")).digest()
    stream = bytes(raw[i] ^ key[i % len(key)] for i in range(len(raw)))
    mac = hmac.new(key, stream, hashlib.sha256).hexdigest()[:16]
    return f"enc:{mac}:{base64.urlsafe_b64encode(stream).decode('ascii')}"


def mask_secret_preview(plain_text: str) -> str:
    digest = hashlib.sha256(str(plain_text or "").encode("utf-8")).hexdigest()
    return f"sha256:{digest[:10]}...{digest[-6:]}"


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
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2500, connectTimeoutMS=2500)
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

        if ADMIN_USER_ID:
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
    except Exception as exc:
        print(f"[DB] تنبيه: تشغيل بالذاكرة الاحتياطية ({exc})")


def get_client_ip(request: web.Request) -> str:
    xff = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    return xff or request.remote or "unknown"


def record_site_visit(request: web.Request) -> None:
    if request.path.startswith("/health"):
        return
    ip = get_client_ip(request)
    ua = request.headers.get("User-Agent", "")
    v_hash = hashlib.sha256(f"{ip}|{ua}|{SESSION_SECRET}".encode("utf-8")).hexdigest()[:24]

    MEM_VISITORS["total_visits"] = int(MEM_VISITORS.get("total_visits", 0)) + 1
    u_set = MEM_VISITORS.setdefault("unique_hashes", set())
    is_new_unique = v_hash not in u_set
    u_set.add(v_hash)

    if stats_col is not None:
        try:
            stats_col.update_one(
                {"_id": "visitors"},
                {"$inc": {"total_visits": 1}, "$set": {"updated_at": _now_str()}},
                upsert=True,
            )
            if is_new_unique:
                stats_col.update_one(
                    {"_id": "unique_visitors"},
                    {"$set": {"hash": v_hash, "seen_at": _now_str()}},
                    upsert=True,
                )
        except Exception:
            pass


def get_visitor_stats() -> tuple[int, int]:
    mem_total = int(MEM_VISITORS.get("total_visits", 0))
    mem_unique = len(MEM_VISITORS.get("unique_hashes", set()))
    db_total = 0
    db_unique = 0
    if stats_col is not None:
        try:
            vdoc = stats_col.find_one({"_id": "visitors"})
            if vdoc:
                db_total = int(vdoc.get("total_visits", 0) or 0)
            db_unique = int(stats_col.count_documents({"_id": {"$ne": "visitors"}}) or 0)
        except Exception:
            pass
    return max(mem_total, db_total), max(mem_unique, db_unique)


def is_site_admin(user: dict | None) -> bool:
    if not user:
        return False
    uid = str(user.get("id", "")).strip()
    if not uid.isdigit():
        return False
    if ADMIN_USER_ID and uid == ADMIN_USER_ID:
        return True
    if uid in MEM_ADMINS:
        return True
    if admins_col is not None:
        try:
            doc = admins_col.find_one({"user_id": uid})
            if doc:
                MEM_ADMINS.add(uid)
                return True
        except Exception:
            pass
    return False


def get_admin_list() -> list[dict]:
    items: dict[str, dict] = {}
    if ADMIN_USER_ID:
        items[ADMIN_USER_ID] = {"user_id": ADMIN_USER_ID, "granted_by": "owner", "updated_at": "-"}
    for uid in MEM_ADMINS:
        if uid not in items:
            items[uid] = {"user_id": uid, "granted_by": "admin", "updated_at": "-"}
    if admins_col is not None:
        try:
            for doc in admins_col.find({}, {"_id": 0}):
                uid = str(doc.get("user_id", "")).strip()
                if uid.isdigit():
                    items[uid] = {
                        "user_id": uid,
                        "granted_by": str(doc.get("granted_by", "owner")),
                        "updated_at": str(doc.get("updated_at", "-")),
                    }
        except Exception:
            pass
    return list(items.values())


def set_admin_user(user_id: str, enabled: bool, granted_by: str = "") -> bool:
    uid = str(user_id or "").strip()
    if not uid.isdigit():
        return False
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
            except Exception:
                pass
        if premium_col is not None:
            try:
                premium_col.update_one(
                    {"user_id": uid},
                    {"$set": {"user_id": uid, "granted_by": granted_by or ADMIN_USER_ID, "updated_at": _now_str()}},
                    upsert=True,
                )
            except Exception:
                pass
        return True
    else:
        if uid == ADMIN_USER_ID:
            return False
        MEM_ADMINS.discard(uid)
        if admins_col is not None:
            try:
                admins_col.delete_one({"user_id": uid})
            except Exception:
                pass
        return True


def is_premium_user(user: dict | None) -> bool:
    if not user:
        return False
    uid = str(user.get("id", "")).strip()
    if not uid.isdigit():
        return False
    if is_site_admin(user):
        return True
    if uid in MEM_PREMIUM:
        return True
    if premium_col is not None:
        try:
            doc = premium_col.find_one({"user_id": uid})
            if doc:
                MEM_PREMIUM.add(uid)
                return True
        except Exception:
            pass
    return False


def get_premium_list() -> list[dict]:
    items: dict[str, dict] = {}
    if ADMIN_USER_ID:
        items[ADMIN_USER_ID] = {"user_id": ADMIN_USER_ID, "granted_by": "owner", "updated_at": "-"}
    for uid in MEM_PREMIUM:
        if uid not in items:
            items[uid] = {"user_id": uid, "granted_by": "admin", "updated_at": "-"}
    if premium_col is not None:
        try:
            for doc in premium_col.find({}, {"_id": 0}):
                uid = str(doc.get("user_id", "")).strip()
                if uid.isdigit():
                    items[uid] = {
                        "user_id": uid,
                        "granted_by": str(doc.get("granted_by", "admin")),
                        "updated_at": str(doc.get("updated_at", "-")),
                    }
        except Exception:
            pass
    return list(items.values())


def set_premium_user(user_id: str, enabled: bool, granted_by: str = "") -> bool:
    uid = str(user_id or "").strip()
    if not uid.isdigit():
        return False
    if enabled:
        MEM_PREMIUM.add(uid)
        if premium_col is not None:
            try:
                premium_col.update_one(
                    {"user_id": uid},
                    {"$set": {"user_id": uid, "granted_by": granted_by or ADMIN_USER_ID, "updated_at": _now_str()}},
                    upsert=True,
                )
            except Exception:
                pass
        return True
    else:
        if uid == ADMIN_USER_ID:
            return False
        MEM_PREMIUM.discard(uid)
        if premium_col is not None:
            try:
                premium_col.delete_one({"user_id": uid})
            except Exception:
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
        except Exception:
            pass


def get_incidents(guild_id: str = "", limit: int = 30) -> list[dict]:
    if incidents_col is not None:
        try:
            flt = {"guild_id": guild_id} if str(guild_id).isdigit() else {}
            docs = list(incidents_col.find(flt, {"_id": 0}).sort("_id", -1).limit(limit))
            if docs:
                return docs
        except Exception:
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
    print(f"[{entry['level']}] {entry['message']}")
    if logs_col is not None:
        try:
            logs_col.insert_one(dict(entry))
        except Exception:
            pass
    if level in ("NUKE", "ADMIN", "SEC", "WARN", "ERROR"):
        record_incident(guild_id or "GLOBAL", level, msg, "CRITICAL" if level in ("NUKE", "ERROR") else "MEDIUM")


def get_recent_logs(limit: int = 50) -> list[dict]:
    if logs_col is not None:
        try:
            docs = list(logs_col.find({}, {"_id": 0}).sort("_id", -1).limit(limit))
            if docs:
                return docs
        except Exception:
            pass
    return list(MEM_LOGS)[:limit]


def get_all_guilds() -> list[dict]:
    result: dict[str, dict] = {k: dict(v) for k, v in MEM_GUILDS.items()}
    if bot_guilds_col is not None:
        try:
            for g in bot_guilds_col.find({}, {"_id": 0}):
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
        except Exception:
            pass
    return list(result.values())


def get_user_visible_guilds(user: dict | None) -> tuple[list[dict], bool]:
    all_bot_guilds = get_all_guilds()
    bot_map = {g["id"]: g for g in all_bot_guilds}
    if not user:
        return [], False

    user_guilds = user.get("guilds")
    if isinstance(user_guilds, list) and user_guilds:
        matched = []
        seen = set()
        for ug in user_guilds:
            gid = str(ug.get("id", "")).strip()
            if not gid.isdigit() or gid in seen:
                continue
            perms = int(ug.get("permissions", 0) or 0)
            is_owner = bool(ug.get("owner", False))
            has_admin_or_manage = is_owner or bool(perms & 0x8) or bool(perms & 0x20)
            if not has_admin_or_manage:
                continue
            seen.add(gid)
            if gid in bot_map:
                info = dict(bot_map[gid])
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

    return all_bot_guilds, False


def resolve_guild_info(guild_id: str, user: dict | None = None) -> dict | None:
    gid = str(guild_id or "").strip()
    if not gid.isdigit():
        return None
    for g in get_all_guilds():
        if g["id"] == gid:
            return g
    if user:
        visible, _ = get_user_visible_guilds(user)
        for g in visible:
            if g["id"] == gid:
                return g
    return None


def resolve_guild_id_from_input(raw_input: str, user: dict | None = None) -> str:
    val = str(raw_input or "").strip()
    if not val:
        return ""
    if val.isdigit():
        return val
    candidates = list(get_all_guilds())
    if user:
        visible, _ = get_user_visible_guilds(user)
        seen = {c["id"] for c in candidates}
        for g in visible:
            if g["id"] not in seen:
                candidates.append(g)
    low = val.lower()
    for g in candidates:
        if str(g.get("name", "")).strip().lower() == low:
            return g["id"]
    for g in candidates:
        if low in str(g.get("name", "")).strip().lower():
            return g["id"]
    return ""


def get_guild_cfg(guild_id: str) -> dict:
    gid = str(guild_id or "").strip()
    cfg = json.loads(json.dumps(DEFAULT_GUILD_CFG))
    if not gid.isdigit():
        return cfg
    mem = MEM_GUILD_CFG[gid]
    for k, v in mem.items():
        if k == "antinuke" and isinstance(v, dict):
            for ak, av in v.items():
                if ak in cfg["antinuke"] and isinstance(av, dict):
                    cfg["antinuke"][ak].update(av)
        elif k == "guild_profile" and isinstance(v, dict):
            cfg["guild_profile"].update(v)
        else:
            cfg[k] = v
    if guild_settings_col is not None:
        try:
            doc = guild_settings_col.find_one({"guild_id": gid}, {"_id": 0})
            if doc:
                for k in DEFAULT_GUILD_CFG:
                    if k == "antinuke" and isinstance(doc.get("antinuke"), dict):
                        for ak, av in doc["antinuke"].items():
                            if ak in cfg["antinuke"] and isinstance(av, dict):
                                cfg["antinuke"][ak].update(av)
                    elif k == "guild_profile" and isinstance(doc.get("guild_profile"), dict):
                        cfg["guild_profile"].update(doc["guild_profile"])
                    elif k in doc:
                        cfg[k] = doc[k]
        except Exception:
            pass
    return cfg


def save_guild_cfg(guild_id: str, updates: dict) -> dict:
    gid = str(guild_id or "").strip()
    if updates.get("reset_defaults"):
        fresh = json.loads(json.dumps(DEFAULT_GUILD_CFG))
        if gid.isdigit():
            MEM_GUILD_CFG[gid] = json.loads(json.dumps(fresh))
            if guild_settings_col is not None:
                try:
                    guild_settings_col.update_one(
                        {"guild_id": gid},
                        {"$set": {"guild_id": gid, **fresh, "updated_at": _now_str()}},
                        upsert=True,
                    )
                except Exception:
                    pass
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
        cfg["guild_profile"].update(updates["guild_profile"])
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
            except Exception:
                pass
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
    blocked = score >= 50 or bool(cfg.get("emergency_mode"))
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
        "logs_count": len(get_recent_logs(100)),
        "signature": hashlib.sha256(f"{_now_str()}|{SESSION_SECRET}".encode("utf-8")).hexdigest()[:16],
    }
    MEM_BACKUPS.appendleft(dict(snapshot))
    if backups_col is not None:
        try:
            backups_col.insert_one(dict(snapshot))
        except Exception:
            pass
    return snapshot


def get_db_backups() -> list[dict]:
    if backups_col is not None:
        try:
            docs = list(backups_col.find({}, {"_id": 0}).sort("_id", -1).limit(10))
            if docs:
                return docs
        except Exception:
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
    MEM_QUEUE.append(payload)
    if queue_col is not None:
        try:
            queue_col.insert_one(dict(payload))
        except Exception:
            pass


def detect_base_url(request: web.Request) -> str:
    if EXPLICIT_WEB_URL:
        return EXPLICIT_WEB_URL
    if EXPLICIT_MAIN_URL:
        return EXPLICIT_MAIN_URL
    host = (
        request.headers.get("X-Forwarded-Host", "").split(",")[0].strip()
        or request.headers.get("Host", "").strip()
    )
    proto = request.headers.get("X-Forwarded-Proto", "").split(",")[0].strip() or "https"
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
    sid = secrets.token_urlsafe(32)
    SESSIONS[sid] = payload
    return sid


def verify_session(token):
    d = SESSIONS.get(token or "")
    return d if d and _safe_exp(d.get("exp", 0)) > time.time() else None


def get_discord_session(request: web.Request) -> dict | None:
    _cleanup_expired()
    tok = request.cookies.get("arab_sec_session") or request.headers.get("X-Arab-Session")
    return verify_session(tok)


def get_lang(request: web.Request) -> str:
    q = str(request.query.get("lang", "")).strip().lower()
    if q in ("ar", "en"):
        return q
    c = str(request.cookies.get("arab_sec_lang", "")).strip().lower()
    if c in ("ar", "en"):
        return c
    return "ar"


def is_rate_limited(ip: str) -> bool:
    now = time.time()
    bucket = RATE_BUCKETS[ip]
    while bucket and now - bucket[0] > 60.0:
        bucket.popleft()
    if len(bucket) >= RATE_LIMIT_PER_MIN:
        return True
    bucket.append(now)
    return False


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
            "To access the Dashboard, view your servers, and manage protection settings, click Login with Discord below."
            if is_en
            else "للدخول إلى الداشبورد وعرض السيرفرات والتحكم بها، اضغط زر Login with Discord بالأسفل."
        ),
        "supervised": "Supervised by" if is_en else "بإشراف",
        "menu": "Menu" if is_en else "القائمة",
    }

    if user:
        uid = esc(user.get("id", ""))
        ava = esc(user.get("avatar", ""))
        uname_safe = esc(user.get("username", "Member"))
        avatar_html = (
            f"<img class='avatar-img' src='https://cdn.discordapp.com/avatars/{uid}/{ava}.png?size=128' alt=''>"
            if uid and ava
            else f"<div class='avatar'>{(uname_safe[:1]).upper()}</div>"
        )
        badge_txt = "ADMIN" if is_admin else ("PREMIUM" if is_prem else "MEMBER")
        drawer_account_block = (
            f"<div class='user-box'>{avatar_html}"
            f"<div><div class='uname'>{uname_safe} <span class='tag'>{badge_txt}</span></div>"
            f"<div class='uhandle'>ID: <code>{uid}</code></div></div></div>"
            f"<a class='drawer-link danger' href='/logout'>{L['logout']}</a>"
        )
    else:
        drawer_account_block = f"<a class='login-btn anim-btn' href='/login'>{L['login_discord']}</a>"

    if require_auth_view and not user:
        final_content = f"""
        <div class="page-title anim-card">
          <div class="sub">{L['auth_sub']}</div>
          <h1>{L['auth_title']}</h1>
        </div>
        <div class="feature-card anim-card" style="text-align:center;">
          <p class="muted" style="margin-bottom:18px;">{L['auth_desc']}</p>
          <a class="btn-discord anim-btn" href="/login">{L['login_discord']}</a>
        </div>
        """
    else:
        final_content = content_html

    flash_banner = f"<div class='flash anim-card'>{esc(flash)}</div>" if flash else ""

    premium_nav = (
        f"<a class='drawer-link {'active' if active_nav == 'premium' else ''}' href='/premium'>{L['premium']}</a>"
        if is_prem
        else ""
    )
    admin_nav = (
        f"<a class='drawer-link {'active' if active_nav == 'admin' else ''}' href='/admin'>{L['admin']}</a>"
        if is_admin
        else ""
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
    --bg: #070912;
    --bg-grad: radial-gradient(circle at 50% -12%, rgba(124, 58, 237, 0.36), rgba(15, 23, 42, 0.94) 55%, #070912 100%);
    --card: #121024;
    --card-2: #191633;
    --border: rgba(139, 92, 246, 0.25);
    --border-bright: rgba(192, 132, 252, 0.8);
    --purple: #7c3aed;
    --purple-bright: #8b5cf6;
    --discord: #2563eb;
    --discord-bright: #3b82f6;
    --green: #10b981;
    --gold: #eab308;
    --danger: #ef4444;
    --text: #f8fafc;
    --muted: #a5b4fc;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
    background: var(--bg);
    background-image: var(--bg-grad);
    background-attachment: fixed;
    color: var(--text);
    min-height: 100vh;
    overflow-x: hidden;
  }}

  @keyframes cardReveal {{
    0% {{ opacity: 0; transform: translate3d(0, 18px, 0) scale(0.985); }}
    100% {{ opacity: 1; transform: translate3d(0, 0, 0) scale(1); }}
  }}
  @keyframes pulseGlow {{
    0%, 100% {{ box-shadow: 0 0 0 0 rgba(139, 92, 246, 0.28), 0 18px 40px rgba(0, 0, 0, 0.35); }}
    50% {{ box-shadow: 0 0 32px 4px rgba(139, 92, 246, 0.22), 0 22px 48px rgba(76, 29, 149, 0.35); }}
  }}
  @keyframes floatSoft {{
    0%, 100% {{ transform: translateY(0px); }}
    50% {{ transform: translateY(-4px); }}
  }}
  .anim-card {{
    animation: cardReveal 0.45s cubic-bezier(0.22, 1, 0.36, 1) both;
  }}
  .anim-btn, .btn, .btn-primary, .btn-outline, .btn-discord, .feature-card, .server-card, .stat-box, .tab-btn, .nuke-card, .lang-btn, .burger {{
    transition: transform 0.2s cubic-bezier(0.22, 1, 0.36, 1), box-shadow 0.24s ease, border-color 0.22s ease, background 0.22s ease;
  }}
  .anim-btn:active, .btn:active, .btn-primary:active, .btn-outline:active, .btn-discord:active, .tab-btn:active, .lang-btn:active, .burger:active {{
    transform: scale(0.95) !important;
    box-shadow: 0 0 0 4px rgba(139, 92, 246, 0.28) !important;
  }}
  .feature-card:active, .server-card:active, .stat-box:active, .nuke-card:active {{
    transform: scale(0.985) !important;
    border-color: var(--border-bright);
  }}
  @media (hover: hover) {{
    .anim-btn:hover, .btn:hover, .btn-primary:hover, .btn-outline:hover, .btn-discord:hover, .tab-btn:hover, .lang-btn:hover, .burger:hover {{
      transform: translateY(-2px);
      border-color: var(--border-bright);
    }}
    .feature-card:hover, .server-card:hover, .stat-box:hover, .nuke-card:hover {{
      transform: translateY(-4px);
      border-color: var(--border-bright);
      box-shadow: 0 16px 34px rgba(76, 29, 149, 0.35);
    }}
  }}

  .topbar {{
    position: sticky;
    top: 0;
    z-index: 30;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 12px 16px;
    background: rgba(15, 12, 33, 0.88);
    backdrop-filter: blur(14px);
    border-bottom: 1px solid var(--border);
  }}
  .brand-wrap {{
    display: flex;
    align-items: center;
    gap: 10px;
    text-decoration: none;
    color: #fff;
  }}
  .brand-badge {{
    width: 36px;
    height: 36px;
    border-radius: 11px;
    background: linear-gradient(135deg, #7c3aed, #4f46e5);
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 900;
    font-size: 15px;
    box-shadow: 0 4px 14px rgba(124, 58, 237, 0.45);
    animation: floatSoft 3.5s ease-in-out infinite;
  }}
  .brand-title {{ font-weight: 800; font-size: 15px; line-height: 1.1; }}
  .brand-sub {{ font-size: 11px; color: var(--muted); }}
  .top-actions {{ display: flex; align-items: center; gap: 8px; }}
  .lang-btn {{
    padding: 8px 12px;
    border-radius: 10px;
    border: 1px solid var(--border);
    background: var(--card-2);
    color: #fff;
    font-size: 12px;
    font-weight: 700;
    cursor: pointer;
    text-decoration: none;
  }}
  .burger {{
    width: 38px;
    height: 38px;
    border-radius: 10px;
    border: 1px solid var(--border);
    background: var(--card-2);
    color: #fff;
    font-size: 18px;
    cursor: pointer;
  }}

  .overlay {{
    display: none;
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.7);
    backdrop-filter: blur(3px);
    z-index: 50;
  }}
  .overlay.open {{ display: block; }}
  .drawer {{
    position: fixed;
    top: 0;
    {('left' if is_en else 'right')}: -300px;
    width: 285px;
    max-width: 85vw;
    height: 100vh;
    background: #0d0b1d;
    border-{('right' if is_en else 'left')}: 1px solid var(--border);
    padding: 18px 14px;
    z-index: 60;
    transition: {('left' if is_en else 'right')} 0.28s cubic-bezier(0.22, 1, 0.36, 1);
    overflow-y: auto;
  }}
  .drawer.open {{ {('left' if is_en else 'right')}: 0; }}
  .drawer-head {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 14px;
  }}
  .close-btn {{
    background: transparent;
    border: none;
    color: var(--muted);
    font-size: 22px;
    cursor: pointer;
  }}
  .user-box {{
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 12px;
    border-radius: 14px;
    background: var(--card);
    border: 1px solid var(--border);
    margin-bottom: 10px;
  }}
  .avatar, .avatar-img {{
    width: 42px;
    height: 42px;
    border-radius: 999px;
    object-fit: cover;
  }}
  .avatar {{
    background: var(--purple);
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 700;
    color: #fff;
  }}
  .uname {{ font-weight: 700; font-size: 14px; }}
  .uhandle {{ font-size: 12px; color: var(--muted); }}
  .tag {{
    display: inline-block;
    font-size: 10px;
    padding: 2px 6px;
    border-radius: 6px;
    background: rgba(139, 92, 246, 0.25);
    color: #ddd6fe;
    margin-{('left' if is_en else 'right')}: 4px;
  }}
  .login-btn {{
    display: block;
    text-align: center;
    padding: 12px;
    border-radius: 12px;
    background: linear-gradient(135deg, #2563eb, #1d4ed8);
    color: #fff;
    text-decoration: none;
    font-weight: 800;
    font-size: 14px;
    margin-bottom: 14px;
    box-shadow: 0 6px 18px rgba(37, 99, 235, 0.35);
  }}
  .drawer-link {{
    display: block;
    padding: 11px 14px;
    border-radius: 12px;
    color: var(--text);
    text-decoration: none;
    font-size: 14px;
    font-weight: 600;
    margin-bottom: 6px;
    transition: background 0.2s ease, transform 0.2s ease;
  }}
  .drawer-link.active, .drawer-link:hover {{
    background: rgba(124, 58, 237, 0.24);
    border-{('left' if is_en else 'right')}: 3px solid var(--purple-bright);
    color: #fff;
  }}
  .drawer-link.danger {{ color: #f87171; }}
  .divider {{ height: 1px; background: var(--border); margin: 12px 0; }}

  .wrap {{
    max-width: 820px;
    margin: 22px auto;
    padding: 0 16px 46px;
  }}
  .hero-box {{
    background: linear-gradient(160deg, rgba(30, 22, 66, 0.92), rgba(16, 13, 36, 0.96));
    border: 1px solid var(--border);
    border-radius: 22px;
    padding: 26px 18px;
    text-align: center;
    margin-bottom: 18px;
    animation: cardReveal 0.45s cubic-bezier(0.22, 1, 0.36, 1) both, pulseGlow 4.2s ease-in-out infinite;
  }}
  .hero-badge {{
    display: inline-block;
    padding: 4px 12px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 700;
    color: #ddd6fe;
    background: rgba(124, 58, 237, 0.22);
    border: 1px solid rgba(139, 92, 246, 0.4);
    margin-bottom: 10px;
  }}
  .hero-title {{
    margin: 0;
    font-size: 28px;
    font-weight: 900;
    color: #fff;
  }}
  .hero-sub {{
    margin: 8px auto 20px;
    max-width: 520px;
    color: var(--muted);
    font-size: 14px;
    line-height: 1.6;
  }}
  .hero-stack {{
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 12px;
    max-width: 340px;
    margin: 0 auto;
  }}
  .btn-primary {{
    display: block;
    width: 100%;
    padding: 13px 18px;
    border-radius: 13px;
    background: linear-gradient(135deg, #7c3aed, #6d28d9);
    color: #fff;
    text-decoration: none;
    font-weight: 800;
    font-size: 15px;
    border: 1px solid rgba(167, 139, 250, 0.45);
    box-shadow: 0 8px 22px rgba(109, 40, 217, 0.4);
  }}
  .btn-outline {{
    display: block;
    width: 100%;
    padding: 13px 18px;
    border-radius: 13px;
    background: var(--card-2);
    color: #fff;
    text-decoration: none;
    font-weight: 800;
    font-size: 15px;
    border: 1px solid var(--border);
  }}
  .btn-discord {{
    display: inline-block;
    padding: 13px 22px;
    border-radius: 13px;
    background: linear-gradient(135deg, #2563eb, #1d4ed8);
    color: #fff;
    text-decoration: none;
    font-weight: 800;
    font-size: 15px;
    border: 1px solid rgba(96, 165, 250, 0.5);
    box-shadow: 0 8px 22px rgba(37, 99, 235, 0.4);
  }}

  .stats-stack {{
    display: flex;
    flex-direction: column;
    gap: 14px;
    margin-bottom: 18px;
  }}
  .stat-box {{
    background: linear-gradient(160deg, rgba(24, 19, 52, 0.95), rgba(14, 12, 30, 0.98));
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 24px 18px;
    text-align: center;
    animation: cardReveal 0.5s cubic-bezier(0.22, 1, 0.36, 1) both;
  }}
  .stat-icon {{
    width: 46px;
    height: 46px;
    margin: 0 auto 10px;
    border-radius: 14px;
    background: rgba(124, 58, 237, 0.2);
    border: 1px solid rgba(139, 92, 246, 0.35);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 22px;
    animation: floatSoft 4s ease-in-out infinite;
  }}
  .stat-num {{
    font-size: 34px;
    font-weight: 900;
    color: #fff;
    letter-spacing: 0.5px;
  }}
  .stat-line {{
    width: 28px;
    height: 2px;
    background: var(--purple-bright);
    margin: 10px auto;
    border-radius: 99px;
  }}
  .stat-label {{
    font-size: 14px;
    font-weight: 700;
    color: var(--muted);
  }}

  .section-heading {{
    text-align: center;
    margin: 24px 0 14px;
  }}
  .section-heading h2 {{
    margin: 0;
    font-size: 22px;
    font-weight: 900;
  }}

  .feature-card {{
    background: linear-gradient(150deg, rgba(25, 20, 56, 0.95), rgba(15, 12, 33, 0.98));
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 18px;
    margin-bottom: 14px;
    display: flex;
    flex-direction: column;
    gap: 12px;
    animation: cardReveal 0.52s cubic-bezier(0.22, 1, 0.36, 1) both;
  }}
  .feature-top {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }}
  .feature-meta {{
    display: flex;
    align-items: center;
    gap: 12px;
  }}
  .feature-icon {{
    width: 48px;
    height: 48px;
    border-radius: 14px;
    background: linear-gradient(135deg, #7c3aed, #4338ca);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 20px;
    flex-shrink: 0;
  }}
  .pill-tag {{
    display: inline-block;
    padding: 4px 10px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 800;
  }}
  .pill-purple {{ background: rgba(124, 58, 237, 0.24); color: #ddd6fe; border: 1px solid rgba(139, 92, 246, 0.4); }}
  .pill-green {{ background: rgba(16, 185, 129, 0.18); color: #6ee7b7; border: 1px solid rgba(16, 185, 129, 0.35); }}
  .feature-title {{ margin: 0; font-size: 18px; font-weight: 800; }}
  .feature-desc {{ margin: 0; color: var(--muted); font-size: 13px; line-height: 1.6; }}
  .feature-bullets {{ list-style: none; padding: 0; margin: 0; font-size: 13px; color: #e2e8f0; }}
  .feature-bullets li {{ margin-bottom: 6px; }}
  .feature-footer {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding-top: 10px;
    border-top: 1px solid rgba(139, 92, 246, 0.16);
  }}
  .open-btn {{
    padding: 9px 16px;
    border-radius: 11px;
    background: linear-gradient(135deg, #7c3aed, #6d28d9);
    color: #fff;
    text-decoration: none;
    font-size: 13px;
    font-weight: 800;
  }}

  .page-title {{ text-align: center; margin-bottom: 18px; }}
  .page-title .sub {{ font-size: 11px; letter-spacing: 2px; color: var(--muted); font-weight: 700; }}
  .page-title h1 {{ margin: 4px 0 0; font-size: 26px; font-weight: 900; color: #fff; }}
  .card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 18px;
    padding: 18px;
    margin-bottom: 14px;
    animation: cardReveal 0.45s cubic-bezier(0.22, 1, 0.36, 1) both;
  }}
  .admin-hero {{
    background: linear-gradient(145deg, rgba(46, 29, 97, 0.92), rgba(16, 13, 36, 0.98));
    border: 1px solid var(--border-bright);
    border-radius: 22px;
    padding: 20px;
    margin-bottom: 14px;
    animation: cardReveal 0.45s cubic-bezier(0.22, 1, 0.36, 1) both;
  }}
  .admin-kpis {{
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 10px;
    margin-top: 14px;
  }}
  @media (max-width: 640px) {{
    .admin-kpis {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
  }}
  .kpi-tile {{
    background: rgba(12, 10, 26, 0.72);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 12px 10px;
    text-align: center;
  }}
  .kpi-val {{ font-size: 20px; font-weight: 900; color: #fff; }}
  .kpi-lbl {{ font-size: 11px; color: var(--muted); margin-top: 3px; }}
  .admin-form-row {{
    display: flex;
    flex-wrap: wrap;
    justify-content: center;
    align-items: center;
    gap: 10px;
    margin-bottom: 14px;
  }}
  .member-pill {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 10px;
    padding: 10px 12px;
    border-radius: 12px;
    background: var(--card-2);
    border: 1px solid rgba(139, 92, 246, 0.16);
    margin-bottom: 8px;
  }}
  .member-pill:last-child {{ margin-bottom: 0; }}
  .grid-2 {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }}
  .grid-cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 12px; }}
  .tab-btn {{
    display: block;
    text-align: center;
    padding: 12px 10px;
    border-radius: 13px;
    background: var(--card);
    border: 1px solid var(--border);
    color: var(--text);
    text-decoration: none;
    font-weight: 700;
    font-size: 14px;
  }}
  .tab-btn.active {{
    border-color: var(--purple-bright);
    background: rgba(124, 58, 237, 0.24);
    color: #fff;
  }}
  .nuke-card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 18px;
    padding: 18px 14px;
    text-align: center;
    margin-bottom: 14px;
    animation: cardReveal 0.48s cubic-bezier(0.22, 1, 0.36, 1) both;
  }}
  .nuke-card h3 {{ margin: 0 0 12px; font-size: 16px; }}
  .field-label {{ display: block; font-size: 13px; color: var(--muted); margin: 10px 0 6px; font-weight: 600; }}
  .ctrl {{
    width: 100%;
    max-width: 340px;
    background: var(--card-2);
    border: 1px solid var(--border);
    color: #fff;
    border-radius: 12px;
    padding: 10px 12px;
    font-size: 14px;
    text-align: center;
  }}
  .check-wrap {{ margin-top: 12px; display: flex; justify-content: center; }}
  .check-box {{
    width: 44px;
    height: 44px;
    border-radius: 12px;
    background: var(--purple);
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    border: 1px solid var(--purple-bright);
  }}
  .check-box input {{ width: 20px; height: 20px; accent-color: #ffffff; cursor: pointer; }}
  .toggle-list {{
    display: flex;
    flex-direction: column;
    gap: 10px;
    margin-top: 12px;
  }}
  .toggle-row {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 10px 12px;
    border-radius: 12px;
    background: var(--card-2);
    border: 1px solid rgba(139, 92, 246, 0.16);
  }}
  .btn {{
    display: inline-block;
    background: var(--purple);
    color: #fff;
    border: none;
    border-radius: 12px;
    padding: 10px 18px;
    font-size: 14px;
    font-weight: 700;
    text-decoration: none;
    cursor: pointer;
  }}
  .btn.ghost {{ background: var(--card-2); border: 1px solid var(--border); color: var(--text); }}
  .btn.danger {{ background: rgba(239, 68, 68, 0.2); border: 1px solid var(--danger); color: #fca5a5; }}
  .btn.gold {{ background: rgba(234, 179, 8, 0.2); border: 1px solid var(--gold); color: #fde047; }}
  .server-card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 18px;
    padding: 16px;
    text-align: center;
    color: var(--text);
    text-decoration: none;
    display: block;
    animation: cardReveal 0.48s cubic-bezier(0.22, 1, 0.36, 1) both;
  }}
  .server-thumb {{
    width: 100%;
    height: 140px;
    border-radius: 14px;
    background: linear-gradient(135deg, #6d28d9, #1e1b4b);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 34px;
    font-weight: 800;
    color: #fff;
    margin: 10px 0;
    object-fit: cover;
  }}
  .flash {{
    background: rgba(124, 58, 237, 0.22);
    border: 1px solid var(--purple-bright);
    color: #ede9fe;
    padding: 12px 16px;
    border-radius: 14px;
    margin-bottom: 14px;
    text-align: center;
    font-weight: 700;
  }}
  .log-row {{ padding: 10px 0; border-bottom: 1px solid var(--border); font-size: 13px; }}
  .log-row:last-child {{ border-bottom: none; }}
  .muted {{ color: var(--muted); font-size: 13px; }}
  code {{ background: var(--card-2); padding: 2px 6px; border-radius: 6px; }}
</style>
</head>
<body>
<header class="topbar">
  <a class="brand-wrap" href="/">
    <div class="brand-badge">AS</div>
    <div>
      <div class="brand-title">{esc(SITE_NAME)}</div>
      <div class="brand-sub">{L['supervised']} {esc(OWNER_NAME)}</div>
    </div>
  </a>
  <div class="top-actions">
    <button class="lang-btn anim-btn" type="button" onclick="switchLang('{next_lang}')">{lang_label}</button>
    <button class="burger anim-btn" type="button" onclick="toggleDrawer(true)" aria-label="{L['menu']}">☰</button>
  </div>
</header>

<div id="overlay" class="overlay" onclick="toggleDrawer(false)"></div>
<aside id="drawer" class="drawer">
  <div class="drawer-head">
    <strong>{esc(SITE_NAME)}</strong>
    <button class="close-btn" type="button" onclick="toggleDrawer(false)">✕</button>
  </div>
  {drawer_account_block}
  <a class="drawer-link {'active' if active_nav == 'home' else ''}" href="/">{L['home']}</a>
  <a class="drawer-link {'active' if active_nav == 'servers' else ''}" href="/servers">{L['servers']}</a>
  <a class="drawer-link {'active' if active_nav == 'guild' else ''}" href="/guild">{L['guild']}</a>
  {premium_nav}
  {admin_nav}
  <a class="drawer-link {'active' if active_nav == 'services' else ''}" href="/services">{L['services']}</a>
  <a class="drawer-link {'active' if active_nav == 'updates' else ''}" href="/updates">{L['updates']}</a>
  <a class="drawer-link {'active' if active_nav == 'links' else ''}" href="/links">{L['links']}</a>
  <div class="divider"></div>
  <a class="drawer-link" href="{esc(BOT_INVITE_URL)}" target="_blank" rel="noopener">{L['invite']}</a>
</aside>

<main class="wrap">
  {flash_banner}
  {final_content}
</main>

<script>
function toggleDrawer(open) {{
  document.getElementById("drawer").classList.toggle("open", open);
  document.getElementById("overlay").classList.toggle("open", open);
}}
function switchLang(targetLang) {{
  try {{
    document.cookie = "arab_sec_lang=" + encodeURIComponent(targetLang) + "; path=/; max-age=" + (86400 * 365);
    localStorage.setItem("arab_sec_lang", targetLang);
  }} catch (e) {{}}
  var url = new URL(window.location.href);
  url.searchParams.set("lang", targetLang);
  window.location.href = url.toString();
}}
(function() {{
  try {{
    var t = localStorage.getItem("arab_sec_tok");
    if (t && document.cookie.indexOf("arab_sec_session=") === -1) {{
      document.cookie = "arab_sec_session=" + encodeURIComponent(t) + "; path=/; max-age=" + (86400 * 7);
    }}
  }} catch (e) {{}}
  document.querySelectorAll(".feature-card, .server-card, .nuke-card, .stat-box").forEach(function(el, idx) {{
    el.style.animationDelay = Math.min(idx * 55, 280) + "ms";
  }});
}})();
</script>
</body>
</html>"""


async def home_handler(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    user = get_discord_session(request)
    flash = str(request.query.get("msg", "")).strip()

    bot_servers_count = len(get_all_guilds())
    total_visits, unique_visitors = get_visitor_stats()
    dash_href = "/servers" if user else "/login"

    hero_html = f"""
    <div class="hero-box">
      <div class="hero-badge">{('DISCORD SECURITY SUITE' if is_en else 'منظومة حماية سيرفرات ديسكورد')}</div>
      <h1 class="hero-title">{esc(SITE_NAME)}</h1>
      <p class="hero-sub">{('Full Anti-Nuke, behavior analytics, permission snapshots, attack simulation, and DB backup safeguards.' if is_en else 'منظومة حماية متكاملة ضد النيوك، تحليل السلوك، نسخ الصلاحيات والاسترجاع، محاكاة الهجمات، والنسخ الاحتياطي.')}</p>
      <div class="hero-stack">
        <a class="btn-primary" href="{esc(BOT_INVITE_URL)}" target="_blank" rel="noopener">Invite Arab Security Bot</a>
        <a class="btn-outline" href="{dash_href}">Dashboard</a>
      </div>
    </div>
    """

    stats_html = f"""
    <div class="stats-stack">
      <div class="stat-box">
        <div class="stat-icon">🛡️</div>
        <div class="stat-num">{bot_servers_count:,}</div>
        <div class="stat-line"></div>
        <div class="stat-label">{('Servers with Bot' if is_en else 'عدد السيرفرات التي يداخلها البوت')}</div>
      </div>
      <div class="stat-box">
        <div class="stat-icon">👥</div>
        <div class="stat-num">{unique_visitors:,}</div>
        <div class="muted">{(f'{total_visits:,} total visits' if is_en else f'{total_visits:,} إجمالي الزيارات')}</div>
        <div class="stat-line"></div>
        <div class="stat-label">{('Website Visitors' if is_en else 'عدد الأشخاص الذين زاروا الموقع')}</div>
      </div>
    </div>
    """

    cards_html = f"""
    <div class="section-heading">
      <h2>{('Core Systems' if is_en else 'الأنظمة والخدمات')}</h2>
    </div>

    <div class="feature-card">
      <div class="feature-top">
        <div class="feature-meta">
          <div class="feature-icon">🔒</div>
          <div>
            <span class="pill-tag pill-purple">{('MOST USED' if is_en else 'الأكثر استخداماً')}</span>
            <h3 class="feature-title">{('Anti-Nuke, Permissions Guard, Rollback & Audit' if is_en else 'حماية النيوك، الصلاحيات، الاسترجاع، والتدقيق')}</h3>
          </div>
        </div>
      </div>
      <p class="feature-desc">{('Webhooks, apps, bots, privilege escalation, role/channel permissions, mass unban/kick/timeout, behavior analysis, snapshots, and simulations.' if is_en else 'حماية الويب هوك والتطبيقات والبوتات، منع تصعيد الصلاحيات والتلاعب بالرتب والقنوات، فك الحظر/الطرد/التايم أوت الجماعي، تحليل السلوك، والنسخ والاسترجاع.')}</p>
      <ul class="feature-bullets">
        <li>✓ {('Trusted Admins, Snapshots & Auto Rollback' if is_en else 'إداريون موثوقون، حفظ نسخة من الصلاحيات، واسترجاع تلقائي')}</li>
        <li>✓ {('Security Score, Attack Simulation & Auto Audit' if is_en else 'تقييم أمان السيرفر، محاكاة الهجمات، والتدقيق التلقائي')}</li>
        <li>✓ {('API Rate Guard, MongoDB Backup & Restore Check' if is_en else 'حماية API وتحديد المعدل، نسخ احتياطي لقاعدة البيانات واختبار الاستعادة')}</li>
      </ul>
      <div class="feature-footer">
        <div>
          <strong style="color:#fff;">{('Active' if is_en else 'مفعّل')}</strong>
          <div class="muted" style="color:#6ee7b7;">• {('Ready Now' if is_en else 'جاهز الآن')}</div>
        </div>
        <a class="open-btn" href="/guild">{('Open Panel →' if is_en else '← افتح اللوحة')}</a>
      </div>
    </div>

    <div class="feature-card">
      <div class="feature-top">
        <div class="feature-meta">
          <div class="feature-icon">✨</div>
          <div>
            <span class="pill-tag pill-green">{('PREMIUM' if is_en else 'بريميوم')}</span>
            <h3 class="feature-title">{('Per-Server Bot Profile' if is_en else 'تخصيص البوت لكل سيرفر')}</h3>
          </div>
        </div>
      </div>
      <p class="feature-desc">{('Customize bot avatar, banner, and bio inside a specific server without affecting other servers.' if is_en else 'تخصيص صورة البوت وبنره وبايو البوت داخل سيرفر محدد فقط دون التأثير على باقي السيرفرات.')}</p>
      <ul class="feature-bullets">
        <li>✓ {('Isolated per server' if is_en else 'مخصص لكل سيرفر على حدة')}</li>
        <li>✓ {('Avatar, banner & bio controls' if is_en else 'تحكم بالصورة والبنر والبايو')}</li>
      </ul>
      <div class="feature-footer">
        <div>
          <strong style="color:#fff;">{('Premium' if is_en else 'بريميوم')}</strong>
          <div class="muted" style="color:#6ee7b7;">• {('Available' if is_en else 'متاحة الآن')}</div>
        </div>
        <a class="open-btn" href="/premium">{('Open Service →' if is_en else '← افتح الخدمة')}</a>
      </div>
    </div>
    """

    body = hero_html + stats_html + cards_html
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
    cards = ""
    for g in guilds:
        gid = esc(g["id"])
        gname = esc(g["name"])
        icon = esc(str(g.get("icon", "")).strip())
        mcount = int(g.get("member_count", 0) or 0)
        missing = bool(g.get("bot_missing"))
        if icon:
            thumb = f"<img class='server-thumb' src='https://cdn.discordapp.com/icons/{gid}/{icon}.png?size=256' alt=''>"
        else:
            initial = esc((g["name"][:2] or "SV").upper())
            thumb = f"<div class='server-thumb'>{initial}</div>"

        target_href = esc(BOT_INVITE_URL) if missing else f"/guild?id={gid}&tab=antinuke"
        target_attr = " target='_blank' rel='noopener'" if missing else ""
        badge = (
            f"<div class='muted' style='color:#c4b5fd;'>{'Add Bot to Server' if is_en else 'إضافة البوت للسيرفر'}</div>"
            if missing
            else f"<div class='muted'>{mcount} {'members' if is_en else 'عضو'}</div>"
        )
        cards += f"""
        <a class="server-card" href="{target_href}"{target_attr}>
          <div style="font-weight:800;font-size:17px;">{gname}</div>
          {thumb}
          {badge}
        </a>
        """

    if not cards:
        note = (
            "No manageable servers found or the bot is not added yet."
            if is_en
            else "لم يتم العثور على سيرفرات تملك فيها صلاحية الإدارة أو البوت غير مضاف فيها بعد."
        ) if has_oauth_guilds else (
            "Account connected. Invite the bot or re-login to refresh servers."
            if is_en
            else "تم ربط حسابك بنجاح، أضف البوت إلى سيرفرك أو أعد تسجيل الدخول لتحديث السيرفرات."
        )
        cards = f"""
        <div class="card" style="text-align:center;">
          <p class="muted">{esc(note)}</p>
          <a class="btn" href="{esc(BOT_INVITE_URL)}" target="_blank" rel="noopener">Invite Arab Security Bot</a>
        </div>
        """

    body = f"""
    <div class="page-title">
      <div class="sub">{('YOUR' if is_en else 'قائمة')}</div>
      <h1>{('SERVERS' if is_en else 'سيرفراتي')}</h1>
    </div>
    <div class="grid-cards">
      {cards}
    </div>
    """
    return web.Response(text=render_page("Servers" if is_en else "سيرفراتي", "servers", body, request), content_type="text/html")


async def handle_guild(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    user = get_discord_session(request)
    if not user:
        return web.Response(
            text=render_page("Security Panel" if is_en else "لوحة الحماية", "guild", "", request, require_auth_view=True),
            content_type="text/html",
        )

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
        if raw_q and not raw_q.isdigit():
            matched_id = resolve_guild_id_from_input(raw_q, user)
            if matched_id:
                gid = matched_id
            else:
                flash = (
                    f"Server '{raw_q}' not found."
                    if is_en
                    else f"لم يتم العثور على سيرفر بالاسم «{raw_q}»."
                )

    if request.method == "POST":
        form = await request.post()
        csrf_val = str(form.get("csrf_token", "")).strip()
        nonce_val = str(form.get("req_nonce", "")).strip()
        if not verify_csrf_token(csrf_val):
            flash = "Session expired, please try again." if is_en else "انتهت صلاحية الجلسة أو الرمز الأمني، أعد المحاولة."
        elif is_replay_request(nonce_val):
            flash = "Duplicate request blocked." if is_en else "تم منع إعادة إرسال طلب مكرر (Replay Guard)."
        else:
            posted_gid = resolve_guild_id_from_input(str(form.get("guild_id", gid)), user) or str(form.get("guild_id", gid)).strip()
            if posted_gid.isdigit():
                gid = posted_gid
                section = str(form.get("section", active_tab)).strip().lower()

                if section == "antinuke":
                    if form.get("reset_defaults") == "on":
                        save_guild_cfg(gid, {"reset_defaults": True})
                        flash = "تمت استعادة الإعدادات الافتراضية للحماية."
                        log_event(f"إعادة ضبط إعدادات الحماية الافتراضية للسيرفر {gid}", guild_id=gid, level="SEC")
                    else:
                        an_updates = {}
                        for key in ANTINUKE_RULE_KEYS:
                            lim_raw = str(form.get(f"{key}_limit", "1")).strip()
                            lim = int(lim_raw) if lim_raw.isdigit() and int(lim_raw) > 0 else 1
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
                    tr_add = str(form.get("tr_add", "")).strip()
                    tr_rem = str(form.get("tr_remove", "")).strip()
                    if add_id.isdigit():
                        save_guild_cfg(gid, {"whitelist_add": add_id})
                        log_event(f"إضافة {add_id} للوايت لست في السيرفر {gid}", guild_id=gid, level="WL")
                        flash = f"Added {add_id} to whitelist." if is_en else f"تمت إضافة {add_id} إلى Whitelist."
                    elif rem_id:
                        save_guild_cfg(gid, {"whitelist_remove": rem_id})
                        flash = f"Removed {rem_id} from whitelist." if is_en else f"تمت إزالة {rem_id} من Whitelist."
                    elif tr_add.isdigit():
                        save_guild_cfg(gid, {"trusted_add": tr_add})
                        log_event(f"إضافة {tr_add} لقائمة الإداريين الموثوقين للسيرفر {gid}", guild_id=gid, level="SEC")
                        flash = f"Added {tr_add} to trusted admins." if is_en else f"تمت إضافة {tr_add} إلى الإداريين الموثوقين."
                    elif tr_rem:
                        save_guild_cfg(gid, {"trusted_remove": tr_rem})
                        flash = f"Removed {tr_rem} from trusted admins." if is_en else f"تمت إزالة {tr_rem} من الإداريين الموثوقين."

    guild_info = resolve_guild_info(gid, user) if gid.isdigit() else None
    guild_display_name = (
        str(guild_info.get("name", "")).strip()
        if guild_info
        else ("Not Selected" if is_en else "لم يتم التحديد")
    )
    guild_icon_hash = str(guild_info.get("icon", "")).strip() if guild_info else ""
    guild_icon_html = (
        f"<img src='https://cdn.discordapp.com/icons/{esc(gid)}/{esc(guild_icon_hash)}.png?size=96' alt='' style='width:44px;height:44px;border-radius:12px;object-fit:cover;border:1px solid var(--border);'>"
        if gid.isdigit() and guild_icon_hash
        else f"<div style='width:44px;height:44px;border-radius:12px;background:var(--purple);display:flex;align-items:center;justify-content:center;font-weight:900;font-size:16px;color:#fff;'>{esc((guild_display_name[:2] or 'SV').upper())}</div>"
    )

    cfg = get_guild_cfg(gid) if gid.isdigit() else json.loads(json.dumps(DEFAULT_GUILD_CFG))
    sec_score, sec_grade = calculate_security_score(cfg)
    csrf_token = issue_csrf_token()
    req_nonce = secrets.token_hex(12)

    tabs = [
        ("general", "General" if is_en else "عام"),
        ("antinuke", "Anti Nuke"),
        ("beast", "Beast Mode"),
        ("raid", "Anti Raid"),
        ("verify", "Verification"),
        ("mod", "Moderation"),
        ("whitelist", "Whitelist & Trusted"),
        ("logs", "Logs & Timeline" if is_en else "السجلات والحوادث"),
    ]
    tabs_html = "".join(
        f"<a class='tab-btn {'active' if key == active_tab else ''}' href='/guild?id={esc(gid)}&tab={key}'>{label}</a>"
        for key, label in tabs
    )

    if active_tab == "antinuke":
        an = cfg.get("antinuke", {})
        cards_spec = [
            ("anti_ban", "ANTI BAN"),
            ("anti_kick", "ANTI KICK"),
            ("anti_role_create", "ANTI ROLE CREATE"),
            ("anti_role_delete", "ANTI ROLE DELETE"),
            ("anti_channel_create", "ANTI CHANNEL CREATE"),
            ("anti_channel_delete", "ANTI CHANNEL DELETE"),
            ("anti_webhook_create", "ANTI WEBHOOK CREATE"),
            ("anti_bot_add", "ANTI BOT ADD"),
            ("anti_guild_update", "ANTI SERVER ICON / UPDATE"),
        ]
        nuke_cards = ""
        for k, heading in cards_spec:
            item = an.get(k, {"enabled": True, "limit": 1, "punishment": "Kick"})
            pun_val = item.get("punishment", "Kick")
            nuke_cards += f"""
            <div class="nuke-card">
              <h3>{heading}</h3>
              <span class="field-label">Limit</span>
              <input class="ctrl" type="number" min="1" max="50" name="{k}_limit" value="{int(item.get('limit', 1))}">
              <span class="field-label">PUNISHMENT TYPE</span>
              <select class="ctrl" name="{k}_punishment">
                <option value="Kick" {'selected' if pun_val == 'Kick' else ''}>Kick</option>
                <option value="Ban" {'selected' if pun_val == 'Ban' else ''}>Ban</option>
                <option value="Remove Roles" {'selected' if pun_val == 'Remove Roles' else ''}>Remove Roles</option>
              </select>
              <div class="check-wrap">
                <label class="check-box" title="{'Enable / Disable' if is_en else 'تفعيل أو إطفاء'}">
                  <input type="checkbox" name="{k}_enabled" {'checked' if item.get('enabled', True) else ''}>
                </label>
              </div>
            </div>
            """

        shield_items = [
            ("anti_webhook_abuse", "مكافحة إساءة استخدام الويب هوك"),
            ("anti_app_abuse", "مكافحة إساءة استخدام التطبيقات"),
            ("anti_privilege_escalation", "منع تصعيد الصلاحيات"),
            ("anti_role_tamper", "منع التلاعب بالرتب"),
            ("anti_channel_perms_tamper", "منع التلاعب بصلاحيات القنوات"),
            ("audit_log_watch", "مراقبة سجلات التدقيق"),
            ("anti_mass_unban", "منع فك الحظر الجماعي"),
            ("anti_mass_kick", "منع الطرد الجماعي"),
            ("anti_mass_timeout", "منع التايم أوت الجماعي"),
            ("admin_behavior_analysis", "تحليل سلوك الإداريين"),
            ("trusted_admins_enabled", "تفعيل نظام الإداريين الموثوقين"),
            ("perms_snapshot_enabled", "تفعيل حفظ نسخة من الصلاحيات"),
            ("auto_rollback_enabled", "الاسترجاع التلقائي"),
            ("gradual_attack_detect", "كشف الهجمات المتدرجة"),
            ("collusion_detect", "كشف الحسابات المتعاونة"),
            ("false_punishment_guard", "منع العقوبات الخاطئة"),
            ("auto_perms_audit", "التدقيق التلقائي للصلاحيات"),
        ]
        toggles_html = "".join(
            f"<label class='toggle-row'><span>{esc(lbl)}</span><input type='checkbox' name='{k}' {'checked' if cfg.get(k) else ''}></label>"
            for k, lbl in shield_items
        )
        snaps = cfg.get("perms_snapshots", [])
        last_snap = snaps[0] if snaps else None
        snap_info = (
            f"آخر نسخة محفوظة: <code>{esc(last_snap.get('id'))}</code> ({esc(last_snap.get('saved_at'))}) • Hash: <code>{esc(last_snap.get('snapshot_hash'))}</code>"
            if last_snap
            else "لم يتم حفظ نسخة من الصلاحيات بعد."
        )

        panel_html = f"""
        <form method="POST" action="/guild?id={esc(gid)}&tab=antinuke">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <input type="hidden" name="req_nonce" value="{req_nonce}">
          <input type="hidden" name="guild_id" value="{esc(gid)}">
          <input type="hidden" name="section" value="antinuke">
          {nuke_cards}
          <div class="card">
            <h3 style="margin:0 0 6px;">أنظمة الحماية والتدقيق المتقدمة</h3>
            <div class="muted" style="margin-bottom:8px;">{snap_info}</div>
            <div class="toggle-list">
              {toggles_html}
              <label class="toggle-row">
                <span>حفظ نسخة جديدة من الصلاحيات الآن</span>
                <input type="checkbox" name="save_snapshot">
              </label>
              <label class="toggle-row">
                <span>تشغيل التدقيق التلقائي للصلاحيات عند الحفظ</span>
                <input type="checkbox" name="run_audit">
              </label>
              <label class="toggle-row">
                <span>إعادة ضبط الإعدادات الافتراضية للسيرفر</span>
                <input type="checkbox" name="reset_defaults">
              </label>
            </div>
            <span class="field-label">محاكاة هجوم (اختياري)</span>
            <select class="ctrl" name="sim_scenario">
              <option value="">بدون محاكاة</option>
              <option value="Mass Ban & Kick">محاكاة حظر وطرد جماعي</option>
              <option value="Webhook & Role Escalation">محاكاة تصعيد صلاحيات وويب هوك</option>
              <option value="Gradual Collusion Attack">محاكاة هجوم متدرج وحسابات متعاونة</option>
            </select>
          </div>
          <div style="text-align:center;">
            <button class="btn" type="submit">{('Save Anti Nuke Settings' if is_en else 'حفظ وتشغيل الأنظمة')}</button>
          </div>
        </form>
        """

    elif active_tab == "general":
        panel_html = f"""
        <form class="card" method="POST" action="/guild?id={esc(gid)}&tab=general">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <input type="hidden" name="req_nonce" value="{req_nonce}">
          <input type="hidden" name="guild_id" value="{esc(gid)}">
          <input type="hidden" name="section" value="general">
          <h3>{('General Settings' if is_en else 'الإعدادات العامة للسيرفر')}</h3>
          <span class="field-label">Prefix</span>
          <input class="ctrl" type="text" name="prefix" value="{esc(cfg.get('prefix', '!'))}" maxlength="6">
          <span class="field-label">Mod Log Channel ID</span>
          <input class="ctrl" type="text" name="mod_log_channel" value="{esc(cfg.get('mod_log_channel', ''))}" placeholder="Channel ID">
          <div class="toggle-list">
            <label class="toggle-row">
              <span>وضع الطوارئ (Emergency Mode)</span>
              <input type="checkbox" name="emergency_mode" {'checked' if cfg.get('emergency_mode') else ''}>
            </label>
            <label class="toggle-row">
              <span>{('Server Lockdown' if is_en else 'قفل السيرفر السريع (Lockdown)')}</span>
              <input type="checkbox" name="lockdown" {'checked' if cfg.get('lockdown') else ''}>
            </label>
            <label class="toggle-row">
              <span>قفل القنوات الصوتية (Voice Lock)</span>
              <input type="checkbox" name="voice_lock" {'checked' if cfg.get('voice_lock') else ''}>
            </label>
            <label class="toggle-row">
              <span>الوضع الصامت للبوت (Silent Mode)</span>
              <input type="checkbox" name="silent_mode" {'checked' if cfg.get('silent_mode') else ''}>
            </label>
            <label class="toggle-row">
              <span>منع دعوات السيرفرات (Anti Invites)</span>
              <input type="checkbox" name="anti_invites" {'checked' if cfg.get('anti_invites', True) else ''}>
            </label>
            <label class="toggle-row">
              <span>{('Maintenance Mode' if is_en else 'وضع الصيانة')}</span>
              <input type="checkbox" name="maintenance" {'checked' if cfg.get('maintenance') else ''}>
            </label>
            <label class="toggle-row">
              <span>{('Anti Spam' if is_en else 'مضاد السبام')}</span>
              <input type="checkbox" name="anti_spam" {'checked' if cfg.get('anti_spam', True) else ''}>
            </label>
            <label class="toggle-row">
              <span>{('Anti Link' if is_en else 'منع الروابط')}</span>
              <input type="checkbox" name="anti_link" {'checked' if cfg.get('anti_link') else ''}>
            </label>
          </div>
          <button class="btn" type="submit" style="margin-top:14px;">{('Save' if is_en else 'حفظ')}</button>
        </form>
        """

    elif active_tab in ("beast", "raid", "verify"):
        titles = {
            "beast": ("Beast Mode", "beast_mode", "Emergency high protection mode" if is_en else "تفعيل وضع الطوارئ القصوى لحماية السيرفر"),
            "raid": ("Anti Raid & New Accounts", "anti_raid", "Protection against mass join raids and fresh accounts" if is_en else "حماية ضد الهجمات الجماعية والحسابات الحديثة"),
            "verify": ("Verification", "verification", "New member verification system" if is_en else "تفعيل نظام التحقق للأعضاء الجدد"),
        }
        t_label, fname, desc = titles[active_tab]
        raid_extra = ""
        if active_tab == "raid":
            raid_extra = f"""
            <div class="toggle-list" style="max-width:340px;margin:14px auto 0;text-align:{'left' if is_en else 'right'};">
              <label class="toggle-row">
                <span>{('Block New Accounts' if is_en else 'حماية الحسابات الحديثة')}</span>
                <input type="checkbox" name="anti_new_accounts" {'checked' if cfg.get('anti_new_accounts') else ''}>
              </label>
            </div>
            <span class="field-label">{('Minimum Account Age (Days)' if is_en else 'أقل عمر للحساب (بالأيام)')}</span>
            <input class="ctrl" type="number" min="1" max="365" name="min_account_age_days" value="{int(cfg.get('min_account_age_days', 7))}">
            """
        panel_html = f"""
        <form class="card" style="text-align:center;" method="POST" action="/guild?id={esc(gid)}&tab={active_tab}">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <input type="hidden" name="req_nonce" value="{req_nonce}">
          <input type="hidden" name="guild_id" value="{esc(gid)}">
          <input type="hidden" name="section" value="{active_tab}">
          <h3>{t_label}</h3>
          <p class="muted">{desc}</p>
          <div class="check-wrap">
            <label class="check-box">
              <input type="checkbox" name="{fname}" {'checked' if cfg.get(fname) else ''}>
            </label>
          </div>
          {raid_extra}
          <button class="btn" type="submit" style="margin-top:16px;">{('Save Status' if is_en else 'حفظ الحالة')}</button>
        </form>
        """

    elif active_tab == "mod":
        panel_html = f"""
        <form class="card" method="POST" action="/guild?id={esc(gid)}&tab=mod">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <input type="hidden" name="req_nonce" value="{req_nonce}">
          <input type="hidden" name="guild_id" value="{esc(gid)}">
          <input type="hidden" name="section" value="mod">
          <h3>{('Remote Moderation' if is_en else 'Moderation عن بُعد')}</h3>
          <span class="field-label">{('Action' if is_en else 'الإجراء')}</span>
          <select class="ctrl" name="cmd_action">
            <option value="kick">Kick</option>
            <option value="ban">Ban</option>
            <option value="timeout">Timeout</option>
            <option value="unban">Unban</option>
          </select>
          <span class="field-label">User ID</span>
          <input class="ctrl" type="text" name="target_user" placeholder="{('Enter User ID' if is_en else 'أدخل ID العضو')}">
          <div style="margin-top:14px;"><button class="btn" type="submit">{('Execute' if is_en else 'تنفيذ الأمر')}</button></div>
        </form>
        """

    elif active_tab == "whitelist":
        wl = cfg.get("whitelist", [])
        wl_items = "".join(
            f"<div class='log-row' style='display:flex;justify-content:space-between;align-items:center;'>"
            f"<code>{esc(uid)}</code>"
            f"<form method='POST' action='/guild?id={esc(gid)}&tab=whitelist' style='margin:0;'>"
            f"<input type='hidden' name='csrf_token' value='{csrf_token}'>"
            f"<input type='hidden' name='req_nonce' value='{req_nonce}'>"
            f"<input type='hidden' name='guild_id' value='{esc(gid)}'>"
            f"<input type='hidden' name='section' value='whitelist'>"
            f"<input type='hidden' name='wl_remove' value='{esc(uid)}'>"
            f"<button class='btn ghost' type='submit'>{'Remove' if is_en else 'إزالة'}</button></form></div>"
            for uid in wl
        ) or f"<p class='muted'>{'No users in whitelist.' if is_en else 'لا يوجد أعضاء في Whitelist حالياً.'}</p>"

        tr_list = cfg.get("trusted_admins", [])
        tr_items = "".join(
            f"<div class='log-row' style='display:flex;justify-content:space-between;align-items:center;'>"
            f"<code>{esc(uid)}</code>"
            f"<form method='POST' action='/guild?id={esc(gid)}&tab=whitelist' style='margin:0;'>"
            f"<input type='hidden' name='csrf_token' value='{csrf_token}'>"
            f"<input type='hidden' name='req_nonce' value='{req_nonce}'>"
            f"<input type='hidden' name='guild_id' value='{esc(gid)}'>"
            f"<input type='hidden' name='section' value='whitelist'>"
            f"<input type='hidden' name='tr_remove' value='{esc(uid)}'>"
            f"<button class='btn ghost' type='submit'>{'Remove' if is_en else 'إزالة'}</button></form></div>"
            for uid in tr_list
        ) or "<p class='muted'>لا يوجد إداريون موثوقون مضافون.</p>"

        panel_html = f"""
        <div class="card">
          <h3>Whitelist</h3>
          <form method="POST" action="/guild?id={esc(gid)}&tab=whitelist" style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:14px;">
            <input type="hidden" name="csrf_token" value="{csrf_token}">
            <input type="hidden" name="req_nonce" value="{req_nonce}">
            <input type="hidden" name="guild_id" value="{esc(gid)}">
            <input type="hidden" name="section" value="whitelist">
            <input class="ctrl" type="text" name="wl_add" placeholder="User ID">
            <button class="btn" type="submit">{('Add' if is_en else 'إضافة')}</button>
          </form>
          {wl_items}
        </div>
        <div class="card">
          <h3>الإداريون الموثوقون (Trusted Admins)</h3>
          <form method="POST" action="/guild?id={esc(gid)}&tab=whitelist" style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:14px;">
            <input type="hidden" name="csrf_token" value="{csrf_token}">
            <input type="hidden" name="req_nonce" value="{req_nonce}">
            <input type="hidden" name="guild_id" value="{esc(gid)}">
            <input type="hidden" name="section" value="whitelist">
            <input class="ctrl" type="text" name="tr_add" placeholder="Trusted Admin User ID">
            <button class="btn" type="submit">إضافة موثوق</button>
          </form>
          {tr_items}
        </div>
        """

    else:
        incidents = get_incidents(gid if gid.isdigit() else "", 20)
        inc_html = "".join(
            f"<div class='log-row'><code>{esc(x.get('time',''))}</code> [{esc(x.get('severity','INFO'))} • {esc(x.get('category',''))}] {esc(x.get('summary',''))}</div>"
            for x in incidents
        ) or "<p class='muted'>لا توجد حوادث مسجلة في التسلسل الزمني.</p>"

        logs = get_recent_logs(25)
        log_html = "".join(
            f"<div class='log-row'><code>{esc(item.get('time',''))}</code> [{esc(item.get('level','LOG'))}] {esc(item.get('message',''))}</div>"
            for item in logs
        ) or f"<p class='muted'>{'No logs yet.' if is_en else 'لا توجد سجلات بعد.'}</p>"
        panel_html = f"""
        <div class="card"><h3>التسلسل الزمني للحوادث (Incident Timeline)</h3>{inc_html}</div>
        <div class="card"><h3>{'Logs' if is_en else 'السجلات'}</h3>{log_html}</div>
        """

    prem_shortcut = (
        f"<div style='margin-top:12px;'><a class='btn gold' href='/premium?id={esc(gid)}'>{('Customize Bot Profile for Server (Premium)' if is_en else 'تخصيص صورة/بنر/بايو البوت لهذا السيرفر (Premium)')}</a></div>"
        if is_premium_user(user) and gid.isdigit()
        else ""
    )

    body = f"""
    <div class="card" style="text-align:center;">
      <div class="muted">{('Selected Server' if is_en else 'السيرفر المحدد')}</div>
      <div style="display:flex;justify-content:center;align-items:center;gap:10px;margin:10px 0 8px;">
        {guild_icon_html}
        <h2 style="margin:0;font-size:22px;font-weight:900;">{esc(guild_display_name)}</h2>
      </div>
      <div class="muted" style="margin-bottom:12px;">تقييم أمان السيرفر: <strong>{sec_score}/100</strong> • <span style="color:#c4b5fd;">{esc(sec_grade)}</span></div>
      <form method="GET" action="/guild" style="display:flex;flex-wrap:wrap;justify-content:center;gap:8px;">
        <input type="hidden" name="tab" value="{active_tab}">
        <input class="ctrl" type="text" name="id" value="{esc(guild_display_name if guild_info else gid)}" placeholder="{('Server name or ID' if is_en else 'اسم السيرفر أو ID')}">
        <button class="btn" type="submit">{('Switch Server' if is_en else 'تبديل السيرفر')}</button>
      </form>
      {prem_shortcut}
    </div>
    <div class="grid-2" style="margin-bottom:16px;">
      {tabs_html}
    </div>
    {panel_html}
    """
    return web.Response(text=render_page("Security Panel" if is_en else "لوحة الحماية", "guild", body, request, flash=flash), content_type="text/html")


async def handle_premium(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    user = get_discord_session(request)
    if not user:
        return web.Response(
            text=render_page("Premium" if is_en else "مزايا البريميوم", "premium", "", request, require_auth_view=True),
            content_type="text/html",
        )
    if not is_premium_user(user):
        body = f"""
        <div class="page-title">
          <div class="sub">PREMIUM ONLY</div>
          <h1>{('Premium Features' if is_en else 'مزايا البريميوم')}</h1>
        </div>
        <div class="card" style="text-align:center;">
          <p class="muted">{('This section is for Premium users to customize bot avatar, banner, and bio per server.' if is_en else 'هذه اللوحة مخصصة لأعضاء البريميوم فقط لتغيير صورة وبنر وبايو البوت داخل سيرفرهم.')}</p>
          <a class="btn ghost" href="/servers">{('Back to Servers' if is_en else 'العودة للسيرفرات')}</a>
        </div>
        """
        return web.Response(text=render_page("Premium" if is_en else "البريميوم", "premium", body, request), content_type="text/html")

    guilds, _ = get_user_visible_guilds(user)
    usable_guilds = [g for g in guilds if not g.get("bot_missing")]
    gid = str(request.query.get("id", "")).strip()
    if not gid and usable_guilds:
        gid = usable_guilds[0]["id"]

    flash = ""
    if request.method == "POST":
        form = await request.post()
        if not verify_csrf_token(str(form.get("csrf_token", "")).strip()):
            flash = "Session expired, please try again." if is_en else "انتهت صلاحية الجلسة، أعد المحاولة."
        else:
            posted_gid = str(form.get("guild_id", gid)).strip()
            if posted_gid.isdigit():
                gid = posted_gid
                bio_val = str(form.get("bio", "")).strip()[:190]
                avatar_val = str(form.get("avatar_url", "")).strip()[:400]
                banner_val = str(form.get("banner_url", "")).strip()[:400]
                save_guild_cfg(
                    gid,
                    {
                        "guild_profile": {
                            "bio": bio_val,
                            "avatar_url": avatar_val,
                            "banner_url": banner_val,
                        }
                    },
                )
                enqueue_remote_action(
                    gid,
                    "set_guild_profile",
                    gid,
                    {
                        "bio": bio_val,
                        "avatar_url": avatar_val,
                        "banner_url": banner_val,
                        "requested_by": str(user.get("id", "")),
                    },
                )
                log_event(
                    f"تحديث بروفايل البوت للسيرفر {gid} (صورة/بنر/بايو) بواسطة {user.get('id')}",
                    guild_id=gid,
                    level="PREM",
                )
                flash = (
                    "Saved and queued bot profile update for this server only."
                    if is_en
                    else "تم حفظ وإرسال طلب تحديث صورة/بنر/بايو البوت لهذا السيرفر فقط."
                )

    cfg = get_guild_cfg(gid) if gid.isdigit() else json.loads(json.dumps(DEFAULT_GUILD_CFG))
    gprof = cfg.get("guild_profile", {})
    csrf_token = issue_csrf_token()

    options_html = "".join(
        f"<option value='{esc(g['id'])}' {'selected' if g['id'] == gid else ''}>{esc(g['name'])}</option>"
        for g in usable_guilds
    ) or f"<option value='{esc(gid)}'>{esc(gid)}</option>"

    body = f"""
    <div class="page-title">
      <div class="sub">PER-SERVER CUSTOMIZATION</div>
      <h1>{('Premium Panel' if is_en else 'لوحة البريميوم (Premium)')}</h1>
    </div>
    <form class="card" method="POST" action="/premium?id={esc(gid)}" style="text-align:center;">
      <input type="hidden" name="csrf_token" value="{csrf_token}">
      <p class="muted">{('Changes apply only to this selected server.' if is_en else 'التعديلات هنا تطبق على بروفايل البوت داخل السيرفر المحدد فقط ولا تؤثر على باقي السيرفرات.')}</p>

      <span class="field-label">{('Select Server' if is_en else 'اختر السيرفر')}</span>
      <select class="ctrl" name="guild_id">
        {options_html}
      </select>

      <span class="field-label">{('Bot Avatar URL (Per Server)' if is_en else 'رابط صورة البوت داخل السيرفر (Avatar URL)')}</span>
      <input class="ctrl" type="url" name="avatar_url" value="{esc(gprof.get('avatar_url', ''))}" placeholder="https://example.com/avatar.png">

      <span class="field-label">{('Bot Banner URL (Per Server)' if is_en else 'رابط بنر البوت داخل السيرفر (Banner URL)')}</span>
      <input class="ctrl" type="url" name="banner_url" value="{esc(gprof.get('banner_url', ''))}" placeholder="https://example.com/banner.png">

      <span class="field-label">{('Bot Bio (Per Server)' if is_en else 'بايو البوت داخل السيرفر (Guild Bio)')}</span>
      <input class="ctrl" type="text" name="bio" value="{esc(gprof.get('bio', ''))}" maxlength="190" placeholder="{('Server bot bio' if is_en else 'اكتب البايو الخاص بالبوت في هذا السيرفر')}">

      <div style="margin-top:16px;">
        <button class="btn gold" type="submit">{('Save for This Server' if is_en else 'حفظ وتطبيق على هذا السيرفر')}</button>
      </div>
    </form>
    """
    return web.Response(text=render_page("Premium" if is_en else "البريميوم", "premium", body, request, flash=flash), content_type="text/html")


async def handle_admin(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    user = get_discord_session(request)
    if not user:
        return web.Response(
            text=render_page("Admin Panel" if is_en else "لوحة الإدارة", "admin", "", request, require_auth_view=True),
            content_type="text/html",
        )
    if not is_site_admin(user):
        body = f"""
        <div class="page-title">
          <div class="sub">RESTRICTED ACCESS</div>
          <h1>{('Admin Panel' if is_en else 'لوحة الإدارة')}</h1>
        </div>
        <div class="card" style="text-align:center;">
          <p class="muted">{('Admins only.' if is_en else 'هذه الصفحة مخصصة للمشرفين فقط.')}</p>
          <a class="btn ghost" href="/servers">{('Back to Servers' if is_en else 'العودة للسيرفرات')}</a>
        </div>
        """
        return web.Response(text=render_page("Admin Panel" if is_en else "لوحة الإدارة", "admin", body, request), content_type="text/html")

    flash = ""
    if request.method == "POST":
        form = await request.post()
        if not verify_csrf_token(str(form.get("csrf_token", "")).strip()):
            flash = "Session expired, please try again." if is_en else "انتهت صلاحية الجلسة، أعد المحاولة."
        else:
            action = str(form.get("admin_action", "")).strip()

            if action == "grant_admin":
                target_uid = str(form.get("target_admin_id", "")).strip()
                if set_admin_user(target_uid, True, granted_by=str(user.get("id", ""))):
                    log_event(f"منح صلاحية Admin للحساب {target_uid} بواسطة {user.get('id')}", level="ADMIN")
                    flash = f"Granted Admin to {target_uid}." if is_en else f"تم منح صلاحية Admin للحساب {target_uid} بنجاح."
                else:
                    flash = "Enter a valid numeric User ID." if is_en else "أدخل User ID صحيح (أرقام فقط)."

            elif action == "revoke_admin":
                target_uid = str(form.get("target_admin_id", "")).strip()
                if set_admin_user(target_uid, False):
                    log_event(f"سحب صلاحية Admin من الحساب {target_uid} بواسطة {user.get('id')}", level="ADMIN")
                    flash = f"Revoked Admin from {target_uid}." if is_en else f"تم سحب صلاحية Admin من الحساب {target_uid}."
                else:
                    flash = "Cannot revoke owner admin or invalid ID." if is_en else "لا يمكن سحب الصلاحية من هذا الحساب أو المعرف غير صحيح."

            elif action == "grant_premium":
                target_uid = str(form.get("target_user_id", "")).strip()
                if set_premium_user(target_uid, True, granted_by=str(user.get("id", ""))):
                    log_event(f"منح بريميوم للحساب {target_uid}", level="ADMIN")
                    flash = f"Granted Premium to {target_uid}." if is_en else f"تم منح البريميوم للحساب {target_uid} بنجاح."
                else:
                    flash = "Enter a valid User ID." if is_en else "أدخل User ID صحيح."

            elif action == "revoke_premium":
                target_uid = str(form.get("target_user_id", "")).strip()
                if set_premium_user(target_uid, False):
                    log_event(f"سحب بريميوم من الحساب {target_uid}", level="ADMIN")
                    flash = f"Revoked Premium from {target_uid}." if is_en else f"تم سحب البريميوم من الحساب {target_uid}."
                else:
                    flash = "Cannot revoke or invalid ID." if is_en else "لا يمكن سحب البريميوم من هذا الحساب أو المعرف غير صحيح."

            elif action == "toggle_lockdown":
                target_gid = str(form.get("target_guild_id", "")).strip()
                if target_gid.isdigit():
                    cur_cfg = get_guild_cfg(target_gid)
                    new_lock = not bool(cur_cfg.get("lockdown", False))
                    save_guild_cfg(target_gid, {"lockdown": new_lock})
                    enqueue_remote_action(target_gid, "set_lockdown", target_gid, {"enabled": new_lock})
                    log_event(
                        f"تغيير حالة قفل السيرفر {target_gid} إلى {'مقفول' if new_lock else 'مفتوح'}",
                        guild_id=target_gid,
                        level="ADMIN",
                    )
                    flash = (
                        f"Lockdown {'enabled' if new_lock else 'disabled'} for server."
                        if is_en
                        else f"تم {'تفعيل' if new_lock else 'إلغاء'} قفل السيرفر بنجاح."
                    )

            elif action == "toggle_emergency":
                target_gid = str(form.get("target_guild_id", "")).strip()
                if target_gid.isdigit():
                    cur_cfg = get_guild_cfg(target_gid)
                    new_emg = not bool(cur_cfg.get("emergency_mode", False))
                    save_guild_cfg(target_gid, {"emergency_mode": new_emg})
                    log_event(
                        f"تغيير وضع الطوارئ للسيرفر {target_gid} إلى {'مفعّل' if new_emg else 'متوقف'}",
                        guild_id=target_gid,
                        level="ADMIN",
                    )
                    flash = f"تم {'تفعيل' if new_emg else 'إيقاف'} وضع الطوارئ للسيرفر {target_gid}."

            elif action == "leave_guild":
                target_gid = str(form.get("target_guild_id", "")).strip()
                if target_gid.isdigit():
                    enqueue_remote_action(target_gid, "leave_guild", target_gid)
                    log_event(f"إخراج البوت من السيرفر {target_gid} بواسطة الإدارة", guild_id=target_gid, level="ADMIN")
                    flash = f"Queued leave guild {target_gid}." if is_en else f"تم إرسال أمر إخراج البوت من السيرفر {target_gid}."

            elif action == "broadcast_alert":
                b_msg = str(form.get("broadcast_text", "")).strip()[:240]
                if b_msg:
                    enqueue_remote_action("0", "broadcast_alert", "all", {"message": b_msg})
                    log_event(f"إرسال تنبيه عام: {b_msg}", level="ADMIN")
                    flash = "تم إرسال التنبيه العام إلى قائمة الأوامر."
                else:
                    flash = "اكتب نص التنبيه أولاً."

            elif action == "create_backup":
                b = create_db_backup()
                log_event(f"إنشاء نسخة احتياطية لقاعدة البيانات [{b['backup_id']}]", level="ADMIN")
                flash = f"تم إنشاء نسخة احتياطية برقم [{b['backup_id']}]."

            elif action == "test_restore":
                ok, rmsg = test_backup_restore(str(form.get("backup_id", "")).strip())
                log_event(rmsg, level="ADMIN" if ok else "WARN")
                flash = rmsg

            elif action == "ping_bot":
                MEM_BOT_HEARTBEAT["status"] = "ONLINE"
                MEM_BOT_HEARTBEAT["last_seen"] = _now_str()
                enqueue_remote_action("0", "heartbeat_check", "bot")
                flash = f"حالة تشغيل البوت: {MEM_BOT_HEARTBEAT['status']} • آخر فحص: {MEM_BOT_HEARTBEAT['last_seen']}"

    csrf_token = issue_csrf_token()
    all_guilds = get_all_guilds()
    prem_users = get_premium_list()
    admin_users = get_admin_list()
    backups = get_db_backups()
    db_state = "MongoDB متصل ومحمّي" if db is not None else "الذاكرة الاحتياطية مفعّلة"

    admin_rows = ""
    for a in admin_users:
        auid = esc(a["user_id"])
        rem_btn = (
            f"<form method='POST' action='/admin' style='margin:0;'>"
            f"<input type='hidden' name='csrf_token' value='{csrf_token}'>"
            f"<input type='hidden' name='admin_action' value='revoke_admin'>"
            f"<input type='hidden' name='target_admin_id' value='{auid}'>"
            f"<button class='btn ghost' type='submit'>{'Remove' if is_en else 'سحب'}</button></form>"
            if a["user_id"] != ADMIN_USER_ID
            else f"<span class='pill-tag pill-purple'>{'OWNER' if is_en else 'أساسي'}</span>"
        )
        admin_rows += f"""
        <div class="member-pill">
          <div><code>{auid}</code> <span class="muted">• {esc(a.get('granted_by','admin'))}</span></div>
          {rem_btn}
        </div>
        """

    guilds_rows = ""
    for g in all_guilds:
        gid = esc(g["id"])
        gname = esc(g["name"])
        mcount = int(g.get("member_count", 0) or 0)
        icon = esc(str(g.get("icon", "")).strip())
        g_cfg = get_guild_cfg(g["id"])
        is_locked = bool(g_cfg.get("lockdown", False))
        is_emg = bool(g_cfg.get("emergency_mode", False))
        lock_lbl = (
            ("Unlock Server" if is_locked else "Lock Server")
            if is_en
            else ("فتح السيرفر" if is_locked else "قفل السيرفر")
        )
        emg_lbl = "إيقاف الطوارئ" if is_emg else "طوارئ"
        icon_preview = (
            f"<img src='https://cdn.discordapp.com/icons/{gid}/{icon}.png?size=64' style='width:44px;height:44px;border-radius:12px;object-fit:cover;' alt=''>"
            if icon
            else f"<div style='width:44px;height:44px;border-radius:12px;background:#261d4d;display:flex;align-items:center;justify-content:center;font-weight:800;'>{esc((g['name'][:2] or 'SV').upper())}</div>"
        )
        status_badges = f"{'• LOCKED ' if is_locked else ''}{'• EMERGENCY' if is_emg else ''}"
        guilds_rows += f"""
        <div class="member-pill" style="flex-wrap:wrap;">
          <div style="display:flex;align-items:center;gap:10px;">
            {icon_preview}
            <div>
              <div style="font-weight:800;font-size:15px;">{gname}</div>
              <div class="muted">{mcount} {'members' if is_en else 'عضو'} {esc(status_badges)}</div>
            </div>
          </div>
          <div style="display:flex;flex-wrap:wrap;gap:8px;">
            <a class="btn ghost" href="/guild?id={gid}&tab=antinuke">{('Manage' if is_en else 'إدارة')}</a>
            <form method="POST" action="/admin" style="margin:0;">
              <input type="hidden" name="csrf_token" value="{csrf_token}">
              <input type="hidden" name="admin_action" value="toggle_lockdown">
              <input type="hidden" name="target_guild_id" value="{gid}">
              <button class="btn gold" type="submit">{lock_lbl}</button>
            </form>
            <form method="POST" action="/admin" style="margin:0;">
              <input type="hidden" name="csrf_token" value="{csrf_token}">
              <input type="hidden" name="admin_action" value="toggle_emergency">
              <input type="hidden" name="target_guild_id" value="{gid}">
              <button class="btn ghost" type="submit">{emg_lbl}</button>
            </form>
            <form method="POST" action="/admin" style="margin:0;">
              <input type="hidden" name="csrf_token" value="{csrf_token}">
              <input type="hidden" name="admin_action" value="leave_guild">
              <input type="hidden" name="target_guild_id" value="{gid}">
              <button class="btn danger" type="submit">{('Leave' if is_en else 'إخراج البوت')}</button>
            </form>
          </div>
        </div>
        """
    if not guilds_rows:
        guilds_rows = f"<p class='muted' style='text-align:center;'>{'No guilds registered yet.' if is_en else 'لا توجد سيرفرات مسجلة للبوت حالياً.'}</p>"

    prem_rows = ""
    for p in prem_users:
        puid = esc(p["user_id"])
        rem_btn = (
            f"<form method='POST' action='/admin' style='margin:0;'>"
            f"<input type='hidden' name='csrf_token' value='{csrf_token}'>"
            f"<input type='hidden' name='admin_action' value='revoke_premium'>"
            f"<input type='hidden' name='target_user_id' value='{puid}'>"
            f"<button class='btn ghost' type='submit'>{'Remove' if is_en else 'سحب'}</button></form>"
            if p["user_id"] != ADMIN_USER_ID
            else f"<span class='pill-tag pill-purple'>{'OWNER' if is_en else 'أساسي'}</span>"
        )
        prem_rows += f"""
        <div class="member-pill">
          <div><code>{puid}</code> <span class="muted">• {esc(p.get('granted_by','admin'))}</span></div>
          {rem_btn}
        </div>
        """

    backup_rows = ""
    for b in backups:
        bid = esc(b.get("backup_id", ""))
        backup_rows += f"""
        <div class="member-pill">
          <div><code>{bid}</code> <span class="muted">• {esc(b.get('created_at',''))}</span></div>
          <form method="POST" action="/admin" style="margin:0;">
            <input type="hidden" name="csrf_token" value="{csrf_token}">
            <input type="hidden" name="admin_action" value="test_restore">
            <input type="hidden" name="backup_id" value="{bid}">
            <button class="btn ghost" type="submit">اختبار الاستعادة</button>
          </form>
        </div>
        """
    if not backup_rows:
        backup_rows = "<p class='muted'>لا توجد نسخ احتياطية محفوظة بعد.</p>"

    body = f"""
    <div class="admin-hero">
      <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;">
        <div>
          <span class="pill-tag pill-purple">COMMAND CENTER</span>
          <h1 style="margin:6px 0 2px;font-size:24px;font-weight:900;">{('Admin Control Panel' if is_en else 'لوحة الإدارة المتقدمة')}</h1>
          <div class="muted">{esc(db_state)} • حالة البوت: <strong>{esc(MEM_BOT_HEARTBEAT['status'])}</strong> • تشفير الأسرار: <code>{esc(mask_secret_preview(SESSION_SECRET))}</code></div>
        </div>
      </div>
      <div class="admin-kpis">
        <div class="kpi-tile">
          <div class="kpi-val">{len(all_guilds)}</div>
          <div class="kpi-lbl">{('Servers' if is_en else 'السيرفرات')}</div>
        </div>
        <div class="kpi-tile">
          <div class="kpi-val">{len(admin_users)}</div>
          <div class="kpi-lbl">{('Admins' if is_en else 'الأدمن')}</div>
        </div>
        <div class="kpi-tile">
          <div class="kpi-val">{len(prem_users)}</div>
          <div class="kpi-lbl">{('Premium' if is_en else 'البريميوم')}</div>
        </div>
        <div class="kpi-tile">
          <div class="kpi-val">{len(backups)}</div>
          <div class="kpi-lbl">نسخ احتياطية</div>
        </div>
      </div>
    </div>

    <div class="card">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">
        <h3 style="margin:0;">🛡️ {('Admin Roles by User ID' if is_en else 'إعطاء صلاحية Admin عبر User ID')}</h3>
        <span class="pill-tag pill-purple">ADMIN</span>
      </div>
      <form method="POST" action="/admin" class="admin-form-row">
        <input type="hidden" name="csrf_token" value="{csrf_token}">
        <input type="hidden" name="admin_action" value="grant_admin">
        <input class="ctrl" type="text" name="target_admin_id" placeholder="{('Enter Account User ID' if is_en else 'أدخل User ID الحساب')}" required>
        <button class="btn" type="submit">{('Give Admin' if is_en else 'إعطاء Admin')}</button>
      </form>
      {admin_rows}
    </div>

    <div class="card">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">
        <h3 style="margin:0;">✨ {('Premium Access by User ID' if is_en else 'منح البريميوم (Premium)')}</h3>
        <span class="pill-tag pill-green">PREMIUM</span>
      </div>
      <form method="POST" action="/admin" class="admin-form-row">
        <input type="hidden" name="csrf_token" value="{csrf_token}">
        <input type="hidden" name="admin_action" value="grant_premium">
        <input class="ctrl" type="text" name="target_user_id" placeholder="{('Enter Account User ID' if is_en else 'أدخل User ID الشخص')}" required>
        <button class="btn gold" type="submit">{('Give Premium' if is_en else 'إعطاء بريميوم')}</button>
      </form>
      {prem_rows}
    </div>

    <div class="card">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">
        <h3 style="margin:0;">📣 تنبيه عام، النسخ الاحتياطي، ومراقبة البوت</h3>
        <span class="pill-tag pill-purple">OPS</span>
      </div>
      <form method="POST" action="/admin" class="admin-form-row">
        <input type="hidden" name="csrf_token" value="{csrf_token}">
        <input type="hidden" name="admin_action" value="broadcast_alert">
        <input class="ctrl" type="text" name="broadcast_text" placeholder="رسالة تنبيه عامة للبوت">
        <button class="btn gold" type="submit">إرسال تنبيه</button>
      </form>
      <div class="admin-form-row">
        <form method="POST" action="/admin" style="margin:0;">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <input type="hidden" name="admin_action" value="create_backup">
          <button class="btn" type="submit">إنشاء نسخة احتياطية</button>
        </form>
        <form method="POST" action="/admin" style="margin:0;">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <input type="hidden" name="admin_action" value="ping_bot">
          <button class="btn ghost" type="submit">فحص تشغيل البوت</button>
        </form>
      </div>
      {backup_rows}
    </div>

    <div class="card">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">
        <h3 style="margin:0;">🌐 {('Bot Guilds' if is_en else 'السيرفرات المتواجد فيها البوت')}</h3>
        <span class="pill-tag pill-purple">{len(all_guilds)}</span>
      </div>
      {guilds_rows}
    </div>
    """
    return web.Response(text=render_page("Admin Panel" if is_en else "لوحة الإدارة", "admin", body, request, flash=flash), content_type="text/html")


async def handle_services(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    body = f"""
    <div class="page-title">
      <div class="sub">PLANS & MODULES</div>
      <h1>{('Services & Plans' if is_en else 'الخدمات والاشتراكات')}</h1>
    </div>
    <div class="feature-card">
      <h3>Full Security, Analytics & Recovery Suite</h3>
      <p class="feature-desc">{('Webhooks, apps, bots, privilege escalation, role/channel permissions, mass unban/kick/timeout, behavior analysis, snapshots, rollback, simulations, API guard, and DB backups.' if is_en else 'منظومة حماية كاملة تشمل الويب هوك والتطبيقات والبوتات، تصعيد الصلاحيات، الإجراءات الجماعية، تحليل السلوك، النسخ والاسترجاع، محاكاة الهجمات، وحماية قاعدة البيانات.')}</p>
    </div>
    <div class="feature-card">
      <h3>Per-Server Bot Profile (Premium)</h3>
      <p class="feature-desc">{('Customize bot avatar, banner, and bio inside a single server without affecting others.' if is_en else 'تخصيص صورة البوت وبنره وبايو البوت داخل سيرفر محدد فقط دون التأثير على باقي السيرفرات.')}</p>
    </div>
    """
    return web.Response(text=render_page("Services" if is_en else "الخدمات", "services", body, request), content_type="text/html")


async def handle_updates(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    logs = get_recent_logs(40)
    rows = "".join(
        f"<div class='log-row'><code>{esc(item.get('time',''))}</code> [{esc(item.get('level','LOG'))}] {esc(item.get('message',''))}</div>"
        for item in logs
    ) or f"<p class='muted'>{'No updates or logs yet.' if is_en else 'لا توجد تحديثات أو سجلات مسجلة حالياً.'}</p>"
    body = f"""
    <div class="page-title">
      <div class="sub">CHANGELOG & ACTIVITY</div>
      <h1>{('Updates & Logs' if is_en else 'التحديثات والسجلات')}</h1>
    </div>
    <div class="card">{rows}</div>
    """
    return web.Response(text=render_page("Updates" if is_en else "التحديثات", "updates", body, request), content_type="text/html")


async def handle_links(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    main_url = esc(detect_main_url(request))
    web_url = esc(detect_base_url(request))
    gid = esc(str(request.query.get("id", "")).strip())
    guild_url = f"{web_url}/guild?id={gid}&tab=antinuke" if gid else f"{web_url}/guild?tab=antinuke"
    body = f"""
    <div class="page-title">
      <div class="sub">QUICK LINKS</div>
      <h1>{('Links' if is_en else 'الروابط')}</h1>
    </div>
    <div class="card">
      <div class="log-row"><strong>{('Main Site' if is_en else 'الموقع الرئيسي')}:</strong> <a href="{main_url}/" style="color:#a78bfa;">{main_url}/</a></div>
      <div class="log-row"><strong>{('Servers' if is_en else 'السيرفرات')}:</strong> <a href="{web_url}/servers" style="color:#a78bfa;">{web_url}/servers</a></div>
      <div class="log-row"><strong>{('Security Panel' if is_en else 'لوحة الحماية')}:</strong> <a href="{guild_url}" style="color:#a78bfa;">{guild_url}</a></div>
      <div class="log-row"><strong>{('Bot Invite' if is_en else 'دعوة البوت')}:</strong> <a href="{esc(BOT_INVITE_URL)}" target="_blank" rel="noopener" style="color:#a78bfa;">{esc(BOT_INVITE_URL)}</a></div>
    </div>
    """
    return web.Response(text=render_page("Links" if is_en else "الروابط", "links", body, request), content_type="text/html")


async def handle_login(request: web.Request) -> web.Response:
    if not DISCORD_CLIENT_ID:
        return web.Response(text="DISCORD_CLIENT_ID غير مضبوط.", status=400, content_type="text/plain")
    params = urlencode(
        {
            "client_id": DISCORD_CLIENT_ID,
            "redirect_uri": detect_redirect_uri(request),
            "response_type": "code",
            "scope": "identify guilds",
        }
    )
    raise web.HTTPFound(f"https://discord.com/api/oauth2/authorize?{params}")


async def handle_callback(request: web.Request) -> web.Response:
    oauth_err = str(request.query.get("error", "")).strip()
    if oauth_err:
        log_event(f"محاولة دخول مرفوضة أو ملغاة من IP {get_client_ip(request)}: {oauth_err}", level="WARN")
        raise web.HTTPFound(f"/?msg={quote('تم إلغاء أو رفض الربط من ديسكورد: ' + oauth_err)}")

    code = str(request.query.get("code", "")).strip()
    if not code or not DISCORD_CLIENT_ID or not DISCORD_CLIENT_SECRET:
        log_event(f"محاولة دخول ناقصة من IP {get_client_ip(request)}", level="WARN")
        raise web.HTTPFound(f"/?msg={quote('بيانات OAuth2 ناقصة أو لم يتم استلام رمز الدخول.')}")

    try:
        async with ClientSession() as session:
            async with session.post(
                "https://discord.com/api/oauth2/token",
                data={
                    "client_id": DISCORD_CLIENT_ID,
                    "client_secret": DISCORD_CLIENT_SECRET,
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": detect_redirect_uri(request),
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10,
            ) as resp:
                if resp.status != 200:
                    err_txt = (await resp.text())[:140]
                    log_event(f"فشل تبادل التوكن ({resp.status}): {err_txt}", level="OAUTH")
                    raise web.HTTPFound(f"/?msg={quote('فشل إتمام الربط مع ديسكورد (تحقق من Client Secret و Redirect URI).')}")
                token_data = await resp.json()

            access_token = str(token_data.get("access_token", "")).strip()
            headers = {"Authorization": f"Bearer {access_token}"}

            async with session.get("https://discord.com/api/users/@me", headers=headers, timeout=10) as uresp:
                if uresp.status != 200:
                    raise web.HTTPFound(f"/?msg={quote('تعذر جلب بيانات الحساب من ديسكورد.')}")
                u = await uresp.json()

            compact_guilds = []
            async with session.get("https://discord.com/api/users/@me/guilds", headers=headers, timeout=10) as gresp:
                if gresp.status == 200:
                    gdata = await gresp.json()
                    if isinstance(gdata, list):
                        for g in gdata[:60]:
                            gid = str(g.get("id", "")).strip()
                            if gid.isdigit():
                                compact_guilds.append(
                                    {
                                        "id": gid,
                                        "name": str(g.get("name", f"Server {gid}"))[:60],
                                        "icon": str(g.get("icon", "") or "")[:40],
                                        "owner": bool(g.get("owner", False)),
                                        "permissions": int(g.get("permissions", 0) or 0),
                                    }
                                )

        payload = {
            "id": str(u.get("id", "")),
            "username": str(u.get("username", "User"))[:40],
            "avatar": str(u.get("avatar", "") or "")[:40],
            "guilds": compact_guilds,
            "exp": float(time.time() + 86400 * 7),
        }
        signed_tok = sign_session(payload)
        log_event(f"تم تسجيل دخول الحساب {payload['username']} ({payload['id']}) [{encrypt_secret(payload['id'])[:18]}]", level="AUTH")

        html_out = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head><meta charset="utf-8"><title>جاري الدخول...</title></head>
<body style="background:#080a12;color:#f8fafc;font-family:sans-serif;text-align:center;padding-top:60px;">
<p>تم ربط الحساب بنجاح، جاري فتح الداشبورد...</p>
<script>
try {{
  var t = {json.dumps(signed_tok)};
  localStorage.setItem("arab_sec_tok", t);
  document.cookie = "arab_sec_session=" + encodeURIComponent(t) + "; path=/; max-age=" + (86400 * 7);
}} catch (e) {{}}
window.location.href = "/servers";
</script>
</body>
</html>"""
        resp = web.Response(text=html_out, content_type="text/html")
        resp.set_cookie(
            "arab_sec_session",
            signed_tok,
            max_age=86400 * 7,
            httponly=False,
            secure=True,
            samesite="Lax",
            path="/",
        )
        return resp
    except web.HTTPException:
        raise
    except Exception as exc:
        log_event(f"فشل ربط الحساب: {exc}", level="WARN")
        raise web.HTTPFound(f"/?msg={quote('تعذر الاتصال بديسكورد أثناء الربط، أعد المحاولة.')}")


async def handle_logout(request: web.Request) -> web.Response:
    tok = request.cookies.get("arab_sec_session") or request.headers.get("X-Arab-Session")
    if tok:
        SESSIONS.pop(tok, None)
    resp = web.HTTPFound("/")
    resp.del_cookie("arab_sec_session", path="/")
    return resp


async def handle_health(request: web.Request) -> web.Response:
    MEM_BOT_HEARTBEAT["last_seen"] = _now_str()
    return web.json_response(
        {
            "ok": True,
            "site": SITE_NAME,
            "owner": OWNER_NAME,
            "bot": MEM_BOT_HEARTBEAT,
            "db_connected": db is not None,
        }
    )


@web.middleware
async def security_middleware(request: web.Request, handler):
    ip = get_client_ip(request)
    if is_rate_limited(ip):
        return web.Response(status=429, text="تم تجاوز الحد المسموح من الطلبات.", content_type="text/plain")
    if request.path.startswith("/api/") or request.path == "/health":
        if request.headers.get("X-Replay-Check") == "1" and is_replay_request(request.headers.get("X-Request-Nonce")):
            return web.Response(status=409, text="طلب مكرر مرفوض.", content_type="text/plain")
    record_site_visit(request)
    try:
        response = await handler(request)
        lang_q = str(request.query.get("lang", "")).strip().lower()
        if lang_q in ("ar", "en"):
            response.set_cookie("arab_sec_lang", lang_q, max_age=86400 * 365, path="/", samesite="Lax")
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response
    except web.HTTPException:
        raise
    except Exception as exc:
        log_event(f"خطأ داخلي في المسار {request.path}: {exc}", level="ERROR")
        return web.Response(
            status=500,
            text="حدث خطأ داخلي في الخادم وتم تسجيله بأمان.",
            content_type="text/plain",
        )


def create_app() -> web.Application:
    app = web.Application(middlewares=[security_middleware])
    app.router.add_get("/", home_handler)
    app.router.add_get("/servers", handle_servers)
    app.router.add_get("/dashboard", handle_servers)
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
    app.router.add_get("/health", handle_health)
    return app


if __name__ == "__main__":
    print(f"========== {SITE_NAME} ({OWNER_NAME}) — Web on {HOST}:{PORT} ==========")
    web.run_app(create_app(), host=HOST, port=PORT, print=None)
