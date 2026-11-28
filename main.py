import asyncio
import base64
import ipaddress
import json
import os
import socket
import time
import traceback
import zlib
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin, urlparse

try:
    import uvloop

    uvloop.install()
except Exception:
    pass

import aiohttp
import discord
from discord import app_commands
from discord.ext import commands, tasks

try:
    from pymongo import MongoClient
    from pymongo.errors import PyMongoError
except Exception:
    MongoClient = None

    class PyMongoError(Exception):
        pass


DISCORD_TOKEN = (os.getenv("DISCORD_TOKEN") or os.getenv("BOT_TOKEN") or "").strip()
WEB_BASE_URL = (os.getenv("WEB_BASE_URL") or "https://arabsecurity.de5.net").strip().rstrip("/")
BOT_SYNC_SECRET = (
    (os.getenv("BOT_SYNC_SECRET") or "").strip()
    or (os.getenv("SILENT_SECRET") or "").strip()
    or "mvdlogQs0_Ktc6sZZMYqR_lzk2fYTZHg"
)
ADMIN_USER_ID = (os.getenv("ADMIN_USER_ID") or "1395418036919468073").strip()
BOOST_GUILD_ID = int(
    (os.getenv("BOOST_GUILD_ID") or "1572298648568729720").strip() or "1572298648568729720"
)

STATS_ALLOWED_IDS = {"1328402855593508874", "1395418036919468073"}
if ADMIN_USER_ID:
    STATS_ALLOWED_IDS.add(ADMIN_USER_ID)

RESTRICTED_OWNER_IDS = {"1328402855593508874", "1395418036919468073"}

MONGO_URI = (
    os.getenv("MONGO_URI")
    or "mongodb+srv://soudfares02_db_user:QiADlkDohqCpFP6z@cluster0.hzhfdxt.mongodb.net/arab_security?retryWrites=true&w=majority"
).strip()
MONGO_DB_NAME = (os.getenv("MONGO_DB") or "arab_security").strip() or "arab_security"

MAX_BIO_LEN = 190
MAX_URL_LEN = 500
MAX_MEDIA_BYTES = 10 * 1024 * 1024
MAX_REDIRECTS = 5
EXPIRY_HOURS = 12
EXPIRY_SECONDS = EXPIRY_HOURS * 3600
MAX_OVERWRITES_PER_CHANNEL = 40
ADMIN_PERM_FLAG = int(discord.Permissions.administrator.flag)

TICKET_NAME_TOKENS = ("ticket", "tickets", "تكت", "تكتات", "تذكره", "تذكرة", "التذاكر")

_db = None
guild_settings_col = None
bot_guilds_col = None
remote_commands_col = None
site_stats_col = None
guild_profiles_col = None
premium_users_col = None
guild_backups_col = None
deleted_items_col = None
_DB_WARNED = False

if MONGO_URI and MongoClient is not None:
    try:
        _mongo_client = MongoClient(
            MONGO_URI,
            serverSelectionTimeoutMS=5000,
            connectTimeoutMS=5000,
            socketTimeoutMS=5000,
            maxPoolSize=30,
            retryWrites=True,
        )
        _mongo_client.admin.command("ping")
        _db = _mongo_client[MONGO_DB_NAME]
        guild_settings_col = _db["guild_settings"]
        bot_guilds_col = _db["bot_guilds"]
        remote_commands_col = _db["remote_commands"]
        site_stats_col = _db["site_stats"]
        guild_profiles_col = _db["guild_profiles"]
        premium_users_col = _db["premium_users"]
        guild_backups_col = _db["guild_backups"]
        deleted_items_col = _db["deleted_items_12h"]
        try:
            deleted_items_col.create_index("expires_at", expireAfterSeconds=0)
            deleted_items_col.create_index([("guild_id", 1), ("deleted_at", -1)])
        except PyMongoError:
            pass
        print(f"[BOT DB] Connected persistently to MongoDB ({MONGO_DB_NAME})")
    except PyMongoError as exc:
        if not _DB_WARNED:
            _DB_WARNED = True
            print(f"[BOT DB] Running in memory fallback (Mongo check: {type(exc).__name__})")


_PROFILE_MEM: dict[str, dict] = {}
_PROFILE_CACHE: dict[str, tuple[float, dict]] = {}
_PROFILE_CACHE_TTL = 5.0
_BACKUP_MEM: dict[str, dict] = {}
_DELETED_MEM: dict[str, list[dict]] = defaultdict(list)
_IGNORE_DELETE_IDS: set[str] = set()
_GUILD_PROFILE_LOCKS: dict[str, asyncio.Lock] = {}
_ACTIVE_BOT: commands.Bot | None = None


def is_restricted_owner(user_id: int | str | None) -> bool:
    return str(user_id or "").strip() in RESTRICTED_OWNER_IDS


def _extract_guild_id(cmd: dict | None, extra: dict | None = None, fallback: str = "") -> str:
    cmd_d = cmd if isinstance(cmd, dict) else {}
    extra_d = (
        extra
        if isinstance(extra, dict)
        else (cmd_d.get("extra") if isinstance(cmd_d.get("extra"), dict) else {})
    )
    nested_dicts = [extra_d, cmd_d]
    for container in (extra_d, cmd_d):
        if isinstance(container, dict):
            for sub_key in ("profile", "guild_profile", "data", "settings", "guild_status_data"):
                if isinstance(container.get(sub_key), dict):
                    nested_dicts.append(container[sub_key])

    for src in nested_dicts:
        if not isinstance(src, dict):
            continue
        for key in ("guild_id", "guildId", "server_id", "serverId"):
            val = src.get(key)
            if val is not None:
                s = str(val).strip()
                if s.isdigit():
                    return s
    fb = str(fallback or "").strip()
    return fb if fb.isdigit() else ""


def _resolve_target_guild(
    bot: commands.Bot | None,
    cmd: dict | None,
    extra: dict | None = None,
    fallback_gid: str = "",
) -> tuple[discord.Guild | None, str, str]:
    """يتحقق بصرامة من أن التعديل يستهدف السيرفر المحدد فقط ويمنع أي تعديل عام للبوت."""
    if bot is None:
        return None, "", "البوت غير متصل."
    gid = _extract_guild_id(cmd, extra, fallback=fallback_gid)
    if not gid or not gid.isdigit():
        return None, "", "يجب تحديد السيرفر (guild_id) أولاً قبل تنفيذ التعديل."
    guild = bot.get_guild(int(gid))
    if guild is None or str(guild.id) != gid:
        return None, gid, f"البوت غير موجود في السيرفر المحدد ({gid})."
    return guild, gid, ""


def _extract_actor_id(cmd: dict | None, extra: dict | None = None) -> str:
    cmd_d = cmd if isinstance(cmd, dict) else {}
    extra_d = (
        extra
        if isinstance(extra, dict)
        else (cmd_d.get("extra") if isinstance(cmd_d.get("extra"), dict) else {})
    )
    for src in (extra_d, cmd_d):
        for key in ("user_id", "actor_id", "discord_id", "owner_id", "by", "id"):
            val = src.get(key)
            if val is not None:
                s = str(val).strip()
                if s.isdigit():
                    return s
    return ""


def _get_guild_profile_lock(gid: str) -> asyncio.Lock:
    lock = _GUILD_PROFILE_LOCKS.get(gid)
    if lock is None:
        lock = asyncio.Lock()
        _GUILD_PROFILE_LOCKS[gid] = lock
    return lock


def _is_expired_ttl(ts_val) -> bool:
    if ts_val is None:
        return False
    now_dt = datetime.now(timezone.utc)
    if isinstance(ts_val, (int, float)):
        val = float(ts_val)
        if val > 1e12:
            val /= 1000.0
        return (now_dt.timestamp() - val) >= EXPIRY_SECONDS
    if isinstance(ts_val, str):
        s = ts_val.strip()
        if not s:
            return False
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return (now_dt - dt).total_seconds() >= EXPIRY_SECONDS
        except Exception:
            return False
    if isinstance(ts_val, datetime):
        dt = ts_val if ts_val.tzinfo else ts_val.replace(tzinfo=timezone.utc)
        return (now_dt - dt).total_seconds() >= EXPIRY_SECONDS
    return False


def _is_doc_active_and_not_expired(doc: dict | None, now_ts: float) -> bool:
    if not isinstance(doc, dict):
        return False
    if doc.get("active") is False or doc.get("is_active") is False or doc.get("premium") is False:
        return False
    if bool(doc.get("permanent")) or bool(doc.get("lifetime")):
        return True

    for key in ("expires_at", "expire_at", "expiresAt", "end_date", "ends_at"):
        raw_exp = doc.get(key)
        if raw_exp is None or raw_exp == "":
            continue
        if isinstance(raw_exp, (int, float)):
            exp_v = float(raw_exp)
            if exp_v > 1e12:
                exp_v /= 1000.0
            if exp_v > now_ts:
                return True
        elif isinstance(raw_exp, datetime):
            dt = raw_exp if raw_exp.tzinfo else raw_exp.replace(tzinfo=timezone.utc)
            if dt.timestamp() > now_ts:
                return True
        elif isinstance(raw_exp, str):
            try:
                dt = datetime.fromisoformat(raw_exp.strip().replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                if dt.timestamp() > now_ts:
                    return True
            except Exception:
                pass

    if doc.get("active") is True or doc.get("is_active") is True or doc.get("premium") is True:
        return True
    return False


def _cleanup_expired_records_sync() -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=EXPIRY_HOURS)

    for gid in list(_DELETED_MEM.keys()):
        _DELETED_MEM[gid] = [
            item
            for item in _DELETED_MEM[gid]
            if not _is_expired_ttl(item.get("deleted_at"))
        ]
        if not _DELETED_MEM[gid]:
            _DELETED_MEM.pop(gid, None)

    if deleted_items_col is not None:
        try:
            deleted_items_col.delete_many({"deleted_at": {"$lt": cutoff}})
        except PyMongoError:
            pass

    if remote_commands_col is not None:
        try:
            remote_commands_col.delete_many(
                {
                    "$or": [
                        {"done_at": {"$lt": cutoff}},
                        {"created_at": {"$lt": cutoff}},
                    ]
                }
            )
        except PyMongoError:
            pass


def _is_ticket_channel(ch: discord.abc.GuildChannel) -> bool:
    cname = (getattr(ch, "name", "") or "").strip().lower()
    if any(tok in cname for tok in TICKET_NAME_TOKENS):
        return True
    cat = getattr(ch, "category", None)
    cat_name = (getattr(cat, "name", "") or "").strip().lower()
    if cat_name and any(tok in cat_name for tok in TICKET_NAME_TOKENS):
        return True
    return False


def _compress_payload(data: dict) -> dict:
    raw = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    compressed = zlib.compress(raw, level=9)
    return {
        "c": True,
        "o": len(raw),
        "z": len(compressed),
        "d": base64.b64encode(compressed).decode("ascii"),
    }


def _decompress_payload(doc: dict | None) -> dict:
    if not isinstance(doc, dict):
        return {}
    b64_data = doc.get("d") if isinstance(doc.get("d"), str) else doc.get("data")
    if (doc.get("c") or doc.get("compressed")) and isinstance(b64_data, str):
        try:
            raw = zlib.decompress(base64.b64decode(b64_data.encode("ascii")))
            parsed = json.loads(raw.decode("utf-8"))
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    snap = doc.get("snapshot")
    return snap if isinstance(snap, dict) else {}


def _serialize_single_role(r: discord.Role) -> dict | None:
    if r.is_default() or r.managed:
        return None
    if r.permissions.administrator:
        return None
    clean_perms = int(r.permissions.value) & ~ADMIN_PERM_FLAG
    return {
        "id": str(r.id),
        "name": r.name[:80],
        "color": int(r.color.value),
        "hoist": bool(r.hoist),
        "mentionable": bool(r.mentionable),
        "pos": int(r.position),
        "permissions": clean_perms,
    }


def _serialize_single_channel(ch: discord.abc.GuildChannel) -> dict | None:
    if _is_ticket_channel(ch):
        return None
    ch_type = (
        "category"
        if isinstance(ch, discord.CategoryChannel)
        else (
            "voice"
            if isinstance(ch, discord.VoiceChannel)
            else ("stage" if isinstance(ch, discord.StageChannel) else "text")
        )
    )
    overwrites = []
    for target, ow in ch.overwrites.items():
        if isinstance(target, discord.Role):
            if target.permissions.administrator:
                continue
            allow_val, deny_val = ow.pair()
            a_clean = int(allow_val.value) & ~ADMIN_PERM_FLAG
            d_clean = int(deny_val.value) & ~ADMIN_PERM_FLAG
            if a_clean != 0 or d_clean != 0:
                overwrites.append(
                    {
                        "t": "r",
                        "r": str(target.id),
                        "a": a_clean,
                        "d": d_clean,
                    }
                )
        elif isinstance(target, discord.Member):
            allow_val, deny_val = ow.pair()
            a_clean = int(allow_val.value) & ~ADMIN_PERM_FLAG
            d_clean = int(deny_val.value) & ~ADMIN_PERM_FLAG
            if a_clean != 0 or d_clean != 0:
                overwrites.append(
                    {
                        "t": "m",
                        "r": str(target.id),
                        "a": a_clean,
                        "d": d_clean,
                    }
                )
        if len(overwrites) >= MAX_OVERWRITES_PER_CHANNEL:
            break

    cat_name = None
    cat_id = None
    if getattr(ch, "category", None) and not any(
        tok in ch.category.name.lower() for tok in TICKET_NAME_TOKENS
    ):
        cat_name = ch.category.name[:80]
        cat_id = str(ch.category.id)

    item = {
        "id": str(ch.id),
        "name": ch.name[:80],
        "type": ch_type,
        "cat": cat_name,
        "cat_id": cat_id,
        "pos": int(getattr(ch, "position", 0) or 0),
        "ow": overwrites,
    }
    if isinstance(ch, discord.TextChannel):
        item["topic"] = (ch.topic or "")[:300]
        item["slowmode"] = int(ch.slowmode_delay or 0)
        item["nsfw"] = bool(ch.nsfw)
    elif isinstance(ch, discord.VoiceChannel):
        item["bitrate"] = int(ch.bitrate or 64000)
        item["limit"] = int(ch.user_limit or 0)
    return item


def _record_deleted_item_sync(gid: str, kind: str, item_data: dict) -> None:
    item_id = str(item_data.get("id") or "")
    item_name = str(item_data.get("name") or "")[:80]
    if not gid.isdigit() or not item_id or not item_name:
        return

    now_dt = datetime.now(timezone.utc)
    exp_dt = now_dt + timedelta(hours=EXPIRY_HOURS)
    packed = _compress_payload(item_data)
    key = f"{'role' if kind == 'role' else 'ch'}:{item_id}"

    mem_entry = {
        "key": key,
        "guild_id": gid,
        "kind": kind,
        "item_id": item_id,
        "name": item_name,
        "data": item_data,
        "deleted_at": now_dt,
        "expires_at": exp_dt,
        "o": packed["o"],
        "z": packed["z"],
    }
    _DELETED_MEM[gid] = [x for x in _DELETED_MEM[gid] if x.get("key") != key]
    _DELETED_MEM[gid].append(mem_entry)

    if deleted_items_col is not None:
        try:
            deleted_items_col.update_one(
                {"guild_id": gid, "key": key},
                {
                    "$set": {
                        "guild_id": gid,
                        "key": key,
                        "kind": kind,
                        "item_id": item_id,
                        "name": item_name,
                        "deleted_at": now_dt,
                        "expires_at": exp_dt,
                        **packed,
                    }
                },
                upsert=True,
            )
        except PyMongoError:
            pass


def _load_deleted_items_sync(gid: str) -> list[dict]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=EXPIRY_HOURS)
    items_by_key: dict[str, dict] = {}

    for item in list(_DELETED_MEM.get(gid) or []):
        if _is_expired_ttl(item.get("deleted_at")):
            continue
        items_by_key[item["key"]] = item

    if deleted_items_col is not None:
        try:
            deleted_items_col.delete_many({"guild_id": gid, "deleted_at": {"$lt": cutoff}})
            for doc in deleted_items_col.find({"guild_id": gid}, {"_id": 0}):
                if _is_expired_ttl(doc.get("deleted_at")):
                    continue
                unpacked = _decompress_payload(doc)
                if unpacked:
                    k = str(doc.get("key") or "")
                    items_by_key[k] = {
                        "key": k,
                        "guild_id": gid,
                        "kind": str(doc.get("kind") or "channel"),
                        "item_id": str(doc.get("item_id") or unpacked.get("id") or ""),
                        "name": str(doc.get("name") or unpacked.get("name") or ""),
                        "data": unpacked,
                        "deleted_at": doc.get("deleted_at"),
                        "o": int(doc.get("o") or 0),
                        "z": int(doc.get("z") or 0),
                    }
        except PyMongoError:
            pass

    return list(items_by_key.values())


def _remove_deleted_items_sync(gid: str, keys: list[str]) -> None:
    if not keys:
        return
    key_set = set(keys)
    if gid in _DELETED_MEM:
        _DELETED_MEM[gid] = [x for x in _DELETED_MEM[gid] if x.get("key") not in key_set]
        if not _DELETED_MEM[gid]:
            _DELETED_MEM.pop(gid, None)

    if deleted_items_col is not None:
        try:
            deleted_items_col.delete_many({"guild_id": gid, "key": {"$in": list(key_set)}})
        except PyMongoError:
            pass


def _empty_profile(guild_id: int | str) -> dict:
    return {
        "guild_id": str(guild_id),
        "avatar_url": "",
        "banner_url": "",
        "bio": "",
        "updated_at": None,
    }


def _empty_guild_profile(guild_id: int | str) -> dict:
    return _empty_profile(guild_id)


def _extract_profile_fields_from_doc(doc: dict | None, gid: str) -> dict:
    merged = _empty_profile(gid)
    if not isinstance(doc, dict):
        return merged
    nested = doc.get("guild_profile") or doc.get("profile") or {}
    sources = [doc]
    if isinstance(nested, dict):
        sources.append(nested)

    for src in sources:
        for k in ("avatar_url", "bot_avatar", "avatar", "icon_url", "avatar_data_url"):
            if k in src and str(src.get(k) or "").strip():
                merged["avatar_url"] = str(src.get(k) or "").strip()
                break
        for k in ("banner_url", "bot_banner", "banner", "banner_data_url"):
            if k in src and str(src.get(k) or "").strip():
                merged["banner_url"] = str(src.get(k) or "").strip()
                break
        for k in ("bio", "bot_bio", "guild_bio", "about", "description"):
            if k in src and str(src.get(k) or "").strip():
                merged["bio"] = str(src.get(k) or "").strip()[:MAX_BIO_LEN]
                break
    if doc.get("updated_at"):
        merged["updated_at"] = doc.get("updated_at")
    return merged


def _is_blocked_ip(ip_obj: ipaddress._BaseAddress) -> bool:
    return bool(
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
        or getattr(ip_obj, "is_site_local", False)
        or (
            isinstance(ip_obj, ipaddress.IPv6Address)
            and ip_obj.ipv4_mapped is not None
            and _is_blocked_ip(ip_obj.ipv4_mapped)
        )
    )


def _resolve_and_check_host_sync(host: str) -> tuple[bool, str]:
    clean_host = (host or "").strip().strip("[]").lower()
    if not clean_host:
        return False, "اسم المضيف غير صالح."
    if (
        clean_host in ("localhost", "localhost.localdomain")
        or clean_host.endswith(".localhost")
        or clean_host.endswith(".local")
        or clean_host.endswith(".internal")
    ):
        return False, "غير مسموح بالوصول إلى العناوين المحلية أو الداخلية."

    try:
        ip_literal = ipaddress.ip_address(clean_host)
        if _is_blocked_ip(ip_literal):
            return False, "غير مسموح بعناوين IP الخاصة أو المحلية أو المحجوزة."
        return True, str(ip_literal)
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(clean_host, None, type=socket.SOCK_STREAM)
    except OSError:
        return False, "تعذر تحليل اسم المضيف للرابط."

    if not infos:
        return False, "لم يتم العثور على عناوين للمضيف."

    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        ip_str = str(sockaddr[0]).split("%")[0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, "عنوان IP غير صالح."
        if _is_blocked_ip(ip_obj):
            return False, "الرابط يشير إلى عنوان شبكة داخلي أو محظور."

    return True, clean_host


def validate_media_url(raw_url: str | None) -> tuple[bool, str]:
    val = str(raw_url or "").strip()
    if not val:
        return True, ""
    if len(val) > MAX_URL_LEN:
        return False, "الرابط أطول من الحد المسموح."
    try:
        parsed = urlparse(val)
    except Exception:
        return False, "صيغة الرابط غير صالحة."

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return False, "يجب أن يبدأ الرابط بـ http:// أو https://."
    if parsed.username or parsed.password:
        return False, "غير مسموح ببيانات اعتماد داخل الرابط."

    host = parsed.hostname or ""
    if not host or "." not in host:
        return False, "اسم المضيف في الرابط غير صالح."

    port = parsed.port
    if port is not None and port not in (80, 443, 8080, 8443):
        return False, "المنفذ غير مسموح به."

    ok_host, err_or_host = _resolve_and_check_host_sync(host)
    if not ok_host:
        return False, err_or_host

    return True, val


def detect_image_type_from_magic(data: bytes) -> str | None:
    if not isinstance(data, (bytes, bytearray)) or len(data) < 12:
        return None
    buf = bytes(data)
    if buf.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if buf.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if buf.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if buf.startswith(b"RIFF") and buf[8:12] == b"WEBP":
        return "webp"
    return None


def _bytes_to_data_uri(data: bytes) -> str | None:
    kind = detect_image_type_from_magic(data)
    if not kind:
        return None
    mime_map = {
        "png": "image/png",
        "jpeg": "image/jpeg",
        "gif": "image/gif",
        "webp": "image/webp",
    }
    b64 = base64.b64encode(data).decode("ascii")
    return f"data:{mime_map[kind]};base64,{b64}"


def _parse_data_url_image(raw_val: str) -> tuple[bool, str, bytes | None]:
    if not raw_val.startswith("data:image/") or ";base64," not in raw_val:
        return False, "صيغة الصورة المرفوعة غير صالحة.", None
    header, b64_part = raw_val.split(";base64,", 1)
    allowed_mimes = (
        "data:image/png",
        "data:image/jpeg",
        "data:image/jpg",
        "data:image/webp",
        "data:image/gif",
    )
    if header.lower() not in allowed_mimes or not b64_part:
        return False, "نوع الصورة غير مدعوم.", None
    try:
        decoded = base64.b64decode(b64_part, validate=True)
        if not decoded or len(decoded) > MAX_MEDIA_BYTES:
            return False, "حجم الصورة غير صالح أو يتجاوز 10MB.", None
        if detect_image_type_from_magic(decoded) is None:
            return False, "الملف ليس صورة حقيقية مدعومة.", None
        clean_data_url = f"{header.lower()};base64,{base64.b64encode(decoded).decode('ascii')}"
        return True, clean_data_url, decoded
    except Exception:
        return False, "فشل فك تشفير الصورة.", None


async def verify_and_fetch_media_input(
    raw_val: str | None,
    session: aiohttp.ClientSession | None = None,
) -> tuple[bool, str, bytes | None]:
    clean = str(raw_val or "").strip()
    if not clean:
        return True, "", None

    if clean.startswith("data:image/"):
        ok_b64, res_or_err, img_bytes = await asyncio.to_thread(_parse_data_url_image, clean)
        if not ok_b64:
            return False, res_or_err, None
        return True, res_or_err, img_bytes

    ok_fmt, err_fmt = await asyncio.to_thread(validate_media_url, clean)
    if not ok_fmt:
        return False, err_fmt, None

    own_session = session is None
    sess = session or aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10))
    current_url = clean

    try:
        for _ in range(MAX_REDIRECTS + 1):
            ok_hop, hop_err = await asyncio.to_thread(validate_media_url, current_url)
            if not ok_hop:
                return False, f"تم رفض التحويل: {hop_err}", None

            async with sess.get(current_url, allow_redirects=False) as resp:
                if resp.status in (301, 302, 303, 307, 308):
                    loc = (resp.headers.get("Location") or "").strip()
                    if not loc:
                        return False, "تحويل HTTP يفتقر إلى عنوان الوجهة.", None
                    current_url = urljoin(current_url, loc)
                    continue

                if resp.status != 200:
                    return False, f"تعذر تحميل الصورة (HTTP {resp.status}).", None

                cl_hdr = (resp.headers.get("Content-Length") or "").strip()
                if cl_hdr.isdigit() and int(cl_hdr) > MAX_MEDIA_BYTES:
                    return False, "حجم الصورة يتجاوز الحد المسموح (10MB).", None

                data = await resp.content.read(MAX_MEDIA_BYTES + 1)
                if not data:
                    return False, "ملف الصورة فارغ.", None
                if len(data) > MAX_MEDIA_BYTES:
                    return False, "حجم الصورة يتجاوز الحد المسموح (10MB).", None

                if detect_image_type_from_magic(data) is None:
                    return False, "الملف ليس صورة حقيقية مدعومة (PNG, JPG, GIF, WEBP).", None

                return True, current_url, data

        return False, "تجاوز الحد الأقصى لعمليات إعادة التوجيه.", None
    except Exception as exc:
        return False, f"تعذر التحقق من الصورة: {exc}", None
    finally:
        if own_session:
            await sess.close()


async def verify_and_fetch_media_url(
    raw_url: str | None,
    session: aiohttp.ClientSession | None = None,
) -> tuple[bool, str]:
    ok, res, _ = await verify_and_fetch_media_input(raw_url, session)
    return ok, res


def get_guild_profile_collection(db=None):
    target_db = db if db is not None else globals().get("_db")
    if target_db is None:
        return globals().get("guild_profiles_col")
    return target_db["guild_profiles"]


def is_guild_premium(
    bot: discord.Client | None,
    guild: discord.Guild | None,
    user_id: int | str | None = None,
) -> bool:
    if guild is None:
        return False

    gid = str(guild.id)
    uid = str(user_id).strip() if user_id is not None and str(user_id).strip().isdigit() else ""
    now_ts = time.time()
    pcol = (
        premium_users_col
        if premium_users_col is not None
        else (_db["premium_users"] if _db is not None else None)
    )

    candidate_ids: set[str] = {gid}
    if uid:
        candidate_ids.add(uid)
    if guild.owner_id:
        candidate_ids.add(str(guild.owner_id))

    if pcol is not None:
        try:
            gdoc = pcol.find_one({"guild_id": gid}, {"_id": 0})
            if isinstance(gdoc, dict):
                if gdoc.get("active") is False:
                    return False
                if _is_doc_active_and_not_expired(gdoc, now_ts):
                    return True

            for cid in candidate_ids:
                udoc = pcol.find_one(
                    {"$or": [{"user_id": cid}, {"_id": cid}, {"id": cid}]},
                    {"_id": 0},
                )
                if isinstance(udoc, dict) and _is_doc_active_and_not_expired(udoc, now_ts):
                    return True
        except PyMongoError:
            pass

    if guild_settings_col is not None:
        try:
            sdoc = guild_settings_col.find_one({"guild_id": gid}, {"_id": 0})
            if isinstance(sdoc, dict):
                if sdoc.get("premium_active") is False:
                    return False
                if bool(sdoc.get("premium_active")):
                    exp_s = float(sdoc.get("premium_expires_at", 0.0) or 0.0)
                    if exp_s == 0.0 or exp_s > now_ts:
                        return True
                perks = sdoc.get("premium_perks")
                if isinstance(perks, dict) and bool(perks.get("active")):
                    exp_p = float(perks.get("expires_at", 0.0) or 0.0)
                    if exp_p == 0.0 or exp_p > now_ts:
                        return True
        except PyMongoError:
            pass

    return False


async def is_guild_premium_async(
    bot: discord.Client | None,
    guild: discord.Guild | None,
    user_id: int | str | None = None,
) -> bool:
    return await asyncio.to_thread(is_guild_premium, bot, guild, user_id)


def _grant_premium_sync(
    target_id: str,
    days: int = 30,
    guild: discord.Guild | None = None,
    granted_by: str = "",
) -> dict:
    clean_id = str(target_id or "").strip()
    now_dt = datetime.now(timezone.utc)
    is_permanent = days <= 0
    exp_dt = None if is_permanent else (now_dt + timedelta(days=days))
    exp_ts = 0.0 if is_permanent else exp_dt.timestamp()

    default_perks = {
        "active": True,
        "permanent": is_permanent,
        "expires_at": exp_ts,
        "custom_profile": True,
        "backup_recovery": True,
        "antinuke_pro": True,
        "auto_lines": True,
        "custom_logs": True,
    }

    pcol = (
        premium_users_col
        if premium_users_col is not None
        else (_db["premium_users"] if _db is not None else None)
    )
    scol = (
        guild_settings_col
        if guild_settings_col is not None
        else (_db["guild_settings"] if _db is not None else None)
    )
    stcol = (
        site_stats_col
        if site_stats_col is not None
        else (_db["site_stats"] if _db is not None else None)
    )

    matched_guild = guild if (guild is not None and str(guild.id) == clean_id) else None
    target_guild_id = str(matched_guild.id) if matched_guild else (str(guild.id) if guild else "")

    user_doc = {
        "user_id": clean_id,
        "discord_id": clean_id,
        "id": clean_id,
        "guild_id": target_guild_id,
        "active": True,
        "is_active": True,
        "premium": True,
        "permanent": is_permanent,
        "lifetime": is_permanent,
        "days": days,
        "expires_at": exp_dt,
        "expire_at": exp_dt,
        "premium_expires_at": exp_ts,
        "premium_perks": default_perks,
        "granted_by": granted_by,
        "updated_at": now_dt,
    }

    if pcol is not None:
        try:
            pcol.update_one(
                {"$or": [{"user_id": clean_id}, {"_id": clean_id}, {"id": clean_id}]},
                {"$set": user_doc, "$setOnInsert": {"created_at": now_dt}},
                upsert=True,
            )
            if target_guild_id:
                pcol.update_one(
                    {"guild_id": target_guild_id},
                    {
                        "$set": {
                            "guild_id": target_guild_id,
                            "user_id": clean_id,
                            "active": True,
                            "is_active": True,
                            "premium": True,
                            "permanent": is_permanent,
                            "lifetime": is_permanent,
                            "expires_at": exp_dt,
                            "premium_expires_at": exp_ts,
                            "premium_perks": default_perks,
                            "granted_by": granted_by,
                            "updated_at": now_dt,
                        },
                        "$setOnInsert": {"created_at": now_dt},
                    },
                    upsert=True,
                )
        except PyMongoError:
            pass

    if scol is not None and target_guild_id.isdigit():
        try:
            scol.update_one(
                {"guild_id": target_guild_id},
                {
                    "$set": {
                        "guild_id": target_guild_id,
                        "premium_active": True,
                        "premium_owner_id": clean_id,
                        "premium_permanent": is_permanent,
                        "premium_expires_at": exp_ts,
                        "premium_perks": default_perks,
                        "updated_at": now_dt,
                    },
                    "$setOnInsert": {"created_at": now_dt},
                },
                upsert=True,
            )
        except PyMongoError:
            pass

    if stcol is not None:
        try:
            stcol.update_one(
                {"_id": f"premium_user_{clean_id}"},
                {
                    "$set": {
                        "user_id": clean_id,
                        "guild_id": target_guild_id,
                        "active": True,
                        "permanent": is_permanent,
                        "expires_at": exp_dt,
                        "premium_perks": default_perks,
                        "granted_by": granted_by,
                        "updated_at": now_dt,
                    }
                },
                upsert=True,
            )
        except PyMongoError:
            pass

    if target_guild_id:
        cfg = get_guild_cfg(target_guild_id)
        cfg["premium_active"] = True
        cfg["premium_owner_id"] = clean_id
        cfg["premium_permanent"] = is_permanent
        cfg["premium_expires_at"] = exp_ts
        cfg["premium_perks"] = default_perks
        _CFG_CACHE[target_guild_id] = (time.monotonic(), cfg)

    return {
        "target_id": clean_id,
        "guild_id": target_guild_id,
        "permanent": is_permanent,
        "days": days,
        "expires_at": exp_dt,
        "perks": default_perks,
    }


def _persist_guild_profile_sync(
    gid: str,
    profile_doc: dict,
    db=None,
) -> tuple[bool, str]:
    target_gid = str(gid or "").strip()
    if not target_gid.isdigit():
        return False, "معرف السيرفر غير صالح."

    target_db = db if db is not None else globals().get("_db")

    if target_db is None:
        return False, "قاعدة البيانات غير متصلة."

    try:
        collection = get_guild_profile_collection(target_db)
        settings_collection = target_db["guild_settings"]

        if collection is None:
            return False, "Collection الخاصة بالبروفايل غير متوفرة."

        clean_doc = {
            "guild_id": target_gid,
            "scope": "guild_only",
            "avatar_url": str(profile_doc.get("avatar_url") or ""),
            "banner_url": str(profile_doc.get("banner_url") or ""),
            "bio": str(profile_doc.get("bio") or "")[:MAX_BIO_LEN],
            "updated_at": profile_doc.get("updated_at") or datetime.now(timezone.utc),
        }

        result = collection.update_one(
            {"guild_id": target_gid},
            {"$set": clean_doc},
            upsert=True,
        )

        if not result.acknowledged:
            return False, "لم يتم تأكيد حفظ البروفايل."

        settings_collection.update_one(
            {"guild_id": target_gid},
            {
                "$set": {
                    "guild_id": target_gid,
                    "avatar_url": clean_doc["avatar_url"],
                    "banner_url": clean_doc["banner_url"],
                    "bio": clean_doc["bio"],
                    "bot_bio": clean_doc["bio"],
                    "guild_bio": clean_doc["bio"],
                    "guild_profile.avatar_url": clean_doc["avatar_url"],
                    "guild_profile.banner_url": clean_doc["banner_url"],
                    "guild_profile.bio": clean_doc["bio"],
                    "updated_at": clean_doc["updated_at"],
                }
            },
            upsert=True,
        )

        return True, "تم الحفظ بنجاح (تخصيص خاص بالسيرفر فقط)."

    except PyMongoError as exc:
        return False, f"فشل الحفظ في MongoDB: {exc}"
    except Exception as exc:
        return False, f"حدث خطأ أثناء الحفظ: {exc}"


async def get_guild_profile(db, guild_id: int | str, force_refresh: bool = False) -> dict | None:
    gid = str(guild_id).strip()
    if not gid.isdigit():
        return None

    now = time.monotonic()
    if force_refresh:
        _PROFILE_CACHE.pop(gid, None)
        _PROFILE_MEM.pop(gid, None)
    else:
        cached = _PROFILE_CACHE.get(gid)
        if cached and (now - cached[0]) < _PROFILE_CACHE_TTL:
            return dict(cached[1])

    collection = get_guild_profile_collection(db)
    if collection is not None:
        try:
            doc = await asyncio.to_thread(
                collection.find_one,
                {"guild_id": gid},
                {"_id": 0},
            )
            if isinstance(doc, dict):
                merged = _extract_profile_fields_from_doc(doc, gid)
                merged["guild_id"] = gid
                _PROFILE_MEM[gid] = dict(merged)
                _PROFILE_CACHE[gid] = (now, dict(merged))
                return dict(merged)
        except PyMongoError:
            pass

    target_db = db if db is not None else globals().get("_db")
    s_col = target_db["guild_settings"] if target_db is not None else guild_settings_col
    if s_col is not None:
        try:
            sdoc = await asyncio.to_thread(
                s_col.find_one,
                {"guild_id": gid},
                {"_id": 0},
            )
            if isinstance(sdoc, dict):
                merged = _extract_profile_fields_from_doc(sdoc, gid)
                merged["guild_id"] = gid
                if merged["avatar_url"] or merged["banner_url"] or merged["bio"]:
                    _PROFILE_MEM[gid] = dict(merged)
                    _PROFILE_CACHE[gid] = (now, dict(merged))
                    return dict(merged)
        except PyMongoError:
            pass

    if gid in _PROFILE_MEM:
        return dict(_PROFILE_MEM[gid])
    return None


async def _patch_guild_member_me(
    guild: discord.Guild | None,
    payload: dict,
    reason: str = "Arab Security Guild-Scoped Profile Update",
) -> tuple[bool, str]:
    """يرسل PATCH /guilds/{guild_id}/members/@me لتعديل بروفايل البوت في السيرفر المحدد فقط."""
    if guild is None or _ACTIVE_BOT is None:
        return False, "السيرفر غير متاح للبوت."
    if not payload:
        return True, "لا يوجد تعديل مطلوب."

    route = discord.http.Route("PATCH", "/guilds/{guild_id}/members/@me", guild_id=guild.id)
    try:
        await _ACTIVE_BOT.http.request(route, json=payload, reason=reason)
        return True, f"تم تطبيق التخصيص داخل السيرفر ({guild.name}) فقط."
    except discord.HTTPException as exc:
        if "bio" in payload and len(payload) == 1:
            return False, f"Discord رفض حقل bio لعضو البوت (HTTP {exc.status}): {exc.text}"
        fallback = {}
        for key_name in ("nick", "bio", "avatar", "banner"):
            if key_name in payload:
                fallback[key_name] = payload[key_name]
                break
        if fallback and fallback != payload:
            try:
                await _ACTIVE_BOT.http.request(route, json=fallback, reason=reason)
                return True, f"تم تطبيق التخصيص داخل السيرفر ({guild.name}) فقط."
            except Exception as exc2:
                return False, f"تعذر تحديث بروفايل السيرفر ({exc2})."
        return False, f"تعذر تحديث بروفايل السيرفر ({exc})."
    except Exception as exc:
        return False, f"حدث خطأ أثناء تطبيق بروفايل السيرفر ({exc})."


async def _apply_discord_member_visuals(
    guild: discord.Guild | None,
    avatar_bytes: bytes | None,
    banner_bytes: bytes | None,
    clear_avatar: bool = False,
    clear_banner: bool = False,
) -> tuple[bool, str]:
    """يطبق التخصيص المرئي على عضو البوت داخل السيرفر المحدد فقط بدون تعديل البوت العام."""
    if guild is None or guild.me is None:
        return False, "السيرفر غير متاح للبوت."

    rest_payload: dict = {}
    if clear_avatar:
        rest_payload["avatar"] = None
    elif avatar_bytes:
        ava_uri = _bytes_to_data_uri(avatar_bytes)
        if ava_uri:
            rest_payload["avatar"] = ava_uri

    if clear_banner:
        rest_payload["banner"] = None
    elif banner_bytes:
        ban_uri = _bytes_to_data_uri(banner_bytes)
        if ban_uri:
            rest_payload["banner"] = ban_uri

    if not rest_payload:
        return True, "لا يوجد تعديل مرئي مباشر مطلوب."

    ok_rest, msg_rest = await _patch_guild_member_me(
        guild, rest_payload, reason="Arab Security Guild Avatar/Banner"
    )
    if ok_rest:
        return True, msg_rest

    kwargs: dict = {}
    if clear_avatar:
        kwargs["avatar"] = None
    elif avatar_bytes:
        kwargs["avatar"] = avatar_bytes
    if clear_banner:
        kwargs["banner"] = None
    elif banner_bytes:
        kwargs["banner"] = banner_bytes

    try:
        await guild.me.edit(**kwargs)
        return True, "تم تطبيق التخصيص داخل السيرفر المحدد فقط."
    except TypeError:
        try:
            kwargs.pop("banner", None)
            if kwargs:
                await guild.me.edit(**kwargs)
                return True, "تم تطبيق الأفاتار في السيرفر (البنر يُعرض في رسائل السيرفر)."
            return True, "تم حفظ التخصيص الخاص بالسيرفر."
        except discord.Forbidden:
            return False, "نقص صلاحيات لعضو البوت داخل السيرفر؛ تم الحفظ لسيرفر التخصيص."
        except Exception as exc:
            return False, f"تم الحفظ داخل السيرفر ({exc})."
    except discord.Forbidden:
        return False, "نقص صلاحيات لعضو البوت داخل السيرفر؛ تم الحفظ لسيرفر التخصيص."
    except Exception as exc:
        return False, f"تم الحفظ داخل السيرفر ({exc})."


async def _apply_guild_only_status_nick(
    guild: discord.Guild | None,
    status_text: str,
) -> tuple[bool, str]:
    """يعدل اسم/لقب البوت داخل السيرفر المحدد فقط (Guild Only) دون تغيير البوت العام."""
    if guild is None or guild.me is None:
        return False, "السيرفر غير متاح للبوت."
    clean_nick = str(status_text or "").strip()[:32]
    try:
        await guild.me.edit(nick=clean_nick or None)
        return True, f"تم تحديث لقب البوت داخل السيرفر ({guild.name}) فقط."
    except discord.Forbidden:
        return False, "البوت يحتاج صلاحية Manage Nicknames لتغيير اللقب داخل هذا السيرفر."
    except Exception as exc:
        return False, f"تعذر تحديث اللقب داخل السيرفر: {exc}"


async def _apply_guild_only_bio(
    guild: discord.Guild | None,
    bio_text: str,
) -> tuple[bool, str]:
    """يطبق بايو البوت داخل السيرفر المحدد فقط ويُحدّث الكاش ليظهر في رسائل السيرفر إذا رفضه Discord API."""
    if guild is None:
        return False, "السيرفر غير محدد."
    clean_bio = str(bio_text or "").strip()[:MAX_BIO_LEN]
    gid = str(guild.id)

    mem_doc = dict(_PROFILE_MEM.get(gid) or _empty_profile(gid))
    mem_doc["guild_id"] = gid
    mem_doc["bio"] = clean_bio
    mem_doc["updated_at"] = datetime.now(timezone.utc)
    _PROFILE_MEM[gid] = dict(mem_doc)
    _PROFILE_CACHE[gid] = (time.monotonic(), dict(mem_doc))
    save_guild_fields(
        gid,
        {
            "bio": clean_bio,
            "bot_bio": clean_bio,
            "guild_bio": clean_bio,
            "guild_profile.bio": clean_bio,
        },
    )

    ok, msg = await _patch_guild_member_me(
        guild,
        {"bio": clean_bio},
        reason="Arab Security Guild-Scoped Bio Update",
    )
    if ok:
        return True, f"تم تحديث بايو البوت داخل السيرفر ({guild.name}) فقط."
    return False, f"تم حفظ البايو للسيرفر وتفعيله في إيمبدات السيرفر ({msg})."


async def save_guild_profile(
    db,
    guild_id: int | str,
    avatar_url: str | None = None,
    banner_url: str | None = None,
    bio: str | None = None,
    clear_fields: set[str] | None = None,
    session: aiohttp.ClientSession | None = None,
    guild: discord.Guild | None = None,
) -> tuple[bool, str]:
    gid = str(guild_id).strip()

    if not gid.isdigit():
        return False, "معرف السيرفر غير صالح."

    async with _get_guild_profile_lock(gid):
        current = await get_guild_profile(db, gid, force_refresh=True) or _empty_profile(gid)

        profile_doc = _empty_profile(gid)
        profile_doc.update(current)

        profile_doc["guild_id"] = gid
        profile_doc["updated_at"] = datetime.now(timezone.utc)

        to_clear = set(clear_fields or set())
        clear_tokens = ("none", "-", "clear", "remove")

        avatar_bytes: bytes | None = None
        banner_bytes: bytes | None = None

        if "avatar" in to_clear:
            profile_doc["avatar_url"] = ""
        elif avatar_url is not None:
            raw = str(avatar_url).strip()
            if not raw or raw.lower() in clear_tokens:
                profile_doc["avatar_url"] = ""
                to_clear.add("avatar")
            else:
                ok, result, img_b = await verify_and_fetch_media_input(raw, session)
                if not ok:
                    return False, f"الافتار: {result}"
                profile_doc["avatar_url"] = result
                avatar_bytes = img_b

        if "banner" in to_clear:
            profile_doc["banner_url"] = ""
        elif banner_url is not None:
            raw = str(banner_url).strip()
            if not raw or raw.lower() in clear_tokens:
                profile_doc["banner_url"] = ""
                to_clear.add("banner")
            else:
                ok, result, img_b = await verify_and_fetch_media_input(raw, session)
                if not ok:
                    return False, f"البنر: {result}"
                profile_doc["banner_url"] = result
                banner_bytes = img_b

        if "bio" in to_clear:
            profile_doc["bio"] = ""
        elif bio is not None:
            raw = str(bio).strip()
            if raw.lower() in clear_tokens:
                profile_doc["bio"] = ""
                to_clear.add("bio")
            else:
                profile_doc["bio"] = raw[:MAX_BIO_LEN]

        if avatar_url is None and banner_url is None and bio is None and not to_clear:
            return False, "لم يتم إرسال أي تعديل."

        ok_db, msg_db = await asyncio.to_thread(
            _persist_guild_profile_sync,
            gid,
            profile_doc,
            db,
        )

        if not ok_db:
            return False, msg_db

        _PROFILE_MEM[gid] = dict(profile_doc)
        _PROFILE_CACHE[gid] = (
            time.monotonic(),
            dict(profile_doc),
        )

        notes: list[str] = []
        if guild is not None and (
            avatar_bytes or banner_bytes or "avatar" in to_clear or "banner" in to_clear
        ):
            _, vis_msg = await _apply_discord_member_visuals(
                guild,
                avatar_bytes=avatar_bytes,
                banner_bytes=banner_bytes,
                clear_avatar=("avatar" in to_clear),
                clear_banner=("banner" in to_clear),
            )
            notes.append(vis_msg)

        if bio is not None or "bio" in to_clear:
            _, bio_msg = await _apply_guild_only_bio(
                guild,
                profile_doc.get("bio", ""),
            )
            notes.append(bio_msg)

        extra_note = f" ({' • '.join(notes)})" if notes else ""
        return True, f"تم حفظ تخصيص السيرفر ({gid}) فقط بنجاح{extra_note}."


async def reset_guild_profile(
    db,
    guild_id: int | str,
    guild: discord.Guild | None = None,
) -> tuple[bool, str, dict]:
    gid = str(guild_id).strip()

    if not gid.isdigit():
        return False, "معرف السيرفر غير صالح.", _empty_profile(gid)

    async with _get_guild_profile_lock(gid):
        fresh = _empty_profile(gid)
        fresh["updated_at"] = datetime.now(timezone.utc)

        ok, msg = await asyncio.to_thread(
            _persist_guild_profile_sync,
            gid,
            fresh,
            db,
        )

        if not ok:
            return False, msg, fresh

        _PROFILE_MEM[gid] = dict(fresh)
        _PROFILE_CACHE[gid] = (
            time.monotonic(),
            dict(fresh),
        )

        if guild is not None:
            await _apply_discord_member_visuals(
                guild,
                avatar_bytes=None,
                banner_bytes=None,
                clear_avatar=True,
                clear_banner=True,
            )
            await _apply_guild_only_bio(guild, "")

        return True, f"تمت إعادة تعيين بروفايل السيرفر ({gid}) فقط.", fresh


async def load_all_guild_profiles(db=None) -> int:
    target_db = db if db is not None else globals().get("_db")
    collection = get_guild_profile_collection(target_db)

    if collection is None:
        return 0

    try:
        profiles = await asyncio.to_thread(lambda: list(collection.find({})))

        for profile in profiles:
            gid = str(profile.get("guild_id", ""))

            if not gid.isdigit():
                continue

            merged = _empty_profile(gid)
            merged.update(_extract_profile_fields_from_doc(profile, gid))
            merged["guild_id"] = gid

            _PROFILE_MEM[gid] = dict(merged)
            _PROFILE_CACHE[gid] = (
                time.monotonic(),
                dict(merged),
            )

        return len(profiles)

    except PyMongoError as exc:
        print(f"[PROFILE CACHE] {exc}")
        return 0


async def list_all_saved_profiles(db) -> list[dict]:
    await load_all_guild_profiles(db)
    return [dict(v) for v in _PROFILE_MEM.values()]


def _is_valid_embed_url(val: str) -> bool:
    s = (val or "").strip()
    if not s or len(s) > 2048:
        return False
    return s.startswith(("https://", "http://", "data:image/"))


def apply_guild_branding(
    embed: discord.Embed,
    guild: discord.Guild | None,
    bot: discord.Client | None = None,
) -> discord.Embed:
    if guild is None or not isinstance(embed, discord.Embed):
        return embed

    gid = str(guild.id)
    cached = _PROFILE_CACHE.get(gid)
    profile = cached[1] if cached else _PROFILE_MEM.get(gid, _empty_profile(gid))

    avatar = str(profile.get("avatar_url") or "").strip()
    banner = str(profile.get("banner_url") or "").strip()
    bio = str(profile.get("bio") or "").strip()

    bot_user = getattr(bot, "user", None)
    default_name = getattr(bot_user, "display_name", None) or "ARAB SECURITY"
    default_avatar = str(bot_user.display_avatar.url) if bot_user else ""

    author_name = (
        embed.author.name
        if embed.author and embed.author.name
        else default_name
    )

    if avatar.startswith(("https://", "http://")):
        try:
            embed.set_author(name=author_name, icon_url=avatar)
        except Exception:
            if default_avatar.startswith(("https://", "http://")):
                embed.set_author(name=author_name, icon_url=default_avatar)
    elif not (embed.author and embed.author.icon_url) and default_avatar.startswith(
        ("https://", "http://")
    ):
        embed.set_author(name=author_name, icon_url=default_avatar)

    if banner.startswith(("https://", "http://")) and not (embed.image and embed.image.url):
        try:
            embed.set_image(url=banner)
        except Exception:
            pass

    if bio and not (embed.footer and embed.footer.text):
        try:
            embed.set_footer(text=bio[:2048])
        except Exception:
            pass

    return embed


_CFG_CACHE: dict[str, tuple[float, dict]] = {}
_CFG_TTL = 60.0
_BOT_START_TIME = time.monotonic()

MSG_TRACKER: dict[tuple[str, str], deque[float]] = defaultdict(lambda: deque(maxlen=25))
JOIN_TRACKER: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=40))
ACTION_TRACKER: dict[tuple[str, str, str], deque[float]] = defaultdict(lambda: deque(maxlen=30))


def _default_cfg() -> dict:
    return {
        "prefix": "!",
        "maintenance": False,
        "mod_log_channel": "",
        "support_role_id": "",
        "auto_lines": {},
        "guild_status": "",
        "guild_status_text": "",
        "guild_status_mode": "guild_only",
        "anti_spam": True,
        "spam_punishment": "Timeout",
        "spam_timeout_seconds": 600,
        "anti_link": True,
        "link_punishment": "Delete & Timeout",
        "link_timeout_seconds": 300,
        "anti_invites": True,
        "anti_files": False,
        "file_punishment": "Delete & Timeout",
        "file_timeout_seconds": 300,
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
        "quarantine_on_nuke": True,
        "role_hierarchy_guard": True,
        "auto_quarantine": True,
        "trusted_admins": [ADMIN_USER_ID],
        "antinuke": {},
        "guild_profile": {},
        "premium_perks": {},
    }


def get_guild_cfg(guild_id: int | str) -> dict:
    gid = str(guild_id).strip()
    now = time.monotonic()
    cached = _CFG_CACHE.get(gid)
    if cached and (now - cached[0]) < _CFG_TTL:
        return cached[1]

    cfg = _default_cfg()
    if guild_settings_col is not None and gid.isdigit():
        try:
            doc = guild_settings_col.find_one({"guild_id": gid}, {"_id": 0})
            if isinstance(doc, dict):
                for k, v in doc.items():
                    if k in cfg:
                        cfg[k] = v
                if "status_text" in doc and not cfg.get("guild_status_text"):
                    cfg["guild_status_text"] = str(doc.get("status_text") or "").strip()
                if "status" in doc and not cfg.get("guild_status"):
                    cfg["guild_status"] = str(doc.get("status") or "").strip()
        except PyMongoError:
            pass

    _CFG_CACHE[gid] = (now, cfg)
    return cfg


async def get_guild_cfg_async(guild_id: int | str) -> dict:
    return await asyncio.to_thread(get_guild_cfg, guild_id)


def _persist_guild_fields_sync(gid: str, fields: dict) -> None:
    if guild_settings_col is not None:
        try:
            guild_settings_col.update_one(
                {"guild_id": gid},
                {
                    "$set": {
                        "guild_id": gid,
                        **fields,
                        "updated_at": datetime.now(timezone.utc),
                    }
                },
                upsert=True,
            )
        except PyMongoError:
            pass


def save_guild_fields(guild_id: int | str, fields: dict) -> None:
    gid = str(guild_id).strip()
    if not gid.isdigit():
        return
    cfg = get_guild_cfg(gid)
    cfg.update(fields)
    _CFG_CACHE[gid] = (time.monotonic(), cfg)
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(asyncio.to_thread(_persist_guild_fields_sync, gid, dict(fields)))
    except RuntimeError:
        _persist_guild_fields_sync(gid, fields)


def _extract_guild_status_payload(cmd: dict, extra: dict) -> dict:
    sources = [extra, cmd]
    for container in (extra, cmd):
        if isinstance(container, dict):
            for sub_key in ("presence", "status_data", "data", "settings", "guild_status_data"):
                if isinstance(container.get(sub_key), dict):
                    sources.append(container[sub_key])

    status_val = ""
    status_text = ""

    for src in sources:
        if not isinstance(src, dict):
            continue
        for k in ("guild_status", "status", "state", "mode"):
            if k in src and src[k] is not None and str(src[k]).strip():
                status_val = str(src[k]).strip()
                break
        for k in ("guild_status_text", "status_text", "activity_text", "custom_status", "text"):
            if k in src and src[k] is not None:
                status_text = str(src[k]).strip()
                break

    if not status_text and str(cmd.get("target") or "").strip():
        status_text = str(cmd.get("target") or "").strip()

    return {
        "guild_status": status_val or "guild_nick",
        "guild_status_text": status_text,
        "guild_status_mode": "guild_only",
    }


def _build_guild_snapshot(guild: discord.Guild) -> dict:
    roles_data = []
    for r in sorted(guild.roles, key=lambda x: x.position):
        r_item = _serialize_single_role(r)
        if r_item is not None:
            roles_data.append(r_item)

    channels_data = []
    for ch in sorted(guild.channels, key=lambda x: x.position):
        if isinstance(ch, discord.CategoryChannel):
            continue
        c_item = _serialize_single_channel(ch)
        if c_item is not None:
            channels_data.append(c_item)

    return {
        "roles": roles_data,
        "channels": channels_data,
        "saved_at": int(time.time()),
    }


def _persist_backup_sync(gid: str, snapshot: dict) -> tuple[int, int]:
    now_dt = datetime.now(timezone.utc)
    snapshot["saved_at"] = int(now_dt.timestamp())
    packed = _compress_payload(snapshot)
    _BACKUP_MEM[gid] = {
        "snapshot": snapshot,
        "saved_at": now_dt,
        "updated_at": now_dt,
        "permanent": True,
        "orig_bytes": packed["o"],
        "comp_bytes": packed["z"],
    }
    if guild_backups_col is not None:
        try:
            guild_backups_col.update_one(
                {"guild_id": gid},
                {
                    "$set": {
                        "guild_id": gid,
                        "permanent": True,
                        "updated_at": now_dt,
                        **packed,
                    }
                },
                upsert=True,
            )
        except PyMongoError:
            pass
    return packed["o"], packed["z"]


def _load_backup_sync(gid: str) -> dict | None:
    mem = _BACKUP_MEM.get(gid)
    if mem and isinstance(mem.get("snapshot"), dict):
        return mem["snapshot"]

    if guild_backups_col is not None:
        try:
            doc = guild_backups_col.find_one({"guild_id": gid}, {"_id": 0})
            if isinstance(doc, dict):
                snap = _decompress_payload(doc)
                if snap:
                    _BACKUP_MEM[gid] = {
                        "snapshot": snap,
                        "saved_at": snap.get("saved_at") or doc.get("updated_at"),
                        "updated_at": doc.get("updated_at"),
                        "permanent": True,
                        "orig_bytes": int(doc.get("o") or doc.get("orig_bytes") or 0),
                        "comp_bytes": int(doc.get("z") or doc.get("comp_bytes") or 0),
                    }
                    return snap
        except PyMongoError:
            pass
    return None


async def get_or_create_snapshot(
    guild: discord.Guild, refresh: bool = False
) -> tuple[dict | None, int, int]:
    gid = str(guild.id)
    if not refresh:
        existing = await asyncio.to_thread(_load_backup_sync, gid)
        if existing:
            mem = _BACKUP_MEM.get(gid) or {}
            return existing, int(mem.get("orig_bytes", 0) or 0), int(mem.get("comp_bytes", 0) or 0)
    snap = _build_guild_snapshot(guild)
    orig_b, comp_b = await asyncio.to_thread(_persist_backup_sync, gid, snap)
    return snap, orig_b, comp_b


def find_missing_items(
    guild: discord.Guild, snap: dict | None, deleted_12h: list[dict] | None = None
) -> list[dict]:
    missing: list[dict] = []
    seen_keys: set[str] = set()
    existing_role_ids = {str(r.id) for r in guild.roles}
    existing_role_names = {r.name.lower() for r in guild.roles}
    existing_channel_ids = {str(c.id) for c in guild.channels if not _is_ticket_channel(c)}

    for d_item in deleted_12h or []:
        k = str(d_item.get("key") or "")
        kind = str(d_item.get("kind") or "")
        d_data = d_item.get("data") if isinstance(d_item.get("data"), dict) else {}
        d_id = str(d_item.get("item_id") or d_data.get("id") or "")
        d_name = str(d_item.get("name") or d_data.get("name") or "").strip()
        if not k or not d_name or k in seen_keys:
            continue
        if kind == "role":
            if d_id in existing_role_ids or d_name.lower() in existing_role_names:
                continue
        else:
            if d_id in existing_channel_ids or any(
                tok in d_name.lower() for tok in TICKET_NAME_TOKENS
            ):
                continue
        seen_keys.add(k)
        missing.append(
            {
                "key": k,
                "kind": kind,
                "name": d_name,
                "data": d_data,
                "from_12h": True,
            }
        )

    if isinstance(snap, dict):
        for r_info in snap.get("roles") or []:
            old_id = str(r_info.get("id") or "")
            r_name = str(r_info.get("name") or "").strip()
            r_key = f"role:{old_id or r_name}"
            if not r_name or r_key in seen_keys:
                continue
            if int(r_info.get("permissions", 0) or 0) & ADMIN_PERM_FLAG:
                continue
            if old_id not in existing_role_ids and r_name.lower() not in existing_role_names:
                seen_keys.add(r_key)
                missing.append(
                    {
                        "key": r_key,
                        "kind": "role",
                        "name": r_name,
                        "data": r_info,
                        "from_12h": False,
                    }
                )

        for c_info in snap.get("channels") or []:
            old_cid = str(c_info.get("id") or "")
            c_name = str(c_info.get("name") or "").strip()
            c_key = f"ch:{old_cid or c_name}"
            if not c_name or c_key in seen_keys:
                continue
            if any(tok in c_name.lower() for tok in TICKET_NAME_TOKENS):
                continue
            if old_cid not in existing_channel_ids:
                seen_keys.add(c_key)
                missing.append(
                    {
                        "key": c_key,
                        "kind": "channel",
                        "name": c_name,
                        "data": c_info,
                        "from_12h": False,
                    }
                )

    return missing


async def restore_selected_items(
    guild: discord.Guild,
    snap: dict | None,
    selected_keys: list[str],
    deleted_12h: list[dict] | None = None,
) -> dict:
    if not guild.me:
        return {"roles": [], "channels": [], "errors": []}

    restored_roles: list[str] = []
    restored_channels: list[str] = []
    restored_keys_to_delete: list[str] = []
    errors: list[str] = []

    restore_all = "__ALL__" in selected_keys
    wanted = set(selected_keys)

    candidates = find_missing_items(guild, snap, deleted_12h)

    role_id_map: dict[str, discord.Role] = {str(r.id): r for r in guild.roles}
    for r in guild.roles:
        role_id_map.setdefault(r.name.lower(), r)

    for item in [c for c in candidates if c["kind"] == "role"]:
        r_key = item["key"]
        if not restore_all and r_key not in wanted:
            continue
        r_info = item["data"]
        old_id = str(r_info.get("id") or "")
        r_name = str(r_info.get("name") or item["name"]).strip()
        try:
            raw_perms = int(r_info.get("permissions", 0) or 0) & ~ADMIN_PERM_FLAG
            perms = discord.Permissions(raw_perms)
            if not guild.me.guild_permissions.administrator:
                perms &= guild.me.guild_permissions
            new_role = await guild.create_role(
                name=r_name[:80],
                permissions=perms,
                color=discord.Color(int(r_info.get("color", 0) or 0)),
                hoist=bool(r_info.get("hoist", False)),
                mentionable=bool(r_info.get("mentionable", False)),
                reason="Arab Security: /recovery Role Restore",
            )
            desired_pos = int(r_info.get("pos") or r_info.get("position") or 0)
            if desired_pos > 0:
                try:
                    max_pos = max(1, guild.me.top_role.position - 1)
                    await new_role.edit(position=max(1, min(desired_pos, max_pos)))
                except discord.HTTPException:
                    pass
            if old_id:
                role_id_map[old_id] = new_role
            role_id_map[r_name.lower()] = new_role
            restored_roles.append(r_name)
            restored_keys_to_delete.append(r_key)
        except Exception as exc:
            errors.append(f"رتبة `{r_name}`: {exc}")

    existing_cat_by_id = {
        str(c.id): c
        for c in guild.categories
        if not any(tok in c.name.lower() for tok in TICKET_NAME_TOKENS)
    }
    existing_cat_by_name = {
        c.name.lower(): c
        for c in guild.categories
        if not any(tok in c.name.lower() for tok in TICKET_NAME_TOKENS)
    }

    channel_candidates = [c for c in candidates if c["kind"] == "channel"]
    channel_candidates.sort(
        key=lambda x: 0 if str((x.get("data") or {}).get("type")) == "category" else 1
    )

    for item in channel_candidates:
        c_key = item["key"]
        if not restore_all and c_key not in wanted:
            continue
        c_info = item["data"]
        c_name = str(c_info.get("name") or item["name"]).strip()
        if not c_name or any(tok in c_name.lower() for tok in TICKET_NAME_TOKENS):
            continue

        overwrites: dict[discord.abc.Snowflake, discord.PermissionOverwrite] = {}
        raw_ows = c_info.get("ow") or c_info.get("overwrites") or []
        for ow in raw_ows:
            target_kind = str(ow.get("t") or "r")
            tid = str(ow.get("r") or ow.get("role_id") or "")
            allow_val = (
                int(ow.get("a") if ow.get("a") is not None else (ow.get("allow") or 0))
                & ~ADMIN_PERM_FLAG
            )
            deny_val = (
                int(ow.get("d") if ow.get("d") is not None else (ow.get("deny") or 0))
                & ~ADMIN_PERM_FLAG
            )
            if target_kind == "m" and tid.isdigit():
                target_member = guild.get_member(int(tid))
                if target_member is not None:
                    overwrites[target_member] = discord.PermissionOverwrite.from_pair(
                        discord.Permissions(allow_val), discord.Permissions(deny_val)
                    )
            else:
                rname = str(ow.get("role_name") or "").lower()
                target_role = role_id_map.get(tid) or (role_id_map.get(rname) if rname else None)
                if isinstance(target_role, discord.Role) and not target_role.permissions.administrator:
                    overwrites[target_role] = discord.PermissionOverwrite.from_pair(
                        discord.Permissions(allow_val), discord.Permissions(deny_val)
                    )

        c_type = str(c_info.get("type") or "text")
        desired_pos = int(c_info.get("pos") or c_info.get("position") or 0)

        if c_type == "category":
            try:
                created_cat = await guild.create_category(
                    name=c_name[:80],
                    overwrites=overwrites or discord.utils.MISSING,
                    reason="Arab Security: /recovery Category Restore",
                )
                if desired_pos >= 0:
                    try:
                        await created_cat.edit(position=desired_pos)
                    except discord.HTTPException:
                        pass
                existing_cat_by_id[str(created_cat.id)] = created_cat
                existing_cat_by_name[c_name.lower()] = created_cat
                restored_channels.append(c_name)
                restored_keys_to_delete.append(c_key)
            except Exception as exc:
                errors.append(f"كاتاقوري `{c_name}`: {exc}")
            continue

        parent_cat = None
        cat_id = str(c_info.get("cat_id") or "").strip()
        cat_name = str(c_info.get("cat") or c_info.get("category_name") or "").strip()
        if cat_id and cat_id in existing_cat_by_id:
            parent_cat = existing_cat_by_id[cat_id]
        elif cat_name and not any(tok in cat_name.lower() for tok in TICKET_NAME_TOKENS):
            parent_cat = existing_cat_by_name.get(cat_name.lower())
            if parent_cat is None:
                try:
                    parent_cat = await guild.create_category(
                        name=cat_name[:80],
                        reason="Arab Security: /recovery Category Restore",
                    )
                    existing_cat_by_id[str(parent_cat.id)] = parent_cat
                    existing_cat_by_name[cat_name.lower()] = parent_cat
                except Exception:
                    parent_cat = None

        try:
            created_ch = None
            if c_type == "voice":
                created_ch = await guild.create_voice_channel(
                    name=c_name[:80],
                    category=parent_cat,
                    bitrate=max(
                        8000, min(guild.bitrate_limit, int(c_info.get("bitrate", 64000) or 64000))
                    ),
                    user_limit=max(
                        0,
                        min(
                            99,
                            int(
                                c_info.get("limit")
                                if c_info.get("limit") is not None
                                else (c_info.get("user_limit") or 0)
                            ),
                        ),
                    ),
                    overwrites=overwrites or discord.utils.MISSING,
                    reason="Arab Security: /recovery Voice Restore",
                )
            elif c_type == "stage":
                created_ch = await guild.create_stage_channel(
                    name=c_name[:80],
                    category=parent_cat,
                    overwrites=overwrites or discord.utils.MISSING,
                    reason="Arab Security: /recovery Stage Restore",
                )
            else:
                created_ch = await guild.create_text_channel(
                    name=c_name[:80],
                    category=parent_cat,
                    topic=str(c_info.get("topic") or "")[:300] or discord.utils.MISSING,
                    slowmode_delay=max(
                        0,
                        min(
                            21600,
                            int(
                                c_info.get("slowmode")
                                if c_info.get("slowmode") is not None
                                else (c_info.get("slowmode_delay") or 0)
                            ),
                        ),
                    ),
                    nsfw=bool(c_info.get("nsfw", False)),
                    overwrites=overwrites or discord.utils.MISSING,
                    reason="Arab Security: /recovery Channel Restore",
                )

            if created_ch is not None and desired_pos >= 0:
                try:
                    await created_ch.edit(position=desired_pos)
                except discord.HTTPException:
                    pass

            restored_channels.append(c_name)
            restored_keys_to_delete.append(c_key)
        except Exception as exc:
            errors.append(f"روم `{c_name}`: {exc}")

    if restored_keys_to_delete:
        await asyncio.to_thread(_remove_deleted_items_sync, str(guild.id), restored_keys_to_delete)

    return {"roles": restored_roles, "channels": restored_channels, "errors": errors}


class RecoverySelect(discord.ui.Select):
    def __init__(
        self,
        guild: discord.Guild,
        snap: dict | None,
        deleted_12h: list[dict],
        missing_items: list[dict],
        owner_id: int,
    ):
        self.guild = guild
        self.snap = snap
        self.deleted_12h = deleted_12h
        self.owner_id = owner_id

        options: list[discord.SelectOption] = [
            discord.SelectOption(
                label="استرجاع الكل (All)",
                value="__ALL__",
                description="إعادة جميع الرومات والرتب المحذوفة وحذفها من قاعدة البيانات",
            )
        ]
        for item in missing_items[:24]:
            kind_label = "رتبة" if item["kind"] == "role" else "روم"
            options.append(
                discord.SelectOption(
                    label=f"{kind_label}: {item['name']}"[:100],
                    value=item["key"][:100],
                    description=f"استرجاع {kind_label} محذوفة بكامل الصلاحيات والمكان",
                )
            )

        super().__init__(
            placeholder="اختر (استرجاع الكل) أو حدد العناصر المطلوبة...",
            min_values=1,
            max_values=len(options),
            options=options,
        )

    async def callback(self, interaction: discord.Interaction) -> None:
        if interaction.user.id != self.owner_id:
            await interaction.response.send_message(
                "هذه القائمة خاصة بمن طلب الأمر فقط.", ephemeral=True
            )
            return

        await interaction.response.defer(thinking=True)

        if not await is_guild_premium_async(_ACTIVE_BOT, self.guild, interaction.user.id):
            await interaction.followup.send(
                embed=make_embed(
                    "Premium مطلوب",
                    "الاسترجاع وحفظ النسخ متاح لمشتركي **Premium** فقط.",
                    discord.Color.red(),
                    guild=self.guild,
                ),
                ephemeral=True,
            )
            return

        res = await restore_selected_items(
            self.guild, self.snap, list(self.values), self.deleted_12h
        )

        existing_perm = await asyncio.to_thread(_load_backup_sync, str(self.guild.id))
        if existing_perm is not None:
            new_snap = _build_guild_snapshot(self.guild)
            await asyncio.to_thread(_persist_backup_sync, str(self.guild.id), new_snap)

        roles_txt = ", ".join(f"`{r}`" for r in res["roles"]) or "لا يوجد"
        ch_txt = ", ".join(f"`{c}`" for c in res["channels"]) or "لا يوجد"
        msg = (
            f"**تم الاسترجاع بنجاح وحذف العناصر المسترجعة من قاعدة البيانات:**\n"
            f"• **الرتب المسترجعة ({len(res['roles'])}):** {roles_txt}\n"
            f"• **الرومات المسترجعة ({len(res['channels'])}):** {ch_txt}"
        )
        if res["errors"]:
            msg += f"\n• **ملاحظات:** `{' | '.join(res['errors'][:3])}`"

        await interaction.followup.send(
            embed=make_embed("نتيجة الاسترجاع", msg, discord.Color.green(), guild=self.guild)
        )


class RecoveryView(discord.ui.View):
    def __init__(
        self,
        guild: discord.Guild,
        snap: dict | None,
        deleted_12h: list[dict],
        missing_items: list[dict],
        owner_id: int,
    ):
        super().__init__(timeout=180)
        self.add_item(RecoverySelect(guild, snap, deleted_12h, missing_items, owner_id))


async def build_recovery_message_payload(
    guild: discord.Guild, owner_id: int
) -> tuple[discord.Embed, discord.ui.View | None]:
    has_prem = await is_guild_premium_async(_ACTIVE_BOT, guild, owner_id)
    if not has_prem:
        emb = make_embed(
            "ميزة حصرية لأصحاب Premium",
            "حفظ النسخ الاحتياطية واسترجاع الرومات والرتب متاح فقط للسيرفرات أو الأعضاء المشتركين في **Premium**.",
            discord.Color.red(),
            guild=guild,
        )
        return emb, None

    gid = str(guild.id)
    snap = await asyncio.to_thread(_load_backup_sync, gid)
    deleted_12h = await asyncio.to_thread(_load_deleted_items_sync, gid)

    missing = find_missing_items(guild, snap, deleted_12h)
    mem = _BACKUP_MEM.get(gid) or {}
    orig_b = int(mem.get("orig_bytes", 0) or 0) + sum(int(x.get("o") or 0) for x in deleted_12h)
    comp_b = int(mem.get("comp_bytes", 0) or 0) + sum(int(x.get("z") or 0) for x in deleted_12h)
    ratio = round((comp_b / orig_b) * 100, 1) if orig_b > 0 else 100.0

    if not missing:
        emb = make_embed(
            "النسخة الاحتياطية جاهزة (لا توجد نواقص)",
            f"لا توجد رومات أو رتب ناقصة حالياً (رومات التكتات ورتب الأدمن مستثناة).\n"
            f"• **النسخة الدائمة (`/save`):** `{'محفوظة دائماً' if snap else 'غير محفوظة بعد'}`\n"
            f"• **مهلة حذف المحذوفات غير المسترجعة:** `{EXPIRY_HOURS}h`\n"
            f"• **الحجم المضغوط:** `{comp_b}` بايت (`{ratio}%`)",
            discord.Color.blurple(),
            guild=guild,
        )
        return emb, None

    roles_missing = [m["name"] for m in missing if m["kind"] == "role"]
    ch_missing = [m["name"] for m in missing if m["kind"] == "channel"]
    desc = (
        f"تم العثور على عناصر محذوفة/ناقصة (رومات التكتات ورتب الأدمن مستثناة):\n"
        f"• **الرتب الناقصة ({len(roles_missing)}):** {', '.join(f'`{x}`' for x in roles_missing[:12]) or 'لا يوجد'}\n"
        f"• **الرومات الناقصة ({len(ch_missing)}):** {', '.join(f'`{x}`' for x in ch_missing[:12]) or 'لا يوجد'}\n"
        f"• **الحجم المضغوط:** `{comp_b}` بايت (`{ratio}%`) • تحذف تلقائياً بعد `{EXPIRY_HOURS}h` إذا لم تُسترجع\n\n"
        f"اختر من القائمة بالأسفل **استرجاع الكل** أو حدد ما تريد استرجاعه (ويُحذف من القاعدة فور الاسترجاع)."
    )
    emb = make_embed("قائمة الاسترجاع — Recovery", desc, discord.Color.gold(), guild=guild)
    view = RecoveryView(guild, snap, deleted_12h, missing, owner_id)
    return emb, view


def is_stats_authorized(user_id: int | str | None) -> bool:
    return str(user_id or "").strip() in STATS_ALLOWED_IDS


def check_support_role_access(member: discord.Member, cfg: dict) -> tuple[bool, str]:
    support_role_id = str(cfg.get("support_role_id") or "").strip()
    if not support_role_id.isdigit():
        return (
            False,
            "Support role is not set yet. An administrator must run `setmodrole @role` first.",
        )

    role = member.guild.get_role(int(support_role_id))
    if role is None:
        return (
            False,
            "Configured support role no longer exists. Please set it again with `setmodrole @role`.",
        )

    if any(r.id == role.id for r in member.roles):
        return True, ""

    return False, f"Only members with the {role.mention} role can use this command."


def is_trusted(guild: discord.Guild, user_id: int | str, cfg: dict) -> bool:
    uid = str(user_id)
    if uid in STATS_ALLOWED_IDS or str(guild.owner_id) == uid:
        return True
    support_role_id = str(cfg.get("support_role_id") or "").strip()
    if support_role_id.isdigit() and uid.isdigit():
        m = guild.get_member(int(uid))
        if m and any(str(r.id) == support_role_id for r in m.roles):
            return True
    if cfg.get("trusted_admins_enabled", True):
        trusted_list = [str(x) for x in (cfg.get("trusted_admins") or [])]
        if uid in trusted_list:
            return True
    return False


def make_embed(
    title: str,
    description: str,
    color: discord.Color = discord.Color.purple(),
    guild: discord.Guild | None = None,
    bot: discord.Client | None = None,
) -> discord.Embed:
    emb = discord.Embed(
        title=title[:250],
        description=description[:3950],
        color=color,
        timestamp=datetime.now(timezone.utc),
    )
    target_bot = bot if bot is not None else _ACTIVE_BOT
    if guild is not None:
        apply_guild_branding(emb, guild, target_bot)
    return emb


def _extract_user_id(raw: str) -> int | None:
    cleaned = raw.strip().replace("<@", "").replace("!", "").replace(">", "")
    return int(cleaned) if cleaned.isdigit() else None


async def _resolve_member(guild: discord.Guild, raw: str) -> discord.Member | None:
    uid = _extract_user_id(raw)
    if uid is None:
        return None
    m = guild.get_member(uid)
    if m is not None:
        return m
    try:
        return await guild.fetch_member(uid)
    except discord.HTTPException:
        return None


def _get_log_channel(guild: discord.Guild, cfg: dict) -> discord.TextChannel | None:
    perks = cfg.get("premium_perks") or {}
    ch_id_raw = str(cfg.get("mod_log_channel") or perks.get("alert_channel_id") or "").strip()
    if ch_id_raw.isdigit():
        ch = guild.get_channel(int(ch_id_raw))
        if isinstance(ch, discord.TextChannel):
            return ch
    return None


def _format_duration_label(seconds: int | None) -> str:
    if seconds is None or seconds <= 0:
        return "Permanent / N/A"
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        mins = s // 60
        rem = s % 60
        return f"{mins}m {rem}s" if rem else f"{mins}m"
    if s < 86400:
        hrs = s // 3600
        rem_m = (s % 3600) // 60
        return f"{hrs}h {rem_m}m" if rem_m else f"{hrs}h"
    days = s // 86400
    rem_h = (s % 86400) // 3600
    return f"{days}d {rem_h}h" if rem_h else f"{days}d"


async def send_mod_log(
    guild: discord.Guild,
    cfg: dict,
    action_title: str,
    actor: discord.Member | discord.abc.User | None,
    target_text: str,
    reason: str,
    duration_text: str | None = None,
    extra_lines: str = "",
    message_content: str | None = None,
    attachments_info: list[str] | None = None,
    color: discord.Color = discord.Color.blurple(),
) -> None:
    ch = _get_log_channel(guild, cfg)
    if ch is None:
        return

    if actor is not None:
        actor_line = f"{actor.mention} (`{actor.id}`)"
    elif guild.me is not None:
        actor_line = f"{guild.me.mention} (`{guild.me.id}`) • Bot / Auto-Mod"
    else:
        actor_line = "`Bot / Auto-Mod`"

    dur_line = duration_text if duration_text else "N/A"
    body = (
        f"**Action:** `{action_title}`\n"
        f"**Target:** {target_text}\n"
        f"**Executed By:** {actor_line}\n"
        f"**Duration:** `{dur_line}`\n"
        f"**Reason:** {reason[:400]}"
    )
    if extra_lines:
        body += f"\n{extra_lines}"
    if attachments_info:
        files_txt = ", ".join(attachments_info)[:400]
        body += f"\n**Attachments:** `{files_txt}`"
    if message_content is not None:
        clean_msg = message_content.replace("```", "'''").strip() or "*[No text content]*"
        body += f"\n**Deleted Content:**\n```{clean_msg[:850]}```"

    try:
        await ch.send(
            embed=make_embed(f"Comprehensive Log • {action_title}", body, color, guild=guild)
        )
    except discord.HTTPException:
        pass


async def send_security_log(
    guild: discord.Guild,
    cfg: dict,
    title: str,
    description: str,
    http_session: aiohttp.ClientSession | None = None,
) -> None:
    if not cfg.get("alert_on_trigger", True):
        return
    ch = _get_log_channel(guild, cfg)
    if ch is not None:
        try:
            await ch.send(embed=make_embed(title, description, discord.Color.orange(), guild=guild))
        except discord.HTTPException:
            pass

    perks = cfg.get("premium_perks") or {}
    webhook_url = str(perks.get("alert_webhook_url") or "").strip()
    ok_wh, clean_wh = validate_media_url(webhook_url)
    if ok_wh and clean_wh:
        try:
            if http_session and not http_session.closed:
                await http_session.post(
                    clean_wh,
                    json={"content": f"**{title}**\n{description[:1800]}"},
                    timeout=aiohttp.ClientTimeout(total=3.0),
                )
        except Exception:
            pass


async def apply_punishment_member(
    member: discord.Member,
    punishment_type: str,
    timeout_seconds: int,
    reason: str,
) -> str:
    p = (punishment_type or "Timeout").strip()
    try:
        if p == "Ban":
            await member.ban(reason=reason[:500])
            return "Ban"
        if p == "Kick":
            await member.kick(reason=reason[:500])
            return "Kick"
        if p == "Delete Only":
            return "Delete Only"
        until = datetime.now(timezone.utc) + timedelta(
            seconds=max(10, min(2419200, int(timeout_seconds or 600)))
        )
        await member.timeout(until, reason=reason[:500])
        return "Timeout"
    except discord.HTTPException:
        return f"{p} (Failed)"


async def apply_antinuke_punishment(
    guild: discord.Guild,
    actor_id: int,
    rule_key: str,
    cfg: dict,
    http_session: aiohttp.ClientSession | None = None,
) -> None:
    rule_cfg = (cfg.get("antinuke") or {}).get(rule_key) or {}
    punishment = str(rule_cfg.get("punishment") or "Ban").strip()
    reason = f"Arab Security Anti-Nuke: {rule_key}"

    member = guild.get_member(actor_id)
    if member is None:
        try:
            member = await guild.fetch_member(actor_id)
        except discord.HTTPException:
            member = None

    try:
        if punishment == "Kick" and member:
            await member.kick(reason=reason)
        elif punishment == "Remove Roles" and member:
            removable = [
                r
                for r in member.roles
                if r != guild.default_role and guild.me and r < guild.me.top_role
            ]
            if removable:
                await member.remove_roles(*removable, reason=reason)
        else:
            await guild.ban(discord.Object(id=actor_id), reason=reason)
    except discord.HTTPException:
        pass

    asyncio.create_task(
        send_mod_log(
            guild,
            cfg,
            f"Anti-Nuke ({rule_key})",
            None,
            f"<@{actor_id}> (`{actor_id}`)",
            reason,
            duration_text="Permanent" if punishment == "Ban" else "Instant",
            extra_lines=f"**Punishment:** `{punishment}`",
            color=discord.Color.dark_red(),
        )
    )
    asyncio.create_task(
        send_security_log(
            guild,
            cfg,
            "Anti-Nuke Triggered",
            f"Rule: `{rule_key}`\nActor: <@{actor_id}> (`{actor_id}`)\nAction: `{punishment}`",
            http_session,
        )
    )


async def _find_audit_actor(
    guild: discord.Guild, action: discord.AuditLogAction, target_id: int | None = None
) -> int | None:
    try:
        async for entry in guild.audit_logs(limit=2, action=action):
            if target_id is None or (entry.target and getattr(entry.target, "id", None) == target_id):
                if entry.user and not entry.user.bot:
                    return int(entry.user.id)
    except (discord.Forbidden, discord.HTTPException):
        pass
    return None


def _record_and_check_limit(
    guild_id: str, actor_id: int, rule_key: str, limit: int, window_sec: float = 15.0
) -> bool:
    now = time.monotonic()
    q = ACTION_TRACKER[(str(guild_id), str(actor_id), rule_key)]
    while q and (now - q[0]) > window_sec:
        q.popleft()
    q.append(now)
    return len(q) >= max(1, int(limit or 1))


def _format_uptime(seconds: float) -> str:
    s = max(0, int(seconds))
    days, rem = divmod(s, 86400)
    hours, rem = divmod(rem, 3600)
    mins, secs = divmod(rem, 60)
    return f"{days}d {hours}h {mins}m {secs}s"


def _parse_duration_seconds(raw: str | None) -> int | None:
    if not raw:
        return 600
    txt = raw.strip().lower()
    if txt.isdigit():
        return max(5, min(2419200, int(txt)))
    unit = txt[-1]
    num_part = txt[:-1]
    if not num_part.isdigit() or unit not in ("s", "m", "h", "d"):
        return None
    val = int(num_part)
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    return max(5, min(2419200, val * mult))


class ArabSecurityBot(commands.Bot):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http_session: aiohttp.ClientSession | None = None

    async def get_http_session(self) -> aiohttp.ClientSession:
        if self.http_session is None or self.http_session.closed:
            self.http_session = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(limit=30, ttl_dns_cache=900, keepalive_timeout=45),
                timeout=aiohttp.ClientTimeout(total=12.0, connect=8.0),
            )
        return self.http_session

    async def close(self) -> None:
        if self.http_session and not self.http_session.closed:
            try:
                await self.http_session.close()
            except Exception:
                pass
        await super().close()


def _extract_profile_field(
    cmd: dict,
    extra: dict,
    keys: tuple[str, ...],
    fallback_action: str | None = None,
    target_val: str = "",
    allow_empty: bool = False,
) -> str | None:
    nested_sources = [extra, cmd]
    for container in (extra, cmd):
        if isinstance(container, dict):
            for sub_key in ("profile", "guild_profile", "data", "settings"):
                if isinstance(container.get(sub_key), dict):
                    nested_sources.append(container[sub_key])

    for src in nested_sources:
        if not isinstance(src, dict):
            continue
        for k in keys:
            if k in src and src[k] is not None:
                val = str(src[k]).strip()
                if val or allow_empty:
                    return val
    if fallback_action and cmd.get("action") == fallback_action:
        if target_val or allow_empty:
            return target_val
    return None


async def apply_web_profile_changes(
    bot: ArabSecurityBot,
    gid_str: str,
    cmd: dict | None = None,
    apply_discord_edit: bool = True,
) -> dict:
    """يطبق التعديلات في السيرفر المحدد فقط (Guild Only) دون المساس بالبوت العام أو السيرفرات الأخرى."""
    result = {
        "guild_id": "",
        "scope": "guild_only",
        "avatar_saved": False,
        "banner_saved": False,
        "bio_saved": False,
        "nick_saved": False,
        "error": None,
    }
    cmd_dict = cmd if isinstance(cmd, dict) else {}
    extra = cmd_dict.get("extra") if isinstance(cmd_dict.get("extra"), dict) else {}

    guild, gid, g_err = _resolve_target_guild(bot, cmd_dict, extra, fallback_gid=gid_str)
    result["guild_id"] = gid
    if guild is None:
        result["error"] = g_err
        return result

    action = str(cmd_dict.get("action") or "").strip()
    target_val = str(cmd_dict.get("target") or "").strip()
    actor_uid = _extract_actor_id(cmd_dict, extra) or ADMIN_USER_ID

    if not await is_guild_premium_async(bot, guild, actor_uid or None):
        result["error"] = f"يتطلب اشتراك Premium نشط للسيرفر ({gid}) أو المستخدم."
        return result

    if apply_discord_edit and isinstance(extra, dict):
        guild_nick = _extract_profile_field(
            cmd_dict,
            extra,
            ("bot_nick", "guild_nick", "nickname", "bot_name"),
            allow_empty=False,
        )
        if guild_nick is not None:
            ok_n, _ = await _apply_guild_only_status_nick(guild, guild_nick)
            result["nick_saved"] = ok_n

    if bool(extra.get("reset")) or action == "reset_profile":
        ok_r, msg_r, _ = await reset_guild_profile(
            _db, gid, guild=guild if apply_discord_edit else None
        )
        if not ok_r:
            result["error"] = msg_r
        elif apply_discord_edit:
            await _apply_guild_only_status_nick(guild, "")
        return result

    clear_fields: set[str] = set()
    if bool(extra.get("clear_avatar")) or action == "clear_avatar":
        clear_fields.add("avatar")
    if bool(extra.get("clear_banner")) or action == "clear_banner":
        clear_fields.add("banner")
    if bool(extra.get("clear_bio")) or action == "clear_bio":
        clear_fields.add("bio")

    avatar_to_save: str | None = None
    if "avatar" not in clear_fields:
        avatar_to_save = _extract_profile_field(
            cmd_dict,
            extra,
            ("avatar_data_url", "avatar_url", "bot_avatar", "avatar"),
            fallback_action="update_avatar",
            target_val=target_val,
        )

    banner_to_save: str | None = None
    if "banner" not in clear_fields:
        banner_to_save = _extract_profile_field(
            cmd_dict,
            extra,
            ("banner_data_url", "banner_url", "bot_banner", "banner"),
            fallback_action="update_banner",
            target_val=target_val,
        )

    bio_to_save: str | None = None
    if "bio" not in clear_fields:
        bio_to_save = _extract_profile_field(
            cmd_dict,
            extra,
            ("bio", "bot_bio", "guild_bio", "about", "description"),
            fallback_action=(
                "update_bio"
                if action == "update_bio"
                else ("update_bot_profile" if action == "update_bot_profile" else None)
            ),
            target_val=target_val,
            allow_empty=True,
        )

    sess = getattr(bot, "http_session", None)
    ok, msg = await save_guild_profile(
        _db,
        gid,
        avatar_url=avatar_to_save,
        banner_url=banner_to_save,
        bio=bio_to_save,
        clear_fields=clear_fields,
        session=sess,
        guild=guild if apply_discord_edit else None,
    )
    if not ok:
        result["error"] = msg
        return result

    latest = await get_guild_profile(_db, gid, force_refresh=True) or _empty_profile(gid)
    _PROFILE_MEM[gid] = dict(latest)
    _PROFILE_CACHE[gid] = (time.monotonic(), dict(latest))
    result["avatar_saved"] = bool(latest.get("avatar_url"))
    result["banner_saved"] = bool(latest.get("banner_url"))
    result["bio_saved"] = bool(latest.get("bio"))
    return result


async def fetch_guild_profile_from_web(bot: ArabSecurityBot, guild_id: int | str) -> dict | None:
    """جلب أحدث بروفايل محفوظ للسيرفر المحدد فقط من API الموقع وتطبيقه على هذا السيرفر."""
    gid = str(guild_id).strip()
    if not gid.isdigit() or not WEB_BASE_URL or not BOT_SYNC_SECRET:
        return None
    try:
        sess = await bot.get_http_session()
        async with sess.get(
            f"{WEB_BASE_URL}/api/bot/guild-profile?guild_id={gid}",
            headers=_api_headers(),
        ) as resp:
            if resp.status != 200:
                return None
            data = await resp.json(content_type=None)
            prof = data.get("guild_profile")
            if isinstance(prof, dict) and prof:
                guild = bot.get_guild(int(gid))
                if guild is not None:
                    await apply_web_profile_changes(
                        bot,
                        gid,
                        {"action": "update_bot_profile", "guild_id": gid, "extra": prof},
                        apply_discord_edit=True,
                    )
                return prof
    except Exception:
        pass
    return None


async def restore_saved_profiles_on_startup(bot: ArabSecurityBot) -> None:
    await load_all_guild_profiles(_db)


async def execute_remote_command(bot: ArabSecurityBot, cmd: dict) -> None:
    action = str(cmd.get("action") or "").strip()
    extra = cmd.get("extra") if isinstance(cmd.get("extra"), dict) else {}
    gid_str = _extract_guild_id(cmd, extra, fallback=str(cmd.get("guild_id") or "").strip())
    target_str = str(cmd.get("target") or "").strip()
    reason_str = str(cmd.get("reason") or "Remote action from Arab Security Panel").strip()

    if action in ("set_status", "update_presence", "change_status", "set_presence"):
        guild, gid_str, _ = _resolve_target_guild(bot, cmd, extra, fallback_gid=gid_str)
        if guild is None:
            return
        payload = _extract_guild_status_payload(cmd, extra)
        save_guild_fields(
            gid_str,
            {
                "guild_status": payload["guild_status"],
                "guild_status_text": payload["guild_status_text"],
                "guild_status_mode": "guild_only",
            },
        )
        ok_nick, nick_msg = await _apply_guild_only_status_nick(
            guild, payload["guild_status_text"]
        )
        cfg = await get_guild_cfg_async(guild.id)
        asyncio.create_task(
            send_mod_log(
                guild,
                cfg,
                "Guild Nick Updated",
                None,
                f"Guild `{guild.name}` (`{guild.id}`)",
                reason_str,
                extra_lines=(
                    f"**Scope:** `Guild Only ({guild.id})`\n"
                    f"**Text:** `{payload['guild_status_text'] or 'Default'}`\n"
                    f"**Result:** `{nick_msg}`"
                ),
                color=discord.Color.green() if ok_nick else discord.Color.orange(),
            )
        )
        return

    if action == "sync_guild_cfg":
        guild, gid_str, _ = _resolve_target_guild(bot, cmd, extra, fallback_gid=gid_str)
        if guild is not None and gid_str.isdigit():
            _CFG_CACHE.pop(gid_str, None)
            _PROFILE_CACHE.pop(gid_str, None)
            cfg = await get_guild_cfg_async(gid_str)
            prof = await get_guild_profile(_db, gid_str, force_refresh=True)
            if isinstance(prof, dict):
                await _apply_guild_only_bio(guild, prof.get("bio", ""))
            if str(cfg.get("guild_status_text") or "").strip():
                await _apply_guild_only_status_nick(guild, str(cfg.get("guild_status_text") or ""))
            await fetch_guild_profile_from_web(bot, gid_str)
            log_ch_val = str(cfg.get("mod_log_channel") or "")
            log_line = (
                f"**Log Channel:** <#{log_ch_val}>"
                if log_ch_val.isdigit()
                else "**Log Channel:** `Not Set`"
            )
            asyncio.create_task(
                send_mod_log(
                    guild,
                    cfg,
                    "Dashboard Config Sync",
                    None,
                    f"Guild `{guild.name}` (`{guild.id}`)",
                    reason_str,
                    extra_lines=(
                        f"**Scope:** `Guild Only ({guild.id})`\n"
                        f"{log_line}\n"
                        f"**Guild Nick:** `{cfg.get('guild_status_text') or cfg.get('guild_status') or 'Default'}`"
                    ),
                    color=discord.Color.blurple(),
                )
            )
        return

    if action in (
        "update_bot_profile",
        "update_avatar",
        "update_banner",
        "update_bio",
        "clear_avatar",
        "clear_banner",
        "clear_bio",
        "reset_profile",
    ):
        guild, gid_str, _ = _resolve_target_guild(bot, cmd, extra, fallback_gid=gid_str)
        if guild is None:
            return
        actor_uid = _extract_actor_id(cmd, extra) or ADMIN_USER_ID
        if not await is_guild_premium_async(bot, guild, actor_uid or None):
            cfg = await get_guild_cfg_async(guild.id)
            asyncio.create_task(
                send_mod_log(
                    guild,
                    cfg,
                    f"Profile Update Rejected ({action})",
                    None,
                    f"Guild `{guild.name}` (`{guild.id}`)",
                    "Premium subscription required for guild or user.",
                    color=discord.Color.orange(),
                )
            )
            return

        res = await apply_web_profile_changes(bot, gid_str, cmd, apply_discord_edit=True)
        cfg = await get_guild_cfg_async(guild.id)
        if res.get("error"):
            asyncio.create_task(
                send_mod_log(
                    guild,
                    cfg,
                    f"Profile Save Failed ({action})",
                    None,
                    f"Guild `{guild.name}` (`{guild.id}`)",
                    res["error"],
                    color=discord.Color.red(),
                )
            )
        else:
            asyncio.create_task(
                send_mod_log(
                    guild,
                    cfg,
                    f"Profile Updated ({action})",
                    None,
                    f"Guild `{guild.name}` (`{guild.id}`)",
                    reason_str,
                    extra_lines=(
                        f"**Scope:** `Guild Only ({gid_str})`\n"
                        f"**Avatar Set:** `{res['avatar_saved']}` • "
                        f"**Banner Set:** `{res['banner_saved']}` • "
                        f"**Bio Set:** `{res['bio_saved']}`"
                    ),
                    color=discord.Color.green(),
                )
            )
        return

    if action == "broadcast":
        msg_text = target_str.strip()
        if not msg_text:
            return
        target_guilds = [bot.get_guild(int(gid_str))] if gid_str.isdigit() else list(bot.guilds)
        for g in target_guilds:
            if g is None:
                continue
            target_ch = g.system_channel
            if not isinstance(target_ch, discord.TextChannel):
                for ch in g.text_channels:
                    if g.me and ch.permissions_for(g.me).send_messages:
                        target_ch = ch
                        break
            if isinstance(target_ch, discord.TextChannel):
                try:
                    await target_ch.send(
                        embed=make_embed("Announcement", msg_text, guild=g, bot=bot)
                    )
                except discord.HTTPException:
                    pass
        return

    if not gid_str.isdigit():
        return
    guild = bot.get_guild(int(gid_str))
    if guild is None:
        return

    cfg = await get_guild_cfg_async(guild.id)

    if action in ("kick", "ban", "unban", "timeout") and target_str.isdigit():
        uid = int(target_str)
        try:
            if action == "kick":
                m = guild.get_member(uid) or await guild.fetch_member(uid)
                await m.kick(reason=reason_str[:500])
                asyncio.create_task(
                    send_mod_log(
                        guild,
                        cfg,
                        "Remote Kick",
                        None,
                        f"<@{uid}> (`{uid}`)",
                        reason_str,
                        color=discord.Color.red(),
                    )
                )
            elif action == "ban":
                await guild.ban(discord.Object(id=uid), reason=reason_str[:500])
                asyncio.create_task(
                    send_mod_log(
                        guild,
                        cfg,
                        "Remote Ban",
                        None,
                        f"<@{uid}> (`{uid}`)",
                        reason_str,
                        duration_text="Permanent",
                        color=discord.Color.dark_red(),
                    )
                )
            elif action == "unban":
                await guild.unban(discord.Object(id=uid), reason=reason_str[:500])
                asyncio.create_task(
                    send_mod_log(
                        guild,
                        cfg,
                        "Remote Unban",
                        None,
                        f"<@{uid}> (`{uid}`)",
                        reason_str,
                        color=discord.Color.green(),
                    )
                )
            elif action == "timeout":
                secs = _parse_duration_seconds(str(cmd.get("duration") or "10m")) or 600
                m = guild.get_member(uid) or await guild.fetch_member(uid)
                until = datetime.now(timezone.utc) + timedelta(seconds=secs)
                await m.timeout(until, reason=reason_str[:500])
                asyncio.create_task(
                    send_mod_log(
                        guild,
                        cfg,
                        "Remote Timeout",
                        None,
                        f"<@{uid}> (`{uid}`)",
                        reason_str,
                        duration_text=_format_duration_label(secs),
                        color=discord.Color.gold(),
                    )
                )
        except discord.HTTPException:
            pass


def _fetch_visits_sync() -> int:
    if site_stats_col is None:
        return 0
    try:
        vdoc = site_stats_col.find_one({"_id": "visitors"}, {"total_visits": 1})
        if isinstance(vdoc, dict):
            return int(vdoc.get("total_visits", 0) or 0)
    except PyMongoError:
        pass
    return 0


def _persist_bot_overview_sync(total_guilds: int, total_members: int, latency_ms: int) -> None:
    if site_stats_col is None:
        return
    try:
        site_stats_col.update_one(
            {"_id": "bot_overview"},
            {
                "$set": {
                    "total_guilds": total_guilds,
                    "total_members": total_members,
                    "latency_ms": latency_ms,
                    "updated_at": datetime.now(timezone.utc),
                }
            },
            upsert=True,
        )
    except PyMongoError:
        pass


def _persist_bot_guilds_sync(payload_guilds: list[dict]) -> None:
    if bot_guilds_col is None:
        return
    try:
        now_dt = datetime.now(timezone.utc)
        for item in payload_guilds:
            bot_guilds_col.update_one(
                {"id": str(item["id"])},
                {"$set": {**item, "active": True, "updated_at": now_dt}},
                upsert=True,
            )
    except PyMongoError:
        pass


def _persist_boosters_sync(guild_id_str: str, boosters: list[dict]) -> None:
    if site_stats_col is None:
        return
    try:
        site_stats_col.update_one(
            {"_id": f"boosters_{guild_id_str}"},
            {
                "$set": {
                    "guild_id": guild_id_str,
                    "boosters": boosters,
                    "count": len(boosters),
                    "updated_at": datetime.now(timezone.utc),
                }
            },
            upsert=True,
        )
    except PyMongoError:
        pass


async def build_stats_embed(
    bot: ArabSecurityBot, guild: discord.Guild | None = None
) -> discord.Embed:
    guilds_count = len(bot.guilds)
    total_members = sum(int(g.member_count or 0) for g in bot.guilds)
    latency_ms = max(1, int(round((bot.latency or 0.0) * 1000)))
    uptime_str = _format_uptime(time.monotonic() - _BOT_START_TIME)
    db_status = "Connected" if guild_settings_col is not None else "Memory Fallback"
    total_visits = await asyncio.to_thread(_fetch_visits_sync)

    return make_embed(
        "Bot & System Statistics",
        f"**Guilds:** `{guilds_count}`\n"
        f"**Total Members:** `{total_members}`\n"
        f"**Latency:** `{latency_ms}ms`\n"
        f"**Uptime:** `{uptime_str}`\n"
        f"**Database:** `{db_status}`\n"
        f"**Site Visits:** `{total_visits}`",
        guild=guild,
        bot=bot,
    )


def build_help_embed(
    prefix: str,
    support_role_id: str = "",
    log_ch_id: str = "",
    guild: discord.Guild | None = None,
    bot: discord.Client | None = None,
) -> discord.Embed:
    role_line = f"<@&{support_role_id}>" if support_role_id.isdigit() else "`Not Set`"
    log_line = f"<#{log_ch_id}>" if log_ch_id.isdigit() else "`Not Set`"
    desc = (
        f"**Support Role:** {role_line}\n"
        f"**Comprehensive Logs (Admin Only Setup):** {log_line}\n"
        f"**Premium Boost Guild:** `{BOOST_GUILD_ID}`\n\n"
        f"**Moderation (Support Role Only)**\n"
        f"`{prefix}kick @user|id [reason]` / `/kick`\n"
        f"`{prefix}ban @user|id [reason]` / `/ban`\n"
        f"`{prefix}unban <user_id> [reason]` / `/unban`\n"
        f"`{prefix}timeout @user|id [10m] [reason]` / `/timeout`\n"
        f"`{prefix}untimeout @user|id [reason]` / `/untimeout`\n\n"
        f"**Profile, Recovery & Setup (Admin Only)**\n"
        f"`{prefix}save` / `/save` — حفظ نسخة دائمة مضغوطة (بدون رتب الأدمن)\n"
        f"`{prefix}recovery` / `/recovery` — استرجاع المحذوفات (مهلة {EXPIRY_HOURS}h ثم تُحذف تلقائياً)\n"
        f"`{prefix}profile` / `/profile` — View saved guild profile (Guild Only • Managed from Website)\n"
        f"`{prefix}checkprem` / `/checkprem` — Inspect Premium match in DB\n"
        f"`{prefix}setmodrole @role` / `/setmodrole` — Set support role (Admin)\n"
        f"`{prefix}setlog #channel` / `/setlog` — Set comprehensive logs channel (Admin)\n"
        f"`{prefix}autoline #channel <line_url>` / `/autoline` — Enable auto line\n"
        f"`{prefix}autolineoff #channel` / `/autolineoff` — Disable auto line\n"
        f"`{prefix}servers` / `/servers` — Connected servers count & sync\n"
        f"`{prefix}sync` / `/sync` — Sync server settings"
    )
    return make_embed("Arab Security Commands", desc, guild=guild, bot=bot)


def _api_headers() -> dict[str, str]:
    return {
        "Content-Type": "application/json",
        "X-Bot-Secret": BOT_SYNC_SECRET,
        "User-Agent": f"ArabSecurityBot/1.0 (+{WEB_BASE_URL})",
    }


def build_bot() -> ArabSecurityBot:
    global _ACTIVE_BOT
    intents = discord.Intents.default()
    intents.guilds = True
    intents.members = True
    intents.messages = True
    intents.message_content = True

    async def dynamic_prefix(bot_inst: commands.Bot, message: discord.Message) -> list[str]:
        if not message.guild:
            return ["!"]
        cfg = await get_guild_cfg_async(message.guild.id)
        p = str(cfg.get("prefix") or "!").strip() or "!"
        return commands.when_mentioned_or(p)(bot_inst, message)

    bot = ArabSecurityBot(
        command_prefix=dynamic_prefix,
        intents=intents,
        help_command=None,
        case_insensitive=True,
    )
    _ACTIVE_BOT = bot

    def _collect_boosters() -> list[dict]:
        target_guild = bot.get_guild(BOOST_GUILD_ID)
        if target_guild is None:
            return []
        boosters_map: dict[str, dict] = {}
        for m in target_guild.members:
            if not m.bot and m.premium_since is not None:
                boosters_map[str(m.id)] = {
                    "user_id": str(m.id),
                    "username": m.display_name or m.name,
                    "guild_id": str(target_guild.id),
                    "premium_since": m.premium_since.isoformat(),
                }
        return list(boosters_map.values())

    async def sync_boosters_to_site() -> bool:
        boosters_list = _collect_boosters()
        asyncio.create_task(
            asyncio.to_thread(_persist_boosters_sync, str(BOOST_GUILD_ID), boosters_list)
        )
        if not WEB_BASE_URL or not BOT_SYNC_SECRET:
            return False
        try:
            sess = await bot.get_http_session()
            async with sess.post(
                f"{WEB_BASE_URL}/api/bot/boost-sync",
                json={"guild_id": str(BOOST_GUILD_ID), "boosters": boosters_list},
                headers=_api_headers(),
            ) as resp:
                return resp.status == 200
        except Exception:
            return False

    async def sync_guilds_to_site(event: str = "heartbeat", guild_name: str = "") -> bool:
        payload_guilds = [
            {
                "id": str(g.id),
                "name": g.name,
                "icon": str(g.icon.key) if g.icon else "",
                "member_count": int(g.member_count or 0),
                "owner_id": str(g.owner_id or ""),
            }
            for g in bot.guilds
        ]
        total_guilds = len(bot.guilds)
        total_members = sum(int(g.member_count or 0) for g in bot.guilds)
        latency_ms = max(1, int(round((bot.latency or 0.0) * 1000)))

        asyncio.create_task(asyncio.to_thread(_persist_bot_guilds_sync, payload_guilds))
        asyncio.create_task(
            asyncio.to_thread(_persist_bot_overview_sync, total_guilds, total_members, latency_ms)
        )

        if not WEB_BASE_URL or not BOT_SYNC_SECRET:
            return False

        body = {
            "guilds": payload_guilds,
            "total_guilds": total_guilds,
            "total_members": total_members,
            "replace_missing": False,
            "latency_ms": latency_ms,
            "event": event,
            "guild_name": guild_name,
        }
        try:
            sess = await bot.get_http_session()
            async with sess.post(
                f"{WEB_BASE_URL}/api/bot/sync-guilds", json=body, headers=_api_headers()
            ) as resp:
                return resp.status == 200
        except Exception:
            return False

    async def sync_premium_grant_to_site(info: dict) -> None:
        if not WEB_BASE_URL or not BOT_SYNC_SECRET:
            return
        try:
            sess = await bot.get_http_session()
            exp_dt = info.get("expires_at")
            payload = {
                "user_id": str(info.get("target_id") or ""),
                "guild_id": str(info.get("guild_id") or ""),
                "active": True,
                "permanent": bool(info.get("permanent")),
                "days": int(info.get("days") or 0),
                "expires_at": exp_dt.isoformat() if isinstance(exp_dt, datetime) else None,
                "perks": info.get("perks") or {},
            }
            for endpoint in ("/api/bot/premium-sync", "/api/bot/give-premium"):
                try:
                    async with sess.post(
                        f"{WEB_BASE_URL}{endpoint}",
                        json=payload,
                        headers=_api_headers(),
                    ) as resp:
                        if resp.status in (200, 201):
                            break
                except Exception:
                    pass
        except Exception:
            pass

    def _poll_mongo_commands_sync() -> list[dict]:
        out: list[dict] = []
        if remote_commands_col is None:
            return out
        try:
            for _ in range(25):
                doc = remote_commands_col.find_one_and_update(
                    {"status": "pending"},
                    {"$set": {"status": "done", "done_at": datetime.now(timezone.utc)}},
                    sort=[("_id", 1)],
                )
                if not isinstance(doc, dict):
                    break
                out.append(doc)
        except PyMongoError:
            pass
        return out

    async def poll_pending_commands() -> None:
        if WEB_BASE_URL and BOT_SYNC_SECRET:
            try:
                sess = await bot.get_http_session()
                async with sess.get(
                    f"{WEB_BASE_URL}/api/bot/pending-commands",
                    headers=_api_headers(),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        cmds = [
                            c for c in (data.get("commands") or []) if isinstance(c, dict)
                        ]
                        if cmds:
                            await asyncio.gather(
                                *(execute_remote_command(bot, c) for c in cmds)
                            )
                        return
            except Exception:
                pass

        docs = await asyncio.to_thread(_poll_mongo_commands_sync)
        if docs:
            await asyncio.gather(*(execute_remote_command(bot, d) for d in docs))

    @tasks.loop(seconds=45)
    async def heartbeat_task() -> None:
        await sync_guilds_to_site("heartbeat")
        await sync_boosters_to_site()

    @tasks.loop(seconds=5)
    async def commands_task() -> None:
        await poll_pending_commands()

    @tasks.loop(minutes=15)
    async def cleanup_expired_task() -> None:
        await asyncio.to_thread(_cleanup_expired_records_sync)

    @bot.event
    async def setup_hook() -> None:
        await bot.get_http_session()
        try:
            synced = await bot.tree.sync()
            print(f"[BOT] Successfully synced {len(synced)} slash commands.")
        except Exception as exc:
            print(f"[BOT] Failed to sync slash commands: {exc}")
            traceback.print_exc()

    @bot.tree.error
    async def on_app_command_error(
        interaction: discord.Interaction, error: app_commands.AppCommandError
    ) -> None:
        print(f"[SLASH ERROR] {error}")
        traceback.print_exc()
        emb = make_embed(
            "Command Error",
            "حدث خطأ أثناء تنفيذ الأمر. تأكد من الصلاحيات وحاول مرة أخرى.",
            discord.Color.red(),
            guild=interaction.guild,
            bot=bot,
        )
        try:
            if interaction.response.is_done():
                await interaction.followup.send(embed=emb, ephemeral=True)
            else:
                await interaction.response.send_message(embed=emb, ephemeral=True)
        except discord.HTTPException:
            pass

    @bot.event
    async def on_ready() -> None:
        print(
            f"[BOT] Logged in as {bot.user} ({bot.user.id}) | Connected Guilds: {len(bot.guilds)}"
        )
        boost_guild = bot.get_guild(BOOST_GUILD_ID)
        if boost_guild and not boost_guild.chunked:
            try:
                await boost_guild.chunk(cache=True)
            except Exception:
                pass
        asyncio.create_task(asyncio.to_thread(_cleanup_expired_records_sync))
        await restore_saved_profiles_on_startup(bot)
        asyncio.create_task(sync_guilds_to_site("ready"))
        asyncio.create_task(sync_boosters_to_site())
        if not heartbeat_task.is_running():
            heartbeat_task.start()
        if not commands_task.is_running():
            commands_task.start()
        if not cleanup_expired_task.is_running():
            cleanup_expired_task.start()

    @bot.event
    async def on_command_error(ctx: commands.Context, error: commands.CommandError) -> None:
        if isinstance(error, commands.CommandNotFound):
            return
        if isinstance(error, commands.MissingRequiredArgument):
            await ctx.send(
                embed=make_embed(
                    "Missing Argument",
                    f"Missing required parameter: `{error.param.name}`",
                    discord.Color.red(),
                    guild=ctx.guild,
                    bot=bot,
                )
            )
            return
        if isinstance(error, commands.BadArgument):
            await ctx.send(
                embed=make_embed(
                    "Invalid Argument",
                    "Please check the user, channel, role, or ID you entered.",
                    discord.Color.red(),
                    guild=ctx.guild,
                    bot=bot,
                )
            )
            return
        if isinstance(error, commands.MissingPermissions):
            await ctx.send(
                embed=make_embed(
                    "Permission Denied",
                    "You do not have permission to run this command.",
                    discord.Color.red(),
                    guild=ctx.guild,
                    bot=bot,
                )
            )
            return
        print(f"[PREFIX CMD ERROR] {error}")
        traceback.print_exc()

    @bot.event
    async def on_guild_join(guild: discord.Guild) -> None:
        cfg = await get_guild_cfg_async(guild.id)
        asyncio.create_task(
            send_mod_log(
                guild,
                cfg,
                "Bot Joined Server",
                None,
                f"`{guild.name}` (`{guild.id}`)",
                "Bot added to guild",
                color=discord.Color.green(),
            )
        )
        asyncio.create_task(sync_guilds_to_site("guild_join", guild.name))
        asyncio.create_task(sync_boosters_to_site())

    @bot.event
    async def on_guild_remove(guild: discord.Guild) -> None:
        _CFG_CACHE.pop(str(guild.id), None)
        asyncio.create_task(sync_guilds_to_site("guild_remove", guild.name))
        asyncio.create_task(sync_boosters_to_site())

    @bot.event
    async def on_member_update(before: discord.Member, after: discord.Member) -> None:
        if after.guild.id == BOOST_GUILD_ID and before.premium_since != after.premium_since:
            asyncio.create_task(sync_boosters_to_site())

    @bot.event
    async def on_member_join(member: discord.Member) -> None:
        guild = member.guild
        cfg = await get_guild_cfg_async(guild.id)
        sess = await bot.get_http_session()

        if cfg.get("anti_bot_raid") and member.bot:
            if not is_trusted(guild, member.id, cfg):
                actor_id = await _find_audit_actor(guild, discord.AuditLogAction.bot_add, member.id)
                rule = (cfg.get("antinuke") or {}).get("anti_bot_add") or {
                    "enabled": True,
                    "limit": 1,
                }
                if rule.get("enabled", True) and actor_id and not is_trusted(guild, actor_id, cfg):
                    if _record_and_check_limit(
                        str(guild.id), actor_id, "anti_bot_add", int(rule.get("limit", 1) or 1)
                    ):
                        await apply_antinuke_punishment(guild, actor_id, "anti_bot_add", cfg, sess)
                try:
                    await member.kick(reason="Arab Security: Anti Bot Raid")
                except discord.HTTPException:
                    pass
            return

        if cfg.get("anti_new_accounts") and not member.bot:
            min_days = max(1, int(cfg.get("min_account_age_days", 7) or 7))
            age = datetime.now(timezone.utc) - member.created_at
            if age.days < min_days:
                try:
                    await member.kick(reason=f"Account younger than {min_days} days")
                except discord.HTTPException:
                    pass
                return

        if cfg.get("anti_raid") and not member.bot:
            now = time.monotonic()
            jq = JOIN_TRACKER[str(guild.id)]
            while jq and (now - jq[0]) > 10.0:
                jq.popleft()
            jq.append(now)
            if len(jq) >= 7:
                try:
                    until = datetime.now(timezone.utc) + timedelta(minutes=10)
                    await member.timeout(until, reason="Arab Security: Anti-Raid Surge")
                except discord.HTTPException:
                    pass

    @bot.event
    async def on_message(message: discord.Message) -> None:
        if message.author.bot or not message.guild:
            return

        raw_stripped = (message.content or "").strip()
        if raw_stripped.lower().startswith("!giv_premium"):
            if not is_restricted_owner(message.author.id):
                return
            parts = raw_stripped.split()
            if len(parts) < 2:
                await message.channel.send(
                    embed=make_embed(
                        "استخدام الأمر",
                        "الاستخدام:\n`!Giv_Premium <@user|user_id|guild_id> [days|perm]`\nمثال: `!Giv_Premium 123456789012345678 30` أو `perm`",
                        discord.Color.gold(),
                        guild=message.guild,
                        bot=bot,
                    )
                )
                return

            target_raw = parts[1]
            target_id_num = _extract_user_id(target_raw)
            if target_id_num is None:
                await message.channel.send(
                    embed=make_embed(
                        "معرف غير صالح",
                        "يرجى إدخال منشن أو ID صحيح للعضو أو السيرفر.",
                        discord.Color.red(),
                        guild=message.guild,
                        bot=bot,
                    )
                )
                return

            days_val = 30
            if len(parts) >= 3:
                dur_tok = parts[2].strip().lower()
                if dur_tok in ("perm", "permanent", "life", "lifetime", "0", "forever"):
                    days_val = 0
                elif dur_tok.isdigit():
                    days_val = max(1, min(3650, int(dur_tok)))

            target_id_str = str(target_id_num)
            info = await asyncio.to_thread(
                _grant_premium_sync,
                target_id_str,
                days_val,
                message.guild,
                str(message.author.id),
            )
            asyncio.create_task(sync_premium_grant_to_site(info))

            exp_txt = (
                "دائم (Permanent)"
                if info["permanent"]
                else f"`{info['days']}` يوم ({info['expires_at'].strftime('%Y-%m-%d %H:%M UTC')})"
            )
            await message.channel.send(
                embed=make_embed(
                    "تم تفعيل Premium بنجاح",
                    f"**المستفيد (ID):** `<@{target_id_str}>` (`{target_id_str}`)\n"
                    f"**السيرفر:** `{message.guild.name}` (`{message.guild.id}`)\n"
                    f"**المدة:** {exp_txt}\n"
                    f"**الحالة:** `مفعّل في الموقع + البوت + جميع المزايا`\n"
                    f"**المزايا المفعلة:** `Custom Profile` • `Save & Recovery` • `Anti-Nuke Pro` • `Auto-Lines` • `Logs`",
                    discord.Color.green(),
                    guild=message.guild,
                    bot=bot,
                )
            )
            return

        guild = message.guild
        cfg = await get_guild_cfg_async(guild.id)

        if isinstance(message.author, discord.Member) and not is_trusted(
            guild, message.author.id, cfg
        ):
            content_raw = message.content or ""
            content_low = content_raw.lower()
            att_names = [a.filename for a in (message.attachments or [])]

            if cfg.get("anti_invites") and (
                "discord.gg/" in content_low
                or "[discord.com/invite/](https://discord.com/invite/)" in content_low
                or "[discordapp.com/invite/](https://discordapp.com/invite/)" in content_low
            ):
                punishment_cfg = str(cfg.get("link_punishment") or "Delete & Timeout")
                timeout_sec = int(cfg.get("link_timeout_seconds", 300) or 300)
                try:
                    await message.delete()
                    applied = await apply_punishment_member(
                        message.author, punishment_cfg, timeout_sec, "Arab Security: Anti-Invite"
                    )
                    dur_lbl = (
                        _format_duration_label(timeout_sec)
                        if "Timeout" in applied or "Timeout" in punishment_cfg
                        else "Instant"
                    )
                    asyncio.create_task(
                        send_mod_log(
                            guild,
                            cfg,
                            "Anti-Invite Triggered",
                            None,
                            f"{message.author.mention} (`{message.author.id}`)",
                            "Posted a Discord invite link",
                            duration_text=dur_lbl,
                            extra_lines=f"**Channel:** <#{message.channel.id}> (`{message.channel.id}`)\n**Punishment:** `{applied}`",
                            message_content=content_raw,
                            attachments_info=att_names or None,
                            color=discord.Color.red(),
                        )
                    )
                except discord.HTTPException:
                    pass
                return

            if cfg.get("anti_link") and ("http://" in content_low or "https://" in content_low):
                punishment_cfg = str(cfg.get("link_punishment") or "Delete & Timeout")
                timeout_sec = int(cfg.get("link_timeout_seconds", 300) or 300)
                try:
                    await message.delete()
                    applied = await apply_punishment_member(
                        message.author, punishment_cfg, timeout_sec, "Arab Security: Anti-Link"
                    )
                    dur_lbl = (
                        _format_duration_label(timeout_sec)
                        if "Timeout" in applied or "Timeout" in punishment_cfg
                        else "Instant"
                    )
                    asyncio.create_task(
                        send_mod_log(
                            guild,
                            cfg,
                            "Anti-Link Triggered",
                            None,
                            f"{message.author.mention} (`{message.author.id}`)",
                            "Posted an external link",
                            duration_text=dur_lbl,
                            extra_lines=f"**Channel:** <#{message.channel.id}> (`{message.channel.id}`)\n**Punishment:** `{applied}`",
                            message_content=content_raw,
                            attachments_info=att_names or None,
                            color=discord.Color.orange(),
                        )
                    )
                except discord.HTTPException:
                    pass
                return

            if cfg.get("anti_files") and att_names:
                punishment_cfg = str(cfg.get("file_punishment") or "Delete & Timeout")
                timeout_sec = int(cfg.get("file_timeout_seconds", 300) or 300)
                try:
                    await message.delete()
                    applied = await apply_punishment_member(
                        message.author, punishment_cfg, timeout_sec, "Arab Security: Anti-File"
                    )
                    dur_lbl = (
                        _format_duration_label(timeout_sec)
                        if "Timeout" in applied or "Timeout" in punishment_cfg
                        else "Instant"
                    )
                    asyncio.create_task(
                        send_mod_log(
                            guild,
                            cfg,
                            "Anti-File Triggered",
                            None,
                            f"{message.author.mention} (`{message.author.id}`)",
                            "Sent blocked attachment file(s)",
                            duration_text=dur_lbl,
                            extra_lines=f"**Channel:** <#{message.channel.id}> (`{message.channel.id}`)\n**Punishment:** `{applied}`",
                            message_content=content_raw,
                            attachments_info=att_names,
                            color=discord.Color.red(),
                        )
                    )
                except discord.HTTPException:
                    pass
                return

            if (
                cfg.get("anti_mention_spam")
                and (len(message.mentions) + len(message.role_mentions)) >= 6
            ):
                try:
                    await message.delete()
                    applied = await apply_punishment_member(
                        message.author, "Timeout", 300, "Arab Security: Mass Mention"
                    )
                    asyncio.create_task(
                        send_mod_log(
                            guild,
                            cfg,
                            "Anti-Mass-Mention Triggered",
                            None,
                            f"{message.author.mention} (`{message.author.id}`)",
                            f"Mentioned `{len(message.mentions) + len(message.role_mentions)}` users/roles",
                            duration_text=_format_duration_label(300),
                            extra_lines=f"**Channel:** <#{message.channel.id}> (`{message.channel.id}`)\n**Punishment:** `{applied}`",
                            message_content=content_raw,
                            attachments_info=att_names or None,
                            color=discord.Color.gold(),
                        )
                    )
                except discord.HTTPException:
                    pass
                return

            if cfg.get("anti_spam"):
                now = time.monotonic()
                mq = MSG_TRACKER[(str(guild.id), str(message.author.id))]
                while mq and (now - mq[0]) > 6.0:
                    mq.popleft()
                mq.append(now)
                if len(mq) >= 6:
                    mq.clear()
                    punishment_cfg = str(cfg.get("spam_punishment") or "Timeout")
                    timeout_sec = int(cfg.get("spam_timeout_seconds", 600) or 600)
                    try:
                        await message.delete()
                    except discord.HTTPException:
                        pass
                    applied = await apply_punishment_member(
                        message.author, punishment_cfg, timeout_sec, "Arab Security: Anti-Spam"
                    )
                    dur_lbl = (
                        _format_duration_label(timeout_sec)
                        if "Timeout" in applied or "Timeout" in punishment_cfg
                        else "Instant"
                    )
                    asyncio.create_task(
                        send_mod_log(
                            guild,
                            cfg,
                            "Anti-Spam Triggered",
                            None,
                            f"{message.author.mention} (`{message.author.id}`)",
                            "Sent rapid repeated messages",
                            duration_text=dur_lbl,
                            extra_lines=f"**Channel:** <#{message.channel.id}> (`{message.channel.id}`)\n**Punishment:** `{applied}`",
                            message_content=content_raw,
                            attachments_info=att_names or None,
                            color=discord.Color.dark_orange(),
                        )
                    )
                    return

        auto_lines = cfg.get("auto_lines") or {}
        line_url = str(auto_lines.get(str(message.channel.id)) or "").strip()
        if line_url.startswith(("https://", "http://")):
            try:
                await message.channel.send(line_url)
            except discord.HTTPException:
                pass

        await bot.process_commands(message)

    @bot.event
    async def on_member_ban(guild: discord.Guild, user: discord.User) -> None:
        cfg = await get_guild_cfg_async(guild.id)
        rule = (cfg.get("antinuke") or {}).get("anti_ban") or {"enabled": True, "limit": 1}
        if not rule.get("enabled", True):
            return
        actor_id = await _find_audit_actor(guild, discord.AuditLogAction.ban, user.id)
        if actor_id and not is_trusted(guild, actor_id, cfg):
            if _record_and_check_limit(
                str(guild.id), actor_id, "anti_ban", int(rule.get("limit", 1) or 1)
            ):
                sess = await bot.get_http_session()
                await apply_antinuke_punishment(guild, actor_id, "anti_ban", cfg, sess)

    @bot.event
    async def on_member_remove(member: discord.Member) -> None:
        guild = member.guild
        cfg = await get_guild_cfg_async(guild.id)
        if guild.id == BOOST_GUILD_ID and member.premium_since is not None:
            asyncio.create_task(sync_boosters_to_site())
        rule = (cfg.get("antinuke") or {}).get("anti_kick") or {"enabled": True, "limit": 1}
        if not rule.get("enabled", True):
            return
        actor_id = await _find_audit_actor(guild, discord.AuditLogAction.kick, member.id)
        if actor_id and not is_trusted(guild, actor_id, cfg):
            if _record_and_check_limit(
                str(guild.id), actor_id, "anti_kick", int(rule.get("limit", 1) or 1)
            ):
                sess = await bot.get_http_session()
                await apply_antinuke_punishment(guild, actor_id, "anti_kick", cfg, sess)

    @bot.event
    async def on_guild_role_create(role: discord.Role) -> None:
        guild = role.guild
        cfg = await get_guild_cfg_async(guild.id)
        rule = (cfg.get("antinuke") or {}).get("anti_role_create") or {
            "enabled": True,
            "limit": 1,
        }
        if not rule.get("enabled", True):
            return
        actor_id = await _find_audit_actor(guild, discord.AuditLogAction.role_create, role.id)
        if actor_id and not is_trusted(guild, actor_id, cfg):
            if _record_and_check_limit(
                str(guild.id), actor_id, "anti_role_create", int(rule.get("limit", 1) or 1)
            ):
                try:
                    _IGNORE_DELETE_IDS.add(str(role.id))
                    await role.delete(reason="Arab Security: Anti Role Create")
                except discord.HTTPException:
                    pass
                sess = await bot.get_http_session()
                await apply_antinuke_punishment(guild, actor_id, "anti_role_create", cfg, sess)

    @bot.event
    async def on_guild_role_delete(role: discord.Role) -> None:
        guild = role.guild
        rid_str = str(role.id)
        if rid_str in _IGNORE_DELETE_IDS:
            _IGNORE_DELETE_IDS.discard(rid_str)
        else:
            r_serialized = _serialize_single_role(role)
            if r_serialized is not None:
                asyncio.create_task(
                    asyncio.to_thread(_record_deleted_item_sync, str(guild.id), "role", r_serialized)
                )

        cfg = await get_guild_cfg_async(guild.id)
        rule = (cfg.get("antinuke") or {}).get("anti_role_delete") or {
            "enabled": True,
            "limit": 1,
        }
        if not rule.get("enabled", True):
            return
        actor_id = await _find_audit_actor(guild, discord.AuditLogAction.role_delete, role.id)
        if actor_id and not is_trusted(guild, actor_id, cfg):
            if _record_and_check_limit(
                str(guild.id), actor_id, "anti_role_delete", int(rule.get("limit", 1) or 1)
            ):
                sess = await bot.get_http_session()
                await apply_antinuke_punishment(guild, actor_id, "anti_role_delete", cfg, sess)

    @bot.event
    async def on_guild_channel_create(channel: discord.abc.GuildChannel) -> None:
        guild = channel.guild
        cfg = await get_guild_cfg_async(guild.id)
        rule = (cfg.get("antinuke") or {}).get("anti_channel_create") or {
            "enabled": True,
            "limit": 2,
        }
        if not rule.get("enabled", True):
            return
        actor_id = await _find_audit_actor(
            guild, discord.AuditLogAction.channel_create, channel.id
        )
        if actor_id and not is_trusted(guild, actor_id, cfg):
            if _record_and_check_limit(
                str(guild.id), actor_id, "anti_channel_create", int(rule.get("limit", 2) or 2)
            ):
                try:
                    _IGNORE_DELETE_IDS.add(str(channel.id))
                    await channel.delete(reason="Arab Security: Anti Channel Create")
                except discord.HTTPException:
                    pass
                sess = await bot.get_http_session()
                await apply_antinuke_punishment(guild, actor_id, "anti_channel_create", cfg, sess)

    @bot.event
    async def on_guild_channel_delete(channel: discord.abc.GuildChannel) -> None:
        guild = channel.guild
        cid_str = str(channel.id)
        if cid_str in _IGNORE_DELETE_IDS:
            _IGNORE_DELETE_IDS.discard(cid_str)
        else:
            c_serialized = _serialize_single_channel(channel)
            if c_serialized is not None:
                asyncio.create_task(
                    asyncio.to_thread(
                        _record_deleted_item_sync, str(guild.id), "channel", c_serialized
                    )
                )

        cfg = await get_guild_cfg_async(guild.id)
        rule = (cfg.get("antinuke") or {}).get("anti_channel_delete") or {
            "enabled": True,
            "limit": 1,
        }
        if not rule.get("enabled", True):
            return
        actor_id = await _find_audit_actor(
            guild, discord.AuditLogAction.channel_delete, channel.id
        )
        if actor_id and not is_trusted(guild, actor_id, cfg):
            if _record_and_check_limit(
                str(guild.id), actor_id, "anti_channel_delete", int(rule.get("limit", 1) or 1)
            ):
                sess = await bot.get_http_session()
                await apply_antinuke_punishment(guild, actor_id, "anti_channel_delete", cfg, sess)

    @bot.event
    async def on_guild_update(before: discord.Guild, after: discord.Guild) -> None:
        cfg = await get_guild_cfg_async(after.id)
        sess = await bot.get_http_session()
        if cfg.get("anti_guild_icon_change") and before.icon != after.icon:
            actor_id = await _find_audit_actor(after, discord.AuditLogAction.guild_update, after.id)
            if actor_id and not is_trusted(after, actor_id, cfg):
                actor_member = after.get_member(actor_id)
                asyncio.create_task(
                    send_mod_log(
                        after,
                        cfg,
                        "Server Icon Changed",
                        actor_member,
                        f"Guild: `{after.name}` (`{after.id}`)",
                        "Server icon was modified",
                        color=discord.Color.blurple(),
                    )
                )
                asyncio.create_task(
                    send_security_log(
                        after,
                        cfg,
                        "Server Icon Changed",
                        f"Changed by <@{actor_id}> (`{actor_id}`).",
                        sess,
                    )
                )

        rule = (cfg.get("antinuke") or {}).get("anti_guild_update") or {
            "enabled": True,
            "limit": 1,
        }
        if rule.get("enabled", True) and before.name != after.name:
            actor_id = await _find_audit_actor(after, discord.AuditLogAction.guild_update, after.id)
            if actor_id and not is_trusted(after, actor_id, cfg):
                if _record_and_check_limit(
                    str(after.id), actor_id, "anti_guild_update", int(rule.get("limit", 1) or 1)
                ):
                    try:
                        await after.edit(name=before.name, reason="Arab Security: Anti Guild Update")
                    except discord.HTTPException:
                        pass
                    await apply_antinuke_punishment(after, actor_id, "anti_guild_update", cfg, sess)

    async def _do_kick(
        guild: discord.Guild, actor: discord.Member, target_raw: str, reason: str
    ) -> discord.Embed:
        cfg = await get_guild_cfg_async(guild.id)
        allowed, err = check_support_role_access(actor, cfg)
        if not allowed:
            return make_embed("Permission Denied", err, discord.Color.red(), guild=guild, bot=bot)

        member = await _resolve_member(guild, target_raw)
        if member is None:
            return make_embed(
                "User Not Found",
                "Could not find this member in the server.",
                discord.Color.red(),
                guild=guild,
                bot=bot,
            )
        if member.id == guild.owner_id or member.id == actor.id:
            return make_embed(
                "Action Blocked",
                "You cannot kick this user.",
                discord.Color.red(),
                guild=guild,
                bot=bot,
            )
        if guild.me and member.top_role >= guild.me.top_role:
            return make_embed(
                "Hierarchy Error",
                "My role must be higher than the target member's role.",
                discord.Color.red(),
                guild=guild,
                bot=bot,
            )

        try:
            await member.kick(reason=reason[:500])
            asyncio.create_task(
                send_mod_log(
                    guild,
                    cfg,
                    "Kick",
                    actor,
                    f"{member.mention} (`{member.id}`)",
                    reason,
                    duration_text="Instant",
                    color=discord.Color.red(),
                )
            )
            return make_embed(
                "Member Kicked",
                f"User: {member.mention} (`{member.id}`)\nBy: {actor.mention}\nReason: {reason[:300]}",
                guild=guild,
                bot=bot,
            )
        except discord.Forbidden:
            return make_embed(
                "Missing Bot Permissions",
                "I need the `Kick Members` permission.",
                discord.Color.red(),
                guild=guild,
                bot=bot,
            )
        except discord.HTTPException as e:
            return make_embed("Kick Failed", f"{e}", discord.Color.red(), guild=guild, bot=bot)

    async def _do_ban(
        guild: discord.Guild, actor: discord.Member, target_raw: str, reason: str
    ) -> discord.Embed:
        cfg = await get_guild_cfg_async(guild.id)
        allowed, err = check_support_role_access(actor, cfg)
        if not allowed:
            return make_embed("Permission Denied", err, discord.Color.red(), guild=guild, bot=bot)

        uid = _extract_user_id(target_raw)
        if uid is None:
            return make_embed(
                "Invalid User",
                "Please mention a user or enter a valid numeric User ID.",
                discord.Color.red(),
                guild=guild,
                bot=bot,
            )
        if uid == guild.owner_id or uid == actor.id:
            return make_embed(
                "Action Blocked",
                "You cannot ban this user.",
                discord.Color.red(),
                guild=guild,
                bot=bot,
            )

        member = guild.get_member(uid)
        if member and guild.me and member.top_role >= guild.me.top_role:
            return make_embed(
                "Hierarchy Error",
                "My role must be higher than the target member's role.",
                discord.Color.red(),
                guild=guild,
                bot=bot,
            )

        try:
            await guild.ban(discord.Object(id=uid), reason=reason[:500], delete_message_seconds=0)
            asyncio.create_task(
                send_mod_log(
                    guild,
                    cfg,
                    "Ban",
                    actor,
                    f"<@{uid}> (`{uid}`)",
                    reason,
                    duration_text="Permanent",
                    color=discord.Color.dark_red(),
                )
            )
            return make_embed(
                "Member Banned",
                f"User: <@{uid}> (`{uid}`)\nBy: {actor.mention}\nReason: {reason[:300]}",
                guild=guild,
                bot=bot,
            )
        except discord.Forbidden:
            return make_embed(
                "Missing Bot Permissions",
                "I need the `Ban Members` permission.",
                discord.Color.red(),
                guild=guild,
                bot=bot,
            )
        except discord.HTTPException as e:
            return make_embed("Ban Failed", f"{e}", discord.Color.red(), guild=guild, bot=bot)

    async def _do_unban(
        guild: discord.Guild, actor: discord.Member, target_raw: str, reason: str
    ) -> discord.Embed:
        cfg = await get_guild_cfg_async(guild.id)
        allowed, err = check_support_role_access(actor, cfg)
        if not allowed:
            return make_embed("Permission Denied", err, discord.Color.red(), guild=guild, bot=bot)

        uid = _extract_user_id(target_raw)
        if uid is None:
            return make_embed(
                "Invalid User ID",
                "Please provide a valid numeric User ID.",
                discord.Color.red(),
                guild=guild,
                bot=bot,
            )

        try:
            await guild.unban(discord.Object(id=uid), reason=reason[:500])
            asyncio.create_task(
                send_mod_log(
                    guild,
                    cfg,
                    "Unban",
                    actor,
                    f"<@{uid}> (`{uid}`)",
                    reason,
                    duration_text="Removed",
                    color=discord.Color.green(),
                )
            )
            return make_embed(
                "User Unbanned",
                f"User: <@{uid}> (`{uid}`)\nBy: {actor.mention}\nReason: {reason[:300]}",
                guild=guild,
                bot=bot,
            )
        except discord.NotFound:
            return make_embed(
                "Not Banned",
                "This user is not currently banned.",
                discord.Color.red(),
                guild=guild,
                bot=bot,
            )
        except discord.Forbidden:
            return make_embed(
                "Missing Bot Permissions",
                "I need the `Ban Members` permission.",
                discord.Color.red(),
                guild=guild,
                bot=bot,
            )
        except discord.HTTPException as e:
            return make_embed("Unban Failed", f"{e}", discord.Color.red(), guild=guild, bot=bot)

    async def _do_timeout(
        guild: discord.Guild,
        actor: discord.Member,
        target_raw: str,
        duration: str,
        reason: str,
    ) -> discord.Embed:
        cfg = await get_guild_cfg_async(guild.id)
        allowed, err = check_support_role_access(actor, cfg)
        if not allowed:
            return make_embed("Permission Denied", err, discord.Color.red(), guild=guild, bot=bot)

        member = await _resolve_member(guild, target_raw)
        if member is None:
            return make_embed(
                "User Not Found",
                "Could not find this member in the server.",
                discord.Color.red(),
                guild=guild,
                bot=bot,
            )
        if member.id == guild.owner_id or member.id == actor.id:
            return make_embed(
                "Action Blocked",
                "You cannot timeout this user.",
                discord.Color.red(),
                guild=guild,
                bot=bot,
            )
        if guild.me and member.top_role >= guild.me.top_role:
            return make_embed(
                "Hierarchy Error",
                "My role must be higher than the target member's role.",
                discord.Color.red(),
                guild=guild,
                bot=bot,
            )

        secs = _parse_duration_seconds(duration)
        if secs is None:
            return make_embed(
                "Invalid Duration",
                "Use formats like `10m`, `1h`, `1d`, or seconds like `600`.",
                discord.Color.red(),
                guild=guild,
                bot=bot,
            )

        dur_lbl = _format_duration_label(secs)
        until = datetime.now(timezone.utc) + timedelta(seconds=secs)
        try:
            await member.timeout(until, reason=reason[:500])
            asyncio.create_task(
                send_mod_log(
                    guild,
                    cfg,
                    "Timeout",
                    actor,
                    f"{member.mention} (`{member.id}`)",
                    reason,
                    duration_text=dur_lbl,
                    color=discord.Color.gold(),
                )
            )
            return make_embed(
                "Member Timed Out",
                f"User: {member.mention} (`{member.id}`)\nDuration: `{dur_lbl}`\nBy: {actor.mention}\nReason: {reason[:300]}",
                guild=guild,
                bot=bot,
            )
        except discord.Forbidden:
            return make_embed(
                "Missing Bot Permissions",
                "I need the `Moderate Members` permission.",
                discord.Color.red(),
                guild=guild,
                bot=bot,
            )
        except discord.HTTPException as e:
            return make_embed("Timeout Failed", f"{e}", discord.Color.red(), guild=guild, bot=bot)

    async def _do_untimeout(
        guild: discord.Guild, actor: discord.Member, target_raw: str, reason: str
    ) -> discord.Embed:
        cfg = await get_guild_cfg_async(guild.id)
        allowed, err = check_support_role_access(actor, cfg)
        if not allowed:
            return make_embed("Permission Denied", err, discord.Color.red(), guild=guild, bot=bot)

        member = await _resolve_member(guild, target_raw)
        if member is None:
            return make_embed(
                "User Not Found",
                "Could not find this member in the server.",
                discord.Color.red(),
                guild=guild,
                bot=bot,
            )

        try:
            await member.timeout(None, reason=reason[:500])
            asyncio.create_task(
                send_mod_log(
                    guild,
                    cfg,
                    "Untimeout",
                    actor,
                    f"{member.mention} (`{member.id}`)",
                    reason,
                    duration_text="Removed",
                    color=discord.Color.green(),
                )
            )
            return make_embed(
                "Timeout Removed",
                f"User: {member.mention} (`{member.id}`)\nBy: {actor.mention}\nReason: {reason[:300]}",
                guild=guild,
                bot=bot,
            )
        except discord.Forbidden:
            return make_embed(
                "Missing Bot Permissions",
                "I need the `Moderate Members` permission.",
                discord.Color.red(),
                guild=guild,
                bot=bot,
            )
        except discord.HTTPException as e:
            return make_embed(
                "Untimeout Failed", f"{e}", discord.Color.red(), guild=guild, bot=bot
            )

    def _build_checkprem_embed(guild: discord.Guild, user_id: int) -> discord.Embed:
        gid = str(guild.id)
        uid = str(user_id)
        pcol = (
            premium_users_col
            if premium_users_col is not None
            else (_db["premium_users"] if _db is not None else None)
        )
        gdoc_found = False
        udoc_found = False
        if pcol is not None:
            try:
                gdoc_found = isinstance(pcol.find_one({"guild_id": gid}, {"_id": 1}), dict)
                udoc_found = isinstance(
                    pcol.find_one(
                        {"$or": [{"user_id": uid}, {"_id": uid}, {"id": uid}]}, {"_id": 1}
                    ),
                    dict,
                )
            except PyMongoError:
                pass
        active = is_guild_premium(bot, guild, user_id)
        return make_embed(
            "Premium Diagnostic",
            f"**Guild ID:** `{gid}`\n"
            f"**User ID:** `{uid}`\n"
            f"**Guild Doc in `premium_users`:** `{'Yes' if gdoc_found else 'No'}`\n"
            f"**User Doc in `premium_users`:** `{'Yes' if udoc_found else 'No'}`\n"
            f"**Effective Status:** `{'Active' if active else 'Inactive'}`",
            discord.Color.green() if active else discord.Color.orange(),
            guild=guild,
            bot=bot,
        )

    @bot.command(name="checkprem")
    async def checkprem_cmd(ctx: commands.Context) -> None:
        if not ctx.guild:
            return
        emb = await asyncio.to_thread(_build_checkprem_embed, ctx.guild, ctx.author.id)
        await ctx.send(embed=emb)

    @bot.tree.command(
        name="checkprem", description="Inspect Premium status for this guild and your user ID"
    )
    async def slash_checkprem(interaction: discord.Interaction) -> None:
        if not interaction.guild:
            return
        await interaction.response.defer(ephemeral=True)
        emb = await asyncio.to_thread(_build_checkprem_embed, interaction.guild, interaction.user.id)
        await interaction.followup.send(embed=emb, ephemeral=True)

    @bot.command(name="save", aliases=["backup"])
    @commands.has_permissions(administrator=True)
    async def save_prefix_cmd(ctx: commands.Context) -> None:
        if not ctx.guild:
            return
        if not await is_guild_premium_async(bot, ctx.guild, ctx.author.id):
            await ctx.send(
                embed=make_embed(
                    "Premium مطلوب",
                    "حفظ النسخ الاحتياطية متاح فقط لمشتركي **Premium**.",
                    discord.Color.red(),
                    guild=ctx.guild,
                    bot=bot,
                )
            )
            return
        snap, orig_b, comp_b = await get_or_create_snapshot(ctx.guild, refresh=True)
        ratio = round((comp_b / orig_b) * 100, 1) if orig_b > 0 else 100.0
        await ctx.send(
            embed=make_embed(
                "تم الحفظ الدائم للنسخة",
                f"تم حفظ نسخة السيرفر بشكل **دائم** في قاعدة البيانات (لا تُحذف كل 12 ساعة).\n"
                f"• **الرتب المحفوظة:** `{len((snap or {}).get('roles') or [])}` (رتب الأدمن مستثناة)\n"
                f"• **الرومات المحفوظة:** `{len((snap or {}).get('channels') or [])}` (رومات التكتات مستثناة)\n"
                f"• **الحجم المضغوط:** `{comp_b}` بايت من `{orig_b}` بايت (`{ratio}%`)",
                discord.Color.green(),
                guild=ctx.guild,
                bot=bot,
            )
        )

    @bot.tree.command(
        name="save",
        description="حفظ نسخة دائمة ومضغوطة للسيرفر (لا تُحذف تلقائياً)",
    )
    async def save_slash_cmd(interaction: discord.Interaction) -> None:
        if (
            not interaction.guild
            or not isinstance(interaction.user, discord.Member)
            or not interaction.user.guild_permissions.administrator
        ):
            await interaction.response.send_message(
                embed=make_embed(
                    "صلاحية مطلوبة",
                    "هذا الأمر متاح للأدمن فقط (`Administrator`).",
                    discord.Color.red(),
                    guild=interaction.guild,
                    bot=bot,
                ),
                ephemeral=True,
            )
            return
        await interaction.response.defer(thinking=True)
        if not await is_guild_premium_async(bot, interaction.guild, interaction.user.id):
            await interaction.followup.send(
                embed=make_embed(
                    "Premium مطلوب",
                    "حفظ النسخ الاحتياطية متاح فقط لمشتركي **Premium**.",
                    discord.Color.red(),
                    guild=interaction.guild,
                    bot=bot,
                ),
                ephemeral=True,
            )
            return
        snap, orig_b, comp_b = await get_or_create_snapshot(interaction.guild, refresh=True)
        ratio = round((comp_b / orig_b) * 100, 1) if orig_b > 0 else 100.0
        await interaction.followup.send(
            embed=make_embed(
                "تم الحفظ الدائم للنسخة",
                f"تم حفظ نسخة السيرفر بشكل **دائم** في قاعدة البيانات (لا تُحذف كل 12 ساعة).\n"
                f"• **الرتب المحفوظة:** `{len((snap or {}).get('roles') or [])}` (رتب الأدمن مستثناة)\n"
                f"• **الرومات المحفوظة:** `{len((snap or {}).get('channels') or [])}` (رومات التكتات مستثناة)\n"
                f"• **الحجم المضغوط:** `{comp_b}` بايت من `{orig_b}` بايت (`{ratio}%`)",
                discord.Color.green(),
                guild=interaction.guild,
                bot=bot,
            )
        )

    @bot.command(name="recovery")
    @commands.has_permissions(administrator=True)
    async def recovery_prefix_cmd(ctx: commands.Context) -> None:
        if not ctx.guild:
            return
        if not await is_guild_premium_async(bot, ctx.guild, ctx.author.id):
            await ctx.send(
                embed=make_embed(
                    "Premium مطلوب",
                    "استرجاع وحفظ النسخ الاحتياطية متاح فقط لمشتركي **Premium**.",
                    discord.Color.red(),
                    guild=ctx.guild,
                    bot=bot,
                )
            )
            return
        emb, view = await build_recovery_message_payload(ctx.guild, ctx.author.id)
        if view is not None:
            await ctx.send(embed=emb, view=view)
        else:
            await ctx.send(embed=emb)

    @bot.tree.command(
        name="recovery",
        description="استرجاع الرومات والرتب المحذوفة (للمشرفين أصحاب Premium فقط)",
    )
    async def recovery_slash_cmd(interaction: discord.Interaction) -> None:
        if (
            not interaction.guild
            or not isinstance(interaction.user, discord.Member)
            or not interaction.user.guild_permissions.administrator
        ):
            await interaction.response.send_message(
                embed=make_embed(
                    "صلاحية مطلوبة",
                    "هذا الأمر متاح للأدمن فقط (`Administrator`).",
                    discord.Color.red(),
                    guild=interaction.guild,
                    bot=bot,
                ),
                ephemeral=True,
            )
            return
        await interaction.response.defer(thinking=True)
        if not await is_guild_premium_async(bot, interaction.guild, interaction.user.id):
            await interaction.followup.send(
                embed=make_embed(
                    "Premium مطلوب",
                    "استرجاع وحفظ النسخ الاحتياطية متاح فقط لمشتركي **Premium**.",
                    discord.Color.red(),
                    guild=interaction.guild,
                    bot=bot,
                ),
                ephemeral=True,
            )
            return
        emb, view = await build_recovery_message_payload(interaction.guild, interaction.user.id)
        if view is not None:
            await interaction.followup.send(embed=emb, view=view)
        else:
            await interaction.followup.send(embed=emb)

    @bot.command(name="help")
    async def help_cmd(ctx: commands.Context) -> None:
        cfg = await get_guild_cfg_async(ctx.guild.id) if ctx.guild else _default_cfg()
        p = str(cfg.get("prefix") or "!")
        srole = str(cfg.get("support_role_id") or "")
        log_ch = str(cfg.get("mod_log_channel") or "")
        await ctx.send(embed=build_help_embed(p, srole, log_ch, guild=ctx.guild, bot=bot))

    @bot.command(name="profile")
    async def profile_cmd(ctx: commands.Context) -> None:
        if not ctx.guild:
            return
        prof = await get_guild_profile(_db, ctx.guild.id, force_refresh=True) or _empty_profile(
            ctx.guild.id
        )
        cfg = await get_guild_cfg_async(ctx.guild.id)
        prem_active = await is_guild_premium_async(bot, ctx.guild, ctx.author.id)
        ava_val = str(prof.get("avatar_url") or "")
        ban_val = str(prof.get("banner_url") or "")
        ava_disp = (
            "Uploaded Image (Data URL)"
            if ava_val.startswith("data:image/")
            else (ava_val or "Default")
        )
        ban_disp = (
            "Uploaded Image (Data URL)"
            if ban_val.startswith("data:image/")
            else (ban_val or "Default")
        )
        await ctx.send(
            embed=make_embed(
                "Saved Guild Profile",
                f"**Guild ID:** `{ctx.guild.id}`\n"
                f"**Scope:** `Guild Only`\n"
                f"**Premium:** `{'Active' if prem_active else 'Inactive'}`\n"
                f"**Guild Nick:** `{cfg.get('guild_status_text') or cfg.get('guild_status') or 'Default'}`\n"
                f"**Avatar:** `{ava_disp}`\n"
                f"**Banner:** `{ban_disp}`\n"
                f"**Bio:** `{prof.get('bio') or 'Default'}`\n"
                f"**Management:** Website Dashboard Only",
                guild=ctx.guild,
                bot=bot,
            )
        )

    @bot.command(name="setmodrole")
    @commands.has_permissions(administrator=True)
    async def setmodrole_cmd(ctx: commands.Context, role: discord.Role) -> None:
        if not ctx.guild:
            return
        cfg = await get_guild_cfg_async(ctx.guild.id)
        save_guild_fields(ctx.guild.id, {"support_role_id": str(role.id)})
        if isinstance(ctx.author, discord.Member):
            asyncio.create_task(
                send_mod_log(
                    ctx.guild,
                    cfg,
                    "Set Support Role",
                    ctx.author,
                    f"{role.mention} (`{role.id}`)",
                    "Updated support role",
                    color=discord.Color.blurple(),
                )
            )
        await ctx.send(
            embed=make_embed(
                "Support Role Updated",
                f"Support role set to {role.mention} (`{role.id}`).\nOnly members with this role can run moderation commands.",
                guild=ctx.guild,
                bot=bot,
            )
        )

    @bot.command(name="setlog")
    @commands.has_permissions(administrator=True)
    async def setlog_cmd(ctx: commands.Context, channel: discord.TextChannel) -> None:
        if not ctx.guild:
            return
        save_guild_fields(ctx.guild.id, {"mod_log_channel": str(channel.id)})
        cfg = await get_guild_cfg_async(ctx.guild.id)
        if isinstance(ctx.author, discord.Member):
            asyncio.create_task(
                send_mod_log(
                    ctx.guild,
                    cfg,
                    "Set Log Channel",
                    ctx.author,
                    f"{channel.mention} (`{channel.id}`)",
                    "Comprehensive log channel configured by Administrator",
                    color=discord.Color.blurple(),
                )
            )
        await ctx.send(
            embed=make_embed(
                "Logs Channel Updated",
                f"All bot, security & moderation logs will be sent to {channel.mention} (`{channel.id}`).",
                guild=ctx.guild,
                bot=bot,
            )
        )

    @bot.command(name="autoline")
    @commands.has_permissions(manage_channels=True)
    async def autoline_cmd(
        ctx: commands.Context, channel: discord.TextChannel, line_url: str
    ) -> None:
        if not ctx.guild:
            return
        clean_url = line_url.strip()
        ok_u, _ = await asyncio.to_thread(validate_media_url, clean_url)
        if not ok_u:
            await ctx.send(
                embed=make_embed(
                    "Invalid URL",
                    "Please provide a valid `http://` or `https://` line URL.",
                    discord.Color.red(),
                    guild=ctx.guild,
                    bot=bot,
                )
            )
            return
        cfg = await get_guild_cfg_async(ctx.guild.id)
        auto_lines = dict(cfg.get("auto_lines") or {})
        auto_lines[str(channel.id)] = clean_url
        save_guild_fields(ctx.guild.id, {"auto_lines": auto_lines})
        if isinstance(ctx.author, discord.Member):
            asyncio.create_task(
                send_mod_log(
                    ctx.guild,
                    cfg,
                    "Auto Line Enabled",
                    ctx.author,
                    f"{channel.mention} (`{channel.id}`)",
                    clean_url,
                    color=discord.Color.green(),
                )
            )
        await ctx.send(
            embed=make_embed(
                "Auto Line Enabled",
                f"Channel: {channel.mention}\nLine URL: {clean_url}",
                guild=ctx.guild,
                bot=bot,
            )
        )

    @bot.command(name="autolineoff")
    @commands.has_permissions(manage_channels=True)
    async def autolineoff_cmd(ctx: commands.Context, channel: discord.TextChannel) -> None:
        if not ctx.guild:
            return
        cfg = await get_guild_cfg_async(ctx.guild.id)
        auto_lines = dict(cfg.get("auto_lines") or {})
        auto_lines.pop(str(channel.id), None)
        save_guild_fields(ctx.guild.id, {"auto_lines": auto_lines})
        if isinstance(ctx.author, discord.Member):
            asyncio.create_task(
                send_mod_log(
                    ctx.guild,
                    cfg,
                    "Auto Line Disabled",
                    ctx.author,
                    f"{channel.mention} (`{channel.id}`)",
                    "Auto line removed",
                    color=discord.Color.orange(),
                )
            )
        await ctx.send(
            embed=make_embed(
                "Auto Line Disabled",
                f"Auto line removed from {channel.mention}.",
                guild=ctx.guild,
                bot=bot,
            )
        )

    @bot.command(name="kick")
    async def kick_cmd(
        ctx: commands.Context, target: str, *, reason: str = "No reason provided"
    ) -> None:
        if not ctx.guild or not isinstance(ctx.author, discord.Member):
            return
        emb = await _do_kick(ctx.guild, ctx.author, target, reason)
        await ctx.send(embed=emb)

    @bot.command(name="ban")
    async def ban_cmd(
        ctx: commands.Context, target: str, *, reason: str = "No reason provided"
    ) -> None:
        if not ctx.guild or not isinstance(ctx.author, discord.Member):
            return
        emb = await _do_ban(ctx.guild, ctx.author, target, reason)
        await ctx.send(embed=emb)

    @bot.command(name="unban")
    async def unban_cmd(
        ctx: commands.Context, target: str, *, reason: str = "No reason provided"
    ) -> None:
        if not ctx.guild or not isinstance(ctx.author, discord.Member):
            return
        emb = await _do_unban(ctx.guild, ctx.author, target, reason)
        await ctx.send(embed=emb)

    @bot.command(name="timeout")
    async def timeout_cmd(
        ctx: commands.Context,
        target: str,
        duration: str = "10m",
        *,
        reason: str = "No reason provided",
    ) -> None:
        if not ctx.guild or not isinstance(ctx.author, discord.Member):
            return
        if _parse_duration_seconds(duration) is None:
            reason = f"{duration} {reason}".strip() if reason != "No reason provided" else duration
            duration = "10m"
        emb = await _do_timeout(ctx.guild, ctx.author, target, duration, reason)
        await ctx.send(embed=emb)

    @bot.command(name="untimeout")
    async def untimeout_cmd(
        ctx: commands.Context, target: str, *, reason: str = "No reason provided"
    ) -> None:
        if not ctx.guild or not isinstance(ctx.author, discord.Member):
            return
        emb = await _do_untimeout(ctx.guild, ctx.author, target, reason)
        await ctx.send(embed=emb)

    @bot.command(name="stats", aliases=["احصائيات"])
    async def stats_cmd(ctx: commands.Context) -> None:
        if not is_stats_authorized(ctx.author.id):
            return
        await ctx.send(embed=await build_stats_embed(bot, guild=ctx.guild))

    @bot.command(name="servers")
    async def servers_cmd(ctx: commands.Context) -> None:
        synced = await sync_guilds_to_site("manual_servers_cmd")
        total_members = sum(int(g.member_count or 0) for g in bot.guilds)
        sync_msg = "Synced with website" if synced else "Local bot count"
        await ctx.send(
            embed=make_embed(
                "Connected Servers",
                f"**Connected Servers:** `{len(bot.guilds)}`\n"
                f"**Total Members:** `{total_members}`\n"
                f"**Sync Status:** `{sync_msg}`",
                guild=ctx.guild,
                bot=bot,
            )
        )

    @bot.command(name="ping")
    async def ping_cmd(ctx: commands.Context) -> None:
        if not is_restricted_owner(ctx.author.id):
            return
        gw_ms = max(1, int(round((bot.latency or 0.0) * 1000)))
        await ctx.send(
            embed=make_embed(
                "Pong",
                f"Gateway: `{gw_ms}ms` | Guilds: `{len(bot.guilds)}`",
                guild=ctx.guild,
                bot=bot,
            )
        )

    @bot.command(name="sync")
    @commands.has_permissions(administrator=True)
    async def sync_cmd(ctx: commands.Context) -> None:
        if ctx.guild:
            _CFG_CACHE.pop(str(ctx.guild.id), None)
            _PROFILE_CACHE.pop(str(ctx.guild.id), None)
            cfg = await get_guild_cfg_async(ctx.guild.id)
            prof = await get_guild_profile(_db, ctx.guild.id, force_refresh=True)
            if isinstance(prof, dict):
                await _apply_guild_only_bio(ctx.guild, prof.get("bio", ""))
            if str(cfg.get("guild_status_text") or "").strip():
                await _apply_guild_only_status_nick(ctx.guild, str(cfg.get("guild_status_text") or ""))
            await fetch_guild_profile_from_web(bot, ctx.guild.id)
        asyncio.create_task(sync_guilds_to_site("manual_sync"))
        asyncio.create_task(sync_boosters_to_site())
        await ctx.send(
            embed=make_embed(
                "Synced",
                "Server settings synced with panel (guild scope only).",
                guild=ctx.guild,
                bot=bot,
            )
        )

    @bot.tree.command(name="help", description="Show available commands")
    async def slash_help(interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)
        cfg = (
            await get_guild_cfg_async(interaction.guild.id)
            if interaction.guild
            else _default_cfg()
        )
        p = str(cfg.get("prefix") or "!")
        srole = str(cfg.get("support_role_id") or "")
        log_ch = str(cfg.get("mod_log_channel") or "")
        await interaction.followup.send(
            embed=build_help_embed(p, srole, log_ch, guild=interaction.guild, bot=bot),
            ephemeral=True,
        )

    @bot.tree.command(name="profile", description="View saved guild profile settings")
    async def slash_profile(interaction: discord.Interaction) -> None:
        if not interaction.guild:
            return
        await interaction.response.defer(ephemeral=True)
        prof = await get_guild_profile(
            _db, interaction.guild.id, force_refresh=True
        ) or _empty_profile(interaction.guild.id)
        cfg = await get_guild_cfg_async(interaction.guild.id)
        prem_active = await is_guild_premium_async(bot, interaction.guild, interaction.user.id)
        ava_val = str(prof.get("avatar_url") or "")
        ban_val = str(prof.get("banner_url") or "")
        ava_disp = (
            "Uploaded Image (Data URL)"
            if ava_val.startswith("data:image/")
            else (ava_val or "Default")
        )
        ban_disp = (
            "Uploaded Image (Data URL)"
            if ban_val.startswith("data:image/")
            else (ban_val or "Default")
        )
        await interaction.followup.send(
            embed=make_embed(
                "Saved Guild Profile",
                f"**Guild ID:** `{interaction.guild.id}`\n"
                f"**Scope:** `Guild Only`\n"
                f"**Premium:** `{'Active' if prem_active else 'Inactive'}`\n"
                f"**Guild Nick:** `{cfg.get('guild_status_text') or cfg.get('guild_status') or 'Default'}`\n"
                f"**Avatar:** `{ava_disp}`\n"
                f"**Banner:** `{ban_disp}`\n"
                f"**Bio:** `{prof.get('bio') or 'Default'}`\n"
                f"**Management:** Website Dashboard Only",
                guild=interaction.guild,
                bot=bot,
            ),
            ephemeral=True,
        )

    @bot.tree.command(
        name="servers", description="Show connected servers count and sync with panel"
    )
    async def slash_servers(interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)
        synced = await sync_guilds_to_site("manual_slash_servers")
        total_members = sum(int(g.member_count or 0) for g in bot.guilds)
        sync_msg = "Synced with website" if synced else "Local bot count"
        await interaction.followup.send(
            embed=make_embed(
                "Connected Servers",
                f"**Connected Servers:** `{len(bot.guilds)}`\n"
                f"**Total Members:** `{total_members}`\n"
                f"**Sync Status:** `{sync_msg}`",
                guild=interaction.guild,
                bot=bot,
            ),
            ephemeral=True,
        )

    @bot.tree.command(name="ping", description="Check bot latency")
    async def slash_ping(interaction: discord.Interaction) -> None:
        if not is_restricted_owner(interaction.user.id):
            await interaction.response.send_message(
                embed=make_embed(
                    "Permission Denied",
                    "Restricted command.",
                    discord.Color.red(),
                    guild=interaction.guild,
                    bot=bot,
                ),
                ephemeral=True,
            )
            return
        gw_ms = max(1, int(round((bot.latency or 0.0) * 1000)))
        await interaction.response.send_message(
            embed=make_embed(
                "Pong",
                f"Gateway: `{gw_ms}ms` | Guilds: `{len(bot.guilds)}`",
                guild=interaction.guild,
                bot=bot,
            ),
            ephemeral=True,
        )

    @bot.tree.command(name="sync", description="Sync server settings with panel")
    async def slash_sync(interaction: discord.Interaction) -> None:
        if (
            not interaction.guild
            or not isinstance(interaction.user, discord.Member)
            or not interaction.user.guild_permissions.administrator
        ):
            await interaction.response.send_message(
                embed=make_embed(
                    "Permission Denied",
                    "Administrator permission required.",
                    discord.Color.red(),
                    guild=interaction.guild,
                    bot=bot,
                ),
                ephemeral=True,
            )
            return
        await interaction.response.defer(ephemeral=True)
        _CFG_CACHE.pop(str(interaction.guild.id), None)
        _PROFILE_CACHE.pop(str(interaction.guild.id), None)
        cfg = await get_guild_cfg_async(interaction.guild.id)
        prof = await get_guild_profile(_db, interaction.guild.id, force_refresh=True)
        if isinstance(prof, dict):
            await _apply_guild_only_bio(interaction.guild, prof.get("bio", ""))
        if str(cfg.get("guild_status_text") or "").strip():
            await _apply_guild_only_status_nick(
                interaction.guild, str(cfg.get("guild_status_text") or "")
            )
        await fetch_guild_profile_from_web(bot, interaction.guild.id)
        asyncio.create_task(sync_guilds_to_site("manual_sync"))
        asyncio.create_task(sync_boosters_to_site())
        await interaction.followup.send(
            embed=make_embed(
                "Synced",
                "Server settings synced with panel (guild scope only).",
                guild=interaction.guild,
                bot=bot,
            ),
            ephemeral=True,
        )

    @bot.tree.command(
        name="setmodrole", description="Set support role allowed to use moderation commands"
    )
    @app_commands.describe(role="Support role")
    async def slash_setmodrole(
        interaction: discord.Interaction, role: discord.Role
    ) -> None:
        if (
            not interaction.guild
            or not isinstance(interaction.user, discord.Member)
            or not interaction.user.guild_permissions.administrator
        ):
            await interaction.response.send_message(
                embed=make_embed(
                    "Permission Denied",
                    "Administrator permission required.",
                    discord.Color.red(),
                    guild=interaction.guild,
                    bot=bot,
                ),
                ephemeral=True,
            )
            return
        save_guild_fields(interaction.guild.id, {"support_role_id": str(role.id)})
        await interaction.response.send_message(
            embed=make_embed(
                "Support Role Updated",
                f"Support role set to {role.mention} (`{role.id}`).",
                guild=interaction.guild,
                bot=bot,
            ),
            ephemeral=True,
        )

    @bot.tree.command(
        name="setlog", description="Set moderation and security logs channel (Administrator only)"
    )
    @app_commands.describe(channel="Logs channel")
    async def slash_setlog(
        interaction: discord.Interaction, channel: discord.TextChannel
    ) -> None:
        if (
            not interaction.guild
            or not isinstance(interaction.user, discord.Member)
            or not interaction.user.guild_permissions.administrator
        ):
            await interaction.response.send_message(
                embed=make_embed(
                    "Permission Denied",
                    "Administrator permission required.",
                    discord.Color.red(),
                    guild=interaction.guild,
                    bot=bot,
                ),
                ephemeral=True,
            )
            return
        save_guild_fields(interaction.guild.id, {"mod_log_channel": str(channel.id)})
        await interaction.response.send_message(
            embed=make_embed(
                "Logs Channel Updated",
                f"Logs channel set to {channel.mention} (`{channel.id}`).",
                guild=interaction.guild,
                bot=bot,
            ),
            ephemeral=True,
        )

    @bot.tree.command(name="autoline", description="Enable auto line in a channel")
    @app_commands.describe(channel="Target channel", line_url="Line image/link URL")
    async def slash_autoline(
        interaction: discord.Interaction, channel: discord.TextChannel, line_url: str
    ) -> None:
        if (
            not interaction.guild
            or not isinstance(interaction.user, discord.Member)
            or not interaction.user.guild_permissions.manage_channels
        ):
            await interaction.response.send_message(
                embed=make_embed(
                    "Permission Denied",
                    "Manage Channels permission required.",
                    discord.Color.red(),
                    guild=interaction.guild,
                    bot=bot,
                ),
                ephemeral=True,
            )
            return
        await interaction.response.defer(ephemeral=True)
        clean_url = line_url.strip()
        ok_u, _ = await asyncio.to_thread(validate_media_url, clean_url)
        if not ok_u:
            await interaction.followup.send(
                embed=make_embed(
                    "Invalid URL",
                    "Please provide a valid `http://` or `https://` line URL.",
                    discord.Color.red(),
                    guild=interaction.guild,
                    bot=bot,
                ),
                ephemeral=True,
            )
            return
        cfg = await get_guild_cfg_async(interaction.guild.id)
        auto_lines = dict(cfg.get("auto_lines") or {})
        auto_lines[str(channel.id)] = clean_url
        save_guild_fields(interaction.guild.id, {"auto_lines": auto_lines})
        await interaction.followup.send(
            embed=make_embed(
                "Auto Line Enabled",
                f"Channel: {channel.mention}\nLine URL: {clean_url}",
                guild=interaction.guild,
                bot=bot,
            ),
            ephemeral=True,
        )

    @bot.tree.command(name="autolineoff", description="Disable auto line in a channel")
    @app_commands.describe(channel="Target channel")
    async def slash_autolineoff(
        interaction: discord.Interaction, channel: discord.TextChannel
    ) -> None:
        if (
            not interaction.guild
            or not isinstance(interaction.user, discord.Member)
            or not interaction.user.guild_permissions.manage_channels
        ):
            await interaction.response.send_message(
                embed=make_embed(
                    "Permission Denied",
                    "Manage Channels permission required.",
                    discord.Color.red(),
                    guild=interaction.guild,
                    bot=bot,
                ),
                ephemeral=True,
            )
            return
        await interaction.response.defer(ephemeral=True)
        cfg = await get_guild_cfg_async(interaction.guild.id)
        auto_lines = dict(cfg.get("auto_lines") or {})
        auto_lines.pop(str(channel.id), None)
        save_guild_fields(interaction.guild.id, {"auto_lines": auto_lines})
        await interaction.followup.send(
            embed=make_embed(
                "Auto Line Disabled",
                f"Auto line removed from {channel.mention}.",
                guild=interaction.guild,
                bot=bot,
            ),
            ephemeral=True,
        )

    @bot.tree.command(name="kick", description="Kick a member (Support Role only)")
    @app_commands.describe(user="Member mention or User ID", reason="Reason")
    async def slash_kick(
        interaction: discord.Interaction, user: str, reason: str = "No reason provided"
    ) -> None:
        if not interaction.guild or not isinstance(interaction.user, discord.Member):
            return
        await interaction.response.defer(thinking=True)
        emb = await _do_kick(interaction.guild, interaction.user, user, reason)
        await interaction.followup.send(embed=emb)

    @bot.tree.command(name="ban", description="Ban a user (Support Role only)")
    @app_commands.describe(user="Member mention or User ID", reason="Reason")
    async def slash_ban(
        interaction: discord.Interaction, user: str, reason: str = "No reason provided"
    ) -> None:
        if not interaction.guild or not isinstance(interaction.user, discord.Member):
            return
        await interaction.response.defer(thinking=True)
        emb = await _do_ban(interaction.guild, interaction.user, user, reason)
        await interaction.followup.send(embed=emb)

    @bot.tree.command(name="unban", description="Unban a user by ID (Support Role only)")
    @app_commands.describe(user_id="User ID", reason="Reason")
    async def slash_unban(
        interaction: discord.Interaction, user_id: str, reason: str = "No reason provided"
    ) -> None:
        if not interaction.guild or not isinstance(interaction.user, discord.Member):
            return
        await interaction.response.defer(thinking=True)
        emb = await _do_unban(interaction.guild, interaction.user, user_id, reason)
        await interaction.followup.send(embed=emb)

    @bot.tree.command(name="timeout", description="Timeout a member (Support Role only)")
    @app_commands.describe(
        user="Member mention or User ID", duration="Duration e.g. 10m, 1h, 600", reason="Reason"
    )
    async def slash_timeout(
        interaction: discord.Interaction,
        user: str,
        duration: str = "10m",
        reason: str = "No reason provided",
    ) -> None:
        if not interaction.guild or not isinstance(interaction.user, discord.Member):
            return
        await interaction.response.defer(thinking=True)
        emb = await _do_timeout(interaction.guild, interaction.user, user, duration, reason)
        await interaction.followup.send(embed=emb)

    @bot.tree.command(name="untimeout", description="Remove timeout from a member (Support Role only)")
    @app_commands.describe(user="Member mention or User ID", reason="Reason")
    async def slash_untimeout(
        interaction: discord.Interaction, user: str, reason: str = "No reason provided"
    ) -> None:
        if not interaction.guild or not isinstance(interaction.user, discord.Member):
            return
        await interaction.response.defer(thinking=True)
        emb = await _do_untimeout(interaction.guild, interaction.user, user, reason)
        await interaction.followup.send(embed=emb)

    @bot.tree.command(name="stats", description="Bot and system statistics")
    async def slash_stats(interaction: discord.Interaction) -> None:
        if not is_stats_authorized(interaction.user.id):
            await interaction.response.send_message(
                embed=make_embed(
                    "Permission Denied",
                    "Restricted command.",
                    discord.Color.red(),
                    guild=interaction.guild,
                    bot=bot,
                ),
                ephemeral=True,
            )
            return
        await interaction.response.defer(ephemeral=True)
        await interaction.followup.send(
            embed=await build_stats_embed(bot, guild=interaction.guild), ephemeral=True
        )

    return bot


async def main() -> None:
    if not DISCORD_TOKEN:
        raise RuntimeError("DISCORD_TOKEN environment variable is required.")
    bot = build_bot()
    async with bot:
        await bot.start(DISCORD_TOKEN)


if __name__ == "__main__":
    asyncio.run(main())
