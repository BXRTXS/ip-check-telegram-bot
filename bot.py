#!/usr/bin/env python3
"""
Telegram-бот: пакетная проверка IPv4 (текст или .txt файл).
Запуск: TG_SOCKS_PROXY для исходящих HTTP-проверок; Bot API — см. IP_CHECK_TG_NO_PROXY в env.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import sys
from html import escape
from pathlib import Path
from urllib.parse import urlparse

from io import BytesIO

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, InputFile, Update
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)
from telegram.request import HTTPXRequest

from access_store import AccessStore, env_admin_user_ids, env_allowed_user_ids
from admin_handlers import (
    cmd_admin,
    is_admin_user_id,
    on_admin_callback,
    try_admin_add_user_text,
)
from activity_store import ActivityStore
from audit_log import AuditLog
from denied_notify_store import DeniedNotifyStore
from lookup_cache import init_lookup_cache
from runtime_config import get_limits, init_runtime_config
from keys import abuseipdb_api_key, otx_api_key, vt_api_key
from dump_analyzer import (
    analyze_dump_bytes,
    analyze_pcap_path,
    caption_requests_dump,
    format_dump_attachment,
    format_dump_html,
    is_dump_filename,
    is_pcap_magic,
    is_text_dump_filename,
)
from dump_ip_batch import DumpIpBatch, dump_check_keyboard, register_dump_ip_batch
from zip_dump import ZipBundle, cleanup_bundle, extract_zip_pcaps, purge_old_bundles
from domain_resolve import extract_domains, format_domain_resolve_html, resolve_domains
from lookups import LookupFlags, extract_ipv4s, run_lookups_for_ips
from settings_store import SettingsStore, UserSettings

log = logging.getLogger(__name__)


def h(s: str) -> str:
    return escape(s, quote=True)


def _truthy(s: str | None) -> bool:
    return s is not None and s.strip().lower() in ("1", "true", "yes", "on")


def _check_proxy_requirement() -> None:
    if not _truthy(os.environ.get("IP_CHECK_REQUIRE_PROXY")):
        return
    if not os.environ.get("TG_SOCKS_PROXY", "").strip():
        print(
            "ip-check-bot: IP_CHECK_REQUIRE_PROXY включён, но TG_SOCKS_PROXY пуст. См. ~/PROXY.md",
            file=sys.stderr,
        )
        raise SystemExit(2)


def _normalize_ptb_proxy(px: str) -> str:
    hpx = px.replace("socks5://", "socks5h://", 1) if px.startswith("socks5://") else px
    if not hpx.startswith("socks5"):
        hpx = f"socks5h://{hpx}"
    return hpx


def _ptb_skip_proxy() -> bool:
    """
    Bot API (getMe / getUpdates / sendMessage) без SOCKS — как TG_BOT_NO_PROXY у filmekom.
    Нужно, если httpx падает на start_tls через mixed; проверки IP по-прежнему через TG_SOCKS_PROXY.
    """
    if _truthy(os.environ.get("IP_CHECK_TG_NO_PROXY")):
        return True
    return _truthy(os.environ.get("TG_BOT_NO_PROXY"))


def _ptb_http_requests(hproxy: str) -> tuple[HTTPXRequest, HTTPXRequest]:
    """Отдельные HTTPXRequest: trust_env=False снимает конфликты с ALL_PROXY/HTTPS_PROXY в systemd."""
    httpx_kw = {"trust_env": False}
    common = dict(
        connect_timeout=30.0,
        write_timeout=30.0,
        pool_timeout=10.0,
        httpx_kwargs=httpx_kw,
    )
    req = HTTPXRequest(proxy=hproxy, read_timeout=25.0, **common)
    gur = HTTPXRequest(
        proxy=hproxy,
        connection_pool_size=1,
        read_timeout=70.0,
        **common,
    )
    return req, gur


def _httpx_proxy_from_env() -> str | None:
    raw = os.environ.get("TG_SOCKS_PROXY", "").strip()
    if not raw:
        return None
    u = urlparse(raw.replace("socks5h://", "socks5://"))
    if u.hostname is None or u.port is None:
        return None
    return f"socks5://{u.hostname}:{u.port}"


def _max_ips() -> int:
    return get_limits().max_ips_per_request


def _access_store(context: ContextTypes.DEFAULT_TYPE) -> AccessStore:
    return context.application.bot_data["access_store"]


def _audit_log(context: ContextTypes.DEFAULT_TYPE) -> AuditLog:
    return context.application.bot_data["audit_log"]


def _activity_store(context: ContextTypes.DEFAULT_TYPE) -> ActivityStore:
    return context.application.bot_data["activity_store"]


def _denied_notify_store(context: ContextTypes.DEFAULT_TYPE) -> DeniedNotifyStore:
    return context.application.bot_data["denied_notify_store"]


def _record_activity(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    *,
    action: str,
) -> None:
    u = update.effective_user
    if not u:
        return
    _activity_store(context).touch(
        u.id,
        username=u.username,
        display_name=_display_name(update),
        action=action,
    )


def _allowed_ids(context: ContextTypes.DEFAULT_TYPE) -> set[int]:
    env_ids: set[int] = context.application.bot_data.get("env_allowed_ids") or set()
    store_ids = _access_store(context).stored_ids()
    return env_ids | store_ids


def _user_denied(context: ContextTypes.DEFAULT_TYPE, update: Update) -> bool:
    uid = update.effective_user.id if update.effective_user else None
    if uid is None:
        return True
    if is_admin_user_id(context, uid):
        return False
    allowed = _allowed_ids(context)
    if not allowed:
        return False
    return uid not in allowed


def _is_admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    uid = update.effective_user.id if update.effective_user else None
    return is_admin_user_id(context, uid)


async def _notify_admins_unknown_user(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    u = update.effective_user
    if not u:
        return
    if not _allowed_ids(context):
        return
    store = _denied_notify_store(context)
    if store.already_notified(u.id):
        return
    store.mark_notified(u.id)
    admins: set[int] = context.application.bot_data.get("admin_user_ids") or set()
    un = f"@{u.username}" if u.username else "—"
    dn = _display_name(update) or "—"
    text = (
        "🆕 <b>Неизвестный user id</b> (первое обращение)\n\n"
        f"id: <code>{u.id}</code>\n"
        f"Имя: {h(dn)}\n"
        f"username: {h(un)}\n\n"
        "Whitelist включён — доступ отклонён.\n"
        "Добавить: /admin → ➕"
    )
    for aid in admins:
        try:
            await context.bot.send_message(aid, text, parse_mode=ParseMode.HTML)
        except Exception:
            log.exception("notify admin %s about unknown user failed", aid)


async def _reject_if_denied(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    if not _user_denied(context, update):
        return False
    u = update.effective_user
    if u:
        _record_activity(update, context, action="access_denied")
        _audit_log(context).append(
            user_id=u.id,
            username=u.username,
            display_name=_display_name(update),
            ips=[],
            mode="access_denied",
            source="whitelist",
        )
        await _notify_admins_unknown_user(update, context)
    text = (
        "⛔ <b>Нет доступа</b> к этому боту.\n"
        "Попросите администратора добавить ваш Telegram user id."
    )
    if update.callback_query:
        await update.callback_query.answer("Нет доступа", show_alert=True)
        if update.callback_query.message:
            await update.callback_query.message.reply_html(text)
    elif update.effective_message:
        await update.effective_message.reply_html(text)
    return True


def _display_name(update: Update) -> str:
    u = update.effective_user
    if not u:
        return ""
    return " ".join(x for x in (u.first_name, u.last_name) if x).strip()


def _touch_allowed_profile(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    u = update.effective_user
    if not u:
        return
    if u.id not in _access_store(context).stored_ids():
        return
    _access_store(context).touch_profile(
        u.id,
        username=u.username,
        display_name=_display_name(update),
    )


def _store(context: ContextTypes.DEFAULT_TYPE) -> SettingsStore:
    return context.application.bot_data["settings_store"]


def _flags_for_user(context: ContextTypes.DEFAULT_TYPE, user_id: int) -> LookupFlags:
    s = _store(context).get(user_id)
    vt_on = s.vt and bool(vt_api_key())
    otx_on = s.otx and bool(otx_api_key())
    abuse_on = s.abuse and bool(abuseipdb_api_key())
    return LookupFlags(
        geo=s.geo,
        vt=vt_on,
        otx=otx_on,
        abuse=abuse_on,
        ripe=s.ripe,
    )


def _has_any_source(flags: LookupFlags, *, single_ip: bool) -> bool:
    base = flags.geo or flags.vt or flags.otx
    if single_ip:
        return base or flags.abuse or flags.ripe
    return base


def _split_long_html_line(line: str, max_len: int) -> list[str]:
    """Длинная строка: не режем внутри <...>."""
    if len(line) <= max_len:
        return [line]
    out: list[str] = []
    rest = line
    while len(rest) > max_len:
        window = rest[:max_len]
        cut = max_len
        gt = window.rfind(">")
        if gt > max_len // 4:
            cut = gt + 1
        else:
            sp = window.rfind(" ")
            if sp > max_len // 4:
                cut = sp + 1
        if cut <= 0:
            cut = max_len
        out.append(rest[:cut])
        rest = rest[cut:]
    if rest:
        out.append(rest)
    return out


def _split_html_safe(text: str, max_len: int) -> list[str]:
    """Разбиение HTML для Telegram без обрыва тегов посередине."""
    if len(text) <= max_len:
        return [text]
    chunks: list[str] = []
    cur = ""
    for line in text.split("\n"):
        extra = 1 if cur else 0
        if len(cur) + extra + len(line) <= max_len:
            cur = line if not cur else cur + "\n" + line
            continue
        if cur:
            chunks.append(cur)
            cur = ""
        if len(line) <= max_len:
            cur = line
        else:
            for part in _split_long_html_line(line, max_len):
                chunks.append(part)
    if cur:
        chunks.append(cur)
    return chunks


def _split_html_chunks(parts: list[str], max_len: int = 3900) -> list[str]:
    chunks: list[str] = []
    sep = "\n\n"
    for p in parts:
        if not p:
            continue
        for piece in _split_html_safe(p, max_len):
            if chunks and len(chunks[-1]) + len(sep) + len(piece) <= max_len:
                chunks[-1] = chunks[-1] + sep + piece
            else:
                chunks.append(piece)
    return chunks


def _settings_body() -> str:
    has_vt = bool(vt_api_key())
    has_otx = bool(otx_api_key())
    has_abuse = bool(abuseipdb_api_key())
    return (
        "<b>Настройки</b> (для вашего аккаунта).\n"
        f"Ключ VT: {'есть' if has_vt else 'нет'} · OTX: {'есть' if has_otx else 'нет'} · "
        f"AbuseIPDB: {'есть' if has_abuse else 'нет'}\n"
        "RIPEstat — только в детальном отчёте (prefix-overview, as-overview, asn-neighbours).\n"
        "Переключатели ниже."
    )


def _settings_keyboard(s: UserSettings) -> InlineKeyboardMarkup:
    has_vt = bool(vt_api_key())
    has_otx = bool(otx_api_key())
    has_abuse = bool(abuseipdb_api_key())
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(
                    f"Гео ip-api: {'вкл' if s.geo else 'выкл'}", callback_data="t:geo"
                ),
            ],
            [
                InlineKeyboardButton(
                    f"VT: {'вкл' if s.vt else 'выкл'}{' (нет ключа)' if not has_vt else ''}",
                    callback_data="t:vt",
                ),
            ],
            [
                InlineKeyboardButton(
                    f"OTX: {'вкл' if s.otx else 'выкл'}{' (нет ключа)' if not has_otx else ''}",
                    callback_data="t:otx",
                ),
            ],
            [
                InlineKeyboardButton(
                    f"AbuseIPDB: {'вкл' if s.abuse else 'выкл'}{' (нет ключа)' if not has_abuse else ''}",
                    callback_data="t:abuse",
                ),
            ],
            [
                InlineKeyboardButton(
                    f"RIPEstat: {'вкл' if s.ripe else 'выкл'}",
                    callback_data="t:ripe",
                ),
            ],
        ]
    )


async def cmd_dump(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if await _reject_if_denied(update, context):
        return
    if not _is_admin(update, context):
        return
    await update.effective_message.reply_html(
        "<b>Анализ дампа трафика</b> (admin)\n\n"
        "• <code>.pcap</code> / <code>.pcapng</code> — Mitigator Packet comments, статистика "
        "по <b>dst/src IP</b>; кнопка массовой проверки Src/Dst IP\n"
        "• <code>.zip</code> — список PCAP внутри, выбор кнопкой\n"
        "• <code>.log</code> или <code>.txt</code> + подпись <code>dump</code> — DROP в логах\n\n"
        "<i>ACL DROP tcp tcp-flags S/SA</i> — отсечение чистых SYN (новые TCP-сессии).\n"
        "Справочник контрмер: "
        '<a href="https://docs.mitigator.ru/v25.02/kb/mitigator_help.pdf">Mitigator help PDF</a>'
    )


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if await _reject_if_denied(update, context):
        return
    _record_activity(update, context, action="start")
    extra = ""
    uid = update.effective_user.id if update.effective_user else None
    if _is_admin(update, context):
        extra = "\n\nАдмин: /admin — пользователи и журнал; /dump — разбор pcap (скрыто)."
    await update.effective_message.reply_html(
        "<b>IP check bot</b>\n\n"
        "Отправьте <b>IPv4</b> или <b>домены</b> списком в сообщении или в <code>.txt</code>.\n"
        "Домены → резолв в IPv4 (DNS, при ключах VT/OTX), затем проверка адресов.\n"
        "<b>1 IP</b> — детальный отчёт (в т.ч. домены за IP, если найдены); "
        "<b>несколько</b> — компактные строки в <code>pre</code> (параллельно, быстро).\n"
        "Сервисы — в /settings."
        + extra
    )


async def cmd_settings(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if await _reject_if_denied(update, context):
        return
    _record_activity(update, context, action="settings")
    uid = update.effective_user.id
    s = _store(context).get(uid)
    await update.effective_message.reply_html(
        _settings_body(),
        reply_markup=_settings_keyboard(s),
    )


async def on_settings_toggle(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    q = update.callback_query
    await q.answer()
    if await _reject_if_denied(update, context):
        return
    data = (q.data or "").strip()
    if not data.startswith("t:"):
        return
    field = data[2:]
    if field not in ("geo", "vt", "otx", "abuse", "ripe"):
        return
    uid = update.effective_user.id
    cur = _store(context).get(uid)
    new_val = not getattr(cur, field)
    new_s = _store(context).set_field(uid, field, new_val)
    await q.edit_message_text(
        _settings_body(),
        parse_mode=ParseMode.HTML,
        reply_markup=_settings_keyboard(new_s),
    )


def _valid_ipv4(s: str) -> bool:
    m = re.fullmatch(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})", (s or "").strip())
    if not m:
        return False
    return all(0 <= int(x) <= 255 for x in m.groups())


def _red_buttons_max() -> int:
    return get_limits().red_buttons_max


def _red_detail_keyboard(red_ips: list[str]) -> InlineKeyboardMarkup | None:
    if not red_ips:
        return None
    mx = _red_buttons_max()
    rows: list[list[InlineKeyboardButton]] = []
    row: list[InlineKeyboardButton] = []
    for ip in red_ips[:mx]:
        cb = f"detail:{ip}"
        if len(cb.encode("utf-8")) > 64:
            continue
        row.append(InlineKeyboardButton(f"🔴 {ip}", callback_data=cb))
        if len(row) >= 2:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    if not rows:
        return None
    return InlineKeyboardMarkup(rows)


async def on_detail_ip(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    q = update.callback_query
    if not q:
        return
    await q.answer()
    if await _reject_if_denied(update, context):
        return
    raw = (q.data or "").strip()
    if not raw.startswith("detail:"):
        return
    ip = raw[len("detail:") :].strip()
    if not _valid_ipv4(ip):
        if q.message:
            await q.message.reply_html("Некорректный IPv4.")
        return
    await _process_ips_message(update, context, ip, source="callback_detail")


def _merge_ips(direct: list[str], from_domains: list[str], *, limit: int) -> list[str]:
    seen: set[str] = set(direct)
    out = list(direct)
    for ip in from_domains:
        if ip in seen:
            continue
        seen.add(ip)
        out.append(ip)
        if len(out) >= limit:
            break
    return out[:limit]


async def _process_ips_message(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    text: str,
    *,
    source: str = "text",
) -> None:
    if await _reject_if_denied(update, context):
        return
    limit = _max_ips()
    ips_direct = extract_ipv4s(text, limit=limit)
    domains = extract_domains(text, limit=limit)
    domain_rows = []
    resolved_ips: list[str] = []

    uid = update.effective_user.id
    flags = _flags_for_user(context, uid)

    proxy = _httpx_proxy_from_env()
    if domains:
        if (flags.vt or flags.otx) and not proxy:
            await update.effective_message.reply_html(
                "<i>VT/OTX для доменов недоступны без TG_SOCKS_PROXY; "
                "использую только DNS.</i>"
            )
        status_dom = await update.effective_message.reply_html(
            f"Резолв <b>{len(domains)}</b> домен(ов)…"
        )
        try:
            domain_rows = await resolve_domains(
                domains,
                proxy_url=proxy,
                use_vt=flags.vt,
                use_otx=flags.otx,
            )
        except Exception as e:
            log.exception("domain resolve failed")
            await status_dom.edit_text(
                f"Ошибка резолва: <code>{h(str(e))}</code>",
                parse_mode=ParseMode.HTML,
            )
            if not ips_direct:
                return
            domain_rows = []
        else:
            for row in domain_rows:
                resolved_ips.extend(row.ips)
            dom_html = format_domain_resolve_html(domain_rows)
            await status_dom.edit_text(dom_html, parse_mode=ParseMode.HTML, disable_web_page_preview=True)

    ips = _merge_ips(ips_direct, resolved_ips, limit=limit)
    if not ips:
        if domains:
            return
        await update.effective_message.reply_html(
            "Не найдено IPv4 и доменов. Пришлите адреса или имена хостов "
            "(<code>example.com</code>) текстом или <code>.txt</code>."
        )
        return

    single = len(ips) == 1
    if not _has_any_source(flags, single_ip=single):
        if domains and domain_rows:
            u = update.effective_user
            if u:
                _record_activity(update, context, action="domain_resolve")
                _audit_log(context).append(
                    user_id=u.id,
                    username=u.username,
                    display_name=_display_name(update),
                    ips=ips,
                    mode="domain_resolve",
                    source=source,
                )
            await update.effective_message.reply_html(
                "Резолв доменов выше. Для проверки репутации IP включите источники в /settings."
            )
        else:
            await update.effective_message.reply_html(
                "Нет ни одного включённого источника (или нет ключей VT/OTX/AbuseIPDB). "
                "См. /settings."
            )
        return

    if not proxy:
        await update.effective_message.reply_html(
            "Ошибка: для HTTP-запросов нужен <code>TG_SOCKS_PROXY</code>."
        )
        return

    mode = "детально" if len(ips) == 1 else "массово (быстро)"
    intro = f"Проверяю <b>{len(ips)}</b> адресов"
    if domains:
        intro += f" (из {len(domains)} домен(ов))"
    intro += f" — <i>{h(mode)}</i>…"
    cache = context.application.bot_data.get("lookup_cache")
    status = await update.effective_message.reply_html(intro)
    try:
        blocks, red_ips, att, n_cached = await run_lookups_for_ips(
            proxy, ips, flags, cache=cache
        )
    except Exception as e:
        log.exception("lookups failed")
        await status.edit_text(
            f"Ошибка: <code>{h(str(e))}</code>",
            parse_mode=ParseMode.HTML,
        )
        return

    if n_cached:
        ttl = get_limits().lookup_cache_ttl_hours
        cache_note = f"\n<i>📦 {n_cached} IP из кэша (TTL {ttl} ч), без повторных API-запросов</i>"
    else:
        cache_note = ""

    u = update.effective_user
    if u:
        _touch_allowed_profile(update, context)
        mode = "detail" if len(ips) == 1 else "bulk"
        if domains:
            mode = f"{mode}+domains"
        _record_activity(update, context, action=mode)
        _audit_log(context).append(
            user_id=u.id,
            username=u.username,
            display_name=_display_name(update),
            ips=ips,
            mode=mode,
            source=source,
        )

    header = f"<b>Готово</b> — {len(ips)} IP ({h('детальный отчёт' if len(ips) == 1 else 'компактный режим')}){cache_note}\n\n"
    chunks = _split_html_chunks(blocks)
    bulk = len(ips) > 1
    mx = _red_buttons_max()
    if bulk and red_ips and len(red_ips) > mx and chunks:
        chunks[-1] = (
            chunks[-1]
            + f"\n\n<i>Кнопки — первые {mx} из {len(red_ips)} 🔴; остальные пришлите текстом.</i>"
        )
    kb_last = _red_detail_keyboard(red_ips) if bulk else None

    first = header + chunks[0]
    await status.edit_text(
        first,
        parse_mode=ParseMode.HTML,
        disable_web_page_preview=True,
        reply_markup=kb_last if bulk and len(chunks) == 1 else None,
    )
    if len(chunks) > 1:
        for ch in chunks[1:-1]:
            await update.effective_message.reply_html(ch, disable_web_page_preview=True)
        await update.effective_message.reply_html(
            chunks[-1],
            disable_web_page_preview=True,
            reply_markup=kb_last,
        )
    if att:
        fn = f"{ips[0].replace('.', '_')}_ip_check_full.txt"
        await update.effective_message.reply_document(
            document=InputFile(BytesIO(att.encode("utf-8")), filename=fn),
            caption="Полный дамп без обрезки (все поля и списки).",
        )


async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message or not update.message.text:
        return
    if await try_admin_add_user_text(update, context):
        return
    await _process_ips_message(update, context, update.message.text, source="text")


def _txt_max_bytes() -> int:
    return get_limits().max_txt_mb * 1024 * 1024


def _document_is_dump(name: str, data: bytes, caption: str | None) -> bool:
    if is_dump_filename(name):
        return True
    if is_pcap_magic(data):
        return True
    if name.lower().endswith(".gz"):
        return True
    if is_text_dump_filename(name) and caption_requests_dump(caption):
        return True
    if name.lower().endswith(".log"):
        return True
    if name.lower().endswith(".txt") and caption_requests_dump(caption):
        return True
    return False


async def _enrich_dump_src_ips(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    report,
    *,
    status_msg,
) -> None:
    if not report.ok or not report.mitigator or not report.mitigator.src_stats:
        return
    uid = update.effective_user.id if update.effective_user else None
    if uid is None:
        return
    proxy = _httpx_proxy_from_env()
    flags = _flags_for_user(context, uid)
    if not proxy or not _has_any_source(flags, single_ip=False):
        return

    from dump_src_enrich import build_src_enrichment

    try:
        n = len({st.ip for st in report.mitigator.src_stats})
        await status_msg.edit_text(
            f"Разбор pcap готов. Сверяю <b>{n}</b> src IP (geo, VT, OTX)…",
            parse_mode=ParseMode.HTML,
        )
        enrich = await build_src_enrichment(
            proxy,
            report.mitigator.src_stats,
            flags,
            limit=_max_ips(),
            cache=context.application.bot_data.get("lookup_cache"),
        )
    except Exception:
        log.exception("dump src enrichment failed")
        return

    if enrich:
        report.src_enrichment = enrich


async def _send_dump_report(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    report,
    filename: str,
    *,
    status_msg,
) -> None:
    html = format_dump_html(report)
    chunks = _split_html_chunks([html])
    await status_msg.edit_text(chunks[0], parse_mode=ParseMode.HTML, disable_web_page_preview=True)
    for ch in chunks[1:]:
        await update.effective_message.reply_html(ch, disable_web_page_preview=True)

    att = format_dump_attachment(report)
    await update.effective_message.reply_document(
        document=InputFile(
            BytesIO(att.encode("utf-8")),
            filename=f"{Path(filename).stem}_analysis.txt",
        ),
        caption="Полный отчёт по дампу.",
    )

    if report.ok and report.mitigator and update.effective_user:
        batches: dict[str, DumpIpBatch] = context.application.bot_data.setdefault(
            "dump_ip_batches", {}
        )
        batch = register_dump_ip_batch(
            batches,
            owner_user_id=update.effective_user.id,
            mitigator=report.mitigator,
            filename=filename,
        )
        if batch:
            extra = ""
            if report.src_enrichment:
                extra = (
                    "\n<i>Src IP уже в отчёте (подсети + AS).</i> "
                    "Кнопка — повтор или Dst:"
                )
            await update.effective_message.reply_html(
                "<b>Доп. проверка IP из дампа</b> (массовый режим):"
                + extra,
                reply_markup=dump_check_keyboard(batch),
            )


async def _process_dump_document(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    data: bytes,
    filename: str,
    *,
    force_text: bool,
    pcap_path: Path | None = None,
) -> None:
    if not _is_admin(update, context):
        return
    status = await update.effective_message.reply_html(
        f"Разбираю дамп <code>{h(filename)}</code>…"
    )
    try:
        if pcap_path is not None:
            report = await asyncio.to_thread(analyze_pcap_path, pcap_path, filename=filename)
        else:
            report = await asyncio.to_thread(
                analyze_dump_bytes,
                data,
                filename,
                force_text=force_text,
            )
    except Exception as e:
        log.exception("dump analyze failed")
        await status.edit_text(
            f"Ошибка разбора: <code>{h(str(e))}</code>",
            parse_mode=ParseMode.HTML,
        )
        return

    u = update.effective_user
    if u:
        _touch_allowed_profile(update, context)
        _record_activity(update, context, action="dump")
        _audit_log(context).append(
            user_id=u.id,
            username=u.username,
            display_name=_display_name(update),
            ips=[f"dump:{filename}"],
            mode="dump",
            source=report.kind if report.ok else "dump_error",
        )

    await _enrich_dump_src_ips(update, context, report, status_msg=status)
    await _send_dump_report(update, context, report, filename, status_msg=status)


def _zip_pick_keyboard(bundle: ZipBundle) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    row: list[InlineKeyboardButton] = []
    for ent in bundle.entries:
        label = ent.name if len(ent.name) <= 36 else ent.name[:33] + "…"
        cb = f"dz:{bundle.token}:{ent.index}"
        row.append(InlineKeyboardButton(label, callback_data=cb))
        if len(row) >= 1:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    return InlineKeyboardMarkup(rows)


async def _process_zip_document(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    data: bytes,
    filename: str,
) -> None:
    if not _is_admin(update, context):
        return
    uid = update.effective_user.id if update.effective_user else 0
    zip_dir: Path = context.application.bot_data["dump_zip_dir"]
    bundle, err = extract_zip_pcaps(data, owner_user_id=uid, base_dir=zip_dir)
    if err or bundle is None:
        await update.effective_message.reply_html(f"ZIP: {h(err or 'ошибка')}")
        return

    zips: dict = context.application.bot_data.setdefault("dump_zips", {})
    zips[bundle.token] = bundle

    lines = [f"<b>ZIP</b> <code>{h(filename)}</code> — выберите PCAP для анализа:"]
    for ent in bundle.entries[:15]:
        kb = ent.size // 1024
        lines.append(f"• {h(ent.name)} ({kb} KiB)")
    await update.effective_message.reply_html(
        "\n".join(lines),
        reply_markup=_zip_pick_keyboard(bundle),
    )


async def on_dump_check_ips(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    q = update.callback_query
    if not q:
        return
    await q.answer()
    if await _reject_if_denied(update, context):
        return
    if not _is_admin(update, context):
        await q.answer("Только для админа", show_alert=True)
        return

    raw = (q.data or "").strip()
    parts = raw.split(":")
    if len(parts) != 3 or parts[0] != "dchk":
        return
    token, which = parts[1], parts[2]
    if which not in ("src", "dst", "src24", "dst24"):
        return

    batch: DumpIpBatch | None = context.application.bot_data.get("dump_ip_batches", {}).get(
        token
    )
    uid = update.effective_user.id if update.effective_user else None
    if batch is None or uid != batch.owner_user_id:
        await q.answer("Сессия устарела — пришлите дамп снова", show_alert=True)
        return

    ips = batch.ips_for(which)  # type: ignore[arg-type]
    if not ips:
        await q.answer("Нет IP в этой категории", show_alert=True)
        return

    limit = _max_ips()
    total = len(ips)
    ips = ips[:limit]
    label = "Src" if which == "src" else "Dst"
    trunc_note = (
        f" <i>(лимит {limit}, в дампе {total})</i>" if total > limit else ""
    )
    if q.message:
        await q.message.reply_html(
            f"Массовая проверка <b>{len(ips)}</b> {label} IP из дампа "
            f"<code>{h(batch.filename)}</code>{trunc_note}…"
        )
    await _process_ips_message(update, context, "\n".join(ips), source=f"dump_{which}")


async def on_dump_zip_pick(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    q = update.callback_query
    if not q:
        return
    await q.answer()
    if not _is_admin(update, context):
        return
    raw = (q.data or "").strip()
    parts = raw.split(":")
    if len(parts) != 3 or parts[0] != "dz":
        return
    token, idx_s = parts[1], parts[2]
    try:
        idx = int(idx_s)
    except ValueError:
        return

    bundle: ZipBundle | None = context.application.bot_data.get("dump_zips", {}).get(token)
    if bundle is None:
        if q.message:
            await q.message.reply_html("Сессия ZIP истекла — пришлите архив снова.")
        return
    uid = update.effective_user.id if update.effective_user else None
    if uid != bundle.owner_user_id:
        return

    entry = next((e for e in bundle.entries if e.index == idx), None)
    if entry is None or not entry.path.is_file():
        if q.message:
            await q.message.reply_html("Файл не найден.")
        return

    if q.message:
        await _process_dump_document(
            update,
            context,
            b"",
            entry.name,
            force_text=False,
            pcap_path=entry.path,
        )


async def on_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if await _reject_if_denied(update, context):
        return
    msg = update.message
    if not msg or not msg.document:
        return
    doc = msg.document
    name = doc.file_name or "upload"
    name_l = name.lower()
    caption = msg.caption

    f = await context.bot.get_file(doc.file_id)
    buf = await f.download_as_bytearray()
    data = bytes(buf)

    if _is_admin(update, context) and _document_is_dump(name, data, caption):
        if name_l.endswith(".zip"):
            from zip_dump import _zip_max_bytes

            lim = _zip_max_bytes()
            if doc.file_size and doc.file_size > lim:
                mb = lim // (1024 * 1024)
                await msg.reply_html(f"ZIP слишком большой (лимит {mb} МБ).")
                return
            await _process_zip_document(update, context, data, name)
            return

        from dump_analyzer import _dump_max_bytes

        if doc.file_size and doc.file_size > _dump_max_bytes():
            mb = _dump_max_bytes() // (1024 * 1024)
            await msg.reply_html(f"Дамп слишком большой (лимит {mb} МБ, /admin → ⚙️).")
            return
        force_text = name_l.endswith(".log") or (
            name_l.endswith(".txt") and caption_requests_dump(caption)
        )
        await _process_dump_document(update, context, data, name, force_text=force_text)
        return

    if not name_l.endswith(".txt"):
        await msg.reply_html(
            "Пришлите список IPv4 или доменов в файле <code>.txt</code>."
        )
        return
    if doc.file_size and doc.file_size > _txt_max_bytes():
        mb = get_limits().max_txt_mb
        await msg.reply_html(f"Файл слишком большой (лимит {mb} МБ).")
        return
    text = ""
    for enc in ("utf-8", "utf-8-sig", "cp1251", "latin-1"):
        try:
            text = data.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    if not text and data:
        text = data.decode("utf-8", errors="replace")
    await _process_ips_message(update, context, text, source="document")


def main() -> None:
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        level=getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO),
        stream=sys.stdout,
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    _check_proxy_requirement()
    token = os.environ.get("BOT_TOKEN", "").strip()
    if not token:
        print("Задайте BOT_TOKEN в окружении.", file=sys.stderr)
        raise SystemExit(2)

    px = os.environ.get("TG_SOCKS_PROXY", "").strip()
    raw_dd = os.environ.get("IP_CHECK_DATA_DIR", "").strip()
    if raw_dd:
        data_dir = Path(raw_dd).expanduser()
    else:
        data_dir = Path(__file__).resolve().parent / "data"
    store = SettingsStore(data_dir / "user_settings.json")
    access_store = AccessStore(data_dir / "allowed_users.json")
    audit = AuditLog(data_dir / "audit.jsonl")
    runtime_cfg = init_runtime_config(data_dir / "runtime_config.json")
    lookup_cache = init_lookup_cache(data_dir / "lookup_cache.json")
    activity_store = ActivityStore(data_dir / "activity.json")
    denied_notify = DeniedNotifyStore(data_dir / "denied_notified.json")
    admin_ids = env_admin_user_ids()
    env_allowed = env_allowed_user_ids()
    if env_allowed and admin_ids:
        seeded = access_store.seed_from_env_if_empty(env_allowed, added_by=next(iter(admin_ids)))
        if seeded:
            log.info("Импортировано %s user id из env в allowed_users.json", seeded)
    elif env_allowed and not admin_ids:
        log.warning(
            "IP_CHECK_ALLOWED_USER_IDS задан, но IP_CHECK_ADMIN_USER_IDS пуст — "
            "импорт в JSON и /admin недоступны"
        )
    if not admin_ids:
        log.warning("IP_CHECK_ADMIN_USER_IDS пуст — команда /admin отключена")

    builder = Application.builder().token(token)
    if px and not _ptb_skip_proxy():
        hproxy = _normalize_ptb_proxy(px)
        req, gur = _ptb_http_requests(hproxy)
        builder = builder.request(req).get_updates_request(gur)
        log.info("Bot API через SOCKS (HTTPXRequest, trust_env=False): %s", hproxy)
    elif px and _ptb_skip_proxy():
        log.info(
            "Bot API без прокси (IP_CHECK_TG_NO_PROXY/TG_BOT_NO_PROXY); "
            "проверки IP через %s",
            _httpx_proxy_from_env() or "(нет — задайте TG_SOCKS_PROXY)",
        )
    else:
        log.warning("TG_SOCKS_PROXY пуст — на mor Telegram и проверки IP могут не работать.")

    app = builder.build()
    app.bot_data["settings_store"] = store
    app.bot_data["access_store"] = access_store
    app.bot_data["audit_log"] = audit
    app.bot_data["activity_store"] = activity_store
    app.bot_data["denied_notify_store"] = denied_notify
    app.bot_data["runtime_config"] = runtime_cfg
    app.bot_data["lookup_cache"] = lookup_cache
    app.bot_data["admin_user_ids"] = admin_ids
    app.bot_data["env_allowed_ids"] = env_allowed
    dump_zip_dir = data_dir / "dump_zips"
    dump_zip_dir.mkdir(parents=True, exist_ok=True)
    purge_old_bundles(dump_zip_dir)
    app.bot_data["dump_zip_dir"] = dump_zip_dir
    app.bot_data["dump_zips"] = {}
    app.bot_data["dump_ip_batches"] = {}

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("dump", cmd_dump))
    app.add_handler(CommandHandler("settings", cmd_settings))
    app.add_handler(CommandHandler("admin", cmd_admin))
    app.add_handler(CallbackQueryHandler(on_admin_callback, pattern=r"^adm:"))
    app.add_handler(CallbackQueryHandler(on_dump_zip_pick, pattern=r"^dz:"))
    app.add_handler(CallbackQueryHandler(on_dump_check_ips, pattern=r"^dchk:"))
    app.add_handler(CallbackQueryHandler(on_detail_ip, pattern=r"^detail:"))
    app.add_handler(CallbackQueryHandler(on_settings_toggle, pattern=r"^t:(geo|vt|otx|abuse|ripe)$"))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))
    app.add_handler(MessageHandler(filters.Document.ALL, on_document))
    app.add_error_handler(on_ptb_error)

    bootstrap = max(0, int(os.environ.get("IP_CHECK_PTB_BOOTSTRAP_RETRIES", "15")))
    app.run_polling(
        allowed_updates=Update.ALL_TYPES,
        bootstrap_retries=bootstrap,
        drop_pending_updates=False,
    )


async def on_ptb_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    err = context.error
    log.exception("PTB error: %s", err)
    if isinstance(update, Update) and update.effective_message:
        try:
            await update.effective_message.reply_html(
                f"Внутренняя ошибка бота: <code>{h(type(err).__name__)}</code>"
            )
        except Exception:
            log.exception("failed to notify user about error")


if __name__ == "__main__":
    main()
