"""Команды и меню администратора: пользователи, аудит."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from html import escape

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from access_store import AccessStore, AllowedUser
from activity_store import ActivityStore
from audit_log import AuditLog
from runtime_config import (
    EDITABLE_LIMIT_FIELDS,
    RuntimeConfigStore,
    get_limits,
)

ADMIN_PENDING_ADD = "admin_pending_add_user"
ADMIN_PENDING_LIMIT_FIELD = "admin_pending_limit_field"
AUDIT_PAGE_SIZE = 12


def h(s: str) -> str:
    return escape(s, quote=True)


def _access(context: ContextTypes.DEFAULT_TYPE) -> AccessStore:
    return context.application.bot_data["access_store"]


def _audit(context: ContextTypes.DEFAULT_TYPE) -> AuditLog:
    return context.application.bot_data["audit_log"]


def _activity(context: ContextTypes.DEFAULT_TYPE) -> ActivityStore:
    return context.application.bot_data["activity_store"]


def _runtime_cfg(context: ContextTypes.DEFAULT_TYPE) -> RuntimeConfigStore:
    return context.application.bot_data["runtime_config"]


def is_admin_user_id(context: ContextTypes.DEFAULT_TYPE, user_id: int | None) -> bool:
    if user_id is None:
        return False
    admins: set[int] = context.application.bot_data.get("admin_user_ids") or set()
    return user_id in admins


def _user_label(u: AllowedUser) -> str:
    un = f"@{u.username}" if u.username else ""
    dn = u.display_name or ""
    base = " ".join(x for x in (dn, un) if x).strip() or "—"
    note = f" ({u.note})" if u.note else ""
    return f"<code>{u.user_id}</code> {h(base)}{h(note)}"


def admin_menu_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("👥 Список пользователей", callback_data="adm:users")],
            [InlineKeyboardButton("➕ Добавить user id", callback_data="adm:add")],
            [InlineKeyboardButton("🟢 Кто онлайн / активность", callback_data="adm:activity")],
            [InlineKeyboardButton("📊 Последние проверки", callback_data="adm:audit:0")],
            [InlineKeyboardButton("📈 Сводка по пользователям", callback_data="adm:stats")],
            [InlineKeyboardButton("⚙️ Лимиты и таймауты", callback_data="adm:limits")],
            [InlineKeyboardButton("🩺 Health", callback_data="adm:health")],
            [InlineKeyboardButton("🗑 Очистить кэш lookups", callback_data="adm:cache_clear")],
        ]
    )


def _clear_admin_pending(context: ContextTypes.DEFAULT_TYPE) -> None:
    context.user_data.pop(ADMIN_PENDING_ADD, None)
    context.user_data.pop(ADMIN_PENDING_LIMIT_FIELD, None)


def _limits_list_text() -> str:
    lim = get_limits()
    lines = ["<b>Лимиты и таймауты</b> (файл <code>data/runtime_config.json</code>, без перезапуска):"]
    for key, label in EDITABLE_LIMIT_FIELDS.items():
        lines.append(f"• {h(label)}: <b>{getattr(lim, key)}</b>")
    return "\n".join(lines)


def _limits_list_keyboard() -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    row: list[InlineKeyboardButton] = []
    for key, label in EDITABLE_LIMIT_FIELDS.items():
        short = label[:28] + "…" if len(label) > 29 else label
        row.append(InlineKeyboardButton(short, callback_data=f"adm:cfg:{key}"))
        if len(row) >= 1:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    rows.append([InlineKeyboardButton("« Меню", callback_data="adm:menu")])
    return InlineKeyboardMarkup(rows)


def _format_activity_report(context: ContextTypes.DEFAULT_TYPE) -> str:
    lim = get_limits()
    idle_min = lim.online_idle_minutes
    checks_24h = _audit(context).count_ip_checks_last_hours(24.0)
    now = datetime.now(timezone.utc)

    def _parse_iso(s: str):
        if not s:
            return None
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None

    online: list[str] = []
    idle: list[str] = []
    for act in _activity(context).list_all():
        un = f"@{act.username}" if act.username else ""
        who = h(" ".join(x for x in (act.display_name, un) if x).strip() or "—")
        c24 = checks_24h.get(act.user_id, 0)
        ts = _parse_iso(act.last_seen_at)
        ago = ""
        if ts is not None:
            delta = now - ts
            mins = int(delta.total_seconds() // 60)
            if mins < 60:
                ago = f"{mins} мин назад"
            else:
                ago = f"{mins // 60} ч назад"
        line = (
            f"• <code>{act.user_id}</code> {who}\n"
            f"  последняя: <code>{h(act.last_seen_at[:19])}</code> ({h(ago)})\n"
            f"  проверок за 24ч: <b>{c24}</b> · {h(act.last_action)}"
        )
        if ts is not None and (now - ts).total_seconds() <= idle_min * 60:
            online.append(line)
        else:
            idle.append(line)

    lines = [
        f"<b>Активность</b> (онлайн = активность за последние <b>{idle_min}</b> мин):",
    ]
    if online:
        lines.append("")
        lines.append("<b>🟢 Сейчас онлайн</b>")
        lines.extend(online[:25])
    else:
        lines.append("")
        lines.append("<i>🟢 Сейчас онлайн — никого</i>")
    if idle:
        lines.append("")
        lines.append("<b>Остальные (были раньше)</b>")
        lines.extend(idle[:20])
    if not online and not idle:
        lines.append("")
        lines.append("<i>Нет записей активности</i>")
    return "\n".join(lines)


async def cmd_admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    uid = update.effective_user.id if update.effective_user else None
    if not is_admin_user_id(context, uid):
        return
    _clear_admin_pending(context)
    await update.effective_message.reply_html(
        "<b>Админ-панель</b>\n\n"
        "Управление доступом к боту и просмотр журнала проверок.\n"
        "Список в <code>data/allowed_users.json</code> (плюс id из env, если заданы).",
        reply_markup=admin_menu_keyboard(),
    )


def _users_list_text(users: list[AllowedUser], env_extra: set[int]) -> str:
    lines = ["<b>Разрешённые пользователи</b> (в JSON):"]
    if not users:
        lines.append("<i>в файле пусто</i>")
    else:
        for u in users:
            lines.append(f"• {_user_label(u)}")
    only_env = sorted(env_extra - {u.user_id for u in users})
    if only_env:
        lines.append("")
        lines.append("<b>Только из env</b> (IP_CHECK_ALLOWED_USER_IDS):")
        for eid in only_env:
            lines.append(f"• <code>{eid}</code>")
    return "\n".join(lines)


def _users_list_keyboard(users: list[AllowedUser]) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    row: list[InlineKeyboardButton] = []
    for u in users[:24]:
        row.append(InlineKeyboardButton(f"✖ {u.user_id}", callback_data=f"adm:rm:{u.user_id}"))
        if len(row) >= 2:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    rows.append([InlineKeyboardButton("« Назад", callback_data="adm:menu")])
    return InlineKeyboardMarkup(rows)


async def on_admin_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    q = update.callback_query
    if not q:
        return
    uid = update.effective_user.id if update.effective_user else None
    if not is_admin_user_id(context, uid):
        await q.answer("Нет прав", show_alert=True)
        return

    data = (q.data or "").strip()
    if not data.startswith("adm:"):
        return
    await q.answer()

    acc = _access(context)
    aud = _audit(context)
    env_extra: set[int] = context.application.bot_data.get("env_allowed_ids") or set()

    if data == "adm:menu":
        await q.edit_message_text(
            "<b>Админ-панель</b>",
            parse_mode=ParseMode.HTML,
            reply_markup=admin_menu_keyboard(),
        )
        return

    if data == "adm:users":
        users = acc.list_users()
        await q.edit_message_text(
            _users_list_text(users, env_extra),
            parse_mode=ParseMode.HTML,
            reply_markup=_users_list_keyboard(users),
            disable_web_page_preview=True,
        )
        return

    if data == "adm:add":
        context.user_data[ADMIN_PENDING_ADD] = True
        await q.edit_message_text(
            "<b>Добавить пользователя</b>\n\n"
            "Отправьте <b>числовой Telegram user id</b> одним сообщением.\n"
            "Узнать id: @userinfobot или из журнала после первой попытки доступа.\n\n"
            "Отмена: /admin",
            parse_mode=ParseMode.HTML,
        )
        return

    if data.startswith("adm:rm:"):
        try:
            target = int(data.split(":", 2)[2])
        except (IndexError, ValueError):
            return
        admins: set[int] = context.application.bot_data.get("admin_user_ids") or set()
        if target in admins:
            await q.answer("Нельзя удалить админа из whitelist", show_alert=True)
            return
        removed = acc.remove(target)
        users = acc.list_users()
        msg = "Удалён." if removed else "Не был в JSON."
        await q.edit_message_text(
            f"{h(msg)}\n\n{_users_list_text(users, env_extra)}",
            parse_mode=ParseMode.HTML,
            reply_markup=_users_list_keyboard(users),
            disable_web_page_preview=True,
        )
        return

    if data.startswith("adm:audit:"):
        try:
            page = int(data.split(":", 2)[2])
        except (IndexError, ValueError):
            page = 0
        offset = page * AUDIT_PAGE_SIZE
        events, total = aud.read_recent(limit=AUDIT_PAGE_SIZE, offset=offset)
        lines = [f"<b>Журнал проверок</b> (стр. {page + 1}, всего ~{total})"]
        if not events:
            lines.append("<i>пока пусто</i>")
        for ev in events:
            un = f"@{ev.username}" if ev.username else ""
            who = h(" ".join(x for x in (ev.display_name, un) if x).strip() or "—")
            ips_preview = ", ".join(ev.ips[:6])
            if ev.ip_count > len(ev.ips):
                ips_preview += f" …+{ev.ip_count - len(ev.ips)}"
            elif ev.ip_count > 6:
                ips_preview += f" …+{ev.ip_count - 6}"
            lines.append(
                f"• <code>{h(ev.ts[:19])}</code> uid=<code>{ev.user_id}</code> {who}\n"
                f"  {h(ev.mode)} · {ev.ip_count} IP · {h(ev.source)}\n"
                f"  <code>{h(ips_preview)}</code>"
            )
        nav: list[InlineKeyboardButton] = []
        if page > 0:
            nav.append(InlineKeyboardButton("◀", callback_data=f"adm:audit:{page - 1}"))
        if offset + AUDIT_PAGE_SIZE < total:
            nav.append(InlineKeyboardButton("▶", callback_data=f"adm:audit:{page + 1}"))
        rows: list[list[InlineKeyboardButton]] = []
        if nav:
            rows.append(nav)
        rows.append([InlineKeyboardButton("« Меню", callback_data="adm:menu")])
        await q.edit_message_text(
            "\n".join(lines),
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup(rows),
            disable_web_page_preview=True,
        )
        return

    if data == "adm:stats":
        rows = aud.stats_by_user(last_n_events=3000)
        lines = ["<b>Сводка</b> (по последним событиям в журнале):"]
        if not rows:
            lines.append("<i>нет данных</i>")
        for user_id, cnt, username, display_name in rows[:30]:
            un = f"@{username}" if username else ""
            who = h(" ".join(x for x in (display_name, un) if x).strip() or "—")
            lines.append(f"• <code>{user_id}</code> {who}: <b>{cnt}</b> проверок")
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("« Меню", callback_data="adm:menu")]])
        await q.edit_message_text(
            "\n".join(lines),
            parse_mode=ParseMode.HTML,
            reply_markup=kb,
            disable_web_page_preview=True,
        )
        return

    if data == "adm:activity":
        kb = InlineKeyboardMarkup(
            [
                [InlineKeyboardButton("🔄 Обновить", callback_data="adm:activity")],
                [InlineKeyboardButton("« Меню", callback_data="adm:menu")],
            ]
        )
        await q.edit_message_text(
            _format_activity_report(context),
            parse_mode=ParseMode.HTML,
            reply_markup=kb,
            disable_web_page_preview=True,
        )
        return

    if data == "adm:limits":
        await q.edit_message_text(
            _limits_list_text(),
            parse_mode=ParseMode.HTML,
            reply_markup=_limits_list_keyboard(),
            disable_web_page_preview=True,
        )
        return

    if data == "adm:health":
        await q.edit_message_text(
            _format_health_report(context),
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup(
                [
                    [InlineKeyboardButton("🔄 Обновить", callback_data="adm:health")],
                    [InlineKeyboardButton("« Меню", callback_data="adm:menu")],
                ]
            ),
            disable_web_page_preview=True,
        )
        return

    if data == "adm:cache_clear":
        cache = context.application.bot_data.get("lookup_cache")
        n = cache.flush_all() if cache else 0
        await q.edit_message_text(
            f"🗑 Кэш lookups очищен: удалено <b>{n}</b> записей.",
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("« Меню", callback_data="adm:menu")]]
            ),
        )
        return

    if data.startswith("adm:cfg:"):
        key = data.split(":", 2)[2]
        if key not in EDITABLE_LIMIT_FIELDS:
            return
        context.user_data[ADMIN_PENDING_LIMIT_FIELD] = key
        cur = getattr(get_limits(), key)
        label = EDITABLE_LIMIT_FIELDS[key]
        await q.edit_message_text(
            f"<b>{h(label)}</b>\n\n"
            f"Текущее значение: <b>{cur}</b>\n"
            "Отправьте новое число одним сообщением.\n"
            "Отмена: /admin",
            parse_mode=ParseMode.HTML,
        )
        return


def _format_health_report(context: ContextTypes.DEFAULT_TYPE) -> str:
    import os
    import shutil
    from pathlib import Path

    from keys import abuseipdb_api_key, otx_api_key, vt_api_key

    lines = ["<b>🩺 Health</b>"]
    proxy = (os.environ.get("TG_SOCKS_PROXY") or "").strip()
    lines.append(f"• SOCKS: <code>{h(proxy or 'не задан')}</code>")
    lines.append(f"• VT ключ: {'✅' if vt_api_key() else '❌'}")
    lines.append(f"• OTX ключ: {'✅' if otx_api_key() else '❌'}")
    lines.append(f"• AbuseIPDB ключ: {'✅' if abuseipdb_api_key() else '❌'}")
    tshark = (os.environ.get("IP_CHECK_TSHARK") or "tshark").strip() or "tshark"
    tshark_path = shutil.which(tshark) or tshark
    lines.append(
        f"• tshark: <code>{h(tshark_path)}</code> "
        f"{'✅' if shutil.which(tshark) else '❌'}"
    )
    cache = context.application.bot_data.get("lookup_cache")
    if cache:
        st = cache.stats()
        kb = st["bytes"] / 1024
        lines.append(f"• Кэш lookups: <b>{st['entries']}</b> IP, {kb:.1f} KiB")
    else:
        lines.append("• Кэш lookups: —")
    aud = _audit(context)
    try:
        path = Path(aud._path)  # noqa: SLF001
        size = path.stat().st_size if path.is_file() else 0
        _, total = aud.read_recent(limit=1, offset=0)
        lines.append(f"• Audit: ~{total} событий, {size / 1024:.1f} KiB")
    except Exception:
        lines.append("• Audit: ?")
    lim = get_limits()
    lines.append(
        f"• Лимиты: max_ips={lim.max_ips_per_request}, "
        f"bulk_conc={lim.bulk_concurrency}, cache_ttl={lim.lookup_cache_ttl_hours}ч"
    )
    return "\n".join(lines)


# keep set_field path below — try_admin_runtime_limit_text follows in file
PLACEHOLDER_REMOVE = None


async def _unused_placeholder_adm_cfg_removed() -> None:
    return None


# --- runtime limit text handler stays below this point in original file ---


async def try_admin_runtime_limit_text_PLACEHOLDER():
    pass
    key = context.user_data.get(ADMIN_PENDING_LIMIT_FIELD)
    if not key:
        return False
    uid = update.effective_user.id if update.effective_user else None
    if not is_admin_user_id(context, uid):
        context.user_data.pop(ADMIN_PENDING_LIMIT_FIELD, None)
        return False
    msg = update.effective_message
    if not msg or not msg.text:
        return False
    text = msg.text.strip()
    if text.startswith("/"):
        context.user_data.pop(ADMIN_PENDING_LIMIT_FIELD, None)
        if text.split()[0].lower().startswith("/admin"):
            await cmd_admin(update, context)
        return True
    m = re.fullmatch(r"\d{1,6}", text)
    if not m:
        await msg.reply_html("Нужно целое число. Попробуйте снова или /admin.")
        return True
    value = int(text)
    context.user_data.pop(ADMIN_PENDING_LIMIT_FIELD, None)
    try:
        _runtime_cfg(context).set_field(key, value)
    except ValueError:
        await msg.reply_html("Неизвестный параметр.")
        return True
    label = EDITABLE_LIMIT_FIELDS.get(key, key)
    await msg.reply_html(
        f"<b>{h(label)}</b> → <b>{value}</b> (применено без перезапуска).\n/admin — меню.",
        reply_markup=admin_menu_keyboard(),
    )
    return True


async def try_admin_add_user_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """
    Обработка текста «ожидаем user id» для админа.
    Возвращает True, если сообщение обработано (не передавать в проверку IP).
    """
    if await try_admin_runtime_limit_text(update, context):
        return True
    if not context.user_data.get(ADMIN_PENDING_ADD):
        return False
    uid = update.effective_user.id if update.effective_user else None
    if not is_admin_user_id(context, uid):
        context.user_data.pop(ADMIN_PENDING_ADD, None)
        return False

    msg = update.effective_message
    if not msg or not msg.text:
        return False

    text = msg.text.strip()
    if text.startswith("/"):
        _clear_admin_pending(context)
        if text.split()[0].lower().startswith("/admin"):
            await cmd_admin(update, context)
        return True

    m = re.fullmatch(r"\d{5,15}", text)
    if not m:
        await msg.reply_html(
            "Нужен числовой <b>user id</b> (только цифры, 5–15 знаков).\n"
            "Попробуйте снова или /admin для отмены."
        )
        return True

    new_id = int(text)
    context.user_data.pop(ADMIN_PENDING_ADD, None)
    acc = _access(context)
    ok, status = acc.add(new_id, added_by=uid, note="через /admin")
    await msg.reply_html(
        f"Пользователь <code>{new_id}</code>: <b>{h(status)}</b>.\n/admin — меню.",
        reply_markup=admin_menu_keyboard(),
    )
    return True
