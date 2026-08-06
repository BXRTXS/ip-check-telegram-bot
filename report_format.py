"""Форматирование отчётов: детальный (1 IP) и компактный (массово)."""

from __future__ import annotations

import html
from dataclasses import dataclass, field


def h(s: str) -> str:
    return html.escape(s, quote=True)


def _flag_emoji(country_code: str) -> str:
    cc = (country_code or "").strip().upper()
    if len(cc) != 2 or not cc.isalpha():
        return ""
    a, b = ord(cc[0]) + 127397, ord(cc[1]) + 127397
    return chr(a) + chr(b)


@dataclass
class GeoData:
    ok: bool
    error: str | None = None
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    isp: str = ""
    org: str = ""
    as_raw: str = ""
    mobile: bool = False
    proxy: bool = False
    hosting: bool = False


@dataclass
class VTData:
    ok: bool
    error: str | None = None
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    reputation: int | None = None
    window_days: int = 30
    analysis_age_days: int | None = None
    stale: bool = False  # last_analysis старше окна — детекты обнулены


@dataclass
class OTXData:
    ok: bool
    error: str | None = None
    pulse_count: int = 0  # за окно window_days
    sample_names: list[str] = field(default_factory=list)
    window_days: int = 30
    pulse_count_total: int = 0  # всего в ответе OTX (без фильтра)


@dataclass
class HostData:
    """Домены/хосты за IP; в отчёт попадает только если список не пуст."""

    domains: list[str] = field(default_factory=list)
    by_source: dict[str, list[str]] = field(default_factory=dict)

    def has_any(self) -> bool:
        return bool(self.domains)


# ID → краткое имя (как на https://www.abuseipdb.com/categories)
ABUSE_CATEGORY_TITLES: dict[int, str] = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}

# Категории, которые явно подсвечиваем в сводке (DDoS, L7, скан и т.п.)
ABUSE_HIGHLIGHT_CATEGORY_IDS: frozenset[int] = frozenset(
    {4, 6, 10, 14, 15, 16, 18, 19, 20, 21, 22}
)


def abuse_category_title(cid: int) -> str:
    return ABUSE_CATEGORY_TITLES.get(cid, f"#{cid}")


def abuse_format_category_tags(ids: list[int]) -> str:
    if not ids:
        return "—"
    parts = [abuse_category_title(int(c)) for c in ids if c is not None]
    return ", ".join(parts) if parts else "—"


@dataclass
class AbuseReportRow:
    reported_at: str
    categories: list[int]
    comment: str
    reporter_country_code: str = ""
    reporter_country_name: str = ""


@dataclass
class AbuseIPDBData:
    """Поля total_reports / numDistinctUsers — за окно max_age_days (как в UI AbuseIPDB)."""

    ok: bool
    error: str | None = None
    abuse_confidence_score: int = 0
    total_reports: int = 0
    num_distinct_users: int = 0
    last_reported_at: str | None = None
    max_age_days: int = 365
    domain: str | None = None
    hostnames: list[str] = field(default_factory=list)
    reports: list[AbuseReportRow] = field(default_factory=list)
    category_counts: dict[int, int] = field(default_factory=dict)


def abuse_build_category_counts(reports: list[AbuseReportRow]) -> dict[int, int]:
    out: dict[int, int] = {}
    for row in reports:
        for c in row.categories:
            out[c] = out.get(c, 0) + 1
    return dict(sorted(out.items(), key=lambda x: (-x[1], x[0])))


@dataclass
class RIPEstatData:
    """RIPEstat: lines — кратко для Telegram; full_text — полный блок для .txt."""

    ok: bool
    error: str | None = None
    lines: list[str] = field(default_factory=list)
    full_text: str = ""
    primary_asn: int | None = None


def geo_from_ip_api(j: dict) -> GeoData:
    if j.get("status") == "fail":
        return GeoData(ok=False, error=str(j.get("message") or "fail"))
    return GeoData(
        ok=True,
        country=str(j.get("country") or ""),
        country_code=str(j.get("countryCode") or ""),
        region=str(j.get("regionName") or ""),
        city=str(j.get("city") or ""),
        isp=str(j.get("isp") or ""),
        org=str(j.get("org") or ""),
        as_raw=str(j.get("as") or ""),
        mobile=bool(j.get("mobile")),
        proxy=bool(j.get("proxy")),
        hosting=bool(j.get("hosting")),
    )


def _geo_one_line_plain(g: GeoData) -> str:
    """Одна строка гео без HTML (для &lt;pre&gt;)."""
    if not g.ok:
        return g.error or "geo?"
    fe = _flag_emoji(g.country_code)
    cc = g.country_code or "??"
    loc = " · ".join(x for x in (g.city, g.region) if x) or "—"
    isp = g.isp or g.org or "—"
    return f"{fe}{cc} {loc} · {isp}".strip()


def _threat_intel_score(
    vt: VTData,
    otx: OTXData,
    abuse: AbuseIPDBData | None,
) -> tuple[int, list[str]]:
    """Баллы только по VT, OTX, AbuseIPDB (реальные сигналы угроз)."""
    score = 0
    reasons: list[str] = []

    if abuse and abuse.ok:
        if abuse.abuse_confidence_score:
            score += min(abuse.abuse_confidence_score // 2, 40)
            reasons.append(f"AbuseIPDB confidence {abuse.abuse_confidence_score}%")
        if abuse.total_reports:
            score += min(abuse.total_reports * 2, 25)
            reasons.append(
                f"AbuseIPDB {abuse.total_reports} жалоб / {abuse.num_distinct_users} источников "
                f"({abuse.max_age_days} дн.)"
            )

    if vt.ok:
        if vt.malicious:
            add = min(25 * vt.malicious, 70)
            score += add
            reasons.append(f"VT malicious ×{vt.malicious}")
        if vt.suspicious:
            add = min(8 * vt.suspicious, 24)
            score += add
            reasons.append(f"VT suspicious ×{vt.suspicious}")
        if vt.reputation is not None and vt.reputation < 0:
            score += min(15, abs(vt.reputation) // 2)
            reasons.append(f"VT reputation {vt.reputation}")
    elif not vt.ok and vt.error:
        reasons.append(f"VT: {vt.error}")

    if otx.ok and otx.pulse_count:
        add = min(4 * otx.pulse_count, 35)
        score += add
        reasons.append(f"OTX pulses {otx.pulse_count}")

    return score, reasons


def _risk_heuristic(
    g: GeoData,
    vt: VTData,
    otx: OTXData,
    abuse: AbuseIPDBData | None = None,
) -> tuple[int, str, str]:
    """
    0–100: в первую очередь VT / OTX / AbuseIPDB.
    Флаги ip-api hosting/proxy не повышают оценку, если угроз нет
    (типичный VPS/DC без детектов).
    """
    threat, reasons = _threat_intel_score(vt, otx, abuse)
    infra: list[str] = []
    if g.ok:
        if g.hosting:
            infra.append("hosting (ip-api, DC)")
        if g.proxy:
            infra.append("proxy (ip-api)")
        if g.mobile and threat > 0:
            threat = max(0, threat - 8)
            reasons.append("mobile (снижает эвристику)")

    if threat == 0:
        score = 0
        if infra:
            reason_txt = " · ".join(
                infra + ["VT/OTX/Abuse без сигналов — оценка не завышена"]
            )
        else:
            reason_txt = " · ".join(reasons) if reasons else "явных сигналов мало"
    else:
        score = threat
        if g.ok:
            if g.hosting:
                score += 6
                reasons.append("hosting (ip-api)")
            if g.proxy:
                score += 8
                reasons.append("proxy (ip-api)")
        reason_txt = " · ".join(reasons) if reasons else "явных сигналов мало"

    score = max(0, min(100, int(score)))
    # Шкала 10 клеток пропорциональна оценке (раньше была фикс. длиной по tier).
    filled = 0 if score == 0 else min(10, max(1, (score + 9) // 10))
    if score < 18:
        verdict, on = "✅ низкий риск", "🟩"
    elif score < 45:
        verdict, on = "🟡 средний риск", "🟨"
    else:
        verdict, on = "🔴 повышенный риск", "🟥"
    bar = on * filled + "⬜" * (10 - filled)

    foot = f"{bar}\n<i>Факторы:</i> {h(reason_txt)}"
    if threat == 0 and infra:
        foot += (
            "\n<i>Хостинг/proxy у ip-api — справочно (часто VPS/датацентр), "
            "не штраф при чистых проверках.</i>"
        )
    return score, verdict, foot


_GEO_API_FIELDS = (
    "status,message,country,countryCode,regionName,city,isp,org,as,mobile,proxy,hosting,query"
)


def _hosts_html_lines(ip: str, hosts: HostData | None, *, show_max: int) -> list[str]:
    if not hosts or not hosts.has_any():
        return []
    lines: list[str] = [
        "",
        "🌐 <b>Домены / хосты за IP</b>",
        f"• Уникальных имён: <b>{len(hosts.domains)}</b> (PTR, passive DNS, VT, AbuseIPDB)",
    ]
    for d in hosts.domains[:show_max]:
        lines.append(f"  — <code>{h(d)}</code>")
    if len(hosts.domains) > show_max:
        lines.append(f"  — <i>…ещё {len(hosts.domains) - show_max} во вложении .txt</i>")
    lines.append(
        f'• <a href="https://www.virustotal.com/gui/ip-address/{h(ip)}/relations">VT resolutions</a> · '
        f'<a href="https://otx.alienvault.com/indicator/IPv4/{h(ip)}/passive_dns">OTX passive DNS</a>'
    )
    return lines


def _hosts_txt_lines(ip: str, hosts: HostData | None) -> list[str]:
    if not hosts or not hosts.has_any():
        return []
    out = [
        "--- Домены / хосты за IP ---",
        f"уникальных: {len(hosts.domains)}",
    ]
    for src, lst in hosts.by_source.items():
        out.append(f"[{src}] ({len(lst)})")
        for d in lst:
            out.append(f"  {d}")
    out.append(f"VT: https://www.virustotal.com/gui/ip-address/{ip}/relations")
    out.append(f"OTX: https://otx.alienvault.com/indicator/IPv4/{ip}/passive_dns")
    out.append("")
    return out


def build_detail_attachment_text(
    ip: str,
    g: GeoData,
    vt: VTData,
    otx: OTXData,
    abuse: AbuseIPDBData | None,
    ripe: RIPEstatData | None,
    *,
    hosts: HostData | None = None,
    flags_used: str,
) -> str:
    """Полный текстовый дамп без обрезки (для .txt)."""
    sep = "=" * 72
    out: list[str] = [
        "IP check — полный дамп",
        sep,
        f"IP: {ip}",
        f"Источники (настройки): {flags_used}",
        "",
    ]

    out.append("--- ip-api ---")
    if not g.ok:
        out.append(f"Ошибка: {g.error or '—'}")
    else:
        out.append(f"country: {g.country}")
        out.append(f"countryCode: {g.country_code}")
        out.append(f"regionName: {g.region}")
        out.append(f"city: {g.city}")
        out.append(f"isp: {g.isp}")
        out.append(f"org: {g.org}")
        out.append(f"as: {g.as_raw}")
        out.append(f"mobile: {g.mobile}, proxy: {g.proxy}, hosting: {g.hosting}")
    out.append(f"Запрос: http://ip-api.com/json/{ip}?fields={_GEO_API_FIELDS}")
    out.append("")
    out.extend(_hosts_txt_lines(ip, hosts))

    out.append("--- VirusTotal ---")
    if not vt.ok:
        out.append(vt.error or "—")
    else:
        out.append(
            f"malicious={vt.malicious} suspicious={vt.suspicious} "
            f"harmless={vt.harmless} undetected={vt.undetected} reputation={vt.reputation}"
        )
    out.append(f"API: https://www.virustotal.com/api/v3/ip_addresses/{ip}")
    out.append(f"Веб: https://www.virustotal.com/gui/ip-address/{ip}")
    out.append("")

    out.append("--- AlienVault OTX ---")
    if not otx.ok:
        out.append(otx.error or "—")
    else:
        out.append(f"pulse_count={otx.pulse_count}")
        for i, n in enumerate(otx.sample_names, 1):
            out.append(f"  {i}. {n}")
    out.append(f"API: https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general")
    out.append(f"Веб: https://otx.alienvault.com/indicator/IPv4/{ip}")
    out.append("")

    out.append("--- AbuseIPDB ---")
    if abuse is None:
        out.append("(не запрашивался)")
    elif not abuse.ok:
        out.append(abuse.error or "—")
    else:
        out.append(f"abuseConfidenceScore={abuse.abuse_confidence_score}")
        out.append(
            f"totalReports={abuse.total_reports} numDistinctUsers={abuse.num_distinct_users} "
            f"(окно {abuse.max_age_days} дн.)"
        )
        out.append(f"lastReportedAt={abuse.last_reported_at or '—'}")
        if abuse.category_counts:
            out.append("Сводка по категориям (сколько раз встречалась в жалобах):")
            for cid, cnt in abuse.category_counts.items():
                out.append(f"  [{cid}] {abuse_category_title(cid)}: ×{cnt}")
        out.append("")
        out.append(f"Жалобы в ответе API: {len(abuse.reports)} шт.")
        for i, rep in enumerate(abuse.reports, 1):
            out.append(f"--- report #{i} @ {rep.reported_at} ---")
            out.append(f"categories: {abuse_format_category_tags(rep.categories)}")
            if rep.reporter_country_code or rep.reporter_country_name:
                out.append(
                    f"reporter: {rep.reporter_country_code} {rep.reporter_country_name}".strip()
                )
            cmt = (rep.comment or "").strip() or "—"
            out.append(cmt)
    if abuse and abuse.ok:
        out.append(
            f"REST reports (пагинация): https://api.abuseipdb.com/api/v2/reports?ipAddress={ip}"
            f"&maxAgeInDays={abuse.max_age_days}&page=1&perPage=100"
        )
    out.append(f"Веб: https://www.abuseipdb.com/check/{ip}")
    out.append("")

    out.append("--- RIPEstat ---")
    if ripe is None:
        out.append("(не запрашивался)")
    elif not ripe.ok:
        out.append(ripe.error or "—")
    else:
        body = (ripe.full_text or "\n".join(ripe.lines)).strip()
        out.append(body if body else "(пусто)")
    out.append(
        f"prefix-overview JSON: https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}&min_peers_seeing=0"
    )
    if ripe and ripe.primary_asn is not None:
        out.append(
            f"asn-neighbours JSON: https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS{ripe.primary_asn}"
        )
    out.append("")

    score, verdict, _ = _risk_heuristic(g, vt, otx, abuse=abuse)
    out.append("--- Локальная эвристика ---")
    out.append(f"score={score}/100, verdict={verdict}")
    out.append(sep)
    return "\n".join(out)


def bulk_row_is_red(
    g: GeoData,
    vt: VTData,
    otx: OTXData,
    *,
    abuse: AbuseIPDBData | None = None,
) -> bool:
    """Красная зона для кнопки точечной проверки после массового режима."""
    score, verdict, _ = _risk_heuristic(g, vt, otx, abuse=abuse)
    if score >= 45 or "🔴" in verdict:
        return True
    if vt.ok and vt.malicious >= 1:
        return True
    if vt.ok and vt.suspicious >= 8:
        return True
    if otx.ok and otx.pulse_count >= 12:
        return True
    if abuse and abuse.ok and abuse.abuse_confidence_score >= 50:
        return True
    return False


def format_detailed_html(
    ip: str,
    g: GeoData,
    vt: VTData,
    otx: OTXData,
    *,
    abuse: AbuseIPDBData | None = None,
    ripe: RIPEstatData | None = None,
    hosts: HostData | None = None,
    flags_used: str,
    hosts_show_max: int = 20,
) -> str:
    fe = _flag_emoji(g.country_code) if g.ok else ""
    cc = f" ({h(g.country_code)})" if g.ok and g.country_code else ""

    lines: list[str] = [
        f"🔎 <b>IP</b>: <code>{h(ip)}</code>",
        "",
        f"<i>Источники: {h(flags_used)}.</i>",
        "",
    ]

    lines.append("📍 <b>Геолокация / ASN</b>")
    if not g.ok:
        lines.append(f"• Ошибка: {h(g.error or '—')}")
    else:
        lines.append(f"• Страна: {fe} {h(g.country)}{cc}".strip())
        lines.append(f"• Регион: {h(g.region or '—')}")
        lines.append(f"• Город: {h(g.city or '—')}")
        lines.append(f"• ISP: {h(g.isp or '—')}")
        if g.org:
            lines.append(f"• Org: {h(g.org)}")
        if g.as_raw:
            lines.append(f"• ASN: <code>{h(g.as_raw)}</code>")
        traits = []
        if g.mobile:
            traits.append("mobile")
        if g.proxy:
            traits.append("proxy")
        if g.hosting:
            traits.append("hosting/datacenter")
        lines.append(f"• Признаки ip-api: {h(', '.join(traits) if traits else 'нет')}")
    lines.append(
        f'• <a href="http://ip-api.com/json/{h(ip)}?fields={_GEO_API_FIELDS}">Сырой JSON ip-api</a>'
    )
    lines.extend(_hosts_html_lines(ip, hosts, show_max=hosts_show_max))

    lines.extend(["", "🛡 <b>VirusTotal</b>"])
    if not vt.ok:
        lines.append(f"• {h(vt.error or 'недоступно')}")
    else:
        lines.append(
            f"• Детекты: malicious <b>{vt.malicious}</b>, suspicious <b>{vt.suspicious}</b>, "
            f"harmless {vt.harmless}, undetected {vt.undetected}"
        )
        if vt.reputation is not None:
            lines.append(f"• Reputation: <b>{vt.reputation}</b>")
    lines.append(
        f'• <a href="https://www.virustotal.com/gui/ip-address/{h(ip)}">Страница VT</a> · '
        f'<a href="https://www.virustotal.com/api/v3/ip_addresses/{h(ip)}">REST (нужен ключ)</a>'
    )

    lines.extend(["", "🦠 <b>AlienVault OTX</b>"])
    if not otx.ok:
        lines.append(f"• {h(otx.error or 'недоступно')}")
    else:
        lines.append(f"• Pulses: <b>{otx.pulse_count}</b>")
        for n in otx.sample_names[:8]:
            lines.append(f"  — {h(n)}")
    lines.append(
        f'• <a href="https://otx.alienvault.com/indicator/IPv4/{h(ip)}">Страница OTX</a> · '
        f'<a href="https://otx.alienvault.com/api/v1/indicators/IPv4/{h(ip)}/general">JSON general</a>'
    )

    if abuse is not None:
        lines.extend(["", "🚨 <b>AbuseIPDB</b> <i>(только точечная проверка)</i>"])
        if not abuse.ok:
            lines.append(f"• {h(abuse.error or 'недоступно')}")
        else:
            lines.append(
                f"• За <b>{abuse.max_age_days}</b> дн. (как в API): "
                f"зарегистрировано <b>{abuse.total_reports}</b> жалоб "
                f"от <b>{abuse.num_distinct_users}</b> различных источников."
            )
            lines.append(f"• Abuse confidence: <b>{abuse.abuse_confidence_score}</b> %")
            if abuse.last_reported_at:
                lines.append(f"• Последняя жалоба: {h(abuse.last_reported_at)}")
            else:
                lines.append("• Последняя жалоба: нет данных")

            hi_parts: list[str] = []
            for cid in sorted(
                ABUSE_HIGHLIGHT_CATEGORY_IDS,
                key=lambda c: (-abuse.category_counts.get(c, 0), c),
            ):
                n = abuse.category_counts.get(cid, 0)
                if n:
                    label = abuse_category_title(cid)
                    hi_parts.append(f"<b>{h(label)}</b> ×{n}")
            if hi_parts:
                lines.append("• <b>Важные типы:</b> " + " · ".join(hi_parts))

            if abuse.category_counts:
                top = list(abuse.category_counts.items())[:10]
                rest = len(abuse.category_counts) - len(top)
                cat_line = " · ".join(
                    f"{h(abuse_category_title(cid))} ({cnt})" for cid, cnt in top
                )
                tail = f" …ещё {rest}" if rest > 0 else ""
                lines.append(f"• Все категории (топ-10): {cat_line}{h(tail) if tail else ''}")

            if abuse.reports:
                lines.append(f"• В ответе API — <b>{len(abuse.reports)}</b> записей жалоб (см. .txt).")
                for rep in abuse.reports[:5]:
                    cmt = (rep.comment or "").replace("\n", " ").strip()
                    if len(cmt) > 160:
                        cmt = cmt[:157] + "…"
                    tags = abuse_format_category_tags(rep.categories)
                    lines.append(
                        f"  — <code>{h(rep.reported_at[:19] if rep.reported_at else '?')}</code> "
                        f"[{h(tags)}] {h(cmt or '—')}"
                    )
                if len(abuse.reports) > 5:
                    lines.append(f"  — <i>…и ещё {len(abuse.reports) - 5} во вложении</i>")
            elif abuse.total_reports:
                lines.append(
                    "• <i>Массив reports пуст в ответе check — детали во вложении при дозагрузке /reports.</i>"
                )

        ma = abuse.max_age_days if abuse.ok else 365
        lines.append(
            f'• <a href="https://www.abuseipdb.com/check/{h(ip)}">Страница AbuseIPDB</a> · '
            f'<a href="https://api.abuseipdb.com/api/v2/check?ipAddress={h(ip)}&maxAgeInDays={ma}&verbose=">REST check+verbose</a>'
        )

    if ripe is not None:
        lines.extend(
            [
                "",
                "🌍 <b>RIPEstat</b> (RIPE NCC)",
                "• <a href=\"https://stat.ripe.net/docs/data_api\">Data API</a> · "
                '<a href="https://stat.ripe.net/docs/data-api/api-endpoints/asn-neighbours">asn-neighbours</a>',
            ]
        )
        if not ripe.ok:
            lines.append(f"• {h(ripe.error or 'недоступно')}")
        elif not ripe.lines:
            lines.append("• Нет кратких полей в ответе")
        else:
            for ln in ripe.lines:
                lines.append(f"• {h(ln)}")
        lines.append(
            f'• <a href="https://stat.ripe.net/data/prefix-overview/data.json?resource={h(ip)}&min_peers_seeing=0">prefix-overview JSON</a>'
        )
        if ripe.primary_asn is not None:
            lines.append(
                f'• <a href="https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS{ripe.primary_asn}">asn-neighbours JSON (AS{ripe.primary_asn})</a>'
            )

    score, verdict, bar_block = _risk_heuristic(g, vt, otx, abuse=abuse)
    lines.extend(
        [
            "",
            "📊 <b>Итог (локальная эвристика)</b>",
            f"• Оценка: <b>{score}</b>/100",
            f"• Вердикт: {verdict}",
            bar_block,
        ]
    )

    return "\n".join(lines)


def format_bulk_line_plain(ip: str, g: GeoData, vt: VTData, otx: OTXData, *, abuse_score: int | None = None) -> str:
    """Одна строка на IP, plain text (потом целиком в &lt;pre&gt; с h())."""
    geo_s = _geo_one_line_plain(g)
    if vt.ok:
        vt_s = f"VT m{vt.malicious}/s{vt.suspicious}"
    else:
        vt_s = "VT —"
    if otx.ok:
        otx_s = f"OTX {otx.pulse_count}"
    else:
        otx_s = "OTX —"
    abuse_obj = None
    if abuse_score is not None:
        abuse_obj = AbuseIPDBData(ok=True, abuse_confidence_score=abuse_score)
        ab_s = f"Abuse {abuse_score}"
    else:
        ab_s = None
    score, verdict, _ = _risk_heuristic(g, vt, otx, abuse=abuse_obj)
    vshort = verdict.split()[0] if verdict else "?"
    parts = [ip, geo_s, vt_s, otx_s]
    if ab_s:
        parts.append(ab_s)
    parts.append(f"{score}/100 {vshort}")
    return " │ ".join(parts)


def format_bulk_subnet_block(cidr: str, as_label: str, rows: list) -> list[str]:
    """Сводка по подсети + список IP."""
    typed = rows
    rep = next((r for r in typed if r.g.ok), typed[0])
    geo_s = _geo_one_line_plain(rep.g)
    max_score = 0
    max_verdict = "✅"
    max_mal = max_susp = max_otx = 0
    max_abuse = -1
    any_red = False
    for r in typed:
        ab = None
        if getattr(r, "abuse_score", None) is not None:
            ab = AbuseIPDBData(ok=True, abuse_confidence_score=int(r.abuse_score))
            max_abuse = max(max_abuse, int(r.abuse_score))
        sc, ver, _ = _risk_heuristic(r.g, r.vt, r.otx, abuse=ab)
        if sc > max_score:
            max_score = sc
            max_verdict = ver.split()[0] if ver else "?"
        if r.vt.ok:
            max_mal = max(max_mal, r.vt.malicious)
            max_susp = max(max_susp, r.vt.suspicious)
        if r.otx.ok:
            max_otx = max(max_otx, r.otx.pulse_count)
        if r.is_red:
            any_red = True

    vt_s = f"VT m{max_mal}/s{max_susp}" if any(r.vt.ok for r in typed) else "VT —"
    otx_s = f"OTX max {max_otx}" if any(r.otx.ok for r in typed) else "OTX —"
    ab_s = f"Abuse max {max_abuse}" if max_abuse >= 0 else None
    flag = " 🔴" if any_red else ""
    mid = f"{vt_s} │ {otx_s}"
    if ab_s:
        mid += f" │ {ab_s}"
    header = (
        f"▸ {cidr} ×{len(typed)} │ {as_label} │ {geo_s} │ "
        f"{mid} │ max {max_score}/100 {max_verdict}{flag}"
    )
    ips = [r.ip for r in typed]
    if len(ips) <= 12:
        ip_line = "  " + " · ".join(ips)
    else:
        ip_line = "  " + " · ".join(ips[:10]) + f" … +{len(ips) - 10}"
    return [header, ip_line]


def format_bulk_output(grouped: list) -> list[str]:
    """Строки для &lt;pre&gt;: группы подсетей + одиночные IP."""
    from bulk_subnet import BulkIpRow, BulkSubnetGroup, group_as_for_format

    lines: list[str] = []
    for item in grouped:
        if isinstance(item, BulkSubnetGroup):
            lines.extend(
                format_bulk_subnet_block(
                    str(item.network),
                    group_as_for_format(item),
                    item.rows,
                )
            )
        elif isinstance(item, BulkIpRow):
            lines.append(
                format_bulk_line_plain(
                    item.ip, item.g, item.vt, item.otx, abuse_score=item.abuse_score
                )
            )
    return lines


def bulk_rows_to_csv(rows: list) -> str:
    """CSV для массовой проверки (TSV-совместимый через запятую)."""
    import csv
    from io import StringIO

    buf = StringIO()
    w = csv.writer(buf)
    w.writerow(
        [
            "ip",
            "country",
            "city",
            "asn",
            "isp",
            "vt_malicious",
            "vt_suspicious",
            "otx_pulses",
            "abuse_score",
            "score",
            "verdict",
            "is_red",
        ]
    )
    for r in rows:
        ab = None
        if getattr(r, "abuse_score", None) is not None:
            ab = AbuseIPDBData(ok=True, abuse_confidence_score=int(r.abuse_score))
        score, verdict, _ = _risk_heuristic(r.g, r.vt, r.otx, abuse=ab)
        g = r.g
        w.writerow(
            [
                r.ip,
                g.country if g.ok else "",
                g.city if g.ok else "",
                g.as_raw if g.ok else "",
                g.isp if g.ok else "",
                r.vt.malicious if r.vt.ok else "",
                r.vt.suspicious if r.vt.ok else "",
                r.otx.pulse_count if r.otx.ok else "",
                r.abuse_score if r.abuse_score is not None else "",
                score,
                verdict.split()[0] if verdict else "",
                "1" if r.is_red else "0",
            ]
        )
    return buf.getvalue()


def pack_pre_chunks(
    lines: list[str],
    total: int,
    *,
    subnet_groups: int = 0,
    max_inner: int = 3400,
) -> list[str]:
    """Несколько &lt;pre&gt; блоков по лимиту Telegram (plain lines → h)."""
    chunks: list[str] = []
    cur: list[str] = []
    cur_len = 0
    sep = "\n"
    first_header = True

    def flush() -> None:
        nonlocal first_header, cur_len
        if not cur:
            return
        inner = h(sep.join(cur))
        if first_header:
            extra = f", {subnet_groups} подсетей" if subnet_groups else ""
            chunks.append(
                f"⚡ <b>Массовая проверка</b> — {total} IP{extra}\n<pre>{inner}</pre>"
            )
            first_header = False
        else:
            chunks.append(f"⚡ <i>продолжение</i>\n<pre>{inner}</pre>")
        cur.clear()
        cur_len = 0

    for line in lines:
        add = len(line) + (len(sep) if cur else 0)
        if cur and cur_len + add > max_inner:
            flush()
        if cur:
            cur_len += len(sep) + len(line)
        else:
            cur_len = len(line)
        cur.append(line)
    flush()
    return chunks
