"""Авто-проверка Src IP из дампа: подсети, AS, geo, VT/OTX + статистика pcap."""

from __future__ import annotations

from dataclasses import dataclass, field
from html import escape

from bulk_subnet import BulkIpRow, BulkSubnetGroup, group_as_for_format, group_bulk_by_subnet
from lookups import LookupFlags, fetch_bulk_rows
from mitigator_analyze import IpBlockStats
from report_format import _geo_one_line_plain, _risk_heuristic


def h(s: str) -> str:
    return escape(s, quote=True)


@dataclass
class DumpSrcEnrichment:
    checked: int
    total_unique: int
    truncated: bool
    html_lines: list[str] = field(default_factory=list)
    txt_lines: list[str] = field(default_factory=list)
    red_ips: list[str] = field(default_factory=list)


def _stats_map(stats: list[IpBlockStats]) -> dict[str, IpBlockStats]:
    return {st.ip: st for st in stats}


def _pcap_agg(rows: list[BulkIpRow], smap: dict[str, IpBlockStats]) -> tuple[int, int]:
    drop = total = 0
    for r in rows:
        st = smap.get(r.ip)
        if st:
            drop += st.dropped
            total += st.total
    return drop, total


def _ip_pcap_plain(ip: str, smap: dict[str, IpBlockStats]) -> str:
    st = smap.get(ip)
    if not st:
        return ip
    cm = st.top_countermeasures[0][0] if st.top_countermeasures else "?"
    if len(cm) > 28:
        cm = cm[:25] + "…"
    return f"{ip} ({st.dropped}/{st.total} drop · {cm})"


def _format_subnet_block(
    cidr: str,
    as_label: str,
    rows: list[BulkIpRow],
    smap: dict[str, IpBlockStats],
    *,
    html: bool,
) -> list[str]:
    rep = next((r for r in rows if r.g.ok), rows[0])
    geo_s = _geo_one_line_plain(rep.g)
    max_score = 0
    max_verdict = "✅"
    max_mal = max_susp = max_otx = 0
    any_red = False
    for r in rows:
        sc, ver, _ = _risk_heuristic(r.g, r.vt, r.otx)
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

    drop, total = _pcap_agg(rows, smap)
    vt_s = f"VT m{max_mal}/s{max_susp}" if any(r.vt.ok for r in rows) else "VT —"
    otx_s = f"OTX max {max_otx}" if any(r.otx.ok for r in rows) else "OTX —"
    red = " 🔴" if any_red else ""

    if html:
        header = (
            f"▸ <code>{h(cidr)}</code> ×{len(rows)} │ {h(as_label)} │ {h(geo_s)} │ "
            f"{h(vt_s)} │ {h(otx_s)} │ pcap drop <b>{drop}/{total}</b> │ "
            f"max {max_score}/100 {h(max_verdict)}{red}"
        )
        details = []
        for r in rows[:12]:
            st = smap.get(r.ip)
            if st:
                cm = st.top_countermeasures[0][0] if st.top_countermeasures else "?"
                details.append(
                    f"<code>{h(r.ip)}</code> ({st.dropped}/{st.total} · {h(cm[:32])})"
                )
            else:
                details.append(f"<code>{h(r.ip)}</code>")
        if len(rows) > 12:
            details.append(f"<i>… +{len(rows) - 12} IP</i>")
        return [header, "  " + " · ".join(details)]
    header = (
        f"▸ {cidr} ×{len(rows)} │ {as_label} │ {geo_s} │ "
        f"{vt_s} │ {otx_s} │ pcap drop {drop}/{total} │ max {max_score}/100 {max_verdict}{red}"
    )
    parts = [_ip_pcap_plain(r.ip, smap) for r in rows[:12]]
    if len(rows) > 12:
        parts.append(f"… +{len(rows) - 12}")
    return [header, "  " + " · ".join(parts)]


def _format_single_row(row: BulkIpRow, smap: dict[str, IpBlockStats], *, html: bool) -> str:
    from report_format import format_bulk_line_plain

    base = format_bulk_line_plain(
        row.ip, row.g, row.vt, row.otx, abuse_score=row.abuse_score
    )
    st = smap.get(row.ip)
    if not st:
        return base
    cm = st.top_countermeasures[0][0] if st.top_countermeasures else "?"
    pcap = f"pcap {st.dropped}/{st.total} drop · {cm[:28]}"
    if html:
        return f"{h(base)} │ {h(pcap)}"
    return f"{base} │ {pcap}"


def format_src_enrichment(
    grouped: list[BulkSubnetGroup | BulkIpRow],
    smap: dict[str, IpBlockStats],
    *,
    html: bool,
) -> list[str]:
    lines: list[str] = []
    for item in grouped:
        if isinstance(item, BulkSubnetGroup):
            lines.extend(
                _format_subnet_block(
                    str(item.network),
                    group_as_for_format(item),
                    item.rows,
                    smap,
                    html=html,
                )
            )
        elif isinstance(item, BulkIpRow):
            lines.append(_format_single_row(item, smap, html=html))
    return lines


async def build_src_enrichment(
    proxy_url: str | None,
    src_stats: list[IpBlockStats],
    flags: LookupFlags,
    *,
    limit: int,
    cache=None,
) -> DumpSrcEnrichment | None:
    return await build_side_enrichment(
        proxy_url, src_stats, flags, limit=limit, cache=cache
    )


async def build_side_enrichment(
    proxy_url: str | None,
    stats: list[IpBlockStats],
    flags: LookupFlags,
    *,
    limit: int,
    cache=None,
) -> DumpSrcEnrichment | None:
    if not stats or not proxy_url:
        return None

    unique: list[str] = []
    seen: set[str] = set()
    for st in stats:
        if st.ip not in seen:
            seen.add(st.ip)
            unique.append(st.ip)

    total_unique = len(unique)
    to_check = unique[:limit]
    truncated = total_unique > len(to_check)

    rows = await fetch_bulk_rows(proxy_url, to_check, flags, cache=cache)
    if not rows:
        return None

    smap = _stats_map(stats)
    grouped = group_bulk_by_subnet(rows)
    html_lines = format_src_enrichment(grouped, smap, html=True)
    txt_lines = format_src_enrichment(grouped, smap, html=False)
    red_ips = [r.ip for r in rows if r.is_red]

    return DumpSrcEnrichment(
        checked=len(to_check),
        total_unique=total_unique,
        truncated=truncated,
        html_lines=html_lines,
        txt_lines=txt_lines,
        red_ips=red_ips,
    )
