"""Проверки IP: ip-api, VirusTotal, OTX; точечно — AbuseIPDB, RIPEstat."""

from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass

import httpx

from keys import abuseipdb_api_key, otx_api_key, vt_api_key
from host_lookup import fetch_host_data, tg_show_max
from bulk_subnet import BulkIpRow, BulkSubnetGroup, group_bulk_by_subnet
from lookup_cache import LookupCacheStore
from report_format import (
    AbuseIPDBData,
    AbuseReportRow,
    GeoData,
    HostData,
    OTXData,
    RIPEstatData,
    VTData,
    abuse_build_category_counts,
    bulk_row_is_red,
    build_detail_attachment_text,
    format_bulk_output,
    format_detailed_html,
    geo_from_ip_api,
    pack_pre_chunks,
)

IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)


def extract_ipv4s(text: str, *, limit: int) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for m in IPV4_RE.finditer(text):
        ip = m.group(0)
        if ip in seen:
            continue
        seen.add(ip)
        out.append(ip)
        if len(out) >= limit:
            break
    return out


@dataclass
class LookupFlags:
    geo: bool
    vt: bool
    otx: bool
    abuse: bool
    ripe: bool


_GEO_FIELDS = (
    "status,message,country,countryCode,regionName,city,isp,org,as,mobile,proxy,hosting,query"
)

_RIPE_HOLDER_SEM = asyncio.Semaphore(10)


async def _http_get_retry(
    client: httpx.AsyncClient,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict | None = None,
    timeout: float = 30.0,
    retries: int = 3,
) -> httpx.Response:
    """GET с повтором на 429/5xx; учитывает Retry-After."""
    last: httpx.Response | None = None
    for attempt in range(retries):
        last = await client.get(url, headers=headers, params=params, timeout=timeout)
        if last.status_code not in (429, 500, 502, 503, 504):
            return last
        if attempt >= retries - 1:
            break
        ra = last.headers.get("Retry-After") or last.headers.get("retry-after")
        delay = 1.5 * (2**attempt)
        if ra:
            try:
                delay = max(delay, float(ra))
            except ValueError:
                pass
        await asyncio.sleep(min(delay, 45.0))
    assert last is not None
    return last


async def _geo_batch_raw(client: httpx.AsyncClient, ips: list[str]) -> dict[str, GeoData]:
    out: dict[str, GeoData] = {}
    for start in range(0, len(ips), 100):
        chunk = ips[start : start + 100]
        body = [{"query": ip, "fields": _GEO_FIELDS} for ip in chunk]
        try:
            r = await client.post("http://ip-api.com/batch", json=body, timeout=60.0)
            r.raise_for_status()
            arr = r.json()
        except Exception as e:
            err = GeoData(ok=False, error=type(e).__name__)
            for ip in chunk:
                out[ip] = err
            continue
        if not isinstance(arr, list):
            err = GeoData(ok=False, error="bad_json")
            for ip in chunk:
                out[ip] = err
            continue
        for item in arr:
            if not isinstance(item, dict):
                continue
            q = item.get("query")
            if isinstance(q, str) and q:
                out[q] = geo_from_ip_api(item)
        for ip in chunk:
            out.setdefault(ip, GeoData(ok=False, error="нет в ответе"))
    return out


async def _geo_single(client: httpx.AsyncClient, ip: str) -> GeoData:
    url = "http://ip-api.com/json/" + ip + "?fields=" + _GEO_FIELDS
    try:
        r = await client.get(url, timeout=15.0)
        r.raise_for_status()
        return geo_from_ip_api(r.json())
    except Exception as e:
        return GeoData(ok=False, error=type(e).__name__)


async def _fetch_vt(client: httpx.AsyncClient, ip: str, api_key: str) -> VTData:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    try:
        r = await _http_get_retry(
            client, url, headers={"x-apikey": api_key}, timeout=30.0, retries=3
        )
        if r.status_code == 404:
            return VTData(ok=True, malicious=0, suspicious=0, harmless=0, undetected=0)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        return VTData(ok=False, error=type(e).__name__)

    attr = (data.get("data") or {}).get("attributes") or {}
    stats = attr.get("last_analysis_stats") or {}
    rep = attr.get("reputation")
    rep_i: int | None = None
    if rep is not None:
        try:
            rep_i = int(rep)
        except (TypeError, ValueError):
            try:
                rep_i = int(float(rep))
            except (TypeError, ValueError):
                rep_i = None
    return VTData(
        ok=True,
        malicious=int(stats.get("malicious") or 0),
        suspicious=int(stats.get("suspicious") or 0),
        harmless=int(stats.get("harmless") or 0),
        undetected=int(stats.get("undetected") or 0),
        reputation=rep_i,
    )


async def _fetch_otx(client: httpx.AsyncClient, ip: str, api_key: str) -> OTXData:
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    try:
        r = await _http_get_retry(
            client, url, headers={"X-OTX-API-KEY": api_key}, timeout=30.0, retries=3
        )
        r.raise_for_status()
        j = r.json()
    except Exception as e:
        return OTXData(ok=False, error=type(e).__name__)

    pulse = j.get("pulse_info") or {}
    count = int(pulse.get("count") or 0)
    names: list[str] = []
    pulses = pulse.get("pulses") or []
    if isinstance(pulses, list):
        for p in pulses[:200]:
            if isinstance(p, dict) and p.get("name"):
                names.append(str(p["name"]))
    return OTXData(ok=True, pulse_count=count, sample_names=names)


def _abuse_max_age_days() -> int:
    from runtime_config import get_limits

    return get_limits().abuse_max_age_days


def _abuse_report_pages_cap() -> int:
    from runtime_config import get_limits

    return get_limits().abuse_report_pages_max


def _parse_abuse_report_item(raw: object) -> AbuseReportRow | None:
    if not isinstance(raw, dict):
        return None
    cats: list[int] = []
    for c in raw.get("categories") or []:
        try:
            cats.append(int(c))
        except (TypeError, ValueError):
            continue
    return AbuseReportRow(
        reported_at=str(raw.get("reportedAt") or "").strip(),
        categories=cats,
        comment=str(raw.get("comment") or ""),
        reporter_country_code=str(raw.get("reporterCountryCode") or "").strip(),
        reporter_country_name=str(raw.get("reporterCountryName") or "").strip(),
    )


async def _fetch_abuse_report_pages(
    client: httpx.AsyncClient,
    ip: str,
    api_key: str,
    max_age: int,
    total_hint: int,
) -> list[AbuseReportRow]:
    """Догружаем жалобы, если в check+verbose пришло меньше, чем totalReports."""
    out: list[AbuseReportRow] = []
    per_page = 100
    max_pages = _abuse_report_pages_cap()
    need = max(total_hint, 0)

    for page in range(1, max_pages + 1):
        if need and len(out) >= need:
            break
        r = await _http_get_retry(
            client,
            "https://api.abuseipdb.com/api/v2/reports",
            params={"ipAddress": ip, "maxAgeInDays": max_age, "page": page, "perPage": per_page},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=45.0,
            retries=2,
        )
        r.raise_for_status()
        j = r.json()
        data = j.get("data") if isinstance(j, dict) else None
        if not isinstance(data, dict):
            break
        batch = data.get("results")
        if not isinstance(batch, list):
            break
        for item in batch:
            row = _parse_abuse_report_item(item)
            if row:
                out.append(row)
        if len(batch) < per_page:
            break
    return out


async def _fetch_abuseipdb(client: httpx.AsyncClient, ip: str, api_key: str) -> AbuseIPDBData:
    want = _abuse_max_age_days()
    candidates = [want]
    if want > 90:
        candidates.append(90)
    if want > 30:
        candidates.append(30)
    seen: set[int] = set()
    ages: list[int] = []
    for a in candidates:
        if a not in seen:
            seen.add(a)
            ages.append(a)

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}

    async def _check(age: int) -> httpx.Response:
        params = {"ipAddress": ip, "maxAgeInDays": age, "verbose": ""}
        return await _http_get_retry(
            client, url, params=params, headers=headers, timeout=35.0, retries=3
        )

    r: httpx.Response | None = None
    max_age = 30
    try:
        for age in ages:
            rr = await _check(age)
            if rr.status_code == 422:
                continue
            rr.raise_for_status()
            r = rr
            max_age = age
            break
        if r is None:
            return AbuseIPDBData(
                ok=False,
                error="AbuseIPDB 422 — сузьте IP_CHECK_ABUSE_MAX_AGE_DAYS (тариф API)",
            )
        j = r.json()
    except Exception as e:
        return AbuseIPDBData(ok=False, error=type(e).__name__)

    if isinstance(j, dict) and isinstance(j.get("errors"), list) and j["errors"]:
        parts: list[str] = []
        for e in j["errors"][:3]:
            if isinstance(e, dict):
                parts.append(str(e.get("detail") or e.get("title") or e))
            else:
                parts.append(str(e))
        return AbuseIPDBData(ok=False, error="; ".join(parts)[:220] if parts else "api_error")

    d = j.get("data") if isinstance(j, dict) else None
    if not isinstance(d, dict):
        return AbuseIPDBData(ok=False, error="bad_json")

    total = int(d.get("totalReports") or 0)
    lr = d.get("lastReportedAt")
    lr_s = str(lr) if lr else None

    rows: list[AbuseReportRow] = []
    raw_reports = d.get("reports")
    if isinstance(raw_reports, list):
        for item in raw_reports:
            row = _parse_abuse_report_item(item)
            if row:
                rows.append(row)

    if total > len(rows):
        try:
            rows = await _fetch_abuse_report_pages(client, ip, api_key, max_age, total)
        except Exception:
            pass

    counts = abuse_build_category_counts(rows)
    dom = d.get("domain")
    dom_s = str(dom).strip() if dom else None
    hn_list: list[str] = []
    raw_hn = d.get("hostnames")
    if isinstance(raw_hn, list):
        for x in raw_hn:
            if isinstance(x, str) and x.strip():
                hn_list.append(x.strip())

    return AbuseIPDBData(
        ok=True,
        abuse_confidence_score=int(d.get("abuseConfidenceScore") or 0),
        total_reports=total,
        num_distinct_users=int(d.get("numDistinctUsers") or 0),
        last_reported_at=lr_s,
        max_age_days=max_age,
        domain=dom_s,
        hostnames=hn_list,
        reports=rows,
        category_counts=counts,
    )


async def _fetch_abuseipdb_score_only(
    client: httpx.AsyncClient, ip: str, api_key: str
) -> AbuseIPDBData:
    """Лёгкий check без пагинации /reports — для bulk."""
    want = _abuse_max_age_days()
    ages = []
    for a in (want, 90, 30):
        if a not in ages and a > 0:
            ages.append(a)
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    try:
        r: httpx.Response | None = None
        max_age = 30
        for age in ages:
            rr = await _http_get_retry(
                client,
                url,
                params={"ipAddress": ip, "maxAgeInDays": age},
                headers=headers,
                timeout=25.0,
                retries=3,
            )
            if rr.status_code == 422:
                continue
            rr.raise_for_status()
            r = rr
            max_age = age
            break
        if r is None:
            return AbuseIPDBData(ok=False, error="AbuseIPDB 422")
        j = r.json()
    except Exception as e:
        return AbuseIPDBData(ok=False, error=type(e).__name__)

    if isinstance(j, dict) and isinstance(j.get("errors"), list) and j["errors"]:
        return AbuseIPDBData(ok=False, error="api_error")
    d = j.get("data") if isinstance(j, dict) else None
    if not isinstance(d, dict):
        return AbuseIPDBData(ok=False, error="bad_json")
    lr = d.get("lastReportedAt")
    return AbuseIPDBData(
        ok=True,
        abuse_confidence_score=int(d.get("abuseConfidenceScore") or 0),
        total_reports=int(d.get("totalReports") or 0),
        num_distinct_users=int(d.get("numDistinctUsers") or 0),
        last_reported_at=str(lr) if lr else None,
        max_age_days=max_age,
    )


def _ripe_asn_int(value: object) -> int | None:
    try:
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value
        s = str(value).strip()
        if s.upper().startswith("AS"):
            s = s[2:]
        return int(s)
    except (TypeError, ValueError):
        return None


async def _ripe_as_holder(client: httpx.AsyncClient, asn: int) -> str:
    try:
        r = await client.get(
            "https://stat.ripe.net/data/as-overview/data.json",
            params={"resource": f"AS{asn}"},
            timeout=18.0,
        )
        r.raise_for_status()
        d = (r.json().get("data") or {})
        if not isinstance(d, dict):
            return ""
        return str(d.get("holder") or "").strip()
    except Exception:
        return ""


async def _ripe_asn_neighbours(
    client: httpx.AsyncClient, asn: int
) -> tuple[list[dict], dict | None]:
    try:
        r = await client.get(
            "https://stat.ripe.net/data/asn-neighbours/data.json",
            params={"resource": f"AS{asn}"},
            timeout=22.0,
        )
        r.raise_for_status()
        j = r.json()
    except Exception:
        return [], None
    data = j.get("data") or {}
    if not isinstance(data, dict):
        return [], None
    raw = data.get("neighbours")
    neighbours = [x for x in raw if isinstance(x, dict)] if isinstance(raw, list) else []
    nc = data.get("neighbour_counts")
    nc_d = nc if isinstance(nc, dict) else None
    return neighbours, nc_d


async def _fetch_ripestat(client: httpx.AsyncClient, ip: str) -> RIPEstatData:
    """prefix-overview + as-overview + asn-neighbours (RIPE NCC)."""
    url = "https://stat.ripe.net/data/prefix-overview/data.json"
    try:
        r = await client.get(url, params={"resource": ip, "min_peers_seeing": 0}, timeout=25.0)
        r.raise_for_status()
        j = r.json()
    except Exception as e:
        return RIPEstatData(ok=False, error=type(e).__name__)

    data = j.get("data") or {}
    if not isinstance(data, dict):
        return RIPEstatData(ok=False, error="bad_json")

    lines: list[str] = []

    prefixes = data.get("prefixes")
    if isinstance(prefixes, list):
        for p in prefixes[:5]:
            if isinstance(p, dict) and p.get("prefix"):
                lines.append(f"Покрывающий префикс: {p.get('prefix')}")
            elif isinstance(p, str):
                lines.append(f"Покрывающий префикс: {p}")

    asn_ids: list[int] = []
    asns = data.get("asns")
    if isinstance(asns, list):
        for a in asns[:10]:
            if not isinstance(a, dict):
                continue
            ai = _ripe_asn_int(a.get("asn"))
            if ai is not None:
                asn_ids.append(ai)

    uniq_ann: list[int] = []
    for a in asn_ids:
        if a not in uniq_ann:
            uniq_ann.append(a)

    if not uniq_ann:
        if lines:
            ft = "\n".join(lines)
            return RIPEstatData(ok=True, lines=lines, full_text=ft, primary_asn=None)
        msg = "Нет AS в prefix-overview для этого IP"
        return RIPEstatData(ok=True, lines=[msg], full_text=msg, primary_asn=None)

    primary = uniq_ann[0]
    neighbours, nc_d = await _ripe_asn_neighbours(client, primary)

    def _neigh_sort_key(item: dict) -> tuple:
        typ = str(item.get("type") or item.get("position") or "").lower()
        if typ == "left":
            pri = 0
        elif typ == "right":
            pri = 1
        elif typ == "uncertain":
            pri = 2
        else:
            pri = 3
        power = int(item.get("power") or item.get("path_count") or 0)
        return (pri, -power)

    neigh_sorted = sorted([x for x in neighbours if isinstance(x, dict)], key=_neigh_sort_key)

    need_names: list[int] = list(uniq_ann[:5])
    for item in neigh_sorted:
        ni = _ripe_asn_int(item.get("asn") if item.get("asn") is not None else item.get("neighbour"))
        if ni is None or ni in need_names:
            continue
        need_names.append(ni)
        if len(need_names) >= 120:
            break

    holders = await asyncio.gather(*[_ripe_as_holder(client, a) for a in need_names])
    hm: dict[int, str] = {a: h for a, h in zip(need_names, holders)}

    lines.append("── Анонсирующие AS (prefix-overview) ──")
    for a in uniq_ann[:6]:
        hn = hm.get(a, "")
        lines.append(f"AS{a} — {hn}".strip(" —"))

    lines.append("")
    lines.append(f"── Соседи BGP для AS{primary} (asn-neighbours, данные RIS) ──")
    lines.append(
        "left / right — позиция соседа в AS_PATH относительно этого AS (термины RIPE). "
        "Часто left ближе к транзиту «вверх», right — к более специфичным/клиентским маршрутам; "
        "точный «апстрим» из одного только left не выводится — смотрите картину целиком."
    )

    if nc_d:
        lv = nc_d.get("left")
        rv = nc_d.get("right")
        if lv is not None or rv is not None:
            lines.append(f"Сводка neighbour_counts: left={lv}, right={rv}")

    neigh_row_strs: list[str] = []
    for item in neigh_sorted:
        ni = _ripe_asn_int(item.get("asn") if item.get("asn") is not None else item.get("neighbour"))
        if ni is None:
            continue
        typ = str(item.get("type") or item.get("position") or "?")
        power = int(item.get("power") or item.get("path_count") or 0)
        v4 = item.get("v4_peers")
        v6 = item.get("v6_peers")
        hnm = hm.get(ni, "")
        name = f" ({hnm})" if hnm else ""
        vpart = ""
        if v4 is not None or v6 is not None:
            vpart = f", v4/v6 peers: {v4}/{v6}"
        unc = " ⚠uncertain" if item.get("uncertain") else ""
        neigh_row_strs.append(f"{typ}: AS{ni}{name} — power {power}{vpart}{unc}")

    if not neigh_row_strs:
        lines.append("Нет записей asn-neighbours для этого AS (мало наблюдений RIS).")
        full_body = "\n".join(lines)
        return RIPEstatData(
            ok=True,
            lines=lines,
            full_text=full_body,
            primary_asn=primary,
        )

    full_lines = lines + neigh_row_strs
    if len(uniq_ann) > 1:
        rest = ", ".join(f"AS{x}" for x in uniq_ann[1:6])
        full_lines.append(f"Также в prefix-overview фигурируют: {rest}")

    full_text = "\n".join(full_lines)

    tg_neigh = neigh_row_strs[:3]
    lines.extend(tg_neigh)
    if len(neigh_row_strs) > 3:
        lines.append(f"… ещё {len(neigh_row_strs) - 3} соседей — полный список во вложении .txt")
    if len(uniq_ann) > 1:
        rest = ", ".join(f"AS{x}" for x in uniq_ann[1:6])
        lines.append(f"Также в prefix-overview фигурируют: {rest}")

    return RIPEstatData(ok=True, lines=lines, full_text=full_text, primary_asn=primary)


def _flags_label(flags: LookupFlags) -> str:
    parts = []
    if flags.geo:
        parts.append("ip-api")
    if flags.vt:
        parts.append("VirusTotal")
    if flags.otx:
        parts.append("OTX")
    if flags.abuse:
        parts.append("AbuseIPDB")
    if flags.ripe:
        parts.append("RIPEstat")
    return ", ".join(parts) if parts else "—"


async def _one_ip_intel(
    client: httpx.AsyncClient,
    ip: str,
    flags: LookupFlags,
    geo_pre: GeoData | None,
    sem: asyncio.Semaphore,
    cache: LookupCacheStore | None = None,
) -> tuple[str, GeoData, VTData, OTXData]:
    async with sem:
        cached = cache.get_fresh(ip) if cache else None
        to_save: dict[str, object] = {}

        if geo_pre is not None:
            g = geo_pre
        elif flags.geo and cached and cached.geo is not None:
            g = cached.geo
        elif flags.geo:
            g = await _geo_single(client, ip)
            to_save["geo"] = g
        else:
            g = GeoData(ok=False, error="выкл")

        vt_k = vt_api_key() if flags.vt else None
        otx_k = otx_api_key() if flags.otx else None

        if flags.vt and cached and cached.vt is not None:
            vt = cached.vt
        elif vt_k:

            async def vt_coro() -> VTData:
                return await _fetch_vt(client, ip, vt_k)

            vt = await vt_coro()
            to_save["vt"] = vt
        else:
            vt = VTData(ok=False, error="выкл / нет ключа")

        if flags.otx and cached and cached.otx is not None:
            otx = cached.otx
        elif otx_k:

            async def otx_coro() -> OTXData:
                return await _fetch_otx(client, ip, otx_k)

            otx = await otx_coro()
            to_save["otx"] = otx
        else:
            otx = OTXData(ok=False, error="выкл / нет ключа")

        if cache and to_save:
            cache.merge(ip, **to_save)  # type: ignore[arg-type]

        return ip, g, vt, otx


async def fetch_bulk_rows(
    proxy_url: str | None,
    ips: list[str],
    flags: LookupFlags,
    cache: LookupCacheStore | None = None,
) -> list[BulkIpRow]:
    """Массовая проверка: geo + VT + OTX для списка IP."""
    if not ips:
        return []
    limits = httpx.Limits(max_connections=24, max_keepalive_connections=12)
    transport = httpx.AsyncHTTPTransport(proxy=proxy_url) if proxy_url else None
    from runtime_config import get_limits

    sem = asyncio.Semaphore(get_limits().bulk_concurrency)

    async with httpx.AsyncClient(transport=transport, limits=limits, follow_redirects=True) as client:
        geo_map: dict[str, GeoData] = {}
        if flags.geo:
            need_geo: list[str] = []
            for ip in ips:
                c = cache.get_fresh(ip) if cache else None
                if c and c.geo is not None:
                    geo_map[ip] = c.geo
                else:
                    need_geo.append(ip)
            if need_geo:
                if len(need_geo) == 1:
                    g = await _geo_single(client, need_geo[0])
                    geo_map[need_geo[0]] = g
                    if cache:
                        cache.merge(need_geo[0], geo=g)
                else:
                    fetched = await _geo_batch_raw(client, need_geo)
                    geo_map.update(fetched)
                    if cache:
                        for ip, g in fetched.items():
                            cache.merge(ip, geo=g)

        async def row(ip: str) -> BulkIpRow:
            c = cache.get_fresh(ip) if cache else None
            if c and c.covers(geo=flags.geo, vt=flags.vt, otx=flags.otx):
                g = c.geo if flags.geo else GeoData(ok=False, error="выкл")
                vt = c.vt if flags.vt else VTData(ok=False, error="выкл / нет ключа")
                otx = c.otx if flags.otx else OTXData(ok=False, error="выкл / нет ключа")
                if g is None:
                    g = GeoData(ok=False, error="выкл")
                if vt is None:
                    vt = VTData(ok=False, error="выкл / нет ключа")
                if otx is None:
                    otx = OTXData(ok=False, error="выкл / нет ключа")
            else:
                _, g, vt, otx = await _one_ip_intel(
                    client, ip, flags, geo_map.get(ip), sem, cache=cache
                )
            is_red = bulk_row_is_red(g, vt, otx)
            return BulkIpRow(ip=ip, g=g, vt=vt, otx=otx, is_red=is_red)

        return list(await asyncio.gather(*[row(ip) for ip in ips]))


async def run_lookups_for_ips(
    proxy_url: str | None,
    ips: list[str],
    flags: LookupFlags,
    cache: LookupCacheStore | None = None,
) -> tuple[list[str], list[str], str | None, int]:
    """
    Возвращает (html_chunks, red_ips, detail_attachment_text, cached_count).
    """
    flabel = _flags_label(flags)

    if len(ips) > 1:
        n_cached = cache.count_bulk_cached(ips, flags) if cache else 0
        rows = await fetch_bulk_rows(proxy_url, ips, flags, cache=cache)
        grouped = group_bulk_by_subnet(rows)
        lines = format_bulk_output(grouped)
        red_ips = [r.ip for r in rows if r.is_red]
        n_subnets = sum(1 for g in grouped if isinstance(g, BulkSubnetGroup))
        return (
            pack_pre_chunks(lines, total=len(ips), subnet_groups=n_subnets),
            red_ips,
            None,
            n_cached,
        )

    ip = ips[0]
    cached = cache.get_fresh(ip) if cache else None
    if cached and cached.covers(
        geo=flags.geo,
        vt=flags.vt,
        otx=flags.otx,
        abuse=flags.abuse,
        ripe=flags.ripe,
        hosts=True,
    ):
        g = cached.geo if flags.geo else GeoData(ok=False, error="выкл")
        vt = cached.vt if flags.vt else VTData(ok=False, error="выкл / нет ключа")
        otx = cached.otx if flags.otx else OTXData(ok=False, error="выкл / нет ключа")
        abuse_fmt = cached.abuse if flags.abuse else None
        ripe_fmt = cached.ripe if flags.ripe else None
        hosts_fmt = cached.hosts
        if g is None:
            g = GeoData(ok=False, error="выкл")
        if vt is None:
            vt = VTData(ok=False, error="выкл / нет ключа")
        if otx is None:
            otx = OTXData(ok=False, error="выкл / нет ключа")
        hshow = tg_show_max()
        html = format_detailed_html(
            ip, g, vt, otx,
            abuse=abuse_fmt, ripe=ripe_fmt, hosts=hosts_fmt,
            flags_used=flabel, hosts_show_max=hshow,
        )
        att = build_detail_attachment_text(
            ip, g, vt, otx, abuse_fmt, ripe_fmt,
            hosts=hosts_fmt, flags_used=flabel,
        )
        return [html], [], att, 1

    limits = httpx.Limits(max_connections=24, max_keepalive_connections=12)
    transport = httpx.AsyncHTTPTransport(proxy=proxy_url) if proxy_url else None
    from runtime_config import get_limits

    sem = asyncio.Semaphore(get_limits().bulk_concurrency)

    async with httpx.AsyncClient(transport=transport, limits=limits, follow_redirects=True) as client:
        geo_map: dict[str, GeoData] = {}
        if flags.geo:
            if cached and cached.geo is not None:
                geo_map[ip] = cached.geo
            else:
                geo_map[ip] = await _geo_single(client, ip)
                if cache:
                    cache.merge(ip, geo=geo_map[ip])
        _, g, vt, otx = await _one_ip_intel(
            client, ip, flags, geo_map.get(ip), sem, cache=cache
        )

        async def maybe_abuse() -> AbuseIPDBData | None:
            if not flags.abuse:
                return None
            if cached and cached.abuse is not None:
                return cached.abuse
            k = abuseipdb_api_key()
            if not k:
                return None
            data = await _fetch_abuseipdb(client, ip, k)
            if cache:
                cache.merge(ip, abuse=data)
            return data

        async def maybe_ripe() -> RIPEstatData | None:
            if not flags.ripe:
                return None
            if cached and cached.ripe is not None:
                return cached.ripe
            data = await _fetch_ripestat(client, ip)
            if cache:
                cache.merge(ip, ripe=data)
            return data

        abuse_fmt, ripe_fmt = await asyncio.gather(maybe_abuse(), maybe_ripe())

        if cached and cached.hosts is not None:
            hosts_fmt = cached.hosts
        else:
            hosts_fmt = await fetch_host_data(
                client,
                ip,
                vt_enabled=flags.vt,
                otx_enabled=flags.otx,
                abuse=abuse_fmt,
            )
            if cache and hosts_fmt is not None:
                cache.merge(ip, hosts=hosts_fmt)
            elif cache:
                cache.merge(ip, hosts=HostData())

        hshow = tg_show_max()
        html = format_detailed_html(
            ip,
            g,
            vt,
            otx,
            abuse=abuse_fmt,
            ripe=ripe_fmt,
            hosts=hosts_fmt,
            flags_used=flabel,
            hosts_show_max=hshow,
        )
        att = build_detail_attachment_text(
            ip,
            g,
            vt,
            otx,
            abuse_fmt,
            ripe_fmt,
            hosts=hosts_fmt,
            flags_used=flabel,
        )
        return [html], [], att, 0
