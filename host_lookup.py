"""Домены и имена хостов, связанные с IP (PTR, VT, OTX, AbuseIPDB)."""

from __future__ import annotations

import asyncio
import os
import re
import socket
import httpx

from keys import otx_api_key, vt_api_key
from report_format import AbuseIPDBData, HostData

_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)


def _max_domains() -> int:
    from runtime_config import get_limits

    return get_limits().host_max_domains


def _tg_show_max() -> int:
    from runtime_config import get_limits

    return get_limits().host_tg_show


def normalize_hostname(raw: str, ip: str) -> str | None:
    s = (raw or "").strip().rstrip(".").lower()
    if not s or len(s) > 253 or s == ip.lower():
        return None
    if _IPV4_RE.match(s):
        return None
    if "." not in s:
        return None
    if s.endswith(".in-addr.arpa") or s.endswith(".ip6.arpa"):
        return None
    return s


def _uniq_cap(names: list[str], ip: str, *, cap: int) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in names:
        n = normalize_hostname(raw, ip)
        if not n or n in seen:
            continue
        seen.add(n)
        out.append(n)
        if len(out) >= cap:
            break
    return out


async def _ptr_lookup(ip: str) -> list[str]:
    try:
        host, aliases, _addr = await asyncio.to_thread(socket.gethostbyaddr, ip)
    except OSError:
        return []
    names: list[str] = []
    if host:
        names.append(host)
    if aliases:
        names.extend(aliases)
    return names


async def _fetch_vt_domains(client: httpx.AsyncClient, ip: str, api_key: str) -> list[str]:
    names: list[str] = []
    headers = {"x-apikey": api_key}

    try:
        r = await client.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers=headers,
            timeout=25.0,
        )
        if r.status_code == 404:
            pass
        elif r.is_success:
            attr = (r.json().get("data") or {}).get("attributes") or {}
            for rec in attr.get("last_dns_records") or []:
                if not isinstance(rec, dict):
                    continue
                if str(rec.get("type") or "").upper() == "PTR":
                    val = rec.get("value")
                    if isinstance(val, str):
                        names.append(val)
    except Exception:
        pass

    try:
        limit = min(40, _max_domains())
        r = await client.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions",
            headers=headers,
            params={"limit": limit},
            timeout=25.0,
        )
        if r.status_code == 404:
            return _uniq_cap(names, ip, cap=_max_domains())
        r.raise_for_status()
        for item in r.json().get("data") or []:
            if not isinstance(item, dict):
                continue
            attr = item.get("attributes") or {}
            hn = attr.get("host_name") or attr.get("hostname")
            if isinstance(hn, str) and hn:
                names.append(hn)
    except Exception:
        pass

    return _uniq_cap(names, ip, cap=_max_domains())


async def _fetch_otx_passive_dns(client: httpx.AsyncClient, ip: str, api_key: str) -> list[str]:
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/passive_dns"
    try:
        r = await client.get(url, headers={"X-OTX-API-KEY": api_key}, timeout=30.0)
        r.raise_for_status()
        j = r.json()
    except Exception:
        return []

    names: list[str] = []
    for key in ("passive_dns", "data"):
        block = j.get(key)
        if isinstance(block, list):
            for row in block:
                if not isinstance(row, dict):
                    continue
                hn = row.get("hostname") or row.get("domain") or row.get("host")
                if isinstance(hn, str) and hn:
                    names.append(hn)
        elif isinstance(block, dict):
            inner = block.get("passive_dns")
            if isinstance(inner, list):
                for row in inner:
                    if isinstance(row, dict):
                        hn = row.get("hostname") or row.get("domain")
                        if isinstance(hn, str) and hn:
                            names.append(hn)

    return _uniq_cap(names, ip, cap=_max_domains())


def _domains_from_abuse(abuse: AbuseIPDBData | None, ip: str) -> list[str]:
    if abuse is None or not abuse.ok:
        return []
    raw: list[str] = []
    if abuse.domain:
        raw.append(abuse.domain)
    raw.extend(abuse.hostnames)
    return _uniq_cap(raw, ip, cap=_max_domains())


async def fetch_host_data(
    client: httpx.AsyncClient,
    ip: str,
    *,
    vt_enabled: bool,
    otx_enabled: bool,
    abuse: AbuseIPDBData | None,
) -> HostData | None:
    cap = _max_domains()
    by_source: dict[str, list[str]] = {}

    async def ptr_task() -> None:
        got = _uniq_cap(await _ptr_lookup(ip), ip, cap=cap)
        if got:
            by_source["PTR (reverse DNS)"] = got

    async def vt_task() -> None:
        if not vt_enabled:
            return
        key = vt_api_key()
        if not key:
            return
        got = await _fetch_vt_domains(client, ip, key)
        if got:
            by_source["VirusTotal"] = got

    async def otx_task() -> None:
        if not otx_enabled:
            return
        key = otx_api_key()
        if not key:
            return
        got = await _fetch_otx_passive_dns(client, ip, key)
        if got:
            by_source["OTX passive DNS"] = got

    await asyncio.gather(ptr_task(), vt_task(), otx_task())

    abuse_got = _domains_from_abuse(abuse, ip)
    if abuse_got:
        by_source["AbuseIPDB"] = abuse_got

    merged: list[str] = []
    seen: set[str] = set()
    for src in ("PTR (reverse DNS)", "VirusTotal", "OTX passive DNS", "AbuseIPDB"):
        for d in by_source.get(src, []):
            if d not in seen:
                seen.add(d)
                merged.append(d)
                if len(merged) >= cap:
                    break
        if len(merged) >= cap:
            break
    for src, lst in by_source.items():
        if src in ("PTR (reverse DNS)", "VirusTotal", "OTX passive DNS", "AbuseIPDB"):
            continue
        for d in lst:
            if d not in seen:
                seen.add(d)
                merged.append(d)
                if len(merged) >= cap:
                    break

    if not merged:
        return None
    return HostData(domains=merged, by_source=by_source)


def tg_show_max() -> int:
    return _tg_show_max()
