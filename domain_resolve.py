"""Домен → IPv4: DNS A, при наличии ключей — VirusTotal и OTX."""

from __future__ import annotations

import asyncio
import re
import socket
from dataclasses import dataclass, field

import httpx

from keys import otx_api_key, vt_api_key

_IPV4_FULL = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

# hostname.tld (не IP, не in-addr.arpa)
_DOMAIN_TOKEN = re.compile(
    r"\b"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}"
    r"\b"
)


def normalize_domain(raw: str) -> str | None:
    s = (raw or "").strip().rstrip(".").lower()
    if not s or len(s) > 253 or "." not in s:
        return None
    if _IPV4_FULL.match(s):
        return None
    if s.endswith(".in-addr.arpa") or s.endswith(".ip6.arpa"):
        return None
    if s.startswith("xn--") and len(s) < 5:
        return None
    labels = s.split(".")
    if len(labels) < 2:
        return None
    for lab in labels:
        if not lab or len(lab) > 63:
            return None
        if lab.startswith("-") or lab.endswith("-"):
            return None
    if not re.fullmatch(r"[a-z0-9.-]+", s):
        return None
    return s


def extract_domains(text: str, *, limit: int) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for m in _DOMAIN_TOKEN.finditer(text or ""):
        d = normalize_domain(m.group(0))
        if not d or d in seen:
            continue
        seen.add(d)
        out.append(d)
        if len(out) >= limit:
            break
    return out


def _uniq_ips(names: list[str], *, cap: int = 32) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in names:
        s = (raw or "").strip()
        if not _IPV4_FULL.match(s) or s in seen:
            continue
        seen.add(s)
        out.append(s)
        if len(out) >= cap:
            break
    return out


async def _dns_a_records(domain: str) -> list[str]:
    def _sync() -> list[str]:
        try:
            infos = socket.getaddrinfo(
                domain,
                None,
                family=socket.AF_INET,
                type=socket.SOCK_STREAM,
            )
        except OSError:
            return []
        ips: list[str] = []
        seen: set[str] = set()
        for info in infos:
            ip = info[4][0]
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)
        return ips

    return await asyncio.to_thread(_sync)


async def _vt_domain_ips(client: httpx.AsyncClient, domain: str, api_key: str) -> list[str]:
    ips: list[str] = []
    headers = {"x-apikey": api_key}
    try:
        r = await client.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers=headers,
            timeout=25.0,
        )
        if r.status_code == 404:
            return []
        r.raise_for_status()
        data = r.json()
        attr = (data.get("data") or {}).get("attributes") or {}
        for rec in attr.get("last_dns_records") or []:
            if not isinstance(rec, dict):
                continue
            if str(rec.get("type") or "").upper() != "A":
                continue
            val = rec.get("value")
            if val:
                ips.append(str(val))
    except Exception:
        return []
    return ips


async def _otx_domain_ips(client: httpx.AsyncClient, domain: str, api_key: str) -> list[str]:
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    headers = {"X-OTX-API-KEY": api_key}
    ips: list[str] = []
    try:
        r = await client.get(url, headers=headers, timeout=25.0)
        if r.status_code == 404:
            return []
        r.raise_for_status()
        data = r.json()
    except Exception:
        return []
    blocks: list = []
    for key in ("passive_dns", "data"):
        raw = data.get(key)
        if isinstance(raw, list):
            blocks.extend(raw)
    for row in blocks:
        if not isinstance(row, dict):
            continue
        addr = row.get("address") or row.get("ip")
        if addr:
            ips.append(str(addr))
    return ips


@dataclass
class DomainResolveRow:
    domain: str
    ips: list[str] = field(default_factory=list)
    by_source: dict[str, list[str]] = field(default_factory=dict)
    error: str | None = None


async def _resolve_one(
    client: httpx.AsyncClient | None,
    domain: str,
    *,
    use_vt: bool,
    use_otx: bool,
) -> DomainResolveRow:
    by_source: dict[str, list[str]] = {}
    dns_ips = await _dns_a_records(domain)
    if dns_ips:
        by_source["DNS (A)"] = dns_ips

    if client and use_vt:
        key = vt_api_key()
        if key:
            got = await _vt_domain_ips(client, domain, key)
            if got:
                by_source["VirusTotal"] = _uniq_ips(got)

    if client and use_otx:
        key = otx_api_key()
        if key:
            got = await _otx_domain_ips(client, domain, key)
            if got:
                by_source["OTX passive DNS"] = _uniq_ips(got)

    merged: list[str] = []
    seen: set[str] = set()
    for src in ("DNS (A)", "VirusTotal", "OTX passive DNS"):
        for ip in by_source.get(src, []):
            if ip not in seen:
                seen.add(ip)
                merged.append(ip)

    err: str | None = None
    if not merged:
        err = "нет IPv4" if not by_source else "нет IPv4"
        if not dns_ips and not by_source:
            err = "DNS NXDOMAIN / нет ответа"

    return DomainResolveRow(domain=domain, ips=merged, by_source=by_source, error=err)


async def resolve_domains(
    domains: list[str],
    *,
    proxy_url: str | None,
    use_vt: bool,
    use_otx: bool,
) -> list[DomainResolveRow]:
    if not domains:
        return []

    limits = httpx.Limits(max_connections=16, max_keepalive_connections=8)
    transport = httpx.AsyncHTTPTransport(proxy=proxy_url) if proxy_url else None
    sem = asyncio.Semaphore(8)

    async def _one(d: str) -> DomainResolveRow:
        async with sem:
            if transport:
                async with httpx.AsyncClient(
                    transport=transport, limits=limits, follow_redirects=True
                ) as client:
                    return await _resolve_one(client, d, use_vt=use_vt, use_otx=use_otx)
            return await _resolve_one(None, d, use_vt=False, use_otx=False)

    return list(await asyncio.gather(*[_one(d) for d in domains]))


def format_domain_resolve_html(rows: list[DomainResolveRow]) -> str:
    from html import escape

    def he(s: str) -> str:
        return escape(s, quote=True)

    lines = ["<b>Домены → IPv4</b>"]
    for row in rows:
        if not row.ips:
            msg = row.error or "нет IPv4"
            lines.append(f"• <code>{he(row.domain)}</code> — <i>{he(msg)}</i>")
            continue
        parts = ", ".join(f"<code>{he(ip)}</code>" for ip in row.ips[:12])
        if len(row.ips) > 12:
            parts += f" <i>…+{len(row.ips) - 12}</i>"
        lines.append(f"• <code>{he(row.domain)}</code> → {parts}")
        extra: list[str] = []
        for src, lst in row.by_source.items():
            if src == "DNS (A)" or not lst:
                continue
            only = [ip for ip in lst if ip in row.ips]
            if only:
                extra.append(f"{he(src)}: {len(only)}")
        if extra:
            lines.append(f"  <i>{', '.join(extra)}</i>")
    return "\n".join(lines)
