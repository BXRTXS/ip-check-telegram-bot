"""Кэш результатов проверки IP (TTL по умолчанию 24 ч)."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from typing import Any

from report_format import (
    AbuseIPDBData,
    AbuseReportRow,
    GeoData,
    HostData,
    OTXData,
    RIPEstatData,
    VTData,
)

_STORE: LookupCacheStore | None = None


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _parse_ts(ts: str) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def _ttl_hours() -> float:
    from runtime_config import get_limits

    return float(get_limits().lookup_cache_ttl_hours)


@dataclass
class CachedIpLookup:
    cached_at: str
    geo: GeoData | None = None
    vt: VTData | None = None
    otx: OTXData | None = None
    abuse: AbuseIPDBData | None = None
    ripe: RIPEstatData | None = None
    hosts: HostData | None = None

    def is_expired(self) -> bool:
        ts = _parse_ts(self.cached_at)
        if ts is None:
            return True
        return datetime.now(timezone.utc) - ts > timedelta(hours=_ttl_hours())

    def covers(
        self,
        *,
        geo: bool,
        vt: bool,
        otx: bool,
        abuse: bool = False,
        ripe: bool = False,
        hosts: bool = False,
    ) -> bool:
        if geo and self.geo is None:
            return False
        if vt and self.vt is None:
            return False
        if otx and self.otx is None:
            return False
        if abuse and self.abuse is None:
            return False
        if ripe and self.ripe is None:
            return False
        if hosts and self.hosts is None:
            return False
        return True


def _abuse_to_dict(a: AbuseIPDBData) -> dict[str, Any]:
    d = asdict(a)
    d["category_counts"] = {str(k): v for k, v in (a.category_counts or {}).items()}
    return d


def _abuse_from_dict(d: dict[str, Any]) -> AbuseIPDBData:
    reports_raw = d.get("reports")
    reports: list[AbuseReportRow] = []
    if isinstance(reports_raw, list):
        for r in reports_raw:
            if isinstance(r, dict):
                reports.append(AbuseReportRow(**r))
    cc_raw = d.get("category_counts")
    cc: dict[int, int] = {}
    if isinstance(cc_raw, dict):
        for k, v in cc_raw.items():
            try:
                cc[int(k)] = int(v)
            except (TypeError, ValueError):
                pass
    return AbuseIPDBData(
        ok=bool(d.get("ok")),
        error=d.get("error"),
        abuse_confidence_score=int(d.get("abuse_confidence_score") or 0),
        total_reports=int(d.get("total_reports") or 0),
        num_distinct_users=int(d.get("num_distinct_users") or 0),
        last_reported_at=d.get("last_reported_at"),
        max_age_days=int(d.get("max_age_days") or 365),
        domain=d.get("domain"),
        hostnames=list(d.get("hostnames") or []),
        reports=reports,
        category_counts=cc,
    )


def _entry_to_dict(entry: CachedIpLookup) -> dict[str, Any]:
    out: dict[str, Any] = {"cached_at": entry.cached_at}
    if entry.geo is not None:
        out["geo"] = asdict(entry.geo)
    if entry.vt is not None:
        out["vt"] = asdict(entry.vt)
    if entry.otx is not None:
        out["otx"] = asdict(entry.otx)
    if entry.abuse is not None:
        out["abuse"] = _abuse_to_dict(entry.abuse)
    if entry.ripe is not None:
        out["ripe"] = asdict(entry.ripe)
    if entry.hosts is not None:
        out["hosts"] = asdict(entry.hosts)
    return out


def _entry_from_dict(d: dict[str, Any]) -> CachedIpLookup | None:
    if not isinstance(d, dict) or not d.get("cached_at"):
        return None
    geo = vt = otx = abuse = ripe = hosts = None
    if isinstance(d.get("geo"), dict):
        geo = GeoData(**d["geo"])
    if isinstance(d.get("vt"), dict):
        vt = VTData(**d["vt"])
    if isinstance(d.get("otx"), dict):
        otx = OTXData(**d["otx"])
    if isinstance(d.get("abuse"), dict):
        abuse = _abuse_from_dict(d["abuse"])
    if isinstance(d.get("ripe"), dict):
        ripe = RIPEstatData(**d["ripe"])
    if isinstance(d.get("hosts"), dict):
        h = d["hosts"]
        hosts = HostData(
            domains=list(h.get("domains") or []),
            by_source={str(k): list(v) for k, v in (h.get("by_source") or {}).items()},
        )
    return CachedIpLookup(
        cached_at=str(d["cached_at"]),
        geo=geo,
        vt=vt,
        otx=otx,
        abuse=abuse,
        ripe=ripe,
        hosts=hosts,
    )


class LookupCacheStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = Lock()

    def _load_all(self) -> dict[str, dict[str, Any]]:
        if not self._path.is_file():
            return {}
        try:
            with self._path.open(encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}
        if isinstance(data, dict) and isinstance(data.get("ips"), dict):
            return data["ips"]
        if isinstance(data, dict) and all(isinstance(k, str) for k in data.keys()):
            return data
        return {}

    def _save_all(self, ips: dict[str, dict[str, Any]]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump({"ips": ips}, f, ensure_ascii=False, indent=2)
        tmp.replace(self._path)

    def _purge_expired_unlocked(self, ips: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for ip, raw in ips.items():
            entry = _entry_from_dict(raw)
            if entry and not entry.is_expired():
                out[ip] = raw
        return out

    def get_fresh(self, ip: str) -> CachedIpLookup | None:
        with self._lock:
            raw = self._load_all().get(ip)
        if not raw:
            return None
        entry = _entry_from_dict(raw)
        if entry is None or entry.is_expired():
            return None
        return entry

    def count_bulk_cached(self, ips: list[str], flags) -> int:
        n = 0
        for ip in ips:
            e = self.get_fresh(ip)
            if e and e.covers(geo=flags.geo, vt=flags.vt, otx=flags.otx):
                n += 1
        return n

    def _apply_fields(
        self,
        entry: CachedIpLookup,
        *,
        geo: GeoData | None = None,
        vt: VTData | None = None,
        otx: OTXData | None = None,
        abuse: AbuseIPDBData | None = None,
        ripe: RIPEstatData | None = None,
        hosts: HostData | None = None,
    ) -> None:
        entry.cached_at = _utc_now_iso()
        if geo is not None:
            entry.geo = geo
        if vt is not None:
            entry.vt = vt
        if otx is not None:
            entry.otx = otx
        if abuse is not None:
            entry.abuse = abuse
        if ripe is not None:
            entry.ripe = ripe
        if hosts is not None:
            entry.hosts = hosts

    def merge(
        self,
        ip: str,
        *,
        geo: GeoData | None = None,
        vt: VTData | None = None,
        otx: OTXData | None = None,
        abuse: AbuseIPDBData | None = None,
        ripe: RIPEstatData | None = None,
        hosts: HostData | None = None,
    ) -> None:
        with self._lock:
            ips = self._purge_expired_unlocked(self._load_all())
            raw = ips.get(ip, {})
            entry = _entry_from_dict(raw) if raw else None
            if entry is None or entry.is_expired():
                entry = CachedIpLookup(cached_at=_utc_now_iso())
            self._apply_fields(
                entry, geo=geo, vt=vt, otx=otx, abuse=abuse, ripe=ripe, hosts=hosts
            )
            ips[ip] = _entry_to_dict(entry)
            self._save_all(ips)

    def merge_many(
        self,
        updates: dict[str, dict[str, Any]],
    ) -> None:
        """Одна запись на диск для пачки IP. Значения dict — поля geo/vt/otx/abuse/ripe/hosts."""
        if not updates:
            return
        with self._lock:
            ips = self._purge_expired_unlocked(self._load_all())
            for ip, fields in updates.items():
                if not isinstance(fields, dict):
                    continue
                raw = ips.get(ip, {})
                entry = _entry_from_dict(raw) if raw else None
                if entry is None or entry.is_expired():
                    entry = CachedIpLookup(cached_at=_utc_now_iso())
                self._apply_fields(
                    entry,
                    geo=fields.get("geo"),
                    vt=fields.get("vt"),
                    otx=fields.get("otx"),
                    abuse=fields.get("abuse"),
                    ripe=fields.get("ripe"),
                    hosts=fields.get("hosts"),
                )
                ips[ip] = _entry_to_dict(entry)
            self._save_all(ips)

    def flush_all(self) -> int:
        """Очистить кэш. Возвращает число удалённых записей."""
        with self._lock:
            n = len(self._load_all())
            self._save_all({})
            return n

    def stats(self) -> dict[str, Any]:
        with self._lock:
            ips = self._load_all()
            size = self._path.stat().st_size if self._path.is_file() else 0
            return {"entries": len(ips), "bytes": size, "path": str(self._path)}


def init_lookup_cache(path: Path) -> LookupCacheStore:
    global _STORE
    _STORE = LookupCacheStore(path)
    with _STORE._lock:
        ips = _STORE._purge_expired_unlocked(_STORE._load_all())
        _STORE._save_all(ips)
    return _STORE


def get_lookup_cache() -> LookupCacheStore | None:
    return _STORE
