"""Лимиты и таймауты: defaults из env, правки админом в JSON без перезапуска."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from threading import Lock
from typing import Any


def _env_int(name: str, default: int, *, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(os.environ.get(name, str(default)))))
    except ValueError:
        return default


@dataclass
class RuntimeLimits:
    max_ips_per_request: int = 80
    max_txt_mb: int = 2
    red_buttons_max: int = 20
    bulk_concurrency: int = 12
    audit_max_lines: int = 5000
    audit_ips_max: int = 80
    host_max_domains: int = 80
    host_tg_show: int = 20
    abuse_max_age_days: int = 30
    abuse_report_pages_max: int = 200
    dump_max_mb: int = 15
    dump_timeout_sec: int = 90
    dump_zip_max_mb: int = 50
    dump_zip_max_files: int = 20
    online_idle_minutes: int = 15
    lookup_cache_ttl_hours: int = 24

    def to_dict(self) -> dict[str, int]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> RuntimeLimits:
        base = cls()
        fields = {f.name for f in base.__dataclass_fields__.values()}
        kw: dict[str, int] = {}
        for k, v in d.items():
            if k in fields:
                try:
                    kw[k] = int(v)
                except (TypeError, ValueError):
                    pass
        return cls(**{**base.to_dict(), **kw})

    @classmethod
    def from_env_defaults(cls) -> RuntimeLimits:
        return cls(
            max_ips_per_request=_env_int("IP_CHECK_MAX_IPS_PER_REQUEST", 80, lo=1, hi=500),
            max_txt_mb=_env_int("IP_CHECK_MAX_TXT_MB", 2, lo=1, hi=20),
            red_buttons_max=_env_int("IP_CHECK_RED_BUTTONS_MAX", 20, lo=1, hi=40),
            bulk_concurrency=_env_int("IP_CHECK_BULK_CONCURRENCY", 12, lo=1, hi=32),
            audit_max_lines=_env_int("IP_CHECK_AUDIT_MAX_LINES", 5000, lo=100, hi=50_000),
            audit_ips_max=_env_int("IP_CHECK_AUDIT_IPS_MAX", 80, lo=5, hi=200),
            host_max_domains=_env_int("IP_CHECK_HOST_MAX_DOMAINS", 80, lo=5, hi=500),
            host_tg_show=_env_int("IP_CHECK_HOST_TG_SHOW", 20, lo=3, hi=50),
            abuse_max_age_days=_env_int("IP_CHECK_ABUSE_MAX_AGE_DAYS", 30, lo=1, hi=365),
            abuse_report_pages_max=_env_int(
                "IP_CHECK_ABUSE_REPORT_PAGES_MAX", 200, lo=1, hi=500
            ),
            dump_max_mb=_env_int("IP_CHECK_DUMP_MAX_MB", 15, lo=1, hi=50),
            dump_timeout_sec=_env_int("IP_CHECK_DUMP_TIMEOUT_SEC", 90, lo=15, hi=300),
            dump_zip_max_mb=_env_int("IP_CHECK_DUMP_ZIP_MAX_MB", 50, lo=1, hi=100),
            dump_zip_max_files=_env_int("IP_CHECK_DUMP_ZIP_MAX_FILES", 20, lo=1, hi=30),
            online_idle_minutes=_env_int("IP_CHECK_ONLINE_IDLE_MINUTES", 15, lo=1, hi=120),
            lookup_cache_ttl_hours=_env_int("IP_CHECK_LOOKUP_CACHE_TTL_HOURS", 24, lo=1, hi=168),
        )


# Поля, которые админ может менять через /admin (ключ → подпись)
EDITABLE_LIMIT_FIELDS: dict[str, str] = {
    "max_ips_per_request": "Макс. IP за запрос",
    "max_txt_mb": "Макс. размер .txt (МБ)",
    "red_buttons_max": "Кнопок 🔴 после массовой",
    "bulk_concurrency": "Параллельность массовой",
    "audit_max_lines": "Строк в audit.jsonl",
    "audit_ips_max": "IP в строке аудита",
    "host_max_domains": "Доменов за IP (лимит)",
    "host_tg_show": "Доменов в Telegram",
    "abuse_max_age_days": "Окно VT/OTX/Abuse (дней)",
    "dump_max_mb": "Дамп pcap: макс. МБ",
    "dump_timeout_sec": "Дамп: таймаут tshark (с)",
    "dump_zip_max_mb": "ZIP: макс. МБ",
    "dump_zip_max_files": "ZIP: макс. файлов",
    "online_idle_minutes": "«Онлайн» если активность (мин)",
    "lookup_cache_ttl_hours": "Кэш проверок IP (ч)",
}

_LIMIT_BOUNDS: dict[str, tuple[int, int]] = {
    "max_ips_per_request": (1, 500),
    "max_txt_mb": (1, 20),
    "red_buttons_max": (1, 40),
    "bulk_concurrency": (1, 32),
    "audit_max_lines": (100, 50_000),
    "audit_ips_max": (5, 200),
    "host_max_domains": (5, 500),
    "host_tg_show": (3, 50),
    "abuse_max_age_days": (1, 365),
    "dump_max_mb": (1, 50),
    "dump_timeout_sec": (15, 300),
    "dump_zip_max_mb": (1, 100),
    "dump_zip_max_files": (1, 30),
    "online_idle_minutes": (1, 120),
    "lookup_cache_ttl_hours": (1, 168),
}


class RuntimeConfigStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = Lock()

    def _load_raw(self) -> dict[str, Any]:
        if not self._path.is_file():
            return {}
        try:
            with self._path.open(encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, OSError):
            return {}

    def _save_raw(self, data: dict[str, Any]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        tmp.replace(self._path)

    def _limits_from_raw(self, raw: dict[str, Any]) -> RuntimeLimits:
        if not raw:
            return RuntimeLimits.from_env_defaults()
        return RuntimeLimits.from_dict(raw)

    def get(self) -> RuntimeLimits:
        with self._lock:
            raw = self._load_raw()
            if not raw:
                limits = RuntimeLimits.from_env_defaults()
                self._save_raw(limits.to_dict())
                return limits
            return self._limits_from_raw(raw)

    def set_field(self, key: str, value: int) -> RuntimeLimits:
        if key not in EDITABLE_LIMIT_FIELDS:
            raise ValueError(key)
        lo, hi = _LIMIT_BOUNDS.get(key, (1, 999_999))
        value = max(lo, min(hi, int(value)))
        with self._lock:
            # Не вызывать get() под тем же Lock — иначе deadlock (Lock не реентерабелен).
            cur = self._limits_from_raw(self._load_raw()).to_dict()
            cur[key] = value
            limits = RuntimeLimits.from_dict(cur)
            self._save_raw(limits.to_dict())
            return limits


_STORE: RuntimeConfigStore | None = None


def init_runtime_config(path: Path) -> RuntimeConfigStore:
    global _STORE
    _STORE = RuntimeConfigStore(path)
    _STORE.get()
    return _STORE


def get_limits() -> RuntimeLimits:
    if _STORE is None:
        return RuntimeLimits.from_env_defaults()
    return _STORE.get()
