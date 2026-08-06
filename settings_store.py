"""Персональные настройки пользователя (вкл/выкл сервисы)."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import Lock
from typing import Any


def _truthy(s: str | None, default: bool) -> bool:
    if s is None or s.strip() == "":
        return default
    return s.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class UserSettings:
    geo: bool
    vt: bool
    otx: bool
    abuse: bool
    ripe: bool

    def to_dict(self) -> dict[str, bool]:
        return asdict(self)


class SettingsStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = Lock()
        self._defaults = UserSettings(
            geo=_truthy(os.environ.get("IP_CHECK_DEFAULT_GEO"), True),
            vt=_truthy(os.environ.get("IP_CHECK_DEFAULT_VT"), True),
            otx=_truthy(os.environ.get("IP_CHECK_DEFAULT_OTX"), True),
            abuse=_truthy(os.environ.get("IP_CHECK_DEFAULT_ABUSE"), True),
            ripe=_truthy(os.environ.get("IP_CHECK_DEFAULT_RIPE"), True),
        )

    def _load_raw(self) -> dict[str, Any]:
        if not self._path.is_file():
            return {}
        try:
            with self._path.open(encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}

    def _save_raw(self, data: dict[str, Any]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        tmp.replace(self._path)

    def _settings_from_raw(self, raw: dict[str, Any], user_id: int) -> UserSettings:
        u = raw.get(str(user_id), {})
        return UserSettings(
            geo=bool(u.get("geo", self._defaults.geo)),
            vt=bool(u.get("vt", self._defaults.vt)),
            otx=bool(u.get("otx", self._defaults.otx)),
            abuse=bool(u.get("abuse", self._defaults.abuse)),
            ripe=bool(u.get("ripe", self._defaults.ripe)),
        )

    def get(self, user_id: int) -> UserSettings:
        with self._lock:
            return self._settings_from_raw(self._load_raw(), user_id)

    def set_field(self, user_id: int, field: str, value: bool) -> UserSettings:
        if field not in ("geo", "vt", "otx", "abuse", "ripe"):
            raise ValueError(field)
        with self._lock:
            raw = self._load_raw()
            key = str(user_id)
            cur = dict(raw.get(key, {}))
            cur[field] = value
            raw[key] = cur
            self._save_raw(raw)
            # Не вызывать get() под тем же Lock — иначе deadlock (Lock не реентерабелен).
            return self._settings_from_raw(raw, user_id)
