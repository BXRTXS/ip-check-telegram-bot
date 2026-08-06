"""Уже отправленные админам уведомления о неизвестных user id."""

from __future__ import annotations

import json
from pathlib import Path
from threading import Lock


class DeniedNotifyStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = Lock()

    def _load(self) -> set[int]:
        if not self._path.is_file():
            return set()
        try:
            with self._path.open(encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return set()
        if isinstance(data, dict) and isinstance(data.get("notified"), list):
            out: set[int] = set()
            for x in data["notified"]:
                try:
                    out.add(int(x))
                except (TypeError, ValueError):
                    continue
            return out
        return set()

    def _save(self, ids: set[int]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump({"notified": sorted(ids)}, f, ensure_ascii=False, indent=2)
        tmp.replace(self._path)

    def already_notified(self, user_id: int) -> bool:
        with self._lock:
            return user_id in self._load()

    def mark_notified(self, user_id: int) -> None:
        with self._lock:
            ids = self._load()
            if user_id in ids:
                return
            ids.add(user_id)
            self._save(ids)
