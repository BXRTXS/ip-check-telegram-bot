"""Последняя активность пользователей (для админки «кто онлайн»)."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class UserActivity:
    user_id: int
    last_seen_at: str
    username: str | None = None
    display_name: str = ""
    last_action: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ActivityStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = Lock()

    def touch(
        self,
        user_id: int,
        *,
        username: str | None,
        display_name: str,
        action: str,
    ) -> None:
        with self._lock:
            data = self._load()
            key = str(user_id)
            data[key] = UserActivity(
                user_id=user_id,
                last_seen_at=_utc_now_iso(),
                username=username,
                display_name=display_name,
                last_action=action,
            ).to_dict()
            self._save(data)

    def list_all(self) -> list[UserActivity]:
        with self._lock:
            data = self._load()
            out: list[UserActivity] = []
            for raw in data.values():
                if isinstance(raw, dict) and "user_id" in raw:
                    out.append(
                        UserActivity(
                            user_id=int(raw["user_id"]),
                            last_seen_at=str(raw.get("last_seen_at") or ""),
                            username=raw.get("username"),
                            display_name=str(raw.get("display_name") or ""),
                            last_action=str(raw.get("last_action") or ""),
                        )
                    )
            out.sort(key=lambda u: u.last_seen_at, reverse=True)
            return out

    def _load(self) -> dict[str, Any]:
        if not self._path.is_file():
            return {}
        try:
            with self._path.open(encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}
        if not isinstance(data, dict):
            return {}
        users = data.get("users")
        if isinstance(users, dict):
            return users
        return data if all(k.isdigit() for k in data.keys()) else {}

    def _save(self, users: dict[str, Any]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump({"users": users}, f, ensure_ascii=False, indent=2)
        tmp.replace(self._path)
