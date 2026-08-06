"""Белый список пользователей бота (дополняет IP_CHECK_ALLOWED_USER_IDS из env)."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class AllowedUser:
    user_id: int
    added_at: str
    added_by: int | None = None
    note: str = ""
    username: str | None = None
    display_name: str | None = None
    last_seen_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AllowedUser:
        return cls(
            user_id=int(d["user_id"]),
            added_at=str(d.get("added_at") or _utc_now_iso()),
            added_by=int(d["added_by"]) if d.get("added_by") is not None else None,
            note=str(d.get("note") or ""),
            username=str(d["username"]) if d.get("username") else None,
            display_name=str(d["display_name"]) if d.get("display_name") else None,
            last_seen_at=str(d["last_seen_at"]) if d.get("last_seen_at") else None,
        )


def parse_user_ids_csv(raw: str | None) -> set[int]:
    if not raw or not raw.strip():
        return set()
    out: set[int] = set()
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            out.add(int(part))
        except ValueError:
            continue
    return out


class AccessStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = Lock()

    def _load(self) -> dict[str, Any]:
        if not self._path.is_file():
            return {"users": {}}
        try:
            with self._path.open(encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return {"users": {}}
        if not isinstance(data, dict):
            return {"users": {}}
        if "users" not in data or not isinstance(data["users"], dict):
            data["users"] = {}
        return data

    def _save(self, data: dict[str, Any]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        tmp.replace(self._path)

    def seed_from_env_if_empty(self, env_ids: set[int], *, added_by: int | None) -> int:
        """Один раз переносит IP_CHECK_ALLOWED_USER_IDS в JSON, если файл пуст."""
        if not env_ids:
            return 0
        with self._lock:
            data = self._load()
            users = data["users"]
            if users:
                return 0
            now = _utc_now_iso()
            for uid in sorted(env_ids):
                users[str(uid)] = AllowedUser(
                    user_id=uid,
                    added_at=now,
                    added_by=added_by,
                    note="из env (начальный импорт)",
                ).to_dict()
            self._save(data)
            return len(env_ids)

    def list_users(self) -> list[AllowedUser]:
        with self._lock:
            data = self._load()
            out: list[AllowedUser] = []
            for raw in data["users"].values():
                if isinstance(raw, dict) and "user_id" in raw:
                    out.append(AllowedUser.from_dict(raw))
            out.sort(key=lambda u: u.user_id)
            return out

    def stored_ids(self) -> set[int]:
        return {u.user_id for u in self.list_users()}

    def add(
        self,
        user_id: int,
        *,
        added_by: int | None,
        note: str = "",
        username: str | None = None,
        display_name: str | None = None,
    ) -> tuple[bool, str]:
        with self._lock:
            data = self._load()
            key = str(user_id)
            if key in data["users"]:
                return False, "уже в списке"
            data["users"][key] = AllowedUser(
                user_id=user_id,
                added_at=_utc_now_iso(),
                added_by=added_by,
                note=note.strip(),
                username=username,
                display_name=display_name,
            ).to_dict()
            self._save(data)
            return True, "добавлен"

    def remove(self, user_id: int) -> bool:
        with self._lock:
            data = self._load()
            key = str(user_id)
            if key not in data["users"]:
                return False
            del data["users"][key]
            self._save(data)
            return True

    def touch_profile(
        self,
        user_id: int,
        *,
        username: str | None,
        display_name: str | None,
    ) -> None:
        """Обновить @username / имя при активности (если пользователь в списке)."""
        with self._lock:
            data = self._load()
            key = str(user_id)
            raw = data["users"].get(key)
            if not isinstance(raw, dict):
                return
            now = _utc_now_iso()
            raw["last_seen_at"] = now
            if username:
                raw["username"] = username
            if display_name:
                raw["display_name"] = display_name
            self._save(data)


def env_allowed_user_ids() -> set[int]:
    return parse_user_ids_csv(os.environ.get("IP_CHECK_ALLOWED_USER_IDS"))


def env_admin_user_ids() -> set[int]:
    return parse_user_ids_csv(os.environ.get("IP_CHECK_ADMIN_USER_IDS"))
