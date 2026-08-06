"""Журнал проверок IP: кто, когда, сколько и какие адреса."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from typing import Any

from runtime_config import get_limits


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _parse_ts(ts: str) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


@dataclass
class AuditEvent:
    ts: str
    user_id: int
    username: str | None
    display_name: str
    ip_count: int
    mode: str
    source: str
    ips: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AuditEvent:
        ips_raw = d.get("ips")
        ips = [str(x) for x in ips_raw] if isinstance(ips_raw, list) else []
        return cls(
            ts=str(d.get("ts") or ""),
            user_id=int(d["user_id"]),
            username=str(d["username"]) if d.get("username") else None,
            display_name=str(d.get("display_name") or ""),
            ip_count=int(d.get("ip_count") or len(ips)),
            mode=str(d.get("mode") or "?"),
            source=str(d.get("source") or "?"),
            ips=ips,
        )


class AuditLog:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = Lock()

    def append(
        self,
        *,
        user_id: int,
        username: str | None,
        display_name: str,
        ips: list[str],
        mode: str,
        source: str,
    ) -> None:
        cap = get_limits().audit_ips_max
        stored_ips = ips[:cap]
        ev = AuditEvent(
            ts=_utc_now_iso(),
            user_id=user_id,
            username=username,
            display_name=display_name,
            ip_count=len(ips),
            mode=mode,
            source=source,
            ips=stored_ips,
        )
        line = json.dumps(ev.to_dict(), ensure_ascii=False)
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
            self._trim_if_needed()

    def _trim_if_needed(self) -> None:
        mx = get_limits().audit_max_lines
        if not self._path.is_file():
            return
        try:
            with self._path.open(encoding="utf-8") as f:
                lines = f.readlines()
        except OSError:
            return
        if len(lines) <= mx:
            return
        keep = lines[-mx:]
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            f.writelines(keep)
        tmp.replace(self._path)

    def read_recent(self, *, limit: int = 20, offset: int = 0) -> tuple[list[AuditEvent], int]:
        """Последние события (новые сверху). offset — пропуск с начала «новых»."""
        if not self._path.is_file():
            return [], 0
        with self._lock:
            try:
                with self._path.open(encoding="utf-8") as f:
                    lines = [ln for ln in f if ln.strip()]
            except OSError:
                return [], 0
        events: list[AuditEvent] = []
        for ln in reversed(lines):
            try:
                d = json.loads(ln)
            except json.JSONDecodeError:
                continue
            if isinstance(d, dict):
                events.append(AuditEvent.from_dict(d))
        total = len(events)
        start = offset
        end = offset + limit
        return events[start:end], total

    def stats_by_user(self, *, last_n_events: int = 2000) -> list[tuple[int, int, str | None, str]]:
        """user_id, checks_count, username, display_name — по последним N событиям."""
        events, _ = self.read_recent(limit=last_n_events, offset=0)
        counts: dict[int, int] = {}
        names: dict[int, tuple[str | None, str]] = {}
        for ev in events:
            counts[ev.user_id] = counts.get(ev.user_id, 0) + 1
            names[ev.user_id] = (ev.username, ev.display_name)
        rows = [(uid, counts[uid], names[uid][0], names[uid][1]) for uid in counts]
        rows.sort(key=lambda x: (-x[1], x[0]))
        return rows

    def count_ip_checks_last_hours(self, hours: float = 24.0) -> dict[int, int]:
        """Число проверок IP (detail/bulk) по user_id за последние N часов."""
        if not self._path.is_file():
            return {}
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        counts: dict[int, int] = {}
        with self._lock:
            try:
                with self._path.open(encoding="utf-8") as f:
                    lines = f.readlines()
            except OSError:
                return {}
        for ln in lines:
            ln = ln.strip()
            if not ln:
                continue
            try:
                d = json.loads(ln)
            except json.JSONDecodeError:
                continue
            if not isinstance(d, dict):
                continue
            mode = str(d.get("mode") or "")
            base_mode = mode.split("+", 1)[0]
            if base_mode not in ("detail", "bulk"):
                continue
            ts = _parse_ts(str(d.get("ts") or ""))
            if ts is None or ts < cutoff:
                continue
            try:
                uid = int(d["user_id"])
            except (KeyError, TypeError, ValueError):
                continue
            counts[uid] = counts.get(uid, 0) + 1
        return counts
