"""Сессии IP из Mitigator-дампа для массовой проверки по кнопке."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Literal

from ipaddress import IPv4Network

from telegram import InlineKeyboardButton, InlineKeyboardMarkup

from mitigator_analyze import IpBlockStats, MitigatorReport

DumpWhich = Literal["src", "dst", "src24", "dst24"]

_BATCH_TTL_SEC = 3600
_MAX_BATCHES = 40


@dataclass
class DumpIpBatch:
    token: str
    owner_user_id: int
    src_ips: list[str]
    dst_ips: list[str]
    filename: str
    created_at: float

    def ips_for(self, which: DumpWhich) -> list[str]:
        if which == "src":
            return self.src_ips
        if which == "dst":
            return self.dst_ips
        if which == "src24":
            return slash24_top_ips(self.src_ips)
        if which == "dst24":
            return slash24_top_ips(self.dst_ips)
        return []


def slash24_top_ips(ips: list[str], *, max_nets: int = 12, max_ips: int | None = None) -> list[str]:
    """Топ /24 по порядку списка (уже отсортирован по drop) → IP для bulk."""
    if max_ips is None:
        from runtime_config import get_limits

        max_ips = get_limits().max_ips_per_request
    seen_nets: list[str] = []
    net_ips: dict[str, list[str]] = {}
    for ip in ips:
        try:
            net = str(IPv4Network(f"{ip}/24", strict=False))
        except ValueError:
            continue
        if net not in net_ips:
            if len(seen_nets) >= max_nets:
                continue
            seen_nets.append(net)
            net_ips[net] = []
        net_ips[net].append(ip)
    out: list[str] = []
    for net in seen_nets:
        for ip in net_ips[net]:
            out.append(ip)
            if len(out) >= max_ips:
                return out
    return out


def ips_from_stats(stats: list[IpBlockStats]) -> list[str]:
    """Уникальные IPv4 в порядке убывания drop (как в отчёте дампа)."""
    seen: set[str] = set()
    out: list[str] = []
    for st in stats:
        if st.ip in seen:
            continue
        seen.add(st.ip)
        out.append(st.ip)
    return out


def purge_dump_ip_batches(store: dict[str, DumpIpBatch]) -> None:
    if len(store) <= _MAX_BATCHES:
        return
    now = time.time()
    expired = [k for k, b in store.items() if now - b.created_at > _BATCH_TTL_SEC]
    for k in expired:
        store.pop(k, None)
    if len(store) <= _MAX_BATCHES:
        return
    for k, _ in sorted(store.items(), key=lambda x: x[1].created_at)[: len(store) - _MAX_BATCHES]:
        store.pop(k, None)


def register_dump_ip_batch(
    store: dict[str, DumpIpBatch],
    *,
    owner_user_id: int,
    mitigator: MitigatorReport,
    filename: str,
) -> DumpIpBatch | None:
    src_ips = ips_from_stats(mitigator.src_stats)
    dst_ips = ips_from_stats(mitigator.dst_stats)
    if not src_ips and not dst_ips:
        return None
    token = uuid.uuid4().hex[:12]
    batch = DumpIpBatch(
        token=token,
        owner_user_id=owner_user_id,
        src_ips=src_ips,
        dst_ips=dst_ips,
        filename=filename,
        created_at=time.time(),
    )
    store[token] = batch
    purge_dump_ip_batches(store)
    return batch


def dump_check_keyboard(batch: DumpIpBatch) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    if batch.src_ips:
        n = len(batch.src_ips)
        rows.append(
            [
                InlineKeyboardButton(
                    f"🔍 Проверить Src IP ({n})",
                    callback_data=f"dchk:{batch.token}:src",
                )
            ]
        )
    if batch.dst_ips:
        n = len(batch.dst_ips)
        rows.append(
            [
                InlineKeyboardButton(
                    f"🔍 Проверить Dst IP ({n})",
                    callback_data=f"dchk:{batch.token}:dst",
                )
            ]
        )
    return InlineKeyboardMarkup(rows)
