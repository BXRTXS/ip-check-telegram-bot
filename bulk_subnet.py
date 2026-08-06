"""Группировка IP в массовой проверке по общей подсети."""

from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, collapse_addresses

from report_format import GeoData, OTXData, VTData

_AS_NUM = re.compile(r"AS(\d+)", re.I)


@dataclass
class BulkIpRow:
    ip: str
    g: GeoData
    vt: VTData
    otx: OTXData
    is_red: bool


@dataclass
class BulkSubnetGroup:
    network: IPv4Network
    rows: list[BulkIpRow]


def _as_number(g: GeoData) -> int | None:
    if not g.ok or not g.as_raw:
        return None
    m = _AS_NUM.search(g.as_raw)
    return int(m.group(1)) if m else None


def _group_as(rows: list[BulkIpRow]) -> str:
    nums: dict[int, int] = {}
    for r in rows:
        n = _as_number(r.g)
        if n is not None:
            nums[n] = nums.get(n, 0) + 1
    if not nums:
        for r in rows:
            if r.g.ok and r.g.as_raw:
                return r.g.as_raw.strip()
        return "AS ?"
    best = max(nums, key=lambda k: nums[k])
    for r in rows:
        if _as_number(r.g) == best and r.g.as_raw:
            return r.g.as_raw.strip()
    return f"AS{best}"


def _net24(ip: str) -> IPv4Network:
    return IPv4Network(f"{ip}/24", strict=False)


def _covering_network(ips: list[str]) -> IPv4Network:
    nets = [IPv4Network(f"{ip}/32", strict=False) for ip in ips]
    collapsed = list(collapse_addresses(nets))
    if len(collapsed) == 1:
        return collapsed[0]
    return _net24(ips[0])


def group_bulk_by_subnet(rows: list[BulkIpRow], *, min_size: int = 2) -> list[BulkSubnetGroup | BulkIpRow]:
    """≥min_size IP в одном /24 и одном AS → одна группа; соседние /24 с тем же AS → /23…"""
    if not rows:
        return []

    by24: dict[IPv4Network, list[BulkIpRow]] = {}
    singles: list[BulkIpRow] = []

    for row in rows:
        by24.setdefault(_net24(row.ip), []).append(row)

    groups: list[BulkSubnetGroup] = []
    for net, members in sorted(by24.items(), key=lambda x: int(x[0].network_address)):
        if len(members) >= min_size:
            as_set = {_as_number(r.g) for r in members}
            as_set.discard(None)
            if len(as_set) <= 1:
                cover = _covering_network([r.ip for r in members])
                groups.append(
                    BulkSubnetGroup(
                        network=cover,
                        rows=sorted(members, key=lambda r: IPv4Address(r.ip)),
                    )
                )
            else:
                singles.extend(members)
        else:
            singles.extend(members)

    groups.sort(key=lambda g: int(g.network.network_address))
    merged: list[BulkSubnetGroup] = []
    for grp in groups:
        if (
            merged
            and _group_as(merged[-1].rows) == _group_as(grp.rows)
            and int(grp.network.network_address) == int(merged[-1].network.broadcast_address) + 1
        ):
            combined = merged[-1].rows + grp.rows
            cover = _covering_network([r.ip for r in combined])
            merged[-1] = BulkSubnetGroup(
                network=cover,
                rows=sorted(combined, key=lambda r: IPv4Address(r.ip)),
            )
        else:
            merged.append(grp)

    out: list[BulkSubnetGroup | BulkIpRow] = list(merged)
    out.extend(sorted(singles, key=lambda r: IPv4Address(r.ip)))
    return out


def group_as_for_format(group: BulkSubnetGroup) -> str:
    return _group_as(group.rows)
