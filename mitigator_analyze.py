"""Разбор Packet comments (pkt_comment) в pcap Mitigator."""

from __future__ import annotations

import csv
import io
import re
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from mitigator_kb import explain_countermeasure

_META_LINE = re.compile(
    r"^(Instance ID:|Policy ID:|Passed through policy\s*$)",
    re.IGNORECASE,
)
_DROP_HINT = re.compile(
    r"\b(?:ACL\s+)?DROP\b|\bREJECT\b|\bBLOCK\b|GEO\s*[—\-]|Rate\s*limit|"
    r"Blacklist|Challenge|Invalid|Forbidden|Syn.?flood",
    re.IGNORECASE,
)
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)


@dataclass
class IpBlockStats:
    ip: str
    total: int
    dropped: int
    top_countermeasures: list[tuple[str, int]]
    top_reason_text: str


@dataclass
class MitigatorReport:
    packets_total: int = 0
    with_comment: int = 0
    passed: int = 0
    dropped: int = 0
    unknown: int = 0
    countermeasure_global: list[tuple[str, int]] = field(default_factory=list)
    dst_stats: list[IpBlockStats] = field(default_factory=list)
    src_stats: list[IpBlockStats] = field(default_factory=list)
    legit_verdict: str = ""
    legit_detail: str = ""
    acl_s_sa_count: int = 0
    sample_comments: list[str] = field(default_factory=list)


def _norm_cm(line: str) -> str:
    return re.sub(r"\s+", " ", (line or "").strip())[:200]


def parse_packet_comment(raw: str) -> tuple[str | None, bool, bool]:
    """
    Возвращает (контрмера/итог, dropped, passed_through).
    Последняя содержательная строка — итог; DROP/GEO/… — отбрасывание.
    """
    if not raw or not raw.strip():
        return None, False, False
    lines = [ln.strip() for ln in raw.replace("\r\n", "\n").split("\n") if ln.strip()]
    if not lines:
        return None, False, False

    passed = any(ln.lower() == "passed through policy" for ln in lines)
    countermeasure: str | None = None
    for ln in reversed(lines):
        if _META_LINE.match(ln):
            continue
        if ln.lower() == "passed through policy":
            continue
        countermeasure = ln
        break
    if countermeasure is None:
        countermeasure = lines[-1]

    cm_l = countermeasure.lower()
    dropped = bool(_DROP_HINT.search(countermeasure)) or "drop" in cm_l
    if not dropped and passed and countermeasure and not _META_LINE.match(countermeasure):
        if "—" in countermeasure or "geo" in cm_l or "acl" in cm_l:
            dropped = True

    if not dropped and passed and countermeasure.lower() == "passed through policy":
        dropped = False

    return countermeasure, dropped, passed


def _tshark_rows(path: Path, tshark: str, timeout: int) -> list[tuple[str, str, str]]:
    cmd = [
        tshark,
        "-r",
        str(path),
        "-T",
        "fields",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-e",
        "pkt_comment",
        "-E",
        "header=y",
        "-E",
        "separator=\t",
        "-E",
        "quote=d",
        "-E",
        "occurrence=f",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    if r.returncode != 0 or not r.stdout.strip():
        return []
    reader = csv.DictReader(
        io.StringIO(r.stdout),
        delimiter="\t",
        quotechar='"',
    )
    rows: list[tuple[str, str, str]] = []
    for row in reader:
        src = (row.get("ip.src") or "").strip()
        dst = (row.get("ip.dst") or "").strip()
        if "," in src:
            src = src.split(",")[0].strip()
        if "," in dst:
            dst = dst.split(",")[0].strip()
        cmt = row.get("pkt_comment") or ""
        rows.append((src, dst, cmt))
    return rows


def _build_ip_stats(by_ip: dict[str, list[tuple[str, bool]]], *, top_n: int = 12) -> list[IpBlockStats]:
    out: list[IpBlockStats] = []
    for ip, events in sorted(by_ip.items(), key=lambda x: (-len(x[1]), x[0]))[:top_n]:
        cm_ctr: Counter[str] = Counter()
        dropped = 0
        for cm, is_drop in events:
            if is_drop:
                dropped += 1
            if cm:
                cm_ctr[_norm_cm(cm)] += 1
        top = cm_ctr.most_common(5)
        reason = explain_countermeasure(top[0][0]) if top else "—"
        out.append(
            IpBlockStats(
                ip=ip,
                total=len(events),
                dropped=dropped,
                top_countermeasures=top,
                top_reason_text=reason,
            )
        )
    return out


def _assess_legit(
    *,
    passed: int,
    dropped: int,
    acl_s_sa: int,
    unique_src_dropped: int,
    unique_dst_dropped: int,
) -> tuple[str, str]:
    total = passed + dropped
    if total == 0:
        return "нет данных", "Нет пакетов с комментариями Mitigator."
    drop_pct = 100.0 * dropped / total
    if acl_s_sa > 0 and dropped and acl_s_sa >= dropped * 0.4:
        return (
            "похоже на атаку / сканирование",
            f"Много ACL DROP S/SA ({acl_s_sa} из {dropped} drop, {drop_pct:.0f}% drop). "
            "Типично для SYN-flood или массовых попыток открыть TCP-сессию.",
        )
    if drop_pct >= 85 and unique_src_dropped >= 20:
        return (
            "похоже на атаку",
            f"{drop_pct:.0f}% пакетов с drop, {unique_src_dropped} разных src с отбрасыванием.",
        )
    if drop_pct <= 15 and passed > dropped * 3:
        return (
            "преимущественно легитимный трафик",
            f"Большинство пакетов прошло политику ({passed} passed / {dropped} drop). "
            "Единичные drop — точечная фильтрация (GEO/ACL).",
        )
    if drop_pct >= 50:
        return (
            "смешанный, много фильтрации",
            f"~{drop_pct:.0f}% drop при {passed} passed. Проверьте топ контрмер по dst/src IP.",
        )
    return (
        "смешанный",
        f"Passed {passed}, drop {dropped} ({drop_pct:.0f}% drop). Смотрите разбивку по IP.",
    )


def analyze_mitigator_pcap(path: Path, *, tshark: str, timeout: int) -> MitigatorReport | None:
    rows = _tshark_rows(path, tshark, timeout)
    if not rows:
        return None

    rep = MitigatorReport(packets_total=len(rows))
    global_cm: Counter[str] = Counter()
    dst_events: dict[str, list[tuple[str, bool]]] = defaultdict(list)
    src_events: dict[str, list[tuple[str, bool]]] = defaultdict(list)
    src_dropped: set[str] = set()
    dst_dropped: set[str] = set()
    samples: list[str] = []

    for src, dst, raw_cmt in rows:
        if not raw_cmt.strip():
            continue
        rep.with_comment += 1
        cm, dropped, passed = parse_packet_comment(raw_cmt)
        if passed and not dropped:
            rep.passed += 1
        elif dropped:
            rep.dropped += 1
        else:
            rep.unknown += 1

        if cm:
            ncm = _norm_cm(cm)
            global_cm[ncm] += 1
            if re.search(r"acl\s+drop.*s/sa", ncm, re.I):
                rep.acl_s_sa_count += 1
            if len(samples) < 3:
                samples.append(raw_cmt[:500])

        if dst and _IPV4_RE.match(dst):
            dst_events[dst].append((cm or "?", dropped))
            if dropped:
                dst_dropped.add(dst)
        if src and _IPV4_RE.match(src):
            src_events[src].append((cm or "?", dropped))
            if dropped:
                src_dropped.add(src)

    rep.countermeasure_global = global_cm.most_common(15)
    rep.dst_stats = _build_ip_stats(dst_events)
    rep.src_stats = _build_ip_stats(src_events)
    rep.sample_comments = samples
    rep.legit_verdict, rep.legit_detail = _assess_legit(
        passed=rep.passed,
        dropped=rep.dropped,
        acl_s_sa=rep.acl_s_sa_count,
        unique_src_dropped=len(src_dropped),
        unique_dst_dropped=len(dst_dropped),
    )
    return rep if rep.with_comment else None
