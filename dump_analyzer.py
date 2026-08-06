"""Анализ pcap/pcapng (tshark) и текстовых логов с DROP/reject."""

from __future__ import annotations

import gzip
import os
import re
import shutil
import subprocess
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from html import escape
from pathlib import Path

from dump_src_enrich import DumpSrcEnrichment
from mitigator_analyze import MitigatorReport, analyze_mitigator_pcap
from mitigator_kb import explain_countermeasure


def h(s: str) -> str:
    return escape(s, quote=True)


@dataclass
class DumpFinding:
    severity: str
    title: str
    detail: str
    count: int | None = None


@dataclass
class DumpAnalysis:
    ok: bool
    kind: str
    error: str | None = None
    filename: str = ""
    packet_count: int | None = None
    duration_sec: float | None = None
    summary_lines: list[str] = field(default_factory=list)
    findings: list[DumpFinding] = field(default_factory=list)
    note: str | None = None
    mitigator: MitigatorReport | None = None
    src_enrichment: DumpSrcEnrichment | None = None
    dst_enrichment: DumpSrcEnrichment | None = None


def _tshark_bin() -> str:
    return os.environ.get("IP_CHECK_TSHARK", "tshark").strip() or "tshark"


def _dump_max_bytes() -> int:
    from runtime_config import get_limits

    return get_limits().dump_max_mb * 1024 * 1024


def _dump_timeout() -> int:
    from runtime_config import get_limits

    return get_limits().dump_timeout_sec


def is_pcap_magic(data: bytes) -> bool:
    if len(data) < 4:
        return False
    m = data[:4]
    return m in (
        b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\xc3\xd4",
        b"\x0a\x0d\x0d\x0a",
        b"\x4d\x3c\x2b\x1a",
        b"\x1a\x2b\x3c\x4d",
    )


def is_dump_filename(name: str) -> bool:
    n = (name or "").lower()
    return any(
        n.endswith(ext)
        for ext in (".pcap", ".pcapng", ".cap", ".pcap.gz", ".cap.gz", ".log", ".zip")
    )


def is_text_dump_filename(name: str) -> bool:
    n = (name or "").lower()
    return n.endswith(".log") or "drop" in n or "tcpdump" in n or "dump" in n


def caption_requests_dump(caption: str | None) -> bool:
    if not caption:
        return False
    c = caption.strip().lower()
    return c in ("/dump", "dump", "дамп", "#dump", "analyze", "/analyze")


def prepare_pcap_path(data: bytes, filename: str) -> tuple[Path | None, str | None]:
    """Пишет pcap во временный файл; при .gz распаковывает."""
    name = (filename or "capture.pcap").lower()
    raw = data
    if name.endswith(".gz"):
        try:
            raw = gzip.decompress(data)
        except OSError as e:
            return None, f"не удалось распаковать gzip: {e}"
    if not is_pcap_magic(raw):
        return None, "не похоже на pcap/pcapng (неверная сигнатура)"
    suffix = ".pcapng" if raw[:4] == b"\x0a\x0d\x0d\x0a" else ".pcap"
    fd, tmp = tempfile.mkstemp(suffix=suffix, prefix="ipcheck_")
    os.close(fd)
    p = Path(tmp)
    p.write_bytes(raw)
    return p, None


def _run(cmd: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or "") if isinstance(e.stdout, str) else ""
        err = (e.stderr or "") if isinstance(e.stderr, str) else f"timeout after {timeout}s"
        return subprocess.CompletedProcess(cmd, 124, out, err)
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _capinfos(path: Path, timeout: int) -> tuple[int | None, float | None, list[str]]:
    cap = shutil.which("capinfos")
    if not cap:
        return None, None, []
    r = _run([cap, str(path)], timeout=min(timeout, 30))
    if r.returncode != 0:
        return None, None, []
    packets: int | None = None
    duration: float | None = None
    extras: list[str] = []
    for line in r.stdout.splitlines():
        if "Number of packets" in line:
            m = re.search(r":\s*(\d+)", line.replace(",", ""))
            if m:
                packets = int(m.group(1))
        if "Capture duration" in line:
            m = re.search(r":\s*([\d.]+)", line.replace(",", "."))
            if m:
                try:
                    duration = float(m.group(1))
                except ValueError:
                    pass
        if "File encapsulation" in line:
            extras.append(line.split(":", 1)[-1].strip())
    return packets, duration, extras


def _tshark_count(path: Path, display_filter: str, timeout: int) -> int | None:
    tshark = _tshark_bin()
    if not shutil.which(tshark):
        return None
    r = _run(
        [tshark, "-r", str(path), "-Y", display_filter, "-T", "fields", "-e", "frame.number"],
        timeout=timeout,
    )
    if r.returncode != 0:
        return None
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    return len(lines)


def _tshark_expert(path: Path, timeout: int) -> list[tuple[str, int]]:
    tshark = _tshark_bin()
    if not shutil.which(tshark):
        return []
    r = _run(
        [
            tshark,
            "-r",
            str(path),
            "-T",
            "fields",
            "-e",
            "_ws.expert.message",
            "-e",
            "_ws.expert.severity",
        ],
        timeout=timeout,
    )
    if r.returncode != 0:
        return []
    ctr: Counter[str] = Counter()
    for line in r.stdout.splitlines():
        msg = line.split("\t", 1)[0].strip()
        if msg:
            ctr[msg] += 1
    return ctr.most_common(12)


def _tshark_protocols(path: Path, timeout: int) -> list[str]:
    tshark = _tshark_bin()
    if not shutil.which(tshark):
        return []
    r = _run([tshark, "-r", str(path), "-q", "-z", "io,phs"], timeout=timeout)
    if r.returncode != 0:
        return []
    lines: list[str] = []
    for ln in r.stdout.splitlines():
        s = ln.strip()
        if s and ("frames:" in s or s.startswith("=")):
            if "frames:" in s and not s.startswith("="):
                lines.append(s)
    return lines[:8]


def _add_finding(
    findings: list[DumpFinding],
    *,
    severity: str,
    title: str,
    detail: str,
    count: int | None,
) -> None:
    findings.append(DumpFinding(severity=severity, title=title, detail=detail, count=count))


def analyze_pcap_file(path: Path, *, filename: str) -> DumpAnalysis:
    if not shutil.which(_tshark_bin()):
        return DumpAnalysis(
            ok=False,
            kind="pcap",
            error="tshark не найден (установите wireshark-common / tshark)",
            filename=filename,
        )

    timeout = _dump_timeout()
    packets, duration, cap_extra = _capinfos(path, timeout)

    findings: list[DumpFinding] = []
    summary: list[str] = []
    if packets is not None:
        summary.append(f"Пакетов: {packets}")
    if duration is not None:
        summary.append(f"Длительность захвата: {duration:.3f} с")
    for x in cap_extra[:2]:
        summary.append(f"Инкапсуляция: {x}")

    checks: list[tuple[str, str, str, str]] = [
        (
            "tcp.analysis.retransmission",
            "high",
            "TCP ретрансмиссии",
            "Повторная отправка сегментов — частый признак потерь на пути, перегруза или обрезки MTU.",
        ),
        (
            "tcp.analysis.duplicate_ack",
            "medium",
            "Duplicate ACK",
            "Дубликаты ACK — часто перед fast retransmit; возможна потеря сегмента.",
        ),
        (
            "tcp.analysis.lost_segment",
            "high",
            "Потерянные TCP-сегменты",
            "Wireshark пометил пропуск сегмента в потоке (loss или reorder).",
        ),
        (
            "tcp.analysis.out_of_order",
            "medium",
            "TCP out-of-order",
            "Сегменты пришли не по порядку — multipath, reorder или loss/recovery.",
        ),
        (
            "tcp.analysis.zero_window",
            "medium",
            "TCP Zero Window",
            "Приёмник объявил окно 0 — peer не успевает читать (backpressure).",
        ),
        (
            "tcp.flags.reset==1",
            "high",
            "TCP RST",
            "Сброс соединения — отказ сервиса, ACL/firewall или обрыв сессии.",
        ),
        (
            "icmp.type==3",
            "high",
            "ICMP Destination Unreachable",
            "Узел или firewall вернул «недоступно» — маршрут, фильтр или нет сервиса.",
        ),
        (
            "icmp.type==3 && icmp.code==3",
            "high",
            "ICMP Port Unreachable",
            "Порт закрыт или отфильтрован на стороне назначения.",
        ),
        (
            "tcp.analysis.fast_retransmission",
            "medium",
            "TCP Fast Retransmission",
            "Быстрая ретрансмиссия после нескольких duplicate ACK.",
        ),
    ]

    for filt, sev, title, detail in checks:
        cnt = _tshark_count(path, filt, timeout)
        if cnt and cnt > 0:
            _add_finding(findings, severity=sev, title=title, detail=detail, count=cnt)

    for msg, cnt in _tshark_expert(path, timeout):
        low = msg.lower()
        sev = "medium"
        if any(x in low for x in ("error", "severe", "fail", "lost", "retrans")):
            sev = "high"
        _add_finding(
            findings,
            severity=sev,
            title=f"Expert: {msg[:120]}",
            detail="Сообщение анализатора Wireshark/tshark по полям пакетов.",
            count=cnt,
        )

    protos = _tshark_protocols(path, timeout)
    if protos:
        summary.append("Протоколы: " + "; ".join(protos[:4]))

    mitigator = analyze_mitigator_pcap(path, tshark=_tshark_bin(), timeout=timeout)
    if mitigator:
        summary.append(
            f"Mitigator comments: {mitigator.with_comment} пакетов "
            f"(pass {mitigator.passed}, drop {mitigator.dropped})"
        )

    note = None
    if mitigator:
        note = (
            "Packet comments — поля Mitigator (pkt_comment). "
            "Последняя строка комментария — итог контрмеры. "
            "Справочник: https://docs.mitigator.ru/v25.02/kb/mitigator_help.pdf"
        )
    else:
        note = (
            "В обычном pcap нет Packet comments Mitigator — ниже косвенные признаки tshark. "
            "Для kernel drop нужен drop_monitor / лог firewall."
        )

    if not findings and packets:
        _add_finding(
            findings,
            severity="info",
            title="Явных TCP/ICMP аномалий мало",
            detail="По фильтрам tshark критичных паттернов не найдено. Проверьте нужный интерфейс/VLAN и окно времени.",
            count=None,
        )

    findings.sort(
        key=lambda f: (
            {"high": 0, "medium": 1, "low": 2, "info": 3}.get(f.severity, 9),
            -(f.count or 0),
        )
    )

    return DumpAnalysis(
        ok=True,
        kind="pcap",
        filename=filename,
        packet_count=packets,
        duration_sec=duration,
        summary_lines=summary,
        findings=findings,
        note=note,
        mitigator=mitigator,
    )


def analyze_pcap_path(path: Path, *, filename: str) -> DumpAnalysis:
    return analyze_pcap_file(path, filename=filename)


_DROP_LINE_RE = re.compile(
    r"(?:\bDROP\b|\bREJECT\b|xt_DROP|NF_DROP|netdev_drop|packet dropped|"
    r"drop_xmit|dropped:|IPTables|nftables|conntrack.*drop)",
    re.IGNORECASE,
)


def analyze_text_log(text: str, *, filename: str) -> DumpAnalysis:
    lines = text.splitlines()
    drop_lines = [ln for ln in lines if _DROP_LINE_RE.search(ln)]
    findings: list[DumpFinding] = []
    summary = [f"Строк в файле: {len(lines)}", f"Строк с DROP/reject: {len(drop_lines)}"]

    if not drop_lines:
        return DumpAnalysis(
            ok=True,
            kind="log",
            filename=filename,
            summary_lines=summary,
            findings=[
                DumpFinding(
                    severity="info",
                    title="Строк с DROP/reject не найдено",
                    detail="Проверьте, что это лог firewall/kernel (dmesg, syslog, nft log).",
                    count=None,
                )
            ],
            note="Текстовый разбор: ищем DROP, REJECT, nf_drop, netdev_drop и похожее.",
        )

    ctr: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    for ln in drop_lines[:5000]:
        ctr["drop_lines"] += 1
        m = re.search(r"(?:DROP|REJECT)[:\s]+(.{0,120})", ln, re.I)
        if m:
            reasons[m.group(1).strip()[:80]] += 1
        for key in ("SRC=", "DST=", "PROTO=", "IN=", "OUT="):
            if key in ln.upper():
                pass
        if "reason" in ln.lower():
            rm = re.search(r"reason[=:\s]+([^\s,]+)", ln, re.I)
            if rm:
                reasons[f"reason={rm.group(1)}"] += 1

    _add_finding(
        findings,
        severity="high",
        title="Зафиксированы DROP/reject в логе",
        detail="Пакеты или сессии отбрасывались правилами фильтрации или стеком.",
        count=len(drop_lines),
    )

    for reason, cnt in reasons.most_common(8):
        _add_finding(
            findings,
            severity="medium",
            title=f"Причина/контекст: {reason[:100]}",
            detail="Фрагмент из строки лога (chain, interface, prefix).",
            count=cnt,
        )

    samples = drop_lines[:5]
    summary.append("Примеры строк:")
    summary.extend(s[:200] for s in samples)

    return DumpAnalysis(
        ok=True,
        kind="log",
        filename=filename,
        summary_lines=summary,
        findings=findings,
        note="Разбор текстового лога; для точных kernel drop лучше pcap + tshark.",
    )


def analyze_dump_bytes(data: bytes, filename: str, *, force_text: bool = False) -> DumpAnalysis:
    if len(data) > _dump_max_bytes():
        mb = _dump_max_bytes() // (1024 * 1024)
        return DumpAnalysis(
            ok=False,
            kind="?",
            error=f"файл больше {mb} МБ (лимит IP_CHECK_DUMP_MAX_MB)",
            filename=filename,
        )

    name = filename or "upload"
    if force_text or (is_text_dump_filename(name) and not is_pcap_magic(data)):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("utf-8", errors="replace")
        return analyze_text_log(text, filename=name)

    path, err = prepare_pcap_path(data, name)
    if err:
        if is_text_dump_filename(name) or b"DROP" in data[:8000] or b"REJECT" in data[:8000]:
            try:
                text = data.decode("utf-8", errors="replace")
                return analyze_text_log(text, filename=name)
            except Exception:
                pass
        return DumpAnalysis(ok=False, kind="pcap", error=err, filename=name)
    assert path is not None
    try:
        return analyze_pcap_file(path, filename=name)
    finally:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass


def _mitigator_html(
    rep: MitigatorReport,
    *,
    has_src_enrichment: bool = False,
    has_dst_enrichment: bool = False,
) -> list[str]:
    lines: list[str] = [
        "",
        "🛡 <b>Mitigator (Packet comments)</b>",
        f"• С комментариями: <b>{rep.with_comment}</b> · passed <b>{rep.passed}</b> · "
        f"drop <b>{rep.dropped}</b>",
    ]
    if rep.acl_s_sa_count:
        lines.append(f"• ACL DROP S/SA: <b>{rep.acl_s_sa_count}</b> пакетов")
        lines.append(f"  <i>{h(explain_countermeasure('ACL DROP tcp tcp-flags S/SA'))}</i>")

    lines.extend(
        [
            "",
            f"<b>Оценка трафика:</b> {h(rep.legit_verdict)}",
            f"<i>{h(rep.legit_detail)}</i>",
        ]
    )

    if rep.countermeasure_global:
        lines.append("")
        lines.append("<b>Контрмеры (топ)</b>")
        for cm, cnt in rep.countermeasure_global[:10]:
            lines.append(f"• <b>{h(cm)}</b> ×{cnt}")
            expl = explain_countermeasure(cm)
            if len(expl) < 220:
                lines.append(f"  <i>{h(expl)}</i>")

    if rep.dst_stats:
        lines.append("")
        if has_dst_enrichment:
            lines.append("<b>Dst IP — почему блокируют</b> <i>(pcap + репутация ниже)</i>")
            for st in rep.dst_stats[:5]:
                top_cm = st.top_countermeasures[0][0] if st.top_countermeasures else "?"
                lines.append(
                    f"• <code>{h(st.ip)}</code> — {st.dropped}/{st.total} drop · "
                    f"<b>{h(top_cm)}</b>"
                )
            if len(rep.dst_stats) > 5:
                lines.append(f"<i>… ещё {len(rep.dst_stats) - 5} dst — в блоке ниже</i>")
        else:
            lines.append("<b>Dst IP — почему блокируют (топ)</b>")
            for st in rep.dst_stats[:8]:
                top_cm = st.top_countermeasures[0][0] if st.top_countermeasures else "?"
                lines.append(
                    f"• <code>{h(st.ip)}</code> — {st.dropped}/{st.total} drop · "
                    f"<b>{h(top_cm)}</b>"
                )

    if rep.src_stats:
        lines.append("")
        if has_src_enrichment:
            lines.append("<b>Src IP — кто блокируется</b> <i>(pcap + репутация ниже)</i>")
            for st in rep.src_stats[:5]:
                top_cm = st.top_countermeasures[0][0] if st.top_countermeasures else "?"
                lines.append(
                    f"• <code>{h(st.ip)}</code> — {st.dropped}/{st.total} drop · "
                    f"<b>{h(top_cm)}</b>"
                )
            if len(rep.src_stats) > 5:
                lines.append(f"<i>… ещё {len(rep.src_stats) - 5} src — в блоке ниже</i>")
        else:
            lines.append("<b>Src IP — кто блокируется (топ)</b>")
            for st in rep.src_stats[:8]:
                top_cm = st.top_countermeasures[0][0] if st.top_countermeasures else "?"
                lines.append(
                    f"• <code>{h(st.ip)}</code> — {st.dropped}/{st.total} drop · "
                    f"<b>{h(top_cm)}</b>"
                )

    return lines


def _side_enrichment_html(enrich, *, title: str) -> list[str]:
    if not enrich or not enrich.html_lines:
        return []
    lines = [
        "",
        f"🔍 <b>{h(title)}</b> "
        f"(проверено <b>{enrich.checked}</b> из {enrich.total_unique} уникальных)",
    ]
    if enrich.truncated:
        lines.append("<i>Лимит IP — остальные только в pcap-статистике выше</i>")
    lines.extend(enrich.html_lines)
    return lines


def _src_enrichment_html(enrich) -> list[str]:
    return _side_enrichment_html(enrich, title="Src IP — репутация")


def _dst_enrichment_html(enrich) -> list[str]:
    return _side_enrichment_html(enrich, title="Dst IP — репутация")


def _mitigator_txt(rep: MitigatorReport) -> list[str]:
    out = [
        "--- Mitigator (Packet comments) ---",
        f"with_comment={rep.with_comment} passed={rep.passed} dropped={rep.dropped}",
        f"acl_drop_s_sa={rep.acl_s_sa_count}",
        f"legit: {rep.legit_verdict} — {rep.legit_detail}",
        "",
        "Глобальные контрмеры:",
    ]
    for cm, cnt in rep.countermeasure_global:
        out.append(f"  {cnt} × {cm}")
        out.append(f"    {explain_countermeasure(cm)}")
    out.append("")
    out.append("Dst IP:")
    for st in rep.dst_stats:
        out.append(f"  {st.ip} drop={st.dropped}/{st.total}")
        for cm, c in st.top_countermeasures:
            out.append(f"    {c} × {cm}")
    out.append("")
    out.append("Src IP:")
    for st in rep.src_stats:
        out.append(f"  {st.ip} drop={st.dropped}/{st.total}")
        for cm, c in st.top_countermeasures:
            out.append(f"    {c} × {cm}")
    if rep.sample_comments:
        out.append("")
        out.append("Примеры комментариев:")
        for i, s in enumerate(rep.sample_comments, 1):
            out.append(f"--- sample {i} ---")
            out.append(s)
    out.append("")
    return out


def format_dump_html(report: DumpAnalysis) -> str:
    if not report.ok:
        return (
            f"📉 <b>Анализ дампа</b> — <code>{h(report.filename)}</code>\n"
            f"Ошибка: {h(report.error or '—')}"
        )

    lines: list[str] = [
        f"📉 <b>Анализ дампа</b> — <code>{h(report.filename)}</code>",
        f"<i>Тип: {h(report.kind)}</i>",
        "",
    ]
    for s in report.summary_lines[:12]:
        lines.append(f"• {h(s)}")
    if report.mitigator:
        lines.extend(
            _mitigator_html(
                report.mitigator,
                has_src_enrichment=bool(report.src_enrichment),
                has_dst_enrichment=bool(report.dst_enrichment),
            )
        )
        lines.extend(_dst_enrichment_html(report.dst_enrichment))
        lines.extend(_src_enrichment_html(report.src_enrichment))
    if report.findings:
        lines.extend(["", "<b>Найденное</b>"])
        sev_icon = {"high": "🔴", "medium": "🟡", "low": "🟠", "info": "ℹ️"}
        for f in report.findings[:18]:
            icon = sev_icon.get(f.severity, "•")
            cnt = f" ×<b>{f.count}</b>" if f.count is not None else ""
            lines.append(f"{icon} <b>{h(f.title)}</b>{cnt}")
            lines.append(f"   {h(f.detail)}")
        if len(report.findings) > 18:
            lines.append(f"<i>…ещё {len(report.findings) - 18} пунктов во вложении</i>")
    if report.note:
        lines.extend(["", f"<i>{h(report.note)}</i>"])
    return "\n".join(lines)


def format_dump_attachment(report: DumpAnalysis) -> str:
    out: list[str] = [
        f"Анализ дампа: {report.filename}",
        f"Тип: {report.kind}",
        "",
    ]
    if not report.ok:
        out.append(f"Ошибка: {report.error}")
        return "\n".join(out)
    out.extend(report.summary_lines)
    out.append("")
    if report.mitigator:
        out.extend(_mitigator_txt(report.mitigator))
    if report.dst_enrichment and report.dst_enrichment.txt_lines:
        out.append("")
        out.append(
            f"--- Dst IP репутация ({report.dst_enrichment.checked}/"
            f"{report.dst_enrichment.total_unique}) ---"
        )
        out.extend(report.dst_enrichment.txt_lines)
    if report.src_enrichment and report.src_enrichment.txt_lines:
        out.append("")
        out.append(
            f"--- Src IP репутация ({report.src_enrichment.checked}/"
            f"{report.src_enrichment.total_unique}) ---"
        )
        out.extend(report.src_enrichment.txt_lines)
    for f in report.findings:
        cnt = f" count={f.count}" if f.count is not None else ""
        out.append(f"[{f.severity}] {f.title}{cnt}")
        out.append(f"  {f.detail}")
        out.append("")
    if report.note:
        out.append(report.note)
    return "\n".join(out)
