"""Справочник контрмер Mitigator (по документации и типовым правилам)."""

from __future__ import annotations

import re

# Нормализованные подстроки → пояснение
MITIGATOR_CM_HELP: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"acl\s+drop.*tcp.*flags.*s/sa", re.I),
        "ACL DROP tcp tcp-flags S/SA — отбрасываются TCP SYN без ACK (чистый SYN) "
        "или пакеты по маске флагов S/SA. Обычно это отсечение новых TCP-сессий "
        "(подключений): сканирование, SYN-flood, лишние попытки открыть сессию. "
        "Легитимный клиент при срабатывании не увидит завершённого handshake.",
    ),
    (
        re.compile(r"acl\s+drop", re.I),
        "ACL DROP — пакет отброшен правилом ACL (L3/L4 фильтр Mitigator). "
        "Смотрите протокол/порты/флаги в тексте правила.",
    ),
    (
        re.compile(r"geo\s*[—\-:]", re.I),
        "GEO — IP Geolocation Filter: пакет отфильтрован по геолокации IP "
        "(страна/регион не в белом списке или в чёрном списке).",
    ),
    (
        re.compile(r"rate\s*limit|ratelimit|pps|bps", re.I),
        "Rate limit — превышен порог скорости (PPS/BPS) для защиты или политики.",
    ),
    (
        re.compile(r"blacklist|blocklist|denylist", re.I),
        "Список блокировки — IP/сеть в чёрном списке.",
    ),
    (
        re.compile(r"whitelist|allowlist", re.I),
        "Белый список — пропуск только для разрешённых адресов/сетей.",
    ),
    (
        re.compile(r"\bl7\b|waf|http", re.I),
        "L7 / WAF — сработала прикладная (HTTP) защита или фильтр payload.",
    ),
    (
        re.compile(r"challenge|captcha|js", re.I),
        "Challenge — клиенту нужно пройти проверку (captcha/JS challenge).",
    ),
    (
        re.compile(r"passed through policy", re.I),
        "Passed through policy — пакет прошёл цепочку политик без отбрасывания на этом шаге.",
    ),
    (
        re.compile(r"policy id", re.I),
        "Policy ID — идентификатор политики Mitigator, через которую прошёл пакет.",
    ),
    (
        re.compile(r"instance id", re.I),
        "Instance ID — экземпляр (instance) обработки в Mitigator.",
    ),
    (
        re.compile(r"syn.?flood|synflood", re.I),
        "SYN-flood — защита от флуда TCP SYN.",
    ),
    (
        re.compile(r"udp\s+flood|dns", re.I),
        "UDP/DNS flood — защита от UDP или DNS-амплификации.",
    ),
    (
        re.compile(r"icmp", re.I),
        "ICMP-фильтр — отбрасывание или ограничение ICMP.",
    ),
]

DOCS_URL = "https://docs.mitigator.ru/v25.02/kb/mitigator_help.pdf"


def explain_countermeasure(line: str) -> str:
    s = (line or "").strip()
    if not s:
        return "Пустая контрмера в комментарии пакета."
    for pat, text in MITIGATOR_CM_HELP:
        if pat.search(s):
            return text
    if re.search(r"\bdrop\b|\bblock\b|\breject\b", s, re.I):
        return (
            f"Отбрасывание: «{s}». Точное имя контрмеры — в справочнике Mitigator "
            f"({DOCS_URL})."
        )
    return (
        f"Контрмера/метка: «{s}». В дампах Mitigator последняя строка Packet comments "
        f"обычно описывает итог обработки пакета. Справочник: {DOCS_URL}"
    )
