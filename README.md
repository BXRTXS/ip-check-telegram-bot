# IP check Telegram bot

Проверка IPv4 / доменов через Telegram: ip-api, VirusTotal, AlienVault OTX, AbuseIPDB, RIPEstat. Админ-режим: whitelist, audit, анализ pcap/DROP (Mitigator).

## Быстрый старт

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp ip_check_bot.env.example ip_check_bot.env
cp secrets/keys.example.json secrets/keys.json
chmod 600 ip_check_bot.env secrets/keys.json
# заполните BOT_TOKEN, IP_CHECK_ADMIN_USER_IDS и ключи в secrets/keys.json
```

Секреты **не** коммитятся: `ip_check_bot.env`, `secrets/keys.json`, каталог `data/`.

systemd: см. `ip-check-telegram-bot.service`.

## Ключи

| Файл | Назначение |
|------|------------|
| `ip_check_bot.env` | `BOT_TOKEN`, proxy, admin/allowed IDs, лимиты |
| `secrets/keys.json` | `VT_API_KEY`, `OTX_API_KEY`, `ABUSEIPDB_API_KEY` |

Загрузка: `keys.py` — сначала переменные окружения, иначе JSON из `IP_CHECK_KEYS_JSON`.
