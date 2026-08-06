"""Ключи VT/OTX/AbuseIPDB из env и опционального JSON (как -keys в check_ip_lookups)."""

from __future__ import annotations

import json
import os
from pathlib import Path


def _load_json_keys(path: str | None) -> dict[str, str]:
    if not path:
        return {}
    p = Path(path)
    if not p.is_file():
        return {}
    try:
        with p.open(encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}
    if not isinstance(data, dict):
        return {}
    out: dict[str, str] = {}
    for k in ("VT_API_KEY", "OTX_API_KEY", "ABUSEIPDB_API_KEY"):
        v = data.get(k)
        if isinstance(v, str) and v.strip():
            out[k] = v.strip()
    return out


def vt_api_key() -> str | None:
    j = _load_json_keys(os.environ.get("IP_CHECK_KEYS_JSON", "").strip() or None)
    v = (os.environ.get("VT_API_KEY") or "").strip() or j.get("VT_API_KEY")
    return v or None


def otx_api_key() -> str | None:
    j = _load_json_keys(os.environ.get("IP_CHECK_KEYS_JSON", "").strip() or None)
    v = (os.environ.get("OTX_API_KEY") or "").strip() or j.get("OTX_API_KEY")
    return v or None


def abuseipdb_api_key() -> str | None:
    j = _load_json_keys(os.environ.get("IP_CHECK_KEYS_JSON", "").strip() or None)
    v = (os.environ.get("ABUSEIPDB_API_KEY") or "").strip() or j.get("ABUSEIPDB_API_KEY")
    return v or None
