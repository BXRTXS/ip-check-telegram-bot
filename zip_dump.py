"""Распаковка ZIP с PCAP для выбора админом."""

from __future__ import annotations

import os
import shutil
import tempfile
import time
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path

from dump_analyzer import is_pcap_magic


def _zip_max_bytes() -> int:
    from runtime_config import get_limits

    return get_limits().dump_zip_max_mb * 1024 * 1024


def _max_pcaps_in_zip() -> int:
    from runtime_config import get_limits

    return get_limits().dump_zip_max_files


@dataclass
class ZipPcapEntry:
    index: int
    name: str
    path: Path
    size: int


@dataclass
class ZipBundle:
    token: str
    entries: list[ZipPcapEntry]
    created_at: float
    owner_user_id: int


def extract_zip_pcaps(data: bytes, *, owner_user_id: int, base_dir: Path) -> tuple[ZipBundle | None, str | None]:
    if len(data) > _zip_max_bytes():
        mb = _zip_max_bytes() // (1024 * 1024)
        return None, f"ZIP больше {mb} МБ"

    base_dir.mkdir(parents=True, exist_ok=True)
    token = uuid.uuid4().hex[:12]
    work = base_dir / token
    work.mkdir(parents=True, exist_ok=True)

    zip_path = work / "upload.zip"
    zip_path.write_bytes(data)

    entries: list[ZipPcapEntry] = []
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                name = info.filename
                nl = name.lower().replace("\\", "/")
                if not nl.endswith((".pcap", ".pcapng", ".cap")):
                    continue
                if info.file_size > _zip_max_bytes():
                    continue
                safe = Path(name).name
                if not safe:
                    continue
                dest = work / f"{len(entries):02d}_{safe}"
                with zf.open(info) as src, dest.open("wb") as out:
                    shutil.copyfileobj(src, out)
                if not is_pcap_magic(dest.read_bytes()):
                    dest.unlink(missing_ok=True)
                    continue
                entries.append(
                    ZipPcapEntry(
                        index=len(entries),
                        name=safe,
                        path=dest,
                        size=dest.stat().st_size,
                    )
                )
                if len(entries) >= _max_pcaps_in_zip():
                    break
    except zipfile.BadZipFile:
        shutil.rmtree(work, ignore_errors=True)
        return None, "некорректный ZIP"
    except Exception as e:
        shutil.rmtree(work, ignore_errors=True)
        return None, str(e)[:200]

    zip_path.unlink(missing_ok=True)
    if not entries:
        shutil.rmtree(work, ignore_errors=True)
        return None, "в архиве нет .pcap / .pcapng / .cap"

    return ZipBundle(token=token, entries=entries, created_at=time.time(), owner_user_id=owner_user_id), None


def cleanup_bundle(base_dir: Path, token: str) -> None:
    work = base_dir / token
    if work.is_dir():
        shutil.rmtree(work, ignore_errors=True)


def purge_old_bundles(base_dir: Path, *, max_age_sec: int = 3600) -> None:
    if not base_dir.is_dir():
        return
    now = time.time()
    for p in base_dir.iterdir():
        if not p.is_dir():
            continue
        try:
            if now - p.stat().st_mtime > max_age_sec:
                shutil.rmtree(p, ignore_errors=True)
        except OSError:
            pass
