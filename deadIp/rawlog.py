"""Логирование сырых результатов и история."""
from __future__ import annotations
import json
import os
import time
from pathlib import Path


def _log_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    d = Path(base) / "deadIp" / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_raw(payload: dict) -> Path:
    ts = time.strftime("%Y%m%d-%H%M%S")
    path = _log_dir() / f"{ts}.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def previous_for(target: str) -> dict | None:
    """Ищет предыдущий лог для того же target (для сравнения)."""
    d = _log_dir()
    files = sorted(d.glob("*.json"), reverse=True)
    for f in files:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if data.get("target") == target:
            return data
    return None
