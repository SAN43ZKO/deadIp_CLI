"""Слой 1: ICMP ping."""

from __future__ import annotations

import platform
import re
import shutil
import subprocess

_LOSS_RE = re.compile(r"(\d+(?:[.,]\d+)?)%\s*packet loss")


def ping(host: str, count: int = 10, timeout: float = 2.0) -> dict:
    out = {"available": False, "loss_percent": None, "raw": ""}
    binary = shutil.which("ping")
    if not binary:
        out["error"] = "ping not found"
        return out

    if platform.system() == "Windows":
        cmd = [binary, "-n", str(count), "-w", str(int(timeout * 1000)), host]
    elif platform.system() == "Darwin":
        cmd = [binary, "-c", str(count), "-W", str(int(timeout * 1000)), host]
    else:
        cmd = [binary, "-c", str(count), "-W", str(int(timeout)), host]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=count * timeout + 5,
        )
    except subprocess.TimeoutExpired:
        out["error"] = "timeout"
        out["loss_percent"] = 100.0
        return out

    out["available"] = True
    out["raw"] = proc.stdout + proc.stderr
    m = _LOSS_RE.search(out["raw"])
    if m:
        out["loss_percent"] = float(m.group(1).replace(",", "."))
    else:
        # не смогли распарсить — считаем по коду возврата
        out["loss_percent"] = 0.0 if proc.returncode == 0 else 100.0
    return out
