"""Слой 6: сравнение через Globalping (РФ vs Европа)."""
from __future__ import annotations
import time
import httpx

API = "https://api.globalping.io/v1/measurements"


def globalping_compare(target: str, timeout: float = 40.0) -> dict:
    res = {"available": False, "ru_ok": None, "eu_ok": None, "raw": None}
    try:
        r = httpx.post(
            API,
            json={
                "type": "ping",
                "target": target,
                "locations": [{"magic": "Russia"}, {"magic": "Germany"}],
                "limit": 4,
            },
            timeout=10.0,
        )
        r.raise_for_status()
        mid = r.json()["id"]
    except Exception as e:
        res["error"] = str(e)
        return res

    deadline = time.time() + timeout
    data = None
    while time.time() < deadline:
        try:
            r = httpx.get(f"{API}/{mid}", timeout=10.0)
            data = r.json()
            if data.get("status") == "finished":
                break
        except Exception:
            pass
        time.sleep(2)

    if not data or data.get("status") != "finished":
        res["error"] = "globalping timeout"
        return res

    res["available"] = True
    res["raw"] = data
    ru_ok = eu_ok = None
    for item in data.get("results", []):
        country = (item.get("probe", {}).get("country") or "").upper()
        stats = (item.get("result") or {}).get("stats") or {}
        loss = stats.get("loss")
        ok = loss is not None and loss < 80
        if country == "RU":
            ru_ok = ok if ru_ok is None else (ru_ok and ok)
        elif country in ("DE", "NL", "FR", "GB", "PL"):
            eu_ok = ok if eu_ok is None else (eu_ok and ok)
    res["ru_ok"] = ru_ok
    res["eu_ok"] = eu_ok
    return res
