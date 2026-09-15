"""Резолвинг имён через DoH, чтобы обойти подмену DNS провайдером."""
from __future__ import annotations
import ipaddress
import httpx

DOH_ENDPOINTS = (
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
)

_RTYPE = {"A": 1, "AAAA": 28}


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def resolve_doh(host: str, rtype: str = "A", timeout: float = 5.0) -> list[str]:
    want = _RTYPE[rtype]
    for url in DOH_ENDPOINTS:
        try:
            r = httpx.get(
                url,
                params={"name": host, "type": rtype},
                headers={"accept": "application/dns-json"},
                timeout=timeout,
            )
            r.raise_for_status()
            data = r.json()
            return [a["data"] for a in data.get("Answer", []) if a.get("type") == want]
        except Exception:
            continue
    return []


def resolve_target(target: str, timeout: float = 5.0) -> dict:
    """Возвращает {'input', 'ip', 'domain', 'sni'}."""
    if is_ip(target):
        return {"input": target, "ip": target, "domain": None, "sni": None}
    ips = resolve_doh(target, "A", timeout=timeout)
    if not ips:
        # фолбэк на системный резолвер
        import socket
        try:
            ips = [socket.gethostbyname(target)]
        except OSError:
            ips = []
    if not ips:
        return {"input": target, "ip": None, "domain": target, "sni": target, "error": "dns_failed"}
    return {"input": target, "ip": ips[0], "domain": target, "sni": target, "all_ips": ips}
