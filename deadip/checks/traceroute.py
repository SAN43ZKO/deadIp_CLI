"""Слой 4: traceroute / MTR с каскадом режимов, Cymru AS-lookup и честными ошибками.

Модель блокировки, которую мы детектируем:
  РКН/ТСПУ передаёт провайдеру пользователя инструкцию дропать VPN-трафик.
  Фактически блокировка происходит на стороне ISP пользователя: после его
  магистрального AS пакеты молча теряются. В traceroute это выглядит как
  1–2 отвеченных хопа (роутер + ISP) и длинная тишина до max_hops.

  Такая «ранняя тишина» НЕ означает «сервер мёртв» — сам сервер может быть
  полностью жив, но недоступен именно с этого маршрута. Поэтому признак
  должен идти в паре с ICMP/TCP-провалами и успешным контролем.
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess

# Фолбэк-множество российских AS. Используется, только если Cymru недоступен.
RU_AS_FALLBACK = {
    "AS12389",  # Ростелеком
    "AS15468",  # Google (Rostelecom peer)
    "AS20485",  # ТрансТелеКом
    "AS8331",  # Радуга-Интернет
    "AS3216",  # МТС
    "AS8402",  # Вымпелком
    "AS12332",  # Мегафон
    "AS31133",  # Мегафон
    "AS8359",  # МТС
    "AS31214",  # ТИС-Диалог
}

_AS_RE = re.compile(r"\bAS(\d{1,6})\b")
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_HOP_LINE_RE = re.compile(r"^[ \t]*\d+[ \t.|:]")

_CYMRU_HOST = "whois.cymru.com"
_CYMRU_PORT = 43


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _run(cmd: list[str], timeout: float) -> tuple[str, str, int]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout or "", p.stderr or "", p.returncode
    except subprocess.TimeoutExpired as e:
        out = e.stdout if isinstance(e.stdout, str) else ""
        return out, "timeout", -1
    except FileNotFoundError:
        return "", "not found", -1


def _candidates(target: str, port: int, max_hops: int) -> list[tuple[str, list[str]]]:
    """Список (имя, argv) в порядке предпочтения. TCP — только если root."""
    cands: list[tuple[str, list[str]]] = []
    mtr = shutil.which("mtr")
    tr = shutil.which("traceroute")
    tp = shutil.which("tracepath")
    root = _is_root()

    if mtr:
        if root:
            cands.append(
                (
                    "mtr-tcp",
                    [
                        mtr,
                        "-r",
                        "-b",
                        "-z",
                        "-c",
                        "3",
                        "-T",
                        "-P",
                        str(port),
                        "-m",
                        str(max_hops),
                        target,
                    ],
                )
            )
        cands.append(
            (
                "mtr-udp",
                [
                    mtr,
                    "-r",
                    "-b",
                    "-z",
                    "-c",
                    "3",
                    "-u",
                    "-P",
                    str(port),
                    "-m",
                    str(max_hops),
                    target,
                ],
            )
        )
        cands.append(
            (
                "mtr-icmp",
                [
                    mtr,
                    "-r",
                    "-b",
                    "-z",
                    "-c",
                    "3",
                    "-m",
                    str(max_hops),
                    target,
                ],
            )
        )
        cands.append(
            (
                "mtr-plain",
                [
                    mtr,
                    "-r",
                    "-b",
                    "-c",
                    "3",
                    "-m",
                    str(max_hops),
                    target,
                ],
            )
        )

    if tr:
        if root:
            cands.append(
                (
                    "traceroute-tcp",
                    [
                        tr,
                        "-T",
                        "-p",
                        str(port),
                        "-m",
                        str(max_hops),
                        "-w",
                        "2",
                        target,
                    ],
                )
            )
        cands.append(
            (
                "traceroute-udp",
                [
                    tr,
                    "-U",
                    "-p",
                    str(port),
                    "-m",
                    str(max_hops),
                    "-w",
                    "2",
                    target,
                ],
            )
        )
        cands.append(
            (
                "traceroute-icmp",
                [
                    tr,
                    "-I",
                    "-m",
                    str(max_hops),
                    "-w",
                    "2",
                    target,
                ],
            )
        )

    if tp:
        cands.append(("tracepath", [tp, "-m", str(max_hops), target]))

    return cands


def _cymru_lookup(ips: list[str], timeout: float = 5.0) -> dict[str, dict]:
    """
    Батч-резолв IP → ASN и страна через Team Cymru (whois:43).

    Возвращает: {"83.219.128.0": {"as": "AS20485", "cc": "RU"}, ...}
    Если Cymru недоступен — пустой dict, никаких исключений.
    """
    clean = sorted({ip for ip in ips if ip and ip != "*"})
    if not clean:
        return {}

    try:
        with socket.create_connection((_CYMRU_HOST, _CYMRU_PORT), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(("begin\nverbose\n" + "\n".join(clean) + "\nend\n").encode())
            buf = b""
            while True:
                try:
                    chunk = s.recv(4096)
                except TimeoutError:
                    break
                if not chunk:
                    break
                buf += chunk
    except OSError:
        return {}

    out: dict[str, dict] = {}
    for line in buf.decode("utf-8", "replace").splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 4 or parts[0] == "AS":
            continue
        ip = parts[1]
        if ip.count(".") != 3:
            continue
        asn = f"AS{parts[0]}" if parts[0].isdigit() else None
        cc = parts[3] or None
        out[ip] = {"as": asn, "cc": cc}
    return out


def _parse_hops(raw: str) -> tuple[int, int, list[str]]:
    """
    Возвращает (total_hops, answered_hops, all_ips).
    Многострочные ответы mtr (multipath) учитываются как один хоп.
    """
    total = 0
    answered = 0
    ips: list[str] = []
    current_has_ip = False
    in_hop = False

    def flush() -> None:
        nonlocal answered
        if in_hop and current_has_ip:
            answered += 1

    for line in raw.splitlines():
        if _HOP_LINE_RE.match(line):
            flush()
            total += 1
            in_hop = True
            found = _IP_RE.findall(line)
            current_has_ip = bool(found)
            ips.extend(found)
        elif in_hop and line[:1] in (" ", "\t"):
            found = _IP_RE.findall(line)
            if found:
                current_has_ip = True
                ips.extend(found)

    flush()

    seen: set[str] = set()
    uniq: list[str] = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            uniq.append(ip)
    return total, answered, uniq


def traceroute_tcp(target: str, port: int = 443, max_hops: int = 30, timeout: float = 6.0) -> dict:
    res: dict = {
        "available": False,
        "tool": None,
        "raw": "",
        "stderr": "",
        "reached_target": False,
        "last_hop": None,
        "hops": 0,
        "answered_hops": 0,
        "unanswered_hops": 0,
        "all_as": [],
        "russian_as": [],
        "cymru": None,
        # --- признаки блокировки ---
        "early_silence": False,  # ранняя тишина в RU-AS
        "silence_after_first_as": False,  # чистый паттерн РКН: молчание сразу за ISP
        "blocked_in_ru": False,  # = early_silence (для совместимости)
        # --- прочее ---
        "truncated_early": False,
        "attempts": [],
        "needs_root": False,
        "hint": None,
    }

    cands = _candidates(target, port, max_hops)
    if not cands:
        res["error"] = "mtr/traceroute/tracepath not found"
        res["hint"] = "Установи: apt install mtr-tiny traceroute  (или brew install mtr)"
        return res

    for name, cmd in cands:
        stdout, stderr, rc = _run(cmd, timeout=timeout * max_hops)
        res["attempts"].append(
            {
                "name": name,
                "rc": rc,
                "stdout_len": len(stdout),
                "stderr": stderr.strip()[:300],
            }
        )

        if not stdout.strip():
            low = stderr.lower()
            if "permission" in low or "raw socket" in low or "operation not permitted" in low:
                res["needs_root"] = True
            continue

        total, answered, ips = _parse_hops(stdout)
        raw_as_set = {f"AS{m}" for m in _AS_RE.findall(stdout)}

        res.update(
            {
                "available": True,
                "tool": name,
                "raw": stdout,
                "stderr": stderr,
                "last_hop": ips[-1] if ips else None,
                "hops": total,
                "answered_hops": answered,
                "unanswered_hops": max(total - answered, 0),
                "reached_target": target in ips,
                "all_as": sorted(raw_as_set, key=lambda s: int(s[2:])),
                "russian_as": sorted(raw_as_set & RU_AS_FALLBACK),
            }
        )

        # --- Cymru: добираем AS и страну по IP-хопам ---
        # Нужен и для all_as, и для russian_as, если mtr без -z.
        if ips and (not res["all_as"] or not res["russian_as"]):
            cymru = _cymru_lookup(ips, timeout=5.0)
            if cymru:
                res["cymru"] = cymru
                as_from_cymru = {v["as"] for v in cymru.values() if v.get("as")}
                merged = raw_as_set | as_from_cymru
                res["all_as"] = sorted(merged, key=lambda s: int(s[2:]))
                ru_from_cymru = sorted(
                    v["as"] for v in cymru.values() if v.get("as") and v.get("cc") == "RU"
                )
                res["russian_as"] = ru_from_cymru or sorted(merged & RU_AS_FALLBACK)

        # ===========================================================
        # Признаки блокировки (модель «DPI у провайдера пользователя»)
        # ===========================================================
        unanswered = res["unanswered_hops"]

        # 1. Чистый паттерн РКН: цель не достигнута, ответило ≤2 хопа,
        #    среди них есть RU-AS, и трасса длиннее 5 хопов (то есть мы
        #    реально шли до max_hops, а не оборвались на первом же).
        #    Так выглядит блокировка с домашнего VPS: hop 1 = твой роутер,
        #    hop 2 = ISP, дальше — тишина.
        if not res["reached_target"] and total >= 5 and answered <= 2 and res["russian_as"]:
            res["silence_after_first_as"] = True

        # 2. Ранняя тишина (чуть слабее): ответило ≤3 хопов, большинство
        #    молчит, и есть RU-AS в трассе. Ловит случай, когда до обрыва
        #    успело ответить 3 хопа (например, ISP + его аплинк).
        if (
            not res["reached_target"]
            and total >= 5
            and 1 <= answered <= 3
            and res["russian_as"]
            and unanswered >= total / 2
        ):
            res["early_silence"] = True

        # Для совместимости со старым кодом:
        res["blocked_in_ru"] = res["early_silence"]

        # 3. Аннотация для отчёта (не влияет на вердикт напрямую).
        if not res["reached_target"] and answered >= 1 and unanswered >= 3:
            res["truncated_early"] = True

        if ips:
            break

    if not res["available"]:
        res["error"] = "all traceroute modes failed"
        if res["needs_root"]:
            res["hint"] = (
                "TCP-traceroute требует root. Запусти через sudo или выдай capabilities:\n"
                "  sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which mtr))\n"
                "  sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which traceroute))"
            )
    return res
