"""Слой 2: TCP handshake + проверка передачи данных.

На TLS-портах data-probe не выполняется: корректную проверку рукопожатия
делает отдельный слой tls.py. Иначе живой TLS-сервер молча ждёт полный
ClientHello до таймаута, и мы получаем ложный сигнал «connect, но данные
не пошли» → ложный вердикт «Вероятна блокировка».
"""

from __future__ import annotations

import socket
import time

# Порты, на которых «данные» имеет смысл проверять только через TLS-слой.
# Здесь мы их пропускаем — data_exchange вернётся как None.
TLS_PORTS = {443, 8443, 993, 995, 465, 636}

# Порты, где уместен HTTP HEAD-запрос.
HTTP_PORTS = {80, 8000, 8080, 8880}


def tcp_check(host: str, port: int, timeout: float = 5.0) -> dict:
    res = {
        "port": port,
        "connect": False,
        "data_exchange": None,  # None = «не применимо», а не «провал»
        "rtt_ms": None,
        "error": None,
        "banner": "",
    }

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.perf_counter()

    try:
        s.connect((host, port))
        res["connect"] = True
        res["rtt_ms"] = round((time.perf_counter() - t0) * 1000, 1)

        # На TLS-портах не шлём мусор: проверку рукопожатия делает tls.py.
        # data_exchange остаётся None — это «не применимо».
        if port in TLS_PORTS:
            return res

        # На HTTP-портах — валидный HEAD, ожидаем ответ.
        # На прочих (22, 25, 5432 и т.п.) — просто пробуем прочитать баннер
        # без отправки данных: ssh/smtp/postgres сами пишут первыми.
        try:
            if port in HTTP_PORTS:
                s.sendall(
                    b"HEAD / HTTP/1.0\r\nHost: "
                    + host.encode()
                    + b"\r\nUser-Agent: rkn-diag\r\n\r\n"
                )
            # сокет уже в blocking-режиме с timeout=timeout
            data = s.recv(512)
            res["data_exchange"] = True
            if data:
                res["banner"] = data[:120].hex()
        except (TimeoutError, ConnectionResetError, OSError) as e:
            res["data_exchange"] = False
            res["error"] = type(e).__name__

    except ConnectionResetError:
        res["error"] = "reset"
    except TimeoutError:
        res["error"] = "timeout"
    except ConnectionRefusedError:
        res["error"] = "refused"
    except OSError as e:
        res["error"] = str(e)
    finally:
        try:
            s.close()
        except OSError:
            pass

    return res
