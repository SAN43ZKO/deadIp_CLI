"""Слой 3: TLS handshake — детектор DPI/SNI-фильтрации."""
from __future__ import annotations

import socket
import ssl
import time


def tls_check(host: str, port: int = 443, sni: str | None = None,
              timeout: float = 5.0, retries: int = 2) -> dict:
    res = {
        "port": port,
        "sni": sni,
        "tls": False,
        "error": None,
        "error_kind": None,   # "refused" | "reset" | "timeout" | "tls" | "cert" | "eof" | None
        "tls_version": None,
        "cert_cn": None,
        "attempts": 0,
    }

    last_err: Exception | None = None

    for attempt in range(retries + 1):
        res["attempts"] = attempt + 1
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                # контекст создаём ПОСЛЕ TCP-connect: не тратим время при refused
                ctx = ssl.create_default_context()
                if not sni:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE

                with ctx.wrap_socket(sock, server_hostname=sni) as ss:
                    res["tls"] = True
                    res["tls_version"] = ss.version()
                    try:
                        cert = ss.getpeercert() or {}
                        subj = dict(x[0] for x in cert.get("subject", []))
                        res["cert_cn"] = subj.get("commonName")
                    except Exception:
                        pass
                    return res

        except ConnectionRefusedError as e:
            last_err = e
            res["error_kind"] = "refused"
            res["error"] = f"[Errno 111] Connection refused"
        except ConnectionResetError as e:
            last_err = e
            res["error_kind"] = "reset"          # ← классический DPI
            res["error"] = "connection reset"
        except socket.timeout as e:
            last_err = e
            res["error_kind"] = "timeout"
            res["error"] = "timeout"
        except ssl.SSLEOFError as e:
            last_err = e
            res["error_kind"] = "eof"            # ← ТСПУ часто рвёт FIN'ом
            res["error"] = "unexpected EOF during handshake"
        except ssl.SSLCertVerificationError as e:
            # сертификат не про SNI — это не блокировка, а самоподписанный/чужой
            last_err = e
            res["error_kind"] = "cert"
            res["error"] = f"cert verify failed: {e.verify_message}"
            # повторять смысла нет — рукопожатие дошло до cert-фазы
            return res
        except ssl.SSLError as e:
            last_err = e
            res["error_kind"] = "tls"
            res["error"] = f"SSLError: {e}"
        except OSError as e:
            last_err = e
            res["error_kind"] = "os"
            res["error"] = str(e)

        # retry только для транзиентных сетевых ошибок
        if res["error_kind"] not in ("refused", "timeout", "reset", "eof"):
            break
        if attempt < retries:
            time.sleep(0.5 * (attempt + 1))

    res["error"] = res.get("error") or (str(last_err) if last_err else "unknown")
    return res
