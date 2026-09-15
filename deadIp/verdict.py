CONFIRMED = "Блокировка подтверждена"
LIKELY    = "Вероятна блокировка"
NONE      = "Блокировка не обнаружена"
UNCERTAIN = "Неопределённость"

TLS_PORTS = {443, 8443, 993, 995, 465, 636}


def compute_verdict(checks: dict) -> dict:
    icmp    = checks.get("icmp") or {}
    tcp_list = checks.get("tcp") or []
    tls     = checks.get("tls") or {}
    trace   = checks.get("traceroute") or {}
    control = checks.get("control") or {}
    ext     = checks.get("external") or {}

    # --- ICMP ---
    loss = icmp.get("loss_percent")
    icmp_fail = loss is not None and loss >= 80

    # --- TCP ---
    tcp_all_fail = bool(tcp_list) and all(not t.get("connect") for t in tcp_list)
    tcp_conn_but_dpi = any(
        t.get("connect")
        and t.get("data_exchange") is False
        and t["port"] not in TLS_PORTS
        for t in tcp_list
    )

    # --- TLS ---
    tls_ok    = bool(tls.get("tls"))
    tls_kind  = tls.get("error_kind")
    tls_dpi   = (not tls_ok) and tls_kind in ("reset", "eof")
    # tls_fail — любой провал (в т.ч. timeout), кроме cert-ошибки
    tls_fail  = (not tls_ok) and tls_kind not in (None, "cert")

    # --- Трассировка ---
    trace_ru_soft = bool(trace.get("early_silence"))
    trace_ru_hard = bool(trace.get("silence_after_first_as"))
    trace_ru = trace_ru_soft or trace_ru_hard   # для обратной совместимости

    # --- Контроль ---
    control_ok = bool(control.get("reachable"))

    # --- Внешний слой (Globalping) ---
    ext_avail  = bool(ext.get("available"))
    ext_ru_ok  = ext.get("ru_ok")   # True | False | None
    ext_eu_ok  = ext.get("eu_ok")
    # Явный признак блокировки: РФ не видит, а зарубеж — видит
    ext_ru_block = (
        ext_avail
        and ext_ru_ok is False
        and ext_eu_ok is True
    )

    signals = {
        "icmp_fail": icmp_fail,
        "tcp_all_fail": tcp_all_fail,
        "tcp_conn_but_dpi": tcp_conn_but_dpi,
        "tls_ok": tls_ok,
        "tls_dpi": tls_dpi,
        "tls_fail": tls_fail,
        "trace_ru_soft": trace_ru_soft,
        "trace_ru_hard": trace_ru_hard,
        "control_ok": control_ok,
        "ext_ru_block": ext_ru_block,
    }

    # Контроль-группа тоже недоступна → проблема не в целевом IP
    if control and not control_ok and not ext_avail:
        return {
            "verdict": NONE,
            "reason": "Контрольный ресурс тоже недоступен — проблема на стороне клиента/провайдера.",
            "signals": signals,
        }

    # Чистый паттерн РКН (тишина сразу за ISP) — самый сильный локальный сигнал.
    # Он одного уровня с Globalping RU≠EU. Мягкий сигнал (early_silence) требует
    # ещё одного подтверждения, чтобы дойти до CONFIRMED.
    confirmed = (
        control_ok
        and icmp_fail
        and tcp_all_fail
        and (ext_ru_block or trace_ru_hard or tls_dpi)
    )

    # Грубый счёт на случай, если подтверждения нет
    score = sum([
        icmp_fail,
        tcp_all_fail,
        trace_ru,
        tls_dpi,
        ext_ru_block,
    ])

    if confirmed or score >= 3:
        v = CONFIRMED
        parts = []
        if ext_ru_block:
            parts.append("Globalping: РФ не видит, ЕС видит")
        if trace_ru:
            parts.append(f"обрыв трассы на AS {', '.join(trace.get('russian_as') or [])}")
        if tls_dpi:
            parts.append("TLS: RST/EOF (DPI)")
        reason = "Признаки блокировки: " + "; ".join(parts) + "."
    elif score >= 2 or tcp_conn_but_dpi or tls_dpi or ext_ru_block or trace_ru:
        v = LIKELY
        reason = "Зафиксирована часть признаков блокировки/DPI-фильтрации."
    elif tls_fail and not tls_ok:
        v = UNCERTAIN
        reason = f"TLS-слой завершился ошибкой ({tls.get('error')!r}) — недостаточно данных."
    elif control_ok and not (icmp_fail or tcp_all_fail or tls_dpi or tls_fail
                             or trace_ru or ext_ru_block):
        v = NONE
        reason = "Все проверки прошли успешно."
    else:
        v = UNCERTAIN
        reason = "Недостаточно данных для однозначного вывода."

    return {"verdict": v, "reason": reason, "signals": signals, "score": score}
