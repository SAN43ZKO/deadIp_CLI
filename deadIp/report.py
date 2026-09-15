"""Формирование Markdown-отчёта и JSON."""
from __future__ import annotations
import json
from datetime import datetime, timezone, timedelta

MSK = timezone(timedelta(hours=3))


def _fmt_bool_icon(v: bool) -> str:
    return "✅" if v else "❌"


def build_markdown(target: str, resolved: dict, checks: dict,
                   verdict: dict, user_ip_masked: str | None = None) -> str:
    now = datetime.now(MSK).strftime("%Y-%m-%d %H:%M MSK")
    ip = resolved.get("ip") or "—"
    domain = resolved.get("domain") or "—"

    rows = []
    icmp = checks.get("icmp") or {}
    loss = icmp.get("loss_percent")
    ok = loss is not None and loss < 80
    rows.append(("1", "ICMP ping",
                 _fmt_bool_icon(loss is not None and loss < 80),
                 f"{loss}% loss" if loss is not None else (icmp.get("error") or "—")))

    for t in checks.get("tcp") or []:
        connect = t.get("connect")
        data = t.get("data_exchange")   # True / False / None

        if connect and (data is True or data is None):
            # порт открыт, для TLS-портов None = «ОК, проверит tls.py»
            ok = True
        elif connect and data is False:
            ok = False                  # connect есть, но DPI оборвал данные
        else:
            ok = False                  # connect нет вообще

        if not connect:
            detail = t.get("error") or "—"
        elif data is False:
            detail = f"RTT {t.get('rtt_ms')} ms; data fail: {t.get('error')}"
        elif data is None:
            detail = f"RTT {t.get('rtt_ms')} ms; probe skipped (TLS layer)"
        else:
            detail = f"RTT {t.get('rtt_ms')} ms"
        rows.append(("2", f"TCP {t['port']}", _fmt_bool_icon(ok), detail))

    tls = checks.get("tls") or {}
    tls_ok = bool(tls.get("tls"))
    if not tls_ok:
        det = f"{tls.get('error_kind') or 'error'}: {tls.get('error')}"
        if tls.get("attempts", 1) > 1:
            det += f" (после {tls['attempts']} попыток)"
    else:
        det = tls.get("tls_version") or "—"
    rows.append(("3", f"TLS {tls.get('port', 443)}",
                _fmt_bool_icon(tls_ok), det))

    tr = checks.get("traceroute") or {}
    if not tr.get("available"):
        tr_ok = False
        tr_det = tr.get("hint") or tr.get("error") or "—"
    else:
        # «Успех» = цель достигнута. Признак блокировки отобразим в тексте.
        tr_ok = bool(tr.get("reached_target"))
        all_as = tr.get("all_as") or []
        ru_as  = set(tr.get("russian_as") or [])
        as_str = ", ".join(f"{a} (RU)" if a in ru_as else a for a in all_as) or "—"
        tr_det = (f"last hop {tr.get('last_hop') or '—'}; "
                  f"hops {tr.get('answered_hops', 0)}/{tr.get('hops', 0)}; "
                  f"AS: {as_str}")
        if tr.get("silence_after_first_as"):
            tr_det += " — **трафик умирает сразу за ISP (признак блокировки в РФ)**"
        elif tr.get("early_silence"):
            tr_det += " — **ранняя тишина в RU-AS (возможна блокировка)**"
        elif tr.get("truncated_early"):
            tr_det += " — много молчащих хопов"

    rows.append(("4", f"MTR (TCP {tls.get('port', 443)})",
                 _fmt_bool_icon(tr_ok), tr_det))

    ctrl = checks.get("control") or {}
    rows.append(("5", "Контроль (ya.ru)",
                 _fmt_bool_icon(bool(ctrl.get("reachable"))),
                 ctrl.get("detail") or "—"))

    ext = checks.get("external") or {}
    if ext.get("available"):
        rows.append(("6", "Globalping",
                     _fmt_bool_icon(bool(ext.get("eu_ok")) and not ext.get("ru_ok")),
                     f"RU: {ext.get('ru_ok')}, EU: {ext.get('eu_ok')}"))

    lines = [
        f"# Отчёт о диагностике IP: {ip}",
        "",
        f"**Дата:** {now}",
        f"**Целевой IP:** {ip}",
        f"**Целевой домен:** {domain}",
    ]
    if user_ip_masked:
        lines.append(f"**Источник проверки (замаскирован):** {user_ip_masked}")
    lines += ["", "## Результаты", "",
              "| Слой | Проверка | Результат | Детали |",
              "|------|----------|-----------|--------|"]
    for r in rows:
        lines.append(f"| {r[0]} | {r[1]} | {r[2]} | {r[3]} |")

    tr = checks.get("traceroute") or {}
    if tr.get("russian_as"):
        lines += ["", "### Детали трассировки", ""]
        if tr.get("silence_after_first_as"):
            lines.append(
                f"Трасса до `{resolved.get('ip')}` обрывается сразу за "
                f"провайдером пользователя: ответили только "
                f"{tr.get('answered_hops', 0)} хопов из {tr.get('hops', 0)}, "
                f"дальше — тишина. Это характерный признак блокировки "
                f"на стороне РКН/ТСПУ через провайдера."
            )
        elif tr.get("early_silence"):
            lines.append(
                f"Трасса до `{resolved.get('ip')}` обрывается на раннем этапе: "
                f"ответили {tr.get('answered_hops', 0)} хопов из "
                f"{tr.get('hops', 0)}. Возможна блокировка в РФ."
            )
        if tr.get("russian_as"):
            lines.append("")
            lines.append(
                f"Российские AS в трассе: **{', '.join(tr['russian_as'])}**."
            )

    lines += ["", f"## Вердикт: {verdict['verdict'].upper()}", "",
              verdict["reason"], ""]
    return "\n".join(lines)


def build_json(target: str, resolved: dict, checks: dict, verdict: dict) -> str:
    return json.dumps(
        {
            "target": target,
            "resolved": resolved,
            "checks": checks,
            "verdict": verdict,
            "generated_at": datetime.now(MSK).isoformat(),
        },
        ensure_ascii=False,
        indent=2,
    )
