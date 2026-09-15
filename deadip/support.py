"""Генерация шаблона обращения в техподдержку (RU + EN).

Шаблон должен давать техподдержке провайдера VPS всё, что нужно для
подтверждения блокировки и замены IP:
  - краткая сводка по слоям (ICMP/TCP/TLS/контроль);
  - сырой вывод трассировки — главный аргумент, потому что именно по нему
    видно «трафик умирает сразу за ISP»;
  - команда, которой это можно воспроизвести;
  - автоматический вердикт с обоснованием.

ВАЖНО про ограждения кода:
  Внутри f-строк используются ~~~ (тильды), а не ``` (обратные кавычки),
  чтобы не ломать рендер при копировании текста из Markdown-чатов.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

MSK = timezone(timedelta(hours=3))

# Сколько строк сырого вывода MTR включать в шаблон.
_TRACE_MAX_LINES = 40

# Реконструкция команд по имени tool (для раздела «как воспроизвести»).
_TOOL_CMDS = {
    "mtr-tcp": "sudo mtr -r -b -z -c 3 -T -P {port} -m 30 {target}",
    "mtr-udp": "mtr -r -b -z -c 3 -u -P {port} -m 30 {target}",
    "mtr-icmp": "mtr -r -b -z -c 3 -m 30 {target}",
    "mtr-plain": "mtr -r -b -c 3 -m 30 {target}",
    "traceroute-tcp": "sudo traceroute -T -p {port} -m 30 -w 2 {target}",
    "traceroute-udp": "traceroute -U -p {port} -m 30 -w 2 {target}",
    "traceroute-icmp": "traceroute -I -m 30 -w 2 {target}",
    "tracepath": "tracepath -m 30 {target}",
}


# ---------- helpers ----------


def _fmt_icmp(icmp: dict) -> str:
    loss = icmp.get("loss_percent")
    if loss is None:
        return "нет данных"
    return f"{loss:g}% потерь"


def _fmt_tcp_lines(tcp_list: list[dict]) -> list[str]:
    out: list[str] = []
    for t in tcp_list:
        port = t.get("port")
        if t.get("connect") and t.get("data_exchange") in (True, None):
            rtt = t.get("rtt_ms")
            rtt_str = f", RTT {rtt} ms" if rtt is not None else ""
            if t.get("data_exchange") is None:
                out.append(
                    f"  - TCP {port}: соединение установлено{rtt_str} (TLS проверяется отдельно)"
                )
            else:
                out.append(f"  - TCP {port}: соединение установлено{rtt_str}")
        else:
            err = t.get("error") or "нет ответа"
            out.append(f"  - TCP {port}: {err}")
    return out or ["  - нет данных"]


def _fmt_tls(tls: dict) -> str:
    if tls.get("tls"):
        v = tls.get("tls_version") or "TLS"
        cn = tls.get("cert_cn")
        return f"рукопожатие успешно ({v}{', CN=' + cn if cn else ''})"
    kind = tls.get("error_kind") or "error"
    return f"не выполнено — {kind}: {tls.get('error')}"


def _fmt_as_list(trace: dict) -> str:
    all_as = trace.get("all_as") or []
    ru_as = set(trace.get("russian_as") or [])
    if not all_as:
        return "—"
    return ", ".join(f"{a} (RU)" if a in ru_as else a for a in all_as)


def _trace_block(trace: dict, max_lines: int = _TRACE_MAX_LINES) -> str:
    """Сырой вывод MTR/traceroute, очищенный от шапок."""
    raw = trace.get("raw") or ""
    if not raw.strip():
        return "(трассировка не дала вывода)"

    out: list[str] = []
    for line in raw.splitlines():
        s = line.rstrip()
        if not s:
            out.append("")
            continue
        if s.startswith(("Start:", "HOST:", "traceroute to ")):
            continue
        out.append(s)

    while out and not out[-1].strip():
        out.pop()

    if len(out) > max_lines:
        out = out[:max_lines] + ["... (усечено)"]

    return "\n".join(out)


def _reproduce_cmd(trace: dict, target: str, port: int = 443) -> str | None:
    tool = trace.get("tool")
    if not tool:
        return None
    tpl = _TOOL_CMDS.get(tool)
    if not tpl:
        return None
    return tpl.format(port=port, target=target)


def _trace_summary(trace: dict) -> str:
    if not trace.get("available"):
        return "трассировка не выполнена"
    answered = trace.get("answered_hops", 0)
    total = trace.get("hops", 0)
    last = trace.get("last_hop") or "—"
    as_list = _fmt_as_list(trace)

    if trace.get("reached_target"):
        return f"цель достигнута за {total} хопов; AS: {as_list}"

    if trace.get("silence_after_first_as"):
        return (
            f"трафик умирает сразу за ISP: "
            f"ответили только {answered} из {total} хопов, "
            f"последний видимый — {last}; AS: {as_list}"
        )
    if trace.get("early_silence"):
        return (
            f"ранняя тишина: ответили {answered} из {total} хопов, "
            f"последний — {last}; AS: {as_list}"
        )
    return (
        f"цель не достигнута; ответили {answered} из {total} хопов, "
        f"последний — {last}; AS: {as_list}"
    )


def _fmt_ext(ext: dict) -> str | None:
    if not ext or not ext.get("available"):
        return None
    ru = "видят" if ext.get("ru_ok") else "не видят"
    eu = "видят" if ext.get("eu_ok") else "не видят"
    return f"RU-пробы: {ru}; EU-пробы: {eu}"


# ---------- основной рендер ----------


def render_support_template(
    ip: str,
    verdict: dict,
    checks: dict,
    resolved: dict | None = None,
    target: str | None = None,
) -> str:
    now = datetime.now(MSK).strftime("%Y-%m-%d %H:%M MSK")
    target = target or ip
    domain = (resolved or {}).get("domain")

    icmp = checks.get("icmp") or {}
    tcp = checks.get("tcp") or []
    tls = checks.get("tls") or {}
    trace = checks.get("traceroute") or {}
    control = checks.get("control") or {}
    ext = checks.get("external") or {}

    tcp_lines = "\n".join(_fmt_tcp_lines(tcp))
    trace_block = _trace_block(trace)
    trace_summary = _trace_summary(trace)
    reproduce = (
        _reproduce_cmd(trace, target, port=tls.get("port", 443))
        or f"mtr -r -z -b -c 3 -T -P {tls.get('port', 443)} -m 30 {target}"
    )
    ext_line = _fmt_ext(ext)

    ctrl_ru = "доступен" if control.get("reachable") else "недоступен"
    ctrl_en = "reachable" if control.get("reachable") else "unreachable"

    verdict_text = verdict.get("verdict", "—")
    reason_text = verdict.get("reason", "")

    target_label = ip + (f" ({domain})" if domain and domain != ip else "")

    # Строка про внешнюю проверку добавляется, только если она есть.
    ext_ru_line = f"- Внешняя проверка (Globalping): {ext_line}\n" if ext_line else ""
    ext_en_line = f"- External check (Globalping): {ext_line}\n" if ext_line else ""

    # ============================================================
    # RU-версия
    # Внутри f-строк используем ~~~ для блоков кода, а не ```
    # ============================================================
    ru = f"""**Тема:** Запрос на замену IP — блокировка из РФ (VPS {ip})

**Сообщение:**

Здравствуйте!

Мой VPS {target_label} недоступен из Российской Федерации.
Проверка выполнена: {now}.

### Краткая сводка

- ICMP ping: {_fmt_icmp(icmp)}
- TCP-порты:
{tcp_lines}
- TLS ({tls.get('port', 443)}): {_fmt_tls(tls)}
- Контроль (ya.ru): {ctrl_ru} — проблема изолирована на моём IP
- Трассировка: {trace_summary}
{ext_ru_line}
### Трассировка до {ip} — сырой вывод

Команда для воспроизведения:

~~~
{reproduce}
~~~

Вывод:

~~~
{trace_block}
~~~

### Вердикт автоматической диагностики

**{verdict_text}**

{reason_text}

### Просьба

Причина недоступности — блокировка на стороне РКН/ТСПУ: трафик
дропается молча, трасса обрывается сразу за провайдером пользователя,
ICMP/TCP до цели не проходят. При этом контрольный ресурс (ya.ru)
через того же провайдера работает, а сам сервер доступен из ЕС.

Прошу заменить IP-адрес на новый, не входящий в блокировочные списки РФ.

С уважением,
[Ваше имя]
"""

    # ============================================================
    # EN-версия
    # ============================================================
    tcp_lines_en = (
        tcp_lines.replace("соединение установлено", "connected")
        .replace("нет ответа", "no response")
        .replace("нет данных", "no data")
        .replace("(TLS проверяется отдельно)", "(TLS checked separately)")
    )
    icmp_en = _fmt_icmp(icmp).replace("потерь", "% loss").replace("нет данных", "no data")

    en = f"""**Subject:** IP replacement request — blocked from Russia (VPS {ip})

**Message:**

Hello,

My VPS {target_label} is unreachable from the Russian Federation.
Check performed: {now}.

### Summary

- ICMP ping: {icmp_en}
- TCP ports:
{tcp_lines_en}
- TLS ({tls.get('port', 443)}): {_fmt_tls(tls)}
- Control host (ya.ru): {ctrl_en} — the issue is isolated to my IP
- Traceroute: {trace_summary}
{ext_en_line}
### Traceroute to {ip} — raw output

Reproduce with:

~~~
{reproduce}
~~~

Output:

~~~
{trace_block}
~~~

### Automated verdict

**{verdict_text}**

{reason_text}

### Request

The IP is being silently dropped by the Russian RKN/TSPU filtering
on the customer ISP side: the trace dies right after the ISP hop,
ICMP/TCP to the target do not pass, while the control host (ya.ru)
works through the same provider and the server is reachable from the EU.

Please assign a new IP that is not present in Russian blocklists.

Best regards,
[Your name]
"""

    return ru + "\n---\n\n" + en
