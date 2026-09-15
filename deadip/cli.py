"""CLI-точка входа rkn-diag."""

from __future__ import annotations

import sys
from pathlib import Path

import httpx
import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .checks import external, icmp, tcp, tls, traceroute
from .dns_resolver import resolve_target
from .plugins import run_plugins
from .rawlog import previous_for, save_raw
from .report import build_json, build_markdown
from .support import render_support_template
from .verdict import CONFIRMED, LIKELY, NONE, UNCERTAIN, compute_verdict

app = typer.Typer(add_completion=False, help="Диагностика блокировки IP из РФ (РКН/ТСПУ).")
console = Console()

_VERDICT_STYLE = {
    CONFIRMED: "bold red",
    LIKELY: "bold yellow",
    NONE: "bold green",
    UNCERTAIN: "bold blue",
}


def _get_my_ip(timeout: float = 5.0) -> str | None:
    try:
        r = httpx.get("https://api.ipify.org", timeout=timeout)
        r.raise_for_status()
        return r.text.strip()
    except Exception:
        return None


def _mask(text: str, my_ip: str | None) -> str:
    if my_ip:
        text = text.replace(my_ip, "xxx.xxx.xxx.xxx")
    return text


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"[bold cyan]deadip[/bold cyan] [dim]{__version__}[/dim]")
        raise typer.Exit()


@app.command()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Показать версию и выйти.",
        callback=_version_callback,
        is_eager=True,
    ),
    target: str = typer.Option(..., "--target", "-t", help="IP или домен"),
    ports: str = typer.Option("22,80,443", "--ports", help="TCP-порты через запятую"),
    timeout: float = typer.Option(5.0, "--timeout", help="Таймаут на этап, сек"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Путь для Markdown-отчёта"),
    support_template: bool = typer.Option(
        False, "--support-template", help="Сгенерировать шаблон обращения"
    ),
    json_out: bool = typer.Option(False, "--json", help="Вывод в JSON (в stdout)"),
    no_control: bool = typer.Option(False, "--no-control", help="Пропустить контрольную группу"),
    skip_external: bool = typer.Option(False, "--skip-external", help="Пропустить Globalping"),
    no_color: bool = typer.Option(False, "--no-color", help="Отключить цвета"),
):
    if no_color:
        console.no_color = True

    err_console = Console(stderr=True, no_color=no_color)
    ui = err_console if json_out else console

    ui.rule(f"[bold]deadip[/bold] v{__version__}")

    # 0. Резолвинг
    resolved = resolve_target(target, timeout=timeout)
    if not resolved.get("ip"):
        ui.print(f"[red]Не удалось разрешить {target}[/red]")
        raise typer.Exit(code=2)
    ip = resolved["ip"]
    ui.print(f"Target: [cyan]{target}[/cyan] → [bold]{ip}[/bold]")

    checks: dict = {}

    # 1. ICMP
    with ui.status("Слой 1: ICMP ping..."):
        checks["icmp"] = icmp.ping(ip, count=10, timeout=min(timeout, 2.0))

    # 2. TCP
    port_list = [int(p.strip()) for p in ports.split(",") if p.strip()]
    checks["tcp"] = []
    for p in port_list:
        with ui.status(f"Слой 2: TCP {p}..."):
            checks["tcp"].append(tcp.tcp_check(ip, p, timeout=timeout))

    # 3. TLS
    with ui.status("Слой 3: TLS handshake..."):
        checks["tls"] = tls.tls_check(ip, port=443, sni=resolved.get("sni"), timeout=timeout)

    # 4. MTR
    with ui.status("Слой 4: MTR (TCP 443)..."):
        checks["traceroute"] = traceroute.traceroute_tcp(ip, port=443, timeout=min(timeout, 3.0))

    # 5. Контроль
    if not no_control:
        with ui.status("Слой 5: контрольная группа (ya.ru)..."):
            control_ip = resolve_target("ya.ru", timeout=timeout).get("ip") or "ya.ru"
            c_ping = icmp.ping(control_ip, count=5, timeout=min(timeout, 2.0))
            c_tcp = tcp.tcp_check(control_ip, 443, timeout=timeout)
            loss = c_ping.get("loss_percent")
            loss_ok = loss is not None and loss < 50
            reachable = loss_ok and bool(c_tcp.get("connect"))
            checks["control"] = {
                "reachable": reachable,
                "detail": f"icmp {c_ping.get('loss_percent')}%, tcp443 {'ok' if c_tcp.get('connect') else 'fail'}",
            }

    # 6. External
    if not skip_external:
        with ui.status("Слой 6: Globalping..."):
            checks["external"] = external.globalping_compare(ip, timeout=timeout * 8)

    # Плагины
    plugins = run_plugins(ip, {"resolved": resolved, "checks": checks})
    if plugins:
        checks["plugins"] = plugins

    # Вердикт
    verdict = compute_verdict(checks)

    # ------- Вывод -------
    if json_out:
        # Ключевой момент: JSON пишем в stdout напрямую, без rich.
        # Rich умеет переносить строки и экранировать символы — это ломает JSON.
        sys.stdout.write(build_json(target, resolved, checks, verdict))
        sys.stdout.write("\n")
        sys.stdout.flush()
    else:
        _print_table(resolved, checks)
        style = _VERDICT_STYLE.get(verdict["verdict"], "bold")
        console.print(
            Panel.fit(
                f"[{style}]{verdict['verdict']}[/{style}]\n{verdict['reason']}",
                title="Вердикт",
                border_style=style.split()[-1],
            )
        )

    # ------- Отчёт -------
    my_ip = _get_my_ip()
    md = _mask(
        build_markdown(
            target, resolved, checks, verdict, user_ip_masked="xxx.xxx.xxx.xxx" if my_ip else None
        ),
        my_ip,
    )

    if output:
        output.write_text(md, encoding="utf-8")
        ui.print(f"[green]Отчёт сохранён:[/green] {output}")

    # ------- Шаблон поддержки -------
    if support_template:
        tpl = render_support_template(
            ip,
            verdict,
            checks,
            resolved=resolved,
            target=target,
        )
        if output:
            side = output.with_suffix(".support.md")
            side.write_text(tpl, encoding="utf-8")
            ui.print(f"[green]Шаблон сохранён:[/green] {side}")
        else:
            # --support-template без --output: сохраняем в текущий каталог,
            # в консоль ничего не печатаем.
            side = Path(f"rkn-diag-{ip.replace(':', '_')}.support.md")
            side.write_text(tpl, encoding="utf-8")
            ui.print(f"[green]Шаблон сохранён:[/green] {side}")

    # ------- Сырой лог + сравнение -------
    prev = previous_for(target)
    save_raw(
        {
            "target": target,
            "resolved": resolved,
            "checks": checks,
            "verdict": verdict,
        }
    )
    if prev and prev.get("verdict", {}).get("verdict") != verdict["verdict"]:
        console.print(
            f"[yellow]Δ с прошлым запуском:[/yellow] "
            f"{prev['verdict']['verdict']} → {verdict['verdict']}"
        )


def _print_table(resolved: dict, checks: dict) -> None:
    table = Table(title=f"Результаты для {resolved['ip']}", box=box.SIMPLE_HEAVY)
    table.add_column("Слой", style="dim")
    table.add_column("Проверка")
    table.add_column("Результат")
    table.add_column("Детали", overflow="fold")

    icmp = checks.get("icmp") or {}
    loss = icmp.get("loss_percent")
    ok = loss is not None and loss < 80
    table.add_row(
        "1",
        "ICMP ping",
        "[green]✓[/green]" if ok else "[red]✗[/red]",
        f"{loss}% loss" if loss is not None else (icmp.get("error") or "—"),
    )

    for t in checks.get("tcp") or []:
        connect = t.get("connect")
        data = t.get("data_exchange")  # True / False / None

        if connect and (data is True or data is None):
            # порт открыт, для TLS-портов None = «ОК, проверит tls.py»
            ok = True
        elif connect and data is False:
            ok = False  # connect есть, но DPI оборвал данные
        else:
            ok = False  # connect нет вообще

        if not connect:
            detail = t.get("error") or "—"
        elif data is False:
            detail = f"RTT {t.get('rtt_ms')} ms; data fail: {t.get('error')}"
        elif data is None:
            detail = f"RTT {t.get('rtt_ms')} ms; probe skipped (TLS layer)"
        else:
            detail = f"RTT {t.get('rtt_ms')} ms"

        table.add_row("2", f"TCP {t['port']}", "[green]✓[/green]" if ok else "[red]✗[/red]", detail)

    tls = checks.get("tls") or {}
    tls_ok = bool(tls.get("tls"))
    if not tls_ok:
        det = f"{tls.get('error_kind') or 'error'}: {tls.get('error')}"
        if tls.get("attempts", 1) > 1:
            det += f" (после {tls['attempts']} попыток)"
    else:
        det = tls.get("tls_version") or "—"
    table.add_row(
        "3", f"TLS {tls.get('port', 443)}", "[green]✓[/green]" if tls_ok else "[red]✗[/red]", det
    )

    tr = checks.get("traceroute") or {}
    if not tr.get("available"):
        icon, det = "[red]✗[/red]", tr.get("hint") or tr.get("error") or "—"
    else:
        if tr.get("reached_target"):
            icon = "[green]✓[/green]"
        elif tr.get("silence_after_first_as") or tr.get("early_silence"):
            icon = "[red]✗[/red]"  # не жёлтый: это уже сигнал блокировки
        else:
            icon = "[yellow]~[/yellow]"

        parts = [
            f"last hop {tr.get('last_hop') or '—'}",
            f"hops {tr.get('answered_hops', 0)}/{tr.get('hops', 0)}",
        ]
        all_as = tr.get("all_as") or []
        ru_as = set(tr.get("russian_as") or [])
        if all_as:
            parts.append("AS: " + ", ".join(f"{a}🇷🇺" if a in ru_as else a for a in all_as))
        else:
            parts.append("AS: —")

        if tr.get("silence_after_first_as"):
            parts.append("[red](трафик умирает сразу за ISP — признак блокировки в РФ)[/red]")
        elif tr.get("early_silence"):
            parts.append("[red](ранняя тишина в RU-AS — возможна блокировка)[/red]")
        elif tr.get("truncated_early"):
            parts.append("[yellow](много молчащих хопов)[/yellow]")

        det = "; ".join(parts)

    table.add_row("4", "MTR", icon, det)

    ctrl = checks.get("control") or {}
    if ctrl:
        table.add_row(
            "5",
            "Контроль (ya.ru)",
            "[green]✓[/green]" if ctrl.get("reachable") else "[red]✗[/red]",
            ctrl.get("detail") or "—",
        )

    ext = checks.get("external") or {}
    if ext.get("available"):
        table.add_row(
            "6",
            "Globalping",
            "[green]✓[/green]"
            if (ext.get("eu_ok") and not ext.get("ru_ok"))
            else "[yellow]?[/yellow]",
            f"RU: {ext.get('ru_ok')}, EU: {ext.get('eu_ok')}",
        )

    console.print(table)


if __name__ == "__main__":
    app()
