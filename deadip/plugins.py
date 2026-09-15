"""Примитивная система плагинов: entry points 'rkn_diag.plugins'."""

from __future__ import annotations

from importlib.metadata import entry_points


def load_plugins() -> list:
    try:
        eps = entry_points(group="deadIp.plugins")
    except TypeError:
        eps = entry_points().get("deadIp.plugins", [])
    plugins = []
    for ep in eps:
        try:
            plugins.append((ep.name, ep.load()))
        except Exception:
            continue
    return plugins


def run_plugins(target: str, context: dict) -> dict:
    results = {}
    for name, fn in load_plugins():
        try:
            results[name] = fn(target=target, context=context)
        except Exception as e:
            results[name] = {"error": str(e)}
    return results
