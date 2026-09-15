from deadip.verdict import compute_verdict, CONFIRMED, NONE, UNCERTAIN


def test_confirmed_on_full_set():
    checks = {
        "icmp": {"loss_percent": 100},
        "tcp": [{"port": 22, "connect": False},
                {"port": 80, "connect": False},
                {"port": 443, "connect": False}],
        "tls": {"tls": False, "error_kind": "timeout", "error": "timeout"},
        "traceroute": {"available": True,
                       "silence_after_first_as": True,
                       "early_silence": True,
                       "russian_as": ["AS31214"]},
        "control": {"reachable": True},
        "external": {"available": True, "ru_ok": False, "eu_ok": True},
    }
    v = compute_verdict(checks)
    assert v["verdict"] == CONFIRMED


def test_none_when_everything_ok():
    checks = {
        "icmp": {"loss_percent": 0},
        "tcp": [{"port": 443, "connect": True, "data_exchange": None}],
        "tls": {"tls": True, "tls_version": "TLSv1.3"},
        "traceroute": {"available": True, "reached_target": True},
        "control": {"reachable": True},
        "external": {"available": True, "ru_ok": True, "eu_ok": True},
    }
    v = compute_verdict(checks)
    assert v["verdict"] == NONE


def test_uncertain_when_tls_failed_non_dpi():
    checks = {
        "icmp": {"loss_percent": 0},
        "tcp": [{"port": 443, "connect": True, "data_exchange": None}],
        "tls": {"tls": False, "error_kind": "refused",
                "error": "[Errno 111] Connection refused"},
        "traceroute": {"available": True, "reached_target": True},
        "control": {"reachable": True},
        "external": {"available": True, "ru_ok": True, "eu_ok": True},
    }
    v = compute_verdict(checks)
    assert v["verdict"] in (UNCERTAIN, NONE)
