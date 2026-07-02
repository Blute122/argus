"""Fast, dependency-light smoke tests for core logic (no DB/network needed)."""

import time


def test_sigma_streaming_match():
    from backend.detection.sigma import SigmaRule
    rule = SigmaRule({
        "title": "PS", "level": "critical", "tags": ["attack.t1059.001"],
        "detection": {
            "selection": {"event_type": "powershell_execution", "command_line|contains": ["-enc", "iex"]},
            "condition": "selection",
        },
    }, "ps")
    assert rule.severity == "critical"
    assert rule.technique == "T1059.001"
    assert rule.matches({"event_type": "powershell_execution", "command_line": "powershell -enc AAA"})
    assert not rule.matches({"event_type": "powershell_execution", "command_line": "Get-Process"})
    assert not rule.matches({"event_type": "process_start", "command_line": "iex x"})


def test_sigma_condition_operators():
    from backend.detection.sigma import SigmaRule
    rule = SigmaRule({
        "title": "c",
        "detection": {
            "a": {"event_type": "login"}, "b": {"severity": "high"},
            "filter": {"username": "svc"}, "condition": "(a or b) and not filter",
        },
    }, "c")
    assert rule.matches({"event_type": "login", "username": "alice"})
    assert not rule.matches({"event_type": "login", "username": "svc"})


def test_query_translator_mixed_bool():
    from backend.search.query_translator import build_query
    q = build_query("event_type=failed_login OR event_type=ssh_failed_login earliest=-5m")
    # ((a OR b) AND time)
    assert q["bool"]["must"][0]["bool"]["should"]
    assert q["bool"]["must"][1]["range"]["@timestamp"]["gte"]


def test_syslog_parse():
    from backend.ingestion.parsers import parse
    ev = parse("<34>Oct 11 22:14:15 web01 sshd[1234]: Failed password", source_type="syslog")
    assert ev["source"] == "syslog"
    assert ev["hostname"] == "web01"
    assert ev["process_name"] == "sshd"
    assert ev["severity"] == "critical"


def test_json_passthrough_aliases():
    from backend.ingestion.parsers import parse
    ev = parse('{"source":"windows","event_type":"failed_login","src_ip":"1.2.3.4","message":"x"}')
    assert ev["source_ip"] == "1.2.3.4"
    assert ev["raw_log"] == "x"


def test_totp_roundtrip():
    from backend import mfa
    secret = mfa.generate_secret()
    code = mfa._hotp(secret, int(time.time() // 30))
    assert mfa.verify(secret, code)
    assert not mfa.verify(secret, "000000")


def test_ratelimit_window():
    from backend.ratelimit import _check
    assert [_check("t", 2, 60) for _ in range(4)] == [True, True, False, False]
