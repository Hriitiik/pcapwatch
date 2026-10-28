import json

from pcapwatch.engine import Result
from pcapwatch.models import Finding
from pcapwatch.report import attack_url, to_html, to_json


def make_result(summary="test finding"):
    f = Finding(
        rule="dns_tunneling",
        attack_id="T1071.004",
        src="10.0.0.5",
        start=1700000000.0,
        end=1700000010.0,
        summary=summary,
        evidence={"parent": "evil.com", "unique_subdomains": 40},
    )
    return Result("test.pcap", 100, [], [f])


def test_attack_url():
    assert attack_url("T1071.004") == "https://attack.mitre.org/techniques/T1071/004/"
    assert attack_url("T1046") == "https://attack.mitre.org/techniques/T1046/"


def test_json_structure():
    data = json.loads(to_json(make_result()))
    assert data["packets"] == 100
    assert len(data["findings"]) == 1
    f = data["findings"][0]
    assert f["attack_id"] == "T1071.004"
    assert f["start_iso"] == "2023-11-14T22:13:20Z"
    assert f["evidence"]["parent"] == "evil.com"


def test_html_escapes_attacker_controlled_text():
    out = to_html(make_result(summary="<script>alert(1)</script>"))
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out


def test_html_with_no_findings():
    out = to_html(Result("empty.pcap", 0, [], []))
    assert "No findings." in out
