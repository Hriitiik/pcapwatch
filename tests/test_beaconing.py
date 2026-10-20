import random

from pcapwatch.detectors.beaconing import detect_beaconing
from pcapwatch.models import Flow


def make_flow(t, dport=443, dst="203.0.113.50"):
    return Flow(
        "TCP", "10.0.0.5", 5000 + int(t) % 1000, dst, dport, t, t, packets=3, bytes=200
    )


def test_regular_beacon_detected():
    flows = [make_flow(100 + i * 60 + (i % 3 - 1)) for i in range(20)]
    findings = detect_beaconing(flows)
    assert len(findings) == 1
    assert findings[0].rule == "beaconing"
    assert findings[0].attack_id == "T1071"
    assert 55 <= findings[0].evidence["avg_interval"] <= 65


def test_irregular_traffic_not_detected():
    rng = random.Random(3)
    t, flows = 100.0, []
    for _ in range(20):
        t += rng.uniform(1, 120)
        flows.append(make_flow(t))
    assert detect_beaconing(flows) == []


def test_ntp_allowlisted():
    flows = [make_flow(100 + i * 64, dport=123) for i in range(20)]
    assert detect_beaconing(flows) == []


def test_too_few_connections_not_detected():
    flows = [make_flow(100 + i * 60) for i in range(5)]
    assert detect_beaconing(flows) == []


def test_rapid_burst_not_detected():
    flows = [make_flow(100 + i * 0.1) for i in range(20)]
    assert detect_beaconing(flows) == []
