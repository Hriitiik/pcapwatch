from pcapwatch.detectors.portscan import detect_port_scan
from pcapwatch.models import Flow


def make_flow(src, dst, dport, t):
    return Flow("TCP", src, 50000, dst, dport, t, t, packets=2, bytes=120)


def test_fast_scan_detected():
    flows = [make_flow("10.0.0.5", "10.0.0.9", p, 100 + p * 0.1) for p in range(1, 31)]
    findings = detect_port_scan(flows)
    assert len(findings) == 1
    assert findings[0].attack_id == "T1046"
    assert findings[0].evidence["port_count"] == 30


def test_slow_scan_not_detected():
    # testing slow port scanner with 30 ports but outside the window 60 secs apart
    flows = [make_flow("10.0.0.5", "10.0.0.9", p, 100 + p * 60) for p in range(1, 31)]
    assert detect_port_scan(flows) == []


def test_normal_traffic_not_detected():
    flows = [
        make_flow("10.0.0.5", "10.0.0.9", p, 100 + i)
        for i, p in enumerate([80, 443, 53, 22])
    ]
    assert detect_port_scan(flows) == []
