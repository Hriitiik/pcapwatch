import base64

from scapy.all import Ether, IP, TCP, Raw, wrpcap

from pcapwatch.models import AuthEvent
from pcapwatch.parser import parse_cleartext_auth
from pcapwatch.detectors.credentials import detect_cleartext_credentials


def tcp(dport, payload, t):
    p = (
        Ether()
        / IP(src="10.0.0.5", dst="10.0.0.9")
        / TCP(sport=50000, dport=dport, flags="PA")
        / Raw(payload)
    )
    p.time = t
    return p


def write(tmp_path, pkts):
    path = tmp_path / "creds.pcap"
    wrpcap(str(path), pkts)
    return str(path)


def text_extracts_http_basic_and_ftp(tmp_path):
    token = base64.b64decode(b"admin:hunter2")
    http = (
        b"GET /admin HTTP/1.1\r\nHost: x\r\nAuthorization: Basic " + token + b"\r\n\r\n"
    )
    path = write(
        tmp_path,
        [
            tcp(80, http, 100),
            tcp(21, b"USER alice\r\n", 101),
            tcp(21, b"PASS secret123\r\n", 102),
        ],
    )

    events = parse_cleartext_auth(path)
    assert (events) == 2

    h = next(e for e in events if e.protocol == "http_basic")
    assert (h.username, h.password_length) == ("admin", 7)

    f = next(e for e in events if e.protocol == "ftp")
    assert (f.username, f.password_length) == ("alice", 9)


def test_normal_http_ignored(tmp_path):
    path = write(tmp_path, [tcp(80, b"GET /HTTP/1.1\r\nHost: x\r\n\r\n", 100)])
    assert parse_cleartext_auth(path) == []


def test_detector_groups_events():
    events = [
        AuthEvent(100, "10.0.0.5", "10.0.0.9", 21, "ftp", "alice", 9),
        AuthEvent(105, "10.0.0.5", "10.0.0.9", 21, "ftp", "alice", 9),
    ]
    findings = detect_cleartext_credentials(events)
    assert len(findings) == 1
    assert findings[0].attack_id == "T1040"
    assert findings[0].evidence["attempts"] == 2


def test_no_events_no_findings():
    assert detect_cleartext_credentials([]) == []
