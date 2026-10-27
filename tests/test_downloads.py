import hashlib
from sys import flags

from scapy.all import IP, TCP, Ether, Raw, wrpcap

from pcapwatch.detectors.downloads import detect_downloads
from pcapwatch.models import HTTPFile
from pcapwatch.parser import parse_http_files

C, S = "10.0.0.5", "203.0.113.80"


def seg(src, sport, dst, dport, seq, payload, t):
    p = (
        Ether()
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, seq=seq, flags="PA")
        / Raw(payload)
    )
    p.time = t
    return p


def request(path="/a.exe", host="evil.test"):
    return seg(
        C,
        50000,
        S,
        80,
        1000,
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode(),
        100,
    )


def write(tmp_path, pkts):
    path = tmp_path / "dl.pcap"
    wrpcap(str(path), pkts)
    return str(path)


def test_reassembles_out_of_order(tmp_path):
    body = b"MZ" + b"\x90" * 2000
    resp = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body
    chunks = [(off, resp[off : off + 700]) for off in range(0, len(resp), 700)]

    # server packets are written in reversed order
    pkts = [request()] + [
        seg(S, 80, C, 50000, 5000 + off, c, 101 + i)
        for i, (off, c) in enumerate(reversed(chunks))
    ]
    files = parse_http_files(write(tmp_path, pkts))

    assert len(files) == 1
    f = files[0]
    assert f.sha256 == hashlib.sha256(body).hexdigest()
    assert f.size == len(body)
    assert f.url == "evil.test/a.exe"
    assert f.head == b"MZ\x90\x90"


def test_chunked_body(tmp_path):
    body = b"MZ" + b"A" * 100
    chunked = (
        b"%x\r\n" % 50
        + body[:50]
        + b"\r\n"
        + b"%x\r\n" % (len(body) - 50)
        + body[50:]
        + b"\r\n"
        + b"0\r\n\r\n"
    )
    resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked
    files = parse_http_files(
        write(tmp_path, [request(), seg(S, 80, C, 50000, 5000, resp, 101)])
    )

    assert len(files) == 1
    assert files[0].sha256 == hashlib.sha256(body).hexdigest()


def test_non_http_ignored(tmp_path):
    path = write(tmp_path, [seg(C, 50000, S, 80, 1000, b"hello world", 100)])
    assert parse_http_files(path) == []


def hf(url, head, ctype="application/octet-stream"):
    return HTTPFile(100.0, C, S, 80, url, ctype, 5000, "ab" * 32, head)


def test_pe_detected():
    findings = detect_downloads([hf("evil.test/update.exe", b"MZ\x90\x00")])
    assert len(findings) == 1
    assert findings[0].attack_id == "T1105"
    assert findings[0].evidence["file_type"] == "PE executable"
    assert findings[0].evidence["extension_mismatch"] is False


def test_disguised_pe_flagged():
    findings = detect_downloads([hf("cdn.test/logo.jpg", b"MZ\x90\x00", "image/jpeg")])
    assert findings[0].evidence["extension_mismatch"] is True


def test_script_by_extension():
    findings = detect_downloads([hf("evil.test/run.ps1", b"Invo")])
    assert findings[0].evidence["file_type"] == "script"


def test_benign_files_not_flagged():
    files = [
        hf("x/index.html", b"<htm", "text/html"),
        hf("x/a.jpg", b"\xff\xd8\xff\xe0", "image/jpeg"),
        hf("x/app.js", b"func", "application/javascript"),
    ]
    assert detect_downloads(files) == []
