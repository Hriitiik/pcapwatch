import base64

from scapy.all import Ether, IP, TCP, Raw, wrpcap


def tcp(dport, payload, t):
    p = (
        Ether()
        / IP(src="10.0.0.5", dst="10.0.0.9")
        / TCP(sport=50000, dport=dport, flags="PA")
        / Raw(payload)
    )
    p.time = t
    return p


token = base64.b64encode(b"admin:hunter2")
pkts = [
    tcp(
        80,
        b"GET /admin HTTP/1.1\r\nHost: intranet\r\nAuthorization: Basic "
        + token
        + b"\r\n\r\n",
        1700000000,
    ),
    tcp(80, b"GET /index.html HTTP/1.1\r\nHost: intranet\r\n\r\n", 1700000001),
    tcp(21, b"USER alice\r\n", 1700000002),
    tcp(21, b"PASS secret123\r\n", 1700000003),
]

wrpcap("samples/creds_testing.pcap", pkts)
print("wrote samples/creds_testing.pcap")
