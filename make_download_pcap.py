import hashlib

from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT, SERVER = "10.0.0.5", "203.0.113.80"
pkts = []
t = 1700000000.0


def seg(sport, direction, seq, payload):
    global t
    t += 0.01
    if direction == "c2s":
        ip = IP(src=CLIENT, dst=SERVER)
        tcp = TCP(sport=sport, dport=80, seq=seq, flags="PA")
    else:
        ip = IP(src=SERVER, dst=CLIENT)
        tcp = TCP(sport=80, dport=sport, seq=seq, flags="PA")
    p = Ether() / ip / tcp / Raw(payload)
    p.time = t
    pkts.append(p)


def http_get(sport, host, path, body, ctype):
    seg(sport, "c2s", 1000, f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
    head = (
        f"HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode()
    resp = head + body
    for off in range(0, len(resp), 1000):
        seg(sport, "s2c", 5000 + off, resp[off : off + 1000])
    print(f"{path:<14} sha256 {hashlib.sha256(body).hexdigest()}")


http_get(
    50001,
    "update.evil.test",
    "/update.exe",
    b"MZ" + b"\x90" * 2500,
    "application/octet-stream",
)
http_get(50002, "cdn.evil.test", "/logo.jpg", b"MZ" + b"\x41" * 1500, "image/jpeg")
http_get(
    50003, "intranet", "/index.html", b"<html><body>hello</body></html>", "text/html"
)

wrpcap("samples/download_testing.pcap", pkts)
print("wrote samples/download_testing.pcap")
