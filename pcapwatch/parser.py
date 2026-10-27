import base64
import hashlib
import re
from collections import defaultdict

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Raw, rdpcap

from .models import AuthEvent, DNSQuery, Flow, HTTPFile

BASIC_RE = re.compile(rb"Authorization:\s*Basic\s+([A-Za-z0-9+/=])", re.IGNORECASE)
REQ_RE = re.compile(rb"GET (\S+) HTTP/1\.[01]\r\n(.*?)\r\n\r\n", re.DOTALL)
HOST_RE = re.compile(rb"^Host:\s*(\S+)", re.IGNORECASE | re.MULTILINE)


def parse_pcap(path):
    packets = rdpcap(path)
    flows = {}

    for pkt in packets:
        if IP not in pkt:
            continue
        if TCP in pkt:
            protocol, sport, dport = "TCP", pkt[TCP].sport, pkt[TCP].dport
        elif UDP in pkt:
            protocol, sport, dport = "UDP", pkt[UDP].sport, pkt[UDP].dport
        else:
            continue

        src, dst = pkt[IP].src, pkt[IP].dst
        ts = float(pkt.time)

        forward = (protocol, src, sport, dst, dport)
        reverse = (protocol, dst, dport, src, sport)

        if forward in flows:
            flow = flows[forward]
        elif reverse in flows:
            flow = flows[reverse]
        else:
            flow = Flow(protocol, src, sport, dst, dport, ts, ts)
            flows[forward] = flow

        flow.last_seen = ts
        flow.packets += 1
        flow.bytes += len(pkt)

    return list(flows.values()), len(packets)


def parse_dns_queries(path):
    queries = []
    for pkt in rdpcap(path):
        if IP in pkt and DNS in pkt and DNSQR in pkt and pkt[DNS].qr == 0:
            # qr==0 means packet is query not response
            name = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".").lower()
            queries.append(DNSQuery(float(pkt.time), pkt[IP].src, name))
    return queries


def parse_cleartext_auth(path):
    events = []
    ftp_users = {}

    for pkt in rdpcap(path):
        if not (IP in pkt and TCP in pkt and Raw in pkt):
            continue
        payload = bytes(pkt[Raw].load)
        ts, src, dst = float(pkt.time), pkt[IP].src, pkt[IP].dst
        dport = pkt[TCP].dport

        m = BASIC_RE.search(payload)
        if m:
            try:
                decoded = base64.b64decode(m.group(1)).decode(errors="ignore")
            except ValueError:
                continue
            user, _, password = decoded.partition(":")
            events.append(
                AuthEvent(ts, src, dst, dport, "http_basic", user, len(password))
            )
        if dport == 21:
            for line in payload.split(b"\r\n"):
                if line.upper().startswith(b"USER "):
                    ftp_users[(src, dst)] = line[5:].decode(errors="ignore").strip()
                elif line.upper().startswith(b"PASS "):
                    events.append(
                        AuthEvent(
                            ts,
                            src,
                            dst,
                            dport,
                            "ftp",
                            ftp_users.get((src, dst), "?"),
                            len(line) - 5,
                        )
                    )

    return events


def _reassemble(segments):
    """segments: [(tcp_sq, payload)]. Returns the stream bytes in order,
    with retransmitted data dropped."""
    segments.sort(key=lambda s: s[0])
    out, next_seq = b"", None
    for seq, data in segments:
        if next_seq is None:
            out, next_seq = data, seq + len(data)
        elif seq >= next_seq:
            out += data
            next_seq = seq + len(data)
        elif seq + len(data) > next_seq:
            out += data[next_seq - seq :]
            next_seq = seq + len(data)
    return out


def _dechunk(data):
    """Decode a chunked body. Returns (body, bytes_consumed)."""
    body, pos = b"", 0
    while True:
        eol = data.find(b"\r\n", pos)
        if eol == -1:
            break
        try:
            size = int(data[pos:eol].split(b";")[0], 16)
        except ValueError:
            break
        pos = eol + 2
        if size == 0:
            pos += 2
            break
        body += data[pos : pos + size]
        pos += size + 2
    return body, pos


def _split_responses(data):
    """Return [(headers, body)] for each HTTP response in a stream."""
    responses, pos = [], 0
    while data[pos : pos + 5] == b"HTTP/":
        head_end = data.find(b"\r\n\r\n", pos)
        if head_end == -1:
            break

        lines = data[pos:head_end].decode("latin-1").split("\r\n")
        headers = {}
        for line in lines[1:]:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()

        start = head_end + 4
        if headers.get("transfer-encoding", "").lower() == "chunked":
            body, used = _dechunk(data[start:])
            end = start + used
        elif "content-length" in headers:
            try:
                n = int(headers["content-length"])
            except ValueError:
                break
            body, end = data[start : start + n], start + n
        else:
            body, end = data[start:], len(data)

        responses.append((headers, body))
        pos = end
    return responses


def _split_requests(data):
    """Return ['host/path', ...] for each GET request in a stream."""
    urls = []
    for m in REQ_RE.finditer(data):
        host = HOST_RE.search(m.group(2))
        host = host.group(1).decode(errors="ignore") if host else ""
        urls.append(host + m.group(1).decode(errors="ignore"))
    return urls


def parse_http_files(path):
    streams = defaultdict(list)
    first_ts = {}

    for pkt in rdpcap(path):
        if IP in pkt and TCP in pkt and Raw in pkt:
            key = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
            streams[key].append((pkt[TCP].seq, bytes(pkt[Raw].load)))
            first_ts.setdefault(key, float(pkt.time))

    files = []
    for key, segs in streams.items():
        data = _reassemble(segs)
        if not data.startswith(b"HTTP/"):
            continue

        server, sport, client, cport = key
        requests = _split_requests(
            _reassemble(streams.get((client, cport, server, sport), []))
        )

        for i, (headers, body) in enumerate(_split_responses(data)):
            if not body:
                continue
            files.append(
                HTTPFile(
                    ts=first_ts[key],
                    client=client,
                    server=server,
                    port=sport,
                    url=requests[i] if i < len(requests) else f"{server}/(unknown)",
                    content_type=headers.get("content-type", ""),
                    size=len(body),
                    sha256=hashlib.sha256(body).hexdigest(),
                    head=body[:4],
                )
            )

    return files
