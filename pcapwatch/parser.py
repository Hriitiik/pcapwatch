from scapy.all import DNS, DNSQR, IP, TCP, UDP, rdpcap, Raw

from .models import DNSQuery, Flow, AuthEvent

import base64
import re

BASIC_RE = re.compile(rb"Authorization:\s*Basic\s+([A-Za-z0-9+/=])", re.I)


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
