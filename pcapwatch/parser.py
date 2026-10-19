from scapy.all import DNS, DNSQR, IP, TCP, UDP, rdpcap

from .models import DNSQuery, Flow


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
