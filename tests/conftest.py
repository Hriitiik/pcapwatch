import pytest
from scapy.all import ARP, IP, TCP, UDP, Ether, wrpcap


@pytest.fixture
def sample_pcap(tmp_path):
    client, server, dns = "10.0.0.5", "10.0.0.9", "8.8.8.8"

    pkts = [
        Ether() / IP(src=client, dst=server) / TCP(sport=50000, dport=80, flags="S"),
        Ether() / IP(src=server, dst=client) / TCP(sport=80, dport=50000, flags="SA"),
        Ether() / IP(src=client, dst=server) / TCP(sport=50000, dport=80, flags="A"),
        Ether() / IP(src=client, dst=dns) / UDP(sport=50000, dport=53),
        Ether() / ARP(),
    ]
    for i, p in enumerate(pkts):
        p.time = 1700000000 + i

    path = tmp_path / "sample.pcap"
    wrpcap(str(path), pkts)
    return str(path)
