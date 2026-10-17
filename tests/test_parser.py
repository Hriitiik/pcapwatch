import pytest

from pcapwatch import parser


def test_counts(sample_pcap):
    flows, total = parser.parse_pcap(sample_pcap)
    assert total == 5
    assert len(flows) == 2


def test_tcp_directions_merge(sample_pcap):
    flows, _ = parser.parse_pcap(sample_pcap)
    tcp = next(f for f in flows if f.protocol == "TCP")
    assert tcp.src == "10.0.0.5"
    assert tcp.dport == 80
    assert tcp.packets == 3


def test_timestamps(sample_pcap):
    flows, _ = parser.parse_pcap(sample_pcap)
    tcp = next(f for f in flows if f.protocol == "TCP")
    assert tcp.first_seen == pytest.approx(1700000000)
    assert tcp.last_seen == pytest.approx(1700000002)


def test_udp_flow(sample_pcap):
    flows, _ = parser.parse_pcap(sample_pcap)
    udp = next(f for f in flows if f.protocol == "UDP")
    assert udp.dport == 53
    assert udp.packets == 1
