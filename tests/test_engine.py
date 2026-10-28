from scapy.all import IP, TCP, Ether, wrpcap

from pcapwatch.engine import analyze


def test_analyze_end_to_end(tmp_path):
    pkts = []
    for i, port in enumerate(range(1, 31)):
        p = (
            Ether()
            / IP(src="10.0.0.5", dst="10.0.0.9")
            / TCP(sport=44000 + i, dport=port, flags="S")
        )
        p.time = 1700000000 + i * 0.05
        pkts.append(p)

    path = tmp_path / "scan.pcap"
    wrpcap(str(path), pkts)

    result = analyze(str(path))
    assert result.packets == 30
    assert [f.rule for f in result.findings] == ["port_scan"]
