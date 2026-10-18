import sys
from collections import Counter

from .detectors.portscan import detect_port_scan
from .parser import parse_pcap


def main():
    if len(sys.argv) != 2:
        print("Usage: python -m pcapwatch <file.pcap>")
        sys.exit(1)

    flows, total = parse_pcap(sys.argv[1])

    print(f"Packets: {total}")
    print(f"Flows: {len(flows)}")
    print()
    print("Flows (initiator -> responder):")
    for f in flows:
        print(
            f" {f.protocol} {f.src}:{f.sport} -> {f.dst}:{f.dport} {f.packets} pkts, {f.bytes} bytes"
        )

    ports = Counter(f.dport for f in flows)
    print()
    print("Top destination ports: ", ports.most_common(3))
    findings = detect_port_scan(flows)
    print()
    print("Findings:")
    if not findings:
        print("none")
    for f in findings:
        print(f" [{f.technique}] {f.summary}")


if __name__ == "__main__":
    main()
