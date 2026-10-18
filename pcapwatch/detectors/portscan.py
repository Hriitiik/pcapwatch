from collections import defaultdict

from ..models import Finding

WINDOW = 10.0
MIN_PORTS = 15


def detect_port_scan(flows, window=WINDOW, min_ports=MIN_PORTS):
    # group flows by source, target hosts
    pairs = defaultdict(list)
    for f in flows:
        if f.protocol in ("TCP", "UDP"):
            pairs[(f.src, f.dst)].append(f)

    findings = []
    for (src, dst), group in pairs.items():
        group.sort(key=lambda f: f.first_seen)

        # slide a time window over the flows keep the biggest hit
        best = []
        start = 0
        for end in range(len(group)):
            while group[end].first_seen - group[start].first_seen > window:
                start += 1
            current = group[start : end + 1]
            if len({f.dport for f in current}) > len({f.dport for f in best}):
                best = current

        ports = sorted({f.dport for f in best})
        if len(ports) >= min_ports:
            findings.append(
                Finding(
                    rule="port_scan",
                    attack_id="T1046",
                    src=src,
                    start=best[0].first_seen,
                    end=best[-1].first_seen,
                    summary=f"{src} probed {len(ports)} ports on {dst} in {best[-1].first_seen - best[0].first_seen:.1f} seconds",
                    evidence={
                        "target": dst,
                        "port_count": len(ports),
                        "sample_ports": ports[:10],
                    },
                )
            )

    return findings
