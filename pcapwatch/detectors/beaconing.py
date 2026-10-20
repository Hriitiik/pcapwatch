from collections import defaultdict
from statistics import mean, pstdev

from ..models import Finding

MIN_CONNECTIONS = 8  # enough samples to call it a regular
MAX_JITTER = 0.2  # std/mean of the gaps
MIN_INTERVAL = 1.0  # seconds for ignoring rapid bursts
ALLOWED_PORTS = {123, 5353}  # NTP, mDNS legit periodic traffic


def detect_beaconing(
    flows,
    min_connections=MIN_CONNECTIONS,
    max_jitter=MAX_JITTER,
    min_interval=MIN_INTERVAL,
):
    groups = defaultdict(list)
    for f in flows:
        if f.dport in ALLOWED_PORTS:
            continue
        groups[(f.src, f.dst, f.dport, f.protocol)].append(f.first_seen)

    findings = []
    for (src, dst, dport, protocol), times in groups.items():
        if len(times) < min_connections:
            continue

        times.sort()
        gaps = [b - a for a, b in zip(times, times[1:])]
        avg = mean(gaps)
        if avg < min_interval:
            continue

        jitter = pstdev(gaps) / avg
        if jitter <= max_jitter:
            findings.append(
                Finding(
                    rule="beaconing",
                    attack_id="T1071",
                    src=src,
                    start=times[0],
                    end=times[-1],
                    summary=f"{src} contacted {dst}:{dport} {len(times)} times every ~{avg:.0f}s (jitter {jitter:.0%})",
                    evidence={
                        "dst": dst,
                        "dport": dport,
                        "protocol": protocol,
                        "connections": len(times),
                        "avg_interval": round(avg, 1),
                        "jitter": round(jitter, 3),
                    },
                )
            )
    return findings
