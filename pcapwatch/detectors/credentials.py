from collections import defaultdict
from ..models import Finding


def detect_cleartext_credentials(events):
    groups = defaultdict(list)
    for e in events:
        groups[(e.src, e.dst, e.dport, e.protocol)].append(e)

    findings = []
    for (src, dst, dport, protocol), evs in groups.items():
        users = sorted({e.username for e in evs})
        findings.append(
            Finding(
                rule="cleartext_credentials",
                attack_id="T1040",
                src=src,
                start=min(e.ts for e in evs),
                end=max(e.ts for e in evs),
                summary=f"{src} sent {len(evs)} cleartext {protocol} login(s) to {dst}:{dport} as {', '.join(users)}",
                evidence={
                    "dst": dst,
                    "dport": dport,
                    "protocol": protocol,
                    "usernames": users,
                    "attempts": len(evs),
                },
            )
        )

    return findings
