import math
from collections import Counter, defaultdict

import tldextract

from ..models import Finding

MIN_SUBDOMAINS = 20  # unique subdomains under ojne parent(tunneling)
MIN_SUB_LENGTH = 20  # avg subdoamain length (tunneling)
MIN_DGA_LABEL = 14  # chars in the second-level label (DGA)
MIN_ENTROPY = 3.3  # bits per char (DGA)
MIN_DGA_DOMAINS = 10  # distinct suspicious domains per host (DGA)

_extract = tldextract.TLDExtract(suffix_list_urls=())


def entropy(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def split_name(name):
    e = _extract(name)
    if not e.domain or not e.suffix:
        return None
    parent = f"{e.domain}.{e.suffix}"
    return parent, e.subdomain, e.domain


def detect_dns(queries):
    tunnel = defaultdict(lambda: {"subs": set(), "ts": []})
    dga = defaultdict(lambda: {"domains": set(), "ts": []})

    for q in queries:
        parts = split_name(q.name)
        if parts is None:
            continue
        parent, sub, sld = parts

        if sub:
            t = tunnel[(q.src, parent)]
            t["subs"].add(sub)
            t["ts"].append(q.ts)

        if len(sld) >= MIN_DGA_LABEL and entropy(sld) >= MIN_ENTROPY:
            d = dga[q.src]
            d["domains"].add(parent)
            d["ts"].append(q.ts)

    findings = []

    for (src, parent), t in tunnel.items():
        subs = t["subs"]
        avg_len = sum(len(s) for s in subs) / len(subs)
        if len(subs) >= MIN_SUBDOMAINS and avg_len >= MIN_SUB_LENGTH:
            findings.append(
                Finding(
                    rule="dns_tunneling",
                    attack_id="T1071.004",
                    src=src,
                    start=min(t["ts"]),
                    end=max(t["ts"]),
                    summary=f"{src} sent {len(subs)} unique subdomains to {parent} (avg_length {avg_len:.0f})",
                    evidence={
                        "parent": parent,
                        "unique_subdomains": len(subs),
                        "avg_length": round(avg_len, 1),
                        "examples": sorted(subs)[:3],
                    },
                )
            )

    for src, d in dga.items():
        if len(d["domains"]) >= MIN_DGA_DOMAINS:
            findings.append(
                Finding(
                    rule="dga",
                    attack_id="T1071.004",
                    src=src,
                    start=min(d["ts"]),
                    end=max(d["ts"]),
                    summary=f"{src} queried {len(d['domains'])} high-entropy domains (possible DGA)",
                    evidence={
                        "domain_count": len(d["domains"]),
                        "examples": sorted(d["domains"])[:3],
                    },
                )
            )
    return findings
