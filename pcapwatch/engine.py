from dataclasses import dataclass

from .detectors.beaconing import detect_beaconing
from .detectors.credentials import detect_cleartext_credentials
from .detectors.dns import detect_dns
from .detectors.downloads import detect_downloads
from .detectors.portscan import detect_port_scan
from .parser import (
    parse_cleartext_auth,
    parse_dns_queries,
    parse_http_files,
    parse_pcap,
)


@dataclass
class Result:
    pcap: str
    packets: int
    flows: list
    findings: list


def analyze(path):
    flows, total = parse_pcap(path)
    findings = (
        detect_port_scan(flows)
        + detect_dns(parse_dns_queries(path))
        + detect_beaconing(flows)
        + detect_cleartext_credentials(parse_cleartext_auth(path))
        + detect_downloads(parse_http_files(path))
    )
    findings.sort(key=lambda f: f.start)

    return Result(path, total, flows, findings)
