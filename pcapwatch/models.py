from dataclasses import dataclass


@dataclass
class Flow:
    protocol: str  # TCP, UDP, etc
    src: str  # source ip
    sport: str  # source port
    dst: str  # dest ip
    dport: str  # dest port
    first_seen: float
    last_seen: float
    packets: int = 0
    bytes: int = 0


@dataclass
class Finding:
    rule: str  # detected behavior like port scan
    attack_id: str  # MITRE ATT&CK id
    src: str
    start: float
    end: float
    summary: str  # description
    evidence: dict


@dataclass
class DNSQuery:
    ts: float
    src: str
    name: str
