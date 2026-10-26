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


@dataclass
class AuthEvent:
    ts: float
    src: str
    dst: str
    dport: str
    protocol: str  # http_basic or ftp
    username: str
    password_length: int


@dataclass
class HTTPFile:
    ts: float
    client: str
    server: str
    port: int
    url: str  # host + path e.g. evil.com/updates.exe
    content_type: str
    size: int
    sha256: str
    head: bytes  # first 4 bytes of the body used for magic-byte checks
