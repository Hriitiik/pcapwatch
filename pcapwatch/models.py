from dataclasses import dataclass


@dataclass
class Flow:
    protocol: str
    src: str
    sport: str
    dst: str
    dport: str
    first_seen: float
    last_seen: float
    packets: int = 0
    bytes: int = 0
