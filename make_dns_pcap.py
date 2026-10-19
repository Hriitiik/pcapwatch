import random
import string

from scapy.all import Ether, IP, UDP, DNS, DNSQR, wrpcap

rng = random.Random(7)
chars = string.ascii_lowercase + string.digits


def rand(n):
    return "".join(rng.choice(chars) for _ in range(n))


names = [f"{rand(40)}.evil.com" for _ in range(40)]  # tunneling
names += [f"{rand(16)}.com" for _ in range(15)]  # DGA

pkts = []
for i, name in enumerate(names):
    p = (
        Ether()
        / IP(src="10.0.0.5", dst="8.8.8.8")
        / UDP(sport=40000 + i, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=name))
    )
    p.time = 1700000000 + i * 0.5
    pkts.append(p)

wrpcap("samples/dns_testing.pcap", pkts)
print("wrote samples/dns_testing.pcap")
