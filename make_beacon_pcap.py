import random

from scapy.all import IP, TCP, Ether, wrpcap

rng = random.Random(11)
events = []

# the beacon: one new connection to the same C2 every ~60s, +/- 3s
t = 1700000000.0
for i in range(30):
    t += 60 + rng.uniform(-3, 3)
    events.append((t, "203.0.113.50", 443))

# background: irregular browsing to assorted hosts
t = 1700000000.0
for i in range(40):
    t += rng.uniform(1, 90)
    host = f"198.51.100.{rng.randint(1, 30)}"
    events.append((t, host, rng.choice([80, 443, 8080])))

pkts = []
for i, (ts, dst, dport) in enumerate(sorted(events)):
    p = (
        Ether()
        / IP(src="10.0.0.5", dst=dst)
        / TCP(sport=40000 + i, dport=dport, flags="S")
    )
    p.time = ts
    pkts.append(p)

wrpcap("samples/beacon_testing.pcap", pkts)
print("wrote samples/beacon_testing.pcap")
