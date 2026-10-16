from scapy.all import rdpcap

packets = rdpcap("samples/http.cap")

print("Total packets: ", len(packets))
for pkt in packets[:5]:
    print(pkt.summary())
