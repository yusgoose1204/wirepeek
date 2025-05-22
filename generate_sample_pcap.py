from scapy.all import *

# Define packets
packets = []

# TCP 3-way handshake
packets.append(IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=1234, dport=80, flags="S", seq=100))
packets.append(IP(src="192.168.1.20", dst="192.168.1.10") / TCP(sport=80, dport=1234, flags="SA", seq=200, ack=101))
packets.append(IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=1234, dport=80, flags="A", seq=101, ack=201))

# Normal data exchange
packets.append(IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=1234, dport=80, flags="PA", seq=101, ack=201) / Raw(load="GET /index.html"))
packets.append(IP(src="192.168.1.20", dst="192.168.1.10") / TCP(sport=80, dport=1234, flags="PA", seq=201, ack=116) / Raw(load="HTTP/1.1 200 OK"))

# Simulate a retransmission
packets.append(IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=1234, dport=80, flags="PA", seq=101, ack=201) / Raw(load="GET /index.html"))

# TCP reset
packets.append(IP(src="192.168.1.20", dst="192.168.1.10") / TCP(sport=80, dport=1234, flags="R", seq=210, ack=116))

# Write to PCAP
wrpcap("sample_traffic.pcap", packets)
print("sample_traffic.pcap created successfully.")
