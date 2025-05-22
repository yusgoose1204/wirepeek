from scapy.all import *
import random

SRC_IP = "192.168.1.10"
DST_IP = "192.168.1.20"
SRC_PORT = 12345
DST_PORT = 80

def tcp_handshake(seq_base=1000, ack_base=2000):
    return [
        IP(src=SRC_IP, dst=DST_IP)/TCP(sport=SRC_PORT, dport=DST_PORT, flags='S', seq=seq_base),
        IP(src=DST_IP, dst=SRC_IP)/TCP(sport=DST_PORT, dport=SRC_PORT, flags='SA', seq=ack_base, ack=seq_base+1),
        IP(src=SRC_IP, dst=DST_IP)/TCP(sport=SRC_PORT, dport=DST_PORT, flags='A', seq=seq_base+1, ack=ack_base+1)
    ]

def generate_normal_flow(seq_base=1001, ack_base=2001, count=10):
    packets = []
    seq = seq_base
    ack = ack_base
    for i in range(count):
        payload = f"GET /item/{i} HTTP/1.1\r\nHost: example.com\r\n\r\n"
        packets.append(IP(src=SRC_IP, dst=DST_IP)/TCP(sport=SRC_PORT, dport=DST_PORT, flags='PA', seq=seq, ack=ack)/Raw(load=payload))
        seq += len(payload)
        response = f"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello"
        packets.append(IP(src=DST_IP, dst=SRC_IP)/TCP(sport=DST_PORT, dport=SRC_PORT, flags='PA', seq=ack, ack=seq)/Raw(load=response))
        ack += len(response)
    return packets, seq, ack

def add_retransmissions(packets, retrans_idx=4):
    if 0 <= retrans_idx < len(packets):
        packets.insert(retrans_idx + 2, packets[retrans_idx].copy())
    return packets

def add_tcp_resets(packets, seq=9999, ack=8888):
    packets.append(IP(src=SRC_IP, dst=DST_IP)/TCP(sport=SRC_PORT, dport=DST_PORT, flags='R', seq=seq, ack=ack))
    return packets

def add_high_rtt(packets, spacing_ms=300):
    for i, pkt in enumerate(packets):
        pkt.time = pkt.time + i * (spacing_ms / 1000.0)
    return packets

def generate_combined_test():
    packets = []

    # Normal flow
    packets += tcp_handshake()
    normal_flow, seq, ack = generate_normal_flow()
    packets += normal_flow

    # Retransmission scenario
    packets += tcp_handshake(seq + 1000, ack + 1000)
    retrans_flow, seq2, ack2 = generate_normal_flow(seq + 1001, ack + 1001)
    packets += add_retransmissions(retrans_flow)

    # Reset scenario
    packets += tcp_handshake(seq2 + 1000, ack2 + 1000)
    reset_flow, _, _ = generate_normal_flow(seq2 + 1001, ack2 + 1001)
    packets += add_tcp_resets(reset_flow)

    # High RTT scenario
    packets += tcp_handshake(seq2 + 2000, ack2 + 2000)
    rtt_flow, _, _ = generate_normal_flow(seq2 + 2001, ack2 + 2001)
    packets += add_high_rtt(rtt_flow)

    return packets

# Generate and write the combined PCAP
combined_packets = generate_combined_test()
wrpcap("wirepeek_combined.pcap", combined_packets)
print("✅ wirepeek_combined.pcap created successfully.")
