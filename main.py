import pyshark
from analyzer import analyze_packet, show_percentage

# hardcoded source IP and destination IP for testing
SOURCE_IP = "192.168.1.10"
DESTINATION_IP = "192.168.1.20"

total_packets = 0
seen_sequences = set()
retransmissions = 0
resets = 0
rtt_values = []

capture = pyshark.FileCapture(
    input_file="wirepeek_combined.pcap",
    display_filter=f"ip.src=={SOURCE_IP} && ip.dst=={DESTINATION_IP} && tcp",
    use_json=True,              # Load data in JSON format
    include_raw=False,          # Exclude raw binary data. Prevents loading full packet payload (like POST bodies, email content)
    keep_packets=False          # Avoid keeping all packets in memory
)

for packet in capture:
    total_packets += 1
    retrans, reset, rtt = analyze_packet(packet, seen_sequences)
    retransmissions += retrans
    resets += reset
    if rtt is not None:
        rtt_values.append(rtt)

avg_rtt = sum(rtt_values) / len(rtt_values) if rtt_values else 0
loss_rate = retransmissions / total_packets * 100 if total_packets else 0

print("*** WirePeek Summary ***")
print(f"Between {SOURCE_IP} ➜ {DESTINATION_IP}")
print(f"Total TCP Packets: {total_packets}")
print(f"Avg RTT: {avg_rtt:.3f} ms")
print(f"Retransmissions: {retransmissions} ({show_percentage(retransmissions, total_packets)})")
print(f"TCP Resets: {resets} ({show_percentage(resets, total_packets)})")
print(f"Estimated Packet Loss: {loss_rate:.1f}% (based on retransmission counts)")
