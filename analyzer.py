from scapy.all import rdpcap, TCP, IP
from datetime import datetime

def analyze_pcap(file_path):
    try:
        packets = rdpcap(file_path)
    except Exception as e:
        print(f"Error reading PCAP: {e}")
        return {}

    total_tcp_packets = 0
    regular_retrans = []
    fast_retrans = []  # Placeholder — needs deeper analysis
    duplicate_acks = []
    zero_window_events = []  # Scapy can't see TCP window=0 without TCP options (rare)
    tcp_reset_events = []
    syn_time = None
    syn_ack_time = None

    seen_seqs = set()
    ack_counts = {}
    seen_syn = False

    for pkt in packets:
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            continue

        total_tcp_packets += 1
        tcp = pkt[TCP]
        ip = pkt[IP]
        src = ip.src
        dst = ip.dst
        ts = float(pkt.time)  # convert EDecimal to float
        time_str = datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]

        # SYN
        if tcp.flags == 0x02 and not seen_syn:  # SYN only
            syn_time = float(ts)
            seen_syn = True

        # SYN-ACK
        elif tcp.flags == 0x12 and syn_time and not syn_ack_time:  # SYN + ACK
            syn_ack_time = float(ts)

        # TCP Reset
        if tcp.flags & 0x04:  # RST
            tcp_reset_events.append((src, dst, time_str))

        # Retransmission (simple detection using seq numbers)
        flow_id = (src, dst, tcp.sport, tcp.dport, tcp.seq)
        if flow_id in seen_seqs:
            regular_retrans.append((src, dst, time_str))
        else:
            seen_seqs.add(flow_id)

        # Duplicate ACK detection
        if tcp.ack:
            ack_key = (src, dst, tcp.ack)
            ack_counts[ack_key] = ack_counts.get(ack_key, 0) + 1
            if ack_counts[ack_key] == 2:
                duplicate_acks.append((src, dst, time_str))

    syn_delay_ms = round((syn_ack_time - syn_time) * 1000, 3) if syn_time and syn_ack_time else None

    return {
        'total_tcp_packets': total_tcp_packets,
        'retransmissions': regular_retrans,
        'duplicate_acks': duplicate_acks,
        'fast_retransmissions': fast_retrans,
        'zero_window_events': zero_window_events,
        'tcp_reset_events': tcp_reset_events,
        'syn_delay_ms': syn_delay_ms,
        'avg_rtt_ms': None
    }
