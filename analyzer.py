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
    fast_retrans = []
    duplicate_acks = []
    zero_window_events = []
    tcp_reset_events = []
    syn_time = None
    syn_ack_time = None

    seen_seqs = {}
    ack_history = {}
    retrans_flags = {}

    for pkt in packets:
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            continue

        total_tcp_packets += 1
        tcp = pkt[TCP]
        ip = pkt[IP]
        src = ip.src
        dst = ip.dst
        ts = float(pkt.time)
        time_str = datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]

        flags = tcp.flags

        # SYN and SYN-ACK time detection
        if flags == 0x02 and not syn_time:
            syn_time = ts
        elif flags == 0x12 and syn_time and not syn_ack_time:
            syn_ack_time = ts

        # TCP Reset
        if flags & 0x04:
            tcp_reset_events.append((src, dst, time_str))

        # Track seen sequences with data payload
        payload_len = len(tcp.payload)
        flow_id = (src, dst, tcp.sport, tcp.dport)
        seq_key = (flow_id, tcp.seq)

        if payload_len > 0:
            if seq_key in seen_seqs:
                regular_retrans.append((src, dst, time_str))
                retrans_flags[flow_id] = ts
            else:
                seen_seqs[seq_key] = ts

        # Duplicate ACK detection
        if tcp.ack:
            ack_key = (src, dst, tcp.ack)
            ack_history[ack_key] = ack_history.get(ack_key, 0) + 1
            if ack_history[ack_key] >= 2:
                duplicate_acks.append((src, dst, time_str))

        # Fast retransmission heuristic: if 3+ dup ACKs and we saw a retransmit within short time
        if tcp.seq == 1 and flow_id in retrans_flags and ack_history.get((dst, src, tcp.seq), 0) >= 3:
            fast_retrans.append((src, dst, time_str))

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
