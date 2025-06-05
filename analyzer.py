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

    seen_seq_payload = set()
    ack_history = {}
    dup_ack_tracker = {}
    retrans_candidate = None

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
        payload_len = len(tcp.payload)

        # SYN and SYN-ACK
        if flags == 0x02 and not syn_time:
            syn_time = ts
        elif flags == 0x12 and syn_time and not syn_ack_time:
            syn_ack_time = ts

        # TCP Reset
        if flags & 0x04:
            tcp_reset_events.append((src, dst, time_str))

        # Detect retransmissions: payload with same seq seen again
        if payload_len > 0:
            seq_key = (src, dst, tcp.sport, tcp.dport, tcp.seq)
            if seq_key in seen_seq_payload:
                regular_retrans.append((src, dst, time_str))
                retrans_candidate = (src, dst, tcp.seq, ts)
            else:
                seen_seq_payload.add(seq_key)

        # Detect duplicate ACKs
        if payload_len == 0 and tcp.ack > 0:
            ack_key = (src, dst, tcp.ack)
            ack_history[ack_key] = ack_history.get(ack_key, 0) + 1
            if ack_history[ack_key] == 2:  # first dup
                duplicate_acks.append((src, dst, time_str))

            # Track for fast retrans
            flow = (dst, src, tcp.ack)  # reversed because ACK goes back
            dup_ack_tracker[flow] = dup_ack_tracker.get(flow, 0) + 1

        # Fast retransmission: 3+ dup ACKs for a seq + retransmit of that seq
        if retrans_candidate:
            r_src, r_dst, r_seq, r_time = retrans_candidate
            key = (r_src, r_dst, r_seq)
            if dup_ack_tracker.get((r_dst, r_src, r_seq), 0) >= 3:
                fast_retrans.append((r_src, r_dst, time_str))
                retrans_candidate = None  # prevent duplicate count

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
