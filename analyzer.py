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
    dup_ack_count = {}
    dup_ack_seen = set()

    for pkt in packets:
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            continue

        total_tcp_packets += 1
        tcp = pkt[TCP]
        ip = pkt[IP]
        ts = float(pkt.time)
        time_str = datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]
        src, dst = ip.src, ip.dst
        sport, dport = tcp.sport, tcp.dport
        seq, ack = tcp.seq, tcp.ack
        flags = tcp.flags
        payload_len = len(tcp.payload)

        flow_id = (src, dst, sport, dport)

        # SYN and SYN-ACK timing
        if flags == 0x02 and not syn_time:
            syn_time = ts
        elif flags == 0x12 and syn_time and not syn_ack_time:
            syn_ack_time = ts

        # TCP Reset
        if flags & 0x04:
            tcp_reset_events.append((src, dst, time_str))

        # Duplicate ACK logic (no payload, same ack)
        if payload_len == 0 and ack > 0:
            ack_key = (src, dst, ack)
            dup_ack_count[ack_key] = dup_ack_count.get(ack_key, 0) + 1
            if dup_ack_count[ack_key] >= 2 and ack_key not in dup_ack_seen:
                duplicate_acks.append((src, dst, time_str))
                dup_ack_seen.add(ack_key)

        # Retransmissions (same seq with payload)
        if payload_len > 0:
            seq_key = (src, dst, sport, dport, seq)
            if seq_key in seen_seq_payload:
                regular_retrans.append((src, dst, time_str))
                # Fast retransmission if 3+ dup ACKs received for this seq
                rev_ack_key = (dst, src, seq)
                if dup_ack_count.get(rev_ack_key, 0) >= 3:
                    fast_retrans.append((src, dst, time_str))
            else:
                seen_seq_payload.add(seq_key)

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
