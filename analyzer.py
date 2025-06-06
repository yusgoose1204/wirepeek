import pyshark

def analyze_pcap(file_path):
    try:
        cap = pyshark.FileCapture(file_path, display_filter='tcp', keep_packets=False)
    except Exception as e:
        print(f"Error loading PCAP: {e}")
        return {}

    total_tcp_packets = 0
    regular_retrans = []
    fast_retrans = []
    duplicate_acks = []
    zero_window_events = []
    tcp_reset_events = []
    syn_time = None
    syn_ack_time = None
    rtt_samples = []

    for pkt in cap:
        if 'TCP' not in pkt:
            continue
        total_tcp_packets += 1
        tcp = pkt.tcp
        timestamp = float(pkt.sniff_timestamp)
        src = pkt.ip.src if hasattr(pkt, 'ip') else 'N/A'
        dst = pkt.ip.dst if hasattr(pkt, 'ip') else 'N/A'
        time_str = pkt.sniff_time.strftime("%H:%M:%S.%f")[:-3]

        # SYN time
        if hasattr(tcp, 'flags_syn') and tcp.flags_syn == '1' and tcp.flags_ack == '0':
            syn_time = timestamp

        # SYN-ACK time
        if hasattr(tcp, 'flags_syn') and tcp.flags_syn == '1' and tcp.flags_ack == '1':
            syn_ack_time = timestamp

        # Retransmission detection
        if hasattr(tcp, 'analysis_fast_retransmission'):
            fast_retrans.append((src, dst, time_str))
        elif hasattr(tcp, 'analysis_retransmission'):
            regular_retrans.append((src, dst, time_str))

        # Duplicate ACKs
        if hasattr(tcp, 'analysis_duplicate_ack'):
            duplicate_acks.append((src, dst, time_str))

        # Zero Window
        try:
            if hasattr(tcp, 'window_size') and int(tcp.window_size) == 0:
                zero_window_events.append((src, dst, time_str))
        except:
            pass

        # TCP Reset
        if hasattr(tcp, 'flags_reset') and tcp.flags_reset == '1':
            tcp_reset_events.append((src, dst, time_str))

    cap.close()

    if not syn_time or not syn_ack_time:
        print("SYN or SYN-ACK missing; cannot compute SYN delay.")

    syn_delay_ms = round((syn_ack_time - syn_time) * 1000, 3) if syn_time and syn_ack_time else None
    avg_rtt_ms = round(sum(rtt_samples) / len(rtt_samples) * 1000, 3) if rtt_samples else None

    return {
        'total_tcp_packets': total_tcp_packets,
        'retransmissions': regular_retrans,
        'duplicate_acks': duplicate_acks,
        'fast_retransmissions': fast_retrans,
        'zero_window_events': zero_window_events,
        'tcp_reset_events': tcp_reset_events,
        'syn_delay_ms': syn_delay_ms,
        'avg_rtt_ms': avg_rtt_ms,
    }