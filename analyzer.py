import pyshark

import pyshark

def analyze_pcap(file_path):
    cap = pyshark.FileCapture(file_path, display_filter='tcp', keep_packets=False)

    regular_retrans = 0
    fast_retrans = 0
    duplicate_acks = 0
    zero_window = 0
    tcp_resets = 0
    syn_time = None
    syn_ack_time = None
    sent_times = {}     # SEQ → timestamp
    seen_acks = set()   # To avoid duplicate RTT samples
    rtt_samples = []

    for pkt in cap:
        if 'TCP' not in pkt:
            continue
        tcp = pkt.tcp
        timestamp = float(pkt.sniff_timestamp)

        # SYN time
        if hasattr(tcp, 'flags_syn') and tcp.flags_syn == '1' and tcp.flags_ack == '0':
            syn_time = timestamp

        # SYN-ACK time
        if hasattr(tcp, 'flags_syn') and tcp.flags_syn == '1' and tcp.flags_ack == '1':
            syn_ack_time = timestamp

        # Record SEQ timestamp (request)
        if hasattr(tcp, 'seq'):
            sent_times[str(tcp.seq)] = timestamp

        # RTT: Match ACK to SEQ (response)
        if hasattr(tcp, 'ack'):
            ack_num = int(tcp.ack)
            if str(ack_num) not in seen_acks:
                for delta in range(0, 20):  # Check a window of 20 bytes back
                    candidate_seq = str(ack_num - delta)
                    if candidate_seq in sent_times:
                        rtt = timestamp - sent_times[candidate_seq]
                        if 0 < rtt < 10:
                            rtt_samples.append(rtt)
                            seen_acks.add(str(ack_num))
                            break

        # Retransmission detection
        if hasattr(tcp, 'analysis_fast_retransmission'):
            fast_retrans += 1
        elif hasattr(tcp, 'analysis_retransmission'):
            regular_retrans += 1

        # Duplicate ACKs
        if hasattr(tcp, 'analysis_duplicate_ack'):
            duplicate_acks += 1

        # Zero Window
        try:
            if hasattr(tcp, 'window_size') and int(tcp.window_size) == 0:
                zero_window += 1
        except:
            pass

        # TCP Reset
        if hasattr(tcp, 'flags_reset') and tcp.flags_reset == '1':
            tcp_resets += 1

    cap.close()

    # SYN delay calculation
    syn_delay_ms = round((syn_ack_time - syn_time) * 1000, 3) if syn_time and syn_ack_time else None

    # Basic RTT estimate (avg)
    avg_rtt_ms = round(sum(rtt_samples) / len(rtt_samples) * 1000, 3) if rtt_samples else None

    return {
        'retransmissions': regular_retrans,
        'duplicate_acks': duplicate_acks,
        'fast_retransmissions': fast_retrans,
        'zero_window': zero_window,
        'tcp_resets': tcp_resets,
        'syn_delay_ms': syn_delay_ms,
        'avg_rtt_ms': avg_rtt_ms,
    }
