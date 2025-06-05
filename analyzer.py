import pyshark

def analyze_pcap(file_path):
    try:
        capture = pyshark.FileCapture(file_path, display_filter="tcp", use_json=True)
    except Exception as e:
        print(f"Error opening file: {e}")
        return {}

    total_tcp_packets = 0
    regular_retrans = []
    fast_retrans = []
    duplicate_acks = []
    zero_window_events = []
    tcp_reset_events = []
    syn_time = None
    syn_ack_time = None

    ack_tracker = {}
    dup_ack_seen = set()
    seen_data = set()

    for pkt in capture:
        try:
            tcp = pkt.tcp
            ip = pkt.ip
            total_tcp_packets += 1

            ts = float(pkt.sniff_timestamp)
            time_str = pkt.sniff_time.strftime("%H:%M:%S.%f")[:-3]
            src, dst = ip.src, ip.dst
            sport, dport = tcp.srcport, tcp.dstport
            seq = int(tcp.seq)
            ack = int(tcp.ack)
            payload_len = int(tcp.len)
            flags = tcp.flags

            # SYN/SYN-ACK
            if tcp.flags_syn == '1' and tcp.flags_ack == '0' and not syn_time:
                syn_time = ts
            elif tcp.flags_syn == '1' and tcp.flags_ack == '1' and syn_time and not syn_ack_time:
                syn_ack_time = ts

            # TCP Reset
            if tcp.flags_reset == '1':
                tcp_reset_events.append((src, dst, time_str))

            # Duplicate ACK
            if payload_len == 0:
                key = (src, dst, ack)
                ack_tracker[key] = ack_tracker.get(key, 0) + 1
                if ack_tracker[key] >= 2 and key not in dup_ack_seen:
                    duplicate_acks.append((src, dst, time_str))
                    dup_ack_seen.add(key)

            # Retransmissions
            if payload_len > 0:
                data_key = (src, dst, sport, dport, seq)
                if data_key in seen_data:
                    reverse_ack_key = (dst, src, seq + payload_len)
                    if ack_tracker.get(reverse_ack_key, 0) >= 3:
                        fast_retrans.append((src, dst, time_str))
                    else:
                        regular_retrans.append((src, dst, time_str))
                else:
                    seen_data.add(data_key)

        except AttributeError:
            continue
        except Exception as e:
            print(f"Error processing packet: {e}")
            continue

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
