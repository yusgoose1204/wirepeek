def analyze_packet(packet, seen_sequences):
    retrans = 0
    reset = 0
    rtt = None

    if not hasattr(packet, 'tcp'):
        return retrans, reset, rtt  # Nothing to analyze

    # Check for retransmissions (only if payload)
    if hasattr(packet.tcp, 'seq'):
        seq_id = (packet.ip.src, packet.ip.dst, packet.tcp.seq)
        has_payload = (hasattr(packet, 'data') or
                      (hasattr(packet.tcp, 'len') and int(packet.tcp.len) > 0))
        if has_payload:
            if seq_id in seen_sequences:
                retrans = 1
            else:
                seen_sequences.add(seq_id)

    # Check for TCP reset
    if hasattr(packet.tcp, 'flags') and (int(packet.tcp.flags, 16) & 0x04):
        reset = 1

    # Extract RTT if available
    if hasattr(packet.tcp, 'analysis_ack_rtt'):
        try:
            rtt = float(packet.tcp.analysis_ack_rtt) * 1000  # ms
        except ValueError:
            pass

    return retrans, reset, rtt

def show_percentage(num, total):
    return f"{(num / total) * 100:.1f}%" if total else "0.0%"