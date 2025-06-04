def format_tcp_analysis(metrics: dict, filename: str = "Unknown Capture") -> str:
    lines = []
    lines.append(f"*** WirePeek Summary ***")
    lines.append(f"File: {filename}")
    lines.append("")

    if metrics.get('syn_delay_ms') is not None:
        lines.append(f"🔄 SYN/SYN-ACK Delay: {metrics['syn_delay_ms']} ms")
    if metrics.get('avg_rtt_ms') is not None:
        lines.append(f"⏱ Avg RTT (approx): {metrics['avg_rtt_ms']} ms")
    lines.append("")

    lines.append(f"📦 Regular Retransmissions: {metrics.get('retransmissions', 0)}")
    lines.append(f"⚡ Fast Retransmissions: {metrics.get('fast_retransmissions', 0)}")
    lines.append(f"🔁 Duplicate ACKs: {metrics.get('duplicate_acks', 0)}")
    lines.append(f"📭 Zero Window Events: {metrics.get('zero_window', 0)}")
    lines.append(f"❌ TCP Resets: {metrics.get('tcp_resets', 0)}")

    return "\n".join(lines)
