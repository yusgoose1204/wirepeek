def format_tcp_analysis(metrics: dict, filename: str = "Unknown Capture", max_events_per_category: int = 5) -> str:
    lines = []
    lines.append("*** WirePeek Summary ***")
    lines.append(f"File: {filename}")
    lines.append(f"📊 Total TCP Packets Analyzed: {metrics.get('total_tcp_packets', 0)}")
    if metrics.get('syn_delay_ms') is not None:
        lines.append(f"🔄 SYN/SYN-ACK Delay: {metrics['syn_delay_ms']} ms")
    lines.append("")

    def add_event_section(title, events):
        lines.append(f"{title}: {len(events)}")
        for src, dst, ts in events[:max_events_per_category]:
            lines.append(f"   - {src} ➜ {dst} at {ts}")
        if len(events) > max_events_per_category:
            lines.append(f"   ... and {len(events) - max_events_per_category} more")

    add_event_section("📦 Regular Retransmissions", metrics.get('retransmissions', []))
    add_event_section("⚡ Fast Retransmissions", metrics.get('fast_retransmissions', []))
    add_event_section("🔁 Duplicate ACKs", metrics.get('duplicate_acks', []))
    add_event_section("📉 Zero Window Events", metrics.get('zero_window_events', []))
    add_event_section("❌ TCP Resets", metrics.get('tcp_reset_events', []))

    # --- Interpretations ---
    lines.append("\n💡 Interpretation:")

    total = metrics.get('total_tcp_packets', 1)  # avoid divide-by-zero
    syn_delay = metrics.get('syn_delay_ms')
    if syn_delay:
        if syn_delay > 200:
            lines.append("• Very high handshake delay (>200ms) — investigate for routing or network issues.")
        elif syn_delay > 100:
            lines.append("• High handshake delay (>100ms) — could indicate latency or distant endpoint.")
    retrans_pct = (len(metrics.get('retransmissions', [])) / total) * 100
    if retrans_pct > 5:
        lines.append("• High retransmission rate suggests packet loss or unstable connection.")

    if len(metrics.get('duplicate_acks', [])) > 3:
        lines.append("• Frequent duplicate ACKs may indicate congestion or retransmissions.")

    if len(metrics.get('zero_window_events', [])) >= 1:
        lines.append("• Receiving end may be overloaded or memory constrained (Zero Window).")

    if len(metrics.get('tcp_reset_events', [])) >= 1:
        lines.append("• TCP resets detected — possible abnormal session termination.")

    if retrans_pct <= 5 and len(metrics.get('duplicate_acks', [])) <= 3 and \
            len(metrics.get('zero_window_events', [])) == 0 and len(metrics.get('tcp_reset_events', [])) == 0:
        lines.append("• No major issues detected based on current thresholds.")

    return "\n".join(lines)
