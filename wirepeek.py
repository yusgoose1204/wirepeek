
from analyzer import analyze_pcap
from formatter import format_tcp_analysis
import os

pcap_path = "tcp_dupack.pcapng"
metrics = analyze_pcap(pcap_path)
summary = format_tcp_analysis(metrics, filename=os.path.basename(pcap_path))
print(summary)