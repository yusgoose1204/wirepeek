# WirePeek: Slack-Based PCAP Insight Tool

## 🔍 Overview

WirePeek is a lightweight, containerized web application that integrates with Slack to provide near-instant TCP packet capture analysis. Designed for support and network engineers, WirePeek enables fast insights into common network issues like retransmissions, zero-window stalls, SYN delays, and TCP resets.

Once a .pcap or .pcapng file is attached to a Slack message, users can trigger WirePeek via a custom Slack message shortcut. The app then downloads, parses, and summarizes the file, returning human-readable metrics and potential root causes—all without exposing sensitive traffic contents.

---

## 🚀 How It Works

1. A support engineer uploads a `.pcap` or `.pcapng` file to a Slack thread.
2. The user triggers the **"Analyze with WirePeek"** shortcut on the message.
3. WirePeek:
   - Downloads the file via Slack’s API
   - Runs analysis using `pyshark`
   - Returns high-level TCP insights as a threaded reply

No need to leave Slack or inspect Wireshark manually.

---

## 🚀 Slack Workflow

1. A Slack user uploads a .pcap file in a message.

2. They trigger the "Analyze with WirePeek" shortcut (configured via Slack app settings).

3. WirePeek:

   - Authenticates using Slack bot token
   - Downloads the file securely via url_private_download
   - Stores it temporarily in /tmp/
   - Analyzes using Pyshark filters (TCP-specific)
   - Formats key TCP events into a summary
   - Replies in-thread to the original message with interpreted results
   - Deletes the file after processing

---

## 🧠 Insights Delivered

WirePeek highlights common network issues:

- 🔄 SYN/SYN-ACK Handshake Delay
- 📦 TCP Retransmissions (Regular + Fast)
- 🔁 Duplicate ACKs
- 📉 Zero Window Events
- ❌ TCP Reset Events

With summarized interpretations such as:
- High handshake delay
- Frequent retransmissions
- Signs of congestion or resource exhaustion

---

## 🔐 Security Considerations

WirePeek was designed with security in mind:

- Temporary PCAP files are deleted immediately after processing via `os.remove(local_path)`
- No packet **payload** data is extracted or stored
- No TCP/IP **headers or flags** are exposed
- IP addresses are only used in aggregate summaries (source ➜ destination), not stored
- All network traffic and Slack API calls occur over HTTPS
- No packet data is logged or retained
- The app runs inside a controlled Heroku container with limited scope

---

## 🛠️ Architecture & Deployment

- **Language:** Python 3
- **Core Libraries:** `flask`, `requests`, `pyshark`
- **Slack Integration:** Uses Slack Interactivity + Events API
- **PCAP Parsing:** Built on `pyshark` (Wireshark bindings)
- **Containerization:** Docker-based deployment to Heroku using:
  ```bash
  heroku container:push web -a wirepeek-container
  heroku container:release web -a wirepeek-container
  ```

- Docker image is built and maintained under our organization’s Docker Hub registry.

---

## 🗂️ Project Structure

```
WirePeek/
├── analyzer.py               # Pyshark-based PCAP analysis
├── formatter.py              # Formats the result into a Slack-friendly summary
├── wirepeek.py               # Flask app with Slack interaction logic
├── Dockerfile                # Container setup for Heroku
├── Procfile                  # Heroku entrypoint
├── requirements.txt          # Dependency list
├── captures/                 # Sample PCAPs for testing
└── docs/                     # Internal documentation
```

---

## ✅ Example Output

```text
*** WirePeek Summary ***
File: capture.pcap
📊 Total TCP Packets Analyzed: 1021
🔄 SYN/SYN-ACK Delay: 123.5 ms

📦 Regular Retransmissions: 12
   - 10.0.0.1 ➜ 10.0.0.2 at 12:32:01.002
   ...
⚡ Fast Retransmissions: 3
🔁 Duplicate ACKs: 9
📉 Zero Window Events: 2
❌ TCP Resets: 1

💡 Interpretation:
• High handshake delay (>100ms) — could indicate latency or distant endpoint.
• High retransmission rate suggests packet loss or unstable connection.
• Receiving end may be overloaded (Zero Window).
```

---

## 📘 License

MIT License – see `LICENSE` file for details.
