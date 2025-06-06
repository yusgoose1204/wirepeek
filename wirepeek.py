
from flask import Flask, request, jsonify
from analyzer import analyze_pcap
from formatter import format_tcp_analysis
import os

app = Flask(__name__)

@app.route('/')
def home():
    return 'WirePeek is live!'

@app.route('/slack', methods=['POST'])
def slack_handler():
    # Read slash command text (e.g. file name or hint)
    user_input = request.form.get('text', '')
    user_name = request.form.get('user_name', 'unknown')

    # TEMP: Replace with actual capture file logic
    pcap_path = f"./captures/{user_input.strip()}"  # Optional: validate filename

    try:
        metrics = analyze_pcap(pcap_path)
        summary = format_tcp_analysis(metrics, filename=user_input)
    except Exception as e:
        summary = f"⚠️ Error analyzing {user_input}: {str(e)}"

    return jsonify({
        "response_type": "in_channel",  # visible to everyone in channel
        "text": f"*Requested by:* `{user_name}`\n```\n{summary}\n```"
    })

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
    print(analyze_pcap("./captures/tcp_dupack.pcapng"))

