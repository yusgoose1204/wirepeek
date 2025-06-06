from flask import Flask, request, jsonify
import os
import json
import requests
from threading import Thread

from analyzer import analyze_pcap
from formatter import format_tcp_analysis

app = Flask(__name__)

SLACK_BOT_TOKEN = os.environ["SLACK_BOT_TOKEN"]
SLACK_API_URL = "https://slack.com/api"

headers = {
    "Authorization": f"Bearer {SLACK_BOT_TOKEN}",
    "Content-Type": "application/json"
}


@app.route('/slack/interactive', methods=['POST'])
def handle_interactive():
    payload = json.loads(request.form['payload'])

    if payload['type'] == 'message_action' and payload.get('callback_id') == 'analyze_wirepeek':
        # Acknowledge the shortcut to avoid "Sorry, that didn’t work"
        Thread(target=process_shortcut, args=(payload,)).start()
        return '', 200

    return '', 404


def process_shortcut(payload):
    try:
        user_id = payload['user']['id']
        channel_id = payload['channel']['id']
        message_ts = payload['message']['ts']
        files = payload['message'].get('files', [])

        if not files:
            post_message(channel_id, message_ts, "⚠️ No files were attached to this message.")
            return

        file_url = files[0].get('url_private_download')
        file_name = files[0].get('name', 'capture.pcap')

        # Download the PCAP
        file_resp = requests.get(file_url, headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}"})
        if file_resp.status_code != 200:
            post_message(channel_id, message_ts, "❌ Failed to download the file.")
            return

        # Save to disk
        local_path = f"/tmp/{file_name}"
        with open(local_path, 'wb') as f:
            f.write(file_resp.content)

        # Analyze + Format
        metrics = analyze_pcap(local_path)
        summary = format_tcp_analysis(metrics, filename=file_name)

        # Post result
        post_message(channel_id, message_ts, summary)

    except Exception as e:
        post_message(channel_id, message_ts, f"❌ Unexpected error occurred: {str(e)}")


def post_message(channel, thread_ts, text):
    payload = {
        "channel": channel,
        "thread_ts": thread_ts,
        "text": text
    }
    requests.post(f"{SLACK_API_URL}/chat.postMessage", headers=headers, json=payload)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
