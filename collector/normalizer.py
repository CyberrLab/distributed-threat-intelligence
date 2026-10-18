import json
import urllib.request
import urllib.error
from pathlib import Path


LOG_FILE = Path("/home/cowrie/my-honeypot/var/log/cowrie/cowrie.json")
OUTPUT_FILE = Path("/home/cowrie/my-honeypot/collector/normalized_events.json")
STATE_FILE = Path("/home/cowrie/my-honeypot/collector/normalizer.state")

API_URL = "http://127.0.0.1:8000/events"


def send_to_api(event):
    data = json.dumps(event).encode("utf-8")

    request = urllib.request.Request(
        API_URL,
        data=data,
        headers={
            "Content-Type": "application/json"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.read().decode("utf-8")

    except urllib.error.URLError as error:
        print(f"API connection failed: {error}")
        return None


def normalize_event(event):
    event_id = event.get("eventid", "")

    normalized = {
        "timestamp": event.get("timestamp"),
        "src_ip": event.get("src_ip"),
        "dst_ip": event.get("dst_ip"),
        "service": event.get("protocol"),
        "session": event.get("session"),
        "event_type": event_id,
        "details": {}
    }

    if event_id in [
        "cowrie.login.failed",
        "cowrie.login.success"
    ]:
        normalized["details"] = {
            "username": event.get("username")
        }

    elif event_id == "cowrie.command.input":
        normalized["details"] = {
            "command": event.get("input")
        }

    elif event_id == "cowrie.session.closed":
        normalized["details"] = {
            "duration_ms": event.get("duration_ms")
        }

    else:
        normalized["details"] = {
            "message": event.get("message")
        }

    return normalized


def get_start_position():
    if STATE_FILE.exists():
        try:
            return int(STATE_FILE.read_text().strip())
        except ValueError:
            return 0

    return 0


def save_position(position):
    STATE_FILE.write_text(str(position))


def process_logs():

    start_position = get_start_position()

    with open(LOG_FILE, "r") as log_file:

        log_file.seek(start_position)

        while True:

            line = log_file.readline()

            if not line:
                break

            current_position = log_file.tell()

            try:
                event = json.loads(line)

                normalized = normalize_event(event)

                with open(OUTPUT_FILE, "a") as output_file:
                    output_file.write(
                        json.dumps(normalized) + "\n"
                    )

                response = send_to_api(normalized)

                if response:
                    print(
                        f"Sent to API: "
                        f"{normalized['event_type']} "
                        f"from {normalized['src_ip']}"
                    )

                    save_position(current_position)

            except json.JSONDecodeError:
                print("Skipping invalid JSON line")


if __name__ == "__main__":
    process_logs()
    print("Incremental log normalization completed.")
