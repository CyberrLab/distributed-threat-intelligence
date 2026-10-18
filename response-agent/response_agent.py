import subprocess
import requests


THREAT_INTEL_API = "http://127.0.0.1:8000"
BLOCK_THRESHOLD = 60
BLOCK_DURATION = 300  # 5 minutes


def get_reputation(ip_address):

    url = f"{THREAT_INTEL_API}/threat-intel/{ip_address}"

    response = requests.get(url, timeout=5)
    response.raise_for_status()

    return response.json()


def block_ip(ip_address):

    try:
        result = subprocess.run(
            [
                "ssh",
                "-i",
                "/home/cowrie/.ssh/response_agent",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "StrictHostKeyChecking=accept-new",
                "response@192.168.56.109",
                "sudo",
                "-n",
                "/usr/local/sbin/threat-block",
                ip_address,
                str(BLOCK_DURATION)
            ],
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode == 0:
            print(
                f"Remote firewall block applied on protected server "
                f"for {BLOCK_DURATION} seconds."
            )
            return True

        print("Remote firewall helper failed:")
        print(result.stderr.strip())
        return False

    except subprocess.TimeoutExpired:
        print("Remote firewall helper timed out.")
        return False

    except Exception as error:
        print(f"Remote firewall error: {error}")
        return False


def evaluate_ip(ip_address):

    data = get_reputation(ip_address)
    try:
        data = get_reputation(ip_address)
    except requests.RequestException as error:
        print(f"Threat Intelligence API error: {error}")
        return

    if data.get("status") != "found":
        print(f"No reputation data found for {ip_address}")
        return

    score = data["score"]
    level = data["risk_level"]

    print("\nThreat Intelligence")
    print("-------------------")
    print(f"IP address:  {ip_address}")
    print(f"Risk score:  {score}/100")
    print(f"Risk level:  {level}")

    if score >= BLOCK_THRESHOLD:

        print("\nACTION: BLOCK")
        print("Reason: risk score reached the blocking threshold.")

        block_ip(ip_address)

    else:

        print("\nACTION: ALLOW")
        print("Reason: risk score is below the blocking threshold.")


if __name__ == "__main__":

    ip_address = input("Enter IP address: ").strip()

    evaluate_ip(ip_address)
