import os
import psycopg


DB_CONFIG = {
    "host": os.getenv("DB_HOST", "127.0.0.1"),
    "dbname": os.getenv("DB_NAME", "threat_intel"),
    "user": os.getenv("DB_USER", "threat_app"),
    "password": os.getenv("DB_PASSWORD"),
}


def get_behavior(src_ip):
    with psycopg.connect(**DB_CONFIG) as connection:
        with connection.cursor() as cursor:

            cursor.execute(
                """
                SELECT
                    COUNT(*) AS total_events,
                    COUNT(*) FILTER (
                        WHERE event_type = 'cowrie.login.failed'
                    ) AS failed_logins,
                    COUNT(*) FILTER (
                        WHERE event_type = 'cowrie.login.success'
                    ) AS successful_logins,
                    COUNT(*) FILTER (
                        WHERE event_type = 'cowrie.command.input'
                    ) AS commands,
                    COUNT(DISTINCT dst_ip) AS targets
                FROM security_events
                WHERE src_ip = %s;
                """,
                (src_ip,)
            )

            return cursor.fetchone()


def calculate_risk(behavior):
    total_events, failed_logins, successful_logins, commands, targets = behavior

    score = 0

    # Authentication failures
    score += min(failed_logins * 2, 20)

    # Commands executed in the honeypot
    score += min(commands * 10, 30)

    # Multiple targets
    if targets >= 2:
        score += 20

    # Successful honeypot login
    if successful_logins >= 1:
        score += 10

    return min(score, 100)


def risk_level(score):
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    else:
        return "LOW"

def save_reputation(src_ip, score, level, total_events):
    with psycopg.connect(**DB_CONFIG) as connection:
        with connection.cursor() as cursor:

            cursor.execute(
                """
                INSERT INTO ip_reputation
                (
                    ip_address,
                    score,
                    events_count,
                    last_seen,
                    risk_level,
                    updated_at
                )
                VALUES (%s, %s, %s, NOW(), %s, NOW())
                ON CONFLICT (ip_address)
                DO UPDATE SET
                    score = EXCLUDED.score,
                    events_count = EXCLUDED.events_count,
                    last_seen = NOW(),
                    risk_level = EXCLUDED.risk_level,
                    updated_at = NOW();
                """,
                (
                    src_ip,
                    score,
                    total_events,
                    level
                )
            )

if __name__ == "__main__":

    src_ip = input("Enter source IP: ").strip()

    behavior = get_behavior(src_ip)
    score = calculate_risk(behavior)
    level = risk_level(score)

    print("\nRisk Assessment")
    print("----------------")
    print(f"Source IP:          {src_ip}")
    print(f"Total events:       {behavior[0]}")
    print(f"Failed logins:      {behavior[1]}")
    print(f"Successful logins:  {behavior[2]}")
    print(f"Commands:           {behavior[3]}")
    print(f"Unique targets:     {behavior[4]}")
    print(f"Risk score:         {score}/100")
    print(f"Risk level:         {level}")
    save_reputation(
        src_ip,
        score,
        level,
        behavior[0]
    )

    print("\nReputation saved to PostgreSQL.")
