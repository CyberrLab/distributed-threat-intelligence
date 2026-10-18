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
                    COUNT(*) FILTER (
                        WHERE event_type = 'cowrie.login.failed'
                    ) AS failed_logins,

                    COUNT(*) FILTER (
                        WHERE event_type = 'cowrie.command.input'
                    ) AS commands,

                    COUNT(*) FILTER (
                        WHERE event_type = 'cowrie.command.failed'
                    ) AS failed_commands,

                    COUNT(*) FILTER (
                        WHERE event_type = 'cowrie.login.success'
                    ) AS successful_logins,

                    COUNT(DISTINCT dst_ip) AS targets

                FROM security_events
                WHERE src_ip = %s;
                """,
                (src_ip,)
            )

            behavior = cursor.fetchone()

            cursor.execute(
                """
                SELECT details->>'command'
                FROM security_events
                WHERE src_ip = %s
                  AND event_type = 'cowrie.command.input'
                  AND details->>'command' IS NOT NULL;
                """,
                (src_ip,)
            )

            commands_list = [
                row[0].lower()
                for row in cursor.fetchall()
            ]

            return behavior, commands_list


def calculate_risk(behavior, commands_list):

    (
        failed_logins,
        commands,
        failed_commands,
        successful_logins,
        targets
    ) = behavior

    score = 0
    reasons = []

    # Failed authentication attempts
    if failed_logins > 0:
        points = min(failed_logins * 5, 25)
        score += points
        reasons.append(
            f"{failed_logins} failed login attempt(s)"
        )

    # Failed commands
    if failed_commands > 0:
        points = min(failed_commands * 5, 15)
        score += points
        reasons.append(
            f"{failed_commands} failed command(s)"
        )

    # Command activity
    if commands >= 10:
        score += 15
        reasons.append("high command activity")

    elif commands >= 5:
        score += 10
        reasons.append("moderate command activity")

    elif commands > 0:
        score += 5
        reasons.append("command activity detected")

    # Suspicious command keywords
    suspicious_keywords = [
        "wget",
        "curl",
        "chmod",
        "nc",
        "ncat",
        "netcat",
        "bash -i",
        "python -c",
        "perl -e",
        "rm -rf",
        "passwd",
        "useradd",
        "sudo"
    ]

    suspicious_commands = []

    for command in commands_list:

        for keyword in suspicious_keywords:

            if keyword in command:
                suspicious_commands.append(command)
                break

    if suspicious_commands:
        points = min(len(suspicious_commands) * 10, 30)
        score += points

        reasons.append(
            f"{len(suspicious_commands)} suspicious command(s)"
        )

    # Multiple honeypot targets
    if targets >= 2:
        score += 20
        reasons.append(
            f"activity against {targets} targets"
        )

    # Successful login is context, not strong evidence
    if successful_logins > 0:
        reasons.append(
            f"{successful_logins} successful login(s)"
        )

    return min(score, 100), reasons


def risk_level(score):

    if score >= 80:
        return "CRITICAL"

    elif score >= 60:
        return "HIGH"

    elif score >= 30:
        return "MEDIUM"

    else:
        return "LOW"


def save_reputation(
    src_ip,
    score,
    level,
    total_events
):

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
                VALUES (
                    %s,
                    %s,
                    %s,
                    NOW(),
                    %s,
                    NOW()
                )

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

    src_ip = input(
        "Enter source IP: "
    ).strip()

    behavior, commands_list = get_behavior(src_ip)

    (
        failed_logins,
        commands,
        failed_commands,
        successful_logins,
        targets
    ) = behavior

    total_events = (
        failed_logins
        + commands
        + failed_commands
        + successful_logins
    )

    score, reasons = calculate_risk(
        behavior,
        commands_list
    )

    level = risk_level(score)

    print("\nRisk Assessment")
    print("----------------")

    print(f"Source IP:          {src_ip}")
    print(f"Behavior events:    {total_events}")
    print(f"Failed logins:      {failed_logins}")
    print(f"Successful logins:  {successful_logins}")
    print(f"Commands:           {commands}")
    print(f"Failed commands:    {failed_commands}")
    print(f"Unique targets:     {targets}")

    print(f"\nRisk score:         {score}/100")
    print(f"Risk level:         {level}")

    print("\nReasons")
    print("-------")

    if reasons:

        for reason in reasons:
            print(f"- {reason}")

    else:
        print("- No significant risk indicators detected.")

    save_reputation(
        src_ip,
        score,
        level,
        total_events
    )

    print("\nReputation saved to PostgreSQL.")
