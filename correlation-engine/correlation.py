import os
import psycopg


DB_CONFIG = {
    "host": os.getenv("DB_HOST", "127.0.0.1"),
    "dbname": os.getenv("DB_NAME", "threat_intel"),
    "user": os.getenv("DB_USER", "threat_app"),
    "password": os.getenv("DB_PASSWORD"),
}


def get_ip_behavior(src_ip):
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


if __name__ == "__main__":

    src_ip = input("Enter source IP: ").strip()

    result = get_ip_behavior(src_ip)

    print("\nBehavior summary")
    print("----------------")
    print(f"Source IP:          {src_ip}")
    print(f"Total events:       {result[0]}")
    print(f"Failed logins:      {result[1]}")
    print(f"Successful logins:  {result[2]}")
    print(f"Commands:           {result[3]}")
    print(f"Unique targets:     {result[4]}")
