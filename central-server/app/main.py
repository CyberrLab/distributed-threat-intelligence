import os
from datetime import datetime
from ipaddress import IPv4Address

import psycopg
from psycopg.types.json import Jsonb
from fastapi import FastAPI
from pydantic import BaseModel


app = FastAPI(
    title="Distributed Threat Intelligence API",
    version="0.2.0"
)


DB_CONFIG = {
    "host": os.getenv("DB_HOST", "127.0.0.1"),
    "dbname": os.getenv("DB_NAME", "threat_intel"),
    "user": os.getenv("DB_USER", "threat_app"),
    "password": os.getenv("DB_PASSWORD"),
}


class SecurityEvent(BaseModel):
    timestamp: datetime
    src_ip: IPv4Address
    dst_ip: IPv4Address | None = None
    service: str | None = None
    session: str | None = None
    event_type: str
    details: dict = {}


@app.get("/")
def root():
    return {
        "status": "running",
        "service": "threat-intelligence-api"
    }


@app.post("/events")
def receive_event(event: SecurityEvent):

    with psycopg.connect(**DB_CONFIG) as connection:

        with connection.cursor() as cursor:

            cursor.execute(
                """
                INSERT INTO security_events
                (
                    timestamp,
                    src_ip,
                    dst_ip,
                    service,
                    session,
                    event_type,
                    details
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    event.timestamp,
                    str(event.src_ip),
                    str(event.dst_ip) if event.dst_ip else None,
                    event.service,
                    event.session,
                    event.event_type,
                    Jsonb(event.details)
                )
            )

    return {
        "status": "stored",
        "event_type": event.event_type,
        "src_ip": str(event.src_ip)
    }


@app.get("/threat-intel/{ip_address}")
def get_threat_intelligence(ip_address: IPv4Address):

    with psycopg.connect(**DB_CONFIG) as connection:

        with connection.cursor() as cursor:

            cursor.execute(
                """
                SELECT
                    ip_address,
                    score,
                    events_count,
                    risk_level,
                    last_seen,
                    updated_at
                FROM ip_reputation
                WHERE ip_address = %s;
                """,
                (str(ip_address),)
            )

            result = cursor.fetchone()

    if result is None:
        return {
            "status": "not_found",
            "ip": str(ip_address)
        }

    return {
        "status": "found",
        "ip": str(result[0]),
        "score": result[1],
        "events_count": result[2],
        "risk_level": result[3],
        "last_seen": result[4],
        "updated_at": result[5]
    }
