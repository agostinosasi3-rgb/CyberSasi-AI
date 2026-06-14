"""
log_manager.py
Handles forensic logging of detected events (alerts, blocked IPs,
system actions) to a local SQLite database and JSON log file.

Designed to work standalone (SQLite) for easy testing, but can be
pointed at PostgreSQL by changing DB_URL.
"""

import os
import json
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DB_PATH = os.path.join(_PROJECT_ROOT, "data", "processed", "forensics.db")
DB_URL = f"sqlite:///{DB_PATH}"
JSON_LOG_PATH = os.path.join(_PROJECT_ROOT, "data", "processed", "event_log.json")

Base = declarative_base()


class EventLog(Base):
    __tablename__ = "event_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    src_ip = Column(String)
    dst_ip = Column(String)
    protocol = Column(String)
    label = Column(String)        # 'normal' or 'malicious'
    confidence = Column(Float)
    action_taken = Column(String)  # e.g. 'blocked', 'logged', 'none'


def _get_session():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    engine = create_engine(DB_URL)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()


def log_event(src_ip, dst_ip, protocol, label, confidence, action_taken="logged"):
    """
    Record a detection/response event to the database and a JSON log file.
    """
    session = _get_session()
    event = EventLog(
        timestamp=datetime.utcnow(),
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        label=label,
        confidence=confidence,
        action_taken=action_taken,
    )
    session.add(event)
    session.commit()

    record = {
        "timestamp": event.timestamp.isoformat(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "label": label,
        "confidence": confidence,
        "action_taken": action_taken,
    }
    _append_json_log(record)

    print(f"[LOGGED] {src_ip} -> {dst_ip} | {label} ({confidence}) | action: {action_taken}")
    session.close()
    return record


def _append_json_log(record: dict):
    os.makedirs(os.path.dirname(JSON_LOG_PATH), exist_ok=True)
    logs = []
    if os.path.exists(JSON_LOG_PATH):
        with open(JSON_LOG_PATH, "r") as f:
            try:
                logs = json.load(f)
            except json.JSONDecodeError:
                logs = []
    logs.append(record)
    with open(JSON_LOG_PATH, "w") as f:
        json.dump(logs, f, indent=2)


def get_recent_events(limit: int = 50):
    """Return the most recent events, newest first."""
    session = _get_session()
    events = (
        session.query(EventLog)
        .order_by(EventLog.timestamp.desc())
        .limit(limit)
        .all()
    )
    result = [
        {
            "id": e.id,
            "timestamp": e.timestamp.isoformat(),
            "src_ip": e.src_ip,
            "dst_ip": e.dst_ip,
            "protocol": e.protocol,
            "label": e.label,
            "confidence": e.confidence,
            "action_taken": e.action_taken,
        }
        for e in events
    ]
    session.close()
    return result


if __name__ == "__main__":
    # Smoke test
    log_event("192.168.1.50", "192.168.1.1", "TCP", "malicious", 0.93, "blocked")
    print(get_recent_events(5))
