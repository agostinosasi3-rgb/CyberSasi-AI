"""
main.py
CyberSasi AI - FastAPI backend.

Provides REST API endpoints for:
  - Submitting traffic records for classification
  - Retrieving recent alerts/logs
  - Retrieving summary statistics
  - Listing/managing blocked IPs

Run with:
    uvicorn main:app --reload --host 0.0.0.0 --port 8000
"""

import sys
import os
import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# Allow importing sibling modules (ml_model, response, forensics)
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "..", "ml_model"))
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "..", "response"))
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "..", "forensics"))

from models import TrafficRecord, EventResponse, StatsResponse

try:
    from predict import predict as ml_predict
except FileNotFoundError:
    ml_predict = None

from auto_block import handle_prediction, list_blocked_ips
from log_manager import log_event, get_recent_events

app = FastAPI(
    title="CyberSasi AI API",
    description="AI-Powered Network Intrusion Detection and Auto-Response System",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"message": "CyberSasi AI API is running."}


@app.post("/analyze", response_model=EventResponse)
def analyze_traffic(record: TrafficRecord):
    """
    Submit a traffic record for classification.
    Runs the ML model, applies auto-response if malicious,
    and logs the result.
    """
    df = pd.DataFrame([record.dict()])

    if ml_predict is None:
        raise HTTPException(
            status_code=503,
            detail="ML model not trained yet. Run train_model.py first."
        )

    result_df = ml_predict(df)
    result = result_df.iloc[0]

    prediction_record = {
        "src_ip": record.src_ip,
        "label": result["label"],
        "confidence": float(result["confidence"]),
    }
    action = handle_prediction(prediction_record)

    logged = log_event(
        src_ip=record.src_ip,
        dst_ip=record.dst_ip,
        protocol=record.protocol,
        label=result["label"],
        confidence=float(result["confidence"]),
        action_taken=action["status"],
    )

    return EventResponse(
        id=0,
        timestamp=logged["timestamp"],
        src_ip=logged["src_ip"],
        dst_ip=logged["dst_ip"],
        protocol=logged["protocol"],
        label=logged["label"],
        confidence=logged["confidence"],
        action_taken=logged["action_taken"],
    )


@app.get("/alerts", response_model=list[EventResponse])
def get_alerts(limit: int = 50):
    """Return the most recent detection events/alerts."""
    events = get_recent_events(limit)
    return events


@app.get("/stats", response_model=StatsResponse)
def get_stats():
    """Return summary statistics for the dashboard."""
    events = get_recent_events(1000)
    malicious = [e for e in events if e["label"] == "malicious"]
    normal = [e for e in events if e["label"] == "normal"]
    return StatsResponse(
        total_events=len(events),
        malicious_count=len(malicious),
        normal_count=len(normal),
        blocked_ips=list_blocked_ips(),
    )


@app.get("/blocked-ips")
def get_blocked_ips():
    """Return the list of currently blocked IP addresses."""
    return {"blocked_ips": list_blocked_ips()}
