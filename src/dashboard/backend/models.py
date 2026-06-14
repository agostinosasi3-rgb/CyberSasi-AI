"""
models.py
Pydantic schemas used by the FastAPI dashboard backend.
"""

from pydantic import BaseModel
from typing import Optional


class TrafficRecord(BaseModel):
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: Optional[int] = 0
    dst_port: Optional[int] = 0
    packet_size: int
    ttl: int


class EventResponse(BaseModel):
    id: int
    timestamp: str
    src_ip: str
    dst_ip: str
    protocol: str
    label: str
    confidence: float
    action_taken: str


class StatsResponse(BaseModel):
    total_events: int
    malicious_count: int
    normal_count: int
    blocked_ips: list
