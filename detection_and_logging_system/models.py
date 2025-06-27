import uuid
from sqlalchemy import Integer, String, Column, Text, DateTime, Float, JSON
from sqlalchemy.orm import Mapped, mapped_column
from datetime import datetime
from database import Base
from typing import Optional

class DetectedThreat(Base):

    __tablename__ = "detected_threat"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True, default=lambda: str(uuid.uuid4()))

    detection_id: Mapped[str] = mapped_column(String(255), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    source_type: Mapped[str] = mapped_column(String(20), nullable=False)
    threat_type: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    source_identifier: Mapped[str] = mapped_column(String(255), nullable=False)
    content_snippet: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    confidence_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="new")

    full_details_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    def __repr__(self):
        return f"<DetectedThreat(id={self.id}, threat_type='{self.threat_type}', source_type='{self.source_type}')>"


class NetworkEventLog(Base):
    __tablename__ = "network_event_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    log_source: Mapped[str] = mapped_column(String(50), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    event_description: Mapped[str] = mapped_column(Text, nullable=False)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    action: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    username: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    def __repr__(self):
        return f"<NetworkEventLog(id={self.id}, source='{self.log_source}', desc='{self.event_description[:50]}...')>"