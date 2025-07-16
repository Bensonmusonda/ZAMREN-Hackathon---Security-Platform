import uuid
from sqlalchemy import Column, Integer, String, DateTime, Float, Boolean, JSON, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, ARRAY, JSONB
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime, timezone

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=True)
    email = Column(String, unique=True, index=True, nullable=False)
    phone = Column(String, unique=True, index=True, nullable=True)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)

class DetectedThreat(Base):
    __tablename__ = "detected_threats"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    detection_id = Column(String, unique=True, index=True, nullable=False)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    source_type = Column(String, nullable=False)
    threat_type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    source_identifier = Column(String, nullable=False)
    content_snippet = Column(String, nullable=True)
    confidence_score = Column(Float, nullable=True)
    status = Column(String, default="new", nullable=False)
    full_details_json = Column(JSON, nullable=True)

class NetworkLog(Base):
    __tablename__ = "network_logs"

    id = Column(Integer, primary_key=True, index=True)
    log_source = Column(String, nullable=False)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    event_description = Column(String, nullable=False)
    source_ip = Column(String, nullable=True)
    destination_ip = Column(String, nullable=True)
    protocol = Column(String, nullable=True)
    port = Column(Integer, nullable=True)
    action = Column(String, nullable=True)
    username = Column(String, nullable=True)
    details = Column(JSON, nullable=True)
    # --- NEW COLUMNS FOR RESPONSE LOGGING ---
    response_status_code = Column(Integer, nullable=True)
    response_content_length = Column(Integer, nullable=True)
    response_body_snippet = Column(String, nullable=True)
    # -------------------------------------

class RawSMSLog(Base):
    __tablename__ = "raw_sms_logs"

    id = Column(Integer, primary_key=True, index=True)
    sms_id = Column(String, unique=True, index=True, nullable=False)
    sender_number = Column(String, nullable=False)
    recipient_number = Column(String, nullable=True)
    message_content = Column(String, nullable=False)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    detection_status = Column(String, nullable=True)
    details = Column(JSON, nullable=True)

class RawEmailLog(Base):
    __tablename__ = "raw_email_logs"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(String, unique=True, index=True, nullable=False)
    sender = Column(String, nullable=False)
    recipients = Column(JSONB, nullable=True)
    subject = Column(String, nullable=True)
    body = Column(String, nullable=True)
    received_timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    detection_status = Column(String, nullable=True)
    details = Column(JSON, nullable=True)
    attachment_filename = Column(String, nullable=True)
    attachment_url = Column(String, nullable=True)
    source_ip = Column(String, nullable=True) # Source IP for email origin