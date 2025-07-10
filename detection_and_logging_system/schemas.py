# detection_and_logging_system/schemas.py

import uuid
from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field 

class EmailDetectionInput(BaseModel):
    source_type: str = "email"
    detection_id: str = f"detection-{uuid.uuid4().hex[:8]}"
    timestamp: datetime
    email_id: str
    sender: str
    subject: str
    detection_type: str
    confidence_score: Optional[float] = None
    details: Optional[Dict[str, Any]] = None

class SMSDetectionInput(BaseModel):
    source_type: str = "sms"
    detection_id: str = f"detection-{uuid.uuid4().hex[:8]}"
    timestamp: datetime
    sms_id: str
    sender_number: str
    message_content: str
    detection_type: str
    confidence_score: Optional[float] = None
    details: Optional[Dict[str, Any]] = None

class NetworkDetectionInput(BaseModel):
    source_type: str = "network_ids"
    detection_id: str = f"detection-{uuid.uuid4().hex[:8]}"
    timestamp: datetime
    event_type: str
    source_ip: str
    target_ip: Optional[str] = None
    port: Optional[str] = None
    protocol: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    username: Optional[str] = None
    confidence_score: Optional[float] = None

class DetectedThreat(BaseModel):
    id: uuid.UUID
    detection_id: str
    timestamp: datetime
    source_type: str
    threat_type: str
    severity: str
    source_identifier: str
    content_snippet: Optional[str] = None
    confidence_score: Optional[float] = None
    status: str
    full_details_json: Optional[Dict[str, Any]] = None

    # Optional fields for source-specific details
    sms_id: Optional[str] = None
    sender_number: Optional[str] = None
    message_content: Optional[str] = None
    email_id: Optional[str] = None
    sender: Optional[str] = None
    subject: Optional[str] = None
    source_ip: Optional[str] = None
    target_ip: Optional[str] = None
    port: Optional[str] = None
    protocol: Optional[str] = None
    username: Optional[str] = None

    class Config:
        from_attributes = True

class RawNetworkLogInput(BaseModel):
    log_source: str
    timestamp: datetime=Field(default_factory=lambda: datetime.now(timezone.utc))
    event_description: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    protocol: Optional[str] = None
    port: Optional[int] = None
    action: Optional[str] = None
    username: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

# --- UPDATED: Raw SMS Log Input Schema ---
class RawSMSLogInput(BaseModel):
    sms_id: str # Now required, as it's the primary key
    sender_number: str
    message_content: str
    timestamp: datetime
    detection_status: str
    details: Optional[Dict[str, Any]] = None

# schemas.py addition

class RawSMSLog(RawSMSLogInput):
    """
    Schema for displaying Raw SMS Logs, inheriting from RawSMSLogInput
    and adding database-specific fields if necessary.
    """
    # If your models.RawSMSLog has an 'id' field that's an autoincrementing int
    # and sms_id is just a unique identifier, you'd add:
    # id: int

    class Config:
        from_attributes = True # Important for ORM compatibility

class RawEmailLogInput(BaseModel):
    email_id: str # This should be a unique identifier for the email
    sender: str
    recipient: Optional[str] = None # Assuming a single primary recipient for simplicity
    subject: Optional[str] = None
    body_snippet: Optional[str] = None # A short part of the email body for logging
    received_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    detection_status: Optional[str] = None # 'ham', 'spam', 'phishing' if processed by an email manager
    details: Optional[Dict[str, Any]] = None # Any additional meta-data

class RawEmailLog(RawEmailLogInput):
    """
    Schema for displaying Raw Email Logs, inheriting from RawEmailLogInput
    and adding ORM compatibility.
    """
    # If your models.RawEmailLog has an 'id' field that's an autoincrementing int
    # you'd add:
    # id: int

    class Config:
        from_attributes = True # Crucial for ORM conversion

