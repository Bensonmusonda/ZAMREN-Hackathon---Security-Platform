import uuid
from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime, date

class EmailDetectionInput(BaseModel):
    source_type: str = "email"
    detection_id: str
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
    detection_id: str
    timestamp: datetime
    event_type: str
    source_ip: str
    target_ip: Optional[str] = None
    port: Optional[str] = None
    protocol: Optional[str] = None
    details: Optional[Dict[str, Any]] = None 


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

    class Config:
        from_attributes = True

class RawNetworkLogInput(BaseModel):
    log_source: str
    timestamp: datetime
    event_description: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    protocol: Optional[str] = None
    port: Optional[int] = None
    action: Optional[str] = None
    username: Optional[str] = None
    details: Optional[Dict[str, Any]] = None