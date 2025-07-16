import uuid
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

# --- User Authentication Schemas ---
class UserCreate(BaseModel):
    # This is for user registration
    first_name: str
    last_name: str
    email: str
    phone: str
    password: str # This will be hashed on the server

class UserOut(BaseModel):
    # This is for sending user data back (e.g., after registration)
    username: Optional[str] = None
    email: str
    phone: str
    first_name: str
    last_name: str
    disabled: Optional[bool] = None

    class Config:
        from_attributes = True

class UserInDB(UserOut):
    # This is for internal server use, includes hashed password
    hashed_password: str

class Token(BaseModel):
    # For the JWT response
    access_token: str
    token_type: str

class TokenData(BaseModel):
    # For decoding JWT payload
    username: Optional[str] = None # 'sub' claim from JWT
    email: Optional[str] = None
    phone: Optional[str] = None
# --- End User Authentication Schemas ---


class EmailDetectionInput(BaseModel):
    source_type: str = "email"
    detection_id: str = Field(default_factory=lambda: f"detection-{uuid.uuid4().hex[:8]}")
    timestamp: datetime
    email_id: str
    sender: str
    subject: str
    detection_type: str
    confidence_score: Optional[float] = None
    details: Optional[Dict[str, Any]] = None

class SMSDetectionInput(BaseModel):
    source_type: str = "sms"
    detection_id: str = Field(default_factory=lambda: f"detection-{uuid.uuid4().hex[:8]}")
    timestamp: datetime
    sms_id: str
    sender_number: str
    recipient_number: Optional[str] = None
    message_content: str
    detection_type: str
    confidence_score: Optional[float] = None
    details: Optional[Dict[str, Any]] = None

class NetworkDetectionInput(BaseModel):
    source_type: str = "network_ids"
    detection_id: str = Field(default_factory=lambda: f"detection-{uuid.uuid4().hex[:8]}")
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

    class Config:
        from_attributes = True

class RawNetworkLogInput(BaseModel):
    log_source: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_description: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    protocol: Optional[str] = None
    port: Optional[int] = None
    action: Optional[str] = None
    username: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    # --- NEW FIELDS FOR RESPONSE LOGGING ---
    response_status_code: Optional[int] = None
    response_content_length: Optional[int] = None
    response_body_snippet: Optional[str] = None
    # -------------------------------------

class RawSMSLogInput(BaseModel):
    sms_id: str
    sender_number: str
    recipient_number: Optional[str] = None
    message_content: str
    timestamp: datetime
    detection_status: str
    details: Optional[Dict[str, Any]] = None

class RawSMSLog(RawSMSLogInput):
    class Config:
        from_attributes = True

class RawEmailLogInput(BaseModel):
    email_id: str
    sender: str
    recipients: List[str] = []
    subject: Optional[str] = None
    body: Optional[str] = None
    received_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    detection_status: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    attachment_filename: Optional[str] = None
    attachment_url: Optional[str] = None
    source_ip: Optional[str] = None # Source IP for email origin

class RawEmailLog(RawEmailLogInput):
    class Config:
        from_attributes = True