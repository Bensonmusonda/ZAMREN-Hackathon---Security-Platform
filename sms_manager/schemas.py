# sms_manager/schemas.py
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime, timezone # <--- Ensure timezone is imported if used in main.py default_factory

class RawSMSInput(BaseModel):
    sender_number: str
    recipient_number: Optional[str] = None # <--- ADD THIS LINE
    message_content: str
    sms_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now) # Corrected default for datetime
    details: Optional[Dict[str, Any]] = {}