# sms_manager/schemas.py

from pydantic import BaseModel, Field # Added Field
from typing import Optional, Dict, Any
from datetime import datetime

class RawSMSInput(BaseModel):
    sender_number: str
    message_content: str
    sms_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now) # Corrected default for datetime
    details: Optional[Dict[str, Any]] = {}