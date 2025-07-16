# sms_manager/main.py

from fastapi import FastAPI, HTTPException
from typing import Dict, Any, Optional
import httpx
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timezone
import uuid

from sms_analyzer import sms_detector

import schemas

IDS_RAW_SMS_LOG_URL = "http://localhost:8000/ingest/raw-sms-log"
IDS_DETECTED_SMS_THREAT_URL = "http://localhost:8000/ingest/sms-threat"

app = FastAPI(title="SMS Manager Subsystem", version="1.0.0")

# Configure CORS
origins = [
    "http://localhost",
    "http://localhost:5500",  # Allow requests from your frontend development server
    "http://localhost:5501"
    "http://198.168.56.101:5501", # <--- ADD THIS (e.g., http://192.168.1.101:5501)
    "http://198.168.56.101:5501"
    "http://192.168.56.1:5501"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],  # Allows all HTTP methods (GET, POST, PUT, DELETE, etc.)
    allow_headers=["*"],  # Allows all headers
)

@app.post("/detect_sms", summary="Receive, detect, and log SMS message")
async def detect_sms_message(sms_input: schemas.RawSMSInput):
    print(f"SMS Manager received SMS from {sms_input.sender_number}: '{sms_input.message_content}'")

    if not sms_input.sms_id:
        sms_input.sms_id = f"sms-{uuid.uuid4().hex[:8]}"

    # Ensure timestamp is timezone-aware if the schema defines it with timezone.utc
    current_timestamp = sms_input.timestamp if sms_input.timestamp.tzinfo else sms_input.timestamp.replace(tzinfo=timezone.utc)


    prediction_result = sms_detector.predict_spam(sms_input.message_content)

    raw_sms_log_payload = {
        "sms_id": sms_input.sms_id,
        "sender_number": sms_input.sender_number,
        "recipient_number": sms_input.recipient_number, # <--- ADD THIS LINE
        "message_content": sms_input.message_content,
        "timestamp": current_timestamp.isoformat(), # Ensure ISO format with timezone for main IDS
        "detection_status": prediction_result["label"], # 'ham' or 'spam'
        "details": {
            **sms_input.details, # Include any original details
            "model_prediction_confidence": prediction_result["confidence"]
        }
    }

    async with httpx.AsyncClient() as client:
        try:
            raw_log_response = await client.post(IDS_RAW_SMS_LOG_URL, json=raw_sms_log_payload)
            raw_log_response.raise_for_status()
            print(f"Raw SMS logged to IDS: {raw_log_response.json().get('message', 'N/A')}")
        except httpx.HTTPStatusError as e:
            print(f"Error logging raw SMS to IDS: {e.response.status_code} - {e.response.text}")
        except httpx.RequestError as e:
            print(f"Network error logging raw SMS to IDS: {e}")

    # --- Step 2: If spam, send a detected threat to IDS ---
    if prediction_result["label"] == "spam":
        print(f"--- SPAM DETECTED by SMS Manager ---")
        print(f"Sender: {sms_input.sender_number}, Confidence: {prediction_result['confidence']:.2f}")

        threat_payload = {
            "source_type": "sms",
            "detection_id": f"detection-{uuid.uuid4().hex[:8]}",
            "timestamp": current_timestamp.isoformat(),
            "sms_id": sms_input.sms_id,
            "sender_number": sms_input.sender_number,
            "recipient_number": sms_input.recipient_number, # <--- CONSIDER ADDING THIS IF RELEVANT FOR THREATS
            "message_content": sms_input.message_content,
            "detection_type": "sms_spam",
            "confidence_score": prediction_result["confidence"],
            "details": {**sms_input.details, "prediction_label": "spam", "sms_manager_id": "sms_subsystem_01"}
        }

        async with httpx.AsyncClient() as client:
            try:
                threat_response = await client.post(IDS_DETECTED_SMS_THREAT_URL, json=threat_payload)
                threat_response.raise_for_status()
                ids_threat_response_data = threat_response.json()
                print(f"Threat successfully sent to IDS: {ids_threat_response_data.get('id', 'N/A')}")
                return {
                    "status": "spam_detected_and_reported_to_ids",
                    "prediction": prediction_result,
                    "threat_id_from_ids": ids_threat_response_data.get('id')
                }
            except httpx.HTTPStatusError as e:
                print(f"Error sending threat to IDS: {e.response.status_code} - {e.response.text}")
                raise HTTPException(status_code=500, detail=f"Failed to report spam to main IDS: {e.response.text}")
            except httpx.RequestError as e:
                print(f"Network error sending threat to IDS: {e}")
                raise HTTPException(status_code=500, detail=f"Network error reporting spam to main IDS: {e}")
    else:
        print(f"SMS Manager: SMS from {sms_input.sender_number} is Ham. Confidence: {prediction_result['confidence']:.2f}. No threat reported (only raw log sent).")
        return {
            "status": "ham_detected",
            "prediction": prediction_result
        }