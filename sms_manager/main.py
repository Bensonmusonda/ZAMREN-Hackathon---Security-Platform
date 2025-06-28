from fastapi import FastAPI, HTTPException
from typing import Dict, Any, Optional
import httpx
from datetime import datetime
import uuid

from sms_analyzer import sms_detector

import schemas

IDS_INGESTION_URL = "http://localhost:8000/ingest/sms-threat"

app = FastAPI(title="SMS Manager Subsystem", version="1.0.0")

@app.post("/detect_sms", summary="Receive and detect spam in an SMS message")
async def detect_sms_message(sms_input: schemas.RawSMSInput):
    print(f"SMS Manager received SMS from {sms_input.sender_number}: '{sms_input.message_content}'")

    if not sms_input.sms_id:
        sms_input.sms_id = f"sms-{uuid.uuid4().hex[:8]}"
    
    current_timestamp = sms_input.timestamp

    prediction_result = sms_detector.predict_spam(sms_input.message_content)
    
    if prediction_result["label"] == "spam":
        print(f"--- SPAM DETECTED by SMS Manager ---")
        print(f"Sender: {sms_input.sender_number}, Confidence: {prediction_result['confidence']:.2f}")

        threat_payload = {
            "source_type": "sms",
            "detection_id": f"detection-{uuid.uuid4().hex[:8]}",
            "timestamp": current_timestamp.isoformat(),
            "sms_id": sms_input.sms_id,
            "sender_number": sms_input.sender_number,
            "message_content": sms_input.message_content,
            "detection_type": "sms_spam",
            "confidence_score": prediction_result["confidence"],
            "details": {**sms_input.details, "prediction_label": "spam", "sms_manager_id": "sms_subsystem_01"}
        }
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(IDS_INGESTION_URL, json=threat_payload)
                response.raise_for_status()
                ids_response_data = response.json()
                print(f"Threat successfully sent to IDS: {ids_response_data.get('id', 'N/A')}")
                return {
                    "status": "spam_detected_and_reported_to_ids",
                    "prediction": prediction_result,
                    "threat_id_from_ids": ids_response_data.get('id')
                }
            except httpx.HTTPStatusError as e:
                print(f"Error sending threat to IDS: {e.response.status_code} - {e.response.text}")
                raise HTTPException(status_code=500, detail=f"Failed to report spam to main IDS: {e.response.text}")
            except httpx.RequestError as e:
                print(f"Network error sending threat to IDS: {e}")
                raise HTTPException(status_code=500, detail=f"Network error reporting spam to main IDS: {e}")
    else:
        print(f"SMS Manager: SMS from {sms_input.sender_number} is Ham. Confidence: {prediction_result['confidence']:.2f}. No threat reported.")
        return {
            "status": "ham_detected",
            "prediction": prediction_result
        }
