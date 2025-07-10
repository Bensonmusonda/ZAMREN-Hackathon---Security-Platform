# detection_and_logging_system/actions.py (CORRECTED)

import uuid
from sqlalchemy.orm import Session
import database, schemas, models
from typing import Optional, Dict, Any
from datetime import datetime

def get_threat_severity(threat_type: str, confidence_score: Optional[float]) -> str:
    if threat_type in ["phishing", "fraudulent", "brute_force_attempt", "malware_signature", "sms_spam"]:
        if confidence_score is not None and confidence_score >= 0.8:
            return "critical"
        return "high"
    elif threat_type in ["scam", "suspicious_ip", "potential_brute_force_attempt"]:
        if confidence_score is not None and confidence_score >= 0.7:
            return "medium"
        return "low"
    elif threat_type == "spam":
        return "low"
    return "medium"

def generate_id() -> uuid.UUID:
    return uuid.uuid4()

def detected_sms_threat(sms_threat_input: schemas.SMSDetectionInput, db: Session):
    new_threat = models.DetectedThreat(
        id=generate_id(),
        detection_id=sms_threat_input.detection_id,
        timestamp=sms_threat_input.timestamp,
        source_type=sms_threat_input.source_type,
        threat_type=sms_threat_input.detection_type,
        severity=get_threat_severity(sms_threat_input.detection_type, sms_threat_input.confidence_score),
        source_identifier=sms_threat_input.sender_number, # This is a generic field, not SMS-specific column
        content_snippet=sms_threat_input.message_content, # This is a generic field
        confidence_score=sms_threat_input.confidence_score,
        status="new",
        full_details_json=sms_threat_input.model_dump(mode='json') # The full payload is stored here
    )
    db.add(new_threat)
    db.commit()
    db.refresh(new_threat)
    return schemas.DetectedThreat.from_orm(new_threat)

def detected_email_threat(email_threat_input: schemas.EmailDetectionInput, db: Session):
    new_threat = models.DetectedThreat(
        id=generate_id(),
        detection_id=email_threat_input.detection_id,
        timestamp=email_threat_input.timestamp,
        source_type=email_threat_input.source_type,
        threat_type=email_threat_input.detection_type,
        severity=get_threat_severity(email_threat_input.detection_type, email_threat_input.confidence_score),
        source_identifier=email_threat_input.sender, # Generic field
        content_snippet=email_threat_input.subject, # Generic field
        confidence_score=email_threat_input.confidence_score,
        status="new",
        full_details_json=email_threat_input.model_dump(mode='json') # The full payload is stored here
    )
    db.add(new_threat)
    db.commit()
    db.refresh(new_threat)
    return schemas.DetectedThreat.from_orm(new_threat)

def detected_network_threat(network_threat_input: schemas.NetworkDetectionInput, db: Session):
    threat_type = network_threat_input.event_type

    new_threat = models.DetectedThreat(
        id=generate_id(),
        detection_id=network_threat_input.detection_id,
        timestamp=network_threat_input.timestamp,
        source_type=network_threat_input.source_type,
        threat_type=threat_type,
        severity=get_threat_severity(threat_type, None),
        source_identifier=network_threat_input.source_ip, # Generic field
        content_snippet=f"Event: {network_threat_input.event_type}, IP: {network_threat_input.source_ip}", # Generic field
        confidence_score=network_threat_input.confidence_score,
        status="new",
        full_details_json=network_threat_input.model_dump(mode='json') # The full payload is stored here
    )
    db.add(new_threat)
    db.commit()
    db.refresh(new_threat)
    return schemas.DetectedThreat.from_orm(new_threat)

def log_network_event(log_input: schemas.RawNetworkLogInput, db: Session):
    new_log_entry = models.NetworkEventLog(
        log_source=log_input.log_source,
        timestamp=datetime.now(),
        event_description=log_input.event_description,
        source_ip=log_input.source_ip,
        destination_ip=log_input.destination_ip,
        protocol=log_input.protocol,
        port=log_input.port,
        action=log_input.action,
        username=log_input.username,
        details=log_input.details
    )
    db.add(new_log_entry)
    db.commit()
    db.refresh(new_log_entry)
    return log_input

def log_raw_sms_event(raw_sms_input: schemas.RawSMSLogInput, db: Session):
    new_raw_sms_log = models.RawSMSLog(
        sms_id=raw_sms_input.sms_id,
        sender_number=raw_sms_input.sender_number,
        message_content=raw_sms_input.message_content,
        timestamp=raw_sms_input.timestamp,
        detection_status=raw_sms_input.detection_status,
        details=raw_sms_input.details
    )
    db.add(new_raw_sms_log)
    db.commit()
    db.refresh(new_raw_sms_log)
    return raw_sms_input

def log_raw_email_event(log_input: schemas.RawEmailLogInput, db: Session):
    """
    Logs a raw email event into the database.
    """
    db_log = models.RawEmailLog(**log_input.model_dump()) # Use model_dump() for Pydantic v2
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    return db_log

def get_threat_counts(db: Session):
    # Existing counts (network, sms) will be here...

    # --- Add/Update Email Threat Counts ---
    # Count all detected email threats
    total_email_threats = db.query(models.DetectedThreat).filter_by(source_type="email").count()

    # Count only spam emails detected
    # Based on your /ingest/email-threat JSON, 'threat_type' is used for 'spam'
    spam_emails_detected = db.query(models.DetectedThreat).filter_by(source_type="email", threat_type="spam").count()

    # total_emails_received will remain 0 until raw email logging is implemented.
    # You might keep it 0 or omit it from the response until then.
    total_emails_received = db.query(models.RawEmailLog).count()

    return {
        "total_network_threats": db.query(models.DetectedThreat).filter_by(source_type="network_ids").count(),
        # Add other existing counts...
        "pending_threats": db.query(models.DetectedThreat).filter_by(status="new").count(),
        "brute_force_attacks": db.query(models.DetectedThreat).filter_by(threat_type="brute_force_attack").count(),
        "malware_detections": db.query(models.DetectedThreat).filter_by(threat_type="malware_signature_evil_exe").count(),
        "suspicious_ip_attempts": db.query(models.DetectedThreat).filter_by(threat_type="suspicious_ip_source").count(),
        "sms_spam_detected": db.query(models.DetectedThreat).filter_by(source_type="sms", threat_type="sms_spam").count(),
        "total_sms_received": db.query(models.RawSMSLog).count(), # This assumes you're counting from RawSMSLog
        "total_email_threats": total_email_threats, # <-- UPDATED
        "spam_emails_detected": spam_emails_detected, # <-- UPDATED
        "total_emails_received": total_emails_received # <-- Explained below
    }
