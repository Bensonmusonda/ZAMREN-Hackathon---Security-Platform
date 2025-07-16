# detection_and_logging_system/actions.py

import uuid
from sqlalchemy.orm import Session
from sqlalchemy import func # Ensure func is imported for get_threat_counts
import database, schemas, models
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone # Added timezone for default_factory consistency

def get_threat_severity(threat_type: str, confidence_score: Optional[float]) -> str:
    """Determines the severity of a threat based on its type and confidence score."""
    # Ensure 'malware_attachment' is handled for severity
    if threat_type in ["phishing", "fraudulent", "brute_force_attack", "malware_signature", "sms_spam", "malware_attachment"]:
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
    """Generates a new UUID."""
    return uuid.uuid4()

def detected_sms_threat(sms_threat_input: schemas.SMSDetectionInput, db: Session):
    """Logs a detected SMS threat into the database."""
    new_threat = models.DetectedThreat(
        id=generate_id(),
        detection_id=sms_threat_input.detection_id,
        timestamp=sms_threat_input.timestamp,
        source_type=sms_threat_input.source_type,
        threat_type=sms_threat_input.detection_type, # Maps to threat_type
        severity=get_threat_severity(sms_threat_input.detection_type, sms_threat_input.confidence_score),
        source_identifier=sms_threat_input.sender_number,
        content_snippet=sms_threat_input.message_content,
        confidence_score=sms_threat_input.confidence_score,
        status="new",
        full_details_json=sms_threat_input.model_dump(mode='json')
    )
    db.add(new_threat)
    db.commit()
    db.refresh(new_threat)
    return schemas.DetectedThreat.from_orm(new_threat)

def detected_email_threat(email_threat_input: schemas.EmailDetectionInput, db: Session):
    """Logs a detected email threat into the database."""
    new_threat = models.DetectedThreat(
        id=generate_id(),
        detection_id=email_threat_input.detection_id,
        timestamp=email_threat_input.timestamp,
        source_type=email_threat_input.source_type,
        threat_type=email_threat_input.detection_type, # Maps to threat_type
        severity=get_threat_severity(email_threat_input.detection_type, email_threat_input.confidence_score),
        source_identifier=email_threat_input.sender,
        content_snippet=email_threat_input.subject, # Or a snippet from the attachment if applicable
        confidence_score=email_threat_input.confidence_score,
        status="new",
        full_details_json=email_threat_input.model_dump(mode='json')
    )
    db.add(new_threat)
    db.commit()
    db.refresh(new_threat)
    return schemas.DetectedThreat.from_orm(new_threat)

def detected_network_threat(network_threat_input: schemas.NetworkDetectionInput, db: Session):
    """Logs a detected network threat into the database."""
    threat_type = network_threat_input.event_type # Maps event_type to threat_type

    new_threat = models.DetectedThreat(
        id=generate_id(),
        detection_id=network_threat_input.detection_id,
        timestamp=network_threat_input.timestamp,
        source_type=network_threat_input.source_type,
        threat_type=threat_type,
        severity=get_threat_severity(threat_type, network_threat_input.confidence_score),
        source_identifier=network_threat_input.source_ip,
        content_snippet=f"Event: {network_threat_input.event_type}, IP: {network_threat_input.source_ip}",
        confidence_score=network_threat_input.confidence_score,
        status="new",
        full_details_json=network_threat_input.model_dump(mode='json')
    )
    db.add(new_threat)
    db.commit()
    db.refresh(new_threat)
    return schemas.DetectedThreat.from_orm(new_threat)

# --- Raw Log Functions ---

def log_network_event(log_input: schemas.RawNetworkLogInput, db: Session):
    """
    Logs a raw network event into the database.
    Assumes models.NetworkLog is the correct model for raw network logs.
    """
    new_log_entry = models.NetworkLog(
        log_source=log_input.log_source,
        timestamp=log_input.timestamp,
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
    return new_log_entry

def log_raw_sms_event(raw_sms_input: schemas.RawSMSLogInput, db: Session):
    """Logs a raw SMS event into the database."""
    new_raw_sms_log = models.RawSMSLog(
        sms_id=raw_sms_input.sms_id,
        sender_number=raw_sms_input.sender_number,
        recipient_number=raw_sms_input.recipient_number,
        message_content=raw_sms_input.message_content,
        timestamp=raw_sms_input.timestamp,
        detection_status=raw_sms_input.detection_status,
        details=raw_sms_input.details
    )
    db.add(new_raw_sms_log)
    db.commit()
    db.refresh(new_raw_sms_log)
    return new_raw_sms_log

def log_raw_email_event(log_input: schemas.RawEmailLogInput, db: Session):
    """
    Logs a raw email event into the database, including attachment details.
    """
    db_log = models.RawEmailLog(
        email_id=log_input.email_id,
        sender=log_input.sender,
        recipients=log_input.recipients,
        subject=log_input.subject,
        body=log_input.body,
        received_timestamp=log_input.received_timestamp,
        detection_status=log_input.detection_status,
        details=log_input.details,
        attachment_filename=log_input.attachment_filename, # <--- NEW: Pass attachment filename
        attachment_url=log_input.attachment_url             # <--- NEW: Pass attachment URL
    )
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    return db_log

def get_threat_counts(db: Session) -> Dict[str, int]:
    """
    Returns aggregated counts of different types of threats and logs.
    """
    total_network_threats = db.query(models.DetectedThreat).filter(
        models.DetectedThreat.source_type == "network_ids"
    ).count()
    suspicious_ip_attempts = db.query(models.DetectedThreat).filter(
        models.DetectedThreat.threat_type == "suspicious_ip_attempt"
    ).count()
    brute_force_attacks = db.query(models.DetectedThreat).filter(
        models.DetectedThreat.threat_type == "brute_force_attack"
    ).count()

    total_emails_received = db.query(models.RawEmailLog).count()
    spam_emails_detected = db.query(models.RawEmailLog).filter(
        models.RawEmailLog.detection_status.ilike('%spam%')
    ).count()
    
    # Malware detections - counts both network malware and email attachment malware
    malware_detections = db.query(models.DetectedThreat).filter(
        (models.DetectedThreat.threat_type.ilike('%malware%')) |
        (models.DetectedThreat.source_type.ilike('%attachment%')) # This includes 'email_attachment'
    ).count()

    total_sms_received = db.query(models.RawSMSLog).count()
    sms_spam_detected = db.query(models.RawSMSLog).filter(
        models.RawSMSLog.detection_status.ilike('%spam%')
    ).count()

    pending_threats = db.query(models.DetectedThreat).filter(
        models.DetectedThreat.status == "pending"
    ).count()

    return {
        "total_network_threats": total_network_threats,
        "suspicious_ip_attempts": suspicious_ip_attempts,
        "brute_force_attacks": brute_force_attacks,
        "malware_detections": malware_detections,
        "pending_threats": pending_threats,
        "total_emails_received": total_emails_received,
        "spam_emails_detected": spam_emails_detected,
        "total_sms_received": total_sms_received,
        "sms_spam_detected": sms_spam_detected,
    }