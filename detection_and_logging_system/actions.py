import uuid
from sqlalchemy.orm import Session
import database, schemas, models
from typing import Optional

def get_threat_severity(threat_type: str, confidence_score: Optional[float]) -> str:
    if threat_type in ["phishing", "fraudulent", "brute_force_attempt", "malware_signature"]:
        if confidence_score is not None and confidence_score >= 0.8:
            return "critical"
        return "high"
    elif threat_type in ["scam", "suspicious_ip"]:
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
    new_threat = models.DetectedThreat(
        id=generate_id(),
        detection_id=email_threat_input.detection_id,
        timestamp=email_threat_input.timestamp,
        source_type=email_threat_input.source_type,
        threat_type=email_threat_input.detection_type,
        severity=get_threat_severity(email_threat_input.detection_type, email_threat_input.confidence_score),
        source_identifier=email_threat_input.sender,
        content_snippet=email_threat_input.subject,
        confidence_score=email_threat_input.confidence_score,
        status="new",
        full_details_json=email_threat_input.model_dump(mode='json')
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
        source_identifier=network_threat_input.source_ip,
        content_snippet=f"Event: {network_threat_input.event_type}, IP: {network_threat_input.source_ip}", 

        status="new",
        full_details_json=network_threat_input.model_dump(mode='json')
    )
    db.add(new_threat)
    db.commit()
    db.refresh(new_threat)
    return schemas.DetectedThreat.from_orm(new_threat)

def log_network_event(log_input: schemas.RawNetworkLogInput, db: Session):
    new_log_entry = models.NetworkEventLog(
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
    return log_input