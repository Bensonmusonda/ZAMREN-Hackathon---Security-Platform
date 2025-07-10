import uuid
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
from sqlalchemy import func
import schemas, actions, models
from typing import Optional, Dict, Any

BRUTE_FORCE_TIME_WINDOW_MINUTES = 5
BRUTE_FORCE_THRESHOLD = 5 

SUSPICIOUS_IPS = {
    "1.2.3.4",
    "203.0.113.10",
    "8.8.8.8",
    "192.0.2.1",
    "198.51.100.25",
    "203.0.113.50",
    "10.0.0.10",
    "172.16.0.1",
    "192.168.0.100",
    "100.64.0.1",
    "169.254.0.5", 
    "192.88.99.1", 
    "198.18.0.1",
    "224.0.0.1", 
}

MALWARE_SIGNATURES = [
    "evil.exe",
    "powershell -encodedcommand",
    "nc -lvp", 
    "rm -rf /", 
    "beacon.c2.com", 
    "trojan.downloader", 
    "mimikatz",
    "psexec.exe", 
    "rundll32.exe", 
    "mshta.exe", 
    "certutil -urlcache -f",
    "bitsadmin /transfer",
    "wscript.exe", 
    "macro_enabled.docm",
    "shell.php",
    "base64 --decode"
]

def detect_suspicious_ip(raw_log_input: schemas.RawNetworkLogInput) -> Optional[str]:
    if raw_log_input.source_ip and raw_log_input.source_ip in SUSPICIOUS_IPS:
        return "suspicious_ip_source"
    if raw_log_input.destination_ip and raw_log_input.destination_ip in SUSPICIOUS_IPS:
        return "suspicious_ip_destination"
    return None

def detect_malware_signature(raw_log_input: schemas.RawNetworkLogInput) -> Optional[str]:
    log_content = raw_log_input.event_description.lower()
    if raw_log_input.details:
        log_content += str(raw_log_input.details).lower()

    for signature in MALWARE_SIGNATURES:
        if signature.lower() in log_content:
            return f"malware_signature_{signature.replace(' ', '_').replace('.', '_')}"
    return None

def detect_brute_force_db(raw_log_input: schemas.RawNetworkLogInput, db: Session) -> Optional[str]:
    if raw_log_input.action != "LOGIN_DENIED" or not raw_log_input.source_ip:
        return None

    time_window_start = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=BRUTE_FORCE_TIME_WINDOW_MINUTES)

    query = db.query(models.NetworkEventLog).filter(
        models.NetworkEventLog.source_ip == raw_log_input.source_ip,
        models.NetworkEventLog.action == "LOGIN_DENIED",
        models.NetworkEventLog.timestamp >= time_window_start
    )

    if raw_log_input.username:
        query = query.filter(models.NetworkEventLog.username == raw_log_input.username)

    failed_attempts_count = query.count()

    print(f"Brute-force check for IP {raw_log_input.source_ip} (user {raw_log_input.username or 'N/A'}): {failed_attempts_count} failed attempts in last {BRUTE_FORCE_TIME_WINDOW_MINUTES} minutes.")

    if failed_attempts_count >= BRUTE_FORCE_THRESHOLD:
        return "brute_force_attack"
    
    return None


def analyze_network_event(raw_log_input: schemas.RawNetworkLogInput, db: Session):
    threat_type = None
    confidence_score = None
    source_identifier = raw_log_input.source_ip if raw_log_input.source_ip else "unknown_ip"


    susp_ip_detection = detect_suspicious_ip(raw_log_input)
    if susp_ip_detection:
        threat_type = susp_ip_detection
        confidence_score = 0.8

    malware_sig_detection = detect_malware_signature(raw_log_input)
    if malware_sig_detection:
        if not threat_type:
            threat_type = malware_sig_detection
        else:
            threat_type += f"_{malware_sig_detection}"
        confidence_score = confidence_score or 0.9

    brute_force_detection = detect_brute_force_db(raw_log_input, db)
    if brute_force_detection:
        if not threat_type:
            threat_type = brute_force_detection
        else:
            threat_type += f"_{brute_force_detection}"
        confidence_score = confidence_score or 0.95

    if threat_type:
        threat_timestamp = raw_log_input.timestamp if raw_log_input.timestamp else datetime.now()

        network_threat_input = schemas.NetworkDetectionInput(
            source_type="network_ids",
            detection_id=str(uuid.uuid4()),
            timestamp=threat_timestamp,
            email_id="", sender="", subject="",
            sms_id="", sender_number="", message_content="",
            event_type=threat_type,
            source_ip=raw_log_input.source_ip,
            target_ip=raw_log_input.destination_ip,
            port=str(raw_log_input.port) if raw_log_input.port else None,
            protocol=raw_log_input.protocol,
            detection_type=threat_type,
            confidence_score=confidence_score,
            details={
                "raw_log_id": raw_log_input.id if hasattr(raw_log_input, 'id') else "N/A",
                "raw_log_event_description": raw_log_input.event_description,
                "triggered_rules": threat_type,
                "brute_force_details": {
                    "time_window_minutes": BRUTE_FORCE_TIME_WINDOW_MINUTES,
                    "threshold": BRUTE_FORCE_THRESHOLD,
                    "failed_attempts_in_window": db.query(models.NetworkEventLog).filter(
                        models.NetworkEventLog.source_ip == raw_log_input.source_ip,
                        models.NetworkEventLog.action == "failed_login",
                        models.NetworkEventLog.timestamp >= datetime.now() - timedelta(minutes=BRUTE_FORCE_TIME_WINDOW_MINUTES)
                    ).count() if raw_log_input.source_ip else 0 # Re-query count for details
                } if brute_force_detection else {}
            }
        )
        
        detected_threat_record = actions.detected_network_threat(network_threat_input, db)
        print(f"!!! ALERT !!! Detected Network Threat: {detected_threat_record.threat_type} from {detected_threat_record.source_identifier} (Severity: {detected_threat_record.severity})")
        return detected_threat_record
    
    print(f"Network event processed: No threat detected for {raw_log_input.source_ip or 'unknown IP'}.")
    return None