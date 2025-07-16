import uuid
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
from sqlalchemy import func
import schemas, actions, models
from typing import Optional, Dict, Any
import re

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
    "192.168.56.101", # Your VM IP 1
    "192.168.56.102"  # Your VM IP 2
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

SENSITIVE_DATA_PATTERNS = [
    r"\bpassword\s*=\s*['\"]?[a-zA-Z0-9!@#$%^&*()_+-=\[\]{}|;:'\",.<>/?`~]{6,}\b",
    r"\bapi_key\s*=\s*['\"]?[a-zA-Z0-9]{20,}\b",
    r"\bcredit_card\s*=\s*\d{13,16}\b",
    r"\bsecret\s*=\s*['\"]?[a-zA-Z0-9]{10,}\b",
    r"Bearer\s+[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
    r"pk_[a-zA-Z0-9]{24}",
    r"sk_[a-zA-Z0-9]{24}",
    r"access_token=[a-zA-Z0-9-_.]+",
    r"refresh_token=[a-zA-Z0-9-_.]+",
]

UNUSUAL_STATUS_CODES = {403, 404, 500, 502, 503, 504}
LARGE_RESPONSE_THRESHOLD_BYTES = 1024 * 1024 * 5 # 5 MB
SMALL_RESPONSE_THRESHOLD_BYTES = 50 

EXCLUDED_SMALL_RESPONSE_ACTIONS = {
    "GET__RAW_EMAIL_LOGS",
    "GET__RAW_SMS_LOGS",
    "GET__THREATS_RECENT",
    "GET__THREAT_COUNTS",
    "GET__CURRENT_USER" # Often returns a small JSON object for user details
}

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
    # Only check if the action is a failed login attempt
    if raw_log_input.action != "POST__TOKEN" or raw_log_input.response_status_code != 401 or not raw_log_input.source_ip:
        return None

    time_window_start = datetime.now(timezone.utc) - timedelta(minutes=BRUTE_FORCE_TIME_WINDOW_MINUTES)

    # Count failed login attempts from this source IP within the time window
    query = db.query(models.NetworkLog).filter(
        models.NetworkLog.source_ip == raw_log_input.source_ip,
        models.NetworkLog.action == "POST__TOKEN", # Action for /token endpoint
        models.NetworkLog.response_status_code == 401, # Specifically failed logins
        models.NetworkLog.timestamp >= time_window_start
    )

    # If a username was provided in the log, filter by that too for more specific brute force
    if raw_log_input.username:
        query = query.filter(models.NetworkLog.username == raw_log_input.username)

    failed_attempts_count = query.count()

    print(f"Brute-force check for IP {raw_log_input.source_ip} (user {raw_log_input.username or 'N/A'}): {failed_attempts_count} failed attempts in last {BRUTE_FORCE_TIME_WINDOW_MINUTES} minutes.")

    if failed_attempts_count >= BRUTE_FORCE_THRESHOLD:
        return "brute_force_attack"
    
    return None

def detect_sensitive_data_leak(raw_log_input: schemas.RawNetworkLogInput) -> Optional[str]:
    """
    Checks if sensitive data patterns are present in the response body snippet.
    """
    if raw_log_input.response_body_snippet:
        for pattern in SENSITIVE_DATA_PATTERNS:
            if re.search(pattern, raw_log_input.response_body_snippet, re.IGNORECASE):
                return f"sensitive_data_leak_in_response_{pattern.replace(' ', '_').replace('.', '_')}"
    return None

def detect_unusual_response_status(raw_log_input: schemas.RawNetworkLogInput) -> Optional[str]:
    """
    Flags unusual HTTP status codes in responses.
    """
    if raw_log_input.response_status_code in UNUSUAL_STATUS_CODES:
        # Avoid flagging 401 for /token endpoint as brute force handles it
        if not (raw_log_input.action == "POST__TOKEN" and raw_log_input.response_status_code == 401):
            return f"unusual_response_status_{raw_log_input.response_status_code}"
    return None

def detect_unusual_response_size(raw_log_input: schemas.RawNetworkLogInput) -> Optional[str]:
    """
    Flags unusually large or small response content lengths.
    """
    # --- DEBUG PRINT ---
    print(f"DEBUG: Checking size for action: '{raw_log_input.action}', Is excluded: {raw_log_input.action in EXCLUDED_SMALL_RESPONSE_ACTIONS}")
    # --- END DEBUG PRINT ---

    # First, check if the action is in the exclusion list
    if raw_log_input.action in EXCLUDED_SMALL_RESPONSE_ACTIONS:
        return None # Do not flag these actions for unusually small responses

    if raw_log_input.response_content_length is not None:
        if raw_log_input.response_content_length > LARGE_RESPONSE_THRESHOLD_BYTES:
            return "unusually_large_response"
        elif raw_log_input.response_content_length < SMALL_RESPONSE_THRESHOLD_BYTES and raw_log_input.response_status_code == 200:
            # Only flag unusually small successful responses
            return "unusually_small_successful_response"
    return None

def analyze_network_event(raw_log_input: schemas.RawNetworkLogInput, db: Session):
    threat_type_list = []
    confidence_score = None
    source_identifier = raw_log_input.source_ip if raw_log_input.source_ip else "unknown_ip"
    
    susp_ip_detection = detect_suspicious_ip(raw_log_input)
    if susp_ip_detection:
        threat_type_list.append(susp_ip_detection)
        confidence_score = 0.8

    malware_sig_detection = detect_malware_signature(raw_log_input)
    if malware_sig_detection:
        threat_type_list.append(malware_sig_detection)
        confidence_score = confidence_score or 0.9

    brute_force_detection = detect_brute_force_db(raw_log_input, db)
    if brute_force_detection:
        threat_type_list.append(brute_force_detection)
        confidence_score = confidence_score or 0.95

    sensitive_data_leak_detection = detect_sensitive_data_leak(raw_log_input)
    if sensitive_data_leak_detection:
        threat_type_list.append(sensitive_data_leak_detection)
        confidence_score = confidence_score or 0.9

    unusual_status_detection = detect_unusual_response_status(raw_log_input)
    if unusual_status_detection:
        threat_type_list.append(unusual_status_detection)
        confidence_score = confidence_score or 0.7

    unusual_size_detection = detect_unusual_response_size(raw_log_input)
    if unusual_size_detection:
        threat_type_list.append(unusual_size_detection)
        confidence_score = confidence_score or 0.6

    threat_type = "_and_".join(threat_type_list) if threat_type_list else None

    if threat_type:
        threat_timestamp = raw_log_input.timestamp if raw_log_input.timestamp else datetime.now(timezone.utc)

        network_threat_input = schemas.NetworkDetectionInput(
            source_type="network_ids",
            detection_id=str(uuid.uuid4()),
            timestamp=threat_timestamp,
            event_type=threat_type,
            source_ip=raw_log_input.source_ip,
            target_ip=raw_log_input.destination_ip,
            port=str(raw_log_input.port) if raw_log_input.port else None,
            protocol=raw_log_input.protocol,
            confidence_score=confidence_score,
            details={
                "request_path": raw_log_input.event_description,
                "request_method": raw_log_input.action.split('__')[0] if raw_log_input.action and '__' in raw_log_input.action else raw_log_input.action,
                "response_status_code": raw_log_input.response_status_code,
                "response_content_length": raw_log_input.response_content_length,
                "response_body_snippet": raw_log_input.response_body_snippet,
                "triggered_rules": threat_type,
                "username_attempted": raw_log_input.username,
                "brute_force_details": {
                    "time_window_minutes": BRUTE_FORCE_TIME_WINDOW_MINUTES,
                    "threshold": BRUTE_FORCE_THRESHOLD,
                    "failed_attempts_in_window": db.query(models.NetworkLog).filter(
                        models.NetworkLog.source_ip == raw_log_input.source_ip,
                        models.NetworkLog.action == "POST__TOKEN",
                        models.NetworkLog.response_status_code == 401,
                        models.NetworkLog.timestamp >= datetime.now(timezone.utc) - timedelta(minutes=BRUTE_FORCE_TIME_WINDOW_MINUTES)
                    ).count() if raw_log_input.source_ip else 0
                } if "brute_force_attack" in threat_type_list else {}
            }
        )
        
        detected_threat_record = actions.detected_network_threat(network_threat_input, db)
        print(f"!!! ALERT !!! Detected Network Threat: {detected_threat_record.threat_type} from {detected_threat_record.source_identifier} (Severity: {detected_threat_record.severity})")
        return detected_threat_record
    
    print(f"Network event processed: No threat detected for {raw_log_input.source_ip or 'unknown IP'} on {raw_log_input.event_description}.")
    return None