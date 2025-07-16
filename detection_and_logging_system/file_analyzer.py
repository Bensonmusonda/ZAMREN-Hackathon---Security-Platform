# detection_and_logging_system/file_analyzer.py

import os
import hashlib # <--- Ensure this is imported
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from datetime import datetime, timezone

import schemas, actions, models # Import necessary modules

# Define malware signatures specific to file content
# These are examples; in a real system, this would be a dynamic, regularly updated list
FILE_MALWARE_SIGNATURES = [
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", # EICAR test string
    "malicious_script.js",
    "virus_payload.exe",
    "backdoor.php",
    "exploit.doc",
    "ransomware_note.txt",
    "eval(base64_decode(", # Common in obfuscated web shells/scripts
    "cmd.exe /c",
    "powershell -nop -w hidden -e",
    "Invoke-Expression", # PowerShell command
    "msfvenom", # Metasploit payload indicator
    "shellcode",
    "obfuscated_code", # Generic indicator for suspicious obfuscation
    "<?php passthru(", # PHP web shell common function
    "python -c 'import socket; socket.socket", # Simple reverse shell pattern
    "wget http://malicious.com/payload",
    "curl -o /tmp/evil",
    "nc -e /bin/sh", # Netcat reverse shell
    "meterpreter", # Metasploit meterpreter
]

def scan_file_for_malware(
    file_path: str,
    email_id: str,
    sender: str,
    subject: str,
    db: Session
) -> str:
    """
    Scans the content of a file for known malware signatures.
    If a signature is found, logs a DetectedThreat via actions.detected_email_threat.

    Args:
        file_path (str): The full path to the file on the server.
        email_id (str): The ID of the associated email.
        sender (str): The sender of the associated email.
        subject (str): The subject of the associated email.
        db (Session): Database session.

    Returns:
        str: "malicious_attachment" if malware is found, "clean_attachment" otherwise,
             or "scan_error_attachment" if an error occurs during reading.
    """
    print(f"Scanning file for malware: {file_path}")
    if not os.path.exists(file_path):
        print(f"File not found for scanning: {file_path}. Assuming clean for logging purposes.")
        # Log a threat if file is expected but not found, or handle as a non-issue based on design
        return "clean_attachment" 

    try:
        with open(file_path, 'rb') as f:
            file_content_bytes = f.read()
        
        # Attempt to decode for string search, ignoring errors for binary files
        try:
            file_content_str = file_content_bytes.decode('utf-8', errors='ignore')
        except UnicodeDecodeError:
            file_content_str = file_content_bytes.decode('latin-1', errors='ignore') # Fallback
            
    except Exception as e:
        print(f"Error reading file {file_path} for scanning: {e}")
        return "scan_error_attachment"

    detected_signature = None
    for signature in FILE_MALWARE_SIGNATURES:
        if signature.lower() in file_content_str.lower():
            detected_signature = signature
            break

    if detected_signature:
        threat_type = "malware_attachment"
        severity = "high" # Malware usually high severity
        confidence_score = 0.95 # High confidence for signature match
        
        # Create a snippet for the dashboard/details
        content_snippet_for_threat = file_content_str[:200] + "..." if len(file_content_str) > 200 else file_content_str

        threat_details = {
            "file_path": file_path,
            "detected_signature": detected_signature,
            "email_id": email_id,
            "sender": sender,
            "subject": subject,
            "file_content_hash_sha256": hashlib.sha256(file_content_bytes).hexdigest(),
            "scan_source": "internal_file_analyzer"
        }

        # Construct the EmailDetectionInput schema
        threat_input = schemas.EmailDetectionInput(
            timestamp=datetime.now(timezone.utc),
            email_id=email_id,
            sender=sender,
            subject=subject,
            detection_type=threat_type, # e.g., "malware_attachment"
            confidence_score=confidence_score,
            source_type="email_attachment", # Crucial for frontend categorization
            details=threat_details
        )
        
        # <--- CORRECTED CALL HERE ---
        created_threat = actions.detected_email_threat(email_threat_input=threat_input, db=db)
        # ---------------------------

        print(f"!!! ATTACHMENT MALWARE ALERT !!! Detected: {threat_type} (Signature: '{detected_signature}') in {file_path}. Threat ID: {created_threat.id}")
        return "malicious_attachment"
    else:
        print(f"No malware signatures found in {file_path}")
        return "clean_attachment"