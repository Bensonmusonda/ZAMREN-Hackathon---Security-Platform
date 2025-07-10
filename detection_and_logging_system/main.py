from fastapi import FastAPI, Depends 
from sqlalchemy.orm import Session
import database, models, schemas, actions, network_analyzer
from fastapi.middleware.cors import CORSMiddleware

models.Base.metadata.create_all(bind=database.engine)

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

app = FastAPI()

# Configure CORS
origins = [
    "http://localhost",
    "http://localhost:5500",  # Allow requests from your frontend development server
    # You can add other origins here if your frontend is served from elsewhere (e.g., a deployed URL)
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],  # Allows all HTTP methods (GET, POST, PUT, DELETE, etc.)
    allow_headers=["*"],  # Allows all headers
)


@app.get("/")
def read_root():
    return {"message": "Detection and Logging system is operational"}

@app.post("/ingest/sms-threat", response_model=schemas.DetectedThreat) # Added response_model
def ingest_sms_threat(sms_threat_input: schemas.SMSDetectionInput, db: Session = Depends(get_db)):
    return actions.detected_sms_threat(sms_threat_input, db)

@app.post("/ingest/email-threat", response_model=schemas.DetectedThreat)
def ingest_email_threat(email_threat_input: schemas.EmailDetectionInput, db: Session = Depends(get_db)):
    """
    Ingests an email threat and logs it in both DetectedThreats and RawEmailLogs.
    """
    # 1. Log the raw email event based on the threat input
    # Note: 'recipient' and 'body_snippet' are not in EmailDetectionInput,
    # so they will be set to None in the raw log.
    raw_email_log_input = schemas.RawEmailLogInput(
        email_id=email_threat_input.email_id,
        sender=email_threat_input.sender,
        recipient=None, # Not available in EmailDetectionInput
        subject=email_threat_input.subject,
        body_snippet=None, # Not available in EmailDetectionInput
        received_timestamp=email_threat_input.timestamp,
        detection_status=email_threat_input.detection_type, # Use the threat type as the raw log's detection status
        details=email_threat_input.details # Use the threat details for the raw log's details
    )
    actions.log_raw_email_event(raw_email_log_input, db) # <-- NEW LINE: Call to log raw email

    # 2. Proceed to log the detected threat as before
    return actions.detected_email_threat(email_threat_input, db)

@app.post("/ingest/network-threat", response_model=schemas.DetectedThreat) # Added endpoint and response_model
def ingest_network_threat(network_threat_input: schemas.NetworkDetectionInput, db: Session = Depends(get_db)):
    return actions.detected_network_threat(network_threat_input, db)

@app.get("/threats/recent", response_model=list[schemas.DetectedThreat])
def get_recent_threats(db: Session = Depends(get_db), limit: int = 10):
    threats = db.query(models.DetectedThreat).order_by(models.DetectedThreat.timestamp.desc()).limit(limit).all()
    return [schemas.DetectedThreat.from_orm(threat) for threat in threats]

# main.py additions

@app.get("/network-threats", response_model=list[schemas.DetectedThreat])
def get_network_threats(db: Session = Depends(get_db), limit: int = 100):
    """
    Returns a list of all detected network threats.
    """
    threats = db.query(models.DetectedThreat).filter(
        models.DetectedThreat.source_type == "network_ids"
    ).order_by(models.DetectedThreat.timestamp.desc()).limit(limit).all()
    return [schemas.DetectedThreat.from_orm(threat) for threat in threats]

@app.get("/raw-sms-logs", response_model=list[schemas.RawSMSLog]) # <-- CHANGE THIS LINE
def get_raw_sms_logs(db: Session = Depends(get_db), limit: int = 100):
    """
    Returns a list of raw SMS logs.
    """
    logs = db.query(models.RawSMSLog).order_by(models.RawSMSLog.timestamp.desc()).limit(limit).all()
    # CHANGE THIS LINE as well to use RawSMSLog for conversion
    return [schemas.RawSMSLog.from_orm(log) for log in logs]

@app.get("/raw-email-logs", response_model=list[schemas.RawEmailLog])
def get_raw_email_logs(db: Session = Depends(get_db), limit: int = 100):
    """
    Returns a list of raw email logs.
    """
    logs = db.query(models.RawEmailLog).order_by(models.RawEmailLog.received_timestamp.desc()).limit(limit).all()
    return [schemas.RawEmailLog.from_orm(log) for log in logs]


@app.get("/threat-counts")
def get_threat_counts(db: Session = Depends(get_db)):
    """
    Returns aggregated counts for various threat types.
    """
    # THIS IS THE CHANGE: Now call the function from the 'actions' module
    return actions.get_threat_counts(db)


@app.post("/ingest/raw-network-log")
def ingest_raw_network_log(log_input: schemas.RawNetworkLogInput, db: Session = Depends(get_db)):

    logged_raw_event = actions.log_network_event(log_input, db)

    detected_threat = network_analyzer.analyze_network_event(log_input, db)

    if detected_threat:
        return {"message": "Raw network event logged and threat detected", "raw_log": logged_raw_event.model_dump(), "detected_threat": detected_threat.model_dump()}
    else:
        return {"message": "Raw network event logged, no threat detected", "raw_log": logged_raw_event.model_dump()}


@app.post("/ingest/raw-sms-log", response_model=schemas.RawSMSLog) # Changed response model to RawSMSLog for consistency
def ingest_raw_sms_log(log_input: schemas.RawSMSLogInput, db: Session = Depends(get_db)):
    """
    Ingests a raw SMS log event into the database.
    """
    logged_raw_event = actions.log_raw_sms_event(log_input, db)
    return logged_raw_event

@app.post("/ingest/raw-email-log", response_model=schemas.RawEmailLog)
def ingest_raw_email_log(log_input: schemas.RawEmailLogInput, db: Session = Depends(get_db)):
    """
    Ingests a raw email log event into the database.
    """
    db_log = models.RawEmailLog(**log_input.model_dump()) # Use model_dump() for Pydantic v2
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    return db_log