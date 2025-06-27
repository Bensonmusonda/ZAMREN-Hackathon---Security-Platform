from fastapi import FastAPI, Depends 
from sqlalchemy.orm import Session
import database, models, schemas, actions, network_analyzer

models.Base.metadata.create_all(bind=database.engine)

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Detection and Logging system is operational"}

@app.post("/ingest/sms-threat", response_model=schemas.DetectedThreat) # Added response_model
def ingest_sms_threat(sms_threat_input: schemas.SMSDetectionInput, db: Session = Depends(get_db)):
    return actions.detected_sms_threat(sms_threat_input, db)

@app.post("/ingest/email-threat", response_model=schemas.DetectedThreat) # Added endpoint and response_model
def ingest_email_threat(email_threat_input: schemas.EmailDetectionInput, db: Session = Depends(get_db)):
    return actions.detected_email_threat(email_threat_input, db)

@app.post("/ingest/network-threat", response_model=schemas.DetectedThreat) # Added endpoint and response_model
def ingest_network_threat(network_threat_input: schemas.NetworkDetectionInput, db: Session = Depends(get_db)):
    return actions.detected_network_threat(network_threat_input, db)

@app.get("/threats/recent", response_model=list[schemas.DetectedThreat])
def get_recent_threats(db: Session = Depends(get_db), limit: int = 10):
    threats = db.query(models.DetectedThreat).order_by(models.DetectedThreat.timestamp.desc()).limit(limit).all()
    return [schemas.DetectedThreat.from_orm(threat) for threat in threats]


@app.post("/ingest/raw-network-log")
def ingest_raw_network_log(log_input: schemas.RawNetworkLogInput, db: Session = Depends(get_db)):

    logged_raw_event = actions.log_network_event(log_input, db)

    detected_threat = network_analyzer.analyze_network_event(log_input, db)

    if detected_threat:
        return {"message": "Raw network event logged and threat detected", "raw_log": logged_raw_event.model_dump(), "detected_threat": detected_threat.model_dump()}
    else:
        return {"message": "Raw network event logged, no threat detected", "raw_log": logged_raw_event.model_dump()}