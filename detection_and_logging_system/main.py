import os
import shutil
from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from sqlalchemy import func
from sqlalchemy.dialects import postgresql
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from typing import List, Optional, Annotated, Dict, Any
from uuid import uuid4

import database, models, schemas
import actions, network_analyzer
import file_analyzer
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import StreamingResponse

models.Base.metadata.create_all(bind=database.engine)

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

app = FastAPI(title="Main IDS & User Portal", version="1.0.0")

origins = [
    "http://localhost",
    "http://localhost:5500",
    "http://localhost:5501",
    "http://127.0.0.1:5500",
    "http://localhost:3000",
    "http://localhost:8080",
    "http://localhost:8000",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:8000",
    "http://192.168.56.1:5501", # Your host's frontend access point from VM
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = datetime.now(timezone.utc)
        
        client_ip = request.client.host if request.client else "unknown"
        request_method = request.method
        request_path = request.url.path
        request_query_params = str(request.url.query)
        
        response = await call_next(request)

        end_time = datetime.now(timezone.utc)
        
        response_status_code = response.status_code
        response_content_length = response.headers.get("content-length")
        
        response_body_snippet = None
        if "content-type" in response.headers and "text" in response.headers["content-type"].lower():
            try:
                response_body_bytes = b""
                async for chunk in response.body_iterator:
                    response_body_bytes += chunk
                
                response_body_snippet = response_body_bytes.decode('utf-8', errors='ignore')[:500]
                
                response = Response(content=response_body_bytes, media_type=response.media_type, status_code=response.status_code, headers=dict(response.headers))
            except Exception as e:
                print(f"Error reading response body in middleware: {e}")
                response_body_snippet = "Error reading response body."
        
        # --- MODIFIED: Action string generation ---
        # Clean the path: remove leading/trailing slashes, replace slashes and hyphens with underscores, convert to uppercase.
        cleaned_path = request_path.strip('/').replace('/', '_').replace('-', '_').upper()
        action = f"{request_method}_{cleaned_path}" if cleaned_path else request_method # Handle root path
        # --- END MODIFIED ---

        network_log_input = schemas.RawNetworkLogInput(
            log_source="fastapi_middleware",
            timestamp=start_time,
            event_description=f"Request: {request_method} {request_path} | Response Status: {response_status_code}",
            source_ip=client_ip,
            destination_ip=request.url.hostname,
            protocol=request.url.scheme.upper(),
            port=request.url.port,
            action=action, # Use the correctly formatted action
            username=None,
            details={
                "request_headers": dict(request.headers),
                "request_query_params": request_query_params,
                "response_headers": dict(response.headers),
                "response_time_ms": (end_time - start_time).total_seconds() * 1000,
            },
            response_status_code=response_status_code,
            response_content_length=int(response_content_length) if response_content_length else None,
            response_body_snippet=response_body_snippet
        )

        db = next(get_db())
        try:
            actions.log_network_event(network_log_input, db)
            network_analyzer.analyze_network_event(network_log_input, db)
        finally:
            db.close()

        return response

app.add_middleware(LoggingMiddleware)

UPLOAD_DIRECTORY = "uploaded_attachments"
os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)

app.mount("/attachments", StaticFiles(directory=UPLOAD_DIRECTORY), name="attachments")

SECRET_KEY = "your_super_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user_from_db(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        phone: Optional[str] = payload.get("phone")

        if email is None:
            raise credentials_exception
        token_data = schemas.TokenData(email=email, phone=phone)
    except JWTError:
        raise credentials_exception

    user = get_user_from_db(db, email=token_data.email)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: Annotated[models.User, Depends(get_current_user)]):
    if not current_user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    return current_user

@app.post("/register", response_model=schemas.UserOut, status_code=status.HTTP_201_CREATED)
async def register_user(user_create: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == user_create.email).first()
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already registered"
        )
    if user_create.phone:
        db_phone_user = db.query(models.User).filter(models.User.phone == user_create.phone).first()
        if db_phone_user:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Phone number already registered")

    hashed_password = get_password_hash(user_create.password)
    db_user = models.User(
        email=user_create.email,
        phone=user_create.phone,
        first_name=user_create.first_name,
        last_name=user_create.last_name,
        hashed_password=hashed_password,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/token", response_model=schemas.Token)
async def login_for_access_token(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = get_user_from_db(db, email=form_data.username)
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(
        data={"sub": user.email, "phone": user.phone}
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/current_user", response_model=schemas.UserOut)
async def read_users_me(current_user: Annotated[models.User, Depends(get_current_active_user)]):
    return current_user

@app.post("/ingest/raw-email-log", response_model=schemas.RawEmailLog, summary="Ingest raw email log from manager and scan attachments")
async def ingest_raw_email_log(
    email_log_input: schemas.RawEmailLogInput,
    db: Session = Depends(get_db)
):
    print(f"Ingesting raw email log: ID={email_log_input.email_id}, Sender={email_log_input.sender}")

    if not email_log_input.email_id:
        email_log_input.email_id = str(uuid4())

    raw_email_log_db = actions.log_raw_email_event(email_log_input, db)
    print(f"Raw email log stored in DB: ID={raw_email_log_db.email_id}")

    if raw_email_log_db.attachment_url:
        print(f"Attachment URL found: {raw_email_log_db.attachment_url}")
        attachment_filename_from_url = os.path.basename(raw_email_log_db.attachment_url)
        local_attachment_path = os.path.join(UPLOAD_DIRECTORY, attachment_filename_from_url)

        scan_result = file_analyzer.scan_file_for_malware(
            file_path=local_attachment_path,
            email_id=raw_email_log_db.email_id,
            sender=raw_email_log_db.sender,
            subject=raw_email_log_db.subject or "No Subject",
            db=db
        )
        print(f"Attachment scan result for {raw_email_log_db.email_id}: {scan_result}")

        if scan_result == "malicious_attachment":
            if raw_email_log_db.detection_status and raw_email_log_db.detection_status.lower() == "spam":
                raw_email_log_db.detection_status = "spam_and_malicious_attachment"
            else:
                raw_email_log_db.detection_status = "malicious_attachment"
            
            db.add(raw_email_log_db)
            db.commit()
            db.refresh(raw_email_log_db)
            print(f"Updated email log {raw_email_log_db.email_id} detection_status to: {raw_email_log_db.detection_status}")
        elif scan_result == "scan_error_attachment":
             if raw_email_log_db.detection_status and raw_email_log_db.detection_status.lower() == "spam":
                raw_email_log_db.detection_status = "spam_with_attachment_scan_error"
             else:
                raw_email_log_db.detection_status = "attachment_scan_error"
             db.add(raw_email_log_db)
             db.commit()
             db.refresh(raw_email_log_db)
    
    return schemas.RawEmailLog.from_orm(raw_email_log_db)


@app.post("/ingest/raw-sms-log", response_model=schemas.RawSMSLog, summary="Ingest raw SMS log from manager")
async def ingest_raw_sms_log(
    sms_log: schemas.RawSMSLogInput,
    db: Session = Depends(get_db)
):
    if not sms_log.sms_id:
        sms_log.sms_id = str(uuid4())
    db_sms_log = actions.log_raw_sms_event(sms_log, db)
    return schemas.RawSMSLog.from_orm(db_sms_log)

@app.post("/ingest/network-log", response_model=Dict[str, Any], summary="Ingest raw network log from manager")
async def ingest_network_log(
    network_log: schemas.RawNetworkLogInput,
    db: Session = Depends(get_db)
):
    if not network_log.event_description:
        network_log.event_description = f"Network event - {uuid4()}"

    logged_event_orm = actions.log_network_event(network_log, db)
    logged_event_schema = schemas.RawNetworkLogInput.model_validate(logged_event_orm)

    detected_threat_orm = network_analyzer.analyze_network_event(network_log, db)
    
    response_content = {"raw_log": logged_event_schema.model_dump()}
    if detected_threat_orm:
        response_content["message"] = "Raw network event logged and threat detected"
        response_content["detected_threat"] = schemas.DetectedThreat.from_orm(detected_threat_orm).model_dump()
    else:
        response_content["message"] = "Raw network event logged, no threat detected"
    
    return response_content


@app.post("/ingest/email-threat", response_model=schemas.DetectedThreat, summary="Ingest email threat detection")
async def ingest_email_threat(
    threat: schemas.EmailDetectionInput,
    db: Session = Depends(get_db)
):
    detected_threat_orm = actions.detected_email_threat(threat, db)
    return schemas.DetectedThreat.from_orm(detected_threat_orm)


@app.post("/ingest/sms-threat", response_model=schemas.DetectedThreat, summary="Ingest SMS threat detection")
async def ingest_sms_threat(
    threat: schemas.SMSDetectionInput,
    db: Session = Depends(get_db)
):
    detected_threat_orm = actions.detected_sms_threat(threat, db)
    return schemas.DetectedThreat.from_orm(detected_threat_orm)


@app.post("/ingest/network-threat", response_model=schemas.DetectedThreat, summary="Ingest network threat detection")
async def ingest_network_threat(
    threat: schemas.NetworkDetectionInput,
    db: Session = Depends(get_db)
):
    detected_threat_orm = actions.detected_network_threat(threat, db)
    return schemas.DetectedThreat.from_orm(detected_threat_orm)

@app.post("/upload/attachment", summary="Upload an attachment and get its URL")
async def upload_attachment(
    file: UploadFile = File(...),
):
    """
    Receives a file, saves it to the server, and returns its public URL.
    This endpoint is intended to be called by other internal services (e.g., Email Manager).
    """
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No file name provided."
        )

    filename = os.path.basename(file.filename)
    unique_id = uuid4().hex[:8]
    unique_filename = f"{unique_id}_{filename}"
    file_path = os.path.join(UPLOAD_DIRECTORY, unique_filename)

    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not save file: {e}"
        )

    file_url = app.url_path_for("attachments", path=unique_filename)
    
    return JSONResponse(content={"file_url": file_url, "filename": unique_filename})

@app.get("/user/emails/inbox", response_model=List[schemas.RawEmailLog], summary="Get emails received by current user")
async def get_user_inbox_emails(
    current_user: Annotated[models.User, Depends(get_current_active_user)],
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100,
    include_spam: bool = True
):
    user_email = current_user.email

    search_jsonb_array = func.jsonb_build_array(user_email).cast(postgresql.JSONB)

    query = db.query(models.RawEmailLog).filter(
        models.RawEmailLog.recipients.op('@>')(search_jsonb_array)
    )

    if not include_spam:
        query = query.filter(
            models.RawEmailLog.detection_status != "spam",
            models.RawEmailLog.detection_status != "spam_and_malicious_attachment"
        )

    emails = query.order_by(models.RawEmailLog.received_timestamp.desc()).offset(skip).limit(limit).all()
    return emails


@app.get("/raw-sms-logs", response_model=List[schemas.RawSMSLog])
async def get_raw_sms_logs(db: Session = Depends(get_db), skip: int = 0, limit: int = 100):
    logs = db.query(models.RawSMSLog).order_by(models.RawSMSLog.timestamp.desc()).offset(skip).limit(limit).all()
    return logs

@app.get("/raw-email-logs", response_model=List[schemas.RawEmailLog])
async def get_raw_email_logs(db: Session = Depends(get_db), skip: int = 0, limit: int = 100):
    """
    Retrieves a list of recent raw email logs (for dashboard).
    """
    logs = db.query(models.RawEmailLog).order_by(models.RawEmailLog.received_timestamp.desc()).offset(skip).limit(limit).all()
    return logs

@app.get("/threats/recent", response_model=List[schemas.DetectedThreat])
async def get_recent_threats(db: Session = Depends(get_db), skip: int = 0, limit: int = 10):
    """
    Retrieves a list of recent detected threats, ordered by timestamp (for dashboard).
    """
    threats = db.query(models.DetectedThreat).order_by(models.DetectedThreat.timestamp.desc()).offset(skip).limit(limit).all()
    return threats

@app.get("/network-threats", response_model=List[schemas.DetectedThreat])
async def get_network_threats(db: Session = Depends(get_db), skip: int = 0, limit: int = 100):
    threats = db.query(models.DetectedThreat).filter(
        models.DetectedThreat.source_type == "network_ids"
    ).order_by(models.DetectedThreat.timestamp.desc()).offset(skip).limit(limit).all()
    return threats

@app.get("/threat-counts")
async def get_threat_counts(db: Session = Depends(get_db)):
    """
    Get aggregated threat counts for the dashboard.
    This endpoint calls actions.get_threat_counts.
    """
    return actions.get_threat_counts(db)

@app.get("/user/emails/sent", response_model=List[schemas.RawEmailLog], summary="Get emails sent by current user")
async def get_user_sent_emails(
    current_user: Annotated[models.User, Depends(get_current_active_user)],
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100
):
    user_email = current_user.email
    emails = db.query(models.RawEmailLog).filter(
        models.RawEmailLog.sender == user_email
    ).order_by(models.RawEmailLog.received_timestamp.desc()).offset(skip).limit(limit).all()
    return emails

@app.get("/user/sms/sent", response_model=List[schemas.RawSMSLog], summary="Get SMS messages sent by current user")
async def get_user_sent_sms(
    current_user: Annotated[models.User, Depends(get_current_active_user)],
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100
):
    user_phone = current_user.phone
    logs = db.query(models.RawSMSLog).filter(
        models.RawSMSLog.recipient_number == user_phone,
    ).order_by(models.RawSMSLog.timestamp.desc()).offset(skip).limit(limit).all()
    return logs

@app.get("/user/emails/spam", response_model=List[schemas.RawEmailLog], summary="Get emails classified as spam for current user")
async def get_user_spam_emails(
    current_user: Annotated[models.User, Depends(get_current_active_user)],
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100
):
    user_email = current_user.email
    
    search_jsonb_array = func.jsonb_build_array(user_email).cast(postgresql.JSONB)

    emails = db.query(models.RawEmailLog).filter(
        models.RawEmailLog.recipients.op('@>')(search_jsonb_array),
        (models.RawEmailLog.detection_status == "spam") |
        (models.RawEmailLog.detection_status == "spam_and_malicious_attachment")
    ).order_by(models.RawEmailLog.received_timestamp.desc()).offset(skip).limit(limit).all()
    
    return emails

@app.get("/user/sms/spam", response_model=List[schemas.RawSMSLog], summary="Get SMS messages classified as spam for current user")
async def get_user_spam_sms(
    current_user: Annotated[models.User, Depends(get_current_active_user)],
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100
):
    user_phone = current_user.phone
    logs = db.query(models.RawSMSLog).filter(
        models.RawSMSLog.recipient_number == user_phone,
        models.RawSMSLog.detection_status == "spam"
    ).order_by(models.RawSMSLog.timestamp.desc()).offset(skip).limit(limit).all()
    return logs