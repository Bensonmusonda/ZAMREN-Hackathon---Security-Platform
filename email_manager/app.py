import json
import uuid
from datetime import datetime, timezone
import httpx

import os
import hashlib
import shutil # Still needed for copying the UploadFile stream to a new stream for httpx

from fastapi import FastAPI, Request, Form, File, UploadFile, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
import numpy as np
from typing import Optional, List, Dict, Any
import io # Added for BytesIO to handle file stream

from enhanced_classifier import EnhancedRandomForestClassifier
from data_processor_v2 import DataProcessorV2

# --- Configuration ---
# IMPORTANT: Update this URL to where your main Detection and Logging System is running
# Using environment variable for robustness, default to localhost:8000
MAIN_IDS_BASE_URL = os.getenv("MAIN_IDS_BASE_URL", "http://localhost:8000")
# --------------------

# Email Manager doesn't need a temp upload dir if it's not scanning locally
# EMAIL_MANAGER_TEMP_UPLOAD_DIR = "email_manager_temp_uploads"
# os.makedirs(EMAIL_MANAGER_TEMP_UPLOAD_DIR, exist_ok=True) # REMOVED

app = FastAPI(title="Email Spam Classification System", version="1.0.0")

origins = [
    "http://localhost",
    "http://localhost:5500",  # Allow requests from your frontend development server
    "http://localhost:5501",
    "http://192.168.56.1:5501"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Templates
templates = Jinja2Templates(directory="templates")

# Initialize components
classifier = EnhancedRandomForestClassifier()
data_processor = DataProcessorV2()

# Global state
dataset_loaded = False
models_trained = False
processed_data = None
training_results = {}

# Async HTTP client for sending data to Main IDS
http_client = httpx.AsyncClient()


# Startup function to load dataset and train models
@app.on_event("startup")
async def startup_tasks():
    """Load dataset and train models on startup"""
    global dataset_loaded, models_trained, processed_data, training_results
    
    try:
        print("🚀 Starting up Email Spam Classifier...")
        
        # Load dataset
        if os.path.exists("mail_data.csv"):
            print("📊 Loading dataset...")
            data = pd.read_csv("mail_data.csv")
            processed_data = data_processor.process_data(data)
            dataset_loaded = True
            print(f"✅ Dataset loaded: {len(data)} emails")
            
            # Train enhanced Random Forest model
            print("🧠 Training Enhanced Random Forest for spam detection...")
            results = classifier.train_model(processed_data)
            
            training_results = {"Enhanced Random Forest": results, "Random Forest": results}
            models_trained = True
            print(f"✅ Enhanced Random Forest trained successfully!")
            print(f"🏆 F1 Score: {results['f1_score']:.3f}")
            print(f"🎯 Precision: {results['precision']:.3f} | Recall: {results['recall']:.3f}")
            print("🛡️ System ready for enhanced spam detection!")
            
        else:
            print("⚠️ Dataset file 'mail_data.csv' not found")
            
    except Exception as e:
        print(f"❌ Startup error: {str(e)}")
        print("⚠️ Continuing without automatic training. You can train models manually.")


# --- NEW/MODIFIED Pydantic Models for Integration ---

# This model represents the data structure that the Frontend will send to this Email Manager
class IncomingEmailFromFrontend(BaseModel):
    sender: str
    recipients: List[str]
    subject: Optional[str] = None
    body: Optional[str] = None # The main text content of the email

# This model MUST match the RawEmailLogInput in your Main IDS's schemas.py
class RawEmailLogInputForMainIDS(BaseModel):
    email_id: str
    sender: str
    recipients: List[str] = []
    subject: Optional[str] = None
    body: Optional[str] = None
    received_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    detection_status: Optional[str] = None # This will be based on spam for now
    details: Optional[Dict[str, Any]] = None
    attachment_filename: Optional[str] = None
    attachment_url: Optional[str] = None # Stores the URL/path to the file

class EmailThreatDetectionInput(BaseModel):
    """
    Schema for detected email threats to be sent to the Main IDS.
    This should align with your Main IDS's EmailDetectionInput.
    """
    source_type: str = "email" # Changed from "email_manager" to match Main IDS's default
    detection_id: str = Field(default_factory=lambda: f"detection-{uuid.uuid4().hex[:8]}")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    email_id: str # Link back to the raw email
    sender: str
    subject: str
    detection_type: str # e.g., "spam", "phishing", "malware_email"
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    details: Optional[Dict[str, Any]] = None

# --- Existing EmailRequest (retained for UI - no changes here) ---
class EmailRequest(BaseModel):
    text: str
    model_name: Optional[str] = "Naive Bayes"


# --- Endpoint to Ingest Emails (Modified to remove local scanning) ---
@app.post("/ingest-email", summary="Receive, classify, and log an email with attachment")
async def ingest_email_and_process(
    email_json_data: str = Form(...), # Email metadata as a JSON string
    attachment: Optional[UploadFile] = File(None) # The actual file upload (optional)
):
    """
    Receives email data and an optional attachment from the frontend.
    It then:
    1. Parses the email metadata.
    2. If an attachment exists, uploads it directly to the Main IDS's file upload endpoint.
    3. Classifies the email body for spam.
    4. Constructs a RawEmailLogInput payload (including attachment details and spam status)
       and sends it to the Main IDS ingestion endpoint.
    5. If spam is detected, sends a separate threat detection log to the Main IDS.
    """
    if not models_trained:
        raise HTTPException(status_code=400, detail="Email classification models not trained. Please train models first.")

    # 1. Parse email metadata from the form string
    try:
        frontend_email_data = IncomingEmailFromFrontend.model_validate(json.loads(email_json_data))
    except json.JSONDecodeError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid 'email_json_data' JSON format.")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Error parsing email_json_data: {e}")

    email_id = str(uuid.uuid4()) # Generate a unique ID for this email entry
    current_timestamp = datetime.now(timezone.utc)

    print(f"Received email for ingestion: ID={email_id}, From={frontend_email_data.sender}, Subject='{frontend_email_data.subject}'")

    attachment_filename = None
    attachment_url = None
    # Initial detection status, will be updated by spam classification
    overall_detection_status = "clean"
    
    # --- Attachment Handling (Simplified Block) ---
    if attachment:
        attachment_filename = attachment.filename
        print(f"Received attachment: {attachment_filename}")

        try:
            # Read the entire file content into a BytesIO object so it can be re-read
            # by httpx for the upload to Main IDS. The original attachment.file stream
            # can only be read once.
            file_content_bytes = await attachment.read()
            file_stream_for_upload = io.BytesIO(file_content_bytes)

            # Prepare files dictionary for httpx
            files = {'file': (attachment_filename, file_stream_for_upload, attachment.content_type)}
            
            main_ids_upload_url = f"{MAIN_IDS_BASE_URL}/upload/attachment"
            print(f"Attempting to upload attachment to Main IDS: {main_ids_upload_url}")
            upload_response = await http_client.post(main_ids_upload_url, files=files)
            
            upload_response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
            uploaded_file_info = upload_response.json()
            attachment_url = uploaded_file_info.get("file_url")
            print(f"Attachment uploaded successfully to Main IDS. URL: {attachment_url}")

        except httpx.HTTPStatusError as e:
            print(f"❌ Error uploading attachment to Main IDS: {e.response.status_code} - {e.response.text}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to upload attachment to Main IDS: {e.response.text}"
            )
        except Exception as e:
            print(f"❌ Error during attachment processing (upload): {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to process attachment: {e}"
            )
    # --- End Attachment Handling ---


    # 2. Perform Spam Classification on the email body
    email_body_for_classification = frontend_email_data.body or ""
    prediction_label_raw, confidence_score_raw = classifier.predict(email_body_for_classification)
    
    if prediction_label_raw == "spam":
        overall_detection_status = "spam"

    print(f"Email body classified as: {prediction_label_raw} with confidence {confidence_score_raw:.3f}")


    # 3. Construct RawEmailLogInput payload for Main IDS (matches Main IDS schema)
    raw_log_payload_for_main_ids = RawEmailLogInputForMainIDS(
        email_id=email_id,
        sender=frontend_email_data.sender,
        recipients=frontend_email_data.recipients,
        subject=frontend_email_data.subject,
        body=frontend_email_data.body,
        received_timestamp=current_timestamp,
        detection_status=overall_detection_status, # Status from spam classification only
        attachment_filename=attachment_filename,
        attachment_url=attachment_url,
        details={
            "source": "email_manager_ingestion",
            "frontend_input": frontend_email_data.model_dump(exclude_unset=True),
            "spam_classification_result": {
                "label": prediction_label_raw,
                "confidence": float(confidence_score_raw)
            }
            # Removed attachment_scan_status as Main IDS will handle it
        }
    )

    # 4. Send Raw Email Log to Main IDS
    try:
        main_ids_ingest_log_url = f"{MAIN_IDS_BASE_URL}/ingest/raw-email-log"
        print(f"Sending raw email log to Main IDS: {main_ids_ingest_log_url}")
        ingest_response = await http_client.post(
            main_ids_ingest_log_url,
            json=raw_log_payload_for_main_ids.model_dump(mode='json', exclude_none=True)
        )
        ingest_response.raise_for_status()
        print(f"Raw email log sent successfully to Main IDS. Status: {ingest_response.status_code}")

    except httpx.HTTPStatusError as e:
        print(f"❌ Error sending raw email log to Main IDS: {e.response.status_code} - {e.response.text}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to log raw email to Main IDS: {e.response.text}"
        )
    except httpx.RequestError as e:
        print(f"❌ Network error sending raw email log to Main IDS: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Network error connecting to Main IDS for raw email log: {e}"
        )


    # 5. If Spam Detected, Send Email Threat to Main IDS
    if overall_detection_status == "spam": # Malware detection removed from here
        detection_type = "email_spam"
        
        threat_payload = EmailThreatDetectionInput(
            timestamp=current_timestamp,
            email_id=email_id,
            sender=frontend_email_data.sender,
            subject=frontend_email_data.subject,
            detection_type=detection_type,
            confidence_score=float(confidence_score_raw),
            details={
                "classification_model": "Enhanced Random Forest",
                "original_email_body_hash": hashlib.sha256(email_body_for_classification.encode()).hexdigest() if email_body_for_classification else "N/A",
                "attachment_filename": attachment_filename,
                "attachment_url": attachment_url
                # Removed attachment_scan_status
            }
        )
        print(f"Sending email threat detection to {MAIN_IDS_BASE_URL}/ingest/email-threat")
        try:
            response_threat = await http_client.post(
                f"{MAIN_IDS_BASE_URL}/ingest/email-threat",
                json=threat_payload.model_dump(mode='json', exclude_none=True)
            )
            response_threat.raise_for_status()
            print(f"Email threat reported successfully to Main IDS. Status: {response_threat.status_code}")
        except httpx.HTTPStatusError as e:
            print(f"❌ Error sending email threat to Main IDS: {e.response.status_code} - {e.response.text}")
        except httpx.RequestError as e:
            print(f"❌ Network error sending email threat to Main IDS: {e}")


    # Final response to the frontend
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "status": "success",
            "message": "Email ingested, processed, and forwarded.",
            "email_id": email_id,
            "classification": prediction_label_raw,
            "confidence": float(confidence_score_raw),
            "overall_detection_status": overall_detection_status,
            "attachment_url": attachment_url
            # Removed attachment_scan_status
        }
    )


# --- Existing Endpoints (UI related - no changes here unless specified) ---

@app.get("/", response_class=HTMLResponse)
async def root_redirect(request: Request):
    """Redirect to prediction page for easy integration"""
    return RedirectResponse(url="/prediction", status_code=302)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard"""
    return templates.TemplateResponse("index.html", {
        "request": request,
        "dataset_loaded": dataset_loaded,
        "models_trained": models_trained,
        "auto_trained": True # Indicate models were auto-trained
    })

@app.get("/upload", response_class=HTMLResponse)
async def upload_page(request: Request):
    """Data upload page"""
    return templates.TemplateResponse("upload.html", {
        "request": request,
        "dataset_loaded": dataset_loaded
    })

@app.get("/training", response_class=HTMLResponse)
async def training_page(request: Request):
    """Model training page"""
    return templates.TemplateResponse("training.html", {
        "request": request,
        "dataset_loaded": dataset_loaded,
        "models_trained": models_trained
    })

@app.get("/prediction", response_class=HTMLResponse)
async def prediction_page(request: Request):
    """Real-time prediction page"""
    return templates.TemplateResponse("prediction.html", {
        "request": request,
        "models_trained": models_trained,
        "available_models": list(training_results.keys()) if training_results else []
    })

@app.get("/evaluation", response_class=HTMLResponse)
async def evaluation_page(request: Request):
    """Model evaluation page"""
    return templates.TemplateResponse("evaluation.html", {
        "request": request,
        "models_trained": models_trained,
        "training_results": training_results
    })

@app.post("/api/load-dataset")
async def load_dataset():
    """Load the email dataset"""
    global dataset_loaded, processed_data
    
    try:
        # Check if dataset file exists
        if not os.path.exists("mail_data.csv"):
            raise HTTPException(status_code=404, detail="Dataset file not found")
            
        # Load and process data
        data = pd.read_csv("mail_data.csv")
        processed_data = data_processor.process_data(data)
        dataset_loaded = True
            
        # Get summary statistics
        summary = data_processor.get_data_summary(processed_data)
            
        return {
            "success": True,
            "message": f"Successfully loaded {len(data)} emails",
            "summary": summary
        }
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/train-models")
async def train_models(selected_models: List[str] = ["Logistic Regression", "SVM", "Random Forest"]):
    """Train machine learning models"""
    global models_trained, training_results
    
    if not dataset_loaded or processed_data is None:
        raise HTTPException(status_code=400, detail="Please load dataset first")
        
    try:
        # Train models
        results = classifier.train_models(
            processed_data,
            selected_models=selected_models
        )
            
        training_results = results
        models_trained = True
            
        # Convert results for JSON response
        json_results = {}
        for model_name, metrics in results.items():
            json_results[model_name] = {
                "accuracy": float(metrics["accuracy"]),
                "precision": float(metrics["precision"]),
                "recall": float(metrics["recall"]),
                "f1_score": float(metrics["f1_score"]),
                "cv_mean": float(metrics["cv_mean"]),
                "cv_std": float(metrics["cv_std"])
            }
            
        return {
            "success": True,
            "results": json_results,
            "message": f"Successfully trained {len(selected_models)} models"
        }
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/predict-ui")
async def predict_email_ui(request: EmailRequest):
    """
    Make prediction on email text for the UI interface.
    This endpoint is for the web UI, not for system-to-system integration.
    """
    if not models_trained:
        raise HTTPException(status_code=400, detail="No trained models available")
        
    try:
        # Use enhanced Random Forest model
        prediction, confidence = classifier.predict(request.text)
            
        return {
            "success": True,
            "prediction": prediction,
            "confidence": float(confidence),
            "model_used": "Enhanced Random Forest"
        }
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/predict-all")
async def predict_all_models(text: str = Form(...)):
    """Get predictions from all trained models"""
    if not models_trained:
        raise HTTPException(status_code=400, detail="No trained models available")
        
    try:
        predictions = classifier.predict_all_models(text)
            
        # Convert to JSON-serializable format
        results = {}
        for model_name, result in predictions.items():
            results[model_name] = {
                "prediction": result["prediction"],
                "confidence": float(result["confidence"])
            }
            
        return {
            "success": True,
            "predictions": results
        }
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/model-evaluation")
async def get_model_evaluation():
    """Get model evaluation metrics"""
    if not models_trained:
        raise HTTPException(status_code=400, detail="No trained models available")
        
    try:
        evaluation = classifier.evaluate_models()
            
        if evaluation is not None:
            # Convert DataFrame to dict for JSON response
            return {
                "success": True,
                "evaluation": evaluation.to_dict('records')
            }
        else:
            raise HTTPException(status_code=404, detail="No evaluation data available")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/dataset-info")
async def get_dataset_info():
    """Get dataset information"""
    if not dataset_loaded:
        return {"loaded": False}
        
    try:
        if processed_data is not None:
            summary = data_processor.get_data_summary(processed_data)
            return {
                "loaded": True,
                "summary": summary
            }
        else:
            return {"loaded": False}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    # Make sure your Main IDS is running before you run this Email Manager
    uvicorn.run(app, host="0.0.0.0", port=5000)