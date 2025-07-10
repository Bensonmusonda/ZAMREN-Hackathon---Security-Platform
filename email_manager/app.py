from fastapi import FastAPI, Request, Form, File, UploadFile, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import pandas as pd
import numpy as np
from typing import Optional, List
import os
from enhanced_classifier import EnhancedRandomForestClassifier
from data_processor_v2 import DataProcessorV2

app = FastAPI(title="Email Spam Classification System", version="1.0.0")

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

# Startup function to load dataset and train models
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
            print("⚠️  Dataset file 'mail_data.csv' not found")
            
    except Exception as e:
        print(f"❌ Startup error: {str(e)}")
        # Continue without training - user can train manually
        print("⚠️  Continuing without automatic training. You can train models manually.")

# Add startup event
@app.on_event("startup")
async def startup_event():
    await startup_tasks()

class EmailRequest(BaseModel):
    text: str
    model_name: Optional[str] = "Naive Bayes"

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
        "auto_trained": True  # Indicate models were auto-trained
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

@app.post("/api/predict")
async def predict_email(request: EmailRequest):
    """Make prediction on email text"""
    if not models_trained:
        raise HTTPException(status_code=400, detail="No trained models available")
    
    # Skip model validation since we're using enhanced classifier
    
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
    uvicorn.run(app, host="0.0.0.0", port=5000)