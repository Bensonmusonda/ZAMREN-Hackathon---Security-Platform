# train_anomaly_model.py

import os
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta, timezone

# Add the parent directory to the system path to allow imports from 'detection_and_logging_system'
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from detection_and_logging_system.database import Base, engine, get_db
from detection_and_logging_system import models, schemas
from detection_and_logging_system.ml_anomaly_detector import MLAnomalyDetector

# --- Configuration for data collection for training ---
# It's crucial to train on 'normal' data. Define how much data to fetch.
# For a prototype, 1000-5000 recent "normal" logs should be a good starting point.
# You might need to generate some normal traffic first if your DB is empty or only has attack data.
TRAINING_DATA_COUNT = 5000 
# Optionally, define a time window if you prefer recent data
TRAINING_DATA_TIME_WINDOW_DAYS = 7 
# ----------------------------------------------------

def main():
    print("Starting ML Anomaly Model Training...")
    
    # Ensure database tables are created
    Base.metadata.create_all(bind=engine)
    
    db_session = next(get_db()) # Get a database session

    try:
        # Fetch historical data for training
        # Fetching by count and time for robustness
        
        # Get logs from a specific time window
        time_window_start = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=TRAINING_DATA_TIME_WINDOW_DAYS)
        historical_logs = db_session.query(models.NetworkEventLog).\
                            filter(models.NetworkEventLog.timestamp >= time_window_start).\
                            order_by(models.NetworkEventLog.timestamp.desc()).\
                            limit(TRAINING_DATA_COUNT).all()
        
        # Convert SQLAlchemy objects to dictionaries for pandas DataFrame
        historical_logs_data = []
        for log in historical_logs:
            log_dict = {
                "id": log.id,
                "log_source": log.log_source,
                "timestamp": log.timestamp,
                "event_description": log.event_description,
                "source_ip": log.source_ip,
                "destination_ip": log.destination_ip,
                "protocol": log.protocol,
                "port": log.port,
                "action": log.action,
                "username": log.username,
                "details": log.details # Include details if you want to extract features from it
            }
            historical_logs_data.append(log_dict)
            
        print(f"Fetched {len(historical_logs_data)} historical logs for training.")

        ml_detector = MLAnomalyDetector()
        ml_detector.train_model(historical_logs_data)
        
        print("ML Anomaly Model Training Complete.")
        
    except Exception as e:
        print(f"An error occurred during training: {e}")
    finally:
        db_session.close()

if __name__ == "__main__":
    main()