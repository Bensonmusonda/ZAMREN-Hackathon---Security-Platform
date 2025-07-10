# detection_and_logging_system/ml_anomaly_detector.py

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional

# Define the features that the ML model will use
NUMERICAL_FEATURES = ['port', 'hour_of_day', 'day_of_week']
CATEGORICAL_FEATURES = ['log_source', 'protocol', 'action'] # 'username' can be added if it has consistent values

# Time window for collecting logs for ML inference (e.g., last 5 minutes)
ML_INFERENCE_TIME_WINDOW_MINUTES = 5

class MLAnomalyDetector:
    def __init__(self, model_path="ml_anomaly_model.pkl", preprocessor_path="ml_feature_preprocessor.pkl"):
        self.model = None
        self.preprocessor = None
        self.model_path = model_path
        self.preprocessor_path = preprocessor_path
        self._load_model_and_preprocessor()

    def _load_model_and_preprocessor(self):
        """Loads the trained model and preprocessor if they exist."""
        try:
            self.model = joblib.load(self.model_path)
            self.preprocessor = joblib.load(self.preprocessor_path)
            print("ML Anomaly model and preprocessor loaded successfully.")
        except FileNotFoundError:
            print("ML Anomaly model or preprocessor not found. Please train the model first using 'train_anomaly_model.py'.")
            self.model = None
            self.preprocessor = None
        except Exception as e:
            print(f"Error loading ML model/preprocessor: {e}. Please retrain.")
            self.model = None
            self.preprocessor = None

    def _build_preprocessor(self):
        """Builds and returns the ColumnTransformer for feature engineering."""
        # Define transformers for different types of features
        preprocessor = ColumnTransformer(
            transformers=[
                ('cat', OneHotEncoder(handle_unknown='ignore'), CATEGORICAL_FEATURES)
            ],
            remainder='passthrough' # Keep numerical features
        )
        return preprocessor

    def _prepare_features(self, df: pd.DataFrame) -> Optional[pd.DataFrame]:
        """Prepares features from a DataFrame of network logs."""
        if df.empty:
            return None

        # Convert timestamp to time-based features
        df['timestamp'] = pd.to_datetime(df['timestamp']) # Ensure it's datetime object
        df['hour_of_day'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        
        # Ensure 'port' is numeric, handle None/NaNs gracefully
        # Use -1 or a distinct value for missing ports, or a separate indicator feature
        df['port'] = pd.to_numeric(df['port'], errors='coerce').fillna(-1).astype(int) 
        
        # Select the columns that will be fed into the model
        # The order of columns in this list is important for the preprocessor
        feature_df = df[NUMERICAL_FEATURES + CATEGORICAL_FEATURES].copy()
        
        return feature_df

    def train_model(self, historical_logs_data: List[Dict[str, Any]]):
        """
        Trains the Isolation Forest model using historical network logs.
        
        Args:
            historical_logs_data: A list of dictionaries, where each dictionary
                                  represents a row from the NetworkEventLog table.
        """
        if not historical_logs_data:
            print("No historical data provided for training the ML model.")
            self.model = None
            self.preprocessor = None
            return

        print("Preparing data for ML Anomaly Detection model training...")
        historical_df = pd.DataFrame(historical_logs_data)
        
        # Ensure 'port' is handled correctly before _prepare_features
        # We need the original values for the encoder to learn categories
        if 'port' in historical_df.columns:
            historical_df['port'] = historical_df['port'].apply(lambda x: int(x) if pd.notna(x) else None)
        
        feature_df = self._prepare_features(historical_df)

        if feature_df is None or feature_df.empty:
            print("No features extracted for training. Model not trained.")
            self.model = None
            self.preprocessor = None
            return

        # Build and fit the preprocessor on the training data
        self.preprocessor = self._build_preprocessor()
        X_train = self.preprocessor.fit_transform(feature_df)
        
        print(f"Training ML Anomaly Detection model with {X_train.shape[0]} samples and {X_train.shape[1]} features...")
        
        # Initialize Isolation Forest
        # contamination: An estimate of the proportion of outliers in the data set.
        # It helps the model set a decision threshold. Adjust based on your data.
        # For a prototype, 0.01-0.05 is a reasonable starting point if anomalies are rare.
        self.model = IsolationForest(random_state=42, contamination=0.01, n_estimators=100) 
        self.model.fit(X_train)
        
        joblib.dump(self.model, self.model_path)
        joblib.dump(self.preprocessor, self.preprocessor_path) # Save the fitted preprocessor
        print("ML Anomaly model trained and saved.")

    def predict_anomaly(self, current_logs_data: List[Dict[str, Any]]) -> bool:
        """
        Predicts if the current set of logs contains an anomaly.
        
        Args:
            current_logs_data: A list of dictionaries representing recent network logs.
        
        Returns:
            True if an anomaly is detected, False otherwise.
        """
        if self.model is None or self.preprocessor is None:
            print("ML Anomaly model or preprocessor not loaded. Cannot predict.")
            return False
        
        if not current_logs_data:
            return False

        # Convert list of dicts to DataFrame
        current_df = pd.DataFrame(current_logs_data)
        
        # Ensure 'port' is handled correctly for inference as it was for training
        if 'port' in current_df.columns:
            current_df['port'] = current_df['port'].apply(lambda x: int(x) if pd.notna(x) else None)

        feature_df = self._prepare_features(current_df)

        if feature_df is None or feature_df.empty:
            return False

        try:
            # Transform the current data using the *fitted* preprocessor
            X_predict = self.preprocessor.transform(feature_df)
            
            # predict returns -1 for anomalies and 1 for normal
            predictions = self.model.predict(X_predict)
            
            # Get anomaly scores (lower score = more anomalous)
            anomaly_scores = self.model.decision_function(X_predict)
            
            # If any prediction is -1 (anomaly), consider it an anomaly
            is_anomaly = -1 in predictions
            
            if is_anomaly:
                # You can log or use the score for more nuanced alerting
                min_score = anomaly_scores.min()
                print(f"ML Anomaly Detected! Min score: {min_score}")
            else:
                print(f"ML Prediction: No anomaly in current batch.")
            
            return is_anomaly
        except Exception as e:
            print(f"Error during ML anomaly prediction: {e}")
            return False