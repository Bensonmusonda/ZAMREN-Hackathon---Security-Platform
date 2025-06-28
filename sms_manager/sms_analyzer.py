import pandas as pd
import re
import string
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score, classification_report
import os

DATASET_PATH = os.path.join(os.path.dirname(__file__), 'spam.csv')
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'sms_spam_model.pkl')
VECTORIZER_PATH = os.path.join(os.path.dirname(__file__), 'tfidf_vectorizer.pkl')

class SMSSpamDetector:
    def __init__(self):
        self.vectorizer = None
        self.model = None
        self._load_or_train_model()

    def _preprocess_text(self, text):
        if not isinstance(text, str):
            text = str(text)
        text = text.lower()
        text = re.sub(r'\d+', '', text)
        text = text.translate(str.maketrans('', '', string.punctuation))
        return text

    def _load_or_train_model(self):
        if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
            print("Loading existing SMS spam detection model and vectorizer...")
            self.model = joblib.load(MODEL_PATH)
            self.vectorizer = joblib.load(VECTORIZER_PATH)
            print("Model and vectorizer loaded successfully")
        else:
            print("Model or vectorizer not found. Training new SMS spam detection model...")
            self._train_model()
            print("Model training complete and saved.")

    def _train_model(self):
        try:
            df = pd.read_csv(DATASET_PATH, encoding='latin-1', sep=',')
            df = df[['v1', 'v2']]
            df.columns = ['label', 'message']

        except FileNotFoundError:
            print(f"Error: Dataset not found at {DATASET_PATH}")
            raise Exception(f"Error loading dataset. Please ensure 'spam.csv' is in the same directory as the script.")
        except Exception as e:
            raise Exception(f"Error loading dataset: {e}. Check file format and encoding.")

        df['message'] = df['message'].fillna('').astype(str)
        df['processed_message'] = df['message'].apply(self._preprocess_text)

        X = df['processed_message']
        y = df['label'].map({'ham': 0, 'spam': 1})

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        self.vectorizer = TfidfVectorizer(stop_words='english', max_features=5000)
        X_train_tfidf = self.vectorizer.fit_transform(X_train)

        self.model = MultinomialNB()
        self.model.fit(X_train_tfidf, y_train)

        X_test_tfidf = self.vectorizer.transform(X_test)
        y_pred = self.model.predict(X_test_tfidf)
        accuracy = accuracy_score(y_test, y_pred)
        print(f"Model Training Accuracy: {accuracy:.4f}")

        joblib.dump(self.model, MODEL_PATH)
        joblib.dump(self.vectorizer, VECTORIZER_PATH)
        print(f"Model saved to {MODEL_PATH}")
        print(f"Vectorizer saved to {VECTORIZER_PATH}")

    def predict_spam(self, message: str):
        if self.model is None or self.vectorizer is None:
            raise RuntimeError("Model or vectorizer not loaded/trained. Call _load_or_train_model first.")

        processed_message = self._preprocess_text(message)
        message_tfidf = self.vectorizer.transform([processed_message])

        prediction = self.model.predict(message_tfidf)[0]
        prediction_proba = self.model.predict_proba(message_tfidf)[0]

        label = "spam" if prediction == 1 else "ham"
        
        if label == "spam":
            confidence = float(prediction_proba[1])
        else:
            confidence = float(prediction_proba[0])

        return {"label": label, "confidence": confidence}

sms_detector = SMSSpamDetector()

if __name__ == "__main__":
    print("\nTesting SMSSpamDetector directly:")
    test_messages = [
        "SIX chances to win CASH! From 100 to 20,000 pounds txt> CSH11 and send to 87575. Cost 150p/day, 6days, 16+ TsandCs apply Reply HL 4 info",
        "Had your mobile 11 months or more? U R entitled to Update to the latest Nokia for FREE! Call The Mobile Update Co FREE on 0800XXXXXXXX",
        "Hey, how are you doing? Let's catch up later.",
        "Reminder: Your appointment is tomorrow at 3 PM.",
        "WINNER! You have been selected to win a FREE holiday to Mexico! Call 09061012133"
    ]

    for msg in test_messages:
        result = sms_detector.predict_spam(msg)
        print(f"Message: '{msg}'\nPrediction: {result['label']} (Confidence: {result['confidence']:.2f})\n")
