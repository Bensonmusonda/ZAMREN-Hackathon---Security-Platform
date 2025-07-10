from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import pandas as pd
import numpy as np
import re

class EnhancedRandomForestClassifier:
    def __init__(self):
        self.vectorizer = None
        self.model = None
        self.trained = False
        
    def extract_spam_features(self, text):
        """Extract spam-specific features from text"""
        text_lower = text.lower()
        
        # Spam keywords with higher weights
        spam_keywords = [
            'free', 'winner', 'cash', 'prize', 'urgent', 'claim', 'congratulations',
            'lottery', 'jackpot', 'bonus', 'reward', 'offer', 'deal', 'discount',
            'money', 'pounds', 'dollar', '$', '£', 'euro', 'win', 'won', 'guaranteed',
            'limited time', 'act now', 'call now', 'click here', 'txt', 'text',
            'mobile', 'phone', 'call', 'number', 'code', 'pin', 'unlock',
            'selected', 'chosen', 'eligible', 'qualify', 'entitled', 'awarded'
        ]
        
        # Financial/scam patterns
        financial_patterns = [
            r'\b\d+\s*pounds?\b', r'\$\d+', r'£\d+', r'\b\d+\s*euro', 
            r'\b\d{5,}\b',  # Long numbers (phone/codes)
            r'\bcall\s+\d+', r'\btext\s+\d+', r'\btxt\s+\d+',
            r'\bcode\s*[a-z0-9]+', r'\bclaim\s+code\b'
        ]
        
        # Urgency patterns
        urgency_patterns = [
            r'\burgent\b', r'\bexpir', r'\blimited\s+time', r'\bact\s+now',
            r'\bcall\s+now', r'\btoday\s+only', r'\bhurry', r'\bquick',
            r'\bvalid\s+\d+\s+hours?', r'\bends\s+(today|soon)'
        ]
        
        features = {
            'spam_word_count': sum(1 for word in spam_keywords if word in text_lower),
            'has_money_amount': len(re.findall(r'[£$€]\d+|\b\d+\s*pounds?', text_lower)),
            'has_phone_number': len(re.findall(r'\b\d{5,}\b', text)),
            'has_urgency': len(re.findall('|'.join(urgency_patterns), text_lower)),
            'has_claim_code': len(re.findall(r'\bcode\b|\bclaim\b', text_lower)),
            'all_caps_ratio': sum(1 for c in text if c.isupper()) / max(len(text), 1),
            'exclamation_count': text.count('!'),
            'text_length': len(text),
            'word_count': len(text.split()),
            'has_winner': 1 if 'winner' in text_lower or 'won' in text_lower else 0,
            'has_free': 1 if 'free' in text_lower else 0,
            'has_urgent': 1 if 'urgent' in text_lower else 0,
            'has_call_number': 1 if re.search(r'call\s+\d+', text_lower) else 0,
            'multiple_numbers': len(re.findall(r'\d{4,}', text)) > 1
        }
        
        return features
    
    def prepare_enhanced_features(self, data):
        """Prepare enhanced features combining TF-IDF with spam-specific features"""
        # Text features using TF-IDF with spam-focused parameters
        self.vectorizer = TfidfVectorizer(
            max_features=3000,
            stop_words='english',
            ngram_range=(1, 3),  # Include trigrams for better pattern detection
            min_df=2,
            max_df=0.95,
            lowercase=True,
            strip_accents='ascii',
            # Emphasize spam-related terms
            vocabulary=None,
            token_pattern=r'\b[a-zA-Z]{2,}\b|\b\d+\b|[£$€]'
        )
        
        text_features = self.vectorizer.fit_transform(data['text']).toarray()
        
        # Extract spam-specific features
        spam_features_list = []
        for text in data['text']:
            spam_features = self.extract_spam_features(text)
            spam_features_list.append(list(spam_features.values()))
        
        spam_features_array = np.array(spam_features_list)
        
        # Combine text and spam features
        combined_features = np.hstack([text_features, spam_features_array])
        
        return combined_features
    
    def train_model(self, data):
        """Train enhanced Random Forest model"""
        print("Preparing enhanced features for spam detection...")
        
        X = self.prepare_enhanced_features(data)
        y = data['label']
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print("Training Enhanced Random Forest with optimized parameters...")
        
        # Optimized Random Forest for spam detection
        self.model = RandomForestClassifier(
            n_estimators=200,  # More trees for better performance
            max_depth=15,      # Prevent overfitting but allow complexity
            min_samples_split=5,
            min_samples_leaf=2,
            max_features='sqrt',
            class_weight='balanced',  # Handle class imbalance
            random_state=42,
            n_jobs=-1  # Use all cores
        )
        
        self.model.fit(X_train, y_train)
        
        # Evaluate model
        y_pred = self.model.predict(X_test)
        
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, pos_label='spam')
        recall = recall_score(y_test, y_pred, pos_label='spam')
        f1 = f1_score(y_test, y_pred, pos_label='spam')
        
        self.trained = True
        
        results = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1
        }
        
        print(f"Enhanced Random Forest Results:")
        print(f"  Accuracy: {accuracy:.3f}")
        print(f"  Precision: {precision:.3f}")
        print(f"  Recall: {recall:.3f}")
        print(f"  F1 Score: {f1:.3f}")
        
        return results
    
    def predict(self, text):
        """Make prediction on single text"""
        if not self.trained:
            raise ValueError("Model not trained")
        
        # Create temporary dataframe for feature extraction
        temp_df = pd.DataFrame({'text': [text], 'label': ['unknown']})
        features = self.prepare_enhanced_features_single(text)
        
        prediction = self.model.predict([features])[0]
        confidence = self.model.predict_proba([features])[0].max()
        
        return prediction, confidence
    
    def prepare_enhanced_features_single(self, text):
        """Prepare features for single text prediction"""
        # Text features
        text_features = self.vectorizer.transform([text]).toarray()[0]
        
        # Spam features
        spam_features = self.extract_spam_features(text)
        spam_features_array = np.array(list(spam_features.values()))
        
        # Combine features
        combined_features = np.hstack([text_features, spam_features_array])
        
        return combined_features