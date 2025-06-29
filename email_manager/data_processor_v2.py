import pandas as pd
import re
import string
from typing import Dict, List, Tuple
import numpy as np

class DataProcessorV2:
    def __init__(self):
        self.spam_keywords = [
            'free', 'win', 'winner', 'cash', 'prize', 'urgent', 'claim', 'call now',
            'limited time', 'offer', 'guaranteed', 'bonus', 'award', 'congratulations',
            'click here', 'txt', 'mobile', 'ringtone', 'subscription', '£', '$',
            'bonus prize', 'customer service', 'selected', 'valued customer'
        ]
    
    def process_data(self, data: pd.DataFrame) -> pd.DataFrame:
        """
        Process the email dataset with Category and Message columns
        """
        # Create a copy to avoid modifying original data
        processed_data = data.copy()
        
        # Standardize column names to match existing code
        if 'Category' in processed_data.columns and 'Message' in processed_data.columns:
            processed_data = processed_data.rename(columns={
                'Category': 'label',
                'Message': 'text'
            })
        
        # Clean and validate data
        processed_data = self._clean_data(processed_data)
        
        # Ensure we return a DataFrame
        if not isinstance(processed_data, pd.DataFrame):
            processed_data = pd.DataFrame(processed_data)
        
        # Add enhanced features
        processed_data = self._add_enhanced_features(processed_data)
        
        return processed_data
    
    def _clean_data(self, data: pd.DataFrame) -> pd.DataFrame:
        """Clean and standardize the data"""
        # Remove duplicates
        data = data.drop_duplicates(subset=['text'])
        
        # Remove empty messages
        data = data.dropna(subset=['text'])
        data = data[data['text'].str.strip() != '']
        
        # Standardize labels
        data['label'] = data['label'].str.lower().str.strip()
        
        # Clean text
        data['text'] = data['text'].apply(self._clean_text)
        
        return data.reset_index(drop=True)
    
    def _clean_text(self, text: str) -> str:
        """Clean individual text messages"""
        if pd.isna(text):
            return ""
        
        # Convert to string and lower case
        text = str(text).lower()
        
        # Remove HTML entities
        text = re.sub(r'&[a-z]+;', ' ', text)
        text = re.sub(r'&lt;#&gt;', ' NUMBER ', text)
        text = re.sub(r'&lt;url&gt;', ' URL ', text)
        
        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text)
        
        return text.strip()
    
    def _add_enhanced_features(self, data: pd.DataFrame) -> pd.DataFrame:
        """Add enhanced features for better classification"""
        
        # Text length features
        data['text_length'] = data['text'].str.len()
        data['word_count'] = data['text'].str.split().str.len()
        
        # Character features
        data['capital_ratio'] = data['text'].apply(self._calculate_capital_ratio)
        data['exclamation_count'] = data['text'].str.count('!')
        data['question_count'] = data['text'].str.count('\?')
        
        # Number and special character features
        data['number_count'] = data['text'].apply(lambda x: len(re.findall(r'\d+', x)))
        data['currency_mentions'] = data['text'].apply(self._count_currency_mentions)
        data['phone_mentions'] = data['text'].apply(self._count_phone_numbers)
        data['url_mentions'] = data['text'].apply(self._count_urls)
        
        # Spam keyword features
        data['spam_keywords_count'] = data['text'].apply(self._count_spam_keywords)
        data['spam_keywords_ratio'] = data['spam_keywords_count'] / data['word_count'].replace(0, 1)
        
        # Urgency indicators
        data['urgency_words'] = data['text'].apply(self._count_urgency_words)
        data['all_caps_words'] = data['text'].apply(self._count_all_caps_words)
        
        return data
    
    def _calculate_capital_ratio(self, text: str) -> float:
        """Calculate ratio of capital letters"""
        if not text:
            return 0.0
        letters = [c for c in text if c.isalpha()]
        if not letters:
            return 0.0
        return sum(1 for c in letters if c.isupper()) / len(letters)
    
    def _count_currency_mentions(self, text: str) -> int:
        """Count currency mentions (£, $, euro, etc.)"""
        pattern = r'[£$€¥₹]|\b(pound|dollar|euro|money|cash|price)\b'
        return len(re.findall(pattern, text, re.IGNORECASE))
    
    def _count_phone_numbers(self, text: str) -> int:
        """Count phone number patterns"""
        pattern = r'\b\d{5,}\b|call\s+\d+|\d{4,}-\d{4,}'
        return len(re.findall(pattern, text, re.IGNORECASE))
    
    def _count_urls(self, text: str) -> int:
        """Count URL patterns"""
        pattern = r'http[s]?://|www\.|\.com|\.net|\.org|click here'
        return len(re.findall(pattern, text, re.IGNORECASE))
    
    def _count_spam_keywords(self, text: str) -> int:
        """Count spam-related keywords"""
        count = 0
        text_lower = text.lower()
        for keyword in self.spam_keywords:
            count += text_lower.count(keyword)
        return count
    
    def _count_urgency_words(self, text: str) -> int:
        """Count urgency-related words"""
        urgency_words = ['urgent', 'immediate', 'now', 'limited', 'expires', 'hurry', 'fast', 'quick']
        count = 0
        text_lower = text.lower()
        for word in urgency_words:
            count += text_lower.count(word)
        return count
    
    def _count_all_caps_words(self, text: str) -> int:
        """Count words that are entirely in capital letters"""
        words = text.split()
        return sum(1 for word in words if word.isupper() and len(word) > 1)
    
    def get_data_summary(self, data: pd.DataFrame) -> Dict:
        """Get comprehensive summary statistics"""
        summary = {
            'total_emails': len(data),
            'spam_count': len(data[data['label'] == 'spam']),
            'ham_count': len(data[data['label'] == 'ham']),
            'spam_percentage': len(data[data['label'] == 'spam']) / len(data) * 100,
            'avg_text_length': data['text_length'].mean(),
            'avg_word_count': data['word_count'].mean(),
            'avg_spam_keywords': data['spam_keywords_count'].mean(),
            'feature_columns': [col for col in data.columns if col not in ['text', 'label']]
        }
        return summary
    
    def validate_data(self, data: pd.DataFrame) -> Tuple[bool, List[str]]:
        """Validate the processed dataset"""
        errors = []
        
        # Check required columns
        required_cols = ['text', 'label']
        missing_cols = [col for col in required_cols if col not in data.columns]
        if missing_cols:
            errors.append(f"Missing required columns: {missing_cols}")
        
        # Check for empty data
        if len(data) == 0:
            errors.append("Dataset is empty")
        
        # Check label values
        valid_labels = {'spam', 'ham'}
        invalid_labels = set(data['label'].unique()) - valid_labels
        if invalid_labels:
            errors.append(f"Invalid label values found: {invalid_labels}")
        
        # Check for minimum data per class
        if 'label' in data.columns:
            label_counts = data['label'].value_counts()
            for label in valid_labels:
                if label in label_counts and label_counts[label] < 10:
                    errors.append(f"Too few examples for {label}: {label_counts[label]}")
        
        return len(errors) == 0, errors