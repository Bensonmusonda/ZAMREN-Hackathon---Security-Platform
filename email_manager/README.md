# Email Spam Classifier

An enhanced email spam classification system using Random Forest with specialized financial scam detection.

## Performance
- **F1 Score**: 0.909
- **Precision**: 96.5%
- **Accuracy**: 97.9%
- **Recall**: 85.9%

## Features
- Enhanced Random Forest classifier optimized for spam detection
- Financial scam pattern recognition (money, currency, codes)
- Urgency and phone number detection
- Automatic model training on startup
- Web interface with real-time classification

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
python app.py
```

3. Open browser to `http://localhost:5000`

## Files
- `app.py` - Main FastAPI application
- `enhanced_classifier.py` - Enhanced Random Forest classifier
- `data_processor_v2.py` - Data preprocessing
- `mail_data.csv` - Training dataset (5,572 emails)
- `templates/` - HTML templates
- `static/` - CSS and JavaScript files

## Usage
The system automatically:
1. Loads the dataset on startup
2. Trains the enhanced model (~30 seconds)
3. Redirects to prediction page for immediate use
4. Provides real-time email classification

## Integration
Navigate to root URL to go directly to the prediction interface for easy integration into larger projects.