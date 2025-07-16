ZAMREN Security Platform

This repository contains the core components of the ZAMREN Security Platform, an Intrusion Detection System (IDS) designed to monitor and analyze network, email, and SMS traffic for suspicious activities and potential threats.
🌟 Key Features

The platform is modular, consisting of several interconnected services. Recent developments have significantly enhanced its network monitoring capabilities:

    User Authentication & Portal: Provides secure user registration and login functionalities for accessing platform features.

    Email Threat Detection: Ingests raw email logs, scans attachments for malware, and identifies spam/malicious content.

    SMS Threat Detection: Ingests raw SMS logs and performs basic threat analysis.

    Comprehensive Network Traffic Analysis:

        Middleware-based Logging: All incoming requests and outgoing responses to the Main IDS API are automatically intercepted and logged, providing a holistic view of network interactions.

        Suspicious IP Detection: Identifies and flags traffic originating from (or destined for) known suspicious IP addresses.

        Brute-Force Attack Detection: Monitors and alerts on repeated failed login attempts from the same source IP.

        Unusual HTTP Status Code Detection: Flags unexpected or frequent HTTP error responses (e.g., 403, 404, 5xx) that could indicate probing or attacks.

        Unusual Response Size Detection: Detects abnormally large (potential data exfiltration) or unusually small (potential empty/malformed responses) successful responses.

        Sensitive Data Leakage Detection: Scans API response bodies for patterns indicative of sensitive information (e.g., passwords, API keys) being unintentionally exposed.

    Centralized Threat Logging: All detected threats (from email, SMS, or network sources) are logged into a unified detected_threats database for streamlined monitoring and analysis.

    Visual Analytics Dashboard: Offers a web interface to visualize threat summaries, raw logs, and detailed security insights.

📂 Project Structure

ZAMREN Hackathon - Security platform/
├── detection_and_logging_system/  # Main IDS API, central logging, and core analysis logic
│   ├── database.py                # Database connection and session management
│   ├── models.py                  # SQLAlchemy ORM models for database tables
│   ├── schemas.py                 # Pydantic schemas for data validation and serialization
│   ├── actions.py                 # Business logic for logging and interacting with DB
│   ├── network_analyzer.py        # Logic for network threat detection
│   ├── file_analyzer.py           # Logic for file/attachment scanning
│   └── main.py                    # FastAPI application, middleware, and API endpoints
├── email_manager/                 # Service for ingesting and processing email data
│   └── app.py                     # FastAPI application for email ingestion
├── sms_manager/                   # Service for ingesting and processing SMS data
│   └── main.py                    # FastAPI application for SMS ingestion
├── interface_and_visual_analytics_system/ # Frontend dashboard (HTML/CSS/JS)
│   └── (html, css, js files)
├── messaging_system_for_testing/  # Simple frontend for testing email/SMS sending/receiving
│   └── (html, css, js files)
└── README.md                      # This file

🛠️ Prerequisites

Before setting up the project, ensure you have the following installed:

    Python 3.9+

    pip (Python package installer)

    PostgreSQL database server (e.g., PostgreSQL 14 or later)

    psql command-line client (for database setup)

🚀 Setup Instructions

Follow these steps to get all services running locally.
1. Clone the Repository

git clone https://github.com/your-username/ZAMREN-Hackathon-Security-platform.git
cd ZAMREN-Hackathon-Security-platform

2. Database Setup (PostgreSQL)

Create a PostgreSQL database and a dedicated user for the application.

# Open your psql terminal (e.g., by running `psql -U postgres`)
psql -U postgres

# Create the database
CREATE DATABASE ids_db;

# Create a user and grant privileges (replace 'your_password' with a strong password)
CREATE USER ids_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE ids_db TO ids_user;

# Exit psql
\q

Important: Configure your database connection string in detection_and_logging_system/database.py. Ensure it matches the user and password you just created.

# detection_and_logging_system/database.py
SQLALCHEMY_DATABASE_URL = "postgresql://ids_user:your_password@localhost/ids_db"

3. Virtual Environments and Dependencies

It is recommended to use separate virtual environments for each Python service to manage dependencies effectively.
a. detection_and_logging_system (Main IDS)

cd detection_and_logging_system
python -m venv venv
venv\Scripts\activate # On Windows
# source venv/bin/activate # On macOS/Linux

pip install -r requirements.txt # Ensure you have a requirements.txt, or install manually:
# pip install fastapi uvicorn sqlalchemy psycopg2-binary python-jose[cryptography] passlib[bcrypt] python-multipart

b. email_manager

cd ../email_manager
python -m venv venv
venv\Scripts\activate # On Windows
# source venv/bin/activate # On macOS/Linux

pip install -r requirements.txt # Or install manually:
# pip install fastapi uvicorn requests

c. sms_manager

cd ../sms_manager
python -m venv venv
venv\Scripts\activate # On Windows
# source venv/bin/activate # On macOS/Linux

pip install -r requirements.txt # Or install manually:
# pip install fastapi uvicorn requests

4. Run the Subsystems

Open separate terminal windows for each service and execute the commands below.
a. Main IDS (Detection and Logging System)

This is the core FastAPI application.

# In a new terminal, navigate to:
cd C:\Users\benso\Projects\ZAMREN Hackathon - Security platform\detection_and_logging_system

# Activate virtual environment
venv\Scripts\activate # On Windows

# Run the application
uvicorn main:app --reload --host 0.0.0.0 --port 8000

(Note: A DeprecationWarning regarding on_event may appear. This is a known FastAPI warning and does not affect the project's functionality.)
b. Email Manager

This service handles email ingestion.

# In a new terminal, navigate to:
cd C:\Users\benso\Projects\ZAMREN Hackathon - Security platform\email_manager

# Activate virtual environment
venv\Scripts\activate # On Windows

# Run the application
python app.py --reload --port 5000

c. SMS Manager

This service handles SMS ingestion.

# In a new terminal, navigate to:
cd C:\Users\benso\Projects\ZAMREN Hackathon - Security platform\sms_manager

# Activate virtual environment
venv\Scripts\activate # On Windows

# Run the application
uvicorn main:app --reload --host 0.0.0.0 --port 8001

d. Frontend (Interface and Visual Analytics System)

This serves the main dashboard.

# In a new terminal, navigate to:
cd C:\Users\benso\Projects\ZAMREN Hackathon - Security platform\interface_and_visual_analytics_system

# Run a simple HTTP server
python -m http.server 5500

e. Frontend (Messaging System for Testing)

This serves the testing frontend for sending/receiving messages.

# In a new terminal, navigate to:
cd C:\Users\benso\Projects\ZAMREN Hackathon - Security platform\messaging_system_for_testing

# Run a simple HTTP server
python -m http.server 5501

Once all services are running, the main dashboard can be accessed at http://localhost:5500 and the testing messaging system at http://localhost:5501.
✅ Testing the New Network Analysis Features

These tests demonstrate the enhanced network monitoring capabilities of the Main IDS. Ensure all services are running as described in the "Run the Subsystems" section.

Important: Your Ubuntu VM's IP addresses (e.g., 192.168.56.101, 192.168.56.102) should be configured in detection_and_logging_system/network_analyzer.py under SUSPICIOUS_IPS for some tests to function correctly.
Test 1: Suspicious IP & Generic Request/Response Logging (from VM)

This test verifies that the middleware logs every request and that suspicious IP detection is active for any request originating from a flagged IP address.

    From a web browser inside one of your Ubuntu VMs, navigate to your testing frontend's login page: http://<YOUR_HOST_IP>:5501/login.html (e.g., http://192.168.56.1:5501/login.html).

    Perform a single login attempt with incorrect credentials.

    Observe the Main IDS console logs:

        A Network event processed: ... log entry from the middleware should be visible.

        An !!! ALERT !!! Detected Network Threat: suspicious_ip_source ... alert should appear because the VM's IP is included in the SUSPICIOUS_IPS list.

    Verify on the Dashboard (http://localhost:5500):

        Refresh the dashboard.

        The "Suspicious IP Attempts" count should increment.

        A new entry should appear in "Security Insights" with Source: NETWORK_IDS and Threat: suspicious_ip_source.

Test 2: Brute Force Attack (from VM)

This test validates the combined brute-force and suspicious IP detection.

    From the same Ubuntu VM browser used in Test 1, continue making failed login attempts on the login page (http://<YOUR_HOST_IP>:5501/login.html).

    Continue attempts until the BRUTE_FORCE_THRESHOLD is exceeded (default: 5).

    Observe the Main IDS console logs:

        Brute-force check for IP ...: [X] failed attempts... messages will be displayed.

        Upon reaching the threshold, repeated !!! ALERT !!! Detected Network Threat: suspicious_ip_source_and_brute_force_attack ... alerts should appear (or just brute_force_attack if suspicious_ip_source was previously logged as a distinct threat).

    Verify on the Dashboard (http://localhost:5500):

        Refresh the dashboard.

        The "Brute Force Attacks" count should increment.

        New entries in "Security Insights" will display Threat: brute_force_attack (potentially combined with suspicious_ip_source).

Test 3: Unusual Response Status (from VM)

This test confirms the detection of unexpected HTTP status codes.

    From a web browser inside one of your Ubuntu VMs, attempt to access a non-existent API endpoint on your Main IDS. For example, enter this URL directly into the browser's address bar:
    http://<YOUR_HOST_IP>:8000/this-path-does-not-exist (e.g., http://192.168.56.1:8000/this-path-does-not-exist).

    Observe the Main IDS console logs:

        A Network event processed: Request: GET /this-path-does-not-exist | Response Status: 404 log should be visible.

        An !!! ALERT !!! Detected Network Threat: unusual_response_status_404 ... alert should appear.

    Verify on the Dashboard (http://localhost:5500):

        Refresh the dashboard.

        A new entry should appear in "Security Insights" with Source: NETWORK_IDS and Threat: unusual_response_status_404.

Test 4: Sensitive Data Leak in Response (Requires Temporary Code Modification)

⚠️ WARNING: This test requires a temporary modification to your main.py. It is CRITICAL to REVERT THE CHANGE IMMEDIATELY AFTER TESTING to prevent actual data exposure.

    Temporarily modify detection_and_logging_system/main.py:

        Locate a simple, unprotected GET endpoint (e.g., @app.get("/")).

        Modify its return statement to include a string that matches one of the SENSITIVE_DATA_PATTERNS defined in network_analyzer.py.

    # Example: Temporarily modify / to simulate a password leak
    @app.get("/")
    async def read_root():
        # TEMPORARY TEST CODE - REMOVE AFTER TESTING!
        return JSONResponse(content={"message": "Welcome to IDS!", "user_password": "MySecretPassword123!"})

    Restart your Main IDS.

    From any web browser (on your VM or host machine), access the modified endpoint:
    http://<YOUR_HOST_IP>:8000/ (or the specific endpoint you modified).

    Observe the Main IDS console logs:

        A Network event processed: ... log should be visible.

        An !!! ALERT !!! Detected Network Threat: sensitive_data_leak_in_response_... alert should appear.

    Verify on the Dashboard (http://localhost:5500):

        Refresh the dashboard.

        A new entry should appear in "Security Insights" with a Threat related to sensitive data leakage.

    IMMEDIATELY REVERT THE CODE CHANGE IN main.py AND RESTART YOUR MAIN IDS.

📝 Architectural Notes & Development Considerations

This section highlights significant architectural changes and considerations for developers contributing to the project.
Centralized Network Monitoring via Middleware

A LoggingMiddleware has been implemented in detection_and_logging_system/main.py. This middleware automatically intercepts and processes all incoming HTTP requests and outgoing responses handled by the Main IDS API.

Implications:

    Comprehensive Logging: Network interaction details, including client IP, request method/path, response status code, content length, and a snippet of the response body, are now universally logged into the network_logs database table.

    Decoupled Logging: Explicit actions.log_network_event and network_analyzer.analyze_network_event calls have been removed from individual API endpoints (e.g., /token for login attempts, /ingest/raw-email-log). The middleware centralizes this generic network logging.

    Email Source IP Handling: While RawEmailLogInput still includes a source_ip for email-specific analysis, the network_logs entry for an /ingest/raw-email-log request will reflect the IP of the Email Manager service itself, not necessarily the original email sender's IP. For network-level analysis based on the original email sender's IP, this information must be explicitly passed within the details field of RawEmailLogInput and network_analyzer.py adapted to consume it.

    Extended Schema: The RawNetworkLogInput schema and the network_logs database table now incorporate new fields: response_status_code, response_content_length, and response_body_snippet. These are populated by the middleware.

    Enhanced Detection Logic: Developers should review detection_and_logging_system/network_analyzer.py. This module now contains advanced detection functions (detect_sensitive_data_leak, detect_unusual_response_status, detect_unusual_response_size) that leverage the newly available response data.

    Action String Consistency: The middleware generates action strings (e.g., GET_THREAT_COUNTS) by converting path segments (e.g., replacing hyphens with underscores and converting to uppercase) to ensure consistency with predefined exclusion rules in network_analyzer.py.

This refactoring centralizes network monitoring, enhancing the IDS's robustness and extensibility for future detection rule development.
