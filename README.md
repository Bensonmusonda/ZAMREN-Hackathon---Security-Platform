ZAMREN Security Platform
This repository contains the core components of the ZAMREN Security Platform, an Intrusion Detection System (IDS) designed to monitor and analyze network, email, and SMS traffic for suspicious activities and potential threats.
Key Features
The platform is modular, consisting of several interconnected services. Recent developments have significantly enhanced its network monitoring capabilities:
 * User Authentication & Portal: Secure user registration and login system for accessing platform features.
 * Email Threat Detection: Ingests raw email logs, scans attachments for malware, and identifies spam/malicious content.
 * SMS Threat Detection: Ingests raw SMS logs and performs basic threat analysis.
 * Comprehensive Network Traffic Analysis (NEW!):
   * Middleware-based Logging: All incoming requests and outgoing responses to the Main IDS API are now automatically logged, providing a holistic view of network interactions.
   * Suspicious IP Detection: Identifies and flags traffic originating from (or destined for) known suspicious IP addresses.
   * Brute-Force Attack Detection: Monitors and alerts on repeated failed login attempts from the same source IP.
   * Unusual HTTP Status Code Detection: Flags unexpected or frequent error responses (e.g., 403, 404, 5xx) that could indicate probing or attacks.
   * Unusual Response Size Detection: Detects abnormally large (potential data exfiltration) or unusually small (potential empty/malformed responses) successful responses.
   * Sensitive Data Leakage Detection: Scans API response bodies for patterns indicative of sensitive information (e.g., passwords, API keys) being unintentionally exposed.
 * Centralized Threat Logging: All detected threats (from email, SMS, or network sources) are logged into a unified detected_threats database for easy monitoring and analysis.
 * Visual Analytics Dashboard: Provides a web interface to view threat summaries, raw logs, and detailed insights.
Project Structure
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

Prerequisites
Before setting up the project, ensure you have the following installed:
 * Python 3.9+
 * pip (Python package installer)
 * PostgreSQL database server (e.g., PostgreSQL 14 or later)
 * psql command-line client (for database setup)
Setup Instructions
Follow these steps to get all services running locally.
1. Clone the Repository
git clone https://github.com/your-username/ZAMREN-Hackathon-Security-platform.git
cd ZAMREN-Hackathon-Security-platform

2. Database Setup (PostgreSQL)
You need to create a PostgreSQL database and a user for the application.
# Open your psql terminal (e.g., by running `psql -U postgres`)
psql -U postgres

# Create the database
CREATE DATABASE ids_db;

# Create a user and grant privileges (replace 'your_password' with a strong password)
CREATE USER ids_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE ids_db TO ids_user;

# Exit psql
\q

Important: You will need to configure your database connection string in detection_and_logging_system/database.py. Ensure it matches the user and password you just created.
# detection_and_logging_system/database.py
SQLALCHEMY_DATABASE_URL = "postgresql://ids_user:your_password@localhost/ids_db"

3. Virtual Environments and Dependencies
It's recommended to use separate virtual environments for each Python service to manage dependencies.
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
Open separate terminal windows for each service.
a. Main IDS (Detection and Logging System)
This is the core FastAPI application.
# In a new terminal, navigate to:
cd C:\Users\benso\Projects\ZAMREN Hackathon - Security platform\detection_and_logging_system

# Activate virtual environment
venv\Scripts\activate # On Windows

# Run the application
uvicorn main:app --reload --host 0.0.0.0 --port 8000

(Note: You might see a DeprecationWarning regarding on_event. This is a known FastAPI warning and does not affect functionality for this project.)
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

Once all services are running, you can access the main dashboard at http://localhost:5500 and the testing messaging system at http://localhost:5501.
Testing the New Network Analysis Features
These tests demonstrate the enhanced network monitoring capabilities of the Main IDS. Ensure all services are running as described above.
Important: Your Ubuntu VM's IP addresses (e.g., 192.168.56.101, 192.168.56.102) should be configured in detection_and_logging_system/network_analyzer.py under SUSPICIOUS_IPS for some tests to work correctly.
Test 1: Suspicious IP & Generic Request/Response Logging (from VM)
This verifies that the middleware logs every request and that suspicious IP detection works for any request from a flagged IP.
 * From a web browser inside one of your Ubuntu VMs, navigate to your testing frontend's login page: http://<YOUR_HOST_IP>:5501/login.html (e.g., http://192.168.56.1:5501/login.html).
 * Perform a single login attempt with incorrect credentials.
 * Check your Main IDS console logs:
   * You should see a Network event processed: ... log entry from the middleware.
   * You should see an ALERT !!! Detected Network Threat: suspicious_ip_source ... because the VM's IP is in your SUSPICIOUS_IPS list.
 * Check your Dashboard (http://localhost:5500):
   * Refresh your dashboard.
   * The "Suspicious IP Attempts" count should increase.
   * A new entry should appear in "Security Insights" with Source: NETWORK_IDS and Threat: suspicious_ip_source.
Test 2: Brute Force Attack (from VM)
This tests the combined brute-force and suspicious IP detection.
 * From the same Ubuntu VM browser you used in Test 1, continue making failed login attempts to the login page (http://<YOUR_HOST_IP>:5501/login.html).
 * Keep trying until you exceed your BRUTE_FORCE_THRESHOLD (default: 5).
 * Check your Main IDS console logs:
   * You'll continue to see Brute-force check for IP ...: [X] failed attempts... messages.
   * Once the threshold is met, you'll see repeated ALERT !!! Detected Network Threat: suspicious_ip_source_and_brute_force_attack ... (or just brute_force_attack if suspicious_ip_source was already logged as a separate threat before the combined one).
 * Check your Dashboard (http://localhost:5500):
   * Refresh your dashboard.
   * The "Brute Force Attacks" count should increase.
   * New entries in "Security Insights" will show Threat: brute_force_attack (and potentially combined with suspicious_ip_source).
Test 3: Unusual Response Status (from VM)
This tests the detection of unexpected HTTP status codes.
 * From a web browser inside one of your Ubuntu VMs, try to access a non-existent API endpoint on your Main IDS. For example, type this directly into the browser's address bar:
   http://<YOUR_HOST_IP>:8000/this-path-does-not-exist (e.g., http://192.168.56.1:8000/this-path-does-not-exist).
 * Check your Main IDS console logs:
   * You should see a Network event processed: Request: GET /this-path-does-not-exist | Response Status: 404 log.
   * You should see an ALERT !!! Detected Network Threat: unusual_response_status_404 ...
 * Check your Dashboard (http://localhost:5500):
   * Refresh your dashboard.
   * A new entry should appear in "Security Insights" with Source: NETWORK_IDS and Threat: unusual_response_status_404.
Test 4: Sensitive Data Leak in Response (Requires Temporary Code Change)
WARNING: This test requires a temporary modification to your main.py. REMEMBER TO REVERT THE CHANGE IMMEDIATELY AFTER TESTING!
 * Temporarily modify detection_and_logging_system/main.py:
   * Find a simple, unprotected GET endpoint (e.g., @app.get("/")).
   * Modify its return statement to include a sensitive-looking string that matches one of your SENSITIVE_DATA_PATTERNS defined in network_analyzer.py.
   <!-- end list -->
   # Example: Temporarily modify / to leak a password
@app.get("/")
async def read_root():
    # TEMPORARY TEST CODE - REMOVE AFTER TESTING!
    return JSONResponse(content={"message": "Welcome to IDS!", "user_password": "MySecretPassword123!"})

 * Restart your Main IDS.
 * From any browser (VM or host), access that modified endpoint:
   http://<YOUR_HOST_IP>:8000/ (or whatever endpoint you modified).
 * Check your Main IDS console logs:
   * You should see a Network event processed: ... log.
   * You should see an ALERT !!! Detected Network Threat: sensitive_data_leak_in_response_...
 * Check your Dashboard (http://localhost:5500):
   * Refresh your dashboard.
   * A new entry should appear in "Security Insights" with a Threat related to sensitive data leakage.
 * IMMEDIATELY REVERT THE CODE CHANGE IN main.py AND RESTART YOUR MAIN IDS.
For Teammates (Especially Email Manager)
Hi team!
This update brings a significant architectural change to how our Main IDS monitors network traffic. Previously, we had some IP-based logging happening within specific endpoints. This has now been centralized and greatly expanded.
Key points for your awareness:
 * Universal Network Monitoring: The detection_and_logging_system/main.py now includes a LoggingMiddleware. This middleware automatically intercepts every request and response that hits the Main IDS API. It logs comprehensive details (including source IP, path, method, response status, content length, and a snippet of the response body) into the network_logs table.
 * Redundant Logging Removed: Because of this middleware, I've removed the explicit actions.log_network_event and network_analyzer.analyze_network_event calls from individual endpoints like /token (for failed logins) and /ingest/raw-email-log (for the email source IP). The middleware now handles this generic network logging for all traffic.
 * Email Source IP: For the Email Manager, the source_ip field you send in RawEmailLogInput is still crucial for email-specific analysis. However, the IP that the Main IDS logs in network_logs for your /ingest/raw-email-log request will be the IP of the Email Manager service itself, not necessarily the original email sender's IP. If we need to perform network-level analysis on the original email sender's IP, we'll need to ensure that IP is passed in a details field within the RawEmailLogInput and then network_analyzer.py is updated to specifically look for it there during email ingestion analysis. For now, the network analysis focuses on traffic to/from the Main IDS.
 * New Schema Fields: The RawNetworkLogInput schema and the network_logs database table now include fields for response_status_code, response_content_length, and response_body_snippet. These are populated by the new middleware.
 * Review network_analyzer.py: Please take a look at detection_and_logging_system/network_analyzer.py. It now contains new functions (detect_sensitive_data_leak, detect_unusual_response_status, detect_unusual_response_size) that utilize these new response-related fields for advanced threat detection.
 * Action Naming Consistency: The middleware now generates action strings (like GET_THREAT_COUNTS) using underscores instead of hyphens to ensure consistency with the exclusion rules in network_analyzer.py.
This refactoring centralizes network monitoring, making the IDS more robust and easier to extend with new detection rules in the future. Feel free to reach out if you have any questions!
