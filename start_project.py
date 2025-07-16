import subprocess
import os
import signal
import sys
import time

# --- Configuration ---
# Define the base directory of your project
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Define paths to each sub-project relative to BASE_DIR
MESSAGING_SYSTEM_DIR = os.path.join(BASE_DIR, "messaging_system_for_testing")
INTERFACE_SYSTEM_DIR = os.path.join(BASE_DIR, "interface_and_visual_analytics_system")
SMS_MANAGER_DIR = os.path.join(BASE_DIR, "sms_manager")
EMAIL_MANAGER_DIR = os.path.join(BASE_DIR, "email_manager")
IDS_DIR = os.path.join(BASE_DIR, "detection_and_logging_system")

# Define commands for each service
# For venv-activated services, construct the full path to uvicorn.exe
# Assumes 'venv' is the name of your virtual environment folder inside the manager directories.
SMS_UVICORN_PATH = os.path.join(SMS_MANAGER_DIR, 'venv', 'Scripts', 'uvicorn.exe')
IDS_UVICORN_PATH = os.path.join(IDS_DIR, 'venv', 'Scripts', 'uvicorn.exe')

SERVICES = [
    {
        "name": "Messaging System (Frontend)",
        "cmd": [sys.executable, "-m", "http.server", "5501"],
        "cwd": MESSAGING_SYSTEM_DIR,
    },
    {
        "name": "Interface System (Frontend)",
        "cmd": [sys.executable, "-m", "http.server", "5500"],
        "cwd": INTERFACE_SYSTEM_DIR,
    },
    {
        "name": "SMS Manager (FastAPI)",
        "cmd": [SMS_UVICORN_PATH, "main:app", "--reload", "--host", "0.0.0.0", "--port", "8001"],
        "cwd": SMS_MANAGER_DIR,
    },
    {
        "name": "Email Manager (FastAPI)",
        "cmd": [sys.executable, "-m", "uvicorn", "app:app", "--reload", "--host", "0.0.0.0", "--port", "5000"],
        "cwd": EMAIL_MANAGER_DIR,
    },
    {
        "name": "Main IDS (FastAPI)",
        "cmd": [IDS_UVICORN_PATH, "main:app", "--reload", "--host", "0.0.0.0", "--port", "8000"],
        "cwd": IDS_DIR,
    },
]

# List to hold subprocess Popen objects
running_processes = []

def start_service(service_config):
    """Starts a single service in a new subprocess and a new console window."""
    name = service_config["name"]
    cmd = service_config["cmd"]
    cwd = service_config["cwd"]

    print(f"Starting {name} in {cwd} with command: {' '.join(cmd)}")
    try:
        # Use subprocess.Popen to run the command in a new process.
        # CREATE_NEW_CONSOLE opens a new window, so stdout/stderr are not redirected here.
        process = subprocess.Popen(
            cmd,
            cwd=cwd,
            creationflags=subprocess.CREATE_NEW_CONSOLE # This opens a new console window
        )
        running_processes.append(process)
        print(f"  {name} started with PID: {process.pid}")
    except FileNotFoundError:
        print(f"ERROR: Command not found for {name}. Check path: {cmd[0]}")
    except Exception as e:
        print(f"ERROR: Failed to start {name}: {e}")

def stop_services():
    """Terminates all running services, attempting to close their console windows."""
    print("\nAttempting to stop all services...")
    for process in running_processes:
        if process.poll() is None:  # Check if process is still running
            name = SERVICES[running_processes.index(process)]["name"]
            print(f"Stopping {name} (PID: {process.pid})...")
            try:
                if sys.platform == 'win32':
                    # On Windows, sending CTRL_BREAK_EVENT is often more effective
                    # for closing console windows than terminate().
                    os.kill(process.pid, signal.CTRL_BREAK_EVENT)
                else:
                    process.terminate() # Standard termination for other OS
                
                process.wait(timeout=5) # Give it some time to terminate
                if process.poll() is None:
                    print(f"  {name} did not terminate gracefully, killing...")
                    process.kill() # Force kill if it didn't terminate
            except Exception as e:
                print(f"  Error stopping {name}: {e}")
        else:
            name = SERVICES[running_processes.index(process)]["name"]
            print(f"  {name} (PID: {process.pid}) already stopped.")
    print("All services stopped.")

def signal_handler(sig, frame):
    """Handles Ctrl+C signal for graceful shutdown."""
    print("\nCtrl+C detected. Initiating graceful shutdown...")
    stop_services()
    sys.exit(0)

if __name__ == "__main__":
    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    print("--- Starting ZAMREN Hackathon Security Platform Components ---")
    print("Press Ctrl+C to stop all services.")
    print("-" * 60)

    # Start all services
    for service in SERVICES:
        start_service(service)
        time.sleep(1) # Give a moment for each service to start

    print("-" * 60)
    print("All services launched. Monitoring for shutdown...")

    try:
        # Keep the main script running indefinitely until Ctrl+C
        while True:
            for i, p in enumerate(running_processes):
                if p.poll() is not None:
                    print(f"WARNING: {SERVICES[i]['name']} (PID: {p.pid}) has exited unexpectedly!")
            time.sleep(5)
    except KeyboardInterrupt:
        pass
    finally:
        stop_services()
