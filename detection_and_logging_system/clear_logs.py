# Create a new file, for example: clear_logs.py
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base

# Assuming your database setup is in 'database.py' and models in 'models.py'
# You'll need to import your actual database engine and models
from database import SessionLocal, engine # Assuming these are defined in database.py
import models # Assuming your models are defined here, e.g., models.NetworkEventLog

def truncate_network_event_log():
    """Deletes all records from the network_event_log table."""
    with SessionLocal() as db:
        try:
            # Delete all rows from the NetworkEventLog table
            # This is equivalent to TRUNCATE TABLE for most databases when used without a WHERE clause,
            # though it performs row-by-row deletion in SQLite.
            db.query(models.NetworkEventLog).delete()
            db.commit()
            print("NetworkEventLog table truncated successfully.")
        except Exception as e:
            db.rollback()
            print(f"Error truncating table: {e}")

if __name__ == "__main__":
    # Optional: Ensure tables are created if you're running this script standalone
    # and want to ensure the table exists before truncating.
    # models.Base.metadata.create_all(bind=engine) # Uncomment if you need to ensure table creation
    
    truncate_network_event_log()
    print("Database cleanup script finished.")