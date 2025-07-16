from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base # Import Base from your models

# Your PostgreSQL connection string
# Replace 'ids_user', 'your_password', 'localhost', 'ids_db' with your actual details
SQLALCHEMY_DATABASE_URL = "postgresql://postgres:nosneb1010?@localhost/ids_db"

# Create the SQLAlchemy engine
engine = create_engine(SQLALCHEMY_DATABASE_URL)

# Create a SessionLocal class to get database sessions
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# This is for creating tables if not using Alembic or for initial setup.
# Base.metadata.create_all(bind=engine) # This line can also be in main.py, or handled by Alembic

# Dependency function to provide a database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()