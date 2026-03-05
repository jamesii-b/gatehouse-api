"""Initialize database script."""
import sys
import os
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from gatehouse_app import create_app
from gatehouse_app.extensions import db
from sqlalchemy import text
from dotenv import load_dotenv
import os
import time

# Load environment variables
load_dotenv()

# Create application
app = create_app()

import gatehouse_app.models  

with app.app_context():
    # Drop all tables, constraints, and indexes cleanly
    db_url = os.getenv("DATABASE_URL", "")
    db_name = db_url.split("/")[-1] if db_url else "gatehouse_db"
    print(f"⚠️  WARNING: About to drop all tables in database '{db_name}'!")
    print("Countdown to deletion:")
    for i in range(5, 0, -1):
        print(f"{i}...")
        time.sleep(1)
    db.session.execute(text("DROP SCHEMA public CASCADE"))
    db.session.execute(text("CREATE SCHEMA public"))
    db.session.commit()

    # Create all tables
    print("Creating all tables...")
    db.create_all()

    print("Database initialized successfully!")
