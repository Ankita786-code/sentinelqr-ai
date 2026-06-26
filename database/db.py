import sqlite3
import os

# -----------------------------
# Database Path
# -----------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "analytics.db")


# -----------------------------
# Database Connection
# -----------------------------

def connect():
    """
    Connect to SQLite database.
    Creates the database and scans table if they do not exist.
    """

    conn = sqlite3.connect(DB_PATH)

    conn.execute("PRAGMA foreign_keys = ON")

    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        user_ip TEXT,

        qr_url TEXT,

        risk_score INTEGER,

        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP

    )
    """)

    conn.commit()

    return conn