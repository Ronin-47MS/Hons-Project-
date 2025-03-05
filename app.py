from flask import Flask, render_template, jsonify
import sqlite3
from datetime import datetime
import joblib
import os

app = Flask(__name__)

# Calculate the correct paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODEL_PATH = os.path.join(BASE_DIR, "models", "label_encoder.joblib")
DB_PATH = os.path.join(BASE_DIR, "detections.db")

# Load label encoder and create LABEL_MAP dynamically
label_encoder = joblib.load(MODEL_PATH)
LABEL_MAP = dict(enumerate(label_encoder.classes_))
# Verify against your provided mapping:
# LABEL_MAP = {0: 'BENIGN', 1: 'Bot', 2: 'DDoS', 3: 'DoS GoldenEye', 4: 'DoS Hulk', 
#              5: 'DoS Slowhttptest', 6: 'DoS slowloris', 7: 'FTP-Patator', 8: 'Heartbleed', 
#              9: 'Infiltration', 10: 'PortScan', 11: 'SSH-Patator', 12: 'Web Attack – Brute Force', 
#              13: 'Web Attack – Sql Injection', 14: 'Web Attack – XSS'}

# Custom datetime filter for Jinja2
def datetime_filter(value):
    try:
        return datetime.fromtimestamp(float(value)).strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        return "Invalid timestamp"

app.jinja_env.filters['datetime'] = datetime_filter

def init_db():
    """Initialize the database with required table if it doesn't exist."""
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                classification INTEGER NOT NULL
            )
        """)
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database initialization error: {e}")
    finally:
        conn.close()

def get_db_connection():
    """Connect to SQLite database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        print(f"Database connection error: {e}")
        return None

@app.route('/')
def dashboard():
    """Render the dashboard with recent detections and statistics."""
    try:
        conn = get_db_connection()
        if not conn:
            return "Database connection error", 500
        
        # Fetch recent detections
        detections = conn.execute(
            "SELECT * FROM detections ORDER BY timestamp DESC LIMIT 100"
        ).fetchall()
        
        # Convert numeric classification to attack type
        detections_with_types = [
            dict(row, classification=LABEL_MAP.get(int(row['classification']), "Unknown"))
            for row in detections
        ]
        
        # Fetch statistics (count of each attack type)
        stats = conn.execute(
            "SELECT classification, COUNT(*) as count FROM detections GROUP BY classification"
        ).fetchall()
        stats_dict = {LABEL_MAP.get(int(row['classification']), "Unknown"): row['count'] for row in stats}
        
        return render_template('dashboard.html', detections=detections_with_types, stats=stats_dict)
    except Exception as e:
        print(f"Dashboard error: {e}")
        return f"An error occurred: {str(e)}", 500
    finally:
        if conn:
            conn.close()

@app.route('/api/detections')
def api_detections():
    """API endpoint for real-time updates."""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection error"}), 500
        
        detections = conn.execute(
            "SELECT * FROM detections ORDER BY timestamp DESC LIMIT 100"
        ).fetchall()
        return jsonify([dict(row, classification=LABEL_MAP.get(int(row['classification']), "Unknown")) for row in detections])
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/stats')
def api_stats():
    """API endpoint for attack type statistics."""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection error"}), 500
        
        stats = conn.execute(
            "SELECT classification, COUNT(*) as count FROM detections GROUP BY classification"
        ).fetchall()
        return jsonify({LABEL_MAP.get(int(row['classification']), "Unknown"): row['count'] for row in stats})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()

# Initialize database when starting the app
init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)