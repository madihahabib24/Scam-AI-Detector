
from flask import Flask, request, jsonify, session
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime
from detector import analyze_input

app = Flask(__name__)

app.secret_key = "change-this-secret-key"
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

CORS(
    app,
    supports_credentials=True,
    origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "http://127.0.0.1:8000",
        "http://localhost:8000"
    ]
)

DATABASE = "users.db"


def connect_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def create_table():
    with connect_db() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                phone TEXT
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                input TEXT NOT NULL,
                verdict TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                scan_date TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "AI Scam Detector API"
    })


@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}

    name = data.get("name", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not name or not email or not password:
        return jsonify({"error": "All fields are required"}), 400

    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    hashed_password = generate_password_hash(password)

    try:
        with connect_db() as connection:
            connection.execute(
                "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                (name, email, hashed_password)
            )

        return jsonify({"message": "Account created successfully"}), 201

    except sqlite3.IntegrityError:
        return jsonify({"error": "Email already registered"}), 409


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    with connect_db() as connection:
        user = connection.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

    if user and check_password_hash(user["password"], password):
        session.clear()
        session["user_id"] = user["id"]
        return jsonify({"message": "Login successful"})

    return jsonify({"error": "Invalid email or password"}), 401


@app.route("/api/profile", methods=["GET"])
def get_profile():
    user_id = session.get("user_id")

    if not user_id:
        return jsonify({"error": "Please login first"}), 401

    with connect_db() as connection:
        user = connection.execute(
            "SELECT id, name, email, phone FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify(dict(user))


@app.route("/api/profile", methods=["PUT"])
def update_profile():
    user_id = session.get("user_id")

    if not user_id:
        return jsonify({"error": "Please login first"}), 401

    data = request.get_json(silent=True) or {}

    name = data.get("name", "").strip()
    phone = data.get("phone", "").strip()

    if not name:
        return jsonify({"error": "Name is required"}), 400

    with connect_db() as connection:
        connection.execute(
            "UPDATE users SET name = ?, phone = ? WHERE id = ?",
            (name, phone, user_id)
        )

    return jsonify({"message": "Profile updated successfully"})


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out successfully"})


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}

    user_input = data.get("input", "").strip()
    input_type = data.get("type", "auto")

    if not user_input:
        return jsonify({"error": "Please enter a URL or message"}), 400

    result = analyze_input(user_input, input_type)

    user_id = session.get("user_id")

    if user_id:
        with connect_db() as connection:
            connection.execute(
                """
                INSERT INTO scans
                (user_id, input, verdict, risk_level, scan_date)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    user_input,
                    result["verdict"],
                    result["risk_level"],
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                )
            )

    return jsonify(result)


@app.route("/api/history", methods=["GET"])
def scan_history():
    user_id = session.get("user_id")

    if not user_id:
        return jsonify({"error": "Please login first"}), 401

    with connect_db() as connection:
        scans = connection.execute(
            """
            SELECT id, input, verdict, risk_level, scan_date
            FROM scans
            WHERE user_id = ?
            ORDER BY id DESC
            """,
            (user_id,)
        ).fetchall()

    return jsonify([dict(scan) for scan in scans])
print(app.url_map)

if __name__ == "__main__":
    create_table()
    app.run(debug=True, port=5000)
