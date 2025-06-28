from flask import Flask, render_template, request, redirect, url_for, session
from datetime import datetime
import sqlite3
import os
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "devkey")
DB_PATH = "db.sqlite3"

# 방문자 로그 저장 함수
def log_visit(ip, user_agent, url):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS visits_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT,
                    user_agent TEXT,
                    accessed_url TEXT,
                    timestamp TEXT
                )''')
    c.execute('''INSERT INTO visits_log (ip_address, user_agent, accessed_url, timestamp)
                 VALUES (?, ?, ?, ?)''', (ip, user_agent, url, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

@app.before_request
def track_visit():
    if not request.path.startswith("/admin"):
        log_visit(request.remote_addr, request.user_agent.string, request.path)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if username == "HaiCryptid":
            stored_hash = os.environ.get("ADMIN_PASSWORD_HASH")
            if stored_hash and check_password_hash(stored_hash, password):
                session["admin"] = True
                return redirect(url_for("dashboard"))
        return "Login failed", 401

    return render_template("admin_login.html")

@app.route("/admin/dashboard")
def dashboard():
    if not session.get("admin"):
        return redirect(url_for("admin"))

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT ip_address, accessed_url, timestamp FROM visits_log ORDER BY timestamp DESC LIMIT 50")
    logs = c.fetchall()
    conn.close()
    
    return render_template("dashboard.html", logs=logs)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
