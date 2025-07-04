from flask import Flask, render_template, request, redirect, url_for, session
from datetime import datetime
import sqlite3
import os
from werkzeug.security import check_password_hash
from dotenv import load_dotenv
from datetime import datetime, timedelta

load_dotenv()

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")

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
    if not (request.path.startswith("/favicon.ico") or request.path.startswith("/static")):
        log_visit(request.remote_addr, request.user_agent.string, request.path)


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if username == ADMIN_USERNAME:
            if ADMIN_PASSWORD_HASH and check_password_hash(ADMIN_PASSWORD_HASH, password):
                session["admin"] = True
                return redirect(url_for("dashboard"))
        
        return "로그인 실패! 다시 확인해주세요.", 401

    return render_template("adminLogin.html")

@app.route("/admin/dashboard")
def dashboard():
    if not session.get("admin"):
        return redirect(url_for("admin"))

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT ip_address, accessed_url, timestamp FROM visits_log ORDER BY timestamp DESC LIMIT 50")
    logs = c.fetchall()
    conn.close()

    # logs는 [(ip, url, timestamp_str), ...] 꼴이니까, timestamp_str을 KST로 변환
    logs_kst = []
    for ip, url, timestamp_str in logs:
        # ISO 형식 문자열을 datetime으로 변환
        utc_dt = datetime.fromisoformat(timestamp_str)
        # 9시간 더하기
        kst_dt = utc_dt + timedelta(hours=9)
        # 보기 좋은 포맷으로 변환 (예: 2025-07-04 14:17:30)
        kst_str = kst_dt.strftime("%Y-%m-%d %H:%M:%S")
        logs_kst.append((ip, url, kst_str))
    
    return render_template("dashboard.html", logs=logs_kst)

@app.route("/admin/dashboard/clear", methods=["POST"])
def clear_logs():
    if not session.get("admin"):
        return redirect(url_for("admin"))
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM visits_log")
    conn.commit()
    conn.close()
    return redirect(url_for("dashboard"))

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True, port=5000)