from flask import Flask, render_template, request, redirect, session, jsonify
from flask_mysqldb import MySQL

from detection.url_detector import detect_url
from detection.email_detector import detect_email
from database.db_logger import save_url, save_email, save_alert

app = Flask(__name__)
app.secret_key = "phishing_detection_secret_key"

app.config["MYSQL_HOST"] = "localhost"
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = "Apoorva@16"
app.config["MYSQL_DB"] = "phishing_detection"

mysql = MySQL(app)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login")
def login_page():
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    try:
        cur = mysql.connection.cursor()
        cur.execute(
            "SELECT * FROM users WHERE username=%s AND password=%s",
            (username, password)
        )
        user = cur.fetchone()
        cur.close()

        if user:
            session["loggedin"] = True
            session["username"] = username
            return redirect("/dashboard")

        return """
        <h2>Invalid username or password</h2>
        <a href="/login">Go back</a>
        """

    except Exception as e:
        return f"""
        <h2>Database Error</h2>
        <p>{str(e)}</p>
        <a href="/login">Go back</a>
        """


@app.route("/dashboard")
def dashboard():
    if "loggedin" not in session:
        return redirect("/login")

    return render_template(
        "dashboard.html",
        username=session.get("username", "admin")
    )


@app.route("/api/dashboard")
def dashboard_api():
    try:
        cur = mysql.connection.cursor()

        cur.execute("SELECT COUNT(*) FROM detected_urls")
        total_urls = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM detected_urls WHERE status='SAFE'")
        safe_urls = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM detected_urls WHERE status='PHISHING'")
        phishing_urls = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM detected_urls WHERE status='SUSPICIOUS'")
        suspicious_urls = cur.fetchone()[0]

        cur.execute("""
            SELECT id, url, domain_name, status, risk_score, capture_time
            FROM detected_urls
            ORDER BY id DESC
            LIMIT 20
        """)

        rows = cur.fetchall()
        cur.close()

        urls = []
        for row in rows:
            urls.append({
                "id": row[0],
                "url": row[1],
                "domain": row[2],
                "status": row[3],
                "risk": row[4],
                "time": str(row[5])
            })

        return jsonify({
            "total": total_urls,
            "safe": safe_urls,
            "phishing": phishing_urls,
            "suspicious": suspicious_urls,
            "urls": urls
        })

    except Exception as e:
        return jsonify({
            "error": str(e),
            "total": 0,
            "safe": 0,
            "phishing": 0,
            "suspicious": 0,
            "urls": []
        })


@app.route("/api/emails")
def emails_api():
    try:
        cur = mysql.connection.cursor()

        cur.execute("""
            SELECT id, sender_email, subject, malicious_link, status, risk_score, capture_time
            FROM phishing_emails
            ORDER BY id DESC
            LIMIT 20
        """)

        rows = cur.fetchall()
        cur.close()

        emails = []
        for row in rows:
            emails.append({
                "id": row[0],
                "sender": row[1],
                "subject": row[2],
                "link": row[3],
                "status": row[4],
                "risk": row[5],
                "time": str(row[6])
            })

        return jsonify({"emails": emails})

    except Exception as e:
        return jsonify({
            "error": str(e),
            "emails": []
        })


@app.route("/api/alerts")
def alerts_api():
    try:
        cur = mysql.connection.cursor()

        cur.execute("""
            SELECT id, alert_message, severity, created_at
            FROM alerts
            ORDER BY id DESC
            LIMIT 15
        """)

        rows = cur.fetchall()
        cur.close()

        alerts = []
        for row in rows:
            alerts.append({
                "id": row[0],
                "message": row[1],
                "severity": row[2],
                "time": str(row[3])
            })

        return jsonify({"alerts": alerts})

    except Exception as e:
        return jsonify({
            "error": str(e),
            "alerts": []
        })


@app.route("/check_url", methods=["POST"])
def check_url():
    url = request.form.get("url", "").strip()

    if not url:
        return jsonify({
            "url": "",
            "domain": "",
            "status": "SUSPICIOUS",
            "risk_score": 50,
            "message": "URL is empty"
        })

    result = detect_url(url)

    save_url(
        result["url"],
        result["domain"],
        result["status"],
        result["risk_score"]
    )

    if result["status"] == "PHISHING":
        save_alert(
            f"Phishing URL detected: {result['domain']} | Risk: {result['risk_score']}%",
            "HIGH"
        )

    elif result["status"] == "SUSPICIOUS":
        save_alert(
            f"Suspicious URL detected: {result['domain']} | Risk: {result['risk_score']}%",
            "MEDIUM"
        )

    return jsonify(result)


@app.route("/check_email", methods=["POST"])
def check_email():
    sender = request.form.get("sender", "").strip()
    subject = request.form.get("subject", "").strip()
    body = request.form.get("body", "").strip()

    if sender == "" and subject == "" and body == "":
        return jsonify({
            "status": "SUSPICIOUS",
            "risk_score": 50,
            "link": "",
            "message": "Email content is empty"
        })

    status, risk, link = detect_email(sender, subject, body)

    save_email(sender, subject, link, status, risk)

    if status == "PHISHING":
        save_alert(
            f"Phishing email detected from {sender} | Subject: {subject} | Risk: {risk}%",
            "HIGH"
        )

    elif status == "SUSPICIOUS":
        save_alert(
            f"Suspicious email detected from {sender} | Subject: {subject} | Risk: {risk}%",
            "MEDIUM"
        )

    return jsonify({
        "status": status,
        "risk_score": risk,
        "link": link
    })


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True,
        use_reloader=False
    )