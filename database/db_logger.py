import mysql.connector
from datetime import datetime

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "Apoorva@16",
    "database": "phishing_detection"
}


def get_connection():
    return mysql.connector.connect(**DB_CONFIG)


# ---------------- SAVE URL ---------------- #

def save_url(url, domain, status, risk_score):
    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO detected_urls
            (url, domain_name, status, risk_score, capture_time)
            VALUES (%s,%s,%s,%s,%s)
        """, (
            url,
            domain,
            status,
            risk_score,
            datetime.now()
        ))

        conn.commit()

        cur.close()
        conn.close()

        print("Saved URL:", domain)

    except Exception as e:
        print("save_url Error:", e)


# ---------------- SAVE EMAIL ---------------- #

def save_email(sender, subject, link, status, risk_score):
    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO phishing_emails
            (sender_email,subject,malicious_link,status,risk_score,capture_time)
            VALUES (%s,%s,%s,%s,%s,%s)
        """, (
            sender,
            subject,
            link,
            status,
            risk_score,
            datetime.now()
        ))

        conn.commit()

        cur.close()
        conn.close()

        print("Saved Email:", sender)

    except Exception as e:
        print("save_email Error:", e)


# ---------------- SAVE ALERT ---------------- #

def save_alert(message, severity):
    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO alerts
            (alert_message,severity,created_at)
            VALUES (%s,%s,%s)
        """, (
            message,
            severity,
            datetime.now()
        ))

        conn.commit()

        cur.close()
        conn.close()

        print("Alert Saved")

    except Exception as e:
        print("save_alert Error:", e)