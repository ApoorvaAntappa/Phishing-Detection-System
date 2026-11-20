import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))
import imaplib
import email
import time
import os
from email.header import decode_header
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from detection.email_detector import detect_email
from database.db_logger import save_email, save_alert


load_dotenv()

EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_APP_PASSWORD = os.getenv("EMAIL_APP_PASSWORD")
IMAP_SERVER = os.getenv("IMAP_SERVER", "imap.gmail.com")
IMAP_PORT = int(os.getenv("IMAP_PORT", "993"))

CHECK_INTERVAL = 30
seen_email_ids = set()


def clean_text(text):
    if not text:
        return ""

    decoded_parts = decode_header(text)
    final_text = ""

    for part, encoding in decoded_parts:
        if isinstance(part, bytes):
            final_text += part.decode(encoding or "utf-8", errors="ignore")
        else:
            final_text += part

    return final_text


def extract_body(msg):
    body = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition"))

            if "attachment" in disposition:
                continue

            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue

                text = payload.decode(errors="ignore")

                if content_type == "text/plain":
                    body += text

                elif content_type == "text/html":
                    soup = BeautifulSoup(text, "html.parser")
                    body += soup.get_text(" ")

            except Exception:
                pass

    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode(errors="ignore")

    return body


def connect_mail():
    mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
    mail.login(EMAIL_ADDRESS, EMAIL_APP_PASSWORD)
    mail.select("inbox")
    return mail


def scan_latest_emails():
    mail = connect_mail()

    status, data = mail.search(None, "ALL")

    if status != "OK":
        print("Unable to fetch emails")
        mail.logout()
        return

    email_ids = data[0].split()

    latest_ids = email_ids[-10:]

    for eid in latest_ids:
        eid_str = eid.decode()

        if eid_str in seen_email_ids:
            continue

        seen_email_ids.add(eid_str)

        status, msg_data = mail.fetch(eid, "(RFC822)")

        if status != "OK":
            continue

        for response_part in msg_data:
            if not isinstance(response_part, tuple):
                continue

            msg = email.message_from_bytes(response_part[1])

            sender = clean_text(msg.get("From"))
            subject = clean_text(msg.get("Subject"))
            body = extract_body(msg)

            result_status, risk, link = detect_email(sender, subject, body)

            save_email(sender, subject, link, result_status, risk)

            print("\n" + "=" * 60)
            print("New Email Detected")
            print("From   :", sender)
            print("Subject:", subject)
            print("Status :", result_status)
            print("Risk   :", risk)

            if result_status == "PHISHING":
                alert_msg = f"PHISHING EMAIL DETECTED: {subject} | From: {sender} | Risk: {risk}%"
                save_alert(alert_msg, "HIGH")

            elif result_status == "SUSPICIOUS":
                alert_msg = f"SUSPICIOUS EMAIL DETECTED: {subject} | From: {sender} | Risk: {risk}%"
                save_alert(alert_msg, "MEDIUM")

    mail.logout()


def start_email_monitor():
    print("=" * 70)
    print("LIVE GMAIL PHISHING MONITOR STARTED")
    print("Press CTRL + C to stop")
    print("=" * 70)

    while True:
        try:
            scan_latest_emails()
            time.sleep(CHECK_INTERVAL)

        except KeyboardInterrupt:
            print("\nEmail monitor stopped.")
            break

        except Exception as e:
            print("Email Monitor Error:", e)
            time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    start_email_monitor()