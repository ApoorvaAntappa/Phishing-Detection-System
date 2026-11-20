import sys
import time
from pathlib import Path

import pyshark

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))

from detection.url_detector import detect_url
from database.db_logger import save_url, save_alert

INTERFACE_NAME = "Wi-Fi"
DUPLICATE_WAIT_SECONDS = 120

seen_domains = {}

print("=" * 70)
print("REAL-TIME WEBSITE PHISHING MONITOR STARTED")
print("Press CTRL + C to stop")
print("=" * 70)

capture = pyshark.LiveCapture(
    interface=INTERFACE_NAME,
    display_filter="dns.qry.name"
)

try:
    for packet in capture.sniff_continuously():
        try:
            if not hasattr(packet, "dns"):
                continue

            domain = packet.dns.qry_name

            if not domain:
                continue

            domain = domain.lower().strip(".")
            now = time.time()

            if domain in seen_domains:
                if now - seen_domains[domain] < DUPLICATE_WAIT_SECONDS:
                    continue

            seen_domains[domain] = now

            url = "https://" + domain
            result = detect_url(url)

            print("\n" + "=" * 60)
            print("Domain Detected :", result["domain"])
            print("Status          :", result["status"])
            print("Risk Score      :", result["risk_score"], "%")

            save_url(
                result["url"],
                result["domain"],
                result["status"],
                result["risk_score"]
            )

            if result["status"] == "PHISHING":
                save_alert(
                    f"⚠ PHISHING WEBSITE DETECTED: {result['domain']} | Risk: {result['risk_score']}%",
                    "HIGH"
                )
                print("ALERT           : HIGH")

            elif result["status"] == "SUSPICIOUS":
                save_alert(
                    f"⚠ SUSPICIOUS WEBSITE DETECTED: {result['domain']} | Risk: {result['risk_score']}%",
                    "MEDIUM"
                )
                print("ALERT           : MEDIUM")

        except Exception as e:
            print("Packet Error:", e)

except KeyboardInterrupt:
    print("\nLive monitor stopped successfully.")