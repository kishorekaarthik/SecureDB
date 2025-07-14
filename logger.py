import requests
import json
from datetime import datetime

SPLUNK_URL = "http://localhost:8088/services/collector"
SPLUNK_TOKEN = "a5f1e706-6748-43ac-8443-64c6c1df2812"

def log_event(action, user="admin"):
    payload = {
        "time": datetime.now().timestamp(),
        "host": "securedb",
        "source": "secure-ui",
        "sourcetype": "_json",
        "event": {
            "user": user,
            "action": action,
            "timestamp": str(datetime.now())
        }
    }
    headers = {"Authorization": f"Splunk {SPLUNK_TOKEN}"}
    try:
        requests.post(SPLUNK_URL, headers=headers, data=json.dumps(payload))
    except Exception as e:
        print("Splunk logging failed:", e)
