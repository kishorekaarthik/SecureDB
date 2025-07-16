import requests
import json
from datetime import datetime
import urllib3
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --------------------
# 🔸 Splunk HEC Config (for Logging Events)
# --------------------
HEC_URL = "http://localhost:8088/services/collector"
HEC_TOKEN = "YOUR_SPLUNK_HEC_TOKEN"
HEC_SOURCETYPE = "securedb"

def log_event(action, user="admin"):
    payload = {
        "time": datetime.now().timestamp(),
        "host": "securedb",
        "source": "secure-ui",
        "sourcetype": HEC_SOURCETYPE,
        "event": {
            "user": user,
            "action": action,
            "timestamp": str(datetime.now())
        }
    }
    headers = {"Authorization": f"Splunk {HEC_TOKEN}"}
    try:
        requests.post(HEC_URL, headers=headers, data=json.dumps(payload), verify=False)
    except Exception as e:
        print("Splunk logging failed:", e)


# --------------------
# 🔸 Splunk REST API Config (for Fetching Logs)
# --------------------
API_URL = "https://localhost:8089"
SPLUNK_USER = "admin"
SPLUNK_PASS = "admin123"
SPLUNK_INDEX = "main"
CERT_PATH = "splunk_cert.pem"  # Set to False to skip cert validation

def get_ssl_verify():
    """Return correct verify argument based on CERT_PATH existence."""
    return CERT_PATH if os.path.isfile(CERT_PATH) else False

def fetch_splunk_logs(limit=50):
    search_query = f"search index={SPLUNK_INDEX} sourcetype=\"{HEC_SOURCETYPE}\" | sort -_time | head {limit}"

    try:
        # Step 1: Start the search job
        resp = requests.post(
            f"{API_URL}/services/search/jobs",
            auth=(SPLUNK_USER, SPLUNK_PASS),
            data={
                "search": search_query,
                "output_mode": "json",
                "exec_mode": "blocking"
            },
            verify=get_ssl_verify()
        )
        sid = resp.json().get("sid")
        if not sid:
            return ["Could not start search job"]

        # Step 2: Fetch search results
        results = requests.get(
            f"{API_URL}/services/search/jobs/{sid}/results",
            params={"output_mode": "json"},
            auth=(SPLUNK_USER, SPLUNK_PASS),
            verify=get_ssl_verify()
        )
        entries = results.json().get("results", [])
        logs = [entry.get("_raw", json.dumps(entry)) for entry in entries]
        return logs

    except Exception as e:
        return [f"Could not fetch logs from Splunk: {e}"]
