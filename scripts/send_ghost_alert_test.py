"""Safely test the ghost-account alert with HR-correlated lab events."""

import argparse
import json
import os
import urllib.request
from datetime import datetime, timezone

from correlate_identity_events import find_ghost_logins
from send_simulated_events import IP, LABELS

parser = argparse.ArgumentParser()
actions = parser.add_mutually_exclusive_group(required=True)
actions.add_argument("--dry-run", action="store_true")
actions.add_argument("--send", action="store_true")
args = parser.parse_args()

now = datetime.now(timezone.utc)

login = {
    "event_source": "synthetic_iam_lab",
    "event_type": "login",
    "username": "billy.kaplan",
    "status": "success",
    "source_ip": IP,
    "lab_test": "ghost_alert_firing"
}

findings = find_ghost_logins([(now, login)])

if len(findings) != 1:
    raise SystemExit("ERROR: Expected exactly one HR-correlated finding.")

finding = findings[0][1].copy()
finding["lab_test"] = "ghost_alert_firing"

print("GHOST ACCOUNT ALERT TEST")
print("-" * 40)
print("Synthetic login: billy.kaplan")
print("HR correlation: 1 ghost-account finding")
print("Password-spray attempts: 0")
print("Administrator changes: 0")

if args.dry_run:
    print("DRY RUN OK: 2 records prepared; nothing sent.")
    raise SystemExit(0)

url = os.environ.get("LOKI_PUSH_URL", "").strip()

if (
    not url.startswith(("http://", "https://"))
    or not url.endswith("/loki/api/v1/push")
):
    raise SystemExit("ERROR: Authorized LOKI_PUSH_URL is missing.")

timestamp = int(now.timestamp() * 1_000_000_000)

payload = {
    "streams": [{
        "stream": LABELS,
        "values": [
            [str(timestamp), json.dumps(login)],
            [str(timestamp + 1), json.dumps(finding)]
        ]
    }]
}

request = urllib.request.Request(
    url,
    data=json.dumps(payload).encode("utf-8"),
    headers={"Content-Type": "application/json"},
    method="POST"
)

try:
    with urllib.request.urlopen(request, timeout=15) as response:
        print(f"SENT 2 lab records to Loki; HTTP {response.status}.")
except Exception as error:
    raise SystemExit(f"LOKI SEND ERROR: {error}")
