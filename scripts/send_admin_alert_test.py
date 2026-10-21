"""Test unauthorized administrator change detection safely."""

import argparse
import json
import os
import urllib.request
from datetime import datetime, timezone

from send_simulated_events import IP, LABELS

parser = argparse.ArgumentParser()
actions = parser.add_mutually_exclusive_group(required=True)

actions.add_argument("--dry-run", action="store_true")
actions.add_argument("--send", action="store_true")

args = parser.parse_args()

now = datetime.now(timezone.utc)

event = {
    "event_source": "synthetic_iam_lab",
    "event_type": "group_membership_added",
    "actor": "billy.kaplan",
    "username": "billy.kaplan",
    "target_user": "billy.kaplan",
    "target_group": "Administrators",
    "approved": "no",
    "source_ip": IP,
    "lab_test": "admin_alert_firing"
}

print("\nUNAUTHORIZED ADMIN CHANGE ALERT TEST")
print("-" * 45)
print("Actor: billy.kaplan")
print("Target group: Administrators")
print("Approved: no")
print("Admin change events: 1")
print("Password spray attempts: 0")
print("Ghost-account findings: 0")

if args.dry_run:
    print("DRY RUN OK: 1 synthetic event; nothing sent.")
    raise SystemExit(0)

url = os.environ.get("LOKI_PUSH_URL", "").strip()

if (
    not url.startswith(("http://", "https://"))
    or not url.endswith("/loki/api/v1/push")
):
    raise SystemExit("ERROR: Authorized LOKI_PUSH_URL is missing.")

timestamp = str(int(now.timestamp() * 1_000_000_000))

payload = {
    "streams": [{
        "stream": LABELS,
        "values": [
            [timestamp, json.dumps(event)]
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
        print(
            f"SENT 1 synthetic admin-change event "
            f"to Loki; HTTP {response.status}."
        )
except Exception as error:
    raise SystemExit(f"LOKI SEND ERROR: {error}")
