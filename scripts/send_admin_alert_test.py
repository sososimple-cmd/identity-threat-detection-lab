"""Safely test the approval-correlated administrator-change alert."""

import argparse
import json
import os
import urllib.request
from datetime import datetime, timezone

from correlate_privilege_changes import find_suspicious_admin_changes
from send_simulated_events import IP, LABELS


def main():
    parser = argparse.ArgumentParser()

    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--dry-run", action="store_true")
    actions.add_argument("--send", action="store_true")

    args = parser.parse_args()

    now = datetime.now(timezone.utc)

    # STEP 1: Generate a synthetic group-change event.
    # No approval status is embedded in this event.
    event = {
        "event_source": "synthetic_iam_lab",
        "event_type": "group_membership_added",
        "actor": "billy.kaplan",
        "username": "billy.kaplan",
        "target_user": "billy.kaplan",
        "target_group": "Administrators",
        "change_id": "CHG-9001",
        "source_ip": IP,
        "lab_test": "admin_alert_firing"
    }

    # STEP 2: Correlate against the independent approval CSV.
    findings = find_suspicious_admin_changes([(now, event)])

    if len(findings) != 1:
        raise SystemExit(
            "ERROR: Expected exactly one approval-correlated finding."
        )

    finding = findings[0][1].copy()
    finding["lab_test"] = "admin_alert_firing"

    if (
        finding.get("event_type")
        != "suspicious_admin_change_finding"
        or finding.get("change_id") != "CHG-9001"
    ):
        raise SystemExit("ERROR: Unexpected correlation result.")

    print("\nAPPROVAL-CORRELATED ADMIN CHANGE ALERT TEST")
    print("-" * 50)
    print("Actor: billy.kaplan")
    print("Target group: Administrators")
    print("Change ticket: CHG-9001")
    print("Independent approval: Wrong group")
    print("Original event contains approval field: False")
    print("Suspicious admin findings: 1")
    print("Password spray attempts: 0")
    print("Ghost-account findings: 0")

    # STEP 3: Preview without sending anything.
    if args.dry_run:
        print("\nSOURCE EVENT:")
        print(json.dumps(event, indent=2, sort_keys=True))

        print("\nCORRELATED FINDING:")
        print(json.dumps(finding, indent=2, sort_keys=True))

        print("\nDRY RUN OK: 2 lab records prepared; nothing sent.")
        return

    # STEP 4: Require the instructor-authorized Loki endpoint.
    url = os.environ.get("LOKI_PUSH_URL", "").strip()

    if (
        not url.startswith(("http://", "https://"))
        or not url.endswith("/loki/api/v1/push")
    ):
        raise SystemExit(
            "ERROR: Instructor-authorized LOKI_PUSH_URL is missing."
        )

    # STEP 5: Send the original event and derived finding.
    timestamp = int(now.timestamp() * 1_000_000_000)

    payload = {
        "streams": [{
            "stream": LABELS,
            "values": [
                [str(timestamp), json.dumps(event)],
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
        with urllib.request.urlopen(
            request, timeout=15
        ) as response:
            print(
                f"SENT 2 approval-correlated lab records "
                f"to Loki; HTTP {response.status}."
            )
    except Exception as error:
        raise SystemExit(f"LOKI SEND ERROR: {error}")


if __name__ == "__main__":
    main()
