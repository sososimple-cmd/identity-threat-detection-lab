
"""Correlate authentication logs with separate HR termination records."""

import csv
import json
from datetime import datetime, date, timezone
from pathlib import Path

HR_FILE = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "terminated_users.csv"
)


def find_ghost_logins(event_rows):
    # STEP 1: Read the HR termination list.
    with HR_FILE.open(newline="", encoding="utf-8") as file:
        terminated = {
            row["username"].strip().casefold():
                date.fromisoformat(row["termination_date"].strip())
            for row in csv.DictReader(file)
        }

    findings = []

    # STEP 2: Read each authentication event.
    for timestamp, event in event_rows:
        username = str(event.get("username", "")).strip().casefold()
        termination_date = terminated.get(username)

        # STEP 3: Compare authentication and HR records.
        if (
            event.get("event_type") == "login"
            and event.get("status") == "success"
            and termination_date is not None
            and timestamp.date() > termination_date
        ):
            findings.append((
                timestamp,
                {
                    "event_source": "hr_auth_correlation_lab",
                    "event_type": "ghost_account_finding",
                    "username": username,
                    "auth_status": "success",
                    "source_ip": event.get("source_ip", ""),
                    "termination_date": termination_date.isoformat(),
                    "reason": "successful_login_after_termination_date"
                }
            ))

    return findings


if __name__ == "__main__":
    from send_simulated_events import events

    now = datetime.now(timezone.utc)

    # Generate authentication test events.
    findings = find_ghost_logins(events(now))

    # Active employee should not trigger detection.
    active_test = [
        (
            now,
            {
                "event_type": "login",
                "username": "maria",
                "status": "success"
            }
        )
    ]

    # Login before termination should not trigger detection.
    before_test = [
        (
            datetime(2026, 10, 9, tzinfo=timezone.utc),
            {
                "event_type": "login",
                "username": "billy.kaplan",
                "status": "success"
            }
        )
    ]

    checks = {
        "Terminated employee detected":
            len(findings) == 1
            and findings[0][1]["username"] == "billy.kaplan",

        "Active employee ignored":
            len(find_ghost_logins(active_test)) == 0,

        "Pre-termination login ignored":
            len(find_ghost_logins(before_test)) == 0
    }

    for name, passed in checks.items():
        print(f'{"PASS" if passed else "FAIL"}: {name}')

    for timestamp, finding in findings:
        print(
            "CORRELATED FINDING:",
            timestamp.isoformat(),
            json.dumps(finding)
        )

    if not all(checks.values()):
        raise SystemExit(1)
