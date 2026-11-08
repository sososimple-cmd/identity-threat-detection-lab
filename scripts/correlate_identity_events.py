
"""Correlate authentication logs with separate HR termination records."""

import csv
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

HR_FILE = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "terminated_users.csv"
)


def find_ghost_logins(event_rows):
    # STEP 1: Read the HR termination list.
    with HR_FILE.open(newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        required = {"username", "termination_date", "termination_timestamp"}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError("HR CSV requires an explicit termination_timestamp")

        terminated = {}
        for row in reader:
            username = row["username"].strip().casefold()
            recorded = row["termination_timestamp"].strip()
            terminated_at = datetime.fromisoformat(recorded.replace("Z", "+00:00"))
            if terminated_at.tzinfo is None or terminated_at.utcoffset() is None:
                raise ValueError("Termination timestamps must include a timezone")
            terminated[username] = terminated_at.astimezone(timezone.utc)

    findings = []

    # STEP 2: Read each authentication event.
    for timestamp, event in event_rows:
        username = str(event.get("username", "")).strip().casefold()
        termination_at = terminated.get(username)

        # STEP 3: Compare authentication and HR records.
        if (
            event.get("event_type") == "login"
            and event.get("status") == "success"
            and termination_at is not None
            and timestamp.tzinfo is not None
            and timestamp.utcoffset() is not None
            and timestamp.astimezone(timezone.utc) > termination_at
        ):
            findings.append((
                timestamp,
                {
                    "event_source": "hr_auth_correlation_lab",
                    "event_type": "ghost_account_finding",
                    "username": username,
                    "auth_status": "success",
                    "source_ip": event.get("source_ip", ""),
                    "termination_date": termination_at.date().isoformat(),
                    "termination_timestamp": termination_at.isoformat(),
                    "reason": "successful_login_after_termination_timestamp"
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

    # A fixed, synthetic UTC termination timestamp enables same-day tests.
    termination_at = datetime(2026, 10, 10, 12, tzinfo=timezone.utc)

    def billy_login(when):
        return [(when, {
            "event_type": "login",
            "username": "billy.kaplan",
            "status": "success"
        })]

    checks = {
        "Terminated employee detected":
            len(findings) == 1
            and findings[0][1]["username"] == "billy.kaplan",

        "Active employee ignored":
            len(find_ghost_logins(active_test)) == 0,

        "Prior-day login ignored":
            len(find_ghost_logins(billy_login(
                datetime(2026, 10, 9, 23, tzinfo=timezone.utc)
            ))) == 0,

        "Same-day before termination ignored":
            len(find_ghost_logins(billy_login(
                termination_at - timedelta(minutes=1)
            ))) == 0,

        "Exactly at termination not treated as after":
            len(find_ghost_logins(billy_login(termination_at))) == 0,

        "Same-day after termination detected":
            len(find_ghost_logins(billy_login(
                termination_at + timedelta(minutes=1)
            ))) == 1,

        "Timezone-offset login after termination detected":
            len(find_ghost_logins(billy_login(
                datetime.fromisoformat("2026-10-10T08:01:00-04:00")
            ))) == 1
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
