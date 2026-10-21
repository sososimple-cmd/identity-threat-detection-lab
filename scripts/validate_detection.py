
"""Validate simulated IAM detection scenarios locally."""

from collections import defaultdict
from datetime import datetime, timezone

from send_simulated_events import events, IP
from correlate_identity_events import find_ghost_logins


def main():
    # Generate our 10 original synthetic events.
    event_rows = events(datetime.now(timezone.utc))
    raw_events = [event for _, event in event_rows]

    # TEST 1: Password spray
    failed_accounts = defaultdict(set)

    for event in raw_events:
        if (
            event.get("event_type") == "login"
            and event.get("status") == "failed"
        ):
            failed_accounts[event["source_ip"]].add(
                event["username"]
            )

    spray_detected = len(failed_accounts[IP]) == 6

    # TEST 2: Correlate HR termination with authentication.
    ghost_findings = find_ghost_logins(event_rows)

    ghost_detected = (
        len(ghost_findings) == 1
        and ghost_findings[0][1]["username"] == "billy.kaplan"
    )

    # TEST 3: Unauthorized administrator addition
    admin_detected = any(
        event.get("event_type") == "group_membership_added"
        and event.get("target_group") == "Administrators"
        and event.get("approved") == "no"
        for event in raw_events
    )

    # TEST 4: Normal activity should not trigger spray
    normal_activity_safe = (
        len(failed_accounts["198.51.100.11"]) < 5
    )

    # TEST 5: Active employee should not trigger ghost detection
    active_employee_safe = (
        not any(
            finding["username"] == "maria"
            for _, finding in ghost_findings
        )
    )

    checks = [
        ("Password spray detected", spray_detected),
        ("Ghost account correlated with HR", ghost_detected),
        ("Unauthorized admin change detected", admin_detected),
        ("Normal authentication ignored", normal_activity_safe),
        ("Active employee ignored", active_employee_safe),
    ]

    print("\nIDENTITY THREAT DETECTION - VALIDATION")
    print("-" * 45)

    for name, passed in checks:
        result = "PASS" if passed else "FAIL"
        print(f"{result}: {name}")

    print("-" * 45)

    if all(passed for _, passed in checks):
        print("SUCCESS: All 5 local validation tests passed!")
    else:
        print("FAILED: One or more tests failed.")
        raise SystemExit(1)

    print(
        "NOTE: This validates Python logic, not Loki queries "
        "or Grafana alert execution."
    )


if __name__ == "__main__":
    main()
