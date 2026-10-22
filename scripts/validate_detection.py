"""Validate simulated IAM detection scenarios locally."""

from collections import defaultdict
from datetime import datetime, timezone

from send_simulated_events import events, IP
from correlate_identity_events import find_ghost_logins
from correlate_privilege_changes import find_suspicious_admin_changes


def main():
    # Generate the 10 original synthetic events.
    event_rows = events(datetime.now(timezone.utc))
    raw_events = [event for _, event in event_rows]

    # TEST 1: Password spray.
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

    # TEST 2: HR-to-authentication correlation.
    ghost_findings = find_ghost_logins(event_rows)

    ghost_detected = (
        len(ghost_findings) == 1
        and ghost_findings[0][1]["username"] == "billy.kaplan"
    )

    # TEST 3: Independent change-approval correlation.
    admin_findings = find_suspicious_admin_changes(event_rows)

    admin_detected = (
        len(admin_findings) == 1
        and admin_findings[0][1]["event_type"]
            == "suspicious_admin_change_finding"
        and admin_findings[0][1]["change_id"] == "CHG-9001"
        and admin_findings[0][1]["target_group"]
            == "Administrators"
        and admin_findings[0][1]["reason"]
            == "no_valid_matching_change_approval"
        and all(
            "approved" not in event
            for event in raw_events
            if event.get("event_type") == "group_membership_added"
        )
    )

    # TEST 4: Normal activity must not trigger a spray.
    normal_activity_safe = (
        len(failed_accounts["198.51.100.11"]) < 5
    )

    # TEST 5: Active employee must not trigger ghost detection.
    active_employee_safe = (
        not any(
            finding["username"] == "maria"
            for _, finding in ghost_findings
        )
    )

    checks = [
        ("Password spray detected", spray_detected),
        ("Ghost account correlated with HR", ghost_detected),
        ("Approval-correlated admin change detected", admin_detected),
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
