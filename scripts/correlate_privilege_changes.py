"""Correlate admin group changes with independent approval records."""

import csv
from datetime import datetime, timezone
from pathlib import Path

APPROVAL_FILE = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "admin_change_approvals.csv"
)


def find_suspicious_admin_changes(event_rows):
    # Read approval records independently from the event logs.
    with APPROVAL_FILE.open(newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)
        required = {
            "change_id", "actor", "target_user", "target_group",
            "event_type", "status", "valid_from", "valid_until"
        }
        if not required.issubset(reader.fieldnames or []):
            raise ValueError("Approval CSV is missing required columns")
        approvals = list(reader)

    findings = []

    for timestamp, event in event_rows:
        # Only investigate additions to the Administrators group.
        if event.get("event_type") != "group_membership_added":
            continue
        if str(event.get("target_group", "")).casefold() != "administrators":
            continue

        change_id = str(event.get("change_id", "")).strip()
        actor = str(event.get("actor", "")).strip().casefold()
        target_user = str(event.get("target_user", "")).strip().casefold()

        valid_approval = False

        for record in approvals:
            # A ticket must match every relevant attribute.
            if not change_id:
                break

            if not (
                record["change_id"].strip() == change_id
                and record["actor"].strip().casefold() == actor
                and record["target_user"].strip().casefold() == target_user
                and record["target_group"].strip().casefold()
                    == "administrators"
                and record["event_type"].strip()
                    == "group_membership_added"
                and record["status"].strip().casefold() == "approved"
            ):
                continue

            start = datetime.fromisoformat(
                record["valid_from"].strip().replace("Z", "+00:00")
            )
            end = datetime.fromisoformat(
                record["valid_until"].strip().replace("Z", "+00:00")
            )

            if start <= timestamp <= end:
                valid_approval = True
                break

        if not valid_approval:
            findings.append((
                timestamp,
                {
                    "event_source": "approval_correlation_lab",
                    "event_type": "suspicious_admin_change_finding",
                    "change_id": change_id,
                    "actor": actor,
                    "target_user": target_user,
                    "target_group": "Administrators",
                    "source_ip": event.get("source_ip", ""),
                    "reason": "no_valid_matching_change_approval"
                }
            ))

    return findings


if __name__ == "__main__":
    now = datetime(2026, 10, 22, 12, tzinfo=timezone.utc)

    def sample(actor, change_id, group="Administrators"):
        return [(now, {
            "event_type": "group_membership_added",
            "actor": actor,
            "target_user": actor,
            "target_group": group,
            "change_id": change_id
        })]

    def flagged(rows):
        return len(find_suspicious_admin_changes(rows)) == 1

    valid = sample("maria", "CHG-1001")

    # Deliberately lie in the log field.
    # The independent approval must still determine the result.
    valid[0][1]["approved"] = "no"

    checks = {
        "Valid approval stays quiet":
            not flagged(valid),

        "Untrusted approved field ignored":
            not flagged(valid),

        "Wrong-group approval detected":
            flagged(sample("billy.kaplan", "CHG-9001")),

        "Expired approval detected":
            flagged(sample("billy.kaplan", "CHG-9002")),

        "Rejected approval detected":
            flagged(sample("billy.kaplan", "CHG-9003")),

        "Missing ticket detected":
            flagged(sample("billy.kaplan", "")),

        "Non-admin change ignored":
            len(find_suspicious_admin_changes(
                sample("billy.kaplan", "", "Remote Desktop Users")
            )) == 0
    }

    for name, passed in checks.items():
        print(f'{"PASS" if passed else "FAIL"}: {name}')

    if not all(checks.values()):
        raise SystemExit(1)

    print("ALL 7 ADMIN-CORRELATION CHECKS PASSED")
