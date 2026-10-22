
#!/usr/bin/env python3
"""Generate and correlate synthetic IAM security events for Loki."""

import argparse
import datetime as dt
import json
import os
import urllib.request
import urllib.error

from correlate_identity_events import find_ghost_logins
from correlate_privilege_changes import find_suspicious_admin_changes

LABELS = {
    "job": "identity_detection_lab",
    "scenario": "billy_kaplan"
}

# Documentation-only test IP (RFC 5737).
IP = "203.0.113.25"


def events(now):
    # Start four minutes before the present time.
    # This gives our spray attempts a realistic timeline
    # while keeping them inside a five-minute window.
    base = now - dt.timedelta(minutes=4)
    out = []

    def add(seconds, **fields):
        out.append((
            base + dt.timedelta(seconds=seconds),
            {"event_source": "synthetic_iam_lab", **fields}
        ))

    # Normal successful authentication
    add(
        0,
        event_type="login",
        username="maria",
        status="success",
        source_ip="198.51.100.10"
    )

    # Normal failed login from a different IP
    add(
        1,
        event_type="login",
        username="maria",
        status="failed",
        source_ip="198.51.100.11"
    )

    # PASSWORD SPRAY
    # Six different accounts targeted from one source IP.
    # Attempts occur 30 seconds apart.
    spray_users = [
        "alex",
        "brianna",
        "carlos",
        "dina",
        "evan",
        "fatima"
    ]

    for i, username in enumerate(spray_users):
        add(
            5 + i * 30,
            event_type="login",
            username=username,
            status="failed",
            source_ip=IP
        )

    # GHOST ACCOUNT
    # Successful authentication without HR employment status.
    # The separate HR CSV is used by our correlation program.
    add(
        175,
        event_type="login",
        username="billy.kaplan",
        status="success",
        source_ip=IP
    )

    # UNAUTHORIZED PRIVILEGE CHANGE
    add(
        180,
        event_type="group_membership_added",
        actor="billy.kaplan",
        username="billy.kaplan",
        target_user="billy.kaplan",
        target_group="Administrators",
        change_id="CHG-9001",
        source_ip=IP
    )

    return out


def main():
    parser = argparse.ArgumentParser()

    actions = parser.add_mutually_exclusive_group(required=True)

    actions.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview events without sending them"
    )

    actions.add_argument(
        "--send",
        action="store_true",
        help="Send events to authorized Loki endpoint"
    )

    args = parser.parse_args()

    # Generate original synthetic events
    raw_rows = events(dt.datetime.now(dt.timezone.utc))

    # Correlate authentication activity against HR records
    findings = find_ghost_logins(raw_rows)
    admin_findings = find_suspicious_admin_changes(raw_rows)

    # Combine source events and derived findings
    rows = sorted(
        raw_rows + findings + admin_findings,
        key=lambda item: item[0]
    )

    if args.dry_run:
        for timestamp, event in rows:
            print(
                timestamp.isoformat(),
                json.dumps(event, sort_keys=True)
            )

        print(
            f"DRY RUN OK: {len(rows)} synthetic events; nothing sent."
        )

        print(
            f"CORRELATION: {len(findings)} ghost-account finding(s)."
        )

        print(
            "SPRAY TIMING: 6 attempts across 150 seconds."
        )

        return

    # Verify instructor-authorized Loki endpoint
    url = os.getenv("LOKI_PUSH_URL", "").strip()

    if (
        not url.startswith(("http://", "https://"))
        or not url.endswith("/loki/api/v1/push")
    ):
        parser.error(
            "Set LOKI_PUSH_URL to the instructor-authorized "
            "Loki push endpoint ending /loki/api/v1/push."
        )

    payload = {
        "streams": [{
            "stream": LABELS,
            "values": [
                [
                    str(int(timestamp.timestamp() * 1_000_000_000)),
                    json.dumps(event, separators=(",", ":"))
                ]
                for timestamp, event in rows
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
                f"SENT {len(rows)} synthetic events "
                f"to Loki; HTTP {response.status}."
            )

            print(
                f"CORRELATION: {len(findings)} ghost-account finding(s)."
            )

    except urllib.error.HTTPError as error:
        print(
            f"LOKI ERROR HTTP {error.code}: "
            f'{error.read(400).decode(errors="replace")}'
        )
        raise SystemExit(1)

    except Exception as error:
        print(f"LOKI CONNECTION ERROR: {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
