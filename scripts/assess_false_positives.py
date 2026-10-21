"""Analyze false-positive scenarios for the password-spray rule.

All events are synthetic. Nothing is sent to Loki.
"""

from datetime import datetime, timedelta, timezone

THRESHOLD = 5
START = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)
EVALUATION = START + timedelta(minutes=4)


def make_events(ip, usernames, interval=30):
    return [
        {
            "timestamp": START + timedelta(seconds=i * interval),
            "event_type": "login",
            "status": "failed",
            "source_ip": ip,
            "username": username,
        }
        for i, username in enumerate(usernames)
    ]


def distinct_failed_accounts(events):
    window_start = EVALUATION - timedelta(minutes=5)

    return len({
        e["username"]
        for e in events
        if e["event_type"] == "login"
        and e["status"] == "failed"
        and window_start < e["timestamp"] <= EVALUATION
    })


attack = make_events(
    "203.0.113.25",
    ["alex", "brianna", "carlos", "dina", "evan", "fatima"]
)

# Known-benign synthetic fixture: six users behind one VPN IP.
vpn = make_events(
    "198.51.100.200",
    ["anna", "ben", "chris", "david", "emma", "frank"]
)

# A broken service account repeatedly fails, but is only one identity.
service = make_events(
    "192.0.2.50",
    ["backup_service"] * 20,
    interval=8
)

normal = make_events(
    "198.51.100.11",
    ["maria"]
)

cases = [
    ("Simulated password spray", attack, 6, True),
    ("Benign shared-VPN burst", vpn, 6, True),
    ("Repeating service-account failure", service, 1, False),
    ("Isolated normal failure", normal, 1, False),
]

print("\nPASSWORD SPRAY - FALSE POSITIVE ANALYSIS")
print("-" * 58)

all_passed = True

for name, events, expected_count, expected_alert in cases:
    count = distinct_failed_accounts(events)
    alerts = count >= THRESHOLD

    passed = (
        count == expected_count
        and alerts == expected_alert
    )

    all_passed = all_passed and passed

    print(
        f'{"PASS" if passed else "FAIL"}: {name} '
        f'- {count} accounts, alert={alerts}'
    )

print("-" * 58)

if not all_passed:
    raise SystemExit("FAILED: Review scenario results.")

print("SUCCESS: All 4 scenario checks passed!")
print("FINDING: Benign shared-IP activity can meet the spray threshold.")
print("LIMITATION: This is a local rule-model test, not a Loki test.")
print("RECOMMENDATION: Baseline, enrich, and tune before production.")
