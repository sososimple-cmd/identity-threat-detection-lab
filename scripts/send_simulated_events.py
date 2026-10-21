
#!/usr/bin/env python3
"""Generate and correlate synthetic IAM security events for Loki."""

import argparse
import datetime as dt
import json
import os
import urllib.request
import urllib.error

from correlate_identity_events import find_ghost_logins

LABELS = {
    'job': 'identity_detection_lab',
    'scenario': 'billy_kaplan'
}

# Documentation-only IP address
IP = '203.0.113.25'


def events(now):
    base = now - dt.timedelta(seconds=60)
    out = []

    def add(seconds, **fields):
        out.append((
            base + dt.timedelta(seconds=seconds),
            {'event_source': 'synthetic_iam_lab', **fields}
        ))

    # Normal employee authentication
    add(
        0,
        event_type='login',
        username='maria',
        status='success',
        source_ip='198.51.100.10'
    )

    add(
        1,
        event_type='login',
        username='maria',
        status='failed',
        source_ip='198.51.100.11'
    )

    # Simulated password spray
    for i, username in enumerate([
        'alex', 'brianna', 'carlos',
        'dina', 'evan', 'fatima'
    ]):
        add(
            5 + i * 2,
            event_type='login',
            username=username,
            status='failed',
            source_ip=IP
        )

    # Successful login without HR employment status
    add(
        25,
        event_type='login',
        username='billy.kaplan',
        status='success',
        source_ip=IP
    )

    # Unauthorized administrator group change
    add(
        30,
        event_type='group_membership_added',
        actor='billy.kaplan',
        username='billy.kaplan',
        target_user='billy.kaplan',
        target_group='Administrators',
        approved='no',
        source_ip=IP
    )

    return out


def main():
    parser = argparse.ArgumentParser()

    actions = parser.add_mutually_exclusive_group(required=True)

    actions.add_argument(
        '--dry-run',
        action='store_true',
        help='Print synthetic events without sending'
    )

    actions.add_argument(
        '--send',
        action='store_true',
        help='Send to authorized Loki endpoint'
    )

    args = parser.parse_args()

    # STEP 1: Generate synthetic authentication events
    raw_rows = events(dt.datetime.now(dt.timezone.utc))

    # STEP 2: Compare authentication events against HR data
    findings = find_ghost_logins(raw_rows)

    # STEP 3: Combine the raw events and correlated findings
    rows = sorted(
        raw_rows + findings,
        key=lambda item: item[0]
    )

    # STEP 4: Safe dry-run preview
    if args.dry_run:
        for timestamp, event in rows:
            print(
                timestamp.isoformat(),
                json.dumps(event, sort_keys=True)
            )

        print(
            f'DRY RUN OK: {len(rows)} synthetic events; nothing sent.'
        )

        print(
            f'CORRELATION: {len(findings)} ghost-account finding(s).'
        )

        return

    # STEP 5: Verify authorized Loki endpoint
    url = os.getenv('LOKI_PUSH_URL', '').strip()

    if (
        not url.startswith(('http://', 'https://'))
        or not url.endswith('/loki/api/v1/push')
    ):
        parser.error(
            'Set LOKI_PUSH_URL to instructor-authorized '
            'Loki HTTP push endpoint '
            '(ending /loki/api/v1/push).'
        )

    # STEP 6: Prepare Loki payload
    payload = {
        'streams': [{
            'stream': LABELS,
            'values': [
                [
                    str(int(timestamp.timestamp() * 1_000_000_000)),
                    json.dumps(event, separators=(',', ':'))
                ]
                for timestamp, event in rows
            ]
        }]
    }

    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={'Content-Type': 'application/json'},
        method='POST'
    )

    # STEP 7: Send events to Loki
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            print(
                f'SENT {len(rows)} synthetic events '
                f'to Loki; HTTP {response.status}.'
            )

            print(
                f'CORRELATION: {len(findings)} ghost-account finding(s).'
            )

    except urllib.error.HTTPError as error:
        print(
            f'LOKI ERROR HTTP {error.code}: '
            f'{error.read(400).decode(errors="replace")}'
        )
        raise SystemExit(1)

    except Exception as error:
        print(f'LOKI CONNECTION ERROR: {error}')
        raise SystemExit(1)


if __name__ == '__main__':
    main()
