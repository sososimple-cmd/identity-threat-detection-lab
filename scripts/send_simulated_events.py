#!/usr/bin/env python3
"""Generate fictional IAM security events; send only to authorized Loki lab."""
import argparse, datetime as dt, json, os, urllib.request, urllib.error

LABELS = {'job': 'identity_detection_lab', 'scenario': 'billy_kaplan'}
IP = '203.0.113.25' # Documentation-only IP (RFC 5737)

def events(now):
    base = now - dt.timedelta(seconds=60)
    out = []
    def add(seconds, **fields):
        out.append((base + dt.timedelta(seconds=seconds), {'event_source':'synthetic_iam_lab', **fields}))
    add(0, event_type='login', username='maria', status='success', source_ip='198.51.100.10', employment_status='active')
    add(1, event_type='login', username='maria', status='failed', source_ip='198.51.100.11', employment_status='active')
    for i, username in enumerate(['alex', 'brianna', 'carlos', 'dina', 'evan', 'fatima']):
        add(5 + i * 2, event_type='login', username=username, status='failed', source_ip=IP, employment_status='active')
    add(25, event_type='login', username='billy.kaplan', status='success', source_ip=IP, employment_status='terminated')
    add(30, event_type='group_membership_added', actor='billy.kaplan', username='billy.kaplan', target_user='billy.kaplan', target_group='Administrators', approved='no', source_ip=IP)
    return out

def main():
    parser = argparse.ArgumentParser()
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument('--dry-run', action='store_true', help='Print synthetic events only')
    actions.add_argument('--send', action='store_true', help='Push synthetic logs to authorized Loki endpoint')
    args = parser.parse_args()
    rows = events(dt.datetime.now(dt.timezone.utc))
    if args.dry_run:
        for t, event in rows:
            print(t.isoformat(), json.dumps(event, sort_keys=True))
        print(f'DRY RUN OK: {len(rows)} synthetic events; nothing sent.')
        return
    url = os.getenv('LOKI_PUSH_URL', '').strip()
    if not url.startswith(('http://', 'https://')) or not url.endswith('/loki/api/v1/push'):
        parser.error('Set LOKI_PUSH_URL to instructor-authorized Loki HTTP push endpoint (ending /loki/api/v1/push).')
    payload = {'streams': [{'stream': LABELS, 'values': [[str(int(t.timestamp() * 1_000_000_000)), json.dumps(e, separators=(',', ':'))] for t, e in rows]}]}
    request = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={'Content-Type': 'application/json'}, method='POST')
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            print(f'SENT {len(rows)} synthetic events to Loki; HTTP {response.status}.')
    except urllib.error.HTTPError as error:
        print(f'LOKI ERROR HTTP {error.code}: {error.read(400).decode(errors="replace")}')
        raise SystemExit(1)
    except Exception as error:
        print(f'LOKI CONNECTION ERROR: {error}')
        raise SystemExit(1)

if __name__ == '__main__':
    main()
