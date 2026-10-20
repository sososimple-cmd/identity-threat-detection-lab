"""Test detection conditions locally, without sending anything to a server."""
from collections import defaultdict
from datetime import datetime, timezone
from send_simulated_events import events, IP

rows = [ev for _, ev in events(datetime.now(timezone.utc))]
failed_accounts = defaultdict(set)
for e in rows:
    if e['event_type'] == 'login' and e['status'] == 'failed':
        failed_accounts[e['source_ip']].add(e['username'])
spray = len(failed_accounts[IP]) >= 5
terminated = any(e.get('event_type') == 'login' and e.get('status') == 'success' and e.get('employment_status') == 'terminated' for e in rows)
admin = any(e.get('event_type') == 'group_membership_added' and e.get('target_group') == 'Administrators' and e.get('approved') == 'no' for e in rows)
normal_below = len(failed_accounts['198.51.100.11']) < 5
for label, result in [('Password spray threshold', spray), ('Terminated identity successful login', terminated), ('Unapproved administrator addition', admin), ('Normal activity below spray threshold', normal_below)]:
    print(f'{"PASS" if result else "FAIL"}: {label}')
if not all([spray, terminated, admin, normal_below]):
    raise SystemExit(1)
print('All local scenario checks passed. Grafana detection rules must still be tested separately.')
