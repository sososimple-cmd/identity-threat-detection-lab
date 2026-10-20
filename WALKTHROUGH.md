# Ghost Account: Guided lab walkthrough

## 0. Scope and safety
This project **does not perform real login attempts or change real users**. The data is synthetic. OrangeHRM and Authentik are context, not directly queried by these scripts. Instructor's normal authentication logs (if any) are separate Loki streams. Send events **only** if instructor authorizes ingestion to the lab endpoint. Do not put credentials, private URLs, or tokens in public GitHub.

## 1. Verify Grafana
- Open Grafana -> Dashboards -> Detection Lab -> Detection Lab - Starter, if accessible.
- Open Explore and select **loki** (lower-case shown in some installations).
- If Explore shows '0 queries' and '0 rows,' this is not yet evidence of no logs. Click **Label browser** to see available streams. Or use Code mode to query a known stream.
- Screenshot `evidence/screenshots/01-grafana-starter.png` after verifying the starter dashboard.

## 2. Inspect Python and test locally
Unzip this folder and open it with VS Code. In terminal / PowerShell:

```powershell
py --version
py scripts/send_simulated_events.py --dry-run
py scripts/validate_detection.py
```

Save screenshots `02-vscode-python.png` and `03-python-local-tests.png`.

## 3. Push synthetic logs to Loki (requires instructor authorization)
In PowerShell, set the instructor-provided endpoint privately (do not paste this in GitHub):

```powershell
$env:LOKI_PUSH_URL = "http://HOST:PORT/loki/api/v1/push"
py scripts/send_simulated_events.py --send
```

A successful Loki push usually returns HTTP 204. If it fails, capture the error but **do not share sensitive tokens**. The endpoint is HTTP: use only fictional events and no credentials.

## 4. Investigate in Grafana
- Explore -> Loki -> switch from Builder to Code mode.
- Set range to **Last 15 minutes** and run `queries/01-all-events.logql` (paste the query, not the filename).
- If no results, set range to **Last 1 hour**, verify stream labels, or ask instructor whether the endpoint is ingesting to the selected Loki datasource.
- Take screenshot `04-loki-events.png`.

## 5. Write LogQL detections
Paste in each query file's text from `queries/` and run:
- `02-password-spray.logql`: counts DISTINCT failed usernames per IP across five minutes, not just attempts.
- `03-terminated-login.logql`: success with synthetic employment_status=terminated.
- `04-admin-addition.logql`: unapproved addition to Administrators.
- Screenshot `05-password-spray-query.png`, `06-terminated-login-query.png`, `07-admin-addition-query.png`.
- For metric queries, use recent data; the five-minute window expires. Re-send synthetic events once before alert testing if necessary.

## 6. Create dashboard and alert
- In Grafana -> Dashboards -> New dashboard, create panels using queries above. Set panel type Time series for metric queries, Logs or Table for log queries.
- Screenshot `08-detection-dashboard.png`.
- Alerting -> Alert rules -> New alert rule (if permissions allow). Use `queries/05-admin-addition-alert.logql`, Reduce/last, threshold >0, and a short evaluation interval supported by lab. Re-run sender to test and wait for evaluation. Screenshot `09-alert-configuration.png` and **only if firing** `10-alert-firing.png`.
- If you do not have alert permissions, document that limitation truthfully.

## 7. Validate/interpret findings
- Password spray: at least five different accounts with failed logins from same source IP in 5m.
- Terminated-account success: suspicious in this synthetic case, but production requires authoritative HR correlation.
- Administrator addition: only suspicious because synthetic approval field says no; real detection needs change-ticket and entitlement context.
- Consider false positives from misconfigured clients, shared NAT IPs, stale HR state, and expected IT maintenance.

## 8. Publish
- Add your ACTUAL screenshots into `evidence/screenshots/`.
- Write observed counts/timestamps and lessons learned in README; differentiate expected from observed.
- Publish to your GitHub only after removing private server URLs and secrets.
