# The Ghost Account: Identity Threat Detection Lab

**The Employee Left. Their Access Didn't.**

*Detecting password spraying, suspicious terminated-account authentication, and unauthorized privilege changes using Python, Grafana Loki, and LogQL.*

**Technologies:** Python 3 · OrangeHRM · Authentik · Grafana Loki · LogQL · Grafana

**Status:** Implementation completed and validated | October 2026

---

## 1. The Problem — When Identity Controls Fail, Who Detects It?

Employee termination should trigger the removal of access to corporate systems. However, organizations can still face security risks from compromised credentials, stale permissions, unauthorized privilege changes, and gaps in identity monitoring.

A security team needs to answer three critical questions:

- Can we identify password-spraying activity before an attacker compromises an account?
- Can we detect suspicious authentication involving a terminated identity?
- Can we identify unauthorized privilege changes before they go unnoticed?

**Business impact:** Without adequate detection coverage, suspicious account activity may remain undetected, increasing the risk of unauthorized access, data exposure, and privileged-account compromise.

The challenge was to build a monitoring solution that could identify these behaviors, distinguish suspicious activity from ordinary authentication failures, and produce actionable alerts.

## 2. The Solution — Building an Identity Threat Detection Pipeline

I developed an identity threat detection pipeline using **Python, Grafana Loki, LogQL, and Grafana** to identify suspicious authentication and privileged-access activity.

The solution uses structured security events to detect three identity threats:

1. **Password spraying:** Multiple accounts targeted by failed logins from the same source IP.
2. **Terminated-account access:** Successful authentication associated with a terminated employee.
3. **Unauthorized privilege escalation:** An unapproved addition to the Administrators group.

I also configured an automated Grafana alert to identify password-spraying activity when five or more distinct accounts experienced failed authentication from the same IP within five minutes.

The detection logic was validated through controlled, synthetic attack scenarios.

## 3. How I Implemented the Solution

| Phase | Engineering work performed |
|---|---|
| Identity verification | Reviewed Billy Kaplan's termination in OrangeHRM and confirmed his Authentik account was inactive |
| Event generation | Developed and executed Python scripts generating 10 structured synthetic security events |
| Log ingestion | Sent JSON events into Grafana Loki using its HTTP ingestion API |
| Detection engineering | Implemented three LogQL queries targeting password spraying, terminated-account logins, and unauthorized administrator assignments |
| Security monitoring | Built a three-panel Grafana dashboard to investigate suspicious activity |
| Automated alerting | Configured a threshold-based password-spray alert with a one-minute evaluation interval |
| Validation | Tested suspicious and normal activity, confirmed log ingestion, and verified Grafana alert state history |

### Detection Pipeline

```text
HR / Identity Verification
          |
          v
Python Security Event Generator
          |
          v
Grafana Loki — Centralized Logs
          |
          v
LogQL — Detection Logic
          |
          v
Grafana — Investigation Dashboard
          |
          v
Automated Password-Spray Alert
          |
          v
Security Investigation and Validation
```

The HR and identity records provide verified lifecycle context. The authentication and privilege-change incident itself was simulated rather than executed against actual user accounts.

## 4. Results — What the Solution Detected

| Detection or validation | Observed result |
|---|---|
| Password spraying | 6 distinct accounts targeted from one source IP |
| Normal failed authentication | 1 account from a separate IP, below the threshold |
| Terminated identity authentication | 1 matching synthetic successful-login event |
| Unauthorized administrator assignment | 1 matching synthetic privilege-change event |
| Python validation tests | 4 of 4 passed |
| Loki ingestion | HTTP 204 success |
| Grafana investigation | 10 synthetic events retrieved |
| Automated password-spray alert | Successfully entered Alerting/Firing state |

**Key outcome:** The detection pipeline distinguished a simulated password-spray pattern from normal failed authentication and generated an automated security alert that was confirmed through Grafana's recorded state history.

The terminated-login and administrator-change scenarios were validated through LogQL investigation queries. These were not separately configured as automatic alerts.

## 5. Security Investigation — The Ghost Account

Billy Kaplan's HR record documented termination on October 10, 2026. An account review confirmed the corresponding Authentik identity was inactive.

To test detection coverage against a hypothetical security control failure, I generated synthetic events representing:

1. Failed authentication attempts against six accounts.
2. A successful login involving Billy's terminated identity.
3. An unapproved administrator-group membership addition.

The password-spray rule identified the simulated source IP `203.0.113.25` and returned a distinct-account count of six.

The automatic alert was configured to evaluate every minute and trigger when the count exceeded four.

Grafana state history confirmed:

```text
Source IP: 203.0.113.25
Distinct accounts: 6
Alert threshold: > 4
Query result: A=6.000000
Condition result: C=1.000000
Alert state: Alerting
```

No actual authentication or privilege change was performed against Billy's disabled account.

## 6. Detection Queries and Technical Details

The repository's `queries/` directory contains the LogQL implementations for:

- Password-spray detection using a five-minute rolling window and distinct username counts.
- Successful-login investigation for terminated identities.
- Detection of unapproved Administrators group membership additions.

The `scripts/` directory contains the Python event generator and local validation logic.

The accompanying documentation explains how the detection scenarios were reproduced, investigated, and tested.

## 7. Challenges and Troubleshooting

During implementation, Grafana initially failed to retrieve Loki logs because of incorrectly configured data source connections.

I separated ingestion testing from query troubleshooting, verified Loki readiness, confirmed successful HTTP event ingestion, and established a working Grafana data source connection.

After resolving the configuration issue, I validated the query results and configured an automated alert.

This reinforced the importance of troubleshooting the complete security monitoring pipeline rather than assuming that successful log ingestion guarantees successful alerting.

## 8. Lessons Learned and Future Improvements

This project reinforced several detection engineering principles:

- **Detection quality:** Counting distinct accounts helps distinguish password spraying from repeated failures against one account.
- **Identity context:** HR termination records and identity-provider status provide important context for investigating authentication anomalies.
- **Alert validation:** A successful LogQL query does not guarantee that an alert rule will fire. Evaluation frequency, thresholds, and state transitions must be tested.
- **Operational visibility:** Troubleshooting ingestion, data sources, queries, and alert conditions is essential to reliable security monitoring.

Future improvements include integrating authoritative identity lifecycle data with live authentication events, adding automated alerts for privilege changes and terminated-account logins, implementing Sigma rules, and creating incident-response playbooks.

## 9. Project Evidence

### Identity Lifecycle Verification

**Employee termination — OrangeHRM**

![Billy Kaplan termination](evidence/screenshots/01-hr-termination.png)

**Disabled identity — Authentik**

![Billy Kaplan inactive identity](evidence/screenshots/02-authentik-inactive.png)

### Detection Implementation and Validation

**Python validation — Four passing tests**

![Python validation results](evidence/screenshots/03-python-local-tests.png)

**Synthetic security events collected in Loki**

![Billy Kaplan Loki events](evidence/screenshots/04-billy-loki-events.png)

**Three-panel Grafana detection dashboard**

![Grafana detection dashboard](evidence/screenshots/08-billy-detection-dashboard.png)

**Automatic password-spray alert state history**

![Grafana alert state history](evidence/screenshots/10-billy-alert-history.png)

## 10. Reproduction and Security Scope

The project uses Python-generated security events and documentation-only IP addresses. The incident activity is synthetic, and the HR and identity-state observations were verified separately.

The repository includes the event-generation scripts and detection queries. Reproducing Loki ingestion requires an authorized Loki environment.

No real attacks, unauthorized account modifications, or production incidents occurred. Credentials and private infrastructure configuration are excluded from the repository.