
"""Validate actual detection results returned by Grafana Loki."""

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
IP = "203.0.113.25"
NORMAL_IP = "198.51.100.11"

SELECTOR = '{job="identity_detection_lab",scenario="billy_kaplan"}'


def get_loki_url():
    url = os.environ.get("LOKI_QUERY_URL", "").strip()

    if not url:
        push_url = os.environ.get("LOKI_PUSH_URL", "").strip()
        if push_url.endswith("/loki/api/v1/push"):
            url = push_url.replace(
                "/loki/api/v1/push",
                "/loki/api/v1/query"
            )

    if not url.endswith("/loki/api/v1/query"):
        raise RuntimeError(
            "Set LOKI_PUSH_URL or LOKI_QUERY_URL first."
        )

    return url


BASE_URL = get_loki_url()


def request_loki(endpoint, parameters):
    url = BASE_URL.replace(
        "/loki/api/v1/query",
        f"/loki/api/v1/{endpoint}"
    )

    url += "?" + urllib.parse.urlencode(parameters)

    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json"}
    )

    try:
        with urllib.request.urlopen(
            request, timeout=30
        ) as response:
            result = json.load(response)

    except urllib.error.HTTPError as error:
        details = error.read().decode(errors="replace")
        raise RuntimeError(
            f"Loki HTTP {error.code}: {details[:600]}"
        ) from error

    if result.get("status") != "success":
        raise RuntimeError(
            f"Loki returned an error: {result}"
        )

    return result["data"]


def query_logs(logql, start_ns, end_ns):
    data = request_loki(
        "query_range",
        {
            "query": logql,
            "start": str(start_ns),
            "end": str(end_ns),
            "limit": "1000",
            "direction": "forward"
        }
    )

    if data.get("resultType") != "streams":
        raise RuntimeError(
            "Expected Loki log streams."
        )

    records = []

    for stream in data["result"]:
        for timestamp, message in stream["values"]:
            records.append((
                int(timestamp),
                json.loads(message)
            ))

    return records


def query_metric(logql, evaluation_ns):
    data = request_loki(
        "query",
        {
            "query": logql,
            "time": str(evaluation_ns)
        }
    )

    if data.get("resultType") != "vector":
        raise RuntimeError(
            "Expected a Loki instant metric vector. "
            "Check the saved password-spray query."
        )

    return data["result"]


def metric_for_ip(results, ip):
    for result in results:
        if result.get("metric", {}).get("source_ip") == ip:
            return float(result["value"][1])

    # Some queries remove the source IP label.
    if len(results) == 1:
        return float(results[0]["value"][1])

    return 0.0


def report(name, passed, detail):
    status = "PASS" if passed else "FAIL"
    print(f"{status}: {name} - {detail}")
    return passed


def main():
    now = datetime.now(timezone.utc)
    end_24h = int(now.timestamp() * 1_000_000_000)
    start_24h = int(
        (now - timedelta(hours=24)).timestamp()
        * 1_000_000_000
    )

    # Locate the newest correlated finding in Loki.
    ghost_query = (
        SELECTOR
        + ' | json | event_type="ghost_account_finding"'
    )

    recent_findings = query_logs(
        ghost_query, start_24h, end_24h
    )

    if not recent_findings:
        raise RuntimeError(
            "No ghost-account finding in Loki in the last 24 hours."
        )

    # Anchor the test to the actual event time.
    # This works even when the original five-minute
    # detection window has already passed.
    anchor_ns = max(
        timestamp for timestamp, _ in recent_findings
    )

    window_start = anchor_ns - 45_000_000_000
    window_end = anchor_ns + 45_000_000_000
    evaluation_ns = anchor_ns + 1_000_000_000

    print("\nLOKI END-TO-END DETECTION VALIDATION")
    print("-" * 55)
    print("Source: Live Loki HTTP query API")
    print("Test window: 45 seconds before/after ghost event")
    print("-" * 55)

    # TEST 1: Execute the existing saved password-spray LogQL.
    files = sorted(
        (PROJECT / "queries").glob(
            "*password*spray*.logql"
        )
    )

    if not files:
        raise RuntimeError(
            "Password-spray .logql file not found in queries/."
        )

    spray_logql = files[0].read_text(
        encoding="utf-8-sig"
    ).strip()

    spray_results = query_metric(
        spray_logql, evaluation_ns
    )

    spray_count = metric_for_ip(
        spray_results, IP
    )

    test1 = report(
        "Password spray LogQL",
        spray_count == 6,
        f"{spray_count:g} distinct accounts (expected 6)"
    )

    # TEST 2: Execute the ghost-account LogQL.
    ghost_results = query_logs(
        ghost_query, window_start, window_end
    )

    ghost_correct = (
        len(ghost_results) == 1
        and ghost_results[0][1].get("username")
        == "billy.kaplan"
        and ghost_results[0][1].get("auth_status")
        == "success"
        and ghost_results[0][1].get("termination_date")
        == "2026-10-10"
    )

    test2 = report(
        "HR-correlated ghost account LogQL",
        ghost_correct,
        f"{len(ghost_results)} finding(s) (expected 1)"
    )

    # TEST 3: Query unauthorized administrator changes.
    admin_logql = (
        SELECTOR
        + ' | json'
        + ' | event_type="group_membership_added"'
        + ' | target_group="Administrators"'
        + ' | approved="no"'
    )

    admin_results = query_logs(
        admin_logql, window_start, window_end
    )

    test3 = report(
        "Unauthorized administrator change LogQL",
        len(admin_results) == 1,
        f"{len(admin_results)} event(s) (expected 1)"
    )

    # TEST 4: Validate that a normal source IP stays
    # below the password-spray threshold.
    normal_logql = (
        "count by (source_ip) ("
        "sum by (source_ip, username) ("
        "count_over_time("
        + SELECTOR
        + ' | json | event_type="login"'
        + ' | status="failed"'
        + f' | source_ip="{NORMAL_IP}"'
        + " [5m]"
        + ")))"
    )

    normal_results = query_metric(
        normal_logql, evaluation_ns
    )

    normal_count = metric_for_ip(
        normal_results, NORMAL_IP
    )

    test4 = report(
        "Normal authentication below threshold",
        normal_count == 1,
        f"{normal_count:g} distinct account (expected 1)"
    )

    print("-" * 55)

    checks = [test1, test2, test3, test4]

    if all(checks):
        print("SUCCESS: All 4 Loki API validation tests passed!")
        print("The queried detections returned expected results.")
        print(
            "NOTE: Grafana alert firing is not tested here."
        )
    else:
        print("FAILED: Review Loki query results above.")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"ERROR: {error}")
        sys.exit(1)
