
"""Test Loki's five-minute password-spray window."""

import sys
from datetime import datetime, timedelta, timezone

from validate_loki import (
    SELECTOR,
    IP,
    query_logs,
    query_metric,
    metric_for_ip,
)

SECOND = 1_000_000_000


def main():
    print("\nPASSWORD SPRAY - FIVE-MINUTE WINDOW TEST")
    print("-" * 55)

    # Find the newest correlated event from our test batch.
    now = datetime.now(timezone.utc)
    end_ns = int(now.timestamp() * SECOND)
    start_ns = int(
        (now - timedelta(hours=24)).timestamp() * SECOND
    )

    ghost_query = (
        SELECTOR
        + ' | json | event_type="ghost_account_finding"'
    )

    ghosts = query_logs(
        ghost_query, start_ns, end_ns
    )

    if not ghosts:
        raise RuntimeError(
            "No correlated ghost finding found in Loki."
        )

    anchor = max(timestamp for timestamp, _ in ghosts)

    # Retrieve the six spray attempts before Billy's login.
    spray_logs = query_logs(
        SELECTOR
        + ' | json | event_type="login"'
        + ' | status="failed"'
        + f' | source_ip="{IP}"',
        anchor - 171 * SECOND,
        anchor - 19 * SECOND,
    )

    usernames = {
        event.get("username")
        for _, event in spray_logs
    }

    timestamps = [
        timestamp for timestamp, _ in spray_logs
    ]

    if (
        len(spray_logs) != 6
        or len(usernames) != 6
        or max(timestamps) - min(timestamps)
        != 150 * SECOND
    ):
        raise RuntimeError(
            "Expected six distinct failed accounts "
            "spread across exactly 150 seconds. "
            "Check the latest Loki event batch."
        )

    first = min(timestamps)

    # Count DISTINCT usernames within five minutes.
    logql = (
        "count by (source_ip) ("
        "sum by (source_ip, username) ("
        "count_over_time("
        + SELECTOR
        + ' | json | event_type="login"'
        + ' | status="failed"'
        + f' | source_ip="{IP}"'
        + " [5m]"
        + ")))"
    )

    # All six attempts should be included.
    inside_time = first + 151 * SECOND

    # Move forward so the first two attempts expire.
    outside_time = first + 336 * SECOND

    inside_results = query_metric(logql, inside_time)
    outside_results = query_metric(logql, outside_time)

    inside_count = metric_for_ip(inside_results, IP)
    outside_count = metric_for_ip(outside_results, IP)

    test1 = inside_count == 6
    test2 = outside_count == 4

    print(
        f'{"PASS" if test1 else "FAIL"}: '
        f'All attempts inside window - {inside_count:g} '
        "accounts (expected 6)"
    )

    print(
        f'{"PASS" if test2 else "FAIL"}: '
        f'Earliest attempts excluded - {outside_count:g} '
        "accounts (expected 4)"
    )

    print("-" * 55)

    if test1 and test2:
        print("SUCCESS: Five-minute Loki window validated!")
    else:
        print("FAILED: Review Loki window counts.")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"ERROR: {error}")
        sys.exit(1)
