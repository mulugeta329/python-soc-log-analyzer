
from datetime import datetime, timedelta
from collections import defaultdict

from analyzer.log_parser import parse_log_file


def detect_time_based_attacks(events, threshold=3, window_seconds=60):
    """
    Detect IP addresses with repeated failed logins
    within a specified time window.
    """

    ip_events = defaultdict(list)

    # Collect failed login timestamps by source IP
    for event in events:
        if event["event_type"] == "failed":
            timestamp = datetime.strptime(
                "2026 " + event["timestamp"],
                "%Y %b %d %H:%M:%S"
            )

            ip_events[event["source_ip"]].append(timestamp)

    alerts = []

    # Check each IP address
    for ip, timestamps in ip_events.items():
        timestamps.sort()

        start = 0

        for end in range(len(timestamps)):
            while (
                timestamps[end] - timestamps[start]
                > timedelta(seconds=window_seconds)
            ):
                start += 1

            attempts = end - start + 1

            if attempts == threshold:
                alerts.append({
                    "source_ip": ip,
                    "failed_attempts": attempts,
                    "window_seconds": window_seconds,
                    "first_attempt": timestamps[start],
                    "last_attempt": timestamps[end],
                    "severity": "HIGH"
                })

    return alerts


if __name__ == "__main__":
    events = parse_log_file("logs/auth.log")

    alerts = detect_time_based_attacks(events)

    print("\n[TIME-BASED SUSPICIOUS LOGIN DETECTION]")
    print("Detection window: 60 seconds")
    print("Alert threshold: 3 failed attempts")

    if alerts:
        for alert in alerts:
            print(
                f"IP: {alert['source_ip']} | "
                f"Attempts: {alert['failed_attempts']} | "
                f"Severity: {alert['severity']}"
            )
            print(
                f"Time range: {alert['first_attempt']} "
                f"to {alert['last_attempt']}"
            )
    else:
        print("No time-based suspicious activity detected.")
