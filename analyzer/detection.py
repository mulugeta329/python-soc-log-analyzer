
from collections import Counter


def detect_failed_logins(events):
    """Count failed login attempts by username."""

    failed_events = [
        event for event in events
        if event["event_type"] == "failed"
    ]

    username_counts = Counter(
        event["username"] for event in failed_events
    )

    return {
        "total_failed": len(failed_events),
        "username_counts": dict(username_counts)
    }


def detect_suspicious_ips(events, threshold=3):
    """Identify source IPs with repeated failed logins."""

    failed_events = [
        event for event in events
        if event["event_type"] == "failed"
    ]

    ip_counts = Counter(
        event["source_ip"] for event in failed_events
    )

    suspicious_ips = {
        ip: count
        for ip, count in ip_counts.items()
        if count >= threshold
    }

    return suspicious_ips
