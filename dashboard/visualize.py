
import os
from collections import Counter

import matplotlib.pyplot as plt


def generate_visualizations(events, alerts):
    """
    Generate charts showing authentication activity
    and security alert severity.
    """

    # Create dashboard directory if it does not exist
    os.makedirs("dashboard", exist_ok=True)

    # Select failed authentication events
    failed_events = [
        event for event in events
        if event["event_type"] == "failed"
    ]

    # Count failed logins by username
    username_counts = Counter(
        event["username"] for event in failed_events
    )

    # Count failed logins by source IP
    ip_counts = Counter(
        event["source_ip"] for event in failed_events
    )

    # Count alerts by severity
    severity_counts = Counter(
        alert["severity"] for alert in alerts
    )

    # --------------------------------
    # Chart 1: Failed Logins by Username
    # --------------------------------

    plt.figure(figsize=(8, 5))

    if username_counts:
        plt.bar(
            username_counts.keys(),
            username_counts.values()
        )
    else:
        plt.text(0.5, 0.5, "No failed login events",
                 ha="center", va="center")

    plt.title("Failed Login Attempts by Username")
    plt.xlabel("Username")
    plt.ylabel("Number of Failed Attempts")
    plt.tight_layout()

    plt.savefig("dashboard/failed_logins_by_username.png")
    plt.close()

    # --------------------------------
    # Chart 2: Failed Logins by Source IP
    # --------------------------------

    plt.figure(figsize=(8, 5))

    if ip_counts:
        plt.bar(
            ip_counts.keys(),
            ip_counts.values()
        )
        plt.xticks(rotation=30, ha="right")
    else:
        plt.text(0.5, 0.5, "No failed login events",
                 ha="center", va="center")

    plt.title("Failed Login Attempts by Source IP")
    plt.xlabel("Source IP Address")
    plt.ylabel("Number of Failed Attempts")
    plt.tight_layout()

    plt.savefig("dashboard/failed_logins_by_ip.png")
    plt.close()

    # --------------------------------
    # Chart 3: Alert Severity Distribution
    # --------------------------------

    severity_levels = ["LOW", "MEDIUM", "HIGH"]

    severity_values = [
        severity_counts.get(level, 0)
        for level in severity_levels
    ]

    plt.figure(figsize=(7, 5))

    plt.bar(
        severity_levels,
        severity_values
    )

    plt.title("Security Alert Severity Distribution")
    plt.xlabel("Severity Level")
    plt.ylabel("Number of Alerts")
    plt.tight_layout()

    plt.savefig("dashboard/alert_severity_distribution.png")
    plt.close()

    print("\n[VISUALIZATION]")
    print("Generated 3 security analysis charts.")
    print("Charts saved in the dashboard/ directory.")
