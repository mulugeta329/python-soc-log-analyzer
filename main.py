
from analyzer.log_parser import parse_log_file

from analyzer.detection import (
    analyze_authentication_events,
    detect_failed_logins,
    detect_suspicious_ips,
    generate_severity_alerts
)

from analyzer.time_detection import detect_time_based_attacks

from analyzer.report_generator import (
    generate_csv_report,
    generate_incident_summary
)

from dashboard.visualize import generate_visualizations


def main():

    # Read authentication logs
    events = parse_log_file("logs/auth.log")

    # Analyze authentication event categories
    authentication_stats = analyze_authentication_events(events)

    # Detect failed login attempts
    failed_results = detect_failed_logins(events)

    # Detect suspicious source IP addresses
    suspicious_ips = detect_suspicious_ips(
        events,
        threshold=3
    )

    # Generate severity alerts
    alerts = generate_severity_alerts(suspicious_ips)

    # Detect repeated failed logins within a time window
    time_based_alerts = detect_time_based_attacks(
        events,
        threshold=3,
        window_seconds=60
    )

    print("=" * 50)
    print("           PYTHON SOC LOG ANALYZER")
    print("=" * 50)

    print("\n[AUTHENTICATION EVENT STATISTICS]")
    print("Total events:", authentication_stats["total_events"])
    print("Successful logins:", authentication_stats["successful_logins"])
    print("Failed logins:", authentication_stats["failed_logins"])
    print("Invalid usernames:", authentication_stats["invalid_users"])

    print("\n[FAILED LOGIN ATTEMPTS BY USERNAME]")

    for username, count in failed_results["username_counts"].items():
        print(f"{username}: {count} attempts")

    print("\n[SUSPICIOUS SOURCE IP ADDRESSES]")

    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(f"{ip}: {count} failed attempts")
    else:
        print("No suspicious IP addresses detected.")

    print("\n[SECURITY ALERTS]")

    if alerts:
        for alert in alerts:
            print(
                f"IP: {alert['source_ip']} | "
                f"Attempts: {alert['failed_attempts']} | "
                f"Severity: {alert['severity']}"
            )
    else:
        print("No alerts generated.")

    # Display time-based detection results
    print("\n[TIME-BASED SUSPICIOUS LOGIN DETECTION]")
    print("Detection window: 60 seconds")
    print("Alert threshold: 3 failed attempts")

    if time_based_alerts:
        for alert in time_based_alerts:
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

    # Generate CSV report
    report_path = generate_csv_report(alerts)
    print("\nCSV report saved to:", report_path)

    # Generate incident summary
    summary_path = generate_incident_summary(
        events,
        failed_results,
        suspicious_ips,
        alerts
    )

    print("Incident summary saved to:", summary_path)

    # Generate visualizations
    generate_visualizations(events, alerts)

    print("\n" + "=" * 50)
    print("              ANALYSIS COMPLETE")
    print("=" * 50)


if __name__ == "__main__":
    main()
