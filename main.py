
from analyzer.log_parser import parse_log_file

from analyzer.detection import (
    detect_failed_logins,
    detect_suspicious_ips,
    generate_severity_alerts
)


def main():

    # Read authentication logs
    events = parse_log_file("logs/auth.log")

    # Detect failed login attempts
    failed_results = detect_failed_logins(events)

    # Detect suspicious source IP addresses
    suspicious_ips = detect_suspicious_ips(
        events,
        threshold=3
    )

    # Generate severity alerts
    alerts = generate_severity_alerts(suspicious_ips)

    print("=" * 50)
    print("           PYTHON SOC LOG ANALYZER")
    print("=" * 50)

    print("\n[GENERAL STATISTICS]")
    print("Total authentication events:", len(events))
    print("Failed login attempts:", failed_results["total_failed"])

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

    print("\n" + "=" * 50)
    print("              ANALYSIS COMPLETE")
    print("=" * 50)


if __name__ == "__main__":
    main()
