
import csv
import os
from datetime import datetime


def generate_csv_report(alerts, output_path="reports/security_alerts.csv"):
    """
    Export security alerts into a CSV report.
    """

    # Create the reports directory if it doesn't exist
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Define CSV columns
    fieldnames = [
        "timestamp",
        "source_ip",
        "failed_attempts",
        "severity",
        "description"
    ]

    # Write alerts to CSV
    with open(output_path, "w", newline="", encoding="utf-8") as csv_file:

        writer = csv.DictWriter(
            csv_file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for alert in alerts:

            row = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": alert["source_ip"],
                "failed_attempts": alert["failed_attempts"],
                "severity": alert["severity"],
                "description": (
                    f"{alert['failed_attempts']} failed "
                    f"authentication attempts from "
                    f"{alert['source_ip']}"
                )
            }

            writer.writerow(row)

    print(f"\nCSV report successfully generated: {output_path}")

    return output_path


def generate_incident_summary(
    events,
    failed_results,
    suspicious_ips,
    alerts,
    output_path="reports/incident_summary.txt"
):
    """
    Generate a text-based security incident summary.
    """

    # Create the reports directory if it doesn't exist
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Generate the incident summary
    with open(output_path, "w", encoding="utf-8") as report:

        report.write("=" * 50 + "\n")
        report.write("       SECURITY INCIDENT SUMMARY\n")
        report.write("=" * 50 + "\n\n")

        report.write(
            f"Report generated: "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        )

        # General statistics
        report.write("[GENERAL STATISTICS]\n")
        report.write(f"Total authentication events: {len(events)}\n")
        report.write(
            f"Failed login attempts: {failed_results['total_failed']}\n\n"
        )

        # Suspicious IP addresses
        report.write("[SUSPICIOUS SOURCE IP ADDRESSES]\n")

        if suspicious_ips:
            for ip, count in suspicious_ips.items():
                report.write(f"{ip}: {count} failed attempts\n")
        else:
            report.write("No suspicious IP addresses detected.\n")

        # Security alerts
        report.write("\n[SECURITY ALERTS]\n")

        if alerts:
            for alert in alerts:
                report.write(
                    f"IP: {alert['source_ip']} | "
                    f"Attempts: {alert['failed_attempts']} | "
                    f"Severity: {alert['severity']}\n"
                )
        else:
            report.write("No security alerts generated.\n")

        # Recommended defensive actions
        report.write("\n[RECOMMENDED ACTIONS]\n")
        report.write(
            "- Review authentication activity for suspicious patterns.\n"
        )
        report.write(
            "- Verify whether failed login attempts are expected.\n"
        )
        report.write(
            "- Follow organizational procedures for escalating alerts.\n"
        )

    print(f"\nIncident summary generated: {output_path}")

    return output_path
