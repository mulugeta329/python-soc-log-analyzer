
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
