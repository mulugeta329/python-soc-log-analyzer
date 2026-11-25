
from analyzer.log_parser import parse_log_file
from analyzer.detection import (
    detect_failed_logins,
    detect_suspicious_ips
)


def main():

    # Read authentication logs
    events = parse_log_file("logs/auth.log")

    # Detect failed login attempts
    failed_results = detect_failed_logins(events)

    # Identify suspicious source IPs
    suspicious_ips = detect_suspicious_ips(
        events,
        threshold=3
    )

    # Display analysis results
    print("=" * 45)
    print("          PYTHON SOC LOG ANALYZER")
    print("=" * 45)

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
        print("No IP addresses reached the detection threshold.")

    print("\n" + "=" * 45)
    print("             ANALYSIS COMPLETE")
    print("=" * 45)


if __name__ == "__main__":
    main()
