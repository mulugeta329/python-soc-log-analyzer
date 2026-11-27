
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import datetime

from analyzer.log_parser import parse_log_file


def create_authentication_timeline():
    # Read authentication events
    events = parse_log_file("logs/auth.log")

    # The original Linux log timestamps do not include a year.
    # Use 2026 for this simulated project dataset.
    event_times = {
        "success": [],
        "failed": [],
        "invalid_user": []
    }

    for event in events:
        timestamp = datetime.strptime(
            "2026 " + event["timestamp"],
            "%Y %b %d %H:%M:%S"
        )

        event_type = event["event_type"]

        if event_type in event_times:
            event_times[event_type].append(timestamp)

    # Create the timeline chart
    plt.figure(figsize=(12, 6))

    positions = {
        "success": 3,
        "failed": 2,
        "invalid_user": 1
    }

    colors = {
        "success": "green",
        "failed": "red",
        "invalid_user": "orange"
    }

    labels = {
        "success": "Successful Login",
        "failed": "Failed Login",
        "invalid_user": "Invalid User"
    }

    for event_type, timestamps in event_times.items():
        plt.scatter(
            timestamps,
            [positions[event_type]] * len(timestamps),
            color=colors[event_type],
            label=labels[event_type],
            s=80
        )

    plt.yticks(
        [1, 2, 3],
        ["Invalid User", "Failed Login", "Successful Login"]
    )

    plt.xlabel("Time")
    plt.ylabel("Authentication Event")
    plt.title("SSH Authentication Activity Timeline")

    plt.gca().xaxis.set_major_formatter(
        mdates.DateFormatter("%H:%M:%S")
    )

    plt.gcf().autofmt_xdate()
    plt.grid(True, linestyle="--", alpha=0.5)
    plt.legend()
    plt.tight_layout()

    # Save the chart
    plt.savefig(
        "dashboard/authentication_timeline.png",
        dpi=300
    )

    print("Authentication timeline generated successfully.")
    print("Chart saved to dashboard/authentication_timeline.png")

    plt.show()


if __name__ == "__main__":
    create_authentication_timeline()
