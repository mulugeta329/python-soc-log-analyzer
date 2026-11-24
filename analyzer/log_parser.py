
import re


LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}) "
    r"(?P<hostname>\S+) "
    r"sshd\[(?P<pid>\d+)\]: "
    r"(?P<message>.+)$"
)

EVENT_PATTERNS = [
    (
        "success",
        re.compile(
            r"Accepted password for (?P<username>\S+) "
            r"from (?P<source_ip>\S+) port (?P<source_port>\d+)"
            r"(?: (?P<protocol>\S+))?"
        ),
    ),
    (
        "failed",
        re.compile(
            r"Failed password for (?P<username>\S+) "
            r"from (?P<source_ip>\S+) port (?P<source_port>\d+)"
            r"(?: (?P<protocol>\S+))?"
        ),
    ),
    (
        "invalid_user",
        re.compile(
            r"Invalid user (?P<username>\S+) "
            r"from (?P<source_ip>\S+) port (?P<source_port>\d+)"
        ),
    ),
]


def parse_log_line(line):
    """Parse one SSH authentication log line into a dictionary."""
    log_match = LOG_PATTERN.match(line.strip())

    if not log_match:
        return None

    log_data = log_match.groupdict()
    message = log_data.pop("message")

    for event_type, pattern in EVENT_PATTERNS:
        event_match = pattern.search(message)

        if event_match:
            log_data.update(event_match.groupdict())
            log_data["event_type"] = event_type
            return log_data

    return None


def parse_log_file(file_path):
    """Read a log file and return all recognized authentication events."""
    events = []

    with open(file_path, "r", encoding="utf-8") as log_file:
        for line in log_file:
            event = parse_log_line(line)

            if event is not None:
                events.append(event)

    return events


if __name__ == "__main__":
    log_file = "logs/auth.log"
    parsed_events = parse_log_file(log_file)

    print(f"Parsed {len(parsed_events)} authentication events.")

    for event in parsed_events:
        print(event)
