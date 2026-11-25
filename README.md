# Python SOC Log Analyzer

## Project Overview

The Python SOC Log Analyzer is a cybersecurity project designed to simulate basic Security Operations Center (SOC) Level 1 analyst activities.

It analyzes authentication logs, identifies suspicious login attempts, detects repeated failed logins, and generates security alerts using Python.

## Objectives

- Analyze Linux authentication log files.
- Identify failed and successful login attempts.
- Detect suspicious IP addresses.
- Identify repeated authentication failures.
- Classify security alerts based on severity.
- Generate security investigation reports.
- Visualize authentication activities.

## Technologies

- Python 3
- Regular Expressions
- Collections
- Pandas
- Matplotlib
- CSV

## Project Features

1. Authentication log parsing.
2. Failed login detection.
3. Suspicious IP identification.
4. Alert severity classification.
5. CSV report generation.
6. Security event visualization.

## Project Structure

```text
python-soc-log-analyzer/
├── analyzer/
├── dashboard/
├── logs/
├── reports/
├── main.py
├── requirements.txt
└── README.md
```

## Learning Outcomes

- Security log analysis.
- Authentication event monitoring.
- Basic threat detection.
- Security alert investigation.
- Python automation.
- SOC incident documentation.

## Project Status

In Progress.

## Disclaimer

This project is for educational purposes and uses simulated security logs. It focuses on defensive cybersecurity and SOC analysis.

## Author

Aspiring SOC Level 1 Analyst | Cybersecurity Enthusiast

## Dataset Information

The project uses simulated Linux SSH authentication logs.

The dataset includes:

- Successful authentication events.
- Failed authentication attempts.
- Invalid username attempts.
- Multiple source IP addresses.
- Multiple user accounts.

These events are used for practicing
security log analysis and threat detection.

Dataset file: logs/auth.log

## Implemented Features

### 1. Linux Authentication Log Parsing
- Reads simulated Linux SSH authentication logs.
- Extracts timestamps, usernames, source IPs and event types.
- Recognizes successful, failed and invalid-user events.

### 2. Failed Login Detection
- Detects failed SSH password attempts.
- Counts failed login attempts.
- Identifies targeted usernames.

### 3. Suspicious IP Detection
- Groups failed login attempts by source IP.
- Identifies IP addresses reaching a configurable threshold.
- Uses a default threshold of 3 failed attempts.

## Current Project Status

| Feature | Status |
|---|---|
| Project setup | Completed |
| Simulated log dataset | Completed |
| Log parser | Completed |
| Failed login detection | Completed |
| Suspicious IP detection | Completed |
| Severity classification | Planned |
| CSV report generation | Planned |
| Data visualization | Planned |
