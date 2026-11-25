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

| Feature                 | Status |
|---|                          ---|
| Project setup           | Completed |
| Simulated log dataset   | Completed |
| Log parser | Completed  |
| Failed login detection  | Completed |
| Suspicious IP detection | Completed |
| Severity classification | Planned |
| CSV report generation   | Planned |
| Data visualization      | Planned |

### 4. Alert Severity Classification

The analyzer assigns severity levels to suspicious
source IP addresses based on failed authentication counts.

| Failed Attempts | Severity |
|---              |---|
| 1–2             | LOW    |
| 3–4             | MEDIUM |
| 5 or more       | HIGH   |

Features:
- Automatic severity classification.
- Configurable detection thresholds.
- Structured security alert generation.

These thresholds are educational examples and
should be tuned for a real environment.

## Current Project Status

| Feature                 | Status |
|---|---|
| Project setup           | Completed |
| Simulated log dataset   | Completed |
| Log parser | Completed  |
| Failed login detection  | Completed |
| Suspicious IP detection | Completed |
| Severity classification | Completed |
| CSV report generation   | Planned |
| Data visualization      | Planned |


### 5. CSV Security Report Generation

The analyzer automatically exports detected security
alerts into a CSV file.

Report location:

`reports/security_alerts.csv`

Report fields:

- Timestamp
- Source IP address
- Failed login attempts
- Alert severity
- Alert description

The CSV report can be opened using spreadsheet
applications for further investigation.

## Current Project Status

| Feature                 | Status    |

| Project setup           | Completed |
| Simulated log dataset   | Completed |
| Log parser | Completed  |
| Failed login detection  | Completed |
| Suspicious IP detection | Completed |
| Severity classification | Completed |
| CSV report generation   | Completed |
| Data visualization      | Planned   |


### 6. Security Event Visualization

The project uses Matplotlib to visualize authentication
events and detected security alerts.

Generated visualizations:

1. Failed login attempts by username.
2. Failed login attempts by source IP address.
3. Security alert severity distribution.

Chart output directory:

`dashboard/`

The visualizations help analysts understand
authentication activity and identify patterns
in the simulated dataset.

## Current Project Status

| Feature                      | Status    |

| Project setup                | Completed |
| Simulated log dataset        | Completed |
| Log parser                   | Completed |
| Failed login detection       | Completed |
| Suspicious IP detection      | Completed |
| Severity classification      | Completed |
| CSV report generation        | Completed |
| Security event visualization | Completed |
| Final documentation          | Planned   |
