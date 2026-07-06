# SSH Brute-Force Detection Engineering Lab with Splunk

## Overview

This project demonstrates a complete SOC detection workflow for SSH brute-force activity using Splunk.

The lab includes service discovery with Nmap, controlled SSH brute-force simulation with Metasploit, log ingestion into Splunk, SPL-based detection logic, alert configuration, and evidence collection.

## Objective

The objective of this lab was to detect repeated failed SSH login attempts and generate an alert when brute-force behavior was observed.

## Lab Environment

- Kali Linux
- Splunk Enterprise 9.3.1
- OpenSSH Server
- Nmap
- Metasploit Framework
- SPL
- Windows host used for external SSH testing

## Lab Scope

This lab was performed in a controlled local environment.

The target host was my own Kali Linux machine running OpenSSH and Splunk. Nmap and Metasploit were used only against my own lab machine for learning and detection engineering purposes.

## Methodology

1. Used Nmap to confirm that SSH was exposed on port 22.
2. Used Metasploit to generate controlled failed SSH login attempts.
3. Ingested SSH authentication logs into Splunk.
4. Extracted source IP and username fields using SPL.
5. Created a detection query for repeated failed SSH login attempts.
6. Configured a scheduled high-severity alert.
7. Validated the alert in Splunk Triggered Alerts.
8. Exported evidence and screenshots for documentation.

## Service Discovery

Nmap was used to validate that the target host had SSH exposed on port 22.

```bash
nmap -sV -p 22 192.168.1.4 -oN evidence/nmap_ssh_service_scan.txt  

Result:

22/tcp open ssh OpenSSH 10.2p1 Debian 6
Attack Simulation

Metasploit was used in a controlled local lab to generate SSH failed login attempts against my own SSH service.

Module used:

auxiliary/scanner/ssh/ssh_login

The purpose of this step was not exploitation. The goal was to generate authentication failure logs that could be ingested and detected by Splunk.

Data Source

Splunk monitored the following SSH log file:

/var/log/ssh_bruteforce.log

Custom sourcetype:

ssh_Bruteforce

Detection Query
index=main sourcetype=ssh_Bruteforce "Failed password"
| rex "Failed password for (invalid user )?(?<user>\S+) from (?<src_ip>\S+)"
| stats count as failed_attempts earliest(_time) as first_attempt latest(_time) as last_attempt by src_ip, user
| where failed_attempts >= 5
| convert ctime(first_attempt) ctime(last_attempt)
| sort -failed_attempts
Detection Logic

The detection identifies possible SSH brute-force activity by:

Searching for failed SSH login attempts
Extracting the source IP address
Extracting the targeted username
Counting failed attempts by source IP and username
Triggering detection when failed attempts are greater than or equal to 5
Alert Configuration
Alert name: SSH BRUTE FORCE DETECTION
Alert type: Scheduled
Schedule: Every 5 minutes
Trigger condition: Number of results greater than 0
Severity: High
Action: Add to Triggered Alerts
Throttling enabled to reduce repeated alerts
Results

The detection successfully identified multiple failed SSH login attempts.

Example results:

Source IP	User	Failed Attempts
127.0.0.1	admin	12
192.168.1.2	teste	6
192.168.1.4	admin	7

MITRE ATT&CK Mapping
T1110 - Brute Force
T1110.001 - Password Guessing

Evidence
Screenshots
01_nmap_ssh_service_scan.png
02_raw_ssh_logs_ingested.png
03_bruteforce_detection_result.png
04_alert_configuration.png
05_triggered_alerts.png
06_metasploit_detection_result.png

Exported Evidence

nmap_ssh_service_scan.txt
bruteforce_detection_results.csv
metasploit_bruteforce_detection_results.csv
raw_ssh_failed_login_events_1.txt
raw_ssh_failed_login_events_2.txt

Skills Demonstrated

Service discovery with Nmap
Controlled attack simulation with Metasploit
Splunk log ingestion
SPL query writing
Field extraction using rex
SSH brute-force detection logic
Alert creation and validation
Alert severity configuration
Basic SOC detection engineering workflow
MITRE ATT&CK mapping

Project Structure
.
├── evidence
│   ├── bruteforce_detection_results.csv
│   ├── metasploit_bruteforce_detection_results.csv
│   ├── nmap_ssh_service_scan.txt
│   ├── raw_ssh_failed_login_events_1.txt
│   └── raw_ssh_failed_login_events_2.txt
├── screenshots
│   ├── 01_nmap_ssh_service_scan.png
│   ├── 02_raw_ssh_logs_ingested.png
│   ├── 03_bruteforce_detection_result.png
│   ├── 04_alert_configuration.png
│   ├── 05_triggered_alerts.png
│   └── 06_metasploit_detection_result.png
├── spl
│   └── ssh_bruteforce_detection.spl
└── wordlists
    ├── passwords.txt
    └── users.txt
Conclusion

This lab demonstrates a practical detection engineering workflow for SSH brute-force activity.

The project covers service discovery, controlled attack simulation, log ingestion, SPL detection logic, alert configuration, and validation through triggered alerts in Splunk.
