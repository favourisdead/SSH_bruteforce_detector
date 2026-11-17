# SSH Brute-Force Detector

A Python script that analyses SSH authentication logs, counts failed login attempts per IP address, and flags likely brute-force attacks.

## Features
- Parses OpenSSH logs using regex
- Counts failed password attempts per source IP
- Flags IPs exceeding a threshold (default: 5)
- Exports results to `report.csv`

## How to Run
1. Download `OpenSSH_2k.log` from [Loghub](https://github.com/logpai/loghub)
2. Place it in the same folder as the script
3. Run:
   python3 ssh_bruteforce_detector.py

## Output
[ALERT] 183.62.140.253: 286 failed logins
[ALERT] 187.141.143.180: 80 failed logins

## What I Learned
- Writing regex to extract data from unstructured logs
- Using Python's Counter for frequency analysis
- Identifying brute-force patterns in authentication logs
- Exporting findings to CSV for reporting

## Future Improvements
- Command-line arguments for log file and threshold
- Time-window detection (e.g. 5 failures in 1 minute)
- GeoIP lookup for flagged addresses