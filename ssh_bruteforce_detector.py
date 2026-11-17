import re
import csv
import argparse
from collections import Counter

parser = argparse.ArgumentParser(description="Detect SSH brute-force attempts in auth logs.")
parser.add_argument("logfile", help="Path to the SSH log file")
parser.add_argument("-t", "--threshold", type=int, default=5, help="Failed logins before alerting (default: 5)")
parser.add_argument("-o", "--output", default="report.csv", help="CSV report filename (default: report.csv)")
args = parser.parse_args()

pattern = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")
counts = Counter()

with open(args.logfile) as f:
    for line in f:
        match = pattern.search(line)
        if match:
            counts[match.group(2)] += 1

with open(args.output, "w", newline="") as out:
    writer = csv.writer(out)
    writer.writerow(["ip", "failed_logins"])
    for ip, n in counts.most_common():
        if n >= args.threshold:
            print(f"[ALERT] {ip}: {n} failed logins")
            writer.writerow([ip, n])