import re
from collections import Counter
import csv

pattern = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")
counts = Counter()
with open("OpenSSH_2k.log") as f:
    for line in f:
        match = pattern.search(line)
        if match:
            counts[match.group(2)] += 1



with open("report.csv", "w", newline="") as out:
    writer = csv.writer(out)
    writer.writerow(["ip", "failed_logins"])
    for ip, n in counts.most_common():
        if n >= 5:
            print(f"[ALERT] {ip}: {n} failed logins")
            writer.writerow([ip, n])