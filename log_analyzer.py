from collections import defaultdict

FAILED_THRESHOLD = 3

def analyze_logs(file_path):
    failed_attempts = defaultdict(int)
    suspicious_ips = []

    with open(file_path, "r") as file:
        for line in file:
            if "FAILED LOGIN" in line:
                ip = line.strip().split()[-1]
                failed_attempts[ip] += 1

    for ip, count in failed_attempts.items():
        if count >= FAILED_THRESHOLD:
            suspicious_ips.append((ip, count))

    return suspicious_ips

results = analyze_logs("sample_logs.txt")

print("Suspicious IPs Detected:\n")
for ip, attempts in results:
    print(f"IP: {ip} | Failed Attempts: {attempts}")
