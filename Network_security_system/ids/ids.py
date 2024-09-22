import re

# Simple IDS to detect suspicious patterns
class IDS:
    def __init__(self):
        self.signatures = []

    def add_signature(self, pattern):
        self.signatures.append(re.compile(pattern))

    def analyze_traffic(self, traffic):
        for signature in self.signatures:
            if signature.search(traffic):
                return "Suspicious Activity Detected!"
        return "Traffic is clean."

# Add signatures of suspicious activities (for example, scanning or malicious attempts)
ids = IDS()
ids.add_signature(r"Nmap")
ids.add_signature(r"SQL Injection")

# Simulated network traffic
traffic_samples = ["Normal web traffic", "Nmap Scan detected", "User Login", "SQL Injection attempt"]

for traffic in traffic_samples:
    result = ids.analyze_traffic(traffic)
    print(f"Traffic: {traffic} -> {result}")
