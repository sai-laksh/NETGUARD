"""
NETGUARD - Smart Campus Network Monitoring and Security System
Wireshark Packet Analysis Engine (pcap_analyzer.py)

This module parses Wireshark packet capture exports (CSV or structured flow logs),
computes protocol distributions, and executes rule-based anomaly detection algorithms.
Designed for college Computer Networks (CN) capstone integration.
"""

import os
import csv
import json
from collections import defaultdict
from datetime import datetime

class WiresharkAnalyzer:
    def __init__(self, sample_csv_path="data/sample_wireshark_export.csv"):
        self.sample_csv_path = sample_csv_path

    def analyze_csv(self, filepath=None):
        target_path = filepath or self.sample_csv_path
        if not os.path.exists(target_path):
            return {"error": f"Capture file not found: {target_path}"}

        packets = []
        protocol_counts = defaultdict(int)
        ip_traffic = defaultdict(lambda: {"packets": 0, "bytes": 0})
        syn_tracker = defaultdict(lambda: {"syn_count": 0, "targets": set(), "ports": set()})
        flagged_anomalies = []

        with open(target_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                packets.append(row)
                proto = row.get("Protocol", "OTHER").upper()
                protocol_counts[proto] += 1

                length = int(row.get("Length", 0))
                src = row.get("Source", "Unknown")
                dst = row.get("Destination", "Unknown")
                info = row.get("Info", "")
                flag = row.get("Flag", "")

                ip_traffic[src]["packets"] += 1
                ip_traffic[src]["bytes"] += length

                # Rule 2 Heuristic: Repeated Failed Connections / SYN Flood tracking
                if "SYN" in flag:
                    syn_tracker[src]["syn_count"] += 1
                    syn_tracker[src]["targets"].add(dst)
                    # Extract port if present in Info
                    if "→" in info:
                        parts = info.split("→")
                        try:
                            dst_port = parts[1].strip().split()[0]
                            syn_tracker[src]["ports"].add(dst_port)
                        except Exception:
                            pass

                # Rule 3 Heuristic: Cross-VLAN Unauthorized Probing
                if src.startswith("10.10.10.") and dst == "10.10.40.50":
                    flagged_anomalies.append({
                        "rule": "RULE-PAT-03 (Unusual Communication Patterns)",
                        "source": src,
                        "destination": dst,
                        "severity": "Critical",
                        "detail": f"Direct database connection attempt to {dst} from untrusted student VLAN.",
                        "timestamp": row.get("Time", "0.000")
                    })

                # Explicit alert tags in CSV
                alert_tag = row.get("AlertTag", "")
                if alert_tag and alert_tag != "NORMAL":
                    flagged_anomalies.append({
                        "rule": f"Flagged in Wireshark: {alert_tag}",
                        "source": src,
                        "destination": dst,
                        "protocol": proto,
                        "severity": "High" if "BRUTE" in alert_tag or "CROSS" in alert_tag else "Medium",
                        "detail": info,
                        "timestamp": row.get("Time", "0.000")
                    })

        # Evaluate SYN scan threshold
        for src, data in syn_tracker.items():
            if len(data["ports"]) >= 4:
                flagged_anomalies.append({
                    "rule": "RULE-PORT-05 (Unusual Port Activity)",
                    "source": src,
                    "destination": list(data["targets"])[0] if data["targets"] else "Multiple",
                    "severity": "Medium",
                    "detail": f"Sequential SYN port sweep observed probing ports: {', '.join(list(data['ports'])[:5])}...",
                    "timestamp": "Analysis Engine"
                })

        return {
            "total_packets": len(packets),
            "protocol_distribution": dict(protocol_counts),
            "top_talkers": [
                {"ip": ip, "packets": data["packets"], "kilobytes": round(data["bytes"] / 1024, 2)}
                for ip, data in sorted(ip_traffic.items(), key=lambda x: x[1]["bytes"], reverse=True)[:5]
            ],
            "anomalies_detected": flagged_anomalies,
            "analysis_status": "Complete",
            "source_type": "Wireshark PCAP / CSV Export"
        }

if __name__ == "__main__":
    analyzer = WiresharkAnalyzer()
    res = analyzer.analyze_csv()
    print("Wireshark Analyzer Test Result:")
    print(json.dumps(res, indent=2))
