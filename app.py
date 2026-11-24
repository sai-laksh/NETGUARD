"""
NETGUARD - Smart Campus Network Monitoring and Security System
Flask Application Server (app.py)

Provides REST API endpoints and static file serving for the NETGUARD Dashboard.
Supports modular data processing for Wireshark captures and Cisco Packet Tracer network topology.
"""

import os
import json
import random
import csv
import io
from collections import defaultdict
from datetime import datetime
from flask import Flask, jsonify, request, send_from_directory, Response
from pcap_analyzer import WiresharkAnalyzer
from packet_tracer_parser import PacketTracerParser

app = Flask(__name__, static_folder=".", static_url_path="")

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

def load_json_file(filename):
    filepath = os.path.join(DATA_DIR, filename)
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

def save_json_file(filename, data):
    filepath = os.path.join(DATA_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

@app.route("/")
def index():
    return send_from_directory(".", "index.html")

@app.route("/<path:path>")
def static_proxy(path):
    return send_from_directory(".", path)

# ----------------- REST API ENDPOINTS -----------------

@app.route("/api/stats", methods=["GET"])
def get_stats():
    devices = load_json_file("devices.json")
    alerts = load_json_file("alerts.json")

    total_devices = len(devices)
    active_devices = len([d for d in devices if d.get("status") == "Online"])
    critical_alerts = len([a for a in alerts if a.get("severity") == "Critical" and a.get("status") != "Resolved"])
    suspicious_activities = len([a for a in alerts if a.get("status") != "Resolved"])

    # Baseline network health calculation (100% minus penalties for unresolved alerts)
    health_score = 100 - (critical_alerts * 8) - ((suspicious_activities - critical_alerts) * 3)
    health_score = max(55, min(99, health_score))

    # Base live traffic calculation (simulated between 340 and 420 Mbps aggregate)
    rx_traffic = round(random.uniform(180.5, 230.2), 1)
    tx_traffic = round(random.uniform(140.2, 185.8), 1)

    return jsonify({
        "totalDevices": total_devices,
        "activeDevices": active_devices,
        "offlineDevices": total_devices - active_devices,
        "networkTrafficMbps": round(rx_traffic + tx_traffic, 1),
        "inboundTrafficMbps": rx_traffic,
        "outboundTrafficMbps": tx_traffic,
        "suspiciousActivities": suspicious_activities,
        "criticalAlerts": critical_alerts,
        "networkHealthScore": health_score,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

@app.route("/api/devices", methods=["GET"])
def get_devices():
    devices = load_json_file("devices.json")
    department = request.args.get("department")
    status = request.args.get("status")
    search = request.args.get("search", "").lower()

    filtered = devices
    if department and department != "All":
        filtered = [d for d in filtered if d.get("department") == department]
    if status and status != "All":
        filtered = [d for d in filtered if d.get("status") == status]
    if search:
        filtered = [
            d for d in filtered
            if search in d.get("name", "").lower()
            or search in d.get("ip", "").lower()
            or search in d.get("id", "").lower()
            or search in d.get("mac", "").lower()
        ]

    return jsonify(filtered)

@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    alerts = load_json_file("alerts.json")
    severity = request.args.get("severity")
    status = request.args.get("status")
    search = request.args.get("search", "").lower()

    filtered = alerts
    if severity and severity != "All":
        filtered = [a for a in filtered if a.get("severity") == severity]
    if status and status != "All":
        filtered = [a for a in filtered if a.get("status") == status]
    if search:
        filtered = [
            a for a in filtered
            if search in a.get("description", "").lower()
            or search in a.get("sourceIp", "").lower()
            or search in a.get("id", "").lower()
            or search in a.get("category", "").lower()
        ]

    return jsonify(filtered)

@app.route("/api/alerts/<alert_id>/status", methods=["POST"])
def update_alert_status(alert_id):
    data = request.get_json() or {}
    new_status = data.get("status")
    if new_status not in ["New", "Investigating", "Resolved"]:
        return jsonify({"error": "Invalid status value"}), 400

    alerts = load_json_file("alerts.json")
    updated = False
    for a in alerts:
        if a.get("id") == alert_id:
            a["status"] = new_status
            a["updatedAt"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            updated = True
            break

    if updated:
        save_json_file("alerts.json", alerts)
        return jsonify({"success": True, "alertId": alert_id, "newStatus": new_status})
    return jsonify({"error": "Alert not found"}), 404

@app.route("/api/threats/rules", methods=["GET"])
def get_threat_rules():
    rules = load_json_file("threat_rules.json")
    return jsonify(rules)

@app.route("/api/traffic/live", methods=["GET"])
def get_live_traffic():
    # Generate realistic simulated packet stream and aggregate metrics
    rx = round(random.uniform(185.0, 240.0), 1)
    tx = round(random.uniform(145.0, 195.0), 1)
    total_packets = random.randint(18200, 26500)

    tcp_share = int(total_packets * random.uniform(0.68, 0.74))
    udp_share = int(total_packets * random.uniform(0.18, 0.24))
    icmp_share = int(total_packets * random.uniform(0.03, 0.06))
    other_share = total_packets - (tcp_share + udp_share + icmp_share)

    sample_packets = [
        {
            "id": f"PKT-{random.randint(10000, 99999)}",
            "time": datetime.now().strftime("%H:%M:%S"),
            "source": f"10.10.10.{random.randint(10, 120)}",
            "destination": random.choice(["10.10.40.10", "10.10.40.25", "10.10.40.50", "198.51.100.4"]),
            "protocol": random.choice(["TCP", "TCP", "UDP", "HTTPS", "DNS", "ICMP"]),
            "length": random.choice([64, 128, 512, 1460, 1514]),
            "status": "Pass"
        }
        for _ in range(5)
    ]

    return jsonify({
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "inboundMbps": rx,
        "outboundMbps": tx,
        "totalPacketsSec": total_packets,
        "protocolBreakdown": {
            "TCP": tcp_share,
            "UDP": udp_share,
            "ICMP": icmp_share,
            "Other": other_share
        },
        "averageLatencyMs": round(random.uniform(4.2, 11.8), 2),
        "recentPackets": sample_packets
    })

@app.route("/api/topology", methods=["GET"])
def get_topology():
    parser = PacketTracerParser()
    return jsonify(parser.load_topology())

@app.route("/api/analyze/wireshark", methods=["POST", "GET"])
def analyze_wireshark():
    analyzer = WiresharkAnalyzer()
    res = analyzer.analyze_csv()
    return jsonify(res)

@app.route("/api/reports", methods=["GET"])
def get_reports_summary():
    devices = load_json_file("devices.json")
    alerts = load_json_file("alerts.json")

    dept_counts = defaultdict(int)
    for d in devices:
        dept_counts[d.get("department", "Other")] += 1

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for a in alerts:
        sev = a.get("severity", "Low")
        if sev in severity_counts:
            severity_counts[sev] += 1

    return jsonify({
        "generatedAt": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "totalDevices": len(devices),
        "deviceDistribution": dict(dept_counts),
        "alertSeverityCounts": severity_counts,
        "totalAlerts": len(alerts),
        "resolvedAlerts": len([a for a in alerts if a.get("status") == "Resolved"]),
        "networkAvailability": "99.94%",
        "peakBandwidth": "412.0 Mbps",
        "averageDailyTrafficGB": 482.6
    })

@app.route("/api/export/csv/<export_type>", methods=["GET"])
def export_csv(export_type):
    output = io.StringIO()
    writer = csv.writer(output)

    if export_type == "alerts":
        alerts = load_json_file("alerts.json")
        writer.writerow(["Alert ID", "Category", "Description", "Source IP", "Target IP", "Severity", "Timestamp", "Status", "Reason"])
        for a in alerts:
            writer.writerow([
                a.get("id"), a.get("category"), a.get("description"),
                a.get("sourceIp"), a.get("targetIp", "N/A"), a.get("severity"),
                a.get("timestamp"), a.get("status"), a.get("reason")
            ])
        filename = f"netguard_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    elif export_type == "devices":
        devices = load_json_file("devices.json")
        writer.writerow(["Device ID", "Name", "Type", "IP Address", "MAC Address", "Department", "Segment", "Status", "Uptime", "Last Active"])
        for d in devices:
            writer.writerow([
                d.get("id"), d.get("name"), d.get("type"), d.get("ip"),
                d.get("mac"), d.get("department"), d.get("segment"),
                d.get("status"), d.get("uptime"), d.get("lastActive")
            ])
        filename = f"netguard_devices_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    elif export_type == "traffic":
        writer.writerow(["Log ID", "Timestamp", "Metric", "Value", "Unit", "Segment"])
        writer.writerow(["LOG-101", datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "Inbound Bandwidth", "214.5", "Mbps", "Campus Core"])
        writer.writerow(["LOG-102", datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "Outbound Bandwidth", "168.2", "Mbps", "Campus Core"])
        writer.writerow(["LOG-103", datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "TCP Packet Ratio", "71.4", "%", "All Subnets"])
        writer.writerow(["LOG-104", datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "UDP Packet Ratio", "22.1", "%", "All Subnets"])
        writer.writerow(["LOG-105", datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "Average RTT Latency", "6.4", "ms", "Server VLAN 40"])
        filename = f"netguard_traffic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    else:
        return jsonify({"error": "Unknown export type"}), 400

    csv_data = output.getvalue()
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"==================================================")
    print(f" NETGUARD - Campus Network Monitoring & SOC Server")
    print(f" Running at: http://127.0.0.1:{port}")
    print(f" Theme: Dark Emerald Green SOC Dashboard")
    print(f"==================================================")
    app.run(host="0.0.0.0", port=port, debug=True)
