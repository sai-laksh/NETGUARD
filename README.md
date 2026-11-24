# NETGUARD – Smart Campus Network Monitoring and Security System

**A Computer Networks (CN) Capstone Project**  
*SOC-Grade Network Telemetry, Rule-Based Threat Detection & Campus Topology Visualization*

---

## 1. Project Overview

**NETGUARD** is a smart campus network monitoring and security dashboard designed to monitor campus-wide network activity, identify predefined suspicious behaviors (such as brute-force authentication attacks, SYN port sweeps, cross-VLAN unauthorized traversal, and anomalous bandwidth surges), and generate persistent security alerts.

### Capstone Project Components:
- **Cisco Packet Tracer 8.2**: Campus network architecture design, VLAN segmentation (VLAN 10, 20, 30, 40), and switch-router interconnections.
- **Wireshark**: Packet-level inspection, protocol analysis, and traffic capture emulations.
- **Python & Flask**: Data processing engine, anomaly heuristics, and REST API backend.
- **HTML5, CSS3 & Modern JavaScript**: Responsive Security Operations Center (SOC) dashboard interface.
- **Sample / Simulated Network Telemetry**: Initial testing and live demonstration data engine.

> **Important Note:** This website is the dashboard component of our larger capstone project. Initially, it functions independently using realistic simulated network telemetry. It does not falsely claim a live socket connection to Cisco Packet Tracer or Wireshark; rather, it provides a clean, decoupled data ingestion architecture where exported Wireshark captures (`.csv` / `.pcap`) and Packet Tracer topology outputs (`.json`) can be processed and visualized.

---

## 2. Design & Color Palette – Dark Emerald Green

NETGUARD uses a sophisticated, professional dark forest-green and emerald-green theme styled after modern Security Operations Center (SOC) interfaces:

| UI Element | Color Name | Hex Code | Purpose |
| :--- | :--- | :--- | :--- |
| **Main Background** | Deep Forest Black | `#07140F` | Overall dashboard background |
| **Sidebar** | Dark Emerald | `#0B1C13` | Sidebar navigation container |
| **Dashboard Cards** | Forest Green | `#10251B` | Primary surface for cards & tables |
| **Secondary Surfaces**| Emerald Surface | `#17452F` | Table headers, modals & badges |
| **Primary Accent** | Emerald Green | `#237A50` | Primary buttons & trunk lines |
| **Highlight Accent**| Mint Green | `#51D99A` | Active links, metric values, graph lines |
| **Main Text** | Soft White | `#E4F4E9` | Headers, primary data labels |
| **Secondary Text** | Muted Sage Green | `#A5C6B0` | Subtitles, timestamps & metadata |
| **Critical Alerts** | Red | `#EF4444` | Strictly reserved for critical security events |
| **Warnings** | Amber / Orange | `#F59E0B` | Reserved for warnings & attention states |
| **Normal Status** | Mint Green | `#51D99A` | Healthy devices, normal packet flow |

---

## 3. Website Architecture & Pages

The application is structured into 8 functional, responsive modules accessible via the sidebar navigation:

1. **Dashboard (`#dashboard`)**:
   - Executive network summary: Total Connected Devices (22), Active Devices (21), Network Traffic (Mbps), Suspicious Activities (4), Critical Alerts (2), Network Health Score (92%).
   - 4 Interactive SOC Charts: Network Traffic Over Time (Line), Normal vs. Suspicious Traffic (Doughnut), Security Alerts by Severity (Bar), Device Distribution by Department (Doughnut).
   - Recent Security Events table with quick details.

2. **Network Overview (`#network-overview`)**:
   - Visual representation of the campus network across 4 VLAN segments:
     - **Student Network (VLAN 10 / `10.10.10.0/24`)**: Access Switch SW-10, Library WiFi AP-01, Computer Lab workstations, and student BYOD hosts.
     - **Faculty Network (VLAN 20 / `10.10.20.0/24`)**: Access Switch SW-20, CS HOD PC, AI Research workstation, faculty desktops, and network printer.
     - **Administration Network (VLAN 30 / `10.10.30.0/24`)**: Secure Switch SW-30, Registrar, Finance, and Dean terminals.
     - **Server Network & Data Center (VLAN 40 / `10.10.40.0/24`)**: Core Switch SW-40, Campus DNS/DHCP, Web Portal, ERP Database, and NetGuard SPAN Sensor.
   - Interactive HTML5 Canvas topology with animated traffic packet pulses.
   - Click-to-inspect device drawer with live ICMP Ping diagnostics simulator.

3. **Traffic Monitoring (`#traffic`)**:
   - Live metrics: Inbound Throughput, Outbound Throughput, Total Packets/sec, TCP, UDP, ICMP breakdown.
   - Real-time updating bandwidth chart with configurable polling intervals.
   - Live simulated packet capture stream emulating Wireshark frame captures.

4. **Threat Detection (`#threat-detection`)**:
   - Rule-based detection cards for the 5 required threat categories:
     - *Unusual Traffic Volume* (threshold > 300 Mbps or 10k pkts/min).
     - *Repeated Failed Connection Attempts* (> 5 failed SSH/RDP connection resets in 60s).
     - *Unusual Communication Patterns* (unauthorized cross-VLAN traversal into Admin database).
     - *Unexpected Device Activity* (off-hours transmission / non-standard protocols).
     - *Unusual Port Activity* (fast TCP SYN port sweep across $\ge$10 discrete ports).
   - "Explain Rule" interactive heuristic guide.
   - Host isolation action triggering simulated switch port shutdown.

5. **Security Alerts (`#security-alerts`)**:
   - Dedicated incident response console.
   - Multi-criteria filtering by Severity (All, Critical, High, Medium, Low) and Status (New, Investigating, Resolved).
   - Search by IP, Alert ID, or category.
   - Incident Modal displaying timeline, trigger reason, recommended mitigation, and raw synthetic Wireshark capture.
   - **Persistent state changes**: Status updates persist across page reloads via `localStorage` and Flask REST API.

6. **Device Inventory (`#devices`)**:
   - Table of 22 campus devices with IP, MAC, VLAN, Hardware Model, Status, and Uptime.
   - Filter by Department and Connection Status.
   - Search by Name, IP, or MAC.
   - Ping diagnostics tool and "Locate in Topology" shortcut.

7. **Reports (`#reports`)**:
   - 24-hour activity summaries, incident audits, and campus availability statistics.
   - Threat category and segment bandwidth visual charts.
   - **Real CSV Export**: One-click generation and download of `netguard_alerts.csv`, `netguard_devices.csv`, and `netguard_traffic.csv`.
   - Print-friendly Executive Report formatting.

8. **Settings (`#settings`)**:
   - Dark Emerald Green SOC theme specification tokens.
   - Telemetry polling interval slider (1s to 10s).
   - Simulation pause/resume toggle.
   - **Interactive Demo Attack Injector**: Trigger simulated brute-force, SYN port sweep, cross-VLAN violation, or bandwidth surge during your capstone viva!
   - Cisco Packet Tracer & Wireshark future integration architecture guide.

---

## 4. How to Run the Project

The project is beginner-friendly and requires zero complicated build tools or heavy node package installs.

### Option A: One-Click Startup (Windows)
Double-click `run.bat` (or right-click `run.ps1` and select *Run with PowerShell*).  
It automatically detects Python and launches the server, opening your browser.

### Option B: Running with Python Flask Backend
Open your terminal in the `NETGUARD` directory and run:

```powershell
# Using Python
python app.py

# Or if Python 3.9 is located in AppData:
& "$env:LOCALAPPDATA\Programs\Python\Python39\python.exe" app.py
```

Then open your browser at:
```
http://127.0.0.1:5000
```

### Option C: Pure Client-Side Mode (No Backend Required)
You can directly open `index.html` in any web browser (Chrome, Edge, Firefox, Brave):
```powershell
start index.html
```
*NETGUARD includes a built-in client-side simulation engine with `localStorage` persistence and canvas chart rendering fallbacks, so 100% of the functionality works even without running a server or without internet access!*

---

## 5. File & Directory Structure

```
NETGUARD/
│
├── index.html                   # Master responsive dashboard SPA
├── app.py                       # Python Flask server & REST API
├── pcap_analyzer.py             # Wireshark CSV/PCAP packet processing engine
├── packet_tracer_parser.py      # Cisco Packet Tracer topology & link parser
├── run.bat                      # Windows one-click batch launcher
├── run.ps1                      # Windows PowerShell launcher
├── README.md                    # Project documentation & presentation guide
│
├── css/
│   └── style.css                # Dark Emerald Green SOC stylesheet
│
├── js/
│   ├── data.js                  # Data layer, simulated packets, persistence & CSV exporter
│   ├── charts.js                # Chart.js configs & canvas fallback renderers
│   ├── topology.js              # Interactive campus network canvas & animated pulses
│   ├── alerts.js                # Alert management, status persistence & modal handler
│   └── app.js                   # Application router, live clock, toasts & demo controls
│
└── data/
    ├── devices.json             # Campus device inventory (22 nodes across 4 VLANs)
    ├── alerts.json              # Initial security alerts dataset
    ├── threat_rules.json        # 5 predefined threat heuristic specifications
    ├── sample_wireshark_export.csv # Sample exported Wireshark packet capture
    └── packet_tracer_topology.json # Cisco Packet Tracer export format
```

---

## 6. Future Integration with Cisco Packet Tracer & Wireshark

During college viva or capstone demonstrations, explain how the software architecture separates presentation from packet ingestion:

1. **Ingesting Real Wireshark Traffic**:
   - In Wireshark, capture traffic and select `File -> Export Packet Dissections -> As CSV...`.
   - Pass this file into `pcap_analyzer.py` via `WiresharkAnalyzer().analyze_csv("your_capture.csv")`.
   - The Python engine processes protocol distributions, flags TCP RST brute-force anomalies, and feeds the `/api/analyze/wireshark` endpoint.

2. **Ingesting Cisco Packet Tracer Topologies**:
   - In Cisco Packet Tracer, export the device inventory and router configuration logs.
   - `packet_tracer_parser.py` parses switch ports, VLAN assignments, and interface link states (`UP`, `WARNING`, `DOWN`), feeding `/api/topology`.

3. **Zero-Trust Network Access (ZTNA) & ACL Validation**:
   - The cross-VLAN detection rule (`RULE-PAT-03`) emulates how an internal firewall or router Access Control List (ACL) drops packets from unauthorized subnets (e.g. Student VLAN 10 trying to connect directly to MySQL Database port 3306 on Server VLAN 40).

---

## 7. Capstone Viva Q&A Guide

- **Q: Why does the system use a Dark Emerald Green theme instead of generic blue?**  
  *A:* Professional Security Operations Centers (SOCs) use dark emerald palettes to reduce eye fatigue during long monitoring shifts and reserve high-contrast red strictly for critical security alerts, ensuring visual anomalies stand out instantly without color confusion.

- **Q: How does the system detect brute-force attacks?**  
  *A:* Rule `RULE-AUTH-02` monitors Layer 4 TCP connection resets (`RST-ACK`). More than 5 failed connection resets within a 60-second window directed at management ports (SSH 22, RDP 3389) triggers a Critical security alert.

- **Q: How does state persistence work?**  
  *A:* Alert status updates (`New` $\rightarrow$ `Investigating` $\rightarrow$ `Resolved`) are saved to browser `localStorage` and simultaneously dispatched via `POST` to the Flask REST API `/api/alerts/<id>/status`, persisting across refreshes.

- **Q: What happens if there is no internet connection during evaluation?**  
  *A:* All UI icons are inline vector SVGs, and `charts.js` contains a native HTML5 Canvas drawing fallback that automatically renders line, doughnut, and bar charts even if external CDN libraries are unreachable.
