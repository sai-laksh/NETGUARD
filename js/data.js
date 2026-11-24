/**
 * NETGUARD - Smart Campus Network Monitoring and Security System
 * Data Management & Simulation Layer (data.js)
 * 
 * Manages device inventory, security alerts, threat detection rules,
 * simulated live packet stream, localStorage persistence, and CSV export.
 */

const NetGuardData = (() => {
  // Storage keys for persistence
  const STORAGE_ALERTS_KEY = 'netguard_alerts_v1';
  const STORAGE_SETTINGS_KEY = 'netguard_settings_v1';

  // Master initial devices list
  const DEFAULT_DEVICES = [
    {
      id: "DEV-R01",
      name: "Core-Campus-GW",
      type: "Router",
      ip: "10.10.0.1",
      mac: "00:1A:2B:3C:4D:01",
      department: "Infrastructure",
      segment: "Core Gateway",
      status: "Online",
      lastActive: "Just now",
      uptime: "99.98%",
      trafficRate: "142.5 Mbps",
      ports: "Gig0/0/0, Gig0/0/1, TenGig0/1/0",
      model: "Cisco Catalyst 8300 Series"
    },
    {
      id: "DEV-SW01",
      name: "Main-Dist-Switch",
      type: "Switch",
      ip: "10.10.0.2",
      mac: "00:1A:2B:3C:4D:02",
      department: "Infrastructure",
      segment: "Distribution",
      status: "Online",
      lastActive: "Just now",
      uptime: "99.95%",
      trafficRate: "98.2 Mbps",
      ports: "48x 1G SFP+, 4x 10G Uplink",
      model: "Cisco Catalyst 3850 Multilayer"
    },
    {
      id: "DEV-SW-STU",
      name: "Student-Access-SW10",
      type: "Switch",
      ip: "10.10.10.2",
      mac: "00:1A:2B:3C:10:02",
      department: "Student",
      segment: "Student Network",
      status: "Online",
      lastActive: "1 min ago",
      uptime: "99.40%",
      trafficRate: "64.8 Mbps",
      ports: "VLAN 10 (Student-LAN)",
      model: "Cisco Catalyst 2960-X"
    },
    {
      id: "DEV-AP-LIB",
      name: "Library-WiFi-AP01",
      type: "Access Point",
      ip: "10.10.10.15",
      mac: "00:1A:2B:3C:10:15",
      department: "Student",
      segment: "Student Network",
      status: "Online",
      lastActive: "Just now",
      uptime: "98.80%",
      trafficRate: "38.1 Mbps",
      ports: "VLAN 10 (Campus-Student WiFi)",
      model: "Cisco Aironet 2800 Series"
    },
    {
      id: "DEV-PC-LAB1",
      name: "CompLab1-Station04",
      type: "Workstation",
      ip: "10.10.10.45",
      mac: "00:1A:2B:3C:10:45",
      department: "Student",
      segment: "Student Network",
      status: "Attention",
      lastActive: "3 mins ago",
      uptime: "95.20%",
      trafficRate: "412.0 Mbps",
      ports: "Port Fa0/4",
      model: "Dell OptiPlex 7090 - Ubuntu 22.04"
    },
    {
      id: "DEV-PC-LAB2",
      name: "CompLab2-Station12",
      type: "Workstation",
      ip: "10.10.10.52",
      mac: "00:1A:2B:3C:10:52",
      department: "Student",
      segment: "Student Network",
      status: "Online",
      lastActive: "4 mins ago",
      uptime: "97.10%",
      trafficRate: "14.2 Mbps",
      ports: "Port Fa0/12",
      model: "Dell OptiPlex 7090 - Windows 11"
    },
    {
      id: "DEV-BYOD-01",
      name: "Student-BYOD-Host84",
      type: "Laptop",
      ip: "10.10.10.84",
      mac: "00:1A:2B:AA:84:01",
      department: "Student",
      segment: "Student Network",
      status: "Attention",
      lastActive: "Just now",
      uptime: "84.50%",
      trafficRate: "82.4 Mbps",
      ports: "Wireless Assoc via AP01",
      model: "Host OS: Kali Linux 2024.1"
    },
    {
      id: "DEV-BYOD-02",
      name: "Student-Mobile-DHCP",
      type: "Mobile",
      ip: "10.10.10.105",
      mac: "00:1A:2B:BB:10:05",
      department: "Student",
      segment: "Student Network",
      status: "Online",
      lastActive: "2 mins ago",
      uptime: "99.10%",
      trafficRate: "2.8 Mbps",
      ports: "Wireless Assoc via AP01",
      model: "Android Client - DHCP Lease"
    },
    {
      id: "DEV-SW-FAC",
      name: "Faculty-Access-SW20",
      type: "Switch",
      ip: "10.10.20.2",
      mac: "00:1A:2B:3C:20:02",
      department: "Faculty",
      segment: "Faculty Network",
      status: "Online",
      lastActive: "Just now",
      uptime: "99.90%",
      trafficRate: "44.1 Mbps",
      ports: "VLAN 20 (Faculty-LAN)",
      model: "Cisco Catalyst 2960-L"
    },
    {
      id: "DEV-PC-CS01",
      name: "CS-HOD-Workstation",
      type: "Workstation",
      ip: "10.10.20.12",
      mac: "00:1A:2B:3C:20:12",
      department: "Faculty",
      segment: "Faculty Network",
      status: "Online",
      lastActive: "5 mins ago",
      uptime: "99.80%",
      trafficRate: "8.5 Mbps",
      ports: "Port Gi0/12",
      model: "HP EliteDesk 800 G6"
    },
    {
      id: "DEV-PC-RES1",
      name: "AI-Research-Rig-01",
      type: "Workstation",
      ip: "10.10.20.35",
      mac: "00:1A:2B:3C:20:35",
      department: "Faculty",
      segment: "Faculty Network",
      status: "Online",
      lastActive: "Just now",
      uptime: "99.40%",
      trafficRate: "56.3 Mbps",
      ports: "Port Gi0/15",
      model: "Custom Threadripper Workstation"
    },
    {
      id: "DEV-PC-FAC02",
      name: "Networks-Lab-FacultyPC",
      type: "Workstation",
      ip: "10.10.20.48",
      mac: "00:1A:2B:3C:20:48",
      department: "Faculty",
      segment: "Faculty Network",
      status: "Online",
      lastActive: "7 mins ago",
      uptime: "98.90%",
      trafficRate: "11.2 Mbps",
      ports: "Port Gi0/18",
      model: "Lenovo ThinkCentre M920"
    },
    {
      id: "DEV-PRN-FAC",
      name: "Faculty-Office-LaserJet",
      type: "Printer",
      ip: "10.10.20.90",
      mac: "00:1A:2B:3C:20:90",
      department: "Faculty",
      segment: "Faculty Network",
      status: "Offline",
      lastActive: "3 hours ago",
      uptime: "92.00%",
      trafficRate: "0.0 Mbps",
      ports: "Port Gi0/24 (VLAN 20)",
      model: "HP LaserJet Enterprise M608"
    },
    {
      id: "DEV-SW-ADM",
      name: "Admin-Access-SW30",
      type: "Switch",
      ip: "10.10.30.2",
      mac: "00:1A:2B:3C:30:02",
      department: "Administration",
      segment: "Administration Network",
      status: "Online",
      lastActive: "Just now",
      uptime: "99.92%",
      trafficRate: "31.4 Mbps",
      ports: "VLAN 30 (Admin-Secure)",
      model: "Cisco Catalyst 3560-CX"
    },
    {
      id: "DEV-PC-REG",
      name: "Registrar-Secure-PC",
      type: "Workstation",
      ip: "10.10.30.15",
      mac: "00:1A:2B:3C:30:15",
      department: "Administration",
      segment: "Administration Network",
      status: "Online",
      lastActive: "1 min ago",
      uptime: "99.70%",
      trafficRate: "7.9 Mbps",
      ports: "Port Gi0/5",
      model: "Dell Latitude 5430"
    },
    {
      id: "DEV-PC-FIN",
      name: "Finance-Accounts-Host",
      type: "Workstation",
      ip: "10.10.30.22",
      mac: "00:1A:2B:3C:30:22",
      department: "Administration",
      segment: "Administration Network",
      status: "Online",
      lastActive: "2 mins ago",
      uptime: "99.85%",
      trafficRate: "6.4 Mbps",
      ports: "Port Gi0/8",
      model: "Dell OptiPlex 5080 Micro"
    },
    {
      id: "DEV-PC-DEAN",
      name: "Dean-Executive-Laptop",
      type: "Laptop",
      ip: "10.10.30.10",
      mac: "00:1A:2B:3C:30:10",
      department: "Administration",
      segment: "Administration Network",
      status: "Online",
      lastActive: "12 mins ago",
      uptime: "99.10%",
      trafficRate: "4.2 Mbps",
      ports: "Port Gi0/2",
      model: "Lenovo ThinkPad X1 Carbon"
    },
    {
      id: "DEV-SW-SRV",
      name: "DataCenter-Switch-SW40",
      type: "Switch",
      ip: "10.10.40.2",
      mac: "00:1A:2B:3C:40:02",
      department: "Server",
      segment: "Server Network",
      status: "Online",
      lastActive: "Just now",
      uptime: "99.99%",
      trafficRate: "285.6 Mbps",
      ports: "VLAN 40 (Server-Farm Trunk)",
      model: "Cisco Nexus 3048"
    },
    {
      id: "DEV-SRV-DNS",
      name: "Campus-DNS-DHCP-Srv",
      type: "Server",
      ip: "10.10.40.10",
      mac: "00:1A:2B:3C:40:10",
      department: "Server",
      segment: "Server Network",
      status: "Online",
      lastActive: "Just now",
      uptime: "99.99%",
      trafficRate: "22.4 Mbps",
      ports: "DNS (53), DHCP (67/68)",
      model: "BIND9 / ISC DHCP on RHEL 9"
    },
    {
      id: "DEV-SRV-WEB",
      name: "Campus-Web-Portal",
      type: "Server",
      ip: "10.10.40.25",
      mac: "00:1A:2B:3C:40:25",
      department: "Server",
      segment: "Server Network",
      status: "Online",
      lastActive: "Just now",
      uptime: "99.95%",
      trafficRate: "115.8 Mbps",
      ports: "HTTP (80), HTTPS (443)",
      model: "Nginx / Gunicorn Cluster"
    },
    {
      id: "DEV-SRV-ERP",
      name: "Campus-ERP-Database",
      type: "Server",
      ip: "10.10.40.50",
      mac: "00:1A:2B:3C:40:50",
      department: "Server",
      segment: "Server Network",
      status: "Attention",
      lastActive: "Just now",
      uptime: "99.90%",
      trafficRate: "88.6 Mbps",
      ports: "MySQL (3306), SSH (22)",
      model: "PostgreSQL & MySQL Enterprise DB"
    },
    {
      id: "DEV-SRV-MON",
      name: "NetGuard-SOC-Sensor",
      type: "Server",
      ip: "10.10.40.99",
      mac: "00:1A:2B:3C:40:99",
      department: "Server",
      segment: "Server Network",
      status: "Online",
      lastActive: "Just now",
      uptime: "100.00%",
      trafficRate: "45.0 Mbps",
      ports: "Promiscuous SPAN Mirror Port",
      model: "NETGUARD Core Engine Host"
    }
  ];

  // Master initial alerts list
  const DEFAULT_ALERTS = [
    {
      id: "ALT-2026-001",
      threatId: "RULE-AUTH-02",
      category: "Repeated Failed Connection Attempts",
      description: "Repeated SSH authentication failure (14 attempts in 30s) targeting Faculty Access Switch",
      sourceIp: "10.10.10.84",
      targetIp: "10.10.20.2",
      targetPort: 22,
      severity: "Critical",
      timestamp: "2026-11-18 17:42:15",
      status: "New",
      reason: "14 consecutive TCP SYN / RST packets on port 22 exceeding brute-force threshold of 5 attempts within 60s.",
      segment: "Student Network",
      recommendation: "Isolate port Fa0/18 on Student SW-10 and verify student host ownership."
    },
    {
      id: "ALT-2026-002",
      threatId: "RULE-VOL-01",
      category: "Unusual Traffic Volume",
      description: "Outbound bandwidth surge (412 Mbps sustained) from Lab 1 Workstation Station-04",
      sourceIp: "10.10.10.45",
      targetIp: "198.51.100.73",
      targetPort: 443,
      severity: "High",
      timestamp: "2026-11-18 17:35:40",
      status: "Investigating",
      reason: "Traffic spiked to 412 Mbps (normal baseline: 12 Mbps), potential high-speed exfiltration or large unauthorized archive transfer.",
      segment: "Student Network",
      recommendation: "Apply rate-limiting policy on switch port Fa0/4; inspect process list on endpoint."
    },
    {
      id: "ALT-2026-003",
      threatId: "RULE-PAT-03",
      category: "Unusual Communication Patterns",
      description: "Direct database connection attempt from Student BYOD to Campus ERP MySQL Database",
      sourceIp: "10.10.10.84",
      targetIp: "10.10.40.50",
      targetPort: 3306,
      severity: "Critical",
      timestamp: "2026-11-18 17:18:02",
      status: "New",
      reason: "Cross-VLAN connection attempt from untrusted Student VLAN (10) directly to Server VLAN (40) bypassing application gateway.",
      segment: "Student Network",
      recommendation: "Confirm firewall ACL rule drop status; inspect BYOD host MAC for student ID association."
    },
    {
      id: "ALT-2026-004",
      threatId: "RULE-PORT-05",
      category: "Unusual Port Activity",
      description: "Sequential TCP SYN reconnaissance sweep against Server Network range (ports 21-8080)",
      sourceIp: "10.10.10.52",
      targetIp: "10.10.40.0/24",
      targetPort: "Multiple (21,22,80,443,3306,8080)",
      severity: "Medium",
      timestamp: "2026-11-18 16:55:18",
      status: "Investigating",
      reason: "SYN packets sent to 28 discrete ports within 10 seconds without ACK response handshake completion.",
      segment: "Student Network",
      recommendation: "Check if Nmap/Zenmap or automated scanner was executed from CompLab2 station 12."
    },
    {
      id: "ALT-2026-005",
      threatId: "RULE-DEV-04",
      category: "Unexpected Device Activity",
      description: "Faculty office printer initiating outbound DNS query storms to unknown external TLDs",
      sourceIp: "10.10.20.90",
      targetIp: "10.10.40.10",
      targetPort: 53,
      severity: "Medium",
      timestamp: "2026-11-18 15:10:44",
      status: "Resolved",
      reason: "Embedded printer controller requested >300 queries to non-standard domains outside standard business operations.",
      segment: "Faculty Network",
      recommendation: "Firmware was verified and re-flashed; offline status cleared and DNS cache flushed."
    },
    {
      id: "ALT-2026-006",
      threatId: "RULE-PORT-05",
      category: "Unusual Port Activity",
      description: "ICMP Echo broadcast sweep originating from AI Research workstation",
      sourceIp: "10.10.20.35",
      targetIp: "10.10.20.255",
      targetPort: 0,
      severity: "Low",
      timestamp: "2026-11-18 14:02:10",
      status: "Resolved",
      reason: "Broadcast ping packet flood triggered during network benchmark script execution by CS research student.",
      segment: "Faculty Network",
      recommendation: "Research script approved; student advised to use unicast testing parameters."
    },
    {
      id: "ALT-2026-007",
      threatId: "RULE-DEV-04",
      category: "Unexpected Device Activity",
      description: "DHCP lease flapping and high ARP discovery count on Library WiFi Access Point",
      sourceIp: "10.10.10.15",
      targetIp: "10.10.10.255",
      targetPort: 67,
      severity: "Low",
      timestamp: "2026-11-18 11:45:33",
      status: "Resolved",
      reason: "Peak library transit crowd caused rapid DHCP lease renewal requests within 5-minute window.",
      segment: "Student Network",
      recommendation: "DHCP lease time adjusted from 2 hours to 8 hours on Campus-DNS-DHCP-Srv."
    }
  ];

  // Master threat rules definitions
  const THREAT_RULES = [
    {
      id: "RULE-VOL-01",
      category: "Unusual Traffic Volume",
      name: "Excessive Bandwidth Anomaly (Potential Exfiltration / DoS)",
      description: "Flags any host whose sustained transmission rate exceeds 300 Mbps or 10,000 packets per minute for more than 45 seconds.",
      severity: "High",
      threshold: "> 300 Mbps or > 10k pkts/min",
      heuristic: "Baseline bandwidth deviations computed against 24-hour campus rolling average.",
      action: "Generate High Alert, trigger NetFlow capture, alert SOC team."
    },
    {
      id: "RULE-AUTH-02",
      category: "Repeated Failed Connection Attempts",
      name: "Brute-Force Authentication Attempt (SSH / RDP / Telnet)",
      description: "Detects more than 5 consecutive TCP connection resets or authentication rejection responses within a 60-second window directed at management ports (22, 3389, 23).",
      severity: "Critical",
      threshold: "> 5 failed auth within 60s",
      heuristic: "Tracks TCP RST flag and packet count per source-destination port tuple.",
      action: "Generate Critical Alert, isolate attacking source host from access switch port."
    },
    {
      id: "RULE-PAT-03",
      category: "Unusual Communication Patterns",
      name: "Unauthorized Cross-Subnet Traversal (ACL Violation)",
      description: "Identifies non-administrative subnets (e.g., Student VLAN 10) attempting direct connection to confidential administration databases or financial records without authorization.",
      severity: "Critical",
      threshold: "Any student subnet packet to port 3306/5432/1521 on server subnet",
      heuristic: "Compares Layer 3 source IP and Layer 4 destination port against campus Zero-Trust matrix.",
      action: "Log ACL drop, trigger Critical Alert, notify Administrator."
    },
    {
      id: "RULE-DEV-04",
      category: "Unexpected Device Activity",
      name: "Off-Hours Transmission & Out-of-Profile Protocol Use",
      description: "Detects workstation or printer endpoints transmitting anomalous traffic during off-hours (22:00 - 06:00) or initiating unexpected outbound peer-to-peer/IRC protocol connections.",
      severity: "Medium",
      threshold: "Non-standard protocol or transmission outside operational hours",
      heuristic: "Applies device persona baseline modeling comparing current protocol signature to device role.",
      action: "Generate Medium Alert, flag device as 'Requires Attention'."
    },
    {
      id: "RULE-PORT-05",
      category: "Unusual Port Activity",
      name: "Sequential / Fast TCP SYN Port Scanning",
      description: "Detects an endpoint sending SYN packets to 10 or more distinct destination ports on a single host or across multiple hosts within 15 seconds without completing the 3-way handshake.",
      severity: "Medium",
      threshold: ">= 10 unique ports scanned within 15s",
      heuristic: "Measures SYN:ACK ratio and port diversity index in incoming packet stream.",
      action: "Flag as Reconnaissance Attempt, record IP in suspicious actors list."
    }
  ];

  // Dynamic live stream buffer
  let livePacketsBuffer = [];
  let isBackendAvailable = false;

  // Initialize and load persistent data
  function init() {
    if (!localStorage.getItem(STORAGE_ALERTS_KEY)) {
      localStorage.setItem(STORAGE_ALERTS_KEY, JSON.stringify(DEFAULT_ALERTS));
    }
    // Check if Flask backend is available
    checkBackendHealth();
  }

  async function checkBackendHealth() {
    try {
      const resp = await fetch('/api/stats');
      if (resp.ok) {
        isBackendAvailable = true;
        console.log('[NETGUARD] Connected to Flask REST API Backend');
      }
    } catch (e) {
      isBackendAvailable = false;
      console.log('[NETGUARD] Running in Standalone Client Mode (LocalStorage Active)');
    }
  }

  // Get alerts list from localStorage
  function getAlerts() {
    try {
      const data = localStorage.getItem(STORAGE_ALERTS_KEY);
      return data ? JSON.parse(data) : [...DEFAULT_ALERTS];
    } catch (e) {
      return [...DEFAULT_ALERTS];
    }
  }

  // Update alert status and persist
  function updateAlertStatus(alertId, newStatus) {
    const alerts = getAlerts();
    const alert = alerts.find(a => a.id === alertId);
    if (alert) {
      alert.status = newStatus;
      alert.updatedAt = new Date().toISOString().replace('T', ' ').substring(0, 19);
      localStorage.setItem(STORAGE_ALERTS_KEY, JSON.stringify(alerts));

      // Attempt to sync with Flask API if available
      if (isBackendAvailable) {
        fetch(`/api/alerts/${alertId}/status`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: newStatus })
        }).catch(() => {});
      }
      return true;
    }
    return false;
  }

  // Get device inventory
  function getDevices() {
    return [...DEFAULT_DEVICES];
  }

  // Get threat rules
  function getThreatRules() {
    return [...THREAT_RULES];
  }

  // Add simulated threat alert (for demo triggers)
  function injectSimulatedThreat(threatType) {
    const alerts = getAlerts();
    const newId = `ALT-2026-${String(alerts.length + 1).padStart(3, '0')}`;
    const nowStr = new Date().toISOString().replace('T', ' ').substring(0, 19);

    let newAlert = null;
    if (threatType === 'bruteforce') {
      newAlert = {
        id: newId,
        threatId: "RULE-AUTH-02",
        category: "Repeated Failed Connection Attempts",
        description: "Simulated SSH Brute-Force: 20 failed attempts in 25s against Student SW-10",
        sourceIp: "10.10.10.84",
        targetIp: "10.10.10.2",
        targetPort: 22,
        severity: "Critical",
        timestamp: nowStr,
        status: "New",
        reason: "Simulated brute force test packet sequence injected via demo console.",
        segment: "Student Network",
        recommendation: "Isolate port Fa0/18 and check device authentication log."
      };
    } else if (threatType === 'portscan') {
      newAlert = {
        id: newId,
        threatId: "RULE-PORT-05",
        category: "Unusual Port Activity",
        description: "Simulated SYN Port Sweep: 35 ports scanned on Campus DNS Server",
        sourceIp: "10.10.10.52",
        targetIp: "10.10.40.10",
        targetPort: "Ports 20-100",
        severity: "Medium",
        timestamp: nowStr,
        status: "New",
        reason: "Simulated reconnaissance scan detected by NETGUARD Layer 4 monitor.",
        segment: "Student Network",
        recommendation: "Inspect CompLab2 terminal 12 for active scanning processes."
      };
    } else if (threatType === 'crossvlan') {
      newAlert = {
        id: newId,
        threatId: "RULE-PAT-03",
        category: "Unusual Communication Patterns",
        description: "Simulated Cross-VLAN Violation: Direct query to Registrar terminal from Student WiFi",
        sourceIp: "10.10.10.105",
        targetIp: "10.10.30.15",
        targetPort: 445,
        severity: "Critical",
        timestamp: nowStr,
        status: "New",
        reason: "Zero-Trust ACL violation: SMB port 445 probe across segment boundaries.",
        segment: "Student Network",
        recommendation: "Verify switch ACL drop logs and inspect connected mobile device."
      };
    } else {
      newAlert = {
        id: newId,
        threatId: "RULE-VOL-01",
        category: "Unusual Traffic Volume",
        description: "Simulated Traffic Surge: 450 Mbps anomaly spike from Research PC",
        sourceIp: "10.10.20.35",
        targetIp: "198.51.100.99",
        targetPort: 443,
        severity: "High",
        timestamp: nowStr,
        status: "New",
        reason: "Simulated volumetric anomaly triggered via demonstration control panel.",
        segment: "Faculty Network",
        recommendation: "Verify research file transfer parameters and throttle bandwidth."
      };
    }

    alerts.unshift(newAlert);
    localStorage.setItem(STORAGE_ALERTS_KEY, JSON.stringify(alerts));
    return newAlert;
  }

  // Calculate live summary statistics
  function getDashboardStats() {
    const devices = getDevices();
    const alerts = getAlerts();

    const totalDevices = devices.length;
    const activeDevices = devices.filter(d => d.status === 'Online').length;
    const unresolvedAlerts = alerts.filter(a => a.status !== 'Resolved');
    const criticalAlerts = alerts.filter(a => a.severity === 'Critical' && a.status !== 'Resolved').length;

    // Health Score calculation (SOC formula)
    let health = 100 - (criticalAlerts * 8) - ((unresolvedAlerts.length - criticalAlerts) * 3);
    health = Math.max(50, Math.min(99, health));

    // Dynamic bandwidth based on simulated load
    const rx = (195 + (Math.random() * 45 - 20)).toFixed(1);
    const tx = (155 + (Math.random() * 35 - 15)).toFixed(1);
    const totalTraffic = (parseFloat(rx) + parseFloat(tx)).toFixed(1);

    return {
      totalDevices,
      activeDevices,
      offlineDevices: totalDevices - activeDevices,
      totalTrafficMbps: totalTraffic,
      inboundTrafficMbps: rx,
      outboundTrafficMbps: tx,
      suspiciousActivities: unresolvedAlerts.length,
      criticalAlerts,
      networkHealthScore: health
    };
  }

  // Generate a live simulated packet stream
  function generateSimulatedPacket() {
    const protocols = ['TCP', 'TCP', 'UDP', 'HTTPS', 'DNS', 'ICMP', 'SSH', 'ARP'];
    const lengths = [64, 128, 512, 1024, 1460, 1514];
    const srcHost = Math.floor(Math.random() * 120) + 10;
    const dstServer = ['10.10.40.10', '10.10.40.25', '10.10.40.50', '10.10.0.1', '198.51.100.8'][Math.floor(Math.random() * 5)];
    const proto = protocols[Math.floor(Math.random() * protocols.length)];

    const packet = {
      id: `PKT-${Math.floor(10000 + Math.random() * 90000)}`,
      time: new Date().toLocaleTimeString(),
      source: `10.10.10.${srcHost}`,
      destination: dstServer,
      protocol: proto,
      length: lengths[Math.floor(Math.random() * lengths.length)],
      status: proto === 'SSH' && srcHost === 84 ? 'Warning' : 'Pass'
    };

    livePacketsBuffer.unshift(packet);
    if (livePacketsBuffer.length > 50) livePacketsBuffer.pop();
    return packet;
  }

  function getRecentPackets() {
    if (livePacketsBuffer.length === 0) {
      for (let i = 0; i < 8; i++) generateSimulatedPacket();
    }
    return livePacketsBuffer.slice(0, 10);
  }

  // CSV Exporters
  function exportCSV(filename, csvContent) {
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', filename);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }

  function exportAlertsToCSV() {
    const alerts = getAlerts();
    let csv = "Alert ID,Category,Description,Source IP,Target IP,Severity,Timestamp,Status,Detection Reason,Segment\n";
    alerts.forEach(a => {
      csv += `"${a.id}","${a.category}","${a.description.replace(/"/g, '""')}","${a.sourceIp}","${a.targetIp || 'N/A'}","${a.severity}","${a.timestamp}","${a.status}","${(a.reason || '').replace(/"/g, '""')}","${a.segment || 'Campus Network'}"\n`;
    });
    const filename = `NETGUARD_Security_Alerts_${new Date().toISOString().slice(0,10)}.csv`;
    exportCSV(filename, csv);
  }

  function exportDevicesToCSV() {
    const devices = getDevices();
    let csv = "Device ID,Device Name,Type,IP Address,MAC Address,Department,Segment,Connection Status,Uptime,Traffic Rate,Model\n";
    devices.forEach(d => {
      csv += `"${d.id}","${d.name}","${d.type}","${d.ip}","${d.mac}","${d.department}","${d.segment}","${d.status}","${d.uptime}","${d.trafficRate}","${d.model}"\n`;
    });
    const filename = `NETGUARD_Device_Inventory_${new Date().toISOString().slice(0,10)}.csv`;
    exportCSV(filename, csv);
  }

  function exportTrafficToCSV() {
    let csv = "Log ID,Timestamp,Metric Name,Value,Unit,Segment,Source Type\n";
    const now = new Date().toISOString().replace('T', ' ').substring(0, 19);
    csv += `"TRF-101","${now}","Inbound Throughput","218.4","Mbps","Campus Core Gateway","Simulated Wireshark Stream"\n`;
    csv += `"TRF-102","${now}","Outbound Throughput","164.2","Mbps","Campus Core Gateway","Simulated Wireshark Stream"\n`;
    csv += `"TRF-103","${now}","TCP Packet Proportion","72.5","%","Campus Subnets","Simulated Packet Monitor"\n`;
    csv += `"TRF-104","${now}","UDP Packet Proportion","21.3","%","Campus Subnets","Simulated Packet Monitor"\n`;
    csv += `"TRF-105","${now}","ICMP Packet Proportion","4.2","%","Campus Subnets","Simulated Packet Monitor"\n`;
    csv += `"TRF-106","${now}","Average RTT Latency","6.8","ms","Server Farm VLAN 40","Simulated Ping Diagnostics"\n`;
    const filename = `NETGUARD_Traffic_Metrics_${new Date().toISOString().slice(0,10)}.csv`;
    exportCSV(filename, csv);
  }

  // Self initialize
  init();

  return {
    getAlerts,
    updateAlertStatus,
    getDevices,
    getThreatRules,
    getDashboardStats,
    injectSimulatedThreat,
    generateSimulatedPacket,
    getRecentPackets,
    exportAlertsToCSV,
    exportDevicesToCSV,
    exportTrafficToCSV
  };
})();
