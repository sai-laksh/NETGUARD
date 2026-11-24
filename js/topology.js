/**
 * NETGUARD - Smart Campus Network Monitoring and Security System
 * Campus Network Topology Engine (topology.js)
 * 
 * Renders an interactive visual campus network diagram with 4 segments:
 * Student, Faculty, Administration, and Server Farm.
 * Features animated packet flows, status indicators, node inspection drawer,
 * and realistic ping diagnostics.
 */

const NetGuardTopology = (() => {
  let canvas, ctx;
  let animationFrameId = null;
  let activeFilter = 'All';
  let selectedNode = null;
  let hoveredNode = null;
  let packetPulses = [];

  // Topology node positioning and network hierarchy
  const NODES = [
    // Core Backbone
    { id: "DEV-R01", name: "Core-GW-R01", type: "Router", ip: "10.10.0.1", segment: "Core", x: 450, y: 70, status: "Online", icon: "router" },
    { id: "DEV-SW01", name: "Dist-Switch-SW01", type: "Switch", ip: "10.10.0.2", segment: "Core", x: 450, y: 160, status: "Online", icon: "switch" },

    // Student Subnet (10.10.10.0/24) - Top Left
    { id: "DEV-SW-STU", name: "Student-SW10", type: "Switch", ip: "10.10.10.2", segment: "Student", x: 180, y: 240, status: "Online", icon: "switch" },
    { id: "DEV-AP-LIB", name: "Library-AP01", type: "Access Point", ip: "10.10.10.15", segment: "Student", x: 80, y: 330, status: "Online", icon: "ap" },
    { id: "DEV-PC-LAB1", name: "Lab1-Station04", type: "Workstation", ip: "10.10.10.45", segment: "Student", x: 170, y: 350, status: "Attention", icon: "pc" },
    { id: "DEV-PC-LAB2", name: "Lab2-Station12", type: "Workstation", ip: "10.10.10.52", segment: "Student", x: 250, y: 340, status: "Online", icon: "pc" },
    { id: "DEV-BYOD-01", name: "BYOD-Host84", type: "Laptop", ip: "10.10.10.84", segment: "Student", x: 50, y: 440, status: "Attention", icon: "laptop" },
    { id: "DEV-BYOD-02", name: "Student-Mobile", type: "Mobile", ip: "10.10.10.105", segment: "Student", x: 110, y: 440, status: "Online", icon: "mobile" },

    // Faculty Subnet (10.10.20.0/24) - Bottom Left
    { id: "DEV-SW-FAC", name: "Faculty-SW20", type: "Switch", ip: "10.10.20.2", segment: "Faculty", x: 360, y: 260, status: "Online", icon: "switch" },
    { id: "DEV-PC-CS01", name: "CS-HOD-PC", type: "Workstation", ip: "10.10.20.12", segment: "Faculty", x: 310, y: 370, status: "Online", icon: "pc" },
    { id: "DEV-PC-RES1", name: "AI-Research-Rig", type: "Workstation", ip: "10.10.20.35", segment: "Faculty", x: 380, y: 380, status: "Online", icon: "pc" },
    { id: "DEV-PRN-FAC", name: "Faculty-LaserJet", type: "Printer", ip: "10.10.20.90", segment: "Faculty", x: 440, y: 370, status: "Offline", icon: "printer" },

    // Administration Subnet (10.10.30.0/24) - Bottom Right
    { id: "DEV-SW-ADM", name: "Admin-SW30", type: "Switch", ip: "10.10.30.2", segment: "Administration", x: 570, y: 260, status: "Online", icon: "switch" },
    { id: "DEV-PC-REG", name: "Registrar-PC", type: "Workstation", ip: "10.10.30.15", segment: "Administration", x: 520, y: 370, status: "Online", icon: "pc" },
    { id: "DEV-PC-FIN", name: "Finance-PC", type: "Workstation", ip: "10.10.30.22", segment: "Administration", x: 590, y: 380, status: "Online", icon: "pc" },
    { id: "DEV-PC-DEAN", name: "Dean-Laptop", type: "Laptop", ip: "10.10.30.10", segment: "Administration", x: 650, y: 370, status: "Online", icon: "laptop" },

    // Server Network & Data Center (10.10.40.0/24) - Top Right
    { id: "DEV-SW-SRV", name: "DataCenter-SW40", type: "Switch", ip: "10.10.40.2", segment: "Server", x: 740, y: 230, status: "Online", icon: "switch" },
    { id: "DEV-SRV-DNS", name: "DNS-DHCP-Server", type: "Server", ip: "10.10.40.10", segment: "Server", x: 700, y: 330, status: "Online", icon: "server" },
    { id: "DEV-SRV-WEB", name: "Campus-Web-Portal", type: "Server", ip: "10.10.40.25", segment: "Server", x: 760, y: 340, status: "Online", icon: "server" },
    { id: "DEV-SRV-ERP", name: "ERP-Database", type: "Server", ip: "10.10.40.50", segment: "Server", x: 820, y: 330, status: "Attention", icon: "server" },
    { id: "DEV-SRV-MON", name: "NetGuard-Sensor", type: "Server", ip: "10.10.40.99", segment: "Server", x: 870, y: 270, status: "Online", icon: "server" }
  ];

  // Interconnecting links
  const LINKS = [
    { from: "DEV-R01", to: "DEV-SW01", type: "trunk", status: "UP" },
    { from: "DEV-SW01", to: "DEV-SW-STU", type: "trunk", status: "UP" },
    { from: "DEV-SW01", to: "DEV-SW-FAC", type: "trunk", status: "UP" },
    { from: "DEV-SW01", to: "DEV-SW-ADM", type: "trunk", status: "UP" },
    { from: "DEV-SW01", to: "DEV-SW-SRV", type: "trunk", status: "UP" },

    // Student links
    { from: "DEV-SW-STU", to: "DEV-AP-LIB", type: "ethernet", status: "UP" },
    { from: "DEV-SW-STU", to: "DEV-PC-LAB1", type: "ethernet", status: "WARNING" },
    { from: "DEV-SW-STU", to: "DEV-PC-LAB2", type: "ethernet", status: "UP" },
    { from: "DEV-AP-LIB", to: "DEV-BYOD-01", type: "wireless", status: "WARNING" },
    { from: "DEV-AP-LIB", to: "DEV-BYOD-02", type: "wireless", status: "UP" },

    // Faculty links
    { from: "DEV-SW-FAC", to: "DEV-PC-CS01", type: "ethernet", status: "UP" },
    { from: "DEV-SW-FAC", to: "DEV-PC-RES1", type: "ethernet", status: "UP" },
    { from: "DEV-SW-FAC", to: "DEV-PRN-FAC", type: "ethernet", status: "DOWN" },

    // Admin links
    { from: "DEV-SW-ADM", to: "DEV-PC-REG", type: "ethernet", status: "UP" },
    { from: "DEV-SW-ADM", to: "DEV-PC-FIN", type: "ethernet", status: "UP" },
    { from: "DEV-SW-ADM", to: "DEV-PC-DEAN", type: "ethernet", status: "UP" },

    // Server links
    { from: "DEV-SW-SRV", to: "DEV-SRV-DNS", type: "ethernet", status: "UP" },
    { from: "DEV-SW-SRV", to: "DEV-SRV-WEB", type: "ethernet", status: "UP" },
    { from: "DEV-SW-SRV", to: "DEV-SRV-ERP", type: "ethernet", status: "WARNING" },
    { from: "DEV-SW-SRV", to: "DEV-SRV-MON", type: "ethernet", status: "UP" }
  ];

  function init(canvasId) {
    canvas = document.getElementById(canvasId);
    if (!canvas) return;
    ctx = canvas.getContext('2d');

    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);

    // Mouse interaction
    canvas.addEventListener('mousemove', onMouseMove);
    canvas.addEventListener('click', onCanvasClick);

    // Initialize animated packet pulses
    initPulses();

    // Start animation loop
    if (animationFrameId) cancelAnimationFrame(animationFrameId);
    renderLoop();
  }

  function resizeCanvas() {
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width;
    canvas.height = rect.height;
  }

  function initPulses() {
    packetPulses = [];
    for (let i = 0; i < 12; i++) {
      const link = LINKS[Math.floor(Math.random() * LINKS.length)];
      if (link.status !== 'DOWN') {
        packetPulses.push({
          link,
          progress: Math.random(),
          speed: 0.005 + Math.random() * 0.008,
          color: link.status === 'WARNING' ? '#F59E0B' : '#51D99A'
        });
      }
    }
  }

  function renderLoop() {
    if (!ctx) return;
    render();
    animationFrameId = requestAnimationFrame(renderLoop);
  }

  function render() {
    const w = canvas.width;
    const h = canvas.height;
    ctx.clearRect(0, 0, w, h);

    // Compute coordinate scaling
    const scaleX = w / 960;
    const scaleY = h / 520;

    // Draw segment boundary containers
    drawSegmentBackdrops(scaleX, scaleY);

    // Draw links
    LINKS.forEach(link => {
      const n1 = NODES.find(n => n.id === link.from);
      const n2 = NODES.find(n => n.id === link.to);
      if (!n1 || !n2) return;

      const isFilteredOut = activeFilter !== 'All' && n1.segment !== activeFilter && n2.segment !== activeFilter && n1.segment !== 'Core';

      ctx.save();
      ctx.beginPath();
      ctx.moveTo(n1.x * scaleX, n1.y * scaleY);
      ctx.lineTo(n2.x * scaleX, n2.y * scaleY);

      if (isFilteredOut) {
        ctx.strokeStyle = 'rgba(81, 217, 154, 0.05)';
        ctx.lineWidth = 1;
      } else if (link.status === 'DOWN') {
        ctx.strokeStyle = '#EF4444';
        ctx.lineWidth = 1.5;
        ctx.setLineDash([4, 4]);
      } else if (link.status === 'WARNING') {
        ctx.strokeStyle = '#F59E0B';
        ctx.lineWidth = 2;
      } else if (link.type === 'trunk') {
        ctx.strokeStyle = '#237A50';
        ctx.lineWidth = 3;
      } else if (link.type === 'wireless') {
        ctx.strokeStyle = '#51D99A';
        ctx.lineWidth = 1.5;
        ctx.setLineDash([3, 3]);
      } else {
        ctx.strokeStyle = 'rgba(81, 217, 154, 0.35)';
        ctx.lineWidth = 1.8;
      }
      ctx.stroke();
      ctx.restore();
    });

    // Draw animated packet pulses
    packetPulses.forEach(pulse => {
      const n1 = NODES.find(n => n.id === pulse.link.from);
      const n2 = NODES.find(n => n.id === pulse.link.to);
      if (!n1 || !n2) return;

      const isFilteredOut = activeFilter !== 'All' && n1.segment !== activeFilter && n2.segment !== activeFilter && n1.segment !== 'Core';
      if (isFilteredOut) return;

      pulse.progress += pulse.speed;
      if (pulse.progress > 1) {
        pulse.progress = 0;
        pulse.link = LINKS[Math.floor(Math.random() * LINKS.length)];
      }

      const x = (n1.x + (n2.x - n1.x) * pulse.progress) * scaleX;
      const y = (n1.y + (n2.y - n1.y) * pulse.progress) * scaleY;

      ctx.save();
      ctx.beginPath();
      ctx.arc(x, y, 3, 0, Math.PI * 2);
      ctx.fillStyle = pulse.color;
      ctx.shadowColor = pulse.color;
      ctx.shadowBlur = 6;
      ctx.fill();
      ctx.restore();
    });

    // Draw Nodes
    NODES.forEach(node => {
      const isFilteredOut = activeFilter !== 'All' && node.segment !== activeFilter && node.segment !== 'Core';
      drawNode(node, scaleX, scaleY, isFilteredOut);
    });
  }

  function drawSegmentBackdrops(scaleX, scaleY) {
    // Subtle boundary boxes for the 4 segments
    const segments = [
      { name: 'Student Subnet (VLAN 10)', x: 20, y: 200, w: 250, h: 290, color: 'rgba(81, 217, 154, 0.03)' },
      { name: 'Faculty Subnet (VLAN 20)', x: 290, y: 215, w: 180, h: 250, color: 'rgba(35, 122, 80, 0.04)' },
      { name: 'Administration (VLAN 30)', x: 495, y: 215, w: 185, h: 250, color: 'rgba(23, 69, 47, 0.06)' },
      { name: 'Server Farm (VLAN 40)', x: 675, y: 185, w: 260, h: 280, color: 'rgba(81, 217, 154, 0.03)' }
    ];

    segments.forEach(seg => {
      const isTarget = activeFilter === 'All' || seg.name.toLowerCase().includes(activeFilter.toLowerCase());
      ctx.save();
      ctx.fillStyle = seg.color;
      ctx.strokeStyle = isTarget ? 'rgba(81, 217, 154, 0.18)' : 'rgba(81, 217, 154, 0.04)';
      ctx.lineWidth = 1;
      ctx.roundRect ? ctx.roundRect(seg.x * scaleX, seg.y * scaleY, seg.w * scaleX, seg.h * scaleY, 8) : ctx.rect(seg.x * scaleX, seg.y * scaleY, seg.w * scaleX, seg.h * scaleY);
      ctx.fill();
      ctx.stroke();

      ctx.fillStyle = isTarget ? 'rgba(165, 198, 176, 0.65)' : 'rgba(165, 198, 176, 0.2)';
      ctx.font = '10px monospace';
      ctx.fillText(seg.name, (seg.x + 10) * scaleX, (seg.y + 18) * scaleY);
      ctx.restore();
    });
  }

  function drawNode(node, scaleX, scaleY, isFilteredOut) {
    const x = node.x * scaleX;
    const y = node.y * scaleY;
    const radius = node.type === 'Router' ? 20 : node.type === 'Switch' ? 17 : 14;

    const isHovered = hoveredNode && hoveredNode.id === node.id;
    const isSelected = selectedNode && selectedNode.id === node.id;

    ctx.save();
    if (isFilteredOut) {
      ctx.globalAlpha = 0.25;
    }

    // Node background circle
    ctx.beginPath();
    ctx.arc(x, y, radius, 0, Math.PI * 2);
    ctx.fillStyle = isSelected ? '#17452F' : '#10251B';
    ctx.fill();

    // Node border status ring
    ctx.lineWidth = isHovered || isSelected ? 3 : 2;
    if (node.status === 'Online') {
      ctx.strokeStyle = '#51D99A';
      if (isHovered) {
        ctx.shadowColor = '#51D99A';
        ctx.shadowBlur = 10;
      }
    } else if (node.status === 'Attention') {
      ctx.strokeStyle = '#F59E0B';
      if (isHovered) {
        ctx.shadowColor = '#F59E0B';
        ctx.shadowBlur = 10;
      }
    } else {
      ctx.strokeStyle = '#EF4444';
    }
    ctx.stroke();

    // Icon symbol / letter inside
    ctx.fillStyle = node.status === 'Online' ? '#51D99A' : node.status === 'Attention' ? '#F59E0B' : '#A5C6B0';
    ctx.font = `bold ${radius > 16 ? 11 : 9}px sans-serif`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';

    let labelSymbol = 'PC';
    if (node.type === 'Router') labelSymbol = 'RTR';
    else if (node.type === 'Switch') labelSymbol = 'SW';
    else if (node.type === 'Server') labelSymbol = 'SRV';
    else if (node.type === 'Access Point') labelSymbol = 'AP';
    else if (node.type === 'Printer') labelSymbol = 'PRN';
    else if (node.type === 'Mobile') labelSymbol = 'MOB';

    ctx.fillText(labelSymbol, x, y);

    // Device Name & IP Labels
    ctx.font = '10px sans-serif';
    ctx.fillStyle = '#E4F4E9';
    ctx.fillText(node.name, x, y + radius + 12);

    ctx.font = '9px monospace';
    ctx.fillStyle = '#A5C6B0';
    ctx.fillText(node.ip, x, y + radius + 23);

    ctx.restore();
  }

  function onMouseMove(e) {
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;

    const scaleX = canvas.width / 960;
    const scaleY = canvas.height / 520;

    let found = null;
    for (const node of NODES) {
      const nx = node.x * scaleX;
      const ny = node.y * scaleY;
      const dist = Math.hypot(mouseX - nx, mouseY - ny);
      if (dist < 22) {
        found = node;
        break;
      }
    }

    hoveredNode = found;
    canvas.style.cursor = found ? 'pointer' : 'default';
  }

  function onCanvasClick(e) {
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;

    const scaleX = canvas.width / 960;
    const scaleY = canvas.height / 520;

    for (const node of NODES) {
      const nx = node.x * scaleX;
      const ny = node.y * scaleY;
      const dist = Math.hypot(mouseX - nx, mouseY - ny);
      if (dist < 22) {
        inspectNode(node);
        return;
      }
    }
  }

  function setSegmentFilter(segment) {
    activeFilter = segment;
  }

  function inspectNode(node) {
    selectedNode = node;
    const fullDevice = NetGuardData.getDevices().find(d => d.id === node.id) || node;

    const drawer = document.getElementById('nodeDrawer');
    if (!drawer) return;

    document.getElementById('drawerDeviceName').textContent = fullDevice.name;
    document.getElementById('drawerDeviceId').textContent = fullDevice.id;
    document.getElementById('drawerDeviceIp').textContent = fullDevice.ip;
    document.getElementById('drawerDeviceMac').textContent = fullDevice.mac || '00:1A:2B:3C:4D:XX';
    document.getElementById('drawerDeviceSegment').textContent = fullDevice.segment || fullDevice.department;
    document.getElementById('drawerDeviceType').textContent = fullDevice.type;
    document.getElementById('drawerDeviceModel').textContent = fullDevice.model || 'Simulated Network Node';
    document.getElementById('drawerDeviceUptime').textContent = fullDevice.uptime || '99.5%';
    document.getElementById('drawerDeviceTraffic').textContent = fullDevice.trafficRate || '12.4 Mbps';

    const statusEl = document.getElementById('drawerDeviceStatus');
    statusEl.textContent = fullDevice.status;
    statusEl.className = `status-pill ${fullDevice.status.toLowerCase()}`;

    // Reset ping box
    const pingBox = document.getElementById('drawerPingOutput');
    if (pingBox) {
      pingBox.style.display = 'none';
      pingBox.textContent = '';
    }

    drawer.classList.add('active');
  }

  function closeDrawer() {
    const drawer = document.getElementById('nodeDrawer');
    if (drawer) drawer.classList.remove('active');
    selectedNode = null;
  }

  function runPingDiagnostics() {
    if (!selectedNode) return;
    const pingBox = document.getElementById('drawerPingOutput');
    if (!pingBox) return;

    pingBox.style.display = 'block';
    pingBox.textContent = `PING ${selectedNode.ip} (56 data bytes)...\n`;

    if (selectedNode.status === 'Offline') {
      setTimeout(() => {
        pingBox.textContent += `Request timeout for icmp_seq 1\nRequest timeout for icmp_seq 2\n--- ${selectedNode.ip} ping statistics ---\n2 packets transmitted, 0 packets received, 100.0% packet loss\nHost Status: UNREACHABLE`;
      }, 400);
      return;
    }

    let seq = 1;
    const interval = setInterval(() => {
      const rtt = (3.5 + Math.random() * 4.2).toFixed(2);
      pingBox.textContent += `64 bytes from ${selectedNode.ip}: icmp_seq=${seq} ttl=64 time=${rtt} ms\n`;
      seq++;
      if (seq > 4) {
        clearInterval(interval);
        pingBox.textContent += `--- ${selectedNode.ip} ping statistics ---\n4 packets transmitted, 4 received, 0% packet loss, rtt avg 5.24 ms\nDiagnostic Result: LATENCY OPTIMAL (Normal Connection)`;
      }
    }, 250);
  }

  return {
    init,
    setSegmentFilter,
    inspectNode,
    closeDrawer,
    runPingDiagnostics
  };
})();
