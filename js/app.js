/**
 * NETGUARD - Smart Campus Network Monitoring and Security System
 * Main Application Orchestrator (app.js)
 * 
 * Manages view routing, topbar clock, status indicator, notification drawer,
 * device filtering, threat detection heuristics, reports generation, and settings.
 */

const NetGuardApp = (() => {
  let currentRoute = 'dashboard';
  let refreshIntervalMs = 3000;
  let liveTimer = null;
  let isSimulationPaused = false;
  let deviceSearchKeyword = '';
  let deviceDeptFilter = 'All';
  let deviceStatusFilter = 'All';

  function init() {
    setupNavigation();
    setupClock();
    setupNotifications();
    setupDeviceFilters();
    setupSettings();
    setupReportActions();

    // Initialize alerts subsystem
    NetGuardAlerts.init();

    // Check URL hash for direct deep linking
    const hash = window.location.hash.replace('#', '') || 'dashboard';
    navigateTo(hash);

    // Initial statistics rendering
    refreshGlobalStats();

    // Start background live traffic simulation loop
    startLiveTrafficLoop();

    console.log('[NETGUARD] System Initialized Successfully.');
  }

  // =========================================================================
  // VIEW ROUTING SYSTEM
  // =========================================================================
  function setupNavigation() {
    const navLinks = document.querySelectorAll('.nav-item');
    navLinks.forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        const targetView = link.dataset.view;
        if (targetView) {
          window.location.hash = targetView;
          navigateTo(targetView);
        }
      });
    });

    window.addEventListener('hashchange', () => {
      const hash = window.location.hash.replace('#', '') || 'dashboard';
      navigateTo(hash);
    });

    // Mobile menu toggle
    const toggleBtn = document.getElementById('menuToggle');
    const sidebar = document.querySelector('.sidebar');
    if (toggleBtn && sidebar) {
      toggleBtn.addEventListener('click', () => {
        sidebar.classList.toggle('open');
      });
    }
  }

  function navigateTo(viewId) {
    // Validate target view exists
    const targetEl = document.getElementById(`view-${viewId}`);
    if (!targetEl) viewId = 'dashboard';

    currentRoute = viewId;

    // Toggle active page view
    document.querySelectorAll('.page-view').forEach(view => view.classList.remove('active'));
    const activeView = document.getElementById(`view-${viewId}`);
    if (activeView) activeView.classList.add('active');

    // Toggle sidebar active item
    document.querySelectorAll('.nav-item').forEach(item => {
      item.classList.toggle('active', item.dataset.view === viewId);
    });

    // Close mobile sidebar if open
    const sidebar = document.querySelector('.sidebar');
    if (sidebar) sidebar.classList.remove('open');

    // Trigger view-specific initializations
    onViewActivated(viewId);
  }

  function onViewActivated(viewId) {
    if (viewId === 'dashboard') {
      refreshGlobalStats();
      renderDashboardRecentEvents();
      setTimeout(() => {
        NetGuardCharts.initTrafficOverTimeChart('chartTrafficOverTime');
        NetGuardCharts.initTrafficTypeChart('chartTrafficType');
        NetGuardCharts.initAlertsSeverityChart('chartAlertsSeverity');
        NetGuardCharts.initDeviceDistChart('chartDeviceDist');
      }, 50);
    } else if (viewId === 'network-overview') {
      setTimeout(() => {
        NetGuardTopology.init('topologyCanvas');
      }, 80);
    } else if (viewId === 'traffic') {
      renderTrafficPageStats();
      renderTrafficPacketTable();
      setTimeout(() => {
        NetGuardCharts.initLiveTrafficChart('chartLiveTrafficStream');
        NetGuardCharts.initProtocolDistChart('chartProtocolDist');
      }, 50);
    } else if (viewId === 'threat-detection') {
      renderThreatDetectionTable();
    } else if (viewId === 'security-alerts') {
      NetGuardAlerts.renderAlertsTable();
    } else if (viewId === 'devices') {
      renderDevicesTable();
    } else if (viewId === 'reports') {
      renderReportsData();
      setTimeout(() => {
        NetGuardCharts.initReportThreatCategoriesChart('chartReportThreatCategories');
        NetGuardCharts.initReportSegmentBandwidthChart('chartReportSegmentBandwidth');
      }, 50);
    }
  }

  // =========================================================================
  // TOPBAR REAL-TIME CLOCK & STATUS INDICATOR
  // =========================================================================
  function setupClock() {
    const clockEl = document.getElementById('liveClockText');
    const updateTime = () => {
      if (!clockEl) return;
      const now = new Date();
      const options = {
        weekday: 'short',
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
      };
      clockEl.textContent = now.toLocaleDateString('en-US', options);
    };
    updateTime();
    setInterval(updateTime, 1000);
  }

  function refreshGlobalStats() {
    const stats = NetGuardData.getDashboardStats();

    // Summary Metric Cards
    setElText('statTotalDevices', stats.totalDevices);
    setElText('statActiveDevices', stats.activeDevices);
    setElText('statNetworkTraffic', `${stats.totalTrafficMbps} Mbps`);
    setElText('statSuspiciousActivities', stats.suspiciousActivities);
    setElText('statCriticalAlerts', stats.criticalAlerts);
    setElText('statNetworkHealth', `${stats.networkHealthScore}%`);

    // Topbar Status Indicator
    const statusPill = document.getElementById('topbarStatusPill');
    const statusText = document.getElementById('topbarStatusText');
    const pulseDot = document.getElementById('topbarPulseDot');

    if (stats.criticalAlerts > 0) {
      if (statusText) statusText.textContent = `ALERT: ${stats.criticalAlerts} CRITICAL`;
      if (pulseDot) pulseDot.className = 'pulse-dot critical';
    } else if (stats.suspiciousActivities > 0) {
      if (statusText) statusText.textContent = `STATUS: ${stats.suspiciousActivities} SUSPICIOUS`;
      if (pulseDot) pulseDot.className = 'pulse-dot warning';
    } else {
      if (statusText) statusText.textContent = 'SYSTEM ACTIVE: NORMAL';
      if (pulseDot) pulseDot.className = 'pulse-dot';
    }

    // Sidebar Notification Badge Counter
    const notifBadge = document.getElementById('sidebarAlertsBadge');
    if (notifBadge) {
      notifBadge.textContent = stats.suspiciousActivities;
      notifBadge.style.display = stats.suspiciousActivities > 0 ? 'inline-block' : 'none';
    }

    // Topbar Notification Bell Counter
    const bellBadge = document.getElementById('bellBadgeCounter');
    if (bellBadge) {
      bellBadge.textContent = stats.suspiciousActivities;
      bellBadge.style.display = stats.suspiciousActivities > 0 ? 'flex' : 'none';
    }

    // Re-render notification drawer items
    renderNotificationList();
  }

  // =========================================================================
  // NOTIFICATION SYSTEM & BELL DROPDOWN
  // =========================================================================
  function setupNotifications() {
    const bellBtn = document.getElementById('notificationBellBtn');
    const dropdown = document.getElementById('notificationDropdown');

    if (bellBtn && dropdown) {
      bellBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        dropdown.classList.toggle('active');
      });

      document.addEventListener('click', (e) => {
        if (!dropdown.contains(e.target) && !bellBtn.contains(e.target)) {
          dropdown.classList.remove('active');
        }
      });
    }
  }

  function renderNotificationList() {
    const notifListEl = document.getElementById('notificationList');
    if (!notifListEl) return;

    const alerts = NetGuardData.getAlerts().filter(a => a.status !== 'Resolved').slice(0, 5);

    if (alerts.length === 0) {
      notifListEl.innerHTML = `
        <div style="padding: 1.5rem; text-align: center; color: var(--text-muted); font-size: 0.78rem;">
          All security alerts resolved. Network state normal.
        </div>
      `;
      return;
    }

    notifListEl.innerHTML = alerts.map(a => `
      <div class="notification-item ${a.severity.toLowerCase()}" onclick="NetGuardAlerts.openAlertModal('${a.id}')">
        <div class="notif-content">
          <h5>${escapeHtml(a.description)}</h5>
          <p>Host: <code>${a.sourceIp}</code> &bull; ${a.category}</p>
          <span class="notif-time">${a.timestamp}</span>
        </div>
      </div>
    `).join('');
  }

  // =========================================================================
  // DASHBOARD PAGE: RECENT SECURITY EVENTS
  // =========================================================================
  function renderDashboardRecentEvents() {
    const tableBody = document.getElementById('dashboardRecentEventsBody');
    if (!tableBody) return;

    const recent = NetGuardData.getAlerts().slice(0, 5);
    tableBody.innerHTML = recent.map(a => `
      <tr>
        <td><strong style="color: var(--accent-highlight); font-family: monospace;">${a.id}</strong></td>
        <td>
          <div style="font-weight: 600;">${escapeHtml(a.description)}</div>
          <div style="font-size: 0.72rem; color: var(--text-muted);">${escapeHtml(a.category)}</div>
        </td>
        <td><span class="ip-badge" style="background: var(--bg-surface); padding: 0.15rem 0.45rem; border-radius: 4px; border: 1px solid var(--border-subtle);">${a.sourceIp}</span></td>
        <td><span class="severity-pill ${a.severity.toLowerCase()}">${a.severity}</span></td>
        <td style="color: var(--text-muted); font-size: 0.75rem;">${a.timestamp}</td>
        <td><span class="state-pill ${a.status.toLowerCase()}">${a.status}</span></td>
      </tr>
    `).join('');
  }

  // =========================================================================
  // TRAFFIC MONITORING PAGE
  // =========================================================================
  function renderTrafficPageStats() {
    const rx = (195 + (Math.random() * 45 - 20)).toFixed(1);
    const tx = (155 + (Math.random() * 35 - 15)).toFixed(1);
    const totalPackets = Math.floor(21500 + (Math.random() * 3000 - 1500));
    const tcpPkts = Math.floor(totalPackets * 0.71);
    const udpPkts = Math.floor(totalPackets * 0.23);
    const icmpPkts = Math.floor(totalPackets * 0.04);

    setElText('trafficInboundRate', `${rx} Mbps`);
    setElText('trafficOutboundRate', `${tx} Mbps`);
    setElText('trafficTotalPackets', totalPackets.toLocaleString());
    setElText('trafficTcpPackets', tcpPkts.toLocaleString());
    setElText('trafficUdpPackets', udpPkts.toLocaleString());
    setElText('trafficIcmpPackets', icmpPkts.toLocaleString());
    setElText('trafficAvgActivity', 'Normal (High Concurrency)');
  }

  function renderTrafficPacketTable() {
    const tableBody = document.getElementById('trafficPacketTableBody');
    if (!tableBody) return;

    const packets = NetGuardData.getRecentPackets();
    tableBody.innerHTML = packets.map(p => `
      <tr>
        <td style="font-family: monospace; color: var(--accent-highlight);">${p.id}</td>
        <td style="color: var(--text-muted); font-family: monospace;">${p.time}</td>
        <td><code>${p.source}</code></td>
        <td><code>${p.destination}</code></td>
        <td><span style="font-weight: 700; color: ${p.protocol === 'ICMP' ? '#F59E0B' : '#51D99A'};">${p.protocol}</span></td>
        <td style="font-family: monospace;">${p.length} B</td>
        <td><span class="status-pill ${p.status === 'Pass' ? 'online' : 'attention'}">${p.status}</span></td>
      </tr>
    `).join('');
  }

  function startLiveTrafficLoop() {
    if (liveTimer) clearInterval(liveTimer);
    liveTimer = setInterval(() => {
      if (isSimulationPaused) return;

      // Generate new packet
      NetGuardData.generateSimulatedPacket();

      // Update traffic page if active
      if (currentRoute === 'traffic') {
        const rx = parseFloat((195 + (Math.random() * 45 - 20)).toFixed(1));
        const tx = parseFloat((155 + (Math.random() * 35 - 15)).toFixed(1));
        NetGuardCharts.pushLiveTrafficPoint('chartLiveTrafficStream', rx, tx);
        renderTrafficPageStats();
        renderTrafficPacketTable();
      }
    }, refreshIntervalMs);
  }

  // =========================================================================
  // THREAT DETECTION PAGE
  // =========================================================================
  function renderThreatDetectionTable() {
    const tableBody = document.getElementById('threatDetectionTableBody');
    if (!tableBody) return;

    const alerts = NetGuardData.getAlerts();
    tableBody.innerHTML = alerts.map(a => `
      <tr>
        <td><strong style="color: var(--accent-highlight); font-family: monospace;">${a.threatId || 'RULE-GEN'}</strong></td>
        <td>
          <div style="font-weight: 600; color: var(--text-main);">${escapeHtml(a.category)}</div>
          <div style="font-size: 0.72rem; color: var(--text-muted);">${escapeHtml(a.description)}</div>
        </td>
        <td><span class="ip-badge" style="background: var(--bg-surface); padding: 0.2rem 0.5rem; border-radius: 4px; border: 1px solid var(--border-subtle);">${a.sourceIp}</span></td>
        <td style="font-size: 0.75rem; color: var(--text-muted);">${a.timestamp}</td>
        <td><span class="severity-pill ${a.severity.toLowerCase()}">${a.severity}</span></td>
        <td style="max-width: 280px; white-space: normal; font-size: 0.75rem; color: var(--text-muted);">${escapeHtml(a.reason || 'Heuristic anomaly detected.')}</td>
        <td><span class="state-pill ${a.status.toLowerCase()}">${a.status}</span></td>
        <td>
          <div style="display: flex; gap: 0.35rem;">
            <button class="btn btn-outline btn-sm" onclick="NetGuardApp.explainThreatRule('${a.threatId}')">Explain</button>
            ${a.status !== 'Resolved' ? `
              <button class="btn btn-danger btn-sm" onclick="NetGuardApp.isolateDevice('${a.sourceIp}', '${a.id}')">Isolate Host</button>
            ` : `
              <span style="font-size: 0.7rem; color: var(--accent-highlight);">Resolved</span>
            `}
          </div>
        </td>
      </tr>
    `).join('');
  }

  function explainThreatRule(ruleId) {
    const rule = NetGuardData.getThreatRules().find(r => r.id === ruleId) || {
      id: ruleId,
      name: "Standard Campus Network Anomaly Rule",
      category: "Network Anomaly Heuristic",
      description: "Applies statistical packet-rate thresholds and Layer 3/4 header inspections against normal baseline behavior.",
      threshold: "Configurable dynamic threshold",
      heuristic: "Baseline comparison with rolling standard deviation.",
      action: "Log security event, notify SOC, evaluate host isolation."
    };

    const modal = document.getElementById('ruleExplanationModal');
    if (!modal) return;

    document.getElementById('ruleModalTitle').textContent = `${rule.id}: ${rule.category}`;
    document.getElementById('ruleModalName').textContent = rule.name;
    document.getElementById('ruleModalDesc').textContent = rule.description;
    document.getElementById('ruleModalThreshold').textContent = rule.threshold;
    document.getElementById('ruleModalHeuristic').textContent = rule.heuristic;
    document.getElementById('ruleModalAction').textContent = rule.action;

    modal.classList.add('active');
  }

  function closeRuleModal() {
    const modal = document.getElementById('ruleExplanationModal');
    if (modal) modal.classList.remove('active');
  }

  function isolateDevice(sourceIp, alertId) {
    const confirmIso = confirm(`CONFIRM ISOLATION:\nAre you sure you want to isolate host ${sourceIp}?\n\nThis will trigger simulated switch port shutdown on VLAN 10.`);
    if (confirmIso) {
      NetGuardData.updateAlertStatus(alertId, 'Investigating');
      refreshGlobalStats();
      renderThreatDetectionTable();
      showToast(`Host ${sourceIp} quarantined! Port isolated on switch.`, 'warning');
    }
  }

  // =========================================================================
  // DEVICE MANAGEMENT PAGE
  // =========================================================================
  function setupDeviceFilters() {
    const searchInput = document.getElementById('deviceSearchInput');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        deviceSearchKeyword = e.target.value.toLowerCase().trim();
        renderDevicesTable();
      });
    }

    const deptSelect = document.getElementById('deviceDeptSelect');
    if (deptSelect) {
      deptSelect.addEventListener('change', (e) => {
        deviceDeptFilter = e.target.value;
        renderDevicesTable();
      });
    }

    const statusSelect = document.getElementById('deviceStatusSelect');
    if (statusSelect) {
      statusSelect.addEventListener('change', (e) => {
        deviceStatusFilter = e.target.value;
        renderDevicesTable();
      });
    }
  }

  function renderDevicesTable() {
    const tableBody = document.getElementById('devicesTableBody');
    if (!tableBody) return;

    let devices = NetGuardData.getDevices();

    if (deviceDeptFilter !== 'All') {
      devices = devices.filter(d => d.department.toLowerCase() === deviceDeptFilter.toLowerCase());
    }

    if (deviceStatusFilter !== 'All') {
      devices = devices.filter(d => d.status.toLowerCase() === deviceStatusFilter.toLowerCase());
    }

    if (deviceSearchKeyword) {
      devices = devices.filter(d => 
        d.id.toLowerCase().includes(deviceSearchKeyword) ||
        d.name.toLowerCase().includes(deviceSearchKeyword) ||
        d.ip.toLowerCase().includes(deviceSearchKeyword) ||
        d.mac.toLowerCase().includes(deviceSearchKeyword) ||
        d.type.toLowerCase().includes(deviceSearchKeyword)
      );
    }

    if (devices.length === 0) {
      tableBody.innerHTML = `
        <tr>
          <td colspan="8" style="text-align:center; padding: 2rem; color: var(--text-muted);">
            No campus devices match the selected query.
          </td>
        </tr>
      `;
      return;
    }

    tableBody.innerHTML = devices.map(d => {
      const statusClass = d.status.toLowerCase();
      return `
        <tr>
          <td><strong style="color: var(--accent-highlight); font-family: monospace;">${d.id}</strong></td>
          <td>
            <div style="font-weight: 600; color: var(--text-main);">${escapeHtml(d.name)}</div>
            <div style="font-size: 0.72rem; color: var(--text-muted);">${escapeHtml(d.model || '')}</div>
          </td>
          <td><span style="font-size: 0.78rem;">${d.type}</span></td>
          <td><span class="ip-badge" style="background: var(--bg-surface); padding: 0.2rem 0.5rem; border-radius: 4px; border: 1px solid var(--border-subtle);">${d.ip}</span></td>
          <td><span style="font-size: 0.78rem; color: var(--text-muted);">${d.department}</span></td>
          <td><span class="status-pill ${statusClass}">${d.status}</span></td>
          <td style="color: var(--text-muted); font-size: 0.75rem;">${d.lastActive}</td>
          <td>
            <div style="display: flex; gap: 0.35rem;">
              <button class="btn btn-outline btn-sm" onclick="NetGuardApp.openDevicePingModal('${d.id}')">Ping</button>
              <button class="btn btn-primary btn-sm" onclick="NetGuardApp.viewDeviceInTopology('${d.id}')">Locate</button>
            </div>
          </td>
        </tr>
      `;
    }).join('');

    const countEl = document.getElementById('deviceListTotalCount');
    if (countEl) countEl.textContent = `${devices.length} Devices Displayed`;
  }

  function viewDeviceInTopology(deviceId) {
    navigateTo('network-overview');
    const device = NetGuardData.getDevices().find(d => d.id === deviceId);
    if (device) {
      setTimeout(() => {
        NetGuardTopology.inspectNode(device);
      }, 200);
    }
  }

  function openDevicePingModal(deviceId) {
    const device = NetGuardData.getDevices().find(d => d.id === deviceId);
    if (!device) return;

    const modal = document.getElementById('pingModal');
    if (!modal) return;

    document.getElementById('pingModalDeviceName').textContent = `${device.name} (${device.ip})`;
    const outputEl = document.getElementById('pingModalOutput');
    outputEl.textContent = `Testing connectivity to ${device.ip} [MAC: ${device.mac}]...\n`;

    modal.classList.add('active');

    if (device.status === 'Offline') {
      setTimeout(() => {
        outputEl.textContent += `ICMP Request Timeout (10.10.x.x unreachable)\nICMP Request Timeout (10.10.x.x unreachable)\n\n--- ${device.ip} ping statistics ---\n2 packets transmitted, 0 packets received, 100.0% packet loss\nDevice Connection: OFFLINE / UNREACHABLE`;
      }, 500);
      return;
    }

    let seq = 1;
    const interval = setInterval(() => {
      const rtt = (4.0 + Math.random() * 5.0).toFixed(2);
      outputEl.textContent += `64 bytes from ${device.ip}: icmp_seq=${seq} ttl=64 time=${rtt} ms\n`;
      seq++;
      if (seq > 4) {
        clearInterval(interval);
        outputEl.textContent += `\n--- ${device.ip} ping statistics ---\n4 packets transmitted, 4 received, 0% packet loss\nRound-trip min/avg/max = 4.10/6.32/8.90 ms\nStatus: 100% OPERATIONAL (Port Active)`;
      }
    }, 280);
  }

  function closePingModal() {
    const modal = document.getElementById('pingModal');
    if (modal) modal.classList.remove('active');
  }

  // =========================================================================
  // REPORTS PAGE
  // =========================================================================
  function renderReportsData() {
    const stats = NetGuardData.getDashboardStats();
    const alerts = NetGuardData.getAlerts();
    const resolvedCount = alerts.filter(a => a.status === 'Resolved').length;

    setElText('repTotalTrafficGB', '482.6 GB');
    setElText('repPeakThroughput', '412.0 Mbps');
    setElText('repTotalIncidents', alerts.length);
    setElText('repResolvedIncidents', resolvedCount);
    setElText('repAvailability', '99.94%');
    setElText('repActiveSensors', '1 (SPAN Mirror Active)');
  }

  function setupReportActions() {
    const btnExportAlerts = document.getElementById('btnExportAlertsCSV');
    if (btnExportAlerts) {
      btnExportAlerts.addEventListener('click', () => {
        NetGuardData.exportAlertsToCSV();
        showToast('Alerts CSV downloaded successfully.', 'normal');
      });
    }

    const btnExportDevices = document.getElementById('btnExportDevicesCSV');
    if (btnExportDevices) {
      btnExportDevices.addEventListener('click', () => {
        NetGuardData.exportDevicesToCSV();
        showToast('Device Inventory CSV downloaded.', 'normal');
      });
    }

    const btnExportTraffic = document.getElementById('btnExportTrafficCSV');
    if (btnExportTraffic) {
      btnExportTraffic.addEventListener('click', () => {
        NetGuardData.exportTrafficToCSV();
        showToast('Traffic Metrics CSV downloaded.', 'normal');
      });
    }

    const btnPrintReport = document.getElementById('btnPrintReport');
    if (btnPrintReport) {
      btnPrintReport.addEventListener('click', () => {
        window.print();
      });
    }
  }

  // =========================================================================
  // SETTINGS PAGE & SIMULATION CONTROLS
  // =========================================================================
  function setupSettings() {
    const slider = document.getElementById('refreshIntervalSlider');
    const display = document.getElementById('refreshIntervalDisplay');

    if (slider && display) {
      slider.addEventListener('input', (e) => {
        const val = parseInt(e.target.value);
        refreshIntervalMs = val * 1000;
        display.textContent = `${val} seconds`;
        startLiveTrafficLoop();
      });
    }

    const pauseToggle = document.getElementById('togglePauseSimulation');
    if (pauseToggle) {
      pauseToggle.addEventListener('change', (e) => {
        isSimulationPaused = e.target.checked;
        showToast(isSimulationPaused ? 'Live traffic stream paused.' : 'Live traffic stream resumed.', 'normal');
      });
    }
  }

  function triggerSimulatedAttack(attackType) {
    const alert = NetGuardData.injectSimulatedThreat(attackType);
    refreshGlobalStats();
    if (currentRoute === 'threat-detection') renderThreatDetectionTable();
    if (currentRoute === 'security-alerts') NetGuardAlerts.renderAlertsTable();
    if (currentRoute === 'dashboard') {
      renderDashboardRecentEvents();
      NetGuardCharts.initAlertsSeverityChart('chartAlertsSeverity');
      NetGuardCharts.initTrafficTypeChart('chartTrafficType');
    }

    showToast(`DEMO INJECTION: ${alert.category} triggered!`, 'critical');
  }

  // =========================================================================
  // TOAST NOTIFICATIONS
  // =========================================================================
  function showToast(message, type = 'normal') {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
      <svg style="width: 16px; height: 16px; fill: currentColor; flex-shrink: 0;" viewBox="0 0 24 24">
        <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/>
      </svg>
      <span>${escapeHtml(message)}</span>
    `;

    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 3800);
  }

  // Utility helpers
  function setElText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  }

  function escapeHtml(text) {
    if (!text) return '';
    return text.replace(/[&<>"']/g, m => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;'
    })[m]);
  }

  // Public API
  return {
    init,
    navigateTo,
    refreshGlobalStats,
    explainThreatRule,
    closeRuleModal,
    isolateDevice,
    openDevicePingModal,
    closePingModal,
    viewDeviceInTopology,
    triggerSimulatedAttack,
    showToast
  };
})();

// Start application when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  NetGuardApp.init();
});
