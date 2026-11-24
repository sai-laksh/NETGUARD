/**
 * NETGUARD - Smart Campus Network Monitoring and Security System
 * Security Alerts Management Controller (alerts.js)
 * 
 * Handles alert filtering, search, modal inspection, and persistent status changes
 * (New -> Investigating -> Resolved). Synchronizes with localStorage and API.
 */

const NetGuardAlerts = (() => {
  let currentFilter = 'All';
  let currentStatusFilter = 'All';
  let searchKeyword = '';
  let activeAlertForModal = null;

  function init() {
    renderAlertsTable();
    setupEventListeners();
  }

  function setupEventListeners() {
    // Severity Filter Buttons
    const filterBtns = document.querySelectorAll('.alert-severity-btn');
    filterBtns.forEach(btn => {
      btn.addEventListener('click', (e) => {
        filterBtns.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentFilter = btn.dataset.severity || 'All';
        renderAlertsTable();
      });
    });

    // Status Filter Select
    const statusSelect = document.getElementById('alertStatusFilter');
    if (statusSelect) {
      statusSelect.addEventListener('change', (e) => {
        currentStatusFilter = e.target.value;
        renderAlertsTable();
      });
    }

    // Search Input
    const searchInput = document.getElementById('alertSearchInput');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        searchKeyword = e.target.value.toLowerCase().trim();
        renderAlertsTable();
      });
    }
  }

  function renderAlertsTable() {
    const tableBody = document.getElementById('alertsTableBody');
    if (!tableBody) return;

    let alerts = NetGuardData.getAlerts();

    // Filter by severity
    if (currentFilter !== 'All') {
      alerts = alerts.filter(a => a.severity.toLowerCase() === currentFilter.toLowerCase());
    }

    // Filter by status
    if (currentStatusFilter !== 'All') {
      alerts = alerts.filter(a => a.status.toLowerCase() === currentStatusFilter.toLowerCase());
    }

    // Search filter
    if (searchKeyword) {
      alerts = alerts.filter(a => 
        a.id.toLowerCase().includes(searchKeyword) ||
        a.description.toLowerCase().includes(searchKeyword) ||
        a.sourceIp.toLowerCase().includes(searchKeyword) ||
        a.category.toLowerCase().includes(searchKeyword)
      );
    }

    if (alerts.length === 0) {
      tableBody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align:center; padding: 2rem; color: var(--text-muted);">
            No security alerts match the selected criteria.
          </td>
        </tr>
      `;
      return;
    }

    tableBody.innerHTML = alerts.map(alert => {
      const sevClass = alert.severity.toLowerCase();
      const statusClass = alert.status.toLowerCase();

      return `
        <tr>
          <td><strong style="color: var(--accent-highlight); font-family: monospace;">${alert.id}</strong></td>
          <td>
            <div style="font-weight: 600; color: var(--text-main);">${escapeHtml(alert.description)}</div>
            <div style="font-size: 0.72rem; color: var(--text-muted);">${escapeHtml(alert.category)}</div>
          </td>
          <td><span class="ip-badge" style="background-color: var(--bg-surface); padding: 0.2rem 0.5rem; border-radius: 4px; border: 1px solid var(--border-subtle); color: var(--text-main);">${alert.sourceIp}</span></td>
          <td><span class="severity-pill ${sevClass}">${alert.severity}</span></td>
          <td style="color: var(--text-muted); font-size: 0.75rem;">${alert.timestamp}</td>
          <td><span class="state-pill ${statusClass}">${alert.status}</span></td>
          <td>
            <div style="display: flex; gap: 0.4rem;">
              <button class="btn btn-outline btn-sm" onclick="NetGuardAlerts.openAlertModal('${alert.id}')" title="View Incident Timeline & Remediation">
                Details
              </button>
              ${alert.status !== 'Investigating' && alert.status !== 'Resolved' ? `
                <button class="btn btn-warning btn-sm" onclick="NetGuardAlerts.changeStatus('${alert.id}', 'Investigating')" title="Mark as In-Progress">
                  Investigate
                </button>
              ` : ''}
              ${alert.status !== 'Resolved' ? `
                <button class="btn btn-primary btn-sm" onclick="NetGuardAlerts.changeStatus('${alert.id}', 'Resolved')" title="Mark as Cleared">
                  Resolve
                </button>
              ` : `
                <button class="btn btn-outline btn-sm" onclick="NetGuardAlerts.changeStatus('${alert.id}', 'New')" title="Reopen Incident">
                  Reopen
                </button>
              `}
            </div>
          </td>
        </tr>
      `;
    }).join('');

    // Update alerts count in header
    const counterEl = document.getElementById('filteredAlertsCount');
    if (counterEl) {
      counterEl.textContent = `${alerts.length} Incidents Found`;
    }
  }

  function changeStatus(alertId, newStatus) {
    const success = NetGuardData.updateAlertStatus(alertId, newStatus);
    if (success) {
      renderAlertsTable();
      NetGuardApp.refreshGlobalStats();
      NetGuardApp.showToast(`Alert ${alertId} updated to: ${newStatus}`, newStatus === 'Resolved' ? 'normal' : 'warning');
      
      // If modal is open for this alert, update it
      if (activeAlertForModal && activeAlertForModal.id === alertId) {
        openAlertModal(alertId);
      }
    }
  }

  function openAlertModal(alertId) {
    const alert = NetGuardData.getAlerts().find(a => a.id === alertId);
    if (!alert) return;
    activeAlertForModal = alert;

    const modal = document.getElementById('alertDetailModal');
    if (!modal) return;

    document.getElementById('modalAlertId').textContent = alert.id;
    document.getElementById('modalAlertCategory').textContent = alert.category;
    document.getElementById('modalAlertDescription').textContent = alert.description;
    document.getElementById('modalAlertSource').textContent = alert.sourceIp;
    document.getElementById('modalAlertTarget').textContent = `${alert.targetIp || 'N/A'}${alert.targetPort ? ' (Port ' + alert.targetPort + ')' : ''}`;
    document.getElementById('modalAlertTime').textContent = alert.timestamp;
    document.getElementById('modalAlertReason').textContent = alert.reason || 'Triggered heuristic detection threshold.';
    document.getElementById('modalAlertRecommendation').textContent = alert.recommendation || 'Verify host telemetry and apply switch port security policy.';

    const sevEl = document.getElementById('modalAlertSeverity');
    sevEl.textContent = alert.severity;
    sevEl.className = `severity-pill ${alert.severity.toLowerCase()}`;

    const statusEl = document.getElementById('modalAlertStatus');
    statusEl.textContent = alert.status;
    statusEl.className = `state-pill ${alert.status.toLowerCase()}`;

    // Synthetic Wireshark Packet Trigger Snippet
    const rawPacketSnippet = `[Wireshark Frame Capture - Simulated Stream]
Frame 14: 74 bytes on interface eth0
Internet Protocol Version 4, Src: ${alert.sourceIp}, Dst: ${alert.targetIp || '10.10.40.10'}
Transmission Control Protocol, Src Port: 52184, Dst Port: ${alert.targetPort || 22}, [SYN] Seq=0
NetGuard Heuristic Match: ${alert.category}
Status Tag: ALERT_FLAGGED`;

    document.getElementById('modalRawPacketData').textContent = rawPacketSnippet;

    // Action buttons inside modal
    const actionsContainer = document.getElementById('modalActionButtons');
    actionsContainer.innerHTML = `
      <button class="btn btn-outline" onclick="NetGuardAlerts.closeModal()">Close</button>
      ${alert.status !== 'Investigating' && alert.status !== 'Resolved' ? `
        <button class="btn btn-warning" onclick="NetGuardAlerts.changeStatus('${alert.id}', 'Investigating')">Mark Investigating</button>
      ` : ''}
      ${alert.status !== 'Resolved' ? `
        <button class="btn btn-primary" onclick="NetGuardAlerts.changeStatus('${alert.id}', 'Resolved')">Mark Resolved</button>
      ` : `
        <button class="btn btn-outline" onclick="NetGuardAlerts.changeStatus('${alert.id}', 'New')">Reopen Alert</button>
      `}
    `;

    modal.classList.add('active');
  }

  function closeModal() {
    const modal = document.getElementById('alertDetailModal');
    if (modal) modal.classList.remove('active');
    activeAlertForModal = null;
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

  return {
    init,
    renderAlertsTable,
    changeStatus,
    openAlertModal,
    closeModal
  };
})();
