/**
 * NETGUARD - Smart Campus Network Monitoring and Security System
 * Chart Visualization Layer (charts.js)
 * 
 * Configures and manages all charts using Chart.js with the Dark Emerald Green theme:
 * Deep forest black (#07140F), Dark emerald (#0B1C13), Forest green (#10251B),
 * Emerald (#237A50), Mint green (#51D99A), Soft white (#E4F4E9), Muted sage (#A5C6B0).
 * Includes automatic HTML5 Canvas drawing fallback if Chart.js is not loaded offline.
 */

const NetGuardCharts = (() => {
  // Chart instances repository
  const charts = {};

  // Emerald theme color tokens
  const THEME = {
    bgCard: '#10251B',
    bgSurface: '#17452F',
    emerald: '#237A50',
    mint: '#51D99A',
    softWhite: '#E4F4E9',
    mutedSage: '#A5C6B0',
    criticalRed: '#EF4444',
    warningAmber: '#F59E0B',
    gridLines: 'rgba(81, 217, 154, 0.08)'
  };

  // Helper to test if Chart.js is available
  function isChartJsAvailable() {
    return typeof window.Chart !== 'undefined';
  }

  // Global Chart.js defaults configuration
  function applyChartJsThemeDefaults() {
    if (!isChartJsAvailable()) return;
    Chart.defaults.color = THEME.mutedSage;
    Chart.defaults.font.family = "'Segoe UI', Roboto, Helvetica, Arial, sans-serif";
    Chart.defaults.font.size = 11;
    Chart.defaults.plugins.legend.labels.usePointStyle = true;
    Chart.defaults.plugins.legend.labels.boxWidth = 8;
    Chart.defaults.plugins.legend.labels.boxHeight = 8;
    Chart.defaults.plugins.tooltip.backgroundColor = '#0B1C13';
    Chart.defaults.plugins.tooltip.titleColor = THEME.mint;
    Chart.defaults.plugins.tooltip.bodyColor = THEME.softWhite;
    Chart.defaults.plugins.tooltip.borderColor = 'rgba(81, 217, 154, 0.25)';
    Chart.defaults.plugins.tooltip.borderWidth = 1;
    Chart.defaults.plugins.tooltip.padding = 10;
  }

  // 1. Dashboard: Network Traffic Over Time Line Chart
  function initTrafficOverTimeChart(canvasId) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;

    const labels = ['12:00', '13:00', '14:00', '15:00', '16:00', '17:00', '18:00'];
    const inboundData = [165, 182, 210, 195, 230, 245, 224];
    const outboundData = [120, 138, 160, 142, 175, 192, 172];

    if (isChartJsAvailable()) {
      if (charts[canvasId]) charts[canvasId].destroy();
      const ctx = canvas.getContext('2d');
      charts[canvasId] = new Chart(ctx, {
        type: 'line',
        data: {
          labels,
          datasets: [
            {
              label: 'Inbound (Mbps)',
              data: inboundData,
              borderColor: THEME.mint,
              backgroundColor: 'rgba(81, 217, 154, 0.1)',
              borderWidth: 2.5,
              tension: 0.35,
              fill: true,
              pointBackgroundColor: THEME.mint,
              pointRadius: 3
            },
            {
              label: 'Outbound (Mbps)',
              data: outboundData,
              borderColor: THEME.emerald,
              backgroundColor: 'rgba(35, 122, 80, 0.05)',
              borderWidth: 2,
              tension: 0.35,
              fill: true,
              pointBackgroundColor: THEME.emerald,
              pointRadius: 3
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            x: {
              grid: { color: THEME.gridLines },
              ticks: { color: THEME.mutedSage }
            },
            y: {
              grid: { color: THEME.gridLines },
              ticks: { color: THEME.mutedSage },
              suggestedMax: 300
            }
          }
        }
      });
    } else {
      drawFallbackLine(canvas, labels, inboundData, outboundData);
    }
  }

  // 2. Dashboard: Normal vs Suspicious Traffic Doughnut Chart
  function initTrafficTypeChart(canvasId) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;

    const dataValues = [88.5, 9.2, 2.3]; // Normal, Suspicious, Critical
    const labels = ['Normal Packets', 'Suspicious Traffic', 'Critical Violations'];

    if (isChartJsAvailable()) {
      if (charts[canvasId]) charts[canvasId].destroy();
      const ctx = canvas.getContext('2d');
      charts[canvasId] = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels,
          datasets: [{
            data: dataValues,
            backgroundColor: [THEME.mint, THEME.warningAmber, THEME.criticalRed],
            borderColor: THEME.bgCard,
            borderWidth: 3,
            hoverOffset: 4
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { position: 'bottom' }
          },
          cutout: '70%'
        }
      });
    } else {
      drawFallbackDoughnut(canvas, labels, dataValues, [THEME.mint, THEME.warningAmber, THEME.criticalRed]);
    }
  }

  // 3. Dashboard: Security Alerts by Severity Bar Chart
  function initAlertsSeverityChart(canvasId) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;

    const alerts = NetGuardData.getAlerts();
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    alerts.forEach(a => {
      if (counts[a.severity] !== undefined) counts[a.severity]++;
    });

    const labels = ['Low', 'Medium', 'High', 'Critical'];
    const dataValues = [counts.Low, counts.Medium, counts.High, counts.Critical];

    if (isChartJsAvailable()) {
      if (charts[canvasId]) charts[canvasId].destroy();
      const ctx = canvas.getContext('2d');
      charts[canvasId] = new Chart(ctx, {
        type: 'bar',
        data: {
          labels,
          datasets: [{
            label: 'Total Incidents',
            data: dataValues,
            backgroundColor: [
              THEME.mint,
              THEME.emerald,
              THEME.warningAmber,
              THEME.criticalRed
            ],
            borderRadius: 6,
            borderWidth: 0
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false }
          },
          scales: {
            x: {
              grid: { display: false },
              ticks: { color: THEME.mutedSage }
            },
            y: {
              grid: { color: THEME.gridLines },
              ticks: { color: THEME.mutedSage, stepSize: 1 },
              suggestedMax: 4
            }
          }
        }
      });
    } else {
      drawFallbackBar(canvas, labels, dataValues, [THEME.mint, THEME.emerald, THEME.warningAmber, THEME.criticalRed]);
    }
  }

  // 4. Dashboard: Device Distribution by Department Doughnut Chart
  function initDeviceDistChart(canvasId) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;

    const devices = NetGuardData.getDevices();
    const depts = { Student: 0, Faculty: 0, Administration: 0, Server: 0 };
    devices.forEach(d => {
      if (depts[d.department] !== undefined) depts[d.department]++;
    });

    const labels = ['Student', 'Faculty', 'Administration', 'Server Farm'];
    const dataValues = [depts.Student, depts.Faculty, depts.Administration, depts.Server];

    if (isChartJsAvailable()) {
      if (charts[canvasId]) charts[canvasId].destroy();
      const ctx = canvas.getContext('2d');
      charts[canvasId] = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels,
          datasets: [{
            data: dataValues,
            backgroundColor: [
              THEME.mint,
              THEME.emerald,
              THEME.bgSurface,
              '#0B1C13'
            ],
            borderColor: THEME.bgCard,
            borderWidth: 3
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { position: 'bottom' }
          },
          cutout: '68%'
        }
      });
    } else {
      drawFallbackDoughnut(canvas, labels, dataValues, [THEME.mint, THEME.emerald, THEME.bgSurface, '#0B1C13']);
    }
  }

  // 5. Traffic Monitoring: Real-time Live Bandwidth Line Graph
  function initLiveTrafficChart(canvasId) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;

    const initialLabels = ['0s', '5s', '10s', '15s', '20s', '25s', '30s', '35s', '40s', '45s'];
    const rxData = [205, 212, 198, 225, 240, 232, 218, 222, 235, 228];
    const txData = [155, 160, 150, 172, 185, 178, 165, 168, 180, 174];

    if (isChartJsAvailable()) {
      if (charts[canvasId]) charts[canvasId].destroy();
      const ctx = canvas.getContext('2d');
      charts[canvasId] = new Chart(ctx, {
        type: 'line',
        data: {
          labels: initialLabels,
          datasets: [
            {
              label: 'Rx Inbound (Mbps)',
              data: rxData,
              borderColor: THEME.mint,
              backgroundColor: 'rgba(81, 217, 154, 0.12)',
              fill: true,
              borderWidth: 2.5,
              tension: 0.3,
              pointRadius: 2
            },
            {
              label: 'Tx Outbound (Mbps)',
              data: txData,
              borderColor: THEME.emerald,
              backgroundColor: 'rgba(35, 122, 80, 0.08)',
              fill: true,
              borderWidth: 2,
              tension: 0.3,
              pointRadius: 2
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: { duration: 400 },
          scales: {
            x: {
              grid: { color: THEME.gridLines },
              ticks: { color: THEME.mutedSage }
            },
            y: {
              grid: { color: THEME.gridLines },
              ticks: { color: THEME.mutedSage },
              suggestedMin: 100,
              suggestedMax: 350
            }
          }
        }
      });
    } else {
      drawFallbackLine(canvas, initialLabels, rxData, txData);
    }
  }

  // Update live traffic chart with a new simulated data point
  function pushLiveTrafficPoint(canvasId, rx, tx) {
    if (!isChartJsAvailable() || !charts[canvasId]) return;
    const chart = charts[canvasId];
    const now = new Date().toLocaleTimeString().split(' ')[0];

    chart.data.labels.shift();
    chart.data.labels.push(now);

    chart.data.datasets[0].data.shift();
    chart.data.datasets[0].data.push(rx);

    chart.data.datasets[1].data.shift();
    chart.data.datasets[1].data.push(tx);

    chart.update('none');
  }

  // 6. Traffic Monitoring: Protocol Distribution Chart
  function initProtocolDistChart(canvasId) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;

    const labels = ['TCP (HTTP/HTTPS/SSH)', 'UDP (DNS/DHCP/VoIP)', 'ICMP (Ping/Routing)', 'Other Protocols'];
    const dataValues = [71.5, 22.8, 4.3, 1.4];

    if (isChartJsAvailable()) {
      if (charts[canvasId]) charts[canvasId].destroy();
      const ctx = canvas.getContext('2d');
      charts[canvasId] = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels,
          datasets: [{
            data: dataValues,
            backgroundColor: [THEME.mint, THEME.emerald, THEME.bgSurface, '#0B1C13'],
            borderColor: THEME.bgCard,
            borderWidth: 3
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { position: 'bottom' }
          },
          cutout: '65%'
        }
      });
    } else {
      drawFallbackDoughnut(canvas, labels, dataValues, [THEME.mint, THEME.emerald, THEME.bgSurface, '#0B1C13']);
    }
  }

  // 7. Reports: Threat Categories Breakdown
  function initReportThreatCategoriesChart(canvasId) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;

    const labels = [
      'Failed Connections',
      'Traffic Volume',
      'Unusual Patterns',
      'Port Activity',
      'Device Activity'
    ];
    const dataValues = [4, 3, 2, 5, 2];

    if (isChartJsAvailable()) {
      if (charts[canvasId]) charts[canvasId].destroy();
      const ctx = canvas.getContext('2d');
      charts[canvasId] = new Chart(ctx, {
        type: 'bar',
        data: {
          labels,
          datasets: [{
            label: 'Incidents Logged',
            data: dataValues,
            backgroundColor: THEME.emerald,
            hoverBackgroundColor: THEME.mint,
            borderRadius: 6
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: {
              grid: { display: false },
              ticks: { color: THEME.mutedSage }
            },
            y: {
              grid: { color: THEME.gridLines },
              ticks: { color: THEME.mutedSage, stepSize: 1 }
            }
          }
        }
      });
    } else {
      drawFallbackBar(canvas, labels, dataValues, [THEME.emerald, THEME.emerald, THEME.emerald, THEME.emerald, THEME.emerald]);
    }
  }

  // 8. Reports: Bandwidth by Campus Segment
  function initReportSegmentBandwidthChart(canvasId) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;

    const labels = ['Student LAN', 'Faculty LAN', 'Admin Secure', 'Server Farm'];
    const dataValues = [340, 165, 85, 480]; // GB daily aggregate

    if (isChartJsAvailable()) {
      if (charts[canvasId]) charts[canvasId].destroy();
      const ctx = canvas.getContext('2d');
      charts[canvasId] = new Chart(ctx, {
        type: 'bar',
        data: {
          labels,
          datasets: [{
            label: 'Traffic (GB/day)',
            data: dataValues,
            backgroundColor: [THEME.mint, THEME.emerald, THEME.bgSurface, '#51D99A'],
            borderRadius: 6
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: {
              grid: { display: false },
              ticks: { color: THEME.mutedSage }
            },
            y: {
              grid: { color: THEME.gridLines },
              ticks: { color: THEME.mutedSage }
            }
          }
        }
      });
    } else {
      drawFallbackBar(canvas, labels, dataValues, [THEME.mint, THEME.emerald, THEME.bgSurface, '#51D99A']);
    }
  }

  // =========================================================================
  // Canvas Fallback Renderers (For Completely Offline Lab Demonstrations)
  // =========================================================================
  function drawFallbackLine(canvas, labels, ds1, ds2) {
    const ctx = canvas.getContext('2d');
    const w = canvas.width = canvas.parentElement.clientWidth || 400;
    const h = canvas.height = 240;
    ctx.clearRect(0, 0, w, h);

    ctx.fillStyle = '#0B1C13';
    ctx.fillRect(0, 0, w, h);

    // Grid lines
    ctx.strokeStyle = THEME.gridLines;
    ctx.lineWidth = 1;
    for (let i = 1; i <= 4; i++) {
      ctx.beginPath();
      ctx.moveTo(30, (h / 5) * i);
      ctx.lineTo(w - 20, (h / 5) * i);
      ctx.stroke();
    }

    // Dataset 1 (Mint)
    drawLinePlot(ctx, ds1, w, h, THEME.mint, 300);
    // Dataset 2 (Emerald)
    drawLinePlot(ctx, ds2, w, h, THEME.emerald, 300);

    // Text note
    ctx.fillStyle = THEME.mutedSage;
    ctx.font = '10px monospace';
    ctx.fillText('Canvas Render Active', 35, 20);
  }

  function drawLinePlot(ctx, data, w, h, color, maxVal) {
    const startX = 35;
    const endX = w - 25;
    const stepX = (endX - startX) / (data.length - 1);
    ctx.strokeStyle = color;
    ctx.lineWidth = 2.5;
    ctx.beginPath();
    data.forEach((val, idx) => {
      const x = startX + idx * stepX;
      const y = h - 35 - (val / maxVal) * (h - 70);
      if (idx === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();
  }

  function drawFallbackDoughnut(canvas, labels, values, colors) {
    const ctx = canvas.getContext('2d');
    const w = canvas.width = canvas.parentElement.clientWidth || 300;
    const h = canvas.height = 240;
    ctx.clearRect(0, 0, w, h);

    const total = values.reduce((a, b) => a + b, 0);
    let startAngle = -Math.PI / 2;
    const centerX = w / 2;
    const centerY = h / 2 - 15;
    const outerRadius = Math.min(centerX, centerY) - 15;
    const innerRadius = outerRadius * 0.65;

    values.forEach((val, i) => {
      const sliceAngle = (val / total) * (Math.PI * 2);
      ctx.beginPath();
      ctx.arc(centerX, centerY, outerRadius, startAngle, startAngle + sliceAngle);
      ctx.arc(centerX, centerY, innerRadius, startAngle + sliceAngle, startAngle, true);
      ctx.closePath();
      ctx.fillStyle = colors[i % colors.length];
      ctx.fill();
      ctx.strokeStyle = THEME.bgCard;
      ctx.lineWidth = 2;
      ctx.stroke();
      startAngle += sliceAngle;
    });
  }

  function drawFallbackBar(canvas, labels, values, colors) {
    const ctx = canvas.getContext('2d');
    const w = canvas.width = canvas.parentElement.clientWidth || 350;
    const h = canvas.height = 240;
    ctx.clearRect(0, 0, w, h);

    const maxVal = Math.max(...values, 5);
    const startX = 35;
    const endX = w - 20;
    const barWidth = Math.min(35, (endX - startX) / values.length - 15);
    const step = (endX - startX) / values.length;

    values.forEach((val, idx) => {
      const x = startX + idx * step + 8;
      const barHeight = (val / maxVal) * (h - 60);
      const y = h - 30 - barHeight;

      ctx.fillStyle = colors[idx % colors.length];
      ctx.fillRect(x, y, barWidth, barHeight);

      ctx.fillStyle = THEME.mutedSage;
      ctx.font = '10px monospace';
      ctx.fillText(labels[idx].substring(0, 6), x, h - 12);
    });
  }

  // Initialize all theme defaults on load
  applyChartJsThemeDefaults();

  return {
    initTrafficOverTimeChart,
    initTrafficTypeChart,
    initAlertsSeverityChart,
    initDeviceDistChart,
    initLiveTrafficChart,
    pushLiveTrafficPoint,
    initProtocolDistChart,
    initReportThreatCategoriesChart,
    initReportSegmentBandwidthChart
  };
})();
