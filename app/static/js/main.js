/**
 * GHOSTSENTINEL Ω — Main Frontend Application
 *
 * All data comes from the real FastAPI backend.
 * No mock data. No fake scan results.
 * Every action connects to a real API endpoint.
 */

'use strict';

// ─── API helpers ──────────────────────────────────────────────────────────────

const API_BASE = '';   // same origin

async function apiFetch(path, options = {}) {
  const resp = await fetch(API_BASE + path, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  });
  if (!resp.ok) {
    let msg = `HTTP ${resp.status}`;
    try { const j = await resp.json(); msg = j.detail || j.error || msg; } catch {}
    throw new Error(msg);
  }
  return resp.json();
}

async function apiFetchRaw(path, options = {}) {
  const resp = await fetch(API_BASE + path, options);
  if (!resp.ok) {
    let msg = `HTTP ${resp.status}`;
    try { const j = await resp.json(); msg = j.detail || j.error || msg; } catch {}
    throw new Error(msg);
  }
  return resp;
}

// ─── DOM Helpers ──────────────────────────────────────────────────────────────

const $ = (sel, ctx = document) => ctx.querySelector(sel);
const $$ = (sel, ctx = document) => [...ctx.querySelectorAll(sel)];
const el = (tag, cls, html) => { const e = document.createElement(tag); if (cls) e.className = cls; if (html) e.innerHTML = html; return e; };

function setStatus(el, msg, type = 'info') {
  if (!el) return;
  el.textContent = msg;
  el.className = `status-bar ${type}`;
  el.classList.remove('hidden');
}

function clearStatus(el) {
  if (!el) return;
  el.classList.add('hidden');
  el.textContent = '';
  el.className = 'status-bar hidden';
}

function badge(cls, text) {
  return `<span class="badge badge-${cls}">${escHtml(text)}</span>`;
}

function escHtml(str) {
  if (str === null || str === undefined) return 'N/A';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatTs(ts) {
  if (!ts) return 'N/A';
  try { return new Date(ts).toLocaleString(); } catch { return ts; }
}

// ─── Page Navigation ──────────────────────────────────────────────────────────

function initNav() {
  $$('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      $$('.nav-btn').forEach(b => b.classList.remove('active'));
      $$('.page').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      const pg = $(`#page-${btn.dataset.page}`);
      if (pg) pg.classList.add('active');
      onPageActivate(btn.dataset.page);
    });
  });
}

function onPageActivate(page) {
  switch (page) {
    case 'overview': loadOverview(); break;
    case 'wifi':     loadWifiHistory(); break;
    case 'audit':    loadAuditScanList(); break;
    case 'history':  loadHistory(); break;
    case 'findings': loadFindings(); break;
    case 'reports':  loadReports(); loadReportScanList(); break;
    case 'settings': loadHardwareDiagnostics(); break;
    case 'camera':   loadCameraResults(); break;
  }
}

// ─── Overview ─────────────────────────────────────────────────────────────────

async function loadOverview() {
  $('#ov-time').textContent = 'Updated: ' + new Date().toLocaleString();

  // Hardware status
  loadHardwareOverview();

  // Counts from scan history
  try {
    const [wifiScans, devScans, reports] = await Promise.all([
      apiFetch('/api/wifi/scans'),
      apiFetch('/api/devices/scans'),
      apiFetch('/api/reports/list'),
    ]);

    const totalNets = wifiScans.reduce((acc, s) => {
      if (s.result_summary) {
        try { acc += JSON.parse(s.result_summary).networks_found || 0; } catch {}
      }
      return acc;
    }, 0);
    const totalDevs = devScans.reduce((acc, s) => {
      if (s.result_summary) {
        try { acc += JSON.parse(s.result_summary).devices_found || 0; } catch {}
      }
      return acc;
    }, 0);

    $('#ov-networks').textContent = totalNets;
    $('#ov-devices').textContent = totalDevs;
    $('#ov-reports').textContent = reports.length;
  } catch (e) {
    console.warn('Overview counts error:', e);
  }

  // Recent findings
  try {
    const findings = await apiFetch('/api/findings/all/list');
    $('#ov-findings').textContent = findings.length;
    const container = $('#ov-findings-list');
    if (!findings.length) {
      container.innerHTML = '<div class="state-empty">No findings yet. Run a Wi-Fi scan to populate this dashboard.</div>';
      return;
    }
    container.innerHTML = findings.slice(0, 5).map(renderFindingCard).join('');
  } catch (e) {
    $('#ov-findings-list').innerHTML = `<div class="state-error">Could not load findings: ${escHtml(e.message)}</div>`;
  }
}

async function loadHardwareOverview() {
  const sidebar = $('#hw-status');
  try {
    const hw = await apiFetch('/api/system/hardware');
    const wl = hw.wireless_interfaces.length;
    sidebar.textContent = wl ? `✔ ${wl} Wi-Fi adapter(s)` : '⚠ No Wi-Fi adapter';

    const container = $('#ov-hardware');
    container.innerHTML = renderHardwareInfo(hw);
  } catch (e) {
    if (sidebar) sidebar.textContent = 'Hardware check failed';
    const c = $('#ov-hardware');
    if (c) c.innerHTML = `<div class="state-error">Hardware info unavailable: ${escHtml(e.message)}</div>`;
  }
}

function renderHardwareInfo(hw) {
  const adapterHtml = hw.wireless_interfaces.length
    ? hw.wireless_interfaces.map(i => `<span class="hw-ok">✔ ${escHtml(i)}</span>`).join(', ')
    : '<span class="hw-missing">✖ None detected</span>';

  const nmapHtml = hw.nmap_available
    ? `<span class="hw-ok">✔ Available</span> <small style="color:var(--text-muted)">${escHtml(hw.nmap_version || '')}</small>`
    : '<span class="hw-missing">✖ Not found (socket fallback active)</span>';

  const notesHtml = hw.notes.length
    ? hw.notes.map(n => `<div class="hw-note">${escHtml(n)}</div>`).join('')
    : '';

  return `
    <table class="info-table">
      <tr><td>Operating System</td><td>${escHtml(hw.os_name)} ${escHtml(hw.os_version.substring(0, 60))}</td></tr>
      <tr><td>Python Version</td><td>${escHtml(hw.python_version.split(' ')[0])}</td></tr>
      <tr><td>Wireless Interfaces</td><td>${adapterHtml}</td></tr>
      <tr><td>nmap</td><td>${nmapHtml}</td></tr>
      <tr><td>Monitor Mode</td><td>${hw.monitor_mode_capable.length
        ? hw.monitor_mode_capable.map(i => `<span class="hw-ok">✔ ${escHtml(i)}</span>`).join(', ')
        : '<span style="color:var(--text-muted)">NOT SUPPORTED on this configuration</span>'}</td></tr>
    </table>
    ${notesHtml}`;
}

// ─── Wi-Fi Discovery ──────────────────────────────────────────────────────────

let wifiPollTimer = null;
let activeWifiScanId = null;

function initWifi() {
  const scanBtn    = $('#wifi-scan-btn');
  const cancelBtn  = $('#wifi-cancel-btn');
  const searchInput = $('#wifi-search');
  const sortSelect = $('#wifi-sort');

  scanBtn.addEventListener('click', startWifiScan);
  cancelBtn.addEventListener('click', cancelWifiScan);
  searchInput.addEventListener('input', filterWifiResults);
  sortSelect.addEventListener('change', filterWifiResults);
}

async function startWifiScan() {
  const scanBtn   = $('#wifi-scan-btn');
  const cancelBtn = $('#wifi-cancel-btn');
  const statusBar = $('#wifi-scan-status');

  scanBtn.disabled = true;
  cancelBtn.disabled = false;
  setStatus(statusBar, '⏳ Initiating Wi-Fi scan… This may take up to 30 seconds.', 'info');
  $('#wifi-results').innerHTML = '<div class="state-loading"><span class="spinner"></span>Scanning for wireless networks…</div>';

  try {
    const resp = await apiFetch('/api/wifi/scan', { method: 'POST' });
    activeWifiScanId = resp.data.scan_id;
    pollWifiScan(activeWifiScanId);
  } catch (e) {
    setStatus(statusBar, `Error starting scan: ${e.message}`, 'error');
    scanBtn.disabled = false;
    cancelBtn.disabled = true;
  }
}

async function cancelWifiScan() {
  if (!activeWifiScanId) return;
  try {
    await apiFetch(`/api/wifi/scan/${activeWifiScanId}/cancel`, { method: 'POST' });
    setStatus($('#wifi-scan-status'), 'Scan cancelled.', 'warning');
  } catch (e) {
    setStatus($('#wifi-scan-status'), `Cancel failed: ${e.message}`, 'error');
  }
  stopWifiPoll();
}

function pollWifiScan(scanId) {
  clearInterval(wifiPollTimer);
  wifiPollTimer = setInterval(async () => {
    try {
      const r = await apiFetch(`/api/wifi/scan/${scanId}/status`);
      const s = r.data;
      const statusBar = $('#wifi-scan-status');

      if (s.status === 'running' || s.status === 'pending') {
        setStatus(statusBar, `⏳ Scan ${s.status}… Started: ${formatTs(s.started_at)}`, 'info');
      } else {
        stopWifiPoll();
        $('#wifi-scan-btn').disabled = false;
        $('#wifi-cancel-btn').disabled = true;

        if (s.status === 'completed') {
          const summary = s.result_summary || {};
          setStatus(statusBar,
            `✔ Scan complete — ${summary.networks_found || 0} network(s) found via ${summary.method || 'N/A'}` +
            (summary.warning ? ` — ⚠ ${summary.warning}` : ''),
            'success');
          loadWifiNetworks(scanId);
          loadWifiHistory();
        } else if (s.status === 'error') {
          setStatus(statusBar, `✖ Scan error: ${s.error_message || 'Unknown error'}`, 'error');
          $('#wifi-results').innerHTML = `<div class="state-error">Scan failed: ${escHtml(s.error_message)}</div>`;
        } else if (s.status === 'cancelled') {
          setStatus(statusBar, 'Scan was cancelled.', 'warning');
          $('#wifi-results').innerHTML = '<div class="state-empty">Scan was cancelled.</div>';
        }
      }
    } catch (e) {
      stopWifiPoll();
      setStatus($('#wifi-scan-status'), `Poll error: ${e.message}`, 'error');
    }
  }, 2000);
}

function stopWifiPoll() {
  clearInterval(wifiPollTimer);
  wifiPollTimer = null;
}

// Store raw networks for filtering
let _wifiNetworks = [];

async function loadWifiNetworks(scanId) {
  try {
    _wifiNetworks = await apiFetch(`/api/wifi/scan/${scanId}/networks`);
    renderWifiNetworks(_wifiNetworks);
  } catch (e) {
    $('#wifi-results').innerHTML = `<div class="state-error">Could not load networks: ${escHtml(e.message)}</div>`;
  }
}

function renderWifiNetworks(networks) {
  const container = $('#wifi-results');
  if (!networks.length) {
    container.innerHTML = '<div class="state-empty">No networks found. Ensure your Wi-Fi adapter is enabled and nearby networks are broadcasting.</div>';
    return;
  }
  container.innerHTML = networks.map(n => `
    <div class="network-card">
      <div>
        <div class="network-ssid">${escHtml(n.ssid || '(hidden SSID)')}</div>
        <div class="network-bssid">${escHtml(n.bssid || 'BSSID: N/A')}</div>
      </div>
      <div class="network-meta">
        ${badge('info', n.security || 'Unknown')}
      </div>
      <div class="network-meta">
        Ch ${escHtml(n.channel || '—')}
        ${n.frequency_mhz ? `<br><small>${(n.frequency_mhz/1000).toFixed(2)} GHz</small>` : ''}
      </div>
      <div class="network-meta">
        ${n.signal_dbm !== null && n.signal_dbm !== undefined ? `${n.signal_dbm} dBm` : 'Signal: N/A'}
      </div>
      <div class="network-meta">
        <small style="color:var(--text-muted)">WPS: ${escHtml(n.wps_detected || 'unknown')}</small><br>
        <small style="color:var(--text-muted)">${formatTs(n.observed_at)}</small>
      </div>
    </div>`).join('');
}

function filterWifiResults() {
  const query = $('#wifi-search').value.toLowerCase();
  const sort = $('#wifi-sort').value;
  let filtered = _wifiNetworks.filter(n =>
    (n.ssid || '').toLowerCase().includes(query) ||
    (n.bssid || '').toLowerCase().includes(query) ||
    (n.security || '').toLowerCase().includes(query)
  );
  if (sort === 'signal') filtered.sort((a, b) => (b.signal_dbm || -200) - (a.signal_dbm || -200));
  else if (sort === 'ssid') filtered.sort((a, b) => (a.ssid || '').localeCompare(b.ssid || ''));
  else if (sort === 'security') filtered.sort((a, b) => (a.security || '').localeCompare(b.security || ''));
  renderWifiNetworks(filtered);
}

async function loadWifiHistory() {
  const container = $('#wifi-scan-list');
  try {
    const scans = await apiFetch('/api/wifi/scans');
    if (!scans.length) {
      container.innerHTML = '<div class="state-empty">No previous Wi-Fi scans.</div>';
      return;
    }
    container.innerHTML = scans.slice(0, 20).map(s => `
      <div class="history-item">
        <span class="history-id">${s.id.substring(0,8)}…</span>
        <span>Wi-Fi Discovery</span>
        <span class="status-${s.status}">${s.status}</span>
        <span style="color:var(--text-muted);font-size:0.83em">${formatTs(s.started_at)}</span>
        <button class="btn btn-secondary" style="padding:4px 10px;font-size:0.8em"
          onclick="loadWifiNetworks('${escHtml(s.id)}')">View</button>
      </div>`).join('');
  } catch (e) {
    container.innerHTML = `<div class="state-error">Could not load history: ${escHtml(e.message)}</div>`;
  }
}

// ─── Security Audit ───────────────────────────────────────────────────────────

async function loadAuditScanList() {
  const sel = $('#audit-scan-select');
  try {
    const scans = await apiFetch('/api/wifi/scans');
    const completed = scans.filter(s => s.status === 'completed');
    sel.innerHTML = '<option value="">— Choose a completed Wi-Fi scan —</option>' +
      completed.map(s => `<option value="${escHtml(s.id)}">${s.id.substring(0,8)}… — ${formatTs(s.started_at)}</option>`).join('');
  } catch (e) {
    sel.innerHTML = `<option value="">Error loading scans: ${escHtml(e.message)}</option>`;
  }

  sel.addEventListener('change', async () => {
    const scanId = sel.value;
    if (!scanId) {
      $('#audit-results').innerHTML = '<div class="state-empty">No scan selected.</div>';
      return;
    }
    await loadAuditFindings(scanId);
  });
}

async function loadAuditFindings(scanId) {
  const container = $('#audit-results');
  container.innerHTML = '<div class="state-loading"><span class="spinner"></span>Loading findings…</div>';
  try {
    const findings = await apiFetch(`/api/findings/${scanId}`);
    if (!findings.length) {
      container.innerHTML = '<div class="state-empty">No findings generated for this scan. The scan may have returned no networks.</div>';
      return;
    }
    container.innerHTML = findings.map(renderFindingCard).join('');
  } catch (e) {
    container.innerHTML = `<div class="state-error">Could not load findings: ${escHtml(e.message)}</div>`;
  }
}

function renderFindingCard(f) {
  let evidence = [];
  let refs = [];
  try { evidence = JSON.parse(f.evidence || '[]'); } catch {}
  try { refs = JSON.parse(f.references || '[]'); } catch {}

  return `
    <div class="finding-card">
      <div class="finding-header">
        ${badge(f.severity, f.severity)}
        ${badge(f.status, f.status.replace('_', ' '))}
        <span class="finding-title">${escHtml(f.title)}</span>
      </div>
      <div class="finding-desc">${escHtml(f.description)}</div>
      ${evidence.length ? `<div class="finding-evidence">Evidence: ${evidence.map(escHtml).join(' | ')}</div>` : ''}
      ${f.remediation ? `<div class="finding-remediation">💡 ${escHtml(f.remediation)}</div>` : ''}
      ${refs.length ? `<div style="font-size:0.78em;color:var(--text-muted);margin-top:6px">${refs.map(r => `<a href="${escHtml(r)}" target="_blank" rel="noopener" style="color:var(--accent-blue)">${escHtml(r)}</a>`).join(' ')}</div>` : ''}
    </div>`;
}

// ─── Device Discovery ─────────────────────────────────────────────────────────

let activeDevScanId = null;
let devPollTimer = null;

function initDevices() {
  $('#device-scan-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const range = $('#dev-range').value.trim();
    const iface = $('#dev-iface').value.trim();
    const auth  = $('#dev-auth').checked;
    const statusBar = $('#dev-scan-status');

    if (!range) { setStatus(statusBar, 'Please enter a network range.', 'error'); return; }
    if (!iface) { setStatus(statusBar, 'Please enter a network interface name.', 'error'); return; }
    if (!auth)  { setStatus(statusBar, 'You must confirm authorization before scanning.', 'error'); return; }

    setStatus(statusBar, '⏳ Starting device discovery scan…', 'info');
    $('#dev-results').innerHTML = '<div class="state-loading"><span class="spinner"></span>Discovering devices…</div>';
    document.querySelector('#device-scan-form button[type="submit"]').disabled = true;
    $('#dev-cancel-btn').disabled = false;

    try {
      const resp = await apiFetch('/api/devices/scan', {
        method: 'POST',
        body: JSON.stringify({ network_range: range, interface: iface, authorized: true }),
      });
      activeDevScanId = resp.data.scan_id;
      pollDevScan(activeDevScanId);
    } catch (e) {
      setStatus(statusBar, `Error: ${e.message}`, 'error');
      document.querySelector('#device-scan-form button[type="submit"]').disabled = false;
      $('#dev-cancel-btn').disabled = true;
      $('#dev-results').innerHTML = '<div class="state-empty">Scan failed to start.</div>';
    }
  });

  $('#dev-cancel-btn').addEventListener('click', cancelDevScan);
}

function pollDevScan(scanId) {
  clearInterval(devPollTimer);
  devPollTimer = setInterval(async () => {
    try {
      const r = await apiFetch(`/api/devices/scan/${scanId}/status`);
      const s = r.data;
      const statusBar = $('#dev-scan-status');

      if (s.status === 'running' || s.status === 'pending') {
        setStatus(statusBar, `⏳ Scan ${s.status}… (this may take a few minutes for large ranges)`, 'info');
      } else {
        clearInterval(devPollTimer);
        document.querySelector('#device-scan-form button[type="submit"]').disabled = false;
        $('#dev-cancel-btn').disabled = true;

        if (s.status === 'completed') {
          const sum = s.result_summary || {};
          setStatus(statusBar, `✔ Complete — ${sum.devices_found || 0} device(s) found`, 'success');
          loadDeviceResults(scanId);
        } else if (s.status === 'error') {
          setStatus(statusBar, `✖ Error: ${s.error_message}`, 'error');
          $('#dev-results').innerHTML = `<div class="state-error">Scan failed: ${escHtml(s.error_message)}</div>`;
        } else if (s.status === 'cancelled') {
          setStatus(statusBar, 'Scan cancelled.', 'warning');
          $('#dev-results').innerHTML = '<div class="state-empty">Scan cancelled.</div>';
        }
      }
    } catch (e) {
      clearInterval(devPollTimer);
      setStatus($('#dev-scan-status'), `Poll error: ${e.message}`, 'error');
    }
  }, 3000);
}

async function cancelDevScan() {
  if (!activeDevScanId) return;
  try {
    await apiFetch(`/api/devices/scan/${activeDevScanId}/cancel`, { method: 'POST' });
    setStatus($('#dev-scan-status'), 'Cancellation requested.', 'warning');
  } catch (e) {
    setStatus($('#dev-scan-status'), `Cancel error: ${e.message}`, 'error');
  }
  clearInterval(devPollTimer);
}

async function loadDeviceResults(scanId) {
  const container = $('#dev-results');
  try {
    const devices = await apiFetch(`/api/devices/scan/${scanId}/devices`);
    if (!devices.length) {
      container.innerHTML = '<div class="state-empty">No reachable hosts found in range. Ensure you are connected to the same network segment.</div>';
      return;
    }
    container.innerHTML = devices.map(d => {
      let ports = [];
      try { ports = JSON.parse(d.open_ports || '[]'); } catch {}
      let evidence = [];
      try { evidence = JSON.parse(d.camera_evidence || '[]'); } catch {}
      return `
        <div class="device-card">
          <div class="device-ip">${escHtml(d.ip_address)}</div>
          <div class="device-meta">
            MAC: ${escHtml(d.mac_address || 'N/A')} &nbsp;|&nbsp;
            Hostname: ${escHtml(d.hostname || 'N/A')} &nbsp;|&nbsp;
            Vendor: ${escHtml(d.vendor || 'N/A')}<br>
            Open Ports: ${ports.length ? ports.join(', ') : 'None detected'}<br>
            Discovered: ${formatTs(d.discovered_at)}
          </div>
          ${d.is_potential_camera ? `<div class="camera-alert">⚠ Potential camera indicators: ${evidence.map(escHtml).join(' | ')}</div>` : ''}
        </div>`;
    }).join('');
  } catch (e) {
    container.innerHTML = `<div class="state-error">Could not load results: ${escHtml(e.message)}</div>`;
  }
}

// ─── Password Audit ───────────────────────────────────────────────────────────

function initPassword() {
  $('#pw-toggle').addEventListener('click', () => {
    const inp = $('#pw-input');
    inp.type = inp.type === 'password' ? 'text' : 'password';
  });

  $('#pw-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const pw    = $('#pw-input').value;
    const label = $('#pw-label').value.trim() || 'unnamed';
    const resultEl = $('#pw-result');

    if (!pw) {
      resultEl.innerHTML = '<div class="state-error">Please enter a password to assess.</div>';
      resultEl.classList.remove('hidden');
      return;
    }

    resultEl.innerHTML = '<div class="state-loading"><span class="spinner"></span>Analysing locally…</div>';
    resultEl.classList.remove('hidden');

    try {
      const result = await apiFetch('/api/password/audit', {
        method: 'POST',
        body: JSON.stringify({ password: pw, label }),
      });

      // Clear the input immediately after sending
      $('#pw-input').value = '';

      const scoreColours = ['#ff3b3b', '#ff8c00', '#ffd700', '#69f0ae', '#00e676'];
      const col = scoreColours[result.score] || '#888';

      resultEl.innerHTML = `
        <div class="pw-result-box">
          <div class="pw-result-label" style="color:${col}">${escHtml(result.score_label)}</div>
          <div class="pw-crack-time">Estimated crack time (offline slow hash): <strong>${escHtml(result.crack_time_display)}</strong></div>
          <div class="pw-score-bar score-${result.score}"><div class="pw-score-fill"></div></div>
          <table class="info-table" style="margin-top:12px">
            <tr><td>Score</td><td>${result.score} / 4</td></tr>
            <tr><td>Password Length</td><td>${result.length} characters</td></tr>
            <tr><td>Common Pattern Detected</td><td>${result.has_common_pattern ? '<span style="color:var(--accent-red)">Yes</span>' : '<span style="color:var(--accent-green)">No</span>'}</td></tr>
            ${result.warning ? `<tr><td>Warning</td><td style="color:var(--accent-orange)">${escHtml(result.warning)}</td></tr>` : ''}
          </table>
          ${result.suggestions.length ? `
            <div class="pw-suggestions">
              <strong>Suggestions:</strong>
              <ul>${result.suggestions.map(s => `<li>${escHtml(s)}</li>`).join('')}</ul>
            </div>` : ''}
          <p style="font-size:0.75em;color:var(--text-muted);margin-top:12px">
            ⓘ The tested password has been cleared from this field and was not stored or transmitted.
          </p>
        </div>`;
    } catch (e) {
      resultEl.innerHTML = `<div class="state-error">Assessment failed: ${escHtml(e.message)}</div>`;
    }
  });
}

// ─── Camera Inspection ────────────────────────────────────────────────────────

async function loadCameraResults() {
  const container = $('#camera-results');
  try {
    const scans = await apiFetch('/api/devices/scans');
    const completed = scans.filter(s => s.status === 'completed');
    if (!completed.length) {
      container.innerHTML = '<div class="state-empty">No completed device scans. Run a Device Inventory scan first.</div>';
      return;
    }
    // Get devices from all completed device scans
    const allDevicesNested = await Promise.all(
      completed.slice(0, 5).map(s => apiFetch(`/api/devices/scan/${s.id}/devices`).catch(() => []))
    );
    const allDevices = allDevicesNested.flat();
    const cameraDevices = allDevices.filter(d => d.is_potential_camera);

    if (!cameraDevices.length) {
      container.innerHTML = '<div class="state-empty">No potential camera indicators found in recent device scans.<br><small>This does NOT guarantee no cameras exist — offline/disconnected cameras are not detectable.</small></div>';
      return;
    }

    container.innerHTML = `
      <div class="info-box" style="margin-bottom:12px">
        ⚠ ${cameraDevices.length} device(s) show potential camera service indicators.
        This is NOT confirmation of a camera — further physical investigation is required.
      </div>` +
      cameraDevices.map(d => {
        let evidence = [];
        try { evidence = JSON.parse(d.camera_evidence || '[]'); } catch {}
        return `
          <div class="device-card">
            <div class="device-ip">${escHtml(d.ip_address)}</div>
            <div class="device-meta">
              MAC: ${escHtml(d.mac_address || 'N/A')} | Hostname: ${escHtml(d.hostname || 'N/A')}
            </div>
            <div class="camera-alert">
              ⚠ Indicators: ${evidence.map(escHtml).join(' &nbsp;|&nbsp; ')}
            </div>
            <p style="font-size:0.8em;color:var(--text-muted);margin-top:6px">
              Port presence is an indicator only. Perform physical inspection to confirm.
            </p>
          </div>`;
      }).join('');
  } catch (e) {
    container.innerHTML = `<div class="state-error">Could not load camera data: ${escHtml(e.message)}</div>`;
  }
}

function initCamera() {
  // Load saved notes from localStorage
  const saved = localStorage.getItem('gs_camera_notes');
  if (saved) $('#camera-notes').value = saved;

  $('#save-camera-notes').addEventListener('click', () => {
    const notes = $('#camera-notes').value;
    localStorage.setItem('gs_camera_notes', notes);
    $('#camera-notes-status').textContent = '✔ Notes saved locally (browser storage only).';
    $('#camera-notes-status').style.color = 'var(--accent-green)';
    setTimeout(() => { $('#camera-notes-status').textContent = ''; }, 3000);
  });
}

// ─── Scan History ─────────────────────────────────────────────────────────────

async function loadHistory() {
  const container = $('#history-list');
  const query = $('#hist-search').value.toLowerCase();
  container.innerHTML = '<div class="state-loading"><span class="spinner"></span>Loading…</div>';
  try {
    const [wifiScans, devScans] = await Promise.all([
      apiFetch('/api/wifi/scans'),
      apiFetch('/api/devices/scans'),
    ]);
    let all = [...wifiScans, ...devScans].sort((a, b) =>
      new Date(b.started_at || 0) - new Date(a.started_at || 0));
    if (query) all = all.filter(s =>
      s.id.includes(query) || s.scan_type.includes(query) || s.status.includes(query));
    if (!all.length) {
      container.innerHTML = '<div class="state-empty">No scans found.</div>';
      return;
    }
    container.innerHTML = all.map(s => `
      <div class="history-item">
        <span class="history-id">${s.id}</span>
        <span style="color:var(--text-secondary)">${escHtml(s.scan_type.replace('_', ' '))}</span>
        <span class="status-${s.status}">${s.status}</span>
        <span style="color:var(--text-muted);font-size:0.82em">${formatTs(s.started_at)}</span>
        <span style="color:var(--text-muted);font-size:0.82em">${s.completed_at ? formatTs(s.completed_at) : '—'}</span>
      </div>`).join('');
  } catch (e) {
    container.innerHTML = `<div class="state-error">History error: ${escHtml(e.message)}</div>`;
  }
}

function initHistory() {
  $('#hist-refresh').addEventListener('click', loadHistory);
  $('#hist-search').addEventListener('input', loadHistory);
}

// ─── Findings ─────────────────────────────────────────────────────────────────

async function loadFindings() {
  const container = $('#findings-list');
  const sevFilter = $('#findings-severity').value;
  const stFilter  = $('#findings-status').value;
  container.innerHTML = '<div class="state-loading"><span class="spinner"></span>Loading…</div>';
  try {
    let findings = await apiFetch('/api/findings/all/list');
    if (sevFilter) findings = findings.filter(f => f.severity === sevFilter);
    if (stFilter)  findings = findings.filter(f => f.status === stFilter);
    if (!findings.length) {
      container.innerHTML = '<div class="state-empty">No findings match the current filter. Run a Wi-Fi scan to generate findings.</div>';
      return;
    }
    container.innerHTML = findings.map(renderFindingCard).join('');
  } catch (e) {
    container.innerHTML = `<div class="state-error">Could not load findings: ${escHtml(e.message)}</div>`;
  }
}

function initFindings() {
  $('#findings-refresh').addEventListener('click', loadFindings);
  $('#findings-severity').addEventListener('change', loadFindings);
  $('#findings-status').addEventListener('change', loadFindings);
}

// ─── Reports ──────────────────────────────────────────────────────────────────

let selectedReportFmt = 'html';

async function loadReportScanList() {
  const sel = $('#report-scan-select');
  try {
    const [wifiScans, devScans] = await Promise.all([
      apiFetch('/api/wifi/scans'),
      apiFetch('/api/devices/scans'),
    ]);
    const all = [...wifiScans, ...devScans]
      .filter(s => s.status === 'completed')
      .sort((a, b) => new Date(b.started_at || 0) - new Date(a.started_at || 0));
    sel.innerHTML = '<option value="">— Choose a completed scan —</option>' +
      all.map(s => `<option value="${escHtml(s.id)}">${s.id.substring(0,8)}… — ${escHtml(s.scan_type)} — ${formatTs(s.started_at)}</option>`).join('');
  } catch (e) {
    sel.innerHTML = `<option value="">Error: ${escHtml(e.message)}</option>`;
  }
}

async function loadReports() {
  const container = $('#reports-list');
  try {
    const reports = await apiFetch('/api/reports/list');
    if (!reports.length) {
      container.innerHTML = '<div class="state-empty">No reports generated yet.</div>';
      return;
    }
    container.innerHTML = reports.map(r => `
      <div class="report-item">
        <span class="report-filename">${escHtml(r.filename)}</span>
        <span style="color:var(--text-muted);font-size:0.82em">${formatTs(r.generated_at)}</span>
        <span style="color:var(--text-secondary)">${escHtml(r.format)} ${r.size_bytes ? `(${Number(r.size_bytes).toLocaleString()} B)` : ''}</span>
        <a href="/api/reports/download/${escHtml(r.id)}" target="_blank" class="btn btn-secondary" style="padding:4px 12px;font-size:0.8em;text-decoration:none">⬇ Download</a>
      </div>`).join('');
  } catch (e) {
    container.innerHTML = `<div class="state-error">Could not load reports: ${escHtml(e.message)}</div>`;
  }
}

function initReports() {
  // Format buttons
  $$('.fmt-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      $$('.fmt-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      selectedReportFmt = btn.dataset.fmt;
    });
  });

  $('#gen-report-btn').addEventListener('click', async () => {
    const scanId = $('#report-scan-select').value;
    const statusEl = $('#gen-report-status');
    if (!scanId) { statusEl.textContent = 'Please select a scan first.'; statusEl.style.color = 'var(--accent-orange)'; return; }

    statusEl.innerHTML = '<span class="spinner"></span> Generating report…';
    statusEl.style.color = 'var(--accent-blue)';
    try {
      const resp = await apiFetch(
        `/api/reports/generate?scan_id=${encodeURIComponent(scanId)}&fmt=${encodeURIComponent(selectedReportFmt)}`,
        { method: 'POST' }
      );
      statusEl.innerHTML = `✔ ${escHtml(resp.message)}`;
      statusEl.style.color = 'var(--accent-green)';
      loadReports();
    } catch (e) {
      statusEl.textContent = `✖ ${e.message}`;
      statusEl.style.color = 'var(--accent-red)';
    }
  });

  $('#reports-refresh').addEventListener('click', loadReports);
}

// ─── Hardware Diagnostics ─────────────────────────────────────────────────────

async function loadHardwareDiagnostics() {
  const container = $('#hw-details');
  container.innerHTML = '<div class="state-loading"><span class="spinner"></span>Loading hardware info…</div>';
  try {
    const hw = await apiFetch('/api/system/hardware');
    container.innerHTML = renderHardwareInfo(hw);
    $('#app-version').textContent = hw.python_version ? 'GHOSTSENTINEL Ω v' + '0.1.0' : '—';
  } catch (e) {
    container.innerHTML = `<div class="state-error">Hardware diagnostics failed: ${escHtml(e.message)}</div>`;
  }
}

function initSettings() {
  $('#hw-refresh').addEventListener('click', loadHardwareDiagnostics);
}

// ─── Initialisation ───────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  initNav();
  initWifi();
  initDevices();
  initPassword();
  initCamera();
  initHistory();
  initFindings();
  initReports();
  initSettings();

  // Load initial overview
  loadOverview();

  // Also preload wifi history so the history tab is ready
  loadWifiHistory();

  console.log('GHOSTSENTINEL Ω frontend initialised. All data from real backend API.');
});
