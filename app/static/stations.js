'use strict';

// Zone injected by onboard.html template
const PDNS_ZONE = (typeof window._PDNS_ZONE !== 'undefined')
  ? window._PDNS_ZONE
  : 'radiodns.zerotrustradio.org';

// ── State ──────────────────────────────────────────────────────────────────
let _currentStation = null;   // station object returned by POST /rdns/stations
let _currentRecords = [];     // preview records (before save)

// ── Utilities ──────────────────────────────────────────────────────────────

function toFreq5(freq) {
  let s = String(freq).trim().toLowerCase().replace(/\s*mhz\s*/i, '').replace(/\s*khz\s*/i, '');
  let val = parseFloat(s);
  if (isNaN(val)) return null;
  // If less than 200, assume MHz → convert to 10 kHz units
  if (val < 200) val = Math.round(val * 100);
  return String(Math.round(val)).padStart(5, '0');
}

function buildFQDN(freq5, pi, ecc) {
  if (!freq5 || !pi || !ecc) return null;
  const piC = pi.trim().toLowerCase();
  const eccC = ecc.trim().toLowerCase();
  if (!/^[0-9a-f]{4}$/.test(piC)) return null;
  if (!/^[0-9a-f]{2}$/.test(eccC)) return null;
  const gcc = piC[0] + eccC;
  return `${freq5}.${piC}.${gcc}.fm.${PDNS_ZONE}`;
}

function buildSvcFQDN(callsign) {
  const clean = callsign.toLowerCase().replace(/[^a-z0-9-]/g, '');
  if (!clean) return null;
  return `${clean}.svc.${PDNS_ZONE}`;
}

function absDot(name) {
  return name.replace(/\.+$/, '') + '.';
}

function adminKey() {
  return (document.getElementById('f-admin-key') || {}).value || '';
}

function showResult(el, cls, html) {
  el.className = `result-block ${cls}`;
  el.innerHTML = html;
  el.style.display = 'block';
}

function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── Band selector ──────────────────────────────────────────────────────────

document.querySelectorAll('.band-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.band-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('f-band').value = btn.dataset.band;
    const isFM = btn.dataset.band === 'FM';
    document.querySelectorAll('.fm-only').forEach(el => {
      el.classList.toggle('hidden', !isFM);
    });
    updatePreview();
  });
});

// ── Live FQDN preview ──────────────────────────────────────────────────────

function updatePreview() {
  const previewVal = document.getElementById('fqdn-preview-val');
  const band = document.getElementById('f-band').value;

  if (band !== 'FM') {
    const cs = (document.getElementById('f-callsign').value || '').trim();
    const svcFqdn = cs ? buildSvcFQDN(cs) : null;
    if (svcFqdn) {
      previewVal.innerHTML =
        `<span class="fqdn-dim">svc → </span>${escHtml(svcFqdn)}<br>` +
        `<span class="fqdn-dim">epg → _radioepg._tcp.</span>${escHtml(svcFqdn)}<br>` +
        `<span class="fqdn-dim">spi → _radiospi._tcp.</span>${escHtml(svcFqdn)}`;
    } else {
      previewVal.innerHTML = '<span style="color:rgba(1,205,254,0.3)">fill in callsign…</span>';
    }
    return;
  }

  const freq = (document.getElementById('f-freq').value || '').trim();
  const pi   = (document.getElementById('f-pi').value || '').trim();
  const ecc  = (document.getElementById('f-ecc').value || '').trim();
  const cs   = (document.getElementById('f-callsign').value || '').trim();

  const freq5  = toFreq5(freq);
  const fqdn   = buildFQDN(freq5, pi, ecc);
  const svcFqdn = cs ? buildSvcFQDN(cs) : null;

  if (!fqdn && !svcFqdn) {
    previewVal.innerHTML = '<span style="color:rgba(1,205,254,0.3)">fill in frequency, PI code, ECC…</span>';
    return;
  }

  let html = '';
  if (fqdn) {
    html += `<span class="fqdn-dim">cname → </span>${escHtml(fqdn)}<br>`;
  } else {
    html += `<span class="fqdn-dim">cname → </span><span style="color:rgba(255,94,147,0.6)">incomplete…</span><br>`;
  }
  if (svcFqdn) {
    html += `<span class="fqdn-dim">svc   → </span>${escHtml(svcFqdn)}<br>`;
    html += `<span class="fqdn-dim">epg   → _radioepg._tcp.</span>${escHtml(svcFqdn)}<br>`;
    html += `<span class="fqdn-dim">spi   → _radiospi._tcp.</span>${escHtml(svcFqdn)}`;
  }
  previewVal.innerHTML = html;
}

['f-callsign','f-freq','f-pi','f-ecc','f-epg','f-spi'].forEach(id => {
  const el = document.getElementById(id);
  if (el) el.addEventListener('input', updatePreview);
});

// ── Generate / preview records (client-side only) ─────────────────────────

function generateRecords() {
  const band     = document.getElementById('f-band').value;
  const callsign = (document.getElementById('f-callsign').value || '').trim();
  const freq     = (document.getElementById('f-freq').value || '').trim();
  const pi       = (document.getElementById('f-pi').value || '').trim();
  const ecc      = (document.getElementById('f-ecc').value || '').trim();
  const epg      = (document.getElementById('f-epg').value || '').trim() || `epg.${PDNS_ZONE}`;
  const spi      = (document.getElementById('f-spi').value || '').trim() || epg;

  if (!callsign) { alert('Callsign is required'); return null; }
  if (!freq)     { alert('Frequency is required'); return null; }

  const svcFqdn = buildSvcFQDN(callsign);
  if (!svcFqdn) { alert('Callsign produces an invalid DNS label'); return null; }

  const records = [];

  if (band === 'FM') {
    if (!pi)  { alert('PI Code is required for FM'); return null; }
    if (!ecc) { alert('ECC is required for FM'); return null; }
    const freq5 = toFreq5(freq);
    if (!freq5) { alert('Invalid frequency'); return null; }
    const fqdn = buildFQDN(freq5, pi, ecc);
    if (!fqdn) { alert('Invalid PI code or ECC (must be 4 and 2 hex chars respectively)'); return null; }
    records.push({ fqdn, record_type: 'CNAME', record_value: absDot(svcFqdn), ttl: 300 });
    records.push({ fqdn: `_radioepg._tcp.${svcFqdn}`, record_type: 'SRV', record_value: `0 100 80 ${absDot(epg)}`, ttl: 300 });
    records.push({ fqdn: `_radiospi._tcp.${svcFqdn}`, record_type: 'SRV', record_value: `0 100 80 ${absDot(spi)}`, ttl: 300 });
  } else {
    records.push({ fqdn: `_radioepg._tcp.${svcFqdn}`, record_type: 'SRV', record_value: `0 100 80 ${absDot(epg)}`, ttl: 300 });
    records.push({ fqdn: `_radiospi._tcp.${svcFqdn}`, record_type: 'SRV', record_value: `0 100 80 ${absDot(spi)}`, ttl: 300 });
  }

  _currentRecords = records;
  return records;
}

function renderRecordsPreview(records) {
  if (!records || !records.length) return '';
  let lines = '';
  for (const r of records) {
    const cls = r.record_type === 'CNAME' ? 'rec-cname' : 'rec-srv';
    lines += `<span class="${cls}">${escHtml(r.fqdn)}</span>\t${r.ttl}\tIN\t${r.record_type}\t${escHtml(r.record_value)}\n`;
  }
  return lines.trimEnd();
}

document.getElementById('btn-generate').addEventListener('click', () => {
  const records = generateRecords();
  if (!records) return;

  const panel = document.getElementById('generated-records');
  const pre   = document.getElementById('records-preview');
  pre.innerHTML = renderRecordsPreview(records);
  panel.style.display = '';
  document.getElementById('pdns-status').innerHTML  = '';
  document.getElementById('verify-results').innerHTML = '';
  document.getElementById('btn-save').disabled = false;
  document.getElementById('save-status').innerHTML = '';
  panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
});

// ── Save station (POST /rdns/stations) ────────────────────────────────────

async function saveStation() {
  const band          = document.getElementById('f-band').value;
  const callsign      = (document.getElementById('f-callsign').value || '').trim();
  const frequency     = (document.getElementById('f-freq').value || '').trim();
  const pi_code       = (document.getElementById('f-pi').value || '').trim();
  const ecc           = (document.getElementById('f-ecc').value || '').trim();
  const epg_host      = (document.getElementById('f-epg').value || '').trim();
  const spi_host      = (document.getElementById('f-spi').value || '').trim();
  const provider_name = (document.getElementById('f-provider').value || '').trim();
  const website       = (document.getElementById('f-website').value || '').trim();
  const contact_email = (document.getElementById('f-email').value || '').trim();
  const admin_key     = adminKey();

  const body = { callsign, band, frequency, pi_code, ecc, epg_host, spi_host,
                 provider_name, website, contact_email };
  if (admin_key) body.admin_key = admin_key;

  const saveStatus = document.getElementById('save-status');
  showResult(saveStatus, 'info', '<span class="loading">⋯ saving…</span>');

  try {
    const resp = await fetch('/rdns/stations', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(admin_key ? { 'X-Admin-Key': admin_key } : {}),
      },
      body: JSON.stringify(body),
    });
    const data = await resp.json();
    if (!resp.ok) {
      showResult(saveStatus, 'error', `✕ Error ${resp.status}: ${escHtml(data.error || JSON.stringify(data))}`);
      return;
    }
    _currentStation = data;
    showResult(saveStatus, 'ok',
      `✓ Station saved · id=${data.id} · callsign=${escHtml(data.callsign)} · ${data.records ? data.records.length : 0} records generated`
    );
    // Update generated records panel with saved records
    if (data.records) {
      document.getElementById('records-preview').innerHTML = renderRecordsPreview(data.records);
    }
    loadStations();
  } catch (e) {
    showResult(saveStatus, 'error', `✕ Network error: ${escHtml(e.message)}`);
  }
}

document.getElementById('btn-save').addEventListener('click', saveStation);

// ── Apply to PowerDNS ─────────────────────────────────────────────────────

async function applyToPdns(stationId) {
  const ak = adminKey();
  const statusEl = document.getElementById('pdns-status');
  showResult(statusEl, 'info', '<span class="loading">⋯ applying records to PowerDNS…</span>');

  try {
    const resp = await fetch(`/rdns/stations/${stationId}/pdns/apply`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(ak ? { 'X-Admin-Key': ak } : {}),
      },
      body: JSON.stringify(ak ? { admin_key: ak } : {}),
    });
    const data = await resp.json();
    if (!resp.ok) {
      showResult(statusEl, 'error', `✕ Error ${resp.status}: ${escHtml(data.error || JSON.stringify(data))}`);
      return;
    }
    const allOk = data.all_applied;
    let html = allOk
      ? `<b>⚡ All records applied successfully</b><br>`
      : `<b style="color:var(--warn)">⚠ Some records failed</b><br>`;
    for (const r of (data.results || [])) {
      const icon = r.status === 'applied' ? '✓' : '✕';
      const color = r.status === 'applied' ? 'var(--ok)' : 'var(--err)';
      html += `<span style="color:${color}">${icon}</span> <span style="color:var(--cyan)">${escHtml(r.fqdn)}</span> → ${escHtml(r.record_type)} <span style="color:var(--muted)">[${escHtml(r.pdns_response)}]</span><br>`;
    }
    showResult(statusEl, allOk ? 'ok' : 'error', html);
    loadStations();
  } catch (e) {
    showResult(statusEl, 'error', `✕ Network error: ${escHtml(e.message)}`);
  }
}

document.getElementById('btn-apply').addEventListener('click', () => {
  if (!_currentStation) { alert('Save the station first (▶ SAVE STATION)'); return; }
  applyToPdns(_currentStation.id);
});

// ── Verify DNS ────────────────────────────────────────────────────────────

async function verifyDns(stationId) {
  const verifyEl = document.getElementById('verify-results');
  showResult(verifyEl, 'info', '<span class="loading">⋯ verifying records in PowerDNS zone…</span>');

  try {
    const resp = await fetch(`/rdns/stations/${stationId}/pdns/verify`, { method: 'POST' });
    const data = await resp.json();
    if (!resp.ok) {
      showResult(verifyEl, 'error', `✕ Error ${resp.status}: ${escHtml(data.error || JSON.stringify(data))}`);
      return;
    }
    const allOk = data.all_verified;
    let html = allOk
      ? '<b>✓ All records verified in zone</b><br><br>'
      : '<b style="color:var(--warn)">⚠ Some records not found</b><br><br>';
    for (const r of (data.results || [])) {
      const icon = r.found_in_pdns ? '✓' : '✕';
      const color = r.found_in_pdns ? 'var(--ok)' : 'var(--err)';
      html += `<div class="verify-row">
        <span class="${r.found_in_pdns ? 'vr-ok' : 'vr-fail'}">${icon}</span>
        <span class="vr-type">${escHtml(r.record_type)}</span>
        <span class="vr-name">${escHtml(r.fqdn)}</span>
      </div>`;
    }
    showResult(verifyEl, allOk ? 'ok' : 'error', html);
  } catch (e) {
    showResult(verifyEl, 'error', `✕ Network error: ${escHtml(e.message)}`);
  }
}

document.getElementById('btn-verify').addEventListener('click', () => {
  if (!_currentStation) { alert('Save the station first (▶ SAVE STATION)'); return; }
  verifyDns(_currentStation.id);
});

// ── Download zonefile ─────────────────────────────────────────────────────

async function downloadZonefile(stationId) {
  const url = `/rdns/stations/${stationId}/zonefile`;
  const a = document.createElement('a');
  a.href = url;
  a.download = `station_${stationId}.zone`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

document.getElementById('btn-zonefile').addEventListener('click', () => {
  if (!_currentStation) { alert('Save the station first'); return; }
  downloadZonefile(_currentStation.id);
});

// ── Export JSON ───────────────────────────────────────────────────────────

async function exportJson(stationId) {
  try {
    const resp = await fetch(`/rdns/stations/${stationId}`);
    const data = await resp.json();
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `station_${stationId}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  } catch (e) {
    alert(`Export failed: ${e.message}`);
  }
}

document.getElementById('btn-export').addEventListener('click', () => {
  if (!_currentStation) { alert('Save the station first'); return; }
  exportJson(_currentStation.id);
});

// ── Load / render stations table ──────────────────────────────────────────

async function loadStations() {
  const container = document.getElementById('stations-table');
  container.innerHTML = '<div class="loading">⋯ loading stations…</div>';
  try {
    const resp = await fetch('/rdns/stations');
    const stations = await resp.json();
    if (!resp.ok) {
      container.innerHTML = `<div class="result-block error">Error: ${escHtml(stations.error || 'unknown')}</div>`;
      return;
    }
    renderStationsTable(stations, container);
  } catch (e) {
    container.innerHTML = `<div class="result-block error">Network error: ${escHtml(e.message)}</div>`;
  }
}

function renderStationsTable(stations, container) {
  if (!stations || stations.length === 0) {
    container.innerHTML = '<div class="empty-state">◈ no stations registered yet</div>';
    return;
  }
  let html = `<div style="overflow-x:auto"><table class="stations-tbl">
    <thead>
      <tr>
        <th>ID</th>
        <th>Callsign</th>
        <th>Band</th>
        <th>Frequency</th>
        <th>FQDN</th>
        <th>Status</th>
        <th>Records</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody>`;

  for (const s of stations) {
    const status = s.pdns_applied ? 'applied' : 'pending';
    const applied = s.applied_count || 0;
    const total   = s.record_count  || 0;
    html += `<tr>
      <td style="color:var(--muted)">${s.id}</td>
      <td><span class="callsign">${escHtml(s.callsign)}</span></td>
      <td><span class="badge ${s.band.toLowerCase()}">${escHtml(s.band)}</span></td>
      <td style="color:var(--ink)">${escHtml(s.frequency)}</td>
      <td class="fqdn-cell">${s.fqdn ? escHtml(s.fqdn) : '<span style="color:rgba(181,168,255,0.3)">—</span>'}</td>
      <td><span class="badge ${status}">${status}</span></td>
      <td style="color:var(--muted)">${applied}/${total}</td>
      <td>
        <button class="action-btn" onclick="applyToPdnsById(${s.id})">⚡ apply</button>
        <button class="action-btn" onclick="verifyById(${s.id})">✓ verify</button>
        <button class="action-btn" onclick="downloadZonefile(${s.id})">⤓ zone</button>
        <button class="action-btn" onclick="exportJson(${s.id})">⤓ json</button>
      </td>
    </tr>`;
  }
  html += '</tbody></table></div>';
  container.innerHTML = html;
}

// Helpers for table action buttons (no current station context)
async function applyToPdnsById(stationId) {
  const old = _currentStation;
  _currentStation = { id: stationId };
  const pdnsEl = document.getElementById('pdns-status');
  const oldHtml = pdnsEl.innerHTML;
  document.getElementById('generated-records').style.display = '';
  await applyToPdns(stationId);
  _currentStation = old;
}

async function verifyById(stationId) {
  const verifyEl = document.getElementById('verify-results');
  document.getElementById('generated-records').style.display = '';
  const old = _currentStation;
  _currentStation = { id: stationId };
  await verifyDns(stationId);
  _currentStation = old;
}

document.getElementById('btn-refresh-stations').addEventListener('click', loadStations);

// ── Initial load ──────────────────────────────────────────────────────────
loadStations();
updatePreview();
