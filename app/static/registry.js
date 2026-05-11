'use strict';

const PDNS_ZONE = (typeof window._PDNS_ZONE !== 'undefined')
  ? window._PDNS_ZONE : 'radiodns.zerotrustradio.org';

// ── Utilities ──────────────────────────────────────────────────────────────

function esc(s) {
  return String(s ?? '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function showResult(el, cls, html) {
  if (!el) return;
  el.className = `result-block ${cls}`;
  el.innerHTML = html;
  el.style.display = html ? 'block' : 'none';
}

function adminKey(inputId) {
  return (document.getElementById(inputId) || {}).value?.trim() || '';
}

// ── Tabs ───────────────────────────────────────────────────────────────────

document.querySelectorAll('.reg-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.reg-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    const pane = document.getElementById(`tab-${tab.dataset.tab}`);
    if (pane) pane.classList.add('active');
    if (tab.dataset.tab === 'active') loadActiveStations();
  });
});

// ── Stats bar ──────────────────────────────────────────────────────────────

async function loadStats() {
  try {
    const resp = await fetch('/rdns/registry/api/stats');
    const data = await resp.json();
    if (!resp.ok || !data.ok) throw new Error(data.error || 'failed');
    const s = data.stats;
    document.getElementById('stats-bar').innerHTML = [
      `<div class="stat-chip">FCC Facilities <span class="stat-val">${s.fcc_facilities.toLocaleString()}</span></div>`,
      `<div class="stat-chip">Identities <span class="stat-val">${s.identities_total.toLocaleString()}</span></div>`,
      `<div class="stat-chip">Unclaimed <span class="stat-val">${s.unclaimed.toLocaleString()}</span></div>`,
      s.claim_requested ? `<div class="stat-chip">Pending Claims <span class="stat-val">${s.claim_requested}</span></div>` : '',
      `<div class="stat-chip">Active <span class="stat-val">${s.active}</span></div>`,
      s.open_claims ? `<div class="stat-chip" style="border-color:rgba(255,209,102,0.4)">Open Claims <span class="stat-val" style="color:var(--warn)">${s.open_claims}</span></div>` : '',
    ].join('');
  } catch (e) {
    document.getElementById('stats-bar').innerHTML =
      `<div class="stat-chip" style="color:var(--err)">⚠ Registry stats unavailable — ingest FCC data to populate</div>`;
  }
}

loadStats();

// ── Identity card renderer ─────────────────────────────────────────────────

function claimBadge(status) {
  const labels = {
    unclaimed: 'UNCLAIMED', claim_requested: 'PENDING CLAIM',
    verified: 'VERIFIED', active: 'ACTIVE', suspended: 'SUSPENDED',
  };
  return `<span class="claim-badge badge-${status}">${labels[status] || status.toUpperCase()}</span>`;
}

function bandColor(band) {
  return { FM: '#b967ff', AM: '#ff8c42', LPFM: '#01cdfe', TRANSLATOR: '#06c' }[band] || '#aaa';
}

function renderIdentityCard(id) {
  const cs   = esc(id.callsign || '—');
  const freq = id.frequency ? `${esc(id.frequency)} ${id.band === 'AM' ? 'kHz' : 'MHz'}` : '—';
  const loc  = [id.city, id.state].filter(Boolean).map(esc).join(', ') || '';
  const lid  = id.licensee ? `<div class="ic-meta">${esc(id.licensee)}</div>` : '';
  const fqdn = id.facility_fqdn
    ? `<div class="ic-fqdn">◈ ${esc(id.facility_fqdn)}</div>`
    : '';

  let cardClass = 'identity-card';
  if (id.claim_status === 'active')           cardClass += ' active-card';
  if (id.claim_status === 'claim_requested')  cardClass += ' claimed-card';

  const canClaim = ['unclaimed', 'claim_requested'].includes(id.claim_status);

  return `<div class="${cardClass}" onclick="showDetail(${id.id})">
    <div style="display:flex;justify-content:space-between;align-items:flex-start">
      <div class="ic-callsign" style="color:${bandColor(id.band)}">${cs}</div>
      ${claimBadge(id.claim_status)}
    </div>
    <div class="ic-freq">${esc(id.band)} · ${freq}</div>
    ${loc ? `<div class="ic-meta">${loc}</div>` : ''}
    ${lid}
    ${fqdn}
    <div class="ic-actions">
      <button class="ic-btn" onclick="event.stopPropagation();showDetail(${id.id})">◈ detail</button>
      ${canClaim
        ? `<button class="ic-btn primary" onclick="event.stopPropagation();openClaimModal(${id.id},'${cs}','${esc(id.band)}','${esc(id.frequency||'')}')">▶ claim</button>`
        : ''}
      <button class="ic-btn" onclick="event.stopPropagation();fillOnboarding(${JSON.stringify({
        callsign: id.callsign, frequency: id.frequency, band: id.band,
        city: id.city, state: id.state, licensee: id.licensee,
      }).replace(/"/g,'&quot;')})">↗ onboard</button>
    </div>
  </div>`;
}

function renderGrid(results, container) {
  if (!results.length) {
    container.innerHTML = '<div class="empty-state">◈ No identities found</div>';
    return;
  }
  container.innerHTML = `<div class="identity-grid">${results.map(renderIdentityCard).join('')}</div>`;
}

// ── Search ─────────────────────────────────────────────────────────────────

async function doSearch() {
  const q     = document.getElementById('search-q').value.trim();
  const band  = document.getElementById('search-band').value;
  const state = document.getElementById('search-state').value;
  const el    = document.getElementById('search-results');
  if (!q && !band && !state) { el.innerHTML = '<div class="empty-state">◈ Enter search terms above</div>'; return; }

  el.innerHTML = '<div class="loading">⋯ searching…</div>';
  const params = new URLSearchParams();
  if (q)     params.set('q', q);
  if (band)  params.set('band', band);
  if (state) params.set('state', state);
  params.set('limit', '60');

  try {
    const resp = await fetch('/rdns/registry/api/search?' + params);
    const data = await resp.json();
    if (!resp.ok) { el.innerHTML = `<div class="result-block error">⚠ ${esc(data.error)}</div>`; return; }
    const total = data.total || data.results.length;
    const hdr = `<div style="font-family:var(--mono);font-size:0.75rem;color:var(--muted);margin-bottom:8px">
      ${total.toLocaleString()} result${total !== 1 ? 's' : ''}${total > data.results.length ? ` (showing ${data.results.length})` : ''}
    </div>`;
    renderGrid(data.results, el);
    el.innerHTML = hdr + el.innerHTML;
  } catch (e) {
    el.innerHTML = `<div class="result-block error">⚠ ${esc(e.message)}</div>`;
  }
}

document.getElementById('btn-search').addEventListener('click', doSearch);
document.getElementById('search-q').addEventListener('keydown', e => { if (e.key === 'Enter') doSearch(); });

// ── Identity detail panel ──────────────────────────────────────────────────

window.showDetail = async function(id) {
  const panel   = document.getElementById('detail-panel');
  const content = document.getElementById('detail-content');
  panel.style.display = 'block';
  content.innerHTML = '<div class="loading">⋯ loading identity detail…</div>';
  panel.scrollIntoView({ behavior: 'smooth', block: 'start' });

  try {
    const resp = await fetch(`/rdns/registry/api/identities/${id}`);
    const d = await resp.json();
    if (!resp.ok) { content.innerHTML = `<div class="result-block error">⚠ ${esc(d.error)}</div>`; return; }

    const freq = d.frequency ? `${esc(d.frequency)} ${d.band === 'AM' ? 'kHz' : 'MHz'}` : '—';
    const fccData = d.fcc_data || {};

    content.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:8px;margin-bottom:18px">
        <div>
          <div style="font-family:var(--display);font-size:1.1rem;color:var(--pink)">${esc(d.callsign)}</div>
          <div style="font-family:var(--mono);font-size:0.82rem;color:var(--cyan)">${esc(d.band)} · ${freq}</div>
          <div style="font-family:var(--mono);font-size:0.75rem;color:var(--muted)">${[d.city,d.state].filter(Boolean).map(esc).join(', ')}</div>
        </div>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
          ${claimBadge(d.claim_status)}
          ${(['unclaimed','claim_requested'].includes(d.claim_status))
            ? `<button class="ic-btn primary" onclick="openClaimModal(${d.id},'${esc(d.callsign)}','${esc(d.band)}','${esc(d.frequency||'')}')">▶ CLAIM THIS STATION</button>`
            : ''}
        </div>
      </div>

      <div class="dp-section">
        <h4>ZTR Broadcast Namespaces <span style="font-size:0.6rem;color:var(--muted)">(separate from official RadioDNS)</span></h4>
        <div class="ns-list">
          ${d.facility_fqdn ? `<div class="ns-row"><span class="ns-tag ztr">ZTR FACILITY</span> <span style="color:var(--cyan);font-family:var(--mono);font-size:0.78rem">${esc(d.facility_fqdn)}</span></div>` : ''}
          ${d.slug_fqdn     ? `<div class="ns-row"><span class="ns-tag ztr">ZTR BAND</span> <span style="color:var(--cyan);font-family:var(--mono);font-size:0.78rem">${esc(d.slug_fqdn)}</span></div>` : ''}
          ${d.svc_fqdn      ? `<div class="ns-row"><span class="ns-tag ztr">ZTR SVC</span> <span style="color:var(--cyan);font-family:var(--mono);font-size:0.78rem">${esc(d.svc_fqdn)}</span></div>` : ''}
          ${d.radiodns_bearer
            ? `<div class="ns-row"><span class="ns-tag official">RADIODNS BEARER</span> <span style="color:var(--ok);font-family:var(--mono);font-size:0.78rem">${esc(d.radiodns_bearer)}</span></div>`
            : `<div class="ns-row" style="font-family:var(--mono);font-size:0.72rem;color:rgba(181,168,255,0.4)">
                <span class="ns-tag dormant">BEARER PENDING</span> Official RadioDNS bearer requires verified PI + ECC${d.band === 'AM' ? ' (AM has no RadioDNS bearer per spec)' : ''}
               </div>`}
        </div>
      </div>

      <div class="dp-section">
        <h4>FCC Facility Data</h4>
        ${[
          ['Facility ID', d.facility_id],
          ['Licensee', d.licensee],
          ['FCC Status', d.fcc_status],
          ['Service', fccData.service || d.band],
          ['City/State', [d.city,d.state].filter(Boolean).join(', ')],
          ['Frequency', freq],
        ].map(([k,v]) => v ? `<div class="dp-row"><span class="dp-key">${esc(k)}</span><span class="dp-val">${esc(v)}</span></div>` : '').join('')}
      </div>

      ${d.claims && d.claims.length ? `
      <div class="dp-section">
        <h4>Claims (${d.claims.length})</h4>
        ${d.claims.map(c => `<div class="dp-row">
          <span class="dp-key">${esc(c.status)}</span>
          <span class="dp-val">${esc(c.claimant_name)} · ${esc(c.claimant_email)} · ${esc(c.created_at?.slice(0,10) || '')}</span>
        </div>`).join('')}
      </div>` : ''}

      <div style="display:flex;gap:8px;margin-top:14px">
        <button class="ghost" style="font-size:0.72rem" onclick="document.getElementById('detail-panel').style.display='none'">✕ close</button>
        <button class="ic-btn" onclick="fillOnboarding(${JSON.stringify({
          callsign: d.callsign, frequency: d.frequency, band: d.band
        }).replace(/"/g,'&quot;')})">↗ fill onboarding form</button>
      </div>
    `;
  } catch (e) {
    content.innerHTML = `<div class="result-block error">⚠ ${esc(e.message)}</div>`;
  }
};

// ── Dormant tab ────────────────────────────────────────────────────────────

let _dormantOffset = 0;

async function loadDormant(append = false) {
  const band  = document.getElementById('dormant-band').value;
  const state = document.getElementById('dormant-state').value;
  const el    = document.getElementById('dormant-results');
  const pag   = document.getElementById('dormant-pagination');

  if (!append) { _dormantOffset = 0; el.innerHTML = '<div class="loading">⋯ loading…</div>'; }

  const params = new URLSearchParams({ status: 'unclaimed', limit: 48, offset: _dormantOffset });
  if (band)  params.set('band', band);
  if (state) params.set('state', state);

  try {
    const resp = await fetch('/rdns/registry/api/identities?' + params);
    const data = await resp.json();
    if (!resp.ok) { el.innerHTML = `<div class="result-block error">⚠ ${esc(data.error)}</div>`; return; }

    if (!append) {
      el.innerHTML = `<div style="font-family:var(--mono);font-size:0.75rem;color:var(--muted);margin-bottom:8px">
        ${(data.total||0).toLocaleString()} unclaimed identities
      </div><div class="identity-grid" id="dormant-grid"></div>`;
    }
    const grid = document.getElementById('dormant-grid');
    if (grid) grid.innerHTML += data.results.map(renderIdentityCard).join('');

    _dormantOffset += data.results.length;
    pag.style.display = data.results.length === 48 ? 'block' : 'none';
  } catch (e) {
    el.innerHTML = `<div class="result-block error">⚠ ${esc(e.message)}</div>`;
  }
}

document.getElementById('btn-load-dormant').addEventListener('click', () => loadDormant(false));
document.getElementById('btn-dormant-more').addEventListener('click', () => loadDormant(true));

// ── Active stations tab ────────────────────────────────────────────────────

async function loadActiveStations() {
  const el = document.getElementById('active-results');
  el.innerHTML = '<div class="loading">⋯ loading…</div>';
  try {
    const resp = await fetch('/rdns/registry/api/identities?status=active&limit=100');
    const data = await resp.json();
    if (!resp.ok) { el.innerHTML = `<div class="result-block error">⚠ ${esc(data.error)}</div>`; return; }
    if (!data.results.length) {
      el.innerHTML = '<div class="empty-state">◈ No active stations yet — claim and activate identities via the Search tab</div>';
      return;
    }
    renderGrid(data.results, el);
  } catch (e) {
    el.innerHTML = `<div class="result-block error">⚠ ${esc(e.message)}</div>`;
  }
}

// ── Conflicts tab ──────────────────────────────────────────────────────────

document.getElementById('btn-load-conflicts').addEventListener('click', async () => {
  const el = document.getElementById('conflicts-results');
  el.innerHTML = '<div class="loading">⋯ scanning…</div>';
  try {
    const resp = await fetch('/rdns/registry/api/conflicts');
    const data = await resp.json();
    if (!resp.ok) { el.innerHTML = `<div class="result-block error">⚠ ${esc(data.error)}</div>`; return; }

    let html = '';
    if (data.multi_claim_identities.length) {
      html += `<div style="font-family:var(--display);font-size:0.68rem;color:var(--warn);margin-bottom:8px">
        ⚠ ${data.multi_claim_identities.length} identities with multiple pending claims</div>`;
      html += `<div class="identity-grid">${data.multi_claim_identities.map(c =>
        `<div class="identity-card claimed-card">
          <div class="ic-callsign">${esc(c.callsign)}</div>
          <div class="ic-freq">${esc(c.band)} · ${esc(c.frequency||'?')}</div>
          <div class="ic-meta">${c.pending_claims} pending claims</div>
        </div>`
      ).join('')}</div>`;
    }
    if (data.duplicate_active_callsigns.length) {
      html += `<div style="font-family:var(--display);font-size:0.68rem;color:var(--err);margin:12px 0 8px">
        ✕ ${data.duplicate_active_callsigns.length} callsigns with multiple active identities</div>`;
      html += data.duplicate_active_callsigns.map(d =>
        `<div class="dp-row"><span class="dp-key">${esc(d.callsign)}</span>
         <span class="dp-val">${esc(d.bands)} (${d.active_count} active)</span></div>`
      ).join('');
    }
    if (!html) html = '<div class="result-block ok">✓ No conflicts detected</div>';
    el.innerHTML = html;
  } catch (e) {
    el.innerHTML = `<div class="result-block error">⚠ ${esc(e.message)}</div>`;
  }
});

// ── Ingest tab ────────────────────────────────────────────────────────────

async function doIngest(source, formData) {
  const el  = document.getElementById('ingest-status');
  const key = adminKey('f-admin-key-ingest');
  showResult(el, 'info', '<span class="loading">⋯ ingesting FCC facility data…</span>');

  const headers = {};
  if (key) headers['X-Admin-Key'] = key;

  const url = `/rdns/registry/api/ingest?source=${source}`;
  try {
    const resp = await fetch(url, { method: 'POST', headers, body: formData });
    const data = await resp.json();
    if (!resp.ok) {
      showResult(el, 'error', `⚠ ${esc(data.error || JSON.stringify(data))}`);
      return;
    }
    showResult(el, 'ok',
      `✓ Ingest complete<br>` +
      `Parsed: <strong>${data.parsed?.toLocaleString()}</strong> FCC records<br>` +
      `Ingested: <strong>${data.ingested?.toLocaleString()}</strong> facilities<br>` +
      `Provisioned: <strong>${data.provisioned?.toLocaleString()}</strong> identities<br>` +
      `Source: ${esc(data.source)}`
    );
    loadStats();
  } catch (e) {
    showResult(el, 'error', `⚠ ${esc(e.message)}`);
  }
}

document.getElementById('btn-ingest-cdbs').addEventListener('click', () => {
  doIngest('cdbs', null);
});

document.getElementById('btn-upload-facility').addEventListener('click', () => {
  const file = document.getElementById('f-facility-file').files[0];
  if (!file) { alert('Select a facility.dat or facility.csv file first'); return; }
  const fd = new FormData();
  fd.append('file', file);
  doIngest('upload', fd);
});

document.getElementById('btn-provision').addEventListener('click', async () => {
  const el  = document.getElementById('ingest-status');
  const key = adminKey('f-admin-key-ingest');
  showResult(el, 'info', '<span class="loading">⋯ provisioning identities…</span>');
  try {
    const resp = await fetch('/rdns/registry/api/provision', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(key ? { 'X-Admin-Key': key } : {}) },
      body: JSON.stringify({}),
    });
    const data = await resp.json();
    if (!resp.ok) { showResult(el, 'error', `⚠ ${esc(data.error)}`); return; }
    showResult(el, 'ok', `✓ Provisioned ${data.provisioned?.toLocaleString()} new identities`);
    loadStats();
  } catch (e) {
    showResult(el, 'error', `⚠ ${esc(e.message)}`);
  }
});

// ── Admin claims tab ──────────────────────────────────────────────────────

document.getElementById('btn-load-claims').addEventListener('click', loadClaims);

async function loadClaims() {
  const el     = document.getElementById('claims-results');
  const key    = adminKey('f-admin-key-claims');
  const status = document.getElementById('claims-status-filter').value;
  el.innerHTML = '<div class="loading">⋯ loading claims…</div>';

  const params = new URLSearchParams({ limit: 100 });
  if (status) params.set('status', status);
  if (key) params.set('admin_key', key);

  try {
    const resp = await fetch('/rdns/registry/api/claims?' + params, {
      headers: key ? { 'X-Admin-Key': key } : {},
    });
    const data = await resp.json();
    if (!resp.ok) { el.innerHTML = `<div class="result-block error">⚠ ${esc(data.error)}</div>`; return; }

    if (!data.results.length) {
      el.innerHTML = '<div class="empty-state">◈ No claims found</div>';
      return;
    }
    let html = `<div style="overflow-x:auto"><table class="claims-tbl">
      <thead><tr>
        <th>ID</th><th>Callsign</th><th>Band</th><th>Claimant</th>
        <th>Email</th><th>Status</th><th>Submitted</th><th>Actions</th>
      </tr></thead><tbody>`;
    for (const c of data.results) {
      html += `<tr>
        <td style="color:var(--muted)">${c.id}</td>
        <td style="color:var(--pink);font-family:var(--display);font-size:0.72rem">${esc(c.callsign)}</td>
        <td>${esc(c.band||'')}</td>
        <td>${esc(c.claimant_name)}</td>
        <td style="color:var(--cyan)">${esc(c.claimant_email)}</td>
        <td><span class="claim-badge badge-${c.status}">${esc(c.status)}</span></td>
        <td style="color:var(--muted)">${esc((c.created_at||'').slice(0,10))}</td>
        <td>
          ${c.status === 'pending' ? `
            <button class="ic-btn primary" onclick="approveClaim(${c.id},'${key}')">✓ approve</button>
            <button class="ic-btn" style="border-color:rgba(255,94,147,0.4);color:var(--err)" onclick="rejectClaim(${c.id},'${key}')">✕ reject</button>
          ` : ''}
        </td>
      </tr>`;
    }
    html += '</tbody></table></div>';
    el.innerHTML = html;
  } catch (e) {
    el.innerHTML = `<div class="result-block error">⚠ ${esc(e.message)}</div>`;
  }
}

async function approveClaim(claimId, adminKey) {
  const notes = prompt('Approval notes (optional):') || '';
  try {
    const resp = await fetch(`/rdns/registry/api/claims/${claimId}/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(adminKey ? { 'X-Admin-Key': adminKey } : {}) },
      body: JSON.stringify({ notes, activate: true }),
    });
    const d = await resp.json();
    if (resp.ok) { alert(`✓ Claim ${claimId} approved — station activated`); loadClaims(); loadStats(); }
    else alert(`⚠ ${d.error}`);
  } catch (e) { alert(`⚠ ${e.message}`); }
}

async function rejectClaim(claimId, adminKey) {
  const notes = prompt('Rejection reason:') || '';
  if (!notes) return;
  try {
    const resp = await fetch(`/rdns/registry/api/claims/${claimId}/reject`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(adminKey ? { 'X-Admin-Key': adminKey } : {}) },
      body: JSON.stringify({ notes }),
    });
    const d = await resp.json();
    if (resp.ok) { alert(`✓ Claim ${claimId} rejected`); loadClaims(); }
    else alert(`⚠ ${d.error}`);
  } catch (e) { alert(`⚠ ${e.message}`); }
}

// ── Claim modal ────────────────────────────────────────────────────────────

let _claimIdentityId = null;

window.openClaimModal = function(identityId, callsign, band, freq) {
  _claimIdentityId = identityId;
  const sub = document.getElementById('claim-modal-subtitle');
  sub.textContent = `${callsign} · ${band}${freq ? ' · ' + freq + (band === 'AM' ? ' kHz' : ' MHz') : ''}`;
  document.getElementById('claim-modal-status').style.display = 'none';
  document.getElementById('claim-modal').style.display = 'flex';
};

window.closeClaimModal = function() {
  document.getElementById('claim-modal').style.display = 'none';
  _claimIdentityId = null;
};

document.getElementById('btn-submit-claim').addEventListener('click', async () => {
  if (!_claimIdentityId) return;
  const el = document.getElementById('claim-modal-status');

  const body = {
    claimant_name:  document.getElementById('cm-name').value.trim(),
    claimant_email: document.getElementById('cm-email').value.trim(),
    claimant_title: document.getElementById('cm-title').value.trim(),
    claim_reason:   document.getElementById('cm-reason').value.trim(),
    evidence_type:  document.getElementById('cm-evtype').value,
    pi_code:        document.getElementById('cm-pi').value.trim(),
    ecc:            document.getElementById('cm-ecc').value.trim(),
  };

  if (!body.claimant_name || !body.claimant_email) {
    showResult(el, 'error', '⚠ Name and email are required');
    return;
  }

  showResult(el, 'info', '<span class="loading">⋯ submitting claim…</span>');
  try {
    const resp = await fetch(`/rdns/registry/api/identities/${_claimIdentityId}/claim`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await resp.json();
    if (!resp.ok) { showResult(el, 'error', `⚠ ${esc(data.error)}`); return; }
    showResult(el, 'ok', `✓ ${esc(data.message)}<br>Claim ID: ${data.claim_id}`);
    setTimeout(closeClaimModal, 3000);
    loadStats();
  } catch (e) {
    showResult(el, 'error', `⚠ ${esc(e.message)}`);
  }
});

// ── Fill onboarding form ───────────────────────────────────────────────────

window.fillOnboarding = function(stationData) {
  const params = new URLSearchParams();
  if (stationData.callsign)  params.set('callsign', stationData.callsign);
  if (stationData.frequency) params.set('freq', stationData.frequency);
  if (stationData.band)      params.set('band', stationData.band.toUpperCase());
  window.location.href = `/rdns/onboard?${params}`;
};
