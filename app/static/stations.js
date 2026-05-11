'use strict';

// Zone injected by onboard.html template
const PDNS_ZONE = (typeof window._PDNS_ZONE !== 'undefined')
  ? window._PDNS_ZONE
  : 'radiodns.zerotrustradio.org';

const PUBLIC_RADIODNS_SUFFIX = 'fm.radiodns.org';

// ── State ──────────────────────────────────────────────────────────────────
let _currentStation = null;   // station object returned by POST /rdns/stations
let _currentRecords = [];     // preview records (before save)
let _lastBearerCheck = null;  // result of last /rdns/check call

// ── Utilities ──────────────────────────────────────────────────────────────

function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function absDot(name) {
  return name.replace(/\.+$/, '') + '.';
}

function adminKey() {
  return (document.getElementById('f-admin-key') || {}).value || '';
}

function showResult(el, cls, html) {
  if (!el) return;
  el.className = `result-block ${cls}`;
  el.innerHTML = html;
  el.style.display = html ? 'block' : 'none';
}

// ── Frequency / band validation ────────────────────────────────────────────

const FM_MIN = 8750;   // 87.50 MHz in 10 kHz units
const FM_MAX = 10800;  // 108.00 MHz in 10 kHz units
const AM_MIN = 530;    // kHz
const AM_MAX = 1710;   // kHz

/**
 * Parse and range-check a frequency string for the current band.
 * Returns { ok, freq5, freqVal, error }.
 * freq5 is the 5-digit 10 kHz string used in FM FQDNs; null for non-FM.
 */
function validateFreq(band, raw) {
  raw = String(raw || '').trim().toLowerCase()
    .replace(/\s*mhz\s*/i, '').replace(/\s*khz\s*/i, '').trim();

  if (band === 'STREAMING') return { ok: true, freq5: null, freqVal: null, error: null };
  if (!raw) return { ok: false, freq5: null, freqVal: null, error: `frequency is required for ${band}` };

  const val = parseFloat(raw);
  if (isNaN(val)) return { ok: false, freq5: null, freqVal: null, error: `invalid frequency: ${raw}` };

  if (band === 'FM') {
    // Accept MHz (< 200) or already-converted 10 kHz integer (>= 200)
    const tenKhz = val >= 200 ? Math.round(val) : Math.round(val * 100);
    if (tenKhz < FM_MIN || tenKhz > FM_MAX) {
      return {
        ok: false, freq5: null, freqVal: tenKhz,
        error: `FM frequency must be ${FM_MIN/100}–${FM_MAX/100} MHz — got ${raw}. Use AM band for AM kHz frequencies.`,
      };
    }
    return { ok: true, freq5: String(tenKhz).padStart(5, '0'), freqVal: tenKhz, error: null };
  }

  if (band === 'AM') {
    const khz = Math.round(val);
    if (khz < AM_MIN || khz > AM_MAX) {
      return {
        ok: false, freq5: null, freqVal: khz,
        error: `AM frequency must be ${AM_MIN}–${AM_MAX} kHz — got ${raw}`,
      };
    }
    return { ok: true, freq5: null, freqVal: khz, error: null };
  }

  if (band === 'DAB') {
    return { ok: true, freq5: null, freqVal: null, error: null };
  }

  return { ok: false, freq5: null, freqVal: null, error: `unsupported band: ${band}` };
}

function buildFQDNs(freq5, pi, ecc) {
  if (!freq5 || !pi || !ecc) return null;
  const piC = pi.trim().toLowerCase().replace(/^0x/i, '');
  const eccC = ecc.trim().toLowerCase().replace(/^0x/i, '');
  if (!/^[0-9a-f]{4}$/.test(piC)) return null;
  if (!/^[0-9a-f]{2}$/.test(eccC)) return null;
  const gcc = piC[0] + eccC;
  return {
    bearer:  `${freq5}.${piC}.${gcc}.${PUBLIC_RADIODNS_SUFFIX}`,
    managed: `${freq5}.${piC}.${gcc}.fm.${PDNS_ZONE}`,
    gcc,
  };
}

function buildSvcFQDN(callsign) {
  const clean = callsign.toLowerCase().replace(/[^a-z0-9-]/g, '');
  if (!clean) return null;
  return `${clean}.svc.${PDNS_ZONE}`;
}

// ── Station Lookup ────────────────────────────────────────────────────────

// Bearer FQDN pattern: 5digits.4hex.3hex.fm.
const BEARER_FQDN_RE = /^(\d{5})\.([0-9a-f]{4})\.([0-9a-f]{3})\.fm\./i;

async function _doLookup(raw, showWeak = false) {
  const resultsEl = document.getElementById('lookup-results');
  resultsEl.style.display = 'block';

  const isFqdn = BEARER_FQDN_RE.test(raw);
  const url = isFqdn
    ? `/rdns/lookup?fqdn=${encodeURIComponent(raw)}`
    : `/rdns/lookup?callsign=${encodeURIComponent(raw)}${showWeak ? '&show_weak=true' : ''}`;

  resultsEl.innerHTML = `<div class="loading">⋯ ${isFqdn ? 'parsing bearer FQDN' : 'searching ZTR DB + Radio Browser'}…</div>`;

  try {
    const resp = await fetch(url);
    const data = await resp.json();
    if (!resp.ok) {
      resultsEl.innerHTML = `<div class="result-block error">⚠ ${escHtml(data.error || 'lookup failed')}</div>`;
      return;
    }
    if (!data.results || data.results.length === 0) {
      let msg = `<div class="result-block info">◎ No results found for <strong>${escHtml(raw)}</strong>.`;
      if ((data.hidden_count || 0) > 0) {
        msg += ` <button onclick="_doLookup('${escHtml(raw)}',true)" style="background:none;border:none;color:var(--cyan);cursor:pointer;font-family:var(--mono);font-size:0.78rem;text-decoration:underline">Show ${data.hidden_count} low-confidence candidates</button>`;
      }
      msg += ` Fill in the fields manually.</div>`;
      resultsEl.innerHTML = msg;
      return;
    }
    renderLookupResults(data.results, resultsEl, {
      fcc_verified:  data.fcc_verified,
      fcc_facility:  data.fcc_facility,
      hidden_count:  data.hidden_count || 0,
      query:         raw,
    });
  } catch (e) {
    resultsEl.innerHTML = `<div class="result-block error">⚠ Network error: ${escHtml(e.message)}</div>`;
  }
}

async function lookupStation() {
  const raw = (document.getElementById('lookup-callsign').value || '').trim();
  if (!raw) { alert('Enter a callsign or bearer FQDN'); return; }
  await _doLookup(raw, false);
}

// ── Confidence label styling ───────────────────────────────────────────────

const CONFIDENCE_COLORS = {
  exact:    { border: 'rgba(108,255,214,0.4)', bg: 'rgba(108,255,214,0.05)', label: 'var(--ok)' },
  strong:   { border: 'rgba(1,205,254,0.35)',  bg: 'rgba(1,205,254,0.04)',   label: 'var(--cyan)' },
  possible: { border: 'rgba(255,209,102,0.35)',bg: 'rgba(255,209,102,0.04)', label: 'var(--warn)' },
  weak:     { border: 'rgba(255,94,147,0.25)', bg: 'rgba(255,94,147,0.03)', label: 'rgba(255,94,147,0.6)' },
  rejected: { border: 'rgba(255,94,147,0.15)', bg: 'transparent',           label: 'rgba(255,94,147,0.4)' },
};

const IDENTITY_STATUS_ICONS = {
  observed:  '● OBSERVED',
  generated: '◎ GENERATED',
  claimed:   '◈ CLAIMED',
  dormant:   '◈ DORMANT',
  verified:  '✓ FCC VERIFIED',
};

function renderLookupResults(results, el, meta = {}) {
  const total   = results.length;
  const hidden  = meta.hidden_count || 0;
  const fccVerified = meta.fcc_verified || false;
  const fccFacility = meta.fcc_facility || null;

  let hdr = `<div style="font-family:var(--mono);font-size:0.78rem;color:var(--muted);margin-bottom:8px">
    ◈ ${total} result${total !== 1 ? 's' : ''}`;
  if (fccFacility) {
    hdr += ` · <span style="color:var(--ok)">✓ FCC: ${escHtml(fccFacility.callsign)} ${escHtml(fccFacility.frequency || '')} MHz · ${escHtml(fccFacility.city || '')} ${escHtml(fccFacility.state || '')}</span>`;
  } else {
    hdr += ` · <span style="color:var(--warn)">⚠ FCC facility not in registry</span>`;
  }
  if (hidden) {
    hdr += ` · <button id="btn-show-weak" style="background:none;border:none;color:var(--muted);font-family:var(--mono);font-size:0.75rem;cursor:pointer;text-decoration:underline">show ${hidden} low-confidence candidate${hidden !== 1 ? 's' : ''}</button>`;
  }
  hdr += `</div><div style="display:flex;flex-direction:column;gap:6px">`;

  let html = hdr;

  for (let i = 0; i < results.length; i++) {
    const s = results[i];
    const cl    = s.confidence_label || 'weak';
    const score = s.confidence_score ?? 0;
    const cs    = CONFIDENCE_COLORS[cl] || CONFIDENCE_COLORS.weak;
    const freq  = s.frequency ? `${escHtml(s.frequency)} ${s.band === 'AM' ? 'kHz' : 'MHz'}` : '—';
    const loc   = [s.city, s.state].filter(Boolean).map(escHtml).join(', ') || '';
    const hasPi = s.pi_code && s.ecc;
    const statusIcon = IDENTITY_STATUS_ICONS[s.identity_status] || '';
    const warnings = (s.warnings || []);

    const srcLabel = {
      'ztr-db':          '◈ ZTR DB',
      'ztr-cname-scan':  '◈ ZTR scan',
      'ztr-candidates':  '◎ ZTR generated',
      'fqdn-parse':      '◈ FQDN',
      'radio-browser':   '◎ Radio Browser',
    }[s.source] || escHtml(s.source || '');

    const callsignDisplay = s.callsign
      ? escHtml(s.callsign)
      : `<span style="color:rgba(255,94,147,0.4)">UNKNOWN</span>`;

    html += `<div class="lookup-row" data-idx="${i}" onclick="fillFromLookup(${i})" style="
      cursor:pointer;padding:10px 14px;border-radius:6px;
      background:${cs.bg};border:1px solid ${cs.border};
      display:flex;align-items:flex-start;gap:14px;transition:background 0.15s
    " onmouseover="this.style.background='${cs.bg.replace('0.0', '0.1')}'" onmouseout="this.style.background='${cs.bg}'">
      ${s.favicon ? `<img src="${escHtml(s.favicon)}" alt="" style="width:30px;height:30px;object-fit:contain;border-radius:4px;flex-shrink:0;margin-top:2px" onerror="this.style.display='none'">` : '<div style="width:30px;flex-shrink:0"></div>'}
      <div style="flex:1;min-width:0">
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
          <span style="color:var(--pink);font-family:var(--display);font-size:0.8rem;font-weight:bold">${callsignDisplay}</span>
          <span style="color:${cs.label};font-family:var(--mono);font-size:0.68rem;font-weight:bold">${cl.toUpperCase()} · ${score}%</span>
          ${hasPi ? `<span style="color:var(--ok);font-size:0.67rem">● PI+ECC</span>` : ''}
          ${s.fcc_verified ? `<span style="color:var(--ok);font-size:0.67rem">✓ FCC</span>` : `<span style="color:rgba(255,209,102,0.6);font-size:0.67rem">⚠ no FCC</span>`}
          ${statusIcon ? `<span style="color:var(--muted);font-size:0.65rem">${statusIcon}</span>` : ''}
        </div>
        <div style="color:var(--muted);font-size:0.72rem;margin-top:3px">
          ${freq} · ${escHtml(s.band || 'FM')}
          ${hasPi ? ` · PI <code style="color:var(--cyan)">${escHtml(s.pi_code)}</code> · ECC <code style="color:var(--cyan)">${escHtml(s.ecc)}</code>` : ''}
          ${loc ? ` · ${loc}` : ''}
          ${s.licensee ? ` · ${escHtml(s.licensee)}` : ''}
        </div>
        ${s.facility_id ? `<div style="color:rgba(181,168,255,0.5);font-size:0.67rem;margin-top:2px">facility: ${escHtml(s.facility_id)}</div>` : ''}
        ${warnings.length ? `<div style="color:rgba(255,209,102,0.7);font-size:0.67rem;margin-top:3px">⚠ ${warnings.map(escHtml).join(' · ')}</div>` : ''}
        ${(s.match_reasons || []).length && cl !== 'weak' && cl !== 'rejected'
          ? `<div style="color:rgba(108,255,214,0.4);font-size:0.65rem;margin-top:2px">${s.match_reasons.map(escHtml).join(' · ')}</div>` : ''}
        <div style="color:var(--muted);font-size:0.65rem;margin-top:2px">${srcLabel}</div>
      </div>
      ${s.homepage ? `<a href="${escHtml(s.homepage)}" target="_blank" onclick="event.stopPropagation()" style="color:var(--cyan);font-size:0.7rem;white-space:nowrap;margin-top:2px">↗</a>` : ''}
      <span style="color:${cs.label};font-size:0.72rem;white-space:nowrap;margin-top:2px;flex-shrink:0">▶ USE</span>
    </div>`;
  }
  html += '</div>';
  el.innerHTML = html;
  el._lookupResults = results;
  el._lookupMeta = meta;

  // Wire "show weak" button
  const weakBtn = document.getElementById('btn-show-weak');
  if (weakBtn) {
    weakBtn.addEventListener('click', e => {
      e.stopPropagation();
      const cs = (document.getElementById('lookup-callsign').value || '').trim();
      if (cs) _doLookup(cs, true);
    });
  }
}

window.fillFromLookup = function(idx) {
  const resultsEl = document.getElementById('lookup-results');
  const results = resultsEl._lookupResults;
  if (!results || !results[idx]) return;
  const s = results[idx];

  const cl = s.confidence_label || 'weak';

  // Safeguard: warn on weak/rejected
  if (cl === 'rejected') {
    if (!confirm(
      `⚠ This candidate has very low confidence (${s.confidence_score}%).\n\n` +
      `Warnings:\n${(s.warnings || []).join('\n') || 'unknown reasons'}\n\n` +
      `Use anyway? You will need to verify all fields manually.`
    )) return;
  } else if (cl === 'weak') {
    if (!confirm(
      `⚠ Low confidence match (${s.confidence_score}%).\n${(s.warnings || []).join('\n') || ''}\n\nContinue?`
    )) return;
  }

  const filled = [];

  if (s.callsign) { document.getElementById('f-callsign').value = s.callsign; filled.push('callsign'); }
  if (s.frequency) { document.getElementById('f-freq').value = s.frequency; filled.push('frequency'); }
  if (s.pi_code)  { document.getElementById('f-pi').value  = s.pi_code;  filled.push('PI code'); }
  if (s.ecc)      { document.getElementById('f-ecc').value  = s.ecc;      filled.push('ECC'); }
  if (s.homepage) { document.getElementById('f-website').value = s.homepage; filled.push('website'); }

  if (s.band) {
    applyBand(s.band.toUpperCase());
  }

  const hasPi = s.pi_code && s.ecc;
  const warnHtml = cl === 'possible'
    ? `<br><span style="color:var(--warn);font-size:0.75rem">⚠ Possible match (${s.confidence_score}%) — verify frequency and PI code</span>`
    : '';

  resultsEl.innerHTML = `<div class="result-block ${cl === 'exact' || cl === 'strong' ? 'ok' : 'info'}">
    ✓ Autofilled: <strong>${filled.join(', ')}</strong>
    · <span style="color:var(--muted);font-size:0.75rem">${cl} · ${s.confidence_score}%</span>
    ${s.homepage ? `· <a href="${escHtml(s.homepage)}" target="_blank" style="color:var(--cyan)">${escHtml(s.homepage)}</a>` : ''}
    ${hasPi
      ? `<br><span style="color:var(--ok);font-size:0.78rem">● PI code and ECC from ${s.identity_status === 'observed' ? 'ZTR discovery data' : 'candidate data — verify manually'}</span>`
      : `<br><span style="color:var(--warn);font-size:0.78rem">⚠ PI code and ECC not found — enter manually (check radiotext.fm or RDS data)</span>`}
    ${s.fcc_verified ? `<br><span style="color:var(--ok);font-size:0.75rem">✓ FCC verified — facility ${escHtml(s.facility_id || '')} ${escHtml(s.city || '')} ${escHtml(s.state || '')}</span>` : `<br><span style="color:rgba(255,209,102,0.7);font-size:0.75rem">⚠ FCC facility not confirmed</span>`}
    ${warnHtml}
  </div>`;

  updatePreview();
  if (!s.pi_code) document.getElementById('f-pi')?.focus();
  else if (!s.ecc) document.getElementById('f-ecc')?.focus();
};

document.getElementById('btn-lookup').addEventListener('click', lookupStation);
document.getElementById('lookup-callsign').addEventListener('keydown', e => {
  if (e.key === 'Enter') lookupStation();
});

function buildDABFQDN(scids, sid, eid, gcc) {
  scids = (scids || '0').trim().toLowerCase();
  sid   = (sid || '').trim().toLowerCase();
  eid   = (eid || '').trim().toLowerCase();
  gcc   = (gcc || '').trim().toLowerCase();
  if (!sid || !eid || !gcc) return null;
  if (!/^[0-9a-f]{4,8}$/.test(sid)) return null;
  if (!/^[0-9a-f]{4}$/.test(eid))   return null;
  if (!/^[0-9a-f]{3}$/.test(gcc))   return null;
  if (!/^[0-9a-f]{1,3}$/.test(scids)) return null;
  return {
    bearer:  `${scids}.${sid}.${eid}.${gcc}.dab.radiodns.org`,
    managed: `${scids}.${sid}.${eid}.${gcc}.dab.${PDNS_ZONE}`,
  };
}

// ── Band selector ──────────────────────────────────────────────────────────

function applyBand(band) {
  document.getElementById('f-band').value = band;
  document.querySelectorAll('.band-btn').forEach(b => b.classList.toggle('active', b.dataset.band === band));
  const isFM  = band === 'FM';
  const isDAB = band === 'DAB';
  const isAM  = band === 'AM';
  document.querySelectorAll('.fm-only').forEach(el => {
    el.classList.toggle('hidden', !isFM);
    if (el.style !== undefined) el.style.display = isFM ? '' : 'none';
  });
  document.querySelectorAll('.dab-only').forEach(el => { el.style.display = isDAB ? '' : 'none'; });
  document.querySelectorAll('.am-only').forEach(el  => { el.style.display = isAM  ? '' : 'none'; });
  const amNote  = document.getElementById('band-info-am');
  const dabNote = document.getElementById('band-info-dab');
  if (amNote)  amNote.style.display  = isAM  ? 'block' : 'none';
  if (dabNote) dabNote.style.display = isDAB ? 'block' : 'none';
  // Frequency placeholder
  const freqEl = document.getElementById('f-freq');
  if (freqEl) freqEl.placeholder = isAM ? '9600 (kHz, DRM)' : '106.5';
}

document.querySelectorAll('.band-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    _lastBearerCheck = null;
    applyBand(btn.dataset.band);
    updatePreview();
  });
});

// ── Live FQDN preview ──────────────────────────────────────────────────────

function updatePreview() {
  const previewVal = document.getElementById('fqdn-preview-val');
  const band = document.getElementById('f-band').value;
  const cs   = (document.getElementById('f-callsign').value || '').trim();
  const svcFqdn = cs ? buildSvcFQDN(cs) : null;

  if (band === 'DAB') {
    const eid   = (document.getElementById('f-eid')?.value || '').trim();
    const sid   = (document.getElementById('f-sid')?.value || '').trim();
    const scids = (document.getElementById('f-scids')?.value || '0').trim();
    const gcc   = (document.getElementById('f-gcc-dab')?.value || '').trim();
    const fqdns = buildDABFQDN(scids, sid, eid, gcc);
    let html = '';
    if (fqdns) {
      html += `<span class="fqdn-dim">bearer  → </span>${escHtml(fqdns.bearer)}<br>`;
      html += `<span class="fqdn-dim">managed → </span>${escHtml(fqdns.managed)}<br>`;
    } else {
      html += `<span class="fqdn-dim">bearer  → </span><span style="color:rgba(255,94,147,0.5)">fill in EId, SId, GCC…</span><br>`;
    }
    if (svcFqdn) {
      html += `<span class="fqdn-dim">svc     → </span>${escHtml(svcFqdn)}<br>`;
      html += `<span class="fqdn-dim">epg     → _radioepg._tcp.</span>${escHtml(svcFqdn)}<br>`;
      html += `<span class="fqdn-dim">spi     → _radiospi._tcp.</span>${escHtml(svcFqdn)}`;
    }
    previewVal.innerHTML = html || '<span style="color:rgba(1,205,254,0.3)">fill in DAB fields above…</span>';
    return;
  }

  if (band !== 'FM') {
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

  const freq    = (document.getElementById('f-freq').value || '').trim();
  const pi      = (document.getElementById('f-pi').value || '').trim();
  const ecc     = (document.getElementById('f-ecc').value || '').trim();
  const country = (document.getElementById('f-country')?.value || '').trim().toUpperCase();

  const freqResult = validateFreq('FM', freq);

  if (!freq && !pi && !ecc && !cs) {
    previewVal.innerHTML = '<span style="color:rgba(1,205,254,0.3)">fill in fields above…</span>';
    return;
  }

  if (freq && !freqResult.ok) {
    previewVal.innerHTML = `<span style="color:var(--err)">⚠ ${escHtml(freqResult.error)}</span>`;
    return;
  }

  const fqdns = freqResult.freq5 && pi && ecc ? buildFQDNs(freqResult.freq5, pi, ecc) : null;
  // Country code fallback bearer (when ECC missing)
  const countryBearer = freqResult.freq5 && pi && !ecc && /^[A-Z]{2}$/.test(country)
    ? { bearer: `${freqResult.freq5}.${pi.toLowerCase()}.${country.toLowerCase()}.fm.radiodns.org`,
        managed: `${freqResult.freq5}.${pi.toLowerCase()}.${country.toLowerCase()}.fm.${PDNS_ZONE}` }
    : null;

  let html = '';
  if (fqdns) {
    html += `<span class="fqdn-dim">bearer  → </span>${escHtml(fqdns.bearer)}<br>`;
    html += `<span class="fqdn-dim">managed → </span>${escHtml(fqdns.managed)}<br>`;
    if (country && /^[A-Z]{2}$/.test(country)) {
      html += `<span class="fqdn-dim">country → </span><span style="color:rgba(1,205,254,0.45)">${escHtml(freqResult.freq5)}.${escHtml(pi.toLowerCase())}.${escHtml(country.toLowerCase())}.fm.radiodns.org</span><br>`;
    }
  } else if (countryBearer) {
    html += `<span class="fqdn-dim">bearer  → </span>${escHtml(countryBearer.bearer)} <span style="color:var(--warn);font-size:0.72rem">(country fallback)</span><br>`;
    html += `<span class="fqdn-dim">managed → </span>${escHtml(countryBearer.managed)}<br>`;
  } else if (freqResult.freq5) {
    html += `<span class="fqdn-dim">bearer  → </span><span style="color:rgba(255,94,147,0.5)">fill in PI and ECC (or country code)…</span><br>`;
  }
  if (svcFqdn) {
    html += `<span class="fqdn-dim">svc     → </span>${escHtml(svcFqdn)}<br>`;
    html += `<span class="fqdn-dim">epg     → _radioepg._tcp.</span>${escHtml(svcFqdn)}<br>`;
    html += `<span class="fqdn-dim">spi     → _radiospi._tcp.</span>${escHtml(svcFqdn)}`;
  }
  previewVal.innerHTML = html || '<span style="color:rgba(1,205,254,0.3)">fill in fields above…</span>';

  if ((fqdns || countryBearer) && svcFqdn) scheduleAutoCheck();
}

['f-callsign','f-freq','f-pi','f-ecc','f-country','f-epg','f-spi',
 'f-eid','f-sid','f-scids','f-gcc-dab'].forEach(id => {
  const el = document.getElementById(id);
  if (el) el.addEventListener('input', updatePreview);
});

// ── Auto bearer check (debounced) ─────────────────────────────────────────

let _autoCheckTimer = null;
function scheduleAutoCheck() {
  clearTimeout(_autoCheckTimer);
  _autoCheckTimer = setTimeout(runBearerCheck, 800);
}

// ── CHECK CURRENT RADIODNS ────────────────────────────────────────────────

async function runBearerCheck() {
  const band = document.getElementById('f-band').value;
  const freq = (document.getElementById('f-freq').value || '').trim();
  const pi   = (document.getElementById('f-pi').value || '').trim();
  const ecc  = (document.getElementById('f-ecc').value || '').trim();
  const checkEl = document.getElementById('check-status');

  if (band !== 'FM' || !freq || !pi || !ecc) {
    showResult(checkEl, '', '');
    return;
  }

  showResult(checkEl, 'info', '<span class="loading">⋯ checking public RadioDNS bearer…</span>');
  try {
    const resp = await fetch('/rdns/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ band, frequency: freq, pi_code: pi, ecc }),
    });
    const data = await resp.json();
    if (!resp.ok) {
      showResult(checkEl, 'error', `⚠ ${escHtml(data.error || JSON.stringify(data))}`);
      _lastBearerCheck = null;
      return;
    }
    _lastBearerCheck = data;
    const fqdn = data.bearer_fqdn ? `<code>${escHtml(data.bearer_fqdn)}</code>` : '';
    if (!data.exists) {
      showResult(checkEl, 'ok',
        `◎ Available — no existing public RadioDNS record found<br>${fqdn}`);
    } else if (!data.conflict) {
      showResult(checkEl, 'ok',
        `✓ Existing — already points to our managed zone → <code>${escHtml(data.target || '')}</code><br>${fqdn}`);
    } else {
      showResult(checkEl, 'error',
        `⚠ Conflict — bearer already points to another provider: <code>${escHtml(data.target || '')}</code><br>${fqdn}<br>` +
        `<small>You can still save; you will need to confirm override before applying to PowerDNS.</small>`);
    }
  } catch (e) {
    showResult(checkEl, 'error', `⚠ Check failed: ${escHtml(e.message)}`);
    _lastBearerCheck = null;
  }
}

document.getElementById('btn-check') && document.getElementById('btn-check').addEventListener('click', () => {
  clearTimeout(_autoCheckTimer);
  runBearerCheck();
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

  const svcFqdn = buildSvcFQDN(callsign);
  if (!svcFqdn) { alert('Callsign produces an invalid DNS label'); return null; }

  const records = [];

  if (band === 'FM') {
    if (!pi)  { alert('PI Code is required for FM'); return null; }
    if (!ecc) { alert('ECC is required for FM'); return null; }

    const freqResult = validateFreq('FM', freq);
    if (!freqResult.ok) { alert(freqResult.error); return null; }

    const fqdns = buildFQDNs(freqResult.freq5, pi, ecc);
    if (!fqdns) { alert('Invalid PI code or ECC (must be 4 and 2 hex chars respectively)'); return null; }

    records.push({ fqdn: fqdns.managed, record_type: 'CNAME', record_value: absDot(svcFqdn), ttl: 300 });
    records.push({ fqdn: `_radioepg._tcp.${svcFqdn}`, record_type: 'SRV', record_value: `0 100 80 ${absDot(epg)}`, ttl: 300 });
    records.push({ fqdn: `_radiospi._tcp.${svcFqdn}`, record_type: 'SRV', record_value: `0 100 80 ${absDot(spi)}`, ttl: 300 });
  } else if (band === 'DAB') {
    const eid   = (document.getElementById('f-eid')?.value   || '').trim();
    const sid   = (document.getElementById('f-sid')?.value   || '').trim();
    const scids = (document.getElementById('f-scids')?.value || '0').trim();
    const gcc   = (document.getElementById('f-gcc-dab')?.value || '').trim();
    const fqdns = buildDABFQDN(scids, sid, eid, gcc);
    if (!fqdns) { alert('Invalid DAB fields — check EId (4 hex), SId (4–8 hex), GCC (3 hex)'); return null; }
    records.push({ fqdn: fqdns.managed, record_type: 'CNAME', record_value: absDot(svcFqdn), ttl: 300 });
    records.push({ fqdn: `_radioepg._tcp.${svcFqdn}`, record_type: 'SRV', record_value: `0 100 80 ${absDot(epg)}`, ttl: 300 });
    records.push({ fqdn: `_radiospi._tcp.${svcFqdn}`, record_type: 'SRV', record_value: `0 100 80 ${absDot(spi)}`, ttl: 300 });
  } else if (band === 'AM') {
    const freqResult = validateFreq('AM', freq);
    if (!freqResult.ok) { alert(freqResult.error); return null; }
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
    lines += `<span class="${cls}">${escHtml(absDot(r.fqdn))}</span>\t${r.ttl}\tIN\t${r.record_type}\t${escHtml(r.record_value)}\n`;
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

  // Frontend frequency validation before hitting the API
  if (band !== 'STREAMING') {
    const fv = validateFreq(band, frequency);
    if (!fv.ok) {
      showResult(document.getElementById('save-status'), 'error', `⚠ ${escHtml(fv.error)}`);
      return;
    }
  }

  const country_code = (document.getElementById('f-country')?.value || '').trim().toUpperCase();
  const dab_eid   = (document.getElementById('f-eid')?.value   || '').trim();
  const dab_sid   = (document.getElementById('f-sid')?.value   || '').trim();
  const dab_scids = (document.getElementById('f-scids')?.value || '').trim();
  const dab_gcc   = (document.getElementById('f-gcc-dab')?.value || '').trim();

  const body = { callsign, band, frequency, pi_code, ecc, epg_host, spi_host,
                 provider_name, website, contact_email };
  if (country_code) body.country_code = country_code;
  if (band === 'DAB') {
    body.eid     = dab_eid;
    body.sid     = dab_sid;
    body.scids   = dab_scids || '0';
    body.gcc_dab = dab_gcc;
  }
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
    let msg = `✓ Station saved · id=${data.id} · callsign=${escHtml(data.callsign)} · ${data.records ? data.records.length : 0} records`;
    if (data.bearer_fqdn) msg += `<br><span style="color:var(--muted);font-size:0.8rem">bearer → ${escHtml(data.bearer_fqdn)}</span>`;
    if (data.managed_fqdn) msg += `<br><span style="color:var(--muted);font-size:0.8rem">managed → ${escHtml(data.managed_fqdn)}</span>`;
    showResult(saveStatus, 'ok', msg);
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

  // Warn if there's a known conflict and no force flag
  if (_lastBearerCheck && _lastBearerCheck.conflict) {
    const ok = confirm(
      `⚠ Conflict detected: the public RadioDNS bearer already points to "${_lastBearerCheck.target || 'another provider'}".\n\nApply our managed records anyway?`
    );
    if (!ok) return;
  }

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
      html += `<div class="verify-row">
        <span class="${r.found_in_pdns ? 'vr-ok' : 'vr-fail'}">${r.found_in_pdns ? '✓' : '✕'}</span>
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

function downloadZonefile(stationId) {
  const a = document.createElement('a');
  a.href = `/rdns/stations/${stationId}/zonefile`;
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
    container.innerHTML = '<div class="empty-state">◈ awaiting first station registration</div>';
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
      <td><span class="badge ${(s.band||'fm').toLowerCase()}">${escHtml(s.band||'FM')}</span></td>
      <td style="color:var(--ink)">${escHtml(s.frequency||'')}</td>
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
  document.getElementById('generated-records').style.display = '';
  _currentStation = { id: stationId };
  await applyToPdns(stationId);
}

async function verifyById(stationId) {
  document.getElementById('generated-records').style.display = '';
  _currentStation = { id: stationId };
  await verifyDns(stationId);
}

document.getElementById('btn-refresh-stations').addEventListener('click', loadStations);

// ── Initial load ──────────────────────────────────────────────────────────
loadStations();

// Apply registry pre-fill if present (?callsign=&freq=&band=)
if (typeof window._PREFILL !== 'undefined' && window._PREFILL) {
  const pf = window._PREFILL;
  if (pf.callsign) document.getElementById('f-callsign').value = pf.callsign;
  if (pf.freq)     document.getElementById('f-freq').value     = pf.freq;
  if (pf.band)     applyBand(pf.band);
}

updatePreview();
