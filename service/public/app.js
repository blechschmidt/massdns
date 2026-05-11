/* Hybrid Radio Infrastructure — frontend */
(function () {
  'use strict'

  // ---------------------------------------------------------------------------
  // Config (fetched from /service/config)
  // ---------------------------------------------------------------------------
  let CFG = { zone: 'radiodns.zerotrustradio.org', adminKeyRequired: false }

  async function loadConfig() {
    try {
      const r = await fetch('/service/config')
      CFG = await r.json()
      if (CFG.adminKeyRequired) {
        document.getElementById('admin-key-row')?.classList.remove('hidden')
      }
    } catch (_) {}
  }

  // ---------------------------------------------------------------------------
  // Utilities
  // ---------------------------------------------------------------------------
  function $id(id) { return document.getElementById(id) }

  function esc(s) {
    return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
  }

  function setPill(el, text, cls) {
    el.textContent = text
    el.className = 'pill ' + (cls || '')
  }

  // ---------------------------------------------------------------------------
  // FQDN preview
  // ---------------------------------------------------------------------------
  function parseFreq(raw) {
    const s = String(raw || '').trim().toLowerCase().replace(/mhz/, '').trim()
    if (!s) return null
    let n = s.includes('.') ? Math.round(parseFloat(s) * 100) : parseInt(s, 10)
    return isNaN(n) || n < 5000 || n > 15000 ? null : n
  }

  function normHex(s, len) {
    s = String(s || '').trim().toLowerCase().replace(/^0x/, '')
    return new RegExp(`^[0-9a-f]{${len}}$`).test(s) ? s : null
  }

  function computeFQDN(freq, pi, ecc) {
    const f = parseFreq(freq)
    const p = normHex(pi, 4)
    const e = normHex(ecc, 2)
    if (!f || !p || !e) return null
    return `${String(f).padStart(5, '0')}.${p}.${e}.fm.${CFG.zone}`
  }

  function updatePreview() {
    const fqdn = computeFQDN(
      $id('f-freq')?.value,
      $id('f-pi')?.value,
      $id('f-ecc')?.value,
    )
    const el = $id('id-fqdn')
    const note = $id('id-note')
    if (fqdn) {
      el.textContent = fqdn
      el.className = 'id-fqdn valid'
      if (note) note.textContent = '↑ this is how connected-radio devices will discover your station'
    } else {
      el.textContent = 'enter parameters above'
      el.className = 'id-fqdn'
      if (note) note.textContent = ''
    }
  }

  ['f-freq', 'f-pi', 'f-ecc'].forEach(id => {
    $id(id)?.addEventListener('input', updatePreview)
  })

  // ---------------------------------------------------------------------------
  // Tab switching
  // ---------------------------------------------------------------------------
  document.querySelectorAll('.tab[data-tab]').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'))
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'))
      btn.classList.add('active')
      document.querySelector(`.tab-panel[data-tab="${btn.dataset.tab}"]`)?.classList.add('active')
      if (btn.dataset.tab === 'directory') initDirectory()
    })
  })

  // ---------------------------------------------------------------------------
  // Registration form
  // ---------------------------------------------------------------------------
  $id('submit-btn')?.addEventListener('click', submitRegistration)
  $id('clear-btn')?.addEventListener('click', clearForm)

  async function submitRegistration() {
    const statusPill = $id('form-status')
    const resultEl   = $id('provision-result')

    const body = {
      callsign:      $id('f-callsign')?.value?.trim(),
      frequency:     $id('f-freq')?.value?.trim(),
      pi:            $id('f-pi')?.value?.trim(),
      ecc:           $id('f-ecc')?.value?.trim(),
      contact_email: $id('f-email')?.value?.trim(),
      service_type:  $id('f-type')?.value,
      stream_url:    $id('f-stream')?.value?.trim() || undefined,
      website_url:   $id('f-website')?.value?.trim() || undefined,
      country:       $id('f-country')?.value?.trim() || undefined,
      notes:         $id('f-notes')?.value?.trim() || undefined,
    }
    if (CFG.adminKeyRequired) body.admin_key = $id('admin-key')?.value || ''

    if (!body.callsign || !body.frequency || !body.pi || !body.ecc || !body.contact_email) {
      setPill(statusPill, 'required fields missing', 'error')
      return
    }

    setPill(statusPill, 'provisioning…', 'running')
    $id('submit-btn').disabled = true
    resultEl.classList.add('hidden')

    try {
      const resp = await fetch('/service/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const data = await resp.json()

      if (!resp.ok) {
        setPill(statusPill, 'error', 'error')
        resultEl.innerHTML = errorCard(data.error || 'Unknown error')
        resultEl.className = 'provision-result error'
        resultEl.classList.remove('hidden')
        return
      }

      setPill(statusPill, 'published ✓', 'ok')
      resultEl.innerHTML = successCard(data)
      resultEl.className = 'provision-result'
      resultEl.classList.remove('hidden')

      // Upload logo if selected
      const logoFile = $id('f-logo')?.files?.[0]
      if (logoFile && data.id) uploadLogo(data.id, logoFile)

    } catch (e) {
      setPill(statusPill, 'network error', 'error')
      resultEl.innerHTML = errorCard(e.message)
      resultEl.className = 'provision-result error'
      resultEl.classList.remove('hidden')
    } finally {
      $id('submit-btn').disabled = false
    }
  }

  async function uploadLogo(stationId, file) {
    const fd = new FormData()
    fd.append('logo', file)
    const headers = {}
    if (CFG.adminKeyRequired) headers['X-Admin-Key'] = $id('admin-key')?.value || ''
    try {
      await fetch(`/service/stations/${stationId}/logo`, { method: 'POST', headers, body: fd })
    } catch (_) {}
  }

  function successCard(d) {
    const log = d.provisioning?.log || []
    const steps = log.map(s => {
      const icon = s.ok
        ? '<span class="pr-step-icon ok-icon">✓</span>'
        : '<span class="pr-step-icon err-icon">✗</span>'
      const label = { cname: 'CNAME record created', srv: 'SRV records created', si_xml: 'SI.xml published', dns: 'DNS provisioning' }[s.step] || s.step
      const sub = s.ok
        ? (s.url ? `<div class="pr-step-sub">${esc(s.url)}</div>` : (s.record ? `<div class="pr-step-sub">${esc(s.record)}</div>` : ''))
        : `<div class="pr-step-sub" style="color:var(--err)">${esc(s.error)}</div>`
      return `<div class="pr-step">${icon}<div><div class="pr-step-text">${label}</div>${sub}</div></div>`
    }).join('')

    return `
      <div class="pr-title">✓ CONNECTED-RADIO PRESENCE CREATED</div>
      <div class="pr-fqdn-box">
        <div class="pr-fqdn-label">YOUR RADIODNS IDENTIFIER</div>
        <div class="pr-fqdn">${esc(d.fqdn)}</div>
      </div>
      <div class="pr-meta">
        <span class="pr-meta-label">Call Sign</span><span class="pr-meta-val">${esc(d.callsign)}</span>
        <span class="pr-meta-label">Managed Service</span><span class="pr-meta-val">${esc(d.svc_fqdn)}</span>
        ${d.si_url ? `<span class="pr-meta-label">SPI Metadata</span><span class="pr-meta-val"><a href="${esc(d.si_url)}" target="_blank" style="color:var(--cyan)">${esc(d.si_url)}</a></span>` : ''}
      </div>
      <div class="pr-steps">${steps}</div>
      <div class="pr-id-row">Station ID: <span>${esc(d.id)}</span> — use this to check health status</div>
    `
  }

  function errorCard(msg) {
    return `<div class="pr-title error">✗ PROVISIONING FAILED</div>
    <div style="font-family:var(--mono);font-size:0.85rem;color:var(--err)">${esc(msg)}</div>`
  }

  function clearForm() {
    ['f-callsign','f-freq','f-pi','f-ecc','f-email','f-stream','f-website','f-country','f-notes'].forEach(id => {
      const el = $id(id)
      if (el) el.value = ''
    })
    if ($id('f-logo')) $id('f-logo').value = ''
    if ($id('admin-key')) $id('admin-key').value = ''
    setPill($id('form-status'), 'idle')
    $id('provision-result')?.classList.add('hidden')
    updatePreview()
  }

  // ---------------------------------------------------------------------------
  // Directory
  // ---------------------------------------------------------------------------
  let dirLoaded = false

  async function initDirectory() {
    if (dirLoaded) return
    loadPdnsStatus()
    loadDirectory()
  }

  async function loadPdnsStatus() {
    const badge = $id('pdns-badge')
    if (!badge) return
    badge.textContent = 'checking…'
    badge.className = 'pdns-badge'
    try {
      const r = await fetch('/service/pdns-status')
      const d = await r.json()
      if (d.ok) {
        badge.textContent = `PowerDNS ✓ · ${d.rrsets} records`
        badge.className = 'pdns-badge ok'
      } else {
        badge.textContent = 'PowerDNS ✗'
        badge.className = 'pdns-badge err'
      }
    } catch (_) {
      badge.textContent = 'PowerDNS unreachable'
      badge.className = 'pdns-badge err'
    }
  }

  async function loadDirectory() {
    const el = $id('dir-content')
    if (!el) return
    el.innerHTML = '<p class="hint">loading…</p>'
    try {
      const r = await fetch('/service/stations?limit=500')
      const d = await r.json()
      const total = $id('dir-total')
      if (total) total.textContent = d.total ?? '—'
      if (!d.stations?.length) {
        el.innerHTML = '<p class="hint">No stations registered yet.</p>'
        dirLoaded = true
        return
      }
      el.innerHTML = `<div class="station-grid">${d.stations.map(stationCard).join('')}</div>`

      el.querySelectorAll('.del-btn').forEach(btn => {
        btn.addEventListener('click', e => { e.stopPropagation(); deleteStation(btn.dataset.id, btn.dataset.fqdn) })
      })
      el.querySelectorAll('.health-btn').forEach(btn => {
        btn.addEventListener('click', e => {
          e.stopPropagation()
          document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'))
          document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'))
          document.querySelector('.tab[data-tab="validate"]')?.classList.add('active')
          document.querySelector('.tab-panel[data-tab="validate"]')?.classList.add('active')
          const vId = $id('v-id')
          if (vId) { vId.value = btn.dataset.id; runHealthCheck(btn.dataset.id) }
        })
      })
      dirLoaded = true
    } catch (e) {
      el.innerHTML = `<p class="hint" style="color:var(--err)">Error: ${esc(e.message)}</p>`
    }
  }

  function stationCard(s) {
    const trust = trustLabel(s)
    return `
      <div class="station-card">
        <div class="sc-header">
          <span class="sc-callsign">${esc(s.callsign)}</span>
          <span class="sc-trust ${trust.cls}">${trust.label}</span>
        </div>
        <div class="sc-fqdn">${esc(s.fqdn)}</div>
        <div class="sc-meta">${esc(s.frequency)} MHz · ${esc(s.pi)} · ${esc(s.ecc)} · ${esc(s.service_type || 'FM')}</div>
        <div class="sc-actions">
          <button class="health-btn" data-id="${esc(s.id)}">◉ health</button>
          <button class="del-btn" data-id="${esc(s.id)}" data-fqdn="${esc(s.fqdn)}">✕ remove</button>
        </div>
      </div>
    `
  }

  function trustLabel(s) {
    if (s.dns_valid && s.srv_valid && s.si_reachable !== false) return { cls: 'verified', label: '● ON AIR' }
    if (s.dns_valid || s.srv_valid) return { cls: 'partial', label: '◑ PARTIAL' }
    if (s.last_validated) return { cls: 'degraded', label: '○ DEGRADED' }
    return { cls: 'unknown', label: '◌ PENDING' }
  }

  async function deleteStation(id, fqdn) {
    let adminKey = ''
    if (CFG.adminKeyRequired) {
      adminKey = prompt(`Admin key required to remove:\n${fqdn}`) || ''
      if (!adminKey) return
    }
    if (!confirm(`Remove station:\n${fqdn}\n\nThis will delete all DNS records.`)) return
    try {
      const resp = await fetch(`/service/stations/${id}`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json', 'X-Admin-Key': adminKey },
        body: JSON.stringify({ admin_key: adminKey }),
      })
      const data = await resp.json()
      if (resp.ok) {
        dirLoaded = false
        loadDirectory()
        const t = $id('dir-total')
        if (t) t.textContent = Math.max(0, parseInt(t.textContent || '0') - 1)
      } else {
        alert(`Failed: ${data.error}`)
      }
    } catch (e) { alert(`Error: ${e.message}`) }
  }

  $id('dir-refresh')?.addEventListener('click', () => {
    dirLoaded = false
    loadPdnsStatus()
    loadDirectory()
  })

  // ---------------------------------------------------------------------------
  // Health check tab
  // ---------------------------------------------------------------------------
  $id('v-check')?.addEventListener('click', () => {
    const id = $id('v-id')?.value?.trim()
    if (id) runHealthCheck(id)
  })

  async function runHealthCheck(id) {
    const el = $id('health-result')
    if (!el) return
    el.innerHTML = '<p class="hint">running checks…</p>'
    el.classList.remove('hidden')
    try {
      const r = await fetch(`/service/status/${encodeURIComponent(id)}`)
      const d = await r.json()
      if (!r.ok) { el.innerHTML = `<p class="hint" style="color:var(--err)">${esc(d.error)}</p>`; return }
      el.innerHTML = healthCard(d)
    } catch (e) {
      el.innerHTML = `<p class="hint" style="color:var(--err)">Error: ${esc(e.message)}</p>`
    }
  }

  function check(val, na = false) {
    if (val === null || val === undefined) return na ? '<span class="hr-check-val na">N/A</span>' : '<span class="hr-check-val na">—</span>'
    return val
      ? '<span class="hr-check-val pass">✓ PASS</span>'
      : '<span class="hr-check-val fail">✗ FAIL</span>'
  }

  function healthCard(d) {
    const h = d.health
    const trust = d.trust_score || 'unknown'
    const trustLabels = { verified: '✓ VERIFIED — fully operational', partial: '◑ PARTIAL — some checks failing', degraded: '✗ DEGRADED — service issues detected', unknown: '◌ UNKNOWN — not yet validated' }
    return `
      <div class="hr-title">◉ ${esc(d.callsign)} — HEALTH REPORT</div>
      <div class="hr-checks">
        <span class="hr-check-label">RadioDNS CNAME</span>${check(h.dns_valid)}
        <span class="hr-check-label">SRV Records</span>${check(h.srv_valid)}
        <span class="hr-check-label">SPI Metadata (SI.xml)</span>${check(h.si_reachable, true)}
        <span class="hr-check-label">Stream Endpoint</span>${check(h.stream_reachable, true)}
        <span class="hr-check-label">Last Checked</span><span class="hr-check-val" style="color:var(--muted)">${esc(h.last_validated || '—')}</span>
      </div>
      <div class="trust-banner ${trust}">${trustLabels[trust] || trust.toUpperCase()}</div>
      <div style="font-family:var(--mono);font-size:0.72rem;color:var(--muted);margin-top:0.75rem">
        FQDN: ${esc(d.fqdn)}<br>
        SI.xml: <a href="${esc(d.si_url)}" target="_blank" style="color:var(--cyan)">${esc(d.si_url)}</a>
      </div>
    `
  }

  // ---------------------------------------------------------------------------
  // Init
  // ---------------------------------------------------------------------------
  loadConfig()
})()
