/* RadioDNS Service UI */
(function () {
  "use strict";

  const ZONE = window.SVC_CONFIG?.zone || "radiodns.zerotrustradio.org";
  const ADMIN_KEY_REQUIRED = window.SVC_CONFIG?.adminKeyRequired || false;

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  function $id(id) { return document.getElementById(id); }

  function setPill(el, text, cls) {
    el.textContent = text;
    el.className = "pill " + (cls || "");
  }

  function showCard(el, html, isError) {
    el.innerHTML = html;
    el.classList.remove("hidden", "error");
    if (isError) el.classList.add("error");
  }

  function hideCard(el) {
    el.classList.add("hidden");
    el.innerHTML = "";
  }

  // Build a result card HTML string from a registration response
  function buildSuccessCard(data) {
    const recs = (data.dns_records || []).map(r => {
      const cls = r.error ? "err" : r.type.toLowerCase();
      const detail = r.error
        ? `<span style="color:var(--err)">${esc(r.error)}</span>`
        : `<span>${esc(r.name)}</span> → <span style="color:var(--ok)">${esc(r.target || r.content || "")}</span>`;
      return `<div class="rc-rec"><span class="badge ${cls}">${esc(r.type)}</span>${detail}</div>`;
    }).join("");

    const srvNote = data.has_srv && data.svc_base
      ? `<div class="rc-row"><span class="rc-label">SVC base</span><span class="rc-val">${esc(data.svc_base)}</span></div>`
      : "";

    return `
      <div class="rc-title">✓ STATION REGISTERED</div>
      <div class="rc-row"><span class="rc-label">Call sign</span><span class="rc-val highlight">${esc(data.callsign)}</span></div>
      <div class="rc-row"><span class="rc-label">RadioDNS FQDN</span><span class="rc-val highlight">${esc(data.radiodns_fqdn)}</span></div>
      <div class="rc-row"><span class="rc-label">CNAME target</span><span class="rc-val">${esc(data.cname_target)}</span></div>
      <div class="rc-row"><span class="rc-label">Freq / PI / ECC</span><span class="rc-val">${esc(data.freq5)} / ${esc(data.pi)} / ${esc(data.ecc)} (gcc: ${esc(data.gcc)})</span></div>
      ${srvNote}
      <div class="rc-records"><div style="color:var(--muted);font-size:0.78rem;margin-bottom:0.4rem">DNS RECORDS CREATED</div>${recs}</div>
    `;
  }

  function buildStationCard(row) {
    return `
      <div class="rc-title">◉ STATION FOUND</div>
      <div class="rc-row"><span class="rc-label">Call sign</span><span class="rc-val highlight">${esc(row.callsign)}</span></div>
      <div class="rc-row"><span class="rc-label">RadioDNS FQDN</span><span class="rc-val highlight">${esc(row.radiodns_fqdn)}</span></div>
      <div class="rc-row"><span class="rc-label">CNAME target</span><span class="rc-val">${esc(row.cname_target)}</span></div>
      <div class="rc-row"><span class="rc-label">Frequency</span><span class="rc-val">${esc(row.freq_mhz)} MHz</span></div>
      <div class="rc-row"><span class="rc-label">PI / ECC / GCC</span><span class="rc-val">${esc(row.pi)} / ${esc(row.ecc)} / ${esc(row.gcc)}</span></div>
      ${row.epg_host ? `<div class="rc-row"><span class="rc-label">EPG</span><span class="rc-val">${esc(row.epg_host)}:${row.epg_port}</span></div>` : ""}
      ${row.vis_host ? `<div class="rc-row"><span class="rc-label">VIS</span><span class="rc-val">${esc(row.vis_host)}:${row.vis_port}</span></div>` : ""}
      <div class="rc-row"><span class="rc-label">Registered</span><span class="rc-val">${esc(row.created_at)}</span></div>
    `;
  }

  function esc(s) {
    if (s == null) return "";
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  // ---------------------------------------------------------------------------
  // FQDN computation (mirrors server-side logic in JS)
  // ---------------------------------------------------------------------------

  function parseFreq(raw) {
    raw = (raw || "").trim().toLowerCase().replace(/mhz/g, "").trim();
    if (!raw) return null;
    if (raw.includes(".")) {
      const f = parseFloat(raw);
      if (isNaN(f)) return null;
      return Math.round(f * 100);
    }
    const n = parseInt(raw, 10);
    return isNaN(n) ? null : n;
  }

  function normPI(s) {
    s = (s || "").trim().toLowerCase();
    if (s.startsWith("0x")) s = s.slice(2);
    return /^[0-9a-f]{4}$/.test(s) ? s : null;
  }

  function normECC(s) {
    s = (s || "").trim().toLowerCase();
    if (s.startsWith("0x")) s = s.slice(2);
    return /^[0-9a-f]{2}$/.test(s) ? s : null;
  }

  function computeFQDN(freqRaw, piRaw, eccRaw) {
    const freq = parseFreq(freqRaw);
    const pi = normPI(piRaw);
    const ecc = normECC(eccRaw);
    if (freq === null || pi === null || ecc === null) return null;
    if (freq < 0 || freq > 99999) return null;
    const freq5 = String(freq).padStart(5, "0");
    const gcc = pi[0] + ecc;
    return `${freq5}.${pi}.${gcc}.fm.${ZONE}`;
  }

  // ---------------------------------------------------------------------------
  // Live FQDN preview (register tab)
  // ---------------------------------------------------------------------------

  function updateFQDNPreview() {
    const fqdn = computeFQDN(
      ($id("reg-freq") || {}).value,
      ($id("reg-pi") || {}).value,
      ($id("reg-ecc") || {}).value,
    );
    const el = $id("fqdn-value");
    if (!el) return;
    if (fqdn) {
      el.textContent = fqdn;
      el.className = "valid";
    } else {
      el.textContent = "enter frequency, PI, and ECC above";
      el.className = "";
    }

    // Update svc base preview
    const cs = ($id("reg-callsign") || {}).value || "{callsign}";
    const svcEl = $id("svc-base-preview");
    if (svcEl) svcEl.textContent = `${cs.toLowerCase()}.svc.${ZONE}`;
  }

  ["reg-freq", "reg-pi", "reg-ecc", "reg-callsign"].forEach(id => {
    const el = $id(id);
    if (el) el.addEventListener("input", updateFQDNPreview);
  });

  // ---------------------------------------------------------------------------
  // Live FQDN preview (lookup tab)
  // ---------------------------------------------------------------------------

  function updateLookupPreview() {
    const fqdn = computeFQDN(
      ($id("lu-freq") || {}).value,
      ($id("lu-pi") || {}).value,
      ($id("lu-ecc") || {}).value,
    );
    const el = $id("lu-fqdn");
    if (!el) return;
    if (fqdn) {
      el.textContent = fqdn;
      el.className = "valid";
    } else {
      el.textContent = "enter parameters above";
      el.className = "";
    }
  }

  ["lu-freq", "lu-pi", "lu-ecc"].forEach(id => {
    const el = $id(id);
    if (el) el.addEventListener("input", updateLookupPreview);
  });

  // ---------------------------------------------------------------------------
  // Register form submit
  // ---------------------------------------------------------------------------

  const regSubmit = $id("reg-submit");
  const regStatus = $id("reg-status");
  const regResult = $id("reg-result");

  if (regSubmit) {
    regSubmit.addEventListener("click", async () => {
      const body = {
        callsign:      ($id("reg-callsign") || {}).value?.trim(),
        frequency:     ($id("reg-freq") || {}).value?.trim(),
        pi:            ($id("reg-pi") || {}).value?.trim(),
        ecc:           ($id("reg-ecc") || {}).value?.trim(),
        cname_target:  ($id("reg-cname") || {}).value?.trim(),
        contact_email: ($id("reg-email") || {}).value?.trim() || undefined,
        notes:         ($id("reg-notes") || {}).value?.trim() || undefined,
        epg_host:      ($id("reg-epg-host") || {}).value?.trim() || undefined,
        epg_port:      ($id("reg-epg-port") || {}).value ? parseInt($id("reg-epg-port").value) : undefined,
        vis_host:      ($id("reg-vis-host") || {}).value?.trim() || undefined,
        vis_port:      ($id("reg-vis-port") || {}).value ? parseInt($id("reg-vis-port").value) : undefined,
      };

      if (ADMIN_KEY_REQUIRED) {
        body.admin_key = ($id("reg-admin-key") || {}).value || "";
      }

      // Client-side validation
      if (!body.callsign) { setPill(regStatus, "call sign required", "error"); return; }
      if (!body.frequency) { setPill(regStatus, "frequency required", "error"); return; }
      if (!body.pi) { setPill(regStatus, "PI required", "error"); return; }
      if (!body.ecc) { setPill(regStatus, "ECC required", "error"); return; }
      if (!body.cname_target) { setPill(regStatus, "CNAME target required", "error"); return; }

      setPill(regStatus, "registering…", "running");
      regSubmit.disabled = true;
      hideCard(regResult);

      try {
        const resp = await fetch("/service/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
        const data = await resp.json();
        if (!resp.ok) {
          setPill(regStatus, "error", "error");
          showCard(regResult, `<div class="rc-title">✗ ERROR</div><div class="rc-row"><span class="rc-label">message</span><span class="rc-val" style="color:var(--err)">${esc(data.error || "unknown error")}</span></div>`, true);
        } else {
          setPill(regStatus, "registered ✓", "ok");
          showCard(regResult, buildSuccessCard(data));
        }
      } catch (e) {
        setPill(regStatus, "network error", "error");
        showCard(regResult, `<div class="rc-title">✗ NETWORK ERROR</div><div class="rc-row"><span class="rc-val" style="color:var(--err)">${esc(e.message)}</span></div>`, true);
      } finally {
        regSubmit.disabled = false;
      }
    });
  }

  const regClear = $id("reg-clear");
  if (regClear) {
    regClear.addEventListener("click", () => {
      ["reg-callsign","reg-freq","reg-pi","reg-ecc","reg-cname","reg-email","reg-notes",
       "reg-epg-host","reg-epg-port","reg-vis-host","reg-vis-port"].forEach(id => {
        const el = $id(id);
        if (el) el.value = "";
      });
      if ($id("reg-admin-key")) $id("reg-admin-key").value = "";
      setPill(regStatus, "idle");
      hideCard(regResult);
      updateFQDNPreview();
    });
  }

  // ---------------------------------------------------------------------------
  // Directory
  // ---------------------------------------------------------------------------

  async function loadPdnsStatus() {
    const pill = $id("pdns-status-pill");
    if (!pill) return;
    pill.textContent = "checking…";
    pill.className = "pdns-status";
    try {
      const r = await fetch("/service/status");
      const d = await r.json();
      if (d.ok) {
        pill.textContent = `PowerDNS ✓ · ${d.rrset_count} records`;
        pill.className = "pdns-status ok";
      } else {
        pill.textContent = `PowerDNS ✗ · ${d.error || d.detail || "unreachable"}`;
        pill.className = "pdns-status err";
      }
    } catch (e) {
      pill.textContent = "PowerDNS unreachable";
      pill.className = "pdns-status err";
    }
  }

  async function loadDirectory() {
    const wrap = $id("dir-table-wrap");
    const totalEl = $id("dir-total");
    if (!wrap) return;
    wrap.innerHTML = '<p class="hint">loading…</p>';
    try {
      const r = await fetch("/service/stations?limit=500");
      const d = await r.json();
      if (totalEl) totalEl.textContent = d.total ?? "—";
      if (!d.stations || d.stations.length === 0) {
        wrap.innerHTML = '<p class="hint">No stations registered yet.</p>';
        return;
      }
      const rows = d.stations.map(s => `
        <tr>
          <td class="callsign-cell">${esc(s.callsign)}</td>
          <td>${esc(s.freq_mhz)} MHz</td>
          <td>${esc(s.pi)} / ${esc(s.ecc)}</td>
          <td class="fqdn-cell">${esc(s.radiodns_fqdn)}</td>
          <td>${esc(s.cname_target)}</td>
          <td>${s.has_srv ? "✓" : "—"}</td>
          <td>${esc((s.created_at || "").slice(0, 10))}</td>
          <td><button class="del-btn" data-id="${s.id}" data-fqdn="${esc(s.radiodns_fqdn)}">✕</button></td>
        </tr>
      `).join("");
      wrap.innerHTML = `
        <table class="dir-table">
          <thead>
            <tr>
              <th>CALL SIGN</th><th>FREQ</th><th>PI / ECC</th>
              <th>RADIODNS FQDN</th><th>CNAME TARGET</th>
              <th>SRV</th><th>DATE</th><th></th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      `;

      // Wire up delete buttons
      wrap.querySelectorAll(".del-btn").forEach(btn => {
        btn.addEventListener("click", async () => {
          const id = btn.dataset.id;
          const fqdn = btn.dataset.fqdn;
          let adminKey = "";
          if (ADMIN_KEY_REQUIRED) {
            adminKey = prompt(`Admin key required to delete:\n${fqdn}`) || "";
            if (!adminKey) return;
          }
          if (!confirm(`Delete registration for:\n${fqdn}\n\nThis will also remove the DNS record.`)) return;
          btn.disabled = true;
          btn.textContent = "…";
          try {
            const resp = await fetch(`/service/stations/${id}`, {
              method: "DELETE",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ admin_key: adminKey }),
            });
            const data = await resp.json();
            if (resp.ok) {
              btn.closest("tr").remove();
              const total = $id("dir-total");
              if (total) total.textContent = parseInt(total.textContent || "0") - 1;
            } else {
              alert(`Delete failed: ${data.error || "unknown error"}`);
              btn.disabled = false;
              btn.textContent = "✕";
            }
          } catch (e) {
            alert(`Network error: ${e.message}`);
            btn.disabled = false;
            btn.textContent = "✕";
          }
        });
      });
    } catch (e) {
      wrap.innerHTML = `<p class="hint" style="color:var(--err)">Failed to load: ${esc(e.message)}</p>`;
    }
  }

  const dirRefresh = $id("dir-refresh");
  if (dirRefresh) {
    dirRefresh.addEventListener("click", () => {
      loadPdnsStatus();
      loadDirectory();
    });
  }

  // ---------------------------------------------------------------------------
  // Lookup
  // ---------------------------------------------------------------------------

  const luLookup = $id("lu-lookup");
  const luResult = $id("lu-result");

  if (luLookup) {
    luLookup.addEventListener("click", async () => {
      const fqdn = computeFQDN(
        ($id("lu-freq") || {}).value,
        ($id("lu-pi") || {}).value,
        ($id("lu-ecc") || {}).value,
      );
      if (!fqdn) {
        hideCard(luResult);
        return;
      }
      hideCard(luResult);
      luLookup.disabled = true;
      try {
        const r = await fetch("/service/stations?limit=500");
        const d = await r.json();
        const match = (d.stations || []).find(s => s.radiodns_fqdn === fqdn);
        if (match) {
          showCard(luResult, buildStationCard(match));
        } else {
          showCard(luResult, `
            <div class="rc-title" style="color:var(--warn)">◌ NOT REGISTERED</div>
            <div class="rc-row"><span class="rc-label">FQDN</span><span class="rc-val">${esc(fqdn)}</span></div>
            <div class="rc-row"><span class="rc-val" style="color:var(--muted)">This FQDN is not registered with this service.</span></div>
          `);
        }
      } catch (e) {
        showCard(luResult, `<div class="rc-title">✗ ERROR</div><div class="rc-row"><span class="rc-val" style="color:var(--err)">${esc(e.message)}</span></div>`, true);
      } finally {
        luLookup.disabled = false;
      }
    });
  }

  // ---------------------------------------------------------------------------
  // Tab switching (reuse same logic pattern)
  // The app.js already handles tabs globally via data-tab attrs, so we
  // just need to load the directory status when that tab becomes active.
  // ---------------------------------------------------------------------------

  document.addEventListener("click", e => {
    const tab = e.target.closest("[data-tab]");
    if (tab && tab.classList.contains("tab") && tab.dataset.tab === "directory") {
      loadPdnsStatus();
      if (!$id("dir-table-wrap").querySelector("table")) {
        loadDirectory();
      }
    }
  });

})();
