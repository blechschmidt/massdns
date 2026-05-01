(() => {
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => root.querySelectorAll(sel);

  // -------------------- tabs --------------------
  $$("#tabs .tab").forEach((t) => {
    t.addEventListener("click", () => {
      $$("#tabs .tab").forEach((b) => b.classList.remove("active"));
      t.classList.add("active");
      const name = t.dataset.tab;
      $$(".tab-panel").forEach((p) => p.classList.toggle("active", p.dataset.tab === name));
      if (name === "db") refreshSummary();
    });
  });

  // -------------------- helpers --------------------
  function val(id) { return ($("#" + id) || {}).value || ""; }
  function num(v) {
    if (v === "" || v == null) return null;
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
  }
  function lines(v) {
    return (v || "").split("\n").map((s) => s.trim()).filter(Boolean);
  }

  function setStat(step, label, state = "") {
    const el = document.querySelector(`[data-stat="${step}"]`);
    if (!el) return;
    el.textContent = label;
    el.className = "step-stat " + (state || "");
  }
  function appendOut(step, text) {
    const el = document.querySelector(`[data-out="${step}"]`);
    if (!el) return;
    el.textContent += text;
    el.scrollTop = el.scrollHeight;
  }
  function clearOut(step) {
    const el = document.querySelector(`[data-out="${step}"]`);
    if (el) el.textContent = "";
  }

  // -------------------- step runners --------------------
  const controllers = new Map(); // step -> AbortController

  async function runStreaming(step, url, body) {
    if (controllers.get(step)) controllers.get(step).abort();
    clearOut(step);
    setStat(step, "running…", "running");
    const ctl = new AbortController();
    controllers.set(step, ctl);
    let res;
    try {
      res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body || {}),
        signal: ctl.signal,
      });
    } catch (e) {
      setStat(step, "error: " + e.message, "error");
      controllers.delete(step);
      return;
    }
    if (!res.ok) {
      const t = await res.text().catch(() => "");
      appendOut(step, `[HTTP ${res.status}] ${t}\n`);
      setStat(step, `HTTP ${res.status}`, "error");
      controllers.delete(step);
      return;
    }
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    let parsed = 0, hits = 0;
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        let nl;
        while ((nl = buf.indexOf("\n")) >= 0) {
          const line = buf.slice(0, nl);
          buf = buf.slice(nl + 1);
          if (!line.trim()) continue;
          let rec; try { rec = JSON.parse(line); } catch { appendOut(step, line + "\n"); continue; }
          if (rec.event === "log") {
            appendOut(step, "· " + rec.message + "\n");
          } else if (rec.event === "progress") {
            parsed = rec.parsed ?? rec.count ?? parsed;
            hits = rec.hits ?? hits;
            setStat(step, `running… parsed=${parsed} hits=${hits}`, "running");
          } else if (rec.event === "item") {
            hits++;
            appendOut(step, formatItem(rec) + "\n");
            setStat(step, `running… hits=${hits}`, "running");
          } else if (rec.event === "done") {
            const summary = Object.entries(rec).filter(([k]) => k !== "event").map(([k,v]) => `${k}=${v}`).join(" ");
            appendOut(step, "✓ done · " + summary + "\n");
            setStat(step, "done · " + summary, "ok");
          } else if (rec.event === "error") {
            appendOut(step, "✗ " + rec.message + "\n");
            setStat(step, "error: " + rec.message, "error");
          }
        }
      }
      if (controllers.get(step) === ctl) {
        // stream ended without explicit done event
        if (!document.querySelector(`[data-stat="${step}"]`).className.includes("ok")) {
          setStat(step, "stream closed", "ok");
        }
      }
    } catch (e) {
      if (e.name === "AbortError") {
        setStat(step, "stopped", "");
      } else {
        setStat(step, "stream error: " + e.message, "error");
      }
    } finally {
      controllers.delete(step);
    }
  }

  function formatItem(rec) {
    if (rec.kind === "cname")
      return `[CNAME] ${rec.queried} → ${rec.broadcaster}`;
    if (rec.kind === "srv")
      return `[SRV]   ${rec.service_domain} → ${rec.target}:${rec.port} (p=${rec.priority} w=${rec.weight})`;
    if (rec.kind === "si") {
      if (rec.ok) return `[SI]    ${rec.target}  ok ${rec.bytes}B sha=${rec.sha256}`;
      return `[SI]    ${rec.target}  FAIL status=${rec.status ?? "-"} ${rec.error || ""}`;
    }
    if (rec.domain) return rec.domain;
    return JSON.stringify(rec);
  }

  async function runJson(step, url, body) {
    clearOut(step);
    setStat(step, "running…", "running");
    let res;
    try {
      res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body || {}),
      });
    } catch (e) {
      setStat(step, "error: " + e.message, "error");
      return;
    }
    const text = await res.text();
    let data; try { data = JSON.parse(text); } catch { data = text; }
    if (!res.ok) {
      appendOut(step, "[HTTP " + res.status + "] " + text + "\n");
      setStat(step, "error", "error");
      return;
    }
    setStat(step, "ok", "ok");
    appendOut(step, JSON.stringify(data, null, 2) + "\n");
  }

  // -------------------- step bindings --------------------
  $$("button[data-step]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const step = btn.dataset.step;
      switch (step) {
        case "generate":
          await runStreaming(step, "/rdns/generate", {
            ecc: val("g-ecc"),
            pi_start: val("g-pi-start"), pi_end: val("g-pi-end"),
            freq_start: num(val("g-freq-start")),
            freq_end: num(val("g-freq-end")),
            freq_step: num(val("g-freq-step")),
            limit: num(val("g-limit")),
          }); break;
        case "scan-cname":
          await runStreaming(step, "/rdns/scan-cname", {
            rate: num(val("sc-rate")),
            domains: lines(val("sc-domains")) || undefined,
          }); break;
        case "extract-broadcasters":
          await runJson(step, "/rdns/extract-broadcasters", {}); break;
        case "generate-srv":
          await runJson(step, "/rdns/generate-srv", {
            services: val("gs-services").split(",").map((s) => s.trim()).filter(Boolean),
          }); break;
        case "scan-srv":
          await runStreaming(step, "/rdns/scan-srv", {
            rate: num(val("ss-rate")),
            services: val("ss-services").split(",").map((s) => s.trim()).filter(Boolean),
          }); break;
        case "fetch-si":
          await runStreaming(step, "/rdns/fetch-si", {
            timeout: num(val("fs-timeout")),
            http_only: val("fs-http-only") === "true",
          }); break;
        case "parse-si":
          await runJson(step, "/rdns/parse-si", {}); break;
        case "expand-hits":
          await runJson(step, "/rdns/expand-hits", {
            window: num(val("x-window")),
            freq_window: num(val("x-freq-window")),
            freq_step: num(val("x-freq-step")),
            persist: val("x-persist") === "true",
          }); break;
      }
    });
  });

  $$("button[data-stop]").forEach((b) => {
    b.addEventListener("click", () => {
      const details = b.closest("details");
      if (!details) return;
      const stat = details.querySelector("[data-stat]");
      if (!stat) return;
      const step = stat.dataset.stat;
      const ctl = controllers.get(step);
      if (ctl) ctl.abort();
    });
  });

  // -------------------- DB inspector --------------------
  async function refreshSummary() {
    const target = $("#db-summary");
    if (!target) return;
    target.textContent = "loading…";
    try {
      const r = await fetch("/rdns/db/summary");
      const data = await r.json();
      target.innerHTML = "";
      const dbPath = document.createElement("div");
      dbPath.className = "db-path";
      dbPath.textContent = "db: " + data.db;
      target.appendChild(dbPath);
      const grid = document.createElement("div");
      grid.className = "db-counts";
      Object.entries(data.counts).forEach(([k, v]) => {
        const card = document.createElement("div");
        card.className = "count-card";
        card.innerHTML = `<b>${v.toLocaleString()}</b><span>${k}</span>`;
        grid.appendChild(card);
      });
      target.appendChild(grid);
    } catch (e) {
      target.textContent = "failed: " + e.message;
    }
    // also refresh currently active table
    const active = $("#db-table-tabs .db-tab.active");
    if (active) loadTable(active.dataset.table);
  }

  async function loadTable(table) {
    const view = $("#db-table-view");
    view.textContent = "loading " + table + "…";
    try {
      const r = await fetch(`/rdns/db/${table}?limit=200`);
      const data = await r.json();
      if (!r.ok) { view.textContent = data.error || ("HTTP " + r.status); return; }
      view.innerHTML = "";
      const meta = document.createElement("div");
      meta.className = "db-meta";
      meta.textContent = `${data.total.toLocaleString()} rows total · showing ${data.rows.length}`;
      view.appendChild(meta);
      if (!data.rows.length) {
        const e = document.createElement("div");
        e.className = "empty-hint";
        e.textContent = "(empty)";
        view.appendChild(e);
        return;
      }
      const cols = Object.keys(data.rows[0]);
      const tbl = document.createElement("table");
      tbl.className = "db-table";
      const thead = document.createElement("thead");
      const trh = document.createElement("tr");
      cols.forEach((c) => {
        const th = document.createElement("th");
        th.textContent = c; trh.appendChild(th);
      });
      thead.appendChild(trh); tbl.appendChild(thead);
      const tbody = document.createElement("tbody");
      data.rows.forEach((row) => {
        const tr = document.createElement("tr");
        cols.forEach((c) => {
          const td = document.createElement("td");
          let v = row[c];
          if (v == null) { td.textContent = ""; td.className = "null"; }
          else if (typeof v === "string" && v.length > 200) { td.textContent = v.slice(0, 200) + "…"; }
          else td.textContent = String(v);
          tr.appendChild(td);
        });
        tbody.appendChild(tr);
      });
      tbl.appendChild(tbody); view.appendChild(tbl);
    } catch (e) {
      view.textContent = "failed: " + e.message;
    }
  }

  $$("#db-table-tabs .db-tab").forEach((b) => {
    b.addEventListener("click", () => {
      $$("#db-table-tabs .db-tab").forEach((x) => x.classList.remove("active"));
      b.classList.add("active");
      loadTable(b.dataset.table);
    });
  });

  $("#db-refresh")?.addEventListener("click", refreshSummary);
  $("#db-reset")?.addEventListener("click", async () => {
    if (!confirm("Drop and reinitialise the entire RadioDNS database?")) return;
    const r = await fetch("/rdns/db/reset", { method: "POST" });
    if (r.ok) refreshSummary(); else alert("reset failed: " + r.status);
  });
})();
