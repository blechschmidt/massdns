(() => {
  const $ = (sel) => document.querySelector(sel);
  const domains = $("#domains");
  const typeSel = $("#type");
  const runBtn = $("#run");
  const stopBtn = $("#stop");
  const clearBtn = $("#clear");
  const statusPill = $("#status-pill");
  const countEl = $("#count");
  const elapsedEl = $("#elapsed");
  const pretty = $("#pretty");
  const raw = $("#raw");
  const toggles = document.querySelectorAll(".view-toggle button");

  let controller = null;
  let startedAt = 0;
  let timerId = null;
  let count = 0;

  function setStatus(state, label) {
    statusPill.className = "pill " + state;
    statusPill.textContent = label;
  }

  function tickTimer() {
    const sec = (performance.now() - startedAt) / 1000;
    elapsedEl.textContent = sec.toFixed(1) + "s";
  }

  function startTimer() {
    startedAt = performance.now();
    elapsedEl.textContent = "0.0s";
    timerId = setInterval(tickTimer, 100);
  }

  function stopTimer() {
    if (timerId) clearInterval(timerId);
    timerId = null;
    tickTimer();
  }

  function showEmpty(msg) {
    pretty.innerHTML = `<div class="empty-hint">${msg}</div>`;
    raw.textContent = "";
  }

  function appendRaw(line) {
    raw.appendChild(document.createTextNode(line + "\n"));
    raw.scrollTop = raw.scrollHeight;
  }

  function appendPretty(rec) {
    if (count === 1) pretty.innerHTML = "";
    const card = document.createElement("div");
    card.className = "row-card";

    const q = (rec.name || (rec.query && rec.query.name) || "?").replace(/\.$/, "");
    const qtype = rec.type || (rec.query && rec.query.type) || "";
    const status = rec.status || rec.rcode || (rec.error ? "ERROR" : "");

    const left = document.createElement("div");
    left.className = "qname";
    left.innerHTML = `${escapeHtml(q)} <span class="qtype">${escapeHtml(qtype)}</span>`;

    const right = document.createElement("div");
    right.className = "status " + escapeHtml(status);
    right.textContent = status || "";

    card.appendChild(left);
    card.appendChild(right);

    const answers = collectAnswers(rec);
    if (answers.length) {
      const wrap = document.createElement("div");
      wrap.className = "answers";
      for (const a of answers) {
        const row = document.createElement("div");
        row.className = "ans";
        row.innerHTML = `<span class="typ">${escapeHtml(a.type || "")}</span><span class="data">${escapeHtml(a.data || "")}</span>`;
        wrap.appendChild(row);
      }
      card.appendChild(wrap);
    } else if (rec.error) {
      const wrap = document.createElement("div");
      wrap.className = "answers";
      wrap.textContent = String(rec.error);
      card.appendChild(wrap);
    }

    pretty.appendChild(card);
    pretty.scrollTop = pretty.scrollHeight;
  }

  function collectAnswers(rec) {
    const out = [];
    const sources = [];
    if (rec.data && rec.data.answers) sources.push(rec.data.answers);
    if (Array.isArray(rec.answers)) sources.push(rec.answers);
    if (Array.isArray(rec.resp)) sources.push(rec.resp);
    for (const arr of sources) {
      for (const a of arr) {
        out.push({
          type: a.type || a.rrtype || "",
          data: a.data || a.value || a.rdata || "",
        });
      }
    }
    return out;
  }

  function escapeHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function showError(msg) {
    let banner = document.querySelector(".error-banner");
    if (!banner) {
      banner = document.createElement("div");
      banner.className = "error-banner";
      pretty.parentNode.insertBefore(banner, pretty);
    }
    banner.textContent = msg;
  }

  function clearError() {
    const banner = document.querySelector(".error-banner");
    if (banner) banner.remove();
  }

  toggles.forEach((btn) => {
    btn.addEventListener("click", () => {
      toggles.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      const view = btn.dataset.view;
      pretty.classList.toggle("active", view === "pretty");
      raw.classList.toggle("active", view === "raw");
    });
  });

  clearBtn.addEventListener("click", () => {
    showEmpty("No results yet. Submit some domains to begin.");
    count = 0;
    countEl.textContent = "0";
    elapsedEl.textContent = "0.0s";
    setStatus("", "idle");
    clearError();
  });

  stopBtn.addEventListener("click", () => {
    if (controller) controller.abort();
  });

  runBtn.addEventListener("click", async () => {
    clearError();
    const lines = domains.value
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);
    if (!lines.length) {
      showError("Add at least one domain.");
      return;
    }

    count = 0;
    countEl.textContent = "0";
    pretty.innerHTML = "";
    raw.textContent = "";
    setStatus("running", "running");
    runBtn.disabled = true;
    stopBtn.disabled = false;
    startTimer();

    controller = new AbortController();
    let res;
    try {
      res = await fetch("/resolve", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ domains: lines, type: typeSel.value }),
        signal: controller.signal,
      });
    } catch (e) {
      finish("error", "request failed: " + e.message);
      return;
    }

    if (!res.ok) {
      const text = await res.text().catch(() => "");
      finish("error", `HTTP ${res.status}: ${text || res.statusText}`);
      return;
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";

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
          handleLine(line);
        }
      }
      if (buf.trim()) handleLine(buf);
      finish("done", "done");
    } catch (e) {
      if (e.name === "AbortError") {
        finish("", "stopped");
      } else {
        finish("error", "stream error: " + e.message);
      }
    }
  });

  function handleLine(line) {
    appendRaw(line);
    count++;
    countEl.textContent = String(count);
    let rec;
    try { rec = JSON.parse(line); } catch { return; }
    appendPretty(rec);
  }

  function finish(state, label) {
    stopTimer();
    runBtn.disabled = false;
    stopBtn.disabled = true;
    if (state === "error") showError(label);
    setStatus(state, label || "idle");
    controller = null;
    if (count === 0 && state !== "error") {
      showEmpty("No results returned.");
    }
  }

  showEmpty("No results yet. Submit some domains to begin.");
  setStatus("", "idle");
})();
