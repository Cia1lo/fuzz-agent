(() => {
  const page = document.querySelector(".campaign-page");
  if (!page) return;

  const cid = page.dataset.campaignId;
  const eventList = document.getElementById("event-stream");
  const crashTable = document.getElementById("crash-table");
  const stopButton = document.getElementById("stop-campaign");
  const stopResult = document.getElementById("stop-result");

  function text(value, fallback = "") {
    if (value === undefined || value === null || value === "") return fallback;
    return String(value);
  }

  function element(tag, options = {}) {
    const node = document.createElement(tag);
    if (options.className) node.className = options.className;
    if (options.text !== undefined) node.textContent = String(options.text);
    if (options.attrs) {
      Object.entries(options.attrs).forEach(([key, value]) => {
        if (value !== undefined && value !== null) node.setAttribute(key, String(value));
      });
    }
    return node;
  }

  function setText(id, value, fallback = "0") {
    const node = document.getElementById(id);
    if (node) node.textContent = text(value, fallback);
  }

  function setStatus(value) {
    const node = document.getElementById("status");
    if (!node) return;
    const status = text(value, "pending");
    node.textContent = status;
    node.className = `status-badge status-${status}`;
  }

  function firstVulnerability(crash) {
    const match = (crash.vulnerability_matches || [])[0];
    if (!match) return "";
    return `${text(match.cwe, match.rule_id)} ${text(match.title)}`.trim();
  }

  async function refreshStats() {
    const response = await fetch(`/api/campaigns/${cid}/stats`, {
      headers: {"accept": "application/json"},
    });
    if (!response.ok) return;
    const data = await response.json();
    setStatus(data.status);
    setText("elapsed", data.elapsed_sec);
    setText("execs_per_sec", data.execs_per_sec);
    setText("execs_total", data.execs_total);
    setText("edges_covered", data.edges_covered);
    setText("corpus_size", data.corpus_size);
    setText("unique_crashes", data.unique_crashes);
    setText(
      "last_new_coverage_sec_ago",
      data.last_new_coverage_sec_ago === null ? "n/a" : data.last_new_coverage_sec_ago,
      "n/a",
    );
  }

  async function refreshCrashes() {
    if (!crashTable) return;
    const response = await fetch(`/api/campaigns/${cid}/crashes`, {
      headers: {"accept": "application/json"},
    });
    if (!response.ok) return;
    renderCrashes(await response.json());
  }

  function renderCrashes(crashes) {
    crashTable.replaceChildren();
    if (!crashes.length) {
      const row = element("tr");
      row.appendChild(element("td", {
        className: "muted",
        text: "No crashes.",
        attrs: {colspan: 5},
      }));
      crashTable.appendChild(row);
      return;
    }

    crashes.forEach((crash) => {
      const row = element("tr");
      const idCell = element("td");
      const button = element("button", {
        className: "link-button crash-detail-toggle",
        text: crash.crash_id,
        attrs: {type: "button", "data-crash-id": crash.crash_id},
      });
      idCell.appendChild(button);
      const severity = text(crash.severity, "none");
      const severityCell = element("td");
      severityCell.appendChild(element("span", {
        className: `severity-badge severity-${severity}`,
        text: severity,
      }));
      row.append(
        idCell,
        severityCell,
        element("td", {text: firstVulnerability(crash)}),
        element("td", {text: text(crash.sanitizer_kind)}),
        element("td", {text: text(crash.status)}),
      );
      crashTable.appendChild(row);
    });
  }

  async function toggleCrashDetail(button) {
    const row = button.closest("tr");
    const crashId = button.dataset.crashId;
    if (!row || !crashId) return;
    const next = row.nextElementSibling;
    if (next && next.classList.contains("crash-detail-row")) {
      next.remove();
      return;
    }
    const response = await fetch(`/api/campaigns/${cid}/crashes/${encodeURIComponent(crashId)}`, {
      headers: {"accept": "application/json"},
    });
    if (!response.ok) return;
    row.after(crashDetailRow(await response.json()));
  }

  function crashDetailRow(crash) {
    const row = element("tr", {className: "crash-detail-row"});
    const cell = element("td", {attrs: {colspan: 5}});
    const panel = element("div", {className: "crash-detail"});
    panel.append(
      detailItem("Input", crash.input_path),
      detailItem("Minimized", crash.minimized_path || "none"),
      detailItem("Reproduce", crash.reproducible === null ? "unknown" : crash.reproducible),
      detailItem("Stack hash", crash.stack_hash),
    );
    const frames = element("ol", {className: "frame-list"});
    (crash.top_frames || []).slice(0, 8).forEach((frame) => {
      frames.appendChild(element("li", {text: frame}));
    });
    if (frames.childElementCount) {
      const frameBlock = element("div", {className: "detail-item detail-frames"});
      frameBlock.append(element("span", {text: "Top frames"}), frames);
      panel.appendChild(frameBlock);
    }
    cell.appendChild(panel);
    row.appendChild(cell);
    return row;
  }

  function detailItem(label, value) {
    const item = element("div", {className: "detail-item"});
    item.append(element("span", {text: label}), element("strong", {text: text(value, "none")}));
    return item;
  }

  function addEvent(name, event) {
    if (!eventList) return;
    const data = JSON.parse(event.data);
    const kind = data.kind || name;
    const item = element("li", {
      className: name === "replay" ? "replay" : kind,
      text: `[${text(data.ts)}] ${kind} ${JSON.stringify(data.payload || {})}`,
    });
    eventList.prepend(item);
    const latest = document.getElementById("latest-event-kind");
    if (latest && name !== "replay") latest.textContent = kind;
    while (eventList.children.length > 200) eventList.lastElementChild.remove();
    if (["new_coverage", "heartbeat"].includes(kind)) refreshStats();
    if (kind === "new_crash") {
      refreshStats();
      refreshCrashes();
    }
  }

  if (window.EventSource && cid) {
    const source = new EventSource(`/api/campaigns/${cid}/events`);
    ["replay", "new_coverage", "new_crash", "plateau", "oom", "timeout", "engine_error", "heartbeat"]
      .forEach((kind) => source.addEventListener(kind, (event) => addEvent(kind, event)));
  }

  if (crashTable) {
    crashTable.addEventListener("click", (event) => {
      const button = event.target.closest(".crash-detail-toggle");
      if (button) toggleCrashDetail(button);
    });
  }

  if (stopButton) {
    stopButton.addEventListener("click", async () => {
      stopButton.disabled = true;
      if (stopResult) stopResult.textContent = "Stopping campaign...";
      try {
        const response = await fetch(stopButton.dataset.stopUrl, {method: "POST"});
        if (!response.ok) throw new Error(response.statusText);
        if (stopResult) stopResult.textContent = "Stop requested.";
        await refreshStats();
      } catch (error) {
        if (stopResult) stopResult.textContent = `Failed: ${error.message || error}`;
      } finally {
        stopButton.disabled = false;
      }
    });
  }

  refreshStats();
  refreshCrashes();
  setInterval(refreshStats, 2000);
  setInterval(refreshCrashes, 5000);
})();
