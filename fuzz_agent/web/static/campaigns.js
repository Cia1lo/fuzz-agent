(() => {
  const form = document.getElementById("campaign-form");
  const flash = document.getElementById("flash");
  const table = document.getElementById("campaign-table");
  const body = document.getElementById("campaign-table-body");
  const refreshState = document.getElementById("campaign-refresh-state");

  if (!table || !body) return;

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

  function formatDuration(value) {
    const seconds = Number(value || 0);
    if (!Number.isFinite(seconds)) return "0s";
    if (seconds < 90) return `${Math.floor(seconds)}s`;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 90) return `${minutes}m`;
    const hours = Math.floor(minutes / 60);
    return `${hours}h ${minutes % 60}m`;
  }

  function renderCampaigns(campaigns) {
    body.replaceChildren();
    if (!campaigns.length) {
      const row = element("tr");
      row.appendChild(element("td", {
        className: "muted",
        text: "No campaigns yet.",
        attrs: {colspan: 8},
      }));
      body.appendChild(row);
      return;
    }

    campaigns.forEach((campaign) => {
      const stats = campaign.stats || {};
      const latest = campaign.latest_event || {};
      const row = element("tr");

      const campaignCell = element("td");
      campaignCell.append(
        element("a", {
          className: "campaign-link",
          text: campaign.cid,
          attrs: {href: `/campaigns/${campaign.cid}`},
        }),
      );
      if (campaign.artifact_name) {
        campaignCell.appendChild(element("span", {text: campaign.artifact_name}));
      }

      const crashSeverity = campaign.highest_severity || "none";
      const crashCell = element("td");
      crashCell.appendChild(element("span", {
        className: `severity-badge severity-${crashSeverity}`,
        text: text(stats.unique_crashes, campaign.crash_count || 0),
      }));

      row.append(
        campaignCell,
        cellWithBadge(`status-badge status-${campaign.status}`, campaign.status),
        element("td", {text: text(campaign.engine, "unknown")}),
        element("td", {
          text: `${formatDuration(stats.elapsed_sec)} / ${formatDuration(campaign.time_budget_sec)}`,
        }),
        element("td", {text: `${text(stats.execs_per_sec, 0)}/s`}),
        element("td", {text: text(stats.edges_covered, 0)}),
        crashCell,
        element("td", {text: text(latest.kind, "none")}),
      );
      body.appendChild(row);
    });
  }

  function cellWithBadge(className, value) {
    const cell = element("td");
    cell.appendChild(element("span", {className, text: text(value, "unknown")}));
    return cell;
  }

  async function refreshCampaigns() {
    try {
      const response = await fetch(table.dataset.refreshUrl || "/api/campaigns", {
        headers: {"accept": "application/json"},
      });
      if (!response.ok) throw new Error(response.statusText);
      renderCampaigns(await response.json());
      if (refreshState) refreshState.textContent = "live";
    } catch (error) {
      if (refreshState) refreshState.textContent = `stale: ${error.message || error}`;
    }
  }

  if (form) {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const button = form.querySelector("button[type='submit']");
      if (button) button.disabled = true;
      if (flash) flash.textContent = "Starting campaign...";
      try {
        const response = await fetch(form.action, {
          method: "POST",
          body: new FormData(form),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || response.statusText);
        if (flash) {
          flash.replaceChildren(
            document.createTextNode("Started "),
            element("a", {text: data.campaign_id, attrs: {href: `/campaigns/${data.campaign_id}`}}),
          );
        }
        await refreshCampaigns();
      } catch (error) {
        if (flash) flash.textContent = `Failed: ${error.message || error}`;
      } finally {
        if (button) button.disabled = false;
      }
    });
  }

  setInterval(refreshCampaigns, 5000);
})();
