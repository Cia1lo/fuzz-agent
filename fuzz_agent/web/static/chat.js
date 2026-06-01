(() => {
  const params = new URLSearchParams(window.location.search);
  const initialCampaignId = params.get("campaign_id") || "";
  const querySessionId = params.get("session_id") || "";
  let currentCampaignId = initialCampaignId;
  let currentSessionId = querySessionId
    || (initialCampaignId ? newSessionId() : localStorage.getItem("fuzz-agent-chat-session"))
    || newSessionId();

  const log = document.getElementById("chat-log");
  const form = document.getElementById("chat-form");
  const input = document.getElementById("chat-input");
  const submit = document.getElementById("chat-submit");
  const context = document.getElementById("chat-context");
  const sessionShort = document.getElementById("session-short");
  const sessionList = document.getElementById("session-list");
  const newSessionButton = document.getElementById("new-session");
  const commandHints = document.getElementById("command-hints");

  if (!log || !form || !input || !submit || !context || !sessionShort || !sessionList) {
    return;
  }

  const commandChoices = [
    {value: "/status", label: "status", description: "current campaign status"},
    {value: "/trace", label: "trace", description: "recent agent decisions"},
    {value: "/triage", label: "triage", description: "crash triage summary"},
    {value: "/help", label: "help", description: "available commands"},
    {value: "/analyze ", label: "analyze", description: "inspect a target path"},
    {value: "/run ", label: "run", description: "start a fuzz campaign"},
  ];
  const sentMessages = [];
  let recallIndex = null;

  function newSessionId() {
    return (window.crypto && crypto.randomUUID)
      ? crypto.randomUUID()
      : `web-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  }

  function element(tag, options = {}) {
    const node = document.createElement(tag);
    if (options.className) node.className = options.className;
    if (options.id) node.id = options.id;
    if (options.text !== undefined) node.textContent = String(options.text);
    if (options.attrs) {
      Object.entries(options.attrs).forEach(([key, value]) => {
        if (value !== undefined && value !== null) node.setAttribute(key, String(value));
      });
    }
    return node;
  }

  function setCurrentSession(sessionId, campaignId) {
    currentSessionId = sessionId;
    currentCampaignId = campaignId || "";
    localStorage.setItem("fuzz-agent-chat-session", currentSessionId);
    sessionShort.textContent = currentSessionId.slice(0, 8);
    context.replaceChildren();
    const label = element("span", {text: currentCampaignId ? "campaign" : "scope"});
    const value = currentCampaignId
      ? element("a", {text: currentCampaignId, attrs: {href: `/campaigns/${currentCampaignId}`}})
      : element("strong", {text: "global"});
    context.append(label, value);
  }

  function showEmpty() {
    log.replaceChildren();
    const empty = element("div", {className: "chat-empty", id: "chat-empty"});
    empty.append(
      element("span", {text: "ready"}),
      element("strong", {text: "agent command channel"}),
    );
    log.appendChild(empty);
  }

  function addMessage(role, text) {
    const empty = document.getElementById("chat-empty");
    if (empty) empty.remove();
    const row = element("div", {className: `chat-row ${role}`});
    const bubble = element("div", {className: "chat-bubble"});
    bubble.appendChild(element("span", {
      className: "chat-role",
      text: role === "user" ? "you" : "agent",
    }));
    const body = element("div", {className: "chat-text"});
    renderMessageText(body, text || "");
    bubble.appendChild(body);
    if (role !== "user") bubble.appendChild(messageActions(text || ""));
    row.appendChild(bubble);
    log.appendChild(row);
    log.scrollTop = log.scrollHeight;
  }

  function renderMessageText(target, text) {
    target.replaceChildren();
    const fencePattern = /```(?:([A-Za-z0-9_-]+)\n)?([\s\S]*?)```/g;
    let index = 0;
    let match;
    while ((match = fencePattern.exec(text)) !== null) {
      appendMarkdownBlocks(target, text.slice(index, match.index));
      const pre = element("pre");
      const code = element("code", {text: match[2].trimEnd()});
      if (match[1]) code.dataset.language = match[1];
      pre.appendChild(code);
      target.appendChild(pre);
      index = fencePattern.lastIndex;
    }
    appendMarkdownBlocks(target, text.slice(index));
  }

  function appendMarkdownBlocks(target, text) {
    if (!text) return;
    const lines = text.replace(/\r\n/g, "\n").split("\n");
    const paragraph = [];
    let list = null;

    function flushParagraph() {
      const content = paragraph.join("\n").trim();
      paragraph.length = 0;
      if (!content) return;
      const block = element("p", {className: "chat-paragraph"});
      appendInlineMarkdown(block, content);
      target.appendChild(block);
    }

    function flushList() {
      if (list) target.appendChild(list);
      list = null;
    }

    lines.forEach((line) => {
      const trimmed = line.trim();
      if (!trimmed) {
        flushParagraph();
        flushList();
        return;
      }
      const heading = /^(#{1,4})\s+(.+)$/.exec(trimmed);
      if (heading) {
        flushParagraph();
        flushList();
        const block = element(`h${Math.min(6, heading[1].length + 2)}`, {
          className: "chat-heading",
        });
        appendInlineMarkdown(block, heading[2]);
        target.appendChild(block);
        return;
      }
      const unordered = /^[-*]\s+(.+)$/.exec(trimmed);
      const ordered = /^(\d+)\.\s+(.+)$/.exec(trimmed);
      if (unordered || ordered) {
        flushParagraph();
        const tag = ordered ? "ol" : "ul";
        if (!list || list.tagName.toLowerCase() !== tag) {
          flushList();
          list = element(tag, {className: "chat-list"});
        }
        const item = element("li");
        appendInlineMarkdown(item, (unordered || ordered)[ordered ? 2 : 1]);
        list.appendChild(item);
        return;
      }
      flushList();
      paragraph.push(line);
    });
    flushParagraph();
    flushList();
  }

  function appendInlineMarkdown(target, text) {
    const tokenPattern = /(`[^`\n]+`|\*\*[^*\n]+\*\*|\[[^\]\n]+\]\([^) \n]+\))/g;
    text.split("\n").forEach((line, lineIndex) => {
      if (lineIndex > 0) target.appendChild(document.createElement("br"));
      let index = 0;
      let match;
      while ((match = tokenPattern.exec(line)) !== null) {
        appendText(target, line.slice(index, match.index));
        appendMarkdownToken(target, match[0]);
        index = tokenPattern.lastIndex;
      }
      appendText(target, line.slice(index));
    });
  }

  function appendText(target, text) {
    if (text) target.appendChild(document.createTextNode(text));
  }

  function appendMarkdownToken(target, token) {
    if (token.startsWith("`")) {
      target.appendChild(element("code", {text: token.slice(1, -1)}));
      return;
    }
    if (token.startsWith("**")) {
      target.appendChild(element("strong", {text: token.slice(2, -2)}));
      return;
    }
    const link = /^\[([^\]]+)\]\(([^)]+)\)$/.exec(token);
    if (link && safeHref(link[2])) {
      const anchor = element("a", {text: link[1], attrs: {href: link[2]}});
      if (/^https?:\/\//i.test(link[2])) {
        anchor.target = "_blank";
        anchor.rel = "noopener noreferrer";
      }
      target.appendChild(anchor);
      return;
    }
    appendText(target, token);
  }

  function safeHref(value) {
    return /^(https?:\/\/|\/(?!\/)|#)/i.test(value);
  }

  function messageActions(text) {
    const actions = element("div", {className: "chat-actions"});
    const copy = element("button", {text: "copy", attrs: {type: "button"}});
    copy.addEventListener("click", async () => {
      if (navigator.clipboard) await navigator.clipboard.writeText(text);
      copy.textContent = "copied";
      setTimeout(() => {
        copy.textContent = "copy";
      }, 1200);
    });
    actions.appendChild(copy);
    return actions;
  }

  function renderHistory(history) {
    showEmpty();
    if (!history || !history.length) return;
    log.replaceChildren();
    history.forEach((turn) => {
      addMessage(turn.role === "user" ? "user" : "assistant", turn.content);
    });
  }

  function addBusy(text = "working") {
    clearBusy();
    const row = element("div", {className: "chat-row assistant busy", id: "chat-busy"});
    const bubble = element("div", {className: "chat-bubble"});
    bubble.append(
      element("span", {className: "chat-role", text: "agent"}),
      element("div", {className: "chat-text", text}),
    );
    row.appendChild(bubble);
    log.appendChild(row);
    log.scrollTop = log.scrollHeight;
  }

  function updateBusy(text) {
    const body = document.querySelector("#chat-busy .chat-text");
    if (body && text) {
      body.textContent = text;
      log.scrollTop = log.scrollHeight;
    }
  }

  function clearBusy() {
    const row = document.getElementById("chat-busy");
    if (row) row.remove();
  }

  async function readEventStream(response, onEvent) {
    if (!response.body) throw new Error("Streaming is not supported by this browser");
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    while (true) {
      const {value, done} = await reader.read();
      buffer += decoder.decode(value || new Uint8Array(), {stream: !done});
      let boundary = buffer.indexOf("\n\n");
      while (boundary !== -1) {
        const block = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        dispatchSseBlock(block, onEvent);
        boundary = buffer.indexOf("\n\n");
      }
      if (done) break;
    }
    if (buffer.trim()) dispatchSseBlock(buffer, onEvent);
  }

  function dispatchSseBlock(block, onEvent) {
    let eventName = "message";
    const dataLines = [];
    block.split(/\r?\n/).forEach((line) => {
      if (line.startsWith("event:")) eventName = line.slice(6).trim();
      if (line.startsWith("data:")) dataLines.push(line.slice(5).trimStart());
    });
    onEvent(eventName, dataLines.length ? JSON.parse(dataLines.join("\n")) : {});
  }

  function describeStreamEvent(eventName, data) {
    if (eventName === "status") return data.message || "working";
    if (eventName === "campaign") return `campaign ${data.campaign_id} started`;
    if (eventName === "campaign_stats") {
      const elapsed = data.elapsed_sec !== undefined ? `${data.elapsed_sec}s` : "running";
      const crashes = data.unique_crashes !== undefined ? `, crashes ${data.unique_crashes}` : "";
      return `campaign ${data.campaign_id || currentCampaignId}: ${data.status || "running"} ${elapsed}${crashes}`;
    }
    if (eventName === "campaign_event") return `event: ${data.kind || "campaign_event"}`;
    return "";
  }

  async function send(message) {
    addMessage("user", message);
    addBusy("connecting");
    submit.disabled = true;
    input.disabled = true;
    rememberMessage(message);
    let receivedFinal = false;
    try {
      const response = await fetch("/api/chat/stream", {
        method: "POST",
        headers: {"content-type": "application/json"},
        body: JSON.stringify({
          session_id: currentSessionId,
          campaign_id: currentCampaignId || null,
          message: normalizeCommand(message),
        }),
      });
      if (!response.ok) {
        const text = await response.text();
        throw new Error(text || response.statusText);
      }
      await readEventStream(response, (eventName, data) => {
        if (eventName === "final") {
          receivedFinal = true;
          clearBusy();
          setCurrentSession(data.session_id || currentSessionId, data.active_campaign_id || currentCampaignId);
          addMessage("assistant", data.reply || "");
          return;
        }
        if (eventName === "error") throw new Error(data.message || "stream failed");
        if (eventName === "campaign" && data.campaign_id) {
          setCurrentSession(currentSessionId, data.campaign_id);
        }
        updateBusy(describeStreamEvent(eventName, data));
      });
      if (!receivedFinal) throw new Error("stream ended before final response");
      await loadSessions();
    } catch (error) {
      clearBusy();
      addMessage("assistant", `Failed: ${error.message || error}`);
    } finally {
      submit.disabled = false;
      input.disabled = false;
      input.focus();
    }
  }

  async function loadSessions() {
    const response = await fetch("/api/chat/sessions");
    const sessions = response.ok ? await response.json() : [];
    sessionList.replaceChildren();
    if (!sessions.length) {
      sessionList.appendChild(element("div", {className: "session-empty", text: "No sessions yet."}));
      return;
    }
    sessions.forEach((session) => {
      const button = element("button", {className: "session-card", attrs: {type: "button"}});
      if (session.session_id === currentSessionId) button.classList.add("active");
      const title = element("strong", {
        text: session.title || "New session",
        attrs: {title: session.title || "New session"},
      });
      const previewText = sessionPreview(session);
      button.append(
        title,
        element("span", {
          className: "session-preview",
          text: previewText,
          attrs: {title: previewText},
        }),
        element("span", {className: "session-meta", text: sessionMeta(session)}),
      );
      button.addEventListener("click", () => loadSession(session.session_id));
      sessionList.appendChild(button);
    });
  }

  function sessionPreview(session) {
    const preview = session.preview || "";
    if (!preview) return "No messages yet.";
    const role = session.preview_role === "user" ? "you" : "agent";
    return `${role}: ${preview}`;
  }

  function sessionMeta(session) {
    const scope = session.active_campaign_id
      ? `campaign ${session.active_campaign_id}`
      : `${session.turn_count || 0} turns`;
    const recency = relativeTime(session.updated_at);
    return recency ? `${scope} - ${recency}` : scope;
  }

  function relativeTime(value) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "";
    const seconds = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
    if (seconds < 60) return "now";
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h`;
    return date.toLocaleDateString(undefined, {month: "short", day: "numeric"});
  }

  async function loadSession(sessionId) {
    const response = await fetch(`/api/chat/sessions/${sessionId}`);
    if (!response.ok) return;
    const session = await response.json();
    setCurrentSession(session.session_id, session.active_campaign_id || "");
    renderHistory(session.history || []);
    await loadSessions();
  }

  function startNewSession() {
    setCurrentSession(newSessionId(), initialCampaignId);
    showEmpty();
    loadSessions();
    input.focus();
  }

  function normalizeCommand(message) {
    return message.startsWith("/") ? message.slice(1).trimStart() : message;
  }

  function rememberMessage(message) {
    if (sentMessages[sentMessages.length - 1] !== message) sentMessages.push(message);
    recallIndex = null;
  }

  function autosizeInput() {
    input.style.height = "auto";
    input.style.height = `${Math.min(input.scrollHeight, 180)}px`;
  }

  function renderCommandHints() {
    if (!commandHints) return;
    const value = input.value.trim().toLowerCase();
    commandHints.replaceChildren();
    if (!value.startsWith("/")) {
      commandHints.hidden = true;
      return;
    }
    const matches = commandChoices.filter((command) => command.value.startsWith(value)).slice(0, 4);
    if (!matches.length) {
      commandHints.hidden = true;
      return;
    }
    matches.forEach((command) => {
      const button = element("button", {className: "command-hint", attrs: {type: "button"}});
      button.append(
        element("strong", {text: command.label}),
        element("span", {text: command.description}),
      );
      button.addEventListener("click", () => {
        input.value = command.value;
        autosizeInput();
        renderCommandHints();
        input.focus();
      });
      commandHints.appendChild(button);
    });
    commandHints.hidden = false;
  }

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const message = input.value.trim();
    if (!message) return;
    input.value = "";
    autosizeInput();
    renderCommandHints();
    send(message);
  });

  input.addEventListener("input", () => {
    autosizeInput();
    renderCommandHints();
  });

  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
      event.preventDefault();
      form.requestSubmit();
      return;
    }
    if (event.key === "ArrowUp" && !input.value && sentMessages.length) {
      event.preventDefault();
      recallIndex = sentMessages.length - 1;
      input.value = sentMessages[recallIndex];
      autosizeInput();
      return;
    }
    if (event.key === "ArrowDown" && recallIndex !== null) {
      event.preventDefault();
      recallIndex += 1;
      if (recallIndex >= sentMessages.length) {
        recallIndex = null;
        input.value = "";
      } else {
        input.value = sentMessages[recallIndex];
      }
      autosizeInput();
    }
  });

  document.querySelectorAll("[data-command]").forEach((button) => {
    button.addEventListener("click", () => {
      const command = button.getAttribute("data-command");
      if (command) send(command);
    });
  });

  if (newSessionButton) newSessionButton.addEventListener("click", startNewSession);
  setCurrentSession(currentSessionId, currentCampaignId);
  loadSessions().then(() => {
    if (querySessionId) loadSession(querySessionId);
  });
})();
