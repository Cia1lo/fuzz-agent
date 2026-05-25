# Web UI TODO

Scope: make the current web chat usable as a fuzz-agent workbench, not a generic
chat shell. The interface should keep campaign context, command execution, agent
trace, crash triage, and session history visible enough for repeated debugging.

## P0 - Chat Reliability

- [x] Keep the chat layout within a normal browser viewport.
- [x] Bust stale CSS after web UI changes.
- [x] Persist chat sessions across server restarts.
- [x] Keep history detail available after the in-memory session cache is cleared.
- [x] Make slash commands work in the same command path as plain commands.

## P0 - Input Experience

- [x] Replace the single-line message input with an auto-growing composer.
- [x] Send with Enter and insert a newline with Shift+Enter.
- [x] Add lightweight command recall for recent submitted messages.
- [x] Add visible command suggestions for the core agent actions.

## P1 - Message Rendering

- [x] Render fenced code blocks as code blocks instead of flat text.
- [x] Add per-message copy affordance for agent replies.
- [x] Preserve long command output without breaking the layout.
- [ ] Add structured result blocks for status, trace, triage, crashes, and artifacts.

## P1 - Session Ledger

- [x] Store created/updated timestamps for sessions.
- [x] Show session recency in the sidebar.
- [ ] Add delete and rename actions for sessions.
- [ ] Add search or campaign grouping once session count grows.

## P1 - Campaign Context

- [ ] Show the active campaign's status, elapsed time, coverage, and crash count in chat.
- [ ] Add an explicit clear/switch campaign scope control.
- [ ] Link structured chat results back to campaign detail artifacts.

## P2 - Responsive And Polish

- [ ] Turn the history sidebar into a drawer on narrow screens.
- [x] Tighten CSS scoping so generic element rules do not leak into future screens.
- [ ] Add empty, loading, error, and disabled states that explain the current system state.
- [ ] Add browser screenshot checks for desktop and narrow viewports.
