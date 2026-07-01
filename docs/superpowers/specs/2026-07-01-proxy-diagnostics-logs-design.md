# Proxy Diagnostics Logs Design

Date: 2026-07-01

## Goal

Make proxy failures explainable from inside the app. The user should be able to open proxy settings and see what the client is doing right now, what happened earlier in the current run, and the newest persisted logs from disk after a restart.

## Scope

The feature covers MTProxy and network/proxy connection diagnostics. It does not replace the existing main log, MTP log, or `DebugLogs/mtproxy_*.txt` files. It adds a GUI-facing diagnostics stream and a readable proxy logs tab that can also load the newest persisted files.

The first UI entry point is the bottom area of the existing `Proxy settings` box. A new `Logs` tab or section appears there with diagnostic controls and a scrollable log view.

## User Experience

The `Logs` view shows concise rows with:

- timestamp
- source (`MTProxy`, `Network`, `MTP`)
- phase (`resolving`, `connecting`, `tcp_connected`, `client_hello_sent`, `server_hello_ok`, `telegram_check`, `connected`, `failed`)
- proxy endpoint when applicable
- transport and dc when available
- socket or connection id when available
- error category and readable text

Controls:

- source filter: `MTProxy`, `Network`, `All`
- text filter for host, phase, dc, error, or message
- refresh/reload button
- copy visible rows button
- open logs folder button
- clear view button for the current in-memory view only

Secret material is never shown. Proxy secrets, SOCKS passwords, auth keys, raw payload bytes, and full request bodies are redacted before they reach GUI rows or the dedicated proxy log file.

## Architecture

Existing file logging stays in `Logs::writeMtproxy(...)` and continues to write Release-visible `DebugLogs/mtproxy_*.txt`. A new diagnostics model is added beside logging, not as a replacement for it.

The model stores a bounded in-memory ring of recent diagnostic events. Each event is structured data, not only text:

- source
- phase
- severity
- proxy data with redacted credentials
- transport
- dc
- connection id
- socket id
- error category
- message
- timestamp

Transport code emits structured events at the same seams that already update `ProxyConnectionStatus` and write MTProxy log lines. File logging receives a formatted text version of the same event. The GUI subscribes to the in-memory stream for live updates and can request a snapshot of the newest persisted files for older rows.

## Integration Points

Primary source seams:

- `MTP::Instance::setProxyConnectionStatus(...)` for selected-proxy live phase changes
- TCP/HTTP/resolving connection code for DNS, TCP, handshake, Telegram check, success, and failure
- MTProxy abstract socket error mapping for socket-level failures
- proxy check flows that run from proxy rows, proxy details, and rotation manager
- existing log file rotation in `logs.cpp`

Primary UI seam:

- `boxes/connection_box.cpp`, inside `ProxiesBox`, because this is already the proxy settings surface and owns proxy-list/check controls.

## Error Handling

If live diagnostics are unavailable, the tab still opens and explains that no events were captured in this run. If files cannot be opened, the view keeps live events and shows a single readable file-load error row. Large log files are capped to the newest tail so opening the tab does not block the UI.

The diagnostics stream must not create new network work. It observes existing events only.

## Verification

No compile/build is run unless explicitly requested. Verification for this pass should include:

- focused source guard for Release-visible MTProxy logging and diagnostics stream wiring
- focused source guard for the proxy logs tab entry point and controls
- focused source guard for redaction of secrets/passwords in GUI/file diagnostic rows
- `git diff --check`
- line-ending/no-BOM check for edited text files

## Localization Decision

The UI label is `Logs` in English to match the existing strings file. If the product wants a Russian-only fork label later, that is a localization change and not part of the diagnostics architecture.
