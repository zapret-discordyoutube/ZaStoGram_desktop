# MTProxy Module Split Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move proxy and MTProxy code into a dedicated `mtproto/proxy/` module, then clean up the main ownership leaks.

**Architecture:** Stage 1 is mostly mechanical relocation with public names left in `namespace MTP`. Stage 2 moves status and policy ownership behind focused proxy headers while keeping `SessionPrivate`, `TlsSocket`, and UI code as consumers.

**Tech Stack:** Telegram Desktop C++/Qt, CMake source list, Python source-contract tests.

## Execution Status

Completed on 2026-07-02 on branch `dev`.

Commits:

- `c102c380eb` Move proxy core into its module
- `a51cb580e5` Move MTProxy transports into proxy module
- `d5cf8a29bb` Extract proxy status model
- `de83da3717` Extract MTProxy policy ownership

Final proof is source-contract verification and path-scoped whitespace checks.
Compilation was intentionally skipped by repository instruction because no build
was explicitly requested.

---

## File Structure

- Create: `Telegram/SourceFiles/mtproto/proxy/data.{h,cpp}`
- Create: `Telegram/SourceFiles/mtproto/proxy/status.h`
- Create: `Telegram/SourceFiles/mtproto/proxy/check.{h,cpp}`
- Create: `Telegram/SourceFiles/mtproto/proxy/diagnostics.{h,cpp}`
- Create: `Telegram/SourceFiles/mtproto/proxy/handshake_gate.{h,cpp}`
- Create: `Telegram/SourceFiles/mtproto/proxy/resolving_connection.{h,cpp}`
- Create: `Telegram/SourceFiles/mtproto/proxy/mtproxy/adaptive_policy.{h,cpp}`
- Create: `Telegram/SourceFiles/mtproto/proxy/mtproxy/policy.{h,cpp}`
- Create: `Telegram/SourceFiles/mtproto/proxy/mtproxy/tls_socket.{h,cpp}`
- Create: `Telegram/SourceFiles/mtproto/proxy/wss/socket.{h,cpp}`
- Modify: `Telegram/CMakeLists.txt`
- Modify: proxy/transport includes in `Telegram/SourceFiles/mtproto/`
- Modify: proxy UI/settings includes in `Telegram/SourceFiles/core/`, `Telegram/SourceFiles/boxes/`, and `Telegram/SourceFiles/window/`
- Modify: focused Python guards in `Telegram/SourceFiles/tests/`

## Task 1: Move Proxy Module Files

**Files:**
- Move: `Telegram/SourceFiles/mtproto/mtproto_proxy_data.*`
- Move: `Telegram/SourceFiles/mtproto/proxy_check.*`
- Move: `Telegram/SourceFiles/mtproto/proxy_diagnostics.*`
- Move: `Telegram/SourceFiles/mtproto/handshake_gate.*`
- Move: `Telegram/SourceFiles/mtproto/connection_resolving.*`
- Modify: `Telegram/CMakeLists.txt`
- Modify: `Telegram/SourceFiles/tests/test_proxy_diagnostics.py`
- Modify: `Telegram/SourceFiles/tests/test_proxy_connection_status.py`
- Modify: `Telegram/SourceFiles/tests/test_proxy_wss_default.py`
- Modify: `Telegram/SourceFiles/tests/test_handshake_gate.py`
- Modify: `Telegram/SourceFiles/tests/test_windows_release_and_mtproxy_logging.py`
- Modify: includes found by `rg -n "mtproto/(mtproto_proxy_data|proxy_check|proxy_diagnostics|handshake_gate|connection_resolving)" Telegram/SourceFiles`

- [x] **Step 1: Update source-contract tests for the new paths**

Change test path constants to the new names:

```python
PROXY_DIR = SOURCE_DIR / "mtproto" / "proxy"
PROXY_DATA_H = PROXY_DIR / "data.h"
DIAGNOSTICS_H = PROXY_DIR / "diagnostics.h"
DIAGNOSTICS_CPP = PROXY_DIR / "diagnostics.cpp"
PROXY_CHECK_H = PROXY_DIR / "check.h"
PROXY_CHECK_CPP = PROXY_DIR / "check.cpp"
GATE_H = PROXY_DIR / "handshake_gate.h"
GATE_CPP = PROXY_DIR / "handshake_gate.cpp"
RESOLVING_CPP = PROXY_DIR / "resolving_connection.cpp"
```

Update CMake assertions from old entries such as:

```python
assert "mtproto/proxy_diagnostics.cpp" in cmake
```

to new entries:

```python
assert "mtproto/proxy/diagnostics.cpp" in cmake
```

- [x] **Step 2: Run tests to verify path expectations fail before moving**

Run:

```bash
python3 Telegram/SourceFiles/tests/test_proxy_diagnostics.py
python3 Telegram/SourceFiles/tests/test_handshake_gate.py
python3 Telegram/SourceFiles/tests/test_proxy_wss_default.py
```

Expected: at least one failure because the files still live at the old paths.

- [x] **Step 3: Move files into `mtproto/proxy/`**

Run:

```bash
mkdir -p Telegram/SourceFiles/mtproto/proxy
git mv Telegram/SourceFiles/mtproto/mtproto_proxy_data.h Telegram/SourceFiles/mtproto/proxy/data.h
git mv Telegram/SourceFiles/mtproto/mtproto_proxy_data.cpp Telegram/SourceFiles/mtproto/proxy/data.cpp
git mv Telegram/SourceFiles/mtproto/proxy_check.h Telegram/SourceFiles/mtproto/proxy/check.h
git mv Telegram/SourceFiles/mtproto/proxy_check.cpp Telegram/SourceFiles/mtproto/proxy/check.cpp
git mv Telegram/SourceFiles/mtproto/proxy_diagnostics.h Telegram/SourceFiles/mtproto/proxy/diagnostics.h
git mv Telegram/SourceFiles/mtproto/proxy_diagnostics.cpp Telegram/SourceFiles/mtproto/proxy/diagnostics.cpp
git mv Telegram/SourceFiles/mtproto/handshake_gate.h Telegram/SourceFiles/mtproto/proxy/handshake_gate.h
git mv Telegram/SourceFiles/mtproto/handshake_gate.cpp Telegram/SourceFiles/mtproto/proxy/handshake_gate.cpp
git mv Telegram/SourceFiles/mtproto/connection_resolving.h Telegram/SourceFiles/mtproto/proxy/resolving_connection.h
git mv Telegram/SourceFiles/mtproto/connection_resolving.cpp Telegram/SourceFiles/mtproto/proxy/resolving_connection.cpp
```

- [x] **Step 4: Update includes and CMake source list**

Apply these include path replacements across source and tests:

```text
mtproto/mtproto_proxy_data.h        -> mtproto/proxy/data.h
mtproto/proxy_check.h               -> mtproto/proxy/check.h
mtproto/proxy_diagnostics.h         -> mtproto/proxy/diagnostics.h
mtproto/handshake_gate.h            -> mtproto/proxy/handshake_gate.h
mtproto/connection_resolving.h      -> mtproto/proxy/resolving_connection.h
```

In `Telegram/CMakeLists.txt`, replace the old entries with:

```cmake
mtproto/proxy/check.cpp
mtproto/proxy/check.h
mtproto/proxy/data.cpp
mtproto/proxy/data.h
mtproto/proxy/diagnostics.cpp
mtproto/proxy/diagnostics.h
mtproto/proxy/handshake_gate.cpp
mtproto/proxy/handshake_gate.h
mtproto/proxy/resolving_connection.cpp
mtproto/proxy/resolving_connection.h
```

- [x] **Step 5: Run focused verification**

Run:

```bash
python3 Telegram/SourceFiles/tests/test_proxy_diagnostics.py
python3 Telegram/SourceFiles/tests/test_proxy_connection_status.py
python3 Telegram/SourceFiles/tests/test_proxy_wss_default.py
python3 Telegram/SourceFiles/tests/test_handshake_gate.py
python3 Telegram/SourceFiles/tests/test_windows_release_and_mtproxy_logging.py
git diff --check -- Telegram/CMakeLists.txt Telegram/SourceFiles/mtproto Telegram/SourceFiles/core Telegram/SourceFiles/boxes Telegram/SourceFiles/window Telegram/SourceFiles/tests
```

Expected: Python guards pass. Whitespace check reports no issues in touched files.

- [x] **Step 6: Commit stage 1 core move**

Run:

```bash
git add Telegram/CMakeLists.txt Telegram/SourceFiles/mtproto Telegram/SourceFiles/core Telegram/SourceFiles/boxes Telegram/SourceFiles/window Telegram/SourceFiles/tests
git commit -m "Move proxy core into its module"
```

## Task 2: Move MTProxy and WSS Transport Submodules

**Files:**
- Move: `Telegram/SourceFiles/mtproto/details/mtproto_tls_socket.*`
- Move: `Telegram/SourceFiles/mtproto/details/mtproto_proxy_adaptive_policy.*`
- Move: `Telegram/SourceFiles/mtproto/details/mtproto_wss_socket.*`
- Modify: `Telegram/SourceFiles/mtproto/details/mtproto_abstract_socket.cpp`
- Modify: `Telegram/SourceFiles/mtproto/connection_tcp.h`
- Modify: `Telegram/SourceFiles/mtproto/connection_tcp.cpp`
- Modify: `Telegram/SourceFiles/tests/test_mtproxy_tls_psk.py`
- Modify: `Telegram/SourceFiles/tests/test_proxy_wss_default.py`
- Modify: `Telegram/SourceFiles/tests/test_windows_release_and_mtproxy_logging.py`

- [x] **Step 1: Update tests for new transport module paths**

Change path constants to:

```python
PROXY_DIR = SOURCE_DIR / "mtproto" / "proxy"
TLS_SOCKET_CPP = PROXY_DIR / "mtproxy" / "tls_socket.cpp"
ADAPTIVE_POLICY_H = PROXY_DIR / "mtproxy" / "adaptive_policy.h"
ADAPTIVE_POLICY_CPP = PROXY_DIR / "mtproxy" / "adaptive_policy.cpp"
WSS_SOCKET_H = PROXY_DIR / "wss" / "socket.h"
WSS_SOCKET_CPP = PROXY_DIR / "wss" / "socket.cpp"
```

Update CMake assertions to look for:

```python
assert "mtproto/proxy/mtproxy/tls_socket.cpp" in cmake
assert "mtproto/proxy/mtproxy/adaptive_policy.cpp" in cmake
assert "mtproto/proxy/wss/socket.cpp" in cmake
```

- [x] **Step 2: Run tests to verify path expectations fail before moving**

Run:

```bash
python3 Telegram/SourceFiles/tests/test_mtproxy_tls_psk.py
python3 Telegram/SourceFiles/tests/test_proxy_wss_default.py
```

Expected: at least one failure because transport files still live under `mtproto/details/`.

- [x] **Step 3: Move transport files**

Run:

```bash
mkdir -p Telegram/SourceFiles/mtproto/proxy/mtproxy Telegram/SourceFiles/mtproto/proxy/wss
git mv Telegram/SourceFiles/mtproto/details/mtproto_tls_socket.h Telegram/SourceFiles/mtproto/proxy/mtproxy/tls_socket.h
git mv Telegram/SourceFiles/mtproto/details/mtproto_tls_socket.cpp Telegram/SourceFiles/mtproto/proxy/mtproxy/tls_socket.cpp
git mv Telegram/SourceFiles/mtproto/details/mtproto_proxy_adaptive_policy.h Telegram/SourceFiles/mtproto/proxy/mtproxy/adaptive_policy.h
git mv Telegram/SourceFiles/mtproto/details/mtproto_proxy_adaptive_policy.cpp Telegram/SourceFiles/mtproto/proxy/mtproxy/adaptive_policy.cpp
git mv Telegram/SourceFiles/mtproto/details/mtproto_wss_socket.h Telegram/SourceFiles/mtproto/proxy/wss/socket.h
git mv Telegram/SourceFiles/mtproto/details/mtproto_wss_socket.cpp Telegram/SourceFiles/mtproto/proxy/wss/socket.cpp
```

- [x] **Step 4: Update includes and CMake source list**

Apply these replacements:

```text
mtproto/details/mtproto_tls_socket.h              -> mtproto/proxy/mtproxy/tls_socket.h
mtproto/details/mtproto_proxy_adaptive_policy.h   -> mtproto/proxy/mtproxy/adaptive_policy.h
mtproto/details/mtproto_wss_socket.h              -> mtproto/proxy/wss/socket.h
```

In `Telegram/CMakeLists.txt`, replace the old detail entries with:

```cmake
mtproto/proxy/mtproxy/adaptive_policy.cpp
mtproto/proxy/mtproxy/adaptive_policy.h
mtproto/proxy/mtproxy/tls_socket.cpp
mtproto/proxy/mtproxy/tls_socket.h
mtproto/proxy/wss/socket.cpp
mtproto/proxy/wss/socket.h
```

- [x] **Step 5: Run focused verification**

Run:

```bash
python3 Telegram/SourceFiles/tests/test_mtproxy_tls_psk.py
python3 Telegram/SourceFiles/tests/test_proxy_wss_default.py
python3 Telegram/SourceFiles/tests/test_proxy_diagnostics.py
git diff --check -- Telegram/CMakeLists.txt Telegram/SourceFiles/mtproto Telegram/SourceFiles/tests
```

Expected: Python guards pass. Whitespace check reports no issues in touched files.

- [x] **Step 6: Commit stage 1 transport move**

Run:

```bash
git add Telegram/CMakeLists.txt Telegram/SourceFiles/mtproto Telegram/SourceFiles/tests
git commit -m "Move MTProxy transports into proxy module"
```

## Task 3: Extract Proxy Status Model

**Files:**
- Create: `Telegram/SourceFiles/mtproto/proxy/status.h`
- Modify: `Telegram/SourceFiles/mtproto/connection_abstract.h`
- Modify: `Telegram/SourceFiles/mtproto/proxy/diagnostics.h`
- Modify: `Telegram/SourceFiles/mtproto/mtp_instance.h`
- Modify: `Telegram/SourceFiles/window/window_connecting_widget.h`
- Modify: `Telegram/SourceFiles/tests/test_proxy_connection_status.py`

- [x] **Step 1: Update the status test**

Change `test_proxy_connection_status.py` so it asserts:

```python
STATUS_H = SOURCE_DIR / "mtproto" / "proxy" / "status.h"
ABSTRACT_CONNECTION_H = SOURCE_DIR / "mtproto" / "connection_abstract.h"

def test_proxy_status_model_is_exposed_to_ui():
    status_header = STATUS_H.read_text(encoding="utf-8")
    abstract_connection = ABSTRACT_CONNECTION_H.read_text(encoding="utf-8")
    instance_header = INSTANCE_H.read_text(encoding="utf-8")
    widget_header = WIDGET_H.read_text(encoding="utf-8")

    assert "enum class ProxyConnectionPhase" in status_header
    assert "enum class ProxyConnectionError" in status_header
    assert "struct ProxyConnectionStatus" in status_header
    assert '#include "mtproto/proxy/status.h"' in instance_header
    assert '#include "mtproto/proxy/status.h"' in widget_header
    assert "enum class ProxyConnectionPhase" not in abstract_connection
```

- [x] **Step 2: Run the test to verify it fails**

Run:

```bash
python3 Telegram/SourceFiles/tests/test_proxy_connection_status.py
```

Expected: FAIL because `status.h` does not exist yet.

- [x] **Step 3: Create `proxy/status.h` and update includes**

Move these definitions out of `connection_abstract.h` into the new header:

```cpp
#pragma once

#include "mtproto/proxy/data.h"

namespace MTP {

enum class ProxyConnectionPhase {
	None,
	Resolving,
	Connecting,
	Handshake,
	CheckingTelegram,
	Connected,
	Failed,
};

enum class ProxyConnectionError {
	None,
	HostNotFound,
	ConnectionRefused,
	Timeout,
	Authentication,
	ProxyProtocol,
	RemoteClosed,
	Network,
	BadResponse,
	Unknown,
};

struct ProxyConnectionStatus {
	ProxyConnectionPhase phase = ProxyConnectionPhase::None;
	ProxyConnectionError error = ProxyConnectionError::None;
	ProxyData proxy;

	bool operator==(const ProxyConnectionStatus &other) const {
		return (phase == other.phase)
			&& (error == other.error)
			&& (proxy == other.proxy);
	}

};

} // namespace MTP
```

Add `#include "mtproto/proxy/status.h"` to files that use these types directly.

- [x] **Step 4: Run focused verification**

Run:

```bash
python3 Telegram/SourceFiles/tests/test_proxy_connection_status.py
python3 Telegram/SourceFiles/tests/test_proxy_diagnostics.py
git diff --check -- Telegram/SourceFiles/mtproto Telegram/SourceFiles/window Telegram/SourceFiles/tests
```

Expected: Python guards pass. Whitespace check reports no issues in touched files.

- [x] **Step 5: Commit status extraction**

Run:

```bash
git add Telegram/SourceFiles/mtproto Telegram/SourceFiles/window Telegram/SourceFiles/tests
git commit -m "Extract proxy status model"
```

## Task 4: Introduce MTProxy Policy API

**Files:**
- Create: `Telegram/SourceFiles/mtproto/proxy/mtproxy/policy.h`
- Create: `Telegram/SourceFiles/mtproto/proxy/mtproxy/policy.cpp`
- Modify: `Telegram/SourceFiles/mtproto/session_private.cpp`
- Modify: `Telegram/SourceFiles/mtproto/proxy/mtproxy/tls_socket.cpp`
- Modify: `Telegram/SourceFiles/tests/test_handshake_gate.py`
- Create: `Telegram/SourceFiles/tests/test_mtproxy_policy.py`

- [x] **Step 1: Add source guard for policy ownership**

Add a focused Python guard that asserts:

```python
POLICY_H = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "policy.h"
POLICY_CPP = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "policy.cpp"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session_private.cpp"
TLS_SOCKET_CPP = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "tls_socket.cpp"

def test_session_uses_mtproxy_policy_for_spacing_and_cooldown():
    policy_h = POLICY_H.read_text(encoding="utf-8")
    policy_cpp = POLICY_CPP.read_text(encoding="utf-8")
    session = SESSION_CPP.read_text(encoding="utf-8")

    assert "MtproxyConnectionSpacing(" in policy_h
    assert "MtproxyEndpointCooldown(" in policy_h
    assert "ProxyPatternSpacing(" not in session
    assert "CooldownMsForEndpoint(" not in session
    assert "MtproxyConnectionSpacing(" in session
    assert "MtproxyEndpointCooldown(" in session

def test_tls_socket_reports_to_policy_without_owning_cooldown():
    tls = TLS_SOCKET_CPP.read_text(encoding="utf-8")
    assert "MtproxyNoteEndpointFailure(" in tls
    assert "MtproxyRotateTlsProfileOnFailure(" in tls
    assert "CooldownMsForEndpoint(" not in tls
```

- [x] **Step 2: Run the new guard to verify it fails**

Run:

```bash
python3 Telegram/SourceFiles/tests/test_mtproxy_policy.py
```

Expected: FAIL because `policy.h` and `policy.cpp` do not exist yet.

- [x] **Step 3: Create policy wrapper API**

Create `policy.h` with these declarations:

```cpp
#pragma once

#include "mtproto/proxy/data.h"

namespace MTP::details {

[[nodiscard]] crl::time MtproxyConnectionSpacing(
	ProxyConnectionPattern pattern);
[[nodiscard]] int MtproxyEndpointCooldown(const QString &endpointKey);
void MtproxyNoteEndpointFailure(
	const QString &endpointKey,
	const QString &diagnostic);
void MtproxyNoteEndpointSuccess(const QString &endpointKey);
[[nodiscard]] ProxyTlsProfile MtproxyRotateTlsProfileOnFailure(
	const QString &endpointKey,
	const QString &diagnostic,
	ProxyTlsProfile previous);

} // namespace MTP::details
```

Create `policy.cpp` as a small wrapper over existing adaptive policy state and the current spacing switch. Keep `AdaptiveRecipe*` internals in `adaptive_policy.*`.

- [x] **Step 4: Update session and TLS socket callers**

In `session_private.cpp`:

```cpp
const auto spacing = proxied
	? MtproxyConnectionSpacing(_options->stealth.connectionPattern)
	: crl::time(0);
```

Replace endpoint cooldown calls with:

```cpp
_endpointCooldownUntil[found->endpoint] = crl::now()
	+ MtproxyEndpointCooldown(found->endpoint);
```

In `tls_socket.cpp`, replace direct failure/success wrappers:

```cpp
MtproxyNoteEndpointFailure(_endpointKey, diagnostic);
(void)MtproxyRotateTlsProfileOnFailure(
	_endpointKey,
	diagnostic,
	effectiveTlsProfile());
MtproxyNoteEndpointSuccess(_endpointKey);
```

- [x] **Step 5: Run focused verification**

Run:

```bash
python3 Telegram/SourceFiles/tests/test_mtproxy_policy.py
python3 Telegram/SourceFiles/tests/test_handshake_gate.py
python3 Telegram/SourceFiles/tests/test_mtproxy_tls_psk.py
git diff --check -- Telegram/SourceFiles/mtproto Telegram/SourceFiles/tests
```

Expected: Python guards pass. Whitespace check reports no issues in touched files.

- [x] **Step 6: Commit policy extraction**

Run:

```bash
git add Telegram/CMakeLists.txt Telegram/SourceFiles/mtproto Telegram/SourceFiles/tests
git commit -m "Extract MTProxy policy ownership"
```

## Final Verification

- [x] **Step 1: Run all focused proxy checks**

Run:

```bash
python3 Telegram/SourceFiles/tests/test_proxy_diagnostics.py
python3 Telegram/SourceFiles/tests/test_proxy_connection_status.py
python3 Telegram/SourceFiles/tests/test_proxy_wss_default.py
python3 Telegram/SourceFiles/tests/test_handshake_gate.py
python3 Telegram/SourceFiles/tests/test_mtproxy_tls_psk.py
python3 Telegram/SourceFiles/tests/test_windows_release_and_mtproxy_logging.py
python3 Telegram/SourceFiles/tests/test_mtproxy_policy.py
```

Expected: all pass.

- [x] **Step 2: Run path-scoped whitespace check**

Run:

```bash
git diff --check -- Telegram/CMakeLists.txt Telegram/SourceFiles/mtproto Telegram/SourceFiles/core Telegram/SourceFiles/boxes Telegram/SourceFiles/window Telegram/SourceFiles/tests
```

Expected: no output.

- [x] **Step 3: Confirm no full build was run**

Record in the final response that compilation was skipped by repository instruction unless the user explicitly requested it.
