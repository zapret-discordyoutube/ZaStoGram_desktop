# MTProxy Module Split Design

## Goal

Move Telegram Desktop proxy and MTProxy code toward a dedicated module under
`Telegram/SourceFiles/mtproto/proxy/`, so the internet/proxy transport system is
described in one place instead of being spread across generic MTProto files.

The work is intentionally split into two stages:

1. Mechanical relocation with minimal behavior risk.
2. Real ownership cleanup after the moved tree exposes the boundaries clearly.

## Non-Goals

- Do not change proxy behavior during stage 1.
- Do not rename public C++ types or namespaces during stage 1 unless needed for
  compilation.
- Do not merge account MTProto sessions into one socket or introduce true proxy
  multiplexing.
- Do not run a full build unless explicitly requested.

## Stage 1: Mechanical Module Move

Create `Telegram/SourceFiles/mtproto/proxy/` as the new root for proxy-specific
transport code. The first pass should mostly move files, update includes,
update `Telegram/CMakeLists.txt`, and update source-contract tests.

Stage 1 target layout:

```text
Telegram/SourceFiles/mtproto/proxy/
  data.*
  check.*
  diagnostics.*
  handshake_gate.*
  resolving_connection.*
  mtproxy/
    adaptive_policy.*
    tls_socket.*
  wss/
    socket.*
```

Initial source mapping:

```text
mtproto/mtproto_proxy_data.*                  -> mtproto/proxy/data.*
mtproto/proxy_check.*                         -> mtproto/proxy/check.*
mtproto/proxy_diagnostics.*                   -> mtproto/proxy/diagnostics.*
mtproto/handshake_gate.*                      -> mtproto/proxy/handshake_gate.*
mtproto/connection_resolving.*                -> mtproto/proxy/resolving_connection.*
mtproto/details/mtproto_tls_socket.*          -> mtproto/proxy/mtproxy/tls_socket.*
mtproto/details/mtproto_proxy_adaptive_policy.* -> mtproto/proxy/mtproxy/adaptive_policy.*
mtproto/details/mtproto_wss_socket.*          -> mtproto/proxy/wss/socket.*
```

`connection_abstract.*`, `connection_tcp.*`, `connection_http.*`,
`session_private.*`, and `mtp_instance.*` stay in their current locations in
stage 1. They may include the new proxy headers, but should not absorb more
proxy policy logic.

## Stage 2: Ownership Cleanup

After stage 1 source-checks cleanly, and compiles if a build was explicitly
requested, split responsibilities inside the new module.

Planned ownership:

- `proxy/data.*`: proxy endpoint model, secret parsing, direct-IP conversion,
  and `QNetworkProxy` conversion.
- `proxy/status.*`: `ProxyConnectionStatus`, `ProxyConnectionPhase`, and
  `ProxyConnectionError`.
- `proxy/diagnostics.*`: event model, redaction, log tail loading, and mapping
  diagnostics phases into visible status.
- `proxy/check.*`: explicit proxy-list and rotation probes.
- `proxy/handshake_gate.*`: soft global admission delay for proxy handshakes.
- `proxy/resolving_connection.*`: proxy host resolution wrapper.
- `proxy/mtproxy/tls_socket.*`: FakeTLS MTProxy transport executor.
- `proxy/mtproxy/adaptive_policy.*`: endpoint recipe state, TLS profile
  rotation, cooldown decisions, and MTProxy-specific recovery policy.
- `proxy/wss/socket.*`: WSS relay transport.

`SessionPrivate` should ask the proxy policy layer for spacing and cooldown
decisions instead of owning those decisions directly. `TlsSocket` should execute
FakeTLS and report facts, while adaptive recovery decisions live behind the
MTProxy policy API. UI code should depend on model/status/diagnostics/check
headers, not transport internals.

## Data Flow

Transport code reports proxy facts through `ReportProxyEvent(...)`.
Diagnostics redacts and stores events, writes the MTProxy log stream, and maps
events into `ProxyConnectionStatus`. `MTP::Instance` remains the account-level
publication point and filters status updates to the selected proxy. UI widgets
translate status into text and display diagnostics snapshots.

Proxy checks remain separate from live account sessions. `StartProxyCheck(...)`
continues to serve proxy rows, refresh flows, and rotation logic. The first
stage must preserve this call shape.

## Error Handling

The split must preserve phase-specific failure semantics:

- DNS failures remain `HostNotFound`.
- socket timeouts remain `Timeout`.
- bad MTProxy responses remain `BadResponse`.
- remote closes remain distinct from generic network errors where the current
  code already distinguishes them.

Stage 1 must not collapse diagnostics phases into generic connecting or failed
states. Stage 2 may improve naming only if production code, diagnostics text,
and source-contract tests are updated together.

## Testing

Stage 1 verification should use focused source-contract tests and whitespace
checks, not a full build by default:

```bash
python3 Telegram/SourceFiles/tests/test_proxy_diagnostics.py
python3 Telegram/SourceFiles/tests/test_proxy_connection_status.py
python3 Telegram/SourceFiles/tests/test_proxy_wss_default.py
python3 Telegram/SourceFiles/tests/test_handshake_gate.py
python3 Telegram/SourceFiles/tests/test_mtproxy_tls_psk.py
git diff --check -- <touched files>
```

Stage 2 should add or update focused guards for:

- proxy status type location and include direction;
- `SessionPrivate` using proxy policy APIs for spacing/cooldown;
- `TlsSocket` reporting failures without owning high-level recovery policy;
- diagnostics still being centralized through `ReportProxyEvent(...)`.

Compilation remains optional unless explicitly requested by the user, per the
repository verification policy.

## Rollout

Implement stage 1 in one small commit. Implement stage 2 in a later commit after
stage 1 is reviewed and source checks pass. If stage 1 reveals hidden circular
dependencies, keep compatibility forwarding headers temporarily rather than
renaming public types and changing ownership in the same patch.
