import re
from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
DIAGNOSTICS_H = SOURCE_DIR / "mtproto" / "proxy" / "diagnostics.h"
DIAGNOSTICS_CPP = SOURCE_DIR / "mtproto" / "proxy" / "diagnostics.cpp"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session_private.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def mtp_phases():
    header = read(DIAGNOSTICS_H)
    enum = header[header.index("enum class ProxyDiagnosticsPhase"):]
    enum = enum[:enum.index("}")]
    return [name for name in re.findall(r"\bMtp\w+", enum)]


def test_every_mtp_phase_is_declared_emitted_and_formatted():
    phases = mtp_phases()
    # The whole point of MTP-source diagnostics is a release-visible view
    # of the session lifecycle; a phase that is declared but never emitted
    # (or never named in the formatter) is a silent hole - exactly how
    # mtp_key_destroyed was missing while the enum value existed.
    assert len(phases) >= 12
    session = read_session_private_sources()
    diagnostics = read(DIAGNOSTICS_CPP)
    for phase in phases:
        assert f"ProxyDiagnosticsPhase::{phase}" in session, (
            f"{phase} is never emitted from session_private.cpp")
        assert f"ProxyDiagnosticsPhase::{phase}" in diagnostics, (
            f"{phase} is not handled in diagnostics.cpp")


def test_mtp_events_use_the_dedicated_source_channel():
    session = read_session_private_sources()
    start = session.index("void SessionPrivate::logMtprotoEvent(")
    body = session[start:session.index("}", start) + 1]
    # MTP lifecycle events must land on the MTP source so they are on in
    # release builds alongside the MTProxy transport events, not gated
    # behind debug logging.
    assert "ProxyDiagnosticsSource::MTP" in body
    assert ".dc = mtprotoLogDc()" in body


def test_key_lifecycle_events_are_logged():
    session = read_session_private_sources()

    def body(signature):
        start = session.index(signature)
        brace = session.index("{", start)
        depth = 0
        for i in range(brace, len(session)):
            if session[i] == "{":
                depth += 1
            elif session[i] == "}":
                depth -= 1
                if depth == 0:
                    return session[brace:i + 1]
        raise AssertionError(f"body not found: {signature}")

    destroy = body("void SessionPrivate::destroyTemporaryKey(")
    assert "ProxyDiagnosticsPhase::MtpKeyDestroyed" in destroy

    connecting = body("void SessionPrivate::connectToServer(")
    assert "ProxyDiagnosticsPhase::MtpConnecting" in connecting

    received = body("void SessionPrivate::handleReceived(")
    assert "ProxyDiagnosticsPhase::MtpFirstDataReceived" in received

    wait_received = body("void SessionPrivate::waitReceivedFailed(")
    assert "ProxyDiagnosticsPhase::MtpReceiveTimeout" in wait_received
