from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
SESSION_PRIVATE_H = SOURCE_DIR / "mtproto" / "session_private.h"
SESSION_PRIVATE_CPP = SOURCE_DIR / "mtproto" / "session_private.cpp"
TLS_SOCKET_CPP = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy" / "tls_socket.cpp"


def test_session_uses_endpoint_health_admission_instead_of_local_cooldown():
    header = SESSION_PRIVATE_H.read_text(encoding="utf-8")
    source = SESSION_PRIVATE_CPP.read_text(encoding="utf-8")
    append_body = function_body(
        source,
        "bool SessionPrivate::appendTestConnection(")

    assert "_endpointCooldownUntil" not in header
    assert "_endpointCooldownUntil" not in source
    assert "noteTestConnectionFailure" not in header
    assert "noteTestConnectionFailure" not in source
    assert "kEndpointCooldownPenalty" not in source
    assert "MtproxyEndpointCooldown(" not in source
    assert "EndpointHealth::Instance().admit(" in append_body
    assert append_body.index("EndpointHealth::Instance().admit(") < (
        append_body.index("AbstractConnection::Create("))


def test_session_keeps_mtproxy_attempt_lease_until_terminal_outcome():
    header = SESSION_PRIVATE_H.read_text(encoding="utf-8")
    source = SESSION_PRIVATE_CPP.read_text(encoding="utf-8")

    assert "MtProxy::EndpointAttemptLease mtproxyLease;" in header
    assert "std::move(admission.lease)" in source
    assert "i->mtproxyLease.release();" in source
    assert "reportFailure(" in source
    assert "reportSuccess(" in TLS_SOCKET_CPP.read_text(encoding="utf-8")


def function_body(text: str, signature: str) -> str:
    start = text.index(signature)
    brace = text.index(" {\n", start) + 1
    depth = 0
    for index in range(brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[brace + 1:index]
    raise AssertionError("body not found")


if __name__ == "__main__":
    test_session_uses_endpoint_health_admission_instead_of_local_cooldown()
    test_session_keeps_mtproxy_attempt_lease_until_terminal_outcome()
