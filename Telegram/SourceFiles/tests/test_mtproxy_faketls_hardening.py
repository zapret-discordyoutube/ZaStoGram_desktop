from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
MTPROXY_DIR = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
TLS_SOCKET_CPP = MTPROXY_DIR / "tls_socket.cpp"
TLS_SOCKET_HANDSHAKE_CPP = MTPROXY_DIR / "tls_socket_handshake.cpp"
SESSION_PRIVATE_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "session_private.cpp"


def test_immutable_admission_profile_is_used_for_client_hello():
    source = TLS_SOCKET_HANDSHAKE_CPP.read_text(encoding="utf-8")
    header = (MTPROXY_DIR / "tls_socket.h").read_text(encoding="utf-8")
    send_body = function_body(source, "void TlsSocket::sendClientHello()")

    assert "MtProxyAttemptPlan _mtproxyPlan;" in header
    assert "ProxyTlsProfile _preparedTlsProfile" not in header
    assert "applyAdaptiveRecipe" not in source
    assert "const auto profile = effectiveTlsProfile();" in send_body


def function_body(text: str, signature: str) -> str:
    start = text.index(signature)
    brace = text.index(" {\n", start) + 1
    return body_from_brace(text, brace)


def block_after(text: str, marker: str) -> str:
    start = text.index(marker)
    brace = text.index("{", start)
    return body_from_brace(text, brace)


def body_from_brace(text: str, brace: int) -> str:
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
    test_immutable_admission_profile_is_used_for_client_hello()
