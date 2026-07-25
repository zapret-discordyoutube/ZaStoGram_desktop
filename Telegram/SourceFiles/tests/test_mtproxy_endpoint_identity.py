from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
MTPROXY_DIR = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
ROOT = SOURCE_DIR.parents[1]
CMAKE = ROOT / "Telegram" / "CMakeLists.txt"
ENDPOINT_IDENTITY_H = MTPROXY_DIR / "endpoint_identity.h"
ENDPOINT_IDENTITY_CPP = MTPROXY_DIR / "endpoint_identity.cpp"
CONNECTION_STATUS_TYPES_H = (
    SOURCE_DIR / "mtproto" / "runtime" / "connection_status_types.h")
RUNTIME_PROXY_ENDPOINT_H = SOURCE_DIR / "mtproto" / "runtime" / "proxy_endpoint.h"
CHECK_CPP = SOURCE_DIR / "mtproto" / "proxy" / "check.cpp"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "session_private.cpp"
TLS_SOCKET_CPP = MTPROXY_DIR / "tls_socket.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def function_body(source, signature):
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for i in range(brace, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[brace:i + 1]
    raise AssertionError(f"function body not found: {signature}")
