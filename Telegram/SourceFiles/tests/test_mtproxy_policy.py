from pathlib import Path
from session_private_sources import read_session_private_sources


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT_DIR = SOURCE_DIR.parents[1]
PROXY_DIR = SOURCE_DIR / "mtproto" / "proxy"
MTPROXY_DIR = SOURCE_DIR / "mtproto" / "proxy" / "mtproxy"
POLICY_H = MTPROXY_DIR / "policy.h"
POLICY_CPP = MTPROXY_DIR / "policy.cpp"
SESSION_CPP = SOURCE_DIR / "mtproto" / "session" / "private" / "session_private.cpp"
TLS_SOCKET_CPP = MTPROXY_DIR / "tls_socket.cpp"
CLIENT_HELLO_RULES_CPP = MTPROXY_DIR / "client_hello_rules.cpp"
CLIENT_HELLO_FRAGMENTATION_CPP = MTPROXY_DIR / "client_hello_fragmentation.cpp"
TLS_SOCKET_HANDSHAKE_CPP = MTPROXY_DIR / "tls_socket_handshake.cpp"
TLS_SOCKET_PSK_CPP = MTPROXY_DIR / "tls_socket_psk.cpp"
TLS_SOCKET_PSK_H = MTPROXY_DIR / "tls_socket_psk.h"
TLS_SOCKET_RECORDS_CPP = MTPROXY_DIR / "tls_socket_records.cpp"
TLS_SOCKET_UTILS_H = MTPROXY_DIR / "tls_socket_utils.h"
CMAKE = ROOT_DIR / "Telegram" / "CMakeLists.txt"
TD_MTPROTO_CMAKE = ROOT_DIR / "Telegram" / "cmake" / "td_mtproto.cmake"
