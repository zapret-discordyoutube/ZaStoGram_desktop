import re
from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
CMAKE = ROOT / "Telegram" / "CMakeLists.txt"
MTPROTO_DIR = SOURCE_DIR / "mtproto"
SESSION_PRIVATE_DIR = MTPROTO_DIR / "session" / "private"
SESSION_H = SESSION_PRIVATE_DIR / "session_private.h"
SESSION_MAIN = SESSION_PRIVATE_DIR / "session_private.cpp"
SESSION_TRANSPORT = SESSION_PRIVATE_DIR / "transport.cpp"
SESSION_TRANSPORT_H = SESSION_PRIVATE_DIR / "transport.h"
SESSION_MESSAGE_HANDLER = SESSION_PRIVATE_DIR / "message_handler.cpp"
SESSION_MESSAGE_HANDLER_H = SESSION_PRIVATE_DIR / "message_handler.h"
SESSION_PROXY_PORT = SESSION_PRIVATE_DIR / "proxy_port.cpp"
SESSION_PROXY_PORT_H = SESSION_PRIVATE_DIR / "proxy_port.h"
SESSION_CONNECTION = SESSION_PRIVATE_DIR / "connection.cpp"
SESSION_SEND = SESSION_PRIVATE_DIR / "send.cpp"
SESSION_RECEIVE = SESSION_PRIVATE_DIR / "receive.cpp"
SESSION_AUTH = SESSION_PRIVATE_DIR / "auth.cpp"


SPLIT_SOURCES = (
    SESSION_TRANSPORT,
    SESSION_TRANSPORT_H,
    SESSION_MESSAGE_HANDLER,
    SESSION_MESSAGE_HANDLER_H,
    SESSION_PROXY_PORT,
    SESSION_PROXY_PORT_H,
    SESSION_CONNECTION,
    SESSION_SEND,
    SESSION_RECEIVE,
    SESSION_AUTH,
)


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def function_body(text, signature):
    start = text.index(signature)
    brace = text.index("{", start)
    depth = 0
    for index in range(brace, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[brace:index + 1]
    raise AssertionError(f"body not found for {signature}")


def declarations_named(header, name):
    return re.findall(rf"\b{name}\b", header)


def test_session_private_split_sources_are_registered():
    cmake = read(CMAKE)

    for path in SPLIT_SOURCES:
        relative = path.relative_to(SOURCE_DIR).as_posix()
        assert relative in cmake

    for old_name in (
        "session_private_auth.cpp",
        "session_private_connection.cpp",
        "session_private_receive.cpp",
        "session_private_send.cpp",
    ):
        assert old_name not in cmake
        assert not (MTPROTO_DIR / old_name).exists()


def test_session_private_header_groups_private_state():
    header = read(SESSION_H)
    transport = read(SESSION_TRANSPORT_H)

    for name in (
        "RequestState",
        "SessionState",
        "AuthState",
    ):
        assert f"struct {name}" in header

    for name in (
        "TestConnection",
        "ConnectionState",
        "TimingState",
    ):
        assert f"struct {name}" in transport

    assert "RequestState _requestState;" in header
    assert "SessionState _sessionState;" in header
    assert "AuthState _authState;" in header

    assert not declarations_named(header, "_connection")
    assert not declarations_named(header, "_sessionData")
    assert not declarations_named(header, "_keyCreator")


def test_session_private_owns_transport_and_message_handler_components():
    header = read(SESSION_H)
    source = read(SESSION_MAIN)

    assert '#include "mtproto/session/private/transport.h"' in header
    assert '#include "mtproto/session/private/message_handler.h"' in header
    assert '#include "mtproto/session/private/proxy_port.h"' in header
    assert "SessionTransport _transport;" in header
    assert "SessionMessageHandler _messageHandler;" in header
    assert "const not_null<SessionProxyPort*> _proxyPort;" in header
    assert ", _transport(this, _runtime)" in source
    assert ", _messageHandler(this)" in source


def test_transport_and_message_handler_own_bulk_methods():
    transport = read(SESSION_TRANSPORT)
    transport_h = read(SESSION_TRANSPORT_H)
    message_handler = read(SESSION_MESSAGE_HANDLER)
    message_handler_h = read(SESSION_MESSAGE_HANDLER_H)
    connection = read(SESSION_CONNECTION)
    receive = read(SESSION_RECEIVE)
    header = read(SESSION_H)

    assert "class SessionTransport final" in transport_h
    assert "SessionTransport::SessionTransport(" in transport
    assert "SessionTransport::appendTestConnection(" in connection
    assert "SessionTransport::connectToServer(" in connection
    assert "SessionTransport::waitReceivedFailed(" in connection
    assert "SessionTransport::onError(" in connection
    assert "class SessionMessageHandler final" in message_handler_h
    assert "enum class HandleResult" in message_handler_h
    assert "struct OuterInfo" in message_handler_h
    assert "SessionMessageHandler::handleOneReceived(" in receive
    assert "SessionMessageHandler::handleMsgContainer(" in receive
    assert "SessionMessageHandler::handleRpcResult(" in receive
    assert "SessionPrivate::handleOneReceived(" not in receive
    assert "SessionPrivate::handleMsgContainer(" not in receive
    assert "SessionPrivate::handleRpcResult(" not in receive
    assert "HandleResult handleOneReceived(" not in header
    assert "HandleResult handleMsgContainer(" not in header
    assert "HandleResult handleRpcResult(" not in header


def test_session_private_main_keeps_only_glue_not_bulk_modules():
    source = read(SESSION_MAIN)

    forbidden_signatures = (
        "bool SessionPrivate::appendTestConnection(",
        "void SessionPrivate::tryToSend(",
        "SessionPrivate::HandleResult SessionPrivate::handleOneReceived(",
        "void SessionPrivate::applyAuthKey(",
    )
    for signature in forbidden_signatures:
        assert signature not in source

    assert "SessionPrivate::SessionPrivate(" in source
    assert "SessionPrivate::~SessionPrivate(" in source
    assert "void SessionPrivate::logMtprotoEvent(" in source


def test_receive_dispatcher_is_short_and_delegates_cases():
    source = read(SESSION_RECEIVE)
    body = function_body(
        source,
        "SessionMessageHandler::HandleResult SessionMessageHandler::handleOneReceived(")

    assert len(body.splitlines()) <= 90

    handlers = (
        ("mtpc_gzip_packed", "handleGzipPacked"),
        ("mtpc_msg_container", "handleMsgContainer"),
        ("mtpc_msgs_ack", "handleMsgsAck"),
        ("mtpc_bad_msg_notification", "handleBadMsgNotification"),
        ("mtpc_bad_server_salt", "handleBadServerSalt"),
        ("mtpc_msgs_state_info", "handleMsgsStateInfo"),
        ("mtpc_msgs_all_info", "handleMsgsAllInfo"),
        ("mtpc_msg_detailed_info", "handleMsgDetailedInfo"),
        ("mtpc_msg_new_detailed_info", "handleMsgNewDetailedInfo"),
        ("mtpc_rpc_result", "handleRpcResult"),
        ("mtpc_new_session_created", "handleNewSessionCreated"),
        ("mtpc_pong", "handlePong"),
    )
    for constructor, handler in handlers:
        assert f"case {constructor}:" in body
        assert f"return {handler}(" in body
        assert f"SessionMessageHandler::HandleResult SessionMessageHandler::{handler}(" in source

    assert "return handleUpdates(" in body
    assert "SessionMessageHandler::HandleResult SessionMessageHandler::handleUpdates(" in source
